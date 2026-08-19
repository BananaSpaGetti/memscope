"""
Pointer scanning for MemScope: find a stable path to a value that moves.

A garbage-collected or reallocating program puts a value at a fresh address every time it
changes, so no single address stays useful. What stays useful is the *path*: a pointer in a
module's static data, whose target plus an offset is another pointer, and so on, ending at
the live value. That path holds across restarts because it starts somewhere fixed.

This finds such paths by walking pointers backwards from the target: every address whose
stored value lands within a small window below the target is a pointer to it (with an
offset); repeat from each of those until the chain reaches a module's static range.

    py ptrscan.py <pid|name> <address> [--depth 3] [--offset 0x400] [--max 40]
    py ptrscan.py <pid|name> --resolve "game.exe+0x1A2B3C -> 0x18 -> 0x40"

It is heavier than a value scan -- it reads every pointer-sized slot in the process once, so
on a large target that is a lot of memory. Start with a small --depth and --offset. On a
machine with little free RAM, watch what it costs before widening.

Credit for the idea: this is the well-worn Cheat Engine pointer-scan approach, in miniature.
"""

import argparse
import bisect
import ctypes
import ctypes.wintypes as wt
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("memscope", os.path.join(HERE, "memscope.py"))
memscope = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(memscope)

kernel32 = memscope.kernel32
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
PTR = 8                                           # 64-bit pointers


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD), ("th32ModuleID", wt.DWORD), ("th32ProcessID", wt.DWORD),
        ("GlblcntUsage", wt.DWORD), ("ProccntUsage", wt.DWORD),
        ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)), ("modBaseSize", wt.DWORD),
        ("hModule", wt.HMODULE), ("szModule", ctypes.c_wchar * 256),
        ("szExePath", ctypes.c_wchar * 260),
    ]


def modules(pid):
    """(name, base, size) for each module loaded in the process -- the static ranges."""
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if snapshot == -1:
        return []
    out = []
    entry = MODULEENTRY32W()
    entry.dwSize = ctypes.sizeof(entry)
    try:
        if not kernel32.Module32FirstW(snapshot, ctypes.byref(entry)):
            return out
        while True:
            base = ctypes.cast(entry.modBaseAddr, ctypes.c_void_p).value or 0
            out.append((entry.szModule, base, entry.modBaseSize))
            if not kernel32.Module32NextW(snapshot, ctypes.byref(entry)):
                break
    finally:
        kernel32.CloseHandle(snapshot)
    return out


class PointerMap:
    """Every aligned pointer-sized slot in the process, indexed for 'who points near here'."""

    def __init__(self, process):
        self.process = process
        self.region_bounds = []                   # sorted (base, end), to test plausibility
        self.values = []                          # sorted pointer values
        self.addrs = []                           # address holding each value (parallel)
        self._build()

    def _plausible(self, value):
        i = bisect.bisect_right(self.region_bounds, (value, 1 << 63)) - 1
        return i >= 0 and self.region_bounds[i][0] <= value < self.region_bounds[i][1]

    def _build(self):
        regions = list(self.process.regions())
        self.region_bounds = sorted((base, base + size) for base, size in regions)
        pairs = []
        for base, size in regions:
            offset = 0
            while offset < size:
                span = min(4 * 1024 * 1024, size - offset)
                data = self.process.read(base + offset, span)
                if data:
                    for at in range(0, len(data) - PTR + 1, PTR):
                        value = int.from_bytes(data[at:at + PTR], "little")
                        if self._plausible(value):
                            pairs.append((value, base + offset + at))
                        if len(pairs) >= memscope.MAX_HITS:
                            break
                offset += span
        pairs.sort()
        self.values = [v for v, _a in pairs]
        self.addrs = [a for _v, a in pairs]

    def pointers_into(self, target, max_offset):
        """(address, offset) for every slot whose value is in [target - max_offset, target]."""
        lo = bisect.bisect_left(self.values, target - max_offset)
        hi = bisect.bisect_right(self.values, target)
        return [(self.addrs[i], target - self.values[i]) for i in range(lo, hi)]


def static_of(address, module_list):
    for name, base, size in module_list:
        if base <= address < base + size:
            return name, address - base
    return None


def find_paths(process, target, depth, max_offset, max_paths):
    pmap = PointerMap(process)
    module_list = modules(process.pid)
    results = []
    # Each frontier item: (current_address, [offsets from here down to target], seen set)
    frontier = [(target, [], {target})]
    for _level in range(depth):
        nxt = []
        for address, offsets, seen in frontier:
            for holder, offset in pmap.pointers_into(address, max_offset):
                if holder in seen:
                    continue
                chain = [offset] + offsets
                static = static_of(holder, module_list)
                if static:
                    results.append((static[0], static[1], chain))
                    if len(results) >= max_paths:
                        return results, pmap
                else:
                    nxt.append((holder, chain, seen | {holder}))
        frontier = nxt
        if not frontier:
            break
    return results, pmap


def resolve(process, module_name, module_offset, offsets, module_list):
    base = next((b for n, b, _s in module_list if n.lower() == module_name.lower()), None)
    if base is None:
        return None
    # base+offset is the holder slot; each offset dereferences the slot then adds the offset,
    # ending at the live value's address.
    address = base + module_offset
    for offset in offsets:
        data = process.read(address, PTR)
        if not data:
            return None
        address = int.from_bytes(data, "little") + offset
    return address


def format_path(module_name, module_offset, offsets):
    parts = ["%s+0x%X" % (module_name, module_offset)]
    parts += ["0x%X" % o for o in offsets]
    return " -> ".join(parts)


def parse_path(text):
    head, *rest = [p.strip() for p in text.split("->")]
    module_name, _, offset_hex = head.partition("+")
    return module_name, int(offset_hex, 16), [int(o, 16) for o in rest]


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("target", help="pid or process name")
    parser.add_argument("address", nargs="?", help="the address to find paths to (hex)")
    parser.add_argument("--depth", type=int, default=3)
    parser.add_argument("--offset", default="0x400", help="max offset per hop (hex)")
    parser.add_argument("--max", type=int, default=40, help="stop after this many paths")
    parser.add_argument("--resolve", help="a path string to follow and print the address of")
    args = parser.parse_args()

    process = memscope.attach(args.target)
    if not process:
        return 1
    module_list = modules(process.pid)
    try:
        if args.resolve:
            module_name, module_offset, offsets = parse_path(args.resolve)
            address = resolve(process, module_name, module_offset, offsets, module_list)
            if address is None:
                print("could not resolve (module not found or a hop read failed)")
                return 1
            data = process.read(address, 4)
            print("0x%X" % address, "=", int.from_bytes(data, "little") if data else "<unreadable>")
            return 0

        if not args.address:
            print("give an address to scan for, or --resolve a path")
            return 2
        target = int(args.address, 16)
        max_offset = int(args.offset, 16)
        print("scanning for static pointer paths to 0x%X (depth %d, max offset 0x%X)..."
              % (target, args.depth, max_offset))
        results, pmap = find_paths(process, target, args.depth, max_offset, args.max)
        print("mapped %d pointers; found %d path(s)\n" % (len(pmap.values), len(results)))
        for module_name, module_offset, offsets in results:
            address = resolve(process, module_name, module_offset, offsets, module_list)
            ok = "ok" if address == target else "-> 0x%X" % address if address else "stale"
            print("  %s   [%s]" % (format_path(module_name, module_offset, offsets), ok))
        if not results:
            print("  none. Widen --depth or --offset, or the value may not be reached from a")
            print("  module's static data at all.")
        return 0
    finally:
        process.close()


if __name__ == "__main__":
    sys.exit(main())
