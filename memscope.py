"""
MemScope -- a small, general memory scanner for 64-bit Windows processes.

It reads and searches the live memory of any process you have the rights to open, and
narrows a set of candidate addresses the way Cheat Engine or scanmem do: scan for a value,
let it change, scan again for what changed, and repeat until one address is left. Nothing
here is specific to any one program.

This is a debugging and reverse-engineering tool. Reading another process's memory needs the
right to open it: a normal program you started is fine, but something running at a higher
integrity level (many games, anything "as administrator") needs this run from an elevated
terminal, or it fails at OpenProcess with "access denied".

    py memscope.py ps [name]                 list processes, optionally filtered by name
    py memscope.py read <pid> <addr> [opts]  read a value at an address
    py memscope.py dump <pid> <addr> <len>   hex dump around an address
    py memscope.py scan <pid|name>           attach and open the interactive scanner

Inside the scanner (one process, state kept between commands):

    scan 100            addresses currently holding the value 100
    scan                snapshot everything, to narrow by how it changes later
    next 120            of the candidates, those now holding 120
    next up|down|same|changed         narrow by how each candidate moved
    list [n]            show candidates and their current values
    type float          int8/16/32/64, uint*, float, double  (resets the scan)
    write <addr> <v>    write one address (asks first)
    freeze <addr> <v>   keep writing one address every tick until you stop
    pscan <addr>        find a static pointer path to an address that moves (see ptrscan.py)
    reset               throw the candidates away and start over
    quit
"""

import argparse
import ctypes
import ctypes.wintypes as wt
import re
import struct
import sys
import time

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
ACCESS = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION

MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
WRITABLE = {0x04, 0x08, 0x40, 0x80}              # RW, WRITECOPY, EXEC_RW, EXEC_WRITECOPY
PAGE_GUARD = 0x100
TH32CS_SNAPPROCESS = 0x00000002

# Type name -> (struct format, size in bytes). This is the whole notion of "value" the tool
# has; everything else is bytes.
TYPES = {
    "int8": ("<b", 1), "uint8": ("<B", 1),
    "int16": ("<h", 2), "uint16": ("<H", 2),
    "int32": ("<i", 4), "uint32": ("<I", 4),
    "int64": ("<q", 8), "uint64": ("<Q", 8),
    "float": ("<f", 4), "double": ("<d", 8),
}
ALIASES = {"int": "int32", "uint": "uint32", "long": "int64", "byte": "uint8", "short": "int16"}

MAX_SCAN_BYTES = 3 * 1024 * 1024 * 1024
MAX_HITS = 2_000_000


class MEMORY_BASIC_INFORMATION64(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_ulonglong), ("AllocationBase", ctypes.c_ulonglong),
        ("AllocationProtect", wt.DWORD), ("__alignment1", wt.DWORD),
        ("RegionSize", ctypes.c_ulonglong), ("State", wt.DWORD),
        ("Protect", wt.DWORD), ("Type", wt.DWORD), ("__alignment2", wt.DWORD),
    ]


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD), ("cntUsage", wt.DWORD), ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)), ("th32ModuleID", wt.DWORD),
        ("cntThreads", wt.DWORD), ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase", ctypes.c_long), ("dwFlags", wt.DWORD),
        ("szExeFile", ctypes.c_wchar * 260),
    ]


def processes(needle=""):
    """(pid, name) for every process whose exe name contains `needle`, case-insensitively."""
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == -1:
        raise OSError("CreateToolhelp32Snapshot failed")
    out = []
    entry = PROCESSENTRY32W()
    entry.dwSize = ctypes.sizeof(entry)
    try:
        if not kernel32.Process32FirstW(snapshot, ctypes.byref(entry)):
            return out
        while True:
            if needle.lower() in entry.szExeFile.lower():
                out.append((entry.th32ProcessID, entry.szExeFile))
            if not kernel32.Process32NextW(snapshot, ctypes.byref(entry)):
                break
    finally:
        kernel32.CloseHandle(snapshot)
    return out


class Process:
    def __init__(self, pid, name=""):
        self.pid, self.name = pid, name
        self.handle = kernel32.OpenProcess(ACCESS, False, pid)
        if not self.handle:
            err = ctypes.get_last_error()
            hint = ""
            if err == 5:
                hint = ("\n  Access denied: the target runs at a higher integrity level than "
                        "this shell.\n  Run this from an elevated terminal.")
            raise OSError("OpenProcess(%d) failed, error %d.%s" % (pid, err, hint))

    def close(self):
        if self.handle:
            kernel32.CloseHandle(self.handle)
            self.handle = None

    def regions(self):
        """Committed, writable regions -- where mutable state lives."""
        info = MEMORY_BASIC_INFORMATION64()
        address, limit = 0, 0x7FFFFFFFFFFF
        while address < limit:
            if not kernel32.VirtualQueryEx(self.handle, ctypes.c_void_p(address),
                                           ctypes.byref(info), ctypes.sizeof(info)):
                break
            base, size = info.BaseAddress, info.RegionSize
            if size == 0:
                break
            if (info.State == MEM_COMMIT and info.Protect in WRITABLE
                    and not (info.Protect & PAGE_GUARD)):
                yield base, size
            address = base + size

    def read(self, address, size):
        buf = ctypes.create_string_buffer(size)
        got = ctypes.c_size_t(0)
        if not kernel32.ReadProcessMemory(self.handle, ctypes.c_void_p(address), buf, size,
                                          ctypes.byref(got)):
            return None
        return buf.raw[:got.value]

    def write(self, address, data):
        wrote = ctypes.c_size_t(0)
        ok = kernel32.WriteProcessMemory(self.handle, ctypes.c_void_p(address), data,
                                         len(data), ctypes.byref(wrote))
        return bool(ok) and wrote.value == len(data)


def resolve_type(name):
    name = ALIASES.get(name, name)
    if name not in TYPES:
        raise ValueError("unknown type %r; one of %s" % (name, ", ".join(TYPES)))
    return name


def pack(value, kind):
    fmt, _ = TYPES[kind]
    number = float(value) if kind in ("float", "double") else int(value, 0) if isinstance(value, str) else value
    return struct.pack(fmt, number)


def unpack(data, kind):
    fmt, size = TYPES[kind]
    if len(data) < size:
        return None
    return struct.unpack(fmt, data[:size])[0]


def find_aligned(data, needle, align):
    """Offsets of `needle` in `data` at `align`-byte boundaries."""
    return [m.start() for m in re.finditer(re.escape(needle), data) if m.start() % align == 0]


class Scanner:
    def __init__(self, process):
        self.process = process
        self.kind = "int32"
        self.candidates = None            # {address: last_value} or None before first scan

    # --- scanning -----------------------------------------------------------------------

    def first_scan(self, value):
        needle = pack(value, self.kind)
        _, size = TYPES[self.kind]
        align = size if size in (1, 2, 4, 8) else 4
        found = {}
        scanned = 0
        for base, region in self.process.regions():
            offset = 0
            while offset < region:
                span = min(4 * 1024 * 1024, region - offset)
                data = self.process.read(base + offset, span)
                if data:
                    scanned += len(data)
                    for at in find_aligned(data, needle, align):
                        found[base + offset + at] = unpack(data[at:at + size], self.kind)
                        if len(found) >= MAX_HITS:
                            self.candidates = found
                            return found
                offset += span
            if scanned >= MAX_SCAN_BYTES:
                break
        self.candidates = found
        return found

    def snapshot(self):
        """Record every candidate's current value, for narrowing by movement later."""
        _, size = TYPES[self.kind]
        current = {}
        for base, region in self.process.regions():
            offset = 0
            while offset < region:
                span = min(4 * 1024 * 1024, region - offset)
                data = self.process.read(base + offset, span)
                if data:
                    for at in range(0, len(data) - size + 1, size):
                        value = unpack(data[at:at + size], self.kind)
                        current[base + offset + at] = value
                        if len(current) >= MAX_HITS:
                            break
                offset += span
        self.candidates = current
        return current

    def refresh(self):
        """Re-read the current value at each candidate address."""
        out = {}
        for address in self.candidates:
            _, size = TYPES[self.kind]
            data = self.process.read(address, size)
            if data is not None:
                out[address] = unpack(data, self.kind)
        return out

    def narrow_value(self, value):
        target = unpack(pack(value, self.kind), self.kind)
        now = self.refresh()
        self.candidates = {a: v for a, v in now.items() if v == target}
        return self.candidates

    def narrow_move(self, how):
        before = self.candidates
        now = self.refresh()
        keep = {}
        for address, was in before.items():
            if address not in now:
                continue
            value = now[address]
            if (how == "same" and value == was) or (how == "changed" and value != was) \
                    or (how == "up" and value > was) or (how == "down" and value < was):
                keep[address] = value
        self.candidates = keep
        return keep


def attach(target):
    if target.isdigit():
        matches = [(int(target), "")]
    else:
        matches = processes(target)
    if not matches:
        print("no process matching %r" % target)
        return None
    if len(matches) > 1:
        print("more than one match; pick a pid:")
        for pid, name in matches[:20]:
            print("  %-8d %s" % (pid, name))
        return None
    pid, name = matches[0]
    try:
        return Process(pid, name)
    except OSError as problem:
        print(problem)
        return None


def repl(scanner):
    print("attached to pid %d %s -- type help, or quit"
          % (scanner.process.pid, scanner.process.name))
    frozen = {}
    while True:
        try:
            raw = input("memscope> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not raw:
            for address, (value, kind) in frozen.items():
                scanner.process.write(address, pack(value, kind))
            continue
        parts = raw.split()
        command, rest = parts[0], parts[1:]

        if command in ("quit", "exit", "q"):
            break
        elif command == "help":
            print(__doc__[__doc__.index("Inside the scanner"):])
        elif command == "type":
            try:
                scanner.kind = resolve_type(rest[0])
                scanner.candidates = None
                print("type is %s; scan reset" % scanner.kind)
            except (IndexError, ValueError) as problem:
                print(problem)
        elif command == "scan":
            if rest:
                found = scanner.first_scan(rest[0])
                print("%d addresses hold %s" % (len(found), rest[0]))
            else:
                print("snapshotting memory to narrow by movement...")
                found = scanner.snapshot()
                print("%d values recorded; change the value in the program, then `next up`, "
                      "`next down`, `next changed` or `next same`" % len(found))
        elif command == "next":
            if scanner.candidates is None:
                print("scan first")
            elif not rest:
                print("next <value> | up | down | same | changed")
            elif rest[0] in ("up", "down", "same", "changed"):
                kept = scanner.narrow_move(rest[0])
                print("%d left" % len(kept))
            else:
                kept = scanner.narrow_value(rest[0])
                print("%d left" % len(kept))
        elif command == "list":
            if not scanner.candidates:
                print("no candidates")
            else:
                limit = int(rest[0]) if rest else 20
                current = scanner.refresh()
                for address in list(scanner.candidates)[:limit]:
                    print("  0x%X = %s" % (address, current.get(address)))
                if len(scanner.candidates) > limit:
                    print("  ... %d more" % (len(scanner.candidates) - limit))
        elif command == "write":
            if len(rest) < 2:
                print("write <addr> <value>")
                continue
            address = int(rest[0], 16)
            before = unpack(scanner.process.read(address, TYPES[scanner.kind][1]) or b"", scanner.kind)
            answer = input("  0x%X is %s, write %s? [y/N] " % (address, before, rest[1]))
            if answer.strip().lower() == "y":
                ok = scanner.process.write(address, pack(rest[1], scanner.kind))
                print("  written" if ok else "  write failed")
        elif command == "freeze":
            if len(rest) < 2:
                print("freeze <addr> <value>   (blank line re-applies all freezes; `unfreeze` clears)")
                continue
            address = int(rest[0], 16)
            frozen[address] = (rest[1], scanner.kind)
            scanner.process.write(address, pack(rest[1], scanner.kind))
            print("  freezing 0x%X at %s; press Enter to re-apply, `unfreeze` to stop" % (address, rest[1]))
        elif command == "unfreeze":
            frozen.clear()
            print("  all freezes cleared")
        elif command == "pscan":
            if not rest:
                print("pscan <addr> [depth] [max_offset_hex]  -- find static pointer paths")
                continue
            try:
                import ptrscan
            except ImportError:
                print("ptrscan.py not found next to memscope.py")
                continue
            target = int(rest[0], 16)
            depth = int(rest[1]) if len(rest) > 1 else 3
            max_offset = int(rest[2], 16) if len(rest) > 2 else 0x400
            print("scanning for static pointer paths (depth %d, offset 0x%X)..."
                  % (depth, max_offset))
            results, pmap = ptrscan.find_paths(scanner.process, target, depth, max_offset, 40)
            module_list = ptrscan.modules(scanner.process.pid)
            print("mapped %d pointers, %d path(s):" % (len(pmap.values), len(results)))
            for module_name, module_offset, offsets in results:
                addr = ptrscan.resolve(scanner.process, module_name, module_offset, offsets, module_list)
                ok = "ok" if addr == target else "stale"
                print("  %s   [%s]" % (ptrscan.format_path(module_name, module_offset, offsets), ok))
        elif command == "reset":
            scanner.candidates = None
            print("candidates cleared")
        else:
            print("unknown command %r; type help" % command)


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("ps")
    p.add_argument("name", nargs="?", default="")

    p = sub.add_parser("read")
    p.add_argument("pid", type=int)
    p.add_argument("address")
    p.add_argument("--type", default="int32")
    p.add_argument("--count", type=int, default=1)

    p = sub.add_parser("dump")
    p.add_argument("pid", type=int)
    p.add_argument("address")
    p.add_argument("length", type=int, nargs="?", default=64)

    p = sub.add_parser("scan")
    p.add_argument("target", help="pid or process name")

    args = parser.parse_args()

    if args.command == "ps":
        for pid, name in sorted(processes(args.name), key=lambda x: x[1].lower()):
            print("  %-8d %s" % (pid, name))
        return 0

    if args.command == "read":
        kind = resolve_type(args.type)
        proc = attach(str(args.pid))
        if not proc:
            return 1
        _, size = TYPES[kind]
        address = int(args.address, 16)
        for i in range(args.count):
            data = proc.read(address + i * size, size)
            print("  0x%X = %s" % (address + i * size, unpack(data, kind) if data else "<unreadable>"))
        proc.close()
        return 0

    if args.command == "dump":
        proc = attach(str(args.pid))
        if not proc:
            return 1
        address = int(args.address, 16)
        data = proc.read(address, args.length) or b""
        for i in range(0, len(data), 16):
            chunk = data[i:i + 16]
            hexed = " ".join("%02x" % b for b in chunk)
            text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            print("  0x%X  %-47s  %s" % (address + i, hexed, text))
        proc.close()
        return 0

    if args.command == "scan":
        proc = attach(args.target)
        if not proc:
            return 1
        try:
            repl(Scanner(proc))
        finally:
            proc.close()
        return 0

    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
