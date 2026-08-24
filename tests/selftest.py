"""
Self-tests for MemScope, covering the parts that a scan of a live process is otherwise the
only way to exercise.

    py tests/selftest.py                 the offline checks only
    py tests/selftest.py --pid 1234      also run the live checks against that process

The offline checks run against a byte-backed fake process, so they need nothing but this
machine: they cover the page arithmetic in `refresh()`, the caps in `PointerMap._build` and
`find_paths`, and the exception types the scanner REPL has to survive. The live checks need
a real pid and prove the same things against real memory, including the pages that will not
read in bulk, which a fake can only simulate.

Live checks read the target and never write to it. Every value they hand to `freeze` and
`write` is one that cannot be packed, so `pack()` raises before `WriteProcessMemory` is
reached. Choosing a 64-bit target matters for the pointer-map checks: `ptrscan` assumes
8-byte pointers, so on a 32-bit process those checks would measure nothing and are skipped.

This ships with MemScope, so anyone who downloads it can check the copy they have rather
than take its behaviour on trust.
"""

import argparse
import ctypes
import importlib.util
import os
import struct
import sys

# The checks live in tests/, the modules they exercise sit one level up.
TOOLS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAGE = 4096


def _load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(TOOLS, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


memscope = _load("memscope")
sys.path.insert(0, TOOLS)
ptrscan = _load("ptrscan")


class Results:
    def __init__(self):
        self.failed = []

    def check(self, name, ok, detail=""):
        print(("  ok    " if ok else "  FAIL  ") + name + (("  " + detail) if detail else ""))
        if not ok:
            self.failed.append(name)

    def note(self, text):
        print("        " + text)


def old_refresh(scanner):
    """`refresh()` as it was before page batching: one ReadProcessMemory per candidate.

    Kept verbatim as the oracle. The page-batched version has to agree with it exactly,
    which is the only property that matters -- a faster scanner that reports different
    values is worse than a slow one.
    """
    out = {}
    for address in scanner.candidates:
        _, size = memscope.TYPES[scanner.kind]
        data = scanner.process.read(address, size)
        if data is not None:
            out[address] = memscope.unpack(data, scanner.kind)
    return out


class CountingRead:
    """Wrap `process.read` to see which branch of `refresh()` each candidate took."""

    def __init__(self, process):
        self.process, self.real = process, process.read
        self.bulk = self.fallback = self.failed_bulk = self.bytes = 0

    def __enter__(self):
        def read(address, size):
            data = self.real(address, size)
            self.bytes += len(data) if data else 0
            if size == PAGE:
                self.bulk += 1
                if data is None:
                    self.failed_bulk += 1
            else:
                self.fallback += 1
            return data
        self.process.read = read
        return self

    def __exit__(self, *_):
        self.process.read = self.real


# --- offline: a fake process -------------------------------------------------------------

class FakeProcess:
    """A byte-backed stand-in. `dead_pages` refuse a read the way an uncommitted page does."""

    def __init__(self, base, data, dead_pages=()):
        self.pid, self.name = 0, "fake"
        self.base, self.data = base, bytes(data)
        self.dead = set(dead_pages)

    def regions(self):
        yield self.base, len(self.data)

    def read(self, address, size):
        for page in self.dead:
            if address < page + PAGE and page < address + size:
                return None
        start = address - self.base
        if start < 0 or start >= len(self.data):
            return None
        return self.data[start:start + size]


def offline_checks(results):
    print("\noffline (fake process)")

    base = 0x10000000
    blob = bytes((i * 7 + 3) & 0xFF for i in range(PAGE * 4))
    for kind in ("int8", "int32", "int64", "float", "double"):
        size = memscope.TYPES[kind][1]
        for dead in ((), (base + PAGE,), (base, base + PAGE * 3)):
            scanner = memscope.Scanner(FakeProcess(base, blob, dead))
            scanner.kind = kind
            addresses = []
            for page in range(4):
                edge = base + page * PAGE
                # both sides of every boundary, and the value that hangs over it
                addresses += [edge, edge + 1, edge + PAGE - size,
                              edge + PAGE - size + 1, edge + PAGE - 1]
            addresses += [base + PAGE * 4 - 1, base + PAGE * 4 + 8]      # past the end
            scanner.candidates = {a: 0 for a in sorted(set(addresses))}
            results.check("refresh matches the oracle  %-6s %d dead page(s)" % (kind, len(dead)),
                          scanner.refresh() == old_refresh(scanner))

    scanner = memscope.Scanner(FakeProcess(base, blob))
    scanner.candidates = {a: 0 for a in [base + 8, base + PAGE * 3, base + 16, base + PAGE]}
    results.check("refresh is correct on unsorted candidates",
                  scanner.refresh() == old_refresh(scanner))

    # A region of nothing but plausible pointers, so the cap is certain to be reached.
    pointer_base = 0x20000000
    span = 4 * 1024 * 1024
    slots = span * 3 // 8
    process = FakeProcess(pointer_base, (pointer_base + 64).to_bytes(8, "little") * slots)
    saved = ptrscan.memscope.MAX_HITS
    try:
        ptrscan.memscope.MAX_HITS = 1000
        pmap = ptrscan.PointerMap(process)
        results.check("_build stops at MAX_HITS, not one chunk later",
                      len(pmap.values) == 1000, "mapped %d" % len(pmap.values))
        results.check("_build reports that it truncated", pmap.truncated is True)
        ptrscan.memscope.MAX_HITS = slots * 2
        pmap = ptrscan.PointerMap(process)
        results.check("_build maps everything when under the cap",
                      len(pmap.values) == slots and not pmap.truncated,
                      "mapped %d of %d" % (len(pmap.values), slots))
    finally:
        ptrscan.memscope.MAX_HITS = saved

    # Every slot points at one target and nothing is static, so each holder wants a frontier
    # place; the holder sitting at the target itself is already seen, so it is not dropped.
    target_base = 0x30000000
    target = target_base + 0x800
    count = 500
    process = FakeProcess(target_base, target.to_bytes(8, "little") * count)
    _paths, pmap, dropped = ptrscan.find_paths(process, target, 1, 0x400, 40, max_frontier=10)
    results.check("find_paths counts what the frontier cap refused",
                  dropped == count - 1 - 10, "dropped %d" % dropped)
    results.check("scan_limits names the frontier cap",
                  any("frontier capped" in n for n in ptrscan.scan_limits(pmap, dropped)))
    results.check("scan_limits stays quiet when no cap fired",
                  ptrscan.scan_limits(pmap, 0) == [])

    # The REPL handler has to cover every way a bad argument reaches pack(); struct.error is
    # the one that does not inherit from ValueError.
    caught = []
    for value, kind in [("99999999999", "int32"), ("zzz", "int32"),
                        ("abc", "float"), ("300", "int8")]:
        try:
            memscope.pack(value, kind)
            caught.append(None)
        except (ValueError, IndexError, OSError, struct.error) as problem:
            caught.append(type(problem).__name__)
    results.check("the REPL handler covers every bad pack", all(caught), str(caught))


# --- live: a real process ----------------------------------------------------------------

def is_64bit(pid):
    """False for a process running under WOW64, where ptrscan's 8-byte pointers are wrong."""
    handle = memscope.kernel32.OpenProcess(0x0400, False, pid)
    if not handle:
        return None
    try:
        wow64 = ctypes.c_int(0)
        if not memscope.kernel32.IsWow64Process(handle, ctypes.byref(wow64)):
            return None
        return not wow64.value
    finally:
        memscope.kernel32.CloseHandle(handle)


def _differs_every_time(scanner, address, tries=8):
    """Re-read one address both ways, back to back, and see whether they ever agree.

    Live memory moves under the reader, so a single old-then-new pass cannot tell a defect
    from the target doing its job -- and a second oracle pass used as a control is too weak,
    because an address that changes and changes back looks stable to it. This is the
    decisive form: a wrong page offset is wrong on every sample, whereas a value that moves
    agrees as soon as two reads land between two of its writes.
    """
    probe = memscope.Scanner(scanner.process)
    probe.kind = scanner.kind
    probe.candidates = {address: 0}
    for _ in range(tries):
        if probe.refresh().get(address) == old_refresh(probe).get(address):
            return False
    return True


def _compare(results, label, scanner):
    """Check the page-batched read against the oracle over the whole candidate set."""
    before = old_refresh(scanner)
    after = scanner.refresh()
    results.check("%s reads the same addresses as the oracle" % label,
                  set(before) == set(after), "%d vs %d" % (len(after), len(before)))
    differ = [a for a in before if a in after and after[a] != before[a]]
    defects = [a for a in differ if _differs_every_time(scanner, a)]
    results.check("%s values match the oracle" % label, not defects,
                  "%d differed once, %d differ on every sample" % (len(differ), len(defects)))
    if differ:
        results.note("%d of %d candidates moved between the two passes" % (len(differ), len(before)))


def live_refresh_checks(results, process, sample):
    scanner = memscope.Scanner(process)
    found, truncated = scanner.snapshot()
    print("\nlive: refresh (%d candidates, truncated=%s)" % (len(found), truncated))
    full = scanner.candidates
    if len(full) > sample:
        step = len(full) // sample
        scanner.candidates = {a: v for i, (a, v) in enumerate(full.items()) if i % step == 0}
    _compare(results, "refresh", scanner)

    scanner.candidates = full
    with CountingRead(process) as counter:
        scanner.refresh()
    results.note("full set: %d bulk page reads for %d candidates, %d fallbacks"
                 % (counter.bulk, len(full), counter.fallback))

    # Candidates chosen to force both fallback branches against real memory: unaligned, and
    # hanging over the end of a page and of a region.
    forced = {}
    for region_base, size in list(process.regions())[:400]:
        for address in (region_base + 1, region_base + PAGE - 3,
                        region_base + size - 2, region_base + size + 8):
            forced[address] = 0
    scanner.candidates = dict(sorted(forced.items()))
    print("\nlive: forced fallback (%d edge candidates)" % len(forced))
    with CountingRead(process) as counter:
        scanner.refresh()
    results.check("the fallback path actually fired", counter.fallback > 0,
                  "%d fallbacks, %d bulk reads (%d unreadable)"
                  % (counter.fallback, counter.bulk, counter.failed_bulk))
    _compare(results, "edge candidates", scanner)


def _inner_break_build(pmap):
    """`_build` as it stood before the cap was made to stop the whole walk."""
    regions = list(pmap.process.regions())
    pmap.region_bounds = sorted((base, base + size) for base, size in regions)
    pairs = []
    for base, size in regions:
        offset = 0
        while offset < size:
            span = min(4 * 1024 * 1024, size - offset)
            data = pmap.process.read(base + offset, span)
            if data:
                for at in range(0, len(data) - ptrscan.PTR + 1, ptrscan.PTR):
                    value = int.from_bytes(data[at:at + ptrscan.PTR], "little")
                    if pmap._plausible(value):
                        pairs.append((value, base + offset + at))
                    if len(pairs) >= memscope.MAX_HITS:
                        break
            offset += span
    return pairs


def live_pointer_checks(results, process, cap):
    """The cap has to stop the whole walk, measured against the shape it replaced."""
    print("\nlive: pointer map (MAX_HITS forced to %d)" % cap)
    saved = ptrscan.memscope.MAX_HITS
    ptrscan.memscope.MAX_HITS = memscope.MAX_HITS = cap
    try:
        blank = ptrscan.PointerMap.__new__(ptrscan.PointerMap)
        blank.process, blank.region_bounds = process, []
        with CountingRead(process) as counter_old:
            pairs = _inner_break_build(blank)
        with CountingRead(process) as counter_new:
            pmap = ptrscan.PointerMap(process)
        results.check("_build stops the walk at the cap",
                      pmap.truncated and len(pmap.values) == cap,
                      "%d pairs, truncated=%s" % (len(pmap.values), pmap.truncated))
        results.check("_build stops reading once capped", counter_new.bytes < counter_old.bytes,
                      "%d reads / %.2f MB, was %d reads / %.2f MB"
                      % (counter_new.bulk + counter_new.fallback, counter_new.bytes / 2**20,
                         counter_old.bulk + counter_old.fallback, counter_old.bytes / 2**20))
        results.note("the shape it replaced overshot the cap by %d pairs" % (len(pairs) - cap))

        if pmap.values:
            target = pmap.values[len(pmap.values) // 2]
            _paths, capped, dropped = ptrscan.find_paths(process, target, 2, 0x400, 40,
                                                         max_frontier=50)
            notes = ptrscan.scan_limits(capped, dropped)
            results.check("a bounded pointer scan says it was bounded",
                          bool(notes) and any("capped" in n for n in notes),
                          "dropped=%d" % dropped)
            for note in notes:
                results.note(note.strip())
    finally:
        ptrscan.memscope.MAX_HITS = memscope.MAX_HITS = saved


def live_repl_checks(results, process):
    """A bad argument must not end the session or leave a value that cannot be re-applied."""
    print("\nlive: REPL argument handling")
    scanner = memscope.Scanner(process)
    scanner.first_scan("0")
    kept = len(scanner.candidates or {})
    address = "%X" % next(iter(process.regions()))[0]
    frozen = {}
    escaped = []
    for command, rest in [("freeze", [address, "99999999999"]),   # struct.error, not ValueError
                          ("freeze", [address, "zzz"]),
                          ("write", [address, "zzz"]),
                          ("write", [address, "99999999999"]),
                          ("list", ["zzz"]),
                          ("freeze", ["ZZZZ", "1"])]:
        try:
            memscope._dispatch(scanner, command, rest, frozen)
            escaped.append("%s %s raised nothing" % (command, rest[-1]))
        except (ValueError, IndexError, OSError, struct.error):
            pass
        except BaseException as problem:
            # Anything landing here is what would end a real session; EOFError in
            # particular would mean a value is packed after the prompt, not before it.
            escaped.append("%s %s escaped as %s" % (command, rest[-1], type(problem).__name__))
    results.check("no bad argument escapes the REPL handler", not escaped, "; ".join(escaped))
    results.check("a freeze that cannot pack is not recorded", not frozen, repr(frozen))
    results.check("the candidate set survives", len(scanner.candidates or {}) == kept,
                  "%d of %d" % (len(scanner.candidates or {}), kept))


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pid", help="also run the live checks against this pid or name")
    parser.add_argument("--sample", type=int, default=40000,
                        help="candidates compared against the oracle (default 40000)")
    parser.add_argument("--cap", type=int, default=500000,
                        help="MAX_HITS to force during the live pointer checks")
    args = parser.parse_args()

    results = Results()
    offline_checks(results)

    if args.pid:
        process = memscope.attach(args.pid)
        if not process:
            return 1
        try:
            print("\nattached to pid %d %s" % (process.pid, process.name))
            live_refresh_checks(results, process, args.sample)
            live_repl_checks(results, process)
            if is_64bit(process.pid):
                live_pointer_checks(results, process, args.cap)
            else:
                print("\nlive: pointer map -- skipped, the target is not 64-bit")
                results.note("ptrscan assumes 8-byte pointers, so it would measure nothing")
        finally:
            process.close()
    else:
        print("\nlive checks skipped; pass --pid <pid|name> to run them")

    print()
    if results.failed:
        print("FAILED: " + ", ".join(results.failed))
        return 1
    print("all checks pass")
    return 0


if __name__ == "__main__":
    sys.exit(main())
