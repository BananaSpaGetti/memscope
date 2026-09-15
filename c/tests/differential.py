"""
differential.py -- runs MemScope's Python implementation and its C port on the same inputs and
diffs their output byte for byte, the way every task in .plans/port-to-c-memscope.md is
verified: the Python is the oracle, not the C's own tests.

Covers: `ps` with and without a name filter; `read` across every type and every alias and
several counts, an unknown `--type`, an unreadable address, a malformed address, an address
padded with a leading space, a trailing space, a tab and a carriage return, and a non-numeric
`--count`; `dump` at several lengths and boundary addresses, an unreadable address, a malformed
address and a non-numeric length; a scripted REPL session exercising type, scan (an exact
match, leading-zero decimal literals, a float scan of a hex string, and a literal above
2**64), next same/changed, list (including an enormous count), freeze (an unpackable literal,
an out-of-range value, and a negative value into an unsigned type), unfreeze, pscan (a bad
depth and a bad max offset), a bad command, reset and quit; `ptrscan` with no address (exit
2), with no arguments at all, with `--depth 1` and `--depth 2`, with a bad `--depth`, `--max`
and `--offset`, and a `--resolve` round trip in both directions; and `--help`/`-h` at the top
level and for every memscope subcommand and for ptrscan, plus memscope invoked with no
subcommand at all.

`ps` lists the live machine's process table, which can change between the two invocations (a
process can start or exit in between), so that one case is compared by the *intersection* of
pids seen in both listings, asserting none of them disagrees on name, rather than requiring
identical listings. Every other case here runs against one purpose-built target process
(tests/target.c) that this harness compiles, starts and stops itself -- never a game, never a
system process -- so its output is otherwise fully deterministic between the two runs.

Every comparison captures stdout, stderr and the exit code separately, rather than merging the
two streams: an implementation that sends the same class of error to a different stream than
the other is a real divergence, and merging them would hide it. Every comparison also asserts
that neither implementation's output ever names this machine's absolute path or its owner --
the standing guard against the kind of traceback-shaped leak memscope.py and ptrscan.py used
to produce before their fixes (see their own module docstrings for the specific defects).

Run: py MemScope/c/tests/differential.py
"""
import queue
import subprocess
import sys
import threading
from pathlib import Path

HERE = Path(__file__).resolve().parent           # MemScope/c/tests
C_DIR = HERE.parent                              # MemScope/c
MEMSCOPE_DIR = C_DIR.parent                       # MemScope

PYTHON = sys.executable
MEMSCOPE_PY = MEMSCOPE_DIR / "memscope.py"
PTRSCAN_PY = MEMSCOPE_DIR / "ptrscan.py"
MEMSCOPE_EXE = C_DIR / "memscope.exe"
PTRSCAN_EXE = C_DIR / "ptrscan.exe"
TARGET_SRC = HERE / "target.c"

TIMEOUT = 15  # seconds; every subprocess call in this harness is bounded by this.

# "C:\Users" is a generic Windows path prefix, not personal, and safe to write here. The
# machine owner's name must not appear as a literal in this file -- it ships inside the
# public zip (see the project's CLAUDE.md on personal data), and a literal name here would
# itself be the leak this guard exists to catch -- so it is read off the running machine's
# own home directory at import time instead of hardcoded.
def _leak_strings():
    """Strings that must never appear in either implementation's output: the generic Windows
    user-path prefix, and this machine's own home directory name. A traceback-shaped defect
    (see ptrscan.py's --offset, fixed by this plan) leaks exactly these -- this is the
    standing guard against a future one shipping."""
    strings = ["C:\\Users"]
    home_name = Path.home().name
    if home_name:
        strings.append(home_name)
    return tuple(strings)


LEAK_STRINGS = _leak_strings()

mismatches = []  # (label, detail) pairs, printed again in the summary at the end


def record(label, detail):
    mismatches.append((label, detail))
    print("MISMATCH: %s" % label)
    print(detail)


def check_leaks(cmd, stream_name, text):
    """Records a mismatch if `text` (one stream of one subprocess run) names this machine's
    path or its owner -- see LEAK_STRINGS."""
    for leak in LEAK_STRINGS:
        if leak in text:
            record("path leak in %s of: %s" % (stream_name, " ".join(str(c) for c in cmd)),
                   "found %r in:\n%s" % (leak, text))


def run(cmd, input_text=None, timeout=TIMEOUT):
    """Runs `cmd` (a list, no shell) and returns (stdout, stderr, returncode), captured
    separately: the C's argument errors mostly go to stderr, the Python's mostly go to
    stdout, and a harness that merges the two streams cannot see an implementation that sends
    the same class of error to a different stream than the other. Also runs the path-leak
    guard on both streams of every call this harness makes, python and C alike."""
    proc = subprocess.run(cmd, input=input_text, capture_output=True, text=True,
                           timeout=timeout)
    check_leaks(cmd, "stdout", proc.stdout)
    check_leaks(cmd, "stderr", proc.stderr)
    return proc.stdout, proc.stderr, proc.returncode


def first_diff(a, b):
    """The first line at which `a` and `b` differ, formatted for a mismatch report."""
    a_lines = a.splitlines()
    b_lines = b.splitlines()
    for i in range(max(len(a_lines), len(b_lines))):
        la = a_lines[i] if i < len(a_lines) else "<missing>"
        lb = b_lines[i] if i < len(b_lines) else "<missing>"
        if la != lb:
            return "  line %d:\n    python: %r\n    c:      %r" % (i, la, lb)
    return "  (equal length and content up to the point compared)"


def compare(label, py_cmd, c_cmd, input_text=None):
    """Runs both implementations and compares stdout, stderr and exit code, each separately.
    Records and reports the first differing line of stdout and of stderr on a mismatch, but
    never raises -- every case in this harness runs regardless of earlier mismatches, so one
    run reports the complete list."""
    py_out, py_err, py_code = run(py_cmd, input_text)
    c_out, c_err, c_code = run(c_cmd, input_text)
    if py_out == c_out and py_err == c_err and py_code == c_code:
        print("ok  %s" % label)
        return True
    detail = "  stdout:\n" + first_diff(py_out, c_out)
    detail += "\n  stderr:\n" + first_diff(py_err, c_err)
    if py_code != c_code:
        detail += "\n  exit code: python=%d c=%d" % (py_code, c_code)
    record(label, detail)
    return False


def py_memscope(*args):
    return [PYTHON, str(MEMSCOPE_PY)] + list(args)


def c_memscope(*args):
    return [str(MEMSCOPE_EXE)] + list(args)


def py_ptrscan(*args):
    return [PYTHON, str(PTRSCAN_PY)] + list(args)


def c_ptrscan(*args):
    return [str(PTRSCAN_EXE)] + list(args)


# --- ps ---------------------------------------------------------------------------------- #

def parse_ps(output):
    """{pid: name} from a `ps` listing's "  <pid> <name>" lines."""
    out = {}
    for line in output.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[0].isdigit():
            out[int(parts[0])] = parts[1]
    return out


def compare_ps(label, py_cmd, c_cmd):
    """`ps` lists a live machine: a process can start or exit between the two invocations, so
    this compares the *intersection* of pids seen in both listings, asserting none of them
    disagrees on name, rather than requiring identical listings."""
    py_out, _py_err, py_code = run(py_cmd)
    c_out, _c_err, c_code = run(c_cmd)
    py_procs = parse_ps(py_out)
    c_procs = parse_ps(c_out)
    common = set(py_procs) & set(c_procs)
    disagreeing = [pid for pid in common if py_procs[pid] != c_procs[pid]]
    if py_code != 0 or c_code != 0 or disagreeing:
        detail = ("python exit=%d c exit=%d, %d pid(s) in common, disagreeing: %s"
                  % (py_code, c_code, len(common), disagreeing[:5]))
        record(label, detail)
        return False
    print("ok  %s (%d pids in common, 0 disagreeing)" % (label, len(common)))
    return True


# --- the target process -------------------------------------------------------------------- #

def compile_target(exe_path):
    """Builds the target process this harness attaches to.

    Every failure path here reports and exits rather than raising. An uncaught exception would
    print a traceback carrying this machine's absolute paths, which is the exact defect class
    this harness's own leak guard exists to catch -- and this file ships in the public zip."""
    try:
        result = subprocess.run(["gcc", "-std=c11", "-Wall", "-Wextra", "-O2", "-o",
                                  str(exe_path), str(TARGET_SRC), "-lkernel32"],
                                 capture_output=True, text=True, timeout=60)
    except FileNotFoundError:
        print("gcc is not on PATH, so tests/target.c cannot be built.", file=sys.stderr)
        print("Put your C toolchain's bin directory on PATH and run this again.",
              file=sys.stderr)
        raise SystemExit(2)
    except subprocess.TimeoutExpired:
        print("gcc did not finish within 60 seconds building tests/target.c.", file=sys.stderr)
        raise SystemExit(2)
    if result.returncode != 0:
        print("could not compile tests/target.c:", file=sys.stderr)
        sys.stderr.write(result.stdout)
        sys.stderr.write(result.stderr)
        raise SystemExit(2)


def start_target(exe_path):
    """Starts the target with --hold and reads its startup lines up to READY, off a background
    thread so a hang cannot block this harness forever -- `thread.join(timeout=...)` bounds the
    wait, rather than an unbounded blocking read. Returns (Popen, dict of name -> int), where
    the value is the pid for "PID" and an address for everything else."""
    proc = subprocess.Popen([str(exe_path), "--hold"], stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True)
    lines = queue.Queue()

    def pump():
        for line in proc.stdout:
            lines.put(line)
            if line.strip() == "READY":
                return

    thread = threading.Thread(target=pump, daemon=True)
    thread.start()
    thread.join(timeout=10)

    info = {}
    while not lines.empty():
        parts = lines.get().strip().split()
        if len(parts) == 2:
            name, value = parts
            info[name] = int(value, 0)
    if "PID" not in info:
        stop_target(proc)
        raise RuntimeError("target did not report a PID before READY within the timeout")
    return proc, info


def stop_target(proc):
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except Exception:
        proc.kill()


# --- test groups --------------------------------------------------------------------------- #

# (name as typed at the CLI, canonical type it resolves to) -- every type plus every alias.
TYPES_AND_ALIASES = [
    ("int8", "int8"), ("uint8", "uint8"), ("int16", "int16"), ("uint16", "uint16"),
    ("int32", "int32"), ("uint32", "uint32"), ("int64", "int64"), ("uint64", "uint64"),
    ("float", "float"), ("double", "double"),
    ("int", "int32"), ("uint", "uint32"), ("long", "int64"), ("byte", "uint8"),
    ("short", "int16"),
]


def test_ps():
    compare_ps("ps (no filter)", py_memscope("ps"), c_memscope("ps"))
    compare_ps("ps (name filter 'target')", py_memscope("ps", "target"),
                c_memscope("ps", "target"))


def test_read(pid, addrs):
    for alias, canonical in TYPES_AND_ALIASES:
        addr_hex = "0x%X" % addrs[canonical]
        for count in (1, 3):
            compare("read --type %s --count %d" % (alias, count),
                    py_memscope("read", str(pid), addr_hex, "--type", alias, "--count",
                                str(count)),
                    c_memscope("read", str(pid), addr_hex, "--type", alias, "--count",
                               str(count)))

    # An unknown type -- task 16 fixed the Python's traceback here; confirm it still matches.
    compare("read --type nope",
            py_memscope("read", str(pid), "0x%X" % addrs["int32"], "--type", "nope"),
            c_memscope("read", str(pid), "0x%X" % addrs["int32"], "--type", "nope"))

    # An unreadable address -- syntactically fine hex, but not mapped in this process.
    compare("read unreadable address",
            py_memscope("read", str(pid), "0x1"),
            c_memscope("read", str(pid), "0x1"))

    # A malformed address -- rejected cleanly by both, no traceback and no leaked path.
    compare("read malformed address",
            py_memscope("read", str(pid), "zzz"),
            c_memscope("read", str(pid), "zzz"))

    # A non-numeric --count.
    compare("read --count abc",
            py_memscope("read", str(pid), "0x%X" % addrs["int32"], "--count", "abc"),
            c_memscope("read", str(pid), "0x%X" % addrs["int32"], "--count", "abc"))

    # Addresses padded with a leading space, a trailing space, a tab and a carriage return --
    # each is one argv element (no shell involved), so the whitespace survives intact.
    addr_hex = "0x%X" % addrs["int32"]
    for note, padded in [
        ("a leading space", " " + addr_hex),
        ("a trailing space", addr_hex + " "),
        ("a trailing tab", addr_hex + "\t"),
        ("a trailing carriage return", addr_hex + "\r"),
    ]:
        compare("read address padded with %s" % note,
                py_memscope("read", str(pid), padded),
                c_memscope("read", str(pid), padded))


def test_dump(pid, addrs):
    for length in (0, 1, 15, 16, 17, 64, 100):
        for name in ("double", "scan_target"):
            compare("dump length=%d at %s" % (length, name),
                    py_memscope("dump", str(pid), "0x%X" % addrs[name], str(length)),
                    c_memscope("dump", str(pid), "0x%X" % addrs[name], str(length)))

    compare("dump unreadable address",
            py_memscope("dump", str(pid), "0x1"),
            c_memscope("dump", str(pid), "0x1"))

    # A malformed address -- rejected cleanly by both, no traceback and no leaked path.
    compare("dump malformed address",
            py_memscope("dump", str(pid), "zzz"),
            c_memscope("dump", str(pid), "zzz"))

    # A non-numeric length.
    compare("dump length=abc",
            py_memscope("dump", str(pid), "0x%X" % addrs["int32"], "abc"),
            c_memscope("dump", str(pid), "0x%X" % addrs["int32"], "abc"))


def test_repl(pid, addrs):
    addr = "0x%X" % addrs["uint8"]
    leaf = "0x%X" % addrs["leaf"]
    script = "\n".join([
        "type int32",
        "scan 74123698",              # g_scan_target's exact value -- an exact first scan
        "next same",                  # nothing has changed since the scan: all kept
        "next changed",               # still nothing has changed: none kept
        "list",
        "scan 74123698",              # re-scan so a non-empty candidate set exists below
        "list 99999999999999999999999999999999999999",  # an enormous count -- must not raise
        # The 2**63..2**64 window: a magnitude that fits uint64_t but not int64_t used to
        # flip sign on the way into the counter, so this listed candidates instead of none
        # and reported a tally of 7335632962598440506.
        "list -11111111111111111111",
        "list 11111111111111111111",
        # Long literals: CPython's 4300-digit ceiling applies to these decimal conversions,
        # and the tally printed for a negative count is arbitrary-precision arithmetic on
        # the Python side -- an internal 192-byte buffer here silently dropped its
        # HIGH-order digits and printed a smaller number as if it were the answer.
        "list -" + "1" * 200,
        "list " + "1" * 4300,
        "list " + "1" * 4301,
        # CPython truncates the literal it quotes back, at 200 characters of repr.
        "list " + "1" * 300 + "z",
        # A literal above 2**64 parses fine as a Python int but overflows struct.pack for
        # int32; the type name must be reported in the error, not the struct format char 'i'.
        "scan 99999999999999999999999999999999999999",
        "scan 0123",                  # a leading-zero decimal literal -- invalid for int(x, 0)
        "scan 010",                   # same, another leading-zero form
        "type float",                 # resets the scan
        "scan 0x10",                  # a float scan of a hex string -- float() rejects it cleanly
        "type uint8",                 # resets the scan; leaves the frozen set alone
        "freeze %s zzz" % addr,       # unpackable literal -- never recorded
        "freeze %s 99999" % addr,     # out of range for uint8 -- never recorded
        "freeze %s -1" % addr,        # negative into an unsigned type -- never recorded
        "unfreeze",
        "pscan %s abc" % addr,        # a bad depth -- non-numeric, must not traceback
        "pscan %s 2 zzz" % addr,      # a bad max offset -- non-hex, must not traceback
        # Found by the second review. An address wider than 64 bits must be reported, never
        # quietly retargeted -- an earlier fix made the shared parser saturate, so `freeze`
        # and `write` acted on 0x7FFFFFFFFFFFFFFF instead of what was typed.
        "freeze FFFFFFFFFFFFFFFFFF 5",
        "write FFFFFFFFFFFFFFFFFF 5",
        "pscan FFFFFFFFFFFFFFFFFF",
        "freeze %s -0" % addr,        # -0 is zero, and packs into an unsigned type
        # Switch back to the deterministic scan target (a specific, chosen-to-be-rare
        # int32 value -- a common byte value like uint8's would hit unrelated bytes
        # elsewhere in a live process and vary between two separately-launched runs).
        # Without a live candidate set, the huge-negative-count case below
        # short-circuits on "no candidates" before it ever reaches the count argument
        # at all, exercising nothing.
        "type int32",
        "scan 74123698",
        "list -99999999999999999999999999",  # a huge negative count -- no signed overflow
        "pscan %s 5000000000" % addr,  # a depth wider than a 32-bit long
        # A fourth review round found an earlier fix's own regression: a negative max_offset
        # was passed straight through as a two's-complement bit pattern to the unsigned range
        # search, producing 40 false-positive paths where Python's real (non-wrapping)
        # `target - max_offset` arithmetic always finds none. `leaf` has a real static path
        # (see test_ptrscan's --resolve round trip) so a positive offset here is a genuine
        # search, not just a parser check.
        "pscan %s 3 -10" % leaf,
        "pscan %s 3 0x400" % leaf,
        "bogus_command_xyz",          # an unknown command: reported, session continues
        "reset",
        "quit",
        "",
    ])
    compare("REPL scripted session",
            py_memscope("scan", str(pid)),
            c_memscope("scan", str(pid)),
            input_text=script)


def extract_path(ptrscan_output):
    """The first formatted path in a `ptrscan` result listing ("  MODULE+0xOFF -> ...   [ok]"),
    or None if there is none to extract."""
    for line in ptrscan_output.splitlines():
        if "+0x" in line and "   [" in line:
            return line.split("   [")[0].strip()
    return None


def test_ptrscan(pid, addrs):
    leaf = "0x%X" % addrs["leaf"]

    compare("ptrscan no address (exit 2)", py_ptrscan(str(pid)), c_ptrscan(str(pid)))
    compare("ptrscan no arguments at all", py_ptrscan(), c_ptrscan())
    compare("ptrscan --depth 1", py_ptrscan(str(pid), leaf, "--depth", "1"),
            c_ptrscan(str(pid), leaf, "--depth", "1"))
    compare("ptrscan --depth 2", py_ptrscan(str(pid), leaf, "--depth", "2"),
            c_ptrscan(str(pid), leaf, "--depth", "2"))

    # A bad --depth, --max and --offset -- the fix at the heart of this plan's last review
    # findings: none of these three may produce a traceback or a leaked path (--offset used
    # to, being converted by hand after argparse and after the process was already attached).
    compare("ptrscan --depth abc", py_ptrscan(str(pid), leaf, "--depth", "abc"),
            c_ptrscan(str(pid), leaf, "--depth", "abc"))
    compare("ptrscan --max abc", py_ptrscan(str(pid), leaf, "--max", "abc"),
            c_ptrscan(str(pid), leaf, "--max", "abc"))
    compare("ptrscan --offset zzz", py_ptrscan(str(pid), leaf, "--offset", "zzz"),
            c_ptrscan(str(pid), leaf, "--offset", "zzz"))

    # --resolve round trip: a path printed by one implementation must resolve in the other.
    # g_root's static pointer chain (see target.c) guarantees --depth 2 finds at least one.
    py_out, _py_err, py_code = run(py_ptrscan(str(pid), leaf, "--depth", "2"))
    c_out, _c_err, c_code = run(c_ptrscan(str(pid), leaf, "--depth", "2"))
    if py_code != 0 or c_code != 0:
        record("ptrscan --resolve round trip",
               "could not get a path to resolve: python exit=%d c exit=%d" % (py_code, c_code))
        return
    py_path = extract_path(py_out)
    c_path = extract_path(c_out)
    if not py_path or not c_path:
        record("ptrscan --resolve round trip", "no path found in either implementation's output")
        return

    compare("ptrscan --resolve a Python-produced path, in both implementations",
            py_ptrscan(str(pid), "--resolve", py_path),
            c_ptrscan(str(pid), "--resolve", py_path))
    compare("ptrscan --resolve a C-produced path, in both implementations",
            py_ptrscan(str(pid), "--resolve", c_path),
            c_ptrscan(str(pid), "--resolve", c_path))


def test_parser_errors(pid, addrs):
    """Every argument-error path both code reviews found. None of these was covered when the
    harness last reported "all cases match" through a fifteen-finding review -- twice."""
    addr = "0x%X" % addrs["int32"]
    pid = str(pid)

    # memscope: argparse's own wording, on stderr, exit 2.
    compare("memscope unknown subcommand", py_memscope("bogus"), c_memscope("bogus"))
    for sub in ("read", "dump"):
        compare("memscope %s bad pid" % sub,
                py_memscope(sub, "abc", "0x10"), c_memscope(sub, "abc", "0x10"))
        compare("memscope %s no arguments" % sub, py_memscope(sub), c_memscope(sub))
        compare("memscope %s missing address" % sub,
                py_memscope(sub, pid), c_memscope(sub, pid))
        compare("memscope %s extra argument" % sub,
                py_memscope(sub, pid, addr, "extra"), c_memscope(sub, pid, addr, "extra"))
        # int() has arbitrary precision; ctypes then truncates modulo 2**64 and the line
        # printed names an address that was never touched. No such address exists here.
        compare("memscope %s address above 2**64" % sub,
                py_memscope(sub, pid, "FFFFFFFFFFFFFFFFFF"),
                c_memscope(sub, pid, "FFFFFFFFFFFFFFFFFF"))
    compare("memscope dump negative length",
            py_memscope("dump", pid, addr, "-1"), c_memscope("dump", pid, addr, "-1"))
    # A fourth review round found the same leak class survive a fourth time: a length this
    # large used to reach ctypes.create_string_buffer(size) with `size` too big for the
    # index-sized integer it converts through -- an uncaught OverflowError, traceback and
    # this file's own path in it. One byte past the cap, and exactly at it, both now reject
    # cleanly before ever attaching. (An astronomically huge literal, wider than int64_t,
    # still diverges -- the C saturates to LLONG_MAX where Python keeps the exact digits
    # typed; that gap is pre-existing and out of scope here, see the plan log.)
    compare("memscope dump length one byte past the cap",
            py_memscope("dump", pid, addr, "3221225473"),
            c_memscope("dump", pid, addr, "3221225473"))
    compare("memscope dump length exactly at the cap",
            py_memscope("dump", pid, addr, "3221225472"),
            c_memscope("dump", pid, addr, "3221225472"))
    # read's --count has no single allocation to overflow, just a loop that would run for a
    # duration nobody typing a decimal literal this size intended -- same bound, same review
    # round, same reasoning as dump's length just above.
    compare("memscope read count one past the cap",
            py_memscope("read", pid, addr, "--count", "2000001"),
            c_memscope("read", pid, addr, "--count", "2000001"))

    # ptrscan: an option given with no value, a bad address, a bad path, a negative offset,
    # and numbers too wide for the 32-bit long the C used to convert them through.
    for opt in ("--depth", "--offset", "--max", "--resolve"):
        compare("ptrscan %s with no value" % opt,
                py_ptrscan(pid, opt), c_ptrscan(pid, opt))
    compare("ptrscan malformed address", py_ptrscan(pid, "zzz"), c_ptrscan(pid, "zzz"))
    compare("ptrscan --resolve garbage",
            py_ptrscan(pid, "--resolve", "garbage"), c_ptrscan(pid, "--resolve", "garbage"))
    compare("ptrscan --offset -1",
            py_ptrscan(pid, addr, "--offset", "-1", "--depth", "1", "--max", "3"),
            c_ptrscan(pid, addr, "--offset", "-1", "--depth", "1", "--max", "3"))
    # Each of these passes its own flag exactly once -- an earlier version passed --max
    # twice in the --max case ("--max 5000000000 --max 3"), and argparse's own last-flag-
    # wins semantics silently discarded the oversized value before either implementation
    # ever saw it, so this case passed without ever exercising the fix it was meant to cover.
    compare("ptrscan --depth above a 32-bit long",
            py_ptrscan(pid, addr, "--depth", "5000000000", "--max", "3"),
            c_ptrscan(pid, addr, "--depth", "5000000000", "--max", "3"))
    compare("ptrscan --max above a 32-bit long",
            py_ptrscan(pid, addr, "--max", "5000000000", "--depth", "1"),
            c_ptrscan(pid, addr, "--max", "5000000000", "--depth", "1"))

    # A token that starts with '-', is not a known flag, and does not look like a
    # negative number is what argparse calls unrecognized -- collected for the
    # top-level error rather than ever being tried against a positional slot.
    for sub in ("read", "dump"):
        compare("memscope %s unrecognized flag" % sub,
                py_memscope(sub, "--bogus", pid, addr), c_memscope(sub, "--bogus", pid, addr))
    compare("memscope read --count with no value",
            py_memscope("read", pid, "--count"), c_memscope("read", pid, "--count"))
    compare("memscope read --type with no value",
            py_memscope("read", pid, "--type"), c_memscope("read", pid, "--type"))
    # A negative address only reaches memscope.py's read/dump at all via argparse's `--`
    # end-of-options separator, which this hand-rolled C parser does not implement -- so
    # this defense-in-depth fix (finding #9) is verified at the unit level instead of
    # here; see MemScope/c/tests/test_util.c and the direct repl_address()/range checks.
    # A length wide enough to overflow the 32-bit `long` strtol used to parse through --
    # the error must name the digits the user typed, not a saturated LONG_MIN.
    compare("memscope dump length overflows a 32-bit long",
            py_memscope("dump", pid, addr, "-5000000000"),
            c_memscope("dump", pid, addr, "-5000000000"))
    # A single argv token long enough to test whether an error message truncates it.
    long_token = "a" * 300
    compare("memscope unknown subcommand, a long token",
            py_memscope(long_token), c_memscope(long_token))
    # ptrscan's address has the same arbitrary-precision-vs-64-bit gap read/dump's did,
    # and the same negative-address gap besides.
    compare("ptrscan address above 2**64",
            py_ptrscan(pid, "FFFFFFFFFFFFFFFFFF"), c_ptrscan(pid, "FFFFFFFFFFFFFFFFFF"))
    # A --resolve path with a negative hop: a legitimate way to walk backward from a
    # dereferenced pointer, which an earlier fix's blanket negative-hex rejection broke.
    compare("ptrscan --resolve with a negative hop",
            py_ptrscan(pid, "--resolve", "kernel32.dll+0x10 -> -0x20"),
            c_ptrscan(pid, "--resolve", "kernel32.dll+0x10 -> -0x20"))
    # ptrscan's own depth must actually widen past a 32-bit long, not just print a wider
    # banner while still truncating the value the search itself receives.
    compare("ptrscan --depth above a 32-bit long, checked against a real search",
            py_ptrscan(pid, addr, "--depth", "5000000000", "--max", "5"),
            c_ptrscan(pid, addr, "--depth", "5000000000", "--max", "5"))
    # A fourth review round found main_ptrscan.c's argument loop had never received the
    # unrecognized-flag check main_memscope.c's cmd_read/cmd_dump got -- a plan-log claim
    # that both binaries had it was wrong. Without this, --bogus was swallowed into the
    # address slot instead of being reported.
    compare("ptrscan unrecognized flag", py_ptrscan(pid, "--bogus"), c_ptrscan(pid, "--bogus"))
    compare("ptrscan unrecognized flag with an address",
            py_ptrscan(pid, addr, "--bogus"), c_ptrscan(pid, addr, "--bogus"))
    compare("ptrscan extra positional argument",
            py_ptrscan(pid, addr, "extra"), c_ptrscan(pid, addr, "extra"))

    # --- integer literal LENGTH ----------------------------------------------------------
    #
    # Every case above uses a short literal, and that is exactly how a family of defects
    # stayed hidden: three separate parsers here each had a fixed buffer, and a literal
    # longer than it was rejected as invalid where Python parses it and answers something
    # else entirely. Python's int has no length bound at all below CPython's own 4300-digit
    # ceiling on DECIMAL conversions -- and base 16 is exempt even from that.
    #
    # Length is swept rather than sampled: the boundaries are the uint64 ceiling, the int64
    # ceiling (where a magnitude that fits unsigned flips sign on the way into a signed
    # counter), the buffers, and 4300.
    padded_address = "0x" + "0" * 200 + "1"
    compare("memscope read a 200-zero-padded address",
            py_memscope("read", pid, padded_address),
            c_memscope("read", pid, padded_address))
    compare("ptrscan a 200-zero-padded address",
            py_ptrscan(pid, padded_address), c_ptrscan(pid, padded_address))

    for digits in (17, 20, 128, 200):
        big = "1" * digits
        # dump's length error interpolates the value with "%d" on the Python side, so a
        # literal too large for int64_t must be echoed as typed rather than as the
        # saturated parse -- this reported 9223372036854775807 back at the user.
        compare("memscope dump length of %d digits" % digits,
                py_memscope("dump", pid, addr, big), c_memscope("dump", pid, addr, big))
        compare("memscope dump a negative length of %d digits" % digits,
                py_memscope("dump", pid, addr, "-" + big),
                c_memscope("dump", pid, addr, "-" + big))
        compare("memscope read --count of %d digits" % digits,
                py_memscope("read", "--count", big, pid, addr),
                c_memscope("read", "--count", big, pid, addr))

    # A hex literal has no digit ceiling in Python, so a long one is an out-of-range value
    # rather than an invalid one -- a distinction the C used to lose.
    long_hex = "0x" + "f" * 200
    compare("memscope read an address of 200 hex digits",
            py_memscope("read", pid, long_hex), c_memscope("read", pid, long_hex))
    compare("ptrscan --resolve with a 200-digit hop offset",
            py_ptrscan(pid, addr, "--resolve", "a+" + long_hex),
            c_ptrscan(pid, addr, "--resolve", "a+" + long_hex))



def test_help_and_usage():
    """--help and -h at the top level and for every subcommand, on both binaries, plus
    memscope invoked with no subcommand at all and ptrscan invoked with no arguments at all --
    none of this needs a live target."""
    for flag in ("--help", "-h"):
        compare("memscope %s" % flag, py_memscope(flag), c_memscope(flag))
        compare("ptrscan %s" % flag, py_ptrscan(flag), c_ptrscan(flag))
        for sub in ("ps", "read", "dump", "scan"):
            compare("memscope %s %s" % (sub, flag), py_memscope(sub, flag),
                    c_memscope(sub, flag))

    compare("memscope no subcommand", py_memscope(), c_memscope())


# --- entry point ---------------------------------------------------------------------------- #

def main():
    target_exe = C_DIR / "build" / "tests" / "differential_target.exe"
    target_exe.parent.mkdir(parents=True, exist_ok=True)
    compile_target(target_exe)

    test_help_and_usage()

    proc, addrs = start_target(target_exe)
    try:
        pid = addrs["PID"]
        test_ps()
        test_read(pid, addrs)
        test_dump(pid, addrs)
        test_repl(pid, addrs)
        test_ptrscan(pid, addrs)
        test_parser_errors(pid, addrs)
    finally:
        stop_target(proc)

    print()
    if mismatches:
        print("%d mismatch(es):" % len(mismatches))
        for label, detail in mismatches:
            print("  - %s" % label)
        return 1
    print("all cases match")
    return 0


if __name__ == "__main__":
    sys.exit(main())
