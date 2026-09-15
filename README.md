# MemScope

A small, general memory scanner for 64-bit Windows processes, in one file of standard-library
Python. It reads and searches the live memory of any process you have the rights to open, and
narrows a set of candidate addresses the way Cheat Engine or scanmem do -- scan for a value,
let it change, scan again for what changed, until one address is left.

Nothing in it is specific to any one program; it is a debugging and reverse-engineering tool.

There are two implementations: the original, in one file of standard-library Python, and a
native C port in `c/` that builds `memscope.exe` and `ptrscan.exe`. They behave the same --
see "The C port" below for how that is checked.

## Requirements

- Windows, 64-bit.
- To run the Python: Python 3 (`py` on this machine). No third-party packages.
- To run the C build: nothing -- `memscope.exe` and `ptrscan.exe` need no Python installed.
  Building them from source needs a C compiler; see "The C port".
- The right to open the target. A program you started runs at your integrity level and opens
  fine. Something running elevated, or a game with a higher integrity level, needs MemScope
  run from an **elevated terminal**, or `OpenProcess` fails with "access denied".

## Commands

```
py memscope.py ps [name]                 list processes, optionally filtered by name
py memscope.py read <pid> <addr> [opts]  read a value at an address   (--type, --count)
py memscope.py dump <pid> <addr> <len>   hex dump around an address
py memscope.py scan <pid|name>           attach and open the interactive scanner
```

Addresses are hex (`0x14A2B0C8` or `14A2B0C8`).

## The scanner

`scan` attaches to one process and opens a prompt that keeps the candidate set between
commands:

```
scan 100            addresses currently holding the value 100
scan                snapshot everything, to narrow by movement afterwards
next 120            of the candidates, those now holding 120
next up|down|same|changed         narrow by how each candidate moved since last look
list [n]            show candidates and their current values
type float          int8/16/32/64, uint*, float, double  (resets the scan)
write <addr> <v>    write one address (asks first)
freeze <addr> <v>   hold an address at a value; Enter re-applies, unfreeze clears
reset               throw the candidates away
quit
```

The usual loop for a value you can see but whose address you do not know: `scan <value>`,
change it in the program, `next <new value>`, repeat until `list` shows one address. When you
cannot read the number directly, `scan` with no argument snapshots memory and you narrow by
`next up` / `next down` / `next same` / `next changed` as the value moves.

## Types

`int8/16/32/64`, their `uint` forms, `float`, `double`, plus aliases `int`, `uint`, `long`,
`byte`, `short`. Changing type resets the scan, since the byte width changes.

## Notes and limits

- **`scan` with no value is memory-heavy.** It records every aligned slot in every writable
  region; on a large process that is a big dictionary. It is capped at two million entries,
  but on a machine with little free RAM, prefer a valued `scan <n>` first to get a small set,
  then narrow. Check free memory before snapshotting a large game.
- Scanning is 4-byte-aligned for 4-byte types (and to each type's width otherwise), which is
  how compilers place values in practice and keeps the search fast. A value at an unaligned
  offset is missed; that is the standard trade every scanner makes.
- Only committed, writable regions are searched -- that is where mutable state lives.
- Some values move: a garbage-collected runtime re-allocates an object when it changes, so
  an address that held the value becomes stale and a fresh scan finds a different one. When
  narrowing collapses to nothing on such a target, that is why, and the answer is a **pointer
  scan** -- which `ptrscan.py` here does.

## Pointer scanning (`ptrscan.py`)

When the address moves, the stable thing is the *path* to it: a pointer in a module's static
data, whose target plus an offset leads to another pointer, ending at the value. That path
survives restarts. `ptrscan.py` finds one by walking pointers backwards from the target until
the chain reaches a module.

```
py ptrscan.py <pid|name> <addr> [--depth 3] [--offset 0x400] [--max 40]
py ptrscan.py <pid|name> --resolve "game.exe+0x641E80 -> 0x98 -> 0x48"
```

Or, inside the scanner, `pscan <addr>` runs it on the process already attached. Each path is
printed as `module+offset -> offset -> ...` and verified by resolving it back to the address.
It reads every pointer-sized slot in the process once, so it is heavier than a value scan --
start with a small depth and offset, and mind free RAM on a large target.

## The C port

`c/` holds a native C port of both tools, built with a plain `make`:

```
make -C c              builds c/memscope.exe and c/ptrscan.exe
make -C c test          also builds and runs one test executable per file under c/tests/
```

A C compiler (gcc; a Makefile is provided, w64devkit works) must be on `PATH` to build it, but
the resulting `.exe` files need no Python installed to run -- copy them anywhere on a 64-bit
Windows machine. Their command line and output match the Python exactly, including `-h` /
`--help` and every error path -- `c/tests/differential.py` is what checks that; see below.

**The Python remains the reference implementation.** `c/tests/differential.py` runs both
implementations on the same inputs -- process listing, reads and dumps across every type,
scripted scanner sessions, pointer scans, `-h`/`--help`, and every error path -- across 116
cases, and compares stdout, stderr and exit code separately for each. It also fails the run if
either implementation ever prints a path from the machine it runs on. That is why the Python
is still here even though the C build needs it for nothing at runtime: without it, the diffs
that keep the port honest would have nothing to compare against.

Diffing the two found twelve defects in the already-published Python, since a second independent
implementation surfaces things a single one's own tests do not:

- an unknown `--type` printed an unhandled traceback instead of an error message;
- a malformed address given to `read` or `dump` printed an unhandled traceback instead of an
  error message;
- an out-of-range value for a type named the `struct` module's internal format character
  (e.g. `'i'`) instead of the type name the user actually typed;
- `tests/selftest.py`'s live pointer-map checks forced the cap down and asserted the map
  truncated without checking the target was even large enough to reach that cap, so a small
  target failed two checks that had nothing wrong with them;
- `ptrscan.py`'s bad `--offset` printed an unhandled traceback carrying this machine's
  absolute path;
- `memscope.py`'s unknown-type error went to stdout with exit code 1, while its own
  malformed-address error went to stderr with exit code 2; both now go to stderr with exit
  code 2, and the C follows;
- `ptrscan.py`'s address argument and its `--resolve` path were both converted by hand after
  the process had been attached, so a bad one printed an unhandled traceback -- again carrying
  this machine's absolute path;
- `memscope.py`'s `dump` with a negative length reached `ctypes.create_string_buffer` and
  raised, traceback and all;
- an address outside 0..2**64-1, in either direction, was accepted by `read`, `dump` and the
  REPL's `freeze`, `write` and `pscan`: `int()` has arbitrary precision, `ctypes` then
  truncated a too-wide one modulo 2**64, and the line printed named an address nothing had
  touched -- while a negative one (reachable only through argparse's `--` separator) was
  simply never checked at all. No such address exists in a 64-bit process, and `freeze` writes
  memory repeatedly;
- `ptrscan.py`'s `--offset` accepted a negative value and printed it as `max offset 0x-1`,
  which is not a number;
- `ptrscan.py`'s own address argument had no range check of any kind, unlike `--offset`
  alongside it or `read`/`dump`'s identical argument in the other file;
- `memscope.py`'s `dump` and `read` accepted an astronomically large positive length or
  count: `dump` reached `ctypes.create_string_buffer(size)` with `size` too big for the
  index-sized integer it converts through and raised `OverflowError`, traceback and this
  file's own path in it; `read`'s `--count` had no single allocation to overflow, just a
  loop that would run, one real `ReadProcessMemory` call per iteration, for a duration
  nobody who typed a literal that size intended.

All twelve are fixed in this repository's Python. Four code reviews found them; the harness
had reported "all cases match" through all four, because it covered none of the cases
involved each time. Every one of them is now a case in it -- which is the only reason that
sentence above about matching exactly is worth anything.

## Tests

```
py tests/selftest.py                   the offline checks
py tests/selftest.py --pid <pid|name>  and the same checks against a live process
```

The offline half needs nothing: it runs against a byte-backed fake process, and covers the
page arithmetic behind `refresh()` (against the one-read-per-address version it replaced,
across every type, both sides of every page boundary, values hanging over the end, and
unreadable pages), the caps in `PointerMap._build` and `find_paths`, and every exception
`pack()` can raise.

`--pid` repeats those against real memory, where pages that genuinely will not read exercise
a fallback a fake can only simulate, and measures the `_build` cap against the shape it
replaced. It reads the target and never writes to it. Point it at a 64-bit process if you
want the pointer-map checks: `ptrscan` assumes 8-byte pointers, so against a 32-bit target
they would measure nothing, and they are skipped rather than run and believed.

Windows only, like the rest of this: `memscope.py` binds `kernel32` at import.

## Status

The scan / narrow / write engine is tested end to end against a target process holding a
known value: a first scan finds the address, narrowing keeps it, and a write takes. The
movement-narrowing and freeze paths follow the same read loop.

Reading another process's memory is a capability to use responsibly and within the terms of
whatever you point it at. It is meant for your own programs, debugging, and reverse-
engineering you are permitted to do.
