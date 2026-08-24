# MemScope

A small, general memory scanner for 64-bit Windows processes, in one file of standard-library
Python. It reads and searches the live memory of any process you have the rights to open, and
narrows a set of candidate addresses the way Cheat Engine or scanmem do -- scan for a value,
let it change, scan again for what changed, until one address is left.

Nothing in it is specific to any one program; it is a debugging and reverse-engineering tool.

## Requirements

- Windows, 64-bit.
- Python 3 (`py` on this machine). No third-party packages.
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
