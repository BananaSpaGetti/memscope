# Contributing to MemScope

Thanks for your interest. This is a small, single-file tool, so contributions are easy to
review and welcome.

## Reporting a bug

Open an issue with:

- what you ran (the exact command)
- what happened, and what you expected
- whether you ran the Python (`py memscope.py ...`) or the C build (`memscope.exe ...`)
- your Windows version, and either your Python version (`py --version`) or the compiler you
  built the `.exe` with

If it is an `OpenProcess` "access denied", note whether the target runs elevated — that is
expected, and the fix is to run MemScope from an elevated terminal.

## Suggesting a feature

Open an issue describing the use case. MemScope aims to stay small, so features are weighed
against keeping the Python one readable file of the standard library and the C port small
enough to review.

## Submitting a change

There are two implementations to keep in step: the Python (`memscope.py`, `ptrscan.py`),
which is the **reference implementation**, and the C port under `c/`, which is diffed against
it rather than tested purely on its own terms.

1. Fork the repository and create a branch.
2. If you touch the Python: keep it to the standard library, no third-party packages.
3. If you touch the C: build it with `make -C c` (a C compiler must be on `PATH`; w64devkit
   works on Windows) and run `make -C c test`, which builds and runs one test executable per
   file under `c/tests/`. `c/tests/differential.py` runs both implementations on the same
   inputs and diffs their output byte for byte -- run it too if your change could affect
   behaviour either side depends on, since that diff, not either side's own tests, is what
   proves the two still agree.
4. Match the surrounding style — plain, commented where the reason is not obvious.
5. Test against a process you own (there is a worked example in the pull request template).
6. Open a pull request describing what changed and how you checked it.

## Scope

MemScope reads and searches process memory for debugging and reverse-engineering your own
programs and software you are permitted to inspect. Please keep contributions within that
purpose.
