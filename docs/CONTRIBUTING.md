# Contributing to MemScope

Thanks for your interest. This is a small, single-file tool, so contributions are easy to
review and welcome.

## Reporting a bug

Open an issue with:

- what you ran (the exact command)
- what happened, and what you expected
- your Windows version and Python version (`py --version`)

If it is an `OpenProcess` "access denied", note whether the target runs elevated — that is
expected, and the fix is to run MemScope from an elevated terminal.

## Suggesting a feature

Open an issue describing the use case. MemScope aims to stay small and dependency-free, so
features are weighed against keeping it one readable file of the standard library.

## Submitting a change

1. Fork the repository and create a branch.
2. Keep it to standard-library Python 3; no third-party packages.
3. Match the surrounding style — plain, commented where the reason is not obvious.
4. Test against a process you own (there is a worked example in the pull request template).
5. Open a pull request describing what changed and how you checked it.

## Scope

MemScope reads and searches process memory for debugging and reverse-engineering your own
programs and software you are permitted to inspect. Please keep contributions within that
purpose.
