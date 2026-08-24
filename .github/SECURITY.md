# Security Policy

## Supported versions

This is a small, single-file tool. Only the latest commit on the default branch is
supported; fixes are applied there.

## Reporting a vulnerability

Please report security issues **privately**, not in a public issue.

- Preferred: open a private advisory through GitHub — the repository's **Security** tab →
  **Report a vulnerability**.
- Alternatively, contact the maintainer through GitHub.

Please include what the issue is, how to reproduce it, and the impact you see. You will get
a response as soon as reasonably possible, and credit in the fix if you would like it.

## Scope

MemScope reads and writes the memory of processes you have the rights to open. That is its
purpose, not a vulnerability. Relevant reports are things like a crash, an out-of-bounds
read of its own buffers, or a way the tool could be made to write somewhere unintended.
