/*
 * process.h -- the Win32 process layer behind a function-pointer seam.
 *
 * Native port of the process-facing half of MemScope/memscope.py: processes(), the
 * Process class (open/regions/read/write/close), and attach(). Everything that touches
 * a live target goes through struct ProcessIO, so later tasks (the Scanner, the
 * PointerMap) can run against either this real Win32 backend or a fake in-memory one
 * without knowing which they have.
 */

#ifndef MEMSCOPE_PROCESS_H
#define MEMSCOPE_PROCESS_H

#include <stddef.h>
#include <stdint.h>

#define PROCESS_NAME_MAX 260

/* One process from a snapshot: its pid and its exe filename (not a full path), UTF-8. */
typedef struct {
    unsigned long pid;
    char name[PROCESS_NAME_MAX];
} ProcessEntry;

/* One committed, writable, non-guard span of a target's address space. */
typedef struct {
    uint64_t base;
    uint64_t size;
} Region;

typedef struct ProcessIO ProcessIO;

/* Called once per region regions() yields, in ascending address order. Return nonzero
 * to stop enumeration early; 0 to keep going. */
typedef int (*RegionFn)(void *user, uint64_t base, uint64_t size);

/* A process-like memory backend: the real Win32 target, or (in tests) a fake in-memory
 * one, interchangeable at runtime. `ctx` is opaque to callers and owned by whichever
 * backend filled in the struct. */
struct ProcessIO {
    void *ctx;
    void (*regions)(ProcessIO *self, RegionFn visit, void *user);
    /* Reads up to `size` bytes at `address` into `out`. Returns the number of bytes
     * actually read, or 0 if the read failed outright -- mirroring memscope.py's
     * read(), which returns None (falsy, like a 0-length result here) on failure. */
    size_t (*read)(ProcessIO *self, uint64_t address, void *out, size_t size);
    /* Writes `size` bytes from `data` at `address`. Returns nonzero only if every byte
     * was written, matching Process.write()'s `wrote.value == len(data)` check. */
    int (*write)(ProcessIO *self, uint64_t address, const void *data, size_t size);
};

/* (pid, name) for every process whose exe filename contains `needle`, case-insensitively
 * ("" matches every process) -- the native counterpart of memscope.py's processes().
 * Writes up to `cap` matches into `out` (which may be NULL if `cap` is 0, to just count),
 * in snapshot enumeration order. Returns the total number of matches found, which may be
 * more than `cap`, or -1 if the process snapshot could not be taken. */
int process_list(const char *needle, ProcessEntry *out, int cap);

/* Opens `pid` for query/read/write and fills `*io` with a real Win32 backend over it,
 * matching memscope.py's Process.__init__ (the four access rights OR'd together).
 * Returns 0 on success. On failure returns -1 and, if `err_out` is non-NULL, writes a
 * message into it -- including the "run elevated" hint memscope.py prints on error 5. */
int process_open(unsigned long pid, ProcessIO *io, char *err_out, size_t err_out_size);

/* Releases everything process_open allocated. Safe to call on an already-closed or
 * zeroed ProcessIO. */
void process_close(ProcessIO *io);

/* Resolves `target` to exactly one process and opens it, mirroring memscope.py's
 * attach(): a target made only of decimal digits is used directly as a pid (not matched
 * against names, and not checked for existence up front); anything else is matched as a
 * case-insensitive substring of process names. No match, or more than one match, is
 * printed to stdout (as the Python does with print()) and the call fails; an ambiguous
 * match lists up to 20 candidates. On success returns 0 with `*io` filled in and, if
 * non-NULL, `*pid_out` and `name_out` set. */
int process_attach(const char *target, ProcessIO *io, unsigned long *pid_out,
                    char *name_out, size_t name_out_size);

#endif
