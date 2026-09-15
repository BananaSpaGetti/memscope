/*
 * scanner.h -- the value scanner behind memscope's `scan`/`next`/`list` commands.
 *
 * Native port of the Scanner class in MemScope/memscope.py: first_scan(), snapshot(),
 * refresh(), narrow_value() and narrow_move(). Like process.h and ptrmap.h, everything
 * that touches memory goes through struct ProcessIO, so this runs against the real Win32
 * backend or a fake in-memory one without change.
 *
 * Scanner.candidates in Python is a dict {address: last_value}; iterating a Python dict
 * yields insertion order, not sorted order, and memscope.py never relies on it being
 * sorted -- narrow_value() tests `if address not in now` and narrow_move() looks values up
 * by key, both order-free. Here it is a growable array of ScanCandidate kept in whatever
 * order it was built in (first_scan()/snapshot() walk regions() in whatever order that
 * enumerates them, not necessarily ascending by address). Code in this file must not assume
 * the array is sorted; refresh(), narrow_value() and narrow_move() are all written to be
 * order-free the way the Python is. Exactly one type is active per scan session
 * (scanner->kind), so a candidate's decoded value is stored as a plain slot with no type tag
 * of its own.
 */

#ifndef MEMSCOPE_SCANNER_H
#define MEMSCOPE_SCANNER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "process.h"
#include "values.h"

/* Both caps default to memscope.py's MAX_HITS and MAX_SCAN_BYTES, but live on the scanner
 * (not as compile-time constants) so a test can shrink them the way selftest.py's offline
 * checks temporarily lower MAX_HITS to force a cap on a small synthetic blob. */
#define SCANNER_DEFAULT_MAX_HITS 2000000ULL
#define SCANNER_DEFAULT_MAX_SCAN_BYTES (3ULL * 1024 * 1024 * 1024)

/* A decoded scalar with no type tag of its own -- the scanner's `kind` says how to read it.
 * Mirrors the three members of MsValue.as. */
typedef union {
    int64_t i;
    uint64_t u;
    double f;
} ScanSlot;

/* One candidate address and its last-known value. `has_value` is false when a refresh's
 * fallback read returned fewer bytes than the current type needs -- the address is still a
 * live candidate (it was not dropped), it just has no decoded value right now, mirroring
 * Python's `out[address] = unpack(...)` where unpack() returned None but the key was still
 * assigned. An address whose read failed outright is not a candidate at all: it is dropped
 * from the array entirely, mirroring the key being absent from Python's dict. */
typedef struct {
    uint64_t address;
    bool has_value;
    ScanSlot value;
} ScanCandidate;

/* How many candidates a first_scan()/snapshot() left, and whether a cap cut the walk short
 * before the whole address space was covered. */
typedef struct {
    size_t count;
    bool truncated;
} ScanCounts;

/* narrow_move()'s four ways a candidate's value can move between two refreshes, matching
 * memscope.py's `next same|changed|up|down`. */
typedef enum {
    SCANNER_MOVE_SAME,
    SCANNER_MOVE_CHANGED,
    SCANNER_MOVE_UP,
    SCANNER_MOVE_DOWN
} ScannerMove;

typedef struct {
    ProcessIO *process;
    MsType kind;

    /* Candidates in whatever order they were built in -- not guaranteed to be sorted by
     * address. NULL/0/0 before the first scan. */
    ScanCandidate *candidates;
    size_t count;
    size_t capacity;

    /* Whether a scan has ever run -- mirrors Python's `candidates is not None`, which is
     * distinct from an empty result (a scan that matched nothing). */
    bool has_scanned;

    uint64_t max_hits;
    uint64_t max_scan_bytes;
} Scanner;

/* Zeroes `s`, points it at `process`, sets kind to int32 (memscope.py's default) and the
 * caps to the defaults above. Does not scan anything yet. */
void scanner_init(Scanner *s, ProcessIO *process);

/* Releases the candidate array. Safe to call on an already-freed or zeroed scanner. */
void scanner_free(Scanner *s);

/* Throws the candidate set away without scanning again -- mirrors the REPL's `reset` and
 * a `type` change (which resets Python's `self.candidates = None`). */
void scanner_reset(Scanner *s);

/* Packs `literal` under the scanner's current type and does a full memory scan for an exact
 * match, replacing the candidate set. Mirrors Scanner.first_scan(value). Returns false,
 * leaving the candidate set and `*out` untouched, if `literal` cannot be packed under the
 * current type -- the same case Python's pack() raises for, which the REPL's exception
 * wrapper catches -- or if the read buffer itself could not be allocated. On success, `out`
 * (if non-NULL) receives the new count and whether a cap (MAX_HITS, MAX_SCAN_BYTES, or
 * running out of memory partway through) stopped the walk early. */
bool scanner_first_scan(Scanner *s, const char *literal, ScanCounts *out, char *err,
                         size_t err_cap);

/* Records every aligned slot's current value with no filter, replacing the candidate set.
 * Mirrors Scanner.snapshot(). `out` (if non-NULL) receives the new count and whether MAX_HITS,
 * MAX_SCAN_BYTES, or running out of memory (this function has no error channel of its own)
 * stopped the walk before the whole address space was recorded. */
void scanner_snapshot(Scanner *s, ScanCounts *out);

/* Re-reads the current value at every existing candidate address, batching one read per 4 KiB
 * page and reusing it for every candidate in that page, with a per-address fallback for a
 * value that straddles a page boundary or sits in an unreadable page. Mirrors
 * Scanner.refresh(), which returns a fresh dict without touching self.candidates -- this does
 * not modify `s->candidates` either. `*out` is a freshly allocated array holding, in the same
 * order as `s->candidates` (an order-preserving subsequence: an address whose read fails
 * outright is omitted, and one that could not be appended to the output because of an
 * allocation failure ends the walk early), the refreshed value at each surviving address;
 * free it with scanner_candidates_free(). Callers that need to pair this against
 * `s->candidates` (narrow_move()) must do so positionally, not by assuming either array is
 * sorted by address. */
void scanner_refresh(const Scanner *s, ScanCandidate **out, size_t *out_count);

/* Frees an array scanner_refresh() (or scanner_snapshot_candidates(), etc.) allocated. */
void scanner_candidates_free(ScanCandidate *items);

/* Refreshes, then keeps only candidates whose refreshed value equals `literal` packed and
 * unpacked under the current type (the same round trip Python's narrow_value() does, which
 * normalizes a float literal to its type's precision before comparing), replacing the
 * candidate set. Mirrors Scanner.narrow_value(value). Returns false, leaving the candidate
 * set untouched, if `literal` cannot be packed. `out_count` (if non-NULL) receives the
 * number kept. */
bool scanner_narrow_value(Scanner *s, const char *literal, size_t *out_count, char *err,
                           size_t err_cap);

/* Refreshes, then keeps only candidates present in both the old and new sets whose values
 * moved the way `how` asks, replacing the candidate set with the new values. Mirrors
 * Scanner.narrow_move(how). Returns the number kept.
 *
 * Deviation from the reference: CPython's `value > was` / `value < was` raises TypeError
 * when either side is the `None` a short fallback read can leave behind, which is not one
 * of the exceptions memscope.py's REPL wrapper catches and would end the session. A
 * candidate missing a value on either side of an up/down comparison is treated here as not
 * moving that way (dropped), rather than reproducing a crash. same/changed match Python
 * exactly: two missing values compare equal, and a missing value against a present one
 * compares unequal. */
size_t scanner_narrow_move(Scanner *s, ScannerMove how);

#endif
