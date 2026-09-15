/*
 * ptrmap.h -- module enumeration and the PointerMap behind ptrscan's backward walk.
 *
 * Native port of the process-facing half of MemScope/ptrscan.py: modules(), PointerMap
 * (its build, pointers_into range query, and the truncated flag), and static_of(). Like
 * process.h, everything that touches memory goes through struct ProcessIO, so this can run
 * against the real Win32 backend or a fake in-memory one.
 */

#ifndef MEMSCOPE_PTRMAP_H
#define MEMSCOPE_PTRMAP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "process.h"

/* Matches MODULEENTRY32W's szModule, which is what ptrscan.py's modules() keeps. */
#define MODULE_NAME_MAX 256

/* One loaded module: its name and the static range ptrscan resolves paths against. */
typedef struct {
    char name[MODULE_NAME_MAX];
    uint64_t base;
    uint64_t size;
} ModuleEntry;

/* (name, base, size) for every module loaded in `pid`, in snapshot enumeration order --
 * the native counterpart of ptrscan.py's modules(). Writes up to `cap` entries into `out`
 * (which may be NULL if `cap` is 0, to just count), and returns the total number found. A
 * snapshot that cannot be taken is not an error: it yields zero modules, matching
 * modules()'s `return []` on a failed CreateToolhelp32Snapshot. */
int process_modules(unsigned long pid, ModuleEntry *out, int cap);

/* Which module contains `address`, and at what offset into it. Returns false (leaving
 * `*module_out`/`*offset_out` untouched) if no module in `modules[0..count)` contains it,
 * the case ptrscan.py's static_of() returns None for. */
bool ptrmap_static_of(const ModuleEntry *modules, int count, uint64_t address,
                       const ModuleEntry **module_out, uint64_t *offset_out);

/* Both caps default to ptrscan.py's memscope.MAX_HITS and memscope.MAX_SCAN_BYTES, but live
 * on the map (not as compile-time constants) so a test can shrink them the way
 * selftest.py's offline checks temporarily lower MAX_HITS to force the cap on a small
 * synthetic blob. */
#define PTRMAP_DEFAULT_MAX_HITS 2000000ULL
#define PTRMAP_DEFAULT_MAX_SCAN_BYTES (3ULL * 1024 * 1024 * 1024)

/* One slot found holding a plausible pointer: `value` is what it points at, `holder` is
 * the address of the slot itself. */
typedef struct {
    uint64_t value;
    uint64_t holder;
} PointerPair;

/* Every aligned pointer-sized slot in a process that looks like it points somewhere live,
 * indexed for "who points near here". Mirrors ptrscan.py's PointerMap: three parallel
 * Python lists become one growable array of pairs sorted by value, plus a separate sorted
 * array of region bounds for the plausibility test. */
typedef struct {
    /* base/end of every region regions() yielded, in whatever order regions() itself
     * enumerated them -- that order is the walk order _build reads memory in. Nothing may
     * assume it is sorted by base: a ProcessIO backend is free to yield regions in any
     * order, exactly as ptrscan.py's `regions = list(self.process.regions())` does not
     * assume it either. */
    uint64_t *region_base;
    uint64_t *region_end;
    size_t region_count;
    size_t region_capacity;

    /* base/end of the same regions, sorted by base ascending -- built once per
     * pointermap_build() call, purely for plausible()'s binary search. Mirrors
     * ptrscan.py's `self.region_bounds = sorted((base, base + size) for base, size in
     * regions)`, kept separate from region_base/region_end above so sorting it never
     * changes the order _build walks memory in. */
    uint64_t *bounds_base;
    uint64_t *bounds_end;
    size_t bounds_count;

    /* {value, holder} pairs, sorted by (value, holder) ascending. */
    PointerPair *pairs;
    size_t count;
    size_t capacity;

    /* True once a cap (max_hits or max_scan_bytes) stopped the walk before every region was
     * read -- set once, whichever cap fires first, and never cleared afterward. */
    bool truncated;

    /* Caps in effect for the next pointermap_build() call. Set before building; a fresh
     * map from pointermap_init() carries the same defaults ptrscan.py uses. */
    uint64_t max_hits;
    uint64_t max_scan_bytes;
} PointerMap;

/* Zeroes `map` and sets its caps to the defaults above. Does not build anything yet --
 * call pointermap_build() (optionally after lowering max_hits/max_scan_bytes) to do that. */
void pointermap_init(PointerMap *map);

/* Walks every region `process` reports in 4 MiB chunks, reading 8-byte little-endian words
 * at 8-byte alignment and keeping those whose value falls inside some region (checked
 * against `map`'s own region bounds, gathered from `process->regions` at the start of this
 * call). Both `map->max_hits` and `map->max_scan_bytes` stop the ENTIRE walk, not just the
 * chunk being read, and set `map->truncated`. May be called more than once on the same
 * `map`; each call discards whatever the previous one built. */
void pointermap_build(PointerMap *map, ProcessIO *process);

/* Releases everything pointermap_build() allocated. Safe to call on an already-freed or
 * zeroed map. */
void pointermap_free(PointerMap *map);

/* One pointer found near a target: the address of the slot holding it, and the offset from
 * its value up to the target (`target - value`), matching ptrscan.py's `(holder, offset)`. */
typedef struct {
    uint64_t holder;
    uint64_t offset;
} PointerHit;

/* Every (holder, offset) whose stored value lies in [target - max_offset, target], in
 * ascending value order (then ascending holder, for ties) -- the native counterpart of
 * PointerMap.pointers_into(). Writes up to `out_cap` hits into `out` (which may be NULL if
 * out_cap is 0, to just count) and returns the total number found, which may exceed
 * out_cap: callers that need every hit (ptrscan's find_paths does) should size `out` to
 * the count from a first call, or call once with a cap known to be large enough. */
size_t pointermap_pointers_into(const PointerMap *map, uint64_t target, uint64_t max_offset,
                                 PointerHit *out, size_t out_cap);

#endif
