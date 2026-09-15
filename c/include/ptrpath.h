/*
 * ptrpath.h -- the backward BFS to static pointer paths, resolve/verify, and the path
 * string format.
 *
 * Native port of the walking half of MemScope/ptrscan.py: find_paths(), resolve(),
 * format_path(), parse_path() and scan_limits(). Unlike ptrscan.py's find_paths(), which
 * builds its own PointerMap and fetches its own module list internally, ptrpath_find()
 * takes both as parameters -- a fake ProcessIO has no pid to fetch modules for, and a
 * test needs to hand it a PointerMap with caps already lowered. Callers (main_ptrscan.c,
 * repl.c's pscan) build the PointerMap and module list once with ptrmap.h's own
 * functions and pass them in.
 */

#ifndef MEMSCOPE_PTRPATH_H
#define MEMSCOPE_PTRPATH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "process.h"
#include "ptrmap.h"

/* One static pointer path found by ptrpath_find(): the module the outermost holder
 * lives in, the offset into that module of the holder, and the offsets to apply, in
 * forward (module-to-target) order -- ptrscan.py's `(module_name, module_offset,
 * offsets)`. Owns `offsets`; free with ptrpath_free_results(). */
typedef struct {
    char module_name[MODULE_NAME_MAX];
    uint64_t module_offset;
    uint64_t *offsets;
    int offset_count;
} PathResult;

/* The breadth-first backward walk from `target` to static pointer paths -- the native
 * counterpart of ptrscan.py's find_paths(), given an already-built `map` and an
 * already-fetched module list instead of building/fetching them itself.
 *
 * The offset chain carried by each frontier node is a fixed array of length `depth`;
 * the per-node `seen` set of addresses already on that path is a fixed array of length
 * `depth + 1` (the target itself, plus up to `depth` holders) -- both bounded because a
 * path can hold at most `depth` hops. No address appears twice in one path. The
 * frontier is capped at `max_frontier` new (non-static) nodes per level; `*dropped`
 * receives how many were turned away by that cap. A holder that resolves to a static
 * module address is recorded as a result and never expands into a frontier node (so it
 * is never subject to the frontier cap). Hitting `max_paths` stops the walk immediately,
 * matching ptrscan.py's early `return`.
 *
 * Writes a newly allocated array of `*out_count` results (each an entry the caller owns
 * together with its `offsets`; free the whole array with ptrpath_free_results()) into
 * `*out`. Returns false only if an allocation failed outright, in which case `*out` and
 * `*out_count` still hold whatever was found before the failure. */
bool ptrpath_find(const PointerMap *map, const ModuleEntry *modules, int module_count,
                   uint64_t target, int64_t depth, uint64_t max_offset,
                   size_t max_paths, size_t max_frontier,
                   PathResult **out, size_t *out_count, size_t *dropped);

/* Releases an array ptrpath_find() produced, including each entry's `offsets`. Safe to
 * call with results == NULL. */
void ptrpath_free_results(PathResult *results, size_t count);

/* Walks a path forward from `module_name`'s base (matched case-insensitively, first
 * match in `modules[0..module_count)`, as ptrscan.py's resolve() does with `.lower()`),
 * dereferencing and adding each of `offsets[0..offset_count)` in turn. Returns false
 * (leaving `*address_out` untouched) if the module is not loaded or a hop's read
 * returns nothing -- matching resolve()'s `return None` on `not data`. A short read
 * (some bytes but fewer than a pointer) is still used, zero-extended, matching
 * `int.from_bytes` on a short `bytes` object. */
bool ptrpath_resolve(ProcessIO *process, const char *module_name, uint64_t module_offset,
                      const uint64_t *offsets, int offset_count,
                      const ModuleEntry *modules, int module_count, uint64_t *address_out);

/* "module+0xOFF -> 0xOFF -> 0xOFF", matching ptrscan.py's format_path() exactly
 * (uppercase hex, no leading zeros, " -> " joiners). Writes into `buf` (size
 * `buf_size`), truncating and always NUL-terminating if `buf` is too small. Returns the
 * number of bytes the untruncated string would need (excluding the NUL), snprintf-style,
 * so a caller can detect truncation by comparing against `buf_size`. */
int ptrpath_format(const char *module_name, uint64_t module_offset,
                    const uint64_t *offsets, int offset_count, char *buf, size_t buf_size);

/* One divergence from ptrscan.py is deliberate and cannot be closed without arbitrary-
 * precision addresses: if the LAST hop's offset carries the final address past 2**64, that
 * address is never read -- resolve() returns it and the caller prints it -- so ptrscan.py
 * prints a number wider than 64 bits, and this reports the path as unresolvable instead.
 * Every earlier hop IS exact, because its address is read before the next offset is added,
 * and a read of an address that wide fails in both implementations. Measured, recorded here
 * rather than left for the next reader to discover. */
/* Parses "module+0xOFF -> 0xOFF -> 0xOFF", matching ptrscan.py's parse_path(): split on
 * "->", strip each piece, partition the first piece on "+". Every hex number is parsed
 * base 16 with an optional "0x"/"0X" prefix (matching Python's `int(s, 16)`, which is
 * base 16 even when a prefix is present, not base 0). Unlike parse_path(), which raises
 * on a head with no "+" or an unparseable number, this returns false rather than
 * crashing -- a malformed --resolve argument already has to be handled as an error by
 * the caller either way.
 *
 * Writes the module name (truncated to fit `module_name_cap`) into `module_name_out`,
 * the module offset into `*module_offset_out`, and up to `offsets_cap` offsets into
 * `offsets_out`, with `*offset_count_out` set to how many offsets were found (which may
 * exceed `offsets_cap`, mirroring the out-array convention used elsewhere in this
 * codebase). Returns false, leaving every output untouched, if the text cannot be
 * parsed or names more hops than this parser's internal bound allows. */
/* *oversized_out reports a piece that is a valid hex literal but too wide for uint64_t --
 * ptrscan.py parses one (a Python int has no width) and then fails to resolve it, so the
 * caller must treat it as an unresolvable path rather than a malformed one. May be NULL. */
bool ptrpath_parse(const char *text, char *module_name_out, size_t module_name_cap,
                    uint64_t *module_offset_out, uint64_t *offsets_out, size_t offsets_cap,
                    int *offset_count_out, bool *oversized_out);

#define PTRPATH_LIMIT_LINE_MAX 128

/* Up to two lines describing which cap (if any) bounded the search, matching
 * ptrscan.py's scan_limits() text exactly -- the pointer-map line first, then the
 * frontier line, each only if it fired. Fills `out_lines[0]` and, if needed,
 * `out_lines[1]` (each `PTRPATH_LIMIT_LINE_MAX` bytes) and returns how many were filled:
 * 0, 1, or 2. */
int ptrpath_scan_limits(const PointerMap *map, size_t dropped,
                         char out_lines[2][PTRPATH_LIMIT_LINE_MAX]);

#endif
