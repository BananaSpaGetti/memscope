/*
 * ptrpath.c -- see include/ptrpath.h. Native port of ptrscan.py's find_paths(),
 * resolve(), format_path(), parse_path() and scan_limits().
 */

#include "ptrpath.h"
#include "util.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* --- the frontier -------------------------------------------------------------------- */

/* One frontier node: the address discovered so far, its offset chain (a fixed array of
 * length `depth`, forward order, `offset_count` of it valid) and the addresses already
 * on this path (a fixed array of length `depth + 1`, `seen_count` of it valid) --
 * exactly the two bounded arrays include/ptrpath.h documents. Owns both arrays. */
typedef struct {
    uint64_t address;
    uint64_t *offsets;
    int offset_count;
    uint64_t *seen;
    int seen_count;
} PathNode;

typedef struct {
    PathNode *nodes;
    size_t count;
    size_t capacity;
} NodeArray;

static bool node_array_push(NodeArray *arr, PathNode node) {
    if (arr->count == arr->capacity) {
        size_t new_cap = arr->capacity ? arr->capacity * 2 : 64;
        PathNode *grown = (PathNode *)realloc(arr->nodes, new_cap * sizeof(PathNode));
        if (!grown) {
            return false;
        }
        arr->nodes = grown;
        arr->capacity = new_cap;
    }
    arr->nodes[arr->count++] = node;
    return true;
}

static void node_array_free_contents(NodeArray *arr) {
    for (size_t i = 0; i < arr->count; i++) {
        free(arr->nodes[i].offsets);
        free(arr->nodes[i].seen);
    }
    free(arr->nodes);
    arr->nodes = NULL;
    arr->count = 0;
    arr->capacity = 0;
}

static bool in_seen(const uint64_t *seen, int count, uint64_t address) {
    for (int i = 0; i < count; i++) {
        if (seen[i] == address) {
            return true;
        }
    }
    return false;
}

static bool result_array_push(PathResult **arr, size_t *count, size_t *capacity,
                               PathResult item) {
    if (*count == *capacity) {
        size_t new_cap = *capacity ? *capacity * 2 : 16;
        PathResult *grown = (PathResult *)realloc(*arr, new_cap * sizeof(PathResult));
        if (!grown) {
            return false;
        }
        *arr = grown;
        *capacity = new_cap;
    }
    (*arr)[(*count)++] = item;
    return true;
}

/* No real pointer chain runs anywhere near this deep; it bounds the per-node allocation
 * below regardless of what a caller passes, so a --depth wider than `int` (or simply
 * absurd) cannot request gigabytes or wrap through a truncating cast. Every practical
 * depth is far under this and behaves exactly as before -- the search still terminates
 * on its own, usually long before this cap, once the frontier empties or max_frontier
 * fires. A depth this large used to silently truncate through `(int)depth`, landing on
 * an arbitrary and sometimes negative value, and returning wrong -- not just capped --
 * results with no indication anything had gone wrong. */
#define PTRPATH_MAX_DEPTH 4096

bool ptrpath_find(const PointerMap *map, const ModuleEntry *modules, int module_count,
                   uint64_t target, int64_t depth_in, uint64_t max_offset,
                   size_t max_paths, size_t max_frontier,
                   PathResult **out, size_t *out_count, size_t *dropped) {
    *out = NULL;
    *out_count = 0;
    *dropped = 0;
    int depth;
    if (depth_in < 0) {
        depth = 0;
    } else if (depth_in > PTRPATH_MAX_DEPTH) {
        depth = PTRPATH_MAX_DEPTH;
    } else {
        depth = (int)depth_in;
    }

    PathResult *results = NULL;
    size_t results_count = 0, results_cap = 0;
    bool ok = true;
    bool stop = false; /* max_paths reached, or an allocation failed */

    NodeArray frontier = {0};
    PathNode root;
    root.address = target;
    root.offset_count = 0;
    root.offsets = depth > 0 ? (uint64_t *)malloc((size_t)depth * sizeof(uint64_t)) : NULL;
    root.seen = (uint64_t *)malloc(((size_t)depth + 1) * sizeof(uint64_t));
    if ((depth > 0 && !root.offsets) || !root.seen) {
        free(root.offsets);
        free(root.seen);
        return false;
    }
    root.seen[0] = target;
    root.seen_count = 1;
    if (!node_array_push(&frontier, root)) {
        free(root.offsets);
        free(root.seen);
        return false;
    }

    for (int level = 0; level < depth && !stop; level++) {
        NodeArray nxt = {0};
        for (size_t i = 0; i < frontier.count && !stop; i++) {
            PathNode *node = &frontier.nodes[i];
            size_t hit_total = pointermap_pointers_into(map, node->address, max_offset,
                                                         NULL, 0);
            PointerHit *hits = NULL;
            if (hit_total > 0) {
                hits = (PointerHit *)malloc(hit_total * sizeof(PointerHit));
                if (!hits) {
                    ok = false;
                    stop = true;
                    break;
                }
                pointermap_pointers_into(map, node->address, max_offset, hits, hit_total);
            }
            for (size_t h = 0; h < hit_total && !stop; h++) {
                uint64_t holder = hits[h].holder;
                uint64_t offset = hits[h].offset;
                if (in_seen(node->seen, node->seen_count, holder)) {
                    continue;
                }

                /* chain = [offset] + node->offsets, matching ptrscan.py's prepend --
                 * every child gets its own copy, since siblings diverge here. */
                uint64_t *chain = depth > 0
                                       ? (uint64_t *)malloc((size_t)depth * sizeof(uint64_t))
                                       : NULL;
                if (depth > 0 && !chain) {
                    ok = false;
                    stop = true;
                    break;
                }
                if (depth > 0) {
                    chain[0] = offset;
                    for (int k = 0; k < node->offset_count; k++) {
                        chain[1 + k] = node->offsets[k];
                    }
                }
                int chain_count = node->offset_count + 1;

                const ModuleEntry *mod = NULL;
                uint64_t modoff = 0;
                if (ptrmap_static_of(modules, module_count, holder, &mod, &modoff)) {
                    PathResult r;
                    memset(&r, 0, sizeof(r));
                    /* mod->name is already NUL-terminated within MODULE_NAME_MAX by
                     * ms_wide_to_utf8 (ptrmap.c); strncpy's "may not NUL-terminate" warning
                     * is a false positive here, but copy by hand rather than silence it. */
                    size_t name_len = strlen(mod->name);
                    if (name_len >= MODULE_NAME_MAX) {
                        name_len = MODULE_NAME_MAX - 1;
                    }
                    memcpy(r.module_name, mod->name, name_len);
                    r.module_offset = modoff;
                    r.offsets = chain; /* transfer ownership */
                    r.offset_count = chain_count;
                    if (!result_array_push(&results, &results_count, &results_cap, r)) {
                        free(chain);
                        ok = false;
                        stop = true;
                        break;
                    }
                    if (results_count >= max_paths) {
                        stop = true;
                        break;
                    }
                } else if (nxt.count < max_frontier) {
                    PathNode child;
                    child.address = holder;
                    child.offsets = chain; /* transfer ownership */
                    child.offset_count = chain_count;
                    child.seen =
                        (uint64_t *)malloc(((size_t)depth + 1) * sizeof(uint64_t));
                    if (!child.seen) {
                        free(chain);
                        ok = false;
                        stop = true;
                        break;
                    }
                    memcpy(child.seen, node->seen,
                           (size_t)node->seen_count * sizeof(uint64_t));
                    child.seen[node->seen_count] = holder;
                    child.seen_count = node->seen_count + 1;
                    if (!node_array_push(&nxt, child)) {
                        free(chain);
                        free(child.seen);
                        ok = false;
                        stop = true;
                        break;
                    }
                } else {
                    (*dropped)++;
                    free(chain);
                }
            }
            free(hits);
        }
        node_array_free_contents(&frontier);
        frontier = nxt;
        if (frontier.count == 0) {
            break;
        }
    }
    node_array_free_contents(&frontier);

    *out = results;
    *out_count = results_count;
    return ok;
}

void ptrpath_free_results(PathResult *results, size_t count) {
    if (!results) {
        return;
    }
    for (size_t i = 0; i < count; i++) {
        free(results[i].offsets);
    }
    free(results);
}

/* --- resolve --------------------------------------------------------------------------- */

static bool ci_equal(const char *a, const char *b) {
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) {
            return false;
        }
        a++;
        b++;
    }
    return *a == *b;
}

bool ptrpath_resolve(ProcessIO *process, const char *module_name, uint64_t module_offset,
                      const uint64_t *offsets, int offset_count,
                      const ModuleEntry *modules, int module_count, uint64_t *address_out) {
    uint64_t base = 0;
    bool found = false;
    for (int i = 0; i < module_count; i++) {
        if (ci_equal(modules[i].name, module_name)) {
            base = modules[i].base;
            found = true;
            break;
        }
    }
    if (!found) {
        return false;
    }

    /* Wrapping is deliberate: a negative hop offset arrives as its two's-complement
     * pattern, so an addition that overflows is exactly how `value - 16` is computed. An
     * offset genuinely too wide for uint64_t is caught at parse time instead, where the
     * two cases can still be told apart. */
    uint64_t address = base + module_offset;
    for (int i = 0; i < offset_count; i++) {
        uint8_t buf[8] = {0};
        size_t got = process->read(process, address, buf, sizeof(buf));
        if (got == 0) {
            return false;
        }
        uint64_t value = 0;
        memcpy(&value, buf, sizeof(buf)); /* unused tail is zeroed above, matching
                                              int.from_bytes zero-extending a short read */
        address = value + offsets[i];
    }
    if (address_out) {
        *address_out = address;
    }
    return true;
}

/* --- format_path / parse_path ----------------------------------------------------------- */

int ptrpath_format(const char *module_name, uint64_t module_offset,
                    const uint64_t *offsets, int offset_count, char *buf, size_t buf_size) {
    int n = snprintf(buf, buf_size, "%s+0x%llX", module_name,
                      (unsigned long long)module_offset);
    if (n < 0) {
        return n;
    }
    size_t pos = (size_t)n;
    for (int i = 0; i < offset_count; i++) {
        char piece[24];
        int pn = snprintf(piece, sizeof(piece), " -> 0x%llX", (unsigned long long)offsets[i]);
        if (pn < 0) {
            return pn;
        }
        if (pos < buf_size) {
            snprintf(buf + pos, buf_size - pos, "%s", piece);
        }
        pos += (size_t)pn;
    }
    return (int)pos;
}

/* Internal bound on how many "->"-separated pieces a path string can name -- ptrscan.py
 * has no such limit (a Python list grows freely), but a fixed-array parser needs one and
 * this is far past any depth a real scan would ever use (the CLI default is 3). */
#define PTRPATH_PARSE_MAX_PIECES 256

static void trim(char *s) {
    char *start = s;
    while (isspace((unsigned char)*start)) {
        start++;
    }
    if (start != s) {
        memmove(s, start, strlen(start) + 1);
    }
    size_t len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1])) {
        s[--len] = '\0';
    }
}

/* ptrscan.py's parse_path runs int(piece, 16), and a Python int has no width -- so a piece
 * far too large for uint64_t parses there and only fails later, when the resolve tries to
 * read the address it produces. Rejecting it here made a failed resolve (exit 1) into a
 * parse error (exit 2) with a different message.
 *
 * Out-of-range is therefore not a failure here; it is reported through *oversized_at, which
 * records WHERE it happened, because that decides what the caller can honestly say. Every
 * address in a path is read except the last one: ptrscan.py reads base+module_offset, then
 * each hop's result, and the final addition is returned unread. So an oversized piece
 * anywhere but the end produces an address that fails to read in BOTH implementations and is
 * a genuine "could not resolve" -- while an oversized piece at the end is an address
 * ptrscan.py prints, wider than 64 bits, and this port cannot represent at all. Reporting
 * those two as the same thing is what made a deliberate limitation indistinguishable from a
 * misspelled module name. Only a malformed literal fails here. */
static bool parse_path_offset(const char *text, uint64_t *out, int position, int *oversized_at) {
    MsIntOverflow overflow;
    if (ms_parse_py_int(text, 16, false, out, &overflow, NULL, 0)) {
        return true;
    }
    if (overflow.triggered) {
        if (*oversized_at < 0) {
            *oversized_at = position;   /* the first one decides the message */
        }
        *out = 0;
        return true;
    }
    return false;
}

bool ptrpath_parse(const char *text, char *module_name_out, size_t module_name_cap,
                    uint64_t *module_offset_out, uint64_t *offsets_out, size_t offsets_cap,
                    int *offset_count_out, int *oversized_at_out) {
    char buf[2048];
    size_t len = strlen(text);
    if (len >= sizeof(buf)) {
        return false;
    }
    memcpy(buf, text, len + 1);

    char *pieces[PTRPATH_PARSE_MAX_PIECES];
    int piece_count = 0;
    char *cursor = buf;
    for (;;) {
        char *arrow = strstr(cursor, "->");
        if (piece_count >= PTRPATH_PARSE_MAX_PIECES) {
            return false;
        }
        if (arrow) {
            *arrow = '\0';
            pieces[piece_count++] = cursor;
            cursor = arrow + 2;
        } else {
            pieces[piece_count++] = cursor;
            break;
        }
    }
    for (int i = 0; i < piece_count; i++) {
        trim(pieces[i]);
    }

    char *plus = strchr(pieces[0], '+');
    if (!plus) {
        return false;
    }
    *plus = '\0';
    char *module_name = pieces[0];
    char *offset_hex = plus + 1;
    trim(module_name);
    trim(offset_hex);

    /* Position 0 is the module offset; position i is the i'th hop. -1 is "none oversized". */
    int oversized_at = -1;
    uint64_t module_offset;
    if (!parse_path_offset(offset_hex, &module_offset, 0, &oversized_at)) {
        return false;
    }

    int offset_count = piece_count - 1;
    uint64_t parsed_offsets[PTRPATH_PARSE_MAX_PIECES];
    for (int i = 0; i < offset_count; i++) {
        if (!parse_path_offset(pieces[1 + i], &parsed_offsets[i], i + 1, &oversized_at)) {
            return false;
        }
    }

    if (module_name_out && module_name_cap > 0) {
        strncpy(module_name_out, module_name, module_name_cap - 1);
        module_name_out[module_name_cap - 1] = '\0';
    }
    if (module_offset_out) {
        *module_offset_out = module_offset;
    }
    size_t n = (size_t)offset_count < offsets_cap ? (size_t)offset_count : offsets_cap;
    for (size_t i = 0; i < n; i++) {
        offsets_out[i] = parsed_offsets[i];
    }
    if (oversized_at_out) {
        *oversized_at_out = oversized_at;
    }
    if (offset_count_out) {
        *offset_count_out = offset_count;
    }
    return true;
}

/* --- scan_limits ------------------------------------------------------------------------- */

int ptrpath_scan_limits(const PointerMap *map, size_t dropped,
                         char out_lines[2][PTRPATH_LIMIT_LINE_MAX]) {
    int n = 0;
    if (map && map->truncated) {
        snprintf(out_lines[n], PTRPATH_LIMIT_LINE_MAX,
                 "  (pointer map capped at %llu slots -- part of memory was not mapped)",
                 (unsigned long long)map->max_hits);
        n++;
    }
    if (dropped) {
        snprintf(out_lines[n], PTRPATH_LIMIT_LINE_MAX,
                 "  (frontier capped -- %llu branch(es) were not explored)",
                 (unsigned long long)dropped);
        n++;
    }
    return n;
}
