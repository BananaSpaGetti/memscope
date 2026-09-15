/*
 * scanner.c -- see include/scanner.h. Native port of the Scanner class in
 * MemScope/memscope.py.
 */

#include "scanner.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The chunk size first_scan()/snapshot() read a region in, and the page size refresh()
 * batches reads by -- memscope.py's 4 * 1024 * 1024 and PAGE = 4096. */
#define SCANNER_CHUNK_SIZE (4ULL * 1024 * 1024)
#define SCANNER_PAGE_SIZE 4096ULL

/* --- candidate array plumbing ------------------------------------------------------------ */

static ScanSlot slot_from_value(const MsValue *v) {
    ScanSlot slot;
    if (ms_type_is_float(v->kind)) {
        slot.f = v->as.f;
    } else if (ms_type_is_signed(v->kind)) {
        slot.i = v->as.i;
    } else {
        slot.u = v->as.u;
    }
    return slot;
}

static bool slot_equal(MsType kind, ScanSlot a, ScanSlot b) {
    if (ms_type_is_float(kind)) {
        return a.f == b.f;
    }
    if (ms_type_is_signed(kind)) {
        return a.i == b.i;
    }
    return a.u == b.u;
}

/* -1, 0 or 1 the way Python's < and > would compare the same two decoded numbers. */
static int slot_compare(MsType kind, ScanSlot a, ScanSlot b) {
    if (ms_type_is_float(kind)) {
        return (a.f > b.f) - (a.f < b.f);
    }
    if (ms_type_is_signed(kind)) {
        return (a.i > b.i) - (a.i < b.i);
    }
    return (a.u > b.u) - (a.u < b.u);
}

/* Growable-array append shared by every builder below (scan results and refresh output
 * alike). Grows by doubling, matching the other growable arrays in this port. */
typedef struct {
    ScanCandidate *items;
    size_t count;
    size_t capacity;
} CandidateBuilder;

/* Returns false, leaving `b` exactly as it was (old block and old capacity both intact), if
 * growing the array fails -- follows ptrmap.c's append_pair and ptrpath.c's node_array_push,
 * which check the same way. The old code assigned the realloc result and bumped capacity
 * unconditionally, so a failed realloc at MAX_HITS (the array is ~48 MB there, and the next
 * doubling needs 96 MB transient) leaked the old block, left capacity claiming space that
 * did not exist, and made the very next append write through NULL. */
static bool builder_append(CandidateBuilder *b, uint64_t address, bool has_value,
                            ScanSlot value) {
    if (b->count == b->capacity) {
        size_t new_capacity = b->capacity ? b->capacity * 2 : 256;
        ScanCandidate *grown =
            (ScanCandidate *)realloc(b->items, new_capacity * sizeof(ScanCandidate));
        if (!grown) {
            return false;
        }
        b->items = grown;
        b->capacity = new_capacity;
    }
    b->items[b->count].address = address;
    b->items[b->count].has_value = has_value;
    b->items[b->count].value = value;
    b->count++;
    return true;
}

static void scanner_set_candidates(Scanner *s, ScanCandidate *items, size_t count,
                                    size_t capacity) {
    free(s->candidates);
    s->candidates = items;
    s->count = count;
    s->capacity = capacity;
}

void scanner_candidates_free(ScanCandidate *items) {
    free(items);
}

/* --- lifecycle ---------------------------------------------------------------------------- */

void scanner_init(Scanner *s, ProcessIO *process) {
    memset(s, 0, sizeof(*s));
    s->process = process;
    s->kind = MS_TYPE_INT32;
    s->max_hits = SCANNER_DEFAULT_MAX_HITS;
    s->max_scan_bytes = SCANNER_DEFAULT_MAX_SCAN_BYTES;
}

void scanner_free(Scanner *s) {
    free(s->candidates);
    s->candidates = NULL;
    s->count = s->capacity = 0;
}

void scanner_reset(Scanner *s) {
    free(s->candidates);
    s->candidates = NULL;
    s->count = s->capacity = 0;
    s->has_scanned = false;
}

/* --- first_scan --------------------------------------------------------------------------- */

typedef struct {
    Scanner *scanner;
    CandidateBuilder builder;
    const uint8_t *needle;
    size_t needle_len;
    size_t align;
    uint8_t *chunk;
    uint64_t scanned_bytes;
    bool truncated;
} FirstScanCtx;

/* Finds `needle` in `data[0..len)`, non-overlapping, the way ms_find_aligned does, but
 * inserts each aligned hit as it is found so the walk can stop the instant MAX_HITS is
 * reached -- mirroring first_scan()'s immediate `return found` from inside its match loop. */
static bool first_scan_chunk(FirstScanCtx *ctx, uint64_t chunk_address, const uint8_t *data,
                              size_t len) {
    size_t pos = 0;
    while (pos + ctx->needle_len <= len) {
        if (memcmp(data + pos, ctx->needle, ctx->needle_len) == 0) {
            if (pos % ctx->align == 0) {
                MsValue value;
                ms_unpack(data + pos, ctx->needle_len, ctx->scanner->kind, &value);
                if (!builder_append(&ctx->builder, chunk_address + pos, true,
                                     slot_from_value(&value))) {
                    ctx->truncated = true; /* out of memory: stop, keep what we found so far */
                    return true;
                }
                if (ctx->builder.count >= ctx->scanner->max_hits) {
                    ctx->truncated = true;
                    return true; /* stop everything, mid-chunk */
                }
            }
            pos += ctx->needle_len;
        } else {
            pos += 1;
        }
    }
    return false;
}

static int first_scan_region(void *user, uint64_t base, uint64_t region_size) {
    FirstScanCtx *ctx = (FirstScanCtx *)user;
    uint64_t offset = 0;
    while (offset < region_size) {
        uint64_t remaining = region_size - offset;
        size_t span = (size_t)(remaining < SCANNER_CHUNK_SIZE ? remaining : SCANNER_CHUNK_SIZE);
        size_t got = ctx->scanner->process->read(ctx->scanner->process, base + offset,
                                                  ctx->chunk, span);
        if (got > 0) {
            ctx->scanned_bytes += got;
            if (first_scan_chunk(ctx, base + offset, ctx->chunk, got)) {
                return 1;
            }
        }
        offset += span;
    }
    /* Unlike snapshot(), first_scan() only checks the byte cap once a whole region is done. */
    if (ctx->scanned_bytes >= ctx->scanner->max_scan_bytes) {
        ctx->truncated = true;
        return 1;
    }
    return 0;
}

bool scanner_first_scan(Scanner *s, const char *literal, ScanCounts *out, char *err,
                         size_t err_cap) {
    uint8_t needle[MS_MAX_VALUE_SIZE];
    size_t needle_len = 0;
    if (!ms_pack(literal, s->kind, needle, &needle_len, err, err_cap)) {
        return false;
    }

    FirstScanCtx ctx = {0};
    ctx.scanner = s;
    ctx.needle = needle;
    ctx.needle_len = needle_len;
    ctx.align = needle_len;
    ctx.chunk = (uint8_t *)malloc(SCANNER_CHUNK_SIZE);
    if (!ctx.chunk) {
        /* Without a read buffer nothing can be scanned. Report the failure and leave the
         * candidate set untouched, the same contract as an unpackable literal -- rather
         * than silently walking zero regions and reporting "0 addresses hold X" as if
         * memory genuinely held nothing. */
        snprintf(err, err_cap, "out of memory");
        return false;
    }

    s->process->regions(s->process, first_scan_region, &ctx);

    free(ctx.chunk);
    scanner_set_candidates(s, ctx.builder.items, ctx.builder.count, ctx.builder.capacity);
    s->has_scanned = true;
    if (out) {
        out->count = s->count;
        out->truncated = ctx.truncated;
    }
    return true;
}

/* --- snapshot ------------------------------------------------------------------------------ */

typedef struct {
    Scanner *scanner;
    CandidateBuilder builder;
    size_t size;
    uint8_t *chunk;
    uint64_t scanned_bytes;
    bool truncated;
} SnapshotCtx;

static int snapshot_region(void *user, uint64_t base, uint64_t region_size) {
    SnapshotCtx *ctx = (SnapshotCtx *)user;
    uint64_t offset = 0;
    while (offset < region_size) {
        uint64_t remaining = region_size - offset;
        size_t span = (size_t)(remaining < SCANNER_CHUNK_SIZE ? remaining : SCANNER_CHUNK_SIZE);
        size_t got = ctx->scanner->process->read(ctx->scanner->process, base + offset,
                                                  ctx->chunk, span);
        if (got > 0) {
            ctx->scanned_bytes += got;
            size_t at = 0;
            while (at + ctx->size <= got) {
                MsValue value;
                ms_unpack(ctx->chunk + at, ctx->size, ctx->scanner->kind, &value);
                if (!builder_append(&ctx->builder, base + offset + at, true,
                                     slot_from_value(&value))) {
                    ctx->truncated = true; /* out of memory: stop, keep what we found so far */
                    return 1;
                }
                if (ctx->builder.count >= ctx->scanner->max_hits) {
                    ctx->truncated = true;
                    return 1; /* stop everything, mid-chunk */
                }
                at += ctx->size;
            }
        }
        offset += span;
        /* Unlike first_scan(), snapshot() checks the byte cap after every chunk, not just
         * at the end of a region. */
        if (ctx->scanned_bytes >= ctx->scanner->max_scan_bytes) {
            ctx->truncated = true;
            return 1;
        }
    }
    return 0;
}

void scanner_snapshot(Scanner *s, ScanCounts *out) {
    SnapshotCtx ctx = {0};
    ctx.scanner = s;
    ctx.size = ms_type_size(s->kind);
    ctx.chunk = (uint8_t *)malloc(SCANNER_CHUNK_SIZE);

    if (ctx.chunk) {
        s->process->regions(s->process, snapshot_region, &ctx);
        free(ctx.chunk);
    } else {
        /* No read buffer, no scan: this has to be reported as a scan MAX_SCAN_BYTES/MAX_HITS
         * cut short, not as a scan that genuinely found nothing -- snapshot() has no error
         * channel of its own, so `truncated` is the only way to say "this is not the real
         * answer" to the caller. */
        ctx.truncated = true;
    }

    scanner_set_candidates(s, ctx.builder.items, ctx.builder.count, ctx.builder.capacity);
    s->has_scanned = true;
    if (out) {
        out->count = s->count;
        out->truncated = ctx.truncated;
    }
}

/* --- refresh --------------------------------------------------------------------------------- */

void scanner_refresh(const Scanner *s, ScanCandidate **out, size_t *out_count) {
    size_t size = ms_type_size(s->kind);
    CandidateBuilder builder = {0};

    uint8_t page_buf[SCANNER_PAGE_SIZE];
    uint64_t page_base = 0;
    size_t page_len = 0;
    bool have_page = false;
    bool page_ok = false;

    for (size_t i = 0; i < s->count; i++) {
        uint64_t address = s->candidates[i].address;
        uint64_t base = address & ~(SCANNER_PAGE_SIZE - 1);

        if (!have_page || base != page_base) {
            size_t got = s->process->read(s->process, base, page_buf, (size_t)SCANNER_PAGE_SIZE);
            page_ok = got > 0;
            page_len = got;
            page_base = base;
            have_page = true;
        }

        uint64_t at = address - base;
        if (page_ok && at + size <= page_len) {
            MsValue value;
            ms_unpack(page_buf + at, size, s->kind, &value);
            if (!builder_append(&builder, address, true, slot_from_value(&value))) {
                break; /* out of memory: stop early, keep what was already collected */
            }
            continue;
        }

        uint8_t fallback[MS_MAX_VALUE_SIZE];
        size_t got = s->process->read(s->process, address, fallback, size);
        if (got == 0) {
            continue; /* read failed outright: omitted entirely, like a missing dict key */
        }
        if (got < size) {
            /* unpack() would return None here: present, but with no decoded value. */
            ScanSlot empty = {0};
            if (!builder_append(&builder, address, false, empty)) {
                break;
            }
            continue;
        }
        MsValue value;
        ms_unpack(fallback, size, s->kind, &value);
        if (!builder_append(&builder, address, true, slot_from_value(&value))) {
            break;
        }
    }

    *out = builder.items;
    if (out_count) {
        *out_count = builder.count;
    }
}

/* --- narrow_value / narrow_move ---------------------------------------------------------- */

bool scanner_narrow_value(Scanner *s, const char *literal, size_t *out_count, char *err,
                           size_t err_cap) {
    uint8_t packed[MS_MAX_VALUE_SIZE];
    size_t packed_len = 0;
    if (!ms_pack(literal, s->kind, packed, &packed_len, err, err_cap)) {
        return false;
    }
    MsValue target_value;
    ms_unpack(packed, packed_len, s->kind, &target_value);
    ScanSlot target = slot_from_value(&target_value);

    ScanCandidate *fresh = NULL;
    size_t fresh_count = 0;
    scanner_refresh(s, &fresh, &fresh_count);

    size_t kept = 0;
    for (size_t i = 0; i < fresh_count; i++) {
        if (fresh[i].has_value && slot_equal(s->kind, fresh[i].value, target)) {
            fresh[kept++] = fresh[i];
        }
    }

    scanner_set_candidates(s, fresh, kept, fresh_count);
    if (out_count) {
        *out_count = kept;
    }
    return true;
}

size_t scanner_narrow_move(Scanner *s, ScannerMove how) {
    ScanCandidate *fresh = NULL;
    size_t fresh_count = 0;
    scanner_refresh(s, &fresh, &fresh_count);

    /* fresh is built by scanner_refresh() walking s->candidates in exactly that order and
     * omitting only the addresses whose read failed outright -- an order-preserving
     * subsequence of s->candidates, not a sorted array (scanner.h no longer promises
     * ascending address order, and refresh() never reorders). Pairing candidates[oi] with
     * fresh[fi] by that positional correspondence, instead of by walking both arrays with a
     * single cursor under an assumed ascending order, is correct no matter what order the
     * candidates are actually in. The old cursor, given candidates ordered
     * {A+8, A+12288, A+16, A+4096}, would pass A+12288 looking for A+16 and never be able to
     * step back to it, silently dropping a present, matching candidate. */
    CandidateBuilder kept = {0};
    size_t fi = 0;
    for (size_t oi = 0; oi < s->count; oi++) {
        if (fi >= fresh_count || fresh[fi].address != s->candidates[oi].address) {
            continue; /* not in "now": mirrors `if address not in now: continue` */
        }
        const ScanCandidate *now = &fresh[fi];
        const ScanCandidate *was = &s->candidates[oi];
        fi++;

        bool matches;
        switch (how) {
            case SCANNER_MOVE_SAME:
                matches = (now->has_value == was->has_value) &&
                          (!now->has_value || slot_equal(s->kind, now->value, was->value));
                break;
            case SCANNER_MOVE_CHANGED:
                matches = !((now->has_value == was->has_value) &&
                            (!now->has_value || slot_equal(s->kind, now->value, was->value)));
                break;
            case SCANNER_MOVE_UP:
                matches = now->has_value && was->has_value &&
                          slot_compare(s->kind, now->value, was->value) > 0;
                break;
            case SCANNER_MOVE_DOWN:
                matches = now->has_value && was->has_value &&
                          slot_compare(s->kind, now->value, was->value) < 0;
                break;
            default:
                matches = false;
                break;
        }
        if (matches) {
            if (!builder_append(&kept, now->address, now->has_value, now->value)) {
                break; /* out of memory: stop early, keep what was already collected */
            }
        }
    }

    scanner_candidates_free(fresh);
    scanner_set_candidates(s, kept.items, kept.count, kept.capacity);
    return s->count;
}
