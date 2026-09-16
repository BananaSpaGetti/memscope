/*
 * Tests for ptrpath.c: the frontier-cap dropped count and scan_limits text, a full
 * multi-level find_paths + resolve walk against synthetic modules and a fake process,
 * and the parse_path/format_path round-trip -- cross-checked against ptrscan.py (see the
 * comment above test_round_trip()).
 */
#include "ptrpath.h"
#include "ptrmap.h"
#include "process.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;

static void check(const char *name, bool ok, const char *detail) {
    printf("  %s  %s%s%s\n", ok ? "ok  " : "FAIL", name, detail ? "  " : "", detail ? detail : "");
    if (!ok) {
        failures++;
    }
}

/* A tiny address-keyed fake process for resolve(): each entry is one 8-byte
 * little-endian pointer value at one address; any other address fails the read. */
typedef struct {
    uint64_t addr;
    uint64_t value;
} FakeSlot;

typedef struct {
    const FakeSlot *slots;
    int count;
} FakeProcess;

static size_t fake_read(ProcessIO *self, uint64_t address, void *out, size_t size) {
    FakeProcess *fp = (FakeProcess *)self->ctx;
    for (int i = 0; i < fp->count; i++) {
        if (fp->slots[i].addr == address) {
            uint64_t v = fp->slots[i].value;
            size_t n = size < 8 ? size : 8;
            memcpy(out, &v, n);
            return n;
        }
    }
    return 0;
}

static void fake_regions(ProcessIO *self, RegionFn visit, void *user) {
    (void)self;
    (void)visit;
    (void)user;
}

static int fake_write(ProcessIO *self, uint64_t address, const void *data, size_t size) {
    (void)self;
    (void)address;
    (void)data;
    (void)size;
    return 0;
}

static ProcessIO make_fake(FakeProcess *fp) {
    ProcessIO io;
    io.ctx = fp;
    io.regions = fake_regions;
    io.read = fake_read;
    io.write = fake_write;
    return io;
}

/* Mirrors the exact-dropped-count design in the plan: depth 1, N holders all pointing
 * straight at the target (offset 0), no modules loaded, so every holder is non-static
 * and either enters the next frontier or is dropped by max_frontier. With depth 1 the
 * walk never reaches a second level, so `dropped` is arithmetic: exactly N - k. */
static void test_frontier_cap_exact(void) {
    printf("\nfrontier cap: dropped count is exact\n");

    const uint64_t target = 0x500000;
    const int n = 20;
    const size_t k = 7;
    PointerPair pairs[20];
    for (int i = 0; i < n; i++) {
        pairs[i].value = target; /* every holder points straight at the target */
        pairs[i].holder = 0x600000 + (uint64_t)i * 8;
    }

    PointerMap map;
    pointermap_init(&map);
    map.pairs = pairs;
    map.count = (size_t)n;
    map.truncated = false;

    PathResult *out = NULL;
    size_t out_count = 0, dropped = 0;
    bool ok = ptrpath_find(&map, NULL, 0, target, /*depth=*/1, /*max_offset=*/0x10,
                            /*max_paths=*/1000, /*max_frontier=*/k, &out, &out_count,
                            &dropped);
    char detail[64];
    snprintf(detail, sizeof(detail), "dropped=%zu, expected=%d", dropped, n - (int)k);
    check("ptrpath_find succeeded", ok, NULL);
    check("no modules loaded means no result can be static", out_count == 0, NULL);
    check("dropped == N - max_frontier exactly", dropped == (size_t)(n - (int)k), detail);
    ptrpath_free_results(out, out_count);

    char lines[2][PTRPATH_LIMIT_LINE_MAX];
    int nlines = ptrpath_scan_limits(&map, dropped, lines);
    check("scan_limits reports the cap when it fired", nlines == 1, NULL);
    if (nlines == 1) {
        char expected[PTRPATH_LIMIT_LINE_MAX];
        snprintf(expected, sizeof(expected),
                 "  (frontier capped -- %zu branch(es) were not explored)", dropped);
        check("scan_limits text matches ptrscan.py's exactly", strcmp(lines[0], expected) == 0,
              lines[0]);
    }

    /* Raise the cap above every holder: nothing dropped, scan_limits stays silent. */
    out = NULL;
    out_count = 0;
    dropped = 0;
    ok = ptrpath_find(&map, NULL, 0, target, 1, 0x10, 1000, (size_t)n + 1, &out, &out_count,
                       &dropped);
    check("ptrpath_find succeeded (uncapped)", ok, NULL);
    check("dropped == 0 when the cap does not fire", dropped == 0, NULL);
    ptrpath_free_results(out, out_count);
    nlines = ptrpath_scan_limits(&map, dropped, lines);
    check("scan_limits stays silent when nothing was capped", nlines == 0, NULL);

    /* A pointer-map cap firing too produces the other line, first. */
    map.truncated = true;
    map.max_hits = 1234;
    dropped = 3;
    nlines = ptrpath_scan_limits(&map, dropped, lines);
    check("scan_limits reports both caps when both fired", nlines == 2, NULL);
    if (nlines == 2) {
        check("pointer-map line comes first",
              strstr(lines[0], "pointer map capped at 1234 slots") != NULL, lines[0]);
        check("frontier line is second",
              strstr(lines[1], "frontier capped -- 3 branch(es)") != NULL, lines[1]);
    }
}

/* A concrete two-hop path: game.exe+0x10 -> 0x8 -> 0x20, worked out by hand and checked
 * against find_paths against a fake process:
 *   S  = 0x00400010 (inside game.exe, offset 0x10) holds V1 = 0x005FFFF8
 *   H1 = V1 + 0x8   = 0x00600000                  holds V2 = target - 0x20
 *   target = 0x00700000, so V2 = 0x006FFFE0
 * find_paths should discover H1 at level 0 (offset target-V2 = 0x20), then S at level 1
 * (offset H1-V1 = 0x8, and S is static), giving offsets [0x8, 0x20] -- resolve() on that
 * result must land back on target. */
static void test_multilevel_path_and_resolve(void) {
    printf("\nmulti-level path against synthetic modules, then resolve\n");

    const uint64_t target = 0x00700000ULL;
    const uint64_t s_addr = 0x00400010ULL;
    const uint64_t v1 = 0x005FFFF8ULL;
    const uint64_t h1_addr = v1 + 0x8; /* 0x00600000 */
    const uint64_t v2 = target - 0x20; /* 0x006FFFE0 */

    PointerPair pairs[2];
    pairs[0].value = v1;
    pairs[0].holder = s_addr;
    pairs[1].value = v2;
    pairs[1].holder = h1_addr;
    /* v1 < v2, so this is already in the ascending-by-value order pointermap_build
     * would have sorted it into. */

    PointerMap map;
    pointermap_init(&map);
    map.pairs = pairs;
    map.count = 2;

    ModuleEntry modules[1];
    memset(modules, 0, sizeof(modules));
    strncpy(modules[0].name, "game.exe", MODULE_NAME_MAX - 1);
    modules[0].base = 0x00400000ULL;
    modules[0].size = 0x00001000ULL;

    PathResult *out = NULL;
    size_t out_count = 0, dropped = 0;
    bool ok = ptrpath_find(&map, modules, 1, target, /*depth=*/3, /*max_offset=*/0x400,
                            /*max_paths=*/40, /*max_frontier=*/200000, &out, &out_count,
                            &dropped);
    check("ptrpath_find succeeded", ok, NULL);
    check("exactly one static path found", out_count == 1, NULL);
    if (out_count == 1) {
        check("found in game.exe", strcmp(out[0].module_name, "game.exe") == 0,
              out[0].module_name);
        check("module offset is 0x10", out[0].module_offset == 0x10, NULL);
        check("two offsets in forward order",
              out[0].offset_count == 2 && out[0].offsets[0] == 0x8 &&
                  out[0].offsets[1] == 0x20,
              NULL);

        char formatted[128];
        ptrpath_format(out[0].module_name, out[0].module_offset, out[0].offsets,
                        out[0].offset_count, formatted, sizeof(formatted));
        check("formats as game.exe+0x10 -> 0x8 -> 0x20",
              strcmp(formatted, "game.exe+0x10 -> 0x8 -> 0x20") == 0, formatted);

        FakeSlot slots[2] = {{s_addr, v1}, {h1_addr, v2}};
        FakeProcess fp = {slots, 2};
        ProcessIO io = make_fake(&fp);
        uint64_t resolved = 0;
        bool resolved_ok =
            ptrpath_resolve(&io, out[0].module_name, out[0].module_offset, out[0].offsets,
                             out[0].offset_count, modules, 1, &resolved);
        check("resolve() walks the path back to the target",
              resolved_ok && resolved == target, NULL);

        bool missing_ok = ptrpath_resolve(&io, "no-such.dll", 0, out[0].offsets,
                                           out[0].offset_count, modules, 1, &resolved);
        check("resolve() fails on a module that is not loaded", !missing_ok, NULL);
    }
    ptrpath_free_results(out, out_count);
}

/* parse_path/format_path round-trip, cross-checked against ptrscan.py directly:
 *   py -c "... m.parse_path(t) ... m.format_path(*parsed) ..."
 * confirmed every canonical string below round-trips unchanged through the Python, the
 * non-canonical input parses to (module='game.exe', offset=16, offsets=[24]), and
 * "game.exe" alone (no '+') raises ValueError in the Python -- this parser reports that
 * as a plain parse failure instead of a crash, which is the documented difference. */
static void test_round_trip(void) {
    printf("\nparse_path / format_path round-trip (cross-checked against ptrscan.py)\n");

    static const char *canonical[] = {
        "game.exe+0x1A2B3C -> 0x18 -> 0x40",
        "engine.dll+0x0",
        "ui.dll+0xFF -> 0x0 -> 0x8 -> 0x10",
        "a.exe+0x100 -> 0x400",
        "game.exe+0x10 -> 0x8 -> 0x20",
    };
    for (size_t i = 0; i < sizeof(canonical) / sizeof(canonical[0]); i++) {
        char module_name[MODULE_NAME_MAX];
        uint64_t module_offset = 0;
        uint64_t offsets[8];
        int offset_count = 0;
        bool ok = ptrpath_parse(canonical[i], module_name, sizeof(module_name),
                                 &module_offset, offsets, 8, &offset_count, NULL);
        char detail[160];
        snprintf(detail, sizeof(detail), "'%s'", canonical[i]);
        check("parses", ok, detail);
        if (!ok) {
            continue;
        }
        char formatted[160];
        ptrpath_format(module_name, module_offset, offsets, offset_count, formatted,
                        sizeof(formatted));
        check("format(parse(s)) == s", strcmp(formatted, canonical[i]) == 0, formatted);
    }

    /* Non-canonical spacing/prefix still parses to the same tuple ptrscan.py produced. */
    char module_name[MODULE_NAME_MAX];
    uint64_t module_offset = 0;
    uint64_t offsets[8];
    int offset_count = 0;
    bool ok = ptrpath_parse("game.exe+10->0x18", module_name, sizeof(module_name),
                             &module_offset, offsets, 8, &offset_count, NULL);
    check("non-canonical input parses", ok, NULL);
    check("module name matches", ok && strcmp(module_name, "game.exe") == 0, NULL);
    check("offset without a 0x prefix is still base 16", ok && module_offset == 0x10, NULL);
    check("one trailing offset", ok && offset_count == 1 && offsets[0] == 0x18, NULL);

    /* A head with no '+' is what raises ValueError in the Python; this parser reports
     * failure instead of crashing. */
    ok = ptrpath_parse("game.exe", module_name, sizeof(module_name), &module_offset, offsets,
                        8, &offset_count, NULL);
    check("a path with no '+' is rejected, not crashed on", !ok, NULL);
}

/* Where an over-wide hex piece sits, which decides whether the resolve that follows is a real
 * failure or the one divergence ptrpath.h documents.
 *
 * This lives here and not in the differential harness because that harness cannot hold it:
 * for the final-piece case the two implementations are SUPPOSED to disagree -- ptrscan.py
 * prints an address wider than 64 bits and this port cannot represent one. Until the position
 * was reported, that case printed "could not resolve (module not found or a hop read
 * failed)", which names two causes that are both false there and is byte-identical to what a
 * misspelled module name prints. A documented limitation indistinguishable from a typo is
 * also one nothing can test; this is what makes it testable. */
static void test_oversized_piece_position(void) {
    printf("\nwhere an over-wide hex piece sits\n");
    const char *huge = "0xFFFFFFFFFFFFFFFFFF";   /* a valid literal, far past uint64_t */
    char module_name[64];
    uint64_t module_offset = 0;
    uint64_t offsets[8];
    int offset_count = 0;
    int oversized_at = -1;
    char path[256];

    check("nothing over-wide reports -1",
          ptrpath_parse("game.exe+0x10 -> 0x8", module_name, sizeof(module_name),
                         &module_offset, offsets, 8, &offset_count, &oversized_at)
          && oversized_at == -1, NULL);

    oversized_at = -1;
    snprintf(path, sizeof(path), "game.exe+%s", huge);
    check("an over-wide module offset with no hops is position 0, the final piece",
          ptrpath_parse(path, module_name, sizeof(module_name), &module_offset, offsets, 8,
                         &offset_count, &oversized_at)
          && oversized_at == 0 && offset_count == 0, NULL);

    oversized_at = -1;
    snprintf(path, sizeof(path), "game.exe+0x10 -> %s", huge);
    check("an over-wide last hop is position 1 of 1, the final piece",
          ptrpath_parse(path, module_name, sizeof(module_name), &module_offset, offsets, 8,
                         &offset_count, &oversized_at)
          && oversized_at == 1 && offset_count == 1, NULL);

    oversized_at = -1;
    snprintf(path, sizeof(path), "game.exe+0x10 -> %s -> 0x8", huge);
    check("an over-wide EARLIER hop is position 1 of 2, so its address is read and the "
          "resolve really does fail",
          ptrpath_parse(path, module_name, sizeof(module_name), &module_offset, offsets, 8,
                         &offset_count, &oversized_at)
          && oversized_at == 1 && offset_count == 2, NULL);

    oversized_at = -1;
    snprintf(path, sizeof(path), "game.exe+%s -> 0x8", huge);
    check("an over-wide module offset WITH a hop is position 0 of 1, also read",
          ptrpath_parse(path, module_name, sizeof(module_name), &module_offset, offsets, 8,
                         &offset_count, &oversized_at)
          && oversized_at == 0 && offset_count == 1, NULL);

    /* Only the first is recorded: it is the one that decides what happens. */
    oversized_at = -1;
    snprintf(path, sizeof(path), "game.exe+%s -> %s", huge, huge);
    check("two over-wide pieces report the first",
          ptrpath_parse(path, module_name, sizeof(module_name), &module_offset, offsets, 8,
                         &offset_count, &oversized_at) && oversized_at == 0, NULL);

    /* An over-wide piece is a valid literal, never a parse failure -- ptrscan.py's int() has
     * no width, so refusing it here would turn a resolve failure into a parse error. */
    oversized_at = -1;
    check("a MALFORMED piece is still a parse failure",
          !ptrpath_parse("game.exe+0x10 -> zzz", module_name, sizeof(module_name),
                          &module_offset, offsets, 8, &offset_count, &oversized_at), NULL);
}

int main(void) {
    test_frontier_cap_exact();
    test_multilevel_path_and_resolve();
    test_round_trip();
    test_oversized_piece_position();

    printf("\n");
    if (failures) {
        printf("FAILED: %d check(s)\n", failures);
        return 1;
    }
    printf("all checks pass\n");
    return 0;
}
