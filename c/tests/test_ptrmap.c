/*
 * Tests for ptrmap.c: the PointerMap build caps and pointers_into range query, plus
 * ptrmap_static_of. Mirrors the PointerMap checks in MemScope/tests/selftest.py's
 * offline_checks (the synthetic all-pointers-to-one-value case that forces MAX_HITS).
 */
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

/* A byte-backed fake process: one region, `len` bytes starting at `base`. Mirrors
 * selftest.py's FakeProcess -- regions() yields the one span, read() clamps a request that
 * runs past the end of the blob instead of failing it. */
typedef struct {
    uint64_t base;
    uint8_t *data;
    size_t len;
} FakeProcess;

static void fake_regions(ProcessIO *self, RegionFn visit, void *user) {
    FakeProcess *fp = (FakeProcess *)self->ctx;
    visit(user, fp->base, (uint64_t)fp->len);
}

static size_t fake_read(ProcessIO *self, uint64_t address, void *out, size_t size) {
    FakeProcess *fp = (FakeProcess *)self->ctx;
    if (address < fp->base) {
        return 0;
    }
    uint64_t start = address - fp->base;
    if (start >= fp->len) {
        return 0;
    }
    size_t available = fp->len - (size_t)start;
    size_t n = size < available ? size : available;
    memcpy(out, fp->data + start, n);
    return n;
}

static int fake_write(ProcessIO *self, uint64_t address, const void *data, size_t size) {
    (void)self;
    (void)address;
    (void)data;
    (void)size;
    return 0; /* unused by these tests */
}

static ProcessIO make_fake(FakeProcess *fp) {
    ProcessIO io;
    io.ctx = fp;
    io.regions = fake_regions;
    io.read = fake_read;
    io.write = fake_write;
    return io;
}

/* Mirrors selftest.py's cap case exactly: a 12 MiB region (three 4 MiB chunks, so the
 * MAX_HITS cap has to stop the walk mid-chunk rather than just at the end of the first
 * chunk it happens to land in), every 8-byte slot holding `base + 64` -- a value the region
 * itself makes plausible, so every slot is a hit. */
static void test_max_hits_cap(void) {
    printf("\nPointerMap._build stops at max_hits, not one chunk later\n");

    const uint64_t base = 0x20000000ULL;
    const size_t span = 4u * 1024 * 1024 * 3; /* three chunks */
    const size_t slots = span / 8;
    uint8_t *blob = (uint8_t *)malloc(span);
    if (!blob) {
        check("allocate the 12 MiB fake blob", false, "out of memory");
        return;
    }
    uint64_t pointee = base + 64;
    for (size_t i = 0; i < slots; i++) {
        memcpy(blob + i * 8, &pointee, 8);
    }
    FakeProcess fp = {base, blob, span};
    ProcessIO io = make_fake(&fp);

    PointerMap map;
    pointermap_init(&map);
    map.max_hits = 1000;
    pointermap_build(&map, &io);
    char detail[64];
    snprintf(detail, sizeof(detail), "mapped %zu", map.count);
    check("_build stops at MAX_HITS, not one chunk later", map.count == 1000, detail);
    check("_build reports that it truncated", map.truncated == true, NULL);
    pointermap_free(&map);

    pointermap_init(&map);
    map.max_hits = (uint64_t)slots * 2;
    pointermap_build(&map, &io);
    snprintf(detail, sizeof(detail), "mapped %zu of %zu", map.count, slots);
    check("_build maps everything when under the cap", map.count == slots && !map.truncated,
          detail);

    /* Tie ordering: every pair shares one value, so pairs.sort() on (value, holder) puts
     * them in ascending holder order -- pointers_into must preserve that, not whatever
     * order qsort happened to leave the ties in. */
    PointerHit hits[8];
    size_t total = pointermap_pointers_into(&map, pointee, 0x400, hits, 8);
    bool ordered = total >= 8;
    for (size_t i = 0; ordered && i + 1 < 8; i++) {
        ordered = hits[i].holder < hits[i + 1].holder;
    }
    check("pointers_into returns ties in ascending holder order", ordered, NULL);

    pointermap_free(&map);
    free(blob);
}

static void test_pointers_into(void) {
    printf("\npointers_into range query\n");

    const uint64_t base = 0x20000000ULL;
    const size_t span = 4u * 1024 * 1024;
    const size_t slots = span / 8;
    uint8_t *blob = (uint8_t *)malloc(span);
    if (!blob) {
        check("allocate the fake blob", false, "out of memory");
        return;
    }
    uint64_t pointee = base + 64;
    for (size_t i = 0; i < slots; i++) {
        memcpy(blob + i * 8, &pointee, 8);
    }
    FakeProcess fp = {base, blob, span};
    ProcessIO io = make_fake(&fp);

    PointerMap map;
    pointermap_init(&map);
    pointermap_build(&map, &io);
    char detail[64];
    snprintf(detail, sizeof(detail), "mapped %zu of %zu", map.count, slots);
    check("every slot is plausible and mapped", map.count == slots && !map.truncated, detail);

    size_t total = pointermap_pointers_into(&map, pointee, 0x400, NULL, 0);
    check("target == pointee, offset 0: every slot matches", total == slots, NULL);
    PointerHit hit;
    pointermap_pointers_into(&map, pointee, 0x400, &hit, 1);
    check("offset is target - value == 0", hit.offset == 0, NULL);

    total = pointermap_pointers_into(&map, pointee + 0x100, 0x400, &hit, 1);
    check("target shifted by 0x100: every slot still matches", total == slots, NULL);
    check("offset follows the shift", hit.offset == 0x100, NULL);

    total = pointermap_pointers_into(&map, pointee - 1, 0x400, NULL, 0);
    check("target one below pointee: no slot matches", total == 0, NULL);

    total = pointermap_pointers_into(&map, 0, 0x400, NULL, 0);
    check("target 0 with max_offset > target: no underflow, no matches", total == 0, NULL);

    pointermap_free(&map);
    free(blob);
}

/* A multi-region fake process: up to four separately-backed spans, visited by regions() in
 * whatever order the caller lists them in -- unlike FakeProcess above, deliberately not
 * sorted by base, to exercise plausible()'s binary search against an out-of-order backend. */
typedef struct {
    uint64_t base;
    uint8_t *data;
    size_t len;
} FakeRegion;

typedef struct {
    FakeRegion regions[4];
    int count;
} MultiRegionFake;

static void multi_regions(ProcessIO *self, RegionFn visit, void *user) {
    MultiRegionFake *mf = (MultiRegionFake *)self->ctx;
    for (int i = 0; i < mf->count; i++) {
        visit(user, mf->regions[i].base, (uint64_t)mf->regions[i].len);
    }
}

static size_t multi_read(ProcessIO *self, uint64_t address, void *out, size_t size) {
    MultiRegionFake *mf = (MultiRegionFake *)self->ctx;
    for (int i = 0; i < mf->count; i++) {
        FakeRegion *r = &mf->regions[i];
        if (address >= r->base && address - r->base < r->len) {
            uint64_t start = address - r->base;
            size_t available = r->len - (size_t)start;
            size_t n = size < available ? size : available;
            memcpy(out, r->data + start, n);
            return n;
        }
    }
    return 0;
}

static int multi_write(ProcessIO *self, uint64_t address, const void *data, size_t size) {
    (void)self;
    (void)address;
    (void)data;
    (void)size;
    return 0; /* unused by this test */
}

static ProcessIO make_multi(MultiRegionFake *mf) {
    ProcessIO io;
    io.ctx = mf;
    io.regions = multi_regions;
    io.read = multi_read;
    io.write = multi_write;
    return io;
}

/* Mirrors ptrscan.py's `self.region_bounds = sorted(...)` guarding plausible() against
 * whatever order regions() happens to enumerate in. Three regions are reported as
 * C, A, B -- base addresses 0x30000000, 0x10000000, 0x20000000 -- which is not ascending.
 * A pointer into C is stored inside A. A binary search that assumes the base array it is
 * searching is already ascending walks past A's entry (base 0x10000000, mid of the
 * unsorted array) looking for something above it and never returns, so the C-pointing
 * value stored in A gets misjudged against B's bounds instead of A's own -- exactly the
 * bug the out-of-order enumeration triggers if the bounds are not sorted first. */
static void test_out_of_order_regions(void) {
    printf("\nplausible() does not depend on regions() enumeration order\n");

    const uint64_t base_a = 0x10000000ULL;
    const uint64_t base_b = 0x20000000ULL;
    const uint64_t base_c = 0x30000000ULL;
    const size_t region_len = 0x1000;

    uint8_t data_a[0x1000];
    uint8_t data_b[0x1000];
    uint8_t data_c[0x1000];
    memset(data_a, 0, sizeof(data_a));
    memset(data_b, 0, sizeof(data_b));
    memset(data_c, 0, sizeof(data_c));

    uint64_t target_value = base_c + 0x500;
    memcpy(data_a, &target_value, sizeof(target_value));

    MultiRegionFake mf;
    mf.count = 3;
    mf.regions[0].base = base_c;
    mf.regions[0].data = data_c;
    mf.regions[0].len = region_len;
    mf.regions[1].base = base_a;
    mf.regions[1].data = data_a;
    mf.regions[1].len = region_len;
    mf.regions[2].base = base_b;
    mf.regions[2].data = data_b;
    mf.regions[2].len = region_len;
    ProcessIO io = make_multi(&mf);

    PointerMap map;
    pointermap_init(&map);
    pointermap_build(&map, &io);

    char detail[64];
    snprintf(detail, sizeof(detail), "mapped %zu", map.count);
    check("a pointer stored in an out-of-order region is not dropped", map.count == 1, detail);

    PointerHit hit;
    size_t total = pointermap_pointers_into(&map, target_value, 0x10, &hit, 1);
    check("it resolves to the slot that actually holds it", total == 1 && hit.holder == base_a,
          NULL);

    pointermap_free(&map);
}

static void test_static_of(void) {
    printf("\nptrmap_static_of\n");

    ModuleEntry modules[3];
    memset(modules, 0, sizeof(modules));
    strncpy(modules[0].name, "game.exe", MODULE_NAME_MAX - 1);
    modules[0].base = 0x00400000;
    modules[0].size = 0x00100000;
    strncpy(modules[1].name, "engine.dll", MODULE_NAME_MAX - 1);
    modules[1].base = 0x10000000;
    modules[1].size = 0x00050000;
    strncpy(modules[2].name, "ui.dll", MODULE_NAME_MAX - 1);
    modules[2].base = 0x20000000;
    modules[2].size = 0x00010000;

    const ModuleEntry *found = NULL;
    uint64_t offset = 0;
    bool ok = ptrmap_static_of(modules, 3, 0x10001234, &found, &offset);
    check("finds the module containing an interior address", ok && found == &modules[1] &&
                                                                   offset == 0x1234,
          NULL);

    ok = ptrmap_static_of(modules, 3, modules[0].base, &found, &offset);
    check("base address itself resolves at offset 0", ok && found == &modules[0] &&
                                                            offset == 0,
          NULL);

    ok = ptrmap_static_of(modules, 3, modules[1].base + modules[1].size, &found, &offset);
    check("one past a module's end belongs to no module", !ok, NULL);

    ok = ptrmap_static_of(modules, 3, 0x1000, &found, &offset);
    check("an address below every module's base belongs to no module", !ok, NULL);
}

int main(void) {
    test_max_hits_cap();
    test_pointers_into();
    test_out_of_order_regions();
    test_static_of();

    printf("\n");
    if (failures) {
        printf("FAILED: %d check(s)\n", failures);
        return 1;
    }
    printf("all checks pass\n");
    return 0;
}
