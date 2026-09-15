/*
 * Tests for scanner.c: the page-batched refresh() checked against a naive one-read-per-
 * candidate oracle, first_scan/snapshot/narrow_value/narrow_move against a fake process,
 * and the bad-literal contract (candidate set left untouched). Mirrors the offline
 * Scanner checks in MemScope/tests/selftest.py's offline_checks -- the same synthetic
 * blob, the same dead-page sets, and the same page-boundary-straddling addresses.
 *
 * This is what finally exercises scanner.c: it was committed with nothing able to reach
 * it, which is why task 5 stayed marked failed until this file existed.
 */
#include "scanner.h"
#include "process.h"
#include "values.h"

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

/* --- a byte-backed fake process with settable dead pages --------------------------------- */

#define FAKE_PAGE 4096u

typedef struct {
    uint64_t base;
    uint8_t *data;
    size_t len;
    const uint64_t *dead_pages;
    size_t dead_count;
} FakeProcess;

static void fake_regions(ProcessIO *self, RegionFn visit, void *user) {
    FakeProcess *fp = (FakeProcess *)self->ctx;
    visit(user, fp->base, (uint64_t)fp->len);
}

/* Mirrors selftest.py's FakeProcess.read exactly: a read whose byte range overlaps any
 * dead page fails outright (regardless of how much of the range is actually inside that
 * page), and a read starting past the end of the data fails outright too -- but a read
 * that starts inside the data and merely runs past its end is clamped, not failed, the
 * way a Python slice silently returns fewer bytes than asked for. */
static size_t fake_read(ProcessIO *self, uint64_t address, void *out, size_t size) {
    FakeProcess *fp = (FakeProcess *)self->ctx;
    for (size_t i = 0; i < fp->dead_count; i++) {
        uint64_t page = fp->dead_pages[i];
        if (address < page + FAKE_PAGE && page < address + size) {
            return 0;
        }
    }
    if (address < fp->base) {
        return 0;
    }
    uint64_t start = address - fp->base;
    if (start >= (uint64_t)fp->len) {
        return 0;
    }
    size_t available = fp->len - (size_t)start;
    size_t n = size < available ? size : available;
    memcpy(out, fp->data + start, n);
    return n;
}

static int fake_write(ProcessIO *self, uint64_t address, const void *data, size_t size) {
    FakeProcess *fp = (FakeProcess *)self->ctx;
    if (address < fp->base) {
        return 0;
    }
    uint64_t start = address - fp->base;
    if (start >= (uint64_t)fp->len || fp->len - (size_t)start < size) {
        return 0;
    }
    memcpy(fp->data + start, data, size);
    return 1;
}

static ProcessIO make_fake(FakeProcess *fp) {
    ProcessIO io;
    io.ctx = fp;
    io.regions = fake_regions;
    io.read = fake_read;
    io.write = fake_write;
    return io;
}

/* --- shared helpers -------------------------------------------------------------------- */

static ScanSlot slot_from_msvalue(const MsValue *v) {
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

static int compare_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

/* Sorts `addrs[0..n)` and drops duplicates in place, returning the new count -- the C
 * equivalent of selftest.py's `sorted(set(addresses))`. */
static size_t dedupe_sorted(uint64_t *addrs, size_t n) {
    if (n == 0) {
        return 0;
    }
    qsort(addrs, n, sizeof(uint64_t), compare_u64);
    size_t out = 1;
    for (size_t i = 1; i < n; i++) {
        if (addrs[i] != addrs[out - 1]) {
            addrs[out++] = addrs[i];
        }
    }
    return out;
}

/* One ReadProcessMemory per address, exactly the size the type needs -- kept verbatim as
 * the oracle refresh() has to agree with, matching selftest.py's old_refresh(). An address
 * whose read fails outright (returns 0) is dropped, like a missing Python dict key; a
 * short-but-nonzero read is kept with has_value=false, like Python's `out[address] = None`. */
static void oracle_refresh(ProcessIO *io, MsType kind, const uint64_t *addrs, size_t n,
                            ScanCandidate **out, size_t *out_count) {
    size_t type_size = ms_type_size(kind);
    ScanCandidate *arr = (ScanCandidate *)malloc((n ? n : 1) * sizeof(ScanCandidate));
    size_t count = 0;
    for (size_t i = 0; i < n; i++) {
        uint8_t buf[MS_MAX_VALUE_SIZE];
        size_t got = io->read(io, addrs[i], buf, type_size);
        if (got == 0) {
            continue;
        }
        if (got < type_size) {
            ScanSlot empty = {0};
            arr[count].address = addrs[i];
            arr[count].has_value = false;
            arr[count].value = empty;
            count++;
            continue;
        }
        MsValue value;
        ms_unpack(buf, type_size, kind, &value);
        arr[count].address = addrs[i];
        arr[count].has_value = true;
        arr[count].value = slot_from_msvalue(&value);
        count++;
    }
    *out = arr;
    *out_count = count;
}

/* Compares two candidate sets as the sets of (address, has_value, value) they represent --
 * not assuming either array is sorted, since the unsorted-candidates test deliberately
 * is not. Returns true, and leaves `detail` untouched, only if they match exactly. */
static bool sets_match(MsType kind, const ScanCandidate *expected, size_t en,
                        const ScanCandidate *actual, size_t an, char *detail, size_t detail_cap) {
    if (en != an) {
        snprintf(detail, detail_cap, "expected %zu candidates, got %zu", en, an);
        return false;
    }
    for (size_t i = 0; i < en; i++) {
        const ScanCandidate *want = &expected[i];
        const ScanCandidate *got = NULL;
        for (size_t j = 0; j < an; j++) {
            if (actual[j].address == want->address) {
                got = &actual[j];
                break;
            }
        }
        if (!got) {
            snprintf(detail, detail_cap, "address %llX missing from actual",
                     (unsigned long long)want->address);
            return false;
        }
        if (got->has_value != want->has_value) {
            snprintf(detail, detail_cap, "address %llX has_value %d, expected %d",
                     (unsigned long long)want->address, got->has_value, want->has_value);
            return false;
        }
        if (want->has_value && !slot_equal(kind, got->value, want->value)) {
            snprintf(detail, detail_cap, "address %llX value differs", (unsigned long long)want->address);
            return false;
        }
    }
    return true;
}

/* --- refresh() against the oracle, across types, dead pages and page-boundary straddles - */

static void test_refresh_matches_oracle(void) {
    printf("\nrefresh() matches a one-read-per-candidate oracle\n");

    const uint64_t base = 0x10000000ULL;
    const size_t blob_len = FAKE_PAGE * 4;
    uint8_t *blob = (uint8_t *)malloc(blob_len);
    if (!blob) {
        check("allocate the synthetic blob", false, "out of memory");
        return;
    }
    for (size_t i = 0; i < blob_len; i++) {
        blob[i] = (uint8_t)((i * 7 + 3) & 0xFF);
    }

    const uint64_t dead_none[1] = {0};
    const uint64_t dead_one[1] = {base + FAKE_PAGE};
    const uint64_t dead_two[2] = {base, base + FAKE_PAGE * 3};
    struct {
        const uint64_t *pages;
        size_t count;
    } dead_sets[3] = {
        {dead_none, 0},
        {dead_one, 1},
        {dead_two, 2},
    };

    const char *kinds[] = {"int8", "uint8", "int16", "uint16", "int32", "uint32",
                            "int64", "uint64", "float", "double"};

    for (size_t k = 0; k < sizeof(kinds) / sizeof(kinds[0]); k++) {
        MsType kind;
        if (!ms_resolve_type(kinds[k], &kind)) {
            check(kinds[k], false, "resolve_type failed");
            continue;
        }
        size_t size = ms_type_size(kind);

        for (size_t d = 0; d < 3; d++) {
            FakeProcess fp = {base, blob, blob_len, dead_sets[d].pages, dead_sets[d].count};
            ProcessIO io = make_fake(&fp);

            /* Both sides of every page boundary, and the value that hangs over it. */
            uint64_t addrs[4 * 5 + 2];
            size_t n = 0;
            for (int page = 0; page < 4; page++) {
                uint64_t edge = base + (uint64_t)page * FAKE_PAGE;
                addrs[n++] = edge;
                addrs[n++] = edge + 1;
                addrs[n++] = edge + FAKE_PAGE - size;
                addrs[n++] = edge + FAKE_PAGE - size + 1;
                addrs[n++] = edge + FAKE_PAGE - 1;
            }
            addrs[n++] = base + FAKE_PAGE * 4 - 1; /* last byte */
            addrs[n++] = base + FAKE_PAGE * 4 + 8; /* past the end */
            n = dedupe_sorted(addrs, n);

            Scanner s;
            scanner_init(&s, &io);
            s.kind = kind;
            s.candidates = (ScanCandidate *)malloc(n * sizeof(ScanCandidate));
            for (size_t i = 0; i < n; i++) {
                s.candidates[i].address = addrs[i];
                s.candidates[i].has_value = false;
                s.candidates[i].value.u = 0;
            }
            s.count = n;
            s.capacity = n;
            s.has_scanned = true;

            ScanCandidate *actual = NULL;
            size_t actual_count = 0;
            scanner_refresh(&s, &actual, &actual_count);

            ScanCandidate *expected = NULL;
            size_t expected_count = 0;
            oracle_refresh(&io, kind, addrs, n, &expected, &expected_count);

            char detail[128] = {0};
            bool ok = sets_match(kind, expected, expected_count, actual, actual_count, detail,
                                  sizeof(detail));
            char name[96];
            snprintf(name, sizeof(name), "refresh matches the oracle  %-6s %zu dead page(s)",
                     kinds[k], dead_sets[d].count);
            check(name, ok, ok ? NULL : detail);

            scanner_candidates_free(actual);
            free(expected);
            scanner_free(&s);
        }
    }

    free(blob);
}

static void test_refresh_unsorted_candidates(void) {
    printf("\nrefresh() is correct on unsorted candidates\n");

    const uint64_t base = 0x10000000ULL;
    const size_t blob_len = FAKE_PAGE * 4;
    uint8_t *blob = (uint8_t *)malloc(blob_len);
    if (!blob) {
        check("allocate the synthetic blob", false, "out of memory");
        return;
    }
    for (size_t i = 0; i < blob_len; i++) {
        blob[i] = (uint8_t)((i * 7 + 3) & 0xFF);
    }
    FakeProcess fp = {base, blob, blob_len, NULL, 0};
    ProcessIO io = make_fake(&fp);

    /* Deliberately out of address order: base+PAGE*3 sits before base+16. */
    uint64_t addrs[4] = {base + 8, base + FAKE_PAGE * 3, base + 16, base + FAKE_PAGE};

    Scanner s;
    scanner_init(&s, &io);
    s.kind = MS_TYPE_INT32;
    s.candidates = (ScanCandidate *)malloc(4 * sizeof(ScanCandidate));
    for (int i = 0; i < 4; i++) {
        s.candidates[i].address = addrs[i];
        s.candidates[i].has_value = false;
        s.candidates[i].value.u = 0;
    }
    s.count = 4;
    s.capacity = 4;
    s.has_scanned = true;

    ScanCandidate *actual = NULL;
    size_t actual_count = 0;
    scanner_refresh(&s, &actual, &actual_count);

    ScanCandidate *expected = NULL;
    size_t expected_count = 0;
    oracle_refresh(&io, MS_TYPE_INT32, addrs, 4, &expected, &expected_count);

    char detail[128] = {0};
    bool ok = sets_match(MS_TYPE_INT32, expected, expected_count, actual, actual_count, detail,
                          sizeof(detail));
    check("refresh matches the oracle on unsorted input", ok, ok ? NULL : detail);

    scanner_candidates_free(actual);
    free(expected);
    scanner_free(&s);
    free(blob);
}

/* --- first_scan / snapshot / narrow_value / narrow_move against the fake process --------- */

static void write_i32(uint8_t *buf, size_t offset, int32_t v) {
    memcpy(buf + offset, &v, sizeof(v));
}

static void test_first_scan(void) {
    printf("\nfirst_scan against the fake process\n");

    const uint64_t base = 0x40000000ULL;
    uint8_t blob[24];
    int32_t values[6] = {1234, 0, 1234, 7, 9, 1234};
    for (int i = 0; i < 6; i++) {
        write_i32(blob, (size_t)i * 4, values[i]);
    }
    FakeProcess fp = {base, blob, sizeof(blob), NULL, 0};
    ProcessIO io = make_fake(&fp);

    Scanner s;
    scanner_init(&s, &io);
    s.kind = MS_TYPE_INT32;

    ScanCounts counts;
    char err[128] = {0};
    bool ok = scanner_first_scan(&s, "1234", &counts, err, sizeof(err));
    check("first_scan succeeds", ok, ok ? NULL : err);
    check("first_scan finds exactly the three matches", counts.count == 3, NULL);
    check("first_scan does not report a cap", !counts.truncated, NULL);

    bool addr0 = false, addr8 = false, addr20 = false;
    for (size_t i = 0; i < s.count; i++) {
        if (s.candidates[i].address == base + 0 && s.candidates[i].has_value &&
            s.candidates[i].value.i == 1234) {
            addr0 = true;
        }
        if (s.candidates[i].address == base + 8 && s.candidates[i].has_value &&
            s.candidates[i].value.i == 1234) {
            addr8 = true;
        }
        if (s.candidates[i].address == base + 20 && s.candidates[i].has_value &&
            s.candidates[i].value.i == 1234) {
            addr20 = true;
        }
    }
    check("match at offset 0", addr0, NULL);
    check("match at offset 8", addr8, NULL);
    check("match at offset 20", addr20, NULL);

    /* A literal that cannot be packed leaves the candidate set exactly as it was. */
    size_t before_count = s.count;
    ok = scanner_first_scan(&s, "zzz", NULL, err, sizeof(err));
    check("first_scan rejects an unpackable literal", !ok, NULL);
    check("candidate set is untouched after the rejection", s.count == before_count, NULL);

    scanner_free(&s);
}

static void test_snapshot_and_narrow_value(void) {
    printf("\nsnapshot() and narrow_value() against the fake process\n");

    const uint64_t base = 0x41000000ULL;
    uint8_t blob[20];
    int32_t values[5] = {10, 20, 30, 40, 50};
    for (int i = 0; i < 5; i++) {
        write_i32(blob, (size_t)i * 4, values[i]);
    }
    FakeProcess fp = {base, blob, sizeof(blob), NULL, 0};
    ProcessIO io = make_fake(&fp);

    Scanner s;
    scanner_init(&s, &io);
    s.kind = MS_TYPE_INT32;

    ScanCounts counts;
    scanner_snapshot(&s, &counts);
    check("snapshot records every aligned slot", counts.count == 5, NULL);
    check("snapshot does not report a cap", !counts.truncated, NULL);

    bool values_ok = true;
    for (int i = 0; i < 5; i++) {
        uint64_t addr = base + (uint64_t)i * 4;
        bool found = false;
        for (size_t j = 0; j < s.count; j++) {
            if (s.candidates[j].address == addr) {
                found = s.candidates[j].has_value && s.candidates[j].value.i == values[i];
                break;
            }
        }
        values_ok = values_ok && found;
    }
    check("snapshot recorded the current value at every slot", values_ok, NULL);

    size_t narrowed = 0;
    char err[128] = {0};
    bool ok = scanner_narrow_value(&s, "30", &narrowed, err, sizeof(err));
    check("narrow_value succeeds", ok, ok ? NULL : err);
    check("narrow_value keeps only the one matching slot", narrowed == 1, NULL);
    check("the kept slot is the one that held 30",
          s.count == 1 && s.candidates[0].address == base + 8 && s.candidates[0].has_value &&
              s.candidates[0].value.i == 30,
          NULL);

    /* An unpackable literal leaves the (already-narrowed) candidate set untouched. */
    size_t before_count = s.count;
    ok = scanner_narrow_value(&s, "zzz", NULL, err, sizeof(err));
    check("narrow_value rejects an unpackable literal", !ok, NULL);
    check("candidate set is untouched after the rejection", s.count == before_count, NULL);

    scanner_free(&s);
}

/* One (before, after) scenario shared by all four narrow_move directions: slot 0 stays put
 * (same), slot 1 rises, slot 2 falls, slot 3 falls, slot 4 stays put (same) -- so same,
 * changed, up and down each keep a different, independently checkable subset. */
static void run_narrow_move_case(const char *label, ScannerMove how, size_t expect_kept,
                                  const uint64_t *expect_addrs, const int32_t *expect_values,
                                  size_t expect_n) {
    const uint64_t base = 0x42000000ULL;
    uint8_t blob[20];
    int32_t before[5] = {10, 20, 30, 40, 50};
    for (int i = 0; i < 5; i++) {
        write_i32(blob, (size_t)i * 4, before[i]);
    }
    FakeProcess fp = {base, blob, sizeof(blob), NULL, 0};
    ProcessIO io = make_fake(&fp);

    Scanner s;
    scanner_init(&s, &io);
    s.kind = MS_TYPE_INT32;
    scanner_snapshot(&s, NULL);

    int32_t after[5] = {10, 25, 25, 35, 50};
    for (int i = 0; i < 5; i++) {
        write_i32(blob, (size_t)i * 4, after[i]);
    }

    size_t kept = scanner_narrow_move(&s, how);
    char detail[64];
    snprintf(detail, sizeof(detail), "kept %zu, expected %zu", kept, expect_kept);
    char name[64];
    snprintf(name, sizeof(name), "narrow_move %s keeps the right count", label);
    check(name, kept == expect_kept, kept == expect_kept ? NULL : detail);

    bool values_ok = (kept == expect_n);
    for (size_t i = 0; values_ok && i < expect_n; i++) {
        bool found = false;
        for (size_t j = 0; j < s.count; j++) {
            if (s.candidates[j].address == expect_addrs[i]) {
                found = s.candidates[j].has_value && s.candidates[j].value.i == expect_values[i];
                break;
            }
        }
        values_ok = values_ok && found;
    }
    snprintf(name, sizeof(name), "narrow_move %s keeps the expected addresses/values", label);
    check(name, values_ok, NULL);

    scanner_free(&s);
}

static void test_narrow_move(void) {
    printf("\nnarrow_move() against the fake process\n");

    const uint64_t base = 0x42000000ULL;
    uint64_t same_addrs[2] = {base + 0, base + 16};
    int32_t same_values[2] = {10, 50};
    run_narrow_move_case("same", SCANNER_MOVE_SAME, 2, same_addrs, same_values, 2);

    uint64_t changed_addrs[3] = {base + 4, base + 8, base + 12};
    int32_t changed_values[3] = {25, 25, 35};
    run_narrow_move_case("changed", SCANNER_MOVE_CHANGED, 3, changed_addrs, changed_values, 3);

    uint64_t up_addrs[1] = {base + 4};
    int32_t up_values[1] = {25};
    run_narrow_move_case("up", SCANNER_MOVE_UP, 1, up_addrs, up_values, 1);

    uint64_t down_addrs[2] = {base + 8, base + 12};
    int32_t down_values[2] = {25, 35};
    run_narrow_move_case("down", SCANNER_MOVE_DOWN, 2, down_addrs, down_values, 2);
}

/* narrow_move() must give the same result regardless of what order the candidates happen to
 * be in. Deliberately reproduces the exact address ordering scanner.c's narrow_move comment
 * cites -- {A+8, A+12288, A+16, A+4096} -- where a cursor that assumes ascending order
 * passes A+12288 looking for A+16 and can never step back to it. All four addresses change
 * value, so `next changed` should keep all four candidates; the old code kept only two. */
static void test_narrow_move_unsorted_candidates(void) {
    printf("\nnarrow_move() is correct on unsorted candidates\n");

    const uint64_t base = 0x43000000ULL;
    const size_t blob_len = FAKE_PAGE * 4;
    uint8_t *blob = (uint8_t *)malloc(blob_len);
    if (!blob) {
        check("allocate the synthetic blob", false, "out of memory");
        return;
    }
    memset(blob, 0, blob_len);
    write_i32(blob, 8, 1);
    write_i32(blob, 12288, 2);
    write_i32(blob, 16, 3);
    write_i32(blob, 4096, 4);
    FakeProcess fp = {base, blob, blob_len, NULL, 0};
    ProcessIO io = make_fake(&fp);

    Scanner s;
    scanner_init(&s, &io);
    s.kind = MS_TYPE_INT32;

    /* Deliberately out of address order: base+12288 sits before base+16. */
    uint64_t addrs[4] = {base + 8, base + 12288, base + 16, base + 4096};
    s.candidates = (ScanCandidate *)malloc(4 * sizeof(ScanCandidate));
    for (int i = 0; i < 4; i++) {
        s.candidates[i].address = addrs[i];
        s.candidates[i].has_value = false;
        s.candidates[i].value.u = 0;
    }
    s.count = 4;
    s.capacity = 4;
    s.has_scanned = true;

    write_i32(blob, 8, 101);
    write_i32(blob, 12288, 102);
    write_i32(blob, 16, 103);
    write_i32(blob, 4096, 104);

    size_t kept = scanner_narrow_move(&s, SCANNER_MOVE_CHANGED);
    char detail[64];
    snprintf(detail, sizeof(detail), "kept %zu, expected 4", kept);
    check("narrow_move changed keeps all four unsorted candidates", kept == 4,
          kept == 4 ? NULL : detail);

    bool addr16_present = false;
    bool addr4096_present = false;
    for (size_t i = 0; i < s.count; i++) {
        if (s.candidates[i].address == base + 16 && s.candidates[i].has_value &&
            s.candidates[i].value.i == 103) {
            addr16_present = true;
        }
        if (s.candidates[i].address == base + 4096 && s.candidates[i].has_value &&
            s.candidates[i].value.i == 104) {
            addr4096_present = true;
        }
    }
    check("the candidate a monotone cursor would strand (base+16) is kept", addr16_present, NULL);
    check("the candidate after it (base+4096) is kept too", addr4096_present, NULL);

    scanner_free(&s);
    free(blob);
}

int main(void) {
    test_refresh_matches_oracle();
    test_refresh_unsorted_candidates();
    test_first_scan();
    test_snapshot_and_narrow_value();
    test_narrow_move();
    test_narrow_move_unsorted_candidates();

    printf("\n");
    if (failures) {
        printf("FAILED: %d check(s)\n", failures);
        return 1;
    }
    printf("all checks pass\n");
    return 0;
}
