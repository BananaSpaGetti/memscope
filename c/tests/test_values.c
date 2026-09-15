/*
 * Tests for values.c: type resolution, pack/unpack round-tripping, integer range
 * rejection and aligned search. Mirrors the checks MemScope/tests/selftest.py makes of
 * memscope.py's TYPES/resolve_type/pack/unpack/find_aligned.
 */
#include "values.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;

static void check(const char *name, bool ok, const char *detail) {
    printf("  %s  %s%s%s\n", ok ? "ok  " : "FAIL", name, detail ? "  " : "", detail ? detail : "");
    if (!ok) {
        failures++;
    }
}

/* Packs `literal` as `kind` and unpacks it straight back, checking that the decoded value
 * equals `expected` (compared through the member the type's kind dictates) and that no
 * error was reported either way. */
static void check_round_trip_signed(const char *type_name, const char *literal, int64_t expected) {
    MsType kind;
    char name[128];
    snprintf(name, sizeof(name), "round-trip %s '%s'", type_name, literal);
    if (!ms_resolve_type(type_name, &kind)) {
        check(name, false, "resolve_type failed");
        return;
    }
    uint8_t buf[MS_MAX_VALUE_SIZE];
    size_t len = 0;
    char err[128] = {0};
    if (!ms_pack(literal, kind, buf, &len, err, sizeof(err))) {
        check(name, false, err);
        return;
    }
    MsValue value;
    if (!ms_unpack(buf, len, kind, &value)) {
        check(name, false, "unpack failed");
        return;
    }
    char detail[128];
    snprintf(detail, sizeof(detail), "got %lld", (long long)value.as.i);
    check(name, value.as.i == expected, value.as.i == expected ? NULL : detail);
}

static void check_round_trip_unsigned(const char *type_name, const char *literal, uint64_t expected) {
    MsType kind;
    char name[128];
    snprintf(name, sizeof(name), "round-trip %s '%s'", type_name, literal);
    if (!ms_resolve_type(type_name, &kind)) {
        check(name, false, "resolve_type failed");
        return;
    }
    uint8_t buf[MS_MAX_VALUE_SIZE];
    size_t len = 0;
    char err[128] = {0};
    if (!ms_pack(literal, kind, buf, &len, err, sizeof(err))) {
        check(name, false, err);
        return;
    }
    MsValue value;
    if (!ms_unpack(buf, len, kind, &value)) {
        check(name, false, "unpack failed");
        return;
    }
    char detail[128];
    snprintf(detail, sizeof(detail), "got %llu", (unsigned long long)value.as.u);
    check(name, value.as.u == expected, value.as.u == expected ? NULL : detail);
}

static void check_round_trip_float(const char *type_name, const char *literal, double expected) {
    MsType kind;
    char name[128];
    snprintf(name, sizeof(name), "round-trip %s '%s'", type_name, literal);
    if (!ms_resolve_type(type_name, &kind)) {
        check(name, false, "resolve_type failed");
        return;
    }
    uint8_t buf[MS_MAX_VALUE_SIZE];
    size_t len = 0;
    char err[128] = {0};
    if (!ms_pack(literal, kind, buf, &len, err, sizeof(err))) {
        check(name, false, err);
        return;
    }
    MsValue value;
    if (!ms_unpack(buf, len, kind, &value)) {
        check(name, false, "unpack failed");
        return;
    }
    /* float loses precision widened to double, so compare loosely enough to survive that,
     * but tightly enough that a byte-order or size bug still fails. */
    double diff = value.as.f - expected;
    if (diff < 0) {
        diff = -diff;
    }
    double tolerance = (kind == MS_TYPE_FLOAT) ? 1e-3 : 1e-9;
    char detail[128];
    snprintf(detail, sizeof(detail), "got %g", value.as.f);
    check(name, diff <= tolerance, diff <= tolerance ? NULL : detail);
}

static void test_all_types_round_trip(void) {
    printf("\nround-trips (all ten types)\n");
    check_round_trip_signed("int8", "-128", -128);
    check_round_trip_signed("int8", "127", 127);
    check_round_trip_unsigned("uint8", "0", 0);
    check_round_trip_unsigned("uint8", "255", 255);
    check_round_trip_signed("int16", "-32768", -32768);
    check_round_trip_signed("int16", "32767", 32767);
    check_round_trip_unsigned("uint16", "0", 0);
    check_round_trip_unsigned("uint16", "65535", 65535);
    check_round_trip_signed("int32", "-2147483648", INT64_C(-2147483648));
    check_round_trip_signed("int32", "2147483647", 2147483647);
    check_round_trip_unsigned("uint32", "0", 0);
    check_round_trip_unsigned("uint32", "4294967295", 4294967295u);
    check_round_trip_signed("int64", "-9223372036854775808", INT64_MIN);
    check_round_trip_signed("int64", "9223372036854775807", INT64_MAX);
    check_round_trip_unsigned("uint64", "0", 0);
    check_round_trip_unsigned("uint64", "18446744073709551615", UINT64_MAX);
    check_round_trip_float("float", "1.5", 1.5);
    check_round_trip_float("float", "-100.25", -100.25);
    check_round_trip_float("double", "1.5", 1.5);
    check_round_trip_float("double", "-123456.789", -123456.789);
}

static void test_literal_syntax(void) {
    printf("\ninteger literal syntax (int(value, 0) equivalent)\n");
    check_round_trip_signed("int32", "0x1A", 26);
    check_round_trip_signed("int32", "0X1a", 26);
    check_round_trip_signed("int32", "0o17", 15);
    check_round_trip_signed("int32", "0b101", 5);
    check_round_trip_signed("int32", "-0x10", -16);
    check_round_trip_signed("int32", "  42  ", 42);
    check_round_trip_signed("int32", "0", 0);
}

/* Packs `literal` as `type_name` and checks that it is rejected with exactly `expected_err`,
 * the way memscope.py's own error would read. */
static void check_pack_error(const char *type_name, const char *literal, const char *expected_err) {
    MsType kind;
    char name[160];
    snprintf(name, sizeof(name), "pack('%s', %s) rejected as Python would", literal, type_name);
    if (!ms_resolve_type(type_name, &kind)) {
        check(name, false, "resolve_type failed");
        return;
    }
    uint8_t buf[MS_MAX_VALUE_SIZE];
    size_t len = 0;
    char err[160] = {0};
    bool ok = ms_pack(literal, kind, buf, &len, err, sizeof(err));
    if (ok) {
        check(name, false, "pack unexpectedly succeeded");
        return;
    }
    bool matches = strcmp(err, expected_err) == 0;
    check(name, matches, matches ? NULL : err);
}

/* Findings from the review round, each reproduced against the real Python before being
 * handed out: a leading-zero decimal was read as C octal instead of being rejected, a
 * hex-float literal was accepted by strtod where Python's float() rejects it, and a literal
 * above UINT64_MAX reported a made-up "int too large to convert" message instead of the
 * type's own out-of-range wording. */
static void test_review_findings(void) {
    printf("\nreview findings (leading zero, hex float, over-large literal)\n");
    check_pack_error("int32", "0123", "invalid literal for int() with base 0: '0123'");
    check_pack_error("int32", "010", "invalid literal for int() with base 0: '010'");
    check_round_trip_signed("int32", "0", 0);
    check_round_trip_signed("int32", "00", 0);
    check_round_trip_signed("int32", "000", 0);
    check_pack_error("float", "0x10", "could not convert string to float: '0x10'");
    check_pack_error("uint64", "18446744073709551616",
                      "uint64 format requires 0 <= number <= 18446744073709551615");
}

/* Regression: pack_integer's unsigned branch rejected any literal whose sign was negative,
 * including "-0", which Python's int('-0', 0) == 0 packs happily. Confirmed against the
 * real Python: struct.pack('B'/'H'/'Q', int('-0', 0)) and friends succeed as zero, while
 * int('-1', 0) is still out of range for every unsigned width. */
static void test_negative_zero_unsigned(void) {
    printf("\nnegative zero for unsigned types (-0 is zero, not negative)\n");
    check_round_trip_unsigned("uint8", "-0", 0);
    check_round_trip_unsigned("uint8", "-0x0", 0);
    check_round_trip_unsigned("uint8", "-00", 0);
    check_pack_error("uint8", "-1", "uint8 format requires 0 <= number <= 255");
    check_round_trip_unsigned("uint16", "-0", 0);
    check_round_trip_unsigned("uint16", "-0x0", 0);
    check_round_trip_unsigned("uint16", "-00", 0);
    check_pack_error("uint16", "-1", "uint16 format requires 0 <= number <= 65535");
    check_round_trip_unsigned("uint64", "-0", 0);
    check_round_trip_unsigned("uint64", "-0x0", 0);
    check_round_trip_unsigned("uint64", "-00", 0);
    check_pack_error("uint64", "-1", "uint64 format requires 0 <= number <= 18446744073709551615");
}

static void test_aliases(void) {
    printf("\ntype aliases\n");
    MsType kind;
    struct {
        const char *alias;
        MsType expected;
    } cases[] = {
        {"int", MS_TYPE_INT32}, {"uint", MS_TYPE_UINT32}, {"long", MS_TYPE_INT64},
        {"byte", MS_TYPE_UINT8}, {"short", MS_TYPE_INT16},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        bool ok = ms_resolve_type(cases[i].alias, &kind) && kind == cases[i].expected;
        char name[64];
        snprintf(name, sizeof(name), "alias '%s'", cases[i].alias);
        check(name, ok, NULL);
    }
    check("unknown type name is rejected", !ms_resolve_type("nope", &kind), NULL);
}

/* The four known-bad inputs MemScope/tests/selftest.py's offline_checks feeds to pack():
 * an integer literal that parses but overflows its type, a literal that does not parse at
 * all, a float literal that does not parse, and another overflow at a different width. */
static void test_known_bad_inputs(void) {
    printf("\nknown-bad inputs (from selftest.py's offline_checks)\n");
    struct {
        const char *literal;
        const char *type_name;
    } cases[] = {
        {"99999999999", "int32"},
        {"zzz", "int32"},
        {"abc", "float"},
        {"300", "int8"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        MsType kind;
        char name[64];
        snprintf(name, sizeof(name), "pack('%s', %s) is rejected", cases[i].literal, cases[i].type_name);
        if (!ms_resolve_type(cases[i].type_name, &kind)) {
            check(name, false, "resolve_type failed");
            continue;
        }
        uint8_t buf[MS_MAX_VALUE_SIZE];
        size_t len = 0;
        char err[128] = {0};
        bool ok = ms_pack(cases[i].literal, kind, buf, &len, err, sizeof(err));
        check(name, !ok, ok ? "pack unexpectedly succeeded" : NULL);
    }
}

static void test_unpack_short_buffer(void) {
    printf("\nunpack rejects a too-short buffer\n");
    uint8_t data[4] = {1, 2, 3, 4};
    MsValue value;
    check("int64 needs 8 bytes, buffer has 4", !ms_unpack(data, sizeof(data), MS_TYPE_INT64, &value), NULL);
    check("int32 fits in 4 bytes", ms_unpack(data, sizeof(data), MS_TYPE_INT32, &value), NULL);
}

static void test_find_aligned(void) {
    printf("\nfind_aligned\n");
    /* The needle 0xAA 0xBB sits at offsets 0, 2 and 5. With align 2, only 0 and 2 are
     * multiples of the alignment -- offset 5 must not be reported even though the bytes
     * there match too. */
    uint8_t data[] = {0xAA, 0xBB, 0xAA, 0xBB, 0x00, 0xAA, 0xBB, 0x00};
    uint8_t needle[] = {0xAA, 0xBB};
    size_t hits[8];
    size_t count = ms_find_aligned(data, sizeof(data), needle, sizeof(needle), 2, hits, 8);
    check("finds both aligned matches", count == 2, NULL);
    check("first match at offset 0", count >= 1 && hits[0] == 0, NULL);
    check("second match at offset 2", count >= 2 && hits[1] == 2, NULL);

    /* With align 1, the unaligned match at offset 5 is picked up too. */
    count = ms_find_aligned(data, sizeof(data), needle, sizeof(needle), 1, hits, 8);
    check("align 1 also finds the unaligned occurrence", count == 3, NULL);

    /* No match at all. */
    uint8_t absent[] = {0xCC, 0xDD};
    count = ms_find_aligned(data, sizeof(data), absent, sizeof(absent), 2, hits, 8);
    check("no match reports zero", count == 0, NULL);

    /* Regression: Python's find_aligned filters re.finditer, which matches
     * non-overlappingly. 0xFF followed by eight zero bytes contains a 4-zero-byte needle
     * at unaligned offsets 1 and 5; both consume the span that would otherwise put a match
     * at aligned offset 4, so the oracle reports no match at all. A search that tested
     * every aligned offset independently (0, 4) would wrongly report offset 4. Confirmed
     * against the real Python: memscope.find_aligned(b'\xff'+b'\x00'*8, b'\x00'*4, 4) == []. */
    uint8_t shadow[9] = {0xFF, 0, 0, 0, 0, 0, 0, 0, 0};
    uint8_t zeros4[4] = {0, 0, 0, 0};
    count = ms_find_aligned(shadow, sizeof(shadow), zeros4, sizeof(zeros4), 4, hits, 8);
    check("an unaligned match shadows the aligned one beneath it", count == 0, NULL);
}

int main(void) {
    test_all_types_round_trip();
    test_literal_syntax();
    test_review_findings();
    test_negative_zero_unsigned();
    test_aliases();
    test_known_bad_inputs();
    test_unpack_short_buffer();
    test_find_aligned();

    printf("\n");
    if (failures) {
        printf("FAILED: %d check(s)\n", failures);
        return 1;
    }
    printf("all checks pass\n");
    return 0;
}
