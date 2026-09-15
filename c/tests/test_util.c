/*
 * Tests for util.c's ms_parse_hex_u64: a negative literal must be rejected outright, not
 * wrapped, when the caller says it must (every address this port parses); it must be encoded
 * as its two's-complement bit pattern when the caller says a negative value is legitimate (a
 * --resolve path's hop offsets); a leading '+' must still work either way; and a value too
 * large for uint64_t must be rejected rather than silently truncated later on.
 */
#include "util.h"

#include <stdio.h>

static int failures = 0;

static void check(const char *name, bool ok) {
    printf("  %s  %s\n", ok ? "ok  " : "FAIL", name);
    if (!ok) {
        failures++;
    }
}

static void test_negative_literal_rejected(void) {
    printf("\na negative hex literal is rejected when the caller asks for that\n");
    uint64_t out = 0;
    /* Before this fix, strtoull's own sign handling wrapped "-1" into 0xFFFFFFFFFFFFFFFF --
     * exactly the "silently a different value than typed" hazard this review round was
     * dispatched over: ptrscan's --offset -1 turned an intended no-op into an effectively
     * unbounded scan. */
    check("'-1' is rejected", !ms_parse_hex_u64("-1", true, &out));
    check("'-0x10' is rejected", !ms_parse_hex_u64("-0x10", true, &out));
    check("'-FF' is rejected", !ms_parse_hex_u64("-FF", true, &out));
    check("' -1' (leading space, then '-') is rejected", !ms_parse_hex_u64(" -1", true, &out));
}

static void test_negative_literal_encoded_when_allowed(void) {
    printf("\na negative hex literal is two's-complement-encoded when the caller allows it\n");
    uint64_t out = 0;
    /* A --resolve path's hop offsets are added to a dereferenced pointer with plain unsigned
     * arithmetic (ptrpath_resolve): encoding "-1" as 0xFFFFFFFFFFFFFFFF here means that
     * addition reproduces exactly the same 64-bit result as Python's real signed subtraction
     * of 1 would. */
    check("'-1' encodes as 0xFFFFFFFFFFFFFFFF",
          ms_parse_hex_u64("-1", false, &out) && out == 0xFFFFFFFFFFFFFFFFULL);
    out = 0;
    check("'-0x20' encodes as -0x20 two's complement",
          ms_parse_hex_u64("-0x20", false, &out) && out == (uint64_t)-(int64_t)0x20);
    out = 0;
    check("'-0' encodes as 0", ms_parse_hex_u64("-0", false, &out) && out == 0);
}

static void test_plus_literal_accepted(void) {
    printf("\na leading '+' still parses, matching Python's int(s, 16), under either mode\n");
    uint64_t out = 0;
    check("'+10' parses to 0x10 (reject_negative=true)",
          ms_parse_hex_u64("+10", true, &out) && out == 0x10);
    out = 0;
    check("'+0x40' parses to 0x40 (reject_negative=true)",
          ms_parse_hex_u64("+0x40", true, &out) && out == 0x40);
    out = 0;
    check("'0x40' (no sign) parses to 0x40 (reject_negative=true)",
          ms_parse_hex_u64("0x40", true, &out) && out == 0x40);
    out = 0;
    check("'+10' parses to 0x10 (reject_negative=false)",
          ms_parse_hex_u64("+10", false, &out) && out == 0x10);
}

static void test_overflow_rejected(void) {
    printf("\na value above 2**64 is rejected rather than truncated, under either mode\n");
    uint64_t out = 0;
    /* Python's int(s, 16) has arbitrary precision and accepts a value like this one; it is
     * only later, when the value is boxed into a ctypes.c_void_p for the actual
     * ReadProcessMemory call, that ctypes silently masks it down to its low 64 bits. That is
     * the same "different address than typed" hazard ms_parse_hex_u64 exists to avoid, just
     * deferred a few lines in the Python. Rejecting here outright, instead of guessing at a
     * truncation, is the better of the two behaviours -- see the comment in util.c. */
    check("18 hex digits (72 bits) is rejected (reject_negative=true)",
          !ms_parse_hex_u64("FFFFFFFFFFFFFFFFFF", true, &out));
    check("18 hex digits (72 bits) is rejected (reject_negative=false)",
          !ms_parse_hex_u64("FFFFFFFFFFFFFFFFFF", false, &out));
    check("16 hex digits (64 bits, fits exactly) is accepted",
          ms_parse_hex_u64("FFFFFFFFFFFFFFFF", true, &out) && out == 0xFFFFFFFFFFFFFFFFULL);
}

int main(void) {
    test_negative_literal_rejected();
    test_negative_literal_encoded_when_allowed();
    test_plus_literal_accepted();
    test_overflow_rejected();

    printf("\n");
    if (failures) {
        printf("FAILED: %d check(s)\n", failures);
        return 1;
    }
    printf("all checks pass\n");
    return 0;
}
