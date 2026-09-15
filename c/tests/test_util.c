/*
 * Tests for util.c's ms_parse_hex_u64: a negative literal must be rejected outright, not
 * wrapped, when the caller says it must (every address this port parses); it must be encoded
 * as its two's-complement bit pattern when the caller says a negative value is legitimate (a
 * --resolve path's hop offsets); a leading '+' must still work either way; and a value too
 * large for uint64_t must be rejected rather than silently truncated later on.
 */
#include "util.h"


#include <stdio.h>
#include <string.h>

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


static void test_double_sign_rejected(void) {
    printf("\na doubled sign is not a number, the way Python says it is not\n");
    /* Found by unifying this parser with repl.c's onto one core: the old, separate
     * implementation here stripped ONE leading '-' itself and handed the rest to strtoull,
     * which happily accepted a second sign and wrapped -- so "--1" parsed as 1 and "-+1" as
     * -1, neither of which is a number Python would accept:
     *
     *     >>> int("--1", 16)
     *     ValueError: invalid literal for int() with base 16: '--1'
     *
     * The REPL's parser validated every character before converting and always got this
     * right; sharing one core is what carried that over. Reachable in practice through a
     * --resolve hop offset, which is the one caller that passes reject_negative=false. */
    uint64_t out = 0;
    check("\"--1\" is rejected", !ms_parse_hex_u64("--1", false, &out));
    check("\"-+1\" is rejected", !ms_parse_hex_u64("-+1", false, &out));
    check("\"+-1\" is rejected", !ms_parse_hex_u64("+-1", false, &out));
    check("\"++1\" is rejected", !ms_parse_hex_u64("++1", false, &out));
    check("a single sign still works", ms_parse_hex_u64("-1", false, &out));
    check("and so does a bare value", ms_parse_hex_u64("1", true, &out) && out == 1);
}


/* --- literal length, the variable the first corpus for this parser never varied ---------- */

static void fill(char *buf, char c, size_t n) {
    memset(buf, c, n);
    buf[n] = '\0';
}

static void test_leading_zeros_are_not_digits(void) {
    printf("\nleading zeros do not count against the digit buffer\n");
    /* Python: int("0x" + "0" * 200 + "1", 16) == 1. The parser used to measure the literal
     * before stripping them, so a padded address was rejected as invalid while memscope.py
     * read address 1. */
    char literal[512];
    literal[0] = '0';
    literal[1] = 'x';
    fill(literal + 2, '0', 200);
    literal[202] = '1';
    literal[203] = '\0';

    uint64_t out = 0;
    check("a 200-zero-padded hex literal parses", ms_parse_hex_u64(literal, true, &out));
    check("and its value is 1", out == 1);

    char zeros[64];
    fill(zeros, '0', 40);
    check("all zeros is zero, not empty", ms_parse_hex_u64(zeros, true, &out) && out == 0);
}

static void test_decimal_digit_limit(void) {
    printf("\nCPython's 4300-digit ceiling on a decimal conversion\n");
    /* Measured against the interpreter: the limit applies to base 10 and not to base 16,
     * the count is every digit after the sign with leading zeros included, and an invalid
     * character is reported ahead of it. */
    char at_limit[MS_PY_INT_MAX_STR_DIGITS + 8];
    fill(at_limit, '1', MS_PY_INT_MAX_STR_DIGITS);

    char over_limit[MS_PY_INT_MAX_STR_DIGITS + 8];
    fill(over_limit, '1', MS_PY_INT_MAX_STR_DIGITS + 1);

    uint64_t out = 0;
    MsIntOverflow overflow;
    char err[256];

    /* At the limit it is a number -- far too large for uint64_t, so it is reported as out
     * of range rather than as an invalid literal. That distinction is the point. */
    check("4300 digits is not a limit error",
          !ms_parse_py_int(at_limit, 10, false, &out, &overflow, err, sizeof(err))
          && strstr(err, "Exceeds the limit") == NULL);
    check("4300 digits overflows instead", overflow.triggered);

    check("4301 digits is a limit error",
          !ms_parse_py_int(over_limit, 10, false, &out, &overflow, err, sizeof(err))
          && strstr(err, "Exceeds the limit (4300 digits)") != NULL);
    check("and it names the digit count",
          strstr(err, "value has 4301 digits") != NULL);
    check("and it does not claim an overflow", !overflow.triggered);

    /* Base 16 has no such ceiling in CPython. */
    check("4301 hex digits is not a limit error",
          !ms_parse_py_int(over_limit, 16, false, &out, &overflow, err, sizeof(err))
          && strstr(err, "Exceeds the limit") == NULL);

    /* Leading zeros count toward the limit even though they are not significant. */
    char padded[MS_PY_INT_MAX_STR_DIGITS + 108];
    fill(padded, '0', 100);
    fill(padded + 100, '1', MS_PY_INT_MAX_STR_DIGITS);
    check("100 zeros plus 4300 digits is 4400 digits, over the limit",
          !ms_parse_py_int(padded, 10, false, &out, &overflow, err, sizeof(err))
          && strstr(err, "value has 4400 digits") != NULL);

    /* An invalid character is reported before the limit is. */
    char bad[MS_PY_INT_MAX_STR_DIGITS + 8];
    fill(bad, '1', MS_PY_INT_MAX_STR_DIGITS + 1);
    bad[MS_PY_INT_MAX_STR_DIGITS] = 'z';
    check("a bad character outranks the limit",
          !ms_parse_py_int(bad, 10, false, &out, &overflow, err, sizeof(err))
          && strstr(err, "invalid literal") != NULL);
}

static void test_literal_repr_truncation(void) {
    printf("\nCPython truncates the literal it quotes back\n");
    /* CPython formats this message with "%.200R", so what it quotes is repr(literal) cut to
     * 200 characters INCLUDING the quotes -- which is why a long literal keeps its opening
     * quote and loses its closing one. Measured; it reads like a bug until you see it. */
    char literal[512];
    fill(literal, 'A', 300);

    char shown[208];
    ms_py_literal_repr(literal, shown, sizeof(shown));
    check("the repr is cut to 200 characters", strlen(shown) == 200);
    check("it keeps the opening quote", shown[0] == '\'');
    check("and loses the closing one", shown[199] != '\'');

    char shortish[64];
    fill(shortish, 'A', 10);
    ms_py_literal_repr(shortish, shown, sizeof(shown));
    check("a short literal keeps both quotes",
          strlen(shown) == 12 && shown[0] == '\'' && shown[11] == '\'');
}

static void test_canonical_decimal(void) {
    printf("\nrendering a literal the way Python's \"%%d\" renders its int\n");
    /* For the three error messages that echo a count or a length back: strtoll saturates and
     * Python's int does not, so printing the parse quoted a number the user never typed. */
    bool neg = true;
    check("a plain literal is itself",
          strcmp(ms_canonical_decimal("64", &neg), "64") == 0 && !neg);
    check("a '+' is dropped",
          strcmp(ms_canonical_decimal("+64", &neg), "64") == 0 && !neg);
    check("leading zeros are dropped",
          strcmp(ms_canonical_decimal("000064", &neg), "64") == 0 && !neg);
    check("a '-' is reported, not returned",
          strcmp(ms_canonical_decimal("-64", &neg), "64") == 0 && neg);
    check("zero is zero", strcmp(ms_canonical_decimal("0", &neg), "0") == 0 && !neg);
    check("and negative zero is still zero, as int(\"-0\") is",
          strcmp(ms_canonical_decimal("-0", &neg), "0") == 0 && !neg);
    check("all zeros collapse to one",
          strcmp(ms_canonical_decimal("-0000", &neg), "0") == 0 && !neg);
    check("a literal too large for int64_t survives whole",
          strcmp(ms_canonical_decimal("11111111111111111111", &neg),
                 "11111111111111111111") == 0 && !neg);
}

int main(void) {
    test_negative_literal_rejected();
    test_negative_literal_encoded_when_allowed();
    test_plus_literal_accepted();
    test_overflow_rejected();
    test_double_sign_rejected();
    test_leading_zeros_are_not_digits();
    test_decimal_digit_limit();
    test_literal_repr_truncation();
    test_canonical_decimal();

    printf("\n");
    if (failures) {
        printf("FAILED: %d check(s)\n", failures);
        return 1;
    }
    printf("all checks pass\n");
    return 0;
}
