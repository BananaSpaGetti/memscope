/*
 * util.c -- see util.h.
 */
#include "util.h"

#include <windows.h>

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool ms_parse_hex_u64(const char *s, bool reject_negative, uint64_t *out) {
    /* One line, on purpose. This used to be a second implementation of the sign, prefix and
     * overflow handling in ms_parse_py_int below, and the two drifted: a fix to one did not
     * reach the other. The contract is unchanged -- base 16, no error text, no
     * arbitrary-precision fallback -- so every existing caller is unaffected, and there is
     * now one place where a sign or overflow bug can live. */
    if (!s) {
        return false;
    }
    return ms_parse_py_int(s, 16, reject_negative, out, NULL, NULL, 0);
}

/* Parses `s` the way Python's `int(s, base)` does for base 10 or 16 (the only two bases this
 * REPL ever calls it with -- `list`'s count and `write`/`freeze`/`pscan`'s addresses and
 * `pscan`'s own depth/offset): optional surrounding whitespace, an optional sign, an optional
 * "0x"/"0X" prefix when base is 16, then one or more digits of that base and nothing else. On
 * failure, writes a message shaped like CPython's ValueError text into `err` and returns false,
 * leaving `*out` untouched.
 *
 * Unlike Python's int(), a magnitude that does not fit in 64 bits is also reported as failure
 * (ERANGE from strtoull) UNLESS the caller passes a non-NULL `overflow`, in which case it is
 * filled in instead and this returns false only in the sense of "no 64-bit value exists" --
 * the caller decides what that means (list treats it as "all of them" or "none of them" with
 * an exact decimal tally; pscan's depth and offset treat it as unbounded, since a BFS this
 * shallow always terminates on its own long before either value could matter). Passing NULL
 * for `overflow` means the caller has no such fallback and every magnitude out of range is an
 * ordinary parse error -- `write`, `freeze` and `pscan`'s own target address use this, since
 * silently retargeting any of them, as an earlier version of this function did by saturating,
 * is worse than refusing outright.
 *
 * `reject_negative`, when true, fails a negative literal outright with the same wording
 * Python's repl_address() raises for the identical case -- rather than the two's-complement
 * wrap this function would otherwise produce, which is exactly right for `list`'s count (a
 * negative count is a real, meaningful value to Python) and exactly wrong for an address
 * (`write -1 5` must not silently write to 0xFFFFFFFFFFFFFFFF). */
static void ms_invalid_literal(char *err, size_t err_cap, int base, const char *literal) {
    char shown[208];
    ms_py_literal_repr(literal, shown, sizeof(shown));
    snprintf(err, err_cap, "invalid literal for int() with base %d: %s", base, shown);
}

bool ms_parse_py_int(const char *s, int base, bool reject_negative, uint64_t *out,
                          MsIntOverflow *overflow, char *err, size_t err_cap) {
    if (overflow) {
        overflow->triggered = false;
    }
    const char *start = s;
    while (*start && isspace((unsigned char)*start)) {
        start++;
    }
    const char *end = start + strlen(start);
    while (end > start && isspace((unsigned char)end[-1])) {
        end--;
    }

    const char *p = start;
    bool neg = false;
    if (p < end && (*p == '+' || *p == '-')) {
        neg = (*p == '-');
        p++;
    }
    if (base == 16 && end - p >= 2 && p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
        p += 2;
    }

    bool any_digit = false;
    for (const char *q = p; q < end; q++) {
        int ok = (base == 16) ? isxdigit((unsigned char)*q) : isdigit((unsigned char)*q);
        if (!ok) {
            any_digit = false;
            break;
        }
        any_digit = true;
    }
    if (!any_digit || p >= end) {
        if (err) {
            ms_invalid_literal(err, err_cap, base, s);
        }
        return false;
    }

    /* CPython's own ceiling on a decimal conversion, and only on a decimal one: base 16 is
     * exempt from it, which is why this sits behind a base check. Measured against the
     * interpreter -- the count is every digit after the sign with leading zeros included,
     * an invalid character is reported before this rather than after it, and surrounding
     * whitespace is trimmed first. Without it a 4301-digit `list` argument was accepted
     * here and rejected by memscope.py. */
    if (base == 10) {
        size_t digit_count = (size_t)(end - p);
        if (digit_count > MS_PY_INT_MAX_STR_DIGITS) {
            if (err) {
                snprintf(err, err_cap,
                         "Exceeds the limit (%d digits) for integer string conversion: "
                         "value has %zu digits; use sys.set_int_max_str_digits() to "
                         "increase the limit", MS_PY_INT_MAX_STR_DIGITS, digit_count);
            }
            return false;
        }
    }

    /* Leading zeros are not significant digits, and Python does not treat them as any:
     * int("0x" + "0" * 200 + "1", 16) is 1, not an error. Skipping them here is what keeps
     * a padded literal inside the buffer below -- without this, `read <pid> 0x000...001`
     * was rejected as an invalid address while memscope.py read the address 1.
     *
     * Found by sweeping literal LENGTH rather than value. The golden corpus this parser's
     * unification was checked against had 126 cases and topped out at 68 characters, so it
     * never reached the buffer at all; every case in it was one I had already thought of. */
    while (p + 1 < end && *p == '0') {
        p++;
    }

    /* Enough for CPython's own ceiling on a base-10 conversion (4300 digits) plus the NUL,
     * so the bound below is never the thing that rejects a literal Python would accept.
     * Base 16 has no such ceiling, but 16 significant hex digits already fill a uint64_t,
     * so anything longer is rejected as out of range on the ERANGE path below -- which is
     * the same answer Python's caller reaches, and not this buffer's business. */
    char digits[MS_PY_INT_MAX_STR_DIGITS + 52];
    size_t len = (size_t)(end - p);
    if (len >= sizeof(digits)) {
        if (err) {
            snprintf(err, err_cap, "int too large to convert: '%s'", s);
        }
        return false;
    }
    memcpy(digits, p, len);
    digits[len] = '\0';

    if (reject_negative && neg) {
        if (err) {
            snprintf(err, err_cap, "int too large to convert: '%s'", s);
        }
        return false;
    }

    char *stop;
    errno = 0;
    unsigned long long magnitude = strtoull(digits, &stop, base);
    if (*stop != '\0') {
        if (err) {
            ms_invalid_literal(err, err_cap, base, s);
        }
        return false;
    }
    if (errno == ERANGE) {
        if (overflow) {
            overflow->triggered = true;
            overflow->negative = neg;
            snprintf(overflow->magnitude, sizeof(overflow->magnitude), "%s", digits);
        }
        if (err) {
            snprintf(err, err_cap, "int too large to convert: '%s'", s);
        }
        return false;
    }

    /* Negate in unsigned arithmetic, which is defined to wrap, rather than through
     * `-(long long)magnitude`: that conversion is implementation-defined at and above 2**63
     * and the negation of LLONG_MIN is undefined outright. The result is the same
     * two's-complement bit pattern on every machine this targets; the difference is that it
     * is now the one the standard promises rather than the one the optimiser happens to
     * emit. Reachable through a --resolve hop offset, the one caller that allows a negative
     * value -- `--resolve a+-0x8000000000000000` is exactly the undefined case. */
    *out = neg ? (uint64_t)0 - (uint64_t)magnitude : (uint64_t)magnitude;
    return true;
}

const char *ms_canonical_decimal(const char *literal, bool *negative) {
    /* argparse hands the Python side a `type=int` value of arbitrary precision, and its
     * error messages interpolate it with "%d" -- so a length of "11111111111111111111"
     * comes back verbatim. The C parses these with strtoll, which saturates, so the same
     * message read "9223372036854775807": a number the user never typed. Rather than widen
     * the integer (nothing here can hold an arbitrary-precision one), render the literal
     * the way "%d" renders the value it parses to, which is the same normalisation Python
     * applies: no '+', no leading zeros, and no '-' in front of a zero.
     *
     * Every caller has already checked the shape with ms_looks_like_int, so this sees only
     * an optional sign followed by digits. The returned pointer is into `literal`. */
    const char *p = literal;
    bool neg = false;
    if (*p == '+' || *p == '-') {
        neg = (*p == '-');
        p++;
    }
    while (p[0] == '0' && p[1] != '\0') {
        p++;
    }
    if (negative) {
        *negative = neg && !(p[0] == '0' && p[1] == '\0');
    }
    return p;
}

void ms_py_literal_repr(const char *literal, char *out, size_t out_cap) {
    /* CPython builds this message with "%.200R": repr(literal), truncated to 200 characters
     * INCLUDING the quotes the repr adds -- so a literal of 199 characters or more keeps its
     * opening quote and loses its closing one. Measured against the interpreter rather than
     * guessed, because the missing closing quote reads like a bug until you see where the
     * cut happens.
     *
     * Only the truncation is reproduced, not repr()'s escaping: a literal containing a
     * quote, a backslash or a non-ASCII character would be escaped by repr and is not here.
     * Every caller has already rejected such a literal for other reasons or is reporting a
     * string the user typed as a number, so this is the shape that actually reaches a user;
     * it is a known and deliberate limit rather than an oversight. */
    const size_t limit = 200;
    size_t written = 0;
    if (out_cap == 0) {
        return;
    }
    if (written + 1 < out_cap && written < limit) {
        out[written++] = '\'';
    }
    for (const char *p = literal; *p && written < limit && written + 1 < out_cap; p++) {
        out[written++] = *p;
    }
    if (written < limit && written + 1 < out_cap) {
        out[written++] = '\'';
    }
    out[written] = '\0';
}

void ms_wide_to_utf8(const wchar_t *wide, char *out, size_t out_size) {
    if (out_size == 0) {
        return;
    }
    int n = WideCharToMultiByte(CP_UTF8, 0, wide, -1, out, (int)out_size, NULL, NULL);
    if (n <= 0) {
        out[0] = '\0';
    }
}

void ms_to_lower_copy(const char *in, char *out, size_t out_size) {
    size_t i = 0;
    for (; in[i] != '\0' && i + 1 < out_size; i++) {
        out[i] = (char)tolower((unsigned char)in[i]);
    }
    out[i] = '\0';
}


/* True for the strings argparse's `type=int` accepts: an optional sign followed by at least
 * one decimal digit. */
bool ms_looks_like_int(const char *s) {
    if (!s || *s == '\0') {
        return false;
    }
    const char *p = s;
    if (*p == '+' || *p == '-') {
        p++;
    }
    if (*p == '\0') {
        return false;
    }
    for (; *p; p++) {
        if (!isdigit((unsigned char)*p)) {
            return false;
        }
    }
    return true;
}

bool ms_looks_like_negative_number(const char *s) {
    if (!s || s[0] != '-') {
        return false;
    }
    const char *p = s + 1;
    if (*p == '\0') {
        return false;
    }
    bool seen_digit = false, seen_dot = false;
    for (; *p; p++) {
        if (isdigit((unsigned char)*p)) {
            seen_digit = true;
        } else if (*p == '.' && !seen_dot) {
            seen_dot = true;
        } else {
            return false;
        }
    }
    return seen_digit;
}
