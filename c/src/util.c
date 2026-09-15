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
            snprintf(err, err_cap, "invalid literal for int() with base %d: '%s'", base, s);
        }
        return false;
    }

    char digits[128];
    size_t len = (size_t)(end - p);
    if (len >= sizeof(digits)) {
        if (err) {
            snprintf(err, err_cap, "invalid literal for int() with base %d: '%s'", base, s);
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
            snprintf(err, err_cap, "invalid literal for int() with base %d: '%s'", base, s);
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

    *out = neg ? (uint64_t)(-(long long)magnitude) : (uint64_t)magnitude;
    return true;
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

int ms_strip_dashdash(int *argc, char **argv) {
    for (int i = 0; i < *argc; i++) {
        if (strcmp(argv[i], "--") == 0) {
            for (int j = i; j + 1 < *argc; j++) {
                argv[j] = argv[j + 1];
            }
            (*argc)--;
            return i;
        }
    }
    return *argc;
}
