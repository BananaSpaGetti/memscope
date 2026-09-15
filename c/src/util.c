/*
 * util.c -- see util.h.
 */
#include "util.h"

#include <windows.h>

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

bool ms_parse_hex_u64(const char *s, bool reject_negative, uint64_t *out) {
    if (!s) {
        return false;
    }
    while (isspace((unsigned char)*s)) {
        s++;
    }
    if (*s == '\0') {
        return false;
    }
    bool neg = false;
    const char *digits = s;
    if (*digits == '-') {
        /* strtoull would otherwise accept this itself and wrap the magnitude into a huge
         * unsigned value on its own -- the same hazard class the ERANGE saturation bug this
         * review round was dispatched over was, and it is what let `ptrscan --offset -1`
         * turn an intended no-op into an effectively unbounded scan. Handling the sign here
         * ourselves, rather than letting strtoull do it, is what lets a caller that wants a
         * negative literal (a --resolve path's hop offsets) get one on purpose instead of by
         * accident, while a caller that must never see one (every address this port parses)
         * can still refuse it outright. */
        if (reject_negative) {
            return false;
        }
        neg = true;
        digits++;
    }
    char *end = NULL;
    errno = 0;
    unsigned long long v = strtoull(digits, &end, 16);
    if (end == digits) {
        return false;
    }
    while (isspace((unsigned char)*end)) {
        end++;
    }
    /* A magnitude too large for uint64_t is rejected outright (errno == ERANGE). Python's
     * int(s, 16) has arbitrary precision and accepts a value like this; it is only later,
     * when the value is boxed into a ctypes.c_void_p for the actual ReadProcessMemory call,
     * that ctypes silently masks it down to its low 64 bits -- the exact "different address
     * than typed" hazard this function exists to avoid, just deferred a few lines. Rejecting
     * here instead of guessing at a truncation is the better of the two behaviours. */
    if (*end != '\0' || errno == ERANGE) {
        return false;
    }
    /* A negative literal is encoded as its two's-complement bit pattern: ordinary unsigned
     * addition against it (as ptrpath_resolve does for every hop) reproduces exactly the
     * same 64-bit result as Python's real signed subtraction would. */
    *out = neg ? (uint64_t)(-(long long)v) : (uint64_t)v;
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
