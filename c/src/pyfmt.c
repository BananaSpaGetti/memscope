/*
 * pyfmt.c -- see pyfmt.h.
 */
#include "pyfmt.h"

#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Formats the shortest decimal string that round-trips to `value`, the way Python's float
 * repr does (str(float) is repr(float) since Python 3) -- fixed notation for magnitudes
 * between 1e-4 and 1e16, scientific otherwise, always at least one digit either side of the
 * point, exponents signed and at least two digits wide. */
void ms_format_python_double(double value, char *out, size_t out_cap) {
    if (isnan(value)) {
        snprintf(out, out_cap, "nan");
        return;
    }
    if (isinf(value)) {
        snprintf(out, out_cap, "%s", value < 0 ? "-inf" : "inf");
        return;
    }

    int neg = signbit(value) ? 1 : 0;
    double mag = neg ? -value : value;

    /* Try an increasing number of significant digits and stop at the first that parses
     * back to exactly the same double -- the shortest round-tripping representation, which
     * is what Python's repr algorithm also produces. */
    char sci[64];
    int prec;
    for (prec = 0; prec <= 16; prec++) {
        snprintf(sci, sizeof(sci), "%.*e", prec, mag);
        if (strtod(sci, NULL) == mag) {
            break;
        }
    }

    char *e_pos = strchr(sci, 'e');
    int exponent = atoi(e_pos + 1);
    char digits[24];
    size_t dn = 0;
    for (char *p = sci; p < e_pos; p++) {
        if (*p != '.') {
            digits[dn++] = *p;
        }
    }
    digits[dn] = '\0';
    /* The round-trip search above should already avoid a trailing zero, but trim defensively
     * -- a shorter digit string with the same value is possible when the dropped digit is 0. */
    while (dn > 1 && digits[dn - 1] == '0') {
        digits[--dn] = '\0';
    }

    int decpt = exponent + 1; /* position of the decimal point, counted from the first digit */
    char body[64];
    size_t bn = 0;

    if (decpt <= -4 || decpt > 16) {
        body[bn++] = digits[0];
        if (dn > 1) {
            body[bn++] = '.';
            memcpy(body + bn, digits + 1, dn - 1);
            bn += dn - 1;
        }
        int e = decpt - 1;
        bn += (size_t)snprintf(body + bn, sizeof(body) - bn, "e%c%02d", e < 0 ? '-' : '+',
                                abs(e));
    } else if (decpt <= 0) {
        body[bn++] = '0';
        body[bn++] = '.';
        for (int i = 0; i < -decpt; i++) {
            body[bn++] = '0';
        }
        memcpy(body + bn, digits, dn);
        bn += dn;
    } else if ((size_t)decpt >= dn) {
        memcpy(body + bn, digits, dn);
        bn += dn;
        for (int i = 0; i < decpt - (int)dn; i++) {
            body[bn++] = '0';
        }
        body[bn++] = '.';
        body[bn++] = '0';
    } else {
        memcpy(body + bn, digits, (size_t)decpt);
        bn += (size_t)decpt;
        body[bn++] = '.';
        memcpy(body + bn, digits + decpt, dn - (size_t)decpt);
        bn += dn - (size_t)decpt;
    }
    body[bn] = '\0';

    snprintf(out, out_cap, "%s%s", neg ? "-" : "", body);
}

/* Formats a decoded value the way Python's `"%s" % value` formats what unpack() returns:
 * plain decimal for the integer types, Python's shortest-round-trip repr for float/double. */
void ms_format_value(const MsValue *value, char *out, size_t out_cap) {
    if (ms_type_is_float(value->kind)) {
        ms_format_python_double(value->as.f, out, out_cap);
    } else if (ms_type_is_signed(value->kind)) {
        snprintf(out, out_cap, "%" PRId64, value->as.i);
    } else {
        snprintf(out, out_cap, "%" PRIu64, value->as.u);
    }
}
