/*
 * values -- see include/values.h.
 */
#include "values.h"
#include "util.h"

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const char *name;
    size_t size;
    bool is_float;
    bool is_signed;
} TypeInfo;

static const TypeInfo TYPE_TABLE[MS_TYPE_COUNT] = {
    [MS_TYPE_INT8]   = {"int8",   1, false, true},
    [MS_TYPE_UINT8]  = {"uint8",  1, false, false},
    [MS_TYPE_INT16]  = {"int16",  2, false, true},
    [MS_TYPE_UINT16] = {"uint16", 2, false, false},
    [MS_TYPE_INT32]  = {"int32",  4, false, true},
    [MS_TYPE_UINT32] = {"uint32", 4, false, false},
    [MS_TYPE_INT64]  = {"int64",  8, false, true},
    [MS_TYPE_UINT64] = {"uint64", 8, false, false},
    [MS_TYPE_FLOAT]  = {"float",  4, true,  true},
    [MS_TYPE_DOUBLE] = {"double", 8, true,  true},
};

typedef struct {
    const char *name;
    const char *canonical;
} Alias;

static const Alias ALIASES[] = {
    {"int", "int32"}, {"uint", "uint32"}, {"long", "int64"},
    {"byte", "uint8"}, {"short", "int16"},
};

#define LIT_BUF_SIZE 128

/* CPython's default sys.get_int_max_str_digits(). It bounds decimal conversions only; the
 * power-of-two bases have no such limit, which is why the check that uses this sits inside
 * the base-10 branch. */
#define PY_INT_MAX_STR_DIGITS 4300

static bool type_ok(MsType kind) {
    return kind >= 0 && kind < MS_TYPE_COUNT;
}

const char *ms_type_name(MsType kind) {
    return type_ok(kind) ? TYPE_TABLE[kind].name : NULL;
}

size_t ms_type_size(MsType kind) {
    return type_ok(kind) ? TYPE_TABLE[kind].size : 0;
}

bool ms_type_is_float(MsType kind) {
    return type_ok(kind) && TYPE_TABLE[kind].is_float;
}

bool ms_type_is_signed(MsType kind) {
    return type_ok(kind) && TYPE_TABLE[kind].is_signed;
}

bool ms_resolve_type(const char *name, MsType *out) {
    const char *canonical = name;
    for (size_t i = 0; i < sizeof(ALIASES) / sizeof(ALIASES[0]); i++) {
        if (strcmp(name, ALIASES[i].name) == 0) {
            canonical = ALIASES[i].canonical;
            break;
        }
    }
    for (int kind = 0; kind < MS_TYPE_COUNT; kind++) {
        if (strcmp(canonical, TYPE_TABLE[kind].name) == 0) {
            *out = (MsType)kind;
            return true;
        }
    }
    return false;
}

static void set_err(char *err, size_t cap, const char *fmt, ...) {
    if (!err || cap == 0) {
        return;
    }
    va_list args;
    va_start(args, fmt);
    vsnprintf(err, cap, fmt, args);
    va_end(args);
}

/* Trims leading and trailing whitespace, returning false for an all-whitespace or empty
 * string. `*start`/`*end` bound the surviving slice (end is exclusive, not NUL-terminated). */
static bool trim(const char *s, const char **start, const char **end) {
    while (*s && isspace((unsigned char)*s)) {
        s++;
    }
    const char *e = s + strlen(s);
    while (e > s && isspace((unsigned char)e[-1])) {
        e--;
    }
    *start = s;
    *end = e;
    return e > s;
}

static void write_le(uint8_t *out, uint64_t value, size_t size) {
    for (size_t i = 0; i < size; i++) {
        out[i] = (uint8_t)((value >> (8 * i)) & 0xFF);
    }
}

/* Parses the magnitude and sign of an integer literal the way Python's int(literal, 0)
 * does: an optional leading sign, then 0x/0X, 0o/0O, 0b/0B or plain decimal. Each prefixed
 * form is handled by hand and fed to strtoull at the matching base, since C's base-0
 * convention only knows the 0x prefix and treats ANY other leading zero as octal -- exactly
 * the divergence that made "0123" and "010" search for the wrong number. A plain decimal is
 * therefore parsed at base 10 after independently checking Python's leading-zero rule: a
 * leading zero is only legal when every digit is zero ("0" and "00" are fine, "010" is not).
 *
 * Python also accepts underscores as digit separators (1_000 == 1000, with a grammar of
 * where they may appear). That is not implemented here -- it would add a second parsing
 * pass for comparatively little real-world benefit next to the leading-zero fix above -- so
 * a literal containing '_' is rejected the same way plain garbage is. */
/* CPython truncates the literal it quotes back; see ms_py_literal_repr. */
static void invalid_literal(char *err, size_t err_cap, const char *literal) {
    char shown[208];
    ms_py_literal_repr(literal, shown, sizeof(shown));
    set_err(err, err_cap, "invalid literal for int() with base 0: %s", shown);
}

static bool parse_number_literal(const char *literal, bool *negative, uint64_t *magnitude,
                                  bool *overflowed, char *err, size_t err_cap) {
    const char *start, *end;
    if (!trim(literal, &start, &end)) {
        invalid_literal(err, err_cap, literal);
        return false;
    }
    /* Nothing is copied into a fixed buffer until the digits have been counted down to a
     * length that certainly fits one. The previous version copied first and rejected any
     * literal of LIT_BUF_SIZE characters or more as invalid -- but Python has no such
     * bound, so `scan` on a 200-digit value answered "invalid literal" where memscope.py
     * answered that the value is out of range for the scan type. Found by sweeping literal
     * length; the hand-picked cases this parser was checked against were all short. */
    const char *p = start;
    bool neg = false;
    if (p < end && (*p == '+' || *p == '-')) {
        neg = (*p == '-');
        p++;
    }
    if (p >= end) {
        invalid_literal(err, err_cap, literal);
        return false;
    }

    int base = 10;
    if (end - p >= 2 && p[0] == '0' && (p[1] == 'b' || p[1] == 'B')) {
        base = 2;
        p += 2;
    } else if (end - p >= 2 && p[0] == '0' && (p[1] == 'o' || p[1] == 'O')) {
        base = 8;
        p += 2;
    } else if (end - p >= 2 && p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
        base = 16;
        p += 2;
    }
    if (p >= end) {
        invalid_literal(err, err_cap, literal);
        return false;
    }

    /* Every character must be a digit of the chosen base. This replaces the old strtoull
     * end-pointer check, which could not run until after the copy above. */
    for (const char *q = p; q < end; q++) {
        int ok;
        switch (base) {
            case 2:  ok = (*q == '0' || *q == '1'); break;
            case 8:  ok = (*q >= '0' && *q <= '7'); break;
            case 16: ok = isxdigit((unsigned char)*q); break;
            default: ok = isdigit((unsigned char)*q); break;
        }
        if (!ok) {
            invalid_literal(err, err_cap, literal);
            return false;
        }
    }

    if (base == 10) {
        /* Plain decimal: a leading zero is only legal when the whole literal is zero. */
        if (*p == '0') {
            for (const char *q = p; q < end; q++) {
                if (*q != '0') {
                    set_err(err, err_cap,
                            "invalid literal for int() with base 0: '%s'", literal);
                    return false;
                }
            }
        }
        /* CPython's own ceiling on a decimal conversion, and only on a decimal one: the
         * power-of-two bases are exempt from it. Measured -- the count is every digit
         * after the sign, leading zeros included, and an invalid character is reported
         * before this rather than after it. */
        size_t digit_count = (size_t)(end - p);
        if (digit_count > PY_INT_MAX_STR_DIGITS) {
            set_err(err, err_cap,
                    "Exceeds the limit (%d digits) for integer string conversion: value has "
                    "%zu digits; use sys.set_int_max_str_digits() to increase the limit",
                    PY_INT_MAX_STR_DIGITS, digit_count);
            return false;
        }
    }

    while (p + 1 < end && *p == '0') {
        p++;
    }

    /* Past this many significant digits the value cannot fit in uint64_t whatever they are,
     * so the answer is the same one strtoull would reach through ERANGE -- without needing
     * a buffer big enough to hold the literal. */
    static const size_t max_digits[17] = {
        [2] = 64, [8] = 22, [10] = 20, [16] = 16,
    };
    size_t significant = (size_t)(end - p);
    if (significant > max_digits[base]) {
        *negative = neg;
        *magnitude = UINT64_MAX;
        *overflowed = true;
        return true;
    }

    char buf[LIT_BUF_SIZE];
    memcpy(buf, p, significant);
    buf[significant] = '\0';

    char *endp;
    errno = 0;
    unsigned long long mag = strtoull(buf, &endp, base);
    if (endp == buf || *endp != '\0') {
        invalid_literal(err, err_cap, literal);
        return false;
    }

    *negative = neg;
    *magnitude = (uint64_t)mag;
    *overflowed = (errno == ERANGE);
    return true;
}

static bool pack_integer(const char *literal, MsType kind, uint8_t *out,
                          char *err, size_t err_cap) {
    const TypeInfo *info = &TYPE_TABLE[kind];
    size_t size = info->size;

    bool neg;
    uint64_t mag;
    bool overflowed;
    if (!parse_number_literal(literal, &neg, &mag, &overflowed, err, err_cap)) {
        return false;
    }

    if (!info->is_signed) {
        uint64_t max = size == 8 ? UINT64_MAX : ((uint64_t)1 << (size * 8)) - 1;
        /* An over-large literal (strtoull hit ERANGE) is reported the same way as a
         * merely out-of-range one -- Python's int() itself has no upper bound, so it is
         * struct.pack's range check that rejects it, with the same wording either way.
         * A negative sign is only a rejection when the magnitude is non-zero: Python's
         * int('-0', 0) == 0, and struct.pack packs that zero happily for an unsigned type. */
        if (overflowed || (neg && mag != 0) || mag > max) {
            set_err(err, err_cap, "%s format requires 0 <= number <= %llu",
                    info->name, (unsigned long long)max);
            return false;
        }
        write_le(out, mag, size);
        return true;
    }

    /* Signed: the magnitude may be one past the positive max when negated (INT_MIN), which
     * cannot be represented as a positive int64_t, so the range check works in uint64_t. */
    int64_t min_limit;
    uint64_t max_magnitude;
    switch (kind) {
        case MS_TYPE_INT8:  min_limit = INT8_MIN;  max_magnitude = (uint64_t)INT8_MAX;  break;
        case MS_TYPE_INT16: min_limit = INT16_MIN; max_magnitude = (uint64_t)INT16_MAX; break;
        case MS_TYPE_INT32: min_limit = INT32_MIN; max_magnitude = (uint64_t)INT32_MAX; break;
        case MS_TYPE_INT64: min_limit = INT64_MIN; max_magnitude = (uint64_t)INT64_MAX; break;
        default: return false; /* unreachable: only the four signed integer kinds reach here */
    }
    uint64_t max_negative_magnitude = max_magnitude + 1; /* -min_limit, computed without overflow */

    int64_t value;
    if (neg) {
        if (overflowed || mag > max_negative_magnitude) {
            set_err(err, err_cap, "%s format requires %lld <= number <= %lld",
                    info->name, (long long)min_limit, (long long)max_magnitude);
            return false;
        }
        value = (mag == max_negative_magnitude) ? min_limit : -(int64_t)mag;
    } else {
        if (overflowed || mag > max_magnitude) {
            set_err(err, err_cap, "%s format requires %lld <= number <= %lld",
                    info->name, (long long)min_limit, (long long)max_magnitude);
            return false;
        }
        value = (int64_t)mag;
    }
    write_le(out, (uint64_t)value, size);
    return true;
}

static bool pack_float(const char *literal, MsType kind, uint8_t *out,
                        char *err, size_t err_cap) {
    const char *start, *end;
    if (!trim(literal, &start, &end)) {
        set_err(err, err_cap, "could not convert string to float: '%s'", literal);
        return false;
    }
    size_t len = (size_t)(end - start);
    if (len >= LIT_BUF_SIZE) {
        set_err(err, err_cap, "could not convert string to float: '%s'", literal);
        return false;
    }
    char buf[LIT_BUF_SIZE];
    memcpy(buf, start, len);
    buf[len] = '\0';

    /* strtod accepts C99 hex-float literals ("0x10", "0x1.8p3") that Python's float()
     * rejects outright; reject them by hand before strtod gets a chance to parse one. */
    const char *digits = buf;
    if (*digits == '+' || *digits == '-') {
        digits++;
    }
    if (digits[0] == '0' && (digits[1] == 'x' || digits[1] == 'X')) {
        set_err(err, err_cap, "could not convert string to float: '%s'", literal);
        return false;
    }

    char *endp;
    errno = 0;
    double value = strtod(buf, &endp);
    if (endp == buf || *endp != '\0') {
        set_err(err, err_cap, "could not convert string to float: '%s'", literal);
        return false;
    }

    if (kind == MS_TYPE_FLOAT) {
        float f = (float)value;
        memcpy(out, &f, sizeof(f));
    } else {
        memcpy(out, &value, sizeof(value));
    }
    return true;
}

bool ms_pack(const char *literal, MsType kind, uint8_t *out, size_t *out_len,
             char *err, size_t err_cap) {
    if (!type_ok(kind)) {
        set_err(err, err_cap, "unknown type");
        if (out_len) {
            *out_len = 0;
        }
        return false;
    }
    if (out_len) {
        *out_len = TYPE_TABLE[kind].size;
    }
    if (TYPE_TABLE[kind].is_float) {
        return pack_float(literal, kind, out, err, err_cap);
    }
    return pack_integer(literal, kind, out, err, err_cap);
}

bool ms_unpack(const uint8_t *data, size_t size, MsType kind, MsValue *out) {
    if (!type_ok(kind)) {
        return false;
    }
    size_t need = TYPE_TABLE[kind].size;
    if (size < need) {
        return false;
    }
    out->kind = kind;
    switch (kind) {
        case MS_TYPE_INT8: {
            int8_t v;
            memcpy(&v, data, sizeof(v));
            out->as.i = v;
            break;
        }
        case MS_TYPE_UINT8: {
            uint8_t v;
            memcpy(&v, data, sizeof(v));
            out->as.u = v;
            break;
        }
        case MS_TYPE_INT16: {
            int16_t v;
            memcpy(&v, data, sizeof(v));
            out->as.i = v;
            break;
        }
        case MS_TYPE_UINT16: {
            uint16_t v;
            memcpy(&v, data, sizeof(v));
            out->as.u = v;
            break;
        }
        case MS_TYPE_INT32: {
            int32_t v;
            memcpy(&v, data, sizeof(v));
            out->as.i = v;
            break;
        }
        case MS_TYPE_UINT32: {
            uint32_t v;
            memcpy(&v, data, sizeof(v));
            out->as.u = v;
            break;
        }
        case MS_TYPE_INT64: {
            int64_t v;
            memcpy(&v, data, sizeof(v));
            out->as.i = v;
            break;
        }
        case MS_TYPE_UINT64: {
            uint64_t v;
            memcpy(&v, data, sizeof(v));
            out->as.u = v;
            break;
        }
        case MS_TYPE_FLOAT: {
            float v;
            memcpy(&v, data, sizeof(v));
            out->as.f = (double)v;
            break;
        }
        case MS_TYPE_DOUBLE: {
            double v;
            memcpy(&v, data, sizeof(v));
            out->as.f = v;
            break;
        }
        default:
            return false;
    }
    return true;
}

size_t ms_find_aligned(const uint8_t *data, size_t data_len, const uint8_t *needle,
                        size_t needle_len, size_t align, size_t *out, size_t out_cap) {
    if (needle_len == 0 || align == 0 || data_len < needle_len) {
        return 0;
    }
    /* Python's find_aligned filters re.finditer(re.escape(needle), data), and re.finditer
     * finds *non-overlapping* matches, scanning for the next occurrence anywhere after the
     * end of the previous one. A match starting at an unaligned offset still consumes
     * needle_len bytes and can hide an aligned occurrence underneath it -- e.g. searching
     * four zero bytes in 0xFF followed by eight zero bytes finds unaligned matches at 1 and
     * 5 and reports neither, even though bytes 4..8 also equal the needle, because that
     * span was already consumed by the match at offset 1. A search that simply tested every
     * aligned offset independently would report offset 4 and diverge from the oracle. */
    size_t count = 0;
    size_t pos = 0;
    while (pos + needle_len <= data_len) {
        if (memcmp(data + pos, needle, needle_len) == 0) {
            if (pos % align == 0) {
                if (count < out_cap) {
                    out[count] = pos;
                }
                count++;
            }
            pos += needle_len;
        } else {
            pos += 1;
        }
    }
    return count;
}
