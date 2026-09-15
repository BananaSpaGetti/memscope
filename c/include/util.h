/*
 * util.h -- small helpers shared across the port.
 *
 * Each of these existed two or three times over, for the same reason the pyfmt ones did: the
 * task that needed one could edit only a single file. The three copies of the hex parser had
 * drifted apart -- two checked for a NULL string and stripped whitespace but never looked at
 * errno, while the third checked ERANGE but did neither -- so the version here is the union
 * of what each copy got right.
 */
#ifndef MEMSCOPE_UTIL_H
#define MEMSCOPE_UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <wchar.h>

/* Parses `s` as base 16 the way Python's `int(s, 16)` does: an optional sign and an optional
 * "0x"/"0X" prefix, surrounding whitespace stripped, and the whole string consumed. Returns
 * false, leaving *out untouched, on a NULL or empty string, on trailing junk, or on a value
 * whose magnitude is too large for uint64_t.
 *
 * `reject_negative`, when true, also fails outright on a leading '-' rather than encoding it
 * -- right for every address this port parses (no such thing as a negative address exists).
 * When false, a negative literal is encoded as its two's-complement uint64_t bit pattern, which
 * plain unsigned addition against it reproduces exactly the same result as Python's real signed
 * subtraction would -- this is what a --resolve path's hop offsets need, since a negative hop
 * is a legitimate way to walk backward from a dereferenced pointer and Python's own parser
 * places no restriction on their sign. */
bool ms_parse_hex_u64(const char *s, bool reject_negative, uint64_t *out);

/* Narrows a UTF-16 Windows string into `out` as UTF-8, always NUL-terminated. */
void ms_wide_to_utf8(const wchar_t *wide, char *out, size_t out_size);

/* ASCII lowercase copy, always NUL-terminated, truncated to fit `out_size`. */
void ms_to_lower_copy(const char *in, char *out, size_t out_size);

/* True for the strings argparse's `type=int` accepts: an optional sign followed by at
 * least one decimal digit. Shape only -- it says nothing about range. */
bool ms_looks_like_int(const char *s);

/* True for the strings argparse treats as "looks like a negative number" rather than an
 * option: an optional leading '-' followed by digits, or digits with one decimal point
 * (Python's `^-\d+$|^-\d*\.\d+$`). This is what lets `-5` reach a positional argument
 * while `-0x10` and `--bogus` are rejected as unrecognized options instead -- a real
 * argparse quirk, not a guess: `-0x10` fails this shape (the `x` is not a digit), so
 * Python itself refuses it as an address before any int() conversion ever runs. */
bool ms_looks_like_negative_number(const char *s);

/* CPython's default sys.get_int_max_str_digits(). It bounds decimal conversions only; the
 * power-of-two bases have no such limit. */
#define MS_PY_INT_MAX_STR_DIGITS 4300

typedef struct {
    bool triggered;
    bool negative;
    /* Wide enough for every literal ms_parse_py_int will accept, so a magnitude reported
     * back to the user is never a truncated version of what they typed. It was 128, which
     * both truncated silently and made the parser's own digit buffer the smaller of the
     * two -- one bug wearing the other's clothes. */
    char magnitude[MS_PY_INT_MAX_STR_DIGITS + 52];
} MsIntOverflow;

/* Python's `int(s, base)` for base 10 or 16: optional surrounding whitespace, an optional
 * sign, an optional "0x"/"0X" prefix when base is 16, then digits of that base and nothing
 * else. On failure writes a message shaped like CPython's ValueError text into `err` (when
 * given) and returns false, leaving *out untouched.
 *
 * This is the single core both integer parsers in this port run on. `ms_parse_hex_u64` is a
 * call into it; so is repl.c's parse_py_int. They were separate implementations of the same
 * sign and overflow handling until a fix to one failed to reach the other. */
bool ms_parse_py_int(const char *s, int base, bool reject_negative, uint64_t *out,
                     MsIntOverflow *overflow, char *err, size_t err_cap);
/* Renders an integer literal the way Python's "%d" renders the int() it parses to: the sign
 * is reported through *negative (never set for a zero) and the returned pointer is the first
 * significant digit inside `literal`. For error messages that must echo a value too large
 * for int64_t, where printing the saturated parse would quote a number the user never typed.
 * Expects a literal ms_looks_like_int has already accepted. */
const char *ms_canonical_decimal(const char *literal, bool *negative);
/* Writes repr(literal) truncated to 200 characters, the way CPython's "%.200R" renders the
 * literal inside an invalid-literal message. `out` should be at least 208 bytes. */
void ms_py_literal_repr(const char *literal, char *out, size_t out_cap);
#endif /* MEMSCOPE_UTIL_H */
