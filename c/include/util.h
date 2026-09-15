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

/* Parses `s` as base 16 the way Python's `int(s, 16)` does, with one deliberate exception:
 * an optional leading '+' and an optional "0x"/"0X" prefix are accepted, surrounding
 * whitespace is stripped, and the whole string must be consumed -- but a leading '-' is
 * rejected rather than accepted and wrapped into a huge unsigned value the way Python
 * (arbitrary-precision) and a bare strtoull (two's-complement wraparound) would each handle
 * it differently. Returns false, leaving *out untouched, on a NULL or empty string, on a
 * leading '-', on trailing junk, or on a value too large for uint64_t. */
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

#endif /* MEMSCOPE_UTIL_H */
