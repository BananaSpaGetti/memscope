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

typedef struct {
    bool triggered;
    bool negative;
    char magnitude[128];
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

/* argparse's end-of-options separator. Removes the FIRST "--" from argv in place, shifting
 * the rest down and decrementing *argc, and returns the index from which every remaining
 * token is a positional -- never an option, never -h/--help. With no "--" present it returns
 * the unchanged *argc, so a caller can use the result as an upper bound unconditionally.
 *
 * Measured against CPython's argparse rather than assumed, because two halves of it are easy
 * to get wrong:
 *   - only the FIRST "--" is removed. A second is a literal positional, which is why
 *     `dump -- -- 1234 0x400` reports `argument pid: invalid int value: '--'`.
 *   - a "--help" AFTER the separator is not help. `read -- --help` is an error about a
 *     positional, so a help scan has to stop at the boundary this returns.
 * Each parser level does this independently, which is why `memscope -- read 1234 0x400`
 * runs read rather than reporting an unrecognized argument. */
int ms_strip_dashdash(int *argc, char **argv);

#endif /* MEMSCOPE_UTIL_H */
