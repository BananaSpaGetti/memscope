/*
 * values -- the ten scalar types MemScope knows about, and how to move them between text,
 * bytes and a decoded number.
 *
 * This mirrors the TYPES table, resolve_type(), pack()/unpack() and find_aligned() in
 * MemScope/memscope.py exactly: the same ten type names, the same five aliases, integers
 * parsed the way Python's int(value, 0) parses them (0x/0o/0b prefixes and decimal, with
 * out-of-range values rejected rather than truncated, the way struct.pack() rejects them),
 * and floats/doubles parsed the way Python's float() parses them. x64 is little-endian, so
 * pack/unpack are direct little-endian load/store, not a byte-swapping routine.
 */
#ifndef MEMSCOPE_VALUES_H
#define MEMSCOPE_VALUES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    MS_TYPE_INT8,
    MS_TYPE_UINT8,
    MS_TYPE_INT16,
    MS_TYPE_UINT16,
    MS_TYPE_INT32,
    MS_TYPE_UINT32,
    MS_TYPE_INT64,
    MS_TYPE_UINT64,
    MS_TYPE_FLOAT,
    MS_TYPE_DOUBLE,
    MS_TYPE_COUNT
} MsType;

/* No packed value is wider than 8 bytes; buffers passed to ms_pack must be at least this. */
#define MS_MAX_VALUE_SIZE 8

/* A decoded scalar, tagged by which union member holds it: `i` for the signed integer
 * types, `u` for the unsigned integer types, `f` for float and double (float widened to
 * double, the way a Python float always is). */
typedef struct {
    MsType kind;
    union {
        int64_t i;
        uint64_t u;
        double f;
    } as;
} MsValue;

/* The canonical name of a type ("int32", "float", ...), or NULL for an out-of-range kind. */
const char *ms_type_name(MsType kind);

/* Packed size in bytes (1, 2, 4 or 8), or 0 for an out-of-range kind. */
size_t ms_type_size(MsType kind);

bool ms_type_is_float(MsType kind);
bool ms_type_is_signed(MsType kind);

/* Resolves a type name, applying the five aliases (int->int32, uint->uint32, long->int64,
 * byte->uint8, short->int16). Returns true and sets *out on success; returns false, leaving
 * *out untouched, for an unknown name -- the same case Python's resolve_type() raises
 * ValueError for. */
bool ms_resolve_type(const char *name, MsType *out);

/* Parses `literal` as `kind` and writes its little-endian bytes into `out` (which must have
 * room for at least MS_MAX_VALUE_SIZE bytes). *out_len receives the number of bytes written
 * (== ms_type_size(kind)) whether or not parsing succeeds. Integers accept the same syntax
 * as Python's int(literal, 0) -- decimal, and 0x/0o/0b prefixes, with an optional leading
 * sign -- and a value outside the type's range is rejected rather than silently truncated.
 * Floats and doubles are parsed the way Python's float() parses them.
 *
 * Returns false on a malformed literal or an out-of-range integer. If `err` is non-NULL, a
 * NUL-terminated message describing the failure is written there, truncated to err_cap
 * bytes. */
bool ms_pack(const char *literal, MsType kind, uint8_t *out, size_t *out_len,
             char *err, size_t err_cap);

/* Decodes `size` little-endian bytes at `data` as `kind` into *out. `size` must be at least
 * ms_type_size(kind); a longer buffer is fine, only the leading bytes are used, matching
 * Python's unpack(data[:size], kind). Returns false without touching *out if `size` is too
 * small, the case Python's unpack() returns None for. */
bool ms_unpack(const uint8_t *data, size_t size, MsType kind, MsValue *out);

/* Offsets within `data` where the `needle_len` bytes at `needle` occur, restricted to
 * offsets that are multiples of `align` -- a plain byte comparison at each aligned offset,
 * not a general substring search. Writes up to `out_cap` offsets, in ascending order, into
 * `out` (which may be NULL if out_cap is 0) and returns the total number of matches found,
 * which may exceed out_cap. */
size_t ms_find_aligned(const uint8_t *data, size_t data_len, const uint8_t *needle,
                        size_t needle_len, size_t align, size_t *out, size_t out_cap);

#endif
