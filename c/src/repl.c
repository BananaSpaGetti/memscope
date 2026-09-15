/*
 * repl.c -- the interactive scanning REPL behind memscope's `scan` subcommand.
 *
 * Native port of the repl()/_dispatch() functions in MemScope/memscope.py: `help`, `type`,
 * `scan`, `next`, `list`, `write`, `freeze`, `unfreeze`, `pscan`, `reset`, and `quit`/`exit`/
 * `q`, plus the blank-line re-apply of every frozen write. Every command is wrapped so a bad
 * argument prints an error and returns to the prompt instead of ending the session, mirroring
 * the Python REPL catching (ValueError, IndexError, OSError, struct.error) around each
 * dispatched command -- here that is simply: a parsing or packing helper reports failure, the
 * caller prints "  error: <message>" and returns without touching state it has not already
 * committed to. The one exception, matching memscope.py's own inner try/except, is `type`:
 * a missing argument or an unknown type name is printed bare, with no "  error: " prefix.
 *
 * `pscan` calls into ptrpath.c/ptrmap.c the way memscope.py's `pscan` command calls into the
 * sibling ptrscan module: it builds a PointerMap and module list for the attached process and
 * runs ptrpath_find(), matching the REPL's own summary line and "ok"/"stale" verification --
 * not the CLI's three-way "ok"/"-> 0xADDR"/"stale", which is `ptrscan.py`'s own `main()`, a
 * different call site with a different format string.
 */

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "process.h"
#include "ptrmap.h"
#include "ptrpath.h"
#include "pyfmt.h"
#include "scanner.h"
#include "util.h"
#include "values.h"

/* --- Python-compatible number and string formatting -------------------------------------- */

/* A minimal approximation of Python's repr() for an ASCII string with no control characters:
 * single-quoted, unless the text itself contains a single quote and no double quote, in which
 * case double quotes are used instead -- enough for the plain command/type-name tokens this
 * REPL ever wraps in %r. */
static void py_repr(const char *s, char *out, size_t out_cap) {
    bool has_single = strchr(s, '\'') != NULL;
    bool has_double = strchr(s, '"') != NULL;
    char quote = (has_single && !has_double) ? '"' : '\'';
    size_t o = 0;
    if (o + 1 < out_cap) {
        out[o++] = quote;
    }
    for (const char *p = s; *p && o + 2 < out_cap; p++) {
        if (*p == quote || *p == '\\') {
            out[o++] = '\\';
        }
        out[o++] = *p;
    }
    if (o + 1 < out_cap) {
        out[o++] = quote;
    }
    out[o] = '\0';
}

/* --- Python-compatible integer literal parsing -------------------------------------------- */

/* Extra detail parse_py_int reports when a literal's digits are well-formed but its magnitude
 * does not fit in 64 bits -- the one shape a bare pass/fail cannot carry, and the one thing
 * `list`'s count needs that no other caller does: Python's int() has no upper bound, so a count
 * this far outside the candidate range only ever means "all of them" (positive) or "none of
 * them" (negative), and the "... N more" tally then needs the literal's exact decimal
 * magnitude -- which strtoull's ERANGE has already discarded by the time it fires, so it is
 * captured here, before that, instead. Every other caller passes NULL: an address or a depth
 * this large has no such fallback and is simply an error (see parse_py_int's own comment). */
/* The int parser lives in util.c now -- see ms_parse_py_int there. It used to be defined
 * here, with `ms_parse_hex_u64` in util.c as a second, independent implementation of the
 * same sign and overflow handling; a fix to one had no structural reason to reach the
 * other, and that is exactly how an earlier regression happened. One core, two callers. */
#define PyIntOverflow MsIntOverflow

static bool parse_py_int(const char *s, int base, bool reject_negative, uint64_t *out,
                          MsIntOverflow *overflow, char *err, size_t err_cap) {
    return ms_parse_py_int(s, base, reject_negative, out, overflow, err, err_cap);
}/* Adds a small non-negative integer to a large non-negative decimal literal, both given and
 * returned as ASCII digit strings -- schoolbook addition from the least significant digit, the
 * way `list`'s "... N more" tally needs when the count argument's magnitude did not fit in 64
 * bits but Python's arbitrary-precision int still adds it exactly. `add` is always a candidate
 * count, which never needs more than a handful of digits, so only `magnitude`'s length (already
 * bounded by parse_py_int's own digit buffer) drives how large this can get. */
static void add_decimal(const char *magnitude, uint64_t add, char *out, size_t out_cap) {
    char add_digits[32];
    snprintf(add_digits, sizeof(add_digits), "%llu", (unsigned long long)add);
    size_t mlen = strlen(magnitude);
    size_t alen = strlen(add_digits);
    size_t rlen = (mlen > alen ? mlen : alen) + 1;

    /* Wide enough for any magnitude the parser accepts. At 192 this clamp did not truncate
     * the printed tally, it silently dropped the HIGH-order digits of the sum and printed a
     * smaller number as if it were the answer -- `list` on a 200-digit negative count
     * reported 205 digits of a 221-digit total. */
    char reversed[MS_PY_INT_MAX_STR_DIGITS + 64];
    if (rlen > sizeof(reversed)) {
        rlen = sizeof(reversed);
    }
    size_t rpos = 0;
    int carry = 0;
    for (size_t i = 0; i < rlen; i++) {
        int a = (i < mlen) ? magnitude[mlen - 1 - i] - '0' : 0;
        int b = (i < alen) ? add_digits[alen - 1 - i] - '0' : 0;
        int sum = a + b + carry;
        carry = sum / 10;
        reversed[rpos++] = (char)('0' + sum % 10);
    }
    /* Strip every leading zero the addition produced, not just one -- a magnitude
     * padded with extra zeros before its significant digits (an unusual but valid
     * literal, e.g. a 30-digit number written with five extra leading zeros) would
     * otherwise leave some of them in the printed tally. */
    while (rpos > 1 && reversed[rpos - 1] == '0') {
        rpos--;
    }
    size_t o = 0;
    while (rpos > 0 && o + 1 < out_cap) {
        out[o++] = reversed[--rpos];
    }
    out[o] = '\0';
}

/* --- frozen writes -------------------------------------------------------------------------- */

/* One `freeze`d address: the literal text and type it was frozen under, replayed verbatim on
 * every blank line -- mirroring memscope.py's `frozen[address] = (rest[1], scanner.kind)`,
 * which keeps the type at freeze time rather than the scanner's current type. */
typedef struct {
    uint64_t address;
    char literal[64];
    MsType kind;
} FrozenWrite;

typedef struct {
    FrozenWrite *items;
    size_t count;
    size_t capacity;
} FrozenSet;

/* Inserts or updates `address`, preserving dict-like insertion order: an address already
 * present keeps its position and only its literal/kind change. Returns false, leaving `fs`
 * unchanged, if growing the array failed -- the way ptrmap.c's append_pair reports it. */
static bool frozen_set(FrozenSet *fs, uint64_t address, const char *literal, MsType kind) {
    for (size_t i = 0; i < fs->count; i++) {
        if (fs->items[i].address == address) {
            snprintf(fs->items[i].literal, sizeof(fs->items[i].literal), "%s", literal);
            fs->items[i].kind = kind;
            return true;
        }
    }
    if (fs->count == fs->capacity) {
        size_t new_capacity = fs->capacity ? fs->capacity * 2 : 8;
        FrozenWrite *grown = (FrozenWrite *)realloc(fs->items, new_capacity * sizeof(FrozenWrite));
        if (!grown) {
            return false;
        }
        fs->items = grown;
        fs->capacity = new_capacity;
    }
    FrozenWrite *entry = &fs->items[fs->count++];
    entry->address = address;
    snprintf(entry->literal, sizeof(entry->literal), "%s", literal);
    entry->kind = kind;
    return true;
}

static void frozen_clear(FrozenSet *fs) {
    fs->count = 0;
}

/* Re-applies every frozen write, in insertion order -- the blank-line command. Mirrors
 * `for address, (value, kind) in frozen.items(): scanner.process.write(address, pack(value,
 * kind))`. A literal that no longer packs under its own recorded type cannot happen (it was
 * proven to pack at freeze time and neither the literal nor the type is ever changed after
 * that), so failures here are silently skipped rather than reported, the same as Python
 * simply not raising in that path. */
static void frozen_reapply(FrozenSet *fs, ProcessIO *process) {
    for (size_t i = 0; i < fs->count; i++) {
        uint8_t payload[MS_MAX_VALUE_SIZE];
        size_t payload_len = 0;
        if (ms_pack(fs->items[i].literal, fs->items[i].kind, payload, &payload_len, NULL, 0)) {
            process->write(process, fs->items[i].address, payload, payload_len);
        }
    }
}

/* --- the `Inside the scanner` help text, verbatim from memscope.py's __doc__ slice --------- */

static const char HELP_TEXT[] =
    "Inside the scanner (one process, state kept between commands):\n"
    "\n"
    "    scan 100            addresses currently holding the value 100\n"
    "    scan                snapshot everything, to narrow by how it changes later\n"
    "    next 120            of the candidates, those now holding 120\n"
    "    next up|down|same|changed         narrow by how each candidate moved\n"
    "    list [n]            show candidates and their current values\n"
    "    type float          int8/16/32/64, uint*, float, double  (resets the scan)\n"
    "    write <addr> <v>    write one address (asks first)\n"
    "    freeze <addr> <v>   keep writing one address every tick until you stop\n"
    "    pscan <addr>        find a static pointer path to an address that moves (see "
    "ptrscan.py)\n"
    "    reset               throw the candidates away and start over\n"
    "    quit\n";

/* --- small line/token helpers -------------------------------------------------------------- */

/* Reads one line from stdin with no length limit, stripping the trailing newline. Returns a
 * malloc'd, NUL-terminated string the caller frees, or NULL at end-of-file with nothing read
 * -- mirroring input() raising EOFError. Also returns NULL, discarding whatever was read so
 * far, if growing the buffer failed. */
static char *read_line(void) {
    size_t capacity = 128;
    size_t length = 0;
    char *buf = (char *)malloc(capacity);
    if (!buf) {
        return NULL;
    }
    bool any = false;
    int c;
    while ((c = fgetc(stdin)) != EOF) {
        any = true;
        if (c == '\n') {
            break;
        }
        if (length + 1 >= capacity) {
            size_t new_capacity = capacity * 2;
            char *grown = (char *)realloc(buf, new_capacity);
            if (!grown) {
                free(buf);
                return NULL;
            }
            buf = grown;
            capacity = new_capacity;
        }
        buf[length++] = (char)c;
    }
    if (!any) {
        free(buf);
        return NULL;
    }
    /* A line ending in "\r\n" (piped from a Windows-authored script) should strip the same
     * way stripping trailing whitespace below already handles it; nothing extra needed here. */
    buf[length] = '\0';
    return buf;
}

static void strip_whitespace(char *s) {
    char *start = s;
    while (*start && isspace((unsigned char)*start)) {
        start++;
    }
    size_t len = strlen(start);
    while (len > 0 && isspace((unsigned char)start[len - 1])) {
        len--;
    }
    memmove(s, start, len);
    s[len] = '\0';
}

#define REPL_MAX_TOKENS 8

typedef struct {
    char *command;
    char *rest[REPL_MAX_TOKENS];
    int rest_count;
} ReplTokens;

/* Splits `line` (already trimmed and non-empty) on runs of whitespace, the way Python's
 * `str.split()` with no arguments does. `line` is modified in place; the returned tokens
 * point into it. Extra tokens past REPL_MAX_TOKENS are dropped -- every command this REPL
 * knows takes at most a handful of arguments. */
static void tokenize(char *line, ReplTokens *tokens) {
    tokens->command = NULL;
    tokens->rest_count = 0;
    char *p = line;
    char **slot = &tokens->command;
    int stored = 0;
    while (*p) {
        while (*p && isspace((unsigned char)*p)) {
            *p++ = '\0';
        }
        if (!*p) {
            break;
        }
        char *token_start = p;
        while (*p && !isspace((unsigned char)*p)) {
            p++;
        }
        if (slot == &tokens->command) {
            tokens->command = token_start;
            slot = NULL;
        } else if (stored < REPL_MAX_TOKENS) {
            tokens->rest[stored++] = token_start;
        }
    }
    tokens->rest_count = stored;
}

/* --- command implementations --------------------------------------------------------------- */

static const char *TYPE_NAMES_JOINED =
    "int8, uint8, int16, uint16, int32, uint32, int64, uint64, float, double";

/* `type <name>` -- mirrors its own inner try/except in memscope.py: a missing argument or an
 * unknown name is printed bare (no "  error: " prefix), and the scan is reset only on
 * success. */
static void cmd_type(Scanner *scanner, ReplTokens *tokens) {
    if (tokens->rest_count < 1) {
        printf("list index out of range\n");
        return;
    }
    MsType kind;
    if (!ms_resolve_type(tokens->rest[0], &kind)) {
        char repr[128];
        py_repr(tokens->rest[0], repr, sizeof(repr));
        printf("unknown type %s; one of %s\n", repr, TYPE_NAMES_JOINED);
        return;
    }
    scanner->kind = kind;
    scanner_reset(scanner);
    printf("type is %s; scan reset\n", ms_type_name(kind));
}

/* `scan [value]` -- an exact first scan with a value, or a snapshot without one. */
static void cmd_scan(Scanner *scanner, ReplTokens *tokens) {
    if (tokens->rest_count >= 1) {
        ScanCounts counts;
        char err[256];
        if (!scanner_first_scan(scanner, tokens->rest[0], &counts, err, sizeof(err))) {
            printf("  error: %s\n", err);
            return;
        }
        printf("%zu addresses hold %s\n", counts.count, tokens->rest[0]);
    } else {
        printf("snapshotting memory to narrow by movement...\n");
        ScanCounts counts;
        scanner_snapshot(scanner, &counts);
        char note[128];
        note[0] = '\0';
        if (counts.truncated) {
            snprintf(note, sizeof(note), "  (capped at %llu -- the rest of memory was not "
                                          "recorded)",
                     (unsigned long long)scanner->max_hits);
        }
        printf("%zu values recorded%s; change the value in the program, then `next up`, "
               "`next down`, `next changed` or `next same`\n",
               counts.count, note);
    }
}

/* `next <value>|up|down|same|changed`. */
static void cmd_next(Scanner *scanner, ReplTokens *tokens) {
    if (!scanner->has_scanned) {
        printf("scan first\n");
        return;
    }
    if (tokens->rest_count < 1) {
        printf("next <value> | up | down | same | changed\n");
        return;
    }
    const char *arg = tokens->rest[0];
    if (strcmp(arg, "up") == 0 || strcmp(arg, "down") == 0 || strcmp(arg, "same") == 0 ||
        strcmp(arg, "changed") == 0) {
        ScannerMove how = strcmp(arg, "up") == 0     ? SCANNER_MOVE_UP
                           : strcmp(arg, "down") == 0 ? SCANNER_MOVE_DOWN
                           : strcmp(arg, "same") == 0 ? SCANNER_MOVE_SAME
                                                       : SCANNER_MOVE_CHANGED;
        size_t kept = scanner_narrow_move(scanner, how);
        printf("%zu left\n", kept);
    } else {
        size_t kept;
        char err[256];
        if (!scanner_narrow_value(scanner, arg, &kept, err, sizeof(err))) {
            printf("  error: %s\n", err);
            return;
        }
        printf("%zu left\n", kept);
    }
}

/* `list [n]` (default 20). */
static void cmd_list(Scanner *scanner, ReplTokens *tokens) {
    if (scanner->count == 0) {
        printf("no candidates\n");
        return;
    }
    int64_t limit = 20;
    /* A count whose magnitude does not fit in 64 bits is the one place `list` still needs
     * Python's arbitrary precision: a huge positive one simply means "all of them" (Python's
     * slice `[:limit]` with limit past the list's length returns the whole list), a huge
     * negative one means "none of them" (the slice returns empty), and the "... N more" tally
     * in the negative case needs the literal's true magnitude, kept in `overflow_magnitude`
     * rather than the 64-bit value parse_py_int refuses to produce for it. */
    bool overflow_all = false;
    bool overflow_none = false;
    char overflow_magnitude[sizeof(((PyIntOverflow *)0)->magnitude)] = "";
    if (tokens->rest_count >= 1) {
        uint64_t parsed;
        const char *list_token = tokens->rest[0];
        while (isspace((unsigned char)*list_token)) {
            list_token++;
        }
        bool list_token_negative = (*list_token == '-');
        PyIntOverflow overflow;
        char err[256];   /* the digit-limit message is ~139 characters */
        if (!parse_py_int(tokens->rest[0], 10, false, &parsed, &overflow, err, sizeof(err))) {
            if (!overflow.triggered) {
                printf("  error: %s\n", err);
                return;
            }
            if (overflow.negative) {
                overflow_none = true;
                snprintf(overflow_magnitude, sizeof(overflow_magnitude), "%s",
                         overflow.magnitude);
            } else {
                overflow_all = true;
            }
        } else if ((int64_t)parsed < 0 || (list_token_negative && parsed != 0)) {
            /* Fits uint64_t but not int64_t, so narrowing it here would flip its sign --
             * the same window cmd_pscan's depth has. Python's int has no such boundary, so
             * take the decisions the overflow branch above takes: a magnitude that large is
             * every candidate when positive and none when negative. */
            bool list_banner_negative = false;
            const char *list_digits = ms_canonical_decimal(list_token, &list_banner_negative);
            if (list_banner_negative) {
                overflow_none = true;
                snprintf(overflow_magnitude, sizeof(overflow_magnitude), "%s", list_digits);
            } else {
                overflow_all = true;
            }
        } else {
            /* int64_t, not `long`: Windows's LLP64 model makes `long` 32 bits even in a
             * 64-bit build, which would truncate a large-but-valid count. */
            limit = (int64_t)parsed;
        }
    }

    int64_t total = (int64_t)scanner->count;
    int64_t end;
    if (overflow_all) {
        end = total;
    } else if (overflow_none) {
        end = 0;
    } else {
        end = (limit >= 0) ? (limit < total ? limit : total)
                            : (total + limit > 0 ? total + limit : 0);
    }

    for (int64_t i = 0; i < end; i++) {
        uint64_t address = scanner->candidates[i].address;
        uint8_t buf[MS_MAX_VALUE_SIZE];
        size_t size = ms_type_size(scanner->kind);
        size_t got = scanner->process->read(scanner->process, address, buf, size);
        char text[64];
        if (got == 0) {
            snprintf(text, sizeof(text), "<unreadable>");
        } else {
            MsValue value;
            if (ms_unpack(buf, got, scanner->kind, &value)) {
                ms_format_value(&value, text, sizeof(text));
            } else {
                snprintf(text, sizeof(text), "None");
            }
        }
        printf("  0x%" PRIX64 " = %s\n", address, text);
    }
    if (overflow_none) {
        /* total - limit, computed exactly: limit's magnitude does not fit in 64 bits, so the
         * true difference (total + |limit|) may not either -- add_decimal never overflows
         * because it works in decimal digits, not machine words. */
        char more[MS_PY_INT_MAX_STR_DIGITS + 64];  /* holds total + any magnitude the parser accepts */
        add_decimal(overflow_magnitude, (uint64_t)total, more, sizeof(more));
        printf("  ... %s more\n", more);
    } else if (!overflow_all && total > limit) {
        printf("  ... %" PRId64 " more\n", total - limit);
    }
}

/* `write <addr> <value>` -- prompts y/N before writing. */
static void cmd_write(Scanner *scanner, ReplTokens *tokens) {
    if (tokens->rest_count < 2) {
        printf("write <addr> <value>\n");
        return;
    }
    uint64_t address;
    char err[256];   /* the digit-limit message is ~139 characters */
    if (!parse_py_int(tokens->rest[0], 16, true, &address, NULL, err, sizeof(err))) {
        printf("  error: %s\n", err);
        return;
    }

    size_t size = ms_type_size(scanner->kind);
    uint8_t before_buf[MS_MAX_VALUE_SIZE];
    size_t before_got = scanner->process->read(scanner->process, address, before_buf, size);
    char before_text[64];
    MsValue before_value;
    if (before_got > 0 && ms_unpack(before_buf, before_got, scanner->kind, &before_value)) {
        ms_format_value(&before_value, before_text, sizeof(before_text));
    } else {
        snprintf(before_text, sizeof(before_text), "None");
    }

    uint8_t payload[MS_MAX_VALUE_SIZE];
    size_t payload_len = 0;
    char pack_err[256];
    if (!ms_pack(tokens->rest[1], scanner->kind, payload, &payload_len, pack_err,
                 sizeof(pack_err))) {
        printf("  error: %s\n", pack_err);
        return;
    }

    printf("  0x%" PRIX64 " is %s, write %s? [y/N] ", address, before_text, tokens->rest[1]);
    fflush(stdout);
    char *answer = read_line();
    bool yes = false;
    if (answer) {
        strip_whitespace(answer);
        yes = (answer[0] == 'y' || answer[0] == 'Y') && answer[1] == '\0';
        free(answer);
    }
    if (yes) {
        int ok = scanner->process->write(scanner->process, address, payload, payload_len);
        printf(ok ? "  written\n" : "  write failed\n");
    }
}

/* `freeze <addr> <value>` -- writes once immediately, then again on every blank line until
 * `unfreeze`. A value that cannot be packed under the current type is never recorded and
 * leaves the frozen set untouched, matching the Python test suite's assertion. */
static void cmd_freeze(Scanner *scanner, ReplTokens *tokens, FrozenSet *frozen) {
    if (tokens->rest_count < 2) {
        printf("freeze <addr> <value>   (blank line re-applies all freezes; `unfreeze` "
               "clears)\n");
        return;
    }
    uint64_t address;
    char err[256];   /* the digit-limit message is ~139 characters */
    if (!parse_py_int(tokens->rest[0], 16, true, &address, NULL, err, sizeof(err))) {
        printf("  error: %s\n", err);
        return;
    }
    uint8_t payload[MS_MAX_VALUE_SIZE];
    size_t payload_len = 0;
    char pack_err[256];
    if (!ms_pack(tokens->rest[1], scanner->kind, payload, &payload_len, pack_err,
                 sizeof(pack_err))) {
        printf("  error: %s\n", pack_err);
        return;
    }
    if (!frozen_set(frozen, address, tokens->rest[1], scanner->kind)) {
        printf("  error: out of memory\n");
        return;
    }
    scanner->process->write(scanner->process, address, payload, payload_len);
    printf("  freezing 0x%" PRIX64 " at %s; press Enter to re-apply, `unfreeze` to stop\n",
           address, tokens->rest[1]);
}

/* `pscan <addr> [depth] [max_offset_hex]` -- find static pointer paths to `addr`. Mirrors
 * memscope.py's REPL `pscan` branch: build a PointerMap and this process's module list, run
 * the backward BFS, and report each path found with "ok"/"stale" (not the CLI's three-way
 * status -- see the file header). `max_paths` is hardcoded to 40 and the frontier cap to
 * 200000, exactly as memscope.py calls `ptrscan.find_paths(scanner.process, target, depth,
 * max_offset, 40)`. */
static void cmd_pscan(Scanner *scanner, unsigned long pid, ReplTokens *tokens) {
    if (tokens->rest_count < 1) {
        printf("pscan <addr> [depth] [max_offset_hex]  -- find static pointer paths\n");
        return;
    }
    uint64_t target;
    char err[256];   /* the digit-limit message is ~139 characters */
    if (!parse_py_int(tokens->rest[0], 16, true, &target, NULL, err, sizeof(err))) {
        printf("  error: %s\n", err);
        return;
    }
    /* int64_t, not `long`: Windows's LLP64 model makes `long` 32 bits even in a 64-bit build,
     * which truncated a large-but-valid depth (`pscan <addr> 5000000000` became 705032704)
     * -- exactly the reason cmd_list was widened the same way. Unlike write/freeze/pscan's
     * own target address, depth and max offset are allowed to be negative or wider than 64
     * bits here, matching Python's plain int()/int(x, 16) with no bound of its own -- a
     * search this shallow always terminates on its own long before either value could
     * matter, so there is nothing here worth refusing outright. */
    int64_t depth = 3;
    char depth_banner[MS_PY_INT_MAX_STR_DIGITS + 64] = "3";      /* holds any magnitude the parser accepts */
    if (tokens->rest_count > 1) {
        uint64_t depth_parsed;
        const char *depth_token = tokens->rest[1];
        while (isspace((unsigned char)*depth_token)) {
            depth_token++;
        }
        bool depth_token_negative = (*depth_token == '-');
        PyIntOverflow overflow;
        if (!parse_py_int(tokens->rest[1], 10, false, &depth_parsed, &overflow, err, sizeof(err))) {
            if (!overflow.triggered) {
                            printf("  error: %s\n", err);
                return;
            }
            if (overflow.negative) {
                /* Python's range() over a magnitude this negative is empty too, same
                 * outcome as depth 0. */
                depth = 0;
                snprintf(depth_banner, sizeof(depth_banner), "-%s", overflow.magnitude);
            } else {
                /* ptrpath_find clamps internally (PTRPATH_MAX_DEPTH); the search still
                 * terminates the moment the frontier empties, exactly as Python's does. */
                depth = INT64_MAX;
                snprintf(depth_banner, sizeof(depth_banner), "%s", overflow.magnitude);
            }
        } else if ((int64_t)depth_parsed < 0 || (depth_token_negative && depth_parsed != 0)) {
            /* The magnitude fits uint64_t but not int64_t, so narrowing it here would flip
             * its sign: `pscan <addr> -11111111111111111111` reported a depth of
             * 7335632962598440505 and then searched to it. Python has no such boundary, so
             * take the same two decisions the overflow branch above takes, for the same
             * reasons -- an empty range when negative, a clamped search when positive -- and
             * report the number the user actually typed. */
            bool banner_negative = false;
            const char *banner_digits = ms_canonical_decimal(depth_token, &banner_negative);
            if (banner_negative) {
                depth = 0;
                snprintf(depth_banner, sizeof(depth_banner), "-%s", banner_digits);
            } else {
                depth = INT64_MAX;
                snprintf(depth_banner, sizeof(depth_banner), "%s", banner_digits);
            }
        } else {
            depth = (int64_t)depth_parsed;
            snprintf(depth_banner, sizeof(depth_banner), "%" PRId64, depth);
        }
    }
    uint64_t max_offset = 0x400;
    bool max_offset_negative = false;
    char max_offset_banner[MS_PY_INT_MAX_STR_DIGITS + 64] = "400";  /* same */
    if (tokens->rest_count > 2) {
        const char *p = tokens->rest[2];
        while (isspace((unsigned char)*p)) p++;
        bool token_negative = (*p == '-');

        PyIntOverflow overflow;
        if (!parse_py_int(tokens->rest[2], 16, false, &max_offset, &overflow, err, sizeof(err))) {
            /* A magnitude this large has no fixed-width equivalent either, but unlike depth,
             * Python's own math (target - max_offset, real arithmetic) makes the sign the
             * only thing that matters here: saturate the positive case (an offset this wide
             * already covers every address a hop could land on -- pointermap_pointers_into
             * clamps its lower bound at 0 regardless, so this is exact, not approximate) and
             * treat the negative case the same as any other negative offset below. */
            if (!overflow.triggered) {
                printf("  error: %s\n", err);
                return;
            }
            max_offset_negative = overflow.negative;
            if (overflow.negative) {
                snprintf(max_offset_banner, sizeof(max_offset_banner), "%s", overflow.magnitude);
            } else {
                max_offset = UINT64_MAX;
                snprintf(max_offset_banner, sizeof(max_offset_banner), "%s", overflow.magnitude);
            }
        } else {
            max_offset_negative = token_negative;
            if (token_negative) {
                /* max_offset already holds the two's-complement encoding parse_py_int produces
                 * for a negative literal (needed for the write/freeze/resolve callers that
                 * genuinely add it); recover the plain magnitude just for display here. */
                uint64_t magnitude = (uint64_t)(-(int64_t)max_offset);
                snprintf(max_offset_banner, sizeof(max_offset_banner), "%" PRIX64, magnitude);
            } else {
                snprintf(max_offset_banner, sizeof(max_offset_banner), "%" PRIX64, max_offset);
            }
        }
    }
    if (max_offset_negative) {
        /* Python's pointers_into does `target - max_offset` with real (non-wrapping)
         * arithmetic: subtracting a negative max_offset always pushes the lower bound above
         * the upper one, so the match window is empty at every node, every level -- the
         * search finds nothing, no matter depth or the actual max_offset magnitude. Forcing
         * depth to 0 reproduces exactly that outcome without pointermap_pointers_into (which
         * only understands an unsigned max_offset) ever seeing the two's-complement bit
         * pattern -- the earlier version passed it through unchanged and a wraparound match
         * window produced 40 false-positive paths where Python found none. */
        depth = 0;
    }
    printf("scanning for static pointer paths (depth %s, offset 0x%s%s)...\n",
           depth_banner, max_offset_negative ? "-" : "", max_offset_banner);

    int module_count = process_modules(pid, NULL, 0);
    ModuleEntry *modules = NULL;
    if (module_count > 0) {
        modules = (ModuleEntry *)malloc((size_t)module_count * sizeof(ModuleEntry));
        if (modules) {
            /* The count above comes from an earlier snapshot; a module can load or unload
             * before this second snapshot fills modules[]. Treat this return value, not the
             * first, as authoritative -- it is the only one that reflects what actually got
             * written into modules[]. The fourth site of this defect: process_attach,
             * main_memscope.c and main_ptrscan.c all fixed it this same way. */
            int filled = process_modules(pid, modules, module_count);
            module_count = filled < module_count ? filled : module_count;
            if (module_count < 0) {
                module_count = 0;
            }
        } else {
            module_count = 0;
        }
    }

    PointerMap map;
    pointermap_init(&map);
    pointermap_build(&map, scanner->process);

    PathResult *results = NULL;
    size_t result_count = 0;
    size_t dropped = 0;
    ptrpath_find(&map, modules, module_count, target, depth, max_offset, 40, 200000,
                 &results, &result_count, &dropped);

    printf("mapped %zu pointers, %zu path(s):\n", map.count, result_count);
    char limit_lines[2][PTRPATH_LIMIT_LINE_MAX];
    int limit_count = ptrpath_scan_limits(&map, dropped, limit_lines);
    for (int i = 0; i < limit_count; i++) {
        printf("%s\n", limit_lines[i]);
    }

    for (size_t i = 0; i < result_count; i++) {
        PathResult *r = &results[i];
        uint64_t address;
        bool resolved = ptrpath_resolve(scanner->process, r->module_name, r->module_offset,
                                         r->offsets, r->offset_count, modules, module_count,
                                         &address);
        char path_text[512];
        ptrpath_format(r->module_name, r->module_offset, r->offsets, r->offset_count,
                        path_text, sizeof(path_text));
        printf("  %s   [%s]\n", path_text, (resolved && address == target) ? "ok" : "stale");
    }

    ptrpath_free_results(results, result_count);
    pointermap_free(&map);
    free(modules);
}

/* --- dispatch and the REPL loop ------------------------------------------------------------- */

static void dispatch(Scanner *scanner, unsigned long pid, ReplTokens *tokens,
                      FrozenSet *frozen) {
    const char *command = tokens->command;
    if (strcmp(command, "help") == 0) {
        printf("%s\n", HELP_TEXT);
    } else if (strcmp(command, "type") == 0) {
        cmd_type(scanner, tokens);
    } else if (strcmp(command, "scan") == 0) {
        cmd_scan(scanner, tokens);
    } else if (strcmp(command, "next") == 0) {
        cmd_next(scanner, tokens);
    } else if (strcmp(command, "list") == 0) {
        cmd_list(scanner, tokens);
    } else if (strcmp(command, "write") == 0) {
        cmd_write(scanner, tokens);
    } else if (strcmp(command, "freeze") == 0) {
        cmd_freeze(scanner, tokens, frozen);
    } else if (strcmp(command, "unfreeze") == 0) {
        frozen_clear(frozen);
        printf("  all freezes cleared\n");
    } else if (strcmp(command, "pscan") == 0) {
        cmd_pscan(scanner, pid, tokens);
    } else if (strcmp(command, "reset") == 0) {
        scanner_reset(scanner);
        printf("candidates cleared\n");
    } else {
        char repr[128];
        py_repr(command, repr, sizeof(repr));
        printf("unknown command %s; type help\n", repr);
    }
}

/* The REPL loop proper: mirrors memscope.py's repl(). */
static void repl_loop(Scanner *scanner, unsigned long pid, const char *name) {
    printf("attached to pid %lu %s -- type help, or quit\n", pid, name ? name : "");
    FrozenSet frozen = {0};

    for (;;) {
        printf("memscope> ");
        fflush(stdout);
        char *line = read_line();
        if (!line) {
            printf("\n");
            break;
        }
        strip_whitespace(line);
        if (line[0] == '\0') {
            frozen_reapply(&frozen, scanner->process);
            free(line);
            continue;
        }

        ReplTokens tokens;
        tokenize(line, &tokens);

        if (strcmp(tokens.command, "quit") == 0 || strcmp(tokens.command, "exit") == 0 ||
            strcmp(tokens.command, "q") == 0) {
            free(line);
            break;
        }
        dispatch(scanner, pid, &tokens, &frozen);
        free(line);
    }

    free(frozen.items);
}

/* Attaches to `target` (a pid or a process-name substring, exactly like memscope.py's
 * attach()) and runs the REPL against it. Returns 0 on success, 1 if no process could be
 * attached to -- mirroring `main()`'s `scan` branch: `proc = attach(...); if not proc: return
 * 1; try: repl(Scanner(proc)) finally: proc.close(); return 0`. */
int repl_main(const char *target) {
    ProcessIO io;
    unsigned long pid = 0;
    char name[PROCESS_NAME_MAX] = "";
    if (process_attach(target, &io, &pid, name, sizeof(name)) != 0) {
        return 1;
    }

    Scanner scanner;
    scanner_init(&scanner, &io);
    repl_loop(&scanner, pid, name);
    scanner_free(&scanner);

    process_close(&io);
    return 0;
}
