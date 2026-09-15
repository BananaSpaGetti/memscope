/*
 * memscope -- native port of MemScope/memscope.py.
 *
 * The ps, read and dump subcommands: hand-rolled argument parsing that matches memscope.py's
 * argparse setup exactly in flag names, defaults and output formatting. `scan` (the
 * interactive REPL) is wired in by a later task in the port-to-c plan.
 */

#include <ctype.h>
#include <inttypes.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "process.h"
#include "pyfmt.h"
#include "repl.h"
#include "util.h"
#include "values.h"

/* Same defaults as PTRMAP_DEFAULT_MAX_HITS/SCANNER_DEFAULT_MAX_SCAN_BYTES (ptrmap.h,
 * scanner.h) and memscope.py's own MAX_HITS/MAX_SCAN_BYTES. read/dump has no map or scanner
 * of its own to hang the constant off of, so the two numbers are repeated here rather than
 * pulling in either header just for them -- matching this codebase's existing precedent of
 * the same pair being repeated between ptrmap.h and scanner.h already. */
#define MS_READ_MAX_COUNT 2000000LL
#define MS_DUMP_MAX_LENGTH (3LL * 1024 * 1024 * 1024)

/* --- Python-compatible number formatting ------------------------------------------------ */

/* --- small argument-parsing helpers ------------------------------------------------------ */

/* True if any element of argv is exactly "-h" or "--help" -- the way argparse recognises the
 * help flag anywhere among a subcommand's arguments, taking priority over every other error. */
static bool has_help_flag_before(int argc, char **argv, int limit) {
    /* `limit` is ms_strip_dashdash's boundary: a -h or --help AFTER argparse's `--` is not
     * help at all, it is a positional. Measured: `read -- --help` reports an error about a
     * positional, not the read help. */
    if (limit < argc) {
        argc = limit;
    }
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            return true;
        }
    }
    return false;
}

/* --- usage and help text, reproducing argparse's layout ----------------------------------- */

static const char *USAGE_TOP = "usage: memscope.py [-h] {ps,read,dump,scan} ...\n";
static const char *USAGE_READ = "usage: memscope.py read [-h] [--type TYPE] [--count COUNT] pid address\n";
static const char *USAGE_DUMP = "usage: memscope.py dump [-h] pid address [length]\n";

/* argparse's own error format: a usage block, then "memscope.py[ subcommand]: error: message",
 * both to stderr, exit 2. `subcommand` is NULL for the two errors the top-level parser itself
 * raises -- an invalid subcommand choice, and positional arguments no subparser consumed --
 * and the read/dump names for the errors their own subparsers raise. */
static void print_parse_error(const char *usage, const char *subcommand, const char *message) {
    fputs(usage, stderr);
    if (subcommand) {
        fprintf(stderr, "memscope.py %s: error: %s\n", subcommand, message);
    } else {
        fprintf(stderr, "memscope.py: error: %s\n", message);
    }
}

/* argparse's "unrecognized arguments" error: raised by the top-level parser, after a
 * subparser otherwise succeeds, for positionals past what that subparser declared -- so it
 * always uses the top usage block and the un-prefixed "memscope.py: error:", never the
 * subcommand's own. */
static void print_unrecognized(int count, const char **items) {
    fputs(USAGE_TOP, stderr);
    fputs("memscope.py: error: unrecognized arguments:", stderr);
    for (int i = 0; i < count; i++) {
        fputc(' ', stderr);
        fputs(items[i], stderr);
    }
    fputc('\n', stderr);
}

/* The full top-level help: argparse's usage line, then the module docstring verbatim, then the
 * positional/options footer argparse adds. The usage line and error prefixes below all say
 * "memscope.py" rather than this binary's own name, matching argparse's `prog` (derived from
 * the script argparse actually ran as) so this help text reads identically to the Python's --
 * the docstring body already says "memscope.py" throughout, so anything else would print two
 * different names for the same tool in the same block of text. */
static void print_full_help(void) {
    fputs(
        "usage: memscope.py [-h] {ps,read,dump,scan} ...\n"
        "\n"
        "MemScope -- a small, general memory scanner for 64-bit Windows processes.\n"
        "\n"
        "It reads and searches the live memory of any process you have the rights to open, and\n"
        "narrows a set of candidate addresses the way Cheat Engine or scanmem do: scan for a value,\n"
        "let it change, scan again for what changed, and repeat until one address is left. Nothing\n"
        "here is specific to any one program.\n"
        "\n"
        "This is a debugging and reverse-engineering tool. Reading another process's memory needs the\n"
        "right to open it: a normal program you started is fine, but something running at a higher\n"
        "integrity level (many games, anything \"as administrator\") needs this run from an elevated\n"
        "terminal, or it fails at OpenProcess with \"access denied\".\n"
        "\n"
        "    py memscope.py ps [name]                 list processes, optionally filtered by name\n"
        "    py memscope.py read <pid> <addr> [opts]  read a value at an address\n"
        "    py memscope.py dump <pid> <addr> <len>   hex dump around an address\n"
        "    py memscope.py scan <pid|name>           attach and open the interactive scanner\n"
        "\n"
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
        "    pscan <addr>        find a static pointer path to an address that moves (see ptrscan.py)\n"
        "    reset               throw the candidates away and start over\n"
        "    quit\n"
        "\n"
        "positional arguments:\n"
        "  {ps,read,dump,scan}\n"
        "\n"
        "options:\n"
        "  -h, --help           show this help message and exit\n",
        stdout);
}

static void print_ps_help(void) {
    fputs(
        "usage: memscope.py ps [-h] [name]\n"
        "\n"
        "positional arguments:\n"
        "  name\n"
        "\n"
        "options:\n"
        "  -h, --help  show this help message and exit\n",
        stdout);
}

static void print_read_help(void) {
    fputs(
        "usage: memscope.py read [-h] [--type TYPE] [--count COUNT] pid address\n"
        "\n"
        "positional arguments:\n"
        "  pid\n"
        "  address\n"
        "\n"
        "options:\n"
        "  -h, --help     show this help message and exit\n"
        "  --type TYPE\n"
        "  --count COUNT\n",
        stdout);
}

static void print_dump_help(void) {
    fputs(
        "usage: memscope.py dump [-h] pid address [length]\n"
        "\n"
        "positional arguments:\n"
        "  pid\n"
        "  address\n"
        "  length\n"
        "\n"
        "options:\n"
        "  -h, --help  show this help message and exit\n",
        stdout);
}

static void print_scan_help(void) {
    fputs(
        "usage: memscope.py scan [-h] target\n"
        "\n"
        "positional arguments:\n"
        "  target      pid or process name\n"
        "\n"
        "options:\n"
        "  -h, --help  show this help message and exit\n",
        stdout);
}

/* --- ps ------------------------------------------------------------------------------------ */

typedef struct {
    ProcessEntry entry;
    int order; /* original snapshot position, to keep the sort stable like Python's sorted() */
} PsRow;

static int ps_compare(const void *a, const void *b) {
    const PsRow *ra = (const PsRow *)a;
    const PsRow *rb = (const PsRow *)b;
    char la[PROCESS_NAME_MAX];
    char lb[PROCESS_NAME_MAX];
    ms_to_lower_copy(ra->entry.name, la, sizeof(la));
    ms_to_lower_copy(rb->entry.name, lb, sizeof(lb));
    int cmp = strcmp(la, lb);
    if (cmp != 0) {
        return cmp;
    }
    return ra->order - rb->order;
}

static int cmd_ps(int argc, char **argv) {
    const int positional_from = ms_strip_dashdash(&argc, argv);
    if (has_help_flag_before(argc, argv, positional_from)) {
        print_ps_help();
        return 0;
    }

    /* After a `--` the next token is the name even when it looks like an option, which is
     * what makes `ps -- --bogus` a search for a process called "--bogus". */
    const char *name = argc > 0 ? argv[0] : "";

    int count = process_list(name, NULL, 0);
    if (count < 0) {
        fprintf(stderr, "CreateToolhelp32Snapshot failed\n");
        return 1;
    }
    if (count == 0) {
        return 0;
    }

    ProcessEntry *entries = (ProcessEntry *)malloc((size_t)count * sizeof(ProcessEntry));
    PsRow *rows = (PsRow *)malloc((size_t)count * sizeof(PsRow));
    if (!entries || !rows) {
        free(entries);
        free(rows);
        return 1;
    }
    /* The count above comes from an earlier snapshot; a matching process can exit before this
     * second snapshot fills entries[]. Treat this return value, not the first, as authoritative
     * -- it is the only one that reflects what actually got written into entries[]. */
    int filled = process_list(name, entries, count);
    if (filled < 0) {
        filled = 0;
    }
    int usable = filled < count ? filled : count;
    for (int i = 0; i < usable; i++) {
        rows[i].entry = entries[i];
        rows[i].order = i;
    }

    qsort(rows, (size_t)usable, sizeof(PsRow), ps_compare);

    for (int i = 0; i < usable; i++) {
        printf("  %-8lu %s\n", rows[i].entry.pid, rows[i].entry.name);
    }

    free(rows);
    free(entries);
    return 0;
}

/* --- read ---------------------------------------------------------------------------------- */

static int cmd_read(int argc, char **argv) {
    const int positional_from = ms_strip_dashdash(&argc, argv);
    if (has_help_flag_before(argc, argv, positional_from)) {
        print_read_help();
        return 0;
    }

    const char *pid_str = NULL;
    const char *address_str = NULL;
    const char *type_str = "int32";
    int64_t count = 1;
    const char *extras[argc > 0 ? argc : 1];
    int extra_count = 0;

    for (int i = 0; i < argc; i++) {
        const char *arg = argv[i];
        if (i >= positional_from) {
            /* Past argparse's `--` even a KNOWN flag is a positional: `read -- 1234 0x400
             * --type int8` fills pid and address, then reports --type and int8 as
             * unrecognized, because read declares only two positionals. Guarding just the
             * unrecognized branch below was not enough -- these flag branches run first. */
            if (!pid_str) {
                pid_str = arg;
                if (!ms_looks_like_int(pid_str)) {
                    char message[32832]; /* see the identical comment below. */
                    snprintf(message, sizeof(message),
                             "argument pid: invalid int value: '%s'", pid_str);
                    print_parse_error(USAGE_READ, "read", message);
                    return 2;
                }
            } else if (!address_str) {
                address_str = arg;
            } else {
                extras[extra_count++] = arg;
            }
        } else if (strncmp(arg, "--type", 6) == 0 && (arg[6] == '\0' || arg[6] == '=')) {
            if (arg[6] == '=') {
                type_str = arg + 7;
            } else if (i + 1 < argc) {
                type_str = argv[++i];
            } else {
                print_parse_error(USAGE_READ, "read", "argument --type: expected one argument");
                return 2;
            }
        } else if (strncmp(arg, "--count", 7) == 0 && (arg[7] == '\0' || arg[7] == '=')) {
            const char *value;
            if (arg[7] == '=') {
                value = arg + 8;
            } else if (i + 1 < argc) {
                value = argv[++i];
            } else {
                print_parse_error(USAGE_READ, "read", "argument --count: expected one argument");
                return 2;
            }
            if (!ms_looks_like_int(value)) {
                char message[32832]; /* room for any argv[] token Windows allows (its
                                       command-line limit is 32767 characters) plus this
                                       message's own fixed text -- large enough that no
                                       real input can be truncated, unlike Python's
                                       unbounded string formatting for the same message. */
                snprintf(message, sizeof(message), "argument --count: invalid int value: '%s'", value);
                print_parse_error(USAGE_READ, "read", message);
                return 2;
            }
            count = strtoll(value, NULL, 10);
        } else if (i < positional_from && arg[0] == '-' && arg[1] != '\0'
                   && !ms_looks_like_negative_number(arg)) {
            /* A token that starts with '-', is not one of this subcommand's known flags,
             * and does not look like a negative number is what argparse itself calls
             * "unrecognized" -- collected for the top-level error below rather than ever
             * being tried against a positional slot. `-5` still reaches pid/address here;
             * `-0x10` and `--bogus` do not, matching Python exactly. Past `--` none of that
             * applies: everything left is a positional, so `read -- --help` lands in the
             * pid slot and is reported as an invalid int, which is what Python does. */
            extras[extra_count++] = arg;
        } else if (!pid_str) {
            /* argparse converts a positional the moment it is matched, not once the whole
             * command line is parsed -- so an invalid pid is reported here, even if a later
             * flag or the address is still to come. */
            pid_str = arg;
            if (!ms_looks_like_int(pid_str)) {
                char message[32832]; /* room for any argv[] token Windows allows (its
                                       command-line limit is 32767 characters) plus this
                                       message's own fixed text -- large enough that no
                                       real input can be truncated, unlike Python's
                                       unbounded string formatting for the same message. */
                snprintf(message, sizeof(message), "argument pid: invalid int value: '%s'", pid_str);
                print_parse_error(USAGE_READ, "read", message);
                return 2;
            }
        } else if (!address_str) {
            address_str = arg;
        } else {
            extras[extra_count++] = arg;
        }
    }

    if (!pid_str || !address_str) {
        print_parse_error(USAGE_READ, "read",
                           !pid_str ? "the following arguments are required: pid, address"
                                    : "the following arguments are required: address");
        return 2;
    }
    if (extra_count > 0) {
        print_unrecognized(extra_count, extras);
        return 2;
    }

    MsType kind;
    if (!ms_resolve_type(type_str, &kind)) {
        fprintf(stderr, "unknown type '%s'; one of int8, uint8, int16, uint16, int32, uint32, "
                        "int64, uint64, float, double\n", type_str);
        return 2;
    }

    uint64_t address;
    if (!ms_parse_hex_u64(address_str, true, &address)) {
        fprintf(stderr, "read: invalid address '%s'\n", address_str);
        return 2;
    }

    /* A count this large never finishes -- each iteration is its own ReadProcessMemory
     * call, so there is nothing here to overflow the way dump's malloc does below, just a
     * loop that would run for a duration nobody who typed a decimal literal this size
     * intended. Matches memscope.py's own bound, added the same review round for the same
     * reason. */
    if (count > MS_READ_MAX_COUNT) {
        fprintf(stderr, "read: count must not exceed %lld: '%" PRId64 "'\n",
                MS_READ_MAX_COUNT, count);
        return 2;
    }

    ProcessIO io;
    if (process_attach(pid_str, &io, NULL, NULL, 0) != 0) {
        return 1;
    }

    size_t size = ms_type_size(kind);
    for (int64_t i = 0; i < count; i++) {
        uint64_t at = address + (uint64_t)i * (uint64_t)size;
        uint8_t buf[MS_MAX_VALUE_SIZE];
        size_t got = io.read(&io, at, buf, size);
        char text[64];
        if (got == 0) {
            snprintf(text, sizeof(text), "<unreadable>");
        } else if (got < size) {
            /* A read that returns fewer bytes than the type needs is still truthy in Python
             * (a non-empty bytes object), so unpack() is called and returns None -- and
             * printing "%s" % None prints the literal word "None". */
            snprintf(text, sizeof(text), "None");
        } else {
            MsValue value;
            ms_unpack(buf, size, kind, &value);
            ms_format_value(&value, text, sizeof(text));
        }
        printf("  0x%" PRIX64 " = %s\n", at, text);
    }

    process_close(&io);
    return 0;
}

/* --- dump ---------------------------------------------------------------------------------- */

static int cmd_dump(int argc, char **argv) {
    const int positional_from = ms_strip_dashdash(&argc, argv);
    if (has_help_flag_before(argc, argv, positional_from)) {
        print_dump_help();
        return 0;
    }

    const char *pid_str = NULL;
    const char *address_str = NULL;
    int64_t length = 64;
    bool have_length = false;
    const char *extras[argc > 0 ? argc : 1];
    int extra_count = 0;

    for (int i = 0; i < argc; i++) {
        const char *arg = argv[i];
        if (i < positional_from && arg[0] == '-' && arg[1] != '\0'
            && !ms_looks_like_negative_number(arg)) {
            /* See cmd_read's identical check: an unrecognized option-like token is collected
             * here rather than tried against pid/address/length, matching argparse. `-5` (a
             * valid negative dump length) still reaches the length slot below; `--bogus`
             * and `-0x10` do not. Past `--` every token is a positional instead. */
            extras[extra_count++] = arg;
        } else if (!pid_str) {
            /* argparse converts a positional the moment it is matched, not once the whole
             * command line is parsed -- so an invalid pid is reported here, even if the
             * address or length is still to come. */
            pid_str = argv[i];
            if (!ms_looks_like_int(pid_str)) {
                char message[32832]; /* room for any argv[] token Windows allows (its
                                       command-line limit is 32767 characters) plus this
                                       message's own fixed text -- large enough that no
                                       real input can be truncated, unlike Python's
                                       unbounded string formatting for the same message. */
                snprintf(message, sizeof(message), "argument pid: invalid int value: '%s'", pid_str);
                print_parse_error(USAGE_DUMP, "dump", message);
                return 2;
            }
        } else if (!address_str) {
            address_str = argv[i];
        } else if (!have_length) {
            if (!ms_looks_like_int(argv[i])) {
                char message[32832]; /* room for any argv[] token Windows allows (its
                                       command-line limit is 32767 characters) plus this
                                       message's own fixed text -- large enough that no
                                       real input can be truncated, unlike Python's
                                       unbounded string formatting for the same message. */
                snprintf(message, sizeof(message), "argument length: invalid int value: '%s'", argv[i]);
                print_parse_error(USAGE_DUMP, "dump", message);
                return 2;
            }
            length = strtoll(argv[i], NULL, 10);
            have_length = true;
        } else {
            extras[extra_count++] = argv[i];
        }
    }

    if (!pid_str || !address_str) {
        print_parse_error(USAGE_DUMP, "dump",
                           !pid_str ? "the following arguments are required: pid, address"
                                    : "the following arguments are required: address");
        return 2;
    }
    if (extra_count > 0) {
        print_unrecognized(extra_count, extras);
        return 2;
    }

    uint64_t address;
    if (!ms_parse_hex_u64(address_str, true, &address)) {
        fprintf(stderr, "dump: invalid address '%s'\n", address_str);
        return 2;
    }

    /* A negative length is meaningless -- there is nothing to dump backwards. This used to
     * fall through to the `if (length > 0)` below, printing nothing and exiting 0, while
     * memscope.py rejected it; reject it here the same way, and before attaching. */
    if (length < 0) {
        fprintf(stderr, "dump: length must not be negative: '%" PRId64 "'\n", length);
        return 2;
    }
    /* A length this large reaches malloc((size_t)length) with a request nothing here can
     * satisfy -- and on the Python side, the same length reaches
     * ctypes.create_string_buffer(size) with `size` too big for the index-sized integer it
     * converts through, an uncaught OverflowError with this file's own path in the
     * traceback. Matches memscope.py's own bound, added the same review round for the same
     * reason. */
    if (length > MS_DUMP_MAX_LENGTH) {
        fprintf(stderr, "dump: length must not exceed %lld bytes: '%" PRId64 "'\n",
                MS_DUMP_MAX_LENGTH, length);
        return 2;
    }

    ProcessIO io;
    if (process_attach(pid_str, &io, NULL, NULL, 0) != 0) {
        return 1;
    }

    if (length > 0) {
        uint8_t *data = (uint8_t *)malloc((size_t)length);
        if (!data) {
            process_close(&io);
            return 1;
        }
        size_t got = io.read(&io, address, data, (size_t)length);

        for (size_t i = 0; i < got; i += 16) {
            size_t chunk = (got - i < 16) ? (got - i) : 16;
            char hexed[64];
            size_t hn = 0;
            char text[17];
            size_t tn = 0;
            for (size_t j = 0; j < chunk; j++) {
                uint8_t b = data[i + j];
                if (j > 0) {
                    hexed[hn++] = ' ';
                }
                hn += (size_t)snprintf(hexed + hn, sizeof(hexed) - hn, "%02x", b);
                text[tn++] = (b >= 32 && b < 127) ? (char)b : '.';
            }
            hexed[hn] = '\0';
            text[tn] = '\0';
            printf("  0x%" PRIX64 "  %-47s  %s\n", address + (uint64_t)i, hexed, text);
        }

        free(data);
    }

    process_close(&io);
    return 0;
}

/* --- entry point ----------------------------------------------------------------------------- */

int main(int argc, char **argv) {
    /* The top-level parser has its own `--`, but it only ever owns one that comes BEFORE
     * the subcommand name: once argparse has matched the subcommand, every remaining token
     * goes to the subparser untouched, separator included. So `memscope -- read 1234 0x400`
     * runs read, while in `dump -- -- 1234 0x400` both separators belong to dump -- which
     * strips the first and reports the second as an invalid pid, exactly as Python does.
     * Stripping greedily here ate the subparser's separator and got both of those wrong.
     *
     * The `argc > 2` is the other half of it: argparse only consumes the separator when a
     * positional follows it for the parser to match. A lone `memscope --` has nothing to
     * match, so the token survives and is reported as an unrecognized argument rather than
     * printing the help. Measured, not reasoned about. */
    if (argc > 2 && strcmp(argv[1], "--") == 0) {
        for (int i = 1; i + 1 < argc; i++) {
            argv[i] = argv[i + 1];
        }
        argc--;
    }

    if (argc < 2) {
        /* No subcommand: argparse's parse_args() succeeds with args.command == None, and main()
         * falls through to parser.print_help() (to stdout) followed by `return 2`. */
        print_full_help();
        return 2;
    }

    const char *command = argv[1];
    if (strcmp(command, "--") == 0) {
        /* A separator with nothing after it to match is not a subcommand and not an invalid
         * choice either: argparse consumes it, finds no command, and then reports the token
         * it could not place. Measured -- `memscope --` says "unrecognized arguments: --". */
        const char *leftover[1] = {command};
        print_unrecognized(1, leftover);
        return 2;
    }
    if (strcmp(command, "-h") == 0 || strcmp(command, "--help") == 0) {
        print_full_help();
        return 0;
    }

    int sub_argc = argc - 2;
    char **sub_argv = argv + 2;

    if (strcmp(command, "ps") == 0) {
        return cmd_ps(sub_argc, sub_argv);
    }
    if (strcmp(command, "read") == 0) {
        return cmd_read(sub_argc, sub_argv);
    }
    if (strcmp(command, "dump") == 0) {
        return cmd_dump(sub_argc, sub_argv);
    }
    if (strcmp(command, "scan") == 0) {
        const int scan_positional_from = ms_strip_dashdash(&sub_argc, sub_argv);
        if (has_help_flag_before(sub_argc, sub_argv, scan_positional_from)) {
            print_scan_help();
            return 0;
        }
        if (sub_argc < 1) {
            fprintf(stderr, "usage: memscope scan <pid|name>\n");
            return 2;
        }
        return repl_main(sub_argv[0]);
    }

    char message[32832]; /* see the identical comment above; same reasoning. */
    snprintf(message, sizeof(message),
             "argument command: invalid choice: '%s' (choose from ps, read, dump, scan)", command);
    print_parse_error(USAGE_TOP, NULL, message);
    return 2;
}
