/*
 * ptrscan -- native port of MemScope/ptrscan.py.
 *
 * `ptrscan <pid|name> [address] [--depth N] [--offset HEX] [--max N] [--resolve "PATH"]`:
 * build the process's pointer map and module list, then either resolve a given path
 * string (`--resolve`) or run the backward BFS (ptrpath_find) from an address and print
 * every static path found, each with its verification status -- exactly ptrscan.py's
 * main().
 */

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "process.h"
#include "ptrmap.h"
#include "ptrpath.h"
#include "util.h"

/* The frontier cap ptrscan.py's find_paths() hardcodes as its default and every caller
 * (the CLI, the REPL) relies on unchanged. */
#define DEFAULT_MAX_FRONTIER 200000

/* Matches argparse's own wrapping of this parser's usage line at the 80-column fallback
 * width shutil.get_terminal_size() uses when stdout is not a tty -- the case every
 * reproduction against ptrscan.py (piped or redirected) hits. */
static void print_usage(void) {
    fprintf(stderr,
            "usage: ptrscan.py [-h] [--depth DEPTH] [--offset OFFSET] [--max MAX]\n"
            "                  [--resolve RESOLVE]\n"
            "                  target [address]\n");
}

/* argparse's own error format: the usage block, then "prog: error: message", both to
 * stderr, exit 2 -- what every one of ptrscan.py's parser errors looks like. */
static void print_usage_error(const char *message) {
    print_usage();
    fprintf(stderr, "ptrscan.py: error: %s\n", message);
}

/* argparse's "unrecognized arguments" error: same usage block and prog prefix as any other
 * parser error here, since ptrscan.py has a single parser, not memscope.py's subparsers. */
static void print_unrecognized(int count, const char **items) {
    print_usage();
    fputs("ptrscan.py: error: unrecognized arguments:", stderr);
    for (int i = 0; i < count; i++) {
        fputc(' ', stderr);
        fputs(items[i], stderr);
    }
    fputc('\n', stderr);
}

/* argparse's `-h`/`--help` output: the usage block above, ptrscan.py's module docstring
 * (RawDescriptionHelpFormatter -- printed verbatim, not rewrapped), then the
 * positional/optional argument list, to stdout, exit 0. */
static void print_help(void) {
    printf(
        "usage: ptrscan.py [-h] [--depth DEPTH] [--offset OFFSET] [--max MAX]\n"
        "                  [--resolve RESOLVE]\n"
        "                  target [address]\n"
        "\n"
        "Pointer scanning for MemScope: find a stable path to a value that moves.\n"
        "\n"
        "A garbage-collected or reallocating program puts a value at a fresh address every "
        "time it\n"
        "changes, so no single address stays useful. What stays useful is the *path*: a "
        "pointer in a\n"
        "module's static data, whose target plus an offset is another pointer, and so on, "
        "ending at\n"
        "the live value. That path holds across restarts because it starts somewhere "
        "fixed.\n"
        "\n"
        "This finds such paths by walking pointers backwards from the target: every address "
        "whose\n"
        "stored value lands within a small window below the target is a pointer to it (with "
        "an\n"
        "offset); repeat from each of those until the chain reaches a module's static "
        "range.\n"
        "\n"
        "    py ptrscan.py <pid|name> <address> [--depth 3] [--offset 0x400] [--max 40]\n"
        "    py ptrscan.py <pid|name> --resolve \"game.exe+0x1A2B3C -> 0x18 -> 0x40\"\n"
        "\n"
        "It is heavier than a value scan -- it reads every pointer-sized slot in the process "
        "once, so\n"
        "on a large target that is a lot of memory. Start with a small --depth and --offset. "
        "On a\n"
        "machine with little free RAM, watch what it costs before widening.\n"
        "\n"
        "Credit for the idea: this is the well-worn Cheat Engine pointer-scan approach, in "
        "miniature.\n"
        "\n"
        "positional arguments:\n"
        "  target             pid or process name\n"
        "  address            the address to find paths to (hex)\n"
        "\n"
        "options:\n"
        "  -h, --help         show this help message and exit\n"
        "  --depth DEPTH\n"
        "  --offset OFFSET    max offset per hop (hex)\n"
        "  --max MAX          stop after this many paths\n"
        "  --resolve RESOLVE  a path string to follow and print the address of\n");
}

int main(int argc, char **argv) {
    const char *target_str = NULL;
    const char *address_str = NULL;
    const char *depth_str = NULL;
    const char *offset_str = NULL;
    const char *max_str = NULL;
    const char *resolve_str = NULL;
    const char *extras[argc > 1 ? argc : 1];
    int extra_count = 0;

    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];
        if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) {
            /* argparse's help action fires the moment it is parsed, ahead of any
             * required-argument or value check that comes later in argv -- so this has to
             * sit before target/depth/max validation, not after it. */
            print_help();
            return 0;
        } else if (strncmp(arg, "--depth", 7) == 0 && (arg[7] == '\0' || arg[7] == '=')) {
            if (arg[7] == '=') {
                depth_str = arg + 8;
            } else if (i + 1 < argc) {
                depth_str = argv[++i];
            } else {
                print_usage_error("argument --depth: expected one argument");
                return 2;
            }
            /* type=int validates the moment argparse consumes the value, not later --
             * matches ptrscan.py rejecting this before ever attaching to the process. */
            if (!ms_looks_like_int(depth_str)) {
                char message[256];
                snprintf(message, sizeof(message), "argument --depth: invalid int value: '%s'",
                         depth_str);
                print_usage_error(message);
                return 2;
            }
        } else if (strncmp(arg, "--offset", 8) == 0 && (arg[8] == '\0' || arg[8] == '=')) {
            if (arg[8] == '=') {
                offset_str = arg + 9;
            } else if (i + 1 < argc) {
                offset_str = argv[++i];
            } else {
                print_usage_error("argument --offset: expected one argument");
                return 2;
            }
            /* type=hex_offset (ptrscan.py) now validates the moment argparse consumes the
             * value, before the process is ever attached, and reports an ordinary parser
             * error -- not the hand-rolled ValueError this used to reproduce after attach.
             * Match that here, at the same point --depth and --max validate below. */
            uint64_t offset_check;
            if (!ms_parse_hex_u64(offset_str, true, &offset_check)) {
                char message[256];
                snprintf(message, sizeof(message), "argument --offset: invalid hex value: '%s'",
                         offset_str);
                print_usage_error(message);
                return 2;
            }
        } else if (strncmp(arg, "--max", 5) == 0 && (arg[5] == '\0' || arg[5] == '=')) {
            if (arg[5] == '=') {
                max_str = arg + 6;
            } else if (i + 1 < argc) {
                max_str = argv[++i];
            } else {
                print_usage_error("argument --max: expected one argument");
                return 2;
            }
            if (!ms_looks_like_int(max_str)) {
                char message[256];
                snprintf(message, sizeof(message), "argument --max: invalid int value: '%s'",
                         max_str);
                print_usage_error(message);
                return 2;
            }
        } else if (strncmp(arg, "--resolve", 9) == 0 && (arg[9] == '\0' || arg[9] == '=')) {
            if (arg[9] == '=') {
                resolve_str = arg + 10;
            } else if (i + 1 < argc) {
                resolve_str = argv[++i];
            } else {
                print_usage_error("argument --resolve: expected one argument");
                return 2;
            }
        } else if (arg[0] == '-' && arg[1] != '\0' && !ms_looks_like_negative_number(arg)) {
            /* A token that starts with '-', is not one of this parser's known flags, and
             * does not look like a negative number is what argparse itself calls
             * "unrecognized" -- collected for the error below rather than ever being tried
             * against target/address. `-5` still reaches a positional here; `-0x10` and
             * `--bogus` do not, matching Python exactly (verified against ptrscan.py). */
            extras[extra_count++] = arg;
        } else if (!target_str) {
            target_str = arg;
        } else if (!address_str) {
            address_str = arg;
        } else {
            extras[extra_count++] = arg;
        }
    }

    if (!target_str) {
        print_usage_error("the following arguments are required: target");
        return 2;
    }
    if (extra_count > 0) {
        print_unrecognized(extra_count, extras);
        return 2;
    }

    ProcessIO io;
    unsigned long pid = 0;
    if (process_attach(target_str, &io, &pid, NULL, 0) != 0) {
        return 1;
    }

    int module_count = process_modules(pid, NULL, 0);
    ModuleEntry *modules = NULL;
    if (module_count > 0) {
        modules = (ModuleEntry *)malloc((size_t)module_count * sizeof(ModuleEntry));
        if (!modules) {
            process_close(&io);
            return 1;
        }
        /* The count above comes from an earlier snapshot; a module can load or unload
         * before this second snapshot fills modules[]. Treat this return value, not the
         * first, as authoritative -- it is the only one that reflects what actually got
         * written into modules[]. A snapshot that fails here is not an error (ptrmap.h),
         * so a non-positive fill just leaves module_count at 0 rather than aborting. */
        int filled = process_modules(pid, modules, module_count);
        module_count = filled < module_count ? filled : module_count;
        if (module_count < 0) {
            module_count = 0;
        }
    }

    int result = 0;

    if (resolve_str) {
        char module_name[MODULE_NAME_MAX];
        uint64_t module_offset;
        uint64_t offsets[256];
        int offset_count;
        int oversized_at = -1;
        if (!ptrpath_parse(resolve_str, module_name, sizeof(module_name), &module_offset,
                            offsets, sizeof(offsets) / sizeof(offsets[0]), &offset_count,
                            &oversized_at) ||
            /* ptrpath_parse's contract allows *offset_count_out to exceed offsets_cap (it
             * reports what it found, not what it stored), so the caller has to check. It
             * cannot fire today only because this array and the parser's internal piece
             * bound are both 256 -- change either and it starts mattering, which is why it
             * stays rather than being pruned as dead. */
            offset_count > (int)(sizeof(offsets) / sizeof(offsets[0]))) {
            fprintf(stderr, "ptrscan: could not parse path '%s'\n", resolve_str);
            result = 2;
        } else {
            uint64_t address;
            /* An offset too wide for uint64_t is a valid literal to ptrscan.py, which parses
             * it and carries on. Where it sits decides what happens, so it decides what can
             * be said: every address in a path is read except the last, so an oversized piece
             * before the end produces a read that fails in both implementations -- a real
             * "could not resolve" -- while one AT the end is an address ptrscan.py prints,
             * wider than 64 bits and not representable here.
             *
             * Reporting the second as the first was wrong twice over: both causes that
             * message names are false (the module is found, every hop reads), and it is
             * exactly what a misspelled module name prints, so a documented limitation was
             * indistinguishable from a typo. */
            bool resolved = ptrpath_resolve(&io, module_name, module_offset, offsets,
                                             offset_count, modules, module_count, &address);
            if (!resolved) {
                /* Checked FIRST, because ptrscan.py checks it first: resolve() looks the
                 * module up before it does any arithmetic, so a missing module answers even
                 * a path whose offsets are nonsense. Reporting the overflow ahead of this
                 * made `--resolve "nosuch.dll+0x10 -> <over-wide>"` blame the width when
                 * Python blames the module. */
                printf("could not resolve (module not found or a hop read failed)\n");
                result = 1;
            } else if (oversized_at >= 0 && oversized_at == offset_count) {
                if (offset_count == 0) {
                    printf("the module offset leaves the 64-bit address space; "
                           "ptrscan.py would print an address wider than 64 bits\n");
                } else {
                    printf("hop %d leaves the 64-bit address space; "
                           "ptrscan.py would print an address wider than 64 bits\n",
                           offset_count);
                }
                result = 1;
            } else if (oversized_at >= 0) {
                /* An over-wide piece before the end: ptrscan.py carries it into an address
                 * no read can satisfy, so the resolve fails there. It is parsed as 0 here,
                 * which can land somewhere readable, so the failure is forced rather than
                 * left to chance. */
                printf("could not resolve (module not found or a hop read failed)\n");
                result = 1;
            } else {
                uint8_t buf[4] = {0, 0, 0, 0};
                size_t got = io.read(&io, address, buf, sizeof(buf));
                if (got == 0) {
                    printf("0x%" PRIX64 " = <unreadable>\n", address);
                } else {
                    uint32_t value = (uint32_t)buf[0] | ((uint32_t)buf[1] << 8) |
                                      ((uint32_t)buf[2] << 16) | ((uint32_t)buf[3] << 24);
                    printf("0x%" PRIX64 " = %" PRIu32 "\n", address, value);
                }
                result = 0;
            }
        }
    } else {
        if (!address_str) {
            printf("give an address to scan for, or --resolve a path\n");
            result = 2;
        } else {
            uint64_t target;
            if (!ms_parse_hex_u64(address_str, true, &target)) {
                fprintf(stderr, "ptrscan: invalid address '%s'\n", address_str);
                result = 2;
            } else {
                /* --depth and --max were already validated as the parsing loop consumed
                 * them (argparse's type=int fires there, not here) -- but only for shape:
                 * ms_looks_like_int checks that the string is a sign plus decimal digits, not
                 * that it fits any particular width. Python's int() has arbitrary
                 * precision, so a depth like 5000000000 parses and prints exactly as typed;
                 * a 32-bit `long` (what Windows gives you) would silently saturate it long
                 * before the banner below ever sees it, so the conversion has to be 64-bit.
                 * A value too big even for that saturates at strtoll's own extreme, the
                 * same compromise this codebase already makes elsewhere for a number
                 * bigger than any fixed-width type can hold. */
                int64_t depth = 3;
                if (depth_str) {
                    errno = 0;
                    depth = (int64_t)strtoll(depth_str, NULL, 10);
                    /* A string this large is still not an argparse error in Python --
                     * int() has arbitrary precision and keeps the exact digits. The
                     * closest a fixed-width type can come is to saturate at whichever
                     * extreme the sign points at; ERANGE here just confirms that is what
                     * happened, since strtoll already returned that extreme itself. */
                    if (errno == ERANGE) {
                        depth = (depth < 0) ? INT64_MIN : INT64_MAX;
                    }
                }
                /* --offset was already validated as type=hex_offset in the parsing loop
                 * above, so this conversion cannot fail here. */
                uint64_t max_offset = 0x400;
                if (offset_str) {
                    ms_parse_hex_u64(offset_str, true, &max_offset);
                }
                int64_t max_paths = 40;
                if (max_str) {
                    errno = 0;
                    max_paths = (int64_t)strtoll(max_str, NULL, 10);
                    if (errno == ERANGE) {
                        max_paths = (max_paths < 0) ? INT64_MIN : INT64_MAX;
                    }
                }

                printf("scanning for static pointer paths to 0x%" PRIX64
                       " (depth %" PRId64 ", max offset 0x%" PRIX64 ")...\n",
                       target, depth, max_offset);

                PointerMap map;
                pointermap_init(&map);
                pointermap_build(&map, &io);

                PathResult *results = NULL;
                size_t result_count = 0;
                size_t dropped = 0;
                ptrpath_find(&map, modules, module_count, target, depth, max_offset,
                             (size_t)(max_paths > 0 ? max_paths : 0), DEFAULT_MAX_FRONTIER,
                             &results, &result_count, &dropped);

                printf("mapped %zu pointers; found %zu path(s)\n", map.count, result_count);

                char limit_lines[2][PTRPATH_LIMIT_LINE_MAX];
                int limit_count = ptrpath_scan_limits(&map, dropped, limit_lines);
                for (int i = 0; i < limit_count; i++) {
                    printf("%s\n", limit_lines[i]);
                }
                printf("\n");

                for (size_t i = 0; i < result_count; i++) {
                    PathResult *r = &results[i];
                    uint64_t address;
                    bool resolved = ptrpath_resolve(&io, r->module_name, r->module_offset,
                                                     r->offsets, r->offset_count, modules,
                                                     module_count, &address);
                    char path_text[512];
                    ptrpath_format(r->module_name, r->module_offset, r->offsets,
                                    r->offset_count, path_text, sizeof(path_text));
                    if (resolved && address == target) {
                        printf("  %s   [ok]\n", path_text);
                    } else if (resolved && address != 0) {
                        printf("  %s   [-> 0x%" PRIX64 "]\n", path_text, address);
                    } else {
                        printf("  %s   [stale]\n", path_text);
                    }
                }
                if (result_count == 0) {
                    printf("  none. Widen --depth or --offset, or the value may not be "
                           "reached from a\n");
                    printf("  module's static data at all.\n");
                }

                ptrpath_free_results(results, result_count);
                pointermap_free(&map);
                result = 0;
            }
        }
    }

    free(modules);
    process_close(&io);
    return result;
}
