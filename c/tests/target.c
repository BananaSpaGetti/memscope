/*
 * target.c -- a small purpose-built process for tests/differential.py to attach memscope and
 * ptrscan (both the Python originals and the C port) to.
 *
 * This file lives under tests/, but the Makefile builds it as its own named target
 * (build/tests/target.exe) rather than sweeping it into `make test`'s wildcard -- it holds no
 * self-tests of its own.
 *
 * Run as `target --hold` (which is how differential.py starts it): prints its own pid, then
 * the address of one instance of every scannable type and a two-hop heap pointer chain, one
 * "NAME 0xADDRESS" pair per line, a trailing "READY" line, then idles in a bounded sleep loop
 * until the harness terminates it. Nothing here ever writes to its own memory after startup,
 * so every value stays exactly where and what it was printed as for as long as the process
 * lives.
 */
#include <windows.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* One instance of every scannable type, at values unlikely to occur by coincidence elsewhere
 * in this small process's memory. */
static volatile int8_t g_int8 = -66;
static volatile uint8_t g_uint8 = 233;
static volatile int16_t g_int16 = -12345;
static volatile uint16_t g_uint16 = 54321;
static volatile int32_t g_int32 = -1234567890;
static volatile uint32_t g_uint32 = 3987654321u;
static volatile int64_t g_int64 = -9012345678901234LL;
static volatile uint64_t g_uint64 = 17123456789012345ULL;
static volatile float g_float = 12.5f;
static volatile double g_double = 987654.321;

/* A value distinct from all of the above, for the REPL's `scan <value>` test -- an exact scan
 * for it cannot coincidentally also match one of the fixed values above. */
static volatile int32_t g_scan_target = 74123698;

/* A two-hop static pointer chain for ptrscan: g_root lives in this module's own static data
 * (so it is a valid chain root), and points at a heap block (mid) that itself points at a
 * second heap block (leaf) holding the value ptrscan is asked to find a path to. Neither heap
 * address is static, so a depth-1 search finds nothing and a depth-2 search finds exactly the
 * one path through g_root. */
static void *g_root = NULL;

static void print_addr(const char *name, const volatile void *addr) {
    printf("%s 0x%llX\n", name, (unsigned long long)(uintptr_t)addr);
}

int main(int argc, char **argv) {
    if (argc < 2 || strcmp(argv[1], "--hold") != 0) {
        /* `make test` runs this with no arguments and wants a clean, immediate exit. */
        return 0;
    }

    uint64_t *leaf = (uint64_t *)malloc(sizeof(uint64_t));
    uint64_t **mid = (uint64_t **)malloc(sizeof(uint64_t *));
    if (!leaf || !mid) {
        return 1;
    }
    *leaf = 0x2A2A2A2A2A2A2A2AULL; /* the value ptrscan's path resolves down to */
    *mid = leaf;
    g_root = mid;

    printf("PID %lu\n", (unsigned long)GetCurrentProcessId());
    print_addr("int8", &g_int8);
    print_addr("uint8", &g_uint8);
    print_addr("int16", &g_int16);
    print_addr("uint16", &g_uint16);
    print_addr("int32", &g_int32);
    print_addr("uint32", &g_uint32);
    print_addr("int64", &g_int64);
    print_addr("uint64", &g_uint64);
    print_addr("float", &g_float);
    print_addr("double", &g_double);
    print_addr("scan_target", &g_scan_target);
    print_addr("leaf", leaf);
    printf("READY\n");
    fflush(stdout);

    for (;;) {
        Sleep(50);
    }
    return 0;
}
