/*
 * process.c -- the real Win32 backend for struct ProcessIO, plus process listing and
 * attach(). Native port of the process-facing half of MemScope/memscope.py.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "process.h"
#include "util.h"

/* The four access rights memscope.py ORs together for OpenProcess. */
#define PROCESS_ACCESS \
    (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION)

typedef struct {
    HANDLE handle;
} Win32Ctx;

/* --- the real Win32 backend ----------------------------------------------------------- */

static void win32_regions(ProcessIO *self, RegionFn visit, void *user) {
    Win32Ctx *ctx = (Win32Ctx *)self->ctx;
    MEMORY_BASIC_INFORMATION info;
    uint64_t address = 0;
    const uint64_t limit = 0x7FFFFFFFFFFFULL;

    while (address < limit) {
        if (VirtualQueryEx(ctx->handle, (LPCVOID)(uintptr_t)address, &info, sizeof(info)) == 0) {
            break;
        }
        uint64_t base = (uint64_t)(uintptr_t)info.BaseAddress;
        uint64_t size = (uint64_t)info.RegionSize;
        if (size == 0) {
            break;
        }
        /* Protect carries the base protection in its low byte with modifier flags above
         * it (PAGE_GUARD, PAGE_NOCACHE, PAGE_WRITECOMBINE). Mask to the low byte before
         * the writable-set test, or a writable page tagged NOCACHE or WRITECOMBINE is
         * missed; but test PAGE_GUARD unmasked, and still exclude guard pages, which
         * raise when read. */
        DWORD base_protect = info.Protect & 0xFF;
        int writable = base_protect == PAGE_READWRITE || base_protect == PAGE_WRITECOPY ||
                       base_protect == PAGE_EXECUTE_READWRITE ||
                       base_protect == PAGE_EXECUTE_WRITECOPY;
        if (info.State == MEM_COMMIT && writable && !(info.Protect & PAGE_GUARD)) {
            if (visit(user, base, size)) {
                return;
            }
        }
        address = base + size;
    }
}

static size_t win32_read(ProcessIO *self, uint64_t address, void *out, size_t size) {
    Win32Ctx *ctx = (Win32Ctx *)self->ctx;
    SIZE_T got = 0;
    if (!ReadProcessMemory(ctx->handle, (LPCVOID)(uintptr_t)address, out, size, &got)) {
        return 0;
    }
    return (size_t)got;
}

static int win32_write(ProcessIO *self, uint64_t address, const void *data, size_t size) {
    Win32Ctx *ctx = (Win32Ctx *)self->ctx;
    SIZE_T wrote = 0;
    BOOL ok = WriteProcessMemory(ctx->handle, (LPVOID)(uintptr_t)address, data, size, &wrote);
    return ok && wrote == size;
}

int process_open(unsigned long pid, ProcessIO *io, char *err_out, size_t err_out_size) {
    HANDLE handle = OpenProcess(PROCESS_ACCESS, FALSE, (DWORD)pid);
    if (!handle) {
        DWORD err = GetLastError();
        if (err_out && err_out_size) {
            if (err == 5) {
                snprintf(err_out, err_out_size,
                         "OpenProcess(%lu) failed, error %lu.\n"
                         "  Access denied: the target runs at a higher integrity level than "
                         "this shell.\n"
                         "  Run this from an elevated terminal.",
                         pid, (unsigned long)err);
            } else {
                snprintf(err_out, err_out_size, "OpenProcess(%lu) failed, error %lu.", pid,
                         (unsigned long)err);
            }
        }
        return -1;
    }

    Win32Ctx *ctx = (Win32Ctx *)malloc(sizeof(Win32Ctx));
    if (!ctx) {
        CloseHandle(handle);
        if (err_out && err_out_size) {
            snprintf(err_out, err_out_size, "out of memory opening pid %lu", pid);
        }
        return -1;
    }
    ctx->handle = handle;

    io->ctx = ctx;
    io->regions = win32_regions;
    io->read = win32_read;
    io->write = win32_write;
    return 0;
}

void process_close(ProcessIO *io) {
    if (!io || !io->ctx) {
        return;
    }
    Win32Ctx *ctx = (Win32Ctx *)io->ctx;
    if (ctx->handle) {
        CloseHandle(ctx->handle);
    }
    free(ctx);
    io->ctx = NULL;
}

/* --- listing and attach ---------------------------------------------------------------- */

int process_list(const char *needle, ProcessEntry *out, int cap) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return -1;
    }

    char lower_needle[PROCESS_NAME_MAX];
    ms_to_lower_copy(needle ? needle : "", lower_needle, sizeof(lower_needle));

    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(entry);
    int count = 0;

    if (Process32FirstW(snapshot, &entry)) {
        do {
            char name[PROCESS_NAME_MAX];
            ms_wide_to_utf8(entry.szExeFile, name, sizeof(name));
            char lower_name[PROCESS_NAME_MAX];
            ms_to_lower_copy(name, lower_name, sizeof(lower_name));

            if (lower_needle[0] == '\0' || strstr(lower_name, lower_needle) != NULL) {
                if (out && count < cap) {
                    out[count].pid = entry.th32ProcessID;
                    strncpy(out[count].name, name, PROCESS_NAME_MAX - 1);
                    out[count].name[PROCESS_NAME_MAX - 1] = '\0';
                }
                count++;
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return count;
}

static int is_decimal(const char *target) {
    if (!target || target[0] == '\0') {
        return 0;
    }
    for (const char *p = target; *p; p++) {
        if (!isdigit((unsigned char)*p)) {
            return 0;
        }
    }
    return 1;
}

int process_attach(const char *target, ProcessIO *io, unsigned long *pid_out, char *name_out,
                    size_t name_out_size) {
    unsigned long pid;
    char name[PROCESS_NAME_MAX] = "";

    /* A target made only of decimal digits is used directly as a pid, matching
     * memscope.py's `target.isdigit()` -- it is never matched against process names, and
     * its existence is not checked here; a bad pid simply fails at OpenProcess below. */
    if (is_decimal(target)) {
        pid = strtoul(target, NULL, 10);
    } else {
        int count = process_list(target, NULL, 0);
        if (count <= 0) {
            printf("no process matching '%s'\n", target);
            return -1;
        }
        ProcessEntry *matches = (ProcessEntry *)malloc((size_t)count * sizeof(ProcessEntry));
        if (!matches) {
            printf("no process matching '%s'\n", target);
            return -1;
        }
        /* The count above comes from an earlier snapshot; the matching process could exit
         * before this second snapshot fills matches[]. Treat this return value, not the
         * first, as authoritative -- it is the only one that reflects what actually got
         * written into matches[]. */
        int filled = process_list(target, matches, count);
        if (filled <= 0) {
            printf("no process matching '%s'\n", target);
            free(matches);
            return -1;
        }
        if (filled > 1) {
            printf("more than one match; pick a pid:\n");
            /* process_list can report more matches than fit in matches[] (capacity was
             * `count`); only entries below that capacity were actually written. */
            int usable = filled < count ? filled : count;
            int shown = usable < 20 ? usable : 20;
            for (int i = 0; i < shown; i++) {
                printf("  %-8lu %s\n", matches[i].pid, matches[i].name);
            }
            free(matches);
            return -1;
        }
        pid = matches[0].pid;
        strncpy(name, matches[0].name, sizeof(name) - 1);
        free(matches);
    }

    char err[512];
    if (process_open(pid, io, err, sizeof(err)) != 0) {
        printf("%s\n", err);
        return -1;
    }

    if (pid_out) {
        *pid_out = pid;
    }
    if (name_out && name_out_size) {
        strncpy(name_out, name, name_out_size - 1);
        name_out[name_out_size - 1] = '\0';
    }
    return 0;
}
