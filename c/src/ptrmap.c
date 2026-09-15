/*
 * ptrmap.c -- see include/ptrmap.h. Native port of ptrscan.py's modules(), PointerMap and
 * static_of().
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>

#include <stdlib.h>
#include <string.h>

#include "ptrmap.h"
#include "util.h"

#define PTRMAP_CHUNK_SIZE (4ULL * 1024 * 1024)
#define PTRMAP_PTR_SIZE 8

/* --- modules ----------------------------------------------------------------------------- */

int process_modules(unsigned long pid, ModuleEntry *out, int cap) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0; /* matches modules()'s `return []` on a failed snapshot */
    }

    MODULEENTRY32W entry;
    entry.dwSize = sizeof(entry);
    int count = 0;

    if (Module32FirstW(snapshot, &entry)) {
        do {
            if (out && count < cap) {
                ms_wide_to_utf8(entry.szModule, out[count].name, MODULE_NAME_MAX);
                out[count].base = (uint64_t)(uintptr_t)entry.modBaseAddr;
                out[count].size = entry.modBaseSize;
            }
            count++;
        } while (Module32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return count;
}

bool ptrmap_static_of(const ModuleEntry *modules, int count, uint64_t address,
                       const ModuleEntry **module_out, uint64_t *offset_out) {
    for (int i = 0; i < count; i++) {
        if (modules[i].base <= address && address < modules[i].base + modules[i].size) {
            if (module_out) {
                *module_out = &modules[i];
            }
            if (offset_out) {
                *offset_out = address - modules[i].base;
            }
            return true;
        }
    }
    return false;
}

/* --- PointerMap ---------------------------------------------------------------------------- */

void pointermap_init(PointerMap *map) {
    memset(map, 0, sizeof(*map));
    map->max_hits = PTRMAP_DEFAULT_MAX_HITS;
    map->max_scan_bytes = PTRMAP_DEFAULT_MAX_SCAN_BYTES;
}

void pointermap_free(PointerMap *map) {
    if (!map) {
        return;
    }
    free(map->region_base);
    free(map->region_end);
    free(map->bounds_base);
    free(map->bounds_end);
    free(map->pairs);
    map->region_base = NULL;
    map->region_end = NULL;
    map->region_count = 0;
    map->region_capacity = 0;
    map->bounds_base = NULL;
    map->bounds_end = NULL;
    map->bounds_count = 0;
    map->pairs = NULL;
    map->count = 0;
    map->capacity = 0;
    map->truncated = false;
}

/* Collects regions()'s output into map->region_base/region_end, in whatever order
 * regions() itself yields -- the walk order pointermap_build reads memory in. Nothing here
 * assumes that order is ascending by base; build_bounds() below sorts a separate copy for
 * the plausibility test. */
static int collect_region(void *user, uint64_t base, uint64_t size) {
    PointerMap *map = (PointerMap *)user;
    if (map->region_count == map->region_capacity) {
        size_t new_cap = map->region_capacity ? map->region_capacity * 2 : 64;
        uint64_t *new_base = (uint64_t *)realloc(map->region_base, new_cap * sizeof(uint64_t));
        uint64_t *new_end = (uint64_t *)realloc(map->region_end, new_cap * sizeof(uint64_t));
        /* Keep whichever half grew (realloc leaves the original block intact on failure),
         * drop this region, and stop collecting further ones rather than write past a
         * capacity that failed to grow. */
        if (new_base) {
            map->region_base = new_base;
        }
        if (new_end) {
            map->region_end = new_end;
        }
        if (!new_base || !new_end) {
            return 1;
        }
        map->region_capacity = new_cap;
    }
    map->region_base[map->region_count] = base;
    map->region_end[map->region_count] = base + size;
    map->region_count++;
    return 0; /* never stop the enumeration early */
}

/* One (base, end) bound, sortable as a unit so base and end never come apart while
 * qsort() reorders them. */
typedef struct {
    uint64_t base;
    uint64_t end;
} RegionBound;

static int compare_bounds(const void *a, const void *b) {
    const RegionBound *ba = (const RegionBound *)a;
    const RegionBound *bb = (const RegionBound *)b;
    if (ba->base != bb->base) {
        return ba->base < bb->base ? -1 : 1;
    }
    if (ba->end != bb->end) {
        return ba->end < bb->end ? -1 : 1;
    }
    return 0;
}

/* Sorts a copy of the just-collected region bounds by base, ascending, into
 * map->bounds_base/bounds_end -- exactly ptrscan.py's
 * `self.region_bounds = sorted((base, base + size) for base, size in regions)`, kept apart
 * from map->region_base/region_end so plausible()'s binary search never depends on the
 * order regions() happened to enumerate in. Returns false (leaving the map's bounds arrays
 * freed and empty) if the copy could not be allocated. */
static bool build_bounds(PointerMap *map) {
    map->bounds_count = map->region_count;
    if (map->region_count == 0) {
        return true;
    }
    RegionBound *bounds = (RegionBound *)malloc(map->region_count * sizeof(RegionBound));
    if (!bounds) {
        map->bounds_count = 0;
        return false;
    }
    for (size_t i = 0; i < map->region_count; i++) {
        bounds[i].base = map->region_base[i];
        bounds[i].end = map->region_end[i];
    }
    qsort(bounds, map->region_count, sizeof(RegionBound), compare_bounds);

    uint64_t *sorted_base = (uint64_t *)malloc(map->region_count * sizeof(uint64_t));
    uint64_t *sorted_end = (uint64_t *)malloc(map->region_count * sizeof(uint64_t));
    if (!sorted_base || !sorted_end) {
        free(bounds);
        free(sorted_base);
        free(sorted_end);
        map->bounds_count = 0;
        return false;
    }
    for (size_t i = 0; i < map->region_count; i++) {
        sorted_base[i] = bounds[i].base;
        sorted_end[i] = bounds[i].end;
    }
    free(bounds);

    map->bounds_base = sorted_base;
    map->bounds_end = sorted_end;
    return true;
}

/* bisect_right(region_bounds, (value, 1<<63)) - 1, against map->bounds_base/bounds_end
 * (sorted by build_bounds(), independently of region_base/region_end's enumeration order):
 * the last region whose base is <= value, checked against its end. */
static bool plausible(const PointerMap *map, uint64_t value) {
    size_t lo = 0, hi = map->bounds_count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (map->bounds_base[mid] <= value) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    if (lo == 0) {
        return false;
    }
    size_t i = lo - 1;
    return value < map->bounds_end[i];
}

/* Returns false (leaving `map` unchanged) if growing the array failed, so the caller can
 * treat running out of memory as another reason the walk was cut short. */
static bool append_pair(PointerMap *map, uint64_t value, uint64_t holder) {
    if (map->count == map->capacity) {
        size_t new_cap = map->capacity ? map->capacity * 2 : 1024;
        PointerPair *grown = (PointerPair *)realloc(map->pairs, new_cap * sizeof(PointerPair));
        if (!grown) {
            return false;
        }
        map->pairs = grown;
        map->capacity = new_cap;
    }
    map->pairs[map->count].value = value;
    map->pairs[map->count].holder = holder;
    map->count++;
    return true;
}

static int compare_pairs(const void *a, const void *b) {
    const PointerPair *pa = (const PointerPair *)a;
    const PointerPair *pb = (const PointerPair *)b;
    if (pa->value != pb->value) {
        return pa->value < pb->value ? -1 : 1;
    }
    if (pa->holder != pb->holder) {
        return pa->holder < pb->holder ? -1 : 1;
    }
    return 0;
}

void pointermap_build(PointerMap *map, ProcessIO *process) {
    pointermap_free(map);
    /* pointermap_free() only releases the arrays and clears `truncated`; it leaves
     * max_hits/max_scan_bytes alone, so a rebuild keeps whatever caps the caller set. A map
     * that was zero-initialised without pointermap_init() (max_hits/max_scan_bytes still 0)
     * falls back to ptrscan.py's defaults rather than capping at zero. */
    if (map->max_hits == 0) {
        map->max_hits = PTRMAP_DEFAULT_MAX_HITS;
    }
    if (map->max_scan_bytes == 0) {
        map->max_scan_bytes = PTRMAP_DEFAULT_MAX_SCAN_BYTES;
    }

    process->regions(process, collect_region, map);

    if (!build_bounds(map)) {
        /* No sorted bounds to test plausibility against: nothing more can be scanned. */
        map->truncated = true;
        return;
    }

    uint8_t *buf = (uint8_t *)malloc(PTRMAP_CHUNK_SIZE);
    if (!buf) {
        /* No scratch buffer to read into: nothing more can be scanned. */
        map->truncated = true;
        return;
    }
    uint64_t scanned = 0;

    for (size_t r = 0; r < map->region_count && !map->truncated; r++) {
        uint64_t base = map->region_base[r];
        uint64_t size = map->region_end[r] - base;
        uint64_t offset = 0;
        while (offset < size) {
            uint64_t span = (size - offset < PTRMAP_CHUNK_SIZE) ? size - offset
                                                                 : PTRMAP_CHUNK_SIZE;
            size_t got = process->read(process, base + offset, buf, (size_t)span);
            if (got > 0) {
                scanned += got;
                for (size_t at = 0; at + PTRMAP_PTR_SIZE <= got; at += PTRMAP_PTR_SIZE) {
                    uint64_t value;
                    memcpy(&value, buf + at, PTRMAP_PTR_SIZE);
                    if (plausible(map, value)) {
                        if (!append_pair(map, value, base + offset + at)) {
                            map->truncated = true;
                            break;
                        }
                        if ((uint64_t)map->count >= map->max_hits) {
                            map->truncated = true;
                            break;
                        }
                    }
                }
            }
            offset += span;
            if (map->truncated || scanned >= map->max_scan_bytes) {
                map->truncated = true;
                break;
            }
        }
    }

    free(buf);
    if (map->count > 0) {
        qsort(map->pairs, map->count, sizeof(PointerPair), compare_pairs);
    }
}

static size_t lower_bound_value(const PointerPair *pairs, size_t count, uint64_t value) {
    size_t lo = 0, hi = count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (pairs[mid].value < value) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return lo;
}

static size_t upper_bound_value(const PointerPair *pairs, size_t count, uint64_t value) {
    size_t lo = 0, hi = count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (pairs[mid].value <= value) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return lo;
}

size_t pointermap_pointers_into(const PointerMap *map, uint64_t target, uint64_t max_offset,
                                 PointerHit *out, size_t out_cap) {
    uint64_t lower = (target >= max_offset) ? target - max_offset : 0;
    size_t lo = lower_bound_value(map->pairs, map->count, lower);
    size_t hi = upper_bound_value(map->pairs, map->count, target);
    size_t total = (hi > lo) ? hi - lo : 0;
    size_t n = total < out_cap ? total : out_cap;
    for (size_t i = 0; i < n; i++) {
        out[i].holder = map->pairs[lo + i].holder;
        out[i].offset = target - map->pairs[lo + i].value;
    }
    return total;
}
