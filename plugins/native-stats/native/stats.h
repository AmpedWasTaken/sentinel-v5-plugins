#ifndef SENTINEL_NATIVE_STATS_H
#define SENTINEL_NATIVE_STATS_H

#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#define SENTINEL_EXPORT __declspec(dllexport)
#else
#define SENTINEL_EXPORT __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sentinel_native_stats {
    uint64_t bytes;
    uint64_t ascii_letters;
    uint64_t digits;
    uint64_t spaces;
    uint64_t fnv1a64;
} sentinel_native_stats;

/* Stable v1 C ABI: Python declares the matching ctypes.Structure. */
SENTINEL_EXPORT uint32_t sentinel_stats_abi_version(void);
/* Returns 0 on success; -1 if pointers are invalid. */
SENTINEL_EXPORT int sentinel_stats_analyze(
    const uint8_t *data, size_t length, sentinel_native_stats *out);

#ifdef __cplusplus
}
#endif
#endif
