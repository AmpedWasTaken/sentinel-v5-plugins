#include "stats.h"

SENTINEL_EXPORT uint32_t sentinel_stats_abi_version(void) {
    return 1U;
}

SENTINEL_EXPORT int sentinel_stats_analyze(
    const uint8_t *data, size_t length, sentinel_native_stats *out) {
    size_t i;
    uint64_t hash = UINT64_C(14695981039346656037);

    if (out == NULL || (data == NULL && length != 0U)) {
        return -1;
    }

    out->bytes = (uint64_t)length;
    out->ascii_letters = 0U;
    out->digits = 0U;
    out->spaces = 0U;
    out->fnv1a64 = hash;

    for (i = 0; i < length; i++) {
        const uint8_t value = data[i];

        if ((value >= (uint8_t)'a' && value <= (uint8_t)'z') ||
            (value >= (uint8_t)'A' && value <= (uint8_t)'Z')) {
            out->ascii_letters++;
        }
        if (value >= (uint8_t)'0' && value <= (uint8_t)'9') {
            out->digits++;
        }
        if (value == (uint8_t)' ' || value == (uint8_t)'\t' ||
            value == (uint8_t)'\n' || value == (uint8_t)'\r') {
            out->spaces++;
        }
        hash ^= (uint64_t)value;
        hash *= UINT64_C(1099511628211);
    }
    out->fnv1a64 = hash;
    return 0;
}
