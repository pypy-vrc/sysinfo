#pragma once

typedef struct sha1 {
    uint64_t bytes;
    uint32_t a, b, c, d, e, f;
    uint8_t buf[64];
} sha1_t;

extern void sha1_init(sha1_t *ctx);
extern void sha1_update(sha1_t *ctx, const void *buf, size_t len);
extern void sha1_final(sha1_t *ctx, void *result);
