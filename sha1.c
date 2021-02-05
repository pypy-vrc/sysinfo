#include "pch.h"

#define GET(i) \
    arr[i] = (p[i * 4] << 24) \
           | (p[i * 4 + 1] << 16) \
           | (p[i * 4 + 2] << 8) \
           | (p[i * 4 + 3])

#define SCHEDULE(i) \
    temp = arr[i - 16] ^ arr[i - 14] ^ arr[i - 8] ^ arr[i - 3]; \
    arr[i] = (temp << 1) | (temp >> 31)

#define STEP(k, i, a, b, e, f) \
    e += k + arr[i] + ((a << 5) | (a >> 27)) + (f); \
    b = (b << 30) | (b >> 2)

#define ROUND0(a, b, c, d, e, i) \
    STEP(0x5a827999, i, a, b, e, (b & c) | ((~b) & d))

#define ROUND1(a, b, c, d, e, i) \
    STEP(0x6ed9eba1, i, a, b, e, b ^ c ^ d)

#define ROUND2(a, b, c, d, e, i) \
    STEP(0x8f1bbcdc, i, a, b, e, (b & c) ^ ((b ^ c) & d))

#define ROUND3(a, b, c, d, e, i) \
    STEP(0xca62c1d6, i, a, b, e, b ^ c ^ d)

void *sha1_update_(sha1_t *ctx, const void *buf, size_t len)
{
    uint8_t *p;
    uint32_t temp, a, b, c, d, e, copy_a, copy_b, copy_c, copy_d, copy_e;
    uint32_t arr[80];

    p = (uint8_t *)buf;
    a = ctx->a;
    b = ctx->b;
    c = ctx->c;
    d = ctx->d;
    e = ctx->e;

    do {
        GET(0);
        GET(1);
        GET(2);
        GET(3);
        GET(4);
        GET(5);
        GET(6);
        GET(7);
        GET(8);
        GET(9);
        GET(10);
        GET(11);
        GET(12);
        GET(13);
        GET(14);
        GET(15);

        p += 64;

        SCHEDULE(16);
        SCHEDULE(17);
        SCHEDULE(18);
        SCHEDULE(19);
        SCHEDULE(20);
        SCHEDULE(21);
        SCHEDULE(22);
        SCHEDULE(23);
        SCHEDULE(24);
        SCHEDULE(25);
        SCHEDULE(26);
        SCHEDULE(27);
        SCHEDULE(28);
        SCHEDULE(29);
        SCHEDULE(30);
        SCHEDULE(31);
        SCHEDULE(32);
        SCHEDULE(33);
        SCHEDULE(34);
        SCHEDULE(35);
        SCHEDULE(36);
        SCHEDULE(37);
        SCHEDULE(38);
        SCHEDULE(39);
        SCHEDULE(40);
        SCHEDULE(41);
        SCHEDULE(42);
        SCHEDULE(43);
        SCHEDULE(44);
        SCHEDULE(45);
        SCHEDULE(46);
        SCHEDULE(47);
        SCHEDULE(48);
        SCHEDULE(49);
        SCHEDULE(50);
        SCHEDULE(51);
        SCHEDULE(52);
        SCHEDULE(53);
        SCHEDULE(54);
        SCHEDULE(55);
        SCHEDULE(56);
        SCHEDULE(57);
        SCHEDULE(58);
        SCHEDULE(59);
        SCHEDULE(60);
        SCHEDULE(61);
        SCHEDULE(62);
        SCHEDULE(63);
        SCHEDULE(64);
        SCHEDULE(65);
        SCHEDULE(66);
        SCHEDULE(67);
        SCHEDULE(68);
        SCHEDULE(69);
        SCHEDULE(70);
        SCHEDULE(71);
        SCHEDULE(72);
        SCHEDULE(73);
        SCHEDULE(74);
        SCHEDULE(75);
        SCHEDULE(76);
        SCHEDULE(77);
        SCHEDULE(78);
        SCHEDULE(79);

        copy_a = a;
        copy_b = b;
        copy_c = c;
        copy_d = d;
        copy_e = e;

        ROUND0(a, b, c, d, e, 0);
	    ROUND0(e, a, b, c, d, 1);
	    ROUND0(d, e, a, b, c, 2);
	    ROUND0(c, d, e, a, b, 3);
	    ROUND0(b, c, d, e, a, 4);
	    ROUND0(a, b, c, d, e, 5);
	    ROUND0(e, a, b, c, d, 6);
	    ROUND0(d, e, a, b, c, 7);
	    ROUND0(c, d, e, a, b, 8);
	    ROUND0(b, c, d, e, a, 9);
	    ROUND0(a, b, c, d, e, 10);
	    ROUND0(e, a, b, c, d, 11);
	    ROUND0(d, e, a, b, c, 12);
	    ROUND0(c, d, e, a, b, 13);
	    ROUND0(b, c, d, e, a, 14);
	    ROUND0(a, b, c, d, e, 15);
	    ROUND0(e, a, b, c, d, 16);
	    ROUND0(d, e, a, b, c, 17);
	    ROUND0(c, d, e, a, b, 18);
	    ROUND0(b, c, d, e, a, 19);
	    ROUND1(a, b, c, d, e, 20);
	    ROUND1(e, a, b, c, d, 21);
	    ROUND1(d, e, a, b, c, 22);
	    ROUND1(c, d, e, a, b, 23);
	    ROUND1(b, c, d, e, a, 24);
	    ROUND1(a, b, c, d, e, 25);
	    ROUND1(e, a, b, c, d, 26);
	    ROUND1(d, e, a, b, c, 27);
	    ROUND1(c, d, e, a, b, 28);
	    ROUND1(b, c, d, e, a, 29);
	    ROUND1(a, b, c, d, e, 30);
	    ROUND1(e, a, b, c, d, 31);
	    ROUND1(d, e, a, b, c, 32);
	    ROUND1(c, d, e, a, b, 33);
	    ROUND1(b, c, d, e, a, 34);
	    ROUND1(a, b, c, d, e, 35);
	    ROUND1(e, a, b, c, d, 36);
	    ROUND1(d, e, a, b, c, 37);
	    ROUND1(c, d, e, a, b, 38);
	    ROUND1(b, c, d, e, a, 39);
	    ROUND2(a, b, c, d, e, 40);
	    ROUND2(e, a, b, c, d, 41);
	    ROUND2(d, e, a, b, c, 42);
	    ROUND2(c, d, e, a, b, 43);
	    ROUND2(b, c, d, e, a, 44);
	    ROUND2(a, b, c, d, e, 45);
	    ROUND2(e, a, b, c, d, 46);
	    ROUND2(d, e, a, b, c, 47);
	    ROUND2(c, d, e, a, b, 48);
	    ROUND2(b, c, d, e, a, 49);
	    ROUND2(a, b, c, d, e, 50);
	    ROUND2(e, a, b, c, d, 51);
	    ROUND2(d, e, a, b, c, 52);
	    ROUND2(c, d, e, a, b, 53);
	    ROUND2(b, c, d, e, a, 54);
	    ROUND2(a, b, c, d, e, 55);
	    ROUND2(e, a, b, c, d, 56);
	    ROUND2(d, e, a, b, c, 57);
	    ROUND2(c, d, e, a, b, 58);
	    ROUND2(b, c, d, e, a, 59);
	    ROUND3(a, b, c, d, e, 60);
	    ROUND3(e, a, b, c, d, 61);
	    ROUND3(d, e, a, b, c, 62);
	    ROUND3(c, d, e, a, b, 63);
	    ROUND3(b, c, d, e, a, 64);
	    ROUND3(a, b, c, d, e, 65);
	    ROUND3(e, a, b, c, d, 66);
	    ROUND3(d, e, a, b, c, 67);
	    ROUND3(c, d, e, a, b, 68);
	    ROUND3(b, c, d, e, a, 69);
	    ROUND3(a, b, c, d, e, 70);
	    ROUND3(e, a, b, c, d, 71);
	    ROUND3(d, e, a, b, c, 72);
	    ROUND3(c, d, e, a, b, 73);
	    ROUND3(b, c, d, e, a, 74);
	    ROUND3(a, b, c, d, e, 75);
	    ROUND3(e, a, b, c, d, 76);
	    ROUND3(d, e, a, b, c, 77);
	    ROUND3(c, d, e, a, b, 78);
	    ROUND3(b, c, d, e, a, 79);

        a += copy_a;
        b += copy_b;
        c += copy_c;
        d += copy_d;
        e += copy_e;
    } while (len -= 64);

    ctx->a = a;
    ctx->b = b;
    ctx->c = c;
    ctx->d = d;
    ctx->e = e;

    return p;
}

void sha1_init(sha1_t *ctx)
{
    ctx->bytes = 0;
    ctx->a = 0x67452301;
    ctx->b = 0xefcdab89;
    ctx->c = 0x98badcfe;
    ctx->d = 0x10325476;
    ctx->e = 0xc3d2e1f0;
}

void sha1_update(sha1_t *ctx, const void *buf, size_t len)
{
    size_t used, free;

    used = ((size_t)ctx->bytes) & 63;
    ctx->bytes += len;

    if (used) {
        free = 64 - used;

        if (len < free) {
            memcpy(&ctx->buf[used], buf, len);
            return;
        }

        memcpy(&ctx->buf[used], buf, free);
        buf = (char *)buf + free;
        len -= free;
        sha1_update_(ctx, ctx->buf, 64);
    }

    if (len >= 64) {
        buf = sha1_update_(ctx, buf, len & ~63);
        len &= 63;
    }

    memcpy(ctx->buf, buf, len);
}

void sha1_final(sha1_t *ctx, void *result)
{
    size_t used, free;
    uint8_t *p;

    used = ((size_t)ctx->bytes) & 63;
    ctx->buf[used++] = 128;
    free = 64 - used;

    if (free < 8) {
        memset(&ctx->buf[used], 0, free);
        sha1_update_(ctx, ctx->buf, 64);
        used = 0;
        free = 64;
    }

    memset(&ctx->buf[used], 0, free - 8);

    ctx->bytes <<= 3;
    ctx->buf[56] = (uint8_t)(ctx->bytes >> 56);
    ctx->buf[57] = (uint8_t)(ctx->bytes >> 48);
    ctx->buf[58] = (uint8_t)(ctx->bytes >> 40);
    ctx->buf[59] = (uint8_t)(ctx->bytes >> 32);
    ctx->buf[60] = (uint8_t)(ctx->bytes >> 24);
    ctx->buf[61] = (uint8_t)(ctx->bytes >> 16);
    ctx->buf[62] = (uint8_t)(ctx->bytes >> 8);
    ctx->buf[63] = (uint8_t)ctx->bytes;

    sha1_update_(ctx, ctx->buf, 64);

    if (result == NULL) {
        return;
    }

    p = (uint8_t *)result;
    p[0] = (uint8_t)(ctx->a >> 24);
    p[1] = (uint8_t)(ctx->a >> 16);
    p[2] = (uint8_t)(ctx->a >> 8);
    p[3] = (uint8_t)ctx->a;
    p[4] = (uint8_t)(ctx->b >> 24);
    p[5] = (uint8_t)(ctx->b >> 16);
    p[6] = (uint8_t)(ctx->b >> 8);
    p[7] = (uint8_t)ctx->b;
    p[8] = (uint8_t)(ctx->c >> 24);
    p[9] = (uint8_t)(ctx->c >> 16);
    p[10] = (uint8_t)(ctx->c >> 8);
    p[11] = (uint8_t)ctx->c;
    p[12] = (uint8_t)(ctx->d >> 24);
    p[13] = (uint8_t)(ctx->d >> 16);
    p[14] = (uint8_t)(ctx->d >> 8);
    p[15] = (uint8_t)ctx->d;
    p[16] = (uint8_t)(ctx->e >> 24);
    p[17] = (uint8_t)(ctx->e >> 16);
    p[18] = (uint8_t)(ctx->e >> 8);
    p[19] = (uint8_t)ctx->e;
}
