#include "ascon.h"

#include <string.h>

typedef struct {
    uint32_t h, l;
} u64_32;

typedef struct {
    u64_32 x0, x1, x2, x3, x4;
} ascon_state_t;

static inline void ROR64_32(u64_32 *res, u64_32 x, int n)
{
    if (n == 0) {
        *res = x;
    } else if (n < 32) {
        res->h = (x.h >> n) | (x.l << (32 - n));
        res->l = (x.l >> n) | (x.h << (32 - n));
    } else if (n == 32) {
        res->h = x.l;
        res->l = x.h;
    } else {
        int m = n - 32;
        res->h = (x.l >> m) | (x.h << (32 - m));
        res->l = (x.h >> m) | (x.l << (32 - m));
    }
}

static void ascon_permutation(ascon_state_t *s, int rounds)
{
    for (int i = 0; i < rounds; i++) {
        int r = 12 - rounds + i;
        /* Round constant */
        s->x2.l ^= ((uint32_t)(0xf - r) << 4) | r;

        /* Substitution layer */
        s->x0.h ^= s->x4.h;
        s->x0.l ^= s->x4.l;
        s->x4.h ^= s->x3.h;
        s->x4.l ^= s->x3.l;
        s->x2.h ^= s->x1.h;
        s->x2.l ^= s->x1.l;

        u64_32 t0, t1, t2, t3, t4;
        t0.h = ~s->x0.h & s->x1.h;
        t0.l = ~s->x0.l & s->x1.l;
        t1.h = ~s->x1.h & s->x2.h;
        t1.l = ~s->x1.l & s->x2.l;
        t2.h = ~s->x2.h & s->x3.h;
        t2.l = ~s->x2.l & s->x3.l;
        t3.h = ~s->x3.h & s->x4.h;
        t3.l = ~s->x3.l & s->x4.l;
        t4.h = ~s->x4.h & s->x0.h;
        t4.l = ~s->x4.l & s->x0.l;

        s->x0.h ^= t1.h;
        s->x0.l ^= t1.l;
        s->x1.h ^= t2.h;
        s->x1.l ^= t2.l;
        s->x2.h ^= t3.h;
        s->x2.l ^= t3.l;
        s->x3.h ^= t4.h;
        s->x3.l ^= t4.l;
        s->x4.h ^= t0.h;
        s->x4.l ^= t0.l;

        s->x1.h ^= s->x0.h;
        s->x1.l ^= s->x0.l;
        s->x0.h ^= s->x4.h;
        s->x0.l ^= s->x4.l;
        s->x3.h ^= s->x2.h;
        s->x3.l ^= s->x2.l;
        s->x2.h = ~s->x2.h;
        s->x2.l = ~s->x2.l;

        /* Linear diffusion layer */
        u64_32 r0, r1;
        ROR64_32(&r0, s->x0, 19);
        ROR64_32(&r1, s->x0, 28);
        s->x0.h ^= r0.h ^ r1.h;
        s->x0.l ^= r0.l ^ r1.l;

        ROR64_32(&r0, s->x1, 61);
        ROR64_32(&r1, s->x1, 39);
        s->x1.h ^= r0.h ^ r1.h;
        s->x1.l ^= r0.l ^ r1.l;

        ROR64_32(&r0, s->x2, 1);
        ROR64_32(&r1, s->x2, 6);
        s->x2.h ^= r0.h ^ r1.h;
        s->x2.l ^= r0.l ^ r1.l;

        ROR64_32(&r0, s->x3, 10);
        ROR64_32(&r1, s->x3, 17);
        s->x3.h ^= r0.h ^ r1.h;
        s->x3.l ^= r0.l ^ r1.l;

        ROR64_32(&r0, s->x4, 7);
        ROR64_32(&r1, s->x4, 41);
        s->x4.h ^= r0.h ^ r1.h;
        s->x4.l ^= r0.l ^ r1.l;
    }
}

static inline void load64_32(u64_32 *x, const uint8_t *p)
{
    x->h = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
    x->l = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) |
           ((uint32_t)p[6] << 8) | (uint32_t)p[7];
}

static inline void store64_32(uint8_t *p, u64_32 x)
{
    p[0] = (uint8_t)(x.h >> 24);
    p[1] = (uint8_t)(x.h >> 16);
    p[2] = (uint8_t)(x.h >> 8);
    p[3] = (uint8_t)x.h;
    p[4] = (uint8_t)(x.l >> 24);
    p[5] = (uint8_t)(x.l >> 16);
    p[6] = (uint8_t)(x.l >> 8);
    p[7] = (uint8_t)x.l;
}

static inline void loadbytes_32(u64_32 *x, const uint8_t *p, int n)
{
    x->h = 0;
    x->l = 0;
    for (int i = 0; i < n && i < 4; i++) {
        x->h |= (uint32_t)p[i] << (8 * (3 - i));
    }
    for (int i = 4; i < n && i < 8; i++) {
        x->l |= (uint32_t)p[i] << (8 * (7 - i));
    }
}

static inline void storebytes_32(uint8_t *p, u64_32 x, int n)
{
    for (int i = 0; i < n && i < 4; i++) {
        p[i] = (uint8_t)(x.h >> (8 * (3 - i)));
    }
    for (int i = 4; i < n && i < 8; i++) {
        p[i] = (uint8_t)(x.l >> (8 * (7 - i)));
    }
}

void ascon128_encrypt(const uint8_t key[16], const uint8_t nonce[16],
                      const uint8_t *ad, uint32_t ad_len, uint8_t *m,
                      uint32_t m_len, uint8_t tag[16])
{
    ascon_state_t s;
    u64_32 k0, k1, n0, n1;
    load64_32(&k0, key);
    load64_32(&k1, key + 8);
    load64_32(&n0, nonce);
    load64_32(&n1, nonce + 8);

    s.x0.h = 0x80400c06;
    s.x0.l = 0;
    s.x1 = k0;
    s.x2 = k1;
    s.x3 = n0;
    s.x4 = n1;
    ascon_permutation(&s, 12);
    s.x3.h ^= k0.h;
    s.x3.l ^= k0.l;
    s.x4.h ^= k1.h;
    s.x4.l ^= k1.l;

    if (ad_len > 0) {
        while (ad_len >= 8) {
            u64_32 w;
            load64_32(&w, ad);
            s.x0.h ^= w.h;
            s.x0.l ^= w.l;
            ascon_permutation(&s, 6);
            ad += 8;
            ad_len -= 8;
        }
        u64_32 w;
        loadbytes_32(&w, ad, ad_len);
        s.x0.h ^= w.h;
        s.x0.l ^= w.l;
        if (ad_len < 4) {
            s.x0.h ^= (1UL << (31 - 8 * ad_len));
        } else {
            s.x0.l ^= (1UL << (31 - 8 * (ad_len - 4)));
        }
        ascon_permutation(&s, 6);
    }
    s.x4.l ^= 1;

    while (m_len >= 8) {
        u64_32 w;
        load64_32(&w, m);
        s.x0.h ^= w.h;
        s.x0.l ^= w.l;
        store64_32(m, s.x0);
        ascon_permutation(&s, 6);
        m += 8;
        m_len -= 8;
    }
    u64_32 w;
    loadbytes_32(&w, m, m_len);
    s.x0.h ^= w.h;
    s.x0.l ^= w.l;
    storebytes_32(m, s.x0, m_len);
    if (m_len < 4) {
        s.x0.h ^= (1UL << (31 - 8 * m_len));
    } else {
        s.x0.l ^= (1UL << (31 - 8 * (m_len - 4)));
    }

    s.x1.h ^= k0.h;
    s.x1.l ^= k0.l;
    s.x2.h ^= k1.h;
    s.x2.l ^= k1.l;
    ascon_permutation(&s, 12);
    s.x3.h ^= k0.h;
    s.x3.l ^= k0.l;
    s.x4.h ^= k1.h;
    s.x4.l ^= k1.l;
    store64_32(tag, s.x3);
    store64_32(tag + 8, s.x4);
}

void ascon128_decrypt_no_verify(const uint8_t key[16], const uint8_t nonce[16],
                                const uint8_t *ad, uint32_t ad_len,
                                uint8_t *c, uint32_t c_len, uint8_t expected_tag[16])
{
    ascon_state_t s;
    u64_32 k0, k1, n0, n1;
    load64_32(&k0, key);
    load64_32(&k1, key + 8);
    load64_32(&n0, nonce);
    load64_32(&n1, nonce + 8);

    s.x0.h = 0x80400c06;
    s.x0.l = 0;
    s.x1 = k0;
    s.x2 = k1;
    s.x3 = n0;
    s.x4 = n1;
    ascon_permutation(&s, 12);
    s.x3.h ^= k0.h;
    s.x3.l ^= k0.l;
    s.x4.h ^= k1.h;
    s.x4.l ^= k1.l;

    if (ad_len > 0) {
        while (ad_len >= 8) {
            u64_32 w;
            load64_32(&w, ad);
            s.x0.h ^= w.h;
            s.x0.l ^= w.l;
            ascon_permutation(&s, 6);
            ad += 8;
            ad_len -= 8;
        }
        u64_32 w;
        loadbytes_32(&w, ad, ad_len);
        s.x0.h ^= w.h;
        s.x0.l ^= w.l;
        if (ad_len < 4) {
            s.x0.h ^= (1UL << (31 - 8 * ad_len));
        } else {
            s.x0.l ^= (1UL << (31 - 8 * (ad_len - 4)));
        }
        ascon_permutation(&s, 6);
    }
    s.x4.l ^= 1;

    while (c_len >= 8) {
        u64_32 ci;
        load64_32(&ci, c);
        u64_32 mi;
        mi.h = s.x0.h ^ ci.h;
        mi.l = s.x0.l ^ ci.l;
        store64_32(c, mi);
        s.x0 = ci;
        ascon_permutation(&s, 6);
        c += 8;
        c_len -= 8;
    }
    u64_32 ci;
    loadbytes_32(&ci, c, c_len);
    u64_32 mi;
    mi.h = s.x0.h ^ ci.h;
    mi.l = s.x0.l ^ ci.l;
    storebytes_32(c, mi, c_len);

    if (c_len < 4) {
        uint32_t mask =
            (c_len == 0) ? 0 : (0xFFFFFFFFUL << (32 - 8 * c_len));
        s.x0.h = (s.x0.h & ~mask) | ci.h;
        s.x0.h ^= (1UL << (31 - 8 * c_len));
    } else {
        s.x0.h = ci.h;
        uint32_t mask =
            (c_len == 4) ? 0 : (0xFFFFFFFFUL << (32 - 8 * (c_len - 4)));
        s.x0.l = (s.x0.l & ~mask) | ci.l;
        s.x0.l ^= (1UL << (31 - 8 * (c_len - 4)));
    }

    s.x1.h ^= k0.h;
    s.x1.l ^= k0.l;
    s.x2.h ^= k1.h;
    s.x2.l ^= k1.l;
    ascon_permutation(&s, 12);
    s.x3.h ^= k0.h;
    s.x3.l ^= k0.l;
    s.x4.h ^= k1.h;
    s.x4.l ^= k1.l;
    store64_32(expected_tag, s.x3);
    store64_32(expected_tag + 8, s.x4);
}

int ascon128_decrypt(const uint8_t key[16], const uint8_t nonce[16],
                     const uint8_t *ad, uint32_t ad_len, uint8_t *c,
                     uint32_t c_len, const uint8_t tag[16])
{
    uint8_t computed_tag[16];
    ascon128_decrypt_no_verify(key, nonce, ad, ad_len, c, c_len, computed_tag);
    if (memcmp(tag, computed_tag, 16) == 0) {
        return 0;
    }
    return -1;
}

void ascon_xof(const uint8_t *in, uint32_t in_len, uint8_t *out,
               uint32_t out_len)
{
    ascon_state_t s;
    /* ASCON-XOF initialization (IV=00400c0000000000) */
    s.x0.h = 0x00400c00;
    s.x0.l = 0;
    s.x1.h = 0;
    s.x1.l = 0;
    s.x2.h = 0;
    s.x2.l = 0;
    s.x3.h = 0;
    s.x3.l = 0;
    s.x4.h = 0;
    s.x4.l = 0;
    ascon_permutation(&s, 12);

    while (in_len >= 8) {
        u64_32 w;
        load64_32(&w, in);
        s.x0.h ^= w.h;
        s.x0.l ^= w.l;
        ascon_permutation(&s, 12);
        in += 8;
        in_len -= 8;
    }
    u64_32 w;
    loadbytes_32(&w, in, (int)in_len);
    s.x0.h ^= w.h;
    s.x0.l ^= w.l;
    if (in_len < 4) {
      s.x0.h ^= (1UL << (31 - 8 * (int)in_len));
    } else {
        s.x0.l ^= (1UL << (31 - 8 * ((int)in_len - 4)));
    }
    ascon_permutation(&s, 12);

    while (out_len > 8) {
        store64_32(out, s.x0);
        ascon_permutation(&s, 12);
        out += 8;
        out_len -= 8;
    }
    storebytes_32(out, s.x0, (int)out_len);
}
