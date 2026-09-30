// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
//
// Vendored SHA-256 + HMAC-SHA-256 (no external dependencies; the executor build
// forbids linking libcrypto). Used by the MPTCP mutation layer to recompute keys
// and MP_JOIN HMACs in userspace from wire-captured keys. Matches
// net/mptcp/crypto.c exactly (implemented helpers below in parentheses):
//   token = be32(SHA256(be64(key))[0:4])                   (syz_mptcp_token_from_key)
//   idsn  = be64(SHA256(be64(key))[24:32])                 (no helper yet -- add when a mutation needs the IDSN)
//   MP_JOIN HMAC = HMAC-SHA256(be64(k1) || be64(k2), msg)  (syz_mptcp_join_hmac; truncate as the wire needs)
// SHA-256 is the standard FIPS 180-4 construction.
//
// Naming caveat: the csource reproducer generator rewrites the substrings
// uint8/uint16/uint32/uint64 -> uintN_t (a bare, non-word-bounded replace), so
// never use those as a substring inside an identifier in this file (e.g. a name
// like syz_uint32_load would become syz_uint32_t_load in the reproducer only).
#ifndef EXECUTOR_COMMON_LINUX_MPTCP_CRYPTO_H
#define EXECUTOR_COMMON_LINUX_MPTCP_CRYPTO_H

#include <string.h>

struct syz_sha256 {
	uint32 h[8];
	uint64 len;
	uint8 buf[64];
	uint32 idx;
};

static const uint32 syz_sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

#define SHA256_ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static inline void syz_sha256_block(struct syz_sha256* c, const uint8* p)
{
	uint32 w[64], a, b, cc, d, e, f, g, h, t1, t2;

	for (int i = 0; i < 16; i++)
		w[i] = ((uint32)p[i * 4] << 24) | ((uint32)p[i * 4 + 1] << 16) |
		       ((uint32)p[i * 4 + 2] << 8) | (uint32)p[i * 4 + 3];
	for (int i = 16; i < 64; i++) {
		uint32 s0 = SHA256_ROR32(w[i - 15], 7) ^ SHA256_ROR32(w[i - 15], 18) ^ (w[i - 15] >> 3);
		uint32 s1 = SHA256_ROR32(w[i - 2], 17) ^ SHA256_ROR32(w[i - 2], 19) ^ (w[i - 2] >> 10);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}
	a = c->h[0];
	b = c->h[1];
	cc = c->h[2];
	d = c->h[3];
	e = c->h[4];
	f = c->h[5];
	g = c->h[6];
	h = c->h[7];
	for (int i = 0; i < 64; i++) {
		uint32 S1 = SHA256_ROR32(e, 6) ^ SHA256_ROR32(e, 11) ^ SHA256_ROR32(e, 25);
		uint32 ch = (e & f) ^ (~e & g);
		t1 = h + S1 + ch + syz_sha256_k[i] + w[i];
		uint32 S0 = SHA256_ROR32(a, 2) ^ SHA256_ROR32(a, 13) ^ SHA256_ROR32(a, 22);
		uint32 maj = (a & b) ^ (a & cc) ^ (b & cc);
		t2 = S0 + maj;
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = cc;
		cc = b;
		b = a;
		a = t1 + t2;
	}
	c->h[0] += a;
	c->h[1] += b;
	c->h[2] += cc;
	c->h[3] += d;
	c->h[4] += e;
	c->h[5] += f;
	c->h[6] += g;
	c->h[7] += h;
}

static inline void syz_sha256_init(struct syz_sha256* c)
{
	c->h[0] = 0x6a09e667;
	c->h[1] = 0xbb67ae85;
	c->h[2] = 0x3c6ef372;
	c->h[3] = 0xa54ff53a;
	c->h[4] = 0x510e527f;
	c->h[5] = 0x9b05688c;
	c->h[6] = 0x1f83d9ab;
	c->h[7] = 0x5be0cd19;
	c->len = 0;
	c->idx = 0;
}

static inline void syz_sha256_update(struct syz_sha256* c, const uint8* data, size_t n)
{
	for (size_t i = 0; i < n; i++) {
		c->buf[c->idx++] = data[i];
		if (c->idx == 64) {
			syz_sha256_block(c, c->buf);
			c->idx = 0;
		}
	}
	c->len += n;
}

static inline void syz_sha256_final(struct syz_sha256* c, uint8 out[32])
{
	uint64 bits = c->len * 8;
	uint8 pad = 0x80;
	syz_sha256_update(c, &pad, 1);
	pad = 0;
	while (c->idx != 56)
		syz_sha256_update(c, &pad, 1);
	uint8 lenb[8];
	for (int i = 0; i < 8; i++)
		lenb[i] = (uint8)(bits >> (56 - i * 8));
	syz_sha256_update(c, lenb, 8);
	for (int i = 0; i < 8; i++) {
		out[i * 4] = (uint8)(c->h[i] >> 24);
		out[i * 4 + 1] = (uint8)(c->h[i] >> 16);
		out[i * 4 + 2] = (uint8)(c->h[i] >> 8);
		out[i * 4 + 3] = (uint8)(c->h[i]);
	}
}

static inline void syz_sha256(const uint8* data, size_t n, uint8 out[32])
{
	struct syz_sha256 c;
	syz_sha256_init(&c);
	syz_sha256_update(&c, data, n);
	syz_sha256_final(&c, out);
}

// HMAC-SHA256 (RFC 2104), block size 64.
static inline void syz_hmac_sha256(const uint8* key, size_t keylen,
				   const uint8* msg, size_t msglen, uint8 out[32])
{
	uint8 k[64], ipad[64], opad[64], inner[32];
	struct syz_sha256 c;

	memset(k, 0, sizeof(k));
	if (keylen > 64)
		syz_sha256(key, keylen, k); // keys >64B are hashed; ours are 16B
	else if (keylen)
		memcpy(k, key, keylen); // guard keylen==0: memcpy(,NULL,0) is UB
	for (size_t i = 0; i < 64; i++) {
		ipad[i] = k[i] ^ 0x36;
		opad[i] = k[i] ^ 0x5c;
	}
	syz_sha256_init(&c);
	syz_sha256_update(&c, ipad, 64);
	syz_sha256_update(&c, msg, msglen);
	syz_sha256_final(&c, inner);
	syz_sha256_init(&c);
	syz_sha256_update(&c, opad, 64);
	syz_sha256_update(&c, inner, 32);
	syz_sha256_final(&c, out);
}

// be64 helper without pulling <endian.h> semantics ambiguity.
static inline void syz_put_be64(uint8 b[8], uint64 v)
{
	for (int i = 0; i < 8; i++)
		b[i] = (uint8)(v >> (56 - i * 8));
}

// token = be32(SHA256(be64(key))[0:4]) -- matches mptcp_crypto_key_sha().
static inline uint32 syz_mptcp_token_from_key(uint64 key)
{
	uint8 in[8], h[32];
	syz_put_be64(in, key);
	syz_sha256(in, 8, h);
	return ((uint32)h[0] << 24) | ((uint32)h[1] << 16) |
	       ((uint32)h[2] << 8) | (uint32)h[3];
}

// MP_JOIN HMAC = HMAC-SHA256(be64(k1)||be64(k2), msg) -- matches
// mptcp_crypto_hmac_sha(); full 32-byte output, caller truncates as the wire needs.
static inline void syz_mptcp_join_hmac(uint64 k1, uint64 k2,
				       const uint8* msg, size_t msglen, uint8 out[32])
{
	uint8 key[16];
	syz_put_be64(key, k1);
	syz_put_be64(key + 8, k2);
	syz_hmac_sha256(key, sizeof(key), msg, msglen, out);
}

#endif // EXECUTOR_COMMON_LINUX_MPTCP_CRYPTO_H
