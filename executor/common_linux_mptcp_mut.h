// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
//
// MPTCP mutation layer (increment 3): the (matcher, field-mutator) that the
// stateless NFQUEUE engine (common_linux_mptcp_nfq.h) drives. It rewrites an
// MP_JOIN option on an egress packet to exercise the kernel's crypto gate
// (HMAC/nonce validation), then the engine recomputes the TCP checksum.
//
// Determinism (design mptcp_mutation_and_key_capture.md 6a/6b): the mutation is a
// pure function of packet content + a per-proc instruction that the syscall
// thread PUBLISHES (release) before it triggers the join, and the worker reads
// (acquire). The recorded program carries only the RULE (which op); run-specific
// values are re-derived live. The HMAC-bearing MP_JOIN ACK carries no token, so
// the instruction is keyed on the subflow's per-slot IP source address (known at
// publish time, replay-stable).
//
// Ingress-injection Phase 0 (design ingress_injection_design.md 7): adds the
// MPTCP_MUT_CRYPTO_SELFVERIFY op. It does NOT mutate -- it broadens the matcher to
// also observe the server SYN-ACK (bearing R_B, which the saddr-only mutation
// filter dropped), stashes R_A (client SYN) and R_B (server SYN-ACK) per handshake,
// then at the client ACK recomputes the MP_JOIN HMAC from the captured nonces + the
// wire-captured MP_CAPABLE keys and asserts it equals the HMAC the kernel put on the
// wire. This is the first live caller of the vendored crypto (crypto.h), and the
// acceptance gate that R_B capture + the HMAC recompute are correct before any
// adversarial inject is built on them.
#ifndef EXECUTOR_COMMON_LINUX_MPTCP_MUT_H
#define EXECUTOR_COMMON_LINUX_MPTCP_MUT_H

#include <string.h> // memset, memcpy, memcmp

// The Phase-0 self-verify op recomputes the MP_JOIN HMAC via the vendored
// HMAC-SHA256. crypto.h is a sibling header, already included before this one by
// common_linux_mptcp.h; the explicit include (idempotent via its guard) makes the
// dependency order-independent. Note crypto.h's identifier caveat: the csource
// generator bare-substring-rewrites uint8/16/32/64 -> uintN_t, so no identifier
// here embeds those substrings (the field/op names below are all clear).
#include "common_linux_mptcp_crypto.h"

// Mutation ops (the RULE stored in the program's join_subflow arg). Kept small;
// grown per the design 5 grammar. 0 = no mutation (engine hook is a pass-through).
// HMAC_* corrupt the client ACK's 20-byte HMAC (server-side gate: MPJoinAckHMac-
// Failure). NONCE_* corrupt the client SYN's 4-byte nonce (drives a different gate:
// the SYN-ACK thmac the client then validates against its real nonce).
#define MPTCP_MUT_NONE 0
#define MPTCP_MUT_HMAC_FLIP 1 // flip one bit of the ACK HMAC
#define MPTCP_MUT_HMAC_ZERO 2 // zero the whole ACK HMAC
#define MPTCP_MUT_NONCE_FLIP 3 // flip one bit of the SYN nonce
#define MPTCP_MUT_CRYPTO_SELFVERIFY 4 // Phase 0: capture R_A/R_B, recompute+verify the ACK HMAC; no mutation

// MP_JOIN wire constants (RFC 8684; net/mptcp/options.c).
// SYN:     [kind][len=12][sub|bkup][join_id][token:be32][nonce:be32]
// SYN-ACK: [kind][len=16][sub|bkup][join_id][thmac:be64][nonce:be32]
// ACK:     [kind][len=24][rsv][rsv][hmac:20]
#define MPTCP_TCPOPT 30
#define MPTCP_SUB_JOIN 1
#define MPTCP_JOIN_SYN_OLEN 12
#define MPTCP_JOIN_SYN_NONCE_OFF 8 // nonce after kind,len,sub|bkup,join_id,token:4
#define MPTCP_JOIN_SYNACK_OLEN 16
#define MPTCP_JOIN_SYNACK_NONCE_OFF 12 // nonce after kind,len,sub|bkup,join_id,thmac:8
#define MPTCP_JOIN_NONCE_LEN 4
#define MPTCP_JOIN_ACK_OLEN 24
#define MPTCP_JOIN_HMAC_OFF 4 // hmac after the 4-byte option header
#define MPTCP_JOIN_HMAC_LEN 20

// Self-verify result codes (published by the worker, read by the syscall thread).
#define MPTCP_SELFVERIFY_PENDING 0
#define MPTCP_SELFVERIFY_MATCH 1
#define MPTCP_SELFVERIFY_MISMATCH (-1)
#define MPTCP_SELFVERIFY_NO_KEYS (-2) // keys_valid was false (pair not CAPTURE_KEYS)
#define MPTCP_SELFVERIFY_NO_NONCE (-3) // reached ACK before both nonces were captured

// The published instruction. Single-writer (the joining syscall thread), single
// reader class (the NFQUEUE worker). active is the release/acquire gate.
//
// Concurrency note (unchanged from the mutation layer): this is a single global
// spec, so one join's publish/retire window must not overlap another's -- the same
// single-join assumption the existing HMAC/NONCE ops already rely on. The SELFVERIFY
// capture fields (below) are per-handshake and reset at publish, so they inherit the
// same single-in-flight-join contract.
struct syz_mptcp_mut_spec {
	volatile int active;
	uint32 src_addr_be; // match egress MP_JOIN from this per-slot local address
	int op;

	// --- Phase-0 SELFVERIFY inputs (published by the syscall thread) ---
	// The pair's wire-captured MP_CAPABLE keys, host order: client=local (sender
	// of the 3rd MP_CAPABLE ACK), server=remote. keys_valid gates them.
	uint64 local_key;
	uint64 remote_key;
	int keys_valid;

	// --- Phase-0 SELFVERIFY capture stash (worker-written, per handshake) ---
	// Nonces kept as the raw 4 wire bytes (network/big-endian) -- exactly the
	// bytes the kernel feeds to the HMAC (put_unaligned_be32), so they concatenate
	// straight into the message with no byte-order juggling. Published to the ACK
	// step via the have_* release flags (which also establish happens-before for
	// the array writes, so the arrays themselves need not be volatile).
	uint8 r_a[MPTCP_JOIN_NONCE_LEN]; // client SYN nonce (local_nonce)
	uint8 r_b[MPTCP_JOIN_NONCE_LEN]; // server SYN-ACK nonce (remote_nonce)
	volatile int have_r_a;
	volatile int have_r_b;

	// --- Phase-0 SELFVERIFY result (worker-written, syscall-thread-read) ---
	uint8 wire_hmac[MPTCP_JOIN_HMAC_LEN]; // the ACK HMAC the kernel emitted
	uint8 calc_hmac[MPTCP_JOIN_HMAC_LEN]; // our recompute from captured nonces+keys
	volatile int verify_done; // MPTCP_SELFVERIFY_* (release on publish of result)
};
static struct syz_mptcp_mut_spec syz_mptcp_mut;

// Publish before triggering the join; retire after. release/acquire via `active`.
// keys/keys_valid are only consulted by the SELFVERIFY op; pass 0/0/0 otherwise.
static inline void syz_mptcp_mut_publish(uint32 src_addr_be, int op,
					 uint64 local_key, uint64 remote_key, int keys_valid)
{
	syz_mptcp_mut.src_addr_be = src_addr_be;
	syz_mptcp_mut.op = op;
	syz_mptcp_mut.local_key = local_key;
	syz_mptcp_mut.remote_key = remote_key;
	syz_mptcp_mut.keys_valid = keys_valid;
	// Reset the per-handshake capture stash so a reused global spec / a replay
	// starts clean (run-specific values are always re-derived live).
	syz_mptcp_mut.have_r_a = 0;
	syz_mptcp_mut.have_r_b = 0;
	syz_mptcp_mut.verify_done = MPTCP_SELFVERIFY_PENDING;
	__atomic_store_n(&syz_mptcp_mut.active, 1, __ATOMIC_RELEASE);
}

static inline void syz_mptcp_mut_retire(void)
{
	__atomic_store_n(&syz_mptcp_mut.active, 0, __ATOMIC_RELEASE);
}

// SELFVERIFY result for the syscall thread (MPTCP_SELFVERIFY_*). Acquire-loaded so
// the wire_hmac/calc_hmac arrays the worker wrote before the release are visible.
static inline int syz_mptcp_mut_verify_result(void)
{
	return __atomic_load_n(&syz_mptcp_mut.verify_done, __ATOMIC_ACQUIRE);
}

// Phase-0 SELFVERIFY: observe one MP_JOIN option (o points at its kind byte, olen
// is its length) and advance the handshake capture. Never mutates. from_client is
// true for the client->server direction (SYN / ACK), false for server->client
// (SYN-ACK). On the client ACK it recomputes the HMAC and publishes the verdict.
static inline void syz_mptcp_mut_selfverify_capture(const uint8* o, uint8 olen, int from_client)
{
	if (from_client && olen == MPTCP_JOIN_SYN_OLEN) {
		// client SYN carries R_A (local_nonce) at the nonce offset.
		memcpy(syz_mptcp_mut.r_a, o + MPTCP_JOIN_SYN_NONCE_OFF, MPTCP_JOIN_NONCE_LEN);
		__atomic_store_n(&syz_mptcp_mut.have_r_a, 1, __ATOMIC_RELEASE);
		return;
	}
	if (!from_client && olen == MPTCP_JOIN_SYNACK_OLEN) {
		// server SYN-ACK carries R_B (remote_nonce) -- the value the saddr-only
		// mutation filter dropped; the broadened matcher captures it here.
		memcpy(syz_mptcp_mut.r_b, o + MPTCP_JOIN_SYNACK_NONCE_OFF, MPTCP_JOIN_NONCE_LEN);
		__atomic_store_n(&syz_mptcp_mut.have_r_b, 1, __ATOMIC_RELEASE);
		return;
	}
	if (from_client && olen == MPTCP_JOIN_ACK_OLEN) {
		// client ACK carries the 20-byte HMAC the kernel computed. Self-verify.
		if (!syz_mptcp_mut.keys_valid) {
			__atomic_store_n(&syz_mptcp_mut.verify_done, MPTCP_SELFVERIFY_NO_KEYS, __ATOMIC_RELEASE);
			return;
		}
		if (!__atomic_load_n(&syz_mptcp_mut.have_r_a, __ATOMIC_ACQUIRE) ||
		    !__atomic_load_n(&syz_mptcp_mut.have_r_b, __ATOMIC_ACQUIRE)) {
			__atomic_store_n(&syz_mptcp_mut.verify_done, MPTCP_SELFVERIFY_NO_NONCE, __ATOMIC_RELEASE);
			return;
		}
		memcpy(syz_mptcp_mut.wire_hmac, o + MPTCP_JOIN_HMAC_OFF, MPTCP_JOIN_HMAC_LEN);
		// Kernel client-side ACK HMAC (net/mptcp/subflow.c subflow_finish_connect
		// -> subflow_generate_hmac(local_key, remote_key, local_nonce, remote_nonce)):
		//   msg = be32(R_A) || be32(R_B)   -- r_a/r_b already hold the wire (be) bytes
		//   HMAC-SHA256(be64(local_key) || be64(remote_key), msg), take 20 bytes.
		uint8 msg[2 * MPTCP_JOIN_NONCE_LEN];
		uint8 digest[32];
		memcpy(msg, syz_mptcp_mut.r_a, MPTCP_JOIN_NONCE_LEN);
		memcpy(msg + MPTCP_JOIN_NONCE_LEN, syz_mptcp_mut.r_b, MPTCP_JOIN_NONCE_LEN);
		syz_mptcp_join_hmac(syz_mptcp_mut.local_key, syz_mptcp_mut.remote_key,
				    msg, sizeof(msg), digest);
		memcpy(syz_mptcp_mut.calc_hmac, digest, MPTCP_JOIN_HMAC_LEN);
		int match = memcmp(syz_mptcp_mut.wire_hmac, syz_mptcp_mut.calc_hmac, MPTCP_JOIN_HMAC_LEN) == 0;
		__atomic_store_n(&syz_mptcp_mut.verify_done,
				 match ? MPTCP_SELFVERIFY_MATCH : MPTCP_SELFVERIFY_MISMATCH,
				 __ATOMIC_RELEASE);
	}
}

// The NFQUEUE hook (matches syz_nfq_mutate_fn). Return contract (engine-shared,
// see common_linux_mptcp_nfq.h): >0 = the packet's new total IP length (the engine
// re-injects that many bytes and recomputes checksums; == len for a same-length
// rewrite, > len for a graft); 0 = pass through unmodified; <0 = drop. The
// mutation ops rewrite in place at the same length, so they return `len`. The
// Phase-0 SELFVERIFY op only observes, so it always returns 0.
static inline int syz_mptcp_mut_hook(uint8* pkt, int len)
{
	if (!__atomic_load_n(&syz_mptcp_mut.active, __ATOMIC_ACQUIRE))
		return 0;
	if (len < (int)sizeof(struct iphdr))
		return 0;
	struct iphdr* ip = (struct iphdr*)pkt;
	if (ip->protocol != IPPROTO_TCP)
		return 0;
	int op = syz_mptcp_mut.op;
	// Direction gate. Mutation ops act only on packets FROM the client subflow
	// address (the egress SYN/ACK we rewrite), so the saddr filter is kept. The
	// SELFVERIFY op additionally needs the server SYN-ACK (R_B), which is sourced
	// from the server and destined TO the client address -- so it matches EITHER
	// direction of this subflow's handshake, keyed on the per-slot client address
	// appearing as saddr or daddr (distinct per subflow, so no cross-talk on lo).
	int from_client = (ip->saddr == syz_mptcp_mut.src_addr_be);
	int to_client = (ip->daddr == syz_mptcp_mut.src_addr_be);
	if (op == MPTCP_MUT_CRYPTO_SELFVERIFY) {
		if (!from_client && !to_client)
			return 0;
	} else if (!from_client) {
		return 0;
	}
	int ihl = ip->ihl * 4;
	if (ihl < (int)sizeof(struct iphdr) || len < ihl + (int)sizeof(struct tcphdr))
		return 0;
	struct tcphdr* th = (struct tcphdr*)(pkt + ihl);
	int thl = th->doff * 4;
	if (thl < (int)sizeof(struct tcphdr) || len < ihl + thl)
		return 0;
	uint8* o = pkt + ihl + sizeof(struct tcphdr);
	uint8* end = pkt + ihl + thl;
	while (o < end) {
		uint8 kind = o[0];
		if (kind == 0) // end of option list
			break;
		if (kind == 1) { // NOP
			o++;
			continue;
		}
		if (o + 1 >= end)
			break;
		uint8 olen = o[1];
		if (olen < 2 || o + olen > end)
			break;
		if (kind == MPTCP_TCPOPT && (o[2] >> 4) == MPTCP_SUB_JOIN) {
			// SELFVERIFY: observe only (capture nonces / verify at the ACK).
			if (op == MPTCP_MUT_CRYPTO_SELFVERIFY) {
				syz_mptcp_mut_selfverify_capture(o, olen, from_client);
				return 0;
			}
			// HMAC ops target the ACK (20-byte HMAC).
			if (olen == MPTCP_JOIN_ACK_OLEN) {
				uint8* hmac = o + MPTCP_JOIN_HMAC_OFF;
				if (op == MPTCP_MUT_HMAC_FLIP) {
					hmac[0] ^= 0x01; // deterministic single-bit corruption
					return len; // same-length in-place rewrite
				}
				if (op == MPTCP_MUT_HMAC_ZERO) {
					memset(hmac, 0, MPTCP_JOIN_HMAC_LEN);
					return len; // same-length in-place rewrite
				}
			}
			// NONCE ops target the SYN (4-byte nonce).
			if (olen == MPTCP_JOIN_SYN_OLEN && op == MPTCP_MUT_NONCE_FLIP) {
				o[MPTCP_JOIN_SYN_NONCE_OFF] ^= 0x01;
				return len; // same-length in-place rewrite
			}
		}
		o += olen;
	}
	return 0;
}

#endif // EXECUTOR_COMMON_LINUX_MPTCP_MUT_H
