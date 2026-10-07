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
// Ingress Phase 1: OVERWRITE the client ACK's 20-byte HMAC with a VALID value
// recomputed from the captured nonces + MP_CAPABLE keys (the same value SELFVERIFY
// proved == the kernel's). With unmutated nonces the written bytes are byte-identical
// to the kernel's own HMAC, so the subflow is ACCEPTED -- but now via a harness-authored
// HMAC that crossed subflow_hmac_valid, reaching subflow_syn_recv_sock's ref-transfer
// region. Same-length rewrite (returns len). Needs captured keys + both nonces; if
// either is missing it DROPs the ACK (fail-loud -> the oracle shows NO accept, rather
// than letting the kernel's own genuine HMAC mask a capture miss as a clean join).
#define MPTCP_MUT_HMAC_FORGE 5

// --- Phase 2 (A1/B2): same-length inbound grammar, engine unchanged. ---
// DSS mapping-corruption set (the classic MPTCP "MAP_*" mutations). Each acts on
// the DSS option (subtype 2) of an egress DATA segment FROM the client subflow
// address, rewriting a mapping field IN PLACE (same length -> returns len). They
// reach the server's mapping validation in softirq (subflow_check_data_avail ->
// validate_mapping / mptcp_validate_data_csum, net/mptcp/subflow.c), the
// "accept-but-wrong" region that the reject-only JOIN ops cannot touch.
#define MPTCP_MUT_DSS_SEQ 6 // corrupt the Data Sequence Number (stale/forward DSN)
#define MPTCP_MUT_DSS_SUBSEQ 7 // off-by-one the Subflow Sequence Number (hole/overlap)
#define MPTCP_MUT_DSS_LEN_INF 8 // Data-Level Length = 0 (the "infinite mapping" special case)
#define MPTCP_MUT_DSS_LEN_OFF 9 // Data-Level Length += 1 (mapping over/under-run)
#define MPTCP_MUT_DSS_CSUM 10 // corrupt the DSS checksum (mptcp_validate_data_csum drop path)
#define MPTCP_MUT_DSS_DATA_FIN 11 // set the F (DATA_FIN) flag on a data segment
// B2: flip a bit of the server SYN-ACK thmac (seen at LOCAL_OUT, destined TO the
// client) -> client-side subflow_thmac_valid (subflow_finish_connect) reject path.
#define MPTCP_MUT_THMAC_FLIP 12

// --- Phase 3a (A5): length-GROWING graft, the first op to exercise the NFQUEUE
// length-grow path (design ingress_injection_design.md §4; all ops before this were
// same-length). Graft an unauthenticated ADD_ADDR *echo* option onto a client egress
// MPTCP subflow segment: +8 bytes of TCP option, doff bumped, engine recomputes
// tot_len + IP/TCP csums. Unauthenticated (add_addr_hmac_valid returns true for echo,
// net/mptcp/options.c:1182) -> reaches mptcp_pm_add_addr_echoed. (The authenticated
// NON-echo variant that reaches mptcp_pm_add_addr_received -- the raced pm->remote
// single-slot, the 005/006-adjacent target -- is Phase 3b: it needs a computed
// add-addr HMAC over the captured keys, a P2 forge, not this op.)
#define MPTCP_MUT_ADD_ADDR_ECHO 13

// --- Phase 3b (A5 authenticated): length-growing graft of an AUTHENTICATED non-echo
// ADD_ADDR option (16 bytes) carrying a computed add-addr HMAC over the captured keys
// -- a P2 forge on the same crypto as the MP_JOIN HMAC. The server validates it
// (add_addr_hmac_valid, options.c:1185) and, being non-echo, routes it to
// mptcp_pm_add_addr_received -- the raced pm->remote single-slot (the 005/006-adjacent
// target), which the echo path (Phase 3a) does NOT reach. Needs captured keys.
#define MPTCP_MUT_ADD_ADDR_AUTH 14

// --- Phase 4 (A3): MP_FAIL graft on a live msk. Unauthenticated 12-byte option ->
// mptcp_pm_mp_fail_received (pm.c:872): takes msk->fallback_lock, flips allow_subflows
// / arms the infinite-map fallback -- the 006 fallback machinery, "historically the
// buggiest MPTCP corner". The Phase-4 point is to RACE this against the teardown verbs
// (join_close_race/disconnect/close_server) = the 005/006 UAF cluster. First a
// capability proof that the graft fires + reaches the handler; the race is the hunt.
#define MPTCP_MUT_MP_FAIL 15

// MP_JOIN wire constants (RFC 8684; net/mptcp/options.c).
// SYN:     [kind][len=12][sub|bkup][join_id][token:be32][nonce:be32]
// SYN-ACK: [kind][len=16][sub|bkup][join_id][thmac:be64][nonce:be32]
// ACK:     [kind][len=24][rsv][rsv][hmac:20]
#define MPTCP_TCPOPT 30
#define MPTCP_SUB_MP_CAPABLE 0
#define MPTCP_SUB_JOIN 1
#define MPTCP_JOIN_SYN_OLEN 12
#define MPTCP_JOIN_SYN_NONCE_OFF 8 // nonce after kind,len,sub|bkup,join_id,token:4
#define MPTCP_JOIN_SYNACK_OLEN 16
#define MPTCP_JOIN_SYNACK_NONCE_OFF 12 // nonce after kind,len,sub|bkup,join_id,thmac:8
#define MPTCP_JOIN_NONCE_LEN 4
#define MPTCP_JOIN_ACK_OLEN 24
#define MPTCP_JOIN_HMAC_OFF 4 // hmac after the 4-byte option header
#define MPTCP_JOIN_HMAC_LEN 20
#define MPTCP_JOIN_SYNACK_THMAC_OFF 4 // thmac after kind,len,sub|bkup,join_id
#define MPTCP_JOIN_SYNACK_THMAC_LEN 8

// DSS option (RFC 8684 Fig.9; net/mptcp/options.c mptcp_parse_option / subtype 2):
//   [kind=30][len][subtype(hi nibble)=2 | rsv][rsv..F m M a A]
//   then, in order: Data ACK (A? a?8:4), then the mapping if M set:
//   DSN (m?8:4) | Subflow-Seq(4) | Data-Level-Length(2) | Checksum(2, if negotiated)
#define MPTCP_SUB_DSS 2
// ADD_ADDR graft (Phase 3a). Subtype 3 (MPTCPOPT_ADD_ADDR); echo flag = BIT(0)
// (MPTCP_ADDR_ECHO). Echo IPv4-no-port option = 8 bytes (TCPOLEN_MPTCP_ADD_ADDR_BASE):
// [kind=30][len=8][subtype<<4 | echo][addr_id][IPv4 addr:4]. Grown TCP header must
// stay <= 60 bytes (doff field max 15 words); named distinctly from the nfq header's
// MPTCP_TCP_MAX_HDR, which is not yet included where this header sits.
#define MPTCP_SUB_ADD_ADDR 3
#define MPTCP_ADDR_ECHO_FLAG 0x01
#define MPTCP_ADD_ADDR_ECHO_OLEN 8
#define MPTCP_ADD_ADDR_AUTH_OLEN 16 // non-echo IPv4, no port, +8-byte ahmac (TCPOLEN_MPTCP_ADD_ADDR)
#define MPTCP_ADD_ADDR_GRAFT_ID 0x9 // announced address id (arbitrary, distinct)
// MP_FAIL graft (Phase 4). Subtype 6; 12-byte option (TCPOLEN_MPTCP_FAIL):
// [kind=30][len=12][subtype<<4|rsv][rsv][fail_seq:be64]. Unauthenticated; coexists
// with DSS/RST only (options.c:405), which the DSS data/ack carriers satisfy.
#define MPTCP_SUB_MP_FAIL 6
#define MPTCP_MP_FAIL_OLEN 12
#define MPTCP_MP_FAIL_SEQ 0x1000 // fail_seq (data-level seq for the infinite map; arbitrary)
#define MPTCP_MUT_MAX_TCP_HDR 60
#define MPTCP_DSS_FLAG_A 0x01 // Data ACK present
#define MPTCP_DSS_FLAG_a 0x02 // Data ACK is 8 octets (else 4)
#define MPTCP_DSS_FLAG_M 0x04 // mapping (DSN/SSN/len/csum) present
#define MPTCP_DSS_FLAG_m 0x08 // DSN is 8 octets (else 4)
#define MPTCP_DSS_FLAG_F 0x10 // DATA_FIN
#define MPTCP_DSS_FLAGS_OFF 3 // the flags byte within the option
#define MPTCP_DSS_FIELDS_OFF 4 // first variable field (Data ACK or mapping)

// Self-verify result codes (published by the worker, read by the syscall thread).
#define MPTCP_SELFVERIFY_PENDING 0
#define MPTCP_SELFVERIFY_MATCH 1
#define MPTCP_SELFVERIFY_MISMATCH (-1)
#define MPTCP_SELFVERIFY_NO_KEYS (-2) // keys_valid was false (pair not CAPTURE_KEYS)
#define MPTCP_SELFVERIFY_NO_NONCE (-3) // reached ACK before both nonces were captured

// Phase-1 FORGE result codes (published by the worker on the ACK, read by the
// syscall thread for the debug oracle). Mirror the SELFVERIFY codes.
#define MPTCP_FORGE_PENDING 0
#define MPTCP_FORGE_WROTE 1 // wrote a valid HMAC onto the ACK (same-length)
#define MPTCP_FORGE_NO_KEYS (-2) // keys_valid was false (pair not CAPTURE_KEYS) -> dropped
#define MPTCP_FORGE_NO_NONCE (-3) // reached ACK before both nonces were captured -> dropped

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

	// --- Phase-1 FORGE result (worker-written, syscall-thread-read) ---
	volatile int forge_done; // MPTCP_FORGE_* (release on publish of result)
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
	syz_mptcp_mut.forge_done = MPTCP_FORGE_PENDING;
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

// FORGE result for the syscall thread (MPTCP_FORGE_*). Acquire-loaded.
static inline int syz_mptcp_mut_forge_result(void)
{
	return __atomic_load_n(&syz_mptcp_mut.forge_done, __ATOMIC_ACQUIRE);
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

// Phase-1 FORGE: observe one MP_JOIN option (o points at its kind byte, olen its
// length). Reuses the SELFVERIFY capture stash: on the client SYN it stashes R_A, on
// the server SYN-ACK it stashes R_B (both pass through unmodified), and on the client
// ACK it OVERWRITES the 20-byte HMAC with HMAC-SHA256(be64(client_key)||be64(server_key),
// R_A||R_B)[0:20] -- the exact value SELFVERIFY proved equals the kernel's -- so the
// server accepts a harness-authored HMAC. Returns the engine code: 0 = pass through
// (SYN/SYN-ACK), len = same-length rewrite (ACK), <0 = drop (fail-loud on missing
// keys/nonces so the oracle shows no accept rather than a kernel-HMAC masked join).
static inline int syz_mptcp_mut_forge(uint8* o, uint8 olen, int from_client, int len)
{
	if (from_client && olen == MPTCP_JOIN_SYN_OLEN) {
		// client SYN carries R_A (the real nonce -- Phase 1 does NOT mutate it;
		// §3b: a mutated SYN nonce makes the client reset on the SYN-ACK thmac).
		memcpy(syz_mptcp_mut.r_a, o + MPTCP_JOIN_SYN_NONCE_OFF, MPTCP_JOIN_NONCE_LEN);
		__atomic_store_n(&syz_mptcp_mut.have_r_a, 1, __ATOMIC_RELEASE);
		return 0; // pass through
	}
	if (!from_client && olen == MPTCP_JOIN_SYNACK_OLEN) {
		// server SYN-ACK carries R_B (seen via the broadened direction gate).
		memcpy(syz_mptcp_mut.r_b, o + MPTCP_JOIN_SYNACK_NONCE_OFF, MPTCP_JOIN_NONCE_LEN);
		__atomic_store_n(&syz_mptcp_mut.have_r_b, 1, __ATOMIC_RELEASE);
		return 0; // pass through
	}
	if (from_client && olen == MPTCP_JOIN_ACK_OLEN) {
		if (!syz_mptcp_mut.keys_valid) {
			// Fail LOUD: drop the ACK so the oracle shows NO accept, rather than
			// letting the kernel's own genuine HMAC mask a capture miss.
			__atomic_store_n(&syz_mptcp_mut.forge_done, MPTCP_FORGE_NO_KEYS, __ATOMIC_RELEASE);
			return -1; // NF_DROP
		}
		if (!__atomic_load_n(&syz_mptcp_mut.have_r_a, __ATOMIC_ACQUIRE) ||
		    !__atomic_load_n(&syz_mptcp_mut.have_r_b, __ATOMIC_ACQUIRE)) {
			__atomic_store_n(&syz_mptcp_mut.forge_done, MPTCP_FORGE_NO_NONCE, __ATOMIC_RELEASE);
			return -1; // NF_DROP
		}
		uint8* hmac = o + MPTCP_JOIN_HMAC_OFF;
		// Same construction SELFVERIFY proved == the wire ACK HMAC (and == what the
		// server's subflow_hmac_valid recomputes): client key first, server key second,
		// message = be32(R_A)||be32(R_B) (r_a/r_b hold the raw wire be bytes).
		uint8 msg[2 * MPTCP_JOIN_NONCE_LEN];
		uint8 digest[32];
		memcpy(msg, syz_mptcp_mut.r_a, MPTCP_JOIN_NONCE_LEN);
		memcpy(msg + MPTCP_JOIN_NONCE_LEN, syz_mptcp_mut.r_b, MPTCP_JOIN_NONCE_LEN);
		syz_mptcp_join_hmac(syz_mptcp_mut.local_key, syz_mptcp_mut.remote_key,
				    msg, sizeof(msg), digest);
		memcpy(hmac, digest, MPTCP_JOIN_HMAC_LEN); // overwrite (truncate 32 -> 20)
		__atomic_store_n(&syz_mptcp_mut.forge_done, MPTCP_FORGE_WROTE, __ATOMIC_RELEASE);
		return len; // same-length in-place rewrite
	}
	return 0;
}

// Phase 2 (A1): same-length DSS mapping-field corruption. `o` points at the DSS
// option's kind byte, `olen` is its length. Parses the flags byte to locate the
// mapping fields, rewrites exactly one in place, and returns `len` (same length).
// Returns 0 (pass unmodified) when the option does not carry the field the op
// targets -- a flagless / Data-ACK-only DSS is not falsely mutated, and a truncated
// mapping is left alone rather than written out of bounds.
static inline int syz_mptcp_mut_dss(uint8* o, uint8 olen, int op, int len)
{
	if (olen < MPTCP_DSS_FIELDS_OFF + 1)
		return 0;
	uint8 flags = o[MPTCP_DSS_FLAGS_OFF];

	// DATA_FIN sets the F flag; valid on any DSS (even ack-only), so handle it first.
	if (op == MPTCP_MUT_DSS_DATA_FIN) {
		o[MPTCP_DSS_FLAGS_OFF] = flags | MPTCP_DSS_FLAG_F;
		return len;
	}

	// Every other op corrupts the mapping block. Skip the Data ACK if present.
	int off = MPTCP_DSS_FIELDS_OFF;
	if (flags & MPTCP_DSS_FLAG_A)
		off += (flags & MPTCP_DSS_FLAG_a) ? 8 : 4;
	if (!(flags & MPTCP_DSS_FLAG_M))
		return 0; // no mapping present to corrupt
	int dsn_len = (flags & MPTCP_DSS_FLAG_m) ? 8 : 4;
	int dsn_off = off;
	int subseq_off = dsn_off + dsn_len;
	int dlen_off = subseq_off + 4;
	int csum_off = dlen_off + 2;
	if (dlen_off + 2 > (int)olen)
		return 0; // DSN + Subflow-Seq + Data-Level-Length must fit the option

	switch (op) {
	case MPTCP_MUT_DSS_SEQ: {
		// Push the low 32 bits of the DSN out of the expected data window.
		uint8* p = o + dsn_off + dsn_len - 4;
		uint32 v = ((uint32)p[0] << 24) | ((uint32)p[1] << 16) | ((uint32)p[2] << 8) | p[3];
		v -= 0x00010000u;
		p[0] = v >> 24;
		p[1] = v >> 16;
		p[2] = v >> 8;
		p[3] = v;
		return len;
	}
	case MPTCP_MUT_DSS_SUBSEQ: {
		// Off-by-one the subflow sequence number -> mapping hole / overlap.
		uint8* p = o + subseq_off;
		uint32 v = ((uint32)p[0] << 24) | ((uint32)p[1] << 16) | ((uint32)p[2] << 8) | p[3];
		v += 1;
		p[0] = v >> 24;
		p[1] = v >> 16;
		p[2] = v >> 8;
		p[3] = v;
		return len;
	}
	case MPTCP_MUT_DSS_LEN_INF:
		o[dlen_off] = 0; // Data-Level Length 0 == the "infinite mapping" special case
		o[dlen_off + 1] = 0;
		return len;
	case MPTCP_MUT_DSS_LEN_OFF: {
		uint16 v = ((uint16)o[dlen_off] << 8) | o[dlen_off + 1];
		v += 1; // mapping over/under-run by one byte
		o[dlen_off] = v >> 8;
		o[dlen_off + 1] = v;
		return len;
	}
	case MPTCP_MUT_DSS_CSUM:
		if (csum_off + 2 > (int)olen)
			return 0; // checksum not negotiated / absent -> nothing to corrupt
		o[csum_off] ^= 0x01; // bad DSS csum -> mptcp_validate_data_csum drop path
		return len;
	}
	return 0;
}

// Shared length-grow graft: insert `optlen` bytes (`optbytes`, a well-formed TCP
// option; optlen a multiple of 4) at the START of the TCP options of a client egress
// ESTABLISHED, NON-HANDSHAKE segment that has option room. Returns len+optlen, or 0
// (pass unmodified) if the segment is a handshake segment or has no room. The engine
// recomputes tot_len + IP/TCP csums for the new length; this only inserts + bumps doff.
//
// Carrier rule (VM-run-hardened): reject MP_JOIN/MP_CAPABLE segments -- grafting an
// ADD_ADDR there corrupts the handshake (options.c:266 forbids the coexistence) and
// the subflow never establishes (the bug the first Phase-3a run caught). from_client
// (checked by the hook) means saddr == the joined subflow's local addr, so any such
// segment IS this subflow's traffic. The DSS-carrying data segments are option-full on
// a timestamps connection ([RUN]-4) -- MPTCP_INIT_NO_TIMESTAMPS frees the room.
static inline int syz_mptcp_mut_graft_opt(uint8* pkt, int len, int ihl,
					  struct tcphdr* th, const uint8* optbytes, int optlen)
{
	int thl = th->doff * 4;
	uint8* opt = pkt + ihl + sizeof(struct tcphdr);
	uint8* oend = pkt + ihl + thl;
	int forbidden = 0;
	for (uint8* o = opt; o < oend;) {
		uint8 k = o[0];
		if (k == 0)
			break;
		if (k == 1) {
			o++;
			continue;
		}
		if (o + 1 >= oend)
			break;
		uint8 ol = o[1];
		if (ol < 2 || o + ol > oend)
			break;
		if (k == MPTCP_TCPOPT && ol >= 3) {
			uint8 sub = o[2] >> 4;
			if (sub == MPTCP_SUB_MP_CAPABLE || sub == MPTCP_SUB_JOIN)
				forbidden = 1;
		}
		o += ol;
	}
	if (forbidden)
		return 0;
	// Grown TCP header must stay <= 60 bytes (doff <= 15 words); skip full carriers.
	if (thl + optlen > MPTCP_MUT_MAX_TCP_HDR)
		return 0;
	int optstart = ihl + (int)sizeof(struct tcphdr);
	int tail = len - optstart;
	memmove(pkt + optstart + optlen, pkt + optstart, (size_t)tail);
	memcpy(pkt + optstart, optbytes, (size_t)optlen);
	th->doff += optlen / 4;
	return len + optlen;
}

// Phase 3a: unauthenticated echo ADD_ADDR (8 bytes) -> mptcp_pm_add_addr_echoed.
static inline int syz_mptcp_mut_add_addr_echo(uint8* pkt, int len, int ihl, struct tcphdr* th)
{
	uint8 o[MPTCP_ADD_ADDR_ECHO_OLEN];
	o[0] = MPTCP_TCPOPT; // kind 30
	o[1] = MPTCP_ADD_ADDR_ECHO_OLEN; // opsize 8 (TCPOLEN_MPTCP_ADD_ADDR_BASE)
	o[2] = (MPTCP_SUB_ADD_ADDR << 4) | MPTCP_ADDR_ECHO_FLAG; // subtype 3 | echo bit
	o[3] = MPTCP_ADD_ADDR_GRAFT_ID;
	o[4] = 127; // 127.0.0.8 (echo: value cosmetic)
	o[5] = 0;
	o[6] = 0;
	o[7] = 8;
	return syz_mptcp_mut_graft_opt(pkt, len, ihl, th, o, MPTCP_ADD_ADDR_ECHO_OLEN);
}

// Phase 3b: AUTHENTICATED non-echo ADD_ADDR (16 bytes) -> mptcp_pm_add_addr_received.
// The server validates via add_addr_generate_hmac(remote_key, local_key, addr) =
// HMAC-SHA256(be64(client_key)||be64(server_key), id||addr||port) truncated to the
// LAST 8 bytes of the 32-byte digest. We hold client_key=local_key, server_key=
// remote_key (captured), so syz_mptcp_join_hmac(local_key, remote_key, msg) gives the
// matching keyed digest; the wire ahmac is digest[24..31] (the kernel compares via
// get_unaligned_be64 on both sides, so byte-for-byte equality suffices). msg layout
// (options.c:699) = id, addr(4, AF_INET), port_hi, port_lo (port 0). Needs keys.
static inline int syz_mptcp_mut_add_addr_auth(uint8* pkt, int len, int ihl, struct tcphdr* th)
{
	if (!syz_mptcp_mut.keys_valid)
		return 0; // no captured keys -> can't forge a valid ahmac
	uint8 id = MPTCP_ADD_ADDR_GRAFT_ID;
	uint8 addr0 = 127, addr1 = 0, addr2 = 0, addr3 = 8; // 127.0.0.8
	uint8 msg[7];
	msg[0] = id;
	msg[1] = addr0;
	msg[2] = addr1;
	msg[3] = addr2;
	msg[4] = addr3;
	msg[5] = 0; // port high (port 0)
	msg[6] = 0; // port low
	uint8 digest[32];
	syz_mptcp_join_hmac(syz_mptcp_mut.local_key, syz_mptcp_mut.remote_key,
			    msg, sizeof(msg), digest);
	uint8 o[MPTCP_ADD_ADDR_AUTH_OLEN];
	o[0] = MPTCP_TCPOPT; // kind 30
	o[1] = MPTCP_ADD_ADDR_AUTH_OLEN; // opsize 16 (TCPOLEN_MPTCP_ADD_ADDR)
	o[2] = (MPTCP_SUB_ADD_ADDR << 4); // subtype 3, NO echo bit -> add_addr_received path
	o[3] = id;
	o[4] = addr0;
	o[5] = addr1;
	o[6] = addr2;
	o[7] = addr3;
	memcpy(o + 8, digest + 24, 8); // ahmac = last 8 bytes of the digest (be64 on wire)
	return syz_mptcp_mut_graft_opt(pkt, len, ihl, th, o, MPTCP_ADD_ADDR_AUTH_OLEN);
}

// Phase 4 (A3): graft an unauthenticated 12-byte MP_FAIL option -> mptcp_pm_mp_fail_received
// (msk->fallback_lock, allow_subflows=false, arms infinite-map; the 006 fallback
// machinery). Coexists only with DSS/RST (options.c:405) -- the DSS data/ack carriers
// satisfy that, and the shared helper's handshake-reject carrier rule is enough.
static inline int syz_mptcp_mut_mp_fail(uint8* pkt, int len, int ihl, struct tcphdr* th)
{
	uint8 o[MPTCP_MP_FAIL_OLEN];
	o[0] = MPTCP_TCPOPT; // kind 30
	o[1] = MPTCP_MP_FAIL_OLEN; // 12 (TCPOLEN_MPTCP_FAIL)
	o[2] = (MPTCP_SUB_MP_FAIL << 4); // subtype 6, rsv nibble 0
	o[3] = 0; // rsv byte (kernel skips subtype+this via ptr += 2, then reads fail_seq)
	uint64 seq = MPTCP_MP_FAIL_SEQ;
	o[4] = (uint8)(seq >> 56);
	o[5] = (uint8)(seq >> 48);
	o[6] = (uint8)(seq >> 40);
	o[7] = (uint8)(seq >> 32);
	o[8] = (uint8)(seq >> 24);
	o[9] = (uint8)(seq >> 16);
	o[10] = (uint8)(seq >> 8);
	o[11] = (uint8)(seq);
	return syz_mptcp_mut_graft_opt(pkt, len, ihl, th, o, MPTCP_MP_FAIL_OLEN);
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
	// SELFVERIFY and FORGE both need the server SYN-ACK (R_B), destined TO the
	// client address, so they match EITHER direction of this subflow's handshake.
	// The mutation ops act only on egress FROM the client, so they keep the saddr
	// filter.
	// SELFVERIFY/FORGE need the server SYN-ACK (R_B), and THMAC_FLIP rewrites that
	// SYN-ACK (destined TO the client) -- all three match EITHER direction of this
	// subflow's handshake. The JOIN HMAC/NONCE ops and all DSS data-segment ops act
	// only on egress FROM the client, so they keep the saddr-only filter.
	if (op == MPTCP_MUT_CRYPTO_SELFVERIFY || op == MPTCP_MUT_HMAC_FORGE ||
	    op == MPTCP_MUT_THMAC_FLIP) {
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
	// Phase 3a (A5): length-growing ADD_ADDR echo graft (whole-segment op, not a
	// per-option rewrite). from_client only (reaches the server RX). Returns len+8 on
	// a graft, 0 if the segment is not a graftable MPTCP subflow segment.
	if (op == MPTCP_MUT_ADD_ADDR_ECHO || op == MPTCP_MUT_ADD_ADDR_AUTH) {
		int r = (op == MPTCP_MUT_ADD_ADDR_ECHO)
			    ? syz_mptcp_mut_add_addr_echo(pkt, len, ihl, th)
			    : syz_mptcp_mut_add_addr_auth(pkt, len, ihl, th);
		if (r != 0)
			debug("syz_mptcp_mut_add_addr: grafted %s ADD_ADDR, newlen=%d\n",
			      op == MPTCP_MUT_ADD_ADDR_ECHO ? "echo" : "auth", r);
		return r;
	}
	// Phase 4 (A3): MP_FAIL graft -> mptcp_pm_mp_fail_received (fallback machinery).
	if (op == MPTCP_MUT_MP_FAIL) {
		int r = syz_mptcp_mut_mp_fail(pkt, len, ihl, th);
		if (r != 0)
			debug("syz_mptcp_mut_mp_fail: grafted MP_FAIL, newlen=%d\n", r);
		return r;
	}
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
			// FORGE: capture nonces on SYN/SYN-ACK, write a valid HMAC on the ACK.
			if (op == MPTCP_MUT_HMAC_FORGE) {
				return syz_mptcp_mut_forge(o, olen, from_client, len);
			}
			// THMAC flip (B2): corrupt the server SYN-ACK's 8-byte thmac (seen
			// here at LOCAL_OUT, destined to the client) -> client-side
			// subflow_thmac_valid reject in subflow_finish_connect.
			if (op == MPTCP_MUT_THMAC_FLIP && to_client &&
			    olen == MPTCP_JOIN_SYNACK_OLEN) {
				o[MPTCP_JOIN_SYNACK_THMAC_OFF] ^= 0x01;
				return len; // same-length in-place rewrite
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
		// Phase 2 (A1): DSS mapping corruption on egress data segments. Subtype 2;
		// gated to the DSS op range so a DSS option is never touched by a JOIN op.
		if (kind == MPTCP_TCPOPT && (o[2] >> 4) == MPTCP_SUB_DSS &&
		    op >= MPTCP_MUT_DSS_SEQ && op <= MPTCP_MUT_DSS_DATA_FIN) {
			int r = syz_mptcp_mut_dss(o, olen, op, len);
			if (r != 0) {
				debug("syz_mptcp_mut_dss: op=%d fired (same-length DSS mapping rewrite)\n", op);
				return r;
			}
		}
		o += olen;
	}
	return 0;
}

#endif // EXECUTOR_COMMON_LINUX_MPTCP_MUT_H
