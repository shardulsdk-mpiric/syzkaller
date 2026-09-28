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
#ifndef EXECUTOR_COMMON_LINUX_MPTCP_MUT_H
#define EXECUTOR_COMMON_LINUX_MPTCP_MUT_H

#include <string.h> // memset

// Mutation ops (the RULE stored in the program's join_subflow arg). Kept small;
// grown per the design 5 grammar. 0 = no mutation (engine hook is a pass-through).
// HMAC_* corrupt the client ACK's 20-byte HMAC (server-side gate: MPJoinAckHMac-
// Failure). NONCE_* corrupt the client SYN's 4-byte nonce (drives a different gate:
// the SYN-ACK thmac the client then validates against its real nonce).
#define MPTCP_MUT_NONE 0
#define MPTCP_MUT_HMAC_FLIP 1 // flip one bit of the ACK HMAC
#define MPTCP_MUT_HMAC_ZERO 2 // zero the whole ACK HMAC
#define MPTCP_MUT_NONCE_FLIP 3 // flip one bit of the SYN nonce

// MP_JOIN wire constants (RFC 8684; net/mptcp/options.c).
// SYN:     [kind][len=12][sub|bkup][join_id][token:be32][nonce:be32]
// SYN-ACK: [kind][len=16][sub|bkup][join_id][thmac:be64][nonce:be32]
// ACK:     [kind][len=24][rsv][rsv][hmac:20]
#define MPTCP_TCPOPT 30
#define MPTCP_SUB_JOIN 1
#define MPTCP_JOIN_SYN_OLEN 12
#define MPTCP_JOIN_SYN_NONCE_OFF 8 // nonce after kind,len,sub|bkup,join_id,token:4
#define MPTCP_JOIN_ACK_OLEN 24
#define MPTCP_JOIN_HMAC_OFF 4 // hmac after the 4-byte option header
#define MPTCP_JOIN_HMAC_LEN 20

// The published instruction. Single-writer (the joining syscall thread), single
// reader class (the NFQUEUE worker). active is the release/acquire gate.
struct syz_mptcp_mut_spec {
	volatile int active;
	uint32 src_addr_be; // match egress MP_JOIN from this per-slot local address
	int op;
};
static struct syz_mptcp_mut_spec syz_mptcp_mut;

// Publish before triggering the join; retire after. release/acquire via `active`.
static inline void syz_mptcp_mut_publish(uint32 src_addr_be, int op)
{
	syz_mptcp_mut.src_addr_be = src_addr_be;
	syz_mptcp_mut.op = op;
	__atomic_store_n(&syz_mptcp_mut.active, 1, __ATOMIC_RELEASE);
}

static inline void syz_mptcp_mut_retire(void)
{
	__atomic_store_n(&syz_mptcp_mut.active, 0, __ATOMIC_RELEASE);
}

// The NFQUEUE hook (matches syz_nfq_mutate_fn). Returns 1 if it mutated the
// packet in place (engine then recomputes the TCP checksum), 0 to pass through.
static inline int syz_mptcp_mut_hook(uint8* pkt, int len)
{
	if (!__atomic_load_n(&syz_mptcp_mut.active, __ATOMIC_ACQUIRE))
		return 0;
	if (len < (int)sizeof(struct iphdr))
		return 0;
	struct iphdr* ip = (struct iphdr*)pkt;
	if (ip->protocol != IPPROTO_TCP || ip->saddr != syz_mptcp_mut.src_addr_be)
		return 0;
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
			int op = syz_mptcp_mut.op;
			// HMAC ops target the ACK (20-byte HMAC).
			if (olen == MPTCP_JOIN_ACK_OLEN) {
				uint8* hmac = o + MPTCP_JOIN_HMAC_OFF;
				if (op == MPTCP_MUT_HMAC_FLIP) {
					hmac[0] ^= 0x01; // deterministic single-bit corruption
					return 1;
				}
				if (op == MPTCP_MUT_HMAC_ZERO) {
					memset(hmac, 0, MPTCP_JOIN_HMAC_LEN);
					return 1;
				}
			}
			// NONCE ops target the SYN (4-byte nonce).
			if (olen == MPTCP_JOIN_SYN_OLEN && op == MPTCP_MUT_NONCE_FLIP) {
				o[MPTCP_JOIN_SYN_NONCE_OFF] ^= 0x01;
				return 1;
			}
		}
		o += olen;
	}
	return 0;
}

#endif // EXECUTOR_COMMON_LINUX_MPTCP_MUT_H
