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
#ifndef SYZ_COMMON_LINUX_MPTCP_MUT_H
#define SYZ_COMMON_LINUX_MPTCP_MUT_H

// Mutation ops (the RULE stored in the program's join_subflow arg). Kept small;
// grown per the design 5 grammar. 0 = no mutation (engine hook is a pass-through).
#define SYZ_MPTCP_MUT_NONE 0
#define SYZ_MPTCP_MUT_HMAC_FLIP 1 // flip one bit of the ACK's 20-byte HMAC

// MP_JOIN wire constants (RFC 8684; net/mptcp/options.c).
#define SYZ_TCPOPT_MPTCP 30
#define SYZ_MPTCP_SUB_JOIN 1
#define SYZ_MPJ_ACK_OLEN 24 // [kind][len][rsv][rsv][hmac:20]
#define SYZ_MPJ_HMAC_OFF 4 // hmac starts after the 4-byte option header

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
		if (kind == SYZ_TCPOPT_MPTCP && olen == SYZ_MPJ_ACK_OLEN &&
		    (o[2] >> 4) == SYZ_MPTCP_SUB_JOIN) {
			uint8* hmac = o + SYZ_MPJ_HMAC_OFF;
			if (syz_mptcp_mut.op == SYZ_MPTCP_MUT_HMAC_FLIP) {
				hmac[0] ^= 0x01; // deterministic single-bit corruption
				return 1;
			}
		}
		o += olen;
	}
	return 0;
}

#endif // SYZ_COMMON_LINUX_MPTCP_MUT_H
