// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
//
// WIP (increment 1, NOT yet wired/verified): general-substrate STATELESS NFQUEUE
// mutation engine. Subsystem-agnostic. A subsystem layer registers a single
// mutate hook; the worker applies it to EVERY packet whose content the hook
// chooses to mutate -- a pure function of packet content + the layer's spec, with
// NO fire-once flag. That statelessness is what makes replay bit-identical (the
// property the BRF fork's stateful fire-once NFQUEUE design lacked -> its zero
// reproducers; see brf/.claude/designs/mptcp_mutation_and_key_capture.md §2/§4).
//
// NFQUEUE holds the skb until userspace verdicts, so the mutation is applied to
// the held packet synchronously before it proceeds. The one exception to
// statelessness is the per-flow stall (syz_nfq_stall_*, below), which delays,
// holds or drops one flow's packets for a bounded time and leaves every other
// packet, and the mutation hook, as they were. Raw-netlink (no
// libnetfilter_queue dependency), mirroring the executor's other self-contained
// netlink builders.
#ifndef EXECUTOR_COMMON_LINUX_MPTCP_NFQ_H
#define EXECUTOR_COMMON_LINUX_MPTCP_NFQ_H

#include <arpa/inet.h>
#include <errno.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netlink.h>
#include <linux/tcp.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define NFQ_QUEUE_NUM 0

// nftables objects that carry the diverting rule (see syz_nfq_install_rule).
#define NFQ_NFT_TABLE "syz_mptcp_mut"
#define NFQ_NFT_CHAIN "out"

// The subsystem hook: given a mutable copy of the IP packet (len bytes, sitting in
// a buffer with ample headroom -- see the worker's 128 KiB buffer), it may rewrite
// and/or GROW the packet in place and returns:
//   > 0 : the packet's new total IP length. The engine re-injects exactly that many
//         bytes and recomputes the checksums (TCP always; IP header only when the
//         length changed). Equal to `len` for a same-length rewrite; greater for a
//         length-grow graft (the hook is then responsible for having updated
//         tcph->doff / the IP+TCP option geometry, and for staying within the
//         TCP option-space bound, SYZ-free macro MPTCP_TCP_MAX_OPT_SPACE below).
//     0 : pass through unmodified (the engine verdict-accepts the original packet).
//   < 0 : drop the packet (NF_DROP).
// Must be a pure function of the packet content and the layer's (persistently-set)
// spec -- no per-call state, no fire-once. Set once by the subsystem layer before
// syz_nfq_setup(). (Contract widened from the original bool for the ingress-injection
// length-grow graft, design ingress_injection_design.md §4; a hook that only ever
// returns len/0 behaves exactly as the pre-widening engine did.)
typedef int (*syz_nfq_mutate_fn)(uint8* ip_pkt, int len);
static syz_nfq_mutate_fn syz_nfq_hook;

// TCP options cap at 40 bytes (data-offset <= 15 words => header <= 60 bytes, 20 of
// them the fixed header). A length-grow graft must keep the grown TCP header within
// this; the engine also sanity-bounds it (a returned length implying doff > 15 is
// dropped rather than injected malformed). [RUN]-4: grafting onto a carrier already
// near the cap can exceed it -- the graft op must target a low-option carrier.
#define MPTCP_TCP_MAX_OPT_SPACE 40
#define MPTCP_TCP_MAX_HDR 60 // 20 fixed + 40 options; doff field max is 15 words

static int syz_nfq_fd = -1;
static int syz_nfq_setup_done;
static int syz_nfq_rule_installed;
static pthread_t syz_nfq_worker_thread;
static int syz_nfq_worker_started;
static volatile int syz_nfq_worker_stop;

// ---- local netlink-attribute walkers (no libnl) ----
#define NFQ_NLA_OK(a, len) ((len) >= (int)sizeof(struct nlattr) && \
			    (a)->nla_len >= sizeof(struct nlattr) && (int)(a)->nla_len <= (len))
#define NFQ_NLA_DATA(a) ((void*)((char*)(a) + NLA_HDRLEN))
#define NFQ_NLA_NEXT(a, len) ((len) -= NLA_ALIGN((a)->nla_len), \
			      (struct nlattr*)((char*)(a) + NLA_ALIGN((a)->nla_len)))

// ---- IPv4 checksum recompute (after an in-place TCP-segment rewrite) ----
// The TCP pass (syz_nfq_tcp_csum_v4) recomputes only the TCP checksum, assuming the
// IP header was untouched. A length-grow graft DOES change the IP header (tot_len)
// and the TCP header (doff), so the engine additionally recomputes the IP-header
// checksum (syz_nfq_ip_csum_v4) whenever the length changed -- ip_rcv_core drops a
// bad IP csum. ([RUN]-5: loopback RX may carry CHECKSUM_UNNECESSARY, making the L4
// recompute cosmetic, but the IP-header csum is validated regardless; recompute
// both so the path is correct off-loopback too.)
static inline uint16 syz_nfq_csum_fold(uint32 sum)
{
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	return (uint16)(~sum);
}

static inline uint16 syz_nfq_csum_buf(uint32 sum, const uint16* buf, int size)
{
	while (size > 1) {
		sum += *buf++;
		size -= 2;
	}
	if (size) {
		// Pad the trailing odd byte into a 16-bit word at the low-address
		// position, matching the native 16-bit loads above on either
		// endianness (a plain `sum += *(uint8*)buf` is only correct on LE).
		uint16 last = 0;
		memcpy(&last, buf, 1);
		sum += last;
	}
	return syz_nfq_csum_fold(sum);
}

// l4_len is the TCP header+payload length as ACTUALLY COPIED (plen - ihl),
// never derived from the packet's own tot_len -- so a mutated or short-copied
// tot_len cannot make this pass read past the captured buffer.
static inline void syz_nfq_tcp_csum_v4(struct tcphdr* tcph, const struct iphdr* iph, int l4_len)
{
	uint32 sum = 0;

	sum += (iph->saddr >> 16) & 0xFFFF;
	sum += iph->saddr & 0xFFFF;
	sum += (iph->daddr >> 16) & 0xFFFF;
	sum += iph->daddr & 0xFFFF;
	sum += htons(iph->protocol);
	sum += htons((uint16)l4_len);
	tcph->check = 0;
	tcph->check = syz_nfq_csum_buf(sum, (const uint16*)tcph, l4_len);
}

// IP-header checksum over ihl*4 bytes (standard ones-complement of the header with
// the check field zeroed). Only needed after a length/IP-header change.
static inline void syz_nfq_ip_csum_v4(struct iphdr* iph)
{
	int ihl = iph->ihl * 4;
	iph->check = 0;
	iph->check = syz_nfq_csum_buf(0, (const uint16*)iph, ihl);
}

// ---- raw-netlink NFQUEUE plumbing ----
static inline int syz_nfq_send_msg(int fd, uint16 msg_type, uint16 res_id,
				   const void* attr_payload, uint16 attr_len)
{
	char buf[256], ack[256];
	struct nlmsghdr* nlh = (struct nlmsghdr*)buf;
	struct nfgenmsg* nfg = (struct nfgenmsg*)NLMSG_DATA(nlh);

	if (NLMSG_LENGTH(sizeof(*nfg)) + attr_len > sizeof(buf))
		return -1;
	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_len = NLMSG_LENGTH(sizeof(*nfg));
	nlh->nlmsg_type = msg_type;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq = (uint32)time(NULL);
	nfg->nfgen_family = AF_UNSPEC;
	nfg->version = NFNETLINK_V0;
	nfg->res_id = htons(res_id);
	if (attr_payload && attr_len > 0) {
		memcpy((char*)nlh + NLMSG_ALIGN(nlh->nlmsg_len), attr_payload, attr_len);
		nlh->nlmsg_len += attr_len;
	}
	if (send(fd, buf, nlh->nlmsg_len, 0) < 0)
		return -1;
	ssize_t n = recv(fd, ack, sizeof(ack), 0);
	if (n < 0)
		return -1;
	struct nlmsghdr* anlh = (struct nlmsghdr*)ack;
	if ((size_t)n < sizeof(struct nlmsghdr) || !NLMSG_OK(anlh, (size_t)n))
		return -1;
	if (anlh->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr* e = (struct nlmsgerr*)NLMSG_DATA(anlh);
		if (e->error) {
			errno = -e->error;
			return -1;
		}
	}
	return 0;
}

static inline int syz_nfq_config_cmd(int fd, uint16 q, uint8 cmd, uint16 pf)
{
	struct {
		struct nlattr nla;
		struct nfqnl_msg_config_cmd cfg;
	} __attribute__((packed)) p;
	p.nla.nla_len = sizeof(p);
	p.nla.nla_type = NFQA_CFG_CMD;
	p.cfg.command = cmd;
	p.cfg._pad = 0;
	p.cfg.pf = htons(pf);
	return syz_nfq_send_msg(fd, (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_CONFIG, q, &p, sizeof(p));
}

static inline int syz_nfq_config_params(int fd, uint16 q, uint8 mode, uint32 range)
{
	struct {
		struct nlattr nla;
		struct nfqnl_msg_config_params params;
	} __attribute__((packed)) p;
	p.nla.nla_len = sizeof(p);
	p.nla.nla_type = NFQA_CFG_PARAMS;
	p.params.copy_mode = mode;
	p.params.copy_range = htonl(range);
	return syz_nfq_send_msg(fd, (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_CONFIG, q, &p, sizeof(p));
}

// Set queue flags (via NFQA_CFG_FLAGS + NFQA_CFG_MASK). We use it for
// NFQA_CFG_F_FAIL_OPEN: if the queue fills or the reader can't keep up, the
// kernel accepts the packet instead of dropping it, so a stalled/dead engine
// never blackholes loopback TCP (paired with NFT_QUEUE_FLAG_BYPASS on the rule).
static inline int syz_nfq_config_flags(int fd, uint16 q, uint32 flags)
{
	struct {
		struct nlattr fla;
		uint32 flags;
		struct nlattr mla;
		uint32 mask;
	} __attribute__((packed)) p;
	p.fla.nla_len = NLA_HDRLEN + sizeof(uint32);
	p.fla.nla_type = NFQA_CFG_FLAGS;
	p.flags = htonl(flags);
	p.mla.nla_len = NLA_HDRLEN + sizeof(uint32);
	p.mla.nla_type = NFQA_CFG_MASK;
	p.mask = htonl(flags);
	return syz_nfq_send_msg(fd, (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_CONFIG, q, &p, sizeof(p));
}

// ---- raw-netlink nftables rule install/delete (no iptables/nft binary) ----
//
// A csource reproducer runs in a bare tmpfs sandbox with no iptables binary, so
// the diverting rule is installed over NETLINK_NETFILTER / NFNL_SUBSYS_NFTABLES
// on the engine's own socket, as an nft transaction batch. nft equivalent:
//
//   table ip syz_mptcp_mut {
//     chain out {
//       type filter hook output priority 0; policy accept;
//       oif "lo" ip protocol tcp queue num 0 bypass
//     }
//   }
//
// Byte-order/width contract (include/uapi/linux/netfilter/nf_tables.h and
// net/netfilter/nf_tables_api.c, nft_{meta,payload,cmp,queue}.c):
//   - every NLA_U32 nft attribute (registers, keys, ops, hooknum, priority,
//     policy, payload base/offset/len) is read with ntohl(nla_get_be32()) ->
//     send htonl();
//   - NFTA_QUEUE_NUM / NFTA_QUEUE_FLAGS are NLA_U16 read with ntohs() -> htons();
//   - NFTA_DATA_VALUE is raw bytes (NLA_BINARY) compared byte-for-byte against
//     the register (nft_cmp_eval memcmp / nft_cmp_fast mask), so the ifindex is
//     sent as a host-endian u32 (meta oif stores dev->ifindex as a host u32)
//     and ip protocol as one byte.
//   - NFT_REG_1 is the legacy 16-byte register (register-store/-load are
//     validated against the value length, 4 and 1 here, both fit).
//   - NFNL_MSG_BATCH_BEGIN/END carry nfgenmsg.res_id = htons(NFNL_SUBSYS_NFTABLES).
//   - NFT_MSG_NEWRULE requires NLM_F_CREATE (nf_tables_newrule: -EINVAL
//     otherwise); NEWTABLE/NEWCHAIN accept it too.
//
// Ack protocol (net/netfilter/nfnetlink.c, nfnetlink_rcv_batch): the whole
// batch must arrive in ONE datagram. Acks/errors are queued per message and
// delivered (one datagram each, in message order) only after the batch has
// been committed or aborted. We set NLM_F_ACK on the inner messages, NOT on
// BATCH_BEGIN/END: whether BATCH_END itself gets acked on commit differs
// between kernel versions (6.8 does not, newer trees do), while inner-message
// acks are delivered on every version. A committed batch yields
// NLMSG_ERROR{error=0} for each inner message; any per-message failure yields
// NLMSG_ERROR{error<0} for it and aborts the batch (nothing half-installed);
// a commit failure is acked against the BATCH_BEGIN header. Every message
// carries a distinct, monotonically increasing nlmsg_seq and the reader only
// honours acks whose echoed seq falls in this batch's range, so an ack left
// behind by an earlier batch on the same socket can never be mistaken for one
// of ours; success is the error-free ack of the last inner message.

// Append-only netlink message builder over a fixed buffer. Every put() is
// NLA_ALIGN-padded (buffer is pre-zeroed), so nlmsg_len is always 4-aligned
// and messages can be laid back-to-back for a batch. Overflow latches err;
// the commit refuses to send a buffer with err set.
struct syz_nft_buf {
	char* p;
	int len;
	int cap;
	int err;
	uint32 seq_lo; // seq of BATCH_BEGIN
	uint32 seq_hi; // seq of BATCH_END
	uint32 ack_seq; // seq of the last inner (NLM_F_ACK'd) message
};

static uint32 syz_nft_next_seq;

static inline void syz_nft_buf_init(struct syz_nft_buf* b, char* p, int cap)
{
	memset(p, 0, cap);
	b->p = p;
	b->len = 0;
	b->cap = cap;
	b->err = 0;
	b->seq_lo = b->seq_hi = b->ack_seq = 0;
}

static inline void* syz_nft_reserve(struct syz_nft_buf* b, int n)
{
	void* at = b->p + b->len;
	if (b->err || b->len + NLA_ALIGN(n) > b->cap) {
		b->err = 1;
		return NULL;
	}
	b->len += NLA_ALIGN(n);
	return at;
}

static inline void syz_nft_put(struct syz_nft_buf* b, uint16 type, const void* data, uint16 dlen)
{
	struct nlattr* a = (struct nlattr*)syz_nft_reserve(b, NLA_HDRLEN + dlen);
	if (!a)
		return;
	a->nla_len = NLA_HDRLEN + dlen;
	a->nla_type = type;
	if (dlen)
		memcpy((char*)a + NLA_HDRLEN, data, dlen);
}

static inline void syz_nft_put_be32(struct syz_nft_buf* b, uint16 type, uint32 v)
{
	uint32 be = htonl(v);
	syz_nft_put(b, type, &be, sizeof(be));
}

static inline void syz_nft_put_be16(struct syz_nft_buf* b, uint16 type, uint16 v)
{
	uint16 be = htons(v);
	syz_nft_put(b, type, &be, sizeof(be));
}

// NUL-terminated on the wire: accepted by NLA_STRING (nla_strcmp/nla_strdup
// tolerate a trailing NUL) and required by NLA_NUL_STRING (NFTA_CHAIN_TYPE in
// older trees).
static inline void syz_nft_put_str(struct syz_nft_buf* b, uint16 type, const char* s)
{
	syz_nft_put(b, type, s, (uint16)(strlen(s) + 1));
}

// Returns the byte offset of the nest header (offsets, not pointers: the
// buffer is fixed, but this keeps the helpers pointer-free and trivially
// re-entrant across nest levels).
static inline int syz_nft_nest_start(struct syz_nft_buf* b, uint16 type)
{
	int off = b->len;
	struct nlattr* a = (struct nlattr*)syz_nft_reserve(b, NLA_HDRLEN);
	if (!a)
		return -1;
	a->nla_type = NLA_F_NESTED | type;
	return off;
}

static inline void syz_nft_nest_end(struct syz_nft_buf* b, int off)
{
	if (b->err || off < 0)
		return;
	((struct nlattr*)(b->p + off))->nla_len = (uint16)(b->len - off);
}

// Every message gets the next seq from a process-wide counter (never reused,
// see the ack-protocol note above). NLM_F_ACK'd messages update ack_seq.
static inline int syz_nft_msg_start(struct syz_nft_buf* b, uint16 type, uint16 flags,
				    uint8 family, uint16 res_id)
{
	int off = b->len;
	struct nlmsghdr* nlh = (struct nlmsghdr*)syz_nft_reserve(b, NLMSG_LENGTH(sizeof(struct nfgenmsg)));
	if (!nlh)
		return -1;
	nlh->nlmsg_type = type;
	nlh->nlmsg_flags = flags;
	nlh->nlmsg_seq = ++syz_nft_next_seq;
	nlh->nlmsg_pid = 0;
	if (flags & NLM_F_ACK)
		b->ack_seq = nlh->nlmsg_seq;
	struct nfgenmsg* nfg = (struct nfgenmsg*)NLMSG_DATA(nlh);
	nfg->nfgen_family = family;
	nfg->version = NFNETLINK_V0;
	nfg->res_id = htons(res_id);
	return off;
}

static inline void syz_nft_msg_end(struct syz_nft_buf* b, int off)
{
	if (b->err || off < 0)
		return;
	((struct nlmsghdr*)(b->p + off))->nlmsg_len = (uint32)(b->len - off);
}

// One rule expression: NFTA_LIST_ELEM { NFTA_EXPR_NAME, NFTA_EXPR_DATA { ... } }.
// Returns the NFTA_EXPR_DATA nest offset; the caller adds the expression's
// attributes then calls syz_nft_expr_end() with both offsets.
static inline void syz_nft_expr_start(struct syz_nft_buf* b, const char* name, int* elem, int* data)
{
	*elem = syz_nft_nest_start(b, NFTA_LIST_ELEM);
	syz_nft_put_str(b, NFTA_EXPR_NAME, name);
	*data = syz_nft_nest_start(b, NFTA_EXPR_DATA);
}

static inline void syz_nft_expr_end(struct syz_nft_buf* b, int elem, int data)
{
	syz_nft_nest_end(b, data);
	syz_nft_nest_end(b, elem);
}

// "cmp": reg1 == <value> (raw bytes, vlen of them).
static inline void syz_nft_expr_cmp_eq(struct syz_nft_buf* b, const void* value, uint16 vlen)
{
	int elem = 0, data = 0;
	syz_nft_expr_start(b, "cmp", &elem, &data);
	syz_nft_put_be32(b, NFTA_CMP_SREG, NFT_REG_1);
	syz_nft_put_be32(b, NFTA_CMP_OP, NFT_CMP_EQ);
	int d = syz_nft_nest_start(b, NFTA_CMP_DATA);
	syz_nft_put(b, NFTA_DATA_VALUE, value, vlen);
	syz_nft_nest_end(b, d);
	syz_nft_expr_end(b, elem, data);
}

// Send one nft batch (already laid out in b) and wait for its outcome. Skips
// any non-ack traffic that may be queued on the shared socket (NFQUEUE packet
// messages during cleanup) and any ack whose echoed seq is not this batch's.
// First in-range error decides failure; the error-free ack of the last inner
// message decides success. Bounded by the socket's SO_RCVTIMEO (EAGAIN) and
// by a datagram count.
static inline int syz_nft_batch_commit(int fd, struct syz_nft_buf* b)
{
	char ack[2048];

	if (b->err) {
		errno = EMSGSIZE;
		return -1;
	}
	if (send(fd, b->p, b->len, 0) < 0)
		return -1;
	for (int i = 0; i < 256; i++) {
		ssize_t n = recv(fd, ack, sizeof(ack), 0);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		struct nlmsghdr* nlh = (struct nlmsghdr*)ack;
		size_t left = (size_t)n;
		for (; NLMSG_OK(nlh, left); nlh = NLMSG_NEXT(nlh, left)) {
			if (nlh->nlmsg_type != NLMSG_ERROR)
				continue;
			if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
				errno = EBADMSG;
				return -1;
			}
			struct nlmsgerr* e = (struct nlmsgerr*)NLMSG_DATA(nlh);
			// netlink_ack() always echoes the original nlmsghdr in e->msg.
			uint32 s = e->msg.nlmsg_seq;
			if (s < b->seq_lo || s > b->seq_hi)
				continue;
			if (e->error) {
				errno = -e->error;
				return -1;
			}
			if (s == b->ack_seq)
				return 0;
		}
	}
	errno = ETIMEDOUT;
	return -1;
}

static inline void syz_nft_batch_begin(struct syz_nft_buf* b)
{
	int m = syz_nft_msg_start(b, NFNL_MSG_BATCH_BEGIN, NLM_F_REQUEST, AF_UNSPEC,
				  NFNL_SUBSYS_NFTABLES);
	b->seq_lo = syz_nft_next_seq;
	syz_nft_msg_end(b, m);
}

static inline void syz_nft_batch_end(struct syz_nft_buf* b)
{
	int m = syz_nft_msg_start(b, NFNL_MSG_BATCH_END, NLM_F_REQUEST, AF_UNSPEC,
				  NFNL_SUBSYS_NFTABLES);
	b->seq_hi = syz_nft_next_seq;
	syz_nft_msg_end(b, m);
}

// Batch { BEGIN, DELTABLE ip syz_mptcp_mut, END }. Deleting the table drops
// its chain and rule with it. ENOENT if the table does not exist.
static inline int syz_nfq_delete_rule(int fd)
{
	char raw[256];
	struct syz_nft_buf b;

	syz_nft_buf_init(&b, raw, sizeof(raw));
	syz_nft_batch_begin(&b);
	int m = syz_nft_msg_start(&b, (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_DELTABLE,
				  NLM_F_REQUEST | NLM_F_ACK, NFPROTO_IPV4, 0);
	syz_nft_put_str(&b, NFTA_TABLE_NAME, NFQ_NFT_TABLE);
	syz_nft_msg_end(&b, m);
	syz_nft_batch_end(&b);
	return syz_nft_batch_commit(fd, &b);
}

// nft_compat "target" expression attributes (<linux/netfilter/nf_tables_compat.h>,
// which older headers lack) and the xt_NFQUEUE v3 target info: queue 0 of 1,
// with the bypass flag.
#define SYZ_NFTA_TARGET_NAME 1
#define SYZ_NFTA_TARGET_REV 2
#define SYZ_NFTA_TARGET_INFO 3
#define SYZ_XT_NFQ_FLAG_BYPASS 0x01

// Batch { BEGIN, NEWTABLE, NEWCHAIN (filter/output/prio 0/accept),
// NEWRULE [meta oif -> reg1; cmp reg1 == ifindex(lo); payload nh[9]:1 -> reg1;
// cmp reg1 == IPPROTO_TCP; queue num 0 bypass], END }.
//
// The queue verdict needs CONFIG_NFT_QUEUE. A kernel without it (the "queue"
// expression is then unknown, ENOENT) often still has the xtables NFQUEUE target
// and nft_compat, so with compat set the rule ends in the equivalent compat
// expression instead: target NFQUEUE rev 3 {queuenum 0, queues_total 1, bypass}.
static inline int syz_nfq_install_rule_as(int fd, bool compat)
{
	char raw[1024];
	struct syz_nft_buf b;
	uint32 lo_ifindex = if_nametoindex("lo");
	uint8 tcp = IPPROTO_TCP;

	if (lo_ifindex == 0) {
		errno = ENODEV;
		return -1;
	}
	// A previous run that died without cleanup leaves the table behind;
	// re-adding the rule to it would stack a duplicate. Best effort, like the
	// PF_UNBIND-before-PF_BIND above.
	(void)syz_nfq_delete_rule(fd);

	syz_nft_buf_init(&b, raw, sizeof(raw));
	syz_nft_batch_begin(&b);

	int m = syz_nft_msg_start(&b, (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWTABLE,
				  NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK, NFPROTO_IPV4, 0);
	syz_nft_put_str(&b, NFTA_TABLE_NAME, NFQ_NFT_TABLE);
	syz_nft_msg_end(&b, m);

	m = syz_nft_msg_start(&b, (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWCHAIN,
			      NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK, NFPROTO_IPV4, 0);
	syz_nft_put_str(&b, NFTA_CHAIN_TABLE, NFQ_NFT_TABLE);
	syz_nft_put_str(&b, NFTA_CHAIN_NAME, NFQ_NFT_CHAIN);
	syz_nft_put_str(&b, NFTA_CHAIN_TYPE, "filter");
	syz_nft_put_be32(&b, NFTA_CHAIN_POLICY, NF_ACCEPT);
	int n = syz_nft_nest_start(&b, NFTA_CHAIN_HOOK);
	syz_nft_put_be32(&b, NFTA_HOOK_HOOKNUM, NF_INET_LOCAL_OUT);
	syz_nft_put_be32(&b, NFTA_HOOK_PRIORITY, 0);
	syz_nft_nest_end(&b, n);
	syz_nft_msg_end(&b, m);

	m = syz_nft_msg_start(&b, (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE,
			      NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK, NFPROTO_IPV4, 0);
	syz_nft_put_str(&b, NFTA_RULE_TABLE, NFQ_NFT_TABLE);
	syz_nft_put_str(&b, NFTA_RULE_CHAIN, NFQ_NFT_CHAIN);
	int exprs = syz_nft_nest_start(&b, NFTA_RULE_EXPRESSIONS);
	// meta oif -> reg1
	int elem = 0, data = 0;
	syz_nft_expr_start(&b, "meta", &elem, &data);
	syz_nft_put_be32(&b, NFTA_META_KEY, NFT_META_OIF);
	syz_nft_put_be32(&b, NFTA_META_DREG, NFT_REG_1);
	syz_nft_expr_end(&b, elem, data);
	// reg1 == ifindex(lo)   (host-endian u32, as nft_meta_store_ifindex writes it)
	syz_nft_expr_cmp_eq(&b, &lo_ifindex, sizeof(lo_ifindex));
	// ip protocol (network header byte 9, 1 byte) -> reg1
	syz_nft_expr_start(&b, "payload", &elem, &data);
	syz_nft_put_be32(&b, NFTA_PAYLOAD_DREG, NFT_REG_1);
	syz_nft_put_be32(&b, NFTA_PAYLOAD_BASE, NFT_PAYLOAD_NETWORK_HEADER);
	syz_nft_put_be32(&b, NFTA_PAYLOAD_OFFSET, 9);
	syz_nft_put_be32(&b, NFTA_PAYLOAD_LEN, 1);
	syz_nft_expr_end(&b, elem, data);
	// reg1 == IPPROTO_TCP
	syz_nft_expr_cmp_eq(&b, &tcp, sizeof(tcp));
	// queue num 0 bypass
	if (compat) {
		uint16 info[4] = {NFQ_QUEUE_NUM, 1, SYZ_XT_NFQ_FLAG_BYPASS, 0};
		syz_nft_expr_start(&b, "target", &elem, &data);
		syz_nft_put_str(&b, SYZ_NFTA_TARGET_NAME, "NFQUEUE");
		syz_nft_put_be32(&b, SYZ_NFTA_TARGET_REV, 3);
		syz_nft_put(&b, SYZ_NFTA_TARGET_INFO, info, sizeof(info));
		syz_nft_expr_end(&b, elem, data);
	} else {
		syz_nft_expr_start(&b, "queue", &elem, &data);
		syz_nft_put_be16(&b, NFTA_QUEUE_NUM, NFQ_QUEUE_NUM);
		syz_nft_put_be16(&b, NFTA_QUEUE_FLAGS, NFT_QUEUE_FLAG_BYPASS);
		syz_nft_expr_end(&b, elem, data);
	}
	syz_nft_nest_end(&b, exprs);
	syz_nft_msg_end(&b, m);

	syz_nft_batch_end(&b);
	return syz_nft_batch_commit(fd, &b);
}

static inline int syz_nfq_install_rule(int fd)
{
	if (syz_nfq_install_rule_as(fd, false) == 0)
		return 0;
	if (errno != ENOENT)
		return -1;
	debug("syz_nfq_install_rule: no nft queue expression, using the xtables NFQUEUE target\n");
	return syz_nfq_install_rule_as(fd, true);
}

// ---- Per-flow stall (the one stateful extension of the engine) ----
//
// A stall is a filter on one TCP flow (an IPv4 address/port pair, either or both
// directions) plus what to do with its packets for a bounded time: DELAY each one
// by delay_ms, BLOCK (hold) all of them until the stall ends, or DROP them. A
// syscall thread publishes a stall in a free slot, keeps it for a bounded time,
// then retires it and waits until the worker has released every packet it held
// (syz_nfq_stall_begin/end), so nothing outlives the call.
//
// Only the stalled flow is affected. The worker keeps verdicting every other
// packet as it arrives, in arrival order, and runs the mutation hook on every
// packet first, exactly as before: a packet the hook drops or rewrites gets that
// verdict at once and is never held, and the hook sees each packet at arrival, so
// what it captures (MP_JOIN nonces, ...) is captured when it always was. A held
// packet costs a queue id and a deadline, not a copy: the kernel keeps the skb
// until the worker accepts it, unmodified. Held packets of one stall are released
// in arrival order. The hold list is bounded; a packet that does not fit is
// dropped, like a full bottleneck queue (TCP retransmits it). Flows are told
// apart by port, because every pair of an executor process shares its netns.
#define SYZ_NFQ_STALL_MAX 8
#define SYZ_NFQ_HELD_MAX 256
#define SYZ_NFQ_STALL_DELAY 0
#define SYZ_NFQ_STALL_BLOCK 1
#define SYZ_NFQ_STALL_DROP 2
// Directions, relative to the (a, b) endpoints of the stall.
#define SYZ_NFQ_STALL_A_TO_B 1
#define SYZ_NFQ_STALL_B_TO_A 2

struct syz_nfq_stall {
	int claimed; // owned by a syscall thread (claimed with a compare-exchange)
	int active; // the spec below is valid; release-stored after it is written
	uint32 gen; // bumped per use, so held packets of a retired stall are told apart
	uint32 addr_a, addr_b; // network order
	uint16 port_a, port_b; // network order, 0 matches any port
	int dirs;
	int mode;
	int delay_ms;
	int held; // packets currently held for this slot (worker-written)
};

struct syz_nfq_held {
	uint32 id;
	uint64 due_ms; // UINT64_MAX: until the stall is retired (BLOCK)
	int slot;
	uint32 gen;
};

static struct syz_nfq_stall syz_nfq_stalls[SYZ_NFQ_STALL_MAX];
static struct syz_nfq_held syz_nfq_held_list[SYZ_NFQ_HELD_MAX]; // worker-only
static int syz_nfq_held_n; // worker-only

static inline uint64 syz_nfq_now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

// Publishes a stall and returns its slot, or -1 if all slots are taken.
static inline int syz_nfq_stall_begin(uint32 addr_a, uint16 port_a, uint32 addr_b, uint16 port_b,
				      int dirs, int mode, int delay_ms)
{
	for (int i = 0; i < SYZ_NFQ_STALL_MAX; i++) {
		int expected = 0;
		struct syz_nfq_stall* st = &syz_nfq_stalls[i];
		if (!__atomic_compare_exchange_n(&st->claimed, &expected, 1, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
			continue;
		st->addr_a = addr_a;
		st->addr_b = addr_b;
		st->port_a = port_a;
		st->port_b = port_b;
		st->dirs = dirs;
		st->mode = mode;
		st->delay_ms = delay_ms;
		__atomic_store_n(&st->gen, __atomic_load_n(&st->gen, __ATOMIC_RELAXED) + 1, __ATOMIC_RELEASE);
		__atomic_store_n(&st->active, 1, __ATOMIC_RELEASE);
		return i;
	}
	return -1;
}

// Retires the stall and waits (bounded) until the worker has released what it
// held. Returns the number of packets still held at the deadline (0 normally);
// those are released by the worker later, since their generation is stale.
static inline int syz_nfq_stall_end(int slot)
{
	struct syz_nfq_stall* st = &syz_nfq_stalls[slot];
	int held = 0;
	__atomic_store_n(&st->active, 0, __ATOMIC_RELEASE);
	for (int i = 0; i < 200; i++) {
		held = __atomic_load_n(&st->held, __ATOMIC_ACQUIRE);
		if (held == 0)
			break;
		usleep(5000);
	}
	__atomic_store_n(&st->claimed, 0, __ATOMIC_RELEASE);
	return held;
}

// Worker: the stall a packet belongs to, or -1. Only IPv4/TCP is matched.
static inline int syz_nfq_stall_match(const uint8* pkt, int len, uint32* gen_out)
{
	if (len < (int)sizeof(struct iphdr))
		return -1;
	const struct iphdr* ip = (const struct iphdr*)pkt;
	int ihl = ip->ihl * 4;
	if (ip->protocol != IPPROTO_TCP || ihl < (int)sizeof(struct iphdr) || len < ihl + (int)sizeof(struct tcphdr))
		return -1;
	const struct tcphdr* th = (const struct tcphdr*)(pkt + ihl);
	for (int i = 0; i < SYZ_NFQ_STALL_MAX; i++) {
		struct syz_nfq_stall* st = &syz_nfq_stalls[i];
		if (!__atomic_load_n(&st->active, __ATOMIC_ACQUIRE))
			continue;
		bool ab = ip->saddr == st->addr_a && ip->daddr == st->addr_b &&
			  (!st->port_a || th->source == st->port_a) && (!st->port_b || th->dest == st->port_b);
		bool ba = ip->saddr == st->addr_b && ip->daddr == st->addr_a &&
			  (!st->port_b || th->source == st->port_b) && (!st->port_a || th->dest == st->port_a);
		if ((ab && (st->dirs & SYZ_NFQ_STALL_A_TO_B)) || (ba && (st->dirs & SYZ_NFQ_STALL_B_TO_A))) {
			*gen_out = __atomic_load_n(&st->gen, __ATOMIC_ACQUIRE);
			return i;
		}
	}
	return -1;
}

static inline int syz_nfq_send_verdict(int fd, uint16 q, uint32 id, uint32 verdict,
				       const uint8* payload, uint16 plen);

// Worker: accept every held packet that is due or whose stall has been retired,
// in arrival order. Returns how long the worker may wait for the next packet:
// -1 when nothing is held (block as before), else ms until the next deadline,
// capped so a retired BLOCK stall is noticed within a few ms.
static inline int syz_nfq_stall_service(void)
{
	if (syz_nfq_held_n == 0)
		return -1;
	uint64 now = syz_nfq_now_ms();
	uint64 next = now + 5;
	int kept = 0;
	for (int i = 0; i < syz_nfq_held_n; i++) {
		struct syz_nfq_held* h = &syz_nfq_held_list[i];
		struct syz_nfq_stall* st = &syz_nfq_stalls[h->slot];
		bool live = __atomic_load_n(&st->active, __ATOMIC_ACQUIRE) &&
			    __atomic_load_n(&st->gen, __ATOMIC_ACQUIRE) == h->gen;
		if (!live || h->due_ms <= now) {
			syz_nfq_send_verdict(syz_nfq_fd, NFQ_QUEUE_NUM, h->id, NF_ACCEPT, NULL, 0);
			__atomic_sub_fetch(&st->held, 1, __ATOMIC_RELEASE);
			continue;
		}
		if (h->due_ms < next)
			next = h->due_ms;
		syz_nfq_held_list[kept++] = *h;
	}
	syz_nfq_held_n = kept;
	if (kept == 0)
		return -1;
	return (int)(next - now);
}

// Worker: decide a pass-through packet's verdict under the stalls. Returns true if
// the stall took it (held or dropped); false to accept it now.
static inline bool syz_nfq_stall_take(uint16 q, uint32 id, const uint8* pkt, int len)
{
	uint32 gen = 0;
	int slot = syz_nfq_stall_match(pkt, len, &gen);
	if (slot < 0)
		return false;
	struct syz_nfq_stall* st = &syz_nfq_stalls[slot];
	if (st->mode == SYZ_NFQ_STALL_DROP || syz_nfq_held_n >= SYZ_NFQ_HELD_MAX) {
		syz_nfq_send_verdict(syz_nfq_fd, q, id, NF_DROP, NULL, 0);
		return true;
	}
	struct syz_nfq_held* h = &syz_nfq_held_list[syz_nfq_held_n++];
	h->id = id;
	h->due_ms = st->mode == SYZ_NFQ_STALL_DELAY ? syz_nfq_now_ms() + st->delay_ms : (uint64)-1;
	h->slot = slot;
	h->gen = gen;
	__atomic_add_fetch(&st->held, 1, __ATOMIC_RELEASE);
	return true;
}

static inline int syz_nfq_send_verdict(int fd, uint16 q, uint32 id, uint32 verdict,
				       const uint8* payload, uint16 plen)
{
	static char buf[65536 + 256];
	struct nlmsghdr* nlh = (struct nlmsghdr*)buf;
	struct nfgenmsg* nfg = (struct nfgenmsg*)NLMSG_DATA(nlh);
	struct {
		struct nlattr nla;
		struct nfqnl_msg_verdict_hdr vh;
	} __attribute__((packed)) vhdr;
	char* cur;

	if (NLMSG_LENGTH(sizeof(*nfg)) + sizeof(vhdr) + NLA_HDRLEN + plen > sizeof(buf))
		return -1;
	memset(buf, 0, NLMSG_LENGTH(sizeof(*nfg)));
	nlh->nlmsg_len = NLMSG_LENGTH(sizeof(*nfg));
	nlh->nlmsg_type = (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_VERDICT;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nfg->nfgen_family = AF_UNSPEC;
	nfg->version = NFNETLINK_V0;
	nfg->res_id = htons(q);
	vhdr.nla.nla_len = sizeof(vhdr);
	vhdr.nla.nla_type = NFQA_VERDICT_HDR;
	vhdr.vh.verdict = htonl(verdict);
	vhdr.vh.id = htonl(id);
	cur = (char*)nlh + NLMSG_ALIGN(nlh->nlmsg_len);
	memcpy(cur, &vhdr, sizeof(vhdr));
	nlh->nlmsg_len += sizeof(vhdr);
	if (payload && plen > 0) {
		struct nlattr pa;
		pa.nla_len = NLA_HDRLEN + plen;
		pa.nla_type = NFQA_PAYLOAD;
		cur = (char*)nlh + NLMSG_ALIGN(nlh->nlmsg_len);
		memcpy(cur, &pa, sizeof(pa));
		memcpy(cur + NLA_HDRLEN, payload, plen);
		nlh->nlmsg_len += NLA_HDRLEN + plen;
	}
	return (int)send(fd, buf, nlh->nlmsg_len, 0);
}

// Worker: recv each queued packet, run the (stateless) hook, verdict-accept it
// (rewritten if the hook mutated, original otherwise). The hook is a pure
// function of content, so every matching packet is mutated identically on replay.
static inline void* syz_nfq_worker_loop(void* arg)
{
	(void)arg;
	// Must hold a full-size loopback segment's NFQUEUE message: lo MTU is 64 KiB,
	// so the copied payload can approach 64 KiB and the message (payload + netlink
	// + nfqueue attrs) exceeds 64 KiB. A buffer <= 64 KiB would truncate it, fail
	// NLMSG_OK, and the packet would get no verdict (skb held forever).
	static char buf[128 * 1024];
	while (!__atomic_load_n(&syz_nfq_worker_stop, __ATOMIC_SEQ_CST)) {
		// With packets held by a stall, wait no longer than the next release
		// deadline; otherwise block in recv as always (SO_RCVTIMEO bounds it).
		int wait_ms = syz_nfq_stall_service();
		ssize_t n;
		if (wait_ms >= 0) {
			struct pollfd pfd;
			pfd.fd = syz_nfq_fd;
			pfd.events = POLLIN;
			pfd.revents = 0;
			if (poll(&pfd, 1, wait_ms) <= 0)
				continue;
			n = recv(syz_nfq_fd, buf, sizeof(buf), MSG_DONTWAIT);
		} else {
			n = recv(syz_nfq_fd, buf, sizeof(buf), 0);
		}
		if (n < 0) {
			// EAGAIN/EWOULDBLOCK: SO_RCVTIMEO fired -- loop back to re-check
			// the stop flag (this is the only wake source for a clean join).
			// ENOBUFS: rcvbuf overran; the datagram is lost but the socket
			// stays usable, so keep serving rather than killing the engine
			// (a dead worker leaves the rule bound and blackholes lo TCP).
			if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS)
				continue;
			break;
		}
		struct nlmsghdr* nlh = (struct nlmsghdr*)buf;
		if (!NLMSG_OK(nlh, (size_t)n))
			continue;
		if ((nlh->nlmsg_type >> 8) != NFNL_SUBSYS_QUEUE ||
		    (nlh->nlmsg_type & 0xff) != NFQNL_MSG_PACKET)
			continue;
		struct nfgenmsg* nfg = (struct nfgenmsg*)NLMSG_DATA(nlh);
		uint16 q = ntohs(nfg->res_id);
		struct nlattr* a = (struct nlattr*)((char*)nfg + NLMSG_ALIGN(sizeof(*nfg)));
		int alen = nlh->nlmsg_len - NLMSG_HDRLEN - NLMSG_ALIGN(sizeof(*nfg));
		uint32 id = 0;
		uint8* payload = NULL;
		int plen = 0;
		while (NFQ_NLA_OK(a, alen)) {
			if (a->nla_type == NFQA_PACKET_HDR &&
			    a->nla_len >= NLA_HDRLEN + sizeof(struct nfqnl_msg_packet_hdr)) {
				struct nfqnl_msg_packet_hdr* ph = (struct nfqnl_msg_packet_hdr*)NFQ_NLA_DATA(a);
				id = ntohl(ph->packet_id);
			} else if (a->nla_type == NFQA_PAYLOAD) {
				payload = (uint8*)NFQ_NLA_DATA(a);
				plen = a->nla_len - NLA_HDRLEN;
			}
			a = NFQ_NLA_NEXT(a, alen);
		}
		// Hook return contract (see syz_nfq_mutate_fn): 0 = pass through,
		// >0 = new total length to re-inject, <0 = drop.
		int ret = 0;
		if (syz_nfq_hook && payload && plen >= (int)(sizeof(struct iphdr) + sizeof(struct tcphdr)))
			ret = syz_nfq_hook(payload, plen);
		int vrc;
		if (ret < 0) {
			vrc = syz_nfq_send_verdict(syz_nfq_fd, q, id, NF_DROP, NULL, 0);
		} else if (ret > 0) {
			int newlen = ret;
			struct iphdr* ip = (struct iphdr*)payload;
			int ihl = ip->ihl * 4;
			// IP tot_len is a 16-bit field; a sane loopback segment fits well
			// under 64 KiB. Reject an out-of-range length rather than inject a
			// malformed/buffer-overrunning packet (defensive against a buggy hook;
			// the verdict builder also guards its own buffer).
			if (newlen < ihl + (int)sizeof(struct tcphdr) || newlen > 65535) {
				debug("syz_nfq_worker_loop: hook bad len=%d (plen=%d); passing original\n", newlen, plen);
				vrc = syz_nfq_send_verdict(syz_nfq_fd, q, id, NF_ACCEPT, NULL, 0);
			} else if (ip->protocol == IPPROTO_TCP) {
				struct tcphdr* tcph = (struct tcphdr*)(payload + ihl);
				int thl = tcph->doff * 4;
				// Enforce the TCP option-space bound (design §4): a grown header
				// past 60 bytes (doff > 15) can't be represented and would be
				// malformed -- drop rather than inject it.
				if (thl < (int)sizeof(struct tcphdr) || thl > MPTCP_TCP_MAX_HDR ||
				    newlen < ihl + thl) {
					debug("syz_nfq_worker_loop: TCP opt-space bound violated doff=%d; dropping\n", (int)tcph->doff);
					vrc = syz_nfq_send_verdict(syz_nfq_fd, q, id, NF_DROP, NULL, 0);
				} else {
					// On a length change the engine is authoritative for tot_len
					// and recomputes the IP-header csum; the TCP csum pass always
					// follows. A same-length rewrite leaves the IP header (and its
					// csum) untouched -- exactly the pre-widening behaviour.
					if (newlen != plen) {
						ip->tot_len = htons((uint16)newlen);
						syz_nfq_ip_csum_v4(ip);
					}
					syz_nfq_tcp_csum_v4(tcph, ip, newlen - ihl);
					vrc = syz_nfq_send_verdict(syz_nfq_fd, q, id, NF_ACCEPT, payload, (uint16)newlen);
				}
			} else {
				// Non-TCP length change: fix tot_len + IP csum, no L4 pass.
				if (newlen != plen) {
					ip->tot_len = htons((uint16)newlen);
					syz_nfq_ip_csum_v4(ip);
				}
				vrc = syz_nfq_send_verdict(syz_nfq_fd, q, id, NF_ACCEPT, payload, (uint16)newlen);
			}
		} else if (payload && syz_nfq_stall_take(q, id, payload, plen)) {
			vrc = 0; // held or dropped by a stall
		} else {
			vrc = syz_nfq_send_verdict(syz_nfq_fd, q, id, NF_ACCEPT, NULL, 0);
		}
		if (vrc < 0) {
			debug("syz_nfq_worker_loop: verdict send failed id=%u errno=%d\n", id, errno);
		}
	}
	return NULL;
}

static inline void syz_nfq_cleanup(void)
{
	if (syz_nfq_worker_started) {
		__atomic_store_n(&syz_nfq_worker_stop, 1, __ATOMIC_SEQ_CST);
		pthread_join(syz_nfq_worker_thread, NULL);
		syz_nfq_worker_started = 0;
	}
	if (syz_nfq_rule_installed) {
		// Must run before the fd is closed: the delete goes over that socket.
		if (syz_nfq_delete_rule(syz_nfq_fd) < 0) {
			debug("syz_nfq_cleanup: nft table delete failed errno=%d\n", errno);
		}
		syz_nfq_rule_installed = 0;
	}
	if (syz_nfq_fd >= 0) {
		close(syz_nfq_fd);
		syz_nfq_fd = -1;
	}
}

// The subsystem layer sets syz_nfq_hook before calling syz_nfq_setup().
static int syz_nfq_setup_locked(void);
static int syz_nfq_setup_lock;

// Idempotent and safe to call from several threads at once (a mutated join and a
// stall can both be the first user).
static inline int syz_nfq_setup(void)
{
	if (__atomic_load_n(&syz_nfq_setup_done, __ATOMIC_ACQUIRE))
		return 0;
	while (__atomic_exchange_n(&syz_nfq_setup_lock, 1, __ATOMIC_ACQUIRE))
		usleep(50);
	int ret = syz_nfq_setup_locked();
	__atomic_store_n(&syz_nfq_setup_lock, 0, __ATOMIC_RELEASE);
	return ret;
}

static int syz_nfq_setup_locked(void)
{
	struct sockaddr_nl sa;

	if (syz_nfq_setup_done)
		return 0;
	syz_nfq_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
	if (syz_nfq_fd < 0)
		return -1;
	// Ask the kernel to drop silently rather than raise ENOBUFS (which would
	// otherwise surface as a recv error) on rcvbuf overrun, and grow the
	// receive buffer so a burst of held packets is less likely to overrun it.
	{
		int one = 1;
		int rcvbuf = 4 << 20;
		setsockopt(syz_nfq_fd, SOL_NETLINK, NETLINK_NO_ENOBUFS, &one, sizeof(one));
		if (setsockopt(syz_nfq_fd, SOL_SOCKET, SO_RCVBUFFORCE, &rcvbuf, sizeof(rcvbuf)) < 0)
			setsockopt(syz_nfq_fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
	}
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (bind(syz_nfq_fd, (struct sockaddr*)&sa, sizeof(sa)) < 0)
		goto fail;
	(void)syz_nfq_config_cmd(syz_nfq_fd, 0, NFQNL_CFG_CMD_PF_UNBIND, AF_INET);
	(void)syz_nfq_config_cmd(syz_nfq_fd, 0, NFQNL_CFG_CMD_PF_BIND, AF_INET);
	if (syz_nfq_config_cmd(syz_nfq_fd, NFQ_QUEUE_NUM, NFQNL_CFG_CMD_BIND, AF_UNSPEC) < 0)
		goto fail;
	if (syz_nfq_config_params(syz_nfq_fd, NFQ_QUEUE_NUM, NFQNL_COPY_PACKET, 0xffff) < 0)
		goto fail;
	// Fail-open: if the queue can't be served, accept rather than drop. Best
	// effort -- older kernels may not support it, so don't fail setup on it.
	(void)syz_nfq_config_flags(syz_nfq_fd, NFQ_QUEUE_NUM, NFQA_CFG_F_FAIL_OPEN);
	// Bound the worker's blocking recv so it periodically returns to re-check
	// syz_nfq_worker_stop -- this is the wake source that lets cleanup join it
	// (netlink has no working shutdown() and we send no signal). Set only now,
	// after the config ACK exchanges above have completed on this fd.
	{
		struct timeval rtv = {0, 100000};
		setsockopt(syz_nfq_fd, SOL_SOCKET, SO_RCVTIMEO, &rtv, sizeof(rtv));
	}
	// Scope tightly to loopback TCP (the harness runs on lo). The queue
	// expression carries the bypass flag so that if no reader is bound (engine
	// died/exited abnormally) matching packets bypass the queue instead of
	// being dropped (blackholing lo TCP). Raw nftables netlink on this same
	// socket: no iptables/nft binary needed (a csource reproducer has none).
	if (syz_nfq_install_rule(syz_nfq_fd) < 0) {
		debug("syz_nfq_setup: nft rule install failed errno=%d (CAP_NET_ADMIN? CONFIG_NF_TABLES?)\n", errno);
		goto fail;
	}
	syz_nfq_rule_installed = 1;
	atexit(syz_nfq_cleanup);
	if (pthread_create(&syz_nfq_worker_thread, NULL, syz_nfq_worker_loop, NULL) != 0)
		goto fail;
	syz_nfq_worker_started = 1;
	__atomic_store_n(&syz_nfq_setup_done, 1, __ATOMIC_RELEASE);
	return 0;
fail:
	syz_nfq_cleanup();
	return -1;
}

#endif // EXECUTOR_COMMON_LINUX_MPTCP_NFQ_H
