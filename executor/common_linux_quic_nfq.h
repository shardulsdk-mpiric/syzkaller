// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
//
// UDP variant of the MPTCP stateless NFQUEUE wire engine
// (common_linux_mptcp_nfq.h). QUIC runs over UDP, so the diverting nft rule
// matches `ip protocol udp` (not tcp) and the worker recomputes the UDP
// checksum (not TCP) after an in-place rewrite. Everything else mirrors the
// MPTCP engine: raw NETLINK_NETFILTER (no libnetfilter_queue / nft binary), a
// LOCAL_OUT hook scoped to loopback, NFQA_CFG_F_FAIL_OPEN + queue bypass so a
// dead reader never blackholes loopback, and a single subsystem-set mutate hook
// applied to every matching held packet before the verdict.
//
// QUIC_-prefixed throughout so this coexists with common_linux_mptcp_nfq.h in
// the same SYZ_EXECUTOR build (both define static netlink/nft helpers).
#ifndef EXECUTOR_COMMON_LINUX_QUIC_NFQ_H
#define EXECUTOR_COMMON_LINUX_QUIC_NFQ_H

#include <arpa/inet.h>
#include <errno.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netlink.h>
#include <linux/udp.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define QUIC_NFQ_QUEUE_NUM 1
#define QUIC_NFQ_NFT_TABLE "syz_quic_mut"
#define QUIC_NFQ_NFT_CHAIN "out"

// Subsystem hook: given a copy of the IP packet (len bytes), mutate it IN PLACE
// and return 1 if mutated, 0 to pass through. Set once by the QUIC layer before
// quic_nfq_setup(). Unlike the MPTCP engine's pure-content hook, the QUIC
// path-challenge hook carries a tiny bit of cross-packet state (the captured
// entropy): the gate it crosses is DEFINED by carrying a kernel-generated value
// across packets, so statelessness is not applicable here.
typedef int (*quic_nfq_mutate_fn)(uint8* ip_pkt, int len);
static quic_nfq_mutate_fn quic_nfq_hook;

static int quic_nfq_fd = -1;
static int quic_nfq_setup_done;
static int quic_nfq_rule_installed;
static pthread_t quic_nfq_worker_thread;
static int quic_nfq_worker_started;
static volatile int quic_nfq_worker_stop;

#define QUIC_NFQ_NLA_OK(a, len) ((len) >= (int)sizeof(struct nlattr) &&            \
				 (a)->nla_len >= sizeof(struct nlattr) &&         \
				 (int)(a)->nla_len <= (len))
#define QUIC_NFQ_NLA_DATA(a) ((void*)((char*)(a) + NLA_HDRLEN))
#define QUIC_NFQ_NLA_NEXT(a, len) ((len) -= NLA_ALIGN((a)->nla_len),              \
				   (struct nlattr*)((char*)(a) + NLA_ALIGN((a)->nla_len)))

static inline uint16 quic_nfq_csum_fold(uint32 sum)
{
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	return (uint16)(~sum);
}

static inline uint16 quic_nfq_csum_buf(uint32 sum, const uint16* buf, int size)
{
	while (size > 1) {
		sum += *buf++;
		size -= 2;
	}
	if (size) {
		uint16 last = 0;
		memcpy(&last, buf, 1);
		sum += last;
	}
	return quic_nfq_csum_fold(sum);
}

// Recompute the IPv4 UDP checksum over pseudo-header + UDP header + payload.
// l4_len is the UDP header+payload length AS COPIED (plen - ihl), never derived
// from the packet's own fields, so a mutated length cannot overread the buffer.
static inline void quic_nfq_udp_csum_v4(struct udphdr* udph, const struct iphdr* iph, int l4_len)
{
	uint32 sum = 0;

	sum += (iph->saddr >> 16) & 0xFFFF;
	sum += iph->saddr & 0xFFFF;
	sum += (iph->daddr >> 16) & 0xFFFF;
	sum += iph->daddr & 0xFFFF;
	sum += htons(iph->protocol);
	sum += htons((uint16)l4_len);
	udph->check = 0;
	udph->check = quic_nfq_csum_buf(sum, (const uint16*)udph, l4_len);
	// RFC 768: a computed 0 is transmitted as 0xFFFF (0 means "no checksum").
	if (udph->check == 0)
		udph->check = 0xFFFF;
}

static inline int quic_nfq_send_msg(int fd, uint16 msg_type, uint16 res_id,
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

static inline int quic_nfq_config_cmd(int fd, uint16 q, uint8 cmd, uint16 pf)
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
	return quic_nfq_send_msg(fd, (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_CONFIG, q, &p, sizeof(p));
}

static inline int quic_nfq_config_params(int fd, uint16 q, uint8 mode, uint32 range)
{
	struct {
		struct nlattr nla;
		struct nfqnl_msg_config_params params;
	} __attribute__((packed)) p;
	p.nla.nla_len = sizeof(p);
	p.nla.nla_type = NFQA_CFG_PARAMS;
	p.params.copy_mode = mode;
	p.params.copy_range = htonl(range);
	return quic_nfq_send_msg(fd, (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_CONFIG, q, &p, sizeof(p));
}

static inline int quic_nfq_config_flags(int fd, uint16 q, uint32 flags)
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
	return quic_nfq_send_msg(fd, (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_CONFIG, q, &p, sizeof(p));
}

// ---- raw-netlink nftables rule install/delete (mirrors the MPTCP engine) ----
struct quic_nft_buf {
	char* p;
	int len;
	int cap;
	int err;
	uint32 seq_lo;
	uint32 seq_hi;
	uint32 ack_seq;
};

static uint32 quic_nft_next_seq;

static inline void quic_nft_buf_init(struct quic_nft_buf* b, char* p, int cap)
{
	memset(p, 0, cap);
	b->p = p;
	b->len = 0;
	b->cap = cap;
	b->err = 0;
	b->seq_lo = b->seq_hi = b->ack_seq = 0;
}

static inline void* quic_nft_reserve(struct quic_nft_buf* b, int n)
{
	void* at = b->p + b->len;
	if (b->err || b->len + NLA_ALIGN(n) > b->cap) {
		b->err = 1;
		return NULL;
	}
	b->len += NLA_ALIGN(n);
	return at;
}

static inline void quic_nft_put(struct quic_nft_buf* b, uint16 type, const void* data, uint16 dlen)
{
	struct nlattr* a = (struct nlattr*)quic_nft_reserve(b, NLA_HDRLEN + dlen);
	if (!a)
		return;
	a->nla_len = NLA_HDRLEN + dlen;
	a->nla_type = type;
	if (dlen)
		memcpy((char*)a + NLA_HDRLEN, data, dlen);
}

static inline void quic_nft_put_be32(struct quic_nft_buf* b, uint16 type, uint32 v)
{
	uint32 be = htonl(v);
	quic_nft_put(b, type, &be, sizeof(be));
}

static inline void quic_nft_put_be16(struct quic_nft_buf* b, uint16 type, uint16 v)
{
	uint16 be = htons(v);
	quic_nft_put(b, type, &be, sizeof(be));
}

static inline void quic_nft_put_str(struct quic_nft_buf* b, uint16 type, const char* s)
{
	quic_nft_put(b, type, s, (uint16)(strlen(s) + 1));
}

static inline int quic_nft_nest_start(struct quic_nft_buf* b, uint16 type)
{
	int off = b->len;
	struct nlattr* a = (struct nlattr*)quic_nft_reserve(b, NLA_HDRLEN);
	if (!a)
		return -1;
	a->nla_type = NLA_F_NESTED | type;
	return off;
}

static inline void quic_nft_nest_end(struct quic_nft_buf* b, int off)
{
	if (b->err || off < 0)
		return;
	((struct nlattr*)(b->p + off))->nla_len = (uint16)(b->len - off);
}

static inline int quic_nft_msg_start(struct quic_nft_buf* b, uint16 type, uint16 flags,
				     uint8 family, uint16 res_id)
{
	int off = b->len;
	struct nlmsghdr* nlh = (struct nlmsghdr*)quic_nft_reserve(b, NLMSG_LENGTH(sizeof(struct nfgenmsg)));
	if (!nlh)
		return -1;
	nlh->nlmsg_type = type;
	nlh->nlmsg_flags = flags;
	nlh->nlmsg_seq = ++quic_nft_next_seq;
	nlh->nlmsg_pid = 0;
	if (flags & NLM_F_ACK)
		b->ack_seq = nlh->nlmsg_seq;
	struct nfgenmsg* nfg = (struct nfgenmsg*)NLMSG_DATA(nlh);
	nfg->nfgen_family = family;
	nfg->version = NFNETLINK_V0;
	nfg->res_id = htons(res_id);
	return off;
}

static inline void quic_nft_msg_end(struct quic_nft_buf* b, int off)
{
	if (b->err || off < 0)
		return;
	((struct nlmsghdr*)(b->p + off))->nlmsg_len = (uint32)(b->len - off);
}

static inline void quic_nft_expr_start(struct quic_nft_buf* b, const char* name, int* elem, int* data)
{
	*elem = quic_nft_nest_start(b, NFTA_LIST_ELEM);
	quic_nft_put_str(b, NFTA_EXPR_NAME, name);
	*data = quic_nft_nest_start(b, NFTA_EXPR_DATA);
}

static inline void quic_nft_expr_end(struct quic_nft_buf* b, int elem, int data)
{
	quic_nft_nest_end(b, data);
	quic_nft_nest_end(b, elem);
}

static inline void quic_nft_expr_cmp_eq(struct quic_nft_buf* b, const void* value, uint16 vlen)
{
	int elem = 0, data = 0;
	quic_nft_expr_start(b, "cmp", &elem, &data);
	quic_nft_put_be32(b, NFTA_CMP_SREG, NFT_REG_1);
	quic_nft_put_be32(b, NFTA_CMP_OP, NFT_CMP_EQ);
	int d = quic_nft_nest_start(b, NFTA_CMP_DATA);
	quic_nft_put(b, NFTA_DATA_VALUE, value, vlen);
	quic_nft_nest_end(b, d);
	quic_nft_expr_end(b, elem, data);
}

static inline int quic_nft_batch_commit(int fd, struct quic_nft_buf* b)
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

static inline void quic_nft_batch_begin(struct quic_nft_buf* b)
{
	int m = quic_nft_msg_start(b, NFNL_MSG_BATCH_BEGIN, NLM_F_REQUEST, AF_UNSPEC,
				   NFNL_SUBSYS_NFTABLES);
	b->seq_lo = quic_nft_next_seq;
	quic_nft_msg_end(b, m);
}

static inline void quic_nft_batch_end(struct quic_nft_buf* b)
{
	int m = quic_nft_msg_start(b, NFNL_MSG_BATCH_END, NLM_F_REQUEST, AF_UNSPEC,
				   NFNL_SUBSYS_NFTABLES);
	b->seq_hi = quic_nft_next_seq;
	quic_nft_msg_end(b, m);
}

static inline int quic_nfq_delete_rule(int fd)
{
	char raw[256];
	struct quic_nft_buf b;

	quic_nft_buf_init(&b, raw, sizeof(raw));
	quic_nft_batch_begin(&b);
	int m = quic_nft_msg_start(&b, (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_DELTABLE,
				   NLM_F_REQUEST | NLM_F_ACK, NFPROTO_IPV4, 0);
	quic_nft_put_str(&b, NFTA_TABLE_NAME, QUIC_NFQ_NFT_TABLE);
	quic_nft_msg_end(&b, m);
	quic_nft_batch_end(&b);
	return quic_nft_batch_commit(fd, &b);
}

// Batch { BEGIN, NEWTABLE, NEWCHAIN (filter/output/prio 0/accept),
// NEWRULE [meta oif == lo; ip protocol == udp; queue num Q bypass], END }.
static inline int quic_nfq_install_rule(int fd)
{
	char raw[1024];
	struct quic_nft_buf b;
	uint32 lo_ifindex = if_nametoindex("lo");
	uint8 udp = IPPROTO_UDP;

	if (lo_ifindex == 0) {
		errno = ENODEV;
		return -1;
	}
	(void)quic_nfq_delete_rule(fd);

	quic_nft_buf_init(&b, raw, sizeof(raw));
	quic_nft_batch_begin(&b);

	int m = quic_nft_msg_start(&b, (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWTABLE,
				   NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK, NFPROTO_IPV4, 0);
	quic_nft_put_str(&b, NFTA_TABLE_NAME, QUIC_NFQ_NFT_TABLE);
	quic_nft_msg_end(&b, m);

	m = quic_nft_msg_start(&b, (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWCHAIN,
			       NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK, NFPROTO_IPV4, 0);
	quic_nft_put_str(&b, NFTA_CHAIN_TABLE, QUIC_NFQ_NFT_TABLE);
	quic_nft_put_str(&b, NFTA_CHAIN_NAME, QUIC_NFQ_NFT_CHAIN);
	quic_nft_put_str(&b, NFTA_CHAIN_TYPE, "filter");
	quic_nft_put_be32(&b, NFTA_CHAIN_POLICY, NF_ACCEPT);
	int nst = quic_nft_nest_start(&b, NFTA_CHAIN_HOOK);
	quic_nft_put_be32(&b, NFTA_HOOK_HOOKNUM, NF_INET_LOCAL_OUT);
	quic_nft_put_be32(&b, NFTA_HOOK_PRIORITY, 0);
	quic_nft_nest_end(&b, nst);
	quic_nft_msg_end(&b, m);

	m = quic_nft_msg_start(&b, (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE,
			       NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK, NFPROTO_IPV4, 0);
	quic_nft_put_str(&b, NFTA_RULE_TABLE, QUIC_NFQ_NFT_TABLE);
	quic_nft_put_str(&b, NFTA_RULE_CHAIN, QUIC_NFQ_NFT_CHAIN);
	int exprs = quic_nft_nest_start(&b, NFTA_RULE_EXPRESSIONS);
	int elem = 0, data = 0;
	quic_nft_expr_start(&b, "meta", &elem, &data);
	quic_nft_put_be32(&b, NFTA_META_KEY, NFT_META_OIF);
	quic_nft_put_be32(&b, NFTA_META_DREG, NFT_REG_1);
	quic_nft_expr_end(&b, elem, data);
	quic_nft_expr_cmp_eq(&b, &lo_ifindex, sizeof(lo_ifindex));
	// ip protocol (network header byte 9, 1 byte) -> reg1
	quic_nft_expr_start(&b, "payload", &elem, &data);
	quic_nft_put_be32(&b, NFTA_PAYLOAD_DREG, NFT_REG_1);
	quic_nft_put_be32(&b, NFTA_PAYLOAD_BASE, NFT_PAYLOAD_NETWORK_HEADER);
	quic_nft_put_be32(&b, NFTA_PAYLOAD_OFFSET, 9);
	quic_nft_put_be32(&b, NFTA_PAYLOAD_LEN, 1);
	quic_nft_expr_end(&b, elem, data);
	quic_nft_expr_cmp_eq(&b, &udp, sizeof(udp));
	quic_nft_expr_start(&b, "queue", &elem, &data);
	quic_nft_put_be16(&b, NFTA_QUEUE_NUM, QUIC_NFQ_QUEUE_NUM);
	quic_nft_put_be16(&b, NFTA_QUEUE_FLAGS, NFT_QUEUE_FLAG_BYPASS);
	quic_nft_expr_end(&b, elem, data);
	quic_nft_nest_end(&b, exprs);
	quic_nft_msg_end(&b, m);

	quic_nft_batch_end(&b);
	return quic_nft_batch_commit(fd, &b);
}

static inline int quic_nfq_send_verdict(int fd, uint16 q, uint32 id, uint32 verdict,
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

static inline void* quic_nfq_worker_loop(void* arg)
{
	(void)arg;
	static char buf[128 * 1024];
	while (!__atomic_load_n(&quic_nfq_worker_stop, __ATOMIC_SEQ_CST)) {
		ssize_t n = recv(quic_nfq_fd, buf, sizeof(buf), 0);
		if (n < 0) {
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
		while (QUIC_NFQ_NLA_OK(a, alen)) {
			if (a->nla_type == NFQA_PACKET_HDR &&
			    a->nla_len >= NLA_HDRLEN + sizeof(struct nfqnl_msg_packet_hdr)) {
				struct nfqnl_msg_packet_hdr* ph = (struct nfqnl_msg_packet_hdr*)QUIC_NFQ_NLA_DATA(a);
				id = ntohl(ph->packet_id);
			} else if (a->nla_type == NFQA_PAYLOAD) {
				payload = (uint8*)QUIC_NFQ_NLA_DATA(a);
				plen = a->nla_len - NLA_HDRLEN;
			}
			a = QUIC_NFQ_NLA_NEXT(a, alen);
		}
		int mutated = 0;
		if (quic_nfq_hook && payload && plen >= (int)(sizeof(struct iphdr) + sizeof(struct udphdr)))
			mutated = quic_nfq_hook(payload, plen);
		int vrc;
		if (mutated) {
			struct iphdr* ip = (struct iphdr*)payload;
			int ihl = ip->ihl * 4;
			if (ip->protocol == IPPROTO_UDP && plen >= ihl + (int)sizeof(struct udphdr))
				quic_nfq_udp_csum_v4((struct udphdr*)(payload + ihl), ip, plen - ihl);
			vrc = quic_nfq_send_verdict(quic_nfq_fd, q, id, NF_ACCEPT, payload, (uint16)plen);
		} else {
			vrc = quic_nfq_send_verdict(quic_nfq_fd, q, id, NF_ACCEPT, NULL, 0);
		}
		if (vrc < 0) {
			debug("quic_nfq_worker_loop: verdict send failed id=%u errno=%d\n", id, errno);
		}
	}
	return NULL;
}

static inline void quic_nfq_cleanup(void)
{
	if (quic_nfq_worker_started) {
		__atomic_store_n(&quic_nfq_worker_stop, 1, __ATOMIC_SEQ_CST);
		pthread_join(quic_nfq_worker_thread, NULL);
		quic_nfq_worker_started = 0;
	}
	if (quic_nfq_rule_installed) {
		if (quic_nfq_delete_rule(quic_nfq_fd) < 0) {
			debug("quic_nfq_cleanup: nft table delete failed errno=%d\n", errno);
		}
		quic_nfq_rule_installed = 0;
	}
	if (quic_nfq_fd >= 0) {
		close(quic_nfq_fd);
		quic_nfq_fd = -1;
	}
}

// Idempotent. The QUIC layer sets quic_nfq_hook before calling this.
static inline int quic_nfq_setup(void)
{
	struct sockaddr_nl sa;

	if (quic_nfq_setup_done)
		return 0;
	quic_nfq_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
	if (quic_nfq_fd < 0)
		return -1;
	{
		int one = 1;
		int rcvbuf = 4 << 20;
		setsockopt(quic_nfq_fd, SOL_NETLINK, NETLINK_NO_ENOBUFS, &one, sizeof(one));
		if (setsockopt(quic_nfq_fd, SOL_SOCKET, SO_RCVBUFFORCE, &rcvbuf, sizeof(rcvbuf)) < 0)
			setsockopt(quic_nfq_fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
	}
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (bind(quic_nfq_fd, (struct sockaddr*)&sa, sizeof(sa)) < 0)
		goto fail;
	(void)quic_nfq_config_cmd(quic_nfq_fd, 0, NFQNL_CFG_CMD_PF_UNBIND, AF_INET);
	(void)quic_nfq_config_cmd(quic_nfq_fd, 0, NFQNL_CFG_CMD_PF_BIND, AF_INET);
	if (quic_nfq_config_cmd(quic_nfq_fd, QUIC_NFQ_QUEUE_NUM, NFQNL_CFG_CMD_BIND, AF_UNSPEC) < 0)
		goto fail;
	if (quic_nfq_config_params(quic_nfq_fd, QUIC_NFQ_QUEUE_NUM, NFQNL_COPY_PACKET, 0xffff) < 0)
		goto fail;
	(void)quic_nfq_config_flags(quic_nfq_fd, QUIC_NFQ_QUEUE_NUM, NFQA_CFG_F_FAIL_OPEN);
	{
		struct timeval rtv = {0, 100000};
		setsockopt(quic_nfq_fd, SOL_SOCKET, SO_RCVTIMEO, &rtv, sizeof(rtv));
	}
	if (quic_nfq_install_rule(quic_nfq_fd) < 0) {
		debug("quic_nfq_setup: nft rule install failed errno=%d (CAP_NET_ADMIN? CONFIG_NF_TABLES?)\n", errno);
		goto fail;
	}
	quic_nfq_rule_installed = 1;
	atexit(quic_nfq_cleanup);
	if (pthread_create(&quic_nfq_worker_thread, NULL, quic_nfq_worker_loop, NULL) != 0)
		goto fail;
	quic_nfq_worker_started = 1;
	quic_nfq_setup_done = 1;
	return 0;
fail:
	quic_nfq_cleanup();
	return -1;
}

#endif // EXECUTOR_COMMON_LINUX_QUIC_NFQ_H
