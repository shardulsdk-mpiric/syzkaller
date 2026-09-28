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
// the held packet synchronously before it proceeds. Raw-netlink (no
// libnetfilter_queue dependency), mirroring the executor's other self-contained
// netlink builders.
#ifndef SYZ_COMMON_LINUX_MPTCP_NFQ_H
#define SYZ_COMMON_LINUX_MPTCP_NFQ_H

#include <arpa/inet.h>
#include <errno.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netlink.h>
#include <linux/tcp.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define SYZ_NFQ_QUEUE_NUM 0

// The subsystem hook: given a copy of the IP packet (len bytes), mutate it IN
// PLACE and return 1 if mutated, 0 to pass through. Must be a pure function of
// the packet content and the layer's (persistently-set) spec -- no per-call state,
// no fire-once. Set once by the subsystem layer before syz_nfq_setup().
typedef int (*syz_nfq_mutate_fn)(uint8* ip_pkt, int len);
static syz_nfq_mutate_fn syz_nfq_hook;

static int syz_nfq_fd = -1;
static int syz_nfq_setup_done;
static int syz_nfq_iptables_inserted;
static pthread_t syz_nfq_worker_thread;
static int syz_nfq_worker_started;
static volatile int syz_nfq_worker_stop;

// ---- local netlink-attribute walkers (no libnl) ----
#define SYZ_NLA_OK(a, len) ((len) >= (int)sizeof(struct nlattr) && \
			    (a)->nla_len >= sizeof(struct nlattr) && (int)(a)->nla_len <= (len))
#define SYZ_NLA_DATA(a) ((void*)((char*)(a) + NLA_HDRLEN))
#define SYZ_NLA_NEXT(a, len) ((len) -= NLA_ALIGN((a)->nla_len), \
			      (struct nlattr*)((char*)(a) + NLA_ALIGN((a)->nla_len)))

// ---- IPv4 TCP checksum recompute (after an in-place TCP-segment rewrite) ----
// NOTE: this recomputes only the TCP checksum and assumes the hook mutated TCP
// payload/option bytes, NOT the IP header. A hook that changes IP-header fields
// (tot_len, ihl, addrs, ttl, ...) needs the IP header checksum recomputed too
// (ip_rcv_core drops a bad one) and must not be trusted to bound this pass --
// that is out of scope until a grammar needs it (see review round 2, F6).
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

// ---- raw-netlink NFQUEUE plumbing ----
static inline int syz_nfq_send_msg(int fd, uint16 msg_type, uint16 res_id,
				   const void* attr_payload, uint16 attr_len)
{
	char buf[256], ack[256];
	struct nlmsghdr* nlh = (struct nlmsghdr*)buf;
	struct nfgenmsg* nfg = (struct nfgenmsg*)NLMSG_DATA(nlh);
	ssize_t n;

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
	n = recv(fd, ack, sizeof(ack), 0);
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
// never blackholes loopback TCP (paired with --queue-bypass on the rule).
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
		ssize_t n = recv(syz_nfq_fd, buf, sizeof(buf), 0);
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
		while (SYZ_NLA_OK(a, alen)) {
			if (a->nla_type == NFQA_PACKET_HDR &&
			    a->nla_len >= NLA_HDRLEN + sizeof(struct nfqnl_msg_packet_hdr)) {
				struct nfqnl_msg_packet_hdr* ph = (struct nfqnl_msg_packet_hdr*)SYZ_NLA_DATA(a);
				id = ntohl(ph->packet_id);
			} else if (a->nla_type == NFQA_PAYLOAD) {
				payload = (uint8*)SYZ_NLA_DATA(a);
				plen = a->nla_len - NLA_HDRLEN;
			}
			a = SYZ_NLA_NEXT(a, alen);
		}
		int mutated = 0;
		if (syz_nfq_hook && payload && plen >= (int)(sizeof(struct iphdr) + sizeof(struct tcphdr)))
			mutated = syz_nfq_hook(payload, plen);
		int vrc;
		if (mutated) {
			struct iphdr* ip = (struct iphdr*)payload;
			int ihl = ip->ihl * 4;
			if (ip->protocol == IPPROTO_TCP && plen >= ihl + (int)sizeof(struct tcphdr))
				syz_nfq_tcp_csum_v4((struct tcphdr*)(payload + ihl), ip, plen - ihl);
			vrc = syz_nfq_send_verdict(syz_nfq_fd, q, id, NF_ACCEPT, payload, (uint16)plen);
		} else {
			vrc = syz_nfq_send_verdict(syz_nfq_fd, q, id, NF_ACCEPT, NULL, 0);
		}
		if (vrc < 0)
			debug("syz_nfq_worker_loop: verdict send failed id=%u errno=%d\n", id, errno);
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
	if (syz_nfq_iptables_inserted) {
		if (system("iptables -D OUTPUT -o lo -p tcp -j NFQUEUE --queue-num 0 --queue-bypass") != 0)
			debug("syz_nfq_cleanup: iptables -D failed\n");
		syz_nfq_iptables_inserted = 0;
	}
	if (syz_nfq_fd >= 0) {
		close(syz_nfq_fd);
		syz_nfq_fd = -1;
	}
}

// Idempotent. The subsystem layer sets syz_nfq_hook before calling this.
static inline int syz_nfq_setup(void)
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
	if (syz_nfq_config_cmd(syz_nfq_fd, SYZ_NFQ_QUEUE_NUM, NFQNL_CFG_CMD_BIND, AF_UNSPEC) < 0)
		goto fail;
	if (syz_nfq_config_params(syz_nfq_fd, SYZ_NFQ_QUEUE_NUM, NFQNL_COPY_PACKET, 0xffff) < 0)
		goto fail;
	// Fail-open: if the queue can't be served, accept rather than drop. Best
	// effort -- older kernels may not support it, so don't fail setup on it.
	(void)syz_nfq_config_flags(syz_nfq_fd, SYZ_NFQ_QUEUE_NUM, NFQA_CFG_F_FAIL_OPEN);
	// Bound the worker's blocking recv so it periodically returns to re-check
	// syz_nfq_worker_stop -- this is the wake source that lets cleanup join it
	// (netlink has no working shutdown() and we send no signal). Set only now,
	// after the config ACK exchanges above have completed on this fd.
	{
		struct timeval rtv = {0, 100000};
		setsockopt(syz_nfq_fd, SOL_SOCKET, SO_RCVTIMEO, &rtv, sizeof(rtv));
	}
	// Scope tightly to loopback TCP (the harness runs on lo). --queue-bypass so
	// that if no reader is bound (engine died/exited abnormally) matching
	// packets bypass the queue instead of being dropped (blackholing lo TCP).
	if (system("iptables -I OUTPUT -o lo -p tcp -j NFQUEUE --queue-num 0 --queue-bypass") != 0) {
		debug("syz_nfq_setup: iptables -I failed (CAP_NET_ADMIN?)\n");
		goto fail;
	}
	syz_nfq_iptables_inserted = 1;
	atexit(syz_nfq_cleanup);
	if (pthread_create(&syz_nfq_worker_thread, NULL, syz_nfq_worker_loop, NULL) != 0)
		goto fail;
	syz_nfq_worker_started = 1;
	syz_nfq_setup_done = 1;
	return 0;
fail:
	syz_nfq_cleanup();
	return -1;
}

#endif // SYZ_COMMON_LINUX_MPTCP_NFQ_H
