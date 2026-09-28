// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// MPTCP (Multipath TCP, RFC 8684) MP_CAPABLE pair + MP_JOIN subflow
// pseudo-syscalls.
//
// syz_mptcp_pair_init() drives a single MP_CAPABLE-negotiated MPTCP
// connection to completion on loopback: socket(IPPROTO_MPTCP), bind(),
// listen() on the server side, connect() + accept() to run the
// handshake, then a 1-byte bidirectional round-trip to flip
// fully_established on BOTH endpoints (see the comment inline for why
// that round-trip is required). The resulting client/server fds are
// held in a small static pool; the pool index is returned as the
// mptcp_pair resource (see sys/linux/socket_mptcp_flow.txt).
//
// syz_mptcp_pair_close() closes both fds and frees the slot -- the
// real resource-consuming edge a reproducer needs, per the
// pseudo-syscall convention in docs/pseudo_syscalls.md.
//
// syz_mptcp_join_subflow() adds a second producer/consumer pair: it
// drives a real MP_JOIN handshake on an established pair via the
// kernel's userspace path-manager genl API (MPTCP_PM_CMD_SUBFLOW_CREATE)
// and returns a new mptcp_subflow resource that references its parent
// pair slot. NORMAL mode only -- the kernel computes the join's
// nonce/HMAC end-to-end, nothing here touches the wire -- so it still
// needs nothing beyond a stock CONFIG_MPTCP kernel.
// syz_mptcp_subflow_destroy() is the corresponding consuming edge
// (MPTCP_PM_CMD_SUBFLOW_DESTROY): a subflow resource exists only because
// a join created it, and this is the only call that can consume it --
// exactly the producer -> consumer dependency edge the reproducibility
// convention in docs/pseudo_syscalls.md is about.
//
// Scope of this increment: no mutation, no nonce/HMAC capture, no
// kernel-side instrumentation -- those need kernel-side support and/or
// wire-level tampering and land as a later increment. This file runs
// unmodified on any stock CONFIG_MPTCP kernel and has no dependency
// beyond the standard socket/netlink headers already used throughout
// common_linux.h. The netlink message building below is a small
// self-contained raw-netlink builder rather than a reuse of
// common_linux.h's own nlmsg/netlink_init/netlink_attr/netlink_send_ext
// -- those live behind a guard keyed to several unrelated subsystems'
// feature flags (SYZ_NET_DEVICES, SYZ_WIFI, SYZ_802154, ...) that a
// plain MPTCP-only reproducer never sets; see the comment above
// struct mptcp_nlmsg for the full reasoning.
//
// The server_addr/client_addr syzlang inputs are accepted (so the
// resource contract stays real-address shaped for later increments
// that add non-loopback / multi-address / netns support) but are not
// yet consulted: v0 always binds and connects on 127.0.0.1 with an
// ephemeral server port, which is what makes a bare MP_CAPABLE
// handshake reliable on a stock kernel with no extra setup. The new
// subflow's local address is fixed at 127.0.0.2 -- see the file comment
// above syz_mptcp_join_subflow for why a fixed address is fine here.

#ifndef EXECUTOR_COMMON_LINUX_MPTCP_H
#define EXECUTOR_COMMON_LINUX_MPTCP_H

#include <endian.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <linux/genetlink.h>
#include <linux/netlink.h>

// Mutation layer (dormant until the MP_JOIN HMAC hook wires it): the no-deps
// crypto + the stateless NFQUEUE engine. Guarded to the mutation-carrying call
// so minimal reproducers that don't mutate don't pull in pthread/netfilter.
#if SYZ_EXECUTOR || __NR_syz_mptcp_join_subflow
#include "common_linux_mptcp_crypto.h"
#include "common_linux_mptcp_mut.h"
#include "common_linux_mptcp_nfq.h"
#endif

// IPPROTO_MPTCP is provided by <netinet/in.h> on any glibc recent enough to
// know about MPTCP (which any host running a CONFIG_MPTCP kernel will have);
// deliberately not given a local fallback definition here -- pkg/csource's
// reference-build preprocessing pass runs with -nostdinc, so a guarded
// fallback (`#ifndef IPPROTO_MPTCP ... #endif`) would wrongly fire during
// that pass and then collide with the real header's definition when the
// generated reproducer is actually compiled.
//
// SOL_MPTCP / MPTCP_INFO are a different case: unlike IPPROTO_MPTCP,
// neither is defined by <netinet/in.h> on any glibc in current use (they
// live in the newer <linux/mptcp.h> uapi header, which this file
// deliberately does not include -- see the comment on
// struct syz_mptcp_info_short below), so a guarded fallback here cannot
// collide with anything.
#ifndef SOL_MPTCP
#define SOL_MPTCP 284
#endif
#ifndef MPTCP_INFO
#define MPTCP_INFO 1
#endif

// MPTCP_PM_ADDR_FLAG_* (uapi, from <linux/mptcp.h>): mirrored explicitly
// for the same reason as SOL_MPTCP/MPTCP_INFO above. These are stable
// uapi bit values that can't change without breaking existing userspace.
#ifndef MPTCP_PM_ADDR_FLAG_SIGNAL
#define MPTCP_PM_ADDR_FLAG_SIGNAL (1U << 0)
#define MPTCP_PM_ADDR_FLAG_SUBFLOW (1U << 1)
#define MPTCP_PM_ADDR_FLAG_BACKUP (1U << 2)
#define MPTCP_PM_ADDR_FLAG_FULLMESH (1U << 3)
#define MPTCP_PM_ADDR_FLAG_IMPLICIT (1U << 4)
#endif

// MPTCP_PM_CMD_SUBFLOW_CREATE/DESTROY plus the MPTCP_PM_ATTR_TOKEN /
// MPTCP_PM_ATTR_ADDR_REMOTE attributes they need are recent additions to
// the mptcp_pm genl policy (they moved into their own uapi header,
// <linux/mptcp_pm.h>, generated from
// Documentation/netlink/specs/mptcp_pm.yaml) that most distros' copies
// of <linux/mptcp.h>/<linux/mptcp_pm.h> still predate -- this host's
// /usr/include/linux/mptcp.h is one such case. Mirrored here
// unconditionally, same rationale and the same "won't change, it's
// uapi" guarantee as the flags above.
//
// Deliberately NOT gated on __has_include(<linux/mptcp_pm.h>): that
// query still has to resolve the header to answer, and pkg/csource's
// reference-build preprocessing pass runs cpp with -nostdinc and no
// include path at all (see the IPPROTO_MPTCP comment above), where
// __has_include's own header lookup hits a hard "no include path"
// error that -- unlike a plain unresolved #include, which cpp just
// leaves untouched and keeps going -- aborts the whole pass with
// "confused by earlier errors, bailing out" and silently truncates the
// generated C reproducer. Nothing else in this tree includes
// <linux/mptcp.h>/<linux/mptcp_pm.h>, so there's no real header to
// prefer over this fallback anyway.
#ifndef MPTCP_PM_NAME
#define MPTCP_PM_NAME "mptcp_pm"
#define MPTCP_PM_VER 1
enum {
	MPTCP_PM_ATTR_UNSPEC_FB,
	MPTCP_PM_ATTR_ADDR,
	MPTCP_PM_ATTR_RCV_ADD_ADDRS,
	MPTCP_PM_ATTR_SUBFLOWS,
	MPTCP_PM_ATTR_TOKEN,
	MPTCP_PM_ATTR_LOC_ID,
	MPTCP_PM_ATTR_ADDR_REMOTE,
};
enum {
	MPTCP_PM_ADDR_ATTR_UNSPEC_FB,
	MPTCP_PM_ADDR_ATTR_FAMILY,
	MPTCP_PM_ADDR_ATTR_ID,
	MPTCP_PM_ADDR_ATTR_ADDR4,
	MPTCP_PM_ADDR_ATTR_ADDR6,
	MPTCP_PM_ADDR_ATTR_PORT,
	MPTCP_PM_ADDR_ATTR_FLAGS,
	MPTCP_PM_ADDR_ATTR_IF_IDX,
};
enum {
	MPTCP_PM_CMD_UNSPEC_FB,
	MPTCP_PM_CMD_ADD_ADDR,
	MPTCP_PM_CMD_DEL_ADDR,
	MPTCP_PM_CMD_GET_ADDR,
	MPTCP_PM_CMD_FLUSH_ADDRS,
	MPTCP_PM_CMD_SET_LIMITS,
	MPTCP_PM_CMD_GET_LIMITS,
	MPTCP_PM_CMD_SET_FLAGS,
	MPTCP_PM_CMD_ANNOUNCE,
	MPTCP_PM_CMD_REMOVE,
	MPTCP_PM_CMD_SUBFLOW_CREATE,
	MPTCP_PM_CMD_SUBFLOW_DESTROY,
};
// Subsets of enum mptcp_event_type and enum mptcp_event_attr -- same uapi
// header family (linux/mptcp_pm.h) as the PM cmd/attr enums above, so mirrored
// under the same MPTCP_PM_NAME sentinel. Read by the SUB_ESTABLISHED event
// parser (mptcp_pm_recv_subflow_sport) to recover the kernel-auto-assigned
// subflow source port. SPORT arrives in NETWORK byte order (kernel
// nla_put_be16 of inet_sport) -- see the ntohs() at the read site; DESTROY's
// MPTCP_PM_ADDR_ATTR_PORT is host order.
enum {
	MPTCP_EVENT_SUB_ESTABLISHED = 10,
};
enum {
	MPTCP_ATTR_TOKEN = 1,
	MPTCP_ATTR_LOC_ID = 3,
	MPTCP_ATTR_SADDR4 = 5,
	MPTCP_ATTR_SPORT = 9,
};
#endif

#define MPTCP_PAIR_POOL_SIZE 64
#define MPTCP_SUBFLOW_POOL_SIZE 64

// The kernel binds a new subflow's local endpoint to whatever port we put
// in MPTCP_PM_ADDR_ATTR_PORT (0 lets it auto-assign, like a bare
// connect()). We use a small deterministic port per subflow slot instead
// of 0: syz_mptcp_subflow_destroy() has to reconstruct the exact same
// (local, remote) tuple later from data already sitting in the pool --
// see mptcp_pm_nl_subflow_destroy_doit()'s exact-match lookup in
// net/mptcp/pm_userspace.c -- and a fixed, slot-derived port makes that
// reconstruction exact with no extra query step. The base sits below
// the default net.ipv4.ip_local_port_range lower bound (32768) so it
// doesn't collide with kernel-assigned ephemeral ports on the same host.
#define MPTCP_SUBFLOW_LOCAL_PORT_BASE 25000

// Bound on the 50ms MPTCP_INFO poll in syz_mptcp_join_subflow -- ~1s
// total, generous for a loopback handshake that normally completes in
// well under a millisecond.
#define MPTCP_SUBFLOW_INFO_MAX_RETRIES 20

// MPTCP_INIT_RWND_CLAMP (harness flag; mirrored in socket_mptcp_flow.txt and
// its .const): clamp the server receive window so a syz_mptcp_drive_traffic
// burst cannot flush inline -- the backlog is pushed from the softirq
// deferred-send path (__mptcp_check_push -> __mptcp_subflow_push_pending).
#define MPTCP_INIT_RWND_CLAMP 1
// SO_RCVBUF applied to the server side when clamped. The kernel doubles the
// request and enforces SOCK_MIN_RCVBUF; 16 KiB keeps the advertised window
// well under a burst while leaving room for the fully_established priming.
#define MPTCP_CLAMP_RCVBUF (16 * 1024)

// MPTCP_INIT_CAPTURE_KEYS (harness flag; mirrored in .txt + .const): sniff the
// MP_CAPABLE handshake off loopback (AF_PACKET) and store both keys on the pair,
// so the mutation layer can recompute MP_JOIN HMACs -- replaces MPTCP_DEBUG_KEYS.
#define MPTCP_INIT_CAPTURE_KEYS 2

struct syz_mptcp_pair_slot {
	bool in_use;
	int server_fd;
	int client_fd;

	// Kept open for the pair's whole lifetime as of this increment
	// (previously closed right after accept()): an MP_JOIN subflow SYN
	// targets the SAME (addr, port) as the original MP_CAPABLE
	// connection, and the kernel only routes it into the MPTCP
	// token/join path (subflow_syn_recv_sock, net/mptcp/subflow.c) for
	// SYNs arriving at a live MPTCP listener -- once the listener is
	// closed there is nothing to receive that SYN and the kernel just
	// TCP-RSTs it (confirmed via /proc/net/snmp's Tcp: AttemptFails/
	// OutRsts both incrementing on syz_mptcp_join_subflow, with every
	// MPTcpExt Join* counter staying at 0 -- the SYN never reached any
	// MPTCP code at all). syz_mptcp_pair_close() closes it now instead.
	int server_listen_fd;

	// Captured once the pair is fully established (see
	// syz_mptcp_pair_init): the CLIENT msk's own MPTCP token and the
	// server's bound port. syz_mptcp_join_subflow() issues
	// MPTCP_PM_CMD_SUBFLOW_CREATE against this token, which is how the
	// kernel identifies which msk to open a new subflow from -- the new
	// subflow leaves from the client's msk towards the server, matching
	// local=127.0.0.2 / remote=127.0.0.1:server_port_h below.
	uint32 token;
	uint16 server_port_h; // host byte order -- see the byte-order note
			      // on mptcp_pm_subflow_create.

	// Bumped every time this slot is (re)allocated by syz_mptcp_pair_init.
	// A subflow records the generation of its parent pair at join time
	// (syz_mptcp_subflow_slot.pair_generation); syz_mptcp_subflow_destroy
	// refuses to act on a pair whose generation no longer matches, so a
	// stale subflow whose parent slot was closed and REUSED by a different
	// pair can't issue a genl DESTROY against the new occupant's token.
	// Preserved across syz_mptcp_pair_close (not zeroed) so reuse always
	// yields a strictly newer value.
	uint32 generation;

	// Set when the pair was created with MPTCP_INIT_RWND_CLAMP: the server
	// receive window is pinned small so syz_mptcp_drive_traffic switches to
	// burst + partial-drain, leaving data on the msk send head for the
	// softirq deferred-push path.
	bool rwnd_clamped;

	// Captured off the wire when MPTCP_INIT_CAPTURE_KEYS is set: the two
	// MP_CAPABLE keys (client=local, server=remote), for userspace HMAC recompute.
	// keys_valid gates them: capture is best-effort (a bounded sniff of the
	// handshake), so a consumer MUST check keys_valid before using the keys --
	// an unset flag means capture was not requested or did not complete, and the
	// key fields are then meaningless (and are cleared on slot reuse).
	uint64 local_key;
	uint64 remote_key;
	bool keys_valid;
};

// A subflow produced by syz_mptcp_join_subflow(). References its parent
// pair by pool index so syz_mptcp_subflow_destroy() can look the pair
// (and its token) back up; nothing here outlives the parent pair being
// closed, but a stale reference is handled gracefully (see
// syz_mptcp_subflow_destroy).
struct syz_mptcp_subflow_slot {
	bool in_use;
	int pair_slot;
	uint32 pair_generation; // parent pair's generation at join time (see
				// syz_mptcp_pair_slot.generation)
	uint8 addr_id;
	uint32 local_addr_be; // this subflow's distinct local 127/8 address (per slot),
			      // so the kernel PM sees distinct local addrs for concurrent
			      // subflows; DESTROY reuses it
	uint16 local_port_h;
	uint16 remote_port_h;
};

// Subset of struct mptcp_info (uapi <linux/mptcp.h>) needed here: just
// the live subflow count and the token. A private subset rather than
// including the uapi header directly, because getsockopt(MPTCP_INFO)
// only ever writes min(optlen, kernel's real struct size) bytes -- as
// long as this subset is laid out as an exact prefix of the real struct
// (it is: mptcpi_subflows..mptcpi_token, matching the field order and
// the documented 16-bit hole after the six single-byte counters), it
// reads correctly regardless of how many fields the real struct has
// grown since.
struct syz_mptcp_info_short {
	uint8 mptcpi_subflows;
	uint8 mptcpi_add_addr_signal;
	uint8 mptcpi_add_addr_accepted;
	uint8 mptcpi_subflows_max;
	uint8 mptcpi_add_addr_signal_max;
	uint8 mptcpi_add_addr_accepted_max;
	uint8 _pad_hole[2]; // "16-bit hole that can no longer be filled"
	uint32 mptcpi_flags;
	uint32 mptcpi_token;
};

static struct syz_mptcp_pair_slot syz_mptcp_pair_pool[MPTCP_PAIR_POOL_SIZE];

// Which of the five pseudo-syscalls in this file end up compiled in
// determines which of the shared pool/netlink/setup helpers below are
// reachable. pkg/csource's per-pseudo-syscall smoke test
// (pkg/csource.testPseudoSyscalls, "single_syz_mptcp_*") builds one call
// at a time with -Werror, so a helper that's unconditionally defined but
// only reachable from a DIFFERENT call than the one under test fails
// that build with -Werror=unused-function/-variable. Each helper below
// is gated to the precise union of calls that reach it, mirroring how
// common_linux.h itself gates shared netlink helpers per subsystem.
// join_subflow and subflow_destroy are the two calls that operate on a
// subflow (produce / consume it, respectively) -- both the subflow pool
// itself and the nested-attribute nest_begin/end helpers (only
// SUBFLOW_CREATE/DESTROY payloads nest attributes; GETFAMILY's request
// doesn't) are needed by exactly this pair.
#define MPTCP_NEED_SUBFLOW_CALL (SYZ_EXECUTOR || __NR_syz_mptcp_join_subflow || __NR_syz_mptcp_subflow_destroy || __NR_syz_mptcp_subflow_info)
#define MPTCP_NEED_NLMSG (SYZ_EXECUTOR || __NR_syz_mptcp_pair_init || __NR_syz_mptcp_join_subflow || __NR_syz_mptcp_subflow_destroy)
#define MPTCP_NEED_PM_SETUP (SYZ_EXECUTOR || __NR_syz_mptcp_pair_init || __NR_syz_mptcp_join_subflow)

#if MPTCP_NEED_SUBFLOW_CALL
static struct syz_mptcp_subflow_slot syz_mptcp_subflow_pool[MPTCP_SUBFLOW_POOL_SIZE];
#endif

// ---------- Userspace path-manager setup (needed for MP_JOIN) ----------
//
// syz_mptcp_join_subflow() asks the kernel's userspace path-manager to
// create a subflow on an already-established msk
// (MPTCP_PM_CMD_SUBFLOW_CREATE). Two preconditions have to be in place
// before the first join on a given msk can succeed, and both reach back
// into syz_mptcp_pair_init():
//
//   1. mptcp_pm_data_reset() (net/mptcp/pm.c) captures pm_type from the
//      net.mptcp.pm_type sysctl at MSK CREATION time -- i.e. inside
//      socket(IPPROTO_MPTCP) -- and never re-reads it later. Writing the
//      sysctl to userspace-PM (1) only takes effect for msks created
//      AFTER the write, so syz_mptcp_pair_init() has to call
//      mptcp_pm_ensure_setup() before it creates either endpoint's
//      socket, not merely before any later join.
//   2. The server's acceptance gate for an incoming MP_JOIN in
//      userspace-PM mode (mptcp_userspace_pm_active(), consulted from
//      mptcp_can_accept_new_subflow() in net/mptcp/subflow.c) requires a
//      live multicast listener on the "mptcp_pm_events" genl group --
//      we never need to read an event, just to hold the subscription
//      open.
//
// mptcp_pm_ensure_setup() is idempotent (mptcp_pm_setup_done latches)
// and is called from both syz_mptcp_pair_init() and
// syz_mptcp_join_subflow(), so whichever runs first in a given process
// does the one-time work -- a C reproducer that re-enters at either
// pseudo-syscall still works.

// ---------- Self-contained raw netlink message building ----------
//
// Deliberately NOT reusing common_linux.h's struct nlmsg /
// netlink_init() / netlink_attr() / netlink_send_ext() /
// netlink_nest() / netlink_done(): all of those live inside one big
// `#if SYZ_EXECUTOR || SYZ_NET_DEVICES || SYZ_NET_INJECTION ||
// SYZ_DEVLINK_PCI || SYZ_WIFI || SYZ_802154 || __NR_syz_genetlink_get_
// family_id || ...` guard, none of whose flags a plain MPTCP-only
// reproducer sets -- linking one leaves the SUBFLOW_CREATE/DESTROY
// senders below with undefined references to them. A small local copy,
// scoped to exactly what genl request/reply framing needs, keeps this
// file buildable standalone and matches how the rest of it already
// avoids coupling to other subsystems' feature flags.
//
// Needed by (MPTCP_NEED_NLMSG): pair_init and join_subflow (both via
// mptcp_pm_ensure_setup -> mptcp_pm_resolve_family) and subflow_destroy
// (via mptcp_pm_subflow_destroy) -- every one of the four calls except
// pair_close, which never touches netlink.
#if MPTCP_NEED_NLMSG
struct mptcp_nlmsg {
	char buf[512];
	char* pos;
	bool overflow; // set if any attr write would exceed buf; checked by send
};

static int mptcp_pm_genl_sock = -1; // request/reply socket: GETFAMILY, SUBFLOW_CREATE/DESTROY
static uint16 mptcp_pm_family_id;

// The request/reply socket above is shared across threads under the default
// -threaded model. Two concurrent transactions on one socket can each recv
// the other's reply, so serialize every send+recv pair under this lock and
// stamp each request with a unique nlmsg_seq the reply is matched against
// (defence in depth against a stale datagram left in the socket buffer).
static int mptcp_nlmsg_lock;
static uint32 mptcp_nlmsg_seq_ctr;

// Minimal spinlock over an int flag, used both here and by the one-time
// userspace-PM setup below. __atomic builtins need no header and are
// available in every reproducer build; usleep is already used in this file.
static void mptcp_spin_lock(volatile int* lock)
{
	while (__atomic_exchange_n(lock, 1, __ATOMIC_ACQUIRE))
		usleep(50);
}

static void mptcp_spin_unlock(volatile int* lock)
{
	__atomic_store_n(lock, 0, __ATOMIC_RELEASE);
}

static void mptcp_nlmsg_init(struct mptcp_nlmsg* m, int typ, const void* data, int size)
{
	struct nlmsghdr* hdr = (struct nlmsghdr*)m->buf;

	memset(m->buf, 0, sizeof(m->buf));
	m->overflow = false;
	if (sizeof(struct nlmsghdr) + NLMSG_ALIGN(size) > sizeof(m->buf)) {
		m->overflow = true;
		m->pos = m->buf;
		return;
	}
	hdr->nlmsg_type = typ;
	hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	memcpy(hdr + 1, data, size);
	m->pos = (char*)(hdr + 1) + NLMSG_ALIGN(size);
}

static void mptcp_nlmsg_attr(struct mptcp_nlmsg* m, int typ, const void* data, int size)
{
	struct nlattr* attr = (struct nlattr*)m->pos;

	if (m->overflow)
		return;
	if (m->pos + NLMSG_ALIGN(sizeof(struct nlattr) + size) > m->buf + sizeof(m->buf)) {
		m->overflow = true;
		return;
	}
	attr->nla_len = sizeof(*attr) + size;
	attr->nla_type = typ;
	if (size > 0)
		memcpy(attr + 1, data, size);
	m->pos += NLMSG_ALIGN(attr->nla_len);
}

// Only SUBFLOW_CREATE/DESTROY payloads nest attributes (GETFAMILY's
// request doesn't), so these two are needed by join_subflow and
// subflow_destroy only -- see MPTCP_NEED_SUBFLOW_CALL.
#if MPTCP_NEED_SUBFLOW_CALL
static void mptcp_nlmsg_nest_begin(struct mptcp_nlmsg* m, struct nlattr** nest_out, int typ)
{
	struct nlattr* attr = (struct nlattr*)m->pos;

	if (m->overflow || m->pos + sizeof(struct nlattr) > m->buf + sizeof(m->buf)) {
		m->overflow = true;
		*nest_out = NULL;
		return;
	}
	attr->nla_type = typ;
	m->pos += sizeof(*attr);
	*nest_out = attr;
}

static void mptcp_nlmsg_nest_end(struct mptcp_nlmsg* m, struct nlattr* nest)
{
	if (!nest)
		return;
	nest->nla_len = m->pos - (char*)nest;
}
#endif // MPTCP_NEED_SUBFLOW_CALL

// Sends m and waits for one reply datagram. Returns the number of bytes
// received (>=0) on success -- for a bare NLM_F_ACK request (our
// SUBFLOW_CREATE/DESTROY calls) that's just the ack, callers only check
// the sign; for a data-bearing reply (GETFAMILY) it's the real payload,
// left in m->buf[0..return value) for the caller to parse. Returns -1
// with errno set on a short write/read or a nonzero NLMSG_ERROR ack.
static int mptcp_nlmsg_send(struct mptcp_nlmsg* m, int sock)
{
	struct nlmsghdr* hdr = (struct nlmsghdr*)m->buf;
	struct sockaddr_nl addr;
	ssize_t n;
	uint32 seq;
	int attempts;

	// A message that overran buf[] was never fully built -- refuse to send
	// a truncated request rather than let the kernel misparse it.
	if (m->overflow) {
		debug("mptcp_nlmsg_send: message overflowed buf\n");
		errno = EMSGSIZE;
		return -1;
	}

	seq = __atomic_add_fetch(&mptcp_nlmsg_seq_ctr, 1, __ATOMIC_RELAXED);
	hdr->nlmsg_len = m->pos - m->buf;
	hdr->nlmsg_seq = seq;
	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;

	// Hold the shared socket for the whole send+recv so a concurrent
	// transaction can't steal our reply (m->buf is per-call stack, only
	// the socket is shared).
	mptcp_spin_lock(&mptcp_nlmsg_lock);
	n = sendto(sock, m->buf, hdr->nlmsg_len, 0, (struct sockaddr*)&addr, sizeof(addr));
	if (n != (ssize_t)hdr->nlmsg_len) {
		mptcp_spin_unlock(&mptcp_nlmsg_lock);
		debug("mptcp_nlmsg_send: short write: %zd/%u errno=%d\n", n, hdr->nlmsg_len, errno);
		return -1;
	}
	// Skip any stale/foreign datagram whose seq doesn't match ours.
	for (attempts = 0; attempts < 8; attempts++) {
		n = recv(sock, m->buf, sizeof(m->buf), 0);
		if (n < (ssize_t)sizeof(struct nlmsghdr)) {
			mptcp_spin_unlock(&mptcp_nlmsg_lock);
			debug("mptcp_nlmsg_send: short read: %zd errno=%d\n", n, errno);
			errno = EINVAL;
			return -1;
		}
		hdr = (struct nlmsghdr*)m->buf;
		if (hdr->nlmsg_seq == seq)
			break;
		debug("mptcp_nlmsg_send: skipping reply seq=%u want=%u\n", hdr->nlmsg_seq, seq);
	}
	mptcp_spin_unlock(&mptcp_nlmsg_lock);
	if (attempts == 8) {
		errno = EINVAL;
		return -1;
	}

	if (hdr->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr* ne = (struct nlmsgerr*)(hdr + 1);

		if (ne->error) {
			errno = -ne->error;
			return -1;
		}
	}
	return (int)n;
}
#endif // MPTCP_NEED_NLMSG

// Needed by (MPTCP_NEED_PM_SETUP): pair_init and join_subflow only --
// the two callers of mptcp_pm_ensure_setup(). subflow_destroy reads
// mptcp_pm_genl_sock/mptcp_pm_family_id directly (see the NLMSG block
// above) but never calls ensure_setup, so it doesn't need these.
#if MPTCP_NEED_PM_SETUP
static int mptcp_pm_setup_done;
static int mptcp_pm_setup_lock; // serializes the one-time setup under -threaded
static int mptcp_pm_event_sock = -1; // held open + subscribed so mptcp_userspace_pm_active() is true
static uint32 mptcp_pm_event_grp_id; // "mptcp_pm_events" mcast group id, for per-join event sockets

// Parse a CTRL_CMD_GETFAMILY reply for the mptcp_pm family id and the id
// of its "mptcp_pm_events" multicast group.
static int mptcp_pm_resolve_family(int sock, uint16* family_id_out, uint32* event_grp_id_out)
{
	struct mptcp_nlmsg m;
	struct genlmsghdr genlhdr;
	uint16 family_id = 0;
	uint32 event_grp_id = 0;
	int n;

	memset(&genlhdr, 0, sizeof(genlhdr));
	genlhdr.cmd = CTRL_CMD_GETFAMILY;
	mptcp_nlmsg_init(&m, GENL_ID_CTRL, &genlhdr, sizeof(genlhdr));
	mptcp_nlmsg_attr(&m, CTRL_ATTR_FAMILY_NAME, MPTCP_PM_NAME, strlen(MPTCP_PM_NAME) + 1);
	n = mptcp_nlmsg_send(&m, sock);
	if (n < 0) {
		debug("mptcp_pm_resolve_family: GETFAMILY: %d\n", errno);
		return -1;
	}

	char* end = m.buf + n;
	struct nlattr* attr = (struct nlattr*)(m.buf + NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(genlhdr)));
	for (; (char*)attr + sizeof(struct nlattr) <= end && (char*)attr + NLMSG_ALIGN(attr->nla_len) <= end;
	     attr = (struct nlattr*)((char*)attr + NLMSG_ALIGN(attr->nla_len))) {
		if ((attr->nla_type & NLA_TYPE_MASK) == CTRL_ATTR_FAMILY_ID) {
			// Guard the 2-byte read like the MCAST_GRP_ID sibling below: a
			// header-only attr at the buffer tail must not be read past.
			if (attr->nla_len < sizeof(struct nlattr) + sizeof(uint16))
				continue;
			family_id = *(uint16*)(attr + 1);
			continue;
		}
		if ((attr->nla_type & NLA_TYPE_MASK) != CTRL_ATTR_MCAST_GROUPS)
			continue;
		// Nested array of unnamed nested attrs, each holding
		// {CTRL_ATTR_MCAST_GRP_NAME, CTRL_ATTR_MCAST_GRP_ID}.
		char* gend = (char*)attr + attr->nla_len;
		char* gpos = (char*)(attr + 1);
		for (; gpos + sizeof(struct nlattr) <= gend;) {
			struct nlattr* grp = (struct nlattr*)gpos;
			if (grp->nla_len < sizeof(struct nlattr) || gpos + grp->nla_len > gend)
				break;
			char* iend = (char*)grp + grp->nla_len;
			char* ipos = (char*)(grp + 1);
			const char* gname = NULL;
			uint32 gid = 0;
			for (; ipos + sizeof(struct nlattr) <= iend;) {
				struct nlattr* inner = (struct nlattr*)ipos;
				if (inner->nla_len < sizeof(struct nlattr) || ipos + inner->nla_len > iend)
					break;
				if ((inner->nla_type & NLA_TYPE_MASK) == CTRL_ATTR_MCAST_GRP_NAME)
					gname = (const char*)(inner + 1);
				else if ((inner->nla_type & NLA_TYPE_MASK) == CTRL_ATTR_MCAST_GRP_ID &&
					 inner->nla_len >= sizeof(struct nlattr) + sizeof(uint32))
					gid = *(uint32*)(inner + 1);
				ipos += NLMSG_ALIGN(inner->nla_len);
			}
			if (gname && strcmp(gname, "mptcp_pm_events") == 0)
				event_grp_id = gid;
			gpos += NLMSG_ALIGN(grp->nla_len);
		}
	}
	recv(sock, m.buf, sizeof(m.buf), 0); // drain the trailing NLM_F_ACK ack

	if (family_id == 0 || event_grp_id == 0) {
		debug("mptcp_pm_resolve_family: parse incomplete (family_id=%d event_grp_id=%d)\n",
		      family_id, event_grp_id);
		errno = ENOENT;
		return -1;
	}
	*family_id_out = family_id;
	*event_grp_id_out = event_grp_id;
	return 0;
}

static int mptcp_pm_ensure_setup(void)
{
	struct sockaddr_nl sa;
	uint32 event_grp_id = 0;
	int sock = -1, event_sock = -1;

	// Fast path once setup has been published.
	if (__atomic_load_n(&mptcp_pm_setup_done, __ATOMIC_ACQUIRE))
		return 0;

	// Serialize first-time setup: exactly one thread does the pm_type write,
	// family resolve and event subscription; others wait and then observe
	// setup_done. Idempotent re-entry from either pair_init or join_subflow.
	mptcp_spin_lock(&mptcp_pm_setup_lock);
	if (mptcp_pm_setup_done) {
		mptcp_spin_unlock(&mptcp_pm_setup_lock);
		return 0;
	}

	if (!write_file("/proc/sys/net/mptcp/pm_type", "1")) {
		debug("mptcp_pm_ensure_setup: write pm_type=1: %d\n", errno);
		goto fail;
	}

	sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (sock < 0) {
		debug("mptcp_pm_ensure_setup: socket(genl): %d\n", errno);
		goto fail;
	}
	// Bound the reply recv in mptcp_nlmsg_send(): it runs while holding
	// mptcp_nlmsg_lock, so a reply that never arrives would wedge every other
	// genl user in this proc. All requests set NLM_F_ACK so a reply is
	// expected; this is a defensive ceiling, not the normal path.
	{
		struct timeval rtv = {2, 0};
		setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &rtv, sizeof(rtv));
	}
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (bind(sock, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
		debug("mptcp_pm_ensure_setup: bind(genl): %d\n", errno);
		goto fail;
	}
	if (mptcp_pm_resolve_family(sock, &mptcp_pm_family_id, &event_grp_id) < 0)
		goto fail;

	event_sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (event_sock < 0) {
		debug("mptcp_pm_ensure_setup: socket(event): %d\n", errno);
		goto fail;
	}
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (bind(event_sock, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
		debug("mptcp_pm_ensure_setup: bind(event): %d\n", errno);
		goto fail;
	}
	if (setsockopt(event_sock, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &event_grp_id, sizeof(event_grp_id)) < 0) {
		debug("mptcp_pm_ensure_setup: NETLINK_ADD_MEMBERSHIP mptcp_pm_events: %d\n", errno);
		goto fail;
	}

	mptcp_pm_genl_sock = sock;
	mptcp_pm_event_sock = event_sock;
	mptcp_pm_event_grp_id = event_grp_id;
	__atomic_store_n(&mptcp_pm_setup_done, 1, __ATOMIC_RELEASE);
	debug("mptcp_pm_ensure_setup: pm_type=1 family_id=%d event_grp_id=%d\n",
	      mptcp_pm_family_id, event_grp_id);
	mptcp_spin_unlock(&mptcp_pm_setup_lock);
	return 0;

fail:
	if (event_sock >= 0)
		close(event_sock);
	if (sock >= 0)
		close(sock);
	mptcp_spin_unlock(&mptcp_pm_setup_lock);
	return -1;
}
#endif // MPTCP_NEED_PM_SETUP

// Needed only by syz_mptcp_join_subflow().
#if SYZ_EXECUTOR || __NR_syz_mptcp_join_subflow
// Send one MPTCP_PM_CMD_SUBFLOW_CREATE and wait for its ack.
//
// Byte-order gotcha (kernel uapi quirk): MPTCP_PM_ADDR_ATTR_ADDR4 is
// network-byte-order in the attribute (the kernel reads it raw via
// nla_get_in_addr), but MPTCP_PM_ADDR_ATTR_PORT is HOST-byte-order --
// the kernel applies htons() itself on the way in
// (net/mptcp/pm_netlink.c, mptcp_pm_parse_addr: `addr->port =
// htons(nla_get_u16(...))`). Passing network order here double-swaps
// the port and aims the MP_JOIN SYN at the wrong port, with no error
// and no debug output -- it just silently never establishes.
static int mptcp_pm_subflow_create(uint32 token, uint8 addr_id, uint32 addr_flags,
				   uint32 local_addr_be, uint16 local_port_h,
				   uint32 remote_addr_be, uint16 remote_port_h)
{
	struct mptcp_nlmsg m;
	struct genlmsghdr genlhdr;
	struct nlattr* nest;
	uint16 fam_v = AF_INET;

	memset(&genlhdr, 0, sizeof(genlhdr));
	genlhdr.cmd = MPTCP_PM_CMD_SUBFLOW_CREATE;
	genlhdr.version = MPTCP_PM_VER;
	mptcp_nlmsg_init(&m, mptcp_pm_family_id, &genlhdr, sizeof(genlhdr));
	mptcp_nlmsg_attr(&m, MPTCP_PM_ATTR_TOKEN, &token, sizeof(token));

	// MPTCP_PM_ATTR_ADDR: the new subflow's local endpoint. FLAGS is
	// only included when non-zero (the NORMAL/backup=0 path omits it
	// entirely, matching the shape a hand-written ip-mptcp(8) call
	// would send).
	mptcp_nlmsg_nest_begin(&m, &nest, MPTCP_PM_ATTR_ADDR | NLA_F_NESTED);
	mptcp_nlmsg_attr(&m, MPTCP_PM_ADDR_ATTR_FAMILY, &fam_v, sizeof(fam_v));
	mptcp_nlmsg_attr(&m, MPTCP_PM_ADDR_ATTR_ID, &addr_id, sizeof(addr_id));
	mptcp_nlmsg_attr(&m, MPTCP_PM_ADDR_ATTR_ADDR4, &local_addr_be, sizeof(local_addr_be));
	mptcp_nlmsg_attr(&m, MPTCP_PM_ADDR_ATTR_PORT, &local_port_h, sizeof(local_port_h));
	if (addr_flags)
		mptcp_nlmsg_attr(&m, MPTCP_PM_ADDR_ATTR_FLAGS, &addr_flags, sizeof(addr_flags));
	mptcp_nlmsg_nest_end(&m, nest);

	// MPTCP_PM_ATTR_ADDR_REMOTE: where the new subflow connects to.
	mptcp_nlmsg_nest_begin(&m, &nest, MPTCP_PM_ATTR_ADDR_REMOTE | NLA_F_NESTED);
	mptcp_nlmsg_attr(&m, MPTCP_PM_ADDR_ATTR_FAMILY, &fam_v, sizeof(fam_v));
	mptcp_nlmsg_attr(&m, MPTCP_PM_ADDR_ATTR_ADDR4, &remote_addr_be, sizeof(remote_addr_be));
	mptcp_nlmsg_attr(&m, MPTCP_PM_ADDR_ATTR_PORT, &remote_port_h, sizeof(remote_port_h));
	mptcp_nlmsg_nest_end(&m, nest);

	return mptcp_nlmsg_send(&m, mptcp_pm_genl_sock);
}
#endif // __NR_syz_mptcp_join_subflow

// Needed only by syz_mptcp_subflow_destroy().
#if SYZ_EXECUTOR || __NR_syz_mptcp_subflow_destroy
// MPTCP_PM_CMD_SUBFLOW_DESTROY: same nested-address payload shape as
// SUBFLOW_CREATE, no flags attr. The kernel looks the subflow up by
// exact (local addr+port, remote addr+port) tuple on the msk identified
// by token (mptcp_nl_find_ssk() in net/mptcp/pm_userspace.c) -- which is
// why syz_mptcp_join_subflow() commits to a specific local port instead
// of letting the kernel pick one, and why syz_mptcp_subflow_slot keeps
// both ports around for this call to reconstruct the tuple.
static int mptcp_pm_subflow_destroy(uint32 token, uint8 addr_id,
				    uint32 local_addr_be, uint16 local_port_h,
				    uint32 remote_addr_be, uint16 remote_port_h)
{
	struct mptcp_nlmsg m;
	struct genlmsghdr genlhdr;
	struct nlattr* nest;
	uint16 fam_v = AF_INET;

	memset(&genlhdr, 0, sizeof(genlhdr));
	genlhdr.cmd = MPTCP_PM_CMD_SUBFLOW_DESTROY;
	genlhdr.version = MPTCP_PM_VER;
	mptcp_nlmsg_init(&m, mptcp_pm_family_id, &genlhdr, sizeof(genlhdr));
	mptcp_nlmsg_attr(&m, MPTCP_PM_ATTR_TOKEN, &token, sizeof(token));

	mptcp_nlmsg_nest_begin(&m, &nest, MPTCP_PM_ATTR_ADDR | NLA_F_NESTED);
	mptcp_nlmsg_attr(&m, MPTCP_PM_ADDR_ATTR_FAMILY, &fam_v, sizeof(fam_v));
	mptcp_nlmsg_attr(&m, MPTCP_PM_ADDR_ATTR_ID, &addr_id, sizeof(addr_id));
	mptcp_nlmsg_attr(&m, MPTCP_PM_ADDR_ATTR_ADDR4, &local_addr_be, sizeof(local_addr_be));
	mptcp_nlmsg_attr(&m, MPTCP_PM_ADDR_ATTR_PORT, &local_port_h, sizeof(local_port_h));
	mptcp_nlmsg_nest_end(&m, nest);

	mptcp_nlmsg_nest_begin(&m, &nest, MPTCP_PM_ATTR_ADDR_REMOTE | NLA_F_NESTED);
	mptcp_nlmsg_attr(&m, MPTCP_PM_ADDR_ATTR_FAMILY, &fam_v, sizeof(fam_v));
	mptcp_nlmsg_attr(&m, MPTCP_PM_ADDR_ATTR_ADDR4, &remote_addr_be, sizeof(remote_addr_be));
	mptcp_nlmsg_attr(&m, MPTCP_PM_ADDR_ATTR_PORT, &remote_port_h, sizeof(remote_port_h));
	mptcp_nlmsg_nest_end(&m, nest);

	return mptcp_nlmsg_send(&m, mptcp_pm_genl_sock);
}
#endif // __NR_syz_mptcp_subflow_destroy

#if SYZ_EXECUTOR || __NR_syz_mptcp_pair_init
// Parse a captured IP packet for an MP_CAPABLE option carrying both keys (the
// third ACK). Verified against the kernel token in test_wire_key_capture.c.
static int mptcp_parse_mpcapable(const uint8* pkt, int len, uint64* sndr, uint64* rcvr)
{
	if (len < (int)sizeof(struct iphdr))
		return 0;
	const struct iphdr* ip = (const struct iphdr*)pkt;
	if (ip->protocol != IPPROTO_TCP)
		return 0;
	int ihl = ip->ihl * 4;
	if (len < ihl + (int)sizeof(struct tcphdr))
		return 0;
	const struct tcphdr* th = (const struct tcphdr*)(pkt + ihl);
	int thl = th->doff * 4;
	if (len < ihl + thl)
		return 0;
	const uint8* o = pkt + ihl + sizeof(struct tcphdr);
	const uint8* end = pkt + ihl + thl;
	while (o < end) {
		uint8 kind = o[0];
		if (kind == 0)
			break;
		if (kind == 1) {
			o++;
			continue;
		}
		if (o + 1 >= end)
			break;
		uint8 olen = o[1];
		if (olen < 2 || o + olen > end)
			break;
		if (kind == 30 && (o[2] >> 4) == 0 && olen >= 20) {
			uint64 sk, rk;
			memcpy(&sk, o + 4, 8);
			memcpy(&rk, o + 12, 8);
			*sndr = be64toh(sk);
			*rcvr = be64toh(rk);
			return 1;
		}
		o += olen;
	}
	return 0;
}

static long syz_mptcp_pair_init(volatile long a0, volatile long a1, volatile long a2)
{
	// server_addr / client_addr: not yet consulted, see file comment.
	(void)a0;
	(void)a1;
	unsigned long init_flags = (unsigned long)a2;

	struct sockaddr_in srv_addr;
	socklen_t alen;
	int slot;
	int one = 1;
	int server_listen_fd = -1, client_fd = -1, server_fd = -1, cap_fd = -1;

	// Claim a free slot atomically: mark in_use with a compare-exchange so
	// two pair_init calls running on separate threads (the default
	// -threaded execution model) can never settle on the same slot. The
	// slot is held from here; every failure path below releases it (goto
	// fail). Bump the generation immediately after claiming -- before any
	// other field is written -- to minimize the window a stale
	// subflow_destroy can race into. That window is not zero: in_use=true is
	// published by the claim before the generation bump lands, so a stale
	// destroy can briefly see in_use=true AND the old generation still
	// matching its pair_generation, and pass its staleness guard. It is
	// benign, because in that window pair->token is still 0 (zeroed by the
	// prior syz_mptcp_pair_close, not yet re-set by this call), so the genl
	// DESTROY it issues targets a non-existent token and the kernel rejects
	// it (ENOENT) -- no live subflow is destroyed. Once the bumped
	// generation is visible the mismatch rejects the stale destroy outright.
	for (slot = 0; slot < MPTCP_PAIR_POOL_SIZE; slot++) {
		bool expected = false;
		if (__atomic_compare_exchange_n(&syz_mptcp_pair_pool[slot].in_use,
						&expected, true, false,
						__ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
			break;
	}
	if (slot == MPTCP_PAIR_POOL_SIZE) {
		debug("syz_mptcp_pair_init: pool exhausted (size=%d)\n",
		      MPTCP_PAIR_POOL_SIZE);
		return -1;
	}
	// Release store (paired with the acquire loads in syz_mptcp_subflow_destroy
	// and at join time) so the bump establishes happens-before and is not a
	// plain-int data race on the shared pool.
	__atomic_store_n(&syz_mptcp_pair_pool[slot].generation,
			 __atomic_load_n(&syz_mptcp_pair_pool[slot].generation, __ATOMIC_RELAXED) + 1,
			 __ATOMIC_RELEASE);

	// Must run before either endpoint's socket(IPPROTO_MPTCP) call --
	// see the "Userspace path-manager setup" comment above
	// mptcp_pm_ensure_setup() for why pm_type has to be set before the
	// msk exists, not merely before a later join.
	if (mptcp_pm_ensure_setup() < 0) {
		debug("syz_mptcp_pair_init: userspace-PM setup failed\n");
		goto fail;
	}

	server_listen_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);
	if (server_listen_fd < 0) {
		debug("syz_mptcp_pair_init: server socket: %d\n", errno);
		goto fail;
	}
	setsockopt(server_listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	memset(&srv_addr, 0, sizeof(srv_addr));
	srv_addr.sin_family = AF_INET;
	srv_addr.sin_port = 0; // let the kernel pick an ephemeral port
	srv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(server_listen_fd, (struct sockaddr*)&srv_addr, sizeof(srv_addr)) < 0) {
		debug("syz_mptcp_pair_init: bind: %d\n", errno);
		goto fail;
	}
	alen = sizeof(srv_addr);
	if (getsockname(server_listen_fd, (struct sockaddr*)&srv_addr, &alen) < 0) {
		debug("syz_mptcp_pair_init: getsockname: %d\n", errno);
		goto fail;
	}
	if (init_flags & MPTCP_INIT_RWND_CLAMP) {
		// Pin the receiver window small on the listener BEFORE listen() so the
		// accepted msk inherits a small window_clamp from its first
		// advertisement; re-applied on the accepted fd post-accept below.
		int rcvbuf = MPTCP_CLAMP_RCVBUF;
		setsockopt(server_listen_fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
	}
	if (listen(server_listen_fd, 1) < 0) {
		debug("syz_mptcp_pair_init: listen: %d\n", errno);
		goto fail;
	}

	if (init_flags & MPTCP_INIT_CAPTURE_KEYS) {
		// Open the loopback capture BEFORE connect() so the handshake is buffered.
		cap_fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
		if (cap_fd >= 0) {
			struct sockaddr_ll sll;
			memset(&sll, 0, sizeof(sll));
			sll.sll_family = AF_PACKET;
			sll.sll_protocol = htons(ETH_P_IP);
			sll.sll_ifindex = if_nametoindex("lo");
			if (bind(cap_fd, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
				close(cap_fd);
				cap_fd = -1;
			}
		}
	}

	client_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);
	if (client_fd < 0) {
		debug("syz_mptcp_pair_init: client socket: %d\n", errno);
		goto fail;
	}
	if (connect(client_fd, (struct sockaddr*)&srv_addr, sizeof(srv_addr)) < 0) {
		debug("syz_mptcp_pair_init: connect: %d\n", errno);
		goto fail;
	}
	server_fd = accept(server_listen_fd, NULL, NULL);
	if (server_fd < 0) {
		debug("syz_mptcp_pair_init: accept: %d\n", errno);
		goto fail;
	}
	if (init_flags & MPTCP_INIT_RWND_CLAMP) {
		int rcvbuf = MPTCP_CLAMP_RCVBUF;
		setsockopt(server_fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
	}
	// The listener stays open and bound for the rest of the pair's
	// lifetime -- see the server_listen_fd comment on
	// struct syz_mptcp_pair_slot for why an MP_JOIN increment can't
	// close it after the first accept() the way a MP_CAPABLE-only
	// v0 could.

	// Drive a 1-byte round-trip to force the CLIENT-side msk into
	// fully_established. After a bare connect()+accept(), the SERVER
	// msk is already fully_established (set in mptcp_sock_create_accept
	// on third-ACK receipt), but the CLIENT msk is not --
	// check_fully_established (net/mptcp/options.c) only flips the
	// client side when an inbound DSS/use_ack packet arrives. Any later
	// caller that needs a fully_established msk on either side (e.g. a
	// future MP_JOIN increment, which fails at __mptcp_subflow_connect
	// with -ENOTCONN otherwise) would be one directional send away from
	// working by accident; doing both directions here makes the pair
	// unconditionally usable regardless of which side is driven next.
	{
		char b = 'x';
		ssize_t n;

		n = send(client_fd, &b, 1, 0);
		if (n != 1) {
			debug("syz_mptcp_pair_init: prime send c->s: %d\n", errno);
			goto fail;
		}
		n = recv(server_fd, &b, 1, MSG_WAITALL);
		if (n != 1) {
			debug("syz_mptcp_pair_init: prime recv on s: %d\n", errno);
			goto fail;
		}
		n = send(server_fd, &b, 1, 0);
		if (n != 1) {
			debug("syz_mptcp_pair_init: prime send s->c: %d\n", errno);
			goto fail;
		}
		n = recv(client_fd, &b, 1, MSG_WAITALL);
		if (n != 1) {
			debug("syz_mptcp_pair_init: prime recv on c: %d\n", errno);
			goto fail;
		}
	}

	if (cap_fd >= 0) {
		struct timeval tv = {0, 100000};
		setsockopt(cap_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		char cbuf[2048];
		for (int i = 0; i < 100; i++) {
			ssize_t cn = recv(cap_fd, cbuf, sizeof(cbuf), 0);
			if (cn <= 0)
				break;
			uint64 sk, rk;
			if (mptcp_parse_mpcapable((const uint8*)cbuf, (int)cn, &sk, &rk)) {
				syz_mptcp_pair_pool[slot].local_key = sk;
				syz_mptcp_pair_pool[slot].remote_key = rk;
				syz_mptcp_pair_pool[slot].keys_valid = true;
			}
		}
		close(cap_fd);
		cap_fd = -1;
		debug("syz_mptcp_pair_init: captured keys local=0x%llx remote=0x%llx\n",
		      (unsigned long long)syz_mptcp_pair_pool[slot].local_key,
		      (unsigned long long)syz_mptcp_pair_pool[slot].remote_key);
	}

	// Capture the CLIENT msk's own token via the standard MPTCP_INFO
	// sockopt (stock uapi, no kernel patch needed) -- this is what lets
	// a later syz_mptcp_join_subflow() identify which msk to open a new
	// subflow from. Treated as fatal: a pair resource whose token we
	// failed to capture can never be joined, so failing loudly here
	// beats returning a resource that silently can't support the
	// producer edge it exists to support.
	{
		struct syz_mptcp_info_short info;
		socklen_t ilen = sizeof(info);

		memset(&info, 0, sizeof(info));
		if (getsockopt(client_fd, SOL_MPTCP, MPTCP_INFO, &info, &ilen) < 0) {
			debug("syz_mptcp_pair_init: MPTCP_INFO: %d\n", errno);
			goto fail;
		}
		syz_mptcp_pair_pool[slot].token = info.mptcpi_token;
	}

	// in_use was already published by the atomic claim above; fill the rest
	// of the slot before returning. The consuming calls (join/close) can
	// only reach this slot via the resource this call returns, so no
	// additional barrier is needed for these fields.
	syz_mptcp_pair_pool[slot].server_fd = server_fd;
	syz_mptcp_pair_pool[slot].client_fd = client_fd;
	syz_mptcp_pair_pool[slot].server_listen_fd = server_listen_fd;
	syz_mptcp_pair_pool[slot].server_port_h = ntohs(srv_addr.sin_port);
	syz_mptcp_pair_pool[slot].rwnd_clamped = (init_flags & MPTCP_INIT_RWND_CLAMP) != 0;
	debug("syz_mptcp_pair_init: pair %d established, port %d, token %u gen %u\n",
	      slot, ntohs(srv_addr.sin_port), syz_mptcp_pair_pool[slot].token,
	      syz_mptcp_pair_pool[slot].generation);
	return slot;

fail:
	if (server_fd >= 0)
		close(server_fd);
	if (client_fd >= 0)
		close(client_fd);
	if (server_listen_fd >= 0)
		close(server_listen_fd);
	if (cap_fd >= 0)
		close(cap_fd);
	// Release the slot claimed above (generation stays bumped -- it only
	// ever has to increase, and a burned number is harmless).
	__atomic_store_n(&syz_mptcp_pair_pool[slot].in_use, false, __ATOMIC_RELEASE);
	return -1;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_mptcp_pair_close
static long syz_mptcp_pair_close(volatile long a0)
{
	long slot = a0;

	if (slot < 0 || slot >= MPTCP_PAIR_POOL_SIZE) {
		debug("syz_mptcp_pair_close: slot %ld out of range\n", slot);
		return -1;
	}
	if (!syz_mptcp_pair_pool[slot].in_use) {
		debug("syz_mptcp_pair_close: slot %ld not in use\n", slot);
		return -1;
	}
	if (syz_mptcp_pair_pool[slot].server_listen_fd >= 0)
		close(syz_mptcp_pair_pool[slot].server_listen_fd);
	if (syz_mptcp_pair_pool[slot].server_fd >= 0)
		close(syz_mptcp_pair_pool[slot].server_fd);
	if (syz_mptcp_pair_pool[slot].client_fd >= 0)
		close(syz_mptcp_pair_pool[slot].client_fd);
	// Clear the slot but PRESERVE generation (a reused slot must always get
	// a strictly newer value -- see syz_mptcp_pair_slot.generation), then
	// publish in_use=false LAST with a release store so a concurrent
	// pair_init claiming this slot only observes it free once fully cleared.
	syz_mptcp_pair_pool[slot].server_fd = 0;
	syz_mptcp_pair_pool[slot].client_fd = 0;
	syz_mptcp_pair_pool[slot].server_listen_fd = 0;
	syz_mptcp_pair_pool[slot].token = 0;
	syz_mptcp_pair_pool[slot].server_port_h = 0;
	syz_mptcp_pair_pool[slot].rwnd_clamped = false;
	// Reset captured keys so a slot reused by a later pair_init whose capture
	// does not complete cannot hand a consumer the previous occupant's keys.
	syz_mptcp_pair_pool[slot].local_key = 0;
	syz_mptcp_pair_pool[slot].remote_key = 0;
	syz_mptcp_pair_pool[slot].keys_valid = false;
	__atomic_store_n(&syz_mptcp_pair_pool[slot].in_use, false, __ATOMIC_RELEASE);
	return 0;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_mptcp_join_subflow

// The MPTCP_EVENT_SUB_ESTABLISHED / MPTCP_ATTR_* values used below are mirrored
// with the other uapi enums under the MPTCP_PM_NAME sentinel near the top of
// this file.

// Read the auto-assigned local port back from the SUB_ESTABLISHED event, so
// syz_mptcp_subflow_destroy() can address the exact 4-tuple. Match on the
// (client) msk token + this subflow's distinct local address (saddr4, network
// order) -- the address pins THIS subflow even if a concurrent join reused the
// addr_id. evfd must already be bound and subscribed to the events mcast group.
// Bounded by a ~2s wall-clock deadline (NOT a message count) so a burst of
// foreign events from concurrent MPTCP activity in this netns can't starve the
// wait. Returns 0 and *sport_out on success, -1 on timeout.
static int mptcp_pm_recv_subflow_sport(int evfd, uint32 token, uint32 saddr4_be, uint16* sport_out)
{
	char ebuf[2048];
	struct timespec start, cur;

	clock_gettime(CLOCK_MONOTONIC, &start);
	for (;;) {
		clock_gettime(CLOCK_MONOTONIC, &cur);
		if ((cur.tv_sec - start.tv_sec) * 1000 + (cur.tv_nsec - start.tv_nsec) / 1000000 > 2000)
			return -1;
		ssize_t n = recv(evfd, ebuf, sizeof(ebuf), 0);
		if (n < 0)
			continue; // SO_RCVTIMEO tick (EAGAIN) or transient; the deadline bounds us
		int len = (int)n; // signed: NLMSG_OK/NEXT underflow on an unaligned tail otherwise
		struct nlmsghdr* nlh = (struct nlmsghdr*)ebuf;
		for (; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
			if (nlh->nlmsg_len < NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(struct genlmsghdr)))
				continue;
			struct genlmsghdr* gh = (struct genlmsghdr*)NLMSG_DATA(nlh);
			if (gh->cmd != MPTCP_EVENT_SUB_ESTABLISHED)
				continue;
			char* a = (char*)nlh + NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(struct genlmsghdr));
			char* aend = (char*)nlh + nlh->nlmsg_len;
			uint32 ev_token = 0, ev_saddr4 = 0;
			uint16 ev_sport = 0;
			int have_token = 0, have_sport = 0, have_saddr4 = 0;
			while (a + sizeof(struct nlattr) <= aend) {
				struct nlattr* at = (struct nlattr*)a;
				if (at->nla_len < sizeof(struct nlattr) || a + NLMSG_ALIGN(at->nla_len) > aend)
					break;
				void* d = a + NLA_HDRLEN;
				int dlen = (int)at->nla_len - NLA_HDRLEN;
				uint16 ty = at->nla_type & NLA_TYPE_MASK;
				if (ty == MPTCP_ATTR_TOKEN && dlen >= (int)sizeof(uint32)) {
					ev_token = *(uint32*)d;
					have_token = 1;
				} else if (ty == MPTCP_ATTR_SADDR4 && dlen >= (int)sizeof(uint32)) {
					ev_saddr4 = *(uint32*)d; // network order, as sent
					have_saddr4 = 1;
				} else if (ty == MPTCP_ATTR_SPORT && dlen >= (int)sizeof(uint16)) {
					ev_sport = *(uint16*)d;
					have_sport = 1;
				}
				a += NLMSG_ALIGN(at->nla_len);
			}
			if (have_token && have_sport && ev_token == token &&
			    (!have_saddr4 || ev_saddr4 == saddr4_be)) {
				// MPTCP_ATTR_SPORT is network byte order in the event
				// (nla_put_be16 of inet_sport); DESTROY's PORT attr is
				// host order, so convert here.
				*sport_out = ntohs(ev_sport);
				return 0;
			}
		}
	}
}

/*
 * NORMAL-mode MP_JOIN (see the file comment for the mechanism and scope).
 *
 * addr_id 0 is rejected by the kernel ("invalid addr id" in
 * mptcp_userspace_pm_append_new_local_addr, net/mptcp/pm_userspace.c);
 * so 0 is coerced to 1 here and any other value passes through unchanged.
 * (syzlang int8 carries no signedness; the value is just the low byte of a2.)
 */
static long syz_mptcp_join_subflow(volatile long a0, volatile long a1, volatile long a2, volatile long a3)
{
	long pair_slot = a0;
	uint8 addr_id = (uint8)a1;
	uint8 backup = (uint8)a2; // syzlang clamps to [0:1]
	int mut_op = (int)a3; // MPTCP_MUT_* -- 0 (NONE) leaves the join unmutated
	struct syz_mptcp_pair_slot* pair;
	uint32 local_addr_be; // this subflow's distinct per-slot local address (set below)
	const uint32 remote_addr_be = htonl(0x7f000001); // 127.0.0.1: the pair's server
	uint32 addr_flags;
	uint16 local_port_h;
	int sub_slot;
	int retries;
	int evfd = -1;

	if (pair_slot < 0 || pair_slot >= MPTCP_PAIR_POOL_SIZE) {
		debug("syz_mptcp_join_subflow: pair slot %ld out of range\n", pair_slot);
		return -1;
	}
	pair = &syz_mptcp_pair_pool[pair_slot];
	if (!pair->in_use) {
		debug("syz_mptcp_join_subflow: pair slot %ld not in use\n", pair_slot);
		return -1;
	}

	// Idempotent -- syz_mptcp_pair_init() already ran this for the
	// common case, but a C reproducer could in principle call this
	// pseudo-syscall path without going back through pair_init's own
	// copy of the check (it can't, in practice: the pair resource this
	// call consumes can only come from pair_init, so pair_init's call
	// already ran). Kept for direct-re-entry safety per the file
	// comment above mptcp_pm_ensure_setup().
	if (mptcp_pm_ensure_setup() < 0)
		return -1;

	if (addr_id == 0)
		addr_id = 1;

	// Atomic claim, same rationale as the pair pool: two join calls on
	// separate threads must not settle on the same subflow slot. Held from
	// here; the SUBFLOW_CREATE and poll failure paths below release it.
	for (sub_slot = 0; sub_slot < MPTCP_SUBFLOW_POOL_SIZE; sub_slot++) {
		bool expected = false;
		if (__atomic_compare_exchange_n(&syz_mptcp_subflow_pool[sub_slot].in_use,
						&expected, true, false,
						__ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
			break;
	}
	if (sub_slot == MPTCP_SUBFLOW_POOL_SIZE) {
		debug("syz_mptcp_join_subflow: subflow pool exhausted (size=%d)\n",
		      MPTCP_SUBFLOW_POOL_SIZE);
		return -1;
	}

	// addr_flags: SUBFLOW is forced unconditionally by the kernel
	// handler regardless of what we send (mptcp_pm_nl_subflow_create_doit
	// ORs it in); SIGNAL is rejected outright. BACKUP is the only flag
	// this pseudo-syscall exposes, via the syzlang `backup` parameter.
	addr_flags = backup ? MPTCP_PM_ADDR_FLAG_BACKUP : 0;

	// Distinct local address per subflow slot (127.0.0.2 + slot). The kernel's
	// userspace PM (mptcp_userspace_pm_append_new_local_addr) compares the local
	// address WITH port, so with port 0 every subflow would present 127.0.0.2:0
	// and a second join on the same pair with a different addr_id would be
	// rejected -EINVAL -- breaking concurrent multi-subflow. A per-slot address
	// keeps concurrent subflows distinct; stored on the slot for DESTROY.
	local_addr_be = htonl(0x7f000002 + (uint32)sub_slot);

	// Let the kernel auto-assign the subflow's local port (port 0): it tracks
	// TIME_WAIT and never reuses a cooling-down port, so a repeated program
	// (syzkaller repeat mode / a C-reproducer loop) can't hit EADDRINUSE the way
	// a fixed port does. We read the chosen port back from the SUB_ESTABLISHED
	// event for DESTROY. Subscribe a fresh events socket BEFORE SUBFLOW_CREATE so
	// the notification can't be missed. If that can't be set up, fall back to a
	// procid+slot-scoped fixed port (below the ephemeral floor; repeat-mode may
	// then EADDRINUSE, but the common single-run case still works).
	local_port_h = 0;
	evfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (evfd >= 0) {
		struct sockaddr_nl esa;
		struct timeval rtv = {0, 100000};
		memset(&esa, 0, sizeof(esa));
		esa.nl_family = AF_NETLINK;
		if (bind(evfd, (struct sockaddr*)&esa, sizeof(esa)) < 0 ||
		    setsockopt(evfd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
			       &mptcp_pm_event_grp_id, sizeof(mptcp_pm_event_grp_id)) < 0) {
			close(evfd);
			evfd = -1;
		} else {
			setsockopt(evfd, SOL_SOCKET, SO_RCVTIMEO, &rtv, sizeof(rtv));
		}
	}
	if (evfd < 0)
		local_port_h = MPTCP_SUBFLOW_LOCAL_PORT_BASE +
			       (int)procid * MPTCP_SUBFLOW_POOL_SIZE + sub_slot;

	// Mutation (increment 3): if requested, install the NFQUEUE interceptor and
	// publish the instruction (keyed on this subflow's per-slot source address)
	// BEFORE SUBFLOW_CREATE fires the SYN, so the worker catches the egress
	// MP_JOIN ACK and applies the op. Retired on every exit path below. With a
	// HMAC-corrupting op the kernel rejects the subflow, so the establishment
	// poll below times out and the join returns -1 (expected -- the value is the
	// exercised crypto-failure path, not a live subflow).
	if (mut_op != MPTCP_MUT_NONE) {
		syz_nfq_hook = syz_mptcp_mut_hook; // set before setup (engine contract)
		if (syz_nfq_setup() != 0) {
			// A requested mutation that cannot be installed must NOT masquerade
			// as a clean join (that would hide a broken mutation environment and
			// silently defeat repro-by-construction). Fail the call loudly.
			debug("syz_mptcp_join_subflow: NFQUEUE setup failed; failing the mutated join\n");
			if (evfd >= 0)
				close(evfd);
			__atomic_store_n(&syz_mptcp_subflow_pool[sub_slot].in_use, false, __ATOMIC_RELEASE);
			return -1;
		}
		syz_mptcp_mut_publish(local_addr_be, mut_op);
	}

	if (mptcp_pm_subflow_create(pair->token, addr_id, addr_flags,
				    local_addr_be, local_port_h,
				    remote_addr_be, pair->server_port_h) < 0) {
		debug("syz_mptcp_join_subflow: SUBFLOW_CREATE: %d\n", errno);
		if (evfd >= 0)
			close(evfd);
		if (mut_op != MPTCP_MUT_NONE)
			syz_mptcp_mut_retire();
		__atomic_store_n(&syz_mptcp_subflow_pool[sub_slot].in_use, false, __ATOMIC_RELEASE);
		return -1;
	}

	// SUBFLOW_CREATE returns once __mptcp_subflow_connect() has fired
	// the SYN; the server-side msk's subflow count then increments once
	// the kernel's MPTCP option parser accepts the incoming MP_JOIN
	// (mptcp_pm_allow_new_subflow path). Poll MPTCP_INFO with a ~1s
	// ceiling -- a loopback handshake completes in well under that.
	for (retries = 0; retries < MPTCP_SUBFLOW_INFO_MAX_RETRIES; retries++) {
		struct syz_mptcp_info_short info;
		socklen_t ilen = sizeof(info);

		memset(&info, 0, sizeof(info));
		if (getsockopt(pair->server_fd, SOL_MPTCP, MPTCP_INFO, &info, &ilen) == 0 &&
		    info.mptcpi_subflows >= 1)
			break;
		usleep(50000); // 50ms
	}
	if (retries == MPTCP_SUBFLOW_INFO_MAX_RETRIES) {
		debug("syz_mptcp_join_subflow: pair=%ld subflow not established within ~1s\n",
		      pair_slot);
		if (evfd >= 0)
			close(evfd);
		if (mut_op != MPTCP_MUT_NONE)
			syz_mptcp_mut_retire();
		__atomic_store_n(&syz_mptcp_subflow_pool[sub_slot].in_use, false, __ATOMIC_RELEASE);
		return -1;
	}

	// Read the kernel-assigned local port back from the SUB_ESTABLISHED event
	// (only when we used port 0, i.e. evfd is up), matched by this subflow's
	// distinct local address. On failure local_port_h stays 0; a later DESTROY
	// with port 0 is rejected by the kernel at parse (EINVAL, "missing local
	// port") and the slot bookkeeping is freed either way. Braces on both arms
	// are load-bearing: csource strips the debug() line, and without them the
	// following close(evfd) would bind to the else and leak the fd on success.
	if (evfd >= 0) {
		uint16 sport = 0;
		if (mptcp_pm_recv_subflow_sport(evfd, pair->token, local_addr_be, &sport) == 0) {
			local_port_h = sport;
		} else {
			debug("syz_mptcp_join_subflow: pair=%ld no SUB_ESTABLISHED sport (DESTROY rejected, slot freed)\n",
			      pair_slot);
		}
		close(evfd);
		evfd = -1;
	}

	// The egress ACK has been sent (and mutated, if requested) by now; retire the
	// instruction so a later join reusing this per-slot address isn't corrupted.
	if (mut_op != MPTCP_MUT_NONE)
		syz_mptcp_mut_retire();

	// in_use already published by the atomic claim above. Record the
	// parent's current generation so a later destroy can detect slot reuse.
	syz_mptcp_subflow_pool[sub_slot].pair_slot = (int)pair_slot;
	syz_mptcp_subflow_pool[sub_slot].pair_generation =
	    __atomic_load_n(&pair->generation, __ATOMIC_ACQUIRE);
	syz_mptcp_subflow_pool[sub_slot].addr_id = addr_id;
	syz_mptcp_subflow_pool[sub_slot].local_addr_be = local_addr_be;
	syz_mptcp_subflow_pool[sub_slot].local_port_h = local_port_h;
	syz_mptcp_subflow_pool[sub_slot].remote_port_h = pair->server_port_h;
	debug("syz_mptcp_join_subflow: pair=%ld subflow=%d established "
	      "(addr_id=%u backup=%u local_port=%u)\n",
	      pair_slot, sub_slot, addr_id, backup, local_port_h);
	return sub_slot;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_mptcp_subflow_destroy
static long syz_mptcp_subflow_destroy(volatile long a0)
{
	long sub_slot = a0;
	long err = 0;
	struct syz_mptcp_subflow_slot* sub;
	struct syz_mptcp_pair_slot* pair;
	const uint32 remote_addr_be = htonl(0x7f000001);

	if (sub_slot < 0 || sub_slot >= MPTCP_SUBFLOW_POOL_SIZE) {
		debug("syz_mptcp_subflow_destroy: slot %ld out of range\n", sub_slot);
		return -1;
	}
	sub = &syz_mptcp_subflow_pool[sub_slot];
	if (!__atomic_load_n(&sub->in_use, __ATOMIC_ACQUIRE)) {
		debug("syz_mptcp_subflow_destroy: slot %ld not in use\n", sub_slot);
		return -1;
	}

	pair = &syz_mptcp_pair_pool[sub->pair_slot];
	if (!__atomic_load_n(&pair->in_use, __ATOMIC_ACQUIRE) ||
	    __atomic_load_n(&pair->generation, __ATOMIC_ACQUIRE) != sub->pair_generation) {
		// Parent pair already gone, OR its pool slot was closed and
		// REUSED by a different pair (generation mismatch): either way
		// this subflow no longer maps to a live kernel object we may
		// address. Issuing a genl DESTROY now would, in the reuse case,
		// target the NEW occupant's token with our stale tuple -- so
		// just free our own bookkeeping. (Closing a pair tears its
		// subflows down kernel-side already.)
		debug("syz_mptcp_subflow_destroy: slot %ld parent pair %d stale "
		      "(in_use=%d gen have=%u want=%u), freeing bookkeeping only\n",
		      sub_slot, sub->pair_slot, pair->in_use,
		      pair->generation, sub->pair_generation);
		goto free_slot;
	}

	if (mptcp_pm_subflow_destroy(pair->token, sub->addr_id,
				     sub->local_addr_be, sub->local_port_h,
				     remote_addr_be, sub->remote_port_h) < 0) {
		// Free the bookkeeping even on genl failure: this subflow slot is a
		// syzkaller resource consumed by the call regardless, and a DESTROY
		// error usually means the kernel object is already gone. Leaving
		// in_use set would leak the slot -- for the rest of the program under
		// the fork server, or for the whole process in a fork-serverless C
		// reproducer. Signal the error through the return value but still
		// release the slot via free_slot.
		debug("syz_mptcp_subflow_destroy: SUBFLOW_DESTROY: %d\n", errno);
		err = -1;
		goto free_slot;
	}

free_slot:
	// Clear fields, then publish in_use=false LAST (release store) so a
	// concurrent join claiming this slot only sees it free once cleared.
	sub->pair_slot = 0;
	sub->pair_generation = 0;
	sub->addr_id = 0;
	sub->local_port_h = 0;
	sub->remote_port_h = 0;
	__atomic_store_n(&sub->in_use, false, __ATOMIC_RELEASE);
	return err;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_mptcp_subflow_info
// Non-consuming lifecycle op (op-set increment 1): name a LIVE subflow WITHOUT
// destroying it. This proves the resource model supports operations other than
// syz_mptcp_subflow_destroy on an mptcp_subflow handle -- the basis for the
// adversarial multi-subflow lifecycle orderings this op set is built for
// (syzkaller can now pile ops on a still-live subflow before teardown, e.g.
// info/traffic then a racing close). It validates the handle maps to an in-use
// slot whose parent pair is still live (same generation -- the stale/reuse guard
// mirrors syz_mptcp_subflow_destroy), then does a benign MPTCP_INFO getsockopt on
// the parent msk to confirm it is alive, and reports the current subflow count.
// It NEVER frees the slot: the subflow stays addressable for later ops.
static long syz_mptcp_subflow_info(volatile long a0)
{
	long sub_slot = a0;
	struct syz_mptcp_subflow_slot* sub;
	struct syz_mptcp_pair_slot* pair;
	uint8 info[128];
	socklen_t len = sizeof(info);

	if (sub_slot < 0 || sub_slot >= MPTCP_SUBFLOW_POOL_SIZE) {
		debug("syz_mptcp_subflow_info: slot %ld out of range\n", sub_slot);
		return -1;
	}
	sub = &syz_mptcp_subflow_pool[sub_slot];
	if (!__atomic_load_n(&sub->in_use, __ATOMIC_ACQUIRE)) {
		debug("syz_mptcp_subflow_info: slot %ld not in use\n", sub_slot);
		return -1;
	}
	pair = &syz_mptcp_pair_pool[sub->pair_slot];
	if (!__atomic_load_n(&pair->in_use, __ATOMIC_ACQUIRE) ||
	    __atomic_load_n(&pair->generation, __ATOMIC_ACQUIRE) != sub->pair_generation) {
		debug("syz_mptcp_subflow_info: slot %ld parent pair %d stale, not live\n",
		      sub_slot, sub->pair_slot);
		return -1;
	}

	memset(info, 0, sizeof(info));
	if (getsockopt(pair->client_fd, SOL_MPTCP, MPTCP_INFO, info, &len) < 0) {
		debug("syz_mptcp_subflow_info: MPTCP_INFO: %d\n", errno);
		return -1;
	}
	// info[0] == mptcpi_subflows: first field of struct mptcp_info, stable uapi.
	debug("syz_mptcp_subflow_info: slot %ld live, mptcpi_subflows=%u\n",
	      sub_slot, info[0]);
	return info[0];
}
#endif

#if SYZ_EXECUTOR || __NR_syz_mptcp_drive_traffic
// Push data client->server on an established pair, exercising the MPTCP data
// path. On a pair created with MPTCP_INIT_RWND_CLAMP the single send + full
// drain becomes a bounded burst + single partial drain: a backlog larger than
// the clamped receiver can absorb is left on the msk send head, so the kernel
// flushes it from the ACK-driven softirq push path (__mptcp_check_push ->
// __mptcp_subflow_push_pending) instead of inline in mptcp_sendmsg. Bounded
// (<=4 KiB/send, <=64 sends) so a mutated data_len can't wedge the pair.
static long syz_mptcp_drive_traffic(volatile long a0, volatile long a1, volatile long a2)
{
	long slot = a0;
	const void* data = (const void*)a1;
	size_t data_len = (size_t)a2;
	struct syz_mptcp_pair_slot* pair;
	char drain_buf[4096];
	ssize_t sent = 0, drained;

	if (slot < 0 || slot >= MPTCP_PAIR_POOL_SIZE) {
		debug("syz_mptcp_drive_traffic: slot %ld out of range\n", slot);
		return -1;
	}
	pair = &syz_mptcp_pair_pool[slot];
	if (!pair->in_use) {
		debug("syz_mptcp_drive_traffic: slot %ld not in use\n", slot);
		return -1;
	}
	if (pair->client_fd < 0 || pair->server_fd < 0) {
		debug("syz_mptcp_drive_traffic: slot %ld fds not set\n", slot);
		return -1;
	}
	if (data_len > sizeof(drain_buf))
		data_len = sizeof(drain_buf);

	if (pair->rwnd_clamped) {
		// Backpressure mode: burst until the clamped window EAGAINs, building a
		// backlog larger than the receiver can absorb, then drain only ONE
		// bufferful. A window update goes back but the send head stays
		// non-empty, so the remainder is flushed from the softirq deferred-push
		// path -- the point of MPTCP_INIT_RWND_CLAMP. Bounded to 64 sends.
		for (int i = 0; i < 64; i++) {
			ssize_t n = send(pair->client_fd, data, data_len, MSG_DONTWAIT | MSG_NOSIGNAL);
			if (n <= 0)
				break;
			sent += n;
		}
		drained = recv(pair->server_fd, drain_buf, sizeof(drain_buf), MSG_DONTWAIT | MSG_NOSIGNAL);
		(void)drained;
	} else {
		sent = send(pair->client_fd, data, data_len, MSG_DONTWAIT | MSG_NOSIGNAL);
		// Bounded drain so the RX buffer doesn't fill and EAGAIN later sends.
		for (int i = 0; i < 8; i++) {
			drained = recv(pair->server_fd, drain_buf, sizeof(drain_buf), MSG_DONTWAIT | MSG_NOSIGNAL);
			if (drained <= 0)
				break;
		}
	}
	debug("syz_mptcp_drive_traffic: pair=%ld clamped=%d sent=%zd\n", slot, pair->rwnd_clamped, sent);
	return sent < 0 ? 0 : (long)sent;
}
#endif

#endif // EXECUTOR_COMMON_LINUX_MPTCP_H
