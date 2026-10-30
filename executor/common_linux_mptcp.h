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
#include <fcntl.h>
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
#if SYZ_EXECUTOR || __NR_syz_mptcp_join_subflow || __NR_syz_mptcp_subflow_stall || __NR_syz_mptcp_subflow_fail
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
#ifndef MPTCP_PM_ADDR_FLAG_LAMINAR
#define MPTCP_PM_ADDR_FLAG_LAMINAR (1U << 5)
#endif
// MPTCP_PM_ATTR_SUBFLOW_RETRIES is newer than most uapi headers (and absent on
// kernels without the subflow-retries limit), so it gets its own name here.
#define SYZ_MPTCP_PM_ATTR_SUBFLOW_RETRIES 7

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
// MPTCP_INIT_NO_TIMESTAMPS (harness flag; mirrored in .txt + .const): disable TCP
// timestamps in the executor's netns before any socket is created, so this pair's
// segments carry no 12-byte TS option. This FREES TCP option space -- required for
// the Phase-3 length-grow graft ops (ADD_ADDR etc): a timestamps+full-DSS data
// segment already fills the 40-byte option cap (design [RUN]-4), leaving no room for
// an 8-byte graft. Opt-in, so Phase 0-2 progs are unaffected.
#define MPTCP_INIT_NO_TIMESTAMPS 4
// MPTCP_INIT_CHECKSUM (harness flag; mirrored in .txt + .const): set
// net.mptcp.checksum_enabled=1 in the netns before any socket, so the MP_CAPABLE
// handshake negotiates DSS checksums (msk->csum_enabled) and every DSS mapping
// carries a checksum. This ACTIVATES the Phase-2 DSS_CSUM op (inert without
// negotiation) and lights up the validate_data_csum RX path (subflow.c:1034) --
// a mapping-validation path we otherwise never reach. Opt-in.
#define MPTCP_INIT_CHECKSUM 8
// MPTCP_INIT_LISTEN_ANY (harness flag; mirrored in .txt + .const): bind the
// server's listener to 0.0.0.0 instead of 127.0.0.1, so subflows towards an
// address announced by a signal endpoint (127.0.1.x) reach it. Opt-in, so
// existing programs keep their listener.
#define MPTCP_INIT_LISTEN_ANY 16
// MPTCP_INIT_DENY_JOIN_ID0 (harness flag; mirrored in .txt + .const): set
// net.mptcp.allow_join_initial_addr_port=0 while the pair is created, so the
// handshake carries the MP_CAPABLE C flag (peer must not join the initial
// address/port) and the in-kernel PM's c-flag handling runs.
#define MPTCP_INIT_DENY_JOIN_ID0 32

// syz_mptcp_pair_init pm argument (harness constants; mirrored in .txt + .const):
// bit 0 puts the client end on the in-kernel path manager, bit 1 the server end.
// Clear bits mean the userspace path manager.
#define MPTCP_PAIR_PM_USERSPACE 0
#define MPTCP_PAIR_PM_CLIENT_KERNEL 1
#define MPTCP_PAIR_PM_SERVER_KERNEL 2
#define MPTCP_PAIR_PM_KERNEL 3

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

	// The netns settings this pair was created with. The kernel re-reads them
	// later for this pair (the PM and checksum setting on disconnect, the
	// timestamps setting on a join SYN), so the calls that trigger those reads
	// apply them again rather than leaving the pair at the mercy of whatever the
	// netns holds by then.
	bool client_kernel_pm;
	bool server_kernel_pm;
	bool checksum_enabled;
	bool no_timestamps;

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

// Every call except the in-kernel PM configuration ops and the self-contained
// listener_close_race works on a pair.
#if SYZ_EXECUTOR || __NR_syz_mptcp_pair_init || __NR_syz_mptcp_pair_close ||                      \
    __NR_syz_mptcp_join_subflow || __NR_syz_mptcp_subflow_destroy ||                              \
    __NR_syz_mptcp_subflow_info || __NR_syz_mptcp_inject_join_syn ||                              \
    __NR_syz_mptcp_join_close_race || __NR_syz_mptcp_close_server || __NR_syz_mptcp_disconnect || \
    __NR_syz_mptcp_drive_traffic || __NR_syz_mptcp_pm_announce || __NR_syz_mptcp_pm_remove ||      \
    __NR_syz_mptcp_pm_set_flags || __NR_syz_mptcp_pm_get_endpoint || __NR_syz_mptcp_pm_dump_endpoints || \
    __NR_syz_mptcp_subflow_stall || __NR_syz_mptcp_subflow_fail
static struct syz_mptcp_pair_slot syz_mptcp_pair_pool[MPTCP_PAIR_POOL_SIZE];
#endif

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
// Userspace PM signalling on one msk (announce / remove / set_flags).
#define MPTCP_NEED_PM_USERSPACE (SYZ_EXECUTOR || __NR_syz_mptcp_pm_announce || __NR_syz_mptcp_pm_remove || __NR_syz_mptcp_pm_set_flags || __NR_syz_mptcp_pm_get_endpoint || __NR_syz_mptcp_pm_dump_endpoints)
// In-kernel PM configuration: the endpoint commands share one message builder.
#define MPTCP_NEED_PM_ENDPOINT (SYZ_EXECUTOR || __NR_syz_mptcp_pm_add_endpoint || __NR_syz_mptcp_pm_del_endpoint || __NR_syz_mptcp_pm_set_endpoint_flags || __NR_syz_mptcp_pm_get_endpoint)
// GET / DUMP replies, also used to learn a kernel-assigned endpoint id.
#define MPTCP_NEED_PM_QUERY (SYZ_EXECUTOR || __NR_syz_mptcp_pm_add_endpoint || __NR_syz_mptcp_pm_get_endpoint || __NR_syz_mptcp_pm_dump_endpoints || __NR_syz_mptcp_pm_get_limits)
#define MPTCP_NEED_PM_CONFIG (MPTCP_NEED_PM_ENDPOINT || MPTCP_NEED_PM_QUERY || __NR_syz_mptcp_pm_set_limits || __NR_syz_mptcp_pm_flush_endpoints)
// The calls that send on the shared genl socket (netns_cycle uses its own).
#define MPTCP_NEED_GENL_SOCK (SYZ_EXECUTOR || __NR_syz_mptcp_pair_init || __NR_syz_mptcp_join_subflow || __NR_syz_mptcp_subflow_destroy || MPTCP_NEED_PM_CONFIG || MPTCP_NEED_PM_USERSPACE)
#define MPTCP_NEED_NLMSG (MPTCP_NEED_GENL_SOCK || __NR_syz_mptcp_netns_cycle)
#define MPTCP_NEED_PM_SETUP (SYZ_EXECUTOR || __NR_syz_mptcp_pair_init || __NR_syz_mptcp_join_subflow || MPTCP_NEED_PM_CONFIG || MPTCP_NEED_PM_USERSPACE)
// netns_cycle resolves the genl family on its own socket, in its own netns.
#define MPTCP_NEED_PM_FAMILY (MPTCP_NEED_PM_SETUP || __NR_syz_mptcp_netns_cycle)
// The calls that apply netns settings for one pair (see mptcp_netns_save):
// pair_init at creation, join for the subflow SYN, disconnect for the msk reset.
// Only pair_init and disconnect switch the path manager.
#define MPTCP_NEED_NETNS_SAVE (SYZ_EXECUTOR || __NR_syz_mptcp_pair_init || __NR_syz_mptcp_join_subflow || __NR_syz_mptcp_disconnect)
// set_sysctl only needs the lock and the sysctl read/write helpers.
#define MPTCP_NEED_NETNS_SETTINGS (MPTCP_NEED_NETNS_SAVE || __NR_syz_mptcp_set_sysctl)
#define MPTCP_NEED_PM_SWITCH (SYZ_EXECUTOR || __NR_syz_mptcp_pair_init || __NR_syz_mptcp_disconnect)

// remove and set_flags also act on a joined subflow, and subflow_stall reads it
// (the subflow names the flow).
#if MPTCP_NEED_SUBFLOW_CALL || __NR_syz_mptcp_pm_remove || __NR_syz_mptcp_pm_set_flags || __NR_syz_mptcp_subflow_stall
static struct syz_mptcp_subflow_slot syz_mptcp_subflow_pool[MPTCP_SUBFLOW_POOL_SIZE];
#endif

#if MPTCP_NEED_NLMSG || MPTCP_NEED_NETNS_SETTINGS
// Minimal spinlock over an int flag, used by the genl transactions, the one-time
// netlink setup and the netns settings below. __atomic builtins need no header and
// are available in every reproducer build; usleep is already used in this file.
static void mptcp_spin_lock(volatile int* lock)
{
	while (__atomic_exchange_n(lock, 1, __ATOMIC_ACQUIRE))
		usleep(50);
}

static void mptcp_spin_unlock(volatile int* lock)
{
	__atomic_store_n(lock, 0, __ATOMIC_RELEASE);
}
#endif

// ---------- Path-manager selection and userspace-PM setup ----------
//
// Each msk runs one path manager, fixed when the msk is created:
// mptcp_pm_data_reset() (net/mptcp/pm.c) copies the netns setting
// (net.mptcp.path_manager, or the older pm_type) into it. That happens inside
// socket(IPPROTO_MPTCP) for the client, when the handshake clones the server msk
// off the listener, and again on disconnect. syz_mptcp_pair_init() therefore
// writes each end's choice right before that end's msk is created, under
// mptcp_netns_lock, and restores the netns setting once the server end has been
// accepted (see mptcp_netns_save). The choice is part of the program and nothing
// outlives the call.
//
// A userspace-PM end additionally needs the one-time netlink setup in
// mptcp_pm_ensure_netlink():
//
//   1. The genl family id, for MPTCP_PM_CMD_SUBFLOW_CREATE/DESTROY (join and
//      subflow_destroy act on a userspace client end).
//   2. A live listener on the "mptcp_pm_events" genl group: the server's
//      acceptance gate for an incoming MP_JOIN in userspace-PM mode
//      (mptcp_userspace_pm_active(), consulted from
//      mptcp_can_accept_new_subflow() in net/mptcp/subflow.c) requires one. We
//      never need to read an event, just to hold the subscription open.
//
// mptcp_pm_ensure_netlink() is idempotent (mptcp_pm_setup_done latches). It is
// called from syz_mptcp_pair_init() when at least one end is userspace and from
// syz_mptcp_join_subflow(), so a C reproducer that re-enters at either
// pseudo-syscall still works. A pair with both ends on the in-kernel PM never
// touches it.

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
// mptcp_pm_ensure_netlink -> mptcp_pm_resolve_family) and subflow_destroy
// (via mptcp_pm_subflow_destroy) -- every one of the four calls except
// pair_close, which never touches netlink.
#if MPTCP_NEED_NLMSG
struct mptcp_nlmsg {
	char buf[512];
	char* pos;
	bool overflow; // set if any attr write would exceed buf; checked by send
};

#if MPTCP_NEED_GENL_SOCK
static int mptcp_pm_genl_sock = -1; // request/reply socket: GETFAMILY, SUBFLOW_CREATE/DESTROY
static uint16 mptcp_pm_family_id;
#endif

// The request/reply socket above is shared across threads under the default
// -threaded model. Two concurrent transactions on one socket can each recv
// the other's reply, so serialize every send+recv pair under this lock and
// stamp each request with a unique nlmsg_seq the reply is matched against
// (defence in depth against a stale datagram left in the socket buffer).
static int mptcp_nlmsg_lock;
static uint32 mptcp_nlmsg_seq_ctr;

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

// Only SUBFLOW_CREATE/DESTROY and the endpoint commands nest attributes
// (GETFAMILY's request doesn't) -- see MPTCP_NEED_SUBFLOW_CALL and
// MPTCP_NEED_PM_ENDPOINT.
#if MPTCP_NEED_SUBFLOW_CALL || MPTCP_NEED_PM_ENDPOINT || __NR_syz_mptcp_pm_announce || __NR_syz_mptcp_pm_set_flags || __NR_syz_mptcp_netns_cycle
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
#endif // MPTCP_NEED_SUBFLOW_CALL || MPTCP_NEED_PM_ENDPOINT || announce || set_flags || netns_cycle

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

	// A message that overran buf[] was never fully built -- refuse to send
	// a truncated request rather than let the kernel misparse it.
	if (m->overflow) {
		debug("mptcp_nlmsg_send: message overflowed buf\n");
		errno = EMSGSIZE;
		return -1;
	}

	uint32 seq = __atomic_add_fetch(&mptcp_nlmsg_seq_ctr, 1, __ATOMIC_RELAXED);
	hdr->nlmsg_len = m->pos - m->buf;
	hdr->nlmsg_seq = seq;
	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;

	// Hold the shared socket for the whole send+recv so a concurrent
	// transaction can't steal our reply (m->buf is per-call stack, only
	// the socket is shared).
	mptcp_spin_lock(&mptcp_nlmsg_lock);
	ssize_t n = sendto(sock, m->buf, hdr->nlmsg_len, 0, (struct sockaddr*)&addr, sizeof(addr));
	if (n != (ssize_t)hdr->nlmsg_len) {
		mptcp_spin_unlock(&mptcp_nlmsg_lock);
		debug("mptcp_nlmsg_send: short write: %zd/%u errno=%d\n", n, hdr->nlmsg_len, errno);
		return -1;
	}
	// Skip any stale/foreign datagram whose seq doesn't match ours.
	int attempts = 0;
	for (; attempts < 8; attempts++) {
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
// the two callers of mptcp_pm_ensure_netlink(). subflow_destroy reads
// mptcp_pm_genl_sock/mptcp_pm_family_id directly (see the NLMSG block
// above) but never calls ensure_setup, so it doesn't need these.
#if MPTCP_NEED_PM_SETUP
static int mptcp_pm_setup_done;
static int mptcp_pm_setup_lock; // serializes the one-time netlink setup under -threaded
static int mptcp_pm_event_sock = -1; // held open + subscribed so mptcp_userspace_pm_active() is true
static uint32 mptcp_pm_event_grp_id; // "mptcp_pm_events" mcast group id, for per-join event sockets
#endif // MPTCP_NEED_PM_SETUP

#if MPTCP_NEED_PM_FAMILY

// Parse a CTRL_CMD_GETFAMILY reply for the mptcp_pm family id and the id
// of its "mptcp_pm_events" multicast group.
static int mptcp_pm_resolve_family(int sock, uint16* family_id_out, uint32* event_grp_id_out)
{
	struct mptcp_nlmsg m;
	struct genlmsghdr genlhdr;
	uint16 family_id = 0;
	uint32 event_grp_id = 0;

	memset(&genlhdr, 0, sizeof(genlhdr));
	genlhdr.cmd = CTRL_CMD_GETFAMILY;
	mptcp_nlmsg_init(&m, GENL_ID_CTRL, &genlhdr, sizeof(genlhdr));
	mptcp_nlmsg_attr(&m, CTRL_ATTR_FAMILY_NAME, MPTCP_PM_NAME, strlen(MPTCP_PM_NAME) + 1);
	int n = mptcp_nlmsg_send(&m, sock);
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
#endif // MPTCP_NEED_PM_FAMILY

#if MPTCP_NEED_PM_SETUP
static int mptcp_pm_ensure_netlink(void)
{
	struct sockaddr_nl sa;
	uint32 event_grp_id = 0;
	int sock = -1, event_sock = -1;

	// Fast path once setup has been published.
	if (__atomic_load_n(&mptcp_pm_setup_done, __ATOMIC_ACQUIRE))
		return 0;

	// Serialize first-time setup: exactly one thread does the family resolve
	// and event subscription; others wait and then observe setup_done.
	// Idempotent re-entry from either pair_init or join_subflow. The path
	// manager itself is chosen per msk by pair_init, not here.
	mptcp_spin_lock(&mptcp_pm_setup_lock);
	if (mptcp_pm_setup_done) {
		mptcp_spin_unlock(&mptcp_pm_setup_lock);
		return 0;
	}

	sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (sock < 0) {
		debug("mptcp_pm_ensure_netlink: socket(genl): %d\n", errno);
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
		debug("mptcp_pm_ensure_netlink: bind(genl): %d\n", errno);
		goto fail;
	}
	if (mptcp_pm_resolve_family(sock, &mptcp_pm_family_id, &event_grp_id) < 0)
		goto fail;

	event_sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (event_sock < 0) {
		debug("mptcp_pm_ensure_netlink: socket(event): %d\n", errno);
		goto fail;
	}
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (bind(event_sock, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
		debug("mptcp_pm_ensure_netlink: bind(event): %d\n", errno);
		goto fail;
	}
	if (setsockopt(event_sock, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &event_grp_id, sizeof(event_grp_id)) < 0) {
		debug("mptcp_pm_ensure_netlink: NETLINK_ADD_MEMBERSHIP mptcp_pm_events: %d\n", errno);
		goto fail;
	}

	mptcp_pm_genl_sock = sock;
	mptcp_pm_event_sock = event_sock;
	mptcp_pm_event_grp_id = event_grp_id;
	__atomic_store_n(&mptcp_pm_setup_done, 1, __ATOMIC_RELEASE);
	debug("mptcp_pm_ensure_netlink: family_id=%d event_grp_id=%d\n",
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

#if MPTCP_NEED_NETNS_SETTINGS
// Netns settings the kernel reads when it creates an msk or a subflow. They are
// per-netns, and the executor's netns outlives every program it runs, so a call
// that changes one for its pair saves it first and restores it before returning
// (all under mptcp_netns_lock, since threads share the netns). The pair records
// its own values so the later calls that make the kernel re-read them can apply
// them again. The executor's per-program netns reset (reset_net_namespace) puts
// them back too, for a program killed in the middle of such a call.
#define MPTCP_SYSCTL_PATH_MANAGER "/proc/sys/net/mptcp/path_manager"
#define MPTCP_SYSCTL_PM_TYPE "/proc/sys/net/mptcp/pm_type"
#define MPTCP_SYSCTL_CHECKSUM "/proc/sys/net/mptcp/checksum_enabled"
#define MPTCP_SYSCTL_TIMESTAMPS "/proc/sys/net/ipv4/tcp_timestamps"
#define MPTCP_SYSCTL_JOIN_ID0 "/proc/sys/net/mptcp/allow_join_initial_addr_port"

static int mptcp_netns_lock;

#if MPTCP_NEED_NETNS_SAVE
struct mptcp_netns_saved {
	const char* pm_path; // path_manager, or pm_type on kernels without it; NULL if not saved
	char pm[32];
	char checksum[8]; // empty if not saved
	char timestamps[8];
	char join_id0[8];
};
#endif

static bool mptcp_sysctl_read(const char* path, char* buf, int size)
{
	int fd = open(path, O_RDONLY);
	if (fd < 0)
		return false;
	int n = read(fd, buf, size - 1);
	close(fd);
	if (n <= 0)
		return false;
	buf[n] = 0;
	if (buf[n - 1] == '\n')
		buf[n - 1] = 0;
	return true;
}

static bool mptcp_sysctl_write(const char* path, const char* val)
{
	int fd = open(path, O_WRONLY);
	if (fd < 0) {
		debug("mptcp_sysctl_write: open %s: %d\n", path, errno);
		return false;
	}
	int len = strlen(val);
	bool ok = write(fd, val, len) == len;
	if (!ok) {
		debug("mptcp_sysctl_write: write %s=%s: %d\n", path, val, errno);
	}
	close(fd);
	return ok;
}

#if MPTCP_NEED_NETNS_SAVE
// Saves the settings a call is about to change. The caller holds mptcp_netns_lock
// until the matching mptcp_netns_restore().
static void mptcp_netns_save(struct mptcp_netns_saved* saved, bool pm, bool checksum, bool timestamps,
			     bool join_id0)
{
	memset(saved, 0, sizeof(*saved));
	if (pm) {
		if (mptcp_sysctl_read(MPTCP_SYSCTL_PATH_MANAGER, saved->pm, sizeof(saved->pm)))
			saved->pm_path = MPTCP_SYSCTL_PATH_MANAGER;
		else if (mptcp_sysctl_read(MPTCP_SYSCTL_PM_TYPE, saved->pm, sizeof(saved->pm)))
			saved->pm_path = MPTCP_SYSCTL_PM_TYPE;
	}
	if (checksum && !mptcp_sysctl_read(MPTCP_SYSCTL_CHECKSUM, saved->checksum, sizeof(saved->checksum)))
		saved->checksum[0] = 0;
	if (timestamps && !mptcp_sysctl_read(MPTCP_SYSCTL_TIMESTAMPS, saved->timestamps, sizeof(saved->timestamps)))
		saved->timestamps[0] = 0;
	if (join_id0 && !mptcp_sysctl_read(MPTCP_SYSCTL_JOIN_ID0, saved->join_id0, sizeof(saved->join_id0)))
		saved->join_id0[0] = 0;
}

static void mptcp_netns_restore(const struct mptcp_netns_saved* saved)
{
	if (saved->pm_path)
		mptcp_sysctl_write(saved->pm_path, saved->pm);
	if (saved->checksum[0])
		mptcp_sysctl_write(MPTCP_SYSCTL_CHECKSUM, saved->checksum);
	if (saved->timestamps[0])
		mptcp_sysctl_write(MPTCP_SYSCTL_TIMESTAMPS, saved->timestamps);
	if (saved->join_id0[0])
		mptcp_sysctl_write(MPTCP_SYSCTL_JOIN_ID0, saved->join_id0);
}
#endif // MPTCP_NEED_NETNS_SAVE
#endif // MPTCP_NEED_NETNS_SETTINGS

#if MPTCP_NEED_PM_SWITCH
// Selects the path manager for msks created from now on in this netns. Prefers
// path_manager (pm_type is deprecated since v6.15); older kernels only have pm_type.
static bool mptcp_set_pm(bool kernel_pm)
{
	if (access(MPTCP_SYSCTL_PATH_MANAGER, F_OK) == 0)
		return mptcp_sysctl_write(MPTCP_SYSCTL_PATH_MANAGER, kernel_pm ? "kernel" : "userspace");
	return mptcp_sysctl_write(MPTCP_SYSCTL_PM_TYPE, kernel_pm ? "0" : "1");
}
#endif // MPTCP_NEED_PM_SWITCH

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
	struct nlattr* nest = NULL;
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
	uint16 fam_v = AF_INET;

	memset(&genlhdr, 0, sizeof(genlhdr));
	genlhdr.cmd = MPTCP_PM_CMD_SUBFLOW_DESTROY;
	genlhdr.version = MPTCP_PM_VER;
	mptcp_nlmsg_init(&m, mptcp_pm_family_id, &genlhdr, sizeof(genlhdr));
	mptcp_nlmsg_attr(&m, MPTCP_PM_ATTR_TOKEN, &token, sizeof(token));

	struct nlattr* nest = NULL;
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

// ---------- In-kernel path-manager configuration ----------
//
// The in-kernel PM acts on its own, from endpoints and limits configured per
// netns: it opens subflows from "subflow" endpoints, announces "signal"
// endpoints with ADD_ADDR, meshes "fullmesh" ones, and retries subflows closed
// after an error. Configuration applies to every kernel-PM msk in the netns,
// both before a pair is created (acted on when it is established) and while it
// is live (the kernel walks existing msks). These ops only build valid commands:
// endpoint i < 8 uses id i+1 and address 127.0.1.(i+1) on lo (clear of the
// 127.0.0.2+ range join_subflow uses); endpoint 8 uses id 9 and 127.0.0.1, the
// address every pair's initial subflow uses, which is how a host configures an
// endpoint on its primary address. The descriptions only offer flag
// combinations the kernel accepts. The executor's per-program netns reset
// flushes endpoints and restores the limits, so nothing outlives the program.
//
// Both ends of a pair live in the same netns, so they share one endpoint table:
// both ends announce signal endpoints and both try to open subflows from
// subflow endpoints (the server's attempts fail, the client is not listening).
// Two real hosts would each have their own table.

#if MPTCP_NEED_PM_ENDPOINT
#define MPTCP_PM_ENDPOINT_MAX 8
#define MPTCP_PM_ENDPOINT_INITIAL 8
// Endpoints added without an id (the kernel assigns one): handles 16..23, address
// 127.0.4.(h-15). The add learns the assigned id from a dump.
#define MPTCP_PM_ENDPOINT_AUTO 16
// Not an endpoint: DEL_ADDR with id 0 and the initial address, which the kernel
// treats as "withdraw the initial subflow's address" on every msk using it.
#define MPTCP_PM_ENDPOINT_ID0 256
// Port of a signal endpoint created with a port: the kernel opens its own
// listener there (mptcp_pm_nl_create_listen_socket). Per netns, so per proc.
#define MPTCP_PM_ENDPOINT_PORT_BASE 26100

static uint8 mptcp_pm_auto_ids[MPTCP_PM_ENDPOINT_MAX]; // learnt ids, 0 = not known

// Maps an endpoint handle to the id and address its commands carry. id 0 with an
// auto handle means the id is not known (the add failed or was not made).
static bool mptcp_pm_endpoint_resolve(long h, uint8* id, uint32* addr_be)
{
	if (h >= 0 && h < MPTCP_PM_ENDPOINT_MAX) {
		*id = (uint8)(h + 1);
		*addr_be = htonl(0x7f000101 + (uint32)h);
	} else if (h == MPTCP_PM_ENDPOINT_INITIAL) {
		*id = MPTCP_PM_ENDPOINT_INITIAL + 1;
		*addr_be = htonl(0x7f000001);
	} else if (h >= MPTCP_PM_ENDPOINT_AUTO && h < MPTCP_PM_ENDPOINT_AUTO + MPTCP_PM_ENDPOINT_MAX) {
		*id = mptcp_pm_auto_ids[h - MPTCP_PM_ENDPOINT_AUTO];
		*addr_be = htonl(0x7f000401 + (uint32)(h - MPTCP_PM_ENDPOINT_AUTO));
	} else if (h == MPTCP_PM_ENDPOINT_ID0) {
		*id = 0;
		*addr_be = htonl(0x7f000001);
	} else {
		return false;
	}
	return true;
}

static void mptcp_pm_endpoint_build(struct mptcp_nlmsg* m, int cmd, uint8 id, uint32 addr_be, bool with_addr,
				    uint32 flags, uint16 port_h)
{
	struct genlmsghdr genlhdr;
	struct nlattr* nest = NULL;

	memset(&genlhdr, 0, sizeof(genlhdr));
	genlhdr.cmd = cmd;
	genlhdr.version = MPTCP_PM_VER;
	mptcp_nlmsg_init(m, mptcp_pm_family_id, &genlhdr, sizeof(genlhdr));
	mptcp_nlmsg_nest_begin(m, &nest, MPTCP_PM_ATTR_ADDR | NLA_F_NESTED);
	// An add without an id lets the kernel assign one; id 0 is otherwise only sent
	// for the id-0 removal, which also carries the address.
	if (id || cmd != MPTCP_PM_CMD_ADD_ADDR)
		mptcp_nlmsg_attr(m, MPTCP_PM_ADDR_ATTR_ID, &id, sizeof(id));
	if (with_addr) {
		uint16 fam = AF_INET;
		mptcp_nlmsg_attr(m, MPTCP_PM_ADDR_ATTR_FAMILY, &fam, sizeof(fam));
		mptcp_nlmsg_attr(m, MPTCP_PM_ADDR_ATTR_ADDR4, &addr_be, sizeof(addr_be));
	}
	if (cmd == MPTCP_PM_CMD_ADD_ADDR) {
		uint32 ifindex = if_nametoindex("lo");
		mptcp_nlmsg_attr(m, MPTCP_PM_ADDR_ATTR_IF_IDX, &ifindex, sizeof(ifindex));
		if (port_h)
			mptcp_nlmsg_attr(m, MPTCP_PM_ADDR_ATTR_PORT, &port_h, sizeof(port_h));
	}
	// SET_FLAGS replaces the backup/fullmesh bits, so it always sends FLAGS (0 clears them).
	if (flags || cmd == MPTCP_PM_CMD_SET_FLAGS)
		mptcp_nlmsg_attr(m, MPTCP_PM_ADDR_ATTR_FLAGS, &flags, sizeof(flags));
	mptcp_nlmsg_nest_end(m, nest);
}

#if SYZ_EXECUTOR || __NR_syz_mptcp_pm_add_endpoint || __NR_syz_mptcp_pm_del_endpoint || __NR_syz_mptcp_pm_set_endpoint_flags
// Builds and sends an endpoint command for endpoint handle h. ADD_ADDR carries the
// full address; DEL_ADDR and SET_FLAGS look the endpoint up by id.
static int mptcp_pm_endpoint_cmd(int cmd, long h, uint32 flags, uint16 port_h)
{
	struct mptcp_nlmsg m;
	uint8 id;
	uint32 addr_be;

	if (!mptcp_pm_endpoint_resolve(h, &id, &addr_be))
		return -1;
	if (!id && h != MPTCP_PM_ENDPOINT_ID0 && cmd != MPTCP_PM_CMD_ADD_ADDR) {
		debug("mptcp_pm_endpoint_cmd: endpoint %ld has no known id\n", h);
		errno = ENOENT;
		return -1;
	}
	mptcp_pm_endpoint_build(&m, cmd, id, addr_be, cmd == MPTCP_PM_CMD_ADD_ADDR || h == MPTCP_PM_ENDPOINT_ID0,
				flags, port_h);
	return mptcp_nlmsg_send(&m, mptcp_pm_genl_sock);
}
#endif
#endif // MPTCP_NEED_PM_ENDPOINT

#if MPTCP_NEED_PM_QUERY
// Sends a GET or DUMP request and reads every reply to it up to the ACK or the
// DONE, so nothing is left queued for the next command on the shared socket. For
// each address in the replies, calls cb (when given) with its id and IPv4 address.
// Returns 0, or -1 with errno.
static int mptcp_nlmsg_query(struct mptcp_nlmsg* m, bool dump, void (*cb)(void* ctx, uint8 id, uint32 addr_be),
			     void* ctx)
{
	struct nlmsghdr* hdr = (struct nlmsghdr*)m->buf;
	struct sockaddr_nl sa;
	static char buf[16384];
	int ret = -1, err = EINVAL;

	if (m->overflow) {
		errno = EMSGSIZE;
		return -1;
	}
	uint32 seq = __atomic_add_fetch(&mptcp_nlmsg_seq_ctr, 1, __ATOMIC_RELAXED);
	hdr->nlmsg_len = m->pos - m->buf;
	hdr->nlmsg_seq = seq;
	// A dump ends with DONE and gets no ACK.
	if (dump)
		hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	mptcp_spin_lock(&mptcp_nlmsg_lock);
	if (sendto(mptcp_pm_genl_sock, m->buf, hdr->nlmsg_len, 0, (struct sockaddr*)&sa, sizeof(sa)) !=
	    (ssize_t)hdr->nlmsg_len) {
		err = errno;
		goto out;
	}
	for (int i = 0; i < 64; i++) {
		ssize_t n = recv(mptcp_pm_genl_sock, buf, sizeof(buf), 0);
		if (n < (ssize_t)sizeof(struct nlmsghdr)) {
			err = n < 0 ? errno : EINVAL;
			goto out;
		}
		int left = (int)n;
		for (struct nlmsghdr* h = (struct nlmsghdr*)buf; NLMSG_OK(h, left); h = NLMSG_NEXT(h, left)) {
			if (h->nlmsg_seq != seq)
				continue;
			if (h->nlmsg_type == NLMSG_DONE) {
				ret = 0;
				goto out;
			}
			if (h->nlmsg_type == NLMSG_ERROR) {
				int e = ((struct nlmsgerr*)NLMSG_DATA(h))->error;
				if (e)
					err = -e;
				else
					ret = 0;
				goto out;
			}
			// genlmsghdr, then attributes; pick MPTCP_PM_ATTR_ADDR nests.
			int alen = (int)h->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);
			struct nlattr* a = (struct nlattr*)((char*)NLMSG_DATA(h) + GENL_HDRLEN);
			for (; alen >= (int)sizeof(*a) && a->nla_len >= sizeof(*a) && a->nla_len <= alen;
			     alen -= NLA_ALIGN(a->nla_len), a = (struct nlattr*)((char*)a + NLA_ALIGN(a->nla_len))) {
				if ((a->nla_type & NLA_TYPE_MASK) != MPTCP_PM_ATTR_ADDR || !cb)
					continue;
				uint8 id = 0;
				uint32 addr_be = 0;
				int ilen = a->nla_len - NLA_HDRLEN;
				struct nlattr* b = (struct nlattr*)((char*)a + NLA_HDRLEN);
				for (; ilen >= (int)sizeof(*b) && b->nla_len >= sizeof(*b) && b->nla_len <= ilen;
				     ilen -= NLA_ALIGN(b->nla_len), b = (struct nlattr*)((char*)b + NLA_ALIGN(b->nla_len))) {
					if (b->nla_type == MPTCP_PM_ADDR_ATTR_ID && b->nla_len >= NLA_HDRLEN + 1)
						id = *(uint8*)((char*)b + NLA_HDRLEN);
					else if (b->nla_type == MPTCP_PM_ADDR_ATTR_ADDR4 && b->nla_len >= NLA_HDRLEN + 4)
						memcpy(&addr_be, (char*)b + NLA_HDRLEN, 4);
				}
				cb(ctx, id, addr_be);
			}
		}
	}
out:
	mptcp_spin_unlock(&mptcp_nlmsg_lock);
	if (ret)
		errno = err;
	return ret;
}
#endif // MPTCP_NEED_PM_QUERY

#if SYZ_EXECUTOR || __NR_syz_mptcp_pm_add_endpoint
// Adds endpoint idx and returns it as the endpoint handle. kind is one of the
// flag combinations the kernel accepts (signal, subflow, signal+subflow,
// subflow+fullmesh); mods adds backup and/or laminar. with_port only applies to
// a signal-only endpoint, the one kind the kernel lets carry a port.
struct mptcp_pm_auto_ctx {
	uint32 addr_be;
	uint8 id;
};

static void mptcp_pm_auto_match(void* ctx, uint8 id, uint32 addr_be)
{
	struct mptcp_pm_auto_ctx* c = (struct mptcp_pm_auto_ctx*)ctx;
	if (addr_be == c->addr_be)
		c->id = id;
}

static long syz_mptcp_pm_add_endpoint(volatile long a0, volatile long a1, volatile long a2, volatile long a3)
{
	long h = a0;
	uint32 flags = (uint32)a1 | (uint32)a2;
	bool signal_only = (flags & (MPTCP_PM_ADDR_FLAG_SIGNAL | MPTCP_PM_ADDR_FLAG_SUBFLOW)) == MPTCP_PM_ADDR_FLAG_SIGNAL;
	uint16 port_h = (a3 && signal_only && h < MPTCP_PM_ENDPOINT_MAX) ? MPTCP_PM_ENDPOINT_PORT_BASE + h : 0;
	bool is_auto = h >= MPTCP_PM_ENDPOINT_AUTO && h < MPTCP_PM_ENDPOINT_AUTO + MPTCP_PM_ENDPOINT_MAX;
	uint8 id;
	uint32 addr_be;

	if (h == MPTCP_PM_ENDPOINT_ID0 || !mptcp_pm_endpoint_resolve(h, &id, &addr_be))
		return -1;
	if (mptcp_pm_ensure_netlink() < 0)
		return -1;
	if (is_auto)
		mptcp_pm_auto_ids[h - MPTCP_PM_ENDPOINT_AUTO] = 0;
	if (mptcp_pm_endpoint_cmd(MPTCP_PM_CMD_ADD_ADDR, h, flags, port_h) < 0) {
		debug("syz_mptcp_pm_add_endpoint: endpoint %ld flags 0x%x port %d: %d\n", h, flags, port_h, errno);
		return -1;
	}
	if (is_auto) {
		// The add's ACK doesn't carry the id the kernel chose: find it in a dump.
		struct mptcp_pm_auto_ctx ctx = {addr_be, 0};
		struct mptcp_nlmsg m;
		mptcp_pm_endpoint_build(&m, MPTCP_PM_CMD_GET_ADDR, 0, 0, false, 0, 0);
		if (mptcp_nlmsg_query(&m, true, mptcp_pm_auto_match, &ctx) < 0 || !ctx.id) {
			debug("syz_mptcp_pm_add_endpoint: endpoint %ld added, id not found\n", h);
			return -1;
		}
		mptcp_pm_auto_ids[h - MPTCP_PM_ENDPOINT_AUTO] = ctx.id;
	}
	debug("syz_mptcp_pm_add_endpoint: endpoint %ld flags 0x%x port %d\n", h, flags, port_h);
	return h;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_mptcp_pm_del_endpoint
// Removes the endpoint: the kernel sends RM_ADDR for a signal endpoint and
// closes subflows using a subflow endpoint, on every kernel-PM msk.
static long syz_mptcp_pm_del_endpoint(volatile long a0)
{
	long idx = a0;

	if (mptcp_pm_ensure_netlink() < 0)
		return -1;
	if (mptcp_pm_endpoint_cmd(MPTCP_PM_CMD_DEL_ADDR, idx, 0, 0) < 0) {
		debug("syz_mptcp_pm_del_endpoint: idx %ld: %d\n", idx, errno);
		return -1;
	}
	return 0;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_mptcp_pm_set_endpoint_flags
// Sets the endpoint's backup and fullmesh bits. Changing backup sends MP_PRIO on
// the subflows using it; fullmesh is only offered for non-signal endpoints.
static long syz_mptcp_pm_set_endpoint_flags(volatile long a0, volatile long a1)
{
	long idx = a0;
	uint32 flags = (uint32)a1 & (MPTCP_PM_ADDR_FLAG_BACKUP | MPTCP_PM_ADDR_FLAG_FULLMESH);

	if (idx == MPTCP_PM_ENDPOINT_ID0)
		return -1;
	if (mptcp_pm_ensure_netlink() < 0)
		return -1;
	if (mptcp_pm_endpoint_cmd(MPTCP_PM_CMD_SET_FLAGS, idx, flags, 0) < 0) {
		debug("syz_mptcp_pm_set_endpoint_flags: idx %ld flags 0x%x: %d\n", idx, flags, errno);
		return -1;
	}
	return 0;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_mptcp_pm_flush_endpoints
// Removes every endpoint at once (RM_ADDR / subflow close on all kernel-PM msks).
static long syz_mptcp_pm_flush_endpoints(void)
{
	struct mptcp_nlmsg m;
	struct genlmsghdr genlhdr;

	if (mptcp_pm_ensure_netlink() < 0)
		return -1;
	memset(&genlhdr, 0, sizeof(genlhdr));
	genlhdr.cmd = MPTCP_PM_CMD_FLUSH_ADDRS;
	genlhdr.version = MPTCP_PM_VER;
	mptcp_nlmsg_init(&m, mptcp_pm_family_id, &genlhdr, sizeof(genlhdr));
	if (mptcp_nlmsg_send(&m, mptcp_pm_genl_sock) < 0) {
		debug("syz_mptcp_pm_flush_endpoints: %d\n", errno);
		return -1;
	}
	return 0;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_mptcp_pm_set_limits
static int mptcp_pm_send_limits(uint32 subflows, uint32 add_addr_accepted, uint32 subflow_retries)
{
	struct mptcp_nlmsg m;
	struct genlmsghdr genlhdr;

	memset(&genlhdr, 0, sizeof(genlhdr));
	genlhdr.cmd = MPTCP_PM_CMD_SET_LIMITS;
	genlhdr.version = MPTCP_PM_VER;
	mptcp_nlmsg_init(&m, mptcp_pm_family_id, &genlhdr, sizeof(genlhdr));
	mptcp_nlmsg_attr(&m, MPTCP_PM_ATTR_RCV_ADD_ADDRS, &add_addr_accepted, sizeof(add_addr_accepted));
	mptcp_nlmsg_attr(&m, MPTCP_PM_ATTR_SUBFLOWS, &subflows, sizeof(subflows));
	if (subflow_retries)
		mptcp_nlmsg_attr(&m, SYZ_MPTCP_PM_ATTR_SUBFLOW_RETRIES, &subflow_retries, sizeof(subflow_retries));
	return mptcp_nlmsg_send(&m, mptcp_pm_genl_sock);
}

// Sets the in-kernel PM limits: extra subflows per msk, accepted ADD_ADDRs, and
// retries of subflows closed after an error. The retries limit only exists on
// kernels with that feature; elsewhere the kernel rejects the attribute, so the
// call falls back to the other two, keeping it valid on both sides of a
// differential run.
static long syz_mptcp_pm_set_limits(volatile long a0, volatile long a1, volatile long a2)
{
	uint32 subflows = (uint32)a0;
	uint32 add_addr_accepted = (uint32)a1;
	uint32 subflow_retries = (uint32)a2;

	if (mptcp_pm_ensure_netlink() < 0)
		return -1;
	int err = mptcp_pm_send_limits(subflows, add_addr_accepted, subflow_retries);
	if (err < 0 && errno == EINVAL && subflow_retries)
		err = mptcp_pm_send_limits(subflows, add_addr_accepted, 0);
	if (err < 0) {
		debug("syz_mptcp_pm_set_limits: %u/%u/%u: %d\n", subflows, add_addr_accepted, subflow_retries, errno);
		return -1;
	}
	return 0;
}
#endif

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

static long syz_mptcp_pair_init(volatile long a0, volatile long a1, volatile long a2, volatile long a3,
				volatile long a4, volatile long a5)
{
	// server_addr / client_addr: not yet consulted, see file comment.
	(void)a0;
	(void)a1;
	unsigned long init_flags = (unsigned long)a2;
	// MPTCP_PAIR_PM_*: which ends run the in-kernel path manager.
	bool client_kernel_pm = ((unsigned long)a3 & MPTCP_PAIR_PM_CLIENT_KERNEL) != 0;
	bool server_kernel_pm = ((unsigned long)a3 & MPTCP_PAIR_PM_SERVER_KERNEL) != 0;
	// Typed handles for the userspace-PM ends (same value as the returned pair),
	// NULL for an end that runs the in-kernel PM. Invalid until the pair is
	// established, so a failed call can't leave them aliasing slot 0.
	long* client_out = (long*)a4;
	long* server_out = (long*)a5;
	if (client_out)
		*client_out = -1;
	if (server_out)
		*server_out = -1;

	struct sockaddr_in srv_addr;
	socklen_t alen = sizeof(srv_addr);
	int one = 1;
	int server_listen_fd = -1, client_fd = -1, server_fd = -1, cap_fd = -1;
	struct mptcp_netns_saved saved;
	bool netns_locked = false;
	bool checksum_enabled = false;

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
	int slot = 0;
	for (; slot < MPTCP_PAIR_POOL_SIZE; slot++) {
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

	// A userspace-PM end needs the genl family and the event listener (see the
	// "Path-manager selection" comment above mptcp_pm_ensure_netlink). Done before
	// taking mptcp_netns_lock; it never touches netns settings.
	if ((!client_kernel_pm || !server_kernel_pm) && mptcp_pm_ensure_netlink() < 0) {
		debug("syz_mptcp_pair_init: userspace-PM netlink setup failed\n");
		goto fail;
	}

	// Everything this pair changes in the netns is saved here and restored once
	// the server end has been accepted. The kernel has read every setting by then:
	// the PM and checksum setting when each msk is created, the timestamps setting
	// in the handshake.
	mptcp_spin_lock(&mptcp_netns_lock);
	netns_locked = true;
	mptcp_netns_save(&saved, true,
			 (init_flags & MPTCP_INIT_CHECKSUM) != 0,
			 (init_flags & MPTCP_INIT_NO_TIMESTAMPS) != 0,
			 (init_flags & MPTCP_INIT_DENY_JOIN_ID0) != 0);
	// The C flag is decided while the MP_CAPABLE options are built, inside the
	// handshake below.
	if (init_flags & MPTCP_INIT_DENY_JOIN_ID0)
		mptcp_sysctl_write(MPTCP_SYSCTL_JOIN_ID0, "0");

	// Phase 3: free TCP option room for the length-grow graft ops by disabling TCP
	// timestamps in this (unshared) netns before any socket exists. Per-netns sysctl;
	// best-effort (a failure just leaves TS on -> the graft finds no roomy carrier).
	if (init_flags & MPTCP_INIT_NO_TIMESTAMPS) {
		int tsfd = open("/proc/sys/net/ipv4/tcp_timestamps", O_WRONLY);
		if (tsfd >= 0) {
			if (write(tsfd, "0\n", 2) != 2) {
				debug("syz_mptcp_pair_init: tcp_timestamps disable short write errno=%d\n", errno);
			}
			close(tsfd);
		} else {
			debug("syz_mptcp_pair_init: open tcp_timestamps errno=%d\n", errno);
		}
	}

	// Phase 2 follow-up: negotiate DSS checksums so the DSS_CSUM op is live and the
	// validate_data_csum RX path runs. Per-netns sysctl; set before any socket.
	if (init_flags & MPTCP_INIT_CHECKSUM) {
		int cfd = open("/proc/sys/net/mptcp/checksum_enabled", O_WRONLY);
		if (cfd >= 0) {
			if (write(cfd, "1\n", 2) != 2) {
				debug("syz_mptcp_pair_init: checksum_enabled short write errno=%d\n", errno);
			}
			close(cfd);
		} else {
			debug("syz_mptcp_pair_init: open checksum_enabled errno=%d\n", errno);
		}
	}
	// Record the checksum setting the pair negotiates with (the flag's value, or
	// the netns default), for disconnect to apply again.
	{
		char cbuf[8];
		checksum_enabled = mptcp_sysctl_read(MPTCP_SYSCTL_CHECKSUM, cbuf, sizeof(cbuf)) && cbuf[0] == '1';
	}

	// The client msk takes its path manager in socket(), so create it now, under
	// the client's choice. The server msk is cloned off the listener during the
	// handshake, so the server's choice must be in place before connect().
	if (!mptcp_set_pm(client_kernel_pm)) {
		debug("syz_mptcp_pair_init: select client PM failed\n");
		goto fail;
	}
	client_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);
	if (client_fd < 0) {
		debug("syz_mptcp_pair_init: client socket: %d\n", errno);
		goto fail;
	}
	if (!mptcp_set_pm(server_kernel_pm)) {
		debug("syz_mptcp_pair_init: select server PM failed\n");
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
	srv_addr.sin_addr.s_addr = htonl((init_flags & MPTCP_INIT_LISTEN_ANY) ? INADDR_ANY : INADDR_LOOPBACK);
	if (bind(server_listen_fd, (struct sockaddr*)&srv_addr, sizeof(srv_addr)) < 0) {
		debug("syz_mptcp_pair_init: bind: %d\n", errno);
		goto fail;
	}
	if (getsockname(server_listen_fd, (struct sockaddr*)&srv_addr, &alen) < 0) {
		debug("syz_mptcp_pair_init: getsockname: %d\n", errno);
		goto fail;
	}
	// The client always connects to 127.0.0.1, whatever the listener is bound to.
	srv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
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

	if (connect(client_fd, (struct sockaddr*)&srv_addr, sizeof(srv_addr)) < 0) {
		debug("syz_mptcp_pair_init: connect: %d\n", errno);
		goto fail;
	}
	server_fd = accept(server_listen_fd, NULL, NULL);
	if (server_fd < 0) {
		debug("syz_mptcp_pair_init: accept: %d\n", errno);
		goto fail;
	}
	// Both msks exist and the handshake is complete: nothing below makes the
	// kernel read the netns settings for this pair.
	mptcp_netns_restore(&saved);
	mptcp_spin_unlock(&mptcp_netns_lock);
	netns_locked = false;
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
	syz_mptcp_pair_pool[slot].client_kernel_pm = client_kernel_pm;
	syz_mptcp_pair_pool[slot].server_kernel_pm = server_kernel_pm;
	syz_mptcp_pair_pool[slot].checksum_enabled = checksum_enabled;
	syz_mptcp_pair_pool[slot].no_timestamps = (init_flags & MPTCP_INIT_NO_TIMESTAMPS) != 0;
	if (client_out)
		*client_out = slot;
	if (server_out)
		*server_out = slot;
	debug("syz_mptcp_pair_init: pair %d established, port %d, token %u gen %u, pm client=%s server=%s\n",
	      slot, ntohs(srv_addr.sin_port), syz_mptcp_pair_pool[slot].token,
	      syz_mptcp_pair_pool[slot].generation,
	      client_kernel_pm ? "kernel" : "userspace", server_kernel_pm ? "kernel" : "userspace");
	return slot;

fail:
	if (netns_locked) {
		mptcp_netns_restore(&saved);
		mptcp_spin_unlock(&mptcp_netns_lock);
	}
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

	// Disarm any DSS data-segment mutation still ARMED for this pair's subflows
	// (Phase 2): the pair is going away. Idempotent for the handshake-scoped ops.
	// Guarded to the mutation layer's include condition (join-less repro builds).
#if SYZ_EXECUTOR || __NR_syz_mptcp_join_subflow
	syz_mptcp_mut_retire();
#endif

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

// Pull one named SNMP counter out of the two-line "MPTcpExt:" block of
// /proc/net/netstat: a header line of column names followed by a value line, both
// prefixed "MPTcpExt:". Returns the value for `name`, or -1 if absent. Walks both
// lines token-for-token so the column index need not be hard-coded. Debug-only.
static inline long syz_mptcp_mib_get(const char* h, const char* h_end,
				     const char* v, const char* v_end, const char* name)
{
	size_t namelen = strlen(name);
	// skip the leading "MPTcpExt:" label on both lines
	while (h < h_end && *h != ' ')
		h++;
	while (v < v_end && *v != ' ')
		v++;
	while (h < h_end) {
		while (h < h_end && *h == ' ')
			h++;
		while (v < v_end && *v == ' ')
			v++;
		if (h >= h_end)
			break;
		const char* htok = h;
		while (h < h_end && *h != ' ')
			h++;
		const char* vtok = v;
		while (v < v_end && *v != ' ')
			v++;
		if ((size_t)(h - htok) == namelen && memcmp(htok, name, namelen) == 0) {
			long x = 0;
			for (const char* p = vtok; p < v_end && *p >= '0' && *p <= '9'; p++)
				x = x * 10 + (*p - '0');
			return x;
		}
	}
	return -1;
}

// Debug-only Phase-1 directional oracle: read the MP_JOIN ACK accept/reject SNMP
// counters from /proc/net/netstat IN THE CURRENT (worker) netns -- the netns the
// join ran in, which the execprog child creates fresh per run, so each counter's
// absolute value is its +N delta for this join. FORGE (accept) -> MPJoinAckRx +1 /
// MPJoinAckHMacFailure +0; the HMAC-corrupting ops (reject) -> the reverse. Reads
// nothing onto the wire and is stripped from the csource reproducer (debug-only).
static inline void syz_mptcp_dbg_mib(const char* tag, long pair_slot)
{
	int fd = open("/proc/net/netstat", O_RDONLY);
	if (fd < 0)
		return;
	static char nsbuf[16384];
	int n = 0, r;
	while (n < (int)sizeof(nsbuf) - 1 &&
	       (r = read(fd, nsbuf + n, sizeof(nsbuf) - 1 - n)) > 0)
		n += r;
	close(fd);
	nsbuf[n] = 0;
	char* h = strstr(nsbuf, "MPTcpExt:");
	if (!h)
		return;
	char* h_end = strchr(h, '\n');
	if (!h_end)
		return;
	char* v = strstr(h_end, "MPTcpExt:");
	if (!v)
		return;
	char* v_end = strchr(v, '\n');
	if (!v_end)
		v_end = nsbuf + n;
	// Call syz_mptcp_mib_get directly in the debug() args (no intermediate locals
	// -- an initialized-but-unread local trips -Werror=unused-variable in the
	// debug-stripped csource reproducer, which -Wno-unused-but-set-variable does
	// NOT cover). syz_mptcp_mib_get is static inline, so when csource strips this
	// whole debug() call it simply goes unreferenced without an unused-function
	// warning (same reason the other static-inline helpers are safe).
	debug("syz_mptcp_join_subflow: pair=%ld %s MPTcpExt "
	      "MPJoinAckRx=%ld MPJoinAckHMacFailure=%ld "
	      "MPJoinSynAckRx=%ld MPJoinSynAckHMacFailure=%ld\n",
	      pair_slot, tag,
	      syz_mptcp_mib_get(h, h_end, v, v_end, "MPJoinAckRx"),
	      syz_mptcp_mib_get(h, h_end, v, v_end, "MPJoinAckHMacFailure"),
	      syz_mptcp_mib_get(h, h_end, v, v_end, "MPJoinSynAckRx"),
	      syz_mptcp_mib_get(h, h_end, v, v_end, "MPJoinSynAckHMacFailure"));
}

// ADD_ADDR receipt oracle (Phase 3a/3b). AddAddr = non-echo ADD_ADDR received with a
// VALID add-addr HMAC (MPTCP_MIB_ADDADDR, options.c:1271 -> add_addr_received, the
// raced pm->remote target); EchoAdd = echo ADD_ADDR received (options.c:1274). So
// AddAddr>0 after a drive with MPTCP_MUT_ADD_ADDR_AUTH is the definitive proof the
// FORGED add-addr HMAC validated. Read in the worker netns (same as syz_mptcp_dbg_mib).
static inline void syz_mptcp_dbg_addaddr_mib(const char* tag, long pair_slot)
{
	int fd = open("/proc/net/netstat", O_RDONLY);
	if (fd < 0)
		return;
	static char nsbuf[16384];
	int n = 0, r;
	while (n < (int)sizeof(nsbuf) - 1 &&
	       (r = read(fd, nsbuf + n, sizeof(nsbuf) - 1 - n)) > 0)
		n += r;
	close(fd);
	nsbuf[n] = 0;
	char* h = strstr(nsbuf, "MPTcpExt:");
	if (!h)
		return;
	char* h_end = strchr(h, '\n');
	if (!h_end)
		return;
	char* v = strstr(h_end, "MPTcpExt:");
	if (!v)
		return;
	char* v_end = strchr(v, '\n');
	if (!v_end)
		v_end = nsbuf + n;
	debug("syz_mptcp_addaddr: pair=%ld %s MPTcpExt AddAddr=%ld EchoAdd=%ld AddAddrDrop=%ld MPFailRx=%ld MPFastcloseRx=%ld RmAddr=%ld MPPrioRx=%ld DataCsumErr=%ld\n",
	      pair_slot, tag,
	      syz_mptcp_mib_get(h, h_end, v, v_end, "AddAddr"),
	      syz_mptcp_mib_get(h, h_end, v, v_end, "EchoAdd"),
	      syz_mptcp_mib_get(h, h_end, v, v_end, "AddAddrDrop"),
	      syz_mptcp_mib_get(h, h_end, v, v_end, "MPFailRx"),
	      syz_mptcp_mib_get(h, h_end, v, v_end, "MPFastcloseRx"),
	      syz_mptcp_mib_get(h, h_end, v, v_end, "RmAddr"),
	      syz_mptcp_mib_get(h, h_end, v, v_end, "MPPrioRx"),
	      syz_mptcp_mib_get(h, h_end, v, v_end, "DataCsumErr"));
}

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

// NORMAL-mode MP_JOIN (see the file comment for the mechanism and scope).
//
// addr_id 0 is rejected by the kernel ("invalid addr id" in
// mptcp_userspace_pm_append_new_local_addr, net/mptcp/pm_userspace.c);
// so 0 is coerced to 1 here and any other value passes through unchanged.
// (syzlang int8 carries no signedness; the value is just the low byte of a2.)
static long syz_mptcp_join_subflow(volatile long a0, volatile long a1, volatile long a2, volatile long a3)
{
	long pair_slot = a0;
	uint8 addr_id = (uint8)a1;
	uint8 backup = (uint8)a2; // syzlang clamps to [0:1]
	int mut_op = (int)a3; // MPTCP_MUT_* -- 0 (NONE) leaves the join unmutated
	uint32 local_addr_be; // this subflow's distinct per-slot local address (set below)
	const uint32 remote_addr_be = htonl(0x7f000001); // 127.0.0.1: the pair's server
	int evfd = -1;

	if (pair_slot < 0 || pair_slot >= MPTCP_PAIR_POOL_SIZE) {
		debug("syz_mptcp_join_subflow: pair slot %ld out of range\n", pair_slot);
		return -1;
	}
	struct syz_mptcp_pair_slot* pair = &syz_mptcp_pair_pool[pair_slot];
	if (!pair->in_use) {
		debug("syz_mptcp_join_subflow: pair slot %ld not in use\n", pair_slot);
		return -1;
	}

	// SUBFLOW_CREATE is a userspace-PM command; the kernel rejects it on a
	// kernel-PM msk ("userspace PM not selected"). The description only hands
	// this call a userspace client end, so this is a guard for a mismatched
	// handle, not a path the generator aims at.
	if (pair->client_kernel_pm) {
		debug("syz_mptcp_join_subflow: pair slot %ld client runs the in-kernel PM\n", pair_slot);
		return -1;
	}

	// Idempotent -- syz_mptcp_pair_init() already ran this for a pair with a
	// userspace end. Kept for direct-re-entry safety per the comment above
	// mptcp_pm_ensure_netlink().
	if (mptcp_pm_ensure_netlink() < 0)
		return -1;

	if (addr_id == 0)
		addr_id = 1;

	// Atomic claim, same rationale as the pair pool: two join calls on
	// separate threads must not settle on the same subflow slot. Held from
	// here; the SUBFLOW_CREATE and poll failure paths below release it.
	int sub_slot = 0;
	for (; sub_slot < MPTCP_SUBFLOW_POOL_SIZE; sub_slot++) {
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
	uint32 addr_flags = backup ? MPTCP_PM_ADDR_FLAG_BACKUP : 0;

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
	uint16 local_port_h = 0;
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
		// keys/keys_valid are consumed by MPTCP_MUT_CRYPTO_SELFVERIFY (Phase 0) and
		// MPTCP_MUT_HMAC_FORGE (Phase 1): both recompute the ACK HMAC from the captured
		// nonces + these MP_CAPABLE keys (SELFVERIFY to compare, FORGE to overwrite).
		// The bit/zero mutation ops ignore them. keys_valid requires the pair to have
		// been created with MPTCP_INIT_CAPTURE_KEYS.
		syz_mptcp_mut_publish(local_addr_be, mut_op,
				      pair->local_key, pair->remote_key,
				      pair->keys_valid ? 1 : 0);
	}

	// The new subflow's SYN reads the netns timestamps setting while
	// SUBFLOW_CREATE runs, so apply the pair's own setting around it: a pair
	// created with MPTCP_INIT_NO_TIMESTAMPS keeps timestamp-free subflows.
	struct mptcp_netns_saved saved;
	mptcp_spin_lock(&mptcp_netns_lock);
	mptcp_netns_save(&saved, false, false, pair->no_timestamps, false);
	if (pair->no_timestamps)
		mptcp_sysctl_write(MPTCP_SYSCTL_TIMESTAMPS, "0");
	int create_err = mptcp_pm_subflow_create(pair->token, addr_id, addr_flags,
						 local_addr_be, local_port_h,
						 remote_addr_be, pair->server_port_h);
	int create_errno = errno;
	mptcp_netns_restore(&saved);
	mptcp_spin_unlock(&mptcp_netns_lock);
	errno = create_errno;
	if (create_err < 0) {
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
	int retries = 0;
	for (; retries < MPTCP_SUBFLOW_INFO_MAX_RETRIES; retries++) {
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
		// Reject path: log the MP_JOIN ACK SNMP counters (same worker netns). A
		// HMAC-corrupting op (FLIP/ZERO) shows MPJoinAckHMacFailure +1 / AckRx +0.
		if (mut_op != MPTCP_MUT_NONE)
			syz_mptcp_dbg_mib("REJECT", pair_slot);
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
	}

	// Phase-0 crypto self-verify oracle (design ingress_injection_design.md §7).
	// The join established, so the client ACK (and thus the worker's HMAC recompute)
	// has happened; give the worker a brief grace window to publish its verdict in
	// case the verdict send trails our MPTCP_INFO poll, then log MATCH/MISMATCH.
	// This is the acceptance check that R_B capture + the HMAC recompute are correct;
	// debug() is stripped from the csource reproducer, so it is a debug-only oracle
	// (like the token self-check), never a wire effect. [RUN]-1: a MATCH also
	// confirms LOCAL_OUT saw SYN -> SYN-ACK -> ACK in order (R_A and R_B were both
	// captured before the ACK).
	if (mut_op == MPTCP_MUT_CRYPTO_SELFVERIFY) {
		int vr = syz_mptcp_mut_verify_result();
		for (int i = 0; i < 20 && vr == MPTCP_SELFVERIFY_PENDING; i++) {
			usleep(5000); // up to ~100ms for the worker's release store
			vr = syz_mptcp_mut_verify_result();
		}
		if (vr == MPTCP_SELFVERIFY_MATCH) {
			debug("syz_mptcp_join_subflow: pair=%ld SELFVERIFY MATCH "
			      "(R_B captured, recomputed ACK HMAC == kernel's)\n",
			      pair_slot);
		} else {
			debug("syz_mptcp_join_subflow: pair=%ld SELFVERIFY result=%d "
			      "(1=match -1=mismatch -2=no-keys -3=no-nonce 0=pending)\n",
			      pair_slot, vr);
		}
	}

	// Phase-1 FORGE oracle (design ingress_phase1_design.md §2). The join
	// established (we are past the subflow-count poll), so the worker overwrote the
	// client ACK HMAC with its computed-valid value and the server accepted it via
	// subflow_hmac_valid -- a harness-authored accepted subflow. Grace-window the
	// worker's forge-result release, then log it. debug()-only (stripped from the
	// csource reproducer), like the SELFVERIFY oracle above.
	if (mut_op == MPTCP_MUT_HMAC_FORGE) {
		int fr = syz_mptcp_mut_forge_result();
		for (int i = 0; i < 20 && fr == MPTCP_FORGE_PENDING; i++) {
			usleep(5000); // up to ~100ms for the worker's release store
			fr = syz_mptcp_mut_forge_result();
		}
		if (fr == MPTCP_FORGE_WROTE) {
			debug("syz_mptcp_join_subflow: pair=%ld FORGE_WROTE "
			      "(wrote a valid ACK HMAC; subflow accepted)\n",
			      pair_slot);
		} else {
			debug("syz_mptcp_join_subflow: pair=%ld FORGE result=%d "
			      "(1=wrote -2=no-keys -3=no-nonce 0=pending)\n",
			      pair_slot, fr);
		}
		// Accept path: log the MP_JOIN ACK SNMP counters (same worker netns). FORGE
		// shows MPJoinAckRx +1 / MPJoinAckHMacFailure +0 -- a harness-authored HMAC
		// crossed subflow_hmac_valid (vs the reject ops' +0 / +1).
		syz_mptcp_dbg_mib("ACCEPT", pair_slot);
	}

	// The egress ACK has been sent (and mutated, if requested) by now. The
	// handshake-scoped ops (HMAC/NONCE/SELFVERIFY/FORGE/THMAC) have done their work
	// on the JOIN exchange, so retire the instruction (a later join reusing this
	// per-slot address must not be corrupted). The DSS data-segment ops (Phase 2)
	// must instead stay ARMED for the later syz_mptcp_drive_traffic burst, so they
	// are NOT retired here -- syz_mptcp_subflow_destroy / syz_mptcp_pair_close do it.
	if (mut_op != MPTCP_MUT_NONE &&
	    !(mut_op >= MPTCP_MUT_DSS_SEQ && mut_op <= MPTCP_MUT_DSS_DATA_FIN) &&
	    mut_op != MPTCP_MUT_ADD_ADDR_ECHO && mut_op != MPTCP_MUT_ADD_ADDR_AUTH &&
	    mut_op != MPTCP_MUT_MP_FAIL && mut_op != MPTCP_MUT_MP_FASTCLOSE &&
	    mut_op != MPTCP_MUT_RM_ADDR && mut_op != MPTCP_MUT_MP_PRIO)
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
	const uint32 remote_addr_be = htonl(0x7f000001);

	// Disarm any DSS data-segment mutation that join_subflow left ARMED for this
	// subflow's traffic (Phase 2): the subflow is going away. Idempotent / safe for
	// the handshake-scoped ops, which were already retired at join time. Guarded to
	// the mutation layer's include condition so a join-less reproducer still builds.
#if SYZ_EXECUTOR || __NR_syz_mptcp_join_subflow
	syz_mptcp_mut_retire();
	// Post-drive ADD_ADDR receipt oracle: AddAddr>0 proves a forged non-echo ADD_ADDR
	// HMAC validated (reached add_addr_received). Runs here (after drive_traffic) in
	// the worker netns; stripped from the csource reproducer with the debug() call.
	syz_mptcp_dbg_addaddr_mib("post-drive", a0);
#endif

	if (sub_slot < 0 || sub_slot >= MPTCP_SUBFLOW_POOL_SIZE) {
		debug("syz_mptcp_subflow_destroy: slot %ld out of range\n", sub_slot);
		return -1;
	}
	struct syz_mptcp_subflow_slot* sub = &syz_mptcp_subflow_pool[sub_slot];
	if (!__atomic_load_n(&sub->in_use, __ATOMIC_ACQUIRE)) {
		debug("syz_mptcp_subflow_destroy: slot %ld not in use\n", sub_slot);
		return -1;
	}

	struct syz_mptcp_pair_slot* pair = &syz_mptcp_pair_pool[sub->pair_slot];
	if (!__atomic_load_n(&pair->in_use, __ATOMIC_ACQUIRE) ||
	    __atomic_load_n(&pair->generation, __ATOMIC_ACQUIRE) != sub->pair_generation) {
		// Parent pair already gone, OR its pool slot was closed and
		// REUSED by a different pair (generation mismatch): either way
		// this subflow no longer maps to a live kernel object we may
		// address. Issuing a genl DESTROY now would, in the reuse case,
		// target the NEW occupant's token with our stale tuple -- so
		// just free our own bookkeeping. Closing a pair tears its
		// subflows down kernel-side already.
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
	uint8 info[128];
	socklen_t len = sizeof(info);

	if (sub_slot < 0 || sub_slot >= MPTCP_SUBFLOW_POOL_SIZE) {
		debug("syz_mptcp_subflow_info: slot %ld out of range\n", sub_slot);
		return -1;
	}
	struct syz_mptcp_subflow_slot* sub = &syz_mptcp_subflow_pool[sub_slot];
	if (!__atomic_load_n(&sub->in_use, __ATOMIC_ACQUIRE)) {
		debug("syz_mptcp_subflow_info: slot %ld not in use\n", sub_slot);
		return -1;
	}
	struct syz_mptcp_pair_slot* pair = &syz_mptcp_pair_pool[sub->pair_slot];
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

#if SYZ_EXECUTOR || __NR_syz_mptcp_inject_join_syn || __NR_syz_mptcp_join_close_race
// Shared raw MP_JOIN SYN injection helpers, used by syz_mptcp_inject_join_syn
// (one-shot) and syz_mptcp_join_close_race (burst). Minimal distinct-named on-wire
// structs avoid colliding with system <netinet/...> headers and the parser structs in
// common_linux_mptcp_mut.h; uintN (not stdint) per the executor-header type rule.
struct mptcp_inj_iphdr {
	uint8 vihl, tos;
	uint16 tot_len, id, frag_off;
	uint8 ttl, protocol;
	uint16 check;
	uint32 saddr, daddr;
};
struct mptcp_inj_tcphdr {
	uint16 source, dest;
	uint32 seq, ack_seq;
	uint16 doff_flags, window, check, urg;
};

// Internet checksum over `len` bytes plus a partial sum (TCP pseudo-header).
static uint16 mptcp_inj_csum16(const void* data, int len, uint32 init)
{
	const uint16* p = (const uint16*)data;
	uint32 sum = init;
	while (len > 1) {
		sum += *p++;
		len -= 2;
	}
	if (len)
		sum += *(const uint8*)p;
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return (uint16)~sum;
}

// Source port varied per SYN so successive injections are distinct flows.
static uint16 mptcp_inj_sport = 40000;

// Read the pair's SERVER msk token (mptcpi_token at offset 12 of struct mptcp_info,
// stable uapi). Returns 0 if unavailable.
static uint32 mptcp_inj_server_token(int server_fd)
{
	uint8 info[256];
	socklen_t ilen = sizeof(info);
	uint32 token = 0;
	memset(info, 0, sizeof(info));
	if (getsockopt(server_fd, SOL_MPTCP, MPTCP_INFO, info, &ilen) < 0)
		return 0;
	memcpy(&token, info + 12, sizeof(token));
	return token;
}

// Build and send ONE MP_JOIN SYN (server `token`, dummy nonce -- the crash-relevant
// path is pre-HMAC) to 127.0.0.1:server_port_h over the raw socket `rs` (IP_HDRINCL
// via IPPROTO_RAW). Returns 0 on send, -1 on error.
static int mptcp_inj_send_one(int rs, uint32 token, uint16 server_port_h)
{
	uint8 pkt[64];
	const int iplen = 20, tcplen = 20 + 12, total = 20 + 20 + 12; // +12 = MP_JOIN SYN opt
	struct sockaddr_in dst;

	memset(pkt, 0, sizeof(pkt));
	struct mptcp_inj_iphdr* ip = (struct mptcp_inj_iphdr*)pkt;
	struct mptcp_inj_tcphdr* tcp = (struct mptcp_inj_tcphdr*)(pkt + iplen);
	uint8* opt = pkt + iplen + 20;
	ip->vihl = 0x45;
	ip->tot_len = htons(total);
	ip->id = htons(1);
	ip->ttl = 64;
	ip->protocol = IPPROTO_TCP;
	ip->saddr = htonl(0x7f000001);
	ip->daddr = htonl(0x7f000001);
	ip->check = mptcp_inj_csum16(ip, iplen, 0);
	tcp->source = htons(mptcp_inj_sport++);
	tcp->dest = htons(server_port_h);
	tcp->seq = htonl(0x12345678);
	tcp->doff_flags = htons((uint16)(((tcplen / 4) << 12) | 0x002)); // data-offset + SYN
	tcp->window = htons(65535);
	// MP_JOIN SYN option: [kind=30][len=12][subtype MP_JOIN<<4 | flags=0][addr_id]
	//                     [token:be32][nonce:be32]
	opt[0] = 30;
	opt[1] = 12;
	opt[2] = (1 << 4);
	opt[3] = 0x01; // addr_id
	uint32 tok_be = htonl(token);
	memcpy(opt + 4, &tok_be, 4);
	uint32 nonce = htonl(0xa5a5a5a5); // dummy: crash path is pre-HMAC
	memcpy(opt + 8, &nonce, 4);
	uint32 pseudo = 0;
	pseudo += (ip->saddr & 0xffff) + (ip->saddr >> 16);
	pseudo += (ip->daddr & 0xffff) + (ip->daddr >> 16);
	pseudo += htons(IPPROTO_TCP) + htons((uint16)tcplen);
	tcp->check = mptcp_inj_csum16(tcp, tcplen, pseudo);

	memset(&dst, 0, sizeof(dst));
	dst.sin_family = AF_INET;
	dst.sin_addr.s_addr = htonl(0x7f000001);
	dst.sin_port = htons(server_port_h);
	return sendto(rs, pkt, total, 0, (struct sockaddr*)&dst, sizeof(dst)) < 0 ? -1 : 0;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_mptcp_inject_join_syn
// Raw MP_JOIN SYN injection primitive (lifecycle op-set). Send ONE MP_JOIN SYN
// carrying the pair's SERVER msk token to the loopback listener. Drives the
// incoming-join-request path (subflow_token_join_request -> mptcp_pm_get_local_id
// / mptcp_pm_is_backup) directly -- coverage stock syzkaller reaches only via a
// full userspace-PM SUBFLOW_CREATE round-trip -- and is the injection half of the
// close/teardown race class. On a LIVE msk pm.ops is valid, so no crash; the join
// is rejected later at HMAC. Non-consuming (the pair stays usable).
static long syz_mptcp_inject_join_syn(volatile long a0)
{
	long slot = a0;

	if (slot < 0 || slot >= MPTCP_PAIR_POOL_SIZE) {
		debug("syz_mptcp_inject_join_syn: slot %ld out of range\n", slot);
		return -1;
	}
	struct syz_mptcp_pair_slot* pair = &syz_mptcp_pair_pool[slot];
	if (!__atomic_load_n(&pair->in_use, __ATOMIC_ACQUIRE)) {
		debug("syz_mptcp_inject_join_syn: slot %ld not in use\n", slot);
		return -1;
	}
	uint32 token = mptcp_inj_server_token(pair->server_fd);
	if (!token) {
		debug("syz_mptcp_inject_join_syn: slot %ld no token\n", slot);
		return -1;
	}
	int rs = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (rs < 0) {
		debug("syz_mptcp_inject_join_syn: raw socket: %d\n", errno);
		return -1;
	}
	int r = mptcp_inj_send_one(rs, token, pair->server_port_h);
	close(rs);
	if (r < 0) {
		debug("syz_mptcp_inject_join_syn: sendto: %d\n", errno);
		return -1;
	}
	debug("syz_mptcp_inject_join_syn: slot %ld sent MP_JOIN SYN token=0x%x\n",
	      slot, token);
	return 0;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_mptcp_join_close_race
// Teardown-race op (lifecycle op-set): create the finding-005-class close/teardown
// race on demand -- single-threaded and reproducer-clean (no pthread, so the
// generated C reproducer stays portable). Burst MP_JOIN SYNs (server token) at the
// still-open listener: on loopback a raw sendto defers the SYN to the NET_RX
// softirq backlog, so after the burst several SYNs are still queued for
// subflow_token_join_request when we then close the accepted server msk with
// SO_LINGER{1,0} teardown (mptcp_destroy_common -> token_destroy ->
// pm_ops_release), which runs INLINE only when subflows_alive==0 (protocol.c:3570)
// and is otherwise deferred to the mptcp worker -- either way the window exists. A
// queued SYN's softirq token lookup can thus land in the teardown window. TERMINAL: consumes the pair (frees the slot) like pair_close.
// Per-call hit rate is low (narrow window), but across a campaign's many executions
// + varied pre-race state it explores the teardown-race class for novel bugs. If
// the race is won the kernel panics the VM; a clean run returns 0.
static long syz_mptcp_join_close_race(volatile long a0)
{
	long slot = a0;
	int rs = -1, i;
	const int burst = 64;
	struct linger lg;

	if (slot < 0 || slot >= MPTCP_PAIR_POOL_SIZE) {
		debug("syz_mptcp_join_close_race: slot %ld out of range\n", slot);
		return -1;
	}
	struct syz_mptcp_pair_slot* pair = &syz_mptcp_pair_pool[slot];
	if (!__atomic_load_n(&pair->in_use, __ATOMIC_ACQUIRE)) {
		debug("syz_mptcp_join_close_race: slot %ld not in use\n", slot);
		return -1;
	}

	// Burst MP_JOIN SYNs at the still-open listener; a loopback raw sendto defers
	// each to the NET_RX softirq, so several are still queued when we close below.
	uint32 token = mptcp_inj_server_token(pair->server_fd);
	if (token) {
		rs = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
		if (rs >= 0) {
			for (i = 0; i < burst; i++)
				mptcp_inj_send_one(rs, token, pair->server_port_h);
		}
	}

	// Race point: teardown of the accepted server msk (inline when subflows_alive==0,
	// else mptcp-worker-deferred) vs the queued SYNs' softirq token lookups.
	if (pair->server_fd >= 0) {
		lg.l_onoff = 1;
		lg.l_linger = 0;
		setsockopt(pair->server_fd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
		close(pair->server_fd);
		pair->server_fd = -1;
	}
	if (rs >= 0)
		close(rs);

	// Consume the pair (mirror pair_close: guarded fds, preserve generation,
	// reset keys, in_use=false LAST with a release store).
	if (pair->server_fd >= 0)
		close(pair->server_fd);
	if (pair->server_listen_fd >= 0)
		close(pair->server_listen_fd);
	if (pair->client_fd >= 0)
		close(pair->client_fd);
	pair->server_fd = 0;
	pair->client_fd = 0;
	pair->server_listen_fd = 0;
	pair->token = 0;
	pair->server_port_h = 0;
	pair->rwnd_clamped = false;
	pair->local_key = 0;
	pair->remote_key = 0;
	pair->keys_valid = false;
	__atomic_store_n(&pair->in_use, false, __ATOMIC_RELEASE);
	debug("syz_mptcp_join_close_race: slot %ld raced + consumed\n", slot);
	return 0;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_mptcp_close_server
// Lifecycle verb (breadth): close ONLY the accepted server msk -- the incoming-join
// target -- with SO_LINGER{1,0} teardown (inline when subflows_alive==0, else
// mptcp-worker-deferred; mptcp_destroy_common ->
// token_destroy -> pm_ops_release), leaving the listener and client alive. This
// gives the generator a teardown verb to sequence and (via collide) run CONCURRENTLY
// with joins, so the close/teardown race class emerges from syzkaller's own
// scheduling + coverage guidance rather than a hand-crafted timing op. Reproducer-
// clean (single-threaded, no pthread). NON-consuming: the pair stays in_use with
// server_fd set to -1, so a later pair_close skips it (its `>= 0` guard) and cleans
// up the listener/client; ops that need the server msk (inject/subflow_info) then
// fail gracefully on the closed fd.
static long syz_mptcp_close_server(volatile long a0)
{
	long slot = a0;
	struct linger lg;

	if (slot < 0 || slot >= MPTCP_PAIR_POOL_SIZE) {
		debug("syz_mptcp_close_server: slot %ld out of range\n", slot);
		return -1;
	}
	struct syz_mptcp_pair_slot* pair = &syz_mptcp_pair_pool[slot];
	if (!__atomic_load_n(&pair->in_use, __ATOMIC_ACQUIRE)) {
		debug("syz_mptcp_close_server: slot %ld not in use\n", slot);
		return -1;
	}
	if (pair->server_fd < 0) {
		debug("syz_mptcp_close_server: slot %ld server already closed\n", slot);
		return -1;
	}
	lg.l_onoff = 1;
	lg.l_linger = 0;
	setsockopt(pair->server_fd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
	close(pair->server_fd);
	pair->server_fd = -1;
	debug("syz_mptcp_close_server: slot %ld server msk closed\n", slot);
	return 0;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_mptcp_listener_close_race
// Listener-close / accept-vs-worker race op (lifecycle op-set, design §9d). Targets
// the unaccepted-socket teardown UAF class: 0a3f4f1f ("UaF in listener shutdown"),
// b6985b9b ("UaF destroying unaccepted sockets"), 6aeed904 ("race on unaccepted
// mptcp sockets", msk->first UaF). Self-contained -- claims NO pool slot: create a
// fresh MPTCP listener, complete n MP_CAPABLE handshakes WITHOUT accept()ing them
// (they queue as unaccepted msks on the listener's accept queue), send a byte on
// each so the server-side data_ready schedules the msk worker on the unaccepted
// child, then close the listener so inet_csk_listen_stop -> inet_child_forget frees
// the unaccepted children, racing any in-flight worker / softirq token lookup on
// them. KASAN is the oracle; a won race reports a UAF. Reproducer-clean
// (single-threaded, no pthread). Per-call hit rate is low (narrow race); value
// accrues across a campaign's many executions + varied co-scheduled state.
#define MPTCP_LCR_MAX_UNACCEPTED 8
static long syz_mptcp_listener_close_race(volatile long a0)
{
	long n = a0;
	struct sockaddr_in srv_addr;
	socklen_t alen = sizeof(srv_addr);
	int one = 1;
	int listen_fd = -1;
	int client_fd[MPTCP_LCR_MAX_UNACCEPTED];

	if (n < 1)
		n = 1;
	if (n > MPTCP_LCR_MAX_UNACCEPTED)
		n = MPTCP_LCR_MAX_UNACCEPTED;
	for (int i = 0; i < MPTCP_LCR_MAX_UNACCEPTED; i++)
		client_fd[i] = -1;

	listen_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);
	if (listen_fd < 0) {
		debug("syz_mptcp_listener_close_race: listen socket: %d\n", errno);
		return -1;
	}
	setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	memset(&srv_addr, 0, sizeof(srv_addr));
	srv_addr.sin_family = AF_INET;
	srv_addr.sin_port = 0; // kernel picks an ephemeral port
	srv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(listen_fd, (struct sockaddr*)&srv_addr, sizeof(srv_addr)) < 0) {
		debug("syz_mptcp_listener_close_race: bind: %d\n", errno);
		close(listen_fd);
		return -1;
	}
	if (getsockname(listen_fd, (struct sockaddr*)&srv_addr, &alen) < 0) {
		debug("syz_mptcp_listener_close_race: getsockname: %d\n", errno);
		close(listen_fd);
		return -1;
	}
	if (listen(listen_fd, MPTCP_LCR_MAX_UNACCEPTED) < 0) {
		debug("syz_mptcp_listener_close_race: listen: %d\n", errno);
		close(listen_fd);
		return -1;
	}

	// Complete n MP_CAPABLE handshakes but never accept() -- each queues as an
	// unaccepted msk. Send a byte on each so the server schedules the msk worker
	// (widens the free-vs-worker window; targets the 6aeed904 msk->first path).
	for (int i = 0; i < n; i++) {
		client_fd[i] = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);
		if (client_fd[i] < 0) {
			debug("syz_mptcp_listener_close_race: client %d socket: %d\n", i, errno);
			continue;
		}
		if (connect(client_fd[i], (struct sockaddr*)&srv_addr, sizeof(srv_addr)) < 0) {
			debug("syz_mptcp_listener_close_race: client %d connect: %d\n", i, errno);
			continue;
		}
		if (send(client_fd[i], "x", 1, MSG_DONTWAIT) < 0) {
			debug("syz_mptcp_listener_close_race: client %d send: %d\n", i, errno);
		}
	}

	// Race point: closing the listener runs inet_csk_listen_stop ->
	// inet_child_forget, freeing the unaccepted children, racing any in-flight
	// worker / softirq token lookup on them.
	close(listen_fd);

	for (int i = 0; i < n; i++)
		if (client_fd[i] >= 0)
			close(client_fd[i]);

	debug("syz_mptcp_listener_close_race: raced close vs %ld unaccepted\n", n);
	return 0;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_mptcp_disconnect
// Lifecycle verb (differential-instrument increment 1): disconnect an msk via
// connect(fd, AF_UNSPEC), which drives mptcp_disconnect -> mptcp_destroy_common
// (token 0 via token_destroy; pm.ops=NULL via mptcp_pm_destroy->pm_ops_release,
// pm.c:1179) THEN mptcp_pm_data_reset -> mptcp_pm_ops_init (pm.ops re-installed,
// pm.c:1217) -- on the SAME reused socket. Opens the disconnect/reconnect
// reset-staleness surface: the ~50-line pm.ops NULL->reassign window
// (protocol.c:3643->3695) is UNLOCKED vs the softirq JOIN reader, so an injected
// MP_JOIN SYN whose token lookup lands in it derefs NULL pm.ops (domain-reviewer-
// verified: easier to hit than the close/005 path -- larger window +
// refcount_inc_not_zero always succeeds on a reused, not-freed socket). Disconnects
// the ACCEPTED SERVER msk (the join target the token resolves to netns-globally).
// NON-consuming: the socket is reused not closed, so server_fd stays a valid fd and
// the pair remains usable (reconnect / further ops); the fuzzer collides this with
// inject_join_syn for the memory-safety half.
static long syz_mptcp_disconnect(volatile long a0)
{
	long slot = a0;
	struct sockaddr unspec;

	if (slot < 0 || slot >= MPTCP_PAIR_POOL_SIZE) {
		debug("syz_mptcp_disconnect: slot %ld out of range\n", slot);
		return -1;
	}
	struct syz_mptcp_pair_slot* pair = &syz_mptcp_pair_pool[slot];
	if (!__atomic_load_n(&pair->in_use, __ATOMIC_ACQUIRE)) {
		debug("syz_mptcp_disconnect: slot %ld not in use\n", slot);
		return -1;
	}
	if (pair->server_fd < 0) {
		debug("syz_mptcp_disconnect: slot %ld server msk gone\n", slot);
		return -1;
	}
	// connect(AF_UNSPEC): __inet_stream_connect routes to sk_prot->disconnect
	// (= mptcp_disconnect) before the state switch, so it is state-agnostic.
	// mptcp_disconnect re-reads the netns path-manager and checksum settings
	// (mptcp_pm_data_reset, csum_enabled), so apply the server end's own values
	// around it: the end keeps the PM its typed handle says it has.
	struct mptcp_netns_saved saved;
	mptcp_spin_lock(&mptcp_netns_lock);
	mptcp_netns_save(&saved, true, true, false, false);
	mptcp_set_pm(pair->server_kernel_pm);
	mptcp_sysctl_write(MPTCP_SYSCTL_CHECKSUM, pair->checksum_enabled ? "1" : "0");
	memset(&unspec, 0, sizeof(unspec));
	unspec.sa_family = AF_UNSPEC;
	int err = connect(pair->server_fd, &unspec, sizeof(unspec));
	int connect_errno = errno;
	mptcp_netns_restore(&saved);
	mptcp_spin_unlock(&mptcp_netns_lock);
	errno = connect_errno;
	if (err < 0) {
		debug("syz_mptcp_disconnect: connect(AF_UNSPEC): %d\n", errno);
		return -1;
	}
	debug("syz_mptcp_disconnect: slot %ld server msk disconnected\n", slot);
	return 0;
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
	char drain_buf[4096];
	ssize_t sent = 0, drained;

	if (slot < 0 || slot >= MPTCP_PAIR_POOL_SIZE) {
		debug("syz_mptcp_drive_traffic: slot %ld out of range\n", slot);
		return -1;
	}
	struct syz_mptcp_pair_slot* pair = &syz_mptcp_pair_pool[slot];
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
		// Reverse traffic: have the SERVER send so the client kernel emits pure ACKs
		// (DSS data-ack only, light TCP options ~thl 32) -- the low-option from_client
		// carrier that a >=16-byte graft needs (Phase 3b auth ADD_ADDR, Phase 4). The
		// client's OWN data segments are option-full (DSS mapping -> no room for +16).
		// Additive: client->server data still flows, so the same-length DSS ops
		// (Phase 2) and the 8-byte echo graft (Phase 3a) are unaffected. Bounded.
		for (int i = 0; i < 16; i++) {
			ssize_t rn = send(pair->server_fd, data, data_len, MSG_DONTWAIT | MSG_NOSIGNAL);
			if (rn <= 0)
				break;
			// Drain on the client so its window stays open and it keeps ACKing.
			recv(pair->client_fd, drain_buf, sizeof(drain_buf), MSG_DONTWAIT | MSG_NOSIGNAL);
		}
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

// ---------- Userspace path-manager signalling ----------
//
// What a userspace PM daemon (mptcpd) does for one connection: announce an
// address (ADD_ADDR), withdraw one (RM_ADDR), and mark a subflow backup or not
// (MP_PRIO). Each command names one msk by its token, so the ops take the
// userspace-PM end they act on, and only build commands the kernel accepts for
// it. The token is read from the end's socket on every call: disconnect gives an
// msk a new one.

#if MPTCP_NEED_PM_USERSPACE
// Resolves a userspace-PM end of a live pair to its socket. Returns -1 (with a
// debug line) for a stale handle, a kernel-PM end, or a closed server end; the
// descriptions only hand these ops userspace ends, so these are guards.
static int mptcp_pm_userspace_end_fd(const char* who, long slot, bool server)
{
	if (slot < 0 || slot >= MPTCP_PAIR_POOL_SIZE) {
		debug("%s: pair slot %ld out of range\n", who, slot);
		return -1;
	}
	struct syz_mptcp_pair_slot* pair = &syz_mptcp_pair_pool[slot];
	if (!__atomic_load_n(&pair->in_use, __ATOMIC_ACQUIRE)) {
		debug("%s: pair slot %ld not in use\n", who, slot);
		return -1;
	}
	if (server ? pair->server_kernel_pm : pair->client_kernel_pm) {
		debug("%s: pair slot %ld %s end runs the in-kernel PM\n", who, slot, server ? "server" : "client");
		return -1;
	}
	int fd = server ? pair->server_fd : pair->client_fd;
	if (fd <= 0) {
		debug("%s: pair slot %ld %s end closed\n", who, slot, server ? "server" : "client");
		return -1;
	}
	return fd;
}

// The msk token of an MPTCP socket, 0 if it has none (fallen back, closed).
static uint32 mptcp_pm_fd_token(int fd)
{
	struct syz_mptcp_info_short info;
	socklen_t ilen = sizeof(info);

	memset(&info, 0, sizeof(info));
	if (getsockopt(fd, SOL_MPTCP, MPTCP_INFO, &info, &ilen) < 0)
		return 0;
	return info.mptcpi_token;
}

#endif // MPTCP_NEED_PM_USERSPACE

#if SYZ_EXECUTOR || __NR_syz_mptcp_pm_announce || __NR_syz_mptcp_pm_set_flags
static void mptcp_pm_nlmsg_addr4(struct mptcp_nlmsg* m, int typ, int id, uint32 addr_be, uint16 port_h,
				 uint32 flags)
{
	struct nlattr* nest = NULL;
	uint16 fam_v = AF_INET;
	uint8 id_v = (uint8)id;

	mptcp_nlmsg_nest_begin(m, &nest, typ | NLA_F_NESTED);
	mptcp_nlmsg_attr(m, MPTCP_PM_ADDR_ATTR_FAMILY, &fam_v, sizeof(fam_v));
	if (id >= 0)
		mptcp_nlmsg_attr(m, MPTCP_PM_ADDR_ATTR_ID, &id_v, sizeof(id_v));
	mptcp_nlmsg_attr(m, MPTCP_PM_ADDR_ATTR_ADDR4, &addr_be, sizeof(addr_be));
	if (port_h)
		mptcp_nlmsg_attr(m, MPTCP_PM_ADDR_ATTR_PORT, &port_h, sizeof(port_h));
	if (flags)
		mptcp_nlmsg_attr(m, MPTCP_PM_ADDR_ATTR_FLAGS, &flags, sizeof(flags));
	mptcp_nlmsg_nest_end(m, nest);
}
#endif

#if SYZ_EXECUTOR || __NR_syz_mptcp_pm_announce || __NR_syz_mptcp_pm_remove || __NR_syz_mptcp_pm_set_flags
static void mptcp_pm_nlmsg_start(struct mptcp_nlmsg* m, int cmd, uint32 token)
{
	struct genlmsghdr genlhdr;

	memset(&genlhdr, 0, sizeof(genlhdr));
	genlhdr.cmd = cmd;
	genlhdr.version = MPTCP_PM_VER;
	mptcp_nlmsg_init(m, mptcp_pm_family_id, &genlhdr, sizeof(genlhdr));
	mptcp_nlmsg_attr(m, MPTCP_PM_ATTR_TOKEN, &token, sizeof(token));
}

#endif // MPTCP_NEED_PM_USERSPACE

#if SYZ_EXECUTOR || __NR_syz_mptcp_pm_announce || __NR_syz_mptcp_pm_remove || __NR_syz_mptcp_pm_get_endpoint
// Announcements, so a removal names one that was made. A port announcement also
// owns the listener opened on the announced address and port. Per program (the
// executor forks per program); an announcement whose pair was closed or reused
// is stale and its slot is reclaimed by the next announce.
#define MPTCP_ANNOUNCE_POOL_SIZE 32
#define MPTCP_ANNOUNCE_ID_BASE 240
#define MPTCP_ANNOUNCE_PORT_BASE 26200
struct syz_mptcp_announce_slot {
	bool in_use;
	int pair_slot;
	uint32 pair_generation;
	bool server;
	uint8 id;
	int listen_fd;
};
static struct syz_mptcp_announce_slot syz_mptcp_announce_pool[MPTCP_ANNOUNCE_POOL_SIZE];

static bool mptcp_announce_stale(const struct syz_mptcp_announce_slot* a)
{
	const struct syz_mptcp_pair_slot* pair = &syz_mptcp_pair_pool[a->pair_slot];
	return !__atomic_load_n(&pair->in_use, __ATOMIC_ACQUIRE) || pair->generation != a->pair_generation;
}

#if SYZ_EXECUTOR || __NR_syz_mptcp_pm_announce || __NR_syz_mptcp_pm_remove
static void mptcp_announce_release(struct syz_mptcp_announce_slot* a)
{
	if (a->listen_fd > 0)
		close(a->listen_fd);
	a->listen_fd = 0;
	__atomic_store_n(&a->in_use, false, __ATOMIC_RELEASE);
}
#endif
#endif

#if SYZ_EXECUTOR || __NR_syz_mptcp_pm_announce
#define MPTCP_PM_END_CLIENT 0
#define MPTCP_PM_END_SERVER 1

// syz_mptcp_pm_announce(end, side, idx, port): ADD_ADDR of address idx (id
// 240+idx) from the given end: 127.0.2.(idx+1) from the server, 127.0.3.(idx+1)
// from the client. With port, first opens an MPTCP listener on that address and a
// per-announcement port, the way a daemon that announces a port does, so a peer's
// subflow to it reaches the kernel's announced-listener check. Returns the
// announcement.
static long syz_mptcp_pm_announce(volatile long a0, volatile long a1, volatile long a2, volatile long a3)
{
	long slot = a0;
	bool server = a1 == MPTCP_PM_END_SERVER;
	int idx = (int)(a2 & 7);
	bool with_port = a3 != 0;
	struct sockaddr_in sa;
	struct mptcp_nlmsg m;
	int one = 1;

	int fd = mptcp_pm_userspace_end_fd("syz_mptcp_pm_announce", slot, server);
	if (fd < 0)
		return -1;
	if (mptcp_pm_ensure_netlink() < 0)
		return -1;
	uint32 token = mptcp_pm_fd_token(fd);
	if (!token) {
		debug("syz_mptcp_pm_announce: no msk token\n");
		return -1;
	}

	int ann = -1;
	for (int i = 0; i < MPTCP_ANNOUNCE_POOL_SIZE; i++) {
		struct syz_mptcp_announce_slot* a = &syz_mptcp_announce_pool[i];
		bool expected = false;
		if (__atomic_load_n(&a->in_use, __ATOMIC_ACQUIRE) && mptcp_announce_stale(a))
			mptcp_announce_release(a);
		if (ann < 0 && __atomic_compare_exchange_n(&a->in_use, &expected, true, false,
							   __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
			ann = i;
	}
	if (ann < 0) {
		debug("syz_mptcp_pm_announce: announcement pool exhausted\n");
		return -1;
	}
	struct syz_mptcp_announce_slot* a = &syz_mptcp_announce_pool[ann];
	a->pair_slot = slot;
	a->pair_generation = syz_mptcp_pair_pool[slot].generation;
	a->server = server;
	a->id = MPTCP_ANNOUNCE_ID_BASE + idx;
	a->listen_fd = 0;

	uint32 addr_be = htonl((server ? 0x7f000201 : 0x7f000301) + idx);
	uint16 port_h = 0;
	if (with_port) {
		port_h = MPTCP_ANNOUNCE_PORT_BASE + ann;
		int lfd = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);
		memset(&sa, 0, sizeof(sa));
		sa.sin_family = AF_INET;
		sa.sin_addr.s_addr = addr_be;
		sa.sin_port = htons(port_h);
		if (lfd < 0 || setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0 ||
		    bind(lfd, (struct sockaddr*)&sa, sizeof(sa)) < 0 || listen(lfd, 8) < 0) {
			debug("syz_mptcp_pm_announce: listener on port %d: %d\n", port_h, errno);
			if (lfd >= 0)
				close(lfd);
			mptcp_announce_release(a);
			return -1;
		}
		a->listen_fd = lfd;
	}

	mptcp_pm_nlmsg_start(&m, MPTCP_PM_CMD_ANNOUNCE, token);
	mptcp_pm_nlmsg_addr4(&m, MPTCP_PM_ATTR_ADDR, a->id, addr_be, port_h, MPTCP_PM_ADDR_FLAG_SIGNAL);
	if (mptcp_nlmsg_send(&m, mptcp_pm_genl_sock) < 0) {
		int err = errno;
		debug("syz_mptcp_pm_announce: ANNOUNCE: %d\n", err);
		mptcp_announce_release(a);
		errno = err;
		return -1;
	}
	debug("syz_mptcp_pm_announce: pair %ld %s announced id %d port %d\n", slot,
	      server ? "server" : "client", a->id, port_h);
	return ann;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_mptcp_pm_remove
#define MPTCP_PM_REMOVE_ANNOUNCED 0
#define MPTCP_PM_REMOVE_SUBFLOW 1
#define MPTCP_PM_REMOVE_ID0_CLIENT 2
#define MPTCP_PM_REMOVE_ID0_SERVER 3

// REMOVE of local id `id` on the msk behind fd.
static long mptcp_pm_remove_id(const char* who, int fd, uint8 id)
{
	struct mptcp_nlmsg m;
	uint32 token = mptcp_pm_fd_token(fd);

	if (!token) {
		debug("%s: no msk token\n", who);
		return -1;
	}
	mptcp_pm_nlmsg_start(&m, MPTCP_PM_CMD_REMOVE, token);
	mptcp_nlmsg_attr(&m, MPTCP_PM_ATTR_LOC_ID, &id, sizeof(id));
	return mptcp_nlmsg_send(&m, mptcp_pm_genl_sock) < 0 ? -1 : 0;
}

// syz_mptcp_pm_remove(handle, kind): REMOVE of an announcement, of a joined
// subflow's local address id (on the client msk), or of id 0 on either end.
static long syz_mptcp_pm_remove(volatile long a0, volatile long a1)
{
	long h = a0;
	int fd;

	if (mptcp_pm_ensure_netlink() < 0)
		return -1;
	switch ((int)a1) {
	case MPTCP_PM_REMOVE_ANNOUNCED: {
		if (h < 0 || h >= MPTCP_ANNOUNCE_POOL_SIZE ||
		    !__atomic_load_n(&syz_mptcp_announce_pool[h].in_use, __ATOMIC_ACQUIRE)) {
			debug("syz_mptcp_pm_remove: announcement %ld not in use\n", h);
			return -1;
		}
		struct syz_mptcp_announce_slot* a = &syz_mptcp_announce_pool[h];
		if (mptcp_announce_stale(a)) {
			debug("syz_mptcp_pm_remove: announcement %ld outlived its pair\n", h);
			mptcp_announce_release(a);
			return -1;
		}
		fd = mptcp_pm_userspace_end_fd("syz_mptcp_pm_remove", a->pair_slot, a->server);
		long r = fd < 0 ? -1 : mptcp_pm_remove_id("syz_mptcp_pm_remove", fd, a->id);
		int err = errno;
		mptcp_announce_release(a);
		errno = err;
		return r;
	}
	case MPTCP_PM_REMOVE_SUBFLOW: {
		if (h < 0 || h >= MPTCP_SUBFLOW_POOL_SIZE ||
		    !__atomic_load_n(&syz_mptcp_subflow_pool[h].in_use, __ATOMIC_ACQUIRE)) {
			debug("syz_mptcp_pm_remove: subflow %ld not in use\n", h);
			return -1;
		}
		struct syz_mptcp_subflow_slot* sub = &syz_mptcp_subflow_pool[h];
		if (syz_mptcp_pair_pool[sub->pair_slot].generation != sub->pair_generation) {
			debug("syz_mptcp_pm_remove: subflow %ld outlived its pair\n", h);
			return -1;
		}
		fd = mptcp_pm_userspace_end_fd("syz_mptcp_pm_remove", sub->pair_slot, false);
		return fd < 0 ? -1 : mptcp_pm_remove_id("syz_mptcp_pm_remove", fd, sub->addr_id);
	}
	case MPTCP_PM_REMOVE_ID0_CLIENT:
	case MPTCP_PM_REMOVE_ID0_SERVER:
		fd = mptcp_pm_userspace_end_fd("syz_mptcp_pm_remove", h, a1 == MPTCP_PM_REMOVE_ID0_SERVER);
		return fd < 0 ? -1 : mptcp_pm_remove_id("syz_mptcp_pm_remove", fd, 0);
	}
	return -1;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_mptcp_pm_set_flags
#define MPTCP_PM_PRIO_CLIENT 0
#define MPTCP_PM_PRIO_SERVER 1
#define MPTCP_PM_PRIO_SUBFLOW 2

// syz_mptcp_pm_set_flags(handle, kind, backup): SET_FLAGS with a token, which the
// kernel turns into an MP_PRIO on the one subflow matching the exact local and
// remote address: the initial subflow seen from either end, or a joined subflow
// from the client end.
static long syz_mptcp_pm_set_flags(volatile long a0, volatile long a1, volatile long a2)
{
	long h = a0;
	uint32 flags = a2 ? MPTCP_PM_ADDR_FLAG_BACKUP : 0;
	struct sockaddr_in loc, rem;
	struct mptcp_nlmsg m;
	int fd;

	if (mptcp_pm_ensure_netlink() < 0)
		return -1;
	memset(&loc, 0, sizeof(loc));
	memset(&rem, 0, sizeof(rem));
	if (a1 == MPTCP_PM_PRIO_SUBFLOW) {
		if (h < 0 || h >= MPTCP_SUBFLOW_POOL_SIZE ||
		    !__atomic_load_n(&syz_mptcp_subflow_pool[h].in_use, __ATOMIC_ACQUIRE)) {
			debug("syz_mptcp_pm_set_flags: subflow %ld not in use\n", h);
			return -1;
		}
		struct syz_mptcp_subflow_slot* sub = &syz_mptcp_subflow_pool[h];
		if (syz_mptcp_pair_pool[sub->pair_slot].generation != sub->pair_generation) {
			debug("syz_mptcp_pm_set_flags: subflow %ld outlived its pair\n", h);
			return -1;
		}
		fd = mptcp_pm_userspace_end_fd("syz_mptcp_pm_set_flags", sub->pair_slot, false);
		loc.sin_addr.s_addr = sub->local_addr_be;
		loc.sin_port = htons(sub->local_port_h);
		rem.sin_addr.s_addr = htonl(0x7f000001);
		rem.sin_port = htons(sub->remote_port_h);
	} else {
		socklen_t len = sizeof(loc);
		fd = mptcp_pm_userspace_end_fd("syz_mptcp_pm_set_flags", h, a1 == MPTCP_PM_PRIO_SERVER);
		if (fd >= 0 && getsockname(fd, (struct sockaddr*)&loc, &len) < 0)
			fd = -1;
		len = sizeof(rem);
		if (fd >= 0 && getpeername(fd, (struct sockaddr*)&rem, &len) < 0)
			fd = -1;
	}
	if (fd < 0)
		return -1;
	uint32 token = mptcp_pm_fd_token(fd);
	if (!token) {
		debug("syz_mptcp_pm_set_flags: no msk token\n");
		return -1;
	}
	mptcp_pm_nlmsg_start(&m, MPTCP_PM_CMD_SET_FLAGS, token);
	mptcp_pm_nlmsg_addr4(&m, MPTCP_PM_ATTR_ADDR, -1, loc.sin_addr.s_addr, ntohs(loc.sin_port), flags);
	mptcp_pm_nlmsg_addr4(&m, MPTCP_PM_ATTR_ADDR_REMOTE, -1, rem.sin_addr.s_addr, ntohs(rem.sin_port), 0);
	return mptcp_nlmsg_send(&m, mptcp_pm_genl_sock) < 0 ? -1 : 0;
}
#endif
// ---------- Scenario ops: conditions the other ops cannot create ----------
//
// Each op below sets up one condition the kernel acts on and that no sequence of
// the other ops produces: a subflow that stops making progress while another one
// idles (subflow_stall), a subflow the in-kernel PM sees closed by a path error
// (subflow_fail), an MPTCP sysctl written while connections run (set_sysctl), and a
// network namespace destroyed while MPTCP sockets in it are still in use
// (netns_cycle). Each is bounded in time and leaves nothing behind: packets held by
// a stall are released before the call returns, socket options and sysctls are
// put back (or reset per program), and every fd is closed.

// Ops that act on a live pair after sleeping recheck that the pool slot still
// holds the pair they started on (same generation), so a pair closed and its slot
// reused by another pair_init meanwhile is never touched.
#if SYZ_EXECUTOR || __NR_syz_mptcp_subflow_stall || __NR_syz_mptcp_subflow_fail
static bool mptcp_pair_still(const struct syz_mptcp_pair_slot* pair, uint32 gen)
{
	return __atomic_load_n(&pair->in_use, __ATOMIC_ACQUIRE) &&
	       __atomic_load_n(&pair->generation, __ATOMIC_ACQUIRE) == gen;
}

static uint64 mptcp_now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_mptcp_subflow_stall
// Harness constants (mirrored in socket_mptcp_flow.txt + .const).
#define MPTCP_STALL_TARGET_SUBFLOW 0 // the subflow the handle names
#define MPTCP_STALL_TARGET_INITIAL 1 // the pair's initial subflow
#define MPTCP_STALL_DELAY 0 // each packet of the flow arrives delay_ms late
#define MPTCP_STALL_BLOCK 1 // packets are held until the stall ends
#define MPTCP_STALL_DROP 2 // packets are dropped until the stall ends
#define MPTCP_STALL_TO_SERVER 1 // client -> server packets (data on a client push)
#define MPTCP_STALL_TO_CLIENT 2 // server -> client packets (the ACKs of that data)
#define MPTCP_STALL_MAX_MS 1000
#define MPTCP_STALL_MAX_DELAY_MS 100
#define MPTCP_STALL_TICK_US 10000

// Stalls one subflow of a pair for hold_ms while data is pushed both ways every
// tick, then releases it. With DELAY the subflow keeps working but slowly (its RTT
// grows by the delay, kept under TCP's minimum RTO so it does not time out); with
// BLOCK or DROP its ACKs stop advancing. The other subflows run at full speed and
// go idle between pushes: the state the MPTCP scheduler and reinjection logic
// react to. The handle is a subflow, so its pair is validated by generation.
static long syz_mptcp_subflow_stall(volatile long a0, volatile long a1, volatile long a2, volatile long a3,
				    volatile long a4, volatile long a5, volatile long a6, volatile long a7)
{
	long sub_slot = a0;
	int target = (int)a1;
	int mode = (int)a2;
	int dirs = (int)a3 & (MPTCP_STALL_TO_SERVER | MPTCP_STALL_TO_CLIENT);
	int delay_ms = (int)(uint8)a4;
	int hold_ms = (int)(uint16)a5;
	const void* data = (const void*)a6;
	size_t data_len = (size_t)a7;
	char drain_buf[4096];

	if (sub_slot < 0 || sub_slot >= MPTCP_SUBFLOW_POOL_SIZE)
		return -1;
	struct syz_mptcp_subflow_slot* sub = &syz_mptcp_subflow_pool[sub_slot];
	if (!__atomic_load_n(&sub->in_use, __ATOMIC_ACQUIRE))
		return -1;
	uint32 gen = sub->pair_generation;
	struct syz_mptcp_pair_slot* pair = &syz_mptcp_pair_pool[sub->pair_slot];
	if (!mptcp_pair_still(pair, gen) || pair->client_fd < 0 || pair->server_fd < 0) {
		debug("syz_mptcp_subflow_stall: subflow %ld: pair gone\n", sub_slot);
		return -1;
	}
	if (mode < MPTCP_STALL_DELAY || mode > MPTCP_STALL_DROP)
		mode = MPTCP_STALL_DELAY;
	if (!dirs)
		dirs = MPTCP_STALL_TO_SERVER | MPTCP_STALL_TO_CLIENT;
	if (delay_ms < 1)
		delay_ms = 1;
	if (delay_ms > MPTCP_STALL_MAX_DELAY_MS)
		delay_ms = MPTCP_STALL_MAX_DELAY_MS;
	if (hold_ms > MPTCP_STALL_MAX_MS)
		hold_ms = MPTCP_STALL_MAX_MS;
	if (data_len > sizeof(drain_buf))
		data_len = sizeof(drain_buf);

	// The flow, as (client end, server end). A joined subflow has its own local
	// address; its port is known once the join read it back (0 matches any port).
	uint32 client_addr = sub->local_addr_be;
	uint16 client_port = htons(sub->local_port_h);
	if (target == MPTCP_STALL_TARGET_INITIAL) {
		struct sockaddr_in ca;
		socklen_t calen = sizeof(ca);
		if (getsockname(pair->client_fd, (struct sockaddr*)&ca, &calen) < 0 || ca.sin_port == 0) {
			debug("syz_mptcp_subflow_stall: getsockname: %d\n", errno);
			return -1;
		}
		client_addr = ca.sin_addr.s_addr;
		client_port = ca.sin_port;
	}

	syz_nfq_hook = syz_mptcp_mut_hook; // the engine contract: set before setup
	if (syz_nfq_setup() != 0) {
		debug("syz_mptcp_subflow_stall: NFQUEUE setup failed\n");
		return -1;
	}
	int st = syz_nfq_stall_begin(client_addr, client_port, htonl(0x7f000001), htons(sub->remote_port_h),
				     dirs, mode, delay_ms);
	if (st < 0) {
		debug("syz_mptcp_subflow_stall: no free stall slot\n");
		return -1;
	}
	uint64 end = mptcp_now_ms() + hold_ms;
	long pushed = 0;
	do {
		if (!mptcp_pair_still(pair, gen))
			break;
		ssize_t n = send(pair->client_fd, data, data_len, MSG_DONTWAIT | MSG_NOSIGNAL);
		if (n > 0)
			pushed += n;
		send(pair->server_fd, data, data_len, MSG_DONTWAIT | MSG_NOSIGNAL);
		for (int i = 0; i < 4; i++) {
			if (recv(pair->server_fd, drain_buf, sizeof(drain_buf), MSG_DONTWAIT) <= 0)
				break;
		}
		for (int i = 0; i < 4; i++) {
			if (recv(pair->client_fd, drain_buf, sizeof(drain_buf), MSG_DONTWAIT) <= 0)
				break;
		}
		usleep(MPTCP_STALL_TICK_US);
	} while (mptcp_now_ms() < end);
	int left = syz_nfq_stall_end(st);
	debug("syz_mptcp_subflow_stall: subflow %ld target %d mode %d dirs %d delay %d hold %d: pushed %ld, %d left held\n",
	      sub_slot, target, mode, dirs, delay_ms, hold_ms, pushed, left);
	(void)left;
	return 0;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_mptcp_subflow_fail
#ifndef MPTCP_FULL_INFO
#define MPTCP_FULL_INFO 4
#endif
#define MPTCP_FAIL_MAX_SUBFLOWS 8
#define MPTCP_FAIL_WAIT_MS 3500
// TCP states as tcp_info reports them (include/net/tcp_states.h).
#define MPTCP_FAIL_TCP_ESTABLISHED 1
#define MPTCP_FAIL_TCP_CLOSE 7

// Prefix of struct mptcp_full_info (uapi <linux/mptcp.h>, MPTCP_FULL_INFO): only
// the header is passed, so the kernel fills the two arrays and skips mptcp_info.
struct syz_mptcp_full_info_hdr {
	uint32 size_tcpinfo_kernel;
	uint32 size_tcpinfo_user;
	uint32 size_sfinfo_kernel;
	uint32 size_sfinfo_user;
	uint32 num_subflows;
	uint32 size_arrays_user;
	uint64 subflow_info;
	uint64 tcp_info;
};

// struct mptcp_subflow_info: a u32 id, then the local and remote addresses as
// sockaddr_storage (8-byte aligned, as __kernel_sockaddr_storage is).
struct syz_mptcp_sfinfo {
	uint32 id;
	struct sockaddr_storage local;
	struct sockaddr_storage remote;
};

// Reads the msk's subflows: each one's id, IPv4 addresses and TCP state (the first
// byte of struct tcp_info). Returns their number (at most max), or -1.
static int mptcp_fail_list(int fd, struct syz_mptcp_sfinfo* sf, uint8* state, int max)
{
	uint8 ti[MPTCP_FAIL_MAX_SUBFLOWS][8];
	struct syz_mptcp_full_info_hdr h;
	socklen_t len = sizeof(h);

	memset(&h, 0, sizeof(h));
	memset(sf, 0, sizeof(*sf) * max);
	h.size_tcpinfo_user = sizeof(ti[0]);
	h.size_sfinfo_user = sizeof(*sf);
	h.size_arrays_user = max;
	h.subflow_info = (uint64)(long)sf;
	h.tcp_info = (uint64)(long)ti;
	if (getsockopt(fd, SOL_MPTCP, MPTCP_FULL_INFO, &h, &len) < 0)
		return -1;
	int n = h.num_subflows < (uint32)max ? (int)h.num_subflows : max;
	for (int i = 0; i < n; i++)
		state[i] = ti[i][0];
	return n;
}

// Makes one subflow of a client end on the in-kernel PM fail the way a dead path
// does: TCP gives up on it with a timeout error. The client msk gets the shortest
// keepalive (1s idle, 1 probe, 1s apart), which MPTCP applies to every subflow,
// while all packets of the chosen subflow are dropped. Its probe goes unanswered
// and TCP closes it with ETIMEDOUT about 2s later; the other subflows answer their
// probes and stay up. When the in-kernel PM closes the failed subflow it can
// re-create it (the subflow-retries limit) if another subflow can still send.
// An injected reset would not do: a reset means the path works, and the PM does
// not retry it. Bounded by MPTCP_FAIL_WAIT_MS; the keepalive settings are put back
// and the drop removed before returning.
static long syz_mptcp_subflow_fail(volatile long a0, volatile long a1)
{
	long slot = a0;
	int which = (int)(uint8)a1;
	struct syz_mptcp_sfinfo sf[MPTCP_FAIL_MAX_SUBFLOWS];
	uint8 state[MPTCP_FAIL_MAX_SUBFLOWS];
	int one = 1, zero = 0;

	if (slot < 0 || slot >= MPTCP_PAIR_POOL_SIZE)
		return -1;
	struct syz_mptcp_pair_slot* pair = &syz_mptcp_pair_pool[slot];
	uint32 gen = __atomic_load_n(&pair->generation, __ATOMIC_ACQUIRE);
	if (!mptcp_pair_still(pair, gen) || pair->client_fd < 0)
		return -1;
	// The retry is in-kernel PM behaviour; the description only hands this call a
	// kernel-PM client end.
	if (!pair->client_kernel_pm) {
		debug("syz_mptcp_subflow_fail: pair %ld client runs the userspace PM\n", slot);
		return -1;
	}
	int fd = pair->client_fd;

	// Pick the which-th established IPv4 subflow.
	int n = mptcp_fail_list(fd, sf, state, MPTCP_FAIL_MAX_SUBFLOWS);
	int est[MPTCP_FAIL_MAX_SUBFLOWS], nest = 0;
	for (int i = 0; i < n; i++) {
		if (state[i] == MPTCP_FAIL_TCP_ESTABLISHED && sf[i].local.ss_family == AF_INET)
			est[nest++] = i;
	}
	if (nest == 0) {
		debug("syz_mptcp_subflow_fail: pair %ld: no established subflow (%d listed, errno %d)\n", slot, n, errno);
		return -1;
	}
	struct syz_mptcp_sfinfo* t = &sf[est[which % nest]];
	uint32 id = t->id;
	struct sockaddr_in* l = (struct sockaddr_in*)&t->local;
	struct sockaddr_in* r = (struct sockaddr_in*)&t->remote;

	syz_nfq_hook = syz_mptcp_mut_hook; // the engine contract: set before setup
	if (syz_nfq_setup() != 0) {
		debug("syz_mptcp_subflow_fail: NFQUEUE setup failed\n");
		return -1;
	}
	int st = syz_nfq_stall_begin(l->sin_addr.s_addr, l->sin_port, r->sin_addr.s_addr, r->sin_port,
				     SYZ_NFQ_STALL_A_TO_B | SYZ_NFQ_STALL_B_TO_A, SYZ_NFQ_STALL_DROP, 0);
	if (st < 0)
		return -1;

	// Save the msk's keepalive settings (the getsockopt values include the netns
	// defaults), then arm the shortest keepalive.
	int idle = 0, intvl = 0, cnt = 0, ka = 0;
	socklen_t ol = sizeof(int);
	getsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &ka, &ol);
	ol = sizeof(int);
	getsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, &ol);
	ol = sizeof(int);
	getsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, &ol);
	ol = sizeof(int);
	getsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, &ol);
	setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &one, sizeof(one));
	setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &one, sizeof(one));
	setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &one, sizeof(one));
	setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));

	// Wait until the subflow is closed (gone from the list, or listed as closed:
	// the initial subflow stays listed).
	bool closed = false;
	uint64 end = mptcp_now_ms() + MPTCP_FAIL_WAIT_MS;
	while (mptcp_now_ms() < end && mptcp_pair_still(pair, gen)) {
		usleep(50000);
		n = mptcp_fail_list(fd, sf, state, MPTCP_FAIL_MAX_SUBFLOWS);
		if (n < 0)
			break;
		closed = true;
		for (int i = 0; i < n; i++) {
			if (sf[i].id == id && state[i] != MPTCP_FAIL_TCP_CLOSE)
				closed = false;
		}
		if (closed)
			break;
	}

	if (mptcp_pair_still(pair, gen)) {
		setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, ka ? &one : &zero, sizeof(int));
		if (idle > 0)
			setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
		if (intvl > 0)
			setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl));
		if (cnt > 0)
			setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt));
	}
	syz_nfq_stall_end(st);
	debug("syz_mptcp_subflow_fail: pair %ld subflow id %u %s\n", slot, id, closed ? "closed" : "still open");
	return closed ? 0 : -1;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_mptcp_set_sysctl
// Knobs of syz_mptcp_set_sysctl (harness constants, mirrored in .txt + .const).
#define MPTCP_SYSCTL_KNOB_SCHEDULER 0
#define MPTCP_SYSCTL_KNOB_PATH_MANAGER 1
#define MPTCP_SYSCTL_KNOB_CHECKSUM 2
#define MPTCP_SYSCTL_KNOB_ADD_ADDR_TIMEOUT 3
#define MPTCP_SYSCTL_KNOB_CLOSE_TIMEOUT 4
#define MPTCP_SYSCTL_KNOB_STALE_LOSS_CNT 5
#define MPTCP_SYSCTL_KNOB_ALLOW_JOIN_ID0 6
#define MPTCP_SYSCTL_KNOB_BLACKHOLE_TIMEOUT 7
#define MPTCP_SYSCTL_KNOB_SYN_RETRANS 8
#define MPTCP_SYSCTL_KNOB_ADD_ADDR_V6_PORT_DROP_TS 9

struct mptcp_sysctl_knob {
	const char* name; // under /proc/sys/net/mptcp/
	uint32 max; // values are taken modulo max+1; 0 for a name from a list
	const char* list; // file with the valid names, for string knobs
};

// `enabled` is not offered: turning MPTCP off breaks every other call. Nor is
// pm_type: it is deprecated (since v6.15) in favour of path_manager, and writing
// it rewrites path_manager too. Numeric ranges stay where a connection still
// behaves (timeouts in seconds).
static const struct mptcp_sysctl_knob mptcp_sysctl_knobs[] = {
    {"scheduler", 0, "available_schedulers"},
    {"path_manager", 0, "available_path_managers"},
    {"checksum_enabled", 1, NULL},
    {"add_addr_timeout", 120, NULL},
    {"close_timeout", 120, NULL},
    {"stale_loss_cnt", 16, NULL},
    {"allow_join_initial_addr_port", 1, NULL},
    {"blackhole_timeout", 3600, NULL},
    {"syn_retrans_before_tcp_fallback", 10, NULL},
    {"add_addr_v6_port_drop_ts", 1, NULL},
};

// Writes one MPTCP sysctl with a valid value while whatever else the program runs
// keeps running: names come from the kernel's own list of available ones, numbers
// from the knob's range. The value stays until the executor's per-program netns
// reset restores it (every knob here is in net_sysctls[], common_linux.h). The
// write takes mptcp_netns_lock, which pair_init holds while it sets each end's PM
// and creates the pair: pair_init saves and restores path_manager, checksum and
// allow_join_initial_addr_port around its handshake, so a written value survives
// it and governs msks created by plain socket() calls, and a write never lands
// inside a handshake.
static long syz_mptcp_set_sysctl(volatile long a0, volatile long a1)
{
	uint32 knob = (uint32)a0;
	uint32 val = (uint32)a1;
	char path[128], prev[64], value[64];

	if (knob >= sizeof(mptcp_sysctl_knobs) / sizeof(mptcp_sysctl_knobs[0]))
		return -1;
	const struct mptcp_sysctl_knob* k = &mptcp_sysctl_knobs[knob];
	if (k->list) {
		// Pick the val-th name (modulo their number) of the space-separated list.
		char names[256];
		snprintf(path, sizeof(path), "/proc/sys/net/mptcp/%s", k->list);
		if (!mptcp_sysctl_read(path, names, sizeof(names)))
			return -1;
		int count = 0;
		for (char* p = names; *p;) {
			while (*p == ' ' || *p == '\t')
				p++;
			if (!*p)
				break;
			count++;
			while (*p && *p != ' ' && *p != '\t')
				p++;
		}
		if (count == 0)
			return -1;
		int want = val % count, i = 0;
		value[0] = 0;
		for (char* p = names; *p;) {
			while (*p == ' ' || *p == '\t')
				p++;
			if (!*p)
				break;
			char* s = p;
			while (*p && *p != ' ' && *p != '\t')
				p++;
			if (i++ == want) {
				int l = p - s < (int)sizeof(value) - 1 ? p - s : (int)sizeof(value) - 1;
				memcpy(value, s, l);
				value[l] = 0;
				break;
			}
		}
	} else {
		snprintf(value, sizeof(value), "%u", val % (k->max + 1));
	}
	snprintf(path, sizeof(path), "/proc/sys/net/mptcp/%s", k->name);

	mptcp_spin_lock(&mptcp_netns_lock);
	// Read first: the handler's read side runs too, and the log shows the change.
	if (!mptcp_sysctl_read(path, prev, sizeof(prev)))
		prev[0] = 0;
	bool ok = mptcp_sysctl_write(path, value);
	mptcp_spin_unlock(&mptcp_netns_lock);
	debug("syz_mptcp_set_sysctl: %s: %s -> %s (%s)\n", k->name, prev, value, ok ? "ok" : "failed");
	return ok ? 0 : -1;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_mptcp_netns_cycle
#include <net/if.h>
#include <pthread.h>
#include <sched.h>
#include <sys/ioctl.h>

#define MPTCP_NETNS_MAX_CONNS 4
// Flags (harness constants, mirrored in .txt + .const).
#define MPTCP_NETNS_ENDPOINTS 1 // in-kernel PM endpoints: a subflow one, a signal one with a port
#define MPTCP_NETNS_ABORT 2 // close with SO_LINGER{1,0} (reset) instead of a FIN
#define MPTCP_NETNS_UNREAD 4 // leave data unread in both directions
#define MPTCP_NETNS_SIGNAL_PORT 26116

// In-kernel PM configuration inside the new netns, over a genl socket created
// there (a netlink socket acts in the netns it was created in).
static void mptcp_netns_add_endpoints(void)
{
	int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (sock < 0)
		return;
	struct timeval rtv = {1, 0};
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &rtv, sizeof(rtv));
	uint16 family = 0;
	uint32 grp = 0;
	if (mptcp_pm_resolve_family(sock, &family, &grp) < 0) {
		close(sock);
		return;
	}
	struct mptcp_nlmsg m;
	struct genlmsghdr genlhdr;
	memset(&genlhdr, 0, sizeof(genlhdr));
	genlhdr.version = MPTCP_PM_VER;
	genlhdr.cmd = MPTCP_PM_CMD_SET_LIMITS;
	uint32 two = 2;
	mptcp_nlmsg_init(&m, family, &genlhdr, sizeof(genlhdr));
	mptcp_nlmsg_attr(&m, MPTCP_PM_ATTR_RCV_ADD_ADDRS, &two, sizeof(two));
	mptcp_nlmsg_attr(&m, MPTCP_PM_ATTR_SUBFLOWS, &two, sizeof(two));
	mptcp_nlmsg_send(&m, sock);
	// id 1: subflow endpoint 127.0.1.1; id 2: signal endpoint 127.0.1.2 with a port
	// (the kernel opens its own listener on it).
	uint32 ifindex = if_nametoindex("lo");
	for (int i = 1; i <= 2; i++) {
		uint8 id = i;
		uint16 fam = AF_INET;
		uint32 addr_be = htonl(0x7f000100 + i);
		uint32 flags = i == 1 ? MPTCP_PM_ADDR_FLAG_SUBFLOW : MPTCP_PM_ADDR_FLAG_SIGNAL;
		uint16 port = MPTCP_NETNS_SIGNAL_PORT;
		struct nlattr* nest = NULL;
		genlhdr.cmd = MPTCP_PM_CMD_ADD_ADDR;
		mptcp_nlmsg_init(&m, family, &genlhdr, sizeof(genlhdr));
		mptcp_nlmsg_nest_begin(&m, &nest, MPTCP_PM_ATTR_ADDR | NLA_F_NESTED);
		mptcp_nlmsg_attr(&m, MPTCP_PM_ADDR_ATTR_ID, &id, sizeof(id));
		mptcp_nlmsg_attr(&m, MPTCP_PM_ADDR_ATTR_FAMILY, &fam, sizeof(fam));
		mptcp_nlmsg_attr(&m, MPTCP_PM_ADDR_ATTR_ADDR4, &addr_be, sizeof(addr_be));
		mptcp_nlmsg_attr(&m, MPTCP_PM_ADDR_ATTR_IF_IDX, &ifindex, sizeof(ifindex));
		if (i == 2)
			mptcp_nlmsg_attr(&m, MPTCP_PM_ADDR_ATTR_PORT, &port, sizeof(port));
		mptcp_nlmsg_attr(&m, MPTCP_PM_ADDR_ATTR_FLAGS, &flags, sizeof(flags));
		mptcp_nlmsg_nest_end(&m, nest);
		if (mptcp_nlmsg_send(&m, sock) < 0) {
			debug("mptcp_netns_add_endpoints: endpoint %d: %d\n", i, errno);
		}
	}
	close(sock);
}

// The connections of syz_mptcp_netns_cycle, in the current netns. Every fd opened
// is recorded in fds, for the caller to close.
static long mptcp_netns_connect(int nconns, int flags, int* fds, int* nfds)
{
	struct sockaddr_in sa;
	socklen_t salen = sizeof(sa);
	char buf[2048];

	// connect() and accept() honour the send/receive timeouts: bound both, so a
	// lost handshake packet cannot hold the call for the SYN retry period.
	struct timeval tv = {0, 300000};
	int lfd = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);
	if (lfd < 0)
		return -1;
	fds[(*nfds)++] = lfd;
	setsockopt(lfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(lfd, (struct sockaddr*)&sa, sizeof(sa)) < 0 || getsockname(lfd, (struct sockaddr*)&sa, &salen) < 0 ||
	    listen(lfd, MPTCP_NETNS_MAX_CONNS) < 0)
		return -1;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	memset(buf, 'x', sizeof(buf));
	for (int i = 0; i < nconns; i++) {
		int c = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);
		if (c < 0)
			return -1;
		fds[(*nfds)++] = c;
		setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
		if (connect(c, (struct sockaddr*)&sa, sizeof(sa)) < 0)
			return -1;
		int s = accept(lfd, NULL, NULL);
		if (s < 0)
			return -1;
		fds[(*nfds)++] = s;
		send(c, buf, sizeof(buf), MSG_DONTWAIT | MSG_NOSIGNAL);
		send(s, buf, sizeof(buf), MSG_DONTWAIT | MSG_NOSIGNAL);
		if (!(flags & MPTCP_NETNS_UNREAD)) {
			recv(s, buf, sizeof(buf), MSG_DONTWAIT);
			recv(c, buf, sizeof(buf), MSG_DONTWAIT);
		}
	}
	// Give the in-kernel PM a moment to act on the new connections (it runs from
	// the msk worker once they are fully established).
	if (flags & MPTCP_NETNS_ENDPOINTS)
		usleep(20000);
	return 0;
}

// Creates the namespace from a helper thread, brings its loopback up, and returns
// an fd for it. A new
// namespace initializes every per-netns subsystem of the kernel, far more code
// than the kcov buffer holds: done on the calling thread, it would fill the
// call's coverage with that (truncating what the MPTCP connections reach) and,
// twice in one program, overflow the executor's coverage output. The helper
// thread has no kcov, so only what the call does inside the namespace counts.
static void* mptcp_netns_create_thread(void* arg)
{
	int* fd = (int*)arg;
	*fd = -1;
	if (unshare(CLONE_NEWNET) != 0)
		return NULL;
	// Bringing the loopback device up is generic device code too (addrconf,
	// multicast, ...), and as much coverage again: also done here.
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s >= 0) {
		struct ifreq ifr;
		memset(&ifr, 0, sizeof(ifr));
		strcpy(ifr.ifr_name, "lo");
		if (ioctl(s, SIOCGIFFLAGS, &ifr) == 0) {
			ifr.ifr_flags |= IFF_UP;
			ioctl(s, SIOCSIFFLAGS, &ifr);
		}
		close(s);
	}
	*fd = open("/proc/thread-self/ns/net", O_RDONLY);
	return NULL;
}

// Creates a network namespace (mptcp_net_init runs, on a helper thread), brings its loopback up,
// connects nconns MPTCP pairs in it (optionally with in-kernel PM endpoints, so the
// PM adds subflows and opens its own listener) and pushes data, then returns to
// the caller's netns and closes everything at once. The user sockets were the
// last references to the namespace, so it is destroyed (cleanup_net ->
// mptcp_net_exit and the PM's per-netns exit) while the connections it held are
// still closing: subflows, kernel listener, timers. Only the calling thread
// switches namespace, and it switches back before anything else runs on it.
static long syz_mptcp_netns_cycle(volatile long a0, volatile long a1)
{
	int nconns = (int)(uint8)a0;
	int flags = (int)a1;
	int fds[1 + 2 * MPTCP_NETNS_MAX_CONNS];
	int nfds = 0;
	long ret = -1;

	if (nconns < 1)
		nconns = 1;
	if (nconns > MPTCP_NETNS_MAX_CONNS)
		nconns = MPTCP_NETNS_MAX_CONNS;
	int orig = open("/proc/thread-self/ns/net", O_RDONLY);
	if (orig < 0)
		return -1;
	int nsfd = -1;
	pthread_t th;
	if (pthread_create(&th, NULL, mptcp_netns_create_thread, &nsfd) != 0) {
		close(orig);
		return -1;
	}
	pthread_join(th, NULL);
	if (nsfd < 0 || setns(nsfd, CLONE_NEWNET) < 0) {
		debug("syz_mptcp_netns_cycle: create/enter netns: %d\n", errno);
		if (nsfd >= 0)
			close(nsfd);
		close(orig);
		return -1;
	}
	// From here the calling thread and the sockets below hold the namespace.
	close(nsfd);
	if (flags & MPTCP_NETNS_ENDPOINTS)
		mptcp_netns_add_endpoints();

	ret = mptcp_netns_connect(nconns, flags, fds, &nfds);
	if (setns(orig, CLONE_NEWNET) < 0)
		fail("syz_mptcp_netns_cycle: setns back to the original netns failed");
	close(orig);
	for (int i = 0; i < nfds; i++) {
		if (flags & MPTCP_NETNS_ABORT) {
			struct linger lg;
			lg.l_onoff = 1;
			lg.l_linger = 0;
			setsockopt(fds[i], SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
		}
		close(fds[i]);
	}
	debug("syz_mptcp_netns_cycle: %d conns, flags 0x%x, %d fds: %ld\n", nconns, flags, nfds, ret);
	return ret;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_mptcp_pm_get_endpoint
#define MPTCP_PM_GET_KERNEL 0
#define MPTCP_PM_GET_ANNOUNCED 1

// syz_mptcp_pm_get_endpoint(handle, kind): GET_ADDR of an in-kernel PM endpoint
// by id (ip mptcp endpoint show id N), or of a userspace announcement by token
// and id.
static long syz_mptcp_pm_get_endpoint(volatile long a0, volatile long a1)
{
	long h = a0;
	struct mptcp_nlmsg m;
	uint8 id;
	uint32 addr_be;

	if (mptcp_pm_ensure_netlink() < 0)
		return -1;
	if (a1 == MPTCP_PM_GET_ANNOUNCED) {
		if (h < 0 || h >= MPTCP_ANNOUNCE_POOL_SIZE ||
		    !__atomic_load_n(&syz_mptcp_announce_pool[h].in_use, __ATOMIC_ACQUIRE) ||
		    mptcp_announce_stale(&syz_mptcp_announce_pool[h])) {
			debug("syz_mptcp_pm_get_endpoint: announcement %ld not live\n", h);
			return -1;
		}
		struct syz_mptcp_announce_slot* a = &syz_mptcp_announce_pool[h];
		int fd = mptcp_pm_userspace_end_fd("syz_mptcp_pm_get_endpoint", a->pair_slot, a->server);
		uint32 token = fd < 0 ? 0 : mptcp_pm_fd_token(fd);
		if (!token)
			return -1;
		mptcp_pm_endpoint_build(&m, MPTCP_PM_CMD_GET_ADDR, a->id, 0, false, 0, 0);
		mptcp_nlmsg_attr(&m, MPTCP_PM_ATTR_TOKEN, &token, sizeof(token));
	} else {
		if (h == MPTCP_PM_ENDPOINT_ID0 || !mptcp_pm_endpoint_resolve(h, &id, &addr_be) || !id)
			return -1;
		mptcp_pm_endpoint_build(&m, MPTCP_PM_CMD_GET_ADDR, id, 0, false, 0, 0);
	}
	return mptcp_nlmsg_query(&m, false, NULL, NULL);
}
#endif

#if SYZ_EXECUTOR || __NR_syz_mptcp_pm_dump_endpoints
#define MPTCP_PM_DUMP_KERNEL 0
#define MPTCP_PM_DUMP_CLIENT 1
#define MPTCP_PM_DUMP_SERVER 2

// syz_mptcp_pm_dump_endpoints(handle, kind): dump the in-kernel PM endpoint table
// (ip mptcp endpoint show), or one userspace-PM end's address list (by token).
static long syz_mptcp_pm_dump_endpoints(volatile long a0, volatile long a1)
{
	struct mptcp_nlmsg m;
	struct genlmsghdr genlhdr;

	if (mptcp_pm_ensure_netlink() < 0)
		return -1;
	memset(&genlhdr, 0, sizeof(genlhdr));
	genlhdr.cmd = MPTCP_PM_CMD_GET_ADDR;
	genlhdr.version = MPTCP_PM_VER;
	mptcp_nlmsg_init(&m, mptcp_pm_family_id, &genlhdr, sizeof(genlhdr));
	if (a1 != MPTCP_PM_DUMP_KERNEL) {
		int fd = mptcp_pm_userspace_end_fd("syz_mptcp_pm_dump_endpoints", a0, a1 == MPTCP_PM_DUMP_SERVER);
		uint32 token = fd < 0 ? 0 : mptcp_pm_fd_token(fd);
		if (!token)
			return -1;
		mptcp_nlmsg_attr(&m, MPTCP_PM_ATTR_TOKEN, &token, sizeof(token));
	}
	return mptcp_nlmsg_query(&m, true, NULL, NULL);
}
#endif

#if SYZ_EXECUTOR || __NR_syz_mptcp_pm_get_limits
// syz_mptcp_pm_get_limits(): GET_LIMITS (ip mptcp limits show).
static long syz_mptcp_pm_get_limits(void)
{
	struct mptcp_nlmsg m;
	struct genlmsghdr genlhdr;

	if (mptcp_pm_ensure_netlink() < 0)
		return -1;
	memset(&genlhdr, 0, sizeof(genlhdr));
	genlhdr.cmd = MPTCP_PM_CMD_GET_LIMITS;
	genlhdr.version = MPTCP_PM_VER;
	mptcp_nlmsg_init(&m, mptcp_pm_family_id, &genlhdr, sizeof(genlhdr));
	return mptcp_nlmsg_query(&m, false, NULL, NULL);
}
#endif

#endif // EXECUTOR_COMMON_LINUX_MPTCP_H
