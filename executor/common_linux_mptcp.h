// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found
// in the LICENSE file.

// MPTCP (Multipath TCP, RFC 8684) MP_CAPABLE pair pseudo-syscalls.
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
// Scope of this increment: MP_CAPABLE only. No MP_JOIN, no key/HMAC
// capture, no kernel-side instrumentation -- those need kernel-side
// support and land as a later increment. This file runs unmodified on
// any stock CONFIG_MPTCP kernel and has no dependency beyond the
// standard socket headers already used throughout common_linux.h.
//
// The server_addr/client_addr syzlang inputs are accepted (so the
// resource contract stays real-address shaped for later increments
// that add non-loopback / multi-address / netns support) but are not
// yet consulted: v0 always binds and connects on 127.0.0.1 with an
// ephemeral server port, which is what makes a bare MP_CAPABLE
// handshake reliable on a stock kernel with no extra setup.

#ifndef SYZ_COMMON_LINUX_MPTCP_H
#define SYZ_COMMON_LINUX_MPTCP_H

#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>

// IPPROTO_MPTCP is provided by <netinet/in.h> on any glibc recent enough to
// know about MPTCP (which any host running a CONFIG_MPTCP kernel will have);
// deliberately not given a local fallback definition here -- pkg/csource's
// reference-build preprocessing pass runs with -nostdinc, so a guarded
// fallback (`#ifndef IPPROTO_MPTCP ... #endif`) would wrongly fire during
// that pass and then collide with the real header's definition when the
// generated reproducer is actually compiled.

#define SYZ_MPTCP_PAIR_POOL_SIZE 64

struct syz_mptcp_pair_slot {
	bool in_use;
	int server_fd;
	int client_fd;
};

static struct syz_mptcp_pair_slot syz_mptcp_pair_pool[SYZ_MPTCP_PAIR_POOL_SIZE];

#if SYZ_EXECUTOR || __NR_syz_mptcp_pair_init
static long syz_mptcp_pair_init(volatile long a0, volatile long a1)
{
	// server_addr / client_addr: not yet consulted, see file comment.
	(void)a0;
	(void)a1;

	struct sockaddr_in srv_addr;
	socklen_t alen;
	int slot;
	int one = 1;
	int server_listen_fd = -1, client_fd = -1, server_fd = -1;

	for (slot = 0; slot < SYZ_MPTCP_PAIR_POOL_SIZE; slot++) {
		if (!syz_mptcp_pair_pool[slot].in_use)
			break;
	}
	if (slot == SYZ_MPTCP_PAIR_POOL_SIZE) {
		debug("syz_mptcp_pair_init: pool exhausted (size=%d)\n",
		      SYZ_MPTCP_PAIR_POOL_SIZE);
		return -1;
	}

	server_listen_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);
	if (server_listen_fd < 0) {
		debug("syz_mptcp_pair_init: server socket: %d\n", errno);
		return -1;
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
	if (listen(server_listen_fd, 1) < 0) {
		debug("syz_mptcp_pair_init: listen: %d\n", errno);
		goto fail;
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
	// Single accept done; the listener isn't needed for the rest of
	// this pair's lifetime.
	close(server_listen_fd);
	server_listen_fd = -1;

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

	syz_mptcp_pair_pool[slot].in_use = true;
	syz_mptcp_pair_pool[slot].server_fd = server_fd;
	syz_mptcp_pair_pool[slot].client_fd = client_fd;
	debug("syz_mptcp_pair_init: pair %d established, port %d\n", slot,
	      ntohs(srv_addr.sin_port));
	return slot;

fail:
	if (server_fd >= 0)
		close(server_fd);
	if (client_fd >= 0)
		close(client_fd);
	if (server_listen_fd >= 0)
		close(server_listen_fd);
	return -1;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_mptcp_pair_close
static long syz_mptcp_pair_close(volatile long a0)
{
	long slot = a0;

	if (slot < 0 || slot >= SYZ_MPTCP_PAIR_POOL_SIZE) {
		debug("syz_mptcp_pair_close: slot %ld out of range\n", slot);
		return -1;
	}
	if (!syz_mptcp_pair_pool[slot].in_use) {
		debug("syz_mptcp_pair_close: slot %ld not in use\n", slot);
		return -1;
	}
	if (syz_mptcp_pair_pool[slot].server_fd >= 0)
		close(syz_mptcp_pair_pool[slot].server_fd);
	if (syz_mptcp_pair_pool[slot].client_fd >= 0)
		close(syz_mptcp_pair_pool[slot].client_fd);
	memset(&syz_mptcp_pair_pool[slot], 0, sizeof(syz_mptcp_pair_pool[slot]));
	return 0;
}
#endif

#endif // SYZ_COMMON_LINUX_MPTCP_H
