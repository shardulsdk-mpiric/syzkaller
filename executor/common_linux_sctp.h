// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// SCTP (RFC 9260) association-pair + vtag-capture + chunk-inject
// pseudo-syscalls. Increment 1.
//
// This is the SCTP analogue of the MPTCP harness (common_linux_mptcp.h): it
// satisfies the protocol gate with real endpoints, captures the per-connection
// secret off the wire, then injects past the gate. SCTP's gate is the 32-bit
// verification tag (vtag) echoed on every non-INIT packet
// (sctp_vtag_verify, include/net/sctp/sm.h) -- structurally the same wall as
// MPTCP's token/HMAC gate, but cryptographically simpler: a captured cleartext
// tag, not a 160-bit HMAC. See the kernel KB under
// open/src/kernel/linux/.claude/knowledge/linux/net/sctp/ and the harness
// design at open/src/fuzzing/brf/.claude/designs/sctp_harness_design.md.
//
// syz_sctp_pair_init() drives a real SCTP association to ESTABLISHED on
// loopback: socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP) + SO_REUSEADDR +
// bind(127.0.0.1:0) + listen() on the server, socket(SCTP) + connect() on the
// client. The kernel runs the full 4-way INIT/INIT-ACK/COOKIE-ECHO/COOKIE-ACK
// handshake itself, so the state-cookie HMAC gate is crossed for real with no
// userspace crypto. accept() takes the server side. Both ends are ESTABLISHED
// at COOKIE-ACK, so -- unlike MPTCP -- there is NO fully_established priming
// round-trip, and SCTP has NO genl path-manager setup. The client/server fds
// are held in a static pool; the pool index is the sctp_assoc resource.
//
// With SCTP_INIT_CAPTURE_VTAG the call opens an AF_PACKET loopback sniffer
// BEFORE connect() (so the handshake is buffered) and extracts the init_tag
// from the INIT and INIT-ACK common/chunk headers -- the tag is cleartext on
// the wire and is NOT exposed by any getsockopt (struct sctp_status has no
// vtag field), so on-wire capture is required for the inject path.
//
// syz_sctp_pair_close() closes the fds and frees the slot -- the consuming
// edge (mirrors syz_mptcp_pair_close).
//
// syz_sctp_drive_traffic() sctp_sendmsg()s on the association (reaches the
// DATA / reassembly path) -- analogue of syz_mptcp_drive_traffic.
//
// syz_sctp_inject_chunk() is the edge (M-CARRY): it crafts a full SCTP packet
// (common header with the captured vtag + CRC32c) carrying one attacker-shaped
// chunk and injects it via a raw IPPROTO_SCTP socket toward the server
// endpoint. With vtag_mode=CAPTURED the kernel's sctp_vtag_verify passes and
// the chunk reaches its handler with attacker bytes; ZERO/WRONG are negative
// controls (dropped at the vtag gate). CRC32c (Castagnoli, reflected poly
// 0x82f63b78) is the one new primitive over the MPTCP harness -- a checksum,
// not crypto.
//
// Scope of this increment: NORMAL establish + vtag capture + M-CARRY inject +
// data drive. No NFQUEUE egress mutation (M-WIRE), no feature-sockopt init
// flags (RECONF / idata / PR-SCTP), no kernel-side kcov -- those are
// increment 2. This file runs on any stock CONFIG_IP_SCTP kernel.

#ifndef EXECUTOR_COMMON_LINUX_SCTP_H
#define EXECUTOR_COMMON_LINUX_SCTP_H

#include <endian.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

// IPPROTO_SCTP is provided by <netinet/in.h> on any glibc in current use.
// Deliberately NOT given a guarded local fallback here: pkg/csource's
// reference-build preprocessing runs cpp with -nostdinc, where an
// `#ifndef IPPROTO_SCTP ... #endif` would wrongly fire and then collide with
// the real header when the generated reproducer is actually compiled -- the
// same reasoning as the IPPROTO_MPTCP note in common_linux_mptcp.h.

// Harness-only init flag (mirrored in sys/linux/socket_sctp_flow.txt + .const):
// sniff the INIT/INIT-ACK off loopback and store both directions' vtag on the
// slot, so syz_sctp_inject_chunk can stamp the captured tag.
#define SCTP_INIT_CAPTURE_VTAG 1

// Harness-only vtag-mode selectors for syz_sctp_inject_chunk (mirrored in the
// .txt + .const). CAPTURED echoes the server's tag (passes sctp_vtag_verify);
// ZERO and WRONG are negative controls the gate must reject.
#define SCTP_VTAG_CAPTURED 0
#define SCTP_VTAG_ZERO 1
#define SCTP_VTAG_WRONG 2

#define SCTP_ASSOC_POOL_SIZE 64

// Cap on the injected chunk payload, keeping the craft buffer stack-bounded.
#define SCTP_INJECT_MAX_PAYLOAD 1024

// SCTP chunk types read off the wire during capture (RFC 9260 §3.2).
#define SCTP_CID_INIT 1
#define SCTP_CID_INIT_ACK 2

struct syz_sctp_assoc_slot {
	bool in_use;
	int server_fd;
	int client_fd;
	int server_listen_fd;
	uint16 server_port_h; // host order; the inject dst port
	uint16 client_port_h; // host order; the inject src port (association 4-tuple)

	// Bumped on every (re)allocation, preserved across close, so a reused
	// slot always yields a strictly newer value. Carried for parity with the
	// MPTCP slot's stale-handle guard; increment 1 has no child resource that
	// consults it yet.
	uint32 generation;

	// Captured off the wire when SCTP_INIT_CAPTURE_VTAG is set:
	//   vtag_server (Vs) = the server's my_vtag, advertised in the INIT-ACK
	//                      init_tag. A packet the harness injects TOWARD the
	//                      server must carry vtag=Vs to pass sctp_vtag_verify.
	//   vtag_client (Vc) = the client's my_vtag, advertised in the INIT
	//                      init_tag. Carried for a future client-directed
	//                      inject; the server-directed inject below uses Vs.
	// vtag_valid gates them: capture is a best-effort bounded sniff, so a
	// consumer MUST check vtag_valid (it means Vs at least was captured). The
	// fields are cleared on slot reuse.
	uint32 vtag_server;
	uint32 vtag_client;
	bool vtag_valid;
};

// All four pseudo-syscalls operate on the pool, so it is present whenever any
// one of them is compiled (the per-call csource smoke builds one at a time).
#if SYZ_EXECUTOR || __NR_syz_sctp_pair_init || __NR_syz_sctp_pair_close || \
    __NR_syz_sctp_drive_traffic || __NR_syz_sctp_inject_chunk
static struct syz_sctp_assoc_slot syz_sctp_assoc_pool[SCTP_ASSOC_POOL_SIZE];
#endif

#if SYZ_EXECUTOR || __NR_syz_sctp_pair_init
// Parse an AF_PACKET(SOCK_DGRAM) loopback frame (link header already stripped,
// so it starts at the IP header) for an SCTP INIT / INIT-ACK and extract its
// init_tag. The common header is 12 bytes (src port, dst port, vtag, checksum);
// the first chunk header is 4 bytes (type, flags, length); for INIT/INIT-ACK
// the chunk value begins with the 32-bit init_tag. Returns 1 and fills
// *chunk_type_out / *init_tag_out (host order) on a hit, 0 otherwise.
static int sctp_parse_init_tag(const uint8* pkt, int len, uint8* chunk_type_out, uint32* init_tag_out)
{
	if (len < (int)sizeof(struct iphdr))
		return 0;
	const struct iphdr* ip = (const struct iphdr*)pkt;
	if (ip->protocol != IPPROTO_SCTP)
		return 0;
	int ihl = ip->ihl * 4;
	// common header (12) + chunk header (4) + init_tag (4).
	if (ihl < (int)sizeof(struct iphdr) || len < ihl + 12 + 4 + 4)
		return 0;
	const uint8* chunk = pkt + ihl + 12;
	uint8 ctype = chunk[0];
	if (ctype != SCTP_CID_INIT && ctype != SCTP_CID_INIT_ACK)
		return 0;
	uint32 tag_be = 0;
	memcpy(&tag_be, chunk + 4, sizeof(tag_be));
	*chunk_type_out = ctype;
	*init_tag_out = ntohl(tag_be);
	return 1;
}

static long syz_sctp_pair_init(volatile long a0)
{
	unsigned long init_flags = (unsigned long)a0;
	struct sockaddr_in srv_addr;
	socklen_t alen = sizeof(srv_addr);
	int one = 1;
	int server_listen_fd = -1, client_fd = -1, server_fd = -1, cap_fd = -1;

	// Claim a free slot atomically so two pair_init calls on separate threads
	// (the default -threaded model) can't settle on the same slot. Held from
	// here; every failure path releases it (goto fail).
	int slot = 0;
	for (; slot < SCTP_ASSOC_POOL_SIZE; slot++) {
		bool expected = false;
		if (__atomic_compare_exchange_n(&syz_sctp_assoc_pool[slot].in_use,
						&expected, true, false,
						__ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
			break;
	}
	if (slot == SCTP_ASSOC_POOL_SIZE) {
		debug("syz_sctp_pair_init: pool exhausted (size=%d)\n", SCTP_ASSOC_POOL_SIZE);
		return -1;
	}
	// Release store, paired with any future acquire reader of the slot.
	__atomic_store_n(&syz_sctp_assoc_pool[slot].generation,
			 __atomic_load_n(&syz_sctp_assoc_pool[slot].generation, __ATOMIC_RELAXED) + 1,
			 __ATOMIC_RELEASE);

	server_listen_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
	if (server_listen_fd < 0) {
		debug("syz_sctp_pair_init: server socket: %d\n", errno);
		goto fail;
	}
	setsockopt(server_listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	memset(&srv_addr, 0, sizeof(srv_addr));
	srv_addr.sin_family = AF_INET;
	srv_addr.sin_port = 0; // let the kernel pick an ephemeral port
	srv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(server_listen_fd, (struct sockaddr*)&srv_addr, sizeof(srv_addr)) < 0) {
		debug("syz_sctp_pair_init: bind: %d\n", errno);
		goto fail;
	}
	if (getsockname(server_listen_fd, (struct sockaddr*)&srv_addr, &alen) < 0) {
		debug("syz_sctp_pair_init: getsockname: %d\n", errno);
		goto fail;
	}
	if (listen(server_listen_fd, 1) < 0) {
		debug("syz_sctp_pair_init: listen: %d\n", errno);
		goto fail;
	}

	if (init_flags & SCTP_INIT_CAPTURE_VTAG) {
		// Open the loopback capture BEFORE connect() so the INIT/INIT-ACK
		// exchange is buffered for the parse pass below.
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

	client_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
	if (client_fd < 0) {
		debug("syz_sctp_pair_init: client socket: %d\n", errno);
		goto fail;
	}
	// Blocking connect() returns once the kernel's 4-way handshake reaches
	// ESTABLISHED (COOKIE-ACK), so no priming round-trip is needed.
	if (connect(client_fd, (struct sockaddr*)&srv_addr, sizeof(srv_addr)) < 0) {
		debug("syz_sctp_pair_init: connect: %d\n", errno);
		goto fail;
	}
	server_fd = accept(server_listen_fd, NULL, NULL);
	if (server_fd < 0) {
		debug("syz_sctp_pair_init: accept: %d\n", errno);
		goto fail;
	}

	// The client's ephemeral local port is the inject source port (the
	// association's client-side 4-tuple element).
	{
		struct sockaddr_in cli_addr;
		socklen_t clen = sizeof(cli_addr);

		memset(&cli_addr, 0, sizeof(cli_addr));
		if (getsockname(client_fd, (struct sockaddr*)&cli_addr, &clen) < 0) {
			debug("syz_sctp_pair_init: client getsockname: %d\n", errno);
			goto fail;
		}
		syz_sctp_assoc_pool[slot].client_port_h = ntohs(cli_addr.sin_port);
	}

	if (cap_fd >= 0) {
		struct timeval tv = {0, 100000};
		setsockopt(cap_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		char cbuf[2048];
		bool have_server = false, have_client = false;
		for (int i = 0; i < 100 && !(have_server && have_client); i++) {
			ssize_t cn = recv(cap_fd, cbuf, sizeof(cbuf), 0);
			if (cn <= 0)
				break;
			uint8 ctype = 0;
			uint32 tag = 0;
			if (!sctp_parse_init_tag((const uint8*)cbuf, (int)cn, &ctype, &tag))
				continue;
			if (ctype == SCTP_CID_INIT_ACK) {
				syz_sctp_assoc_pool[slot].vtag_server = tag;
				have_server = true;
			} else if (ctype == SCTP_CID_INIT) {
				syz_sctp_assoc_pool[slot].vtag_client = tag;
				have_client = true;
			}
		}
		close(cap_fd);
		cap_fd = -1;
		// Vs (the server's tag) is the load-bearing one for the server-
		// directed inject; mark valid once it is captured.
		syz_sctp_assoc_pool[slot].vtag_valid = have_server;
		debug("syz_sctp_pair_init: captured vtag_server=0x%x vtag_client=0x%x valid=%d\n",
		      syz_sctp_assoc_pool[slot].vtag_server,
		      syz_sctp_assoc_pool[slot].vtag_client,
		      syz_sctp_assoc_pool[slot].vtag_valid);
	}

	// in_use was published by the atomic claim; fill the rest before returning.
	syz_sctp_assoc_pool[slot].server_fd = server_fd;
	syz_sctp_assoc_pool[slot].client_fd = client_fd;
	syz_sctp_assoc_pool[slot].server_listen_fd = server_listen_fd;
	syz_sctp_assoc_pool[slot].server_port_h = ntohs(srv_addr.sin_port);
	debug("syz_sctp_pair_init: assoc %d established, port %d gen %u\n",
	      slot, ntohs(srv_addr.sin_port), syz_sctp_assoc_pool[slot].generation);
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
	// Release the slot (generation stays bumped -- a burned number is harmless).
	__atomic_store_n(&syz_sctp_assoc_pool[slot].in_use, false, __ATOMIC_RELEASE);
	return -1;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_sctp_pair_close
static long syz_sctp_pair_close(volatile long a0)
{
	long slot = a0;

	if (slot < 0 || slot >= SCTP_ASSOC_POOL_SIZE) {
		debug("syz_sctp_pair_close: slot %ld out of range\n", slot);
		return -1;
	}
	if (!syz_sctp_assoc_pool[slot].in_use) {
		debug("syz_sctp_pair_close: slot %ld not in use\n", slot);
		return -1;
	}
	if (syz_sctp_assoc_pool[slot].server_listen_fd >= 0)
		close(syz_sctp_assoc_pool[slot].server_listen_fd);
	if (syz_sctp_assoc_pool[slot].server_fd >= 0)
		close(syz_sctp_assoc_pool[slot].server_fd);
	if (syz_sctp_assoc_pool[slot].client_fd >= 0)
		close(syz_sctp_assoc_pool[slot].client_fd);
	// Clear the slot but PRESERVE generation, then publish in_use=false LAST
	// (release store) so a concurrent pair_init only observes it free once
	// fully cleared.
	syz_sctp_assoc_pool[slot].server_fd = 0;
	syz_sctp_assoc_pool[slot].client_fd = 0;
	syz_sctp_assoc_pool[slot].server_listen_fd = 0;
	syz_sctp_assoc_pool[slot].server_port_h = 0;
	syz_sctp_assoc_pool[slot].client_port_h = 0;
	syz_sctp_assoc_pool[slot].vtag_server = 0;
	syz_sctp_assoc_pool[slot].vtag_client = 0;
	syz_sctp_assoc_pool[slot].vtag_valid = false;
	__atomic_store_n(&syz_sctp_assoc_pool[slot].in_use, false, __ATOMIC_RELEASE);
	return 0;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_sctp_drive_traffic
// Push data client->server on an established association, exercising the SCTP
// DATA / reassembly path (sctp_eat_data -> ulpq). Bounded (<=4 KiB/send) so a
// mutated data_len can't wedge the association; a bounded drain keeps the RX
// buffer from filling and EAGAINing later sends.
static long syz_sctp_drive_traffic(volatile long a0, volatile long a1, volatile long a2)
{
	long slot = a0;
	const void* data = (const void*)a1;
	size_t data_len = (size_t)a2;
	char drain_buf[4096];
	ssize_t sent = 0, drained;

	if (slot < 0 || slot >= SCTP_ASSOC_POOL_SIZE) {
		debug("syz_sctp_drive_traffic: slot %ld out of range\n", slot);
		return -1;
	}
	struct syz_sctp_assoc_slot* assoc = &syz_sctp_assoc_pool[slot];
	if (!assoc->in_use) {
		debug("syz_sctp_drive_traffic: slot %ld not in use\n", slot);
		return -1;
	}
	if (assoc->client_fd < 0 || assoc->server_fd < 0) {
		debug("syz_sctp_drive_traffic: slot %ld fds not set\n", slot);
		return -1;
	}
	if (data_len > sizeof(drain_buf))
		data_len = sizeof(drain_buf);

	sent = send(assoc->client_fd, data, data_len, MSG_DONTWAIT | MSG_NOSIGNAL);
	for (int i = 0; i < 8; i++) {
		drained = recv(assoc->server_fd, drain_buf, sizeof(drain_buf), MSG_DONTWAIT | MSG_NOSIGNAL);
		if (drained <= 0)
			break;
	}
	debug("syz_sctp_drive_traffic: assoc=%ld sent=%zd\n", slot, sent);
	return sent < 0 ? 0 : (long)sent;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_sctp_inject_chunk
// SCTP packet CRC32c (RFC 9260 Appendix A): Castagnoli polynomial, reflected
// form 0x82f63b78, init 0xffffffff, final XOR 0xffffffff -- NOT the Ethernet
// crc32. The kernel (sctp_compute_cksum, include/net/sctp/checksum.h) computes
// this over the whole SCTP packet with the checksum field zeroed and stores the
// result little-endian; a mismatch drops the packet before association lookup.
static uint32 sctp_crc32c(const uint8* p, int len)
{
	uint32 crc = 0xffffffff;
	for (int i = 0; i < len; i++) {
		crc ^= p[i];
		for (int b = 0; b < 8; b++) {
			if (crc & 1)
				crc = (crc >> 1) ^ 0x82f63b78;
			else
				crc = crc >> 1;
		}
	}
	return ~crc;
}

// SCTP common header (RFC 9260 §3.1) and chunk header (§3.2). Distinct-named to
// avoid colliding with system headers; uintN per the executor-header type rule.
struct sctp_inj_common {
	uint16 src_port;
	uint16 dst_port;
	uint32 vtag;
	uint32 checksum; // little-endian CRC32c
};
struct sctp_inj_chunk {
	uint8 type;
	uint8 flags;
	uint16 length; // network order; header(4) + payload, unpadded
};

// Craft one SCTP packet (common header + a single chunk carrying chunk_payload)
// stamping the vtag selected by vtag_mode, compute CRC32c, and inject it toward
// the server via a raw IPPROTO_SCTP socket (the kernel adds the IP header and
// does NOT compute the SCTP checksum for raw sends, so we must). With
// SCTP_VTAG_CAPTURED the packet passes sctp_vtag_verify on the server's
// association and the chunk reaches its handler; ZERO/WRONG are dropped at the
// gate (negative controls / bad-vtag reject path).
static long syz_sctp_inject_chunk(volatile long a0, volatile long a1, volatile long a2,
				  volatile long a3, volatile long a4)
{
	long slot = a0;
	uint8 chunk_type = (uint8)a1;
	const void* payload = (const void*)a2;
	size_t payload_len = (size_t)a3;
	unsigned long vtag_mode = (unsigned long)a4;
	uint8 pkt[12 + 4 + SCTP_INJECT_MAX_PAYLOAD];

	if (slot < 0 || slot >= SCTP_ASSOC_POOL_SIZE) {
		debug("syz_sctp_inject_chunk: slot %ld out of range\n", slot);
		return -1;
	}
	struct syz_sctp_assoc_slot* assoc = &syz_sctp_assoc_pool[slot];
	if (!__atomic_load_n(&assoc->in_use, __ATOMIC_ACQUIRE)) {
		debug("syz_sctp_inject_chunk: slot %ld not in use\n", slot);
		return -1;
	}
	if (payload_len > SCTP_INJECT_MAX_PAYLOAD)
		payload_len = SCTP_INJECT_MAX_PAYLOAD;

	// Select the vtag per mode. CAPTURED needs a successful sniff (Vs); fail
	// loudly if it is missing rather than silently stamping 0.
	uint32 vtag_h = 0;
	if (vtag_mode == SCTP_VTAG_CAPTURED) {
		if (!assoc->vtag_valid) {
			debug("syz_sctp_inject_chunk: slot %ld CAPTURED but no vtag (init without CAPTURE_VTAG?)\n", slot);
			return -1;
		}
		vtag_h = assoc->vtag_server;
	} else if (vtag_mode == SCTP_VTAG_WRONG) {
		// A deterministic wrong, non-zero tag the gate must reject.
		vtag_h = assoc->vtag_valid ? ~assoc->vtag_server : 0xdeadbeef;
	} else {
		vtag_h = 0; // SCTP_VTAG_ZERO (and any other value)
	}

	// Pad the chunk to a 4-byte boundary (RFC 4960 3.2: a chunk's total length MUST
	// be a multiple of 4; the pad bytes are zero and are NOT counted in ck->length).
	// The kernel's chunk walk (sctp_inq_pop) advances by SCTP_PAD4(length); an
	// unpadded non-4-aligned chunk overruns skb->len, fails sctp_chunk_length_valid,
	// and tears the association down (sctp_sf_violation_chunklen). Without this every
	// payload_len % 4 != 0 inject was poisoning the slot, so later injects became
	// out-of-association traffic -- a major cause of the SCTP coverage plateau.
	int padded_payload = ((int)payload_len + 3) & ~3; // <= SCTP_PAD4(1024) = 1024, fits pkt[]
	int total = 12 + 4 + padded_payload;
	memset(pkt, 0, (size_t)total);
	struct sctp_inj_common* ch = (struct sctp_inj_common*)pkt;
	struct sctp_inj_chunk* ck = (struct sctp_inj_chunk*)(pkt + 12);
	ch->src_port = htons(assoc->client_port_h);
	ch->dst_port = htons(assoc->server_port_h);
	ch->vtag = htonl(vtag_h);
	ch->checksum = 0;
	ck->type = chunk_type;
	ck->flags = 0;
	ck->length = htons((uint16)(4 + payload_len));
	if (payload_len > 0 && payload != NULL)
		memcpy(pkt + 12 + 4, payload, payload_len);
	// CRC32c over the whole packet with checksum zeroed, stored little-endian.
	ch->checksum = htole32(sctp_crc32c(pkt, total));

	int rs = socket(AF_INET, SOCK_RAW, IPPROTO_SCTP);
	if (rs < 0) {
		debug("syz_sctp_inject_chunk: raw socket: %d\n", errno);
		return -1;
	}
	struct sockaddr_in dst;
	memset(&dst, 0, sizeof(dst));
	dst.sin_family = AF_INET;
	dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	dst.sin_port = 0; // ports live in the SCTP header; raw SCTP ignores this
	ssize_t n = sendto(rs, pkt, (size_t)total, 0, (struct sockaddr*)&dst, sizeof(dst));
	close(rs);
	if (n < 0) {
		debug("syz_sctp_inject_chunk: sendto: %d\n", errno);
		return -1;
	}
	debug("syz_sctp_inject_chunk: slot %ld type=%u vtag_mode=%lu vtag=0x%x len=%d\n",
	      slot, chunk_type, vtag_mode, vtag_h, total);
	return 0;
}
#endif

#endif // EXECUTOR_COMMON_LINUX_SCTP_H
