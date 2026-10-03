// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// In-kernel QUIC (net/quic, RFC 9000) Phase-1 connection carrier pseudo-syscalls.
//
// syz_quic_conn_init() brings up an IPPROTO_QUIC socket pair on loopback and
// drives it to ESTABLISHED with FAKE per-level crypto secrets, mirroring the
// kernel's own selftest (tools/testing/selftests/net/quic_test.c:
// set_fake_keys()/send_fake_handshake()/do_handshake()). The kernel does not
// parse TLS inside CRYPTO frames unless ALPN demux is on, so fake handshake
// bytes reach established deterministically -- no userspace TLS agent. The
// established fds are held in a static pool; the slot index is the quic_conn
// resource (analog of syz_mptcp_pair_init).
//
// syz_quic_conn_close() closes both fds and frees the slot.
//
// syz_quic_path_challenge() crosses a capture-echo gate: it triggers connection
// migration so the kernel emits a PATH_CHALLENGE carrying get_random_bytes()
// entropy (unobtainable through any socket API), captures that entropy off the
// plaintext 1-RTT wire via the UDP NFQUEUE engine, and echoes it in the peer's
// PATH_RESPONSE so the kernel's crypto_memneq() path check (net/quic/frame.c)
// succeeds. mode QUIC_PC_ECHO_CAPTURED echoes the captured value (PASS); mode
// QUIC_PC_ECHO_WRONG echoes a corrupted value (the negative control -> REJECT).
// The migration-completed QUIC_EVENT_CONNECTION_MIGRATION notification is the
// pass/fail oracle (the event fires only after crypto_memneq succeeds).

#ifndef EXECUTOR_COMMON_LINUX_QUIC_H
#define EXECUTOR_COMMON_LINUX_QUIC_H

#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

// IPPROTO_QUIC / SOL_QUIC are not provided by glibc. Guarded fallbacks: nothing
// else defines them (unlike IPPROTO_MPTCP, which glibc provides), so the guard
// cannot collide under pkg/csource's -nostdinc reference-build pass or on a real
// compile. Values are the in-kernel QUIC uapi registrations (in.h / socket.h).
#ifndef IPPROTO_QUIC
#define IPPROTO_QUIC 261
#endif
#ifndef SOL_QUIC
#define SOL_QUIC 288
#endif

// enum quic_crypto_level (uapi/linux/quic.h): APP=0, INITIAL=1, HANDSHAKE=2,
// EARLY=3. INITIAL keys are derived by the kernel from the DCID, so no fake
// INITIAL secret is installed (matching the selftest).
#define QUIC_CRYPTO_APP 0
#define QUIC_CRYPTO_INITIAL 1
#define QUIC_CRYPTO_HANDSHAKE 2
#define QUIC_CRYPTO_EARLY 3

// enum quic_cmsg_type: QUIC_STREAM_INFO=0, QUIC_HANDSHAKE_INFO=1.
#define QUIC_HANDSHAKE_INFO 1
// MSG_QUIC_NOTIFICATION == MSG_MORE (enum quic_msg_flags). Set in recvmsg
// msg_flags when the received datagram is an event, not stream data.
#ifndef MSG_QUIC_NOTIFICATION
#define MSG_QUIC_NOTIFICATION MSG_MORE
#endif

// Socket option numbers (uapi/linux/quic.h).
#define QUIC_SOCKOPT_EVENT 0
#define QUIC_SOCKOPT_CONNECTION_MIGRATION 6
#define QUIC_SOCKOPT_TRANSPORT_PARAM 8
#define QUIC_SOCKOPT_CONFIG 9
#define QUIC_SOCKOPT_CRYPTO_SECRET 13
#define QUIC_SOCKOPT_TRANSPORT_PARAM_EXT 14

// enum quic_event_type: QUIC_EVENT_CONNECTION_MIGRATION = 6.
#define QUIC_EVENT_CONNECTION_MIGRATION 6

// TLS cipher types (uapi/linux/tls.h). Mirrored as harness constants so the
// executor needs no tls.h include; must match socket_quic.txt + its .const.
#define QUIC_CIPHER_DEFAULT 0
#define QUIC_CIPHER_AES_GCM_128 51
#define QUIC_CIPHER_AES_GCM_256 52
#define QUIC_CIPHER_AES_CCM_128 53
#define QUIC_CIPHER_CHACHA20_POLY1305 54

// Path-challenge echo modes (harness constants; match .txt + .const).
#define QUIC_PC_ECHO_CAPTURED 0
#define QUIC_PC_ECHO_WRONG 1

// net/quic/path.h QUIC_PATH_ENTROPY_LEN; net/quic/frame.h frame type bytes.
#define QUIC_PATH_ENTROPY_LEN 8
#define QUIC_FRAME_PATH_CHALLENGE 0x1a
#define QUIC_FRAME_PATH_RESPONSE 0x1b

// struct quic_crypto_secret (uapi/linux/quic.h), QUIC_CRYPTO_SECRET_BUFFER_SIZE=48.
#define QUIC_CRYPTO_SECRET_BUFFER_SIZE 48
struct quic_crypto_secret_u {
	uint8 send;
	uint8 level;
	uint16 reserved;
	uint32 type;
	uint8 secret[QUIC_CRYPTO_SECRET_BUFFER_SIZE];
};

// struct quic_handshake_info (uapi): just the crypto level.
struct quic_handshake_info_u {
	uint8 crypto_level;
};

// struct quic_event_option (uapi): {type, on}.
struct quic_event_option_u {
	uint8 type;
	uint8 on;
};

// Prefix of struct quic_transport_param (uapi) up to disable_1rtt_encryption.
// Only the fields we set are needed; the kernel copies min(optlen, sizeof) and
// this is an exact prefix of the real struct, so a short set is fine. We zero
// the whole struct and set remote=0 + disable_1rtt_encryption=1.
struct quic_transport_param_short {
	uint8 remote;
	uint8 disable_active_migration;
	uint8 grease_quic_bit;
	uint8 stateless_reset;
	uint8 disable_1rtt_encryption;
};

#define QUIC_PAIR_POOL_SIZE 64

struct syz_quic_pair_slot {
	bool in_use;
	int client_fd;
	int server_fd;
	int server_listen_fd;
	int family;
	uint32 cipher;
	uint16 client_port_h;
	uint16 server_port_h;
	bool disable_1rtt;
};

static struct syz_quic_pair_slot syz_quic_pair_pool[QUIC_PAIR_POOL_SIZE];

// Out-param snapshot (matches quic_conn_state in socket_quic.txt). syzlang
// int32/int16 map to C int/short here (the executor headers define only the
// unsigned uintN syzkaller types; the layout/width is what must match).
struct syz_quic_conn_state {
	int state;
	int cipher;
	short client_port;
	short server_port;
	int active_estabs;
	int passive_estabs;
};

// The fake per-level secrets table, copied verbatim from the v15 selftest
// (quic_test.c fake_keys[3][2]: {Early, Handshake, Application} x {client,server}).
// Both ends use the SAME table with opposite serv index, so send/recv keys line
// up symmetrically. type is overwritten per-call from the slot's cipher.
static struct quic_crypto_secret_u syz_quic_fake_keys[3][2] = {
    {/* Early */
     {0, 0, 0, QUIC_CIPHER_AES_GCM_128,
      {0x5D, 0x9A, 0x21, 0xF0, 0x3C, 0x88, 0x6B, 0x4E, 0xD2, 0x11, 0xAF, 0x62,
       0xB0, 0x37, 0x8E, 0xC5, 0x79, 0x0D, 0x54, 0xE1, 0xA3, 0x96, 0x2F, 0xCB,
       0x08, 0x7D, 0x41, 0xFA, 0x13, 0xB8, 0x6E, 0x22, 0x9F, 0x30, 0xD4, 0x5B,
       0xE7, 0x12, 0x8A, 0x61, 0x04, 0xC9, 0x3E, 0xF6, 0x57, 0xAD, 0x20, 0x89}},
     {0, 0, 0, QUIC_CIPHER_AES_GCM_128,
      {0xA1, 0x3F, 0xC6, 0x57, 0x8B, 0x0D, 0xE2, 0x49, 0x6C, 0xF1, 0x95, 0x2B,
       0xD7, 0x40, 0x8E, 0x13, 0x54, 0x9A, 0x7F, 0xC2, 0x0B, 0x68, 0x31, 0xEA,
       0x05, 0xD9, 0x22, 0x7C, 0xB3, 0x4F, 0x10, 0x8D, 0xE6, 0x29, 0xF0, 0x57,
       0xAD, 0x1C, 0x83, 0x64, 0xB2, 0x09, 0xC7, 0x3E, 0xF5, 0x61, 0x2A, 0x98}}},
    {/* Handshake */
     {0, 0, 0, QUIC_CIPHER_AES_GCM_128,
      {0x7C, 0x12, 0xA9, 0x4F, 0xD0, 0x38, 0xB2, 0xE5, 0x09, 0x6A, 0xF4, 0x51,
       0xC8, 0x23, 0x9D, 0x7E, 0x10, 0x84, 0xFA, 0x3B, 0x6D, 0x97, 0x0C, 0xE2,
       0x4A, 0xF9, 0x30, 0x11, 0xB6, 0xC5, 0x78, 0x2D, 0x66, 0x1F, 0xCB, 0x5E,
       0x82, 0x90, 0xDA, 0x04, 0x37, 0xAF, 0x15, 0xE8, 0x63, 0xC1, 0x2B, 0x0D}},
     {0, 0, 0, QUIC_CIPHER_AES_GCM_128,
      {0x8F, 0x24, 0xC0, 0x5A, 0x19, 0xE4, 0x72, 0x3D, 0xB3, 0x0F, 0xA1, 0x68,
       0x9C, 0x42, 0xDE, 0x75, 0xF8, 0x07, 0x6B, 0x11, 0xCD, 0x93, 0x20, 0xEA,
       0x5F, 0x38, 0x14, 0xD1, 0x49, 0xBE, 0x80, 0x23, 0xAA, 0x6C, 0x12, 0x5D,
       0xEF, 0x04, 0x97, 0x31, 0x6E, 0x1B, 0xC8, 0xF3, 0x50, 0x08, 0xDA, 0x9E}}},
    {/* Application */
     {0, 0, 0, QUIC_CIPHER_AES_GCM_128,
      {0x9A, 0x5C, 0xEF, 0x12, 0x68, 0x7D, 0x34, 0xB1, 0x02, 0xF9, 0xAD, 0x47,
       0x6C, 0x03, 0xE5, 0x8F, 0x1D, 0xA7, 0x60, 0xCB, 0x35, 0x84, 0x9F, 0x22,
       0x71, 0x0B, 0xDC, 0x56, 0xEE, 0x13, 0x42, 0x9C, 0x5B, 0xF0, 0x28, 0x6D,
       0x81, 0x14, 0xC7, 0x3E, 0xA2, 0x9D, 0x0F, 0x68, 0xB5, 0x7A, 0x11, 0xD3}},
     {0, 0, 0, QUIC_CIPHER_AES_GCM_128,
      {0xC1, 0x3E, 0x7F, 0xB4, 0x09, 0x5A, 0xE8, 0x2D, 0x4C, 0xA7, 0x10, 0xF3,
       0x68, 0x9D, 0x21, 0xCB, 0x57, 0x80, 0x36, 0x1A, 0xF2, 0x4B, 0xC9, 0x05,
       0xE0, 0x6F, 0x93, 0x2A, 0xBD, 0x14, 0x7C, 0x8E, 0x35, 0xDA, 0x0C, 0x41,
       0xF6, 0x92, 0xA0, 0x7B, 0x18, 0xCB, 0x55, 0xE7, 0x6A, 0x1F, 0xD4, 0x0B}}}};

// fake ClientHello (ALPN "fake") + EncryptedExtensions, verbatim from the
// selftest. The kernel does not parse these (ALPN demux off), so the exact
// bytes only need to match the selftest's framing expectations.
static const uint8 syz_quic_fake_client_hello[] = {
    0x01, 0x00, 0x00, 0x36, 0x03, 0x03, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
    0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,
    0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
    0x1e, 0x1f, 0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00, 0x00, 0x0B, 0x00,
    0x10, 0x00, 0x07, 0x00, 0x05, 0x04, 0x66, 0x61, 0x6B, 0x65};
static const uint8 syz_quic_fake_encrypted_extensions[] = {
    0x08, 0x00, 0x00, 0x02, 0x00, 0x00};

static int syz_quic_set_fake_keys(int fd, uint8 level, uint8 serv, uint32 cipher)
{
	struct quic_crypto_secret_u* s;
	int i;

	switch (level) {
	case QUIC_CRYPTO_EARLY:
		i = 0;
		break;
	case QUIC_CRYPTO_HANDSHAKE:
		i = 1;
		break;
	case QUIC_CRYPTO_APP:
		i = 2;
		break;
	default:
		return -1;
	}
	s = &syz_quic_fake_keys[i][serv];
	s->send = 1;
	s->level = level;
	s->type = cipher;
	if (setsockopt(fd, SOL_QUIC, QUIC_SOCKOPT_CRYPTO_SECRET, s, sizeof(*s)) < 0) {
		debug("syz_quic_set_fake_keys: send secret level=%d serv=%d: %d\n", level, serv, errno);
		return -1;
	}
	s = &syz_quic_fake_keys[i][!serv];
	s->send = 0;
	s->level = level;
	s->type = cipher;
	if (setsockopt(fd, SOL_QUIC, QUIC_SOCKOPT_CRYPTO_SECRET, s, sizeof(*s)) < 0) {
		debug("syz_quic_set_fake_keys: recv secret level=%d serv=%d: %d\n", level, serv, errno);
		return -1;
	}
	return 0;
}

// send a CRYPTO-frame handshake message at the given level (mirrors the
// selftest's send_handshake(): the level travels in a QUIC_HANDSHAKE_INFO cmsg).
static int syz_quic_send_handshake(int fd, const void* msg, size_t len, uint8 level)
{
	char outcmsg[CMSG_SPACE(sizeof(struct quic_handshake_info_u))];
	struct quic_handshake_info_u* info;
	struct msghdr outmsg;
	struct cmsghdr* cmsg;
	struct iovec iov;

	iov.iov_base = (void*)msg;
	iov.iov_len = len;
	memset(&outmsg, 0, sizeof(outmsg));
	outmsg.msg_iov = &iov;
	outmsg.msg_iovlen = 1;
	outmsg.msg_control = outcmsg;
	outmsg.msg_controllen = sizeof(outcmsg);
	cmsg = CMSG_FIRSTHDR(&outmsg);
	cmsg->cmsg_level = SOL_QUIC;
	cmsg->cmsg_type = QUIC_HANDSHAKE_INFO;
	cmsg->cmsg_len = CMSG_LEN(sizeof(*info));
	info = (struct quic_handshake_info_u*)CMSG_DATA(cmsg);
	info->crypto_level = level;
	return (int)sendmsg(fd, &outmsg, 0);
}

static int syz_quic_recv_handshake(int fd, void* msg, size_t len, uint8* level)
{
	char incmsg[CMSG_SPACE(sizeof(struct quic_handshake_info_u))];
	struct quic_handshake_info_u* info;
	struct cmsghdr* cmsg;
	struct msghdr inmsg;
	struct iovec iov;
	ssize_t ret;

	iov.iov_base = msg;
	iov.iov_len = len;
	memset(&inmsg, 0, sizeof(inmsg));
	inmsg.msg_iov = &iov;
	inmsg.msg_iovlen = 1;
	inmsg.msg_control = incmsg;
	inmsg.msg_controllen = sizeof(incmsg);
	ret = recvmsg(fd, &inmsg, 0);
	if (ret < 0)
		return (int)ret;
	*level = 0;
	cmsg = CMSG_FIRSTHDR(&inmsg);
	if (cmsg && cmsg->cmsg_level == SOL_QUIC && cmsg->cmsg_type == QUIC_HANDSHAKE_INFO) {
		info = (struct quic_handshake_info_u*)CMSG_DATA(cmsg);
		*level = info->crypto_level;
	}
	return (int)ret;
}

// Mirror of the selftest send_fake_handshake(): for the two message points that
// carry the local transport-param extension (client INITIAL, server HANDSHAKE),
// fetch QUIC_SOCKOPT_TRANSPORT_PARAM_EXT and append it to the hello bytes.
static int syz_quic_send_fake_handshake(int fd, uint8 level, uint8 serv)
{
	char msg[4096];
	char ext[256];
	unsigned int len = sizeof(msg);

	if (!serv && level == QUIC_CRYPTO_INITIAL) {
		unsigned int elen = sizeof(ext);
		socklen_t sl = elen;
		if (getsockopt(fd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM_EXT, ext, &sl) < 0) {
			debug("syz_quic_send_fake_handshake: get TP_EXT c-init: %d\n", errno);
			return -1;
		}
		elen = sl;
		memcpy(msg, syz_quic_fake_client_hello, sizeof(syz_quic_fake_client_hello));
		memcpy(&msg[sizeof(syz_quic_fake_client_hello)], ext, elen);
		len = sizeof(syz_quic_fake_client_hello) + elen;
	} else if (serv && level == QUIC_CRYPTO_HANDSHAKE) {
		unsigned int elen = sizeof(ext);
		socklen_t sl = elen;
		if (getsockopt(fd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM_EXT, ext, &sl) < 0) {
			debug("syz_quic_send_fake_handshake: get TP_EXT s-hs: %d\n", errno);
			return -1;
		}
		elen = sl;
		memcpy(msg, syz_quic_fake_encrypted_extensions, sizeof(syz_quic_fake_encrypted_extensions));
		memcpy(&msg[sizeof(syz_quic_fake_encrypted_extensions)], ext, elen);
		len = sizeof(syz_quic_fake_encrypted_extensions) + elen;
	}
	if (syz_quic_send_handshake(fd, msg, len, level) < 0) {
		debug("syz_quic_send_fake_handshake: send level=%d serv=%d: %d\n", level, serv, errno);
		return -1;
	}
	return 0;
}

static int syz_quic_recv_fake_handshake(int fd, uint8 level, uint8 serv)
{
	char msg[4096];
	uint8 l = 0;
	int ret;

	ret = syz_quic_recv_handshake(fd, msg, sizeof(msg), &l);
	if (ret < 0) {
		debug("syz_quic_recv_fake_handshake: recv level=%d serv=%d: %d\n", level, serv, errno);
		return -1;
	}
	if (l != level) {
		debug("syz_quic_recv_fake_handshake: level mismatch want=%d got=%d serv=%d\n", level, l, serv);
		return -1;
	}
	if (serv && level == QUIC_CRYPTO_INITIAL) {
		char* ext = &msg[sizeof(syz_quic_fake_client_hello)];
		unsigned int elen;
		if ((unsigned)ret < sizeof(syz_quic_fake_client_hello))
			return -1;
		elen = (unsigned)ret - sizeof(syz_quic_fake_client_hello);
		if (setsockopt(fd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM_EXT, ext, elen) < 0) {
			debug("syz_quic_recv_fake_handshake: set TP_EXT s-init: %d\n", errno);
			return -1;
		}
	} else if (!serv && level == QUIC_CRYPTO_HANDSHAKE) {
		char* ext = &msg[sizeof(syz_quic_fake_encrypted_extensions)];
		unsigned int elen;
		if ((unsigned)ret < sizeof(syz_quic_fake_encrypted_extensions))
			return -1;
		elen = (unsigned)ret - sizeof(syz_quic_fake_encrypted_extensions);
		if (setsockopt(fd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM_EXT, ext, elen) < 0) {
			debug("syz_quic_recv_fake_handshake: set TP_EXT c-hs: %d\n", errno);
			return -1;
		}
	}
	return 0;
}

static int syz_quic_set_disable_1rtt(int fd)
{
	struct quic_transport_param_short tp;
	memset(&tp, 0, sizeof(tp));
	tp.remote = 0;
	tp.disable_1rtt_encryption = 1;
	if (setsockopt(fd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM, &tp, sizeof(tp)) < 0) {
		debug("syz_quic_set_disable_1rtt: %d\n", errno);
		return -1;
	}
	return 0;
}

// Read a QUIC SNMP counter from /proc/net/quic/snmp (executor is already inside
// the worker netns). Returns the value, or -1 if not found.
static long syz_quic_read_snmp(const char* name)
{
	char buf[8192];
	int fd = open("/proc/net/quic/snmp", O_RDONLY);
	if (fd < 0)
		return -1;
	ssize_t n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return -1;
	buf[n] = 0;
	char* p = strstr(buf, name);
	if (!p)
		return -1;
	p += strlen(name);
	while (*p == ' ' || *p == '\t')
		p++;
	return strtol(p, NULL, 10);
}

#if SYZ_EXECUTOR || __NR_syz_quic_conn_init
static long syz_quic_conn_init(volatile long a0, volatile long a1)
{
	struct quic_conn_opts_u {
		int family;
		char disable_1rtt;
		int cipher;
	};
	struct quic_conn_opts_u* opts = (struct quic_conn_opts_u*)a0;
	struct syz_quic_conn_state* out = (struct syz_quic_conn_state*)a1;

	int family = AF_INET;
	int disable_1rtt = 0;
	uint32 cipher = QUIC_CIPHER_AES_GCM_128;
	if (opts) {
		family = opts->family ? opts->family : AF_INET;
		disable_1rtt = opts->disable_1rtt ? 1 : 0;
		cipher = opts->cipher ? (uint32)opts->cipher : QUIC_CIPHER_AES_GCM_128;
	}
	if (family != AF_INET && family != AF_INET6)
		family = AF_INET;

	int slot = 0;
	for (; slot < QUIC_PAIR_POOL_SIZE; slot++) {
		bool expected = false;
		if (__atomic_compare_exchange_n(&syz_quic_pair_pool[slot].in_use,
						&expected, true, false,
						__ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
			break;
	}
	if (slot == QUIC_PAIR_POOL_SIZE) {
		debug("syz_quic_conn_init: pool exhausted\n");
		return -1;
	}

	int lfd = -1, cfd = -1, afd = -1;
	struct sockaddr_in sa4;
	socklen_t alen = sizeof(sa4);
	struct timeval tv = {3, 0};

	// Only AF_INET loopback is wired for Phase 1; AF_INET6 falls back to INET.
	family = AF_INET;

	lfd = socket(family, SOCK_DGRAM, IPPROTO_QUIC);
	if (lfd < 0) {
		debug("syz_quic_conn_init: listen socket: %d\n", errno);
		goto fail;
	}
	setsockopt(lfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(lfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	memset(&sa4, 0, sizeof(sa4));
	sa4.sin_family = AF_INET;
	sa4.sin_port = 0;
	sa4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(lfd, (struct sockaddr*)&sa4, sizeof(sa4)) < 0) {
		debug("syz_quic_conn_init: bind: %d\n", errno);
		goto fail;
	}
	if (getsockname(lfd, (struct sockaddr*)&sa4, &alen) < 0) {
		debug("syz_quic_conn_init: getsockname: %d\n", errno);
		goto fail;
	}
	if (disable_1rtt && syz_quic_set_disable_1rtt(lfd) < 0)
		goto fail;
	if (listen(lfd, 1) < 0) {
		debug("syz_quic_conn_init: listen: %d\n", errno);
		goto fail;
	}

	cfd = socket(family, SOCK_DGRAM, IPPROTO_QUIC);
	if (cfd < 0) {
		debug("syz_quic_conn_init: client socket: %d\n", errno);
		goto fail;
	}
	setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	if (connect(cfd, (struct sockaddr*)&sa4, sizeof(sa4)) < 0) {
		debug("syz_quic_conn_init: connect: %d\n", errno);
		goto fail;
	}
	if (disable_1rtt && syz_quic_set_disable_1rtt(cfd) < 0)
		goto fail;

	// accept_socket(): client sends ClientHello (INITIAL), then server accepts.
	if (syz_quic_send_fake_handshake(cfd, QUIC_CRYPTO_INITIAL, 0) < 0)
		goto fail;
	afd = accept(lfd, NULL, NULL);
	if (afd < 0) {
		debug("syz_quic_conn_init: accept: %d\n", errno);
		goto fail;
	}
	setsockopt(afd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(afd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

	// do_handshake(): server side (serv=1), then client side (serv=0).
	if (syz_quic_recv_fake_handshake(afd, QUIC_CRYPTO_INITIAL, 1) < 0)
		goto fail;
	if (syz_quic_set_fake_keys(afd, QUIC_CRYPTO_HANDSHAKE, 1, cipher) < 0)
		goto fail;
	if (syz_quic_send_fake_handshake(afd, QUIC_CRYPTO_INITIAL, 1) < 0)
		goto fail;
	if (syz_quic_send_fake_handshake(afd, QUIC_CRYPTO_HANDSHAKE, 1) < 0)
		goto fail;

	if (syz_quic_recv_fake_handshake(cfd, QUIC_CRYPTO_INITIAL, 0) < 0)
		goto fail;
	if (syz_quic_set_fake_keys(cfd, QUIC_CRYPTO_HANDSHAKE, 0, cipher) < 0)
		goto fail;
	if (syz_quic_recv_fake_handshake(cfd, QUIC_CRYPTO_HANDSHAKE, 0) < 0)
		goto fail;
	if (syz_quic_set_fake_keys(cfd, QUIC_CRYPTO_APP, 0, cipher) < 0)
		goto fail;
	if (syz_quic_send_fake_handshake(cfd, QUIC_CRYPTO_HANDSHAKE, 0) < 0)
		goto fail;

	if (syz_quic_recv_fake_handshake(afd, QUIC_CRYPTO_HANDSHAKE, 1) < 0)
		goto fail;
	if (syz_quic_set_fake_keys(afd, QUIC_CRYPTO_APP, 1, cipher) < 0)
		goto fail;

	// Established. Record the client's local port for later migration.
	{
		struct sockaddr_in csa;
		socklen_t cl = sizeof(csa);
		memset(&csa, 0, sizeof(csa));
		if (getsockname(cfd, (struct sockaddr*)&csa, &cl) == 0)
			syz_quic_pair_pool[slot].client_port_h = ntohs(csa.sin_port);
	}
	syz_quic_pair_pool[slot].client_fd = cfd;
	syz_quic_pair_pool[slot].server_fd = afd;
	syz_quic_pair_pool[slot].server_listen_fd = lfd;
	syz_quic_pair_pool[slot].family = family;
	syz_quic_pair_pool[slot].cipher = cipher;
	syz_quic_pair_pool[slot].server_port_h = ntohs(sa4.sin_port);
	syz_quic_pair_pool[slot].disable_1rtt = disable_1rtt != 0;

	if (out) {
		out->state = 1;
		out->cipher = (int)cipher;
		out->client_port = (short)syz_quic_pair_pool[slot].client_port_h;
		out->server_port = (short)syz_quic_pair_pool[slot].server_port_h;
		out->active_estabs = (int)syz_quic_read_snmp("QuicConnActiveEstabs");
		out->passive_estabs = (int)syz_quic_read_snmp("QuicConnPassiveEstabs");
	}
	debug("syz_quic_conn_init: pair %d ESTABLISHED client_port=%d server_port=%d disable_1rtt=%d "
	      "ActiveEstabs=%ld PassiveEstabs=%ld\n",
	      slot, syz_quic_pair_pool[slot].client_port_h, syz_quic_pair_pool[slot].server_port_h,
	      disable_1rtt, syz_quic_read_snmp("QuicConnActiveEstabs"),
	      syz_quic_read_snmp("QuicConnPassiveEstabs"));
	return slot;

fail:
	if (afd >= 0)
		close(afd);
	if (cfd >= 0)
		close(cfd);
	if (lfd >= 0)
		close(lfd);
	__atomic_store_n(&syz_quic_pair_pool[slot].in_use, false, __ATOMIC_RELEASE);
	return -1;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_quic_conn_close
static long syz_quic_conn_close(volatile long a0)
{
	long slot = a0;
	if (slot < 0 || slot >= QUIC_PAIR_POOL_SIZE)
		return -1;
	if (!syz_quic_pair_pool[slot].in_use)
		return -1;
	if (syz_quic_pair_pool[slot].server_listen_fd >= 0)
		close(syz_quic_pair_pool[slot].server_listen_fd);
	if (syz_quic_pair_pool[slot].server_fd >= 0)
		close(syz_quic_pair_pool[slot].server_fd);
	if (syz_quic_pair_pool[slot].client_fd >= 0)
		close(syz_quic_pair_pool[slot].client_fd);
	syz_quic_pair_pool[slot].client_fd = 0;
	syz_quic_pair_pool[slot].server_fd = 0;
	syz_quic_pair_pool[slot].server_listen_fd = 0;
	syz_quic_pair_pool[slot].client_port_h = 0;
	syz_quic_pair_pool[slot].server_port_h = 0;
	syz_quic_pair_pool[slot].disable_1rtt = false;
	__atomic_store_n(&syz_quic_pair_pool[slot].in_use, false, __ATOMIC_RELEASE);
	return 0;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_quic_path_challenge
#include "common_linux_quic_nfq.h"

// Cross-packet state for the capture-echo hook. The gate (RFC 9000 path
// validation) is DEFINED by carrying a kernel-generated value across packets,
// so this small state is intrinsic, not an accidental stateful shortcut.
static volatile int syz_quic_pc_mode;
static uint8 syz_quic_pc_captured[QUIC_PATH_ENTROPY_LEN];
static volatile int syz_quic_pc_have_capture;
static volatile int syz_quic_pc_saw_challenge;
static volatile int syz_quic_pc_saw_response;

// Locate a PATH_CHALLENGE (0x1a) / PATH_RESPONSE (0x1b) frame in a plaintext
// 1-RTT short-header packet and return the offset of its 8-byte entropy field
// (just past the type byte), or -1. Scans the QUIC payload (past IP+UDP); the
// short header length is variable (DCID + pn), so we scan for the frame-type
// byte with 8 trailing bytes available. Migration probe packets carry only
// PATH_CHALLENGE/RESPONSE (+ ACK/PADDING), so the first match is the frame.
static int syz_quic_find_entropy(uint8* ip_pkt, int len, uint8 frame_type)
{
	struct iphdr* ip = (struct iphdr*)ip_pkt;
	int ihl = ip->ihl * 4;
	int q_off = ihl + (int)sizeof(struct udphdr);
	if (len < q_off + 2)
		return -1;
	uint8* q = ip_pkt + q_off;
	int qlen = len - q_off;
	// Short header has the high bit (0x80) clear; skip long-header/handshake.
	if (q[0] & 0x80)
		return -1;
	for (int i = 1; i + 1 + QUIC_PATH_ENTROPY_LEN <= qlen; i++) {
		if (q[i] == frame_type)
			return q_off + i + 1;
	}
	return -1;
}

// Stateless-per-packet hook (reads the small cross-packet capture state above):
//  - on a PATH_CHALLENGE: capture the entropy (latest wins, so it always tracks
//    the kernel's current paths->entropy even across re-randomized retransmits),
//    then CORRUPT the on-wire copy so the peer's natural echo is wrong -- this
//    makes the harness the sole source of a correct PATH_RESPONSE.
//  - on a PATH_RESPONSE: ECHO_CAPTURED -> overwrite with the captured entropy
//    (validation PASSES); ECHO_WRONG -> overwrite with a definitely-wrong value
//    (validation REJECTS).
static int syz_quic_pc_hook(uint8* ip_pkt, int len)
{
	int off = syz_quic_find_entropy(ip_pkt, len, QUIC_FRAME_PATH_CHALLENGE);
	if (off >= 0) {
		memcpy(syz_quic_pc_captured, ip_pkt + off, QUIC_PATH_ENTROPY_LEN);
		syz_quic_pc_have_capture = 1;
		syz_quic_pc_saw_challenge = 1;
		for (int i = 0; i < QUIC_PATH_ENTROPY_LEN; i++)
			ip_pkt[off + i] ^= 0xFF; // corrupt the peer's copy
		debug("syz_quic_pc_hook: captured PATH_CHALLENGE entropy %02x%02x%02x%02x%02x%02x%02x%02x\n",
		      syz_quic_pc_captured[0], syz_quic_pc_captured[1], syz_quic_pc_captured[2],
		      syz_quic_pc_captured[3], syz_quic_pc_captured[4], syz_quic_pc_captured[5],
		      syz_quic_pc_captured[6], syz_quic_pc_captured[7]);
		return 1;
	}
	off = syz_quic_find_entropy(ip_pkt, len, QUIC_FRAME_PATH_RESPONSE);
	if (off >= 0 && syz_quic_pc_have_capture) {
		syz_quic_pc_saw_response = 1;
		if (syz_quic_pc_mode == QUIC_PC_ECHO_CAPTURED) {
			memcpy(ip_pkt + off, syz_quic_pc_captured, QUIC_PATH_ENTROPY_LEN);
			debug("syz_quic_pc_hook: echoed CAPTURED entropy into PATH_RESPONSE\n");
		} else {
			for (int i = 0; i < QUIC_PATH_ENTROPY_LEN; i++)
				ip_pkt[off + i] = 0xAA; // negative control: wrong value
			debug("syz_quic_pc_hook: echoed WRONG entropy into PATH_RESPONSE\n");
		}
		return 1;
	}
	return 0;
}

// Wait for the QUIC_EVENT_CONNECTION_MIGRATION notification on fd (fires only
// after the kernel's crypto_memneq path-validation succeeds). Returns 1 if the
// event arrives within ~3s (validation PASSED), 0 on timeout (REJECTED).
static int syz_quic_wait_migration_event(int fd)
{
	struct timespec start, cur;
	clock_gettime(CLOCK_MONOTONIC, &start);
	for (;;) {
		clock_gettime(CLOCK_MONOTONIC, &cur);
		long ms = (cur.tv_sec - start.tv_sec) * 1000 + (cur.tv_nsec - start.tv_nsec) / 1000000;
		if (ms > 3000)
			return 0;
		char buf[256];
		struct iovec iov = {buf, sizeof(buf)};
		struct msghdr m;
		memset(&m, 0, sizeof(m));
		m.msg_iov = &iov;
		m.msg_iovlen = 1;
		ssize_t n = recvmsg(fd, &m, MSG_DONTWAIT);
		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				struct timespec ts = {0, 20 * 1000 * 1000};
				nanosleep(&ts, NULL);
				continue;
			}
			return 0;
		}
		if (n >= 1 && (m.msg_flags & MSG_QUIC_NOTIFICATION) &&
		    (uint8)buf[0] == QUIC_EVENT_CONNECTION_MIGRATION) {
			return 1;
		}
	}
}

static long syz_quic_path_challenge(volatile long a0, volatile long a1)
{
	long slot = a0;
	int mode = (int)a1;
	if (slot < 0 || slot >= QUIC_PAIR_POOL_SIZE || !syz_quic_pair_pool[slot].in_use) {
		debug("syz_quic_path_challenge: bad slot %ld\n", slot);
		return -1;
	}
	if (!syz_quic_pair_pool[slot].disable_1rtt) {
		debug("syz_quic_path_challenge: WARNING conn not disable_1rtt; 1-RTT is encrypted, capture will fail\n");
	}

	int cfd = syz_quic_pair_pool[slot].client_fd;

	// Reset capture state and install the hook, then bring up the engine.
	syz_quic_pc_mode = (mode == QUIC_PC_ECHO_WRONG) ? QUIC_PC_ECHO_WRONG : QUIC_PC_ECHO_CAPTURED;
	syz_quic_pc_have_capture = 0;
	syz_quic_pc_saw_challenge = 0;
	syz_quic_pc_saw_response = 0;
	memset(syz_quic_pc_captured, 0, sizeof(syz_quic_pc_captured));
	quic_nfq_hook = syz_quic_pc_hook;
	if (quic_nfq_setup() < 0) {
		debug("syz_quic_path_challenge: nfq setup failed: %d\n", errno);
		return -1;
	}

	// Subscribe the migrating socket to connection-migration events (the oracle).
	struct quic_event_option_u ev = {QUIC_EVENT_CONNECTION_MIGRATION, 1};
	if (setsockopt(cfd, SOL_QUIC, QUIC_SOCKOPT_EVENT, &ev, sizeof(ev)) < 0) {
		debug("syz_quic_path_challenge: event subscribe: %d\n", errno);
	}

	// Trigger migration: new local port = current + 1, same loopback address.
	struct sockaddr_in sa;
	socklen_t sl = sizeof(sa);
	memset(&sa, 0, sizeof(sa));
	if (getsockname(cfd, (struct sockaddr*)&sa, &sl) < 0) {
		debug("syz_quic_path_challenge: getsockname: %d\n", errno);
		return -1;
	}
	sa.sin_port = htons((uint16)(ntohs(sa.sin_port) + 1));
	if (setsockopt(cfd, SOL_QUIC, QUIC_SOCKOPT_CONNECTION_MIGRATION, &sa, sl) < 0) {
		debug("syz_quic_path_challenge: CONNECTION_MIGRATION: %d\n", errno);
		return -1;
	}

	int validated = syz_quic_wait_migration_event(cfd);
	int expected = (syz_quic_pc_mode == QUIC_PC_ECHO_CAPTURED) ? 1 : 0;
	debug("syz_quic_path_challenge: mode=%s saw_challenge=%d saw_response=%d validated=%d expected=%d -> %s\n",
	      syz_quic_pc_mode == QUIC_PC_ECHO_CAPTURED ? "ECHO_CAPTURED" : "ECHO_WRONG",
	      syz_quic_pc_saw_challenge, syz_quic_pc_saw_response, validated, expected,
	      validated == expected ? "GATE-OK" : "GATE-MISMATCH");
	return validated;
}
#endif

#endif // EXECUTOR_COMMON_LINUX_QUIC_H
