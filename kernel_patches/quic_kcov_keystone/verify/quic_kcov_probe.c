/* quic_kcov_probe: prove that net/quic receive-softirq frame-validation
 * coverage reaches a kcov REMOTE collector via the QUIC keystone handle.
 *
 * Mirrors sctp_kcov_probe.c (same isolate-the-remote-stream-by-construction
 * trick), but the exercise is an in-kernel QUIC (net/quic, lxin) connection
 * brought up with FAKE per-level crypto secrets -- the kernel's own selftest
 * recipe (tools/testing/selftests/net/quic_test.c: set_fake_keys/do_handshake),
 * ported from the Mpiric syzkaller executor (common_linux_quic.h). No userspace
 * TLS agent: the kernel does not parse the TLS bytes in CRYPTO frames (ALPN
 * demux off), so the handshake completes deterministically over loopback.
 *
 * Design:
 *   parent: KCOV_INIT_TRACE + KCOV_REMOTE_ENABLE(common_handle = H)
 *           -> the parent's area receives every remote section opened with H.
 *   child (forked AFTER the enable): inherits task->kcov_handle = H but has NO
 *           per-task kcov.  It runs the whole QUIC exercise (client + server in
 *           this one task).  Every quic socket it creates captures H in
 *           quic_init_sock(); the receive-softirq bracket in quic_packet_rcv()
 *           routes the frame-processing PCs to the parent's area.
 *   parent: only fork/wait -> any net/quic PC in its area can ONLY have arrived
 *           through a remote section, i.e. through the keystone.
 *
 * Mode "task": parent does plain KCOV_ENABLE and runs the exercise itself ->
 * the per-task baseline (syscall side + backlog drain), for contrast.
 *
 * To drive frames through SOFTIRQ rather than the backlog drain, the sender
 * sends and then SLEEPS: the 1-RTT packet arrives while the peer task is idle
 * (socket not owned by user) -> quic_packet_rcv() fast path -> softirq.  The
 * graceful close sends a CONNECTION_CLOSE that the idle peer likewise handles
 * in softirq (quic_frame_connection_close_process).
 *
 * Output: "pc <hex>" lines on stdout, one per unique recorded PC.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#define KCOV_INIT_TRACE    _IOR('c', 1, unsigned long)
#define KCOV_ENABLE        _IO('c', 100)
#define KCOV_DISABLE       _IO('c', 101)
#define KCOV_REMOTE_ENABLE _IOW('c', 102, struct kcov_remote_arg)
#define KCOV_TRACE_PC 0
#define KCOV_SUBSYSTEM_COMMON (0x00ull << 56)
#define COVER_SIZE (1 << 20)

#ifndef IPPROTO_QUIC
#define IPPROTO_QUIC 261
#endif
#ifndef SOL_QUIC
#define SOL_QUIC 288
#endif

/* --- QUIC uapi constants (from net/quic uapi, via common_linux_quic.h) --- */
#define QUIC_CRYPTO_APP 0
#define QUIC_CRYPTO_INITIAL 1
#define QUIC_CRYPTO_HANDSHAKE 2
#define QUIC_CRYPTO_EARLY 3
#define QUIC_HANDSHAKE_INFO 1
#define QUIC_STREAM_INFO 0
#define QUIC_SOCKOPT_TRANSPORT_PARAM 8
#define QUIC_SOCKOPT_CRYPTO_SECRET 13
#define QUIC_SOCKOPT_TRANSPORT_PARAM_EXT 14
#define QUIC_CIPHER_AES_GCM_128 51
#define QUIC_CRYPTO_SECRET_BUFFER_SIZE 48

/* MSG_* re-labelled for QUIC stream semantics (uapi/linux/quic.h). */
#define MSG_QUIC_STREAM_NEW MSG_SYN
#define MSG_QUIC_STREAM_FIN MSG_FIN
#define MSG_QUIC_STREAM_UNI MSG_CONFIRM

struct kcov_remote_arg {
	uint32_t trace_mode;
	uint32_t area_size;
	uint32_t num_handles;
	uint64_t common_handle;
	uint64_t handles[];
};

struct quic_crypto_secret_u {
	uint8_t send;
	uint8_t level;
	uint16_t reserved;
	uint32_t type;
	uint8_t secret[QUIC_CRYPTO_SECRET_BUFFER_SIZE];
};
struct quic_handshake_info_u { uint8_t crypto_level; };
struct quic_stream_info_u { long long stream_id; uint32_t stream_flags; };
struct quic_transport_param_short {
	uint8_t remote, disable_active_migration, grease_quic_bit,
		stateless_reset, disable_1rtt_encryption;
};

static void die(const char *m) { perror(m); exit(1); }

/* fake per-level secrets [Early,Handshake,App] x [client,server], verbatim from
 * the v15 selftest / executor table. Both ends use the same table, opposite
 * serv index, so send/recv keys line up symmetrically. */
static struct quic_crypto_secret_u fake_keys[3][2] = {
    {{0,0,0,QUIC_CIPHER_AES_GCM_128,{0x5D,0x9A,0x21,0xF0,0x3C,0x88,0x6B,0x4E,0xD2,0x11,0xAF,0x62,0xB0,0x37,0x8E,0xC5,0x79,0x0D,0x54,0xE1,0xA3,0x96,0x2F,0xCB,0x08,0x7D,0x41,0xFA,0x13,0xB8,0x6E,0x22,0x9F,0x30,0xD4,0x5B,0xE7,0x12,0x8A,0x61,0x04,0xC9,0x3E,0xF6,0x57,0xAD,0x20,0x89}},
     {0,0,0,QUIC_CIPHER_AES_GCM_128,{0xA1,0x3F,0xC6,0x57,0x8B,0x0D,0xE2,0x49,0x6C,0xF1,0x95,0x2B,0xD7,0x40,0x8E,0x13,0x54,0x9A,0x7F,0xC2,0x0B,0x68,0x31,0xEA,0x05,0xD9,0x22,0x7C,0xB3,0x4F,0x10,0x8D,0xE6,0x29,0xF0,0x57,0xAD,0x1C,0x83,0x64,0xB2,0x09,0xC7,0x3E,0xF5,0x61,0x2A,0x98}}},
    {{0,0,0,QUIC_CIPHER_AES_GCM_128,{0x7C,0x12,0xA9,0x4F,0xD0,0x38,0xB2,0xE5,0x09,0x6A,0xF4,0x51,0xC8,0x23,0x9D,0x7E,0x10,0x84,0xFA,0x3B,0x6D,0x97,0x0C,0xE2,0x4A,0xF9,0x30,0x11,0xB6,0xC5,0x78,0x2D,0x66,0x1F,0xCB,0x5E,0x82,0x90,0xDA,0x04,0x37,0xAF,0x15,0xE8,0x63,0xC1,0x2B,0x0D}},
     {0,0,0,QUIC_CIPHER_AES_GCM_128,{0x8F,0x24,0xC0,0x5A,0x19,0xE4,0x72,0x3D,0xB3,0x0F,0xA1,0x68,0x9C,0x42,0xDE,0x75,0xF8,0x07,0x6B,0x11,0xCD,0x93,0x20,0xEA,0x5F,0x38,0x14,0xD1,0x49,0xBE,0x80,0x23,0xAA,0x6C,0x12,0x5D,0xEF,0x04,0x97,0x31,0x6E,0x1B,0xC8,0xF3,0x50,0x08,0xDA,0x9E}}},
    {{0,0,0,QUIC_CIPHER_AES_GCM_128,{0x9A,0x5C,0xEF,0x12,0x68,0x7D,0x34,0xB1,0x02,0xF9,0xAD,0x47,0x6C,0x03,0xE5,0x8F,0x1D,0xA7,0x60,0xCB,0x35,0x84,0x9F,0x22,0x71,0x0B,0xDC,0x56,0xEE,0x13,0x42,0x9C,0x5B,0xF0,0x28,0x6D,0x81,0x14,0xC7,0x3E,0xA2,0x9D,0x0F,0x68,0xB5,0x7A,0x11,0xD3}},
     {0,0,0,QUIC_CIPHER_AES_GCM_128,{0xC1,0x3E,0x7F,0xB4,0x09,0x5A,0xE8,0x2D,0x4C,0xA7,0x10,0xF3,0x68,0x9D,0x21,0xCB,0x57,0x80,0x36,0x1A,0xF2,0x4B,0xC9,0x05,0xE0,0x6F,0x93,0x2A,0xBD,0x14,0x7C,0x8E,0x35,0xDA,0x0C,0x41,0xF6,0x92,0xA0,0x7B,0x18,0xCB,0x55,0xE7,0x6A,0x1F,0xD4,0x0B}}}};

static const uint8_t fake_client_hello[] = {
    0x01,0x00,0x00,0x36,0x03,0x03,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,
    0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,
    0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x00,0x00,0x02,0x13,0x01,0x01,0x00,0x00,0x0B,0x00,
    0x10,0x00,0x07,0x00,0x05,0x04,0x66,0x61,0x6B,0x65};
static const uint8_t fake_enc_ext[] = {0x08,0x00,0x00,0x02,0x00,0x00};

static int set_fake_keys(int fd, uint8_t level, uint8_t serv)
{
	struct quic_crypto_secret_u *s;
	int i = level == QUIC_CRYPTO_EARLY ? 0 :
		level == QUIC_CRYPTO_HANDSHAKE ? 1 :
		level == QUIC_CRYPTO_APP ? 2 : -1;
	if (i < 0) return -1;
	s = &fake_keys[i][serv];
	s->send = 1; s->level = level; s->type = QUIC_CIPHER_AES_GCM_128;
	if (setsockopt(fd, SOL_QUIC, QUIC_SOCKOPT_CRYPTO_SECRET, s, sizeof(*s)) < 0) return -1;
	s = &fake_keys[i][!serv];
	s->send = 0; s->level = level; s->type = QUIC_CIPHER_AES_GCM_128;
	if (setsockopt(fd, SOL_QUIC, QUIC_SOCKOPT_CRYPTO_SECRET, s, sizeof(*s)) < 0) return -1;
	return 0;
}

static int send_hs(int fd, const void *msg, size_t len, uint8_t level)
{
	char cbuf[CMSG_SPACE(sizeof(struct quic_handshake_info_u))];
	struct quic_handshake_info_u *info;
	struct msghdr m; struct cmsghdr *c; struct iovec iov;
	iov.iov_base = (void *)msg; iov.iov_len = len;
	memset(&m, 0, sizeof(m));
	m.msg_iov = &iov; m.msg_iovlen = 1;
	m.msg_control = cbuf; m.msg_controllen = sizeof(cbuf);
	c = CMSG_FIRSTHDR(&m);
	c->cmsg_level = SOL_QUIC; c->cmsg_type = QUIC_HANDSHAKE_INFO;
	c->cmsg_len = CMSG_LEN(sizeof(*info));
	info = (struct quic_handshake_info_u *)CMSG_DATA(c);
	info->crypto_level = level;
	return (int)sendmsg(fd, &m, 0);
}

static int recv_hs(int fd, void *msg, size_t len, uint8_t *level)
{
	char cbuf[CMSG_SPACE(sizeof(struct quic_handshake_info_u))];
	struct quic_handshake_info_u *info;
	struct cmsghdr *c; struct msghdr m; struct iovec iov; ssize_t r;
	iov.iov_base = msg; iov.iov_len = len;
	memset(&m, 0, sizeof(m));
	m.msg_iov = &iov; m.msg_iovlen = 1;
	m.msg_control = cbuf; m.msg_controllen = sizeof(cbuf);
	r = recvmsg(fd, &m, 0);
	if (r < 0) return (int)r;
	*level = 0;
	c = CMSG_FIRSTHDR(&m);
	if (c && c->cmsg_level == SOL_QUIC && c->cmsg_type == QUIC_HANDSHAKE_INFO) {
		info = (struct quic_handshake_info_u *)CMSG_DATA(c);
		*level = info->crypto_level;
	}
	return (int)r;
}

static int send_fake_hs(int fd, uint8_t level, uint8_t serv)
{
	char msg[4096], ext[256]; unsigned int len = 0;
	if (!serv && level == QUIC_CRYPTO_INITIAL) {
		socklen_t sl = sizeof(ext);
		if (getsockopt(fd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM_EXT, ext, &sl) < 0) return -1;
		memcpy(msg, fake_client_hello, sizeof(fake_client_hello));
		memcpy(&msg[sizeof(fake_client_hello)], ext, sl);
		len = sizeof(fake_client_hello) + sl;
	} else if (serv && level == QUIC_CRYPTO_HANDSHAKE) {
		socklen_t sl = sizeof(ext);
		if (getsockopt(fd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM_EXT, ext, &sl) < 0) return -1;
		memcpy(msg, fake_enc_ext, sizeof(fake_enc_ext));
		memcpy(&msg[sizeof(fake_enc_ext)], ext, sl);
		len = sizeof(fake_enc_ext) + sl;
	}
	return send_hs(fd, msg, len, level) < 0 ? -1 : 0;
}

static int recv_fake_hs(int fd, uint8_t level, uint8_t serv)
{
	char msg[4096]; uint8_t l = 0; int r = recv_hs(fd, msg, sizeof(msg), &l);
	if (r < 0 || l != level) return -1;
	if (serv && level == QUIC_CRYPTO_INITIAL) {
		if ((unsigned)r < sizeof(fake_client_hello)) return -1;
		if (setsockopt(fd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM_EXT,
			       &msg[sizeof(fake_client_hello)], r - sizeof(fake_client_hello)) < 0) return -1;
	} else if (!serv && level == QUIC_CRYPTO_HANDSHAKE) {
		if ((unsigned)r < sizeof(fake_enc_ext)) return -1;
		if (setsockopt(fd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM_EXT,
			       &msg[sizeof(fake_enc_ext)], r - sizeof(fake_enc_ext)) < 0) return -1;
	}
	return 0;
}

static int set_disable_1rtt(int fd)
{
	struct quic_transport_param_short tp;
	memset(&tp, 0, sizeof(tp));
	tp.disable_1rtt_encryption = 1;
	return setsockopt(fd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM, &tp, sizeof(tp));
}

static int stream_send(int fd, const void *buf, size_t len)
{
	char cbuf[CMSG_SPACE(sizeof(struct quic_stream_info_u))];
	struct quic_stream_info_u *info;
	struct msghdr m; struct cmsghdr *c; struct iovec iov;
	uint32_t sbits = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN;
	iov.iov_base = (void *)buf; iov.iov_len = len;
	memset(&m, 0, sizeof(m));
	m.msg_iov = &iov; m.msg_iovlen = 1;
	m.msg_control = cbuf; m.msg_controllen = sizeof(cbuf);
	c = CMSG_FIRSTHDR(&m);
	c->cmsg_level = SOL_QUIC; c->cmsg_type = QUIC_STREAM_INFO;
	c->cmsg_len = CMSG_LEN(sizeof(*info));
	m.msg_controllen = c->cmsg_len;
	info = (struct quic_stream_info_u *)CMSG_DATA(c);
	info->stream_id = -1;
	info->stream_flags = sbits;
	return (int)sendmsg(fd, &m, MSG_NOSIGNAL);
}

static void stream_drain(int fd)
{
	char buf[2048];
	for (int i = 0; i < 8; i++) {
		struct iovec iov = {buf, sizeof(buf)};
		struct msghdr m; memset(&m, 0, sizeof(m));
		m.msg_iov = &iov; m.msg_iovlen = 1;
		if (recvmsg(fd, &m, MSG_DONTWAIT) <= 0) break;
	}
}

/* Bring up an established QUIC pair with fake keys (+disable_1rtt), run stream
 * round-trips with sleeps so the RX runs in softirq, then graceful close so the
 * peer handles CONNECTION_CLOSE in softirq. Both roles in this one task. */
static int quic_exercise(int disable_1rtt)
{
	struct sockaddr_in sa; socklen_t al = sizeof(sa);
	struct timeval tv = {3, 0};
	int lfd, cfd, afd, i; char buf[256];

	lfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_QUIC);
	if (lfd < 0) die("socket(quic listen)");
	setsockopt(lfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(lfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET; sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(lfd, (struct sockaddr *)&sa, sizeof(sa)) < 0) die("bind");
	if (getsockname(lfd, (struct sockaddr *)&sa, &al) < 0) die("getsockname");
	if (disable_1rtt && set_disable_1rtt(lfd) < 0) die("disable_1rtt lfd");
	if (listen(lfd, 1) < 0) die("listen");

	cfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_QUIC);
	if (cfd < 0) die("socket(quic client)");
	setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	if (connect(cfd, (struct sockaddr *)&sa, sizeof(sa)) < 0) die("connect");
	if (disable_1rtt && set_disable_1rtt(cfd) < 0) die("disable_1rtt cfd");

	if (send_fake_hs(cfd, QUIC_CRYPTO_INITIAL, 0) < 0) { fprintf(stderr, "send c-init\n"); return -1; }
	afd = accept(lfd, NULL, NULL);
	if (afd < 0) die("accept");
	setsockopt(afd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(afd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

	if (recv_fake_hs(afd, QUIC_CRYPTO_INITIAL, 1) < 0) { fprintf(stderr, "recv s-init\n"); return -1; }
	if (set_fake_keys(afd, QUIC_CRYPTO_HANDSHAKE, 1) < 0) return -1;
	if (send_fake_hs(afd, QUIC_CRYPTO_INITIAL, 1) < 0) return -1;
	if (send_fake_hs(afd, QUIC_CRYPTO_HANDSHAKE, 1) < 0) return -1;

	if (recv_fake_hs(cfd, QUIC_CRYPTO_INITIAL, 0) < 0) { fprintf(stderr, "recv c-init\n"); return -1; }
	if (set_fake_keys(cfd, QUIC_CRYPTO_HANDSHAKE, 0) < 0) return -1;
	if (recv_fake_hs(cfd, QUIC_CRYPTO_HANDSHAKE, 0) < 0) { fprintf(stderr, "recv c-hs\n"); return -1; }
	if (set_fake_keys(cfd, QUIC_CRYPTO_APP, 0) < 0) return -1;
	if (send_fake_hs(cfd, QUIC_CRYPTO_HANDSHAKE, 0) < 0) return -1;

	if (recv_fake_hs(afd, QUIC_CRYPTO_HANDSHAKE, 1) < 0) { fprintf(stderr, "recv s-hs\n"); return -1; }
	if (set_fake_keys(afd, QUIC_CRYPTO_APP, 1) < 0) return -1;

	fprintf(stderr, "ESTABLISHED (disable_1rtt=%d)\n", disable_1rtt);

	/* Stream round-trips; sleep after each send so the incoming 1-RTT packet
	 * is processed in softirq (peer not in a recv syscall) -> keystone. */
	for (i = 0; i < 8; i++) {
		memset(buf, 'a' + i, sizeof(buf));
		stream_send(cfd, buf, sizeof(buf));
		usleep(30 * 1000);          /* c->s delivered in softirq */
		stream_drain(afd);
		stream_send(afd, buf, sizeof(buf) / 2);
		usleep(30 * 1000);          /* s->c delivered in softirq */
		stream_drain(cfd);
	}
	usleep(100 * 1000);

	/* Graceful close: the CONNECTION_CLOSE frame from each close is handled
	 * by the idle peer in softirq -> quic_frame_connection_close_process. */
	close(cfd);
	usleep(120 * 1000);
	close(afd);
	usleep(120 * 1000);
	close(lfd);
	usleep(80 * 1000);
	return 0;
}

static int cmp_ul(const void *x, const void *y)
{
	unsigned long a = *(const unsigned long *)x, b = *(const unsigned long *)y;
	return a < b ? -1 : a > b;
}
static void dump(unsigned long *cover)
{
	unsigned long n = cover[0], i, u = 0;
	unsigned long *v = malloc(n * sizeof(*v));
	if (!v) die("malloc");
	memcpy(v, cover + 1, n * sizeof(*v));
	qsort(v, n, sizeof(*v), cmp_ul);
	for (i = 0; i < n; i++)
		if (i == 0 || v[i] != v[i - 1]) { printf("pc %lx\n", v[i]); u++; }
	fprintf(stderr, "raw=%lu unique=%lu\n", n, u);
	free(v);
}

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "remote";
	int disable_1rtt = argc > 2 ? atoi(argv[2]) : 1;
	int fd = open("/sys/kernel/debug/kcov", O_RDWR);
	unsigned long *cover;
	if (fd < 0) die("open kcov");
	if (ioctl(fd, KCOV_INIT_TRACE, COVER_SIZE)) die("KCOV_INIT_TRACE");
	cover = mmap(NULL, COVER_SIZE * sizeof(unsigned long),
		     PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (cover == MAP_FAILED) die("mmap");

	if (!strcmp(mode, "remote")) {
		struct kcov_remote_arg arg = {
			.trace_mode = KCOV_TRACE_PC, .area_size = COVER_SIZE,
			.num_handles = 0, .common_handle = KCOV_SUBSYSTEM_COMMON | 0x42,
		};
		if (ioctl(fd, KCOV_REMOTE_ENABLE, &arg)) die("KCOV_REMOTE_ENABLE");
		__atomic_store_n(&cover[0], 0, __ATOMIC_RELAXED);
		pid_t p = fork();
		if (p < 0) die("fork");
		if (p == 0) { _exit(quic_exercise(disable_1rtt) ? 1 : 0); }
		int st; waitpid(p, &st, 0);
		usleep(200 * 1000);
		if (ioctl(fd, KCOV_DISABLE, 0)) die("KCOV_DISABLE");
		fprintf(stderr, "child status=%d\n", st);
	} else if (!strcmp(mode, "task")) {
		if (ioctl(fd, KCOV_ENABLE, KCOV_TRACE_PC)) die("KCOV_ENABLE");
		__atomic_store_n(&cover[0], 0, __ATOMIC_RELAXED);
		quic_exercise(disable_1rtt);
		if (ioctl(fd, KCOV_DISABLE, 0)) die("KCOV_DISABLE");
	} else {
		fprintf(stderr, "usage: %s remote|task [disable_1rtt]\n", argv[0]);
		return 2;
	}
	dump(cover);
	return 0;
}
