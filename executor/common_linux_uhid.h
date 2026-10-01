// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// /dev/uhid content-aware responder pseudo-syscall.
//
// A HID driver's .probe may call hid_hw_raw_request(HID_REQ_GET_REPORT),
// which on a uhid device blocks in the kernel for up to 5 s waiting for a
// UHID_GET_REPORT_REPLY whose id matches the UHID_GET_REPORT event it just
// queued to userspace (drivers/hid/uhid.c, __uhid_report_queue_and_wait /
// uhid_report_wake_up). Stock dev_uhid.txt replies blind (no read of the
// request, a guessed id, the wrong reply struct), so a driver whose probe or
// parser depends on the reply content is effectively unreachable.
//
// syz_uhid_create_responder() closes that gap: it opens /dev/uhid, creates
// (UHID_CREATE2) a device whose bus/vendor/product bind it to a chosen target
// driver, and spawns a responder thread that poll()/read()-loops the fd and,
// for every UHID_GET_REPORT / UHID_SET_REPORT it sees, writes the matching
// *_REPLY echoing the request id with err=0 and carrying the fuzzer-chosen
// reply payload as data[] -- the bytes the driver's parser then consumes.
// The uhid fd is returned as the fd_uhid_responder resource (a sub-resource
// of fd_uhid, so stock write$UHID_INPUT2 etc. can be sequenced on it).
//
// syz_uhid_destroy_responder() is the consuming edge: stop + join the thread,
// UHID_DESTROY the device, release the slot.
//
// Same shape as the MPTCP NFQUEUE engine (common_linux_mptcp_nfq.h): one
// self-contained op owns the fd, a background worker with a stop flag joined
// at teardown, and a content-matching reply -- here keyed on the request id
// instead of a TCP option. No kernel-side support needed beyond CONFIG_UHID
// and the target driver being built in.

#ifndef EXECUTOR_COMMON_LINUX_UHID_H
#define EXECUTOR_COMMON_LINUX_UHID_H

#include <errno.h>
#include <fcntl.h>
#include <linux/uhid.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

// Harness flags (uhid_resp_flags in sys/linux/dev_uhid_responder.txt; the
// values are mirrored there as `define`s and in the .const -- keep in sync).
#define UHID_RESP_ECHO_RNUM 1 // data[0] = requested report id (hid-playstation ps_get_report gate)
#define UHID_RESP_CRC32 2 // append crc32 over data[0..size-4) at data[size-4..] (playstation BT bus)
#define UHID_RESP_SET_FAIL 4 // ack UHID_SET_REPORT with err=1 (driver sees -EIO)
#define UHID_RESP_EXACT_LEN 8 // reply size = payload_len instead of the driver-expected/padded size
#define UHID_RESP_WAIT_PROBE 16 // block the op until the responder went quiet or the wait cap hit

// Target profiles (uhid_resp_targets in the .txt; same three-places rule).
#define UHID_TARGET_GENERIC 0
#define UHID_TARGET_PS_DUALSENSE_USB 1
#define UHID_TARGET_PS_DUALSENSE_BT 2
#define UHID_TARGET_PS_DS4_USB 3
#define UHID_TARGET_CP2112 4

#define UHID_RESP_POOL_SIZE 8
#define UHID_RESP_POLL_MS 50
#define UHID_RESP_PROBE_WAIT_MS 200
#define UHID_RESP_PROBE_QUIET_MS 20
#define UHID_RESP_PS_FEATURE_CRC32_SEED 0xA3
// Bus ids from <linux/input.h>; the uhid header already pulls that in.
#define UHID_RESP_BUS_USB 0x03
#define UHID_RESP_BUS_BLUETOOTH 0x05

// Per-report-id reply length a driver's probe validates (playstation checks
// `ret != size`, and on BT reads the CRC from data[size-4]); 0-terminated.
struct uhid_resp_rsize {
	uint8 rnum;
	uint16 size;
};

struct uhid_resp_target {
	const char* name;
	uint16 bus;
	uint32 vendor;
	uint32 product;
	struct uhid_resp_rsize rsizes[4];
};

// One vendor-page application collection with a 64-byte input, output and
// feature report (report id 1). Enough for hid_parse() and hidraw connect on
// every target below; the drivers bind on bus/vendor/product, not on the
// descriptor contents.
static const uint8 uhid_resp_rdesc[] = {
    0x06, 0x00, 0xff, // Usage Page (Vendor Defined 0xFF00)
    0x09, 0x01, // Usage (0x01)
    0xa1, 0x01, // Collection (Application)
    0x85, 0x01, //   Report ID (1)
    0x09, 0x02, //   Usage (0x02)
    0x15, 0x00, //   Logical Minimum (0)
    0x26, 0xff, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //   Report Size (8)
    0x95, 0x40, //   Report Count (64)
    0x81, 0x02, //   Input (Data,Var,Abs)
    0x09, 0x03, //   Usage (0x03)
    0x91, 0x02, //   Output (Data,Var,Abs)
    0x09, 0x04, //   Usage (0x04)
    0xb1, 0x02, //   Feature (Data,Var,Abs)
    0xc0, // End Collection
};

// Vendor/product ids from drivers/hid/hid-ids.h; report ids/sizes from
// drivers/hid/hid-playstation.c (DS_FEATURE_REPORT_* / DS4_FEATURE_REPORT_*).
static const struct uhid_resp_target uhid_resp_targets[] = {
    {"generic", UHID_RESP_BUS_USB, 0x1234, 0x5678, {{0, 0}}},
    // USB_VENDOR_ID_SONY / USB_DEVICE_ID_SONY_PS5_CONTROLLER: hid-playstation,
    // dualsense_create -> calibration 0x05/41, pairing 0x09/20, firmware 0x20/64.
    {"ps-dualsense-usb", UHID_RESP_BUS_USB, 0x054c, 0x0ce6, {{0x05, 41}, {0x09, 20}, {0x20, 64}, {0, 0}}},
    {"ps-dualsense-bt", UHID_RESP_BUS_BLUETOOTH, 0x054c, 0x0ce6, {{0x05, 41}, {0x09, 20}, {0x20, 64}, {0, 0}}},
    // USB_DEVICE_ID_SONY_PS4_CONTROLLER_2: dualshock4_create on USB ->
    // calibration 0x02/37, pairing 0x12/16, firmware 0xa3/49.
    {"ps-ds4-usb", UHID_RESP_BUS_USB, 0x054c, 0x09cc, {{0x02, 37}, {0x12, 16}, {0xa3, 49}, {0, 0}}},
    // USB_VENDOR_ID_CYGNAL / USB_DEVICE_ID_CYGNAL_CP2112: hid-cp2112 probe
    // wants exactly 3 bytes for CP2112_GET_VERSION_INFO (0x05).
    {"cp2112", UHID_RESP_BUS_USB, 0x10c4, 0xea90, {{0x05, 3}, {0, 0}}},
};

struct uhid_resp_slot {
	int pub_fd; // the fd returned to the program (fd_uhid_responder)
	int priv_fd; // dup held by the thread; never exposed, so a program-side close() can't alias it
	pthread_t thread;
	int started;
	volatile int stop;
	volatile uint64 last_activity_ms; // last request answered (0 = none yet)
	const struct uhid_resp_target* target;
	uint32 flags;
	uint32 payload_len;
	uint8 payload[UHID_DATA_MAX];
};

static struct uhid_resp_slot uhid_resp_pool[UHID_RESP_POOL_SIZE];
static int uhid_resp_atexit_registered;

static inline uint64 uhid_resp_now_ms(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (uint64)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

// Reflected CRC-32 (poly 0xEDB88320), same contract as the kernel's
// crc32_le(): no pre/post inversion, the caller supplies the seed. The
// playstation driver checks ~crc32_le(crc32_le(~0, &seed, 1), data, len).
static inline uint32 uhid_resp_crc32_le(uint32 crc, const uint8* p, size_t len)
{
	for (size_t i = 0; i < len; i++) {
		crc ^= p[i];
		for (int k = 0; k < 8; k++)
			crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
	}
	return crc;
}

// Reply length for a GET_REPORT on report id rnum. The driver's requested
// count is not visible in the event, and the kernel delivers
// min3(count, size, UHID_DATA_MAX): padding to UHID_DATA_MAX therefore makes
// every `ret != expected` validator pass. A target's rsizes entry overrides
// that so a BT CRC lands at the slot the driver reads it from; EXACT_LEN lets
// the fuzzer drive the short-reply error paths instead.
static inline uint32 uhid_resp_reply_size(const struct uhid_resp_slot* s, uint8 rnum)
{
	if (s->flags & UHID_RESP_EXACT_LEN)
		return s->payload_len;
	for (int i = 0; i < 4 && s->target->rsizes[i].size; i++) {
		if (s->target->rsizes[i].rnum == rnum)
			return s->target->rsizes[i].size;
	}
	return UHID_DATA_MAX;
}

static inline void uhid_resp_answer_get(struct uhid_resp_slot* s, const struct uhid_event* req)
{
	struct uhid_event rep;
	memset(&rep, 0, sizeof(rep));
	rep.type = UHID_GET_REPORT_REPLY;
	rep.u.get_report_reply.id = req->u.get_report.id; // echo the real id: this is the match key
	rep.u.get_report_reply.err = 0;
	uint32 size = uhid_resp_reply_size(s, req->u.get_report.rnum);
	uint8* data = rep.u.get_report_reply.data;
	uint32 copy = s->payload_len < size ? s->payload_len : size;
	memcpy(data, s->payload, copy);
	if ((s->flags & UHID_RESP_ECHO_RNUM) && size >= 1)
		data[0] = req->u.get_report.rnum;
	if ((s->flags & UHID_RESP_CRC32) && size >= 5) {
		uint8 seed = UHID_RESP_PS_FEATURE_CRC32_SEED;
		uint32 crc = uhid_resp_crc32_le(0xFFFFFFFFu, &seed, 1);
		crc = ~uhid_resp_crc32_le(crc, data, size - 4);
		data[size - 4] = (uint8)crc;
		data[size - 3] = (uint8)(crc >> 8);
		data[size - 2] = (uint8)(crc >> 16);
		data[size - 1] = (uint8)(crc >> 24);
	}
	rep.u.get_report_reply.size = (uint16)size;
	// type + {id, err, size} + data: the kernel zero-extends short writes.
	size_t wlen = sizeof(rep.type) + sizeof(rep.u.get_report_reply) - UHID_DATA_MAX + size;
	if (write(s->priv_fd, &rep, wlen) < 0) {
		debug("uhid_resp: GET_REPORT_REPLY id=%u rnum=%u failed errno=%d\n", req->u.get_report.id, req->u.get_report.rnum, errno);
	}
}

static inline void uhid_resp_answer_set(struct uhid_resp_slot* s, const struct uhid_event* req)
{
	struct uhid_event rep;
	memset(&rep, 0, sizeof(rep));
	rep.type = UHID_SET_REPORT_REPLY;
	rep.u.set_report_reply.id = req->u.set_report.id;
	rep.u.set_report_reply.err = (s->flags & UHID_RESP_SET_FAIL) ? 1 : 0;
	if (write(s->priv_fd, &rep, sizeof(rep.type) + sizeof(rep.u.set_report_reply)) < 0) {
		debug("uhid_resp: SET_REPORT_REPLY id=%u failed errno=%d\n", req->u.set_report.id, errno);
	}
}

static inline void* uhid_resp_thread(void* arg)
{
	struct uhid_resp_slot* s = (struct uhid_resp_slot*)arg;
	struct uhid_event ev;
	while (!__atomic_load_n(&s->stop, __ATOMIC_SEQ_CST)) {
		struct pollfd pfd = {s->priv_fd, POLLIN, 0};
		// Bounded poll so the loop periodically re-checks the stop flag --
		// that is the only wake source destroy/cleanup rely on for a clean join.
		int prc = poll(&pfd, 1, UHID_RESP_POLL_MS);
		if (prc < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (prc == 0)
			continue;
		// Short kernel reads must be zero-extended by userspace (uapi/linux/uhid.h).
		memset(&ev, 0, sizeof(ev));
		ssize_t n = read(s->priv_fd, &ev, sizeof(ev));
		if (n < 0) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			break;
		}
		if (n < (ssize_t)sizeof(ev.type))
			continue;
		switch (ev.type) {
		case UHID_GET_REPORT:
			uhid_resp_answer_get(s, &ev);
			s->last_activity_ms = uhid_resp_now_ms();
			break;
		case UHID_SET_REPORT:
			uhid_resp_answer_set(s, &ev);
			s->last_activity_ms = uhid_resp_now_ms();
			break;
		case UHID_OUTPUT:
			// Stub: the OUTPUT -> INPUT2 sibling responder (hid-nintendo,
			// hid-logitech-hidpp) hooks in here; not part of this op.
			break;
		default: // UHID_START / STOP / OPEN / CLOSE: state notices, nothing to answer
			break;
		}
	}
	return NULL;
}

static inline void uhid_resp_slot_teardown(struct uhid_resp_slot* s)
{
	if (!s->started)
		return;
	__atomic_store_n(&s->stop, 1, __ATOMIC_SEQ_CST);
	pthread_join(s->thread, NULL);
	s->started = 0;
	struct uhid_event ev;
	memset(&ev, 0, sizeof(ev));
	ev.type = UHID_DESTROY;
	if (write(s->priv_fd, &ev, sizeof(ev.type)) < 0) {
		debug("uhid_resp: UHID_DESTROY failed errno=%d\n", errno);
	}
	close(s->priv_fd);
	s->priv_fd = -1;
	s->pub_fd = -1;
}

static inline void uhid_resp_cleanup_all(void)
{
	for (int i = 0; i < UHID_RESP_POOL_SIZE; i++)
		uhid_resp_slot_teardown(&uhid_resp_pool[i]);
}

static inline struct uhid_resp_slot* uhid_resp_lookup(int fd)
{
	for (int i = 0; i < UHID_RESP_POOL_SIZE; i++) {
		if (uhid_resp_pool[i].started && uhid_resp_pool[i].pub_fd == fd)
			return &uhid_resp_pool[i];
	}
	return NULL;
}

#if SYZ_EXECUTOR || __NR_syz_uhid_create_responder
// a0: target (uhid_resp_targets), a1/a2: reply payload + len, a3: uhid_resp_flags.
static long syz_uhid_create_responder(volatile long a0, volatile long a1, volatile long a2, volatile long a3)
{
	long target = a0;
	const uint8* payload = (const uint8*)a1;
	size_t payload_len = (size_t)a2;
	uint32 flags = (uint32)a3;

	if (target < 0 || target >= (long)(sizeof(uhid_resp_targets) / sizeof(uhid_resp_targets[0]))) {
		debug("syz_uhid_create_responder: target %ld out of range\n", target);
		errno = EINVAL;
		return -1;
	}
	struct uhid_resp_slot* s = NULL;
	for (int i = 0; i < UHID_RESP_POOL_SIZE && !s; i++) {
		if (!uhid_resp_pool[i].started)
			s = &uhid_resp_pool[i];
	}
	if (!s) {
		debug("syz_uhid_create_responder: pool exhausted\n");
		errno = ENOSPC;
		return -1;
	}
	int fd = open("/dev/uhid", O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0) {
		debug("syz_uhid_create_responder: open(/dev/uhid) failed errno=%d\n", errno);
		return -1;
	}
	int priv_fd = dup(fd);
	if (priv_fd < 0) {
		close(fd);
		return -1;
	}
	const struct uhid_resp_target* t = &uhid_resp_targets[target];
	struct uhid_event ev;
	memset(&ev, 0, sizeof(ev));
	ev.type = UHID_CREATE2;
	snprintf((char*)ev.u.create2.name, sizeof(ev.u.create2.name), "syz-%s", t->name);
	snprintf((char*)ev.u.create2.phys, sizeof(ev.u.create2.phys), "syz-uhid");
	snprintf((char*)ev.u.create2.uniq, sizeof(ev.u.create2.uniq), "syz-uhid");
	ev.u.create2.rd_size = sizeof(uhid_resp_rdesc);
	ev.u.create2.bus = t->bus;
	ev.u.create2.vendor = t->vendor;
	ev.u.create2.product = t->product;
	memcpy(ev.u.create2.rd_data, uhid_resp_rdesc, sizeof(uhid_resp_rdesc));
	size_t clen = sizeof(ev.type) + sizeof(ev.u.create2) - HID_MAX_DESCRIPTOR_SIZE + sizeof(uhid_resp_rdesc);
	// Arm the slot BEFORE the create: the kernel schedules hid_add_device ->
	// driver .probe -> GET_REPORT on a worker right away, and the thread must
	// already own its state when it starts draining the fd.
	memset(s, 0, sizeof(*s));
	s->pub_fd = fd;
	s->priv_fd = priv_fd;
	s->target = t;
	s->flags = flags;
	if (!payload)
		payload_len = 0;
	if (payload_len > UHID_DATA_MAX)
		payload_len = UHID_DATA_MAX;
	s->payload_len = (uint32)payload_len;
	if (payload_len)
		memcpy(s->payload, payload, payload_len);
	if (write(fd, &ev, clen) < 0) {
		debug("syz_uhid_create_responder: UHID_CREATE2 (%s) failed errno=%d\n", t->name, errno);
		close(priv_fd);
		close(fd);
		return -1;
	}
	if (!uhid_resp_atexit_registered) {
		atexit(uhid_resp_cleanup_all);
		uhid_resp_atexit_registered = 1;
	}
	if (pthread_create(&s->thread, NULL, uhid_resp_thread, s) != 0) {
		debug("syz_uhid_create_responder: pthread_create failed errno=%d\n", errno);
		close(priv_fd);
		close(fd);
		return -1;
	}
	s->started = 1;
	if (flags & UHID_RESP_WAIT_PROBE) {
		// Give the async probe its handshake while this program is still
		// alive: return once a request was answered and the fd went quiet,
		// or at the cap.
		uint64 start = uhid_resp_now_ms();
		while (uhid_resp_now_ms() - start < UHID_RESP_PROBE_WAIT_MS) {
			uint64 last = s->last_activity_ms;
			if (last && uhid_resp_now_ms() - last >= UHID_RESP_PROBE_QUIET_MS)
				break;
			usleep(5000);
		}
	}
	return fd;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_uhid_destroy_responder
static long syz_uhid_destroy_responder(volatile long a0)
{
	struct uhid_resp_slot* s = uhid_resp_lookup((int)a0);
	if (!s) {
		debug("syz_uhid_destroy_responder: fd %ld is not a live responder\n", (long)a0);
		errno = EBADF;
		return -1;
	}
	// Only the private dup is closed here; the program-visible fd stays with
	// the program's own lifetime (a close(fd) it may already have issued must
	// not be doubled onto a possibly reused number).
	uhid_resp_slot_teardown(s);
	return 0;
}
#endif

#endif // EXECUTOR_COMMON_LINUX_UHID_H
