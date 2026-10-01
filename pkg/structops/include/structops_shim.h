/* SPDX-License-Identifier: GPL-2.0 */
/* Force-included (-include) ahead of every rendered struct_ops translation
 * unit by pkg/structops' host compile step.
 *
 * vmlinux.h is the target kernel's BTF dumped as C (bpftool btf dump
 * format c); it is included here first so the inline helpers below can
 * name kernel types.  The rendered unit's own #include "vmlinux.h" is
 * then a no-op through the header's include guard.
 *
 * tcp_sk() is a kernel static inline (include/linux/tcp.h), so it is not
 * in BTF and not in vmlinux.h; the BPF selftests get it from
 * bpf_tcp_helpers.h.  The tcp_congestion_ops render calls it in every
 * callback prologue, so it is provided here, as in the selftests. */
#ifndef STRUCTOPS_SHIM_H
#define STRUCTOPS_SHIM_H

#include "vmlinux.h"

static inline struct tcp_sock *tcp_sk(const struct sock *sk)
{
	return (struct tcp_sock *)sk;
}

#endif
