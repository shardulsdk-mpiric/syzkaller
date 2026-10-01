/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Minimal stand-in for libbpf's bpf/bpf_tracing.h: the BPF_PROG() macro
 * only (up to 5 typed arguments after the ctx pointer), with the same
 * expansion libbpf uses, so struct_ops callbacks compile identically
 * with or without libbpf-dev on the host. */
#ifndef __BPF_TRACING_H__
#define __BPF_TRACING_H__

#define ___bpf_concat(a, b) a ## b
#define ___bpf_apply(fn, n) ___bpf_concat(fn, n)
#define ___bpf_nth(_, _1, _2, _3, _4, _5, _6, _7, _8, _9, _a, _b, _c, N, ...) N
#define ___bpf_narg(...) \
	___bpf_nth(_, ##__VA_ARGS__, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)

#define ___bpf_ctx_cast0()            ctx
#define ___bpf_ctx_cast1(x)           ___bpf_ctx_cast0(), (void *)ctx[0]
#define ___bpf_ctx_cast2(x, args...)  ___bpf_ctx_cast1(args), (void *)ctx[1]
#define ___bpf_ctx_cast3(x, args...)  ___bpf_ctx_cast2(args), (void *)ctx[2]
#define ___bpf_ctx_cast4(x, args...)  ___bpf_ctx_cast3(args), (void *)ctx[3]
#define ___bpf_ctx_cast5(x, args...)  ___bpf_ctx_cast4(args), (void *)ctx[4]
#define ___bpf_ctx_cast(args...)      ___bpf_apply(___bpf_ctx_cast, ___bpf_narg(args))(args)

/* BPF_PROG(name, args...) defines name(unsigned long long *ctx) as a thin
 * wrapper that unpacks the ctx array into the typed arguments of a
 * static always-inline ____name(ctx, args...), whose body follows. */
#define BPF_PROG(name, args...)						    \
name(unsigned long long *ctx);						    \
static __always_inline typeof(name(0))					    \
____##name(unsigned long long *ctx, ##args);				    \
typeof(name(0)) name(unsigned long long *ctx)				    \
{									    \
	_Pragma("GCC diagnostic push")					    \
	_Pragma("GCC diagnostic ignored \"-Wint-conversion\"")		    \
	return ____##name(___bpf_ctx_cast(args));			    \
	_Pragma("GCC diagnostic pop")					    \
}									    \
static __always_inline typeof(name(0))					    \
____##name(unsigned long long *ctx, ##args)

#endif
