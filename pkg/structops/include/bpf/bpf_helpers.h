/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Minimal stand-in for libbpf's bpf/bpf_helpers.h: just the attribute
 * macros the pkg/structops render uses.  Keeping this in-tree means the
 * host compile step needs clang + bpftool only, not libbpf-dev.  Macro
 * names and expansions match libbpf (tools/lib/bpf/bpf_helpers.h). */
#ifndef __BPF_HELPERS__
#define __BPF_HELPERS__

#define SEC(name) __attribute__((section(name), used))

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#define __ksym __attribute__((section(".ksyms")))
#define __kconfig __attribute__((section(".kconfig")))
#define __weak __attribute__((weak))

#ifndef NULL
#define NULL ((void *)0)
#endif

#endif
