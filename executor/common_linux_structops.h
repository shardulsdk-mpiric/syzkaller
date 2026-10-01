// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// BPF struct_ops carrier -- loader for syz_bpf_struct_ops_load
// (sys/linux/bpf_struct_ops.txt).
//
// PLACEHOLDER.  The native loader is not written yet; this stub only keeps the
// generated syscall table (executor/syscalls.h references every described
// syz_* call) linking, and makes an enabled description inert: the call fails
// with ENOSYS and nothing is loaded.  The loader that replaces this body takes
// the object blob (obj, len), parses its ELF (.BTF, .BTF.ext, .struct_ops /
// .struct_ops.link, .rel*), resolves kfunc and struct_ops value-type BTF ids
// against /sys/kernel/btf/vmlinux, and issues raw bpf() BPF_BTF_LOAD /
// BPF_PROG_LOAD (one per callback) / BPF_MAP_CREATE (BPF_MAP_TYPE_STRUCT_OPS)
// / BPF_MAP_UPDATE_ELEM / BPF_LINK_CREATE -- no libbpf, per
// docs/pseudo_syscalls.md.

#if SYZ_EXECUTOR || __NR_syz_bpf_struct_ops_load
#include <errno.h>

static long syz_bpf_struct_ops_load(volatile long obj, volatile long len)
{
	(void)obj;
	(void)len;
	errno = ENOSYS;
	return -1;
}
#endif
