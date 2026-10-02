# eBPF struct_ops fuzzing

This fork extends syzkaller to fuzz kernel code reachable only through a
**verifier-accepted BPF `struct_ops` program**: it generates a semantically
valid program for a `struct_ops` surface, loads it through its own libbpf-free
loader (raw `bpf()` syscalls), registers it, and lets the callbacks run -- so the
kernel paths behind the eBPF verifier get exercised, which a byte-level fuzzer
cannot reach.

## Attribution

Builds on **Syzkaller** (Google -- Dmitry Vyukov et al.) via **BRF**, the eBPF
Runtime Fuzzer (Hsin-Wei Hung & Ardalan Amiri Sani, UC Irvine;
arXiv:2305.08782), whose eBPF-runtime-fuzzing approach this generalizes to
`struct_ops` surfaces. An extension, not a new platform. Preserve `LICENSE`,
`AUTHORS`, `CONTRIBUTORS`; cite both.

## The gate this gets past

The **eBPF verifier**. A `struct_ops` program only loads if it type-checks: the
right member functions, valid kfunc signatures, `KF_RET_NULL` guards, correct
iterator new/next/destroy discipline, writes only to `btf_struct_access`-writable
fields. Random bytes never load. The generator in `pkg/structops/` produces
programs that pass the verifier, so the fuzzer gets *past* it into the subsystem
callback code.

## What this adds over upstream syzkaller

- A **`struct_ops` program generator** (`pkg/structops/`) that emits
  verifier-valid programs for a surface, compiled host-side with
  `BPF_NO_PRESERVE_ACCESS_INDEX` (no CO-RE relocations, so the loader stays
  library-free).
- A **native, libbpf-free loader** (`executor/common_linux_structops.h`) driven
  by the `syz_bpf_struct_ops_load` pseudo-syscall.
- **Spec-storage corpus** (`pkg/structops/materialize/`): the corpus stores the
  generative spec, not a compiled blob, and re-materializes each program
  host-side against the live kernel's BTF at the manager's queue boundary -- so a
  run survives a kernel rebase instead of starting cold.

## The op-set

```
syz_bpf_struct_ops_load$tcp_cong(obj, len)     -> fd_bpf_link
syz_bpf_struct_ops_load$mptcp_sched(obj, len)  -> fd_bpf_link
```

The syscall `$variant` selects the surface; the `obj` blob is a generated load
recipe produced by `pkg/structops` via `Target.SpecialTypes`
(`sys/linux/init_structops.go`). Mutating a blob **re-generates** it (the
`no_squash` attribute stops the mutator flattening it into an ANYBLOB that would
just fail at load).

Surfaces today:

| `$variant` | kernel struct | where |
|---|---|---|
| `tcp_cong` | `struct tcp_congestion_ops` | `net/ipv4/bpf_tcp_ca.c` (mainline) |
| `mptcp_sched` | `struct mptcp_sched_ops` | `net/mptcp/bpf.c` (mptcp/export tree) |

## How the loader works (native, no libbpf)

The blob is a load recipe: the compiled object's BTF, one record per callback
program (instructions, the struct member it fills, kfunc call sites by **name**),
and the instance struct's name. Everything kernel-image-specific is resolved at
load time by name against `/sys/kernel/btf/vmlinux`, because BTF ids differ per
build. The sequence mirrors libbpf's `struct_ops` path with raw `bpf()`:

```
BPF_BTF_LOAD         the object's BTF (func_info per program)
BPF_PROG_LOAD  x N   one BPF_PROG_TYPE_STRUCT_OPS program per callback
                     (attach_btf_id = struct's vmlinux id,
                      expected_attach_type = member index)
BPF_MAP_CREATE       BPF_MAP_TYPE_STRUCT_OPS, value bpf_struct_ops_<name>, BPF_F_LINK
BPF_MAP_UPDATE_ELEM  program fds in their callback slots + a unique .name
BPF_LINK_CREATE      the registration (tcp_register_congestion_control,
                     mptcp_register_scheduler, ...); returns the link fd
```

Registration is **always** through a `BPF_F_LINK` map + link, so the registration
dies with the link fd (which the executor's end-of-program fd sweep closes). A
link-less `struct_ops` registration would take a reference on its own map and
outlive the program -- every executed program would leave another congestion
control / scheduler registered and accumulate.

## Kernel requirements

- `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_JIT=y`, `CONFIG_DEBUG_INFO_BTF=y`
  (the loader needs `/sys/kernel/btf/vmlinux`)
- the surface's own config: `tcp_cong` needs the BPF TCP-CA support; `mptcp_sched`
  needs an MPTCP tree that has BPF scheduler `struct_ops` (`net/mptcp/bpf.c`)
- `CONFIG_KASAN=y`, `CONFIG_KCOV=y` as usual
- host-side program compilation needs `clang` + `pahole` available to the manager

## See also

- `.claude/extension_overview.md` -- the extension architecture end to end.
- `docs/linux/mptcp_protocol_fuzzing.md`, `docs/linux/sctp_protocol_fuzzing.md`
  -- the sibling protocol harnesses.
- `pkg/structops/` -- the generator, recipe, and materialize code.
