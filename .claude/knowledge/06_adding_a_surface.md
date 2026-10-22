# Adding a surface

The recipe for extending the harness with a new protocol surface or a new op on
an existing one, following the state-carrier pattern (01). This is the
`adding_a_protocol_surface` thread in `tasks/index.md`.

## First: pick the gate and the mechanism

Before writing code, be explicit about:

1. **The gate** the surface sits behind -- and, per 01, the gate *behind that
   one*. Confirm it is socket-API-inaccessible (so crossing it is real edge, not
   a test-mode bypass of an outer gate).
2. **The mechanism** that crosses it (01): echo-back of a captured secret,
   constructed validity (grammar / verifier-valid artifact), or both.
3. **Where the target code runs.** If it runs in the calling task, you need no
   coverage annotation. If it runs in softirq/workqueue/deferred context, plan an
   async-path coverage annotation series (03) so the new paths are visible and
   steerable.

## The three planes

Every surface is expressed across the same three planes:

```
sys/linux/<name>_flow.txt(.const)   descriptions: the pseudo-syscalls, args, resources (syzlang)
executor/common_linux_<name>.h      the C carrier: do the stateful/crypto work, capture state
pkg/<generator>/                    (constructed-validity surfaces only) the artifact generator
```

Plus registration (`pkg/vminfo/linux_syscalls.go`) and, optionally, a coverage
annotation series (`kernel_patches/`).

## The checklist

1. **Describe it** in `sys/linux/<name>_flow.txt`: the producer pseudo-syscall
   that returns a `resource`, the consuming (close/free) op, and the ops that
   take the resource. Give the resource an invalid-default sentinel
   (`0xffffffffffffffff`) so a defaulted handle can't alias live slot 0. Use
   `$variant`s to bind a per-op constant (e.g. SCTP's vtag mode) when you don't
   want the fuzzer wasting draws on modes a gate rejects early.

2. **A flag constant lives in THREE places** -- the `.txt` `define`, the matching
   `.txt.const` value, and the executor `#define`. A missing `.const` fails
   extraction with "defined for none of the arches". Harness-only constants (no
   kernel header defines them) must carry their values in the `.txt` so
   `make extract` stays reproducible.

3. **Implement the carrier** in `executor/common_linux_<name>.h`: drive the real
   protocol step, capture the kernel-generated state into the slot/out-param, and
   keep a small static pool indexed by the returned resource. Reuse the NFQUEUE
   wire engine (`common_linux_mptcp_nfq.h`, UDP variant for datagram protocols)
   for egress mutation, and raw-socket + recomputed-checksum injection for
   M-CARRY.

4. **Register the pseudo-syscall** in `pkg/vminfo/linux_syscalls.go` -- map the
   op's `CallName` to a `*Supported` probe, or syz-manager panics when a config
   enables it. A new `$variant` of an existing op shares the entry (the map is
   keyed by `CallName`), so a variant needs no new registration.

5. **(Constructed-validity surfaces) wire the generator.** For a struct_ops-style
   surface, add the per-surface table (writable fields, kfunc set, callback
   signatures, instance metadata) in `pkg/structops/`, register it, add the
   `syz_*_load$<surface>` op + blob type in `bpf_struct_ops.txt`, and register the
   `SpecialType` (the map in `sys/linux/init.go`; the generator in
   `sys/linux/init_structops.go`). Mind the two wrinkles a plain table doesn't
   cover: per-callback kfunc scoping, and kernel-injected prologue/epilogue
   kfuncs. Persist the generative *spec*, not the compiled recipe, so the corpus
   survives a kernel rebase (`pkg/structops/materialize/`).

6. **Decide coverage.** If the target path runs off-task, add an annotation
   series under `kernel_patches/` following the skb-carried-handle pattern (03) --
   no new UAPI.

7. **Regenerate + build, then verify.**
   - `make descriptions` after editing a `.txt`.
   - a **full `make`** (not just `make executor`) before starting a campaign, or
     syz-manager aborts with a revision mismatch.
   - build the executor where current kernel UAPI headers are available (in the
     target VM or a host with current headers).
   - gate battery for a constructed-validity surface: the golden test (the
     pre-existing surfaces' golden hashes must stay unchanged -- that proves the
     shared-model extension is inert for them), `go build`/`vet`, the executor
     build, then a VM run confirming the artifact loads + registers + exercises.
   - keep build caches off a small root filesystem.

## Routing a clean surface addition

Adding a surface is clean engineering (no vulnerability detail), so it can run as
a parallel worker in a git worktree of the fork (its own `bin/`), never `make` in
a tree with a live campaign (it would rev-mismatch the running manager). Source
edits to `.txt`/`.go` in a tree are safe (no rebuild); the build is what must be
isolated.

## The honest bar for "cheap"

"A table, not a fork" holds for callbacks / writable-fields / kfunc-sets /
instance metadata. It does **not** hold for a kfunc that needs a new C idiom (a
new statement kind), which is a generator extension. When a new surface's wrinkles
balloon past a table plus a small generic extension, say so -- that negative is
high-value information about where the pattern's cheapness ends.
</content>
