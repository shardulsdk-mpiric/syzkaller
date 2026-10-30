# Stage 5: Build

- Base and every patched kernel use the **same `.config`** (copy, `olddefconfig`,
  diff the results: a new Kconfig symbol from a series is the only allowed
  difference, and it must be enabled).
- Build on the strongest machine and ship binaries; a fuzzing host need not
  have a kernel toolchain.
- Ship per kernel: `arch/x86/boot/bzImage`, `vmlinux` (symbolization), and
  `vmlinux.o` if the engine hashes per-function symbols (syz-diffrepro
  `-base_obj/-patched_obj`). Keep the source tree reachable for report
  symbolization or set `kernel_src` appropriately.
- syz-diffrepro + executor: `make syz-diffrepro` in the fork at the commit you
  record; never mix revs. Then **pin** them: copy `bin/` into the campaign's
  run record as `syzkaller_<shortsha>/` (read-only, `SHA256SUMS`, a README with
  provenance) and point every config's `"syzkaller"` there. A source tree's
  `bin/` gets rebuilt by other sessions. On each fuzzing host, copy the
  directory and run `sha256sum -c SHA256SUMS` before launching.
- Sanitizer variants (KASAN vs KCSAN vs KMSAN are mutually exclusive): if a
  picked series' risk is a data race, it needs a KCSAN build of its own; one
  KASAN build does not cover it. Record which picked series the chosen build
  cannot see.
- **Harness-required kernel options**: check the protocol harness's requirements
  against the built `.config`, not just the sanitizer and protocol options. The
  MPTCP wire-mutation layer needs `CONFIG_NFT_QUEUE` (or the xtables fallback
  with `NFT_COMPAT` + `NETFILTER_XT_TARGET_NFQUEUE`); without it every
  mutation op is a silent no-op. Verify with a smoke program that a mutation
  actually changes a counter (e.g. a JOIN HMAC failure MIB) before a long run.
