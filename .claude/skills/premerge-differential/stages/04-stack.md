# Stage 4: Stack (groups, ordering, conflicts)

1. **Split into run groups** when running on several machines: one base, one
   patched kernel per group. Group by what the fuzzer needs to reach the code
   (e.g. in-kernel-PM series need the PM-mode harness change; the rest do not),
   so each group can start as soon as its own prerequisites hold. Smaller
   groups = tighter function-level aiming and cleaner attribution.
   A second axis is the sanitizer: KASAN and KCSAN cannot share a kernel, so
   race-prone series (fixes and new lockless code) get their own KCSAN build
   with its own KCSAN base. A series may sit in more than one group.
2. **Order** within a group: fixes (`-net`) before features (`-next`), and
   declared dependencies first (cover letters say "depends on"). Series
   superseding parts of another: carry the newer, drop the overlapping patches
   of the older.
3. **Apply together** on a branch `<campaign>-<group>` from the base. Standalone
   apply (stage 2) does not predict combined conflicts: same-area fixes (e.g.
   two lifetime fixes on one list) collide.
   Two collisions to expect: **competing fixes for one bug** (two authors,
   different mechanisms) cannot stack, so split them across groups; and a
   renamed v-bump that intake missed (read the changelog of the colliding
   series). **Shared bit/enum numbers** (two series taking the same free flag
   bit) apply with a textual conflict; renumber one and record it.
4. **Conflicts with the keystone itself** happen: a series touching an
   annotated function conflicts with our kcov hunk. Resolve by keeping the
   series' logic and re-placing the annotation; note it in the record.
5. **Every hand rebase is reviewed by the user** before it goes into a kernel.
   Write the specific question a reviewer would ask (e.g. "callback now runs
   under spin_lock_bh — allowed?"), not "please review".
6. Record per group: series id, version, msgid, mbox sha256, apply order, and
   which patches were rebased (with the reviewed diff).

Gate: `git log <base>..<group>` matches the recorded list; `make` of the
protocol directory with W=1 is clean.
