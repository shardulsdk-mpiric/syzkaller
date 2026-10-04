// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package structops generates BPF struct_ops programs -- a table-driven,
// verifier-contract-aware C source generator for a kernel struct_ops
// surface (an MPTCP `mptcp_sched_ops` packet scheduler, a
// `tcp_congestion_ops` congestion-control module).  The rendered C is
// compiled (clang -target bpf, against the target kernel's vmlinux.h) by
// the caller; this package only generates and renders.
//
// Provenance.  This is a source import of `prog/brf_structops.go` from
// Mpiric's BRF fork (shardulsdk-mpiric/brf, branch
// protocol_flow_fuzzing_harness, HEAD ae620fde4; the struct_ops commits
// are 0ed20e082 fd35a192b c20b013a9 6ace5243a 17fd6a6ad).  BRF is
// Hsin-Wei Hung and Ardalan Amiri Sani's eBPF runtime fuzzer (UC Irvine,
// arXiv:2305.08782), itself a fork of syzkaller; the generator was
// written by Mpiric as an extension of BRF and is imported here as
// source, not history, because the fork's commits target BRF's 2024
// in-VM generate/compile architecture.  The generator logic, tables and
// rendered text are unchanged from the fork (the fork-side golden hash in
// structops_test.go pins this).  What changed on import:
//
//   - identifiers lost their `StructOps`/`structOps`/`Bpf` prefixes
//     (`StructOpsProg` -> `Prog`, `StructOpsStmt` -> `Stmt`,
//     `structOpsSurface` -> `Surface`, `BpfKfunc` -> `Kfunc`, ...);
//   - the fork's `*randGen` (syzkaller's prog-internal rand wrapper) is
//     replaced by the `Rand` interface below; `*math/rand.Rand` and
//     `prog.Gen.Rand()` both satisfy it, and `randGen.bin` is
//     reproduced bit-for-bit so draw sequences are identical;
//   - the fork's `BpfProg.StructOps` coupling, its gob-on-disk files, and
//     the live-fuzzer MPTCP-vs-CC rotation knob (`structOpsCCWeight` /
//     `pickStructOpsSurface`) are gone: in native syzkaller the surface is
//     chosen by the syzlang blob type the fuzzer picked
//     (`Target.SpecialTypes`, see sys/linux/init_structops.go).
//
// The original design notes follow.
//
// BRF Phase 3, Stage C-full -- generation and rendering of a fuzzed
// MPTCP `mptcp_sched_ops` BPF struct_ops packet scheduler.
//
// This file is deliberately self-contained: BRF's generic helper-call
// generator renders an attached program with a single
// `SEC(...) int func(ctx)` shape and a flat call list.  A struct_ops
// scheduler has a different shape -- two `void` callbacks, one `int`
// callback, and a `SEC(".struct_ops.link")` map instance -- so it gets
// its own model and its own renderer.
//
// Scope (Stage C-minimal): the `get_send` callback is a FIXED kfunc
// prologue/epilogue skeleton (fetch the first subflow ->
// `mptcp_subflow_set_scheduled`) wrapped around a BRF-generated body of
// context reads, context *writes*, and arithmetic.  The two writable
// fields are exactly those accepted by `bpf_mptcp_sched_btf_struct_access`
// in net/mptcp/bpf.c: `struct mptcp_sock.snd_burst` and
// `struct mptcp_subflow_context.avg_pacing_rate`.
//
// Re-pin (2026-10, kernel 7.3-rc / mptcp/export): the prologue originally
// derived the subflow as `bpf_mptcp_subflow_ctx(msk->first)`, and
// `msk->first` was a pool value usable as a kfunc argument.  The current
// verifier rejects that: a pointer loaded by walking a trusted ctx pointer
// is NOT trusted, and every `KF_ARG_PTR_TO_BTF_ID` kfunc argument must be
// ("R1 must be referenced or trusted", check_kfunc_args).  The prologue
// now fetches the first subflow through the open-coded subflow iterator
// (`bpf_iter_mptcp_subflow_new/next/destroy`, the idiom of the kernel's
// own tools/testing/selftests/bpf/progs/mptcp_bpf_first.c) -- an
// iterator-returned pointer is PTR_TRUSTED, and stays so after the
// iterator is destroyed (mptcp_bpf_burst.c schedules a subflow saved from
// a finished bpf_for_each).  The `struct sock *` pool value is the
// trusted cast `(struct sock *)msk` (what mptcp_bpf_burst.c passes to
// mptcp_set_timeout), never `msk->first`.  The kfunc table was refreshed
// to the kernel's current `bpf_mptcp_common_kfunc_ids`
// (bpf_mptcp_subflow_queues_empty is gone; bpf_sk_stream_memory_free now
// takes the subflow context).
//
// Scope (Stage C-full, Stage 1): the generated body additionally emits
// straight-line, contract-aware calls to six more common MPTCP kfuncs
// (`bpf_mptcp_common_kfunc_ids` in net/mptcp/bpf.c).  Each call is
// generated only when every argument type is satisfiable from the typed
// values in scope (`msk`, `msk->first`, `subflow`, and earlier
// kfunc/ctx-read locals); a KF_RET_NULL pointer result is bound to a
// local and immediately NULL-checked before any use; a scalar result is
// bound to a local usable in later arithmetic; a void kfunc is emitted
// for effect.  No generated branching beyond the mandatory KF_RET_NULL
// guards.
//
// Scope (Stage C-full, Stage 2a): two additions.  (1) The subflow
// iterator -- the three `bpf_iter_mptcp_subflow_*` kfuncs
// (`bpf_mptcp_iter_kfunc_ids` in net/mptcp/bpf.c) -- becomes one
// possible `get_send` body statement kind.  It is ALWAYS rendered as the
// complete, verifier-required `new -> next* -> destroy` triple (an
// atomic compound statement, never partial): an open-coded iterator
// declaration, a `while ((sfN = ..._next(&it)))` loop whose condition is
// the KF_RET_NULL NULL-check, and the mandatory `..._destroy(&it)`.  The
// loop body is a short generated read/write/arith/kfunc-call sequence
// over the loop variable `sfN`.  (2) `init`/`release` -- previously
// empty `{}` -- get a generated `msk`-reachable body (reads/writes/arith
// and `msk`-satisfiable kfunc calls; never `mptcp_subflow_set_scheduled`
// -- those callbacks do not schedule).
//
// Scope (Stage C-full, Stage 2b): generated free-form `if/else`.  An
// `if (<cond>) { <branch> } [else { <branch> }]` statement kind is added
// to the `get_send` body generator.  The condition is a simple boolean
// expression -- a comparison / bit-test against a fuzzer constant or the
// truthiness of an in-scope SCALAR local (never a pointer: prologue and
// kfunc-return pointers are already NULL-guarded, so a pointer condition
// is redundant or constant-true).  Each branch body is generated with the
// existing body machinery under a `bodyScope` with `noReturn` SET: with no
// `return` in any branch every path falls through to the fixed scheduling
// epilogue, so `get_send` always schedules >= 1 subflow -- no per-path
// scheduling analysis is needed.  A KF_RET_NULL-pointer kfunc (its guard
// emits a `return`) is therefore not offered inside a branch body, the
// same exclusion the iterator loop body applies.  Branch-local variables
// are block-scoped: each branch is its own generated statement slice with
// its own typed-value pool, so a local declared inside a branch is never
// referenced after the branch closes.  Nesting depth and total statement
// count are capped so generated programs stay within the verifier's
// instruction/complexity limits.
package structops

import (
	"bytes"
	"fmt"
)

// Rand is the source of randomness the generator draws from.  It is the
// subset of *math/rand.Rand the generator uses; prog.Gen.Rand() returns a
// *math/rand.Rand, so a SpecialTypes handler passes that straight through.
type Rand interface {
	Intn(n int) int
}

// randGen is the in-package rand wrapper.  It reproduces exactly the two
// methods the generator used on BRF's prog-internal `randGen` (`Intn`,
// `bin`), with `bin` defined identically (`Intn(2) == 0`), so the random
// draw sequence -- and hence the rendered text -- is byte-identical to
// the fork for the same seed.
type randGen struct {
	Rand
}

func (r *randGen) bin() bool {
	return r.Intn(2) == 0
}

// schedNameMax mirrors MPTCP_SCHED_NAME_MAX (include/net/mptcp.h); the
// rendered `.name` must fit.
const schedNameMax = 16

// Kfunc models a kernel kfunc callable from a struct_ops program.
// BRF models BPF *helpers* (BpfHelper); kfuncs are a distinct ABI --
// they are plain extern symbols resolved via `__ksym` rather than the
// numbered helper-id mechanism -- so they need their own tiny model.
//
// CDecl is the full `extern ... __ksym;` declaration text.  The
// remaining fields carry enough to *generate a correct call*: the
// return type, the argument types, and the verifier contract on the
// return value.
//
// Argument and return types are stored as plain C type strings (with
// any `const` qualifier kept verbatim from the kernel signature).
// Type matching in the call generator strips `const` -- a `struct
// sock *` value satisfies a `const struct sock *` parameter.
type Kfunc struct {
	Name  string
	CDecl string
	// RetType is the C type of the return value; "" means void.
	RetType string
	// ArgTypes are the C types of the parameters, in order.
	ArgTypes []string
	// IsPtrRet is true when the return value is a pointer.
	IsPtrRet bool
	// RetNull mirrors the kernel KF_RET_NULL flag.  The verifier
	// requires a NULL-check before use ONLY for a *pointer* return
	// (IsPtrRet && RetNull); KF_RET_NULL on a scalar-returning kfunc
	// just means the scalar may be 0 -- no guard is needed.
	RetNull bool
	// Release mirrors the kernel KF_RELEASE flag: the call releases the
	// reference its pointer argument holds.  The body generator has no
	// reference-lifecycle model (nothing tracks which pool pointer is still
	// live), so a Release kfunc is never generated-callable; a surface that
	// must release a referenced argument does it in a FIXED epilogue
	// (Qdisc_ops.enqueue: bpf_qdisc_skb_drop on the skb__ref ctx arg).
	Release bool
	// Terminal marks the kfunc a scope's terminal statement calls
	// (sched_ext's scx_bpf_dsq_insert: the liveness-by-construction insert
	// that ends every ops.enqueue path, see StmtDsqInsert).  It is never a
	// generated StmtKfuncCall draw -- a second insert of the same task is a
	// runtime error (scheduler ejection), not a bug -- and is emitted only
	// where bodyScope.terminal asks for it.
	Terminal bool
}

// needsNullGuard reports whether a kfunc's return value must be bound
// to a local and NULL-checked before any use.  This is precisely the
// verifier rule for a KF_RET_NULL *pointer* return.
func (kf *Kfunc) needsNullGuard() bool {
	return kf.IsPtrRet && kf.RetNull
}

// mptcpSchedKfuncs are the kfuncs the generated bodies may call: the
// kernel's CURRENT `bpf_mptcp_common_kfunc_ids` set (net/mptcp/bpf.c),
// in registration order.  Of these, `mptcp_subflow_set_scheduled` is the
// FIXED epilogue's kfunc (rendered by the surface, never generated); the
// other six are what the Stage C-full Stage 1 call generator draws on.
//
// The three `bpf_iter_mptcp_subflow_*` iterator kfuncs
// (`bpf_mptcp_iter_kfunc_ids`) are modelled separately
// (`mptcpSubflowIterKfuncs`) -- they are not callable individually by the
// kfunc-call generator; the renderer emits the verifier-required
// `new -> next* -> destroy` triple as one atomic unit (the fixed get_send
// prologue, and every generated StmtSubflowIter).
//
// No longer in the kernel's set (and so dropped here):
// `bpf_mptcp_subflow_queues_empty` (unresolvable kfunc -> load failure)
// and `mptcp_pm_subflow_chk_stale`.
//
// Signatures are transcribed verbatim from net/mptcp/bpf.c (the
// `__bpf_kfunc` definitions) and net/mptcp/protocol.h.  Every pointer
// parameter must receive a TRUSTED pointer (check_kfunc_args): the ctx
// `msk`, its cast `(struct sock *)msk`, the prologue / iterator `subflow`,
// or a kfunc-returned (hence implicitly trusted) pointer.
var mptcpSchedKfuncs = []Kfunc{
	{
		// __bpf_kfunc struct mptcp_subflow_context *
		// bpf_mptcp_subflow_ctx(const struct sock *sk)
		// Returns NULL unless sk is an MPTCP subflow's tcp_sock -- so
		// on `(struct sock *)msk` it yields NULL and the guard returns
		// -1 (a legal "nothing to schedule" path); on a
		// bpf_mptcp_subflow_tcp_sock result it round-trips to the
		// subflow context.
		Name: "bpf_mptcp_subflow_ctx",
		CDecl: "extern struct mptcp_subflow_context *\n" +
			"bpf_mptcp_subflow_ctx(const struct sock *sk) __ksym;",
		RetType:  "struct mptcp_subflow_context *",
		ArgTypes: []string{"const struct sock *"},
		IsPtrRet: true,
		RetNull:  true, // BTF_ID_FLAGS(..., KF_RET_NULL)
	},
	{
		// __bpf_kfunc struct sock *
		// bpf_mptcp_subflow_tcp_sock(const struct mptcp_subflow_context *subflow)
		Name: "bpf_mptcp_subflow_tcp_sock",
		CDecl: "extern struct sock *\n" +
			"bpf_mptcp_subflow_tcp_sock(const struct mptcp_subflow_context *subflow) __ksym;",
		RetType:  "struct sock *",
		ArgTypes: []string{"const struct mptcp_subflow_context *"},
		IsPtrRet: true,
		RetNull:  true, // BTF_ID_FLAGS(..., KF_RET_NULL)
	},
	{
		Name: "mptcp_subflow_set_scheduled",
		CDecl: "extern void\n" +
			"mptcp_subflow_set_scheduled(struct mptcp_subflow_context *subflow,\n" +
			"\t\t\t    bool scheduled) __ksym;",
		RetType:  "", // void
		ArgTypes: []string{"struct mptcp_subflow_context *", "bool"},
	},
	{
		// bool mptcp_subflow_active(struct mptcp_subflow_context *subflow);
		Name: "mptcp_subflow_active",
		CDecl: "extern bool\n" +
			"mptcp_subflow_active(struct mptcp_subflow_context *subflow) __ksym;",
		RetType:  "bool",
		ArgTypes: []string{"struct mptcp_subflow_context *"},
	},
	{
		// void mptcp_set_timeout(struct sock *sk);  -- sk is the MPTCP
		// socket itself (the kernel's bpf_burst passes (struct sock *)msk).
		Name: "mptcp_set_timeout",
		CDecl: "extern void\n" +
			"mptcp_set_timeout(struct sock *sk) __ksym;",
		RetType:  "", // void
		ArgTypes: []string{"struct sock *"},
	},
	{
		// u64 mptcp_wnd_end(const struct mptcp_sock *msk);
		Name: "mptcp_wnd_end",
		CDecl: "extern __u64\n" +
			"mptcp_wnd_end(const struct mptcp_sock *msk) __ksym;",
		RetType:  "__u64",
		ArgTypes: []string{"const struct mptcp_sock *"},
	},
	{
		// __bpf_kfunc bool
		// bpf_sk_stream_memory_free(const struct mptcp_subflow_context *subflow)
		// (takes the subflow context now, not `const struct sock *`; no
		// longer flagged KF_RET_NULL -- a scalar return never needed a
		// guard anyway).
		Name: "bpf_sk_stream_memory_free",
		CDecl: "extern bool\n" +
			"bpf_sk_stream_memory_free(const struct mptcp_subflow_context *subflow) __ksym;",
		RetType:  "bool",
		ArgTypes: []string{"const struct mptcp_subflow_context *"},
	},
}

// mptcpSubflowIterKfuncs are the three open-coded-iterator kfuncs from
// `bpf_mptcp_iter_kfunc_ids` in net/mptcp/bpf.c.  They are not callable
// individually by the kfunc-call generator: the BPF verifier enforces
// the lifecycle `new -> next* -> destroy` on EVERY path, so the renderer
// only ever emits all three together as the atomic iterator idiom (see
// renderSubflowIter).  Modelled here purely to carry the
// `extern ... __ksym;` decls and the verbatim signatures.
//
//   - bpf_iter_mptcp_subflow_new(struct bpf_iter_mptcp_subflow *it,
//     struct sock *sk)         -> int, KF_ITER_NEW
//   - bpf_iter_mptcp_subflow_next(struct bpf_iter_mptcp_subflow *it)
//     -> struct mptcp_subflow_context *, KF_ITER_NEXT | KF_RET_NULL
//   - bpf_iter_mptcp_subflow_destroy(struct bpf_iter_mptcp_subflow *it)
//     -> void, KF_ITER_DESTROY
//
// `struct bpf_iter_mptcp_subflow` is the opaque public iterator type
// (net/mptcp/bpf.c: `__u64 __opaque[2]`); it is BTF-exported and so
// resolved from vmlinux.h -- no local definition is emitted.
var mptcpSubflowIterKfuncs = []Kfunc{
	{
		Name: "bpf_iter_mptcp_subflow_new",
		CDecl: "extern int\n" +
			"bpf_iter_mptcp_subflow_new(struct bpf_iter_mptcp_subflow *it,\n" +
			"\t\t\t   struct sock *sk) __ksym;",
		RetType:  "int",
		ArgTypes: []string{"struct bpf_iter_mptcp_subflow *", "struct sock *"},
	},
	{
		Name: "bpf_iter_mptcp_subflow_next",
		CDecl: "extern struct mptcp_subflow_context *\n" +
			"bpf_iter_mptcp_subflow_next(struct bpf_iter_mptcp_subflow *it) __ksym;",
		RetType:  "struct mptcp_subflow_context *",
		ArgTypes: []string{"struct bpf_iter_mptcp_subflow *"},
		IsPtrRet: true,
		RetNull:  true, // KF_ITER_NEXT | KF_RET_NULL
	},
	{
		Name: "bpf_iter_mptcp_subflow_destroy",
		CDecl: "extern void\n" +
			"bpf_iter_mptcp_subflow_destroy(struct bpf_iter_mptcp_subflow *it) __ksym;",
		RetType:  "", // void
		ArgTypes: []string{"struct bpf_iter_mptcp_subflow *"},
	},
}

// CtxField models one writable context field reachable from a
// struct_ops scheduler callback.  Owner is the C struct type the field
// lives on; Accessor is the C lvalue used to reach it from the callback
// (relative to the fixed locals `msk` / `subflow`).  CType drives the
// generated value's range.
type CtxField struct {
	Owner    string // e.g. "struct mptcp_sock"
	Field    string // e.g. "snd_burst"
	Accessor string // e.g. "msk->snd_burst"
	CType    string // e.g. "int", "unsigned long"
}

// mptcpSchedWriteFields is the EXACT writable surface accepted by
// bpf_mptcp_sched_btf_struct_access (net/mptcp/bpf.c:44) -- a write to
// any other field is a verifier -EACCES.  This is the audit's headline
// transport-state write primitive.
var mptcpSchedWriteFields = []CtxField{
	{
		Owner:    "struct mptcp_sock",
		Field:    "snd_burst",
		Accessor: "msk->snd_burst",
		CType:    "int",
	},
	{
		Owner:    "struct mptcp_subflow_context",
		Field:    "avg_pacing_rate",
		Accessor: "subflow->avg_pacing_rate",
		CType:    "unsigned long",
	},
}

// tcpCongKfuncs are the kfuncs callable from a BPF tcp_congestion_ops
// module, registered in net/ipv4/bpf_tcp_ca.c
// (bpf_tcp_ca_check_kfunc_ids).  Signatures are verbatim from
// include/net/tcp.h.  None return a KF_RET_NULL pointer (all return a
// scalar or void), so no NULL-guard is ever needed.  The two
// tcp_slow_start / tcp_cong_avoid_ai helpers take `__u32` scalar args
// (acked / w), exercising the scalar-literal path added to pickKfuncArgs.
var tcpCongKfuncs = []Kfunc{
	{
		Name:     "tcp_reno_ssthresh",
		CDecl:    "extern __u32 tcp_reno_ssthresh(struct sock *sk) __ksym;",
		RetType:  "__u32",
		ArgTypes: []string{"struct sock *"},
	},
	{
		Name: "tcp_reno_cong_avoid",
		CDecl: "extern void tcp_reno_cong_avoid(struct sock *sk, __u32 ack, " +
			"__u32 acked) __ksym;",
		RetType:  "", // void
		ArgTypes: []string{"struct sock *", "__u32", "__u32"},
	},
	{
		Name:     "tcp_reno_undo_cwnd",
		CDecl:    "extern __u32 tcp_reno_undo_cwnd(struct sock *sk) __ksym;",
		RetType:  "__u32",
		ArgTypes: []string{"struct sock *"},
	},
	{
		Name: "tcp_slow_start",
		CDecl: "extern __u32 tcp_slow_start(struct tcp_sock *tp, __u32 acked) " +
			"__ksym;",
		RetType:  "__u32",
		ArgTypes: []string{"struct tcp_sock *", "__u32"},
	},
	{
		Name: "tcp_cong_avoid_ai",
		CDecl: "extern void tcp_cong_avoid_ai(struct tcp_sock *tp, __u32 w, " +
			"__u32 acked) __ksym;",
		RetType:  "", // void
		ArgTypes: []string{"struct tcp_sock *", "__u32", "__u32"},
	},
}

// tcpCongWriteFields is the writable ctx surface for a BPF
// tcp_congestion_ops module: the struct tcp_sock fields accepted by
// bpf_tcp_ca_btf_struct_access (net/ipv4/bpf_tcp_ca.c).  All are reached
// from a callback via the `tp` local (`struct tcp_sock *tp =
// tcp_sk(sk);`).  Modelled as "unsigned int" so genCtxValue's
// default (non-negative) branch sizes the generated values.
var tcpCongWriteFields = []CtxField{
	{
		Owner:    "struct tcp_sock",
		Field:    "snd_cwnd",
		Accessor: "tp->snd_cwnd",
		CType:    "unsigned int",
	},
	{
		Owner:    "struct tcp_sock",
		Field:    "snd_ssthresh",
		Accessor: "tp->snd_ssthresh",
		CType:    "unsigned int",
	},
	{
		Owner:    "struct tcp_sock",
		Field:    "snd_cwnd_cnt",
		Accessor: "tp->snd_cwnd_cnt",
		CType:    "unsigned int",
	},
}

// StmtKind tags the kind of a generated body statement.
type StmtKind int

const (
	// StmtCtxRead -- read a writable ctx field into a local.
	StmtCtxRead StmtKind = iota
	// StmtCtxWrite -- write a fuzzer-chosen value to a
	// writable ctx field (the headline write primitive).
	StmtCtxWrite
	// StmtArith -- derive a fresh local from arithmetic over
	// an earlier local and a fuzzer-chosen constant.
	StmtArith
	// StmtKfuncCall -- call a modelled MPTCP kfunc with
	// typed, in-scope arguments.  A pointer return that is
	// KF_RET_NULL is bound to a local and IMMEDIATELY followed by a
	// `if (!local) return -1;` guard (`return;` in a void callback;
	// rendered as part of this same statement); a scalar return is
	// bound to a local; a void kfunc is emitted for effect.
	StmtKfuncCall
	// StmtSubflowIter -- the open-coded subflow iterator.
	// Rendered as ONE atomic compound statement: the iterator
	// declaration, `bpf_iter_mptcp_subflow_new`, a
	// `while ((sfN = bpf_iter_mptcp_subflow_next(&it)))` loop with a
	// short generated body over `sfN`, and the mandatory
	// `bpf_iter_mptcp_subflow_destroy`.  The verifier enforces the
	// `new -> next* -> destroy` lifecycle on every path, so the three
	// kfuncs are never emitted apart.
	StmtSubflowIter
	// StmtIfElse -- a generated free-form `if/else` (Stage
	// 2b).  Rendered as `if (<cond>) { <IfBody> }` optionally followed
	// by `else { <ElseBody> }`.  The condition is a simple boolean
	// expression over an in-scope scalar local (Cond* fields); both
	// branch bodies are generated with the existing body machinery
	// under a `noReturn` scope, so no branch emits a `return` and every
	// path falls through to the fixed scheduling epilogue.
	StmtIfElse
	// StmtDsqInsert -- a scope's TERMINAL statement: the one dispatch-queue
	// insert that ends every path of a sched_ext ops.enqueue body
	// (`scx_bpf_dsq_insert(p, <dsq_id>, <slice>, <enq_flags>);`).  It is
	// generated (dsq id, slice and flags are fuzzer draws, so the insert
	// itself is a mutation dimension) but its PLACE is fixed: genBody
	// appends exactly one as the last statement of a scope whose
	// bodyScope.terminal is set, after the drawn statements, and the
	// branch / loop scopes inside that body never carry one.  With the
	// body under noReturn this gives "every path ends in exactly one
	// insert" by construction -- the liveness scaffold of the sched_ext
	// surface design.  Rendered as a void kfunc call; KfuncIdx / KfuncArgs
	// carry the call exactly as a StmtKfuncCall does.
	StmtDsqInsert
)

// Stmt is one statement of the BRF-generated get_send body.
// All fields are exported so a Prog gob-serializes cleanly
// alongside the rest of BpfProg.
type Stmt struct {
	Kind StmtKind
	// Field index into the program's WriteFields slice -- valid for
	// CtxRead and CtxWrite generated against the fixed get_send
	// surface.  Retained for introspection; the renderer uses
	// FieldAccessor / FieldCType (which are context-correct even
	// inside an iterator loop body, where the subflow base local is
	// `sfN`, not the fixed `subflow`).
	FieldIdx int
	// FieldAccessor is the fully-resolved C lvalue of a CtxRead /
	// CtxWrite (e.g. "msk->snd_burst", "sf3->avg_pacing_rate").
	FieldAccessor string
	// FieldCType is the C type of FieldAccessor.
	FieldCType string
	// Var is the local declared by CtxRead / Arith / KfuncCall
	// (e.g. "s0").  Empty for a void KfuncCall.
	Var string
	// CType is the C type of Var.
	CType string
	// Val is the fuzzer-chosen constant -- valid for CtxWrite and
	// Arith.  For an Arith shift (Op "<<"/">>") it is the shift amount,
	// always in [0,30] so the shift stays within the operand's width.
	// Unused when SrcVar2 is set (a two-local Arith).
	Val int64
	// SrcVar is the (left) operand local for Arith.
	SrcVar string
	// SrcVar2 is the optional RIGHT operand local for a two-local Arith
	// (`Var = SrcVar Op SrcVar2`).  Empty for the constant-RHS form
	// (`Var = SrcVar Op Val`).  Never set for a shift Op (the shift
	// amount is always the bounded constant Val).  When set, it names an
	// in-scope scalar local, so the result stays a typed scalar.
	SrcVar2 string
	// Op is the Arith operator: an arithmetic/bitwise op ("+", "-", "*",
	// "^", "|", "&") or a shift ("<<", ">>").
	Op string
	// KfuncIdx indexes the program's Kfuncs slice -- valid for
	// KfuncCall.
	KfuncIdx int
	// KfuncArgs are the C expressions passed as arguments to the
	// kfunc -- valid for KfuncCall.  Each is a typed, in-scope value
	// (`msk`, `(struct sock *)msk`, `subflow`, or an earlier local).
	KfuncArgs []string
	// NullGuard is true when this KfuncCall's pointer result is
	// KF_RET_NULL and the renderer must emit the mandatory
	// `if (!Var) return -1;` guard immediately after the call (`return;`
	// in a void callback -- the renderer picks the form from the enclosing
	// callback's return type).
	NullGuard bool
	// IterId is a per-statement unique id for a SubflowIter -- it
	// names the iterator local (`itN`) and the loop variable
	// (`sfN`), keeping nested/repeated iterators non-colliding.
	IterId int
	// IterSockExpr is the `struct sock *` expression passed to
	// `bpf_iter_mptcp_subflow_new` -- the MPTCP socket, `(struct
	// sock *)msk`.  Valid for SubflowIter.
	IterSockExpr string
	// IterBody is the (possibly empty) short generated loop body of a
	// SubflowIter, executed with the loop variable `sfN` in scope as
	// a valid `struct mptcp_subflow_context *`.  Reuses the same
	// Stmt kinds as the top-level body.
	IterBody []Stmt
	// CondVar is the in-scope scalar local the condition tests --
	// valid for IfElse.  Always a scalar (`int` / `unsigned long` /
	// `bool` / `__u64`); never a pointer (see StmtIfElse).
	CondVar string
	// CondOp is the condition operator for IfElse: one of ">", "<",
	// "==", "!=", "&", or "" (the empty string meaning a bare
	// truthiness test `if (CondVar)`).
	CondOp string
	// CondVal is the fuzzer-chosen constant the condition compares /
	// bit-tests against -- valid for IfElse when CondOp != "".
	CondVal int64
	// CondJoin optionally makes the IfElse condition a COMPOUND boolean
	// of two clauses: "" (single clause), "&&", or "||".  When non-empty
	// the rendered condition is `(<clause1>) <CondJoin> (<clause2>)`,
	// where clause2 is `Cond2Var Cond2Op Cond2Val`.  Both clauses test
	// only in-scope scalar locals, so the compound predicate adds
	// control-flow diversity without any new value or type.
	CondJoin string
	// Cond2Var / Cond2Op / Cond2Val are the second condition clause --
	// valid for IfElse when CondJoin != "".  Cond2Op is always a real
	// comparison / bit-test (never the bare-truthiness empty string), so
	// the compound predicate is well-formed.
	Cond2Var string
	Cond2Op  string
	Cond2Val int64
	// IfBody is the generated body of the `if` branch -- valid for
	// IfElse.  Always non-empty.  Generated under a `noReturn` scope,
	// so it emits no `return`.
	IfBody []Stmt
	// ElseBody is the generated body of the optional `else` branch --
	// valid for IfElse.  When nil/empty the renderer emits no `else`.
	// Generated under the same `noReturn` scope as IfBody.
	ElseBody []Stmt
}

// Callback is one generated callback of a struct_ops program:
// its op suffix (e.g. "_get_send"), its return type, any arguments after
// the fixed ctx arg, the FIXED prologue/epilogue text the renderer wraps
// around the generated middle, and the generated Body itself.  All fields
// are exported so a Prog gob-serializes cleanly.
//
// This is the general, surface-agnostic replacement for the three named
// MPTCP body fields (GetSendBody / InitBody / ReleaseBody): a surface
// declares one Callback per op it renders, and the renderer
// walks them uniformly.
type Callback struct {
	// Suffix is the op name suffix appended to the instance name to form
	// the C function name (e.g. "_get_send" -> "brf_ab12_get_send").
	Suffix string
	// RetType is the callback's C return type ("void", "int", "__u32").
	RetType string
	// ArgsAfterCtx are the C parameter declarations after the fixed ctx
	// arg, in order (e.g. for cong_avoid: ["__u32 ack", "__u32 acked"]).
	// The fixed ctx arg itself is supplied by the surface.
	ArgsAfterCtx []string
	// Prologue is FIXED C text emitted verbatim (already tab-indented)
	// at the top of the callback body, before the generated Body.  Empty
	// for a callback with no fixed skeleton.
	Prologue string
	// Epilogue is FIXED C text emitted verbatim (already tab-indented)
	// after the generated Body -- e.g. a scheduling call + `return 0;`,
	// or a `return tp->snd_cwnd;`.  Empty for a void callback that needs
	// no fixed tail.
	Epilogue string
	// Body is the BRF-generated middle of this callback.
	Body []Stmt
}

// Prog is the per-program model of a generated struct_ops
// program (an MPTCP scheduler by default; a tcp_congestion_ops module
// under the CC surface).  It hangs off BpfProg.StructOps and is what
// Render renders.
//
// Surface tags which struct_ops surface generated this program (e.g.
// "mptcp_sched" / "tcp_cong"); it drives the per-struct rendering knobs
// the renderer cannot infer from the callbacks alone (the instance struct
// type, the link section, the ctx arg, the kfunc-externs comment, the
// fixed prologue-kfunc names).  Callbacks carries the general,
// gob-stable per-callback representation that replaced the three named
// MPTCP body fields.
type Prog struct {
	Surface     string
	SchedName   string
	WriteFields []CtxField
	Kfuncs      []Kfunc
	IterKfuncs  []Kfunc
	Callbacks   []Callback
	// PrologueKfuncs names the kfuncs the renderer emits itself as part
	// of a fixed prologue/epilogue (e.g. MPTCP's bpf_mptcp_subflow_ctx /
	// mptcp_subflow_set_scheduled).  They are excluded from the generated
	// kfunc-call set and force-included in the rendered externs.
	PrologueKfuncs []string
	// Instance are the generated instance-data values (one per
	// Surface.instanceFields entry, same order); nil for a surface that
	// sets none.
	Instance []InstanceVal
}

// isPrologueKfunc reports whether name is one of the kfuncs the renderer
// emits itself (so the body generator must not also emit a call to it).
func (sop *Prog) isPrologueKfunc(name string) bool {
	for _, n := range sop.PrologueKfuncs {
		if n == name {
			return true
		}
	}
	return false
}

// body returns the generated body of the callback whose op suffix matches
// (e.g. sop.body("_get_send")), or nil if no such callback exists.  Tests
// use it to fetch a callback's body by suffix without depending on slice
// order.
func (sop *Prog) body(suffix string) []Stmt {
	for i := range sop.Callbacks {
		if sop.Callbacks[i].Suffix == suffix {
			return sop.Callbacks[i].Body
		}
	}
	return nil
}

// allBodies returns every callback's generated body, for the walkStmts
// callers (usesSubflowIter / usedKfuncIdxs) that must range the whole
// statement tree regardless of surface.
func (sop *Prog) allBodies() [][]Stmt {
	out := make([][]Stmt, len(sop.Callbacks))
	for i := range sop.Callbacks {
		out[i] = sop.Callbacks[i].Body
	}
	return out
}

// arithOps -- the arithmetic/bitwise operators genBody
// may pick for an Arith statement.  No division/modulo: a generated `/0`
// would be a compile-time-constant UB the verifier rejects, which is
// noise rather than signal here.
var arithOps = []string{"+", "-", "*", "^", "|", "&"}

// shiftOps -- the shift operators an Arith statement may pick.
// A shift's right operand is ALWAYS the bounded constant Val (0..30, see
// genBody), never a local: a shift by a value >= the operand
// width is C UB and a verifier reject, so the amount is kept in range by
// construction rather than left to a runtime local.
var shiftOps = []string{"<<", ">>"}

// condJoins -- the boolean connectives genIfElse may use to
// build a COMPOUND two-clause condition.  Short-circuit `&&` / `||` over
// two in-scope scalar clauses; precedence is fine (both bind looser than
// the per-clause comparison), and the renderer parenthesises each clause
// regardless.
var condJoins = []string{"&&", "||"}

// genCtxValue picks a fuzzer value sized to a writable field's
// C type.  `int` (snd_burst) gets a signed 32-bit draw -- negative
// values are interesting transport state -- and so does `ktime_t`
// (skb->tstamp, an s64 departure time); `__u32` gets the full 32-bit
// range, top bit included (a qdisc's limit / q.qlen / qstats counters
// near UINT_MAX are the wrap cases); `__u64` a wide draw (the
// qdisc_skb_cb words); `unsigned long` (avg_pacing_rate) and anything
// else a non-negative 31-bit draw.
func genCtxValue(r *randGen, ctype string) int64 {
	switch ctype {
	case "int", "ktime_t":
		return int64(r.Intn(1<<32)) - (1 << 31)
	case "__u32", "u32":
		return int64(r.Intn(1 << 32))
	case "__u64", "u64":
		return int64(r.Intn(1 << 62))
	default: // "unsigned long" and any future unsigned field
		return int64(r.Intn(1 << 31))
	}
}

// normalizeCType strips a leading `const ` qualifier so a value's type
// can be matched against a kfunc parameter type regardless of
// const-ness.  `const struct sock *` and `struct sock *` denote the
// same value for call-argument purposes.
func normalizeCType(t string) string {
	for {
		if len(t) > 6 && t[:6] == "const " {
			t = t[6:]
			continue
		}
		break
	}
	return t
}

// typedVal is one value in scope inside the generated get_send body: a
// C expression and its (normalized) C type.  The pool starts with the
// three fixed values -- `msk`, `(struct sock *)msk`, `subflow` -- and
// grows with every ctx-read local, arithmetic local, and (Stage 1) typed
// kfunc-call result local.  Every pointer in the pool is TRUSTED in the
// verifier's sense (ctx, a cast of ctx, an iterator element, or a kfunc
// result), which is what lets any of them be a kfunc argument; a pointer
// loaded by walking a struct (e.g. `msk->first`) is not, and is never
// pooled.
type typedVal struct {
	expr  string // C expression, e.g. "msk", "(struct sock *)msk", "s3"
	ctype string // normalized C type, e.g. "struct sock *"
}

// mskSockExpr is the `struct sock *` view of the MPTCP socket -- the
// trusted cast of the ctx pointer, as the kernel's own bpf_burst
// scheduler passes it to mptcp_set_timeout / bpf_for_each.
const mskSockExpr = "(struct sock *)msk"

// scalarCType reports whether a C type is a usable arithmetic scalar
// (an integer-like value an Arith statement may operate on).  Pointer
// types are excluded.
func scalarCType(t string) bool {
	switch normalizeCType(t) {
	case "int", "unsigned long", "bool", "__u64", "u64", "long",
		"unsigned int", "__u32", "u32", "ktime_t":
		return true
	default:
		return false
	}
}

// pickKfuncArgs tries to satisfy every parameter type of kf from the
// typed-value pool.  It returns the chosen argument expressions and
// true on success; if any parameter type has no matching in-scope
// value it returns false and the kfunc is not called.  The verifier
// contract "pass only typed, in-scope values" is enforced here: an
// argument is only ever a pool entry whose normalized type equals the
// parameter's normalized type.
func pickKfuncArgs(r *randGen, kf *Kfunc, pool []typedVal) ([]string, bool) {
	args := make([]string, 0, len(kf.ArgTypes))
	for _, pt := range kf.ArgTypes {
		want := normalizeCType(pt)
		var cands []string
		for _, v := range pool {
			if v.ctype == want {
				cands = append(cands, v.expr)
			}
		}
		if want == "bool" {
			// `bool` is also satisfiable by a fuzzer-chosen literal
			// -- mptcp_subflow_set_scheduled's `scheduled` arg is the
			// only bool parameter, and the fixed epilogue always
			// passes `true`; for any generated bool arg, offer both
			// literals as candidates so a call is never blocked.
			cands = append(cands, "true", "false")
		} else if integerCType(want) {
			// A scalar-integer parameter (e.g. the tcp_congestion_ops
			// kfuncs' `__u32 ack` / `acked` / `w`) is satisfiable by an
			// in-scope scalar local (already added above when its type
			// matches exactly) OR by a fuzzer-chosen literal -- offer a
			// small literal candidate so a CC kfunc call is never
			// blocked for want of a same-typed scalar local.
			//
			// MPTCP-output safety: no MPTCP kfunc has an integer-scalar
			// parameter (their args are pointers + the one bool above),
			// so this branch is never taken for an MPTCP draw -- the
			// MPTCP random-draw sequence is unchanged.  Confirmed by the
			// golden hash.
			cands = append(cands, fmt.Sprintf("%d", r.Intn(1<<16)))
		}
		if len(cands) == 0 {
			return nil, false
		}
		args = append(args, cands[r.Intn(len(cands))])
	}
	return args, true
}

// integerCType reports whether a (normalized) C type is a scalar integer
// a kfunc may receive as a fuzzer literal.  Deliberately excludes "bool"
// (handled separately, with its own true/false literals) so the literal
// offered is type-appropriate.
func integerCType(t string) bool {
	switch t {
	case "__u32", "u32", "unsigned int", "int", "unsigned long", "long",
		"__u64", "u64":
		return true
	default:
		return false
	}
}

// ctxWriteField is one writable ctx field available to a body, with the
// accessor already resolved for the body's surface -- e.g. the top-level
// get_send body sees `subflow->avg_pacing_rate`, but an iterator loop
// body sees `sfN->avg_pacing_rate` (same field, different base local).
type ctxWriteField struct {
	accessor string // resolved C lvalue
	ctype    string // C type
}

// bodyScope parameterises genBody for the three surfaces it
// renders: the top-level get_send body, an iterator loop body, and the
// init/release bodies.  It carries the seed typed-value pool, the
// writable fields resolved for this surface, and whether the subflow
// iterator is an allowed statement kind here.
type bodyScope struct {
	// pool is the set of typed values in scope at body entry.
	pool []typedVal
	// writeFields are the ctx fields writable/readable from this body.
	writeFields []ctxWriteField
	// allowIter permits StmtSubflowIter as a statement kind.
	// True only for the top-level get_send body -- iterator loop
	// bodies do not nest an iterator, and init/release do not iterate.
	allowIter bool
	// requireWrite biases the last statement toward a ctx write so the
	// headline write primitive is reliably exercised.  True for
	// get_send; false for the (short) iterator loop body and for
	// init/release, where a guaranteed write is not wanted.
	requireWrite bool
	// noReturn forbids any statement that emits a `return` -- i.e. a
	// KF_RET_NULL-pointer kfunc call (whose mandatory guard is
	// `if (!v) return -1;`).  Set TRUE for an iterator loop body: this
	// explicit iterator idiom has no `__attribute__((cleanup))`, so a
	// `return` from inside the `while` loop would skip
	// `bpf_iter_mptcp_subflow_destroy` and the verifier would reject
	// the program for an unreleased iterator.  Set TRUE for an
	// `if`/`else` branch body too (Stage 2b): a `return` inside a
	// branch would make `get_send` skip the fixed scheduling epilogue
	// on that path, so no branch may return -- every path then falls
	// through to the epilogue and always schedules.  A KF_RET_NULL-
	// pointer kfunc is simply not offered when noReturn is set; a
	// non-guarded scalar/void kfunc still is.  noReturn is about the
	// PATH, not the return type: a void callback with no fixed epilogue
	// may leave it clear and its guards render as `return;`
	// (guardReturn).
	noReturn bool
	// allowIf permits StmtIfElse as a statement kind (Stage
	// 2b).  True for the top-level get_send body and -- subject to the
	// depth cap -- for an `if`/`else` branch body, so generated
	// branching may nest.  False for init/release and for an iterator
	// loop body, which are kept straight-line.
	allowIf bool
	// depth is the current `if`/`else` nesting depth (0 at a callback's
	// top level).  ifElseMaxDepth caps it -- a branch body deeper than
	// the cap is generated with allowIf cleared, so generated programs
	// stay within the verifier's instruction/complexity limits.
	depth int
	// minStmt / maxStmt bound the generated statement count.
	minStmt, maxStmt int
	// kfuncAllow, when non-nil, restricts the kfuncs this body may call to
	// the named subset of the surface's kfunc table -- the generator-side
	// image of a kernel per-op kfunc filter (Qdisc_ops'
	// bpf_qdisc_kfunc_filter keys the allowed set on the callback: the
	// watchdog from enqueue / dequeue only, bstats_update from dequeue
	// only; a call outside the op's set is a verifier -EACCES).  nil, the
	// two older surfaces, means the whole table is callable.
	kfuncAllow []string
	// terminal, when set, makes genBody end this scope's body with exactly
	// one StmtDsqInsert drawn from it (after the nStmt drawn statements).
	// Only a callback's top-level scope sets it; the branch and iterator
	// scopes genBody opens inside never inherit it, so the body has one
	// terminal insert on every path.  Pair it with noReturn so no drawn
	// statement can leave before the insert.  nil on every scope of the
	// older surfaces.
	terminal *terminalInsert
}

// terminalInsert is what a scope's terminal StmtDsqInsert is drawn from:
// the insert kfunc (which must be in the surface table and marked
// Kfunc.Terminal), the task expression it inserts, and the candidate
// expressions for its three fuzzed arguments.  All candidates are C
// expressions the rendered program can name (vmlinux.h enum constants,
// literals); the generator picks, it does not interpret.
type terminalInsert struct {
	kfunc string // e.g. "scx_bpf_dsq_insert"
	task  string // the task_struct expression, e.g. "p"
	// dsqIDs are the candidate dsq_id expressions; one is drawn.  A Phase-2
	// surface lists the drained builtins (SCX_DSQ_GLOBAL, SCX_DSQ_LOCAL,
	// SCX_DSQ_LOCAL_ON | cpu); a user DSQ joins only when the surface's
	// dispatch drains it.
	dsqIDs []string
	// slices are the candidate slice expressions; one is drawn (e.g. "0",
	// "SCX_SLICE_DFL", "SCX_SLICE_INF", a literal).
	slices []string
	// enqFlags are the candidate flag bits; an independent coin per bit
	// picks the OR'ed subset, "0" when none.
	enqFlags []string
}

// ifElseMaxDepth caps generated `if`/`else` nesting (Stage 2b).  A
// branch body at this depth is generated with `if`/`else` no longer an
// offered statement kind, so the deepest branch is straight-line.  Kept
// small (2) so a generated `get_send` body stays well within the BPF
// verifier's instruction- and branch-complexity limits.
const ifElseMaxDepth = 2

// kfuncAllowed reports whether this scope may call the named kfunc: always
// when no allow-list is set, else only when the name is on it.
func (sc *bodyScope) kfuncAllowed(name string) bool {
	if sc.kfuncAllow == nil {
		return true
	}
	for _, n := range sc.kfuncAllow {
		if n == name {
			return true
		}
	}
	return false
}

// genBody generates a BRF struct_ops body: a short,
// randomly-ordered sequence of ctx reads, ctx writes (the write
// primitive), arithmetic over the read locals, Stage-1 straight-line
// contract-aware kfunc calls, and -- when sc.allowIter -- the Stage-2a
// subflow iterator.  Fixed prologue/epilogue text is added by the
// renderer, not here -- this is purely the generated middle.
//
// The generator threads a pool of TYPED values seeded from sc.pool and
// grown with every typed local it produces.  A kfunc call is generated
// only when every argument type is satisfiable from the pool; a
// KF_RET_NULL pointer result is bound to a local and IMMEDIATELY
// guarded, and only then enters the pool.  varId is a shared counter so
// every local across the whole callback (including nested iterator loop
// bodies) is uniquely named.
func genBody(r *randGen, sop *Prog, sc bodyScope, varId *int) []Stmt {
	var body []Stmt
	// readVars tracks (local name, C type) of scalar locals available
	// as arithmetic operands.
	type readVar struct {
		name  string
		ctype string
	}
	var readVars []readVar

	// pool is the set of typed values in scope -- seeded from the
	// scope and grown locally.  Copied so the caller's slice is not
	// aliased.
	pool := append([]typedVal(nil), sc.pool...)

	// callableKfuncs returns the indices of kfuncs whose every
	// argument type is satisfiable from the current pool.  The
	// surface's fixed-skeleton kfuncs (MPTCP:
	// mptcp_subflow_set_scheduled) are excluded from generation -- the
	// renderer emits those itself as the fixed prologue/epilogue.
	// When sc.noReturn is set, a KF_RET_NULL-pointer kfunc is excluded
	// too: its mandatory guard emits a `return`, which is unsafe
	// inside an iterator loop body (see bodyScope.noReturn).
	callableKfuncs := func() []int {
		var idxs []int
		for ki := range sop.Kfuncs {
			kf := &sop.Kfuncs[ki]
			if sop.isPrologueKfunc(kf.Name) {
				continue
			}
			if sc.noReturn && kf.needsNullGuard() {
				continue
			}
			if kf.Release || kf.Terminal || !sc.kfuncAllowed(kf.Name) {
				// No reference-lifecycle model (Kfunc.Release), a
				// terminal-only kfunc (Kfunc.Terminal), or outside this
				// callback's kernel-permitted set.  All decided before
				// any random draw, so a surface without any of them
				// leaves the draw sequence untouched.
				continue
			}
			if _, ok := pickKfuncArgs(r, kf, pool); ok {
				idxs = append(idxs, ki)
			}
		}
		return idxs
	}

	// emitCtxRead appends a ctx read of writeFields[fi], registering
	// the new local in readVars and the pool.  Factored out because
	// it is also the fallback when a chosen kind is not satisfiable.
	emitCtxRead := func(fi int) {
		f := sc.writeFields[fi]
		v := fmt.Sprintf("s%d", *varId)
		*varId++
		body = append(body, Stmt{
			Kind:          StmtCtxRead,
			FieldIdx:      fi,
			FieldAccessor: f.accessor,
			FieldCType:    f.ctype,
			Var:           v,
			CType:         f.ctype,
		})
		readVars = append(readVars, readVar{v, f.ctype})
		pool = append(pool, typedVal{expr: v, ctype: normalizeCType(f.ctype)})
	}

	// kinds is the set of statement kinds the generator may draw from
	// for this scope.  The four straight-line kinds are always in;
	// the iterator is added only when sc.allowIter; the `if`/`else`
	// statement (Stage 2b) only when sc.allowIf and the nesting cap is
	// not yet reached.
	kinds := []StmtKind{
		StmtCtxRead, StmtCtxWrite,
		StmtArith, StmtKfuncCall,
	}
	if sc.allowIter {
		kinds = append(kinds, StmtSubflowIter)
	}
	if sc.allowIf && sc.depth < ifElseMaxDepth {
		kinds = append(kinds, StmtIfElse)
	}

	span := sc.maxStmt - sc.minStmt + 1
	if span < 1 {
		span = 1
	}
	nStmt := sc.minStmt + r.Intn(span)
	for i := 0; i < nStmt; i++ {
		// Pick freely among the statement kinds available to this scope.
		kind := kinds[r.Intn(len(kinds))]
		if sc.requireWrite && i == nStmt-1 {
			// Bias the last statement toward a write so the headline
			// primitive is reliably exercised.
			haveWrite := false
			for _, st := range body {
				if st.Kind == StmtCtxWrite {
					haveWrite = true
				}
			}
			if !haveWrite {
				kind = StmtCtxWrite
			}
		}
		if kind == StmtArith && len(readVars) == 0 {
			// No operand yet -- fall back to a read.
			kind = StmtCtxRead
		}
		if kind == StmtKfuncCall && len(callableKfuncs()) == 0 {
			// No kfunc satisfiable from the pool -- fall back to a
			// read (always satisfiable).
			kind = StmtCtxRead
		}
		if kind == StmtIfElse && len(readVars) == 0 {
			// The condition tests an in-scope scalar local; none yet --
			// fall back to a read, which produces one.
			kind = StmtCtxRead
		}

		switch kind {
		case StmtCtxRead:
			emitCtxRead(r.Intn(len(sc.writeFields)))
		case StmtCtxWrite:
			fi := r.Intn(len(sc.writeFields))
			f := sc.writeFields[fi]
			body = append(body, Stmt{
				Kind:          StmtCtxWrite,
				FieldIdx:      fi,
				FieldAccessor: f.accessor,
				FieldCType:    f.ctype,
				Val:           genCtxValue(r, f.ctype),
			})
		case StmtArith:
			src := readVars[r.Intn(len(readVars))]
			v := fmt.Sprintf("s%d", *varId)
			*varId++
			st := Stmt{
				Kind:   StmtArith,
				Var:    v,
				CType:  src.ctype,
				SrcVar: src.name,
			}
			switch {
			case r.Intn(4) == 0:
				// Shift: bounded amount keeps the result within the
				// operand width (>= width would be UB / a verifier
				// reject), so the RHS is always the constant, never a
				// local.
				st.Op = shiftOps[r.Intn(len(shiftOps))]
				st.Val = int64(r.Intn(31)) // 0..30
			default:
				st.Op = arithOps[r.Intn(len(arithOps))]
				// Prefer a second in-scope scalar local as the RHS so the
				// generated data flow is local-to-local, not just
				// local-to-constant; fall back to a constant when no other
				// scalar local is in scope.
				var cands []string
				for _, rv := range readVars {
					if rv.name != src.name && scalarCType(rv.ctype) {
						cands = append(cands, rv.name)
					}
				}
				if len(cands) > 0 && r.bin() {
					st.SrcVar2 = cands[r.Intn(len(cands))]
				} else {
					st.Val = int64(r.Intn(1 << 16))
				}
			}
			body = append(body, st)
			readVars = append(readVars, readVar{v, src.ctype})
			pool = append(pool, typedVal{expr: v, ctype: normalizeCType(src.ctype)})
		case StmtKfuncCall:
			idxs := callableKfuncs()
			ki := idxs[r.Intn(len(idxs))]
			kf := &sop.Kfuncs[ki]
			// pickKfuncArgs already succeeded inside callableKfuncs;
			// re-roll a fresh argument choice for this call.
			args, ok := pickKfuncArgs(r, kf, pool)
			if !ok {
				// Defensive -- pool only grows, so this cannot
				// happen; fall back to a read rather than emit a
				// malformed call.
				emitCtxRead(r.Intn(len(sc.writeFields)))
				continue
			}
			st := Stmt{
				Kind:      StmtKfuncCall,
				KfuncIdx:  ki,
				KfuncArgs: args,
			}
			switch {
			case kf.RetType == "":
				// void -- call for effect, no local, no pool entry.
			case kf.needsNullGuard():
				// KF_RET_NULL pointer -- bind, guard, then publish.
				v := fmt.Sprintf("s%d", *varId)
				*varId++
				st.Var = v
				st.CType = kf.RetType
				st.NullGuard = true
				// The local enters the pool only AFTER the guard --
				// which the renderer emits immediately after the
				// call, so any later statement sees a guarded value.
				pool = append(pool, typedVal{
					expr: v, ctype: normalizeCType(kf.RetType),
				})
			default:
				// Scalar (or non-RET_NULL pointer) -- bind to a
				// local usable later.
				v := fmt.Sprintf("s%d", *varId)
				*varId++
				st.Var = v
				st.CType = kf.RetType
				if scalarCType(kf.RetType) {
					readVars = append(readVars, readVar{v, kf.RetType})
				}
				pool = append(pool, typedVal{
					expr: v, ctype: normalizeCType(kf.RetType),
				})
			}
			body = append(body, st)
		case StmtSubflowIter:
			body = append(body, genSubflowIter(r, sop, varId))
		case StmtIfElse:
			// readVars is non-empty here (the fallback above guarantees
			// it); build the condition over an in-scope scalar local,
			// then generate the branch bodies.  Pass the CURRENT pool /
			// scalar-local set as the branch seeds -- a branch sees
			// everything declared before the `if`.  Branch-body locals
			// do NOT re-enter this function's pool / readVars: each
			// branch is a separate genBody call with its own
			// pool, which is exactly C block scoping (a local declared
			// inside a branch is unreachable after the branch closes).
			condNames := make([]string, len(readVars))
			for ci, rv := range readVars {
				condNames[ci] = rv.name
			}
			body = append(body, genIfElse(r, sop, sc, varId, pool, condNames))
		}
	}
	if sc.terminal != nil {
		// The scope's terminal statement, last on every path (the drawn
		// statements above never `return` under noReturn, and the branch
		// and loop scopes they opened carry no terminal of their own).
		body = append(body, genDsqInsert(r, sop, sc.terminal))
	}
	return body
}

// genDsqInsert draws one StmtDsqInsert from the scope's terminalInsert:
// the kfunc by name from the program's table, one dsq id, one slice, and
// an independently-drawn subset of the enqueue flags.
func genDsqInsert(r *randGen, sop *Prog, ti *terminalInsert) Stmt {
	ki := -1
	for i := range sop.Kfuncs {
		if sop.Kfuncs[i].Name == ti.kfunc {
			ki = i
			break
		}
	}
	if ki < 0 || !sop.Kfuncs[ki].Terminal {
		// A surface-table error, not a runtime condition: the terminal
		// kfunc must be in the table and marked Terminal (so it is never
		// also a generated draw).
		panic(fmt.Sprintf("structops: surface %s: terminal kfunc %q is not a Terminal table entry",
			sop.Surface, ti.kfunc))
	}
	flags := ""
	for _, f := range ti.enqFlags {
		if r.bin() {
			if flags != "" {
				flags += " | "
			}
			flags += f
		}
	}
	if flags == "" {
		flags = "0"
	}
	return Stmt{
		Kind:     StmtDsqInsert,
		KfuncIdx: ki,
		KfuncArgs: []string{
			ti.task,
			ti.dsqIDs[r.Intn(len(ti.dsqIDs))],
			ti.slices[r.Intn(len(ti.slices))],
			flags,
		},
	}
}

// condOps -- the condition operators genIfElse may pick for an
// `if`/`else`.  The empty string is the bare truthiness test
// `if (s0)`; the rest are a comparison or a bit-test against a fuzzer
// constant.  No division/modulo and no assignment: a condition is a
// pure read of an in-scope scalar.
var condOps = []string{"", ">", "<", "==", "!=", "&"}

// genIfElse builds one StmtIfElse: a generated free-form
// `if`/`else` (Stage 2b).  condNames are the in-scope scalar locals the
// condition may test (guaranteed non-empty by the caller); seedPool is
// the typed-value pool visible at the `if` -- the branch bodies are
// generated against a COPY of it, so a branch may use any value declared
// before the `if` but a branch-local value never escapes the branch.
//
// Both branch bodies are generated with `noReturn` set: with no `return`
// in either branch every path falls through to the fixed scheduling
// epilogue, so `get_send` always schedules >= 1 subflow.  `allowIf`
// stays on (subject to the depth cap via sc.depth+1) so branching may
// nest; `allowIter` carries the parent's setting so a branch of the
// top-level body may still contain the subflow iterator.  `requireWrite`
// is cleared -- a forced write per branch is not wanted.
func genIfElse(r *randGen, sop *Prog, sc bodyScope, varId *int,
	seedPool []typedVal, condNames []string) Stmt {
	st := Stmt{
		Kind:    StmtIfElse,
		CondVar: condNames[r.Intn(len(condNames))],
		CondOp:  condOps[r.Intn(len(condOps))],
	}
	if st.CondOp != "" {
		// A 16-bit constant keeps comparisons / bit-tests in a range
		// that is meaningful against the scalar locals in scope.
		st.CondVal = int64(r.Intn(1 << 16))
	}
	// Optionally make the predicate a COMPOUND two-clause boolean
	// (`(clause1) && (clause2)` / `|| `).  The second clause tests
	// another in-scope scalar local with a real comparison (never the
	// bare-truthiness empty op), so the compound condition is always
	// well-formed.  Pure control-flow diversity: no new value or type.
	if r.Intn(3) == 0 {
		st.CondJoin = condJoins[r.Intn(len(condJoins))]
		st.Cond2Var = condNames[r.Intn(len(condNames))]
		// condOps[0] is "" (bare truthiness); pick from index 1+
		// so clause2 is always a real comparison / bit-test.
		st.Cond2Op = condOps[1+r.Intn(len(condOps)-1)]
		st.Cond2Val = int64(r.Intn(1 << 16))
	}

	// The branch scope: same writable surface and same iterator
	// permission as the enclosing scope, but `noReturn` set (no branch
	// may return) and `requireWrite` cleared.  depth+1 lets the nesting
	// cap stop runaway recursion.
	branchScope := bodyScope{
		pool:         append([]typedVal(nil), seedPool...),
		writeFields:  sc.writeFields,
		allowIter:    sc.allowIter,
		requireWrite: false,
		noReturn:     true,
		allowIf:      sc.allowIf,
		depth:        sc.depth + 1,
		minStmt:      1,
		maxStmt:      3,
		kfuncAllow:   sc.kfuncAllow,
	}
	st.IfBody = genBody(r, sop, branchScope, varId)
	if r.bin() {
		// Optional `else` -- generated against a fresh copy of the same
		// seed scope so its locals are independent of the `if` branch.
		elseScope := branchScope
		elseScope.pool = append([]typedVal(nil), seedPool...)
		st.ElseBody = genBody(r, sop, elseScope, varId)
	}
	return st
}

// genSubflowIter builds one StmtSubflowIter: the open-coded
// subflow iterator.  The verifier requires the `new -> next* -> destroy`
// lifecycle on every path, so this statement is ALWAYS rendered as the
// complete triple (see renderSubflowIter) -- it is never partial.
//
// The loop variable `sfN` is a valid `struct mptcp_subflow_context *`
// inside the loop (the `while` condition is the KF_RET_NULL NULL-check),
// so the loop body is generated with `sfN` seeded into a fresh pool and
// the avg_pacing_rate write field re-based onto `sfN`.  The loop body
// does NOT nest another iterator (allowIter false) and is kept short.
func genSubflowIter(r *randGen, sop *Prog, varId *int) Stmt {
	id := *varId
	*varId++
	sfVar := fmt.Sprintf("sf%d", id)

	// The loop body sees `sfN` (the per-iteration subflow) plus the
	// callback's `msk` and its `(struct sock *)` cast.  Writes are
	// confined to the subflow field re-based onto `sfN`; reading/writing
	// msk->snd_burst is also valid inside the loop.
	loopScope := bodyScope{
		pool: []typedVal{
			{expr: "msk", ctype: "struct mptcp_sock *"},
			{expr: mskSockExpr, ctype: "struct sock *"},
			{expr: sfVar, ctype: "struct mptcp_subflow_context *"},
		},
		writeFields: []ctxWriteField{
			{accessor: "msk->snd_burst", ctype: "int"},
			{accessor: sfVar + "->avg_pacing_rate", ctype: "unsigned long"},
		},
		allowIter:    false,
		requireWrite: false,
		noReturn:     true, // no `return` inside the loop -- see noReturn
		minStmt:      0,
		maxStmt:      3,
	}
	loopBody := genBody(r, sop, loopScope, varId)

	return Stmt{
		Kind:         StmtSubflowIter,
		IterId:       id,
		Var:          sfVar,
		CType:        "struct mptcp_subflow_context *",
		IterSockExpr: "(struct sock *)msk",
		IterBody:     loopBody,
	}
}

// instanceField is one callback entry of a struct_ops instance: the
// callback op suffix and the EXACT whitespace separating the field name
// from `=` in the rendered struct (hand-aligned, kept verbatim).
type instanceField struct {
	suffix string
	sep    string
}

// InstanceField is one scalar instance-data member a surface sets in the
// rendered instance (`.timeout_ms = 0x5dc,`).  It is the fuzzable
// replacement for fixed flags text: the value is a per-program draw, so
// e.g. a sched_ext `.flags` can carry a random subset of SCX_OPS_* bits and
// `.timeout_ms` a pinned low range, and the kernel's own validation of
// each member (->init_member) becomes part of the fuzzed surface.
type InstanceField struct {
	// Field is the member name ("flags", "timeout_ms").
	Field string
	// Sep is the whitespace between `.Field` and `=` (hand-aligned).
	Sep string
	// gen draws the value; nil means the fixed Value is used.
	gen func(r *randGen) uint64
	// Value is the fixed value when gen is nil.
	Value uint64
}

// InstanceVal is one generated instance-data value: the member and the
// value drawn for it.  Exported so a Prog / Spec gob-serializes it.
type InstanceVal struct {
	Field string
	Value uint64
}

// genInstance draws the surface's instance-data values for one program.
// It runs after the callback bodies, so a surface without instance fields
// adds no draw and its programs are unchanged.
func genInstance(r *randGen, surf *Surface) []InstanceVal {
	if len(surf.instanceFields) == 0 {
		return nil
	}
	out := make([]InstanceVal, len(surf.instanceFields))
	for i, f := range surf.instanceFields {
		v := f.Value
		if f.gen != nil {
			v = f.gen(r)
		}
		out[i] = InstanceVal{Field: f.Field, Value: v}
	}
	return out
}

// instanceSep returns the hand-aligned whitespace for an instance-data
// member, or a single space for one the surface no longer declares.
func (surf *Surface) instanceSep(field string) string {
	for i := range surf.instanceFields {
		if surf.instanceFields[i].Field == field {
			return surf.instanceFields[i].Sep
		}
	}
	return " "
}

// callbackSpec is the per-callback knowledge a surface declares:
// the op suffix, return type, any args after the fixed ctx arg, the FIXED
// prologue/epilogue text the renderer wraps around the generated body,
// and a scope() func returning the bodyScope the body is generated under.
//
// scope is a func (not a value) so each callback's pool / writeFields are
// built fresh per program; it takes the surface so a scope can reference
// surface-wide data (writable fields, ctx var) without duplicating it.
type callbackSpec struct {
	suffix       string
	retType      string
	argsAfterCtx []string
	prologue     string
	epilogue     string
	scope        func(surf *Surface) bodyScope
	// ctxType / ctxVar, when non-empty, override the surface-wide first
	// argument for THIS callback only: a surface whose ops do not all take
	// the same first argument (Qdisc_ops.enqueue takes the skb first, its
	// other four ops the qdisc) declares the odd one out here.
	ctxType string
	ctxVar  string
}

// Surface captures everything that was hard-coded for the MPTCP
// scheduler, so a second struct_ops surface (tcp_congestion_ops) is a
// TABLE entry rather than a fork.  The body-generation machinery
// (genBody / genIfElse / pickKfuncArgs / the Stmt kinds)
// is surface-agnostic and reused unchanged; a surface supplies only the
// per-struct facts around it.
type Surface struct {
	// tag is the Prog.Surface value identifying this surface.
	tag string
	// instanceStruct is the C struct type of the `.struct_ops` instance
	// (e.g. "struct mptcp_sched_ops", "struct tcp_congestion_ops").
	instanceStruct string
	// linkSection is the SEC string the instance is placed in
	// (".struct_ops.link" for MPTCP, ".struct_ops" for the CC selftests).
	linkSection string
	// progSection is the SEC string each callback function is placed in.
	progSection string
	// nameMax caps the generated `.name` length (MPTCP_SCHED_NAME_MAX /
	// TCP_CA_NAME_MAX, both 16).
	nameMax int
	// namePrefix is the generated-name prefix (e.g. "brf_").
	namePrefix string
	// ctxType / ctxVar are the callback's fixed first-argument type and
	// variable (e.g. "struct mptcp_sock *" / "msk").
	ctxType string
	ctxVar  string
	// kfuncs / iterKfuncs are the callable kfunc set and the (optional)
	// iterator kfunc set for this surface.
	kfuncs     []Kfunc
	iterKfuncs []Kfunc
	// iterInPrologue is true when a callback's FIXED prologue text itself
	// calls the iterator kfuncs (MPTCP get_send fetches its subflow
	// through the iterator), so their externs are always rendered -- not
	// only when a generated StmtSubflowIter uses them.
	iterInPrologue bool
	// writeFields is the writable ctx surface for this struct_ops type.
	writeFields []CtxField
	// prologueKfuncNames are the kfuncs the renderer emits ITSELF as part
	// of a callback's fixed prologue/epilogue -- they are excluded from
	// the generated kfunc-call set (the generator must not re-emit them)
	// but are force-included in the rendered externs.  For MPTCP these
	// are bpf_mptcp_subflow_ctx / mptcp_subflow_set_scheduled; the CC
	// surface has none.
	prologueKfuncNames []string
	// kfuncExternComment is the verbatim comment line above the kfunc
	// externs block (kept exactly as the MPTCP render had it).
	kfuncExternComment string
	// iterExternComment is the verbatim comment above the iterator
	// externs block.
	iterExternComment string
	// headerComment is the verbatim banner comment after the SPDX line.
	headerComment string
	// instanceCallbackOrder lists the callback `.<field> = (void
	// *)<name><suffix>,` lines to emit in the instance, in render order.
	// Each carries the callback suffix and the EXACT whitespace between
	// the field name and `=` (hand-aligned in the source, so stored
	// verbatim to keep the render byte-identical).  ".name" is appended
	// last by the renderer.
	instanceCallbackOrder []instanceField
	// nameSep is the whitespace between `.name` and `=`.
	nameSep string
	// nameField is the instance member that carries the registered name;
	// "" means `name` (mptcp_sched_ops, tcp_congestion_ops).  Qdisc_ops
	// calls it `id` (its TCA_KIND string, char[IFNAMSIZ]).  The loader
	// looks the member up under the same two names
	// (executor/common_linux_structops.h).
	nameField string
	// layoutStructs names kernel structs, beyond layoutProbeCommon, whose
	// layout this surface's field accessors depend on; the Configure-time
	// layout self-check (layout.go) probes them too.
	layoutStructs []string
	// instanceFields are the scalar, non-callback instance members this
	// surface sets (`.flags`, `.timeout_ms`, ...), rendered between the
	// callback pointers and `.name` in this order.  Each value is drawn per
	// program (InstanceField.gen) or fixed, persists in the Spec, and
	// reaches the kernel through the recipe's DATA records (recipe.go) --
	// so it must be a member the subsystem's ->init_member() accepts a
	// value for; the kernel rejects a non-zero value in any other
	// non-callback member.  Empty on mptcp_sched and tcp_cong (their
	// renders, and golden hashes, are unchanged).
	instanceFields []InstanceField
	// callbacks are the per-callback specs, in GENERATION order (the
	// order bodies are generated, which fixes the random-draw sequence).
	// The RENDER order is given separately by renderOrder.
	callbacks []callbackSpec
	// renderOrder lists callback suffixes in the order they are RENDERED
	// (which may differ from generation order -- MPTCP generates
	// get_send/init/release but renders init/release/get_send).
	renderOrder []string
}

// callbackCtx returns the first-argument type and variable of the callback
// with the given suffix: the callback's own override when it declares one,
// else the surface-wide ctxType / ctxVar.
func (surf *Surface) callbackCtx(suffix string) (string, string) {
	for i := range surf.callbacks {
		if cs := &surf.callbacks[i]; cs.suffix == suffix && cs.ctxType != "" {
			return cs.ctxType, cs.ctxVar
		}
	}
	return surf.ctxType, surf.ctxVar
}

// resolveWriteFields returns the surface's writable fields as the
// renderer-facing ctxWriteField list (accessor + ctype).
func (surf *Surface) resolveWriteFields() []ctxWriteField {
	out := make([]ctxWriteField, len(surf.writeFields))
	for i, f := range surf.writeFields {
		out[i] = ctxWriteField{accessor: f.Accessor, ctype: f.CType}
	}
	return out
}

// MptcpSched is the MPTCP `mptcp_sched_ops` surface.  The callbacks are
// listed in GENERATION order (get_send, init, release -- which fixes the
// random-draw sequence) and RENDERED in renderOrder (init, release,
// get_send -- which fixes the text).
//
// The get_send prologue fetches the FIRST subflow through the open-coded
// subflow iterator and closes the iterator at once -- the one-element
// form of the kernel selftest's `bpf_for_each(mptcp_subflow, subflow,
// (struct sock *)msk)` (tools/testing/selftests/bpf/progs/mptcp_bpf_first.c).
// `_next` returns a trusted pointer that does not depend on the iterator
// staying open, so destroying before the generated body is what keeps
// the body's own `return -1` NULL-guards legal (a `return` past a live
// iterator is a verifier reject for an unreleased iterator).  The
// epilogue schedules that subflow, so get_send always schedules >= 1
// subflow on every fall-through path.
var MptcpSched = &Surface{
	tag:            "mptcp_sched",
	instanceStruct: "struct mptcp_sched_ops",
	linkSection:    ".struct_ops.link",
	progSection:    "struct_ops",
	nameMax:        schedNameMax,
	namePrefix:     "brf_",
	ctxType:        "struct mptcp_sock *",
	ctxVar:         "msk",
	kfuncs:         mptcpSchedKfuncs,
	iterKfuncs:     mptcpSubflowIterKfuncs,
	iterInPrologue: true,
	writeFields:    mptcpSchedWriteFields,
	prologueKfuncNames: []string{
		"mptcp_subflow_set_scheduled",
	},
	kfuncExternComment: "/* MPTCP scheduler kfuncs (net/mptcp/bpf.c). */",
	iterExternComment:  "/* MPTCP subflow-iterator kfuncs (net/mptcp/bpf.c). */",
	headerComment:      "/* BRF-generated MPTCP struct_ops scheduler (Phase 3, Stage C). */",
	instanceCallbackOrder: []instanceField{
		{"_init", "\t\t"},
		{"_release", "\t"},
		{"_get_send", "\t"},
	},
	nameSep: "\t\t",
	callbacks: []callbackSpec{
		{
			suffix:  "_get_send",
			retType: "int",
			prologue: "\tstruct bpf_iter_mptcp_subflow it;\n" +
				"\tstruct mptcp_subflow_context *subflow;\n\n" +
				"\tbpf_iter_mptcp_subflow_new(&it, " + mskSockExpr + ");\n" +
				"\tsubflow = bpf_iter_mptcp_subflow_next(&it);\n" +
				"\tbpf_iter_mptcp_subflow_destroy(&it);\n" +
				"\tif (!subflow)\n" +
				"\t\treturn -1;\n\n",
			epilogue: "\tmptcp_subflow_set_scheduled(subflow, true);\n" +
				"\treturn 0;\n",
			scope: func(surf *Surface) bodyScope {
				return bodyScope{
					pool: []typedVal{
						{expr: "msk", ctype: "struct mptcp_sock *"},
						{expr: mskSockExpr, ctype: "struct sock *"},
						{expr: "subflow", ctype: "struct mptcp_subflow_context *"},
					},
					writeFields:  surf.resolveWriteFields(),
					allowIter:    true,
					requireWrite: true,
					allowIf:      true,
					depth:        0,
					minStmt:      3,
					maxStmt:      8,
				}
			},
		},
		{
			suffix:  "_init",
			retType: "void",
			scope:   mptcpInitReleaseScope,
		},
		{
			suffix:  "_release",
			retType: "void",
			scope:   mptcpInitReleaseScope,
		},
	},
	renderOrder: []string{"_init", "_release", "_get_send"},
}

// mptcpInitReleaseScope is the bodyScope for the MPTCP init / release
// bodies.  Only `msk` (and its `(struct sock *)` cast) is in scope --
// there is no scheduling and no `subflow` prologue -- so the writable
// surface is just `msk->snd_burst`, the iterator is not allowed, and no
// write is forced.  noReturn is set: init/release are `void`, and when
// this scope was written a KF_RET_NULL-pointer guard could only render as
// `return -1;`, so such kfuncs were not offered here.  The renderer now
// emits `return;` for a void callback (guardReturn), but the scope keeps
// noReturn: offering the guarded kfuncs would change the draw sequence
// and the golden-pinned render of every existing MPTCP program.
func mptcpInitReleaseScope(surf *Surface) bodyScope {
	return bodyScope{
		pool: []typedVal{
			{expr: "msk", ctype: "struct mptcp_sock *"},
			{expr: mskSockExpr, ctype: "struct sock *"},
		},
		writeFields: []ctxWriteField{
			{accessor: "msk->snd_burst", ctype: "int"},
		},
		allowIter:    false,
		requireWrite: false,
		noReturn:     true,
		minStmt:      2,
		maxStmt:      4,
	}
}

// tcpCongOpsScope is the bodyScope shared by the tcp_congestion_ops
// callbacks (ssthresh / cong_avoid / undo_cwnd).  Each callback takes
// `struct sock *sk`; its prologue derives `struct tcp_sock *tp =
// tcp_sk(sk);`, so both `sk` and `tp` are in the seed pool.  The writable
// surface is the three btf-struct-access tcp_sock fields, reached via
// `tp->`.  noReturn is set: ssthresh/undo_cwnd end in a fixed `return
// <u32>;` epilogue, so the generated body must not early-return (a
// KF_RET_NULL guard's `return -1;` would also be the wrong type for a
// `__u32` callback); cong_avoid is void, likewise no early return.  The
// CC surface has no iterator and no required write.
func tcpCongOpsScope(surf *Surface) bodyScope {
	return bodyScope{
		pool: []typedVal{
			{expr: "sk", ctype: "struct sock *"},
			{expr: "tp", ctype: "struct tcp_sock *"},
		},
		writeFields:  surf.resolveWriteFields(),
		allowIter:    false,
		requireWrite: false,
		noReturn:     true,
		allowIf:      true,
		depth:        0,
		minStmt:      2,
		maxStmt:      5,
	}
}

// TCPCong is the SECOND struct_ops surface: a fuzzed
// tcp_congestion_ops BPF congestion-control module.  Ground truth is the
// in-tree kernel: net/ipv4/bpf_tcp_ca.c (writable fields, callable
// kfuncs), include/net/tcp.h (signatures), and the selftest
// tools/testing/selftests/bpf/progs/bpf_dctcp.c (SEC(".struct_ops"),
// tcp_sk(sk)).  A BPF CC must provide ssthresh, undo_cwnd, and a
// cong_avoid/cong_control (net/ipv4/tcp_cong.c gate); this surface renders
// the three required ops.
//
// Production note: wiring CC into the LIVE fuzzer rotation needs executor
// support (compile/load/attach of a tcp_congestion_ops object and
// selection via net.ipv4.tcp_congestion_control) and is a VM follow-up;
// generateMptcp's production path stays MPTCP and ProgTypeMap /
// rotation are unchanged.  This surface is exercised host-side via
// Generate in the tests.
var TCPCong = &Surface{
	tag:                "tcp_cong",
	instanceStruct:     "struct tcp_congestion_ops",
	linkSection:        ".struct_ops",
	progSection:        "struct_ops",
	nameMax:            16, // TCP_CA_NAME_MAX
	namePrefix:         "brf_",
	ctxType:            "struct sock *",
	ctxVar:             "sk",
	kfuncs:             tcpCongKfuncs,
	iterKfuncs:         nil,
	writeFields:        tcpCongWriteFields,
	prologueKfuncNames: nil,
	kfuncExternComment: "/* tcp_congestion_ops kfuncs (net/ipv4/bpf_tcp_ca.c). */",
	iterExternComment:  "",
	headerComment:      "/* BRF-generated tcp_congestion_ops struct_ops module. */",
	instanceCallbackOrder: []instanceField{
		{"_ssthresh", "\t"},
		{"_cong_avoid", "\t"},
		{"_undo_cwnd", "\t"},
	},
	nameSep: "\t\t",
	callbacks: []callbackSpec{
		{
			suffix:   "_ssthresh",
			retType:  "__u32",
			prologue: "\tstruct tcp_sock *tp = tcp_sk(sk);\n\n",
			epilogue: "\treturn tp->snd_ssthresh;\n",
			scope:    tcpCongOpsScope,
		},
		{
			suffix:       "_cong_avoid",
			retType:      "void",
			argsAfterCtx: []string{"__u32 ack", "__u32 acked"},
			prologue:     "\tstruct tcp_sock *tp = tcp_sk(sk);\n\n",
			epilogue:     "",
			scope:        tcpCongOpsScope,
		},
		{
			suffix:   "_undo_cwnd",
			retType:  "__u32",
			prologue: "\tstruct tcp_sock *tp = tcp_sk(sk);\n\n",
			epilogue: "\treturn tp->snd_cwnd;\n",
			scope:    tcpCongOpsScope,
		},
	},
	renderOrder: []string{"_ssthresh", "_cong_avoid", "_undo_cwnd"},
}

// surfaces is the registry of known surfaces, keyed by tag.  The
// renderer looks a program's surface up here AFTER gob deserialization
// (the Prog carries only the Surface tag, not the descriptor),
// so the per-struct render knobs (instance struct type, link section, ctx
// arg, comments) survive a round-trip without bloating the gob.
var surfaces = map[string]*Surface{
	MptcpSched.tag: MptcpSched,
	TCPCong.tag:    TCPCong,
}

// surface returns the descriptor for this program's Surface tag,
// defaulting to the MPTCP surface for an empty/unknown tag (so a program
// generated before the Surface field existed still renders as MPTCP).
func (sop *Prog) surface() *Surface {
	if s, ok := surfaces[sop.Surface]; ok {
		return s
	}
	return MptcpSched
}

// ByTag returns the registered surface with the given tag ("mptcp_sched",
// "tcp_cong"), or nil.
func ByTag(tag string) *Surface {
	return surfaces[tag]
}

// Tag returns the surface's registry tag.
func (surf *Surface) Tag() string {
	return surf.tag
}

// Generate builds a fully-generated struct_ops program for surf, drawing
// from r.  The same (seed, surface) always yields the same program: the
// golden-hash test pins the MPTCP and CC renders over a fixed seed range
// to the fork's bytes.
//
// Surface choice is the caller's: in the fuzzer the syzlang blob type
// selects the surface (sys/linux/init_structops.go); there is no in-package
// MPTCP-vs-CC rotation.
func Generate(r Rand, surf *Surface) *Prog {
	return generate(&randGen{r}, surf)
}

// generateMptcp is the fork's GOLDEN-anchored entry point: the MPTCP
// scheduler with no surface choice.  Kept so the golden test exercises
// exactly the fork's production path.
func generateMptcp(r *randGen) *Prog {
	return generate(r, MptcpSched)
}

// generate builds a fully-generated struct_ops program for the given
// surface.  Bodies are generated in the surface's callbacks order (which
// fixes the random-draw sequence); a single shared varId counter names
// every local uniquely across all callbacks.
func generate(r *randGen, surf *Surface) *Prog {
	sop := &Prog{
		Surface:        surf.tag,
		WriteFields:    surf.writeFields,
		Kfuncs:         surf.kfuncs,
		IterKfuncs:     surf.iterKfuncs,
		PrologueKfuncs: surf.prologueKfuncNames,
	}
	// A short, unique-enough name within the surface's name cap.
	name := fmt.Sprintf("%s%x", surf.namePrefix, r.Intn(1<<24))
	if len(name) >= surf.nameMax {
		name = name[:surf.nameMax-1]
	}
	sop.SchedName = name

	// Generate each callback's body in surface (generation) order.
	sop.Callbacks = make([]Callback, len(surf.callbacks))
	varId := 0
	for i, spec := range surf.callbacks {
		sop.Callbacks[i] = Callback{
			Suffix:       spec.suffix,
			RetType:      spec.retType,
			ArgsAfterCtx: spec.argsAfterCtx,
			Prologue:     spec.prologue,
			Epilogue:     spec.epilogue,
			Body:         genBody(r, sop, spec.scope(surf), &varId),
		}
	}
	sop.Instance = genInstance(r, surf)
	return sop
}

// walkStmts invokes fn on every statement in body, recursing into the
// loop body of every SubflowIter and both branch bodies of every IfElse
// so callers see the whole statement tree.
func walkStmts(body []Stmt, fn func(*Stmt)) {
	for i := range body {
		st := &body[i]
		fn(st)
		switch st.Kind {
		case StmtSubflowIter:
			walkStmts(st.IterBody, fn)
		case StmtIfElse:
			walkStmts(st.IfBody, fn)
			walkStmts(st.ElseBody, fn)
		}
	}
}

// usesSubflowIter reports whether any generated body uses the subflow
// iterator -- the renderer emits the three `bpf_iter_mptcp_subflow_*`
// externs only when at least one does.
func (sop *Prog) usesSubflowIter() bool {
	found := false
	for _, b := range sop.allBodies() {
		walkStmts(b, func(st *Stmt) {
			if st.Kind == StmtSubflowIter {
				found = true
			}
		})
	}
	return found
}

// usedKfuncIdxs returns the indices of every kfunc the rendered
// translation unit actually references -- the surface's fixed
// prologue/epilogue kfuncs plus every kfunc a generated KfuncCall
// statement targets in ANY body (get_send / init / release, including
// inside iterator loop bodies) -- so Render emits an
// `extern … __ksym;` decl for exactly those and no more.  An unused
// extern is harmless, but emitting only the used set keeps each rendered
// scheduler honest about its kfunc surface.
func (sop *Prog) usedKfuncIdxs() []int {
	used := make(map[int]bool)
	for ki, kf := range sop.Kfuncs {
		if sop.isPrologueKfunc(kf.Name) {
			used[ki] = true // fixed prologue / epilogue
		}
	}
	for _, b := range sop.allBodies() {
		walkStmts(b, func(st *Stmt) {
			if st.Kind == StmtKfuncCall || st.Kind == StmtDsqInsert {
				used[st.KfuncIdx] = true
			}
		})
	}
	// Return indices in Kfuncs order for a stable render.
	var idxs []int
	for ki := range sop.Kfuncs {
		if used[ki] {
			idxs = append(idxs, ki)
		}
	}
	return idxs
}

// renderBody renders a generated body to BPF C.  indent is the leading
// whitespace prefixed to every statement (one tab at callback scope,
// two inside an iterator loop).  guardRet is the `return` statement a
// KF_RET_NULL guard emits -- `return -1;` in a value-returning callback,
// `return;` in a void one (guardReturn) -- the same throughout a callback,
// so it is threaded down into branch and loop bodies.  The body may itself
// contain a SubflowIter, whose loop body is rendered recursively at
// indent+"\t".
func (sop *Prog) renderBody(s *bytes.Buffer, body []Stmt, indent, guardRet string) {
	for _, st := range body {
		switch st.Kind {
		case StmtCtxRead:
			fmt.Fprintf(s, "%s%s %s = %s;\n",
				indent, st.FieldCType, st.Var, st.FieldAccessor)
		case StmtCtxWrite:
			fmt.Fprintf(s, "%s%s = %d;\n", indent, st.FieldAccessor, st.Val)
		case StmtArith:
			if st.SrcVar2 != "" {
				// Two-local form: Var = SrcVar Op SrcVar2.
				fmt.Fprintf(s, "%s%s %s = %s %s %s;\n",
					indent, st.CType, st.Var, st.SrcVar, st.Op, st.SrcVar2)
			} else {
				// Constant-RHS form (also the only shift form): the RHS
				// is the constant Val.
				fmt.Fprintf(s, "%s%s %s = %s %s %d;\n",
					indent, st.CType, st.Var, st.SrcVar, st.Op, st.Val)
			}
		case StmtKfuncCall:
			kf := &sop.Kfuncs[st.KfuncIdx]
			argList := joinArgs(st.KfuncArgs)
			if st.Var == "" {
				// void kfunc -- call for effect.
				fmt.Fprintf(s, "%s%s(%s);\n", indent, kf.Name, argList)
			} else {
				// kfunc with a result -- bind to a typed local.
				fmt.Fprintf(s, "%s%s %s = %s(%s);\n",
					indent, st.CType, st.Var, kf.Name, argList)
			}
			if st.NullGuard {
				// Mandatory KF_RET_NULL pointer guard -- emitted
				// IMMEDIATELY after the call so the local is only
				// ever used after the verifier sees it null-checked.
				fmt.Fprintf(s, "%sif (!%s)\n", indent, st.Var)
				fmt.Fprintf(s, "%s\t%s\n", indent, guardRet)
			}
		case StmtDsqInsert:
			// The scope's terminal insert: a void kfunc call, last in its
			// body (see StmtDsqInsert).
			kf := &sop.Kfuncs[st.KfuncIdx]
			fmt.Fprintf(s, "%s/* Generated terminal insert (liveness). */\n", indent)
			fmt.Fprintf(s, "%s%s(%s);\n", indent, kf.Name, joinArgs(st.KfuncArgs))
		case StmtSubflowIter:
			sop.renderSubflowIter(s, st, indent, guardRet)
		case StmtIfElse:
			sop.renderIfElse(s, st, indent, guardRet)
		}
	}
}

// joinArgs renders a kfunc argument list.
func joinArgs(args []string) string {
	out := ""
	for i, a := range args {
		if i > 0 {
			out += ", "
		}
		out += a
	}
	return out
}

// guardReturn is the `return` a KF_RET_NULL guard emits in a callback of
// the given return type: a void callback cannot `return -1;`, so it
// returns bare; every other callback keeps the fork's `return -1;` (the
// MPTCP get_send "nothing to schedule" path).  A value-returning callback
// whose epilogue must run (tcp_cong's `return tp->snd_cwnd;`) keeps its
// body noReturn and never reaches this.
func guardReturn(retType string) string {
	if retType == "void" {
		return "return;"
	}
	return "return -1;"
}

// renderIfElse renders one IfElse (Stage 2b) as
// `if (<cond>) { <IfBody> }` optionally followed by
// `else { <ElseBody> }`.  The condition is a comparison / bit-test
// against a fuzzer constant, or -- when CondOp is empty -- the bare
// truthiness of an in-scope scalar local.  Both branch bodies are
// rendered recursively at indent+"\t"; they were generated under a
// `noReturn` scope, so neither emits a `return` and every path falls
// through to the caller's fixed scheduling epilogue.
// renderCondClause renders one boolean clause of an IfElse condition:
// the bare truthiness `v` when op is empty, else the comparison /
// bit-test `v op val`.
func renderCondClause(v, op string, val int64) string {
	if op == "" {
		return v
	}
	return fmt.Sprintf("%s %s %d", v, op, val)
}

func (sop *Prog) renderIfElse(s *bytes.Buffer, st Stmt, indent, guardRet string) {
	cond := renderCondClause(st.CondVar, st.CondOp, st.CondVal)
	if st.CondJoin != "" {
		// Compound predicate: parenthesise each clause so the connective
		// reads unambiguously regardless of per-clause operator.
		cond = fmt.Sprintf("(%s) %s (%s)", cond, st.CondJoin,
			renderCondClause(st.Cond2Var, st.Cond2Op, st.Cond2Val))
	}
	fmt.Fprintf(s, "%s/* BRF-generated if/else. */\n", indent)
	fmt.Fprintf(s, "%sif (%s) {\n", indent, cond)
	sop.renderBody(s, st.IfBody, indent+"\t", guardRet)
	if len(st.ElseBody) > 0 {
		fmt.Fprintf(s, "%s} else {\n", indent)
		sop.renderBody(s, st.ElseBody, indent+"\t", guardRet)
	}
	fmt.Fprintf(s, "%s}\n", indent)
}

// renderSubflowIter renders one SubflowIter as the complete,
// verifier-required `new -> next* -> destroy` triple -- ALWAYS all three
// together, never partial.  The `while` condition is the KF_RET_NULL
// NULL-check on `bpf_iter_mptcp_subflow_next`; inside the loop `sfN` is a
// valid `struct mptcp_subflow_context *`.  Modelled on the kernel
// selftest `tools/testing/selftests/bpf/progs/mptcp_bpf_rr.c`, whose
// `bpf_for_each(mptcp_subflow, subflow, (struct sock *)msk)` expands to
// exactly this idiom; the socket argument is `(struct sock *)msk`.
func (sop *Prog) renderSubflowIter(s *bytes.Buffer, st Stmt, indent, guardRet string) {
	itVar := fmt.Sprintf("it%d", st.IterId)
	sfVar := st.Var
	fmt.Fprintf(s, "%s/* BRF-generated subflow iterator. */\n", indent)
	fmt.Fprintf(s, "%sstruct bpf_iter_mptcp_subflow %s;\n", indent, itVar)
	fmt.Fprintf(s, "%sstruct mptcp_subflow_context *%s;\n", indent, sfVar)
	fmt.Fprintf(s, "%sbpf_iter_mptcp_subflow_new(&%s, %s);\n",
		indent, itVar, st.IterSockExpr)
	fmt.Fprintf(s, "%swhile ((%s = bpf_iter_mptcp_subflow_next(&%s))) {\n",
		indent, sfVar, itVar)
	sop.renderBody(s, st.IterBody, indent+"\t", guardRet)
	fmt.Fprintf(s, "%s}\n", indent)
	fmt.Fprintf(s, "%sbpf_iter_mptcp_subflow_destroy(&%s);\n", indent, itVar)
}

// Render renders a generated struct_ops program to a complete BPF C
// translation unit: vmlinux.h, the kfunc externs, the `SEC("struct_ops")`
// callbacks, and the `SEC(".struct_ops[.link]")` instance.  The MPTCP
// get_send callback interleaves the fixed kfunc skeleton with the
// generated body.  Mirrors the shape of
// tools/testing/selftests/bpf/progs/mptcp_bpf_first.c (MPTCP) and
// bpf_dctcp.c (CC).
func (sop *Prog) Render() string {
	surf := sop.surface()
	s := new(bytes.Buffer)

	fmt.Fprintf(s, "// SPDX-License-Identifier: GPL-2.0\n")
	fmt.Fprintf(s, "%s\n", surf.headerComment)
	fmt.Fprintf(s, "#include \"vmlinux.h\"\n")
	fmt.Fprintf(s, "#include <bpf/bpf_helpers.h>\n")
	fmt.Fprintf(s, "#include <bpf/bpf_tracing.h>\n\n")

	fmt.Fprintf(s, "char _license[] SEC(\"license\") = \"GPL\";\n\n")

	// Kfunc externs -- emit only the kfuncs this program actually
	// references (the surface's prologue/epilogue kfuncs plus every kfunc
	// a generated call targets).
	fmt.Fprintf(s, "%s\n", surf.kfuncExternComment)
	for _, ki := range sop.usedKfuncIdxs() {
		fmt.Fprintf(s, "%s\n", sop.Kfuncs[ki].CDecl)
	}
	// Iterator kfuncs -- emitted when the surface defines them and either
	// a fixed prologue (MPTCP get_send) or a generated body uses the
	// iterator.  The verifier requires the full new -> next* -> destroy
	// triple, so either all three externs are needed or none are.
	if len(sop.IterKfuncs) > 0 && (surf.iterInPrologue || sop.usesSubflowIter()) {
		fmt.Fprintf(s, "%s\n", surf.iterExternComment)
		for i := range sop.IterKfuncs {
			fmt.Fprintf(s, "%s\n", sop.IterKfuncs[i].CDecl)
		}
	}
	fmt.Fprintf(s, "\n")

	// Callbacks, in the surface's RENDER order (which may differ from the
	// generation order that fixed the random-draw sequence).
	for _, suffix := range surf.renderOrder {
		cb := sop.callback(suffix)
		if cb == nil {
			continue
		}
		fmt.Fprintf(s, "SEC(\"%s\")\n", surf.progSection)
		// Signature: `<ret> BPF_PROG(<name><suffix>, <ctx> [, args...])`;
		// the ctx arg is the surface's unless this callback overrides it.
		ctxType, ctxVar := surf.callbackCtx(cb.Suffix)
		fmt.Fprintf(s, "%s BPF_PROG(%s%s, %s%s",
			cb.RetType, sop.SchedName, cb.Suffix, ctxType, ctxVar)
		for _, a := range cb.ArgsAfterCtx {
			fmt.Fprintf(s, ", %s", a)
		}
		fmt.Fprintf(s, ")\n{\n")
		// Fixed prologue (verbatim, already indented).
		if cb.Prologue != "" {
			fmt.Fprint(s, cb.Prologue)
		}
		fmt.Fprintf(s, "\t/* BRF-generated body. */\n")
		if len(cb.Body) == 0 {
			fmt.Fprintf(s, "\t/* (empty) */\n")
		}
		sop.renderBody(s, cb.Body, "\t", guardReturn(cb.RetType))
		// Fixed epilogue (verbatim, already indented) -- preceded by a
		// blank line, matching the MPTCP get_send layout.
		if cb.Epilogue != "" {
			fmt.Fprintf(s, "\n")
			fmt.Fprint(s, cb.Epilogue)
		}
		fmt.Fprintf(s, "}\n\n")
	}

	// The struct_ops map instance.
	fmt.Fprintf(s, "SEC(\"%s\")\n", surf.linkSection)
	fmt.Fprintf(s, "%s %s = {\n", surf.instanceStruct, sop.SchedName)
	for _, f := range surf.instanceCallbackOrder {
		// `.get_send` from suffix "_get_send" -- the suffix's leading
		// underscore becomes the field's leading dot.  sep is the
		// hand-aligned whitespace before `=`.
		field := "." + f.suffix[1:]
		fmt.Fprintf(s, "\t%s%s= (void *)%s%s,\n",
			field, f.sep, sop.SchedName, f.suffix)
	}
	// Instance data, in surface order.  Hex: a hex literal takes the first
	// of int / unsigned / long / unsigned long that holds it, so a
	// full-width u64 value needs no suffix and a narrower member converts
	// silently.  Digest reads these values back out of the compiled object
	// (recipe.go DATA records); the loader copies them into the map value.
	for _, v := range sop.Instance {
		fmt.Fprintf(s, "\t.%s%s= %#x,\n", v.Field, surf.instanceSep(v.Field), v.Value)
	}
	nameField := surf.nameField
	if nameField == "" {
		nameField = "name"
	}
	fmt.Fprintf(s, "\t.%s%s= \"%s\",\n", nameField, surf.nameSep, sop.SchedName)
	fmt.Fprintf(s, "};\n")

	return s.String()
}

// callback returns a pointer to the callback with the given op suffix, or
// nil if none.  Used by the renderer to fetch a callback in render order.
func (sop *Prog) callback(suffix string) *Callback {
	for i := range sop.Callbacks {
		if sop.Callbacks[i].Suffix == suffix {
			return &sop.Callbacks[i]
		}
	}
	return nil
}
