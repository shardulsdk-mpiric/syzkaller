// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Tests for the struct_ops generator.  Imported from BRF's
// prog/brf_structops_test.go together with the generator (see the
// provenance note in structops.go).  The test bodies are the fork's,
// verbatim modulo identifier renames; the helpers below replace the fork's
// BpfProg / randGen / gob-on-disk plumbing with a thin test-local shape so
// the bodies did not have to change.  Added on import:
// TestStructOpsGolden, the port-fidelity oracle.
//
// What the fork's tests check, by stage:
//
// Stage C: a generated MPTCP struct_ops scheduler renders the structural
// invariants the kernel verifier and bpf_struct_ops loader require.
//
// Stage C-full Stage 1: generated schedulers emit straight-line kfunc
// calls and every KF_RET_NULL *pointer* result is NULL-checked before any
// use (TestStructOpsKfuncCalls).
//
// Stage C-full Stage 2a: a generated subflow iterator is ALWAYS the
// complete `new -> next* -> destroy` triple (TestStructOpsSubflowIter) and
// the generated `init` / `release` bodies are non-empty
// (TestStructOpsInitReleaseBodies).
//
// Stage C-full Stage 2b: generated free-form `if/else` renders balanced,
// properly-indented C, no branch body emits a `return`, branch-local
// variables do not leak past their branch, and the nesting depth is capped
// (TestStructOpsIfElse).
//
// Run: go test ./pkg/structops/ -run StructOps -v

package structops

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"fmt"
	"math/rand"
	"regexp"
	"strings"
	"testing"
)

// testProg mirrors the shape the fork's tests were written against -- a
// BpfProg carrying a StructOps model -- so the test bodies are the fork's.
type testProg struct {
	StructOps *Prog
}

func (p *testProg) Render() string {
	return p.StructOps.Render()
}

func (p *testProg) isStructOps() bool {
	return p.StructOps != nil
}

// newTestRand seeds the generator exactly as the fork's tests did
// (`newRand(target, rand.NewSource(seed))`, whose only draws are
// `Intn`/`bin` on the embedded *rand.Rand), so a seed names the same
// program here as there.
func newTestRand(seed int64) *randGen {
	return &randGen{rand.New(rand.NewSource(seed))}
}

// newStructOpsTestProg builds an MPTCP struct_ops program via the fork's
// golden-anchored production entry point.
func newStructOpsTestProg(t *testing.T, seed int64) *testProg {
	t.Helper()
	return &testProg{StructOps: generateMptcp(newTestRand(seed))}
}

// gobRoundTrip encodes and decodes p's model through gob, as the fork did
// via its on-disk .gob files.  Nothing in native syzkaller gob-serialises
// the model (the fuzzer carries the rendered/compiled blob), but the
// exported-fields discipline the round-trip tests enforce is kept.
func gobRoundTrip(t *testing.T, seed int64, p *testProg) *testProg {
	t.Helper()
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(p.StructOps); err != nil {
		t.Fatalf("seed %d: gob encode: %v", seed, err)
	}
	q := &testProg{StructOps: new(Prog)}
	if err := gob.NewDecoder(&buf).Decode(q.StructOps); err != nil {
		t.Fatalf("seed %d: gob decode: %v", seed, err)
	}
	return q
}

func TestStructOpsGenAndRender(t *testing.T) {
	for seed := int64(0); seed < 64; seed++ {
		p := newStructOpsTestProg(t, seed)
		if !p.isStructOps() {
			t.Fatalf("seed %d: isStructOps() false", seed)
		}
		if p.StructOps.SchedName == "" {
			t.Fatalf("seed %d: empty SchedName", seed)
		}
		if len(p.StructOps.SchedName) >= schedNameMax {
			t.Errorf("seed %d: SchedName %q exceeds MPTCP_SCHED_NAME_MAX",
				seed, p.StructOps.SchedName)
		}

		src := p.Render()
		name := p.StructOps.SchedName

		// Required structural fragments of a valid mptcp_sched_ops
		// struct_ops scheduler.
		mustContain := []string{
			"#include \"vmlinux.h\"",
			"SEC(\"struct_ops\")",
			"SEC(\".struct_ops.link\")",
			"struct mptcp_sched_ops " + name + " = {",
			"BPF_PROG(" + name + "_get_send, struct mptcp_sock *msk)",
			"BPF_PROG(" + name + "_init, struct mptcp_sock *msk)",
			"BPF_PROG(" + name + "_release, struct mptcp_sock *msk)",
			"bpf_iter_mptcp_subflow_new(&it, (struct sock *)msk)",
			"subflow = bpf_iter_mptcp_subflow_next(&it)",
			"bpf_iter_mptcp_subflow_destroy(&it)",
			"mptcp_subflow_set_scheduled(subflow, true)",
			"__ksym;",
			".name\t\t= \"" + name + "\",",
		}
		for _, frag := range mustContain {
			if !strings.Contains(src, frag) {
				t.Errorf("seed %d: rendered source missing %q\n---\n%s",
					seed, frag, src)
			}
		}

		// At least one write to a btf_struct_access-writable field
		// must appear -- the headline write primitive.
		if !strings.Contains(src, "msk->snd_burst =") &&
			!strings.Contains(src, "subflow->avg_pacing_rate =") {
			t.Errorf("seed %d: no context write generated\n---\n%s", seed, src)
		}

		// No write to any field outside the writable surface: a
		// write reaches the verifier as `<lvalue> = `.  The only
		// `->`-write lvalues permitted are `msk->snd_burst` and
		// `avg_pacing_rate` reached via the fixed `subflow` local or
		// an iterator loop variable `sfN`.
		iterSubflowWrite := regexp.MustCompile(`^sf[0-9]+->avg_pacing_rate$`)
		for _, line := range strings.Split(src, "\n") {
			l := strings.TrimSpace(line)
			eq := strings.Index(l, " = ")
			arrow := strings.Index(l, "->")
			if eq == -1 || arrow == -1 || arrow > eq {
				continue
			}
			// declarations like `int s0 = msk->snd_burst;` are
			// reads, not writes -- skip lines whose lvalue is a
			// declared local.
			lvalue := strings.TrimSpace(l[:eq])
			if strings.HasPrefix(lvalue, "int ") ||
				strings.HasPrefix(lvalue, "unsigned long ") {
				continue
			}
			if lvalue != "msk->snd_burst" &&
				lvalue != "subflow->avg_pacing_rate" &&
				!iterSubflowWrite.MatchString(lvalue) {
				t.Errorf("seed %d: write to non-writable lvalue %q",
					seed, lvalue)
			}
		}
	}
}

// cmpStmts deeply compares two generated-body slices, recursing
// into a SubflowIter's loop body.  path is a human-readable prefix for
// error messages (e.g. "GetSendBody", "GetSendBody[2].IterBody").
func cmpStmts(t *testing.T, path string, want, got []Stmt) {
	t.Helper()
	if len(want) != len(got) {
		t.Errorf("%s len: got %d want %d", path, len(got), len(want))
		return
	}
	for i := range want {
		ws, gs := want[i], got[i]
		if ws.Kind != gs.Kind {
			t.Errorf("%s[%d]: Kind got %d want %d", path, i, gs.Kind, ws.Kind)
		}
		switch ws.Kind {
		case StmtKfuncCall:
			if gs.KfuncIdx != ws.KfuncIdx {
				t.Errorf("%s[%d]: KfuncIdx got %d want %d",
					path, i, gs.KfuncIdx, ws.KfuncIdx)
			}
			if gs.NullGuard != ws.NullGuard {
				t.Errorf("%s[%d]: NullGuard got %v want %v",
					path, i, gs.NullGuard, ws.NullGuard)
			}
			if len(gs.KfuncArgs) != len(ws.KfuncArgs) {
				t.Fatalf("%s[%d]: KfuncArgs len got %d want %d",
					path, i, len(gs.KfuncArgs), len(ws.KfuncArgs))
			}
			for j := range ws.KfuncArgs {
				if gs.KfuncArgs[j] != ws.KfuncArgs[j] {
					t.Errorf("%s[%d] arg %d: got %q want %q",
						path, i, j, gs.KfuncArgs[j], ws.KfuncArgs[j])
				}
			}
		case StmtSubflowIter:
			if gs.IterId != ws.IterId {
				t.Errorf("%s[%d]: IterId got %d want %d",
					path, i, gs.IterId, ws.IterId)
			}
			if gs.Var != ws.Var || gs.IterSockExpr != ws.IterSockExpr {
				t.Errorf("%s[%d]: iter Var/SockExpr got %q/%q want %q/%q",
					path, i, gs.Var, gs.IterSockExpr,
					ws.Var, ws.IterSockExpr)
			}
			cmpStmts(t,
				path+"["+itoa(i)+"].IterBody", ws.IterBody, gs.IterBody)
		case StmtIfElse:
			if gs.CondVar != ws.CondVar || gs.CondOp != ws.CondOp ||
				gs.CondVal != ws.CondVal {
				t.Errorf("%s[%d]: cond got %q/%q/%d want %q/%q/%d",
					path, i, gs.CondVar, gs.CondOp, gs.CondVal,
					ws.CondVar, ws.CondOp, ws.CondVal)
			}
			if gs.CondJoin != ws.CondJoin || gs.Cond2Var != ws.Cond2Var ||
				gs.Cond2Op != ws.Cond2Op || gs.Cond2Val != ws.Cond2Val {
				t.Errorf("%s[%d]: cond2 got %q/%q/%q/%d want %q/%q/%q/%d",
					path, i, gs.CondJoin, gs.Cond2Var, gs.Cond2Op, gs.Cond2Val,
					ws.CondJoin, ws.Cond2Var, ws.Cond2Op, ws.Cond2Val)
			}
			cmpStmts(t,
				path+"["+itoa(i)+"].IfBody", ws.IfBody, gs.IfBody)
			cmpStmts(t,
				path+"["+itoa(i)+"].ElseBody", ws.ElseBody, gs.ElseBody)
		case StmtCtxRead, StmtCtxWrite:
			if gs.FieldAccessor != ws.FieldAccessor {
				t.Errorf("%s[%d]: FieldAccessor got %q want %q",
					path, i, gs.FieldAccessor, ws.FieldAccessor)
			}
		}
	}
}

// itoa is a tiny local int->string for cmpStmts paths.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// firstIterSeed returns the lowest seed in [0, limit) whose generated
// scheduler uses the subflow iterator, or -1 if none does.  Used so
// tests exercise the iterator path without hardcoding a seed.
func firstIterSeed(t *testing.T, limit int64) int64 {
	t.Helper()
	for seed := int64(0); seed < limit; seed++ {
		p := newStructOpsTestProg(t, seed)
		if p.StructOps.usesSubflowIter() {
			return seed
		}
	}
	return -1
}

// usesIfElse reports whether any generated body of sop contains a
// generated `if`/`else` statement.
func usesIfElse(sop *Prog) bool {
	found := false
	for _, b := range [][]Stmt{
		sop.body("_get_send"), sop.body("_init"), sop.body("_release"),
	} {
		walkStmts(b, func(st *Stmt) {
			if st.Kind == StmtIfElse {
				found = true
			}
		})
	}
	return found
}

// firstIfElseSeed returns the lowest seed in [0, limit) whose generated
// scheduler emits an `if`/`else`, or -1 if none does.
func firstIfElseSeed(t *testing.T, limit int64) int64 {
	t.Helper()
	for seed := int64(0); seed < limit; seed++ {
		p := newStructOpsTestProg(t, seed)
		if usesIfElse(p.StructOps) {
			return seed
		}
	}
	return -1
}

func TestStructOpsGobRoundTrip(t *testing.T) {
	// Seed 7 is a baseline sample; the iterator seed covers the
	// recursive gob path through a SubflowIter's nested IterBody; the
	// if/else seed covers the recursive gob path through an IfElse's
	// IfBody / ElseBody (Stage 2b).
	seeds := []int64{7}
	if it := firstIterSeed(t, 256); it >= 0 {
		seeds = append(seeds, it)
	} else {
		t.Error("no subflow iterator generated across 256 seeds -- " +
			"iterator gob path is untested")
	}
	if ie := firstIfElseSeed(t, 256); ie >= 0 {
		seeds = append(seeds, ie)
	} else {
		t.Error("no if/else generated across 256 seeds -- " +
			"if/else gob path is untested")
	}
	for _, seed := range seeds {
		p := newStructOpsTestProg(t, seed)
		q := gobRoundTrip(t, seed, p)
		if q.StructOps == nil {
			t.Fatalf("seed %d: StructOps lost across gob round-trip", seed)
		}
		if q.StructOps.SchedName != p.StructOps.SchedName {
			t.Errorf("seed %d: SchedName: got %q want %q",
				seed, q.StructOps.SchedName, p.StructOps.SchedName)
		}
		if len(q.StructOps.Kfuncs) != len(p.StructOps.Kfuncs) {
			t.Errorf("seed %d: Kfuncs len: got %d want %d",
				seed, len(q.StructOps.Kfuncs), len(p.StructOps.Kfuncs))
		}
		if len(q.StructOps.IterKfuncs) != len(p.StructOps.IterKfuncs) {
			t.Errorf("seed %d: IterKfuncs len: got %d want %d",
				seed, len(q.StructOps.IterKfuncs),
				len(p.StructOps.IterKfuncs))
		}
		// Stage C-full Stage 1/2a: every body -- with kfunc-call
		// statements (KfuncArgs + NullGuard) and SubflowIter
		// statements (IterBody recursively) -- must survive the gob
		// round-trip intact, since rendering happens after
		// deserialization.
		cmpStmts(t, "GetSendBody",
			p.StructOps.body("_get_send"), q.StructOps.body("_get_send"))
		cmpStmts(t, "InitBody",
			p.StructOps.body("_init"), q.StructOps.body("_init"))
		cmpStmts(t, "ReleaseBody",
			p.StructOps.body("_release"), q.StructOps.body("_release"))
	}
}

// TestStructOpsKfuncCalls is the Stage C-full Stage 1 check.  It
// asserts that generated schedulers exercise the kfunc-call generator
// and that every generated call honours the verifier contract:
//
//   - a KF_RET_NULL *pointer* result is NULL-checked before any use;
//   - every kfunc argument is a typed, in-scope value;
//   - the fixed prologue/epilogue is left intact.
func TestStructOpsKfuncCalls(t *testing.T) {
	// The set of values that may legally appear as a kfunc argument:
	// the three fixed prologue values plus any `sN` local.  An `sN`
	// local is only ever in scope after its declaring statement, and
	// the renderer emits statements in order, so a syntactic
	// membership check here is sufficient to confirm "typed,
	// in-scope" -- a non-member argument is necessarily wrong.
	fixedArgs := map[string]bool{
		"msk": true, "(struct sock *)msk": true, "subflow": true,
		"true": true, "false": true,
	}

	// Names of kfuncs whose pointer return is KF_RET_NULL -- their
	// result MUST be guarded.  Derived from the model so the test
	// tracks mptcpSchedKfuncs.
	ptrRetNull := map[string]bool{}
	for i := range mptcpSchedKfuncs {
		kf := &mptcpSchedKfuncs[i]
		if kf.needsNullGuard() {
			ptrRetNull[kf.Name] = true
		}
	}

	sawKfuncCall := false
	sawGuard := false
	for seed := int64(0); seed < 256; seed++ {
		p := newStructOpsTestProg(t, seed)
		sop := p.StructOps

		// Walk the model: every KfuncCall must reference a valid
		// kfunc, pass only in-scope args, and -- when its kfunc
		// needs a guard -- carry NullGuard and bind a local.
		declared := map[string]bool{}
		for si, st := range sop.body("_get_send") {
			switch st.Kind {
			case StmtCtxRead:
				if st.Var != "" {
					declared[st.Var] = true
				}
			case StmtArith:
				// A two-local Arith's RHS operand must already be in
				// scope (declared by an earlier statement).
				if st.SrcVar2 != "" && !declared[st.SrcVar2] {
					t.Errorf("seed %d stmt %d: Arith SrcVar2 %q not in scope",
						seed, si, st.SrcVar2)
				}
				if st.Var != "" {
					declared[st.Var] = true
				}
			case StmtKfuncCall:
				sawKfuncCall = true
				if st.KfuncIdx < 0 || st.KfuncIdx >= len(sop.Kfuncs) {
					t.Fatalf("seed %d stmt %d: KfuncIdx %d out of range",
						seed, si, st.KfuncIdx)
				}
				kf := &sop.Kfuncs[st.KfuncIdx]
				if len(st.KfuncArgs) != len(kf.ArgTypes) {
					t.Errorf("seed %d stmt %d: %s got %d args, want %d",
						seed, si, kf.Name, len(st.KfuncArgs),
						len(kf.ArgTypes))
				}
				for _, a := range st.KfuncArgs {
					if !fixedArgs[a] && !declared[a] {
						t.Errorf("seed %d stmt %d: %s arg %q is not "+
							"a typed, in-scope value",
							seed, si, kf.Name, a)
					}
				}
				// Verifier contract: KF_RET_NULL pointer -> guard.
				if ptrRetNull[kf.Name] {
					if !st.NullGuard {
						t.Errorf("seed %d stmt %d: %s is KF_RET_NULL "+
							"pointer but NullGuard is false",
							seed, si, kf.Name)
					}
					if st.Var == "" {
						t.Errorf("seed %d stmt %d: %s result not "+
							"bound to a local",
							seed, si, kf.Name)
					}
				}
				if st.NullGuard {
					sawGuard = true
				}
				if st.Var != "" {
					declared[st.Var] = true
				}
			}
		}

		// Render and confirm the verifier contract holds in the C:
		// for every KF_RET_NULL pointer call, the call line is
		// immediately followed by `if (!sN)` / `return -1;`, and the
		// local does not appear before that guard.
		src := p.Render()
		lines := strings.Split(src, "\n")
		for li, line := range lines {
			l := strings.TrimSpace(line)
			for kfName := range ptrRetNull {
				// A guarded call binds a local: `<type> sN = kfName(...)`.
				if !strings.Contains(l, " = "+kfName+"(") {
					continue
				}
				// Extract the bound local name (`sN`).
				eq := strings.Index(l, " = ")
				lhs := strings.Fields(strings.TrimSpace(l[:eq]))
				if len(lhs) == 0 {
					t.Errorf("seed %d: malformed kfunc-call line %q",
						seed, l)
					continue
				}
				local := lhs[len(lhs)-1]
				// The next two lines must be the mandatory guard.
				if li+2 >= len(lines) {
					t.Errorf("seed %d: %s call not followed by guard",
						seed, kfName)
					continue
				}
				g1 := strings.TrimSpace(lines[li+1])
				g2 := strings.TrimSpace(lines[li+2])
				if g1 != "if (!"+local+")" || g2 != "return -1;" {
					t.Errorf("seed %d: %s result %q not immediately "+
						"NULL-checked; got %q / %q",
						seed, kfName, local, g1, g2)
				}
			}
		}

		// The fixed prologue/epilogue must survive untouched.
		for _, frag := range []string{
			"subflow = bpf_iter_mptcp_subflow_next(&it)",
			"mptcp_subflow_set_scheduled(subflow, true)",
			"return 0;",
		} {
			if !strings.Contains(src, frag) {
				t.Errorf("seed %d: fixed skeleton fragment %q missing",
					seed, frag)
			}
		}

		// Every kfunc the body calls must have an `extern … __ksym;`
		// decl in the rendered source.
		for _, st := range sop.body("_get_send") {
			if st.Kind != StmtKfuncCall {
				continue
			}
			kfName := sop.Kfuncs[st.KfuncIdx].Name
			if !strings.Contains(src, "\n"+kfName+"(") &&
				!strings.Contains(src, " "+kfName+"(") {
				continue // referenced; extern presence checked next
			}
			if !strings.Contains(src, kfName) {
				t.Errorf("seed %d: kfunc %q called but no extern decl",
					seed, kfName)
			}
		}
	}

	if !sawKfuncCall {
		t.Error("no kfunc call generated across 256 seeds -- " +
			"Stage C-full Stage 1 generator is not firing")
	}
	if !sawGuard {
		t.Error("no KF_RET_NULL guard generated across 256 seeds -- " +
			"the pointer-return contract path is untested")
	}
}

// TestStructOpsSubflowIter is the Stage C-full Stage 2a check for the
// subflow iterator.  It asserts that:
//
//   - across many seeds the iterator is generated at least once;
//   - every generated SubflowIter statement carries the modelled
//     `(struct sock *)msk` socket expression and a loop variable;
//   - in the rendered C, every iterator is the COMPLETE
//     `new -> next* -> destroy` triple -- the count of `_new`, `_next`
//     and `_destroy` call-sites is consistent with that, the three
//     iterator kfuncs all have an `extern ... __ksym;` decl, and the
//     `while` condition is the KF_RET_NULL NULL-check on `_next`.
func TestStructOpsSubflowIter(t *testing.T) {
	sawIter := false
	// `(sfN = bpf_iter_mptcp_subflow_next(&itN))` -- the while-loop
	// condition: the next-call IS the NULL-check.
	whileCond := regexp.MustCompile(
		`while \(\(sf[0-9]+ = bpf_iter_mptcp_subflow_next\(&it[0-9]+\)\)\) \{`)

	for seed := int64(0); seed < 256; seed++ {
		p := newStructOpsTestProg(t, seed)
		sop := p.StructOps

		// Count SubflowIter statements across every body and validate
		// each one's model fields.
		nIter := 0
		for _, b := range [][]Stmt{
			sop.body("_get_send"), sop.body("_init"), sop.body("_release"),
		} {
			walkStmts(b, func(st *Stmt) {
				if st.Kind != StmtSubflowIter {
					return
				}
				nIter++
				if st.IterSockExpr != "(struct sock *)msk" {
					t.Errorf("seed %d: iter sock expr %q, want "+
						"%q", seed, st.IterSockExpr, "(struct sock *)msk")
				}
				if st.Var == "" {
					t.Errorf("seed %d: SubflowIter has no loop variable",
						seed)
				}
				if st.CType != "struct mptcp_subflow_context *" {
					t.Errorf("seed %d: iter loop var type %q, want "+
						"%q", seed, st.CType,
						"struct mptcp_subflow_context *")
				}
			})
		}
		// init/release must never iterate -- only get_send may.
		for _, b := range [][]Stmt{sop.body("_init"), sop.body("_release")} {
			for _, st := range b {
				if st.Kind == StmtSubflowIter {
					t.Errorf("seed %d: iterator generated in "+
						"init/release -- only get_send may iterate", seed)
				}
			}
		}
		if nIter == 0 {
			continue
		}
		sawIter = true

		// Rendered C: the iterator must be the complete triple.  Every
		// modelled SubflowIter renders exactly one `_new`, one
		// `_destroy` and one `_next` (the `while` condition), on top of
		// the ONE fixed prologue triple (`&it`) every get_send carries.
		// A partial iterator -- any of the three missing -- is a
		// verifier reject.
		src := p.Render()
		const prologueIters = 1
		want := nIter + prologueIters
		nNew := strings.Count(src, "bpf_iter_mptcp_subflow_new(&")
		nNext := strings.Count(src, "bpf_iter_mptcp_subflow_next(&")
		nDestroy := strings.Count(src, "bpf_iter_mptcp_subflow_destroy(&")
		if nNew != want || nNext != want || nDestroy != want {
			t.Errorf("seed %d: %d iterators modelled (+%d prologue) but "+
				"rendered new=%d next=%d destroy=%d -- not a complete triple\n%s",
				seed, nIter, prologueIters, nNew, nNext, nDestroy, src)
		}

		// The `while` condition must be the KF_RET_NULL NULL-check on
		// `_next` -- this is the verifier-required idiom.
		if got := len(whileCond.FindAllString(src, -1)); got != nIter {
			t.Errorf("seed %d: %d iterators but %d well-formed "+
				"while-conditions\n%s", seed, nIter, got, src)
		}

		// All three iterator kfuncs must have an extern decl.
		for _, kf := range []string{
			"bpf_iter_mptcp_subflow_new",
			"bpf_iter_mptcp_subflow_next",
			"bpf_iter_mptcp_subflow_destroy",
		} {
			if !strings.Contains(src, "extern") ||
				!strings.Contains(src, kf+"(") {
				t.Errorf("seed %d: iterator kfunc %q has no extern decl\n%s",
					seed, kf, src)
			}
		}

		// The iterator declaration and destroy must bracket the loop:
		// for each `_new(&itN, ...)` line there is a later
		// `_destroy(&itN)` line.  Per-iterator-id, _destroy follows
		// _new in source order.
		lines := strings.Split(src, "\n")
		idRe := regexp.MustCompile(`bpf_iter_mptcp_subflow_new\(&(it[0-9]+),`)
		for li, line := range lines {
			m := idRe.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			id := m[1]
			foundDestroy := false
			for _, later := range lines[li+1:] {
				if strings.Contains(later,
					"bpf_iter_mptcp_subflow_destroy(&"+id+")") {
					foundDestroy = true
					break
				}
			}
			if !foundDestroy {
				t.Errorf("seed %d: iterator %q has _new but no later "+
					"_destroy\n%s", seed, id, src)
			}
		}
	}

	if !sawIter {
		t.Error("no subflow iterator generated across 256 seeds -- " +
			"the Stage C-full Stage 2a iterator generator is not firing")
	}
}

// TestStructOpsInitReleaseBodies is the Stage C-full Stage 2a check for
// the non-empty init / release callbacks.  Before Stage 2a both were
// rendered with empty `{}`; now each gets a generated `msk`-reachable
// body.  The test asserts both bodies are non-empty in the model and
// the rendered C, that neither schedules
// (`mptcp_subflow_set_scheduled` is a get_send-only kfunc), and that
// the rendered callback bodies are not literally empty.
func TestStructOpsInitReleaseBodies(t *testing.T) {
	for seed := int64(0); seed < 128; seed++ {
		p := newStructOpsTestProg(t, seed)
		sop := p.StructOps

		if len(sop.body("_init")) == 0 {
			t.Errorf("seed %d: InitBody is empty", seed)
		}
		if len(sop.body("_release")) == 0 {
			t.Errorf("seed %d: ReleaseBody is empty", seed)
		}

		// init/release do not schedule -- mptcp_subflow_set_scheduled
		// must never be called from either body.
		for _, b := range []struct {
			name string
			body []Stmt
		}{
			{"InitBody", sop.body("_init")},
			{"ReleaseBody", sop.body("_release")},
		} {
			walkStmts(b.body, func(st *Stmt) {
				if st.Kind != StmtKfuncCall {
					return
				}
				if sop.Kfuncs[st.KfuncIdx].Name ==
					"mptcp_subflow_set_scheduled" {
					t.Errorf("seed %d: %s calls "+
						"mptcp_subflow_set_scheduled -- init/release "+
						"do not schedule", seed, b.name)
				}
			})
		}

		// Rendered C: the init/release callback bodies must contain a
		// generated statement, not just the `{ }` braces.  Extract the
		// brace-delimited body of each and confirm it is non-trivial.
		src := p.Render()
		for _, suffix := range []string{"_init", "_release"} {
			marker := "BPF_PROG(" + sop.SchedName + suffix +
				", struct mptcp_sock *msk)"
			idx := strings.Index(src, marker)
			if idx < 0 {
				t.Fatalf("seed %d: rendered source missing %q", seed, marker)
			}
			open := strings.Index(src[idx:], "{")
			closeBrace := strings.Index(src[idx:], "\n}")
			if open < 0 || closeBrace < 0 || closeBrace <= open {
				t.Fatalf("seed %d: malformed %s callback body", seed, suffix)
			}
			body := strings.TrimSpace(src[idx+open+1 : idx+closeBrace])
			// The body always carries the `/* BRF-generated body. */`
			// comment; require at least one further non-comment line.
			hasStmt := false
			for _, ln := range strings.Split(body, "\n") {
				ln = strings.TrimSpace(ln)
				if ln == "" || strings.HasPrefix(ln, "/*") {
					continue
				}
				hasStmt = true
			}
			if !hasStmt {
				t.Errorf("seed %d: %s callback body has no generated "+
					"statement\n%s", seed, suffix, src)
			}
		}
	}
}

// localDeclRe matches a generated local declaration -- `<type> sN = ...`
// or the iterator's `struct ... *sfN;` -- and captures the local name.
// The local types the generator emits are `int`, `unsigned long`,
// `bool`, `__u64`, `struct sock *` and `struct mptcp_subflow_context *`.
var localDeclRe = regexp.MustCompile(
	`^(?:int|unsigned long|bool|__u64|struct sock \*|` +
		`struct mptcp_subflow_context \*|struct bpf_iter_mptcp_subflow) ` +
		`(s[0-9]+|sf[0-9]+|it[0-9]+)\b`)

// localUseRe finds every `sN` / `sfN` / `itN` identifier token on a
// line, so a use-after-scope can be detected.
var localUseRe = regexp.MustCompile(`\b(s[0-9]+|sf[0-9]+|it[0-9]+)\b`)

// TestStructOpsIfElse is the Stage C-full Stage 2b check for generated
// free-form `if/else`.  It asserts that:
//
//   - across many seeds an `if/else` is generated at least once;
//   - the rendered C is brace-balanced and properly nested;
//   - no branch body emits a `return` (model and rendered C) -- so every
//     path falls through to the fixed scheduling epilogue;
//   - the condition tests an in-scope SCALAR local, never a pointer;
//   - a branch-local variable is never referenced after its branch
//     closes (C block scope -- no use-after-scope leak);
//   - generated `if/else` nesting never exceeds the depth cap.
func TestStructOpsIfElse(t *testing.T) {
	sawIfElse := false
	sawElse := false

	// Scalar locals: the only legal condition operands.  A condition
	// over anything else (a pointer local, or an undeclared name) is a
	// generator bug.
	scalarType := map[string]bool{
		"int": true, "unsigned long": true, "bool": true, "__u64": true,
	}

	for seed := int64(0); seed < 256; seed++ {
		p := newStructOpsTestProg(t, seed)
		sop := p.StructOps

		// Model walk: validate every IfElse statement and recurse.
		var checkIfElse func(path string, body []Stmt, depth int)
		checkIfElse = func(path string, body []Stmt, depth int) {
			for i, st := range body {
				switch st.Kind {
				case StmtIfElse:
					sawIfElse = true
					if len(st.ElseBody) > 0 {
						sawElse = true
					}
					if st.CondVar == "" {
						t.Errorf("seed %d %s[%d]: IfElse has no "+
							"condition variable", seed, path, i)
					}
					if depth >= ifElseMaxDepth {
						t.Errorf("seed %d %s[%d]: IfElse at depth %d "+
							"exceeds cap %d", seed, path, i, depth,
							ifElseMaxDepth)
					}
					if len(st.IfBody) == 0 {
						t.Errorf("seed %d %s[%d]: IfElse has empty "+
							"if-body", seed, path, i)
					}
					// No branch may emit a `return`: the only
					// return-emitting statement is a KF_RET_NULL-pointer
					// kfunc call (NullGuard).  Walk both branch bodies.
					for _, br := range [][]Stmt{
						st.IfBody, st.ElseBody,
					} {
						walkStmts(br, func(b *Stmt) {
							if b.Kind == StmtKfuncCall &&
								b.NullGuard {
								t.Errorf("seed %d %s[%d]: branch body "+
									"has a NullGuard kfunc call -- a "+
									"branch must not emit a return",
									seed, path, i)
							}
						})
					}
					checkIfElse(path+"["+itoa(i)+"].IfBody",
						st.IfBody, depth+1)
					checkIfElse(path+"["+itoa(i)+"].ElseBody",
						st.ElseBody, depth+1)
				case StmtSubflowIter:
					// An iterator inside a branch keeps the same depth
					// (the loop body is not an if/else level).
					checkIfElse(path+"["+itoa(i)+"].IterBody",
						st.IterBody, depth)
				}
			}
		}
		checkIfElse("GetSendBody", sop.body("_get_send"), 0)
		// init/release are straight-line (allowIf false) -- no IfElse
		// must ever appear there.
		for _, b := range []struct {
			name string
			body []Stmt
		}{{"InitBody", sop.body("_init")}, {"ReleaseBody", sop.body("_release")}} {
			walkStmts(b.body, func(st *Stmt) {
				if st.Kind == StmtIfElse {
					t.Errorf("seed %d: IfElse generated in %s -- "+
						"init/release are straight-line", seed, b.name)
				}
			})
		}

		if !usesIfElse(sop) {
			continue
		}

		src := p.Render()

		// Brace balance: across the whole rendered TU, `{` and `}`
		// counts match and the running depth never goes negative.
		depth := 0
		minDepth := 0
		for _, ch := range src {
			switch ch {
			case '{':
				depth++
			case '}':
				depth--
				if depth < minDepth {
					minDepth = depth
				}
			}
		}
		if depth != 0 {
			t.Errorf("seed %d: rendered C brace imbalance (net %d)\n%s",
				seed, depth, src)
		}
		if minDepth < 0 {
			t.Errorf("seed %d: rendered C has a `}` with no matching "+
				"`{`\n%s", seed, src)
		}

		// Condition operand must be a declared scalar local.  For each
		// IfElse, CondVar must name a local whose declared type is
		// scalar (never a pointer).
		declType := map[string]string{}
		for _, b := range [][]Stmt{
			sop.body("_get_send"), sop.body("_init"), sop.body("_release"),
		} {
			walkStmts(b, func(st *Stmt) {
				if st.Var != "" && st.CType != "" {
					declType[st.Var] = st.CType
				}
			})
		}
		walkStmts(sop.body("_get_send"), func(st *Stmt) {
			if st.Kind != StmtIfElse {
				return
			}
			ct, ok := declType[st.CondVar]
			if !ok {
				t.Errorf("seed %d: IfElse condition var %q is not a "+
					"declared local", seed, st.CondVar)
				return
			}
			if !scalarType[ct] {
				t.Errorf("seed %d: IfElse condition var %q has "+
					"non-scalar type %q -- conditions must be scalar",
					seed, st.CondVar, ct)
			}
			// A compound predicate's second clause must also test a
			// declared scalar local, with a real (non-empty) operator.
			if st.CondJoin != "" {
				if st.Cond2Op == "" {
					t.Errorf("seed %d: compound IfElse clause2 has empty "+
						"operator", seed)
				}
				ct2, ok2 := declType[st.Cond2Var]
				if !ok2 {
					t.Errorf("seed %d: IfElse Cond2Var %q is not a "+
						"declared local", seed, st.Cond2Var)
				} else if !scalarType[ct2] {
					t.Errorf("seed %d: IfElse Cond2Var %q has non-scalar "+
						"type %q", seed, st.Cond2Var, ct2)
				}
			}
		})

		// Rendered-C return check: a generated `if/else` block (its
		// opening line carries the `/* BRF-generated if/else. */`
		// comment) must contain no `return` until it closes.  Walk
		// lines, tracking brace depth; when inside an if/else block at
		// or below its opening depth, a `return` line is a leak.
		lines := strings.Split(src, "\n")
		ifElseDepths := []int{} // brace depths at which an if/else opened
		curDepth := 0
		for li, line := range lines {
			l := strings.TrimSpace(line)
			isIfElseOpen := li > 0 &&
				strings.Contains(strings.TrimSpace(lines[li-1]),
					"BRF-generated if/else.")
			// Count braces on this line to update depth.
			opens := strings.Count(line, "{")
			closes := strings.Count(line, "}")
			if isIfElseOpen && opens > 0 {
				ifElseDepths = append(ifElseDepths, curDepth)
			}
			if strings.HasPrefix(l, "return ") &&
				len(ifElseDepths) > 0 {
				t.Errorf("seed %d: `return` inside a generated "+
					"if/else branch\n%s", seed, src)
			}
			curDepth += opens - closes
			// Pop any if/else whose block has now closed.
			for len(ifElseDepths) > 0 &&
				curDepth <= ifElseDepths[len(ifElseDepths)-1] {
				ifElseDepths = ifElseDepths[:len(ifElseDepths)-1]
			}
		}

		// Scope-leak check on the rendered C: a local declared inside a
		// `{ }` block must not be referenced after that block closes.
		// Track a stack of per-block declared-local sets; on `}` the
		// top set's locals go out of scope, and any later use of one is
		// a use-after-scope leak.
		assertNoScopeLeak(t, seed, src)
	}

	if !sawIfElse {
		t.Error("no if/else generated across 256 seeds -- the Stage " +
			"C-full Stage 2b generator is not firing")
	}
	if !sawElse {
		t.Error("no if/else with an `else` branch generated across " +
			"256 seeds -- the optional-else path is untested")
	}
}

// TestStructOpsArithRichness is the A1 capability check for the enriched
// arithmetic generator.  Across many seeds it asserts that BOTH new
// forms fire and stay well-formed:
//
//   - a shift Arith (Op "<<"/">>") appears, and its shift amount Val is
//     always in [0,30] (a shift >= the operand width would be UB / a
//     verifier reject);
//   - a two-local Arith (SrcVar2 != "") appears, its RHS operand is a
//     previously-declared scalar local, and it never carries a shift Op
//     (shift RHS is always the bounded constant);
//   - the rendered C of a two-local Arith is `Var = SrcVar Op SrcVar2;`.
func TestStructOpsArithRichness(t *testing.T) {
	sawShift := false
	sawTwoLocal := false
	for seed := int64(0); seed < 256; seed++ {
		p := newStructOpsTestProg(t, seed)
		sop := p.StructOps
		// declType over the whole tree, for the in-scope-scalar check.
		declType := map[string]string{}
		for _, b := range [][]Stmt{
			sop.body("_get_send"), sop.body("_init"), sop.body("_release"),
		} {
			walkStmts(b, func(st *Stmt) {
				if st.Var != "" && st.CType != "" {
					declType[st.Var] = st.CType
				}
			})
		}
		scalar := map[string]bool{
			"int": true, "unsigned long": true, "bool": true,
			"__u64": true, "long": true,
		}
		for _, b := range [][]Stmt{
			sop.body("_get_send"), sop.body("_init"), sop.body("_release"),
		} {
			walkStmts(b, func(st *Stmt) {
				if st.Kind != StmtArith {
					return
				}
				isShift := st.Op == "<<" || st.Op == ">>"
				if isShift {
					sawShift = true
					if st.Val < 0 || st.Val > 30 {
						t.Errorf("seed %d: shift amount %d out of [0,30]",
							seed, st.Val)
					}
					if st.SrcVar2 != "" {
						t.Errorf("seed %d: shift Arith has a local RHS %q "+
							"-- shift amount must be the bounded constant",
							seed, st.SrcVar2)
					}
				}
				if st.SrcVar2 != "" {
					sawTwoLocal = true
					if isShift {
						t.Errorf("seed %d: two-local Arith with shift op %q",
							seed, st.Op)
					}
					if ct, ok := declType[st.SrcVar2]; !ok || !scalar[ct] {
						t.Errorf("seed %d: two-local Arith RHS %q is not a "+
							"declared scalar local (type %q, declared %v)",
							seed, st.SrcVar2, ct, ok)
					}
				}
			})
		}
		// Rendered C of a two-local Arith reads `Var = SrcVar Op SrcVar2;`.
		src := p.Render()
		walkStmts(sop.body("_get_send"), func(st *Stmt) {
			if st.Kind == StmtArith && st.SrcVar2 != "" {
				frag := st.Var + " = " + st.SrcVar + " " + st.Op + " " + st.SrcVar2 + ";"
				if !strings.Contains(src, frag) {
					t.Errorf("seed %d: two-local Arith not rendered as %q\n%s",
						seed, frag, src)
				}
			}
		})
	}
	if !sawShift {
		t.Error("no shift Arith generated across 256 seeds -- the A1 " +
			"shift-operator path is not firing")
	}
	if !sawTwoLocal {
		t.Error("no two-local Arith generated across 256 seeds -- the A1 " +
			"two-local arithmetic path is not firing")
	}
}

// TestStructOpsCompoundCond is the A1 capability check for compound
// `if/else` conditions.  Across many seeds it asserts that a compound
// predicate (CondJoin "&&"/"||") fires, its second clause is a real
// comparison over a declared scalar local, and the rendered C carries a
// parenthesised `(...) && (...)` / `|| ` inside a generated if/else.
func TestStructOpsCompoundCond(t *testing.T) {
	sawCompound := false
	for seed := int64(0); seed < 256; seed++ {
		p := newStructOpsTestProg(t, seed)
		sop := p.StructOps
		declType := map[string]string{}
		walkStmts(sop.body("_get_send"), func(st *Stmt) {
			if st.Var != "" && st.CType != "" {
				declType[st.Var] = st.CType
			}
		})
		scalar := map[string]bool{
			"int": true, "unsigned long": true, "bool": true, "__u64": true,
		}
		walkStmts(sop.body("_get_send"), func(st *Stmt) {
			if st.Kind != StmtIfElse || st.CondJoin == "" {
				return
			}
			sawCompound = true
			if st.CondJoin != "&&" && st.CondJoin != "||" {
				t.Errorf("seed %d: bad CondJoin %q", seed, st.CondJoin)
			}
			if st.Cond2Op == "" {
				t.Errorf("seed %d: compound clause2 has empty operator", seed)
			}
			if ct, ok := declType[st.Cond2Var]; !ok || !scalar[ct] {
				t.Errorf("seed %d: Cond2Var %q not a declared scalar "+
					"(type %q, declared %v)", seed, st.Cond2Var, ct, ok)
			}
			src := p.Render()
			if !strings.Contains(src, " "+st.CondJoin+" ") {
				t.Errorf("seed %d: rendered C lacks the %q connective\n%s",
					seed, st.CondJoin, src)
			}
		})
	}
	if !sawCompound {
		t.Error("no compound if/else condition generated across 256 " +
			"seeds -- the A1 compound-condition path is not firing")
	}
}

// newCCTestProg builds a tcp_congestion_ops struct_ops program via the
// generalized generator + the CC surface.
func newCCTestProg(t *testing.T, seed int64) *testProg {
	t.Helper()
	return &testProg{StructOps: generate(newTestRand(seed), TCPCong)}
}

// TestStructOpsTCPCong is the A2 second-surface check: it drives the
// generalized struct_ops generator through the tcp_congestion_ops surface
// and asserts the CC contract grounded in the kernel tree
// (net/ipv4/bpf_tcp_ca.c, include/net/tcp.h, the bpf_dctcp.c selftest):
//
//   - the generated name fits TCP_CA_NAME_MAX;
//   - the rendered TU has the CC instance, the three required ops, the
//     `tcp_sk(sk)` working-pointer derivation, and the `.name` field;
//   - ssthresh / undo_cwnd bodies end in a `return ...;`;
//   - every ctx WRITE lvalue is one of the three writable tcp_sock
//     fields reached via `tp->` -- no write outside the surface;
//   - at least one CC kfunc call is generated across the seeds, and its
//     args are in-scope locals (`sk` / `tp` / an `sN`) or fuzzer literals.
func TestStructOpsTCPCong(t *testing.T) {
	// CC writable surface: the only legal write lvalues.
	ccWritable := map[string]bool{
		"tp->snd_cwnd": true, "tp->snd_ssthresh": true,
		"tp->snd_cwnd_cnt": true,
	}
	// Legal kfunc-arg fixed values: the two seed-pool locals.  An `sN`
	// local or a decimal literal is also legal.
	ccFixedArgs := map[string]bool{"sk": true, "tp": true}
	litRe := regexp.MustCompile(`^[0-9]+$`)

	sawKfuncCall := false
	for seed := int64(0); seed < 256; seed++ {
		p := newCCTestProg(t, seed)
		sop := p.StructOps

		if sop.Surface != "tcp_cong" {
			t.Fatalf("seed %d: Surface = %q, want %q",
				seed, sop.Surface, "tcp_cong")
		}
		name := sop.SchedName
		if name == "" || len(name) >= 16 {
			t.Errorf("seed %d: SchedName %q outside TCP_CA_NAME_MAX",
				seed, name)
		}

		src := p.Render()
		mustContain := []string{
			"#include \"vmlinux.h\"",
			"struct tcp_congestion_ops " + name + " = {",
			"BPF_PROG(" + name + "_ssthresh, struct sock *sk)",
			"BPF_PROG(" + name + "_cong_avoid, struct sock *sk, __u32 ack, __u32 acked)",
			"BPF_PROG(" + name + "_undo_cwnd, struct sock *sk)",
			"tcp_sk(sk)",
			".name\t\t= \"" + name + "\",",
			"SEC(\".struct_ops\")",
		}
		for _, frag := range mustContain {
			if !strings.Contains(src, frag) {
				t.Errorf("seed %d: rendered CC source missing %q\n---\n%s",
					seed, frag, src)
			}
		}

		// ssthresh / undo_cwnd must end in a `return ...;` -- the fixed
		// non-void epilogue.  Locate each callback body and confirm its
		// last non-blank line is a return.
		for _, suffix := range []string{"_ssthresh", "_undo_cwnd"} {
			marker := "BPF_PROG(" + name + suffix + ", struct sock *sk)"
			idx := strings.Index(src, marker)
			if idx < 0 {
				t.Fatalf("seed %d: rendered source missing %q", seed, marker)
			}
			open := strings.Index(src[idx:], "{")
			closeBrace := strings.Index(src[idx:], "\n}")
			if open < 0 || closeBrace < 0 || closeBrace <= open {
				t.Fatalf("seed %d: malformed %s callback body", seed, suffix)
			}
			body := src[idx+open+1 : idx+closeBrace]
			var lastLine string
			for _, ln := range strings.Split(body, "\n") {
				if strings.TrimSpace(ln) != "" {
					lastLine = strings.TrimSpace(ln)
				}
			}
			if !strings.HasPrefix(lastLine, "return ") ||
				!strings.HasSuffix(lastLine, ";") {
				t.Errorf("seed %d: %s body does not end in a return; got %q",
					seed, suffix, lastLine)
			}
		}

		// Every ctx WRITE lvalue must be in the CC writable surface.  A
		// write reaches the verifier as `<lvalue> = `; declarations
		// (`unsigned int sN = ...`, `__u32 sN = ...`) are reads, skipped.
		for _, line := range strings.Split(src, "\n") {
			l := strings.TrimSpace(line)
			eq := strings.Index(l, " = ")
			arrow := strings.Index(l, "->")
			if eq == -1 || arrow == -1 || arrow > eq {
				continue
			}
			lvalue := strings.TrimSpace(l[:eq])
			if strings.HasPrefix(lvalue, "unsigned int ") ||
				strings.HasPrefix(lvalue, "__u32 ") ||
				strings.HasPrefix(lvalue, "struct ") {
				continue // a declaration, not a ctx write
			}
			if !ccWritable[lvalue] {
				t.Errorf("seed %d: write to non-writable CC lvalue %q",
					seed, lvalue)
			}
		}

		// Model walk: validate every KfuncCall references a CC kfunc and
		// passes only in-scope locals or literals.  `sN` locals declared
		// by an earlier statement are in scope.
		for ci := range sop.Callbacks {
			declared := map[string]bool{}
			walkStmts(sop.Callbacks[ci].Body, func(st *Stmt) {
				switch st.Kind {
				case StmtCtxRead, StmtArith:
					if st.Var != "" {
						declared[st.Var] = true
					}
				case StmtKfuncCall:
					sawKfuncCall = true
					if st.KfuncIdx < 0 || st.KfuncIdx >= len(sop.Kfuncs) {
						t.Fatalf("seed %d: KfuncIdx %d out of range",
							seed, st.KfuncIdx)
					}
					kf := &sop.Kfuncs[st.KfuncIdx]
					if len(st.KfuncArgs) != len(kf.ArgTypes) {
						t.Errorf("seed %d: %s got %d args, want %d",
							seed, kf.Name, len(st.KfuncArgs), len(kf.ArgTypes))
					}
					for _, a := range st.KfuncArgs {
						if ccFixedArgs[a] || declared[a] || litRe.MatchString(a) {
							continue
						}
						t.Errorf("seed %d: %s arg %q is not an in-scope "+
							"local or literal", seed, kf.Name, a)
					}
					// CC kfuncs never return a KF_RET_NULL pointer -- no
					// NullGuard must ever be set.
					if st.NullGuard {
						t.Errorf("seed %d: %s carries a NullGuard -- no CC "+
							"kfunc is a KF_RET_NULL pointer", seed, kf.Name)
					}
					if st.Var != "" {
						declared[st.Var] = true
					}
				}
			})
		}
	}

	if !sawKfuncCall {
		t.Error("no CC kfunc call generated across 256 seeds -- the " +
			"scalar-arg kfunc path is not firing for tcp_congestion_ops")
	}
}

// TestStructOpsTCPCongGobRoundTrip confirms a generated CC program
// survives a gob round-trip intact (the Surface tag, callbacks, and every
// callback body), since rendering happens after deserialization.
func TestStructOpsTCPCongGobRoundTrip(t *testing.T) {
	for _, seed := range []int64{1, 3, 7} {
		p := newCCTestProg(t, seed)
		q := gobRoundTrip(t, seed, p)
		if q.StructOps == nil {
			t.Fatalf("seed %d: StructOps lost across gob round-trip", seed)
		}
		if q.StructOps.Surface != p.StructOps.Surface {
			t.Errorf("seed %d: Surface: got %q want %q",
				seed, q.StructOps.Surface, p.StructOps.Surface)
		}
		if q.StructOps.SchedName != p.StructOps.SchedName {
			t.Errorf("seed %d: SchedName: got %q want %q",
				seed, q.StructOps.SchedName, p.StructOps.SchedName)
		}
		if len(q.StructOps.Callbacks) != len(p.StructOps.Callbacks) {
			t.Fatalf("seed %d: Callbacks len: got %d want %d",
				seed, len(q.StructOps.Callbacks), len(p.StructOps.Callbacks))
		}
		for _, suffix := range []string{"_ssthresh", "_cong_avoid", "_undo_cwnd"} {
			cmpStmts(t, "CC"+suffix,
				p.StructOps.body(suffix), q.StructOps.body(suffix))
		}
		// The rendered C must be identical before and after the round-trip.
		if p.Render() != q.Render() {
			t.Errorf("seed %d: CC render differs after gob round-trip", seed)
		}
	}
}

// TestStructOpsHelpers is the C2 unit coverage for the small pure helpers
// the surface-driven generator relies on -- previously exercised only
// indirectly through the render tests.  Locking their contracts down
// guards the type-matching the kfunc-call generator depends on.
func TestStructOpsHelpers(t *testing.T) {
	// normalizeCType strips any leading const (repeatedly), nothing else.
	for in, want := range map[string]string{
		"const struct sock *":             "struct sock *",
		"struct sock *":                   "struct sock *",
		"const const struct mptcp_sock *": "struct mptcp_sock *",
		"__u32":                           "__u32",
		"":                                "",
	} {
		if got := normalizeCType(in); got != want {
			t.Errorf("normalizeCType(%q) = %q, want %q", in, got, want)
		}
	}

	// scalarCType: true for the integer-like types (incl. the A2-added
	// __u32/u32/unsigned int the CC kfuncs use), false for pointers/structs.
	scalars := []string{"int", "unsigned long", "bool", "__u64", "u64",
		"long", "unsigned int", "__u32", "u32", "const __u32"}
	for _, ct := range scalars {
		if !scalarCType(ct) {
			t.Errorf("scalarCType(%q) = false, want true", ct)
		}
	}
	for _, ct := range []string{"struct sock *", "struct mptcp_sock *",
		"struct tcp_sock *", "void", "char *"} {
		if scalarCType(ct) {
			t.Errorf("scalarCType(%q) = true, want false", ct)
		}
	}
}

// TestStructOpsPickKfuncArgs covers pickKfuncArgs directly, including the
// A2-added scalar-integer satisfaction (an integer parameter is satisfied
// by an in-scope scalar local OR a fuzzer literal) and the failure path
// (a pointer parameter with no matching in-scope value).
func TestStructOpsPickKfuncArgs(t *testing.T) {
	r := newTestRand(1)

	// A pointer param present in the pool is satisfied by that value.
	kfPtr := &Kfunc{Name: "k", ArgTypes: []string{"struct sock *"}}
	pool := []typedVal{{expr: "sk", ctype: "struct sock *"}}
	args, ok := pickKfuncArgs(r, kfPtr, pool)
	if !ok || len(args) != 1 || args[0] != "sk" {
		t.Errorf("pointer arg: ok=%v args=%v, want ok=true [sk]", ok, args)
	}

	// A pointer param NOT in the pool fails (no literal substitute for ptrs).
	if _, ok := pickKfuncArgs(r, kfPtr, []typedVal{
		{expr: "tp", ctype: "struct tcp_sock *"}}); ok {
		t.Error("pointer arg with no matching pool value: ok=true, want false")
	}

	// A scalar-integer param is satisfiable even from an empty pool (the
	// fuzzer-literal fallback) -- this is what lets the CC kfuncs with
	// __u32 args (ack/acked/w) be generated.
	kfScalar := &Kfunc{Name: "k2", ArgTypes: []string{"__u32", "__u32"}}
	args, ok = pickKfuncArgs(r, kfScalar, nil)
	if !ok || len(args) != 2 {
		t.Fatalf("scalar args from empty pool: ok=%v args=%v, want ok=true, 2 args",
			ok, args)
	}
	for _, a := range args {
		if a == "" {
			t.Errorf("scalar arg is empty; want an in-scope local or literal")
		}
	}
}

// TestStructOpsSurfaceRegistry checks the tag->surface registry and the
// per-surface name discipline: both registered surfaces resolve, carry the
// expected instance struct type, and generate names within their cap.
func TestStructOpsSurfaceRegistry(t *testing.T) {
	want := map[string]string{
		"mptcp_sched": "struct mptcp_sched_ops",
		"tcp_cong":    "struct tcp_congestion_ops",
	}
	for tag, instStruct := range want {
		surf, ok := surfaces[tag]
		if !ok {
			t.Errorf("surface tag %q not in registry", tag)
			continue
		}
		if surf.instanceStruct != instStruct {
			t.Errorf("surface %q instanceStruct = %q, want %q",
				tag, surf.instanceStruct, instStruct)
		}
		// Generate stamps Surface, and sop.surface()
		// must resolve back to this same descriptor.
		r := newTestRand(5)
		sop := generate(r, surf)
		if sop.Surface != tag {
			t.Errorf("surface %q: Surface tag = %q", tag, sop.Surface)
		}
		if sop.surface() != surf {
			t.Errorf("surface %q: sop.surface() did not resolve back", tag)
		}
		if len(sop.SchedName) == 0 || len(sop.SchedName) >= surf.nameMax {
			t.Errorf("surface %q: name %q violates cap %d",
				tag, sop.SchedName, surf.nameMax)
		}
	}
	// An unknown tag falls back to the MPTCP surface (the documented
	// default), never nil.
	stray := &Prog{Surface: "no_such_surface"}
	if stray.surface() != MptcpSched {
		t.Error("unknown surface tag did not fall back to MptcpSched")
	}
}

// TestStructOpsGolden is the port-fidelity oracle.  Each hash is sha256
// over the concatenated render of seeds 0..255 (each seeded with
// math/rand.NewSource(seed)), computed on the BRF fork
// (prog/brf_structops.go at brf HEAD ae620fde4) by this same procedure
// immediately before the import.  A mismatch means the generator's draw
// sequence or rendered text diverged from the fork.  Update a hash only
// with a deliberate generator change, and say so in the commit.
func TestStructOpsGolden(t *testing.T) {
	const seeds = 256
	for _, tc := range []struct {
		surf *Surface
		gen  func(*randGen) *Prog
		want string
	}{
		{
			surf: MptcpSched,
			// The fork's production entry point (genStructOpsProg).
			// Re-pinned 2026-10 with the iterator-prologue / current-kfunc
			// surface (see the "Re-pin" note in structops.go); the fork's
			// hash was eccdcc55d70fcb5ecd02bd69c2a356e8bd526dc6c1f861ac9eda86d647148579.
			gen:  generateMptcp,
			want: "a2a20c95c8619ab36d9a38fba6a2a0f85051937202413e4e0691c8cd811b75c1",
		},
		{
			surf: TCPCong,
			gen:  func(r *randGen) *Prog { return generate(r, TCPCong) },
			want: "68640057073c8c8cf6936526ddb585e8c73c256776c035247a4aa6fc2a1d838a",
		},
	} {
		h := sha256.New()
		for seed := int64(0); seed < seeds; seed++ {
			h.Write([]byte(tc.gen(newTestRand(seed)).Render()))
		}
		if got := fmt.Sprintf("%x", h.Sum(nil)); got != tc.want {
			t.Errorf("%s: golden hash over seeds [0,%d) = %s, want %s "+
				"(render diverged from the BRF fork)", tc.surf.tag, seeds, got, tc.want)
		}
	}
	// The exported entry point wraps a bare *rand.Rand in randGen; that
	// wrapping must be transparent, i.e. Generate is the golden path.
	for seed := int64(0); seed < 32; seed++ {
		want := generateMptcp(newTestRand(seed)).Render()
		got := Generate(rand.New(rand.NewSource(seed)), MptcpSched).Render()
		if got != want {
			t.Fatalf("seed %d: Generate(*rand.Rand) differs from the golden path", seed)
		}
	}
}

// TestStructOpsByTag covers the exported surface lookup the SpecialTypes
// glue (sys/linux/init_structops.go) resolves blob types through.
func TestStructOpsByTag(t *testing.T) {
	for tag, want := range map[string]*Surface{
		"mptcp_sched": MptcpSched,
		"tcp_cong":    TCPCong,
	} {
		if got := ByTag(tag); got != want {
			t.Errorf("ByTag(%q) = %v, want %v", tag, got, want)
		}
		if want.Tag() != tag {
			t.Errorf("%q.Tag() = %q", tag, want.Tag())
		}
	}
	if ByTag("no_such_surface") != nil {
		t.Error("ByTag(unknown) != nil")
	}
}

// assertNoScopeLeak verifies that no generated local is referenced
// after the `{ }` block it was declared in has closed -- the C
// block-scope correctness invariant for Stage 2b's branch bodies.  It
// walks the rendered C maintaining a stack of brace-scopes, each
// carrying the locals declared directly in it; a `}` pops the scope and
// retires its locals; a reference to a retired local fails the test.
func assertNoScopeLeak(t *testing.T, seed int64, src string) {
	t.Helper()
	// scopes is a stack of declared-local sets, one per open `{`.
	var scopes []map[string]bool
	retired := map[string]bool{} // locals whose scope has closed
	push := func() { scopes = append(scopes, map[string]bool{}) }
	pop := func() {
		if len(scopes) == 0 {
			return
		}
		top := scopes[len(scopes)-1]
		for name := range top {
			retired[name] = true
		}
		scopes = scopes[:len(scopes)-1]
	}
	declareHere := func(name string) {
		if len(scopes) > 0 {
			scopes[len(scopes)-1][name] = true
		}
		// A name re-entering scope (fresh block) is no longer retired.
		delete(retired, name)
	}

	for _, raw := range strings.Split(src, "\n") {
		line := raw
		l := strings.TrimSpace(line)
		// A declaration introduces a local into the current scope.  Do
		// this before the use-check so a `int s0 = s0 ...` self-ref
		// (which the generator never emits) would still not false-fail.
		if m := localDeclRe.FindStringSubmatch(l); m != nil {
			// The local is declared in whatever scope is current when
			// the `{` of its block has already been pushed.
			declareHere(m[1])
		}
		// Any use of a retired local on this line is a leak.
		for _, m := range localUseRe.FindAllStringSubmatch(l, -1) {
			if retired[m[1]] {
				t.Errorf("seed %d: local %q used after its block "+
					"closed (use-after-scope)\n%s",
					seed, m[1], src)
			}
		}
		// Update the scope stack for braces on this line.  A line may
		// carry both (`} else {`); process left to right.
		for _, ch := range line {
			switch ch {
			case '{':
				push()
			case '}':
				pop()
			}
		}
	}
}
