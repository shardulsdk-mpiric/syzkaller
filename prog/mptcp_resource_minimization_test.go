// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found
// in the LICENSE file.

package prog

import (
	"strings"
	"testing"
)

// Empirical validation of the "REPRO-BY-CONSTRUCTION" design claim for the
// clean MPTCP harness (sys/linux/socket_mptcp_flow.txt,
// executor/common_linux_mptcp.h): because every cross-call dependency is
// modeled as a real syzkaller RESOURCE --
//
//	syz_mptcp_pair_init()      -> produces mptcp_pair
//	syz_mptcp_join_subflow(p)  -> consumes mptcp_pair, produces mptcp_subflow
//	syz_mptcp_subflow_destroy(s) -> consumes mptcp_subflow
//	syz_mptcp_pair_close(p)    -> consumes mptcp_pair
//
// the claim is that syzkaller's program minimizer never orphans load-bearing
// state under a producer -- i.e. it won't drop syz_mptcp_pair_init while
// syz_mptcp_join_subflow still needs the pair it produces, and won't drop
// syz_mptcp_join_subflow while syz_mptcp_subflow_destroy still needs the
// subflow it produces. This is the exact failure mode the old BRF
// opaque-intptr-index design was exposed to (an index into a private pool
// with no syzkaller-visible producer/consumer edge, which the minimizer or
// mutator could silently break).
//
// The base program under test mirrors sys/linux/test/mptcp_join_subflow:
//
//	r0 = syz_mptcp_pair_init(...)
//	r1 = syz_mptcp_join_subflow(r0, 0x1, 0x0)
//	syz_mptcp_subflow_destroy(r1)
//	syz_mptcp_pair_close(r0)
const mptcpMinimizationBaseProg = `
r0 = syz_mptcp_pair_init(&AUTO={0x2, 0x0, @loopback}, &AUTO={0x2, 0x0, @loopback}, 0x0)
r1 = syz_mptcp_join_subflow(r0, 0x1, 0x0)
syz_mptcp_subflow_destroy(r1)
syz_mptcp_pair_close(r0)
`

func mptcpMinimizationTarget(t *testing.T) *Target {
	target, err := GetTarget("linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func mptcpDeserializeBase(t *testing.T, target *Target) *Prog {
	p, err := target.Deserialize([]byte(strings.TrimSpace(mptcpMinimizationBaseProg)), Strict)
	if err != nil {
		t.Fatalf("failed to deserialize base mptcp program: %v", err)
	}
	if len(p.Calls) != 4 {
		t.Fatalf("expected 4 calls in base program, got %v:\n%s", len(p.Calls), p.Serialize())
	}
	return p
}

func callNames(p *Prog) []string {
	names := make([]string, len(p.Calls))
	for i, c := range p.Calls {
		names[i] = c.Meta.Name
	}
	return names
}

func containsCall(p *Prog, name string) bool {
	for _, c := range p.Calls {
		if c.Meta.Name == name {
			return true
		}
	}
	return false
}

// hasOrphanedResourceArg reports whether any resource-typed argument
// anywhere in the program is in its "default" state (Res == nil, i.e. a
// bare constant instead of a live producer link). It is the structural
// stand-in, in this Go-only/no-VM test, for what a real behavioral
// predicate (crash reproduction, coverage match) would notice on its own:
// a pseudo-syscall driven from a defaulted/poison resource value behaves
// differently (the harness's own out-of-range/"not in use" checks make it
// fail outright -- see syz_mptcp_join_subflow / syz_mptcp_subflow_destroy
// in executor/common_linux_mptcp.h) from one driven by the real handle.
//
// Only the call's *input* arguments (c.Args) are examined -- not c.Ret.
// c.Ret is the slot where a call DEFINES/produces a brand new resource
// instance, so Res == nil there is normal (there is nothing upstream for a
// producer's own Ret to point to); it is only a sign of orphaning on a
// consuming argument, where the original, properly-linked program had a
// real producer wired in.
func hasOrphanedResourceArg(p *Prog) bool {
	orphaned := false
	visit := func(arg Arg, _ *ArgCtx) {
		res, ok := arg.(*ResultArg)
		if !ok {
			return
		}
		if _, ok := res.Type().(*ResourceType); !ok {
			return
		}
		if res.Res == nil {
			orphaned = true
		}
	}
	for _, c := range p.Calls {
		for _, arg := range c.Args {
			ForeachSubArg(arg, visit)
		}
	}
	return orphaned
}

// TestMPTCPMinimizationRetainsResourceChain is PART 2(a): with a predicate
// that requires syz_mptcp_subflow_destroy to be present *and reachable
// through an unbroken resource chain* (the structural proxy for "still
// behaves the way the interesting case needs it to"), the minimizer must
// retain both syz_mptcp_join_subflow (produces the subflow subflow_destroy
// consumes) and syz_mptcp_pair_init (produces the pair join_subflow
// consumes) -- their produced resources are consumed downstream, so they
// cannot be dropped without breaking the resource graph the predicate is
// watching.
func TestMPTCPMinimizationRetainsResourceChain(t *testing.T) {
	target := mptcpMinimizationTarget(t)
	p := mptcpDeserializeBase(t, target)

	pred := func(p *Prog, callIndex int) bool {
		return containsCall(p, "syz_mptcp_subflow_destroy") && !hasOrphanedResourceArg(p)
	}

	p1, _ := Minimize(p, -1, MinimizeCallsOnly, pred)

	got := callNames(p1)
	want := []string{"syz_mptcp_pair_init", "syz_mptcp_join_subflow", "syz_mptcp_subflow_destroy"}
	if len(got) != len(want) {
		t.Fatalf("minimized program has wrong call set: got %v, want %v\nserialized:\n%s",
			got, want, p1.Serialize())
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("minimized program has wrong call set: got %v, want %v\nserialized:\n%s",
				got, want, p1.Serialize())
		}
	}
	// syz_mptcp_pair_close was not required by the predicate and should be
	// droppable (this is the trailing, genuinely-unneeded cleanup call).
	if containsCall(p1, "syz_mptcp_pair_close") {
		t.Errorf("expected syz_mptcp_pair_close to be dropped (not required by predicate), got:\n%s", p1.Serialize())
	}
	if hasOrphanedResourceArg(p1) {
		t.Errorf("minimized program has an orphaned (defaulted) resource argument, "+
			"resource graph was NOT honored:\n%s", p1.Serialize())
	}

	// Directly verify the resource chain survives call-by-call, not just
	// "no orphaned arg anywhere": join_subflow's pair argument must still
	// be Res-linked to pair_init's Ret, and subflow_destroy's argument must
	// still be Res-linked to join_subflow's Ret.
	pairInit, joinSubflow, subflowDestroy := p1.Calls[0], p1.Calls[1], p1.Calls[2]
	joinPairArg, ok := joinSubflow.Args[0].(*ResultArg)
	if !ok || joinPairArg.Res != pairInit.Ret {
		t.Errorf("syz_mptcp_join_subflow's pair argument is not linked to syz_mptcp_pair_init's resource")
	}
	destroyArg, ok := subflowDestroy.Args[0].(*ResultArg)
	if !ok || destroyArg.Res != joinSubflow.Ret {
		t.Errorf("syz_mptcp_subflow_destroy's argument is not linked to syz_mptcp_join_subflow's resource")
	}
}

// TestMPTCPMinimizationDropsUnneededSubflow is PART 2(b): with a predicate
// that only needs syz_mptcp_pair_close (plus the same resource-chain
// soundness check), the minimizer CAN and DOES drop
// syz_mptcp_join_subflow + syz_mptcp_subflow_destroy entirely -- this is
// the soundness check in the other direction: the resource model does not
// pin down calls that are genuinely unrelated to what the predicate cares
// about.
func TestMPTCPMinimizationDropsUnneededSubflow(t *testing.T) {
	target := mptcpMinimizationTarget(t)
	p := mptcpDeserializeBase(t, target)

	pred := func(p *Prog, callIndex int) bool {
		return containsCall(p, "syz_mptcp_pair_close") && !hasOrphanedResourceArg(p)
	}

	p1, _ := Minimize(p, -1, MinimizeCallsOnly, pred)

	got := callNames(p1)
	want := []string{"syz_mptcp_pair_init", "syz_mptcp_pair_close"}
	if len(got) != len(want) {
		t.Fatalf("minimized program has wrong call set: got %v, want %v\nserialized:\n%s",
			got, want, p1.Serialize())
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("minimized program has wrong call set: got %v, want %v\nserialized:\n%s",
				got, want, p1.Serialize())
		}
	}
	if containsCall(p1, "syz_mptcp_join_subflow") || containsCall(p1, "syz_mptcp_subflow_destroy") {
		t.Errorf("expected join_subflow/subflow_destroy to be dropped as genuinely unneeded, got:\n%s",
			p1.Serialize())
	}
	// pair_init must survive too: pair_close (which the predicate pins) still
	// consumes its resource.
	pairInit, pairClose := p1.Calls[0], p1.Calls[1]
	closeArg, ok := pairClose.Args[0].(*ResultArg)
	if !ok || closeArg.Res != pairInit.Ret {
		t.Errorf("syz_mptcp_pair_close's argument is not linked to syz_mptcp_pair_init's resource")
	}
}

// TestMPTCPMinimizationNaivePresencePredicateIsInsufficient documents an
// important nuance found while validating the REPRO-BY-CONSTRUCTION claim:
// a predicate that only checks whether a call *name* is still present in
// the program (rather than whether its resource argument is still a live
// producer link) is NOT enough to make the minimizer honor the resource
// graph. Call.RemoveCall() does not refuse to remove a producer whose
// resource is still referenced elsewhere -- it silently rewrites every
// remaining reference to that resource to the type's default ("poison")
// constant (see (t *ResourceType).DefaultArg / removeArg /
// replaceResultArg in prog/prog.go and prog/types.go) and lets the
// consuming call stay in the program with a broken argument.
//
// In real usage this is harmless because the predicates that actually
// drive minimization (crash reproduction, coverage match) are behavioral:
// a pseudo-syscall fed a poisoned/default resource value behaves
// differently (the harness's own bounds/"not in use" checks make it fail),
// so a behavioral predicate rejects the reduction on its own. But a
// predicate that is purely structural over call names, with no sensitivity
// to argument validity, provides no such protection by itself. This test
// pins down that failure mode so it isn't silently assumed away: it is not
// a bug in the harness or in syzkaller, but it is a real caveat on how the
// REPRO-BY-CONSTRUCTION guarantee is actually delivered (by the
// *combination* of real resources plus a validity-sensitive predicate, not
// by resources alone).
func TestMPTCPMinimizationNaivePresencePredicateIsInsufficient(t *testing.T) {
	target := mptcpMinimizationTarget(t)
	p := mptcpDeserializeBase(t, target)

	// Deliberately naive: presence of the call name only, no check on
	// whether its argument is still a live resource link.
	pred := func(p *Prog, callIndex int) bool {
		return containsCall(p, "syz_mptcp_subflow_destroy")
	}

	p1, _ := Minimize(p, -1, MinimizeCallsOnly, pred)

	got := callNames(p1)
	// The naive predicate is satisfied by a single leftover
	// syz_mptcp_subflow_destroy call whose argument has been silently
	// replaced by the resource type's default value -- pair_init and
	// join_subflow both get dropped out from underneath it. This is
	// exactly the orphaning failure the resource model is supposed to
	// prevent; it happens here because the predicate itself carries no
	// information about resource validity.
	if len(got) != 1 || got[0] != "syz_mptcp_subflow_destroy" {
		t.Fatalf("expected the naive predicate to (wrongly) over-minimize to a lone "+
			"syz_mptcp_subflow_destroy call, got %v:\n%s", got, p1.Serialize())
	}
	if !hasOrphanedResourceArg(p1) {
		t.Fatalf("expected the surviving syz_mptcp_subflow_destroy call to carry an " +
			"orphaned (defaulted) resource argument, but none was found")
	}
	arg, ok := p1.Calls[0].Args[0].(*ResultArg)
	if !ok || arg.Res != nil {
		t.Fatalf("expected syz_mptcp_subflow_destroy's argument to be defaulted (Res == nil), "+
			"got Res=%v", arg)
	}
	t.Logf("naive presence-only predicate over-minimized base program to: %s", p1.Serialize())
}
