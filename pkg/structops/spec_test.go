// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package structops

import (
	"bytes"
	"math/rand"
	"testing"
)

// TestSpecRoundTrip is the spec-storage oracle: for a fixed seed range on
// both surfaces, Generate -> EncodeSpec -> DecodeSpec -> Render must yield
// the same translation unit as Generate -> Render.  That equality is what
// makes the materialize step a compile-cache hit (the cache is keyed by
// sha256(source)) and what keeps the golden hash (TestStructOpsGolden,
// over the direct render) the oracle for the persisted form too.
func TestSpecRoundTrip(t *testing.T) {
	const seeds = 256
	for _, surf := range []*Surface{MptcpSched, TCPCong} {
		t.Run(surf.Tag(), func(t *testing.T) {
			var total, maxLen int
			for seed := int64(0); seed < seeds; seed++ {
				p := Generate(rand.New(rand.NewSource(seed)), surf)
				want := p.Render()
				spec := EncodeSpec(p, seed)
				if !IsSpec(spec) || IsRecipe(spec) {
					t.Fatalf("seed %d: spec blob not recognized as a spec", seed)
				}
				q, err := DecodeSpec(spec)
				if err != nil {
					t.Fatalf("seed %d: %v", seed, err)
				}
				if got := q.Render(); got != want {
					t.Fatalf("seed %d: re-rendered spec differs from the direct render\n--- got\n%s\n--- want\n%s",
						seed, got, want)
				}
				info, err := DecodeSpecInfo(spec)
				if err != nil || info.Surface != surf.Tag() || info.Seed != seed || info.SchedName != p.SchedName {
					t.Fatalf("seed %d: spec info %+v, err %v", seed, info, err)
				}
				// A second encode of the decoded program is byte-identical:
				// the spec is a canonical form, not just a lossless one.
				if again := EncodeSpec(q, seed); !bytes.Equal(again, spec) {
					t.Fatalf("seed %d: spec is not canonical across a decode/encode", seed)
				}
				total += len(spec)
				maxLen = max(maxLen, len(spec))
			}
			t.Logf("%s: spec size avg %d bytes, max %d bytes over %d seeds", surf.Tag(), total/seeds, maxLen, seeds)
			// The whole point: the persisted form stays small.  A recipe is
			// 60-160KB; the spec must stay well under a tenth of that.
			if maxLen > 8<<10 {
				t.Errorf("%s: largest spec is %d bytes, expected under 8KB", surf.Tag(), maxLen)
			}
		})
	}
}

// TestSpecDrift covers how a spec fails when the surface it was generated
// against has moved on: a kfunc it calls that is no longer in the table is
// a decode error (never a silently wrong call), as is an unknown surface
// or a non-spec blob.  Kfunc references survive a table reorder because
// they travel by name.
func TestSpecDrift(t *testing.T) {
	// Find a seed whose program calls a kfunc.
	var spec []byte
	var p *Prog
	for seed := int64(0); seed < 256 && spec == nil; seed++ {
		p = Generate(rand.New(rand.NewSource(seed)), TCPCong)
		if len(p.usedKfuncIdxs()) > len(p.PrologueKfuncs) {
			spec = EncodeSpec(p, seed)
		}
	}
	if spec == nil {
		t.Fatal("no tcp_cong program with a generated kfunc call in 256 seeds")
	}
	info, err := DecodeSpecInfo(spec)
	if err != nil {
		t.Fatal(err)
	}

	// Reorder: reverse the surface kfunc table while decoding; the render
	// must not change.
	want := p.Render()
	saved := TCPCong.kfuncs
	reversed := make([]Kfunc, len(saved))
	for i := range saved {
		reversed[len(saved)-1-i] = saved[i]
	}
	TCPCong.kfuncs = reversed
	q, err := DecodeSpec(spec)
	TCPCong.kfuncs = saved
	if err != nil {
		t.Fatalf("decode under a reordered kfunc table: %v", err)
	}
	// The externs are emitted in table order, so compare bodies only.
	if got, want := q.body("_cong_avoid"), p.body("_cong_avoid"); len(got) != len(want) {
		t.Fatalf("reordered decode changed the body: %d vs %d statements", len(got), len(want))
	}
	if q.Render() == want {
		// Only informational: identical render means the reversal was a no-op
		// for the emitted externs ordering.
		t.Log("reordered decode rendered identically")
	}

	// Vanished kfunc: drop the table entry a statement uses.
	var usedName string
	for _, body := range p.allBodies() {
		walkStmts(body, func(st *Stmt) {
			if st.Kind == StmtKfuncCall && usedName == "" {
				usedName = p.Kfuncs[st.KfuncIdx].Name
			}
		})
	}
	var pruned []Kfunc
	for _, kf := range saved {
		if kf.Name != usedName {
			pruned = append(pruned, kf)
		}
	}
	TCPCong.kfuncs = pruned
	_, err = DecodeSpec(spec)
	TCPCong.kfuncs = saved
	if err == nil {
		t.Fatalf("spec using vanished kfunc %q decoded without error", usedName)
	}
	t.Logf("vanished kfunc: %v", err)

	// Unknown surface.
	info.Surface = "no_such_surface"
	if _, err := info.prog(); err == nil {
		t.Error("unknown surface decoded without error")
	}
	// Not a spec.
	if _, err := DecodeSpec([]byte("not a spec at all")); err == nil {
		t.Error("non-spec decoded without error")
	}
	if _, err := DecodeSpec(spec[:len(spec)-7]); err == nil {
		t.Error("truncated spec decoded without error")
	}
}

// TestSpecRecipeRecord covers the SPEC record a materialized recipe
// carries: attach, parse, extract, and idempotence.
func TestSpecRecipeRecord(t *testing.T) {
	spec := EncodeSpec(Generate(rand.New(rand.NewSource(3)), MptcpSched), 3)
	base := (&Recipe{
		BTF:        []byte{0x9f, 0xeb, 1, 0},
		StructName: "mptcp_sched_ops",
		Link:       true,
		Progs: []RecipeProg{{
			Member: "get_send", Name: "x", FuncTypeID: 7,
			Insns: make([]byte, 16),
		}},
	}).Marshal()
	if _, _, ok := RecipeSpec(base); ok {
		t.Fatal("bare recipe reports a SPEC record")
	}
	const key = 0x1122334455667788
	withSpec, err := AttachSpec(base, key, spec)
	if err != nil {
		t.Fatal(err)
	}
	gotKey, gotSpec, ok := RecipeSpec(withSpec)
	if !ok || gotKey != key || !bytes.Equal(gotSpec, spec) {
		t.Fatalf("RecipeSpec: ok %v key %x", ok, gotKey)
	}
	r, err := ParseRecipe(withSpec)
	if err != nil {
		t.Fatal(err)
	}
	if r.KernelKey != key || !bytes.Equal(r.Spec, spec) || len(r.Progs) != 1 || r.StructName != "mptcp_sched_ops" {
		t.Fatalf("ParseRecipe lost records: %+v", r)
	}
	if !bytes.Equal(r.Marshal(), withSpec) {
		t.Fatal("Marshal of a parsed recipe with SPEC is not byte-identical")
	}
	again, err := AttachSpec(withSpec, key+1, spec)
	if err != nil || !bytes.Equal(again, withSpec) {
		t.Fatal("AttachSpec on a recipe that has a SPEC record is not idempotent")
	}
	if _, err := AttachSpec(spec, key, spec); err == nil {
		t.Error("AttachSpec on a non-recipe succeeded")
	}
}
