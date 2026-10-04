// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package structops

import (
	"bytes"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// testInstanceSurface is tcp_cong with one fuzzed instance-data member,
// `.flags` (tcp_congestion_ops.flags, u32; bpf_tcp_ca_init_member accepts
// any value within TCP_CONG_MASK), and one fixed one that is zero (so it
// renders but never reaches the recipe).  Registered under its own tag for
// the test's lifetime so DecodeSpec can resolve it.
func testInstanceSurface(t *testing.T) *Surface {
	t.Helper()
	s := *TCPCong
	s.tag = "tcp_cong_instance_test"
	s.instanceFields = []InstanceField{
		{Field: "flags", Sep: "\t\t", gen: func(r *randGen) uint64 {
			// TCP_CONG_NON_RESTRICTED (1) | TCP_CONG_NEEDS_ECN (2): any
			// subset, so a zero draw is possible and exercises the
			// "zero is not carried" rule.
			return uint64(r.Intn(4))
		}},
	}
	surfaces[s.tag] = &s
	t.Cleanup(func() { delete(surfaces, s.tag) })
	return &s
}

// TestInstanceFieldsRender covers the generator / renderer / spec side of
// instance data: the draw lands in Prog.Instance, renders as a hex member
// initialiser between the callbacks and `.name`, round-trips through the
// spec, and a spec whose instance-field set no longer matches the surface
// is a decode error.
func TestInstanceFieldsRender(t *testing.T) {
	surf := testInstanceSurface(t)
	seen := map[uint64]bool{}
	for seed := int64(0); seed < 64; seed++ {
		p := Generate(rand.New(rand.NewSource(seed)), surf)
		if len(p.Instance) != 1 || p.Instance[0].Field != "flags" {
			t.Fatalf("seed %d: Instance = %+v", seed, p.Instance)
		}
		v := p.Instance[0].Value
		seen[v] = true
		src := p.Render()
		line := "\t.flags\t\t= " + hexLit(v) + ",\n"
		if !strings.Contains(src, line) {
			t.Fatalf("seed %d: render lacks %q:\n%s", seed, line, src)
		}
		// Between the last callback pointer and .name.
		cbIdx := strings.LastIndex(src, "= (void *)")
		if fl, nm := strings.Index(src, line), strings.Index(src, "\t.name"); !(cbIdx < fl && fl < nm) {
			t.Fatalf("seed %d: instance data not between callbacks and .name:\n%s", seed, src)
		}
		spec := EncodeSpec(p, seed)
		q, err := DecodeSpec(spec)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		if q.Render() != src {
			t.Fatalf("seed %d: spec re-render differs", seed)
		}
		if again := EncodeSpec(q, seed); !bytes.Equal(again, spec) {
			t.Fatalf("seed %d: spec not canonical", seed)
		}
	}
	if len(seen) < 3 {
		t.Errorf("flags draw not varying: %v", seen)
	}

	// A surface without instance fields renders none: mptcp_sched is
	// exactly that (TestStructOpsGolden is the oracle; this is the direct
	// statement).  tcp_cong carries the one production `.flags` field,
	// always within TCP_CONG_MASK (bits 0..4), zero included.
	if p := Generate(rand.New(rand.NewSource(1)), MptcpSched); p.Instance != nil {
		t.Errorf("mptcp_sched: Instance = %+v, want nil", p.Instance)
	}
	zeroFlags := false
	for seed := int64(0); seed < 64; seed++ {
		p := Generate(rand.New(rand.NewSource(seed)), TCPCong)
		if len(p.Instance) != 1 || p.Instance[0].Field != "flags" || p.Instance[0].Value&^0x1f != 0 {
			t.Fatalf("tcp_cong seed %d: Instance = %+v", seed, p.Instance)
		}
		zeroFlags = zeroFlags || p.Instance[0].Value == 0
	}
	if !zeroFlags {
		t.Error("tcp_cong: .flags = 0 not drawn in 64 seeds")
	}

	// Drift: the spec carries a field the surface no longer has, or lacks
	// one it gained -- both decode errors, never a silently different
	// instance.
	p := Generate(rand.New(rand.NewSource(3)), surf)
	spec := EncodeSpec(p, 3)
	saved := surf.instanceFields
	surf.instanceFields = nil
	if _, err := DecodeSpec(spec); err == nil || !strings.Contains(err.Error(), "instance fields") {
		t.Errorf("spec with a retired instance field decoded: %v", err)
	}
	surf.instanceFields = []InstanceField{{Field: "flags"}, {Field: "timeout_ms", Value: 7}}
	if _, err := DecodeSpec(spec); err == nil || !strings.Contains(err.Error(), "instance fields") {
		t.Errorf("spec lacking a new instance field decoded: %v", err)
	}
	surf.instanceFields = []InstanceField{{Field: "other"}}
	if _, err := DecodeSpec(spec); err == nil || !strings.Contains(err.Error(), "instance field") {
		t.Errorf("spec with a renamed instance field decoded: %v", err)
	}
	surf.instanceFields = saved
}

// hexLit is the C literal the renderer emits for an instance value (`%#x`:
// "0" for zero, "0x.." otherwise).
func hexLit(v uint64) string {
	return fmt.Sprintf("%#x", v)
}

// TestRecipeDataRecord covers the DATA record's TLV form: Marshal/Parse
// round-trip, its position (after the PROGs, before SPEC), that RecipeSpec
// still finds the SPEC record past it, and that a malformed size is
// rejected.
func TestRecipeDataRecord(t *testing.T) {
	r := &Recipe{
		BTF:        []byte{0x9f, 0xeb, 1, 0, 24, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0},
		StructName: "sched_ext_ops",
		Link:       true,
		Progs: []RecipeProg{{
			Member: "enqueue", Name: "x_enqueue", FuncTypeID: 7,
			Kfuncs: []RecipeKfunc{{InsnIdx: 2, Name: "scx_bpf_dsq_insert"}},
			Insns:  make([]byte, 4*bpfInsnSize),
		}},
		Data: []RecipeData{
			{Member: "flags", Size: 8, Value: 0x11},
			{Member: "timeout_ms", Size: 4, Value: 1500},
		},
	}
	blob := r.Marshal()
	withSpec, err := AttachSpec(blob, 0xabcdef, []byte("spec-bytes"))
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range [][]byte{blob, withSpec} {
		got, err := ParseRecipe(b)
		if err != nil {
			t.Fatal(err)
		}
		if len(got.Data) != 2 || got.Data[0] != r.Data[0] || got.Data[1] != r.Data[1] {
			t.Errorf("Data round-trip: %+v", got.Data)
		}
		if got.StructName != r.StructName || len(got.Progs) != 1 || got.Progs[0].Member != "enqueue" {
			t.Errorf("recipe round-trip: %+v", got)
		}
	}
	if key, spec, ok := RecipeSpec(withSpec); !ok || key != 0xabcdef || string(spec) != "spec-bytes" {
		t.Errorf("RecipeSpec past DATA records: %v %q %v", key, spec, ok)
	}
	// The record count header counts the DATA records.
	if n := int(blob[8]) | int(blob[9])<<8; n != 2+1+2 {
		t.Errorf("nrec = %d, want 5", n)
	}
	// A DATA record with a bad size is rejected.
	bad := &Recipe{BTF: r.BTF, StructName: r.StructName, Progs: r.Progs,
		Data: []RecipeData{{Member: "flags", Size: 3, Value: 1}}}
	if _, err := ParseRecipe(bad.Marshal()); err == nil {
		t.Error("DATA with size 3 parsed")
	}
}

// TestDigestInstanceData runs the real compile step on the instance-data
// surface and checks Digest reads the rendered `.flags` value back out of
// the object: exactly one DATA record when the draw is non-zero (member
// "flags", the u32 width of tcp_congestion_ops.flags, the drawn value),
// none when it is zero.  Needs SYZ_STRUCTOPS_KERNEL_OBJ like
// TestCompileRecipe.
func TestDigestInstanceData(t *testing.T) {
	kobj := os.Getenv("SYZ_STRUCTOPS_KERNEL_OBJ")
	if kobj == "" {
		t.Skip("SYZ_STRUCTOPS_KERNEL_OBJ not set")
	}
	for _, tool := range []string{"clang", "llvm-strip", "bpftool"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%v not in PATH", tool)
		}
	}
	if err := Configure(CompileConfig{KernelObj: kobj, CacheDir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	surf := testInstanceSurface(t)
	var nonzero, zero int
	for seed := int64(0); seed < 8; seed++ {
		p := Generate(rand.New(rand.NewSource(seed)), surf)
		blob, err := Compile(p.Render())
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		r, err := ParseRecipe(blob)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		want := p.Instance[0].Value
		switch {
		case want == 0 && len(r.Data) == 0:
			zero++
		case want != 0 && len(r.Data) == 1 && r.Data[0] == RecipeData{Member: "flags", Size: 4, Value: want}:
			nonzero++
		default:
			t.Errorf("seed %d: .flags = %#x digested as %+v", seed, want, r.Data)
		}
	}
	t.Logf("%d non-zero + %d zero draws digested", nonzero, zero)
	if nonzero == 0 {
		t.Error("no non-zero draw in 8 seeds")
	}
	// mptcp_sched sets no instance data: no DATA record.  The production
	// tcp_cong carries `.flags` and digests to exactly that member (or to
	// nothing when the draw is zero); sched_ext's four members are covered
	// by TestSchedExtCompile.
	for _, s := range []*Surface{TCPCong, MptcpSched} {
		if gate := surfaceKernelGate[s.tag]; gate != "" {
			if sizes, _ := kernelStructSizes(kobj+"/vmlinux", []string{gate}); sizes[gate] == 0 {
				continue
			}
		}
		p := Generate(rand.New(rand.NewSource(0)), s)
		blob, err := Compile(p.Render())
		if err != nil {
			t.Fatalf("%s: %v", s.tag, err)
		}
		r, _ := ParseRecipe(blob)
		switch {
		case s == MptcpSched && len(r.Data) != 0:
			t.Errorf("%s: unexpected DATA records %+v", s.tag, r.Data)
		case s == TCPCong && p.Instance[0].Value == 0 && len(r.Data) != 0:
			t.Errorf("%s: .flags = 0 digested as %+v", s.tag, r.Data)
		case s == TCPCong && p.Instance[0].Value != 0 &&
			(len(r.Data) != 1 || r.Data[0] != RecipeData{Member: "flags", Size: 4, Value: p.Instance[0].Value}):
			t.Errorf("%s: .flags = %#x digested as %+v", s.tag, p.Instance[0].Value, r.Data)
		}
	}
}
