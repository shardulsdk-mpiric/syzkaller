// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package materialize

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/structops"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

// fakeCompile stands in for clang: a deterministic recipe whose BTF record
// is derived from the source, so a different source yields a different
// recipe and the same source the same one.
func fakeCompile(src string) ([]byte, error) {
	if strings.Contains(src, "FAIL_COMPILE") {
		return nil, errors.New("fake clang: refused")
	}
	h := sha256.Sum256([]byte(src))
	return (&structops.Recipe{
		BTF:        append([]byte{0x9f, 0xeb, 1, 0}, h[:]...),
		StructName: "fake_ops",
		Link:       true,
		Progs:      []structops.RecipeProg{{Member: "m", Name: "n", Insns: make([]byte, 8)}},
	}).Marshal(), nil
}

func linuxTarget(t *testing.T) *prog.Target {
	t.Helper()
	target, err := prog.GetTarget("linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	return target
}

// genProg generates a program that contains at least one struct_ops load
// (the fuzzer's own generator, so blobs are real spec blobs).
func genProg(t *testing.T, target *prog.Target, seed int64) *prog.Prog {
	t.Helper()
	calls := map[*prog.Syscall]bool{}
	for _, name := range []string{"syz_bpf_struct_ops_load$tcp_cong", "syz_bpf_struct_ops_load$mptcp_sched"} {
		if target.SyscallMap[name] == nil {
			t.Fatalf("%s not in target", name)
		}
		calls[target.SyscallMap[name]] = true
	}
	ct := target.BuildChoiceTable(nil, calls)
	p := target.Generate(rand.NewSource(seed), 3, ct)
	if len(blobs(p)) == 0 {
		t.Fatalf("seed %d: generated program has no struct_ops blob", seed)
	}
	return p
}

func blobs(p *prog.Prog) [][]byte {
	var out [][]byte
	for _, c := range p.Calls {
		forEachBlob(c, func(arg *prog.DataArg) { out = append(out, arg.Data()) })
	}
	return out
}

// lenArgs returns, per struct_ops load call, the value of its `len
// bytesize[obj]` argument and the blob length it must equal.
func lenArgs(t *testing.T, p *prog.Prog) (lens, want []uint64) {
	t.Helper()
	for _, c := range p.Calls {
		if !strings.HasPrefix(c.Meta.Name, "syz_bpf_struct_ops_load") {
			continue
		}
		n := 0
		forEachBlob(c, func(arg *prog.DataArg) {
			want = append(want, uint64(len(arg.Data())))
			n++
		})
		if n != 1 {
			t.Fatalf("%s: %d blobs", c.Meta.Name, n)
		}
		lens = append(lens, c.Args[1].(*prog.ConstArg).Val)
	}
	return
}

func TestMaterializeProg(t *testing.T) {
	target := linuxTarget(t)
	const key = 0xabcdef0123456789
	m := New(fakeCompile, func() uint64 { return key })
	for seed := int64(0); seed < 8; seed++ {
		p := genProg(t, target, seed)
		before := p.Serialize()
		if l, w := lenArgs(t, p); fmt.Sprint(l) != fmt.Sprint(w) {
			t.Fatalf("seed %d: generated len args %v != blob sizes %v", seed, l, w)
		}
		q, changed := m.Prog(p)
		if !changed || q == p {
			t.Fatalf("seed %d: program with spec blobs not materialized", seed)
		}
		// The original is untouched: still the spec form, byte-identical.
		if !bytes.Equal(p.Serialize(), before) {
			t.Fatalf("seed %d: original program modified by materialize", seed)
		}
		for _, b := range blobs(p) {
			if !structops.IsSpec(b) {
				t.Fatalf("seed %d: original blob is no longer a spec", seed)
			}
		}
		// The clone carries recipes with the SPEC record and the live key,
		// and its len args follow the new blob sizes.
		for i, b := range blobs(q) {
			if !structops.IsRecipe(b) {
				t.Fatalf("seed %d: clone blob %d is not a recipe", seed, i)
			}
			gotKey, spec, ok := structops.RecipeSpec(b)
			if !ok || gotKey != key || !bytes.Equal(spec, blobs(p)[i]) {
				t.Fatalf("seed %d: clone blob %d: SPEC record ok=%v key=%x", seed, i, ok, gotKey)
			}
		}
		if l, w := lenArgs(t, q); fmt.Sprint(l) != fmt.Sprint(w) {
			t.Fatalf("seed %d: materialized len args %v != blob sizes %v", seed, l, w)
		}
		if _, err := q.SerializeForExec(); err != nil {
			t.Fatalf("seed %d: materialized program does not serialize for exec: %v", seed, err)
		}
		// Determinism: materializing again yields the same bytes (the
		// compile cache relies on the same source for the same spec).
		q2, _ := m.Prog(p)
		if !bytes.Equal(q.Serialize(), q2.Serialize()) {
			t.Fatalf("seed %d: materialize is not deterministic", seed)
		}
		// Idempotence: a recipe for the live kernel is left alone.
		if q3, changed := m.Prog(q); changed || q3 != q {
			t.Fatalf("seed %d: live-kernel recipe re-materialized", seed)
		}
	}
	st := m.Stats()
	if st.Programs != 16 || st.Failed != 0 || st.Blobs == 0 || st.Rematerialized != 0 {
		t.Errorf("stats %+v", st)
	}
}

func TestMaterializeStale(t *testing.T) {
	target := linuxTarget(t)
	p := genProg(t, target, 1)
	old := New(fakeCompile, func() uint64 { return 1 })
	q, _ := old.Prog(p)
	// Same recipe comes back on another kernel: re-materialized from its
	// embedded spec, keyed to the new kernel, and the original (recipe
	// form) is untouched.
	newer := New(fakeCompile, func() uint64 { return 2 })
	r, changed := newer.Prog(q)
	if !changed {
		t.Fatal("stale recipe not re-materialized")
	}
	for i, b := range blobs(r) {
		gotKey, spec, ok := structops.RecipeSpec(b)
		if !ok || gotKey != 2 || !bytes.Equal(spec, blobs(p)[i]) {
			t.Fatalf("blob %d: key %x ok %v", i, gotKey, ok)
		}
	}
	if k, _, _ := structops.RecipeSpec(blobs(q)[0]); k != 1 {
		t.Fatal("original stale program was modified")
	}
	if st := newer.Stats(); st.Rematerialized == 0 || st.Blobs != 0 {
		t.Errorf("stats %+v", st)
	}
	// With no live key (compile step not configured) nothing is touched.
	none := New(fakeCompile, func() uint64 { return 0 })
	if _, changed := none.Prog(q); changed {
		t.Fatal("recipe touched without a live kernel key")
	}
	// A legacy recipe without a SPEC record passes through on any kernel.
	legacy := p.Clone()
	for _, c := range legacy.Calls {
		forEachBlob(c, func(arg *prog.DataArg) {
			rec, _ := fakeCompile("legacy")
			arg.SetData(rec)
		})
	}
	if _, changed := newer.Prog(legacy); changed {
		t.Fatal("legacy recipe without SPEC record was modified")
	}
}

func TestMaterializeFailure(t *testing.T) {
	target := linuxTarget(t)
	p := genProg(t, target, 2)
	// Compile failure: the program goes out unchanged (inert blob), counted.
	failing := New(func(string) ([]byte, error) { return nil, errors.New("no clang") },
		func() uint64 { return 1 })
	if q, changed := failing.Prog(p); changed || q != p {
		t.Fatal("compile failure produced a changed program")
	}
	if st := failing.Stats(); st.Failed == 0 || st.Programs != 0 {
		t.Errorf("stats %+v", st)
	}
	// Undecodable spec (corrupt gob after the header): same.
	bad := p.Clone()
	for _, c := range bad.Calls {
		forEachBlob(c, func(arg *prog.DataArg) {
			d := arg.Data()
			arg.SetData(append(d[:8:8], bytes.Repeat([]byte{0xff}, 16)...))
		})
	}
	m := New(fakeCompile, func() uint64 { return 1 })
	if _, changed := m.Prog(bad); changed {
		t.Fatal("corrupt spec produced a changed program")
	}
	// A program with no struct_ops at all is returned as is, no clone.
	plain := target.DataMmapProg()
	if q, changed := m.Prog(plain); changed || q != plain {
		t.Fatal("program without struct_ops was touched")
	}
}

// TestMaterializeSource covers the request boundary: the consumer gets a
// shadow with the materialized program, the producer's request completes
// with the shadow's result, requests without struct_ops pass through, and
// the Stat is bumped once.
func TestMaterializeSource(t *testing.T) {
	target := linuxTarget(t)
	m := New(fakeCompile, func() uint64 { return 7 })
	plain := target.DataMmapProg()
	withOps := genProg(t, target, 5)
	pq := queue.Plain()
	src := m.Source(pq)

	reqPlain := &queue.Request{Prog: plain, ExecOpts: flatrpc.ExecOpts{EnvFlags: flatrpc.ExecEnvSandboxNone}}
	reqOps := &queue.Request{
		Prog:            withOps,
		ExecOpts:        flatrpc.ExecOpts{EnvFlags: flatrpc.ExecEnvSandboxNone, ExecFlags: flatrpc.ExecFlagCollectSignal},
		ReturnAllSignal: []int{0, 1},
		ReturnError:     true,
		ReturnOutput:    true,
		Important:       true,
		Avoid:           []queue.ExecutorID{{VM: 1, Proc: 2}},
	}
	pq.Submit(reqPlain)
	pq.Submit(reqOps)

	if got := src.Next(); got != reqPlain {
		t.Fatal("request without struct_ops did not pass through")
	}
	shadow := src.Next()
	if shadow == nil || shadow == reqOps {
		t.Fatal("request with struct_ops was not shadowed")
	}
	if shadow.Prog == reqOps.Prog || len(shadow.Prog.Calls) != len(reqOps.Prog.Calls) {
		t.Fatal("shadow program is not a materialized clone")
	}
	for _, b := range blobs(shadow.Prog) {
		if !structops.IsRecipe(b) {
			t.Fatal("shadow carries a non-recipe blob")
		}
	}
	for _, b := range blobs(reqOps.Prog) {
		if !structops.IsSpec(b) {
			t.Fatal("original request lost its spec form")
		}
	}
	if shadow.ExecOpts != reqOps.ExecOpts || !shadow.Important || !shadow.ReturnError || !shadow.ReturnOutput ||
		len(shadow.ReturnAllSignal) != 2 || len(shadow.Avoid) != 1 || shadow.Type != reqOps.Type {
		t.Fatalf("shadow lost request fields: %+v", shadow)
	}
	if err := shadow.Validate(); err != nil {
		t.Fatal(err)
	}
	if src.Next() != nil {
		t.Fatal("spurious request")
	}
	res := &queue.Result{Status: queue.Success, Output: []byte("ok")}
	shadow.Done(res)
	got := reqOps.Wait(context.Background())
	if got != res {
		t.Fatalf("original request got result %+v, want the shadow's", got)
	}
	if shadow.Wait(context.Background()) != res {
		t.Fatal("shadow itself not completed")
	}
}
