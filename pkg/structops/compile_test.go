// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package structops

import (
	"errors"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestCompileRecipe runs the real host compile step (clang + llvm-strip +
// bpftool against a kernel build's vmlinux) over a seed range of both
// surfaces and checks the recipe each object digests to.  It needs a
// target kernel build, named by SYZ_STRUCTOPS_KERNEL_OBJ (a directory
// holding vmlinux built with CONFIG_DEBUG_INFO_BTF), and skips otherwise.
func TestCompileRecipe(t *testing.T) {
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
	if n := LayoutChecked(); n < len(layoutProbeCommon) {
		t.Errorf("layout self-check compared only %d structs", n)
	}
	const seeds = 8
	for _, surf := range []*Surface{TCPCong, MptcpSched} {
		t.Run(surf.Tag(), func(t *testing.T) {
			skipUnlessKernelHas(t, kobj, surf)
			start := time.Now()
			for seed := int64(0); seed < seeds; seed++ {
				p := Generate(rand.New(rand.NewSource(seed)), surf)
				src := p.Render()
				blob, err := Compile(src)
				if err != nil {
					t.Fatalf("seed %d: %v", seed, err)
				}
				if !IsRecipe(blob) {
					t.Fatalf("seed %d: not a recipe", seed)
				}
				r, err := ParseRecipe(blob)
				if err != nil {
					t.Fatalf("seed %d: %v", seed, err)
				}
				checkRecipe(t, p, surf, r, src)
				// The cache must serve the same bytes back.
				again, err := Compile(src)
				if err != nil || string(again) != string(blob) {
					t.Fatalf("seed %d: cache miss/mismatch: %v", seed, err)
				}
				// Spec storage: the spec re-renders to the same source, so
				// materializing it is this same cache entry.
				spec := EncodeSpec(p, seed)
				q, err := DecodeSpec(spec)
				if err != nil {
					t.Fatalf("seed %d: %v", seed, err)
				}
				if q.Render() != src {
					t.Fatalf("seed %d: spec re-render differs from the compiled source", seed)
				}
				hits := Stats().CacheHits
				viaSpec, err := Compile(q.Render())
				if err != nil || string(viaSpec) != string(blob) || Stats().CacheHits != hits+1 {
					t.Fatalf("seed %d: materialize via spec was not a cache hit: %v", seed, err)
				}
				withSpec, err := AttachSpec(blob, KernelKey(), spec)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := ParseRecipe(withSpec); err != nil {
					t.Fatalf("seed %d: recipe with SPEC record: %v", seed, err)
				}
				t.Logf("seed %d: spec %d bytes, recipe %d bytes (%.1fx)", seed, len(spec), len(blob),
					float64(len(blob))/float64(len(spec)))
			}
			st := Stats()
			t.Logf("%s: %d seeds compiled in %v, %.0f ms/compile",
				surf.Tag(), seeds, time.Since(start), float64(time.Since(start).Milliseconds())/seeds)
			if st.Failed != 0 {
				t.Errorf("failed compiles: %d", st.Failed)
			}
		})
	}
	if KernelKey() == 0 {
		t.Error("KernelKey is zero after Configure")
	}
	// The on-disk cache serves a fresh compiler for the same kernel without
	// recompiling: same cache dir, new process-level state.
	cacheDir := theCompiler.cfg.CacheDir
	before := Stats()
	if err := Configure(CompileConfig{KernelObj: kobj, CacheDir: cacheDir}); err != nil {
		t.Fatal(err)
	}
	src := Generate(rand.New(rand.NewSource(0)), TCPCong).Render()
	if _, err := Compile(src); err != nil {
		t.Fatal(err)
	}
	if st := Stats(); st.DiskHits != 1 || st.Compiled != 0 {
		t.Errorf("restart on the same kernel recompiled: %+v (previous run %+v)", st, before)
	}
}

// surfaceKernelGate names, per surface, a kernel BTF struct its rendered
// programs cannot compile without: the compile tests skip that surface on
// a kernel build lacking it rather than fail (mptcp_sched is pinned to the
// mptcp/export tree's subflow iterator, which a mainline-based build such
// as the sched_ext Phase-0 kernel does not have).
var surfaceKernelGate = map[string]string{
	MptcpSched.tag: "bpf_iter_mptcp_subflow",
}

func skipUnlessKernelHas(t *testing.T, kobj string, surf *Surface) {
	t.Helper()
	gate, ok := surfaceKernelGate[surf.tag]
	if !ok {
		return
	}
	sizes, err := kernelStructSizes(kobj+"/vmlinux", []string{gate})
	if err != nil {
		t.Fatal(err)
	}
	if sizes[gate] == 0 {
		t.Skipf("kernel BTF has no struct %s; %s programs cannot compile against it", gate, surf.tag)
	}
}

func checkRecipe(t *testing.T, p *Prog, surf *Surface, r *Recipe, src string) {
	t.Helper()
	wantStruct := strings.TrimPrefix(surf.instanceStruct, "struct ")
	if r.StructName != wantStruct {
		t.Errorf("struct name %q, want %q", r.StructName, wantStruct)
	}
	if r.Link != (surf.linkSection == ".struct_ops.link") {
		t.Errorf("link flag %v for section %q", r.Link, surf.linkSection)
	}
	if len(r.BTF) < 24 {
		t.Errorf("BTF too small: %d", len(r.BTF))
	}
	b, err := parseBTF(r.BTF)
	if err != nil {
		t.Fatalf("recipe BTF: %v", err)
	}
	for id := 1; id < b.numTypes(); id++ {
		pos := b.offs[id]
		kind, vlen := b.kindVlen(pos)
		if kind == btfKindFunc && vlen == btfFuncExtern {
			t.Errorf("BTF FUNC %s still extern", b.typeName(uint32(id)))
		}
		if kind == btfKindDatasec && b.typeSizeOrType(uint32(id)) == 0 {
			t.Errorf("BTF DATASEC %s has size 0", b.typeName(uint32(id)))
		}
	}
	// One prog per rendered callback, filling the member its suffix names.
	if len(r.Progs) != len(p.Callbacks) {
		t.Fatalf("%d progs, want %d", len(r.Progs), len(p.Callbacks))
	}
	byMember := map[string]RecipeProg{}
	for _, pr := range r.Progs {
		byMember[pr.Member] = pr
		if pr.Name != p.SchedName+"_"+pr.Member {
			t.Errorf("prog %s fills member %s", pr.Name, pr.Member)
		}
		if len(pr.Insns) == 0 || len(pr.Insns)%bpfInsnSize != 0 {
			t.Errorf("prog %s: %d insn bytes", pr.Name, len(pr.Insns))
		}
		if b.typeKind(pr.FuncTypeID) != btfKindFunc || b.typeName(pr.FuncTypeID) != pr.Name {
			t.Errorf("prog %s: func_type_id %d is not its FUNC", pr.Name, pr.FuncTypeID)
		}
		for _, k := range pr.Kfuncs {
			if int(k.InsnIdx)*bpfInsnSize >= len(pr.Insns) {
				t.Errorf("prog %s: kfunc %s at insn %d out of range", pr.Name, k.Name, k.InsnIdx)
			}
			// Each call site is a BPF_JMP|BPF_CALL (0x85) with imm -1.
			if pr.Insns[k.InsnIdx*bpfInsnSize] != 0x85 {
				t.Errorf("prog %s: kfunc %s site is not a call insn", pr.Name, k.Name)
			}
			if !strings.Contains(src, "extern") || !strings.Contains(src, k.Name+"(") {
				t.Errorf("prog %s: kfunc %s not declared in source", pr.Name, k.Name)
			}
		}
	}
	for _, cb := range p.Callbacks {
		if _, ok := byMember[cb.Suffix[1:]]; !ok {
			t.Errorf("callback %s has no prog", cb.Suffix)
		}
	}
}

// TestLayoutCheck runs the Configure-time layout self-check three ways:
// as Configure runs it (must pass on a sane kernel/toolchain), against
// deliberately wrong expected sizes (must name the struct and both sizes),
// and without -fms-extensions (the historical cause: must fail).
func TestLayoutCheck(t *testing.T) {
	kobj := os.Getenv("SYZ_STRUCTOPS_KERNEL_OBJ")
	if kobj == "" {
		t.Skip("SYZ_STRUCTOPS_KERNEL_OBJ not set")
	}
	for _, tool := range []string{"clang", "bpftool"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%v not in PATH", tool)
		}
	}
	c := &compiler{cfg: CompileConfig{KernelObj: kobj, CacheDir: t.TempDir(),
		Clang: "clang", Strip: "llvm-strip", Bpftool: "bpftool"}}
	if err := c.init(); err != nil {
		t.Fatal(err)
	}
	expected, err := kernelStructSizes(kobj+"/vmlinux", layoutProbeTypes())
	if err != nil {
		t.Fatal(err)
	}
	if expected["sock"] == 0 || expected["tcp_congestion_ops"] == 0 {
		t.Fatalf("kernel BTF sizes missing: %v", expected)
	}
	n, err := c.checkLayout(expected)
	if err != nil {
		t.Fatalf("sane layout check failed: %v", err)
	}
	t.Logf("checked %d structs: %v", n, expected)

	wrong := map[string]uint32{}
	for k, v := range expected {
		wrong[k] = v
	}
	wrong["sock"] += 64
	_, err = c.checkLayout(wrong)
	if !errors.Is(err, ErrLayoutMismatch) {
		t.Fatalf("wrong expected size not detected: %v", err)
	}
	msg := err.Error()
	for _, frag := range []string{"struct sock:", fmt.Sprint(expected["sock"]), fmt.Sprint(wrong["sock"])} {
		if !strings.Contains(msg, frag) {
			t.Errorf("mismatch report lacks %q:\n%s", frag, msg)
		}
	}
	if strings.Contains(msg, "struct tcp_sock:") {
		t.Errorf("mismatch report names an unaffected struct:\n%s", msg)
	}

	_, err = c.checkLayout(expected, "-fno-ms-extensions")
	if !errors.Is(err, ErrLayoutMismatch) {
		t.Fatalf("-fno-ms-extensions layout not detected (kernel without tagged anon members?): %v", err)
	}
	t.Logf("without -fms-extensions: %v", err)
}
