// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package structops

import (
	"math/rand"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

// schedExtInsertRe matches the enqueue terminal insert over the row-A
// candidate sets (schedExtTerminal).
var schedExtInsertRe = regexp.MustCompile(
	`^\tscx_bpf_dsq_insert\(p, (SCX_DSQ_GLOBAL|SCX_DSQ_LOCAL|SCX_DSQ_LOCAL_ON \| cpu), ` +
		`(0|SCX_SLICE_DFL|SCX_SLICE_DFL / 4|1000|SCX_SLICE_INF), ` +
		`(0|(SCX_ENQ_PREEMPT|SCX_ENQ_HEAD|enq_flags)( \| (SCX_ENQ_PREEMPT|SCX_ENQ_HEAD|enq_flags))*)\);$`)

// TestSchedExtSurface pins the row-A contract of the sched_ext surface
// (the design's section 4(a) liveness scaffold and the per-op kfunc table):
//   - enqueue's body is the only one with a terminal insert, exactly one,
//     last in the rendered callback, never inside a branch;
//   - no callback body ever emits a `return` (every scope is noReturn), so
//     select_cpu's `return prev_cpu;` and init's `return 0;` run on every
//     path and the insert is reached on every enqueue path;
//   - the dispatch-only kfunc is called from dispatch only, the Terminal
//     insert is never a plain call, and every cpu argument is a ctx cpu
//     (never a literal); kick flags come from the candidate set;
//   - the four instance fields are present, timeout_ms is within the
//     pinned [1000, 3000] window, flags stay within SCX_OPS_ALL_FLAGS with
//     SWITCH_PARTIAL drawn in a p~0.3-0.5 share of programs;
//   - the spec round-trips to the same text.
func TestSchedExtSurface(t *testing.T) {
	const seeds = 512
	var partial, dispatchSlots, kicks int
	dsqs, slices := map[string]bool{}, map[string]bool{}
	cpuArgRe := regexp.MustCompile(`scx_bpf_(kick_cpu|cpuperf_cap|cpuperf_cur)\(([^,)]+)`)
	kickFlagsRe := regexp.MustCompile(`scx_bpf_kick_cpu\([^,]+, ([^)]+)\)`)
	for seed := int64(0); seed < seeds; seed++ {
		p := Generate(rand.New(rand.NewSource(seed)), SchedExt)
		if p.Surface != "sched_ext" || !strings.HasPrefix(p.SchedName, "scx_") || len(p.SchedName) >= 16 {
			t.Fatalf("seed %d: surface %q name %q", seed, p.Surface, p.SchedName)
		}
		for _, cb := range p.Callbacks {
			inserts := 0
			walkStmts(cb.Body, func(st *Stmt) {
				switch st.Kind {
				case StmtDsqInsert:
					inserts++
				case StmtKfuncCall:
					kf := &p.Kfuncs[st.KfuncIdx]
					if kf.Terminal {
						t.Errorf("seed %d: %s: terminal kfunc as a plain call", seed, cb.Suffix)
					}
					if st.NullGuard {
						t.Errorf("seed %d: %s: a NULL guard (early return) in a row-A body", seed, cb.Suffix)
					}
					if kf.Name == "scx_bpf_dispatch_nr_slots" {
						dispatchSlots++
						if cb.Suffix != "_dispatch" {
							t.Errorf("seed %d: dispatch-only kfunc called from %s", seed, cb.Suffix)
						}
					}
					if kf.Name == "scx_bpf_task_cpu" {
						t.Errorf("seed %d: %s: prologue kfunc scx_bpf_task_cpu generated as a draw", seed, cb.Suffix)
					}
					if kf.Name == "scx_bpf_kick_cpu" {
						kicks++
					}
				}
			})
			if want := map[bool]int{true: 1, false: 0}[cb.Suffix == "_enqueue"]; inserts != want {
				t.Errorf("seed %d: %s: %d terminal inserts, want %d", seed, cb.Suffix, inserts, want)
			}
			// The insert is last at the top level, never nested.
			if cb.Suffix == "_enqueue" && (len(cb.Body) == 0 || cb.Body[len(cb.Body)-1].Kind != StmtDsqInsert) {
				t.Errorf("seed %d: enqueue does not end in the insert", seed)
			}
		}
		src := p.Render()
		if strings.Contains(src, "\treturn -1;") || strings.Contains(src, "\t\treturn;") {
			// `\t\treturn;` would be a guard's return; dispatch's prologue
			// `if (!prev)\n\t\treturn;` is the one legitimate early return,
			// so check the body text per callback instead.
			for _, suffix := range []string{"_select_cpu", "_enqueue", "_running", "_stopping", "_exit"} {
				if body := callbackText(t, src, p.SchedName+suffix); strings.Contains(body, "return;") ||
					strings.Contains(body, "return -1;") {
					t.Errorf("seed %d: early return in %s:\n%s", seed, suffix, body)
				}
			}
			disp := callbackText(t, src, p.SchedName+"_dispatch")
			if strings.Count(disp, "return") != 1 {
				t.Errorf("seed %d: dispatch has a return beyond the prev guard:\n%s", seed, disp)
			}
		}
		// init renders without a ctx (`BPF_PROG(name)`), so delimit it by
		// hand: its only return is the `return 0;` epilogue.
		if i := strings.Index(src, "BPF_PROG("+p.SchedName+"_init)\n{\n"); i < 0 {
			t.Errorf("seed %d: render lacks the ctx-less init", seed)
		} else if init := src[i:]; strings.Count(init[:strings.Index(init, "\n}\n")], "return") != 1 {
			t.Errorf("seed %d: init has a return beyond the epilogue:\n%s", seed, init[:strings.Index(init, "\n}\n")])
		}
		enq := callbackText(t, src, p.SchedName+"_enqueue")
		lines := strings.Split(strings.TrimRight(enq, "\n"), "\n")
		m := schedExtInsertRe.FindStringSubmatch(lines[len(lines)-1])
		if m == nil {
			t.Fatalf("seed %d: enqueue's last line is not a row-A insert: %q", seed, lines[len(lines)-1])
		}
		dsqs[m[1]], slices[m[2]] = true, true
		if strings.Count(src, "scx_bpf_dsq_insert(") != 2 {
			t.Errorf("seed %d: insert occurrences != extern + one call", seed)
		}
		// Signatures: scalar ctx renders with its space; init has no ctx.
		for _, want := range []string{
			"__s32 BPF_PROG(" + p.SchedName + "_select_cpu, struct task_struct *p, __s32 prev_cpu, __u64 wake_flags)",
			"void BPF_PROG(" + p.SchedName + "_dispatch, __s32 cpu, struct task_struct *prev)",
			"__s32 BPF_PROG(" + p.SchedName + "_init)\n",
			"void BPF_PROG(" + p.SchedName + "_exit, struct scx_exit_info *ei)",
			"\tif (!prev)\n\t\treturn;\n",
			"\treturn prev_cpu;\n",
			"\treturn 0;\n",
			"SEC(\".struct_ops.link\")\nstruct sched_ext_ops " + p.SchedName + " = {",
		} {
			if !strings.Contains(src, want) {
				t.Errorf("seed %d: render lacks %q:\n%s", seed, want, src)
			}
		}
		// Every cpu argument is a ctx cpu, every kick flag a candidate (the
		// extern declarations are skipped: they carry parameter names).
		for _, line := range strings.Split(src, "\n") {
			if strings.HasPrefix(line, "extern ") {
				continue
			}
			for _, am := range cpuArgRe.FindAllStringSubmatch(line, -1) {
				if arg := strings.TrimSpace(am[2]); arg != "cpu" && arg != "prev_cpu" {
					t.Errorf("seed %d: cpu argument %q is not a ctx cpu", seed, arg)
				}
			}
			for _, km := range kickFlagsRe.FindAllStringSubmatch(line, -1) {
				switch km[1] {
				case "0", "SCX_KICK_IDLE", "SCX_KICK_PREEMPT":
				default:
					t.Errorf("seed %d: kick flags %q outside the candidate set", seed, km[1])
				}
			}
		}
		// Instance fields.
		if len(p.Instance) != 4 || p.Instance[0].Field != "timeout_ms" || p.Instance[1].Field != "flags" ||
			p.Instance[2].Field != "exit_dump_len" || p.Instance[3].Field != "dispatch_max_batch" {
			t.Fatalf("seed %d: Instance = %+v", seed, p.Instance)
		}
		if to := p.Instance[0].Value; to < 1000 || to > 3000 {
			t.Errorf("seed %d: timeout_ms %d outside the pinned [1000,3000]", seed, to)
		}
		if fl := p.Instance[1].Value; fl&^0x1ff != 0 {
			t.Errorf("seed %d: flags %#x outside SCX_OPS_ALL_FLAGS", seed, fl)
		} else if fl&SchedExtOpsSwitchPartial != 0 {
			partial++
		}
		if !strings.Contains(src, "\t.timeout_ms\t\t= ") || !strings.Contains(src, "\t.flags\t\t\t= ") ||
			!strings.Contains(src, "\t.dispatch_max_batch\t= ") {
			t.Errorf("seed %d: instance data lines missing:\n%s", seed, src)
		}
		q, err := DecodeSpec(EncodeSpec(p, seed))
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		if q.Render() != src {
			t.Fatalf("seed %d: spec re-render differs", seed)
		}
		assertNoScopeLeak(t, seed, src)
	}
	if len(dsqs) != 3 || len(slices) != 5 {
		t.Errorf("terminal draws not covering the candidates: dsq %v slice %v", dsqs, slices)
	}
	if share := float64(partial) / seeds; share < 0.3 || share > 0.5 {
		t.Errorf("SWITCH_PARTIAL in %.2f of programs, want 0.3-0.5", share)
	}
	if dispatchSlots == 0 || kicks == 0 {
		t.Errorf("row-A kfuncs not exercised: dispatch_nr_slots %d kick_cpu %d", dispatchSlots, kicks)
	}
}

// TestSchedExtFieldlessScope pins genBody's field-less mode: a scope with no
// ctx fields draws kfunc calls and arithmetic only, never a read / write,
// and the init / exit bodies are exactly such scopes.
func TestSchedExtFieldlessScope(t *testing.T) {
	calls := 0
	for seed := int64(0); seed < 256; seed++ {
		p := Generate(rand.New(rand.NewSource(seed)), SchedExt)
		for _, suffix := range []string{"_init", "_exit"} {
			walkStmts(p.body(suffix), func(st *Stmt) {
				switch st.Kind {
				case StmtCtxRead, StmtCtxWrite, StmtDsqInsert, StmtSubflowIter:
					t.Errorf("seed %d: %s: statement kind %d in a field-less scope", seed, suffix, st.Kind)
				case StmtKfuncCall:
					calls++
					if n := len(p.Kfuncs[st.KfuncIdx].ArgTypes); n != 0 && p.Kfuncs[st.KfuncIdx].ArgCands == nil {
						t.Errorf("seed %d: %s: kfunc with %d typed args called with an empty pool", seed, suffix, n)
					}
				}
			})
		}
	}
	if calls == 0 {
		t.Error("no kfunc call generated in 256 init/exit bodies")
	}
}

// TestSchedExtCompile is the real compile step over the sched_ext surface
// against a CONFIG_SCHED_CLASS_EXT kernel build (SYZ_STRUCTOPS_KERNEL_OBJ):
// every seed must compile and digest to a recipe whose DATA records are
// exactly the non-zero instance members with the kernel's member widths
// (timeout_ms / exit_dump_len / dispatch_max_batch u32, flags u64).
func TestSchedExtCompile(t *testing.T) {
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
	skipUnlessKernelHas(t, kobj, SchedExt)
	widths := map[string]uint32{"timeout_ms": 4, "flags": 8, "exit_dump_len": 4, "dispatch_max_batch": 4}
	const seeds = 24
	for seed := int64(0); seed < seeds; seed++ {
		p := Generate(rand.New(rand.NewSource(seed)), SchedExt)
		blob, err := Compile(p.Render())
		if err != nil {
			t.Fatalf("seed %d: %v\n%s", seed, err, p.Render())
		}
		r, err := ParseRecipe(blob)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		checkRecipe(t, p, SchedExt, r, p.Render())
		got := map[string]RecipeData{}
		for _, d := range r.Data {
			got[d.Member] = d
		}
		for _, iv := range p.Instance {
			d, ok := got[iv.Field]
			switch {
			case iv.Value == 0 && ok:
				t.Errorf("seed %d: zero .%s carried as %+v", seed, iv.Field, d)
			case iv.Value != 0 && (!ok || d.Value != iv.Value || d.Size != widths[iv.Field]):
				t.Errorf("seed %d: .%s = %#x digested as %+v (want size %d)", seed, iv.Field, iv.Value, d, widths[iv.Field])
			}
			delete(got, iv.Field)
		}
		if len(got) != 0 {
			t.Errorf("seed %d: unexpected DATA records %+v", seed, got)
		}
	}
	if st := Stats(); st.Failed != 0 {
		t.Errorf("failed compiles: %d", st.Failed)
	}
}
