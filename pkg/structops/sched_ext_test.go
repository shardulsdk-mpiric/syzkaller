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

// schedExtInsertRe matches the enqueue terminal insert over the row-B
// candidate sets (schedExtTerminal): the three drained builtins plus the
// user DSQ dispatch drains.
var schedExtInsertRe = regexp.MustCompile(
	`^\tscx_bpf_dsq_insert\(p, (SCX_DSQ_GLOBAL|SCX_DSQ_LOCAL|SCX_DSQ_LOCAL_ON \| cpu|USER_DSQ), ` +
		`(0|SCX_SLICE_DFL|SCX_SLICE_DFL / 4|1000|SCX_SLICE_INF), ` +
		`(0|(SCX_ENQ_PREEMPT|SCX_ENQ_HEAD|enq_flags)( \| (SCX_ENQ_PREEMPT|SCX_ENQ_HEAD|enq_flags))*)\);$`)

// schedExtIterNewRe matches a generated DSQ-iterator `new` call: always
// USER_DSQ, flags from the candidate set.
var schedExtIterNewRe = regexp.MustCompile(`bpf_iter_scx_dsq_new\(&it\d+, (USER_DSQ, (0|SCX_DSQ_ITER_REV))\);`)

// TestSchedExtSurface pins the row-B contract of the sched_ext surface
// (the design's section 4(a) liveness scaffold and the per-op kfunc table):
//   - enqueue's body is the only one with a terminal insert, exactly one,
//     last in the rendered callback, never inside a branch; USER_DSQ is one
//     of its four candidates;
//   - no callback body ever emits a `return` (every scope is noReturn), so
//     select_cpu's `return prev_cpu;`, init's `return 0;` and dispatch's
//     USER_DSQ drain run on every path and the insert is reached on every
//     enqueue path; dispatch's body sits inside `if (prev) { ... }` and the
//     drain follows the block;
//   - init and exit are the sleepable programs (SEC("struct_ops.s")), init's
//     fixed prologue creates USER_DSQ; nothing else is sleepable;
//   - the DSQ iterator appears only in non-sleepable callbacks, always as
//     the complete new / next / destroy triple over USER_DSQ, with its flags
//     from the candidate set;
//   - the dispatch-only kfunc is called from dispatch only, the Terminal
//     insert and the two prologue/epilogue kfuncs are never plain calls,
//     and every cpu argument is a ctx cpu (never a literal); kick flags
//     come from the candidate set;
//   - the four instance fields are present, timeout_ms is within the
//     pinned [1000, 3000] window, flags stay within SCX_OPS_ALL_FLAGS with
//     SWITCH_PARTIAL drawn in a p~0.3-0.5 share of programs and
//     ALWAYS_ENQ_IMMED in a p~0.1 share;
//   - the spec round-trips to the same text.
func TestSchedExtSurface(t *testing.T) {
	const seeds = 512
	var partial, immed, dispatchSlots, kicks, iters int
	dsqs, slices, iterArgs := map[string]bool{}, map[string]bool{}, map[string]bool{}
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
					switch kf.Name {
					case "scx_bpf_task_cpu", "scx_bpf_create_dsq", "scx_bpf_dsq_move_to_local":
						t.Errorf("seed %d: %s: prologue/epilogue kfunc %s generated as a draw", seed, cb.Suffix, kf.Name)
					case "scx_bpf_kick_cpu":
						kicks++
					}
				case StmtSubflowIter:
					iters++
					iterArgs[st.IterSockExpr] = true
					if cb.Sleepable {
						t.Errorf("seed %d: %s: DSQ iterator in a sleepable callback", seed, cb.Suffix)
					}
					if st.CType != "struct task_struct *" || !strings.HasPrefix(st.Var, "t") {
						t.Errorf("seed %d: %s: iterator element %s %s", seed, cb.Suffix, st.CType, st.Var)
					}
					walkStmts(st.IterBody, func(in *Stmt) {
						if in.Kind == StmtSubflowIter || in.Kind == StmtDsqInsert {
							t.Errorf("seed %d: %s: nested iterator / insert inside the DSQ loop", seed, cb.Suffix)
						}
					})
				}
			})
			// Sleepable set and the dispatch guard are surface facts.
			if want := cb.Suffix == "_init" || cb.Suffix == "_exit"; cb.Sleepable != want {
				t.Errorf("seed %d: %s: Sleepable %v", seed, cb.Suffix, cb.Sleepable)
			}
			if want := map[bool]string{true: "prev", false: ""}[cb.Suffix == "_dispatch"]; cb.BodyGuard != want {
				t.Errorf("seed %d: %s: BodyGuard %q", seed, cb.Suffix, cb.BodyGuard)
			}
			if want := map[bool]int{true: 1, false: 0}[cb.Suffix == "_enqueue"]; inserts != want {
				t.Errorf("seed %d: %s: %d terminal inserts, want %d", seed, cb.Suffix, inserts, want)
			}
			// The insert is last at the top level, never nested.
			if cb.Suffix == "_enqueue" && (len(cb.Body) == 0 || cb.Body[len(cb.Body)-1].Kind != StmtDsqInsert) {
				t.Errorf("seed %d: enqueue does not end in the insert", seed)
			}
		}
		src := p.Render()
		// No generated body returns: the void callbacks have no `return` at
		// all (dispatch's drain follows the `if (prev) {}` block, so an early
		// return there would skip it), select_cpu returns only prev_cpu.
		for _, suffix := range []string{"_enqueue", "_dispatch", "_running", "_stopping", "_exit"} {
			if body := callbackText(t, src, p.SchedName+suffix); strings.Contains(body, "return") {
				t.Errorf("seed %d: a return in %s:\n%s", seed, suffix, body)
			}
		}
		if body := callbackText(t, src, p.SchedName+"_select_cpu"); strings.Count(body, "return") != 1 {
			t.Errorf("seed %d: select_cpu has a return beyond the epilogue:\n%s", seed, body)
		}
		disp := callbackText(t, src, p.SchedName+"_dispatch")
		if !strings.HasPrefix(disp, "\tif (prev) {\n\t\t/* BRF-generated body. */\n") ||
			!strings.HasSuffix(disp, "\t}\n\n\t/* Row-B drain: one task from the user DSQ to this CPU's local DSQ. */\n"+
				"\tscx_bpf_dsq_move_to_local(USER_DSQ);\n") {
			t.Errorf("seed %d: dispatch is not guard block + drain:\n%s", seed, disp)
		}
		// init renders without a ctx (`BPF_PROG(name)`), so delimit it by
		// hand: its returns are the prologue's `return ret;` (create_dsq
		// failed -> the enable fails) and the `return 0;` epilogue.
		if i := strings.Index(src, "SEC(\"struct_ops.s\")\n__s32 BPF_PROG("+p.SchedName+"_init)\n{\n"); i < 0 {
			t.Errorf("seed %d: render lacks the sleepable ctx-less init", seed)
		} else if init := src[i:]; strings.Count(init[:strings.Index(init, "\n}\n")], "return") != 2 ||
			!strings.Contains(init, "\t__s32 ret = scx_bpf_create_dsq(USER_DSQ, -1);\n\n\tif (ret)\n\t\treturn ret;\n\n") {
			t.Errorf("seed %d: init is not create_dsq prologue + epilogue:\n%s", seed, init[:strings.Index(init, "\n}\n")])
		}
		// Every iterator is the complete triple over USER_DSQ with
		// candidate flags, and the externs appear exactly when used.
		news := schedExtIterNewRe.FindAllStringSubmatch(src, -1)
		if len(news) != strings.Count(src, "bpf_iter_scx_dsq_new(&") ||
			len(news) != strings.Count(src, "bpf_iter_scx_dsq_destroy(&") ||
			len(news) != strings.Count(src, " = bpf_iter_scx_dsq_next(&") {
			t.Errorf("seed %d: DSQ iterator triple broken (%d new):\n%s", seed, len(news), src)
		}
		if (len(news) > 0) != strings.Contains(src, "extern int bpf_iter_scx_dsq_new(") {
			t.Errorf("seed %d: iterator externs vs use mismatch", seed)
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
			"SEC(\"struct_ops\")\nvoid BPF_PROG(" + p.SchedName + "_dispatch, __s32 cpu, struct task_struct *prev)",
			"SEC(\"struct_ops.s\")\n__s32 BPF_PROG(" + p.SchedName + "_init)\n",
			"SEC(\"struct_ops.s\")\nvoid BPF_PROG(" + p.SchedName + "_exit, struct scx_exit_info *ei)",
			"SEC(\"struct_ops\")\nvoid BPF_PROG(" + p.SchedName + "_enqueue, ",
			"\treturn prev_cpu;\n",
			"\treturn 0;\n",
			"#define USER_DSQ 0x100ULL\n",
			"extern __s32 scx_bpf_create_dsq(__u64 dsq_id, __s32 node) __ksym;\n",
			"extern bool scx_bpf_dsq_move_to_local(__u64 dsq_id) __ksym;\n",
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
		} else {
			if fl&SchedExtOpsSwitchPartial != 0 {
				partial++
			}
			if fl&SchedExtOpsAlwaysEnqImmed != 0 {
				immed++
			}
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
	if len(dsqs) != 4 || len(slices) != 5 {
		t.Errorf("terminal draws not covering the candidates: dsq %v slice %v", dsqs, slices)
	}
	if share := float64(partial) / seeds; share < 0.3 || share > 0.5 {
		t.Errorf("SWITCH_PARTIAL in %.2f of programs, want 0.3-0.5", share)
	}
	if share := float64(immed) / seeds; share < 0.05 || share > 0.15 {
		t.Errorf("ALWAYS_ENQ_IMMED in %.2f of programs, want ~0.1", share)
	}
	if dispatchSlots == 0 || kicks == 0 {
		t.Errorf("row-A kfuncs not exercised: dispatch_nr_slots %d kick_cpu %d", dispatchSlots, kicks)
	}
	if iters == 0 || len(iterArgs) != 2 {
		t.Errorf("DSQ iterator not exercised: %d iterators, new-args %v", iters, iterArgs)
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
		// The sleepable set survives the object: init / exit were in
		// "struct_ops.s" and digest with the PROG flag, nothing else does.
		for _, pr := range r.Progs {
			if want := pr.Member == "init" || pr.Member == "exit"; pr.Sleepable != want {
				t.Errorf("seed %d: prog %s digested Sleepable=%v", seed, pr.Member, pr.Sleepable)
			}
		}
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
