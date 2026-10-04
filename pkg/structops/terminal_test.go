// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package structops

import (
	"math/rand"
	"regexp"
	"strings"
	"testing"
)

// testTerminalKfuncs is a SYNTHETIC sched_ext-shaped kfunc table for the
// terminal / void-guard tests: the real scx_bpf_dsq_insert prototype
// (kernel/sched/ext/ext.c) marked Terminal, a scalar kfunc callable from
// the ctx task, and a made-up KF_RET_NULL pointer kfunc so a void callback
// has a guard to render.  Not a kernel contract; the sched_ext surface row
// (Phase 2) carries the real tables.
var testTerminalKfuncs = []Kfunc{
	{
		Name: "scx_bpf_dsq_insert",
		CDecl: "extern void scx_bpf_dsq_insert(struct task_struct *p, __u64 dsq_id, " +
			"__u64 slice, __u64 enq_flags) __ksym;",
		RetType:  "",
		ArgTypes: []string{"struct task_struct *", "__u64", "__u64", "__u64"},
		Terminal: true,
	},
	{
		Name:     "scx_bpf_task_cpu",
		CDecl:    "extern __u32 scx_bpf_task_cpu(const struct task_struct *p) __ksym;",
		RetType:  "__u32",
		ArgTypes: []string{"const struct task_struct *"},
	},
	{
		Name:     "test_task_ptr_or_null",
		CDecl:    "extern struct cgroup *test_task_ptr_or_null(struct task_struct *p) __ksym;",
		RetType:  "struct cgroup *",
		ArgTypes: []string{"struct task_struct *"},
		IsPtrRet: true,
		RetNull:  true,
	},
}

var testTerminal = &terminalInsert{
	kfunc:    "scx_bpf_dsq_insert",
	task:     "p",
	dsqIDs:   []string{"SCX_DSQ_GLOBAL", "SCX_DSQ_LOCAL"},
	slices:   []string{"0", "SCX_SLICE_DFL", "SCX_SLICE_INF"},
	enqFlags: []string{"SCX_ENQ_PREEMPT", "SCX_ENQ_HEAD"},
}

// testTerminalSurface registers a two-callback surface for the test's
// lifetime: a void `enqueue` whose body ends in the terminal insert (under
// noReturn, as the sched_ext design's liveness scaffold requires), and a
// void `running` with noReturn CLEAR, so a KF_RET_NULL guard renders in a
// void callback.
func testTerminalSurface(t *testing.T) *Surface {
	t.Helper()
	fields := []CtxField{
		{Owner: "struct task_struct", Field: "scx.slice", Accessor: "p->scx.slice", CType: "__u64"},
		{Owner: "struct task_struct", Field: "scx.dsq_vtime", Accessor: "p->scx.dsq_vtime", CType: "__u64"},
	}
	pool := []typedVal{{expr: "p", ctype: "struct task_struct *"}}
	s := &Surface{
		tag:                "terminal_test",
		instanceStruct:     "struct sched_ext_ops",
		linkSection:        ".struct_ops.link",
		progSection:        "struct_ops",
		nameMax:            16,
		namePrefix:         "t_",
		ctxType:            "struct task_struct *",
		ctxVar:             "p",
		kfuncs:             testTerminalKfuncs,
		writeFields:        fields,
		kfuncExternComment: "/* synthetic test kfuncs. */",
		headerComment:      "/* terminal / void-guard test surface. */",
		instanceCallbackOrder: []instanceField{
			{"_enqueue", "\t"},
			{"_running", "\t"},
		},
		nameSep: "\t\t",
		callbacks: []callbackSpec{
			{
				suffix:       "_enqueue",
				retType:      "void",
				argsAfterCtx: []string{"__u64 enq_flags"},
				scope: func(surf *Surface) bodyScope {
					return bodyScope{
						pool:        pool,
						writeFields: surf.resolveWriteFields(),
						noReturn:    true,
						allowIf:     true,
						minStmt:     2,
						maxStmt:     6,
						terminal:    testTerminal,
					}
				},
			},
			{
				suffix:  "_running",
				retType: "void",
				scope: func(surf *Surface) bodyScope {
					return bodyScope{
						pool:        pool,
						writeFields: surf.resolveWriteFields(),
						noReturn:    false,
						allowIf:     true,
						minStmt:     2,
						maxStmt:     5,
					}
				},
			},
		},
		renderOrder: []string{"_enqueue", "_running"},
	}
	surfaces[s.tag] = s
	t.Cleanup(func() { delete(surfaces, s.tag) })
	return s
}

var terminalCallRe = regexp.MustCompile(
	`^\tscx_bpf_dsq_insert\(p, (SCX_DSQ_GLOBAL|SCX_DSQ_LOCAL), (0|SCX_SLICE_DFL|SCX_SLICE_INF), ` +
		`(0|SCX_ENQ_PREEMPT|SCX_ENQ_HEAD|SCX_ENQ_PREEMPT \| SCX_ENQ_HEAD)\);$`)

// callbackText returns the body text of the rendered callback whose name
// ends in suffix: the lines between its `{` and the matching `}`.
func callbackText(t *testing.T, src, name string) string {
	t.Helper()
	i := strings.Index(src, "BPF_PROG("+name+",")
	if i < 0 {
		t.Fatalf("render lacks %s:\n%s", name, src)
	}
	rest := src[i:]
	open := strings.Index(rest, "\n{\n")
	end := strings.Index(rest, "\n}\n")
	if open < 0 || end < open {
		t.Fatalf("cannot delimit %s:\n%s", name, src)
	}
	return rest[open+3 : end+1]
}

// TestStructOpsTerminalInsert pins the terminal-statement contract: a
// scope with bodyScope.terminal ends its body with exactly one
// StmtDsqInsert -- last in the statement list, last in the rendered text,
// never inside a branch, never in a scope without a terminal -- the
// Terminal kfunc is never a generated StmtKfuncCall draw, and the insert's
// three fuzzed arguments vary over the candidate sets.
func TestStructOpsTerminalInsert(t *testing.T) {
	surf := testTerminalSurface(t)
	dsqs, slices, flags := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for seed := int64(0); seed < 256; seed++ {
		p := Generate(rand.New(rand.NewSource(seed)), surf)
		enq := p.body("_enqueue")
		if len(enq) == 0 || enq[len(enq)-1].Kind != StmtDsqInsert {
			t.Fatalf("seed %d: enqueue does not end in StmtDsqInsert: %+v", seed, enq)
		}
		for _, cb := range p.Callbacks {
			inserts, termCalls := 0, 0
			walkStmts(cb.Body, func(st *Stmt) {
				switch st.Kind {
				case StmtDsqInsert:
					inserts++
					if !p.Kfuncs[st.KfuncIdx].Terminal || len(st.KfuncArgs) != 4 || st.KfuncArgs[0] != "p" {
						t.Errorf("seed %d: malformed insert %+v", seed, *st)
					}
				case StmtKfuncCall:
					if p.Kfuncs[st.KfuncIdx].Terminal {
						termCalls++
					}
				}
			})
			if termCalls != 0 {
				t.Errorf("seed %d: %s: Terminal kfunc generated as a plain call", seed, cb.Suffix)
			}
			want := 0
			if cb.Suffix == "_enqueue" {
				want = 1
			}
			if inserts != want {
				t.Errorf("seed %d: %s: %d terminal inserts, want %d", seed, cb.Suffix, inserts, want)
			}
		}
		src := p.Render()
		body := callbackText(t, src, p.SchedName+"_enqueue")
		lines := strings.Split(strings.TrimRight(body, "\n"), "\n")
		last := lines[len(lines)-1]
		m := terminalCallRe.FindStringSubmatch(last)
		if m == nil {
			t.Fatalf("seed %d: enqueue's last line is not the terminal insert: %q\n%s", seed, last, src)
		}
		dsqs[m[1]], slices[m[2]], flags[m[3]] = true, true, true
		if n := strings.Count(src, "scx_bpf_dsq_insert("); n != 2 { // the extern + the one call
			t.Errorf("seed %d: %d scx_bpf_dsq_insert( occurrences, want 2 (extern + call)", seed, n)
		}
		if strings.Contains(callbackText(t, src, p.SchedName+"_running"), "scx_bpf_dsq_insert") {
			t.Errorf("seed %d: insert leaked into running", seed)
		}
		// Spec round trip carries the insert and its draws.
		q, err := DecodeSpec(EncodeSpec(p, seed))
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		if q.Render() != src {
			t.Fatalf("seed %d: spec re-render differs", seed)
		}
		assertNoScopeLeak(t, seed, src)
	}
	if len(dsqs) != 2 || len(slices) != 3 || len(flags) != 4 {
		t.Errorf("terminal draws not covering the candidates: dsq %v slice %v flags %v", dsqs, slices, flags)
	}

	// The spec references the insert kfunc by NAME: decoding against a
	// reordered table still resolves it to the Terminal entry.
	p := Generate(rand.New(rand.NewSource(5)), surf)
	spec := EncodeSpec(p, 5)
	saved := surf.kfuncs
	rev := make([]Kfunc, len(saved))
	for i := range saved {
		rev[len(saved)-1-i] = saved[i]
	}
	surf.kfuncs = rev
	q, err := DecodeSpec(spec)
	surf.kfuncs = saved
	if err != nil {
		t.Fatal(err)
	}
	enq := q.body("_enqueue")
	if st := enq[len(enq)-1]; st.Kind != StmtDsqInsert || q.Kfuncs[st.KfuncIdx].Name != "scx_bpf_dsq_insert" {
		t.Errorf("insert kfunc not remapped by name: %+v", st)
	}

	// A terminal naming a kfunc that is not a Terminal table entry is a
	// surface-table error and panics at generation.
	func() {
		defer func() {
			if recover() == nil {
				t.Error("terminal on a non-Terminal kfunc did not panic")
			}
		}()
		bad := *surf
		bad.callbacks = []callbackSpec{{
			suffix: "_enqueue", retType: "void",
			scope: func(s *Surface) bodyScope {
				return bodyScope{pool: []typedVal{{expr: "p", ctype: "struct task_struct *"}},
					writeFields: s.resolveWriteFields(), noReturn: true, minStmt: 1, maxStmt: 1,
					terminal: &terminalInsert{kfunc: "scx_bpf_task_cpu", task: "p",
						dsqIDs: []string{"SCX_DSQ_GLOBAL"}, slices: []string{"0"}}}
			},
		}}
		Generate(rand.New(rand.NewSource(0)), &bad)
	}()
}

// TestStructOpsVoidGuard pins the void-callback KF_RET_NULL guard: in a
// void callback whose scope allows an early return, a guarded pointer
// kfunc is offered and its guard renders as `return;`, never `return -1;`;
// the value-returning surfaces keep `return -1;` (the golden hash is the
// oracle for those; this checks the form directly).
func TestStructOpsVoidGuard(t *testing.T) {
	if guardReturn("void") != "return;" || guardReturn("int") != "return -1;" || guardReturn("__u32") != "return -1;" {
		t.Fatal("guardReturn forms")
	}
	surf := testTerminalSurface(t)
	guards := 0
	for seed := int64(0); seed < 256; seed++ {
		p := Generate(rand.New(rand.NewSource(seed)), surf)
		src := p.Render()
		if strings.Contains(src, "return -1;") {
			t.Fatalf("seed %d: `return -1;` in a surface of void callbacks:\n%s", seed, src)
		}
		walkStmts(p.body("_enqueue"), func(st *Stmt) {
			if st.NullGuard {
				t.Errorf("seed %d: guarded kfunc offered under noReturn (enqueue)", seed)
			}
		})
		walkStmts(p.body("_running"), func(st *Stmt) {
			if st.NullGuard {
				guards++
			}
		})
		// Every guard line is followed by a bare return at one deeper indent.
		lines := strings.Split(src, "\n")
		for i, l := range lines {
			if strings.HasPrefix(strings.TrimLeft(l, "\t"), "if (!s") {
				indent := l[:len(l)-len(strings.TrimLeft(l, "\t"))]
				if i+1 >= len(lines) || lines[i+1] != indent+"\treturn;" {
					t.Errorf("seed %d: guard %q not followed by `return;`: %q", seed, l, lines[i+1])
				}
			}
		}
	}
	if guards == 0 {
		t.Error("no KF_RET_NULL guard generated in a void callback over 256 seeds")
	}
	// The MPTCP get_send (int) still guards with `return -1;`.
	found := false
	for seed := int64(0); seed < 64 && !found; seed++ {
		src := Generate(rand.New(rand.NewSource(seed)), MptcpSched).Render()
		found = strings.Contains(src, "\t\treturn -1;\n") && !strings.Contains(src, "\treturn;\n")
	}
	if !found {
		t.Error("no `return -1;` guard in 64 MPTCP seeds")
	}
}
