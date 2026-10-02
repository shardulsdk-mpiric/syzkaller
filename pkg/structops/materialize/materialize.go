// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package materialize is the host-side spec->recipe step of the BPF
// struct_ops carrier.
//
// The fuzzer generates, mutates and persists struct_ops programs in their
// generative spec form (pkg/structops/spec.go): small and kernel-agnostic.
// The executor needs the load recipe (pkg/structops/recipe.go) compiled
// against the kernel it runs on, and it cannot compile (no clang in the
// VM).  So the two forms have to diverge somewhere host-side, after a
// program leaves the fuzzer and before it reaches the executor, without
// the recipe form leaking back into the corpus.
//
// That point is the manager's request source: the queue.Source syz-manager
// hands to the rpcserver (Manager.MachineChecked).  Source wraps it; for
// every request whose program carries struct_ops blobs it hands the
// consumer a SHADOW request with a materialized clone and forwards the
// shadow's completion to the original.  Downstream of the boundary -- the
// executor, the rpcserver's "executing program" log that crash reports and
// pkg/repro read -- sees the self-contained kernel-specific form that a
// reproducer needs (repro ships program text to syz-execprog in the VM, so
// a log form that still needed compiling would not reproduce).  Upstream
// -- fuzzer triage, corpus.db, the fuzzer's own job logs -- never sees the
// recipe.  Nothing in prog/, pkg/fuzzer or pkg/rpcserver changes.
//
// Materializing is Decode(spec) -> Render -> Compile, and Compile is cached
// by sha256(source) (in memory and on disk under the per-kernel cache
// root), with generation compiling once to warm it, so per-exec cost is a
// lookup.  The recipe handed out carries a SPEC record (the spec + the
// kernel key it was compiled for), so a recipe-form program that comes
// back around -- a repro.syz seeded into a later campaign on another
// kernel -- is recognized as stale by its key and re-materialized from its
// own spec instead of running inert.
package materialize

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/structops"
	"github.com/google/syzkaller/prog"
)

// ObjTypePrefix is the name prefix of the struct_ops object blob struct
// types (sys/linux/bpf_struct_ops.txt: bpf_struct_ops_obj_<surface>, whose
// single field is the array[int8] blob).  The walker recognizes blobs by
// it; sys/linux's test pins the SpecialTypes names to it.
const ObjTypePrefix = "bpf_struct_ops_obj_"

// Materializer turns struct_ops spec blobs into load recipes with a given
// compile step.  Default() binds it to pkg/structops' configured compiler.
type Materializer struct {
	compile   func(src string) ([]byte, error)
	kernelKey func() uint64
	stats     stats
	logOnce   sync.Once
}

type stats struct {
	programs, blobs, rematerialized, failed atomic.Int64
}

// Stats are the materializer's counters.
type Stats struct {
	// Programs is the number of programs handed out with at least one
	// materialized blob; Blobs counts blobs materialized from a spec,
	// Rematerialized those re-done from a stale recipe's embedded spec,
	// Failed those left as they were (decode/compile failure: inert).
	Programs, Blobs, Rematerialized, Failed int64
}

// New returns a materializer using compile for spec->recipe and kernelKey
// as the identity of the kernel compile targets (recipes carrying another
// key are stale).  Tests inject both.
func New(compile func(src string) ([]byte, error), kernelKey func() uint64) *Materializer {
	return &Materializer{compile: compile, kernelKey: kernelKey}
}

// Default returns a materializer bound to the configured pkg/structops
// compile step (structops.Configure).
func Default() *Materializer {
	return New(structops.Compile, structops.KernelKey)
}

// Stats returns the counters.
func (m *Materializer) Stats() Stats {
	return Stats{
		Programs:       m.stats.programs.Load(),
		Blobs:          m.stats.blobs.Load(),
		Rematerialized: m.stats.rematerialized.Load(),
		Failed:         m.stats.failed.Load(),
	}
}

// Blob materializes one struct_ops blob.  A spec becomes a recipe (with
// its SPEC record); a recipe whose embedded kernel key differs from the
// live one is re-materialized from its embedded spec; anything else (a
// recipe for this kernel, a legacy recipe with no spec, a non-blob) is
// returned as is.  changed reports whether out differs from data.  On
// error out is data, so the caller can always use out.
func (m *Materializer) Blob(data []byte) (out []byte, changed bool, err error) {
	switch {
	case structops.IsSpec(data):
		out, err = m.fromSpec(data)
		if err != nil {
			return data, false, err
		}
		m.stats.blobs.Add(1)
		return out, true, nil
	case structops.IsRecipe(data):
		key, spec, ok := structops.RecipeSpec(data)
		live := m.kernelKey()
		if !ok || live == 0 || key == live {
			return data, false, nil
		}
		out, err = m.fromSpec(spec)
		if err != nil {
			return data, false, fmt.Errorf("stale recipe (kernel %016x, live %016x): %w", key, live, err)
		}
		m.stats.rematerialized.Add(1)
		return out, true, nil
	}
	return data, false, nil
}

func (m *Materializer) fromSpec(spec []byte) ([]byte, error) {
	sop, err := structops.DecodeSpec(spec)
	if err != nil {
		return nil, err
	}
	recipe, err := m.compile(sop.Render())
	if err != nil {
		return nil, err
	}
	return structops.AttachSpec(recipe, m.kernelKey(), spec)
}

// Prog returns p with every struct_ops blob materialized: p itself when
// nothing needed doing, otherwise a clone (p is never modified -- it is
// the fuzzer's, and what the corpus will persist).  Blobs that fail to
// materialize are left as they are in the clone (the executor rejects them
// with EINVAL) and counted; the first failure is logged.
func (m *Materializer) Prog(p *prog.Prog) (*prog.Prog, bool) {
	var work []*prog.DataArg
	for _, c := range p.Calls {
		forEachBlob(c, func(arg *prog.DataArg) {
			if m.needsWork(arg.Data()) {
				work = append(work, arg)
			}
		})
	}
	if len(work) == 0 {
		return p, false
	}
	// Clone and redo the walk on the clone (args are fresh objects); the
	// clone's len args are re-derived by the Builder below.
	q := p.Clone()
	changedAny := false
	for _, c := range q.Calls {
		forEachBlob(c, func(arg *prog.DataArg) {
			out, changed, err := m.Blob(arg.Data())
			if err != nil {
				m.stats.failed.Add(1)
				m.logOnce.Do(func() {
					log.Logf(0, "struct_ops: materialize failed (sent inert; logged once): %v", err)
				})
				return
			}
			if changed {
				arg.SetData(out)
				changedAny = true
			}
		})
	}
	if !changedAny {
		return p, false
	}
	// A blob's size feeds the call's `len bytesize[obj]` argument; the
	// Builder's Append re-assigns sizes (prog keeps that unexported).
	pg := prog.MakeProgGen(p.Target)
	for _, c := range q.Calls {
		if err := pg.Append(c); err != nil {
			return p, false
		}
	}
	q, err := pg.Finalize()
	if err != nil {
		m.stats.failed.Add(1)
		m.logOnce.Do(func() {
			log.Logf(0, "struct_ops: materialized program rejected (sent as is; logged once): %v", err)
		})
		return p, false
	}
	m.stats.programs.Add(1)
	return q, true
}

func (m *Materializer) needsWork(data []byte) bool {
	if structops.IsSpec(data) {
		return true
	}
	if structops.IsRecipe(data) {
		key, _, ok := structops.RecipeSpec(data)
		live := m.kernelKey()
		return ok && live != 0 && key != live
	}
	return false
}

// forEachBlob calls fn on every struct_ops object blob (the data field of
// a bpf_struct_ops_obj_* struct) in c.
func forEachBlob(c *prog.Call, fn func(*prog.DataArg)) {
	prog.ForeachArg(c, func(arg prog.Arg, ctx *prog.ArgCtx) {
		group, ok := arg.(*prog.GroupArg)
		if !ok || len(group.Inner) != 1 || !strings.HasPrefix(group.Type().Name(), ObjTypePrefix) {
			return
		}
		data, ok := group.Inner[0].(*prog.DataArg)
		if !ok || data.Dir() == prog.DirOut {
			return
		}
		ctx.Stop = true
		fn(data)
	})
}

// Source wraps src so that every program request with struct_ops blobs
// reaches the consumer as a shadow request carrying the materialized
// program.  The shadow completes the original with its result, so the
// producer (the fuzzer) observes nothing but the result; requests without
// struct_ops work pass through untouched.
func (m *Materializer) Source(src queue.Source) queue.Source {
	return &source{m: m, src: src}
}

type source struct {
	m   *Materializer
	src queue.Source
}

func (s *source) Next() *queue.Request {
	req := s.src.Next()
	if req == nil || req.Type != flatrpc.RequestTypeProgram || req.Prog == nil {
		return req
	}
	p, changed := s.m.Prog(req.Prog)
	if !changed {
		return req
	}
	return shadow(req, p)
}

// shadow is a copy of req executing p in its place.  Stat stays on the
// original (Done bumps it once, when the forwarded result lands).
func shadow(req *queue.Request, p *prog.Prog) *queue.Request {
	s := &queue.Request{
		Type:            req.Type,
		ExecOpts:        req.ExecOpts,
		Prog:            p,
		ReturnAllSignal: req.ReturnAllSignal,
		ReturnError:     req.ReturnError,
		ReturnOutput:    req.ReturnOutput,
		Important:       req.Important,
		Avoid:           req.Avoid,
	}
	s.OnDone(func(_ *queue.Request, res *queue.Result) bool {
		req.Done(res)
		return true
	})
	return s
}
