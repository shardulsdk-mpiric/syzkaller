// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package linux

import (
	"math/rand"
	"sync"
	"sync/atomic"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/structops"
	"github.com/google/syzkaller/prog"
)

// BPF struct_ops carrier: custom generation/mutation of the struct_ops object
// blob types declared in sys/linux/bpf_struct_ops.txt.
//
// One blob type per struct_ops surface; the type name selects the surface, so
// the fuzzer's choice of syz_bpf_struct_ops_load$<surface> is the surface
// rotation.  Generation renders a fresh program from pkg/structops.  Mutation
// (old != nil) re-generates: a struct_ops object is only useful if the
// verifier accepts it, so byte-level mutation of the blob (what the generic
// mutator would do to an array[int8]) is wasted effort -- a corrupt object
// fails at load.  Registering the types here is also what keeps the generic
// mutator off the blob (prog/mutation.go consults Target.SpecialTypes).
//
// The blob is the program's generative SPEC (pkg/structops/spec.go: surface
// tag + per-callback statement AST, ~1-3KB, kernel-agnostic), NOT the
// compiled load recipe.  The recipe (pkg/structops/recipe.go: BTF + insns
// baked against one kernel's vmlinux.h, 60-160KB) is materialized from the
// spec host-side right before a program is sent to the executor
// (pkg/structops/materialize, wired at syz-manager's request source), so
// what the corpus persists is lean and survives a kernel bump, while what
// the executor and the crash logs see is the self-contained kernel-specific
// form.  The executor rejects a spec blob that reaches it un-materialized
// (no manager-side compile step: tests, execprog in the VM) with EINVAL --
// inert, never crashing.
//
// When the compile step is configured (syz-manager, from kernel_obj /
// struct_ops_vmlinux_h) generation still compiles the rendered program
// once: it validates that the spec materializes against this kernel (a
// program whose render fails to compile -- kfunc/field drift -- is
// re-rolled a few times) and it warms the sha256(source) compile cache, so
// the materialize step is a cache hit.

func (arch *arch) generateStructOpsObjTCPCong(g *prog.Gen, typ prog.Type, dir prog.Dir, old prog.Arg) (
	prog.Arg, []*prog.Call) {
	return generateStructOpsObj(g, typ, dir, structops.TCPCong)
}

func (arch *arch) generateStructOpsObjMptcpSched(g *prog.Gen, typ prog.Type, dir prog.Dir, old prog.Arg) (
	prog.Arg, []*prog.Call) {
	return generateStructOpsObj(g, typ, dir, structops.MptcpSched)
}

func (arch *arch) generateStructOpsObjSchedExt(g *prog.Gen, typ prog.Type, dir prog.Dir, old prog.Arg) (
	prog.Arg, []*prog.Call) {
	return generateStructOpsObj(g, typ, dir, structops.SchedExt)
}

func generateStructOpsObj(g *prog.Gen, typ0 prog.Type, dir prog.Dir, surf *structops.Surface) (
	prog.Arg, []*prog.Call) {
	typ := typ0.(*prog.StructType)
	data := prog.MakeDataArg(typ.Fields[0].Type, dir, structOpsGenerateBlob(g.Rand(), surf))
	return prog.MakeGroupArg(typ, dir, []prog.Arg{data}), nil
}

const structOpsCompileAttempts = 3

// structOpsGenerateBlob generates one program for surf and returns its spec
// blob.  Each program is generated from its own seed (drawn from rnd) so
// the spec records a (seed, surface) provenance that regenerates it under
// the same generator version.
func structOpsGenerateBlob(rnd *rand.Rand, surf *structops.Surface) []byte {
	var spec []byte
	for attempt := 0; attempt < structOpsCompileAttempts; attempt++ {
		seed := rnd.Int63()
		sop := structops.Generate(rand.New(rand.NewSource(seed)), surf)
		spec = structops.EncodeSpec(sop, seed)
		if !structops.Configured() {
			break
		}
		_, err := structops.Compile(sop.Render())
		if err == nil {
			return spec
		}
		structOpsCompileErrors.Add(1)
		if attempt == 0 {
			structOpsLogOnce.Do(func() {
				log.Logf(0, "struct_ops: compile of a generated %s program failed (will re-roll; "+
					"logged once): %v", surf.Tag(), err)
			})
		}
	}
	return spec
}

var (
	structOpsLogOnce       sync.Once
	structOpsCompileErrors atomic.Int64
)
