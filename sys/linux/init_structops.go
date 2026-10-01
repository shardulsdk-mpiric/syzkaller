// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package linux

import (
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
// The blob is the load recipe pkg/structops.Compile produces from the
// rendered C translation unit (clang -O2 -g -target bpf -mcpu=v3
// -DBPF_NO_PRESERVE_ACCESS_INDEX against the target kernel's vmlinux.h,
// llvm-strip -g, then an ELF pre-digest into a flat TLV the executor loads
// with raw bpf() calls; see pkg/structops/recipe.go).  The compile step is
// configured by syz-manager from kernel_obj / struct_ops_vmlinux_h.  When
// it is not configured (tests, tools that only parse programs) the blob
// carries the rendered source instead, which the executor rejects at load
// (EINVAL, no recipe magic) -- inert, never crashing.  A program whose
// render fails to compile (kfunc/field drift against the kernel) is
// re-rolled a few times, then also falls back to the inert source blob.

func (arch *arch) generateStructOpsObjTCPCong(g *prog.Gen, typ prog.Type, dir prog.Dir, old prog.Arg) (
	prog.Arg, []*prog.Call) {
	return generateStructOpsObj(g, typ, dir, structops.TCPCong)
}

func (arch *arch) generateStructOpsObjMptcpSched(g *prog.Gen, typ prog.Type, dir prog.Dir, old prog.Arg) (
	prog.Arg, []*prog.Call) {
	return generateStructOpsObj(g, typ, dir, structops.MptcpSched)
}

func generateStructOpsObj(g *prog.Gen, typ0 prog.Type, dir prog.Dir, surf *structops.Surface) (
	prog.Arg, []*prog.Call) {
	typ := typ0.(*prog.StructType)
	data := prog.MakeDataArg(typ.Fields[0].Type, dir, structOpsGenerateBlob(g, surf))
	return prog.MakeGroupArg(typ, dir, []prog.Arg{data}), nil
}

const structOpsCompileAttempts = 3

func structOpsGenerateBlob(g *prog.Gen, surf *structops.Surface) []byte {
	var src string
	for attempt := 0; attempt < structOpsCompileAttempts; attempt++ {
		src = structops.Generate(g.Rand(), surf).Render()
		if !structops.Configured() {
			break
		}
		recipe, err := structops.Compile(src)
		if err == nil {
			return recipe
		}
		structOpsCompileErrors.Add(1)
		if attempt == 0 {
			structOpsLogOnce.Do(func() {
				log.Logf(0, "struct_ops: compile of a generated %s program failed (will re-roll; "+
					"logged once): %v", surf.Tag(), err)
			})
		}
	}
	return []byte(src)
}

var (
	structOpsLogOnce       sync.Once
	structOpsCompileErrors atomic.Int64
)
