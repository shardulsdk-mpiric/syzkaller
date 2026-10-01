// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package linux

import (
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
// The blob carries the rendered C translation unit.  The host compile step
// that turns it into the ELF object the executor loads -- clang -O2 -g
// -target bpf -mcpu=v3 -DBPF_NO_PRESERVE_ACCESS_INDEX against the target
// kernel's vmlinux.h, then llvm-strip -g -- slots in between Render and
// MakeDataArg below.

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
	src := structops.Generate(g.Rand(), surf).Render()
	data := prog.MakeDataArg(typ.Fields[0].Type, dir, []byte(src))
	return prog.MakeGroupArg(typ, dir, []prog.Arg{data}), nil
}
