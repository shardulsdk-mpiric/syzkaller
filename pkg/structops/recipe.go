// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package structops

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"sort"
)

// The load recipe.
//
// The executor must not parse ELF (docs/pseudo_syscalls.md keeps
// pseudo-syscalls free of libraries, and a reproducer must stay small), so
// the host pre-digests the compiled struct_ops object into a flat
// little-endian TLV that the loader in executor/common_linux_structops.h
// walks with fixed-width records.  Everything that is kernel-image
// specific -- kfunc BTF ids, the struct_ops value type id, member indexes
// and offsets -- is deliberately NOT in the recipe: the loader resolves
// those by name against /sys/kernel/btf/vmlinux in the VM, so the recipe
// only names things.
//
// Layout (all integers little-endian):
//
//	header:  u32 magic "SOPS" | u32 version | u32 nrec
//	record:  u32 type | u32 len | payload[len] | pad to 4
//
//	type 1 BTF       raw .BTF bytes, kernel-ready (see btf.fixupForKernel)
//	type 2 INSTANCE  u32 flags (bit 0: the instance was in .struct_ops.link;
//	                 informational -- the loader registers every surface
//	                 through a link, see common_linux_structops.h)
//	                 char struct_name[64]  ("mptcp_sched_ops")
//	type 3 PROG      char member[32]   struct member this callback fills
//	                 char name[32]     the function symbol (prog_name)
//	                 u32 func_type_id  this prog's FUNC id in the BTF
//	                 u32 nkfunc | u32 ninsn | u32 reserved
//	                 nkfunc x { u32 insn_idx; char name[64] }
//	                 ninsn  x 8-byte bpf_insn (kfunc call imm/off unpatched)
//	type 4 SPEC      u64 kernel_key | spec blob (spec.go)
//	                 the generative spec this recipe was materialized from
//	                 and the KernelKey of the vmlinux.h it was compiled
//	                 against.  Host-only: the executor skips it.  It is what
//	                 lets a recipe-form program (a crash log, a repro.syz)
//	                 be re-materialized against a different kernel
//	                 (materialize.Stale), so the kernel-specific form stays
//	                 recoverable.
//
// The C side mirrors these sizes verbatim (STRUCTOPS_* in the executor).
const (
	recipeMagic   = 0x53504f53 // "SOPS"
	recipeVersion = 1

	recBTF      = 1
	recInstance = 2
	recProg     = 3
	recSpec     = 4

	recipeInstanceFlagLink = 1 << 0

	recipeStructNameLen = 64
	recipeMemberLen     = 32
	recipeProgNameLen   = 32
	recipeKfuncNameLen  = 64
)

// Recipe is the parsed form of a load recipe (host-side mirror of what the
// executor reconstructs); it exists for tests and tooling.
type Recipe struct {
	BTF        []byte
	StructName string
	Link       bool
	Progs      []RecipeProg
	// KernelKey / Spec are the SPEC record (zero / nil when absent).
	KernelKey uint64
	Spec      []byte
}

// RecipeProg is one struct_ops callback program.
type RecipeProg struct {
	Member     string
	Name       string
	FuncTypeID uint32
	Kfuncs     []RecipeKfunc
	Insns      []byte // ninsn * 8
}

// RecipeKfunc is one kfunc call site: the instruction index within the
// prog and the kfunc's name (resolved to a vmlinux BTF id in the VM).
type RecipeKfunc struct {
	InsnIdx uint32
	Name    string
}

const (
	bpfInsnSize = 8

	// ELF relocation types (BPF).
	rBPF64_64 = 1  // 64-bit absolute (data), used for .struct_ops callback ptrs
	rBPF64_32 = 10 // 32-bit imm, used for calls to undefined (kfunc) symbols
	// ABS64 (2) is what clang emits for pointers in .struct_ops data; accept
	// both 1 and 2 there.
	rBPF64_ABS64 = 2
)

// Digest turns a compiled, stripped (llvm-strip -g) struct_ops object into
// a load recipe.  It expects exactly what pkg/structops renders: one
// instance variable in .struct_ops or .struct_ops.link, every callback in
// section "struct_ops", kfuncs as undefined symbols, no CO-RE relocations
// (the compile step uses -DBPF_NO_PRESERVE_ACCESS_INDEX) and no subprog
// calls.
func Digest(obj []byte) ([]byte, error) {
	f, err := elf.NewFile(bytes.NewReader(obj))
	if err != nil {
		return nil, fmt.Errorf("structops: not an ELF object: %w", err)
	}
	defer f.Close()
	if f.Machine != elf.EM_BPF || f.Class != elf.ELFCLASS64 || f.Data != elf.ELFDATA2LSB {
		return nil, fmt.Errorf("structops: not a little-endian 64-bit BPF object")
	}
	syms, err := f.Symbols()
	if err != nil {
		return nil, fmt.Errorf("structops: symbols: %w", err)
	}
	// ELF symbol index n maps to syms[n-1] (debug/elf drops the null symbol).
	symAt := func(n uint32) (elf.Symbol, bool) {
		if n == 0 || int(n) > len(syms) {
			return elf.Symbol{}, false
		}
		return syms[n-1], true
	}
	secData := func(name string) ([]byte, *elf.Section, error) {
		s := f.Section(name)
		if s == nil {
			return nil, nil, nil
		}
		d, err := s.Data()
		if err != nil {
			return nil, nil, fmt.Errorf("structops: section %s: %w", name, err)
		}
		return d, s, nil
	}

	// --- BTF, with the kernel fixups.
	btfData, _, err := secData(".BTF")
	if err != nil {
		return nil, err
	}
	if btfData == nil {
		return nil, fmt.Errorf("structops: object has no .BTF (compiled without -g?)")
	}
	btfData = append([]byte(nil), btfData...) // own copy: fixups mutate it
	b, err := parseBTF(btfData)
	if err != nil {
		return nil, err
	}
	secIndex := func(sec string) int {
		for i, s := range f.Sections {
			if s.Name == sec {
				return i
			}
		}
		return -1
	}
	err = b.fixupForKernel(
		func(sec string) (uint32, bool) {
			s := f.Section(sec)
			if s == nil {
				return 0, false
			}
			return uint32(s.Size), true
		},
		func(sec, name string) (uint32, bool) {
			idx := secIndex(sec)
			for _, s := range syms {
				if s.Name == name && int(s.Section) == idx {
					return uint32(s.Value), true
				}
			}
			return 0, false
		})
	if err != nil {
		return nil, err
	}

	// --- The instance: one global object in .struct_ops or .struct_ops.link.
	instSec, link := ".struct_ops", false
	instData, instS, err := secData(instSec)
	if err != nil {
		return nil, err
	}
	if instS == nil {
		instSec, link = ".struct_ops.link", true
		instData, instS, err = secData(instSec)
		if err != nil {
			return nil, err
		}
	}
	if instS == nil {
		return nil, fmt.Errorf("structops: object has neither .struct_ops nor .struct_ops.link")
	}
	instIdx := secIndex(instSec)
	var inst *elf.Symbol
	for i := range syms {
		s := &syms[i]
		if int(s.Section) == instIdx && elf.ST_TYPE(s.Info) == elf.STT_OBJECT {
			if inst != nil {
				return nil, fmt.Errorf("structops: more than one instance in %s", instSec)
			}
			inst = s
		}
	}
	if inst == nil {
		return nil, fmt.Errorf("structops: no instance object in %s", instSec)
	}
	if inst.Value != 0 || inst.Size != uint64(len(instData)) {
		return nil, fmt.Errorf("structops: instance %s does not span %s", inst.Name, instSec)
	}
	// Its struct type, through the BTF VAR of the same name.
	varID := b.findByNameKind(inst.Name, btfKindVar)
	if varID == 0 {
		return nil, fmt.Errorf("structops: no BTF VAR for instance %s", inst.Name)
	}
	structID := b.skipModifiers(b.typeSizeOrType(varID))
	if b.typeKind(structID) != btfKindStruct {
		return nil, fmt.Errorf("structops: instance %s is not a struct", inst.Name)
	}
	structName := b.typeName(structID)
	if structName == "" || len(structName) >= recipeStructNameLen {
		return nil, fmt.Errorf("structops: bad instance struct name %q", structName)
	}
	members, err := b.members(structID)
	if err != nil {
		return nil, err
	}
	memberAt := func(byteOff uint64) string {
		for _, m := range members {
			if m.bitSize == 0 && uint64(m.bitOff) == byteOff*8 {
				return m.name
			}
		}
		return ""
	}

	// --- Callback programs: FUNC symbols in section "struct_ops".
	progData, progS, err := secData("struct_ops")
	if err != nil {
		return nil, err
	}
	if progS == nil {
		return nil, fmt.Errorf("structops: object has no struct_ops program section")
	}
	progIdx := secIndex("struct_ops")
	type progSym struct {
		sym   elf.Symbol
		start uint64
		end   uint64
	}
	var progSyms []progSym
	for _, s := range syms {
		if int(s.Section) == progIdx && elf.ST_TYPE(s.Info) == elf.STT_FUNC {
			if s.Size == 0 || s.Size%bpfInsnSize != 0 || s.Value+s.Size > uint64(len(progData)) {
				return nil, fmt.Errorf("structops: prog %s has bad extent", s.Name)
			}
			progSyms = append(progSyms, progSym{s, s.Value, s.Value + s.Size})
		}
	}
	sort.Slice(progSyms, func(i, j int) bool { return progSyms[i].start < progSyms[j].start })
	if len(progSyms) == 0 {
		return nil, fmt.Errorf("structops: no callback programs")
	}

	// Which member each prog fills: .rel<instSec> relocs within the instance.
	progMember := map[string]string{}
	if err := forEachRel(f, ".rel"+instSec, func(off uint64, typ uint32, symIdx uint32) error {
		s, ok := symAt(symIdx)
		if !ok {
			return fmt.Errorf("structops: %s: bad symbol index %d", ".rel"+instSec, symIdx)
		}
		if typ != rBPF64_64 && typ != rBPF64_ABS64 {
			return fmt.Errorf("structops: %s: unexpected reloc type %d", ".rel"+instSec, typ)
		}
		member := memberAt(off)
		if member == "" {
			return fmt.Errorf("structops: %s: offset %#x is not a member of %s", ".rel"+instSec, off, structName)
		}
		if len(member) >= recipeMemberLen {
			return fmt.Errorf("structops: member name %q too long", member)
		}
		progMember[s.Name] = member
		return nil
	}); err != nil {
		return nil, err
	}

	// Kfunc call sites: .relstruct_ops relocs against undefined symbols.
	kfuncs := map[string][]RecipeKfunc{}
	if err := forEachRel(f, ".relstruct_ops", func(off uint64, typ uint32, symIdx uint32) error {
		s, ok := symAt(symIdx)
		if !ok {
			return fmt.Errorf("structops: .relstruct_ops: bad symbol index %d", symIdx)
		}
		if s.Section != elf.SHN_UNDEF {
			return fmt.Errorf("structops: .relstruct_ops: reloc against defined symbol %s (subprog calls are not supported)", s.Name)
		}
		if typ != rBPF64_32 {
			return fmt.Errorf("structops: .relstruct_ops: unexpected reloc type %d for %s", typ, s.Name)
		}
		if len(s.Name) >= recipeKfuncNameLen {
			return fmt.Errorf("structops: kfunc name %q too long", s.Name)
		}
		for _, p := range progSyms {
			if off >= p.start && off < p.end {
				kfuncs[p.sym.Name] = append(kfuncs[p.sym.Name],
					RecipeKfunc{InsnIdx: uint32((off - p.start) / bpfInsnSize), Name: s.Name})
				return nil
			}
		}
		return fmt.Errorf("structops: .relstruct_ops: offset %#x in no program", off)
	}); err != nil {
		return nil, err
	}

	r := &Recipe{BTF: b.data, StructName: structName, Link: link} // b.data: post-fixup (may be rebuilt)
	for _, p := range progSyms {
		member, ok := progMember[p.sym.Name]
		if !ok {
			return nil, fmt.Errorf("structops: prog %s is not referenced by the instance", p.sym.Name)
		}
		if len(p.sym.Name) >= recipeProgNameLen {
			return nil, fmt.Errorf("structops: prog name %q too long", p.sym.Name)
		}
		funcID := b.findByNameKind(p.sym.Name, btfKindFunc)
		if funcID == 0 {
			return nil, fmt.Errorf("structops: no BTF FUNC for prog %s", p.sym.Name)
		}
		r.Progs = append(r.Progs, RecipeProg{
			Member:     member,
			Name:       p.sym.Name,
			FuncTypeID: funcID,
			Kfuncs:     kfuncs[p.sym.Name],
			Insns:      progData[p.start:p.end],
		})
	}
	return r.Marshal(), nil
}

// forEachRel walks a REL section (16-byte Elf64_Rel entries).
func forEachRel(f *elf.File, name string, fn func(off uint64, typ, sym uint32) error) error {
	s := f.Section(name)
	if s == nil {
		return nil
	}
	d, err := s.Data()
	if err != nil {
		return fmt.Errorf("structops: %s: %w", name, err)
	}
	if len(d)%16 != 0 {
		return fmt.Errorf("structops: %s: bad size %d", name, len(d))
	}
	le := binary.LittleEndian
	for i := 0; i < len(d); i += 16 {
		off := le.Uint64(d[i:])
		info := le.Uint64(d[i+8:])
		if err := fn(off, uint32(info&0xffffffff), uint32(info>>32)); err != nil {
			return err
		}
	}
	return nil
}

// tlvWriter accumulates little-endian fields.
type tlvWriter struct{ bytes.Buffer }

func (w *tlvWriter) u32(v uint32) {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	w.Write(b[:])
}

// str writes s NUL-padded to a fixed width n.
func (w *tlvWriter) str(s string, n int) {
	buf := make([]byte, n)
	copy(buf, s)
	w.Write(buf)
}

// rec writes one record: type, length, payload, zero padding to 4 bytes.
func (w *tlvWriter) rec(typ uint32, payload []byte) {
	w.u32(typ)
	w.u32(uint32(len(payload)))
	w.Write(payload)
	w.Write(make([]byte, (4-len(payload)%4)%4))
}

// Marshal serialises the recipe to its TLV form.
func (r *Recipe) Marshal() []byte {
	var w tlvWriter
	w.u32(recipeMagic)
	w.u32(recipeVersion)
	nrec := 2 + len(r.Progs)
	if len(r.Spec) != 0 {
		nrec++
	}
	w.u32(uint32(nrec))
	w.rec(recBTF, r.BTF)

	var inst tlvWriter
	flags := uint32(0)
	if r.Link {
		flags |= recipeInstanceFlagLink
	}
	inst.u32(flags)
	inst.str(r.StructName, recipeStructNameLen)
	w.rec(recInstance, inst.Bytes())

	for _, p := range r.Progs {
		var pw tlvWriter
		pw.str(p.Member, recipeMemberLen)
		pw.str(p.Name, recipeProgNameLen)
		pw.u32(p.FuncTypeID)
		pw.u32(uint32(len(p.Kfuncs)))
		pw.u32(uint32(len(p.Insns) / bpfInsnSize))
		pw.u32(0)
		for _, k := range p.Kfuncs {
			pw.u32(k.InsnIdx)
			pw.str(k.Name, recipeKfuncNameLen)
		}
		pw.Write(p.Insns)
		w.rec(recProg, pw.Bytes())
	}
	if len(r.Spec) != 0 {
		w.specRec(r.KernelKey, r.Spec)
	}
	return w.Bytes()
}

func (w *tlvWriter) specRec(kernelKey uint64, spec []byte) {
	payload := make([]byte, 8+len(spec))
	binary.LittleEndian.PutUint64(payload, kernelKey)
	copy(payload[8:], spec)
	w.rec(recSpec, payload)
}

// AttachSpec appends a SPEC record (kernelKey + spec) to a recipe that has
// none: the materializer calls it on Compile's output so the exec/log form
// of a program carries its own generative spec.  A recipe that already has
// one is returned unchanged.
func AttachSpec(recipe []byte, kernelKey uint64, spec []byte) ([]byte, error) {
	if !IsRecipe(recipe) {
		return nil, fmt.Errorf("recipe: AttachSpec on a non-recipe")
	}
	if _, _, ok := RecipeSpec(recipe); ok {
		return recipe, nil
	}
	le := binary.LittleEndian
	nrec := le.Uint32(recipe[8:])
	out := make([]byte, len(recipe), len(recipe)+16+len(spec))
	copy(out, recipe)
	le.PutUint32(out[8:], nrec+1)
	var w tlvWriter
	w.specRec(kernelKey, spec)
	return append(out, w.Bytes()...), nil
}

// RecipeSpec returns the SPEC record of a recipe, if it carries one.  It
// walks only the record headers, so it is cheap to call per program.
func RecipeSpec(recipe []byte) (kernelKey uint64, spec []byte, ok bool) {
	le := binary.LittleEndian
	if !IsRecipe(recipe) || le.Uint32(recipe[4:]) != recipeVersion {
		return 0, nil, false
	}
	nrec := le.Uint32(recipe[8:])
	pos := 12
	for i := uint32(0); i < nrec; i++ {
		if len(recipe)-pos < 8 {
			return 0, nil, false
		}
		typ, n := le.Uint32(recipe[pos:]), int(le.Uint32(recipe[pos+4:]))
		pos += 8
		if len(recipe)-pos < n {
			return 0, nil, false
		}
		if typ == recSpec {
			if n < 8 {
				return 0, nil, false
			}
			return le.Uint64(recipe[pos:]), recipe[pos+8 : pos+n], true
		}
		pos += (n + 3) &^ 3
	}
	return 0, nil, false
}

// ParseRecipe decodes a TLV recipe (the inverse of Marshal); used by tests.
func ParseRecipe(data []byte) (*Recipe, error) {
	le := binary.LittleEndian
	if len(data) < 12 || le.Uint32(data) != recipeMagic || le.Uint32(data[4:]) != recipeVersion {
		return nil, fmt.Errorf("recipe: bad header")
	}
	nrec := le.Uint32(data[8:])
	pos := 12
	r := &Recipe{}
	cstr := func(b []byte) string {
		if i := bytes.IndexByte(b, 0); i >= 0 {
			return string(b[:i])
		}
		return string(b)
	}
	for i := uint32(0); i < nrec; i++ {
		if len(data)-pos < 8 {
			return nil, fmt.Errorf("recipe: truncated record header")
		}
		typ, n := le.Uint32(data[pos:]), int(le.Uint32(data[pos+4:]))
		pos += 8
		if len(data)-pos < n {
			return nil, fmt.Errorf("recipe: truncated record %d", typ)
		}
		p := data[pos : pos+n]
		pos += (n + 3) &^ 3
		switch typ {
		case recBTF:
			r.BTF = p
		case recInstance:
			if n != 4+recipeStructNameLen {
				return nil, fmt.Errorf("recipe: bad INSTANCE size %d", n)
			}
			r.Link = le.Uint32(p)&recipeInstanceFlagLink != 0
			r.StructName = cstr(p[4:])
		case recProg:
			hdr := recipeMemberLen + recipeProgNameLen + 16
			if n < hdr {
				return nil, fmt.Errorf("recipe: bad PROG size %d", n)
			}
			pr := RecipeProg{
				Member:     cstr(p[:recipeMemberLen]),
				Name:       cstr(p[recipeMemberLen : recipeMemberLen+recipeProgNameLen]),
				FuncTypeID: le.Uint32(p[hdr-16:]),
			}
			nk, ni := int(le.Uint32(p[hdr-12:])), int(le.Uint32(p[hdr-8:]))
			q := hdr
			if n != hdr+nk*(4+recipeKfuncNameLen)+ni*bpfInsnSize {
				return nil, fmt.Errorf("recipe: PROG %s size mismatch", pr.Name)
			}
			for j := 0; j < nk; j++ {
				pr.Kfuncs = append(pr.Kfuncs, RecipeKfunc{
					InsnIdx: le.Uint32(p[q:]),
					Name:    cstr(p[q+4 : q+4+recipeKfuncNameLen]),
				})
				q += 4 + recipeKfuncNameLen
			}
			pr.Insns = p[q:]
			r.Progs = append(r.Progs, pr)
		case recSpec:
			if n < 8 {
				return nil, fmt.Errorf("recipe: bad SPEC size %d", n)
			}
			r.KernelKey = le.Uint64(p)
			r.Spec = p[8:]
		default:
			return nil, fmt.Errorf("recipe: unknown record type %d", typ)
		}
	}
	return r, nil
}

// IsRecipe reports whether data starts with the recipe magic (as opposed
// to the rendered C source the generator falls back to when no compiler
// is configured).
func IsRecipe(data []byte) bool {
	return len(data) >= 12 && binary.LittleEndian.Uint32(data) == recipeMagic
}
