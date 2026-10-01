// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package structops

import (
	"encoding/binary"
	"fmt"
)

// A minimal reader/patcher for the BTF of a compiled BPF object
// (Documentation/bpf/btf.rst).  It does exactly what the loader recipe
// needs and nothing more: walk the type table, look types up by name and
// kind, read struct members, and apply the two in-place fixups the kernel's
// BTF_LOAD validation requires of a raw clang object (see fixupForKernel).
// Every record keeps its size and position, so ids never shift.

const (
	btfMagic = 0xeB9F

	btfKindInt       = 1
	btfKindPtr       = 2
	btfKindArray     = 3
	btfKindStruct    = 4
	btfKindUnion     = 5
	btfKindEnum      = 6
	btfKindFwd       = 7
	btfKindTypedef   = 8
	btfKindVolatile  = 9
	btfKindConst     = 10
	btfKindRestrict  = 11
	btfKindFunc      = 12
	btfKindFuncProto = 13
	btfKindVar       = 14
	btfKindDatasec   = 15
	btfKindFloat     = 16
	btfKindDeclTag   = 17
	btfKindTypeTag   = 18
	btfKindEnum64    = 19

	btfFuncStatic = 0
	btfFuncGlobal = 1
	btfFuncExtern = 2

	btfTypeSize   = 12 // struct btf_type
	btfMemberSize = 12 // struct btf_member / btf_var_secinfo / btf_enum64
)

type btfHeader struct {
	hdrLen  uint32
	typeOff uint32
	typeLen uint32
	strOff  uint32
	strLen  uint32
}

// btf is a parsed BTF blob.  data is the whole blob (header included) and
// is mutated in place by the fixups; offs[i] is the byte offset of type
// id i within data (offs[0] is unused: id 0 is the implicit void).
type btf struct {
	data []byte
	hdr  btfHeader
	offs []uint32
}

type btfMember struct {
	name    string
	typ     uint32
	bitOff  uint32 // bit offset within the struct
	bitSize uint32 // 0 unless a bitfield (kind_flag set)
}

func parseBTF(data []byte) (*btf, error) {
	le := binary.LittleEndian
	if len(data) < 24 || le.Uint16(data) != btfMagic {
		return nil, fmt.Errorf("btf: bad magic/size")
	}
	b := &btf{data: data}
	b.hdr = btfHeader{
		hdrLen:  le.Uint32(data[4:]),
		typeOff: le.Uint32(data[8:]),
		typeLen: le.Uint32(data[12:]),
		strOff:  le.Uint32(data[16:]),
		strLen:  le.Uint32(data[20:]),
	}
	h := b.hdr
	if uint64(h.hdrLen)+uint64(h.typeOff)+uint64(h.typeLen) > uint64(len(data)) ||
		uint64(h.hdrLen)+uint64(h.strOff)+uint64(h.strLen) > uint64(len(data)) {
		return nil, fmt.Errorf("btf: header offsets out of range")
	}
	// Index the type table.
	b.offs = append(b.offs, 0)
	pos := h.hdrLen + h.typeOff
	end := pos + h.typeLen
	for pos < end {
		if end-pos < btfTypeSize {
			return nil, fmt.Errorf("btf: truncated type at %#x", pos)
		}
		b.offs = append(b.offs, pos)
		kind, vlen := b.kindVlen(pos)
		extra, err := btfExtraSize(kind, vlen)
		if err != nil {
			return nil, fmt.Errorf("btf: type %d at %#x: %w", len(b.offs)-1, pos, err)
		}
		pos += btfTypeSize + extra
	}
	if pos != end {
		return nil, fmt.Errorf("btf: type table overruns header type_len")
	}
	return b, nil
}

// btfExtraSize returns the size of the kind-specific data that follows a
// struct btf_type record.
func btfExtraSize(kind, vlen uint32) (uint32, error) {
	switch kind {
	case btfKindInt, btfKindVar, btfKindDeclTag:
		return 4, nil
	case btfKindArray:
		return 12, nil
	case btfKindStruct, btfKindUnion, btfKindDatasec, btfKindEnum64:
		return btfMemberSize * vlen, nil
	case btfKindEnum, btfKindFuncProto:
		return 8 * vlen, nil
	case btfKindPtr, btfKindFwd, btfKindTypedef, btfKindVolatile, btfKindConst,
		btfKindRestrict, btfKindFunc, btfKindFloat, btfKindTypeTag:
		return 0, nil
	}
	return 0, fmt.Errorf("unknown kind %d", kind)
}

func (b *btf) numTypes() int { return len(b.offs) }

func (b *btf) kindVlen(pos uint32) (kind, vlen uint32) {
	info := binary.LittleEndian.Uint32(b.data[pos+4:])
	return (info >> 24) & 0x1f, info & 0xffff
}

func (b *btf) kindFlag(pos uint32) bool {
	return binary.LittleEndian.Uint32(b.data[pos+4:])>>31 != 0
}

// typeKind returns the kind of type id, or 0 (void) for id 0.
func (b *btf) typeKind(id uint32) uint32 {
	if id == 0 || int(id) >= len(b.offs) {
		return 0
	}
	k, _ := b.kindVlen(b.offs[id])
	return k
}

// typeName returns the name of type id ("" for anonymous / void).
func (b *btf) typeName(id uint32) string {
	if id == 0 || int(id) >= len(b.offs) {
		return ""
	}
	return b.str(binary.LittleEndian.Uint32(b.data[b.offs[id]:]))
}

// typeSizeOrType returns the size/type union word of type id.
func (b *btf) typeSizeOrType(id uint32) uint32 {
	return binary.LittleEndian.Uint32(b.data[b.offs[id]+8:])
}

func (b *btf) str(off uint32) string {
	start := b.hdr.hdrLen + b.hdr.strOff
	if off >= b.hdr.strLen {
		return ""
	}
	s := b.data[start+off : start+b.hdr.strLen]
	for i, c := range s {
		if c == 0 {
			return string(s[:i])
		}
	}
	return string(s)
}

// findByNameKind returns the id of the first type with the given name and
// kind, or 0.
func (b *btf) findByNameKind(name string, kind uint32) uint32 {
	for id := 1; id < len(b.offs); id++ {
		k, _ := b.kindVlen(b.offs[id])
		if k == kind && b.typeName(uint32(id)) == name {
			return uint32(id)
		}
	}
	return 0
}

// members returns the members of a struct/union type.
func (b *btf) members(id uint32) ([]btfMember, error) {
	if k := b.typeKind(id); k != btfKindStruct && k != btfKindUnion {
		return nil, fmt.Errorf("btf: type %d is not a struct/union", id)
	}
	pos := b.offs[id]
	_, vlen := b.kindVlen(pos)
	kflag := b.kindFlag(pos)
	le := binary.LittleEndian
	var out []btfMember
	for i := uint32(0); i < vlen; i++ {
		m := pos + btfTypeSize + i*btfMemberSize
		off := le.Uint32(b.data[m+8:])
		mem := btfMember{
			name: b.str(le.Uint32(b.data[m:])),
			typ:  le.Uint32(b.data[m+4:]),
		}
		if kflag {
			mem.bitOff = off & 0xffffff
			mem.bitSize = off >> 24
		} else {
			mem.bitOff = off
		}
		out = append(out, mem)
	}
	return out, nil
}

// skipModifiers resolves typedef/const/volatile/restrict/type_tag chains.
func (b *btf) skipModifiers(id uint32) uint32 {
	for i := 0; i < 64; i++ {
		switch b.typeKind(id) {
		case btfKindTypedef, btfKindVolatile, btfKindConst, btfKindRestrict, btfKindTypeTag:
			id = b.typeSizeOrType(id)
		default:
			return id
		}
	}
	return id
}

// fixupForKernel applies, in place, the two edits the kernel's BTF_LOAD
// validator (kernel/bpf/btf.c) requires of a clang-emitted object BTF,
// exactly as libbpf does before loading:
//
//   - FUNC types with EXTERN linkage (the __ksym kfunc declarations) are
//     rejected ("Invalid func linkage": vlen > BTF_FUNC_GLOBAL), so they
//     become STATIC.  Nothing in the kernel reads them; kfunc calls are
//     resolved against vmlinux BTF by the loader.
//   - DATASEC types are emitted with size 0 and all var offsets 0 and the
//     kernel rejects both ("size == 0", "Invalid offset"); the real values
//     are the ELF section size and each var's symbol value, supplied by the
//     caller through secSize / varOff.
//   - The extern declarations' FUNC_PROTOs carry no parameter names (clang
//     emits none for a declaration) and the kernel requires a name on every
//     typed parameter ("Invalid arg#N").  As libbpf does, the missing names
//     are filled with the dummy var's name.
//   - The .ksyms DATASEC lists the extern kfunc FUNCs, but the kernel only
//     accepts VAR entries ("Not a VAR kind member").  As libbpf does, its
//     entries are repointed at a dummy 4-byte int VAR appended to the BTF,
//     laid out 4 bytes apart.
//
// Appending the dummy types rebuilds the blob (types grow, strings move),
// but never renumbers an existing id.
func (b *btf) fixupForKernel(secSize func(sec string) (uint32, bool),
	varOff func(sec, name string) (uint32, bool)) error {
	le := binary.LittleEndian
	needDummy := b.findByNameKind(".ksyms", btfKindDatasec) != 0
	for id := 1; id < len(b.offs) && !needDummy; id++ {
		kind, vlen := b.kindVlen(b.offs[id])
		needDummy = kind == btfKindFunc && vlen == btfFuncExtern
	}
	dummyVar, dummyName := uint32(0), uint32(0)
	if needDummy {
		var err error
		dummyVar, dummyName, err = b.appendDummyVar()
		if err != nil {
			return err
		}
	}
	for id := 1; id < len(b.offs); id++ {
		pos := b.offs[id]
		kind, vlen := b.kindVlen(pos)
		switch kind {
		case btfKindFunc:
			if vlen == btfFuncExtern {
				info := le.Uint32(b.data[pos+4:])
				le.PutUint32(b.data[pos+4:], info&^0xffff|btfFuncStatic)
				proto := le.Uint32(b.data[pos+8:])
				if b.typeKind(proto) != btfKindFuncProto {
					return fmt.Errorf("btf: FUNC %s has no FUNC_PROTO", b.typeName(uint32(id)))
				}
				ppos := b.offs[proto]
				_, nargs := b.kindVlen(ppos)
				for i := uint32(0); i < nargs; i++ {
					param := ppos + btfTypeSize + i*8
					if le.Uint32(b.data[param:]) == 0 && le.Uint32(b.data[param+4:]) != 0 {
						le.PutUint32(b.data[param:], dummyName)
					}
				}
			}
		case btfKindDatasec:
			sec := b.typeName(uint32(id))
			if sec == ".ksyms" {
				le.PutUint32(b.data[pos+8:], 4*vlen)
				for i := uint32(0); i < vlen; i++ {
					vsi := pos + btfTypeSize + i*btfMemberSize
					if b.typeKind(le.Uint32(b.data[vsi:])) != btfKindFunc {
						return fmt.Errorf("btf: .ksyms entry %d is not a kfunc (extern variables are not supported)", i)
					}
					le.PutUint32(b.data[vsi:], dummyVar)
					le.PutUint32(b.data[vsi+4:], 4*i)
					le.PutUint32(b.data[vsi+8:], 4)
				}
				continue
			}
			size, ok := secSize(sec)
			if !ok {
				return fmt.Errorf("btf: DATASEC %q has no ELF section", sec)
			}
			le.PutUint32(b.data[pos+8:], size)
			for i := uint32(0); i < vlen; i++ {
				vsi := pos + btfTypeSize + i*btfMemberSize
				vid := le.Uint32(b.data[vsi:])
				vname := b.typeName(vid)
				off, ok := varOff(sec, vname)
				if !ok {
					return fmt.Errorf("btf: DATASEC %q var %q has no ELF symbol", sec, vname)
				}
				le.PutUint32(b.data[vsi+4:], off)
			}
		}
	}
	return nil
}

// appendDummyVar appends a GLOBAL_ALLOCATED VAR "dummy_ksym" of a 4-byte
// int type (an existing one if the blob has it, else a fresh INT) and
// returns the VAR's id and its name's string offset.  Mirrors libbpf's
// dummy_var for .ksyms.
func (b *btf) appendDummyVar() (uint32, uint32, error) {
	le := binary.LittleEndian
	intID := uint32(0)
	for id := 1; id < len(b.offs); id++ {
		if b.typeKind(uint32(id)) == btfKindInt && b.typeSizeOrType(uint32(id)) == 4 {
			intID = uint32(id)
			break
		}
	}
	var types []byte
	var strs []byte
	strOff := func(s string) uint32 {
		off := b.hdr.strLen + uint32(len(strs))
		strs = append(strs, s...)
		strs = append(strs, 0)
		return off
	}
	nextID := uint32(len(b.offs))
	rec := func(nameOff, info, sizeOrType uint32, extra ...uint32) uint32 {
		var buf [12]byte
		le.PutUint32(buf[0:], nameOff)
		le.PutUint32(buf[4:], info)
		le.PutUint32(buf[8:], sizeOrType)
		types = append(types, buf[:]...)
		for _, e := range extra {
			le.PutUint32(buf[0:], e)
			types = append(types, buf[:4]...)
		}
		id := nextID
		nextID++
		return id
	}
	if intID == 0 {
		// INT "int": size 4, encoding SIGNED, bits 32.
		intID = rec(strOff("int"), btfKindInt<<24, 4, 1<<24|32)
	}
	nameOff := strOff("dummy_ksym")
	varID := rec(nameOff, btfKindVar<<24, intID, 1 /* BTF_VAR_GLOBAL_ALLOCATED */)

	h := b.hdr
	oldTypes := b.data[h.hdrLen+h.typeOff : h.hdrLen+h.typeOff+h.typeLen]
	oldStrs := b.data[h.hdrLen+h.strOff : h.hdrLen+h.strOff+h.strLen]
	out := make([]byte, 0, int(h.hdrLen)+len(oldTypes)+len(types)+len(oldStrs)+len(strs))
	out = append(out, b.data[:h.hdrLen]...)
	out = append(out, oldTypes...)
	out = append(out, types...)
	out = append(out, oldStrs...)
	out = append(out, strs...)
	le.PutUint32(out[8:], 0)                                 // type_off
	le.PutUint32(out[12:], uint32(len(oldTypes)+len(types))) // type_len
	le.PutUint32(out[16:], uint32(len(oldTypes)+len(types))) // str_off
	le.PutUint32(out[20:], uint32(len(oldStrs)+len(strs)))   // str_len
	nb, err := parseBTF(out)
	if err != nil {
		return 0, 0, fmt.Errorf("btf: after append: %w", err)
	}
	*b = *nb
	return varID, nameOff, nil
}
