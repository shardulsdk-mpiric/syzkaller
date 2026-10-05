// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package structops

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"fmt"
)

// The generative spec: the persisted, kernel-agnostic form of a struct_ops
// program.
//
// A compiled load recipe (recipe.go) is specific to one kernel build: it
// carries the object's BTF (a slice of that kernel's vmlinux.h types) and
// instructions with that kernel's field offsets baked in, 60-160KB per
// program.  Storing it in the corpus bloats corpus.db and, worse, rots it:
// after a kernel bump every struct_ops entry is stale (EINVAL at load,
// inert) while the rest of the corpus carries over.
//
// So what the fuzzer generates, mutates and persists is the SPEC -- the
// surface tag plus the generated statement AST per callback, ~1-3KB -- and
// the recipe is an ephemeral per-session artifact the manager materializes
// from it against the live kernel's BTF right before a program is sent to
// the executor (pkg/structops/materialize).  The spec references kernel
// entities only by name (kfuncs, ctx fields, the ops struct), and the
// fixed per-surface text (prologue/epilogue, externs, the instance) is
// re-applied from the CURRENT surface tables at decode time, so a spec
// survives both a kernel bump and a generator re-pin as long as the names
// it uses still exist.  One that no longer decodes/compiles stays a spec
// blob, which the executor rejects at load (no recipe magic) -- inert,
// never crashing -- and the corpus triage drops it.
//
// Wire format: u32 magic "SPEC" | u32 version | gob(Spec).  gob tolerates
// Stmt field additions/removals by name, so an old spec still decodes
// under a newer generator.

const (
	specMagic   = 0x43455053 // "SPEC"
	specVersion = 1
	specHdrLen  = 8
)

// Spec is the persisted form of a generated program.
type Spec struct {
	Version   int
	Surface   string
	SchedName string
	// Seed is the RNG seed the program was generated from (provenance for
	// debugging; the AST below is what gets re-rendered, so a generator
	// change does not alter a stored program).
	Seed int64
	// Kfuncs names the program's kfunc table at generation time;
	// Stmt.KfuncIdx indexes it.  Decode remaps every index onto the
	// current surface table by name, so a table reorder is harmless and a
	// vanished kfunc is a decode error rather than a wrong call.
	Kfuncs    []string
	Callbacks []SpecCallback
	// Instance are the generated instance-data values (Prog.Instance):
	// one per surface InstanceField, by member name.  Decode requires the
	// set to match the current surface's exactly, as it does for
	// callbacks: a surface that gains or loses an instance field retires
	// the specs generated before the change rather than guessing a value.
	Instance []InstanceVal
}

// SpecCallback is one callback's generated body, keyed by its op suffix.
type SpecCallback struct {
	Suffix string
	Body   []Stmt
}

// EncodeSpec serializes the generative spec of sop.  seed is recorded as
// provenance only.
func EncodeSpec(sop *Prog, seed int64) []byte {
	spec := &Spec{
		Version:   specVersion,
		Surface:   sop.Surface,
		SchedName: sop.SchedName,
		Seed:      seed,
		Instance:  sop.Instance,
	}
	for i := range sop.Kfuncs {
		spec.Kfuncs = append(spec.Kfuncs, sop.Kfuncs[i].Name)
	}
	for i := range sop.Callbacks {
		spec.Callbacks = append(spec.Callbacks, SpecCallback{
			Suffix: sop.Callbacks[i].Suffix,
			Body:   sop.Callbacks[i].Body,
		})
	}
	var buf bytes.Buffer
	var hdr [specHdrLen]byte
	binary.LittleEndian.PutUint32(hdr[0:], specMagic)
	binary.LittleEndian.PutUint32(hdr[4:], specVersion)
	buf.Write(hdr[:])
	if err := gob.NewEncoder(&buf).Encode(spec); err != nil {
		panic(fmt.Sprintf("structops: gob encode of a Spec failed: %v", err))
	}
	return buf.Bytes()
}

// IsSpec reports whether data is a spec blob (as opposed to a load recipe
// or anything else).
func IsSpec(data []byte) bool {
	return len(data) >= specHdrLen && binary.LittleEndian.Uint32(data) == specMagic
}

// DecodeSpec rebuilds the program a spec describes against the CURRENT
// surface tables: the fixed per-surface knobs (write fields, kfunc tables,
// callback prologue/epilogue/signature) come from the registered surface,
// the generated bodies from the spec.  Rendering the result yields the
// same translation unit the generator rendered at generation time as long
// as the surface has not changed; after a re-pin it yields the program
// re-expressed against the new surface.
func DecodeSpec(data []byte) (*Prog, error) {
	if !IsSpec(data) {
		return nil, fmt.Errorf("structops: not a spec blob")
	}
	if v := binary.LittleEndian.Uint32(data[4:]); v != specVersion {
		return nil, fmt.Errorf("structops: spec version %d, want %d", v, specVersion)
	}
	spec := new(Spec)
	if err := gob.NewDecoder(bytes.NewReader(data[specHdrLen:])).Decode(spec); err != nil {
		return nil, fmt.Errorf("structops: spec decode: %w", err)
	}
	return spec.prog()
}

// DecodeSpecInfo decodes just the header fields of a spec blob (surface,
// name, seed) for tooling/logging; it does not resolve the surface.
func DecodeSpecInfo(data []byte) (*Spec, error) {
	if !IsSpec(data) {
		return nil, fmt.Errorf("structops: not a spec blob")
	}
	spec := new(Spec)
	if err := gob.NewDecoder(bytes.NewReader(data[specHdrLen:])).Decode(spec); err != nil {
		return nil, fmt.Errorf("structops: spec decode: %w", err)
	}
	return spec, nil
}

func (spec *Spec) prog() (*Prog, error) {
	surf := ByTag(spec.Surface)
	if surf == nil {
		return nil, fmt.Errorf("structops: spec names unknown surface %q", spec.Surface)
	}
	// Kfunc index remap: spec table name -> current surface table index.
	remap := make([]int, len(spec.Kfuncs))
	for i, name := range spec.Kfuncs {
		remap[i] = -1
		for j := range surf.kfuncs {
			if surf.kfuncs[j].Name == name {
				remap[i] = j
				break
			}
		}
	}
	sop := &Prog{
		Surface:        surf.tag,
		SchedName:      spec.SchedName,
		WriteFields:    surf.writeFields,
		Kfuncs:         surf.kfuncs,
		IterKfuncs:     surf.iterKfuncs,
		PrologueKfuncs: surf.prologueKfuncNames,
	}
	bodies := make(map[string][]Stmt, len(spec.Callbacks))
	for i := range spec.Callbacks {
		cb := &spec.Callbacks[i]
		if _, dup := bodies[cb.Suffix]; dup {
			return nil, fmt.Errorf("structops: spec repeats callback %q", cb.Suffix)
		}
		bodies[cb.Suffix] = cb.Body
	}
	sop.Callbacks = make([]Callback, len(surf.callbacks))
	for i, cs := range surf.callbacks {
		body, ok := bodies[cs.suffix]
		if !ok {
			return nil, fmt.Errorf("structops: spec lacks callback %q of surface %s", cs.suffix, surf.tag)
		}
		delete(bodies, cs.suffix)
		sop.Callbacks[i] = Callback{
			Suffix:       cs.suffix,
			RetType:      cs.retType,
			ArgsAfterCtx: cs.argsAfterCtx,
			Prologue:     cs.prologue,
			Epilogue:     cs.epilogue,
			Sleepable:    cs.sleepable,
			BodyGuard:    cs.bodyGuard,
			Body:         body,
		}
	}
	for suffix := range bodies {
		return nil, fmt.Errorf("structops: spec callback %q is not in surface %s", suffix, surf.tag)
	}
	// Instance data: the spec must carry exactly the surface's fields, in
	// the surface's order (the render order).
	if len(spec.Instance) != len(surf.instanceFields) {
		return nil, fmt.Errorf("structops: spec sets %d instance fields, surface %s has %d",
			len(spec.Instance), surf.tag, len(surf.instanceFields))
	}
	for i, v := range spec.Instance {
		if v.Field != surf.instanceFields[i].Field {
			return nil, fmt.Errorf("structops: spec instance field %q, surface %s has %q at %d",
				v.Field, surf.tag, surf.instanceFields[i].Field, i)
		}
	}
	if len(spec.Instance) > 0 {
		sop.Instance = append([]InstanceVal(nil), spec.Instance...)
	}
	var err error
	for _, body := range sop.allBodies() {
		walkStmts(body, func(st *Stmt) {
			if err != nil || (st.Kind != StmtKfuncCall && st.Kind != StmtDsqInsert) {
				return
			}
			if st.KfuncIdx < 0 || st.KfuncIdx >= len(remap) {
				err = fmt.Errorf("structops: spec kfunc index %d out of range", st.KfuncIdx)
				return
			}
			if remap[st.KfuncIdx] < 0 {
				err = fmt.Errorf("structops: spec uses kfunc %q, not in surface %s",
					spec.Kfuncs[st.KfuncIdx], surf.tag)
				return
			}
			st.KfuncIdx = remap[st.KfuncIdx]
		})
	}
	if err != nil {
		return nil, err
	}
	return sop, nil
}
