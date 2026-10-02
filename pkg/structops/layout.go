// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package structops

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// Configure-time layout self-check.
//
// The compile step runs with BPF_NO_PRESERVE_ACCESS_INDEX, so every field
// offset a generated program uses is whatever clang computes from
// vmlinux.h -- there is no CO-RE relocation in the VM to correct it.  If
// clang's layout of a kernel struct differs from the kernel's, programs
// read and write the wrong fields and the verifier rejects them with
// offsets that look plausible ("cannot access ptr member X with off N"),
// or worse, accepts them.  That happened once: vmlinux.h reproduces the
// kernel's -fms-extensions tagged anonymous members (`struct slock_owned;`
// inside socket_lock_t) and without the flag clang silently laid struct
// sock out 64 bytes short.
//
// So Configure compiles ONE probe object that records sizeof() of the
// structs the surfaces touch and compares each against the size the
// kernel's own BTF reports.  A struct whose size matches is laid out the
// same way with overwhelming likelihood (a dropped or re-padded member
// changes the size); any mismatch fails Configure with the type and both
// sizes.

// layoutProbeCommon is the socket closure every surface's callbacks walk
// through; the surfaces' instance and value structs are added per surface.
var layoutProbeCommon = []string{
	"sock_common", "sock", "inet_sock", "inet_connection_sock", "tcp_sock",
	"mptcp_sock", "mptcp_subflow_context",
}

// ErrLayoutMismatch wraps every layout-mismatch error from Configure, so a
// caller can tell "this kernel/toolchain pair would corrupt programs" (be
// loud) from "no compiler/vmlinux here" (leave the carrier unconfigured).
var ErrLayoutMismatch = fmt.Errorf("structops: vmlinux.h layout does not match kernel BTF")

// layoutProbeTypes returns the struct names to probe, sorted.
func layoutProbeTypes() []string {
	seen := map[string]bool{}
	var out []string
	add := func(n string) {
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	for _, n := range layoutProbeCommon {
		add(n)
	}
	for _, surf := range surfaces {
		n := strings.TrimPrefix(surf.instanceStruct, "struct ")
		add(n)
		add("bpf_struct_ops_" + n)
	}
	sort.Strings(out)
	return out
}

// kernelStructSizes reads the .BTF section of a vmlinux and returns the
// size of each named struct that the kernel has (missing ones are simply
// absent from the result: a mainline kernel has no mptcp_sched_ops).
func kernelStructSizes(vmlinux string, names []string) (map[string]uint32, error) {
	f, err := elf.Open(vmlinux)
	if err != nil {
		return nil, fmt.Errorf("structops: %w", err)
	}
	defer f.Close()
	sec := f.Section(".BTF")
	if sec == nil {
		return nil, fmt.Errorf("structops: %s has no .BTF section (CONFIG_DEBUG_INFO_BTF?)", vmlinux)
	}
	data, err := sec.Data()
	if err != nil {
		return nil, fmt.Errorf("structops: %s .BTF: %w", vmlinux, err)
	}
	b, err := parseBTF(data)
	if err != nil {
		return nil, fmt.Errorf("structops: %s: %w", vmlinux, err)
	}
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	sizes := map[string]uint32{}
	for id := 1; id < b.numTypes() && len(sizes) < len(want); id++ {
		if b.typeKind(uint32(id)) != btfKindStruct {
			continue
		}
		n := b.typeName(uint32(id))
		if _, done := sizes[n]; want[n] && !done {
			sizes[n] = b.typeSizeOrType(uint32(id))
		}
	}
	return sizes, nil
}

// probeLayout compiles the sizeof probe against the laid-out include tree
// (with extraArgs appended to the usual clang flags) and returns clang's
// sizeof for each name in names, in order.
func (c *compiler) probeLayout(names []string, extraArgs ...string) ([]uint32, error) {
	var src bytes.Buffer
	src.WriteString("#include \"vmlinux.h\"\n")
	src.WriteString("__attribute__((section(\".rodata\"), used)) const unsigned int structops_probe_sizes[] = {\n")
	for _, n := range names {
		fmt.Fprintf(&src, "\tsizeof(struct %s),\n", n)
	}
	src.WriteString("};\n")
	obj := filepath.Join(c.objDir, "layout_probe.o")
	defer os.Remove(obj)
	args := append(c.clangArgs(obj), extraArgs...)
	cmd := exec.Command(c.cfg.Clang, args...)
	cmd.Stdin = &src
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("structops: layout probe: clang: %w\n%s", err, truncate(stderr.String(), 4096))
	}
	f, err := elf.Open(obj)
	if err != nil {
		return nil, fmt.Errorf("structops: layout probe: %w", err)
	}
	defer f.Close()
	sec := f.Section(".rodata")
	if sec == nil {
		return nil, fmt.Errorf("structops: layout probe has no .rodata")
	}
	data, err := sec.Data()
	if err != nil {
		return nil, fmt.Errorf("structops: layout probe: %w", err)
	}
	if len(data) != 4*len(names) {
		return nil, fmt.Errorf("structops: layout probe: .rodata is %d bytes, want %d", len(data), 4*len(names))
	}
	sizes := make([]uint32, len(names))
	for i := range names {
		sizes[i] = binary.LittleEndian.Uint32(data[4*i:])
	}
	return sizes, nil
}

// checkLayout compares clang's sizeof of every struct in expected against
// the expected (kernel BTF) size and returns an ErrLayoutMismatch listing
// every offender, or nil.  It returns the number of structs checked.
func (c *compiler) checkLayout(expected map[string]uint32, extraArgs ...string) (int, error) {
	var names []string
	for n := range expected {
		names = append(names, n)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return 0, nil
	}
	got, err := c.probeLayout(names, extraArgs...)
	if err != nil {
		return 0, err
	}
	var bad []string
	for i, n := range names {
		if got[i] != expected[n] {
			bad = append(bad, fmt.Sprintf("struct %s: vmlinux.h layout %d bytes, kernel BTF %d bytes",
				n, got[i], expected[n]))
		}
	}
	if len(bad) != 0 {
		return len(names), fmt.Errorf("%w (%d of %d structs; programs compiled against this vmlinux.h "+
			"would use wrong field offsets):\n  %s", ErrLayoutMismatch, len(bad), len(names),
			strings.Join(bad, "\n  "))
	}
	return len(names), nil
}
