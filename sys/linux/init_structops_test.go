// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package linux

import (
	"math/rand"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/structops"
	"github.com/google/syzkaller/pkg/structops/materialize"
	"github.com/google/syzkaller/prog"
)

// TestStructOpsBlobGeneration checks the SpecialTypes wiring end to end
// through the fuzzer's own generator and mutator: generating
// syz_bpf_struct_ops_load$X yields a blob that is the generative spec of a
// struct_ops program for surface X (which decodes and renders to the
// surface's translation unit), and mutating the program re-generates the
// blob (it is never byte-flipped into a non-spec).
func TestStructOpsBlobGeneration(t *testing.T) {
	target, err := prog.GetTarget("linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	// The materializer recognizes blobs by the object struct type name.
	for name := range target.SpecialTypes {
		if strings.HasPrefix(name, "bpf_struct_ops") && !strings.HasPrefix(name, materialize.ObjTypePrefix) {
			t.Errorf("SpecialTypes %q does not carry materialize.ObjTypePrefix %q", name, materialize.ObjTypePrefix)
		}
	}
	for _, tc := range []struct {
		call  string
		frags []string
	}{
		{
			call: "syz_bpf_struct_ops_load$tcp_cong",
			frags: []string{
				"#include \"vmlinux.h\"",
				"SEC(\".struct_ops\")",
				"struct tcp_congestion_ops brf_",
				"_cong_avoid, struct sock *sk, __u32 ack, __u32 acked)",
			},
		},
		{
			call: "syz_bpf_struct_ops_load$mptcp_sched",
			frags: []string{
				"#include \"vmlinux.h\"",
				"SEC(\".struct_ops.link\")",
				"struct mptcp_sched_ops brf_",
				"mptcp_subflow_set_scheduled(subflow, true)",
			},
		},
	} {
		t.Run(tc.call, func(t *testing.T) {
			meta := target.SyscallMap[tc.call]
			if meta == nil {
				t.Fatalf("%s not in SyscallMap", tc.call)
			}
			rs := rand.NewSource(0)
			ct := target.BuildChoiceTable(nil, map[*prog.Syscall]bool{meta: true})
			p := target.Generate(rs, 1, ct)
			check := func(stage string) {
				found := false
				for _, c := range p.Calls {
					if c.Meta != meta {
						continue
					}
					found = true
					raw := structOpsBlob(t, c)
					if !structops.IsSpec([]byte(raw)) {
						t.Fatalf("%s: blob is not a spec (%d bytes)", stage, len(raw))
					}
					sop, err := structops.DecodeSpec([]byte(raw))
					if err != nil {
						t.Fatalf("%s: %v", stage, err)
					}
					blob := sop.Render()
					for _, frag := range tc.frags {
						if !strings.Contains(blob, frag) {
							t.Errorf("%s: blob lacks %q\n---\n%s", stage, frag, blob)
						}
					}
				}
				if !found {
					t.Fatalf("%s: program has no %s call", stage, tc.call)
				}
			}
			check("generate")
			for i := 0; i < 16; i++ {
				p.Mutate(rs, 1, ct, nil, nil)
				check("mutate")
			}
		})
	}
}

// structOpsBlob extracts the object bytes from a syz_bpf_struct_ops_load
// call: arg 0 is ptr[in, bpf_struct_ops_obj_X], whose single field is the
// array[int8] blob.
func structOpsBlob(t *testing.T, c *prog.Call) string {
	t.Helper()
	ptr, ok := c.Args[0].(*prog.PointerArg)
	if !ok || ptr.Res == nil {
		t.Fatalf("%s: arg 0 is not a non-NULL pointer: %#v", c.Meta.Name, c.Args[0])
	}
	group, ok := ptr.Res.(*prog.GroupArg)
	if !ok || len(group.Inner) != 1 {
		t.Fatalf("%s: pointee is not the single-field blob struct: %#v", c.Meta.Name, ptr.Res)
	}
	data, ok := group.Inner[0].(*prog.DataArg)
	if !ok {
		t.Fatalf("%s: blob field is not a DataArg: %#v", c.Meta.Name, group.Inner[0])
	}
	return string(data.Data())
}
