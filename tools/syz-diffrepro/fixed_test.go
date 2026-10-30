// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/manager"
	"github.com/google/syzkaller/pkg/manager/diff"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/stat"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testBaseReport = `==================================================================
BUG: KCSAN: data-race in mptcp_pm_nl_work / mptcp_schedule_work

write to 0xffff888100a0b0c0 of 4 bytes by task 1234 on cpu 0:
 mptcp_pm_nl_work+0x1a2/0x3f0 net/mptcp/pm_netlink.c:456
 mptcp_worker+0x88/0x9c0 net/mptcp/protocol.c:2650
 process_one_work+0x3f4/0x8a0 kernel/workqueue.c:3238

read to 0xffff888100a0b0c0 of 4 bytes by task 5678 on cpu 1:
 mptcp_schedule_work.isra.0+0x5c/0x110 net/mptcp/protocol.c:850
 subflow_data_ready+0x2e/0x40 net/mptcp/subflow.c:1540
==================================================================
`

func testBugs() []manager.DiffBug {
	return []manager.DiffBug{
		{Title: "KCSAN: data-race in mptcp_pm_nl_work / mptcp_schedule_work",
			Base: manager.DiffBugInfo{Crashes: 12}},
		{Title: "WARNING in tcp_recvmsg", Base: manager.DiffBugInfo{Crashes: 3}},
		{Title: "KASAN: use-after-free in foo", Base: manager.DiffBugInfo{Crashes: 2}}, // below cutoff
		{Title: "WARNING in bar", Base: manager.DiffBugInfo{Crashes: 5},
			Patched: manager.DiffBugInfo{Crashes: 1}}, // affects both
		{Title: "lost connection to test machine", Base: manager.DiffBugInfo{Crashes: 9}}, // infra
		{Title: "INFO: task hung in baz", Patched: manager.DiffBugInfo{Crashes: 4}},       // patched-only
	}
}

func titles(rows []fixedRow) []string {
	var ret []string
	for _, row := range rows {
		ret = append(ret, row.Title)
	}
	return ret
}

func TestFixedByPatchCutoffAndCounts(t *testing.T) {
	p := fixedParams{Cutoff: 3, ExecRatio: 0.8}
	res := fixedByPatch(testBugs(), execTotals{Base: 49000, Patched: 49500}, p, nil)
	assert.Equal(t, []string{
		"KCSAN: data-race in mptcp_pm_nl_work / mptcp_schedule_work",
		"WARNING in tcp_recvmsg",
	}, titles(res.Rows))
	assert.Empty(t, res.Withheld)
	assert.False(t, res.FocusApplied)
	assert.Equal(t, 12, res.Rows[0].BaseCrashes)
	assert.Equal(t, 0, res.Rows[0].PatchedCrashes)
	assert.Equal(t, 49000, res.Rows[0].BaseExecs)
	assert.Equal(t, 49500, res.Rows[0].PatchedExecs)

	// A higher cutoff drops the 3-crash title.
	p.Cutoff = 4
	res = fixedByPatch(testBugs(), execTotals{Base: 49000, Patched: 49500}, p, nil)
	assert.Equal(t, []string{"KCSAN: data-race in mptcp_pm_nl_work / mptcp_schedule_work"}, titles(res.Rows))
}

func TestFixedByPatchExecGuard(t *testing.T) {
	p := fixedParams{Cutoff: 3, ExecRatio: 0.8}
	// Patched ran 50% of base: both candidates are withheld, not dropped.
	res := fixedByPatch(testBugs(), execTotals{Base: 49000, Patched: 24500}, p, nil)
	assert.Empty(t, res.Rows)
	assert.Len(t, res.Withheld, 2)
	for _, row := range res.Withheld {
		assert.Equal(t, reasonExecGuard, row.Reason)
	}
	// Exactly at the ratio passes.
	res = fixedByPatch(testBugs(), execTotals{Base: 50000, Patched: 40000}, p, nil)
	assert.Len(t, res.Rows, 2)
	// Ratio 0 disables the guard.
	p.ExecRatio = 0
	res = fixedByPatch(testBugs(), execTotals{Base: 50000, Patched: 1}, p, nil)
	assert.Len(t, res.Rows, 2)
}

func TestFixedByPatchFocus(t *testing.T) {
	focus := map[string]bool{"mptcp_schedule_work": true, "mptcp_pm_nl_work": true}
	readReport := func(bug manager.DiffBug) []byte {
		if strings.HasPrefix(bug.Title, "KCSAN") {
			return []byte(testBaseReport)
		}
		return nil
	}
	execs := execTotals{Base: 49000, Patched: 49500}

	// Focus off: everything is listed, frames are still annotated.
	res := fixedByPatch(testBugs(), execs, fixedParams{Cutoff: 3, ExecRatio: 0.8, FocusFuncs: focus}, readReport)
	assert.False(t, res.FocusApplied)
	assert.Len(t, res.Rows, 2)
	assert.Equal(t, []string{"mptcp_pm_nl_work", "mptcp_schedule_work"}, res.Rows[0].FocusFrames)
	assert.Empty(t, res.Rows[1].FocusFrames)

	// Focus on: only the title with a focus frame stays; the other is withheld.
	res = fixedByPatch(testBugs(), execs,
		fixedParams{Cutoff: 3, ExecRatio: 0.8, Focus: true, FocusFuncs: focus}, readReport)
	assert.True(t, res.FocusApplied)
	assert.Equal(t, []string{"KCSAN: data-race in mptcp_pm_nl_work / mptcp_schedule_work"}, titles(res.Rows))
	assert.Equal(t, []string{"WARNING in tcp_recvmsg"}, titles(res.Withheld))
	assert.Equal(t, reasonNoFocus, res.Withheld[0].Reason)

	// Focus requested but no functions known: not applied, nothing withheld.
	res = fixedByPatch(testBugs(), execs, fixedParams{Cutoff: 3, ExecRatio: 0.8, Focus: true}, readReport)
	assert.False(t, res.FocusApplied)
	assert.Len(t, res.Rows, 2)
	assert.Empty(t, res.Withheld)

	// No retained report: the title's own identifiers are the fallback.
	res = fixedByPatch(testBugs(), execs,
		fixedParams{Cutoff: 3, ExecRatio: 0.8, Focus: true, FocusFuncs: map[string]bool{"tcp_recvmsg": true}}, nil)
	assert.Equal(t, []string{"WARNING in tcp_recvmsg"}, titles(res.Rows))
	assert.Equal(t, []string{"tcp_recvmsg"}, res.Rows[0].FocusFrames)
}

func TestReportFrames(t *testing.T) {
	assert.Equal(t, []string{
		"mptcp_pm_nl_work", "mptcp_worker", "process_one_work",
		"mptcp_schedule_work.isra.0", "subflow_data_ready",
	}, reportFrames([]byte(testBaseReport)))
	assert.Empty(t, reportFrames(nil))
}

func TestExecTotalsFrom(t *testing.T) {
	assert.Equal(t, execTotals{Base: 49000, Patched: 49500}, execTotalsFrom([]stat.UI{
		{Name: "exec total", V: 7},
		{Name: "exec total [base]", V: 49000},
		{Name: "exec total [new]", V: 49500},
		{Name: "fuzzing VMs [new]", V: 3},
	}))
	assert.Equal(t, execTotals{}, execTotalsFrom(nil))
}

func TestModifiedFunctions(t *testing.T) {
	base := map[string]string{"a": "1", "b": "2", "c.isra.0": "3"}
	for i := 0; i < 100; i++ {
		base[string(rune('d'+i))+"_fn"] = "x"
	}
	patched := map[string]string{}
	for k, v := range base {
		patched[k] = v
	}
	patched["b"] = "changed"
	patched["c.isra.0"] = "changed"
	patched["new_fn"] = "n"
	got := modifiedFunctions(base, patched)
	assert.Equal(t, map[string]bool{"b": true, "c.isra.0": true, "c": true, "new_fn": true}, got)

	// Identical kernels: nothing.
	assert.Nil(t, modifiedFunctions(base, base))
	// More than 5% differ: the set says nothing about the change.
	assert.Nil(t, modifiedFunctions(map[string]string{"a": "1"}, map[string]string{"a": "2", "b": "3"}))
	// No hashes at all.
	assert.Nil(t, modifiedFunctions(nil, nil))
}

// TestWriteSummaryFixedSection runs the real writeSummary over a real store
// on disk, so the on-disk base_report is what the focus match reads.
func TestWriteSummaryFixedSection(t *testing.T) {
	outDir := t.TempDir()
	store := &manager.DiffFuzzerStore{BasePath: filepath.Join(outDir, "artifacts")}
	sink := &bugSink{dir: filepath.Join(outDir, "patched_only"), bugs: map[string]*diff.Bug{}}
	const raceTitle = "KCSAN: data-race in mptcp_pm_nl_work / mptcp_schedule_work"
	for i := 0; i < 12; i++ {
		store.BaseCrashed(raceTitle, []byte(testBaseReport))
	}
	for i := 0; i < 3; i++ {
		store.BaseCrashed("WARNING in tcp_recvmsg", []byte("WARNING: CPU: 0 PID: 1 at net/ipv4/tcp.c:1 tcp_recvmsg+0x10/0x20\n"))
	}
	store.BaseCrashed("KASAN: use-after-free in foo", []byte("x"))
	store.PatchedCrashed(&report.Report{Title: "INFO: task hung in baz", Report: []byte("y")})
	store.UpdateStatus("INFO: task hung in baz", manager.DiffBugStatusIgnored)

	fixed := fixedParams{
		Cutoff:     3,
		ExecRatio:  0.8,
		Focus:      true,
		FocusFuncs: map[string]bool{"mptcp_schedule_work": true, "mptcp_pm_nl_work": true},
	}
	execs := execTotals{Base: 49000, Patched: 49500}
	require.NoError(t, writeSummary(outDir, store, sink, 10, execs, fixed, true))

	text, err := os.ReadFile(filepath.Join(outDir, "summary.txt"))
	require.NoError(t, err)
	s := string(text)
	t.Logf("summary.txt:\n%s", s)
	assert.Contains(t, s, "FIXED-BY-PATCH? (1): base crashed with the title >=3 times")
	assert.Contains(t, s, "  exec total: base 49000, patched 49500; focus filter on (2 modified functions)\n")
	assert.Contains(t, s, "  "+raceTitle+"   base 12 crashes   patched 0   (exec base 49000, patched 49500)\n"+
		"    focus frames: mptcp_pm_nl_work, mptcp_schedule_work\n"+
		"    base report: "+filepath.Join(store.BasePath, "crashes")+"/")
	assert.Contains(t, s, "  withheld (1): base-only titles above the cutoff that failed a guard\n"+
		"  WARNING in tcp_recvmsg   base 3 crashes   patched 0   (exec base 49000, patched 49500)\n")
	assert.Contains(t, s, "    withheld: "+reasonNoFocus+"\n")
	assert.NotContains(t, s, "  KASAN: use-after-free in foo   base")
	// The bucket sits after AFFECTS BOTH and before the store dump.
	assert.Less(t, strings.Index(s, "AFFECTS BOTH"), strings.Index(s, "FIXED-BY-PATCH?"))
	assert.Less(t, strings.Index(s, "FIXED-BY-PATCH?"), strings.Index(s, "FULL STORE:"))

	data, err := os.ReadFile(filepath.Join(outDir, "summary.json"))
	require.NoError(t, err)
	t.Logf("summary.json:\n%s", data)
	var got struct {
		FixedByPatch fixedResult `json:"fixed_by_patch"`
		ExecTotals   execTotals  `json:"exec_totals"`
	}
	require.NoError(t, json.Unmarshal(data, &got))
	assert.Equal(t, execs, got.ExecTotals)
	assert.True(t, got.FixedByPatch.FocusApplied)
	require.Len(t, got.FixedByPatch.Rows, 1)
	assert.Equal(t, raceTitle, got.FixedByPatch.Rows[0].Title)
	assert.Equal(t, 12, got.FixedByPatch.Rows[0].BaseCrashes)
	assert.Equal(t, []string{"mptcp_pm_nl_work", "mptcp_schedule_work"}, got.FixedByPatch.Rows[0].FocusFrames)
	require.Len(t, got.FixedByPatch.Withheld, 1)
	assert.Equal(t, reasonNoFocus, got.FixedByPatch.Withheld[0].Reason)
}
