// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/google/syzkaller/pkg/manager"
	"github.com/google/syzkaller/pkg/stat"
)

// Fix verification: the FIXED-BY-PATCH? bucket.
//
// The engine only ever reports crashes of the PATCHED kernel; a base crash
// feeds title suppression (DiffFuzzerStore.EverCrashedBase) and is otherwise
// dropped.  For a series that FIXES a bug the useful signal is the reverse: the
// base kernel hits a title repeatedly while the patched kernel, which executes
// the same program stream (the base pool replays what the patched pool runs),
// never does.  This file derives that bucket from data the run already has: the
// store's per-title base/patched crash counts, the two kernels' "exec total"
// stats, and the base report text the store writes to disk.  It is reporting
// only: nothing here changes the engine's behaviour or uses a VM.

// fixedParams are the knobs of the bucket (the -fixed_* flags).
type fixedParams struct {
	// A title needs at least this many base crashes (and zero patched ones).
	Cutoff int
	// The patched kernel must have executed at least ExecRatio * the base
	// kernel's executions, so that "never on patched" is not "patched ran less".
	ExecRatio float64
	// Keep only titles whose base report has a frame in FocusFuncs.
	Focus bool
	// The series' modified functions (mirrors the engine's "symbols" focus
	// area); nil when the symbol hashes were unavailable or too many symbols
	// differed.  Frames are still annotated when Focus is false.
	FocusFuncs map[string]bool
}

// execTotals are the two kernels' "exec total" stats at the time of the summary.
type execTotals struct {
	Base    int `json:"base"`
	Patched int `json:"patched"`
}

// fixedRow is one FIXED-BY-PATCH? entry (or a withheld candidate).
type fixedRow struct {
	Title          string `json:"title"`
	BaseCrashes    int    `json:"base_crashes"`
	PatchedCrashes int    `json:"patched_crashes"`
	BaseExecs      int    `json:"base_execs"`
	PatchedExecs   int    `json:"patched_execs"`
	// The engine's last base report for the title (artifacts/crashes/<hash>/base_report).
	BaseReport string `json:"base_report,omitempty"`
	// Frames of that report that are among the series' modified functions.
	FocusFrames []string `json:"focus_frames,omitempty"`
	// Why a candidate was withheld from the bucket (empty for listed rows).
	Reason string `json:"reason,omitempty"`
}

// fixedResult is the computed bucket: the listed rows and the base-only
// candidates that failed a guard, so that no base-only title is lost from the
// summary just because a guard held it back.
type fixedResult struct {
	Rows     []fixedRow `json:"rows"`
	Withheld []fixedRow `json:"withheld"`
	// Whether the focus filter was actually applied (requested and focus
	// functions were available).
	FocusApplied bool `json:"focus_applied"`
}

const (
	reasonExecGuard = "exec guard: patched executed less than the ratio of base"
	reasonNoFocus   = "no frame of the base report is in the focus functions"
)

// engineSkipsTitle mirrors the engine's needReproForTitle (unexported): these
// titles are infrastructure failures, not kernel bugs, so a base-only run of
// them says nothing about a fix.
func engineSkipsTitle(title string) bool {
	return strings.Contains(title, "no output") ||
		strings.Contains(title, "lost connection") ||
		strings.Contains(title, "SYZ")
}

// fixedByPatch computes the bucket over the store's current list.  readReport
// returns the base report text for a bug (nil when none is retained); it is a
// parameter so the computation can be tested without a store on disk.
func fixedByPatch(list []manager.DiffBug, execs execTotals, p fixedParams,
	readReport func(manager.DiffBug) []byte) fixedResult {
	res := fixedResult{FocusApplied: p.Focus && len(p.FocusFuncs) > 0}
	execOK := float64(execs.Patched) >= float64(execs.Base)*p.ExecRatio
	for _, bug := range list {
		if bug.Base.Crashes < p.Cutoff || bug.Patched.Crashes != 0 || engineSkipsTitle(bug.Title) {
			continue
		}
		row := fixedRow{
			Title:          bug.Title,
			BaseCrashes:    bug.Base.Crashes,
			PatchedCrashes: bug.Patched.Crashes,
			BaseExecs:      execs.Base,
			PatchedExecs:   execs.Patched,
			BaseReport:     bug.Base.Report,
		}
		if len(p.FocusFuncs) > 0 {
			var text []byte
			if readReport != nil {
				text = readReport(bug)
			}
			row.FocusFrames = focusFrames(bug.Title, text, p.FocusFuncs)
		}
		switch {
		case !execOK:
			row.Reason = reasonExecGuard
			res.Withheld = append(res.Withheld, row)
		case res.FocusApplied && len(row.FocusFrames) == 0:
			row.Reason = reasonNoFocus
			res.Withheld = append(res.Withheld, row)
		default:
			res.Rows = append(res.Rows, row)
		}
	}
	byTitle := func(rows []fixedRow) {
		sort.Slice(rows, func(i, j int) bool { return rows[i].Title < rows[j].Title })
	}
	byTitle(res.Rows)
	byTitle(res.Withheld)
	return res
}

// execTotalsFrom picks the two kernels' "exec total" stats out of a
// stat.Collect result.  The engine names its kernels "base" and "new"
// (pkg/manager/diff: setup("base", ...), setup("new", ...)), and
// rpcserver.NewNamedStats suffixes every stat with " [<name>]".
func execTotalsFrom(stats []stat.UI) execTotals {
	var ret execTotals
	for _, s := range stats {
		switch s.Name {
		case "exec total [base]":
			ret.Base = s.V
		case "exec total [new]":
			ret.Patched = s.V
		}
	}
	return ret
}

// frameRe matches a symbolized stack frame, "func+0xoff/0xsize", as printed by
// the kernel in oops, KASAN, KCSAN and warning reports.
var frameRe = regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_.]*)\+0x[0-9a-fA-F]+/0x[0-9a-fA-F]+`)

// identRe matches a C identifier (with the compiler's ".isra.0"-style
// suffixes), used to pull candidate function names out of a crash title.
var identRe = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_.]*`)

// reportFrames returns the distinct function names of the stack frames in a
// report text, in order of first appearance.
func reportFrames(report []byte) []string {
	var ret []string
	seen := map[string]bool{}
	for _, m := range frameRe.FindAllSubmatch(report, -1) {
		name := string(m[1])
		if !seen[name] {
			seen[name] = true
			ret = append(ret, name)
		}
	}
	return ret
}

// baseSymbol strips the compiler-generated suffix (".isra.0", ".constprop.0",
// ".cold", ...) so a frame and a symbol-table name compare equal either way.
func baseSymbol(name string) string {
	if i := strings.IndexByte(name, '.'); i >= 0 {
		return name[:i]
	}
	return name
}

// focusFrames returns the frames of the base report (and, as a fallback for a
// report the store did not retain, the identifiers of the title) that name one
// of the focus functions, sorted.
func focusFrames(title string, report []byte, focus map[string]bool) []string {
	candidates := reportFrames(report)
	candidates = append(candidates, identRe.FindAllString(title, -1)...)
	seen := map[string]bool{}
	var ret []string
	for _, name := range candidates {
		stripped := baseSymbol(name)
		if (!focus[name] && !focus[stripped]) || seen[stripped] {
			continue
		}
		seen[stripped] = true
		ret = append(ret, stripped)
	}
	slices.Sort(ret)
	return ret
}

// modifiedFunctionThreshold mirrors pkg/manager/diff's modifiedSymbolThreshold:
// when more than this fraction of the symbols differ the pair is not "base +
// series" and the function set says nothing about the change.
const modifiedFunctionThreshold = 0.05

// modifiedFunctions mirrors the engine's unexported modifiedSymbols: the
// patched-side .text symbols whose hash differs from, or is absent in, base;
// nil when the threshold is exceeded.  Both names are stripped of compiler
// suffixes so that frame matching does not depend on them.
func modifiedFunctions(baseHashes, patchedHashes map[string]string) map[string]bool {
	ret := map[string]bool{}
	count := 0
	for name, hash := range patchedHashes {
		if baseHash, ok := baseHashes[name]; !ok || baseHash != hash {
			count++
			if float64(count) > float64(len(patchedHashes))*modifiedFunctionThreshold {
				return nil
			}
			ret[name] = true
			ret[baseSymbol(name)] = true
		}
	}
	if len(ret) == 0 {
		return nil
	}
	return ret
}

// countFunctions counts the distinct functions in a modifiedFunctions set
// (every entry has its suffix-stripped form in the set, so count those).
func countFunctions(funcs map[string]bool) int {
	n := 0
	for name := range funcs {
		if !strings.Contains(name, ".") {
			n++
		}
	}
	return n
}

// writeFixedSection appends the bucket to summary.txt, after AFFECTS BOTH.
func writeFixedSection(text *strings.Builder, res fixedResult, execs execTotals, p fixedParams) {
	fmt.Fprintf(text, "\nFIXED-BY-PATCH? (%d): base crashed with the title >=%d times, patched never did, over "+
		"comparable execution (patched exec total >= %.2f x base); statistical evidence, not proof\n",
		len(res.Rows), p.Cutoff, p.ExecRatio)
	fmt.Fprintf(text, "  exec total: base %d, patched %d", execs.Base, execs.Patched)
	switch {
	case res.FocusApplied:
		fmt.Fprintf(text, "; focus filter on (%d modified functions)\n", countFunctions(p.FocusFuncs))
	case p.Focus:
		fmt.Fprintf(text, "; focus filter requested but no modified functions are known: NOT applied\n")
	default:
		fmt.Fprintf(text, "\n")
	}
	printRow := func(row fixedRow) {
		fmt.Fprintf(text, "  %s   base %d crashes   patched %d   (exec base %d, patched %d)\n",
			row.Title, row.BaseCrashes, row.PatchedCrashes, row.BaseExecs, row.PatchedExecs)
		if len(row.FocusFrames) > 0 {
			fmt.Fprintf(text, "    focus frames: %s\n", strings.Join(row.FocusFrames, ", "))
		}
		if row.BaseReport != "" {
			fmt.Fprintf(text, "    base report: %s\n", row.BaseReport)
		}
		if row.Reason != "" {
			fmt.Fprintf(text, "    withheld: %s\n", row.Reason)
		}
	}
	for _, row := range res.Rows {
		printRow(row)
	}
	if len(res.Withheld) > 0 {
		fmt.Fprintf(text, "  withheld (%d): base-only titles above the cutoff that failed a guard\n", len(res.Withheld))
		for _, row := range res.Withheld {
			printRow(row)
		}
	}
}
