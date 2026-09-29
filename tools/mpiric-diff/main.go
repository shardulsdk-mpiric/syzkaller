// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// mpiric-diff drives the differential (base vs patched kernel) fuzzing engine in
// pkg/manager/diff through its exported API only.  It is Mpiric's replacement
// driver for tools/syz-diff, which cannot run: that driver never sets the
// mandatory Config.PatchedOnly channel, so diff.Run fails before booting a VM.
//
// The composition mirrors syz-cluster/workflow/fuzz/main.go (the only working
// in-tree driver of the engine), minus the cluster RPC plumbing:
//
//	one goroutine drains PatchedOnly/BaseCrashes  |  diff.Run  |  a status ticker
//
// and adds what a standalone run needs: a bounded lifetime (context timeout, plus
// graceful SIGINT/SIGTERM), symbol-level focus areas from vmlinux.o, a written C
// reproducer per patched-only bug (the engine's store only writes the syz prog),
// title-level de-duplication of the engine's repeated deliveries, a VM-budget
// sanity check, and a final on-disk summary that also lists "possibly
// patched-only" titles (many patched crashes, none on base, no reliable repro).
//
// See README.md next to this file for the invocation, the kernel-pair
// requirements and the known foot-guns.  pkg/manager/diff is deliberately not
// modified so the fork stays rebaseable on upstream.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/build"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/manager"
	"github.com/google/syzkaller/pkg/manager/diff"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/vm"
	"golang.org/x/sync/errgroup"
)

var (
	flagBase    = flag.String("base", "", "manager config of the BASE (pre-patch) kernel")
	flagPatched = flag.String("patched", "", "manager config of the PATCHED kernel (the one that is fuzzed)")
	flagPatch   = flag.String("patch", "",
		"git diff / mbox of the series under test (files-level focus areas); may be repeated via commas")
	flagBaseObj    = flag.String("base_obj", "", "base vmlinux.o for symbol hashes (default: <base kernel_obj>/vmlinux.o)")
	flagPatchedObj = flag.String("patched_obj", "",
		"patched vmlinux.o for symbol hashes (default: <patched kernel_obj>/vmlinux.o)")
	flagOut  = flag.String("out", "", "output directory (default: <patched workdir>/mpiric-diff)")
	flagTime = flag.Duration("time", 2*time.Hour,
		"total run time; the engine is cancelled and the summary written after it")
	flagTriage = flag.Duration("triage", 0,
		"MaxTriageTime: stop waiting for corpus triage and start reproductions after this (default: -time/2)")
	flagReach = flag.Duration("reach", 0,
		"FuzzToReachPatched: abort if the patched code is not reached within this time after triage (0 = never abort)")
	flagRepros   = flag.Int("repros", 2, "parallel reproductions to budget VMs for (needs count-fuzzing_vms >= (4N+2)/3)")
	flagPossible = flag.Int("possible_cutoff", 10,
		"report a title as 'possibly patched-only' when it crashed patched at least this often and never on base")
	flagIgnore = flag.String("ignore_titles", "",
		"regexp of crash titles to ignore (the only way to drop e.g. KCSAN reports from the engine)")
	flagDebug = flag.Bool("debug", false, "dump all VM output to console")
)

func main() {
	flag.Parse()
	if !prog.GitRevisionKnown() {
		log.Fatalf("bad mpiric-diff build: build with 'make mpiric-diff', run bin/mpiric-diff")
	}
	if *flagBase == "" || *flagPatched == "" {
		log.Fatalf("both -base and -patched configs are required")
	}
	if *flagTriage == 0 {
		*flagTriage = *flagTime / 2
	}
	ignoreRe, err := compileIgnore(*flagIgnore)
	if err != nil {
		log.Fatalf("bad -ignore_titles: %v", err)
	}

	baseCfg, err := mgrconfig.LoadFile(*flagBase)
	if err != nil {
		log.Fatalf("base config: %v", err)
	}
	patchedCfg, err := mgrconfig.LoadFile(*flagPatched)
	if err != nil {
		log.Fatalf("patched config: %v", err)
	}
	if err := checkVMBudget(baseCfg, patchedCfg, *flagRepros); err != nil {
		log.Fatalf("VM budget: %v", err)
	}

	outDir := *flagOut
	if outDir == "" {
		outDir = filepath.Join(patchedCfg.Workdir, "mpiric-diff")
	}
	artifactsDir := filepath.Join(outDir, "artifacts")
	if err := osutil.MkdirAll(artifactsDir); err != nil {
		log.Fatalf("failed to create %v: %v", artifactsDir, err)
	}

	baseHashes, patchedHashes := readSymbolHashes(baseCfg, patchedCfg)
	if identicalText(baseHashes, patchedHashes) {
		log.Fatalf("base and patched kernels have identical .text symbols; nothing to diff")
	}
	patches, err := readPatches(*flagPatch)
	if err != nil {
		log.Fatalf("failed to read -patch: %v", err)
	}
	if len(patches) > 0 || len(patchedHashes.Text) > 0 {
		diff.PatchFocusAreas(patchedCfg, patches, baseHashes.Text, patchedHashes.Text)
	} else {
		log.Logf(0, "WARNING: no -patch and no symbol hashes: fuzzing is not aimed at the change")
	}

	store := &manager.DiffFuzzerStore{BasePath: artifactsDir}
	sink := &bugSink{dir: filepath.Join(outDir, "patched_only"), bugs: map[string]*diff.Bug{}}

	// Graceful SIGINT/SIGTERM: closes vm.Shutdown, which cancels the context, so
	// that diff.Run returns and the in-memory store still gets written out below.
	osutil.HandleInterrupts(vm.Shutdown)
	ctx, cancel := context.WithTimeout(vm.ShutdownCtx(), *flagTime)
	defer cancel()

	log.Logf(0, "mpiric-diff: run time %v, triage deadline %v, reach gate %v, output %v",
		*flagTime, *flagTriage, *flagReach, outDir)
	err = run(ctx, baseCfg, patchedCfg, store, sink, ignoreRe)
	switch {
	case err == nil:
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		log.Logf(0, "run finished: %v", err)
	case errors.Is(err, diff.ErrPatchedAreaNotReached):
		// The fuzzer never reached the modified code within -reach; that is a
		// legitimate outcome, not a failure of the driver.
		log.Logf(0, "run finished: %v", err)
	default:
		log.Errorf("run failed: %v", err)
	}
	if err := writeSummary(outDir, store, sink, *flagPossible); err != nil {
		log.Fatalf("failed to write the summary: %v", err)
	}
}

func run(ctx context.Context, baseCfg, patchedCfg *mgrconfig.Config, store *manager.DiffFuzzerStore,
	sink *bugSink, ignoreRe *regexp.Regexp) error {
	eg, groupCtx := errgroup.WithContext(ctx)
	// Both sends block the engine's main loop; keep them buffered and drained.
	bugs := make(chan *diff.Bug, 16)
	baseCrashes := make(chan string, 16)
	eg.Go(func() error {
		defer log.Logf(0, "bug collection terminated")
		for {
			select {
			case title := <-baseCrashes:
				log.Logf(0, "base kernel crashed: %q", title)
			case bug := <-bugs:
				sink.add(bug)
			case <-groupCtx.Done():
				return nil
			}
		}
	})
	eg.Go(func() error {
		defer log.Logf(0, "diff fuzzing terminated")
		cfg := diff.Config{
			Debug:        *flagDebug,
			PatchedOnly:  bugs,
			BaseCrashes:  baseCrashes,
			Store:        store,
			ArtifactsDir: store.BasePath, // declared by the engine, not read by it yet

			MaxTriageTime:      *flagTriage,
			FuzzToReachPatched: *flagReach,
		}
		if ignoreRe != nil {
			cfg.IgnoreCrash = func(_ context.Context, title string) (bool, error) {
				if ignoreRe.MatchString(title) {
					log.Logf(1, "crash %q matches -ignore_titles", title)
					return true, nil
				}
				return false, nil
			}
		}
		return diff.Run(groupCtx, baseCfg, patchedCfg, cfg)
	})
	eg.Go(func() error {
		defer log.Logf(0, "status reporting terminated")
		const period = 5 * time.Minute
		for {
			select {
			case <-groupCtx.Done():
				return nil
			case <-time.After(period):
			}
			log.Logf(0, "status:\n%s", store.PlainTextDump())
		}
	})
	return eg.Wait()
}

// bugSink de-duplicates the engine's PatchedOnly deliveries by title.
//
// The engine delivers a title more than once: first with the Fast-mode repro (no
// C program), then after the FullRepro pass (CRepro set), and again on any later
// patched crash of the same title that gets a repro.  We keep the best delivery
// per title, preferring one that carries a C reproducer, and write the artifacts
// the store does not: the C program, the syz program and the report.
type bugSink struct {
	dir  string
	mu   sync.Mutex
	bugs map[string]*diff.Bug
	seen map[string]int
}

func (s *bugSink) add(bug *diff.Bug) {
	if bug == nil || bug.Report == nil {
		return
	}
	title := bug.Report.Title
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seen == nil {
		s.seen = map[string]int{}
	}
	s.seen[title]++
	prev := s.bugs[title]
	if prev != nil && hasCRepro(prev) && !hasCRepro(bug) {
		log.Logf(0, "patched-only %q: delivery #%d without a C repro, keeping the earlier one",
			title, s.seen[title])
		return
	}
	s.bugs[title] = bug
	log.Logf(0, "patched-only %q: delivery #%d, C repro = %v", title, s.seen[title], hasCRepro(bug))
	if err := s.write(title, bug); err != nil {
		log.Errorf("failed to write artifacts for %q: %v", title, err)
	}
}

func hasCRepro(bug *diff.Bug) bool {
	return bug.Repro != nil && bug.Repro.CRepro && bug.Repro.Prog != nil
}

// write stores the artifacts under patched_only/<hash>/, where <hash> is the
// same hash.String(title) the engine's store uses under artifacts/crashes/, so
// the two can be correlated by directory name.
func (s *bugSink) write(title string, bug *diff.Bug) error {
	dir := filepath.Join(s.dir, hash.String([]byte(title)))
	if err := osutil.MkdirAll(dir); err != nil {
		return err
	}
	if err := osutil.WriteFile(filepath.Join(dir, "title"), []byte(title+"\n")); err != nil {
		return err
	}
	if len(bug.Report.Report) > 0 {
		if err := osutil.WriteFile(filepath.Join(dir, "report"), bug.Report.Report); err != nil {
			return err
		}
	}
	if len(bug.Report.Output) > 0 {
		if err := osutil.WriteFile(filepath.Join(dir, "log"), bug.Report.Output); err != nil {
			return err
		}
	}
	if bug.Repro == nil || bug.Repro.Prog == nil {
		return nil
	}
	if err := osutil.WriteFile(filepath.Join(dir, "repro.syz"), bug.Repro.Prog.Serialize()); err != nil {
		return err
	}
	if err := osutil.WriteFile(filepath.Join(dir, "repro.opts"), bug.Repro.Opts.Serialize()); err != nil {
		return err
	}
	if !bug.Repro.CRepro {
		return nil
	}
	cprog, err := bug.Repro.CProgram()
	if err != nil {
		return fmt.Errorf("CProgram: %w", err)
	}
	return osutil.WriteFile(filepath.Join(dir, "repro.c"), cprog)
}

func (s *bugSink) snapshot() (map[string]*diff.Bug, map[string]int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	bugs := make(map[string]*diff.Bug, len(s.bugs))
	for k, v := range s.bugs {
		bugs[k] = v
	}
	seen := make(map[string]int, len(s.seen))
	for k, v := range s.seen {
		seen[k] = v
	}
	return bugs, seen
}

type summary struct {
	PatchedOnly         []summaryBug `json:"patched_only"`
	PossiblyPatchedOnly []summaryBug `json:"possibly_patched_only"`
	AffectsBoth         []string     `json:"affects_both"`
	All                 []manager.DiffBug
}

type summaryBug struct {
	Title          string  `json:"title"`
	PatchedCrashes int     `json:"patched_crashes"`
	BaseCrashes    int     `json:"base_crashes"`
	Deliveries     int     `json:"deliveries,omitempty"`
	Reliability    float64 `json:"reliability,omitempty"`
	CRepro         bool    `json:"c_repro"`
	Dir            string  `json:"dir,omitempty"`
}

// writeSummary reconciles what the engine delivered over PatchedOnly with the
// store's final view and writes summary.txt / summary.json.  It runs after
// diff.Run has returned: the store is in-memory only, so this is the only place
// its final state survives.
func writeSummary(outDir string, store *manager.DiffFuzzerStore, sink *bugSink, possibleCutoff int) error {
	delivered, seen := sink.snapshot()
	list := store.List()
	sort.Slice(list, func(i, j int) bool { return list[i].Title < list[j].Title })

	var sum summary
	sum.All = list
	for _, bug := range list {
		switch {
		case bug.PatchedOnly():
			sb := summaryBug{
				Title:          bug.Title,
				PatchedCrashes: bug.Patched.Crashes,
				Deliveries:     seen[bug.Title],
			}
			if d := delivered[bug.Title]; d != nil {
				sb.CRepro = hasCRepro(d)
				sb.Dir = filepath.Join(sink.dir, hash.String([]byte(bug.Title)))
				if d.Repro != nil {
					sb.Reliability = d.Repro.Reliability
				}
			}
			sum.PatchedOnly = append(sum.PatchedOnly, sb)
		case bug.Base.Crashes == 0 && bug.Patched.Crashes >= possibleCutoff:
			// Crashed the patched kernel repeatedly, never seen on base, but no
			// reproducer cleared the engine's reliability cut-off (or none was
			// found).  This is the realistic outcome for a low-probability race
			// and must be reviewed by hand, not silently dropped.
			sum.PossiblyPatchedOnly = append(sum.PossiblyPatchedOnly, summaryBug{
				Title:          bug.Title,
				PatchedCrashes: bug.Patched.Crashes,
			})
		case bug.AffectsBoth():
			sum.AffectsBoth = append(sum.AffectsBoth, bug.Title)
		}
	}
	// Reconcile: a delivered bug the store somehow does not classify as
	// patched-only (e.g. base crashed with the same title later) is still worth
	// listing, flagged as such.
	inStore := map[string]bool{}
	for _, sb := range sum.PatchedOnly {
		inStore[sb.Title] = true
	}
	for title, d := range delivered {
		if inStore[title] {
			continue
		}
		log.Logf(0, "WARNING: %q was delivered as patched-only but the store no longer classifies it so", title)
		sum.PatchedOnly = append(sum.PatchedOnly, summaryBug{
			Title:      title,
			Deliveries: seen[title],
			CRepro:     hasCRepro(d),
			Dir:        filepath.Join(sink.dir, hash.String([]byte(title))),
		})
	}

	var text strings.Builder
	fmt.Fprintf(&text, "mpiric-diff summary (%s)\n\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(&text, "PATCHED-ONLY (%d): base verified clean by replaying the reproducer\n", len(sum.PatchedOnly))
	for _, sb := range sum.PatchedOnly {
		fmt.Fprintf(&text, "  %s\n    patched crashes=%d deliveries=%d reliability=%.2f c_repro=%v\n    %s\n",
			sb.Title, sb.PatchedCrashes, sb.Deliveries, sb.Reliability, sb.CRepro, sb.Dir)
	}
	fmt.Fprintf(&text, "\nPOSSIBLY PATCHED-ONLY (%d): >=%d patched crashes, 0 on base, "+
		"no reliable repro; review by hand\n", len(sum.PossiblyPatchedOnly), possibleCutoff)
	for _, sb := range sum.PossiblyPatchedOnly {
		fmt.Fprintf(&text, "  %s (patched crashes=%d)\n", sb.Title, sb.PatchedCrashes)
	}
	fmt.Fprintf(&text, "\nAFFECTS BOTH (%d):\n", len(sum.AffectsBoth))
	for _, title := range sum.AffectsBoth {
		fmt.Fprintf(&text, "  %s\n", title)
	}
	fmt.Fprintf(&text, "\nFULL STORE:\n%s", store.PlainTextDump())
	log.Logf(0, "%s", text.String())

	if err := osutil.WriteFile(filepath.Join(outDir, "summary.txt"), []byte(text.String())); err != nil {
		return err
	}
	data, err := json.MarshalIndent(sum, "", "  ")
	if err != nil {
		return err
	}
	return osutil.WriteFile(filepath.Join(outDir, "summary.json"), data)
}

// checkVMBudget refuses configurations the engine does not guard against:
// fuzzing_vms > count panics, fuzzing_vms == count blocks forever (the repro
// loop gets zero VMs), and fewer than (4N+2)/3 spare VMs cannot run N
// reproductions in parallel (pkg/manager/repro.go calculateReproVMs).
func checkVMBudget(baseCfg, patchedCfg *mgrconfig.Config, repros int) error {
	if repros < 1 {
		return fmt.Errorf("-repros must be >= 1")
	}
	patchedCount, err := vmCount(patchedCfg)
	if err != nil {
		return fmt.Errorf("patched: %w", err)
	}
	baseCount, err := vmCount(baseCfg)
	if err != nil {
		return fmt.Errorf("base: %w", err)
	}
	spare := patchedCount - patchedCfg.FuzzingVMs
	if spare <= 0 {
		return fmt.Errorf("patched fuzzing_vms (%d) must be < vm count (%d): the repro loop would get no VMs",
			patchedCfg.FuzzingVMs, patchedCount)
	}
	need := (repros*4 + 2) / 3
	if spare < need {
		return fmt.Errorf("patched vm count (%d) - fuzzing_vms (%d) = %d, but %d parallel repros need %d "+
			"(lower -repros or fuzzing_vms, or raise count)", patchedCount, patchedCfg.FuzzingVMs, spare, repros, need)
	}
	if baseCount < 2 {
		log.Logf(0, "WARNING: base vm count is %d; base verification runs a repro 3-6 times and reserves "+
			"VMs from the same pool, 2+ is recommended", baseCount)
	}
	if baseCfg.FuzzingVMs != 0 {
		log.Logf(0, "WARNING: base fuzzing_vms=%d is ignored by the engine (the base pool only replays)",
			baseCfg.FuzzingVMs)
	}
	log.Logf(0, "VM budget: patched count=%d fuzzing_vms=%d spare=%d (repros=%d need %d); base count=%d",
		patchedCount, patchedCfg.FuzzingVMs, spare, repros, need, baseCount)
	return nil
}

// vmCount instantiates the VM pool the same way the engine will (the qemu
// constructor only validates its config and does not boot anything).
func vmCount(cfg *mgrconfig.Config) (int, error) {
	pool, err := vm.Create(cfg, false)
	if err != nil {
		return 0, fmt.Errorf("failed to create vm pool: %w", err)
	}
	return pool.Count(), nil
}

// readSymbolHashes hashes every .text/.data symbol of both vmlinux.o files.
// Without them diff.PatchFocusAreas cannot add the function-level (weight 6)
// focus area and silently degrades to files only, so a failure is loud.
func readSymbolHashes(baseCfg, patchedCfg *mgrconfig.Config) (base, patched build.SectionHashes) {
	baseObj := *flagBaseObj
	if baseObj == "" {
		baseObj = filepath.Join(baseCfg.KernelObj, "vmlinux.o")
	}
	patchedObj := *flagPatchedObj
	if patchedObj == "" {
		patchedObj = filepath.Join(patchedCfg.KernelObj, "vmlinux.o")
	}
	var err error
	base, err = build.ElfSymbolHashes(baseObj)
	if err != nil {
		log.Logf(0, "WARNING: no base symbol hashes (%v): focus areas degrade to files only", err)
		return build.SectionHashes{}, build.SectionHashes{}
	}
	patched, err = build.ElfSymbolHashes(patchedObj)
	if err != nil {
		log.Logf(0, "WARNING: no patched symbol hashes (%v): focus areas degrade to files only", err)
		return build.SectionHashes{}, build.SectionHashes{}
	}
	log.Logf(0, "symbol hashes: base %d text symbols, patched %d text symbols", len(base.Text), len(patched.Text))
	return base, patched
}

func identicalText(base, patched build.SectionHashes) bool {
	if len(base.Text) == 0 || len(patched.Text) == 0 || len(base.Text) != len(patched.Text) {
		return false
	}
	for name, h := range base.Text {
		if patched.Text[name] != h {
			return false
		}
	}
	return true
}

func readPatches(spec string) ([][]byte, error) {
	var ret [][]byte
	for _, file := range strings.Split(spec, ",") {
		file = strings.TrimSpace(file)
		if file == "" {
			continue
		}
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		ret = append(ret, data)
	}
	return ret, nil
}

func compileIgnore(re string) (*regexp.Regexp, error) {
	if re == "" {
		return nil, nil
	}
	return regexp.Compile(re)
}
