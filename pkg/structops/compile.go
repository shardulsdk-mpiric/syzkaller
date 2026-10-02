// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package structops

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

// Host compile step: rendered C translation unit -> load recipe.
//
// Generation runs host-side in syz-manager (pkg/fuzzer), so the object the
// executor loads must be compiled here and travel inline in the program as
// the syz_bpf_struct_ops_load blob.  The compile is
//
//	clang -O2 -g -target bpf -mcpu=v3 -DBPF_NO_PRESERVE_ACCESS_INDEX
//	      -fms-extensions -include structops_shim.h  (-> the kernel's vmlinux.h)
//	llvm-strip -g                     (drop DWARF; .BTF/.BTF.ext stay)
//	Digest()                          (ELF -> recipe TLV)
//
// against a vmlinux.h dumped from the TARGET kernel build's vmlinux
// (bpftool btf dump file <kernel_obj>/vmlinux format c).  With
// BPF_NO_PRESERVE_ACCESS_INDEX the object carries exact field offsets for
// that kernel and no CO-RE relocations, so the loader needs no relocation
// support; the price is that the blob is specific to the kernel build,
// which syzbot-style reproducers already are.
//
// Results are cached by sha256 of the source (the render is deterministic
// per seed, and the same program is re-executed many times in triage).

//go:embed include
var shimFS embed.FS

// CompileConfig configures the host compile step.  Zero values take the
// defaults noted on each field.
type CompileConfig struct {
	// KernelObj is the kernel build directory; vmlinux.h is dumped from
	// <KernelObj>/vmlinux unless VmlinuxH is set.
	KernelObj string
	// VmlinuxH is a pre-dumped vmlinux.h for the target kernel (optional;
	// overrides KernelObj).
	VmlinuxH string
	// CacheDir holds the include tree (vmlinux.h + shims) and compiled
	// objects.  Default: a per-user temp dir.
	CacheDir string
	// Tool paths; default to clang, llvm-strip, bpftool from PATH.
	Clang, Strip, Bpftool string
}

type compiler struct {
	cfg           CompileConfig
	incDir        string // -I dir: vmlinux.h + bpf/ shims + structops_shim.h
	objDir        string
	layoutChecked int // structs the Configure-time layout self-check compared
	mu            sync.Mutex
	cache         map[[32]byte][]byte
	stats         CompileStats
	initErr       error
	once          sync.Once
}

// CompileStats counts what the compile step did (for logging/measurement).
type CompileStats struct {
	Compiled, CacheHits, Failed int
	CompileTime                 time.Duration
}

var (
	compilerMu  sync.Mutex
	theCompiler *compiler
)

// Configure installs the host compile step: it lays out the include tree
// (dumping vmlinux.h from the kernel build), then runs the layout
// self-check (layout.go) and installs the compiler only if it passes.  An
// error wrapping ErrLayoutMismatch means this vmlinux.h/clang pair would
// compile programs with wrong field offsets; any other error means the
// step cannot run here (no vmlinux, no clang/bpftool).  Until a Configure
// succeeds, Compile returns ErrNotConfigured and the generator leaves the
// rendered source in the blob (which the executor rejects at load with
// EINVAL).
func Configure(cfg CompileConfig) error {
	if cfg.Clang == "" {
		cfg.Clang = "clang"
	}
	if cfg.Strip == "" {
		cfg.Strip = "llvm-strip"
	}
	if cfg.Bpftool == "" {
		cfg.Bpftool = "bpftool"
	}
	if cfg.CacheDir == "" {
		cfg.CacheDir = filepath.Join(os.TempDir(), fmt.Sprintf("syz-structops-%d", os.Getuid()))
	}
	c := &compiler{cfg: cfg, cache: make(map[[32]byte][]byte)}
	if err := c.init(); err != nil {
		return err
	}
	if c.cfg.KernelObj != "" {
		names := layoutProbeTypes()
		expected, err := kernelStructSizes(filepath.Join(c.cfg.KernelObj, "vmlinux"), names)
		if err != nil {
			return err
		}
		if c.layoutChecked, err = c.checkLayout(expected); err != nil {
			return err
		}
	}
	compilerMu.Lock()
	defer compilerMu.Unlock()
	theCompiler = c
	return nil
}

// LayoutChecked returns how many kernel structs the Configure-time layout
// self-check compared (0 if it could not run: no kernel_obj vmlinux).
func LayoutChecked() int {
	compilerMu.Lock()
	defer compilerMu.Unlock()
	if theCompiler == nil {
		return 0
	}
	return theCompiler.layoutChecked
}

// Configured reports whether Configure has been called.
func Configured() bool {
	compilerMu.Lock()
	defer compilerMu.Unlock()
	return theCompiler != nil
}

// ErrNotConfigured is returned by Compile before Configure.
var ErrNotConfigured = fmt.Errorf("structops: host compile step not configured")

// Compile compiles a rendered translation unit to its load recipe.
func Compile(src string) ([]byte, error) {
	compilerMu.Lock()
	c := theCompiler
	compilerMu.Unlock()
	if c == nil {
		return nil, ErrNotConfigured
	}
	return c.compile(src)
}

// Stats returns the compile counters (zero if not configured).
func Stats() CompileStats {
	compilerMu.Lock()
	c := theCompiler
	compilerMu.Unlock()
	if c == nil {
		return CompileStats{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stats
}

func (c *compiler) init() error {
	c.once.Do(func() { c.initErr = c.doInit() })
	return c.initErr
}

// doInit lays out the include tree once per (kernel build, cache dir):
// the embedded shims plus vmlinux.h dumped from the kernel build (or
// copied from the pre-dumped path), under a directory keyed by the
// vmlinux identity so several kernels can share one cache.
func (c *compiler) doInit() error {
	var src string
	var key string
	if c.cfg.VmlinuxH != "" {
		src = c.cfg.VmlinuxH
	} else {
		if c.cfg.KernelObj == "" {
			return fmt.Errorf("structops: neither kernel_obj nor a vmlinux.h is configured")
		}
		src = filepath.Join(c.cfg.KernelObj, "vmlinux")
	}
	st, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("structops: %w", err)
	}
	h := sha256.Sum256([]byte(fmt.Sprintf("%s|%d|%d", src, st.Size(), st.ModTime().UnixNano())))
	key = hex.EncodeToString(h[:8])
	root := filepath.Join(c.cfg.CacheDir, key)
	c.incDir = filepath.Join(root, "include")
	c.objDir = filepath.Join(root, "obj")
	if err := os.MkdirAll(c.objDir, 0755); err != nil {
		return fmt.Errorf("structops: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(c.incDir, "bpf"), 0755); err != nil {
		return fmt.Errorf("structops: %w", err)
	}
	if err := fs.WalkDir(shimFS, "include", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := shimFS.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel("include", p)
		return os.WriteFile(filepath.Join(c.incDir, rel), data, 0644)
	}); err != nil {
		return fmt.Errorf("structops: shim headers: %w", err)
	}
	dst := filepath.Join(c.incDir, "vmlinux.h")
	if st, err := os.Stat(dst); err == nil && st.Size() > 0 {
		return nil // already dumped for this kernel
	}
	var data []byte
	if c.cfg.VmlinuxH != "" {
		data, err = os.ReadFile(src)
		if err != nil {
			return fmt.Errorf("structops: %w", err)
		}
	} else {
		cmd := exec.Command(c.cfg.Bpftool, "btf", "dump", "file", src, "format", "c")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		data, err = cmd.Output()
		if err != nil {
			return fmt.Errorf("structops: bpftool btf dump %s: %w\n%s", src, err, stderr.Bytes())
		}
	}
	if !bytes.Contains(data, []byte("BPF_NO_PRESERVE_ACCESS_INDEX")) {
		return fmt.Errorf("structops: %s does not look like a bpftool vmlinux.h", src)
	}
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return fmt.Errorf("structops: %w", err)
	}
	return os.Rename(tmp, dst)
}

func (c *compiler) compile(src string) ([]byte, error) {
	if err := c.init(); err != nil {
		return nil, err
	}
	key := sha256.Sum256([]byte(src))
	c.mu.Lock()
	if r, ok := c.cache[key]; ok {
		c.stats.CacheHits++
		c.mu.Unlock()
		return r, nil
	}
	c.mu.Unlock()

	start := time.Now()
	recipe, err := c.compileUncached(src, hex.EncodeToString(key[:8]))
	elapsed := time.Since(start)

	c.mu.Lock()
	defer c.mu.Unlock()
	c.stats.CompileTime += elapsed
	if err != nil {
		c.stats.Failed++
		return nil, err
	}
	c.stats.Compiled++
	if len(c.cache) >= 4096 {
		c.cache = make(map[[32]byte][]byte) // bounded; a flush is cheap
	}
	c.cache[key] = recipe
	return recipe, nil
}

// clangArgs is the compile command line for one translation unit read from
// stdin into obj; the layout probe appends to it.
func (c *compiler) clangArgs(obj string) []string {
	return []string{
		"-O2", "-g", "-target", "bpf", "-mcpu=v3",
		"-DBPF_NO_PRESERVE_ACCESS_INDEX",
		// The kernel is built with -fms-extensions and uses tagged anonymous
		// members (`union { struct slock_owned; long combined; }` in
		// socket_lock_t, 7.x); vmlinux.h reproduces them verbatim.  Without
		// the flag clang reads `struct slock_owned;` as an empty declaration
		// and lays struct sock out 64 bytes short, and with CO-RE off every
		// field offset after it is wrong (verifier: "cannot access ptr
		// member ... with off").  The Configure-time layout self-check
		// (layout.go) catches a recurrence.
		"-fms-extensions",
		"-I", c.incDir,
		"-include", filepath.Join(c.incDir, "structops_shim.h"),
		"-x", "c", "-", "-c", "-o", obj,
	}
}

func (c *compiler) compileUncached(src, name string) ([]byte, error) {
	obj := filepath.Join(c.objDir, name+".o")
	defer os.Remove(obj)
	cmd := exec.Command(c.cfg.Clang, c.clangArgs(obj)...)
	cmd.Stdin = bytes.NewReader([]byte(src))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("structops: clang: %w\n%s", err, truncate(stderr.String(), 4096))
	}
	stderr.Reset()
	cmd = exec.Command(c.cfg.Strip, "-g", obj)
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("structops: llvm-strip: %w\n%s", err, truncate(stderr.String(), 4096))
	}
	data, err := os.ReadFile(obj)
	if err != nil {
		return nil, fmt.Errorf("structops: %w", err)
	}
	return Digest(data)
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}
