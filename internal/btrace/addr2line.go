// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package btrace

import (
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Asphaltt/addr2line"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/klauspost/compress/zstd"
)

const (
	debugModulesPath = "/usr/lib/debug/lib/modules/"
)

type kmodAddr2line struct {
	*addr2line.Addr2Line
	kaslr Kaslr
}

// Addr2Line is a wrapper around addr2line.Addr2Line with a cache.
type Addr2Line struct {
	vmlinux string
	a2l     *addr2line.Addr2Line
	kmods   map[string]kmodAddr2line
	cache   *lru.Cache[uintptr, *addr2line.Addr2LineEntry]

	kaslr    Kaslr
	buildDir string
}

// NewAddr2Line creates a new Addr2Line instance from the given vmlinux file.
func NewAddr2Line(vmlinux string, kaslr Kaslr, sysBPF uint64) (*Addr2Line, error) {
	a2l, err := addr2line.New(vmlinux)
	if err != nil {
		return nil, fmt.Errorf("failed to create addr2line from %s: %w", vmlinux, err)
	}

	eaddr := kaslr.effectiveAddr(sysBPF)
	sysBpfLineInfo, err := a2l.Get(eaddr, true)
	if err != nil {
		return nil, fmt.Errorf("failed to get addr2line entry for __x64_sys_bpf: %w", err)
	}

	const bpfSyscallFile = "kernel/bpf/syscall.c"
	if len(sysBpfLineInfo.File) < len(bpfSyscallFile) {
		return nil, fmt.Errorf("unexpected file name for __x64_sys_bpf: %s", sysBpfLineInfo.File)
	}

	buildDir := sysBpfLineInfo.File[:len(sysBpfLineInfo.File)-len(bpfSyscallFile)]

	cache, _ := lru.New[uintptr, *addr2line.Addr2LineEntry](10000)
	return &Addr2Line{
		vmlinux: vmlinux,
		a2l:     a2l,
		kmods:   make(map[string]kmodAddr2line),
		cache:   cache,

		kaslr:    kaslr,
		buildDir: buildDir,
	}, nil
}

func findKernelModuleFileUnderDir(mod, dir string) (string, error) {
	modKo, modKoZst, modKoFile := mod+".ko", mod+".ko.zst", ""

	errFound := errors.New("found")

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if slices.Contains([]string{modKo, modKoZst}, filepath.Base(path)) {
			modKoFile = path
			return errFound
		}

		return nil
	})

	if err == errFound {
		return modKoFile, nil
	}

	if err != nil {
		return "", fmt.Errorf("failed to walk %s: %w", dir, err)
	}

	return "", ErrNotFound
}

func findKernelModuleFile(mod string) (string, error) {
	release, err := getRelease()
	if err != nil {
		return "", fmt.Errorf("failed to get release: %w", err)
	}

	roodDir := filepath.Join(debugModulesPath, release)
	modKoFile, err := findKernelModuleFileUnderDir(mod, roodDir)
	if err != nil {
		return "", fmt.Errorf("failed to find %s: %w", mod, err)
	}

	return modKoFile, nil
}

func zst2readerAt(fd *os.File) (io.ReaderAt, error) {
	dec, err := zstd.NewReader(fd)
	if err != nil {
		return nil, fmt.Errorf("failed to create zstd reader for %s: %w", fd.Name(), err)
	}

	var buf bytes.Buffer
	_, err = dec.WriteTo(&buf)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress %s: %w", fd.Name(), err)
	}

	return newBufferReaderAt(&buf), nil
}

func findSymbolInKmod(modKo, symbol string) (*elf.Symbol, error) {
	var elfFile *elf.File

	if strings.HasSuffix(modKo, ".ko.zst") {
		fd, err := os.Open(modKo)
		if err != nil {
			return nil, fmt.Errorf("failed to open file %s: %w", modKo, err)
		}
		defer fd.Close()

		r, err := zst2readerAt(fd)
		if err != nil {
			return nil, fmt.Errorf("failed to create zstd reader for %s: %w", modKo, err)
		}

		e, err := elf.NewFile(r)
		if err != nil {
			return nil, fmt.Errorf("failed to read ELF file %s: %w", modKo, err)
		}

		elfFile = e

	} else {
		file, err := os.Open(modKo)
		if err != nil {
			return nil, fmt.Errorf("failed to open file %s: %w", modKo, err)
		}
		defer file.Close()

		e, err := elf.NewFile(file)
		if err != nil {
			return nil, fmt.Errorf("failed to read ELF file %s: %w", modKo, err)
		}

		elfFile = e
	}

	symbols, err := elfFile.Symbols()
	if err != nil {
		return nil, fmt.Errorf("failed to get symbols from ELF file %s: %w", modKo, err)
	}

	for _, sym := range symbols {
		if sym.Name == symbol {
			return &sym, nil
		}
	}

	return nil, ErrNotFound
}

func (a2l *Addr2Line) getMod(ksym *KsymEntry) (*addr2line.Addr2Line, Kaslr, error) {
	if ksym == nil || isKernelBuiltinMod(ksym.mod) {
		return a2l.a2l, a2l.kaslr, nil
	}

	var modKo string

	modName := ksym.mod
	kmod, ok := a2l.kmods[modName]
	if ok {
		return kmod.Addr2Line, kmod.kaslr, nil
	}

	modKo, err := findKernelModuleFile(modName)
	if errors.Is(err, ErrNotFound) {
		kmod = kmodAddr2line{}
		kmod.Addr2Line = nil
		kmod.kaslr = Kaslr{}
		a2l.kmods[modName] = kmod // cache the not-found result
		return nil, Kaslr{}, nil
	}
	if err != nil {
		return nil, Kaslr{}, fmt.Errorf("failed to find %s: %w", modName, err)
	}

	VerboseLog("Found %s at %s", modName, modKo)

	var li *addr2line.Addr2Line
	if strings.HasSuffix(modKo, ".ko.zst") {
		fd, err := os.Open(modKo)
		if err != nil {
			return nil, Kaslr{}, fmt.Errorf("failed to open file %s: %w", modKo, err)
		}
		defer fd.Close()

		r, err := zst2readerAt(fd)
		if err != nil {
			return nil, Kaslr{}, fmt.Errorf("failed to create zstd reader for %s: %w", modKo, err)
		}

		li, err = addr2line.NewAt(r, modKo)
		if err != nil {
			VerboseLog("Failed to create addr2line for %s: %v", modName, err)
		}
	} else {
		li, err = addr2line.New(modKo)
		if err != nil {
			VerboseLog("Failed to create addr2line for %s: %v", modName, err)
		}
	}

	sym, err := findSymbolInKmod(modKo, ksym.name)
	if err != nil {
		return nil, Kaslr{}, fmt.Errorf("failed to find symbol %s in %s: %w", ksym.name, modKo, err)
	}

	kmod = kmodAddr2line{}
	kmod.Addr2Line = li
	kmod.kaslr = NewKaslr(ksym.addr, sym.Value)

	a2l.kmods[modName] = kmod

	kaslr := kmod.kaslr
	return kmod.Addr2Line, kaslr, nil
}

// get returns the addr2line entry from the vmlinux file for the given address.
func (a2l *Addr2Line) get(addr uintptr, ksym *KsymEntry) (*addr2line.Addr2LineEntry, error) {
	entry, ok := a2l.cache.Get(addr)
	if ok {
		return entry, nil
	}

	a2lMod, kaslr, err := a2l.getMod(ksym)
	if err != nil {
		return nil, fmt.Errorf("failed to get addr2line for %s: %w", ksym.mod, err)
	}

	if a2lMod == nil {
		return nil, ErrNotFound
	}

	eaddr := kaslr.effectiveAddr(uint64(addr))
	entry, err = a2lMod.Get(eaddr, true)
	if err != nil {
		return nil, fmt.Errorf("failed to get addr2line entry with KASLR offset %#x: %w", kaslr.offset(), err)
	}

	_ = a2l.cache.Add(addr, entry)
	return entry, nil
}
