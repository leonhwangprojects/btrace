// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpflbr

import (
	"bufio"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/exp/maps"
)

const kallsymsFilepath = "/proc/kallsyms"

// KsymEntry represents a symbol entry in /proc/kallsyms.
type KsymEntry struct {
	addr  uint64
	name  string
	mod   string
	trace bool
}

// Addr returns the address of the symbol.
func (ke *KsymEntry) Addr() uint64 {
	return ke.addr
}

// Name returns the name of the symbol.
func (ke *KsymEntry) Name() string {
	return ke.name
}

// Kallsyms represents all t/T symbols in /proc/kallsyms.
type Kallsyms struct {
	symbols map[uint64]*KsymEntry // addr => symbol
	addrs   []uint64              // sorted for binary search

	stext  uint64
	sysBPF uint64
}

// NewKallsyms reads /proc/kallsyms and returns a Kallsyms instance.
func NewKallsyms() (*Kallsyms, error) {
	fd, err := os.Open(kallsymsFilepath)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", kallsymsFilepath, err)
	}
	defer fd.Close()

	var ks Kallsyms
	ks.symbols = make(map[uint64]*KsymEntry)

	scanner := bufio.NewScanner(fd)
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		if fields[1] == "t" || fields[1] == "T" {
			var entry KsymEntry
			entry.addr, err = strconv.ParseUint(fields[0], 16, 64)
			if err != nil {
				return nil, fmt.Errorf("failed to parse addr %s: %w", fields[0], err)
			}

			entry.name = strings.TrimSpace(fields[2])
			if len(fields) >= 4 {
				entry.mod = strings.Trim(fields[3], "[]")
			}
			entry.trace = fields[1] == "T"

			ks.symbols[entry.addr] = &entry

			switch entry.name {
			case "_stext":
				ks.stext = entry.addr

			case "__x64_sys_bpf":
				ks.sysBPF = entry.addr
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to scan %s: %w", kallsymsFilepath, err)
	}

	ks.addrs = maps.Keys(ks.symbols)
	slices.Sort(ks.addrs)

	return &ks, nil
}

// Stext returns the address of _stext.
func (ks *Kallsyms) Stext() uint64 {
	return ks.stext
}

// SysBPF returns the address of __x64_sys_bpf.
func (ks *Kallsyms) SysBPF() uint64 {
	return ks.sysBPF
}

// Find returns the symbol entry of the given address.
func (ks *Kallsyms) Find(kaddr uintptr) (*KsymEntry, bool) {
	addr := uint64(kaddr)
	if addr < ks.addrs[0] || addr > ks.addrs[len(ks.addrs)-1] {
		return nil, false
	}

	total := len(ks.addrs)
	i, j := 0, total
	for i < j {
		h := int(uint(i+j) >> 1)
		if ks.addrs[h] <= addr {
			if h+1 < total && ks.addrs[h+1] > addr {
				return ks.symbols[ks.addrs[h]], true
			}
			i = h + 1
		} else {
			j = h
		}
	}

	return ks.symbols[ks.addrs[i-1]], true
}
