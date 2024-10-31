// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpflbr

import (
	"fmt"

	"github.com/Asphaltt/addr2line"
	lru "github.com/hashicorp/golang-lru/v2"
)

// Addr2Line is a wrapper around addr2line.Addr2Line with a cache.
type Addr2Line struct {
	vmlinux string
	a2l     *addr2line.Addr2Line
	cache   *lru.Cache[uintptr, *addr2line.Addr2LineEntry]
}

// NewAddr2Line creates a new Addr2Line instance from the given vmlinux file.
func NewAddr2Line(vmlinux string) (*Addr2Line, error) {
	a2l, err := addr2line.New(vmlinux)
	if err != nil {
		return nil, fmt.Errorf("failed to create addr2line from %s: %w", vmlinux, err)
	}

	cache, _ := lru.New[uintptr, *addr2line.Addr2LineEntry](10000)
	return &Addr2Line{
		vmlinux: vmlinux,
		a2l:     a2l,
		cache:   cache,
	}, nil
}

// Get returns the addr2line entry from the vmlinux file for the given address.
func (a2l *Addr2Line) Get(addr uintptr) (*addr2line.Addr2LineEntry, error) {
	entry, ok := a2l.cache.Get(addr)
	if ok {
		return entry, nil
	}

	entry, err := a2l.a2l.Get(uint64(addr), true)
	if err != nil {
		return nil, fmt.Errorf("failed to get addr2line entry: %w", err)
	}

	_ = a2l.cache.Add(addr, entry)
	return entry, nil
}
