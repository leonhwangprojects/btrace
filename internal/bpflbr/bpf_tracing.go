// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpflbr

import (
	"fmt"
	"log"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sync/errgroup"
)

const (
	// tracingFuncName is the name of the BPF function that is used for
	// tracing.
	tracingFuncName = "fexit_fn"
)

type bpfTracing struct {
	llock sync.Mutex
	progs []*ebpf.Program
	links []link.Link
}

func (t *bpfTracing) Progs() []*ebpf.Program {
	return t.progs
}

func NewBPFTracing(spec *ebpf.CollectionSpec, reusedMaps map[string]*ebpf.Map, infos []bpfTracingInfo) (*bpfTracing, error) {
	var t bpfTracing
	t.links = make([]link.Link, 0, len(infos))

	var errg errgroup.Group

	for _, info := range infos {
		info := info
		errg.Go(func() error {
			return t.traceProg(spec, reusedMaps, info)
		})
	}

	if err := errg.Wait(); err != nil {
		t.Close()
		return nil, fmt.Errorf("failed to trace bpf progs: %w", err)
	}

	return &t, nil
}

func (t *bpfTracing) Close() {
	t.llock.Lock()
	defer t.llock.Unlock()

	var errg errgroup.Group

	for _, l := range t.links {
		l := l
		errg.Go(func() error {
			return l.Close()
		})
	}

	_ = errg.Wait()
}

func (t *bpfTracing) traceProg(spec *ebpf.CollectionSpec, reusedMaps map[string]*ebpf.Map, info bpfTracingInfo) error {
	spec = spec.Copy()

	progSpec := spec.Programs[tracingFuncName]
	progSpec.AttachTarget = info.prog
	progSpec.AttachTo = info.funcName
	progSpec.AttachType = ebpf.AttachTraceFExit

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		MapReplacements: reusedMaps,
	})
	if err != nil {
		return fmt.Errorf("failed to create bpf collection for tracing: %w", err)
	}
	defer coll.Close()

	prog := coll.Programs[tracingFuncName]
	cloned, err := prog.Clone()
	if err != nil {
		return fmt.Errorf("failed to clone bpf program: %w", err)
	}

	l, err := link.AttachTracing(link.TracingOptions{
		Program:    cloned,
		AttachType: ebpf.AttachTraceFExit,
	})
	if err != nil {
		_ = cloned.Close()
		return fmt.Errorf("failed to attach tracing: %w", err)
	}

	if verbose {
		log.Printf("Tracing %s of prog %v", info.funcName, info.prog)
	}

	t.llock.Lock()
	t.progs = append(t.progs, cloned)
	t.links = append(t.links, l)
	t.llock.Unlock()

	return nil
}
