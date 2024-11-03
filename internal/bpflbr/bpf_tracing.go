// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpflbr

import (
	"fmt"
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
	links []link.Link
}

func newBPFTracing(spec *ebpf.CollectionSpec, reusedMaps map[string]*ebpf.Map, infos []bpfTracingInfo) error {
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
		t.close()
		return fmt.Errorf("failed to trace bpf progs: %w", err)
	}

	return nil
}

func (t *bpfTracing) close() {
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
	l, err := link.AttachTracing(link.TracingOptions{
		Program:    prog,
		AttachType: ebpf.AttachTraceFExit,
	})
	if err != nil {
		return fmt.Errorf("failed to attach tracing: %w", err)
	}

	t.llock.Lock()
	t.links = append(t.links, l)
	t.llock.Unlock()

	return nil
}
