// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpflbr

import (
	"errors"
	"fmt"
	"log"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
)

type bpfTracing struct {
	llock sync.Mutex
	progs []*ebpf.Program
	links []link.Link
	klnks []link.Link
}

func (t *bpfTracing) Progs() []*ebpf.Program {
	return t.progs
}

func NewBPFTracing(spec *ebpf.CollectionSpec, reusedMaps map[string]*ebpf.Map, infos []bpfTracingInfo, kfuncs []string, feat *BPFFeatures) (*bpfTracing, error) {
	var cfg LbrConfig
	cfg.SetSuppressLbr(suppressLbr)
	cfg.SetOutputStack(outputFuncStack)
	cfg.SetReadBranchSnapshot(feat.HasReadBranchSnapshot)
	cfg.FilterPid = uint32(filterPid)

	if err := spec.Variables["lbr_config"].Set(cfg); err != nil {
		return nil, fmt.Errorf("failed to set lbr config: %w", err)
	}

	var t bpfTracing
	t.links = make([]link.Link, 0, len(infos))

	var errg errgroup.Group

	for _, info := range infos {
		info := info
		errg.Go(func() error {
			return t.traceProg(spec, reusedMaps, info)
		})
	}

	for _, fn := range kfuncs {
		fn := fn
		errg.Go(func() error {
			return t.traceFunc(spec, reusedMaps, fn)
		})
	}

	if err := errg.Wait(); err != nil {
		t.Close()
		return nil, fmt.Errorf("failed to trace bpf progs: %w", err)
	}

	return &t, nil
}

func (t *bpfTracing) HaveTracing() bool {
	t.llock.Lock()
	defer t.llock.Unlock()

	return len(t.links) > 0 || len(t.klnks) > 0
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

	errg.Go(func() error {
		for _, l := range t.klnks {
			_ = l.Close()
		}
		return nil
	})

	_ = errg.Wait()
}

func TracingProgName(mode string) string {
	return fmt.Sprintf("f%s_fn", mode)
}

func (t *bpfTracing) traceProg(spec *ebpf.CollectionSpec, reusedMaps map[string]*ebpf.Map, info bpfTracingInfo) error {
	spec = spec.Copy()

	attachType := ebpf.AttachTraceFExit
	if mode == TracingModeEntry {
		attachType = ebpf.AttachTraceFEntry
	}

	tracingFuncName := TracingProgName(mode)
	progSpec := spec.Programs[tracingFuncName]
	progSpec.AttachTarget = info.prog
	progSpec.AttachTo = info.funcName
	progSpec.AttachType = attachType

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		MapReplacements: reusedMaps,
	})
	if err != nil {
		return fmt.Errorf("failed to create bpf collection for tracing: %w", err)
	}
	defer coll.Close()

	prog := coll.Programs[tracingFuncName]
	delete(coll.Programs, tracingFuncName)

	l, err := link.AttachTracing(link.TracingOptions{
		Program:    prog,
		AttachType: attachType,
	})
	if err != nil {
		_ = prog.Close()
		return fmt.Errorf("failed to attach tracing: %w", err)
	}

	if verbose {
		log.Printf("Tracing %s of prog %v", info.funcName, info.prog)
	}

	t.llock.Lock()
	t.progs = append(t.progs, prog)
	t.links = append(t.links, l)
	t.llock.Unlock()

	return nil
}

func (t *bpfTracing) traceFunc(spec *ebpf.CollectionSpec, reusedMaps map[string]*ebpf.Map, fn string) error {
	spec = spec.Copy()

	attachType := ebpf.AttachTraceFExit
	if mode == TracingModeEntry {
		attachType = ebpf.AttachTraceFEntry
	}

	tracingFuncName := TracingProgName(mode)
	progSpec := spec.Programs[tracingFuncName]
	progSpec.AttachTo = fn
	progSpec.AttachType = attachType

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		MapReplacements: reusedMaps,
	})
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return fmt.Errorf("failed to create bpf collection for tracing: %w", err)
	}
	defer coll.Close()

	prog := coll.Programs[tracingFuncName]
	delete(coll.Programs, tracingFuncName)
	l, err := link.AttachTracing(link.TracingOptions{
		Program:    prog,
		AttachType: attachType,
	})
	if err != nil {
		_ = prog.Close()
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.EINVAL) {
			return nil
		}
		if errors.Is(err, unix.EBUSY) {
			if verbose {
				log.Printf("Cannot trace kernel function %s", fn)
			}
			return nil
		}
		return fmt.Errorf("failed to attach tracing: %w", err)
	}

	if verbose {
		log.Printf("Tracing kernel function %s", fn)
	}

	t.llock.Lock()
	t.progs = append(t.progs, prog)
	t.klnks = append(t.klnks, l)
	t.llock.Unlock()

	return nil
}
