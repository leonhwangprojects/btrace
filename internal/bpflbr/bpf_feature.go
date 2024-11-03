// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpflbr

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type BPFFeatures struct {
	KprobeHappened    bool
	HasRingbuf        bool
	HasBranchSnapshot bool
	HasFuncRet        bool
	HasFuncIP         bool
}

func DetectBPFFeatures(spec *ebpf.CollectionSpec) error {
	mapSpec := spec.Maps[".bss"]
	if mapSpec == nil {
		return errors.New("missing .bss map")
	}

	bss, err := ebpf.NewMap(mapSpec)
	if err != nil {
		return fmt.Errorf("failed to create .bss map: %w", err)
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			".bss": bss,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to create bpf collection: %w", err)
	}
	defer coll.Close()

	prog := coll.Programs["detect"]
	l, err := link.AttachTracing(link.TracingOptions{
		Program:    prog,
		AttachType: ebpf.AttachTraceFEntry,
	})
	defer l.Close()

	nanosleep()

	var feat BPFFeatures
	if err := bss.Lookup(uint32(0), &feat); err != nil {
		return fmt.Errorf("failed to lookup .bss: %w", err)
	}

	if !feat.KprobeHappened {
		return errors.New("detection not happened")
	}

	if !feat.HasRingbuf {
		return errors.New("ringbuf map not supported")
	}

	if !feat.HasBranchSnapshot {
		return errors.New("bpf_get_branch_snapshot() helper not supported")
	}

	if !feat.HasFuncRet {
		return errors.New("bpf_get_func_ret() helper not supported")
	}

	if !feat.HasFuncIP {
		return errors.New("bpf_get_func_ip() helper not supported")
	}

	return nil
}
