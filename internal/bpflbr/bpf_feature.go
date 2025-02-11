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
	KprobeHappened        bool
	HasRingbuf            bool
	HasBranchSnapshot     bool
	HasFuncRet            bool
	HasFuncIP             bool
	HasGetStackID         bool
	HasReadBranchSnapshot bool
}

func DetectBPFFeatures(spec *ebpf.CollectionSpec) (*BPFFeatures, error) {
	mapSpec := spec.Maps[".bss"]
	if mapSpec == nil {
		return nil, errors.New("missing .bss map")
	}

	bss, err := ebpf.NewMap(mapSpec)
	if err != nil {
		return nil, fmt.Errorf("failed to create .bss map: %w", err)
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			".bss": bss,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create bpf collection: %w", err)
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
		return nil, fmt.Errorf("failed to lookup .bss: %w", err)
	}

	if !feat.KprobeHappened {
		return nil, errors.New("detection not happened")
	}

	if !feat.HasRingbuf {
		return nil, errors.New("ringbuf map not supported")
	}

	if !feat.HasBranchSnapshot {
		return nil, errors.New("bpf_get_branch_snapshot() helper not supported")
	}

	if !feat.HasFuncRet {
		return nil, errors.New("bpf_get_func_ret() helper not supported")
	}

	if !feat.HasFuncIP {
		return nil, errors.New("bpf_get_func_ip() helper not supported")
	}

	if outputFuncStack && !feat.HasGetStackID {
		return nil, errors.New("bpf_get_stackid() helper not supported for --output-stack")
	}

	return &feat, nil
}
