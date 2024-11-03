// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpflbr

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/knightsc/gapstone"
	"golang.org/x/exp/maps"
)

type bpfProgs struct {
	progs map[ebpf.ProgramID]*ebpf.Program
	infos map[ebpf.ProgramID]*bpfProgInfo

	ksyms map[uintptr]string

	tracings map[string]bpfTracingInfo // id:func -> prog, func
}

func NewBPFProgs(engine gapstone.Engine, pflags []ProgFlag, onlyPrepare bool) (*bpfProgs, error) {
	var progs bpfProgs
	progs.progs = make(map[ebpf.ProgramID]*ebpf.Program, len(pflags))
	progs.infos = make(map[ebpf.ProgramID]*bpfProgInfo, len(pflags))
	progs.tracings = make(map[string]bpfTracingInfo, len(pflags))
	progs.ksyms = make(map[uintptr]string)

	var err error
	defer func() {
		if err != nil {
			progs.Close()
		}
	}()

	err = progs.prepareProgInfos(pflags)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare BPF program infos: %w", err)
	}

	if onlyPrepare {
		return &progs, nil
	}

	for id, prog := range progs.progs {
		progs.infos[id], err = newBPFProgInfo(prog, engine)
		if err != nil {
			return nil, fmt.Errorf("failed to create BPF program info for ID(%d): %w", id, err)
		}

		info := progs.infos[id].progs[0]
		progs.ksyms[info.kaddrRange.start] = info.funcName
	}

	return &progs, nil
}

func (b *bpfProgs) Close() {
	for _, prog := range b.progs {
		_ = prog.Close()
	}
}

func (b *bpfProgs) Tracings() []bpfTracingInfo {
	return maps.Values(b.tracings)
}

func (b *bpfProgs) get(addr uintptr) (*bpfProgLineInfo, bool) {
	for _, info := range b.infos {
		if line, ok := info.get(addr); ok {
			return line, true
		}
	}

	return nil, false
}
