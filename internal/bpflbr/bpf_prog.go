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
		if err := progs.addProg(prog, id, engine); err != nil {
			return nil, err
		}
	}

	return &progs, nil
}

func (b *bpfProgs) addProg(prog *ebpf.Program, id ebpf.ProgramID, engine gapstone.Engine) error {
	var err error
	b.infos[id], err = newBPFProgInfo(prog, engine)
	if err != nil {
		return fmt.Errorf("failed to create BPF program info for ID(%d): %w", id, err)
	}

	info := b.infos[id].progs[0]
	b.ksyms[info.kaddrRange.start] = info.funcName

	return nil
}

func (b *bpfProgs) AddProgs(progs []*ebpf.Program, engine gapstone.Engine) error {
	for _, prog := range progs {
		info, err := prog.Info()
		if err != nil {
			return fmt.Errorf("failed to get prog info: %w", err)
		}

		id, ok := info.ID()
		if !ok {
			return fmt.Errorf("failed to get prog ID")
		}

		err = b.addProg(prog, id, engine)
		if err != nil {
			return fmt.Errorf("failed to add BPF program: %w", err)
		}
	}

	return nil
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
