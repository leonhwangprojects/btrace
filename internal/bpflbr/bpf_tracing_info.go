// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpflbr

import (
	"fmt"

	"github.com/cilium/ebpf"
)

type bpfTracingInfo struct {
	prog     *ebpf.Program
	funcName string
}

func (p *bpfProgs) addTracing(id ebpf.ProgramID, funcName string, prog *ebpf.Program) error {
	key := fmt.Sprintf("%d:%s", id, funcName)
	if _, ok := p.tracings[key]; ok {
		return nil
	}

	if prev, ok := p.progs[id]; ok {
		p.tracings[key] = bpfTracingInfo{
			prog:     prev,
			funcName: funcName,
		}

		return nil
	}

	cloned, err := prog.Clone()
	if err != nil {
		return fmt.Errorf("failed to clone prog %d: %w", id, err)
	}

	p.progs[id] = cloned
	p.tracings[key] = bpfTracingInfo{
		prog:     cloned,
		funcName: funcName,
	}

	return nil
}
