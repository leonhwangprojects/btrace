// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package btrace

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"

	"github.com/leonhwangprojects/btrace/internal/btfx"
)

type bpfTracingInfo struct {
	prog     *ebpf.Program
	fn       *btf.Func
	funcName string
	params   []FuncParamFlags
}

func getFuncParams(fn *btf.Func) ([]FuncParamFlags, error) {
	strUsed := false // Only one string is allowed
	fnParams := fn.Type.(*btf.FuncProto).Params
	params := make([]FuncParamFlags, 0, len(fnParams))
	for _, p := range fnParams {
		v := btfx.IsStr(p.Type)
		isStr := v && !strUsed
		strUsed = strUsed || v

		size, err := btf.Sizeof(p.Type)
		if err != nil {
			return nil, fmt.Errorf("failed to get size of type %v: %w", p.Type, err)
		}

		if size > 16 {
			return nil, fmt.Errorf("size of type %v is too large: %d", p.Type, size)
		}
		if size > 8 {
			// struct arg occupies 2 regs
			params = append(params,
				FuncParamFlags{},
				FuncParamFlags{
					partOfPrevParam: true,
				})
			continue
		}

		params = append(params, FuncParamFlags{
			ParamFlags: ParamFlags{
				IsNumberPtr: btfx.IsNumberPointer(p.Type),
				IsStr:       isStr,
			},
		})
	}
	return params, nil
}

func getProgFunc(info *ebpf.ProgramInfo, funcName string) (*btf.Func, error) {
	fns, err := info.FuncInfos()
	if err != nil {
		return nil, fmt.Errorf("failed to get func infos: %w", err)
	}

	for _, fn := range fns {
		if fn.Func.Name == funcName {
			return fn.Func, nil
		}
	}

	return nil, fmt.Errorf("failed to find func %s", funcName)
}

func (p *bpfProgs) addTracing(id ebpf.ProgramID, funcName string, prog *ebpf.Program) error {
	if prog.Type() == ebpf.Tracing && !p.disasm {
		return nil
	}

	key := fmt.Sprintf("%d:%s", id, funcName)
	if _, ok := p.tracings[key]; ok {
		return nil
	}

	if prev, ok := p.progs[id]; ok {
		fn, err := getProgFunc(p.infos[id], funcName)
		if err != nil {
			return fmt.Errorf("failed to get func for %s: %w", funcName, err)
		}

		params, err := getFuncParams(fn)
		if err != nil {
			return fmt.Errorf("failed to get func params for %s: %w", funcName, err)
		}

		p.tracings[key] = bpfTracingInfo{
			prog:     prev,
			fn:       fn,
			funcName: funcName,
			params:   params,
		}

		return nil
	}

	cloned, err := prog.Clone()
	if err != nil {
		return fmt.Errorf("failed to clone prog %d: %w", id, err)
	}

	info, err := prog.Info()
	if err != nil {
		return fmt.Errorf("failed to get prog info for %d: %w", id, err)
	}

	fn, err := getProgFunc(info, funcName)
	if err != nil {
		return fmt.Errorf("failed to get func for %s: %w", funcName, err)
	}

	params, err := getFuncParams(fn)
	if err != nil {
		return fmt.Errorf("failed to get func params for %s: %w", funcName, err)
	}

	p.progs[id] = cloned
	p.infos[id] = info
	p.tracings[key] = bpfTracingInfo{
		prog:     cloned,
		fn:       fn,
		funcName: funcName,
		params:   params,
	}

	return nil
}
