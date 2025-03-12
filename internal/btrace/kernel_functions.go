// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package btrace

import (
	"fmt"
	"os"

	"github.com/Asphaltt/mybtf"
	"github.com/cilium/ebpf/btf"

	"github.com/leonhwangprojects/btrace/internal/btfx"
)

const (
	MAX_BPF_FUNC_ARGS      = 12
	MAX_BPF_FUNC_ARGS_PREV = 6
)

type ParamFlags struct {
	IsNumberPtr bool
	IsStr       bool
}
type FuncParamFlags struct {
	ParamFlags
	partOfPrevParam bool
}

type KFunc struct {
	Ksym     *KsymEntry
	Func     *btf.Func
	Prms     []FuncParamFlags
	IsRetStr bool
}

func (k KFunc) Name() string {
	return k.Func.Name
}

func isValistParam(p btf.FuncParam) bool {
	_, isVoid := p.Type.(*btf.Void)
	return p.Name == "" && isVoid
}

type KFuncs map[uintptr]KFunc

func findKernelFuncs(funcs []string, ksyms *Kallsyms, maxArgs int, findManyArgs, silent bool) (KFuncs, error) {
	matches, err := kfuncFlags2matches(funcs)
	if err != nil {
		return KFuncs{}, err
	}

	kfuncs := make(KFuncs, len(funcs))

	iterBtfSpec := func(spec *btf.Spec) {
		iter := spec.Iterate()
		for iter.Next() {
			fn, ok := iter.Type.(*btf.Func)
			if !ok {
				continue
			}

			funcProto := fn.Type.(*btf.FuncProto)
			if !matchKfunc(fn.Name, funcProto, matches) {
				continue
			}

			if isValist := len(funcProto.Params) != 0 && isValistParam(funcProto.Params[len(funcProto.Params)-1]); isValist {
				verboseLogIf(!silent, "Skip function %s with variable args", fn.Name)
				continue
			}

			if _, isStruct := mybtf.UnderlyingType(funcProto.Return).(*btf.Struct); isStruct {
				verboseLogIf(!silent, "Skip function %s with struct return type", fn.Name)
				continue
			}

			ksym, ok := ksyms.n2s[fn.Name]
			if !ok {
				verboseLogIf(!silent, "Failed to find ksym for %s", fn.Name)
				continue
			}
			if ksym.duped {
				verboseLogIf(!silent, "Skip multiple-addrs ksym %s", fn.Name)
				continue
			}

			params, err := getFuncParams(fn)
			if err != nil {
				verboseLogIf(!silent, "Failed to get params for %s: %v", fn.Name, err)
				continue
			}

			if findManyArgs {
				if MAX_BPF_FUNC_ARGS_PREV < len(funcProto.Params) && len(funcProto.Params) <= MAX_BPF_FUNC_ARGS {
					kf := KFunc{Ksym: ksym, Func: fn}
					kf.Prms = params
					kf.IsRetStr = btfx.IsStr(funcProto.Return)
					kfuncs[uintptr(ksym.addr)] = kf
				}
				continue
			}

			if len(funcProto.Params) <= maxArgs {
				kf := KFunc{Ksym: ksym, Func: fn}
				kf.Prms = params
				kf.IsRetStr = btfx.IsStr(funcProto.Return)
				kfuncs[uintptr(ksym.addr)] = kf
			} else {
				verboseLogIf(!silent, "Skip function %s with %d args because of limit %d args\n",
					fn.Name, len(funcProto.Params), maxArgs)
			}
		}
	}

	if kfuncAllKmods {
		files, err := os.ReadDir("/sys/kernel/btf")
		if err != nil {
			return nil, fmt.Errorf("failed to read /sys/kernel/btf: %w", err)
		}

		for _, file := range files {
			kmodBtf, err := btf.LoadKernelModuleSpec(file.Name())
			if err != nil {
				return nil, fmt.Errorf("failed to load kernel module BTF: %w", err)
			}

			iterBtfSpec(kmodBtf)
		}
	} else {
		kernelBtf, err := btf.LoadKernelSpec()
		if err != nil {
			return nil, fmt.Errorf("failed to load kernel BTF: %w", err)
		}

		iterBtfSpec(kernelBtf)
	}

	if len(kfuncs) == 0 {
		return nil, fmt.Errorf("no functions found for %v", funcs)
	}

	return kfuncs, nil
}

func FindKernelFuncs(funcs []string, ksyms *Kallsyms, maxArgs int) (KFuncs, error) {
	if len(funcs) == 0 {
		return KFuncs{}, nil
	}

	return findKernelFuncs(funcs, ksyms, maxArgs, false, false)
}
