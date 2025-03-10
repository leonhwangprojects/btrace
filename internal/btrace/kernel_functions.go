// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package btrace

import (
	"fmt"
	"log"
	"os"

	"github.com/cilium/ebpf/btf"

	"github.com/leonhwangprojects/btrace/internal/btfx"
)

const (
	MAX_BPF_FUNC_ARGS = 6
)

type FuncParamFlags struct {
	IsNumberPtr bool
	IsStr       bool
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

type KFuncs map[uintptr]KFunc

func FindKernelFuncs(funcs []string, ksyms *Kallsyms) (KFuncs, error) {
	if len(funcs) == 0 {
		return KFuncs{}, nil
	}

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

			ksym, ok := ksyms.n2s[fn.Name]
			if !ok {
				VerboseLog("Failed to find ksym for %s", fn.Name)
				continue
			}
			if ksym.duped {
				VerboseLog("Skip multiple-addrs ksym %s", fn.Name)
				continue
			}

			if len(funcProto.Params) <= MAX_BPF_FUNC_ARGS {
				kf := KFunc{Ksym: ksym, Func: fn}
				kf.Prms = getFuncParams(fn)
				kf.IsRetStr = btfx.IsStr(funcProto.Return)
				kfuncs[uintptr(ksym.addr)] = kf
			} else if verbose {
				log.Printf("Skip function %s with %d args because of limit %d args\n",
					fn.Name, len(funcProto.Params), MAX_BPF_FUNC_ARGS)
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
