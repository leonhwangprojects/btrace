// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package btrace

import (
	"github.com/cilium/ebpf/btf"

	"github.com/leonhwangprojects/btrace/internal/btfx"
)

const (
	injectStubOutputArgData = "output_arg_data"
)

type funcArgumentOutput struct {
	expr string
	name string
	last string
	typ  btf.Type
}

func (arg *funcArgumentOutput) repr(data, data2 uint64, s string, ksyms *Kallsyms) string {
	return btfx.ReprParam(arg.last, arg.typ, data, data2, s, ksyms.findSymbol)
}
