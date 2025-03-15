// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package btrace

import (
	"fmt"
	"io"

	"github.com/fatih/color"

	"github.com/leonhwangprojects/btrace/internal/btfx"
	"github.com/leonhwangprojects/btrace/internal/strx"
)

const (
	maxOutputArgCnt = 4
	maxOutputStrLen = 32
)

type ArgData struct {
	Args [maxOutputArgCnt][2]uint64
	Str  [maxOutputStrLen]byte
}

func (a *ArgData) str() string {
	return strx.NullTerminated(a.Str[:])
}

func (a *ArgData) repr(w io.Writer, args []funcArgumentOutput, ksyms *Kallsyms) {
	idx := 0
	str := a.str()
	for i, arg := range args {
		if i != 0 {
			fmt.Fprint(w, ", ")
		}

		data := a.Args[idx]
		s := btfx.ReprValueType(arg.last, arg.t, arg.isStr, arg.isNumPtr, data[0], data[1], 0, str, ksyms.findSymbol)
		color.RGB(0x88, 0x88, 0x88 /* gray */).Fprint(w, s)

		if !arg.isStr {
			idx++
		}
	}
	fmt.Fprintln(w)
}
