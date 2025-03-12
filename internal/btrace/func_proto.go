// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package btrace

import (
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"

	"github.com/cilium/ebpf/btf"
	"github.com/fatih/color"
	"github.com/leonhwangprojects/btrace/internal/assert"
	"github.com/leonhwangprojects/btrace/internal/btfx"
	"golang.org/x/exp/maps"
)

func showFuncProto(w io.Writer, fn *btf.Func) {
	clr := color.New(color.FgYellow)

	// func return
	retDesc := btfx.Repr(fn.Type.(*btf.FuncProto).Return)
	if retDesc[len(retDesc)-1] == '*' {
		clr.Fprintf(w, "%s", retDesc)
	} else {
		clr.Fprintf(w, "%s ", retDesc)
	}

	// func name
	clr.Fprint(w, fn.Name)

	// func params
	clr.Fprint(w, "(")
	params := fn.Type.(*btf.FuncProto).Params
	for i, p := range params {
		typDesc := btfx.Repr(p.Type)
		if p.Name != "" {
			if typDesc[len(typDesc)-1] == '*' {
				clr.Fprintf(w, "%s%s", typDesc, p.Name)
			} else {
				clr.Fprintf(w, "%s %s", typDesc, p.Name)
			}
		} else {
			clr.Fprintf(w, "%s", btfx.Repr(p.Type))
		}
		if i != len(params)-1 {
			clr.Fprint(w, ", ")
		}
	}
	clr.Fprint(w, ");\n")
}

func ShowFuncProto(f *Flags) {
	var sb strings.Builder

	haveProg := false
	if len(f.progs) != 0 {
		pflags, err := f.ParseProgs()
		assert.NoErr(err, "Failed to parse bpf prog flags: %v")

		progs, err := NewBPFProgs(pflags, true, true)
		if len(progs.tracings) != 0 {
			fmt.Fprint(&sb, "BPF functions:")
			color.New(color.FgGreen).Fprintf(&sb, " (total %d)\n", len(progs.tracings))

			keys := maps.Keys(progs.tracings)
			sort.Strings(keys)

			for _, k := range keys {
				showFuncProto(&sb, progs.tracings[k].fn)
			}

			haveProg = true
		}
	}

	if len(f.kfuncs) != 0 {
		kallsyms, err := NewKallsyms()
		assert.NoErr(err, "Failed to read /proc/kallsyms: %v")

		if haveProg {
			fmt.Fprintln(&sb)
		}

		kfuncs, err := findKernelFuncs(f.kfuncs, kallsyms, MAX_BPF_FUNC_ARGS, false, true)
		assert.NoErr(err, "Failed to find kernel functions: %v")

		fmt.Fprint(&sb, "Kernel functions:")
		color.New(color.FgGreen).Fprintf(&sb, " (total %d)\n", len(kfuncs))

		keys := maps.Keys(kfuncs)
		slices.Sort(keys)

		for _, k := range keys {
			showFuncProto(&sb, kfuncs[k].Func)
		}
	}

	fmt.Print(sb.String())
}
