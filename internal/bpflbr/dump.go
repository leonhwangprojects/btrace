// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpflbr

import (
	"fmt"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/knightsc/gapstone"

	"github.com/Asphaltt/bpflbr/internal/assert"
)

func DumpProg(pf ProgFlag) {
	prog, err := ebpf.NewProgramFromID(ebpf.ProgramID(pf.progID))
	assert.NoErr(err, "Failed to load prog %d: %v", pf.progID)
	defer prog.Close()

	info, err := prog.Info()
	assert.NoErr(err, "Failed to get prog info: %v", err)

	jitedInsns, _ := info.JitedInsns()
	jitedKsyms, _ := info.KsymAddrs()
	jitedFuncLens, _ := info.JitedFuncLens()
	jitedLineInfos, _ := info.JitedLineInfos()
	assert.SliceNotEmpty(jitedInsns, "No jited insns")
	assert.Equal(len(jitedFuncLens), len(jitedKsyms), "Func len number %d != ksym number %d", len(jitedFuncLens), len(jitedKsyms))

	// jitedFuncLens are the insns length of each function.
	// Then, jitedInsns can be split into len(jitedFuncLens) functions with each function having jitedFuncLens[i] insns.

	li, err := info.LineInfos()
	assert.NoErr(err, "Failed to get line infos: %v")

	lines := li.Lines()
	assert.Equal(len(lines), len(jitedLineInfos), "Line info mismatch: %d != %d (jited)", len(lines), len(jitedLineInfos))

	// Each jitedLineInfo is corresponding to a lineInfo.

	// jitedLineInfos are kernel addresses.
	// jitedKsyms are ksyms for funcs.
	//
	// ksym addr + insn offset = jited line info addr.
	// jited line info addr => line info.

	jited2LineInfos := make(map[uint64]btf.LineInfo, len(jitedLineInfos))
	for i, kaddr := range jitedLineInfos {
		jited2LineInfos[kaddr] = lines[i]
	}

	engine, err := gapstone.New(int(gapstone.CS_ARCH_X86), int(gapstone.CS_MODE_64))
	assert.NoErr(err, "Failed to create engine: %v")
	defer engine.Close()

	intelSyntax := os.Getenv("BPFLBR_DUMP_INTEL_SYNTAX") == "1"
	if !intelSyntax {
		err = engine.SetOption(uint(gapstone.CS_OPT_SYNTAX), uint(gapstone.CS_OPT_SYNTAX_ATT))
		assert.NoErr(err, "Failed to set syntax: %v")
	}

	var sb strings.Builder

	insns := jitedInsns
	for i, funcLen := range jitedFuncLens {
		ksym := uint64(jitedKsyms[i])
		fnInsns := insns[:funcLen]
		pc := uint64(0)

		for len(fnInsns) > 0 {
			kaddr := ksym + pc
			if li, ok := jited2LineInfos[kaddr]; ok {
				fmt.Fprintf(&sb, "; %s:%d:%d %s\n",
					li.Line.FileName(), li.Line.LineNumber(), li.Line.LineColumn(),
					strings.TrimSpace(li.Line.Line()))
			}

			inst, err := engine.Disasm(fnInsns, kaddr, 1)
			assert.NoErr(err, "Failed to disasm instruction: %v", err)

			var opcodes []string
			for _, insn := range inst[0].Bytes {
				opcodes = append(opcodes, fmt.Sprintf("%02x", insn))
			}
			opcode := strings.Join(opcodes, " ")
			fmt.Fprintf(&sb, "%#x: %-19s\t%s\t%s\n", kaddr, opcode, inst[0].Mnemonic, inst[0].OpStr)

			insnSize := uint64(inst[0].Size)
			pc += insnSize
			fnInsns = fnInsns[insnSize:]
		}

		fmt.Fprintln(&sb)

		insns = insns[funcLen:]
	}

	fmt.Print(sb.String())
}
