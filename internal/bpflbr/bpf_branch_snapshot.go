// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpflbr

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

func UpdateBranchSnapshot(prog *ebpf.ProgramSpec, feat *BPFFeatures) error {
	const bpfReadBranchSnapshot asm.BuiltinFunc = 212

	checkGetBranchSnapshot := false
	checkReadBranchSnapshot := false

	helperCallOp := asm.FnGetBranchSnapshot.Call().OpCode
	for i, insn := range prog.Instructions {
		if insn.OpCode != helperCallOp {
			continue
		}

		if insn.Constant == int64(bpfReadBranchSnapshot) {
			checkReadBranchSnapshot = true
			if feat.HasReadBranchSnapshot {
				continue
			} else {
				prog.Instructions[i] = asm.Mov.Imm(asm.R0, 0)
			}
			if checkGetBranchSnapshot {
				break
			}
		} else if insn.Constant == int64(asm.FnGetBranchSnapshot) {
			checkGetBranchSnapshot = true
			if !feat.HasReadBranchSnapshot {
				continue
			} else {
				prog.Instructions[i] = asm.Mov.Imm(asm.R0, 0)
			}
			if checkReadBranchSnapshot {
				break
			}
		}
	}

	return nil
}
