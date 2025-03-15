// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package btrace

const (
	lbrConfigFlagOutputLbrIdx = 0 + iota
	lbrConfigFlagOutputStackIdx
	lbrConfigFlagOutputPktIdx
	lbrConfigFlagOutputArgIdx
	lbrConfigFlagIsRetStrIdx
)

type BtraceConfig struct {
	Flags     uint32
	FilterPid uint32
	FnArgs    [MAX_BPF_FUNC_ARGS]ParamFlags
	FnArgsNr  uint32
}

func (cfg *BtraceConfig) SetOutputLbr(v bool) {
	if v {
		cfg.Flags |= 1 << lbrConfigFlagOutputLbrIdx
	}
}

func (cfg *BtraceConfig) SetOutputStack(v bool) {
	if v {
		cfg.Flags |= 1 << lbrConfigFlagOutputStackIdx
	}
}

func (cfg *BtraceConfig) SetOutputPktTuple(v bool) {
	if v {
		cfg.Flags |= 1 << lbrConfigFlagOutputPktIdx
	}
}

func (cfg *BtraceConfig) SetOutputArgData(v bool) {
	if v {
		cfg.Flags |= 1 << lbrConfigFlagOutputArgIdx
	}
}

func (cfg *BtraceConfig) SetIsRetStr(v bool) {
	if v {
		cfg.Flags |= 1 << lbrConfigFlagIsRetStrIdx
	}
}
