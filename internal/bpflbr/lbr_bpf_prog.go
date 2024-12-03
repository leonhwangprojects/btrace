// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpflbr

const (
	lbrConfigFlagSuppressLbrIdx = 0 + iota
)

type LbrConfig struct {
	Flags uint32
}

func (cfg *LbrConfig) SetSuppressLbr(v bool) {
	if v {
		cfg.Flags |= 1 << lbrConfigFlagSuppressLbrIdx
	}
}
