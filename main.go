// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"github.com/Asphaltt/bpflbr/internal/assert"
	"github.com/Asphaltt/bpflbr/internal/bpflbr"
)

func main() {
	flags, err := bpflbr.ParseFlags()
	assert.NoErr(err, "Failed to parse flags: %v")

	progs, err := flags.ParseProgs()
	assert.NoErr(err, "Failed to parse bpf prog infos: %v")

	if flags.DumpProg() {
		dumpProg(progs)
	}
}

func dumpProg(progs []bpflbr.ProgFlag) {
	assert.SliceLen(progs, 1, "Only one prog ID is allowed for --dump-jited")

	pf := progs[0]
	bpflbr.DumpProg(pf)
}
