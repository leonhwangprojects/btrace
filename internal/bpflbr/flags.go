// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpflbr

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	flag "github.com/spf13/pflag"
)

type ProgFlag struct {
	progID   uint32
	funcName string
}

func parseProgsFlag(progs []string) ([]ProgFlag, error) {
	flags := make([]ProgFlag, 0, len(progs))
	for _, p := range progs {
		id, funcName, ok := strings.Cut(p, ":")

		progID, err := strconv.ParseUint(id, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("failed to parse progID %s from %s: %v", id, p, err)
		}

		var pf ProgFlag
		pf.progID = uint32(progID)
		if ok {
			pf.funcName = funcName
		}
		flags = append(flags, pf)
	}

	return flags, nil
}

type Flags struct {
	progs []string

	dumpProg bool
}

func ParseFlags() (*Flags, error) {
	var flags Flags

	f := flag.NewFlagSet("bpflbr", flag.ExitOnError)
	f.StringSliceVarP(&flags.progs, "prog", "p", nil, "bpf prog info for bpflbr in format PROG[,PROG,..], PROG: <prog ID>[:<prog function name>]; all bpf progs will be traced by default")
	f.BoolVar(&flags.dumpProg, "dump-jited", false, "dump native insn info of bpf prog, the one prog ID must be provided by --prog (its function name will be ignored)")

	return &flags, f.Parse(os.Args)
}

func (f *Flags) ParseProgs() ([]ProgFlag, error) {
	return parseProgsFlag(f.progs)
}

func (f *Flags) DumpProg() bool {
	return f.dumpProg
}
