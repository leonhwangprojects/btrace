// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpflbr

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	flag "github.com/spf13/pflag"
)

const (
	progFlagDescriptorID     = "id"
	progFlagDescriptorPinned = "pinned"
	progFlagDescriptorTag    = "tag"
	progFlagDescriptorName   = "name"
)

var verbose bool

type ProgFlag struct {
	progID uint32
	pinned string
	tag    string
	name   string

	descriptor string
	funcName   string
}

func parseProgFlag(p string) (ProgFlag, error) {
	var pf ProgFlag

	id, funcName, ok := strings.Cut(p, ":")
	switch id {
	case "i", "id":
		id, funcName, ok = strings.Cut(funcName, ":")
		break

	case "p", "pinned":
		pf.descriptor = progFlagDescriptorPinned
		pf.pinned, pf.funcName, _ = strings.Cut(funcName, ":")
		if !fileExists(pf.pinned) {
			return pf, fmt.Errorf("pinned file %s does not exist", pf.pinned)
		}
		return pf, nil

	case "t", "tag":
		pf.descriptor = progFlagDescriptorTag
		pf.tag, pf.funcName, _ = strings.Cut(funcName, ":")
		if pf.tag == "" {
			return pf, errors.New("tag must not be empty")
		}
		return pf, nil

	case "n", "name":
		pf.descriptor = progFlagDescriptorName
		pf.name, pf.funcName, _ = strings.Cut(funcName, ":")
		if pf.name == "" {
			return pf, errors.New("name must not be empty")
		}
		return pf, nil

	default:
	}

	progID, err := strconv.ParseUint(id, 10, 32)
	if err != nil {
		return pf, fmt.Errorf("failed to parse progID %s from %s: %w", id, p, err)
	}

	pf.descriptor = progFlagDescriptorID
	pf.progID = uint32(progID)
	if ok {
		pf.funcName = funcName
	}

	return pf, nil
}

func parseProgsFlag(progs []string) ([]ProgFlag, error) {
	flags := make([]ProgFlag, 0, len(progs))
	for _, p := range progs {
		pf, err := parseProgFlag(p)
		if err != nil {
			return nil, err
		}

		flags = append(flags, pf)
	}

	return flags, nil
}

type Flags struct {
	progs []string

	outputFile string

	dumpProg bool
}

func ParseFlags() (*Flags, error) {
	var flags Flags

	f := flag.NewFlagSet("bpflbr", flag.ExitOnError)
	f.StringSliceVarP(&flags.progs, "prog", "p", nil, "bpf prog info for bpflbr in format PROG[,PROG,..], PROG: PROGID[:<prog function name>], PROGID: <prog ID> or 'i/id:<prog ID>' or 'p/pinned:<pinned file>' or 't/tag:<prog tag>' or 'n/name:<prog full name>'; all bpf progs will be traced by default")
	f.StringVarP(&flags.outputFile, "output", "o", "", "output file for the result, default is stdout")
	f.BoolVar(&flags.dumpProg, "dump-jited", false, "dump native insn info of bpf prog, the one bpf prog must be provided by --prog (its function name will be ignored)")
	f.BoolVarP(&verbose, "verbose", "v", false, "output verbose log")

	return &flags, f.Parse(os.Args)
}

func (f *Flags) ParseProgs() ([]ProgFlag, error) {
	return parseProgsFlag(f.progs)
}

func (f *Flags) OutputFile() string {
	return f.outputFile
}

func (f *Flags) DumpProg() bool {
	return f.dumpProg
}
