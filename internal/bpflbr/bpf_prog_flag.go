// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpflbr

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
)

type progFlags struct {
	empty       bool
	ids         map[uint32]string
	tags        map[string]string
	names       map[string]string
	pinnedPaths map[string]string
}

func newProgFlags(pflags []ProgFlag) progFlags {
	var pf progFlags
	pf.empty = len(pflags) == 0
	pf.ids = make(map[uint32]string)
	pf.tags = make(map[string]string)
	pf.names = make(map[string]string)
	pf.pinnedPaths = make(map[string]string)

	for _, f := range pflags {
		switch f.descriptor {
		case progFlagDescriptorID:
			pf.ids[f.progID] = f.funcName

		case progFlagDescriptorTag:
			pf.tags[f.tag] = f.funcName

		case progFlagDescriptorName:
			pf.names[f.name] = f.funcName

		case progFlagDescriptorPinned:
			pf.pinnedPaths[f.pinned] = f.funcName
		}
	}

	return pf
}

func (p progFlags) allID() bool {
	return len(p.ids) != 0 &&
		len(p.tags) == 0 &&
		len(p.names) == 0 &&
		len(p.pinnedPaths) == 0
}

func (p *bpfProgs) prepareProgInfoByID(id ebpf.ProgramID, funcName string) error {
	prog, err := ebpf.NewProgramFromID(id)
	if err != nil {
		return fmt.Errorf("failed to load prog %d: %w", id, err)
	}
	defer prog.Close()

	if funcName == "" {
		info, err := prog.Info()
		if err != nil {
			return fmt.Errorf("failed to get prog info: %w", err)
		}

		funcName, err = getProgEntryFuncName(info)
		if err != nil {
			return fmt.Errorf("failed to get prog entry func name: %w", err)
		}
	}

	return p.addTracing(id, funcName, prog)
}

func (p *bpfProgs) prepareProgInfosByIDs(pflags []ProgFlag) error {
	for i := range pflags {
		id := ebpf.ProgramID(pflags[i].progID)
		funcName := pflags[i].funcName
		if err := p.prepareProgInfoByID(id, funcName); err != nil {
			return err
		}
	}

	return nil
}

func (p *bpfProgs) prepareProgInfoByPinnedPath(pflag ProgFlag) error {
	prog, err := ebpf.LoadPinnedProgram(pflag.pinned, nil)
	if err != nil {
		return fmt.Errorf("failed to load pinned prog %s: %w", pflag.pinned, err)
	}
	defer prog.Close()

	info, err := prog.Info()
	if err != nil {
		return fmt.Errorf("failed to get prog info of prog %s: %w", pflag.pinned, err)
	}

	funcName, err := getProgFuncName(pflag.funcName, info)
	if err != nil {
		return fmt.Errorf("failed to get prog func name: %w", err)
	}

	id, ok := info.ID()
	if !ok {
		return fmt.Errorf("failed to get prog ID")
	}

	return p.addTracing(id, funcName, prog)
}

func (p *bpfProgs) prepareProgInfo(progID ebpf.ProgramID, pflags progFlags) error {
	prog, err := ebpf.NewProgramFromID(progID)
	if err != nil {
		return fmt.Errorf("failed to load prog %d: %w", progID, err)
	}
	defer prog.Close()

	info, err := prog.Info()
	if err != nil {
		return fmt.Errorf("failed to get prog info: %w", err)
	}

	if _, ok := info.BTFID(); !ok {
		// Skip non-BTF programs.
		return nil
	}

	entryFuncName, err := getProgEntryFuncName(info)
	if err != nil {
		return fmt.Errorf("failed to get prog entry func name: %w", err)
	}

	if pflags.empty {
		return p.addTracing(progID, entryFuncName, prog)
	}

	tag := info.Tag

	if funcName, ok := pflags.ids[uint32(progID)]; ok {
		if funcName == "" {
			funcName = entryFuncName
		}
		if err := p.addTracing(progID, funcName, prog); err != nil {
			return err
		}
	}

	if funcName, ok := pflags.tags[tag]; ok {
		if funcName == "" {
			funcName = entryFuncName
		}
		if err := p.addTracing(progID, funcName, prog); err != nil {
			return err
		}
	}

	if funcName, ok := pflags.names[entryFuncName]; ok {
		if funcName == "" {
			funcName = entryFuncName
		}
		if err := p.addTracing(progID, funcName, prog); err != nil {
			return err
		}
	}

	return nil
}

func (p *bpfProgs) prepareProgInfos(pflags []ProgFlag) error {
	flags := newProgFlags(pflags)
	if flags.allID() {
		return p.prepareProgInfosByIDs(pflags)
	}

	for _, f := range pflags {
		if f.descriptor == progFlagDescriptorPinned {
			if err := p.prepareProgInfoByPinnedPath(f); err != nil {
				return err
			}
		}
	}

	for progID, err := ebpf.ProgramGetNextID(0); err == nil; progID, err = ebpf.ProgramGetNextID(progID) {
		if err := p.prepareProgInfo(progID, flags); err != nil {
			return err
		}
	}

	return nil
}

func getProgFuncName(funcName string, info *ebpf.ProgramInfo) (string, error) {
	if funcName != "" {
		return funcName, nil
	}

	return getProgEntryFuncName(info)
}

// getProgEntryFuncName returns the name of the entry function in the program.
func getProgEntryFuncName(info *ebpf.ProgramInfo) (string, error) {
	if _, ok := info.BTFID(); !ok {
		return "", errors.New("program does not have BTF ID")
	}

	insns, err := info.Instructions()
	if err != nil {
		return "", fmt.Errorf("failed to get program instructions: %w", err)
	}

	if sym := insns[0].Symbol(); sym != "" {
		return sym, nil
	}

	return "", errors.New("no entry func name found in program")
}
