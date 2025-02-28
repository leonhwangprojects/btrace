package btrace

import (
	"debug/dwarf"
	"errors"
	"strings"
)

func getLineInfo(addr uintptr, progs *bpfProgs, a2l *Addr2Line, ksyms *Kallsyms) *branchEndpoint {
	if li, ok := progs.get(addr); ok {
		var ep branchEndpoint
		ep.addr = addr
		ep.offset = addr - li.ksymAddr
		ep.funcName = li.funcName
		ep.fileName = li.fileName
		ep.fileLine = li.fileLine
		ep.isProg = true
		ep.updateInfo()
		return &ep
	}

	var ep branchEndpoint
	ep.addr = addr
	defer ep.updateInfo()

	ksym, ok := ksyms.find(addr)
	if ok {
		ep.funcName = ksym.name
		ep.offset = addr - uintptr(ksym.addr)
	}

	if a2l == nil {
		return &ep
	}

	li, err := a2l.get(addr, ksym)
	if err != nil {
		if errors.Is(err, dwarf.ErrUnknownPC) {
			return &ep
		}
		if ksym != nil {
			VerboseLog("Failed to get addr2line for %s at %#x: %v", ksym.name, addr, err)
		} else {
			VerboseLog("Failed to get addr2line for %#x: %v", addr, err)
		}
		return &ep
	}

	fileName := li.File
	if strings.HasPrefix(fileName, a2l.buildDir) {
		fileName = fileName[len(a2l.buildDir):]
	}

	if ep.funcName == "" {
		ep.funcName = li.Func
	}

	ep.fileName = fileName
	ep.fileLine = uint32(li.Line)
	ep.fromVmlinux = true
	return &ep
}
