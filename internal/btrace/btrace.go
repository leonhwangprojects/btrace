// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package btrace

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/fatih/color"

	"github.com/leonhwangprojects/btrace/internal/btfx"
	"github.com/leonhwangprojects/btrace/internal/strx"
)

const (
	MAX_STACK_DEPTH = 50
)

type LbrEntry struct {
	From  uintptr
	To    uintptr
	Flags uint64
}

type LbrData struct {
	Entries [32]LbrEntry
	NrBytes int64
}

type FnData struct {
	Args [MAX_BPF_FUNC_ARGS][2]uint64 // raw data + pointed data
}

type StrData struct {
	Arg [32]byte
	Ret [32]byte
}

func (s *StrData) arg() string {
	return strx.NullTerminated(s.Arg[:])
}

func (s *StrData) ret() string {
	return strx.NullTerminated(s.Ret[:])
}

type Event struct {
	SessID  uint64
	Retval  int64
	FuncIP  uintptr
	CPU     uint32
	Pid     uint32
	Comm    [16]byte
	StackID int64
	Func    FnData
}

type FuncStack struct {
	IPs [MAX_STACK_DEPTH]uint64
}

func ptr2bytes(p unsafe.Pointer, size int) []byte {
	return unsafe.Slice((*byte)(p), size)
}

func Run(reader *ringbuf.Reader, progs *bpfProgs, addr2line *Addr2Line, ksyms *Kallsyms, kfuncs KFuncs, maps map[string]*ebpf.Map, w io.Writer) error {
	lbrStack := newLBRStack()
	funcStack := make([]string, 0, MAX_STACK_DEPTH)

	stacks := maps["btrace_stacks"]
	lbrs := maps["btrace_lbrs"]
	strs := maps["btrace_strs"]
	pkts := maps["btrace_pkts"]

	var lbrData LbrData
	var strData StrData
	var pktData PktData

	printRetval := mode == TracingModeExit
	colorOutput := !noColorOutput
	useLbr := outputLbr

	funcParamColors := []*color.Color{
		color.RGB(0x9d, 0x9d, 0x9d),
		color.RGB(0x7a, 0x7a, 0x7a),
		color.RGB(0x54, 0x54, 0x54),
		color.RGB(0x9c, 0x91, 0x91),
		color.RGB(0x7c, 0x74, 0x74),
		color.RGB(0x5c, 0x54, 0x54),
	}

	findSymbol := func(addr uint64) string {
		if prog, ok := progs.funcs[uintptr(addr)]; ok {
			return prog.funcName + "[bpf]"
		}

		return ksyms.findSymbol(addr)
	}

	var sb strings.Builder

	unlimited := limitEvents == 0
	for i := int64(limitEvents); unlimited || i > 0; i-- {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}

			return fmt.Errorf("failed to read ringbuf: %w", err)
		}

		if len(record.RawSample) < int(unsafe.Sizeof(Event{}))-int(unsafe.Sizeof(FnData{})) {
			continue
		}

		event := (*Event)(unsafe.Pointer(&record.RawSample[0]))
		if outputFuncStack && event.StackID >= 0 {
			funcStack, err = getFuncStack(event, progs, addr2line, ksyms, stacks, funcStack)
			if err != nil {
				return err
			}
		}

		hasPktTuple := false
		if outputPkt {
			b := ptr2bytes(unsafe.Pointer(&pktData), int(unsafe.Sizeof(pktData)))
			err := pkts.LookupAndDelete(event.SessID, b)
			if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				return fmt.Errorf("failed to lookup pkt data: %w", err)
			}

			hasPktTuple = !pktData.zero()
		}

		if useLbr {
			b := ptr2bytes(unsafe.Pointer(&lbrData), int(unsafe.Sizeof(lbrData)))
			err := lbrs.LookupAndDelete(event.SessID, b)
			if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				return fmt.Errorf("failed to lookup lbr data: %w", err)
			}
		}

		hasLbrEntries := useLbr && lbrData.NrBytes > 0 && lbrData.Entries[0] != (LbrEntry{})
		hasLbrEntries = hasLbrEntries && getLbrStack(event.FuncIP, &lbrData, progs, addr2line, ksyms, lbrStack)

		var targetName string
		var funcProto *btf.Func
		var funcParams []FuncParamFlags
		progInfo, isProg := progs.funcs[event.FuncIP]
		if isProg {
			targetName = progInfo.funcName + "[bpf]"
			funcProto = progInfo.funcProto
			funcParams = progInfo.funcParams
		} else {
			ksym, ok := ksyms.find(event.FuncIP)
			if ok {
				targetName = ksym.name
			} else {
				targetName = fmt.Sprintf("0x%x", event.FuncIP)
			}

			fn, ok := kfuncs[event.FuncIP]
			if ok {
				funcProto = fn.Func
				funcParams = fn.Prms
			}
		}

		useStrData := false
		for _, prm := range funcParams {
			useStrData = useStrData || prm.IsStr
		}
		if !useStrData && funcProto != nil && btfx.IsStr(funcProto.Type.(*btf.FuncProto).Return) {
			useStrData = true
		}
		if useStrData {
			b := ptr2bytes(unsafe.Pointer(&strData), int(unsafe.Sizeof(strData)))
			err := strs.LookupAndDelete(event.SessID, b)
			if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				return fmt.Errorf("failed to lookup str data: %w", err)
			}
		}

		if colorOutput {
			targetName = color.New(color.FgYellow, color.Bold).Sprint(targetName)
		}
		fmt.Fprint(&sb, targetName, " ")

		if colorOutput {
			color.New(color.FgBlue).Fprintf(&sb, "args")
		} else {
			fmt.Fprintf(&sb, "args")
		}
		fmt.Fprintf(&sb, "=(")
		if funcProto != nil {
			params := funcProto.Type.(*btf.FuncProto).Params
			lastIdx := len(params) - 1
			s := strData.arg()
			strUsed := false
			for i, fnParam := range funcParams {
				arg := event.Func.Args[i]

				if strUsed {
					s = ""
				}
				strUsed = strUsed || fnParam.IsStr

				fp := btfx.ReprFuncParam(&params[i], i, fnParam.IsStr, fnParam.IsNumberPtr, arg[0], arg[1], s, findSymbol)
				if colorOutput {
					funcParamColors[i].Fprint(&sb, fp)
				} else {
					fmt.Fprintf(&sb, "%s", fp)
				}

				if i != lastIdx {
					fmt.Fprintf(&sb, ", ")
				}
			}
		} else {
			fmt.Fprintf(&sb, "..UNK..")
		}
		fmt.Fprintf(&sb, ")")

		if printRetval {
			retval := fmt.Sprintf("%d/%#x", event.Retval, uint64(event.Retval))
			if funcProto != nil {
				rettyp := funcProto.Type.(*btf.FuncProto).Return
				retval = btfx.ReprFuncReturn(rettyp, event.Retval, strData.ret(), findSymbol)
			}
			if colorOutput {
				color.New(color.FgGreen).Fprintf(&sb, " retval")
				fmt.Fprint(&sb, "=")
				color.New(color.FgRed).Fprintf(&sb, "%s", retval)
			} else {
				fmt.Fprintf(&sb, " retval=%s", retval)
			}
		}

		if colorOutput {
			color.New(color.FgCyan).Fprintf(&sb, " cpu=%d", event.CPU)
			color.New(color.FgMagenta).Fprintf(&sb, " process=(%d:%s)", event.Pid, strx.NullTerminated(event.Comm[:]))
		} else {
			fmt.Fprintf(&sb, " cpu=%d process=(%d:%s)", event.CPU, event.Pid, strx.NullTerminated(event.Comm[:]))
		}
		fmt.Fprintln(&sb)

		if hasPktTuple {
			fmt.Fprint(&sb, "Pkt tuple: ")
			color.New(color.FgGreen).Fprintln(&sb, pktData.repr())
		}

		if hasLbrEntries {
			fmt.Fprintln(&sb, "LBR stack:")
			lbrStack.output(&sb)
		}
		hasFuncEntries := len(funcStack) > 0
		if hasFuncEntries {
			fmt.Fprintln(&sb, "Func stack:")
			for _, entry := range funcStack {
				fmt.Fprint(&sb, entry)
			}
		}
		fmt.Fprintln(w, sb.String())

		sb.Reset()
		lbrStack.reset()
		funcStack = funcStack[:0]
	}

	return ErrFinished
}

func getLbrStack(funcIP uintptr, lbrData *LbrData, progs *bpfProgs, addr2line *Addr2Line, ksyms *Kallsyms, stack *lbrStack) bool {
	progInfo, isProg := progs.funcs[funcIP]

	nrEntries := lbrData.NrBytes / int64(8*3)
	entries := lbrData.Entries[:nrEntries]
	if !verbose {
		if !isProg {
			for i := range entries {
				if ksym, ok := ksyms.find(entries[i].From); ok && ksym.addr == uint64(funcIP) {
					entries = entries[i:]
					break
				}
			}
		} else if mode == TracingModeExit {
			for i := range entries {
				if progInfo.contains(entries[i].From) || progInfo.contains(entries[i].To) {
					entries = entries[i:]
					break
				}
			}

			for i := len(entries) - 1; i >= 0; i-- {
				if progInfo.contains(entries[i].From) || progInfo.contains(entries[i].To) {
					entries = entries[:i+1]
					break
				}
			}
		} else {
			for i := range entries {
				if progInfo.contains(entries[i].From) {
					entries = entries[i:]
					break
				}
			}
		}

		if len(entries) == 0 {
			return false
		}
	}

	lbrEntries := make([]branchEntry, 0, len(entries))
	for _, entry := range entries {
		from := getLineInfo(entry.From, progs, addr2line, ksyms)
		to := getLineInfo(entry.To, progs, addr2line, ksyms)
		lbrEntries = append(lbrEntries, branchEntry{from, to})
	}

	last := len(lbrEntries) - 1
	stack.pushFirstEntry(lbrEntries[last])
	for i := last - 1; i >= 0; i-- {
		stack.pushEntry(lbrEntries[i])
	}

	return true
}

func getFuncStack(event *Event, progs *bpfProgs, addr2line *Addr2Line, ksym *Kallsyms, funcStacks *ebpf.Map, stack []string) ([]string, error) {
	id := uint32(event.StackID)

	var data FuncStack
	err := funcStacks.Lookup(id, &data)
	if err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return stack, nil
		}
		return stack, fmt.Errorf("failed to lookup func stack map: %w", err)
	}
	_ = funcStacks.Delete(id)

	ips := data.IPs[:]
	if !verbose {
		ips = ips[3:] // Skip the first 3 entries as they are entries for fentry/fexit and its trampoline.
	}
	for _, ip := range ips {
		if ip == 0 {
			continue
		}

		li := getLineInfo(uintptr(ip), progs, addr2line, ksym)

		var sb strings.Builder
		fmt.Fprint(&sb, "  ")
		if noColorOutput {
			if verbose {
				fmt.Fprintf(&sb, "0x%x:", ip)
			}
			fmt.Fprintf(&sb, "%-50s", fmt.Sprintf("%s+%#x", li.funcName, li.offset))
			if li.fileName != "" {
				fmt.Fprintf(&sb, "\t; %s:%d", li.fileName, li.fileLine)
			}
		} else {
			if verbose {
				color.New(color.FgBlue).Fprintf(&sb, "%#x", ip)
				fmt.Fprint(&sb, ":")
			}

			offset := fmt.Sprintf("+%#x", li.offset)
			color.RGB(0xE1, 0xD5, 0x77 /* light yellow */).Fprint(&sb, li.funcName)
			fmt.Fprintf(&sb, "%-*s", 50-len(li.funcName), offset)
			if li.fileName != "" {
				color.RGB(0x88, 0x88, 0x88 /* gray */).Fprintf(&sb, "\t; %s:%d", li.fileName, li.fileLine)
			}
		}

		fmt.Fprintln(&sb)

		stack = append(stack, sb.String())
	}

	return stack, nil
}
