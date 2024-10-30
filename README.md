<!--
 Copyright 2024 Leon Hwang.
 SPDX-License-Identifier: Apache-2.0
-->

# bpflbr: an eBPF enhanced tool to trace some details of bpf prog with LBR

Here're some references to learn about LBR:

- [An introduction to last branch records](https://lwn.net/Articles/680985/).
- [Advanced usage of last branch records](https://lwn.net/Articles/680996/).
- [How to configure LBR (Last Branch Record) on Intel CPUs](https://sorami-chi.hateblo.jp/entry/2017/12/17/230000).
- [Intel® 64 and IA-32 Architectures Software Developer Manuals](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html).

## bpflbr PoC

```bash
# ./bpflbr -p 850
Recv a record for kprobe_skb_1: retval=0 nr_bytes=768
[#31] rethook_trampoline_handler+0xaf       (kernel/trace/rethook.c:331)           -> arch_rethook_fixup_return+0x0         (arch/x86/kernel/rethook.c:113)
      arch_rethook_fixup_return+0xb         (arch/x86/kernel/rethook.c:114)        -> rethook_trampoline_handler+0xb4       (kernel/trace/rethook.c:335)
      rethook_trampoline_handler+0xe3       (kernel/trace/rethook.c:341)           -> rethook_recycle+0x0                   (kernel/trace/rethook.c:153)
      rethook_recycle+0x18                  (arch/x86/include/asm/atomic.h:97)     -> rethook_recycle+0x29                  (include/linux/freelist.h:70)
      rethook_recycle+0x40                  (include/linux/freelist.h:52)          -> rethook_recycle+0x1a                  (include/linux/freelist.h:70)
      rethook_recycle+0x24                  (include/linux/freelist.h:70)          -> rethook_trampoline_handler+0xe8       (kernel/trace/rethook.c:338)
      rethook_trampoline_handler+0x102      (kernel/trace/rethook.c:346)           -> arch_rethook_trampoline_callback+0x3a (arch/x86/kernel/rethook.c:92)
      arch_rethook_trampoline_callback+0x53 (arch/x86/kernel/rethook.c:93)         -> arch_rethook_trampoline+0x31
      arch_rethook_trampoline+0x51                                                 -> __x64_sys_bpf+0x1a                    (kernel/bpf/syscall.c:5530)
      __x64_sys_bpf+0x25                    (kernel/bpf/syscall.c:5530)            -> arch_rethook_trampoline+0x0
      arch_rethook_trampoline+0x2c                                                 -> arch_rethook_trampoline_callback+0x0  (arch/x86/kernel/rethook.c:68)
      arch_rethook_trampoline_callback+0x35 (arch/x86/kernel/rethook.c:86)         -> rethook_trampoline_handler+0x0        (kernel/trace/rethook.c:291)
      rethook_trampoline_handler+0x33       (kernel/trace/rethook.c:228)           -> rethook_trampoline_handler+0x41       (kernel/trace/rethook.c:228)
      rethook_trampoline_handler+0x6d       (kernel/trace/rethook.c:316)           -> rethook_trampoline_handler+0xa0       (kernel/trace/rethook.c:318)
      rethook_trampoline_handler+0xa5       (kernel/trace/rethook.c:318)           -> rethook_trampoline_handler+0x71       (kernel/trace/rethook.c:320)
      rethook_trampoline_handler+0x8d       (kernel/trace/rethook.c:322)           -> kretprobe_rethook_handler+0x0         (kernel/kprobes.c:2156)
      kretprobe_rethook_handler+0x43        (kernel/kprobes.c:2170)                -> kretprobe_dispatcher+0x0              (kernel/trace/trace_kprobe.c:1684)
      kretprobe_dispatcher+0x3b             (kernel/trace/trace_kprobe.c:1702)     -> kretprobe_dispatcher+0x6d             (kernel/trace/trace_kprobe.c:1703)
      kretprobe_dispatcher+0x76             (kernel/trace/trace_kprobe.c:1703)     -> kretprobe_perf_func+0x0               (kernel/trace/trace_kprobe.c:1577)
      kretprobe_perf_func+0x4e              (kernel/trace/trace_kprobe.c:1584)     -> trace_call_bpf+0x0                    (kernel/trace/bpf_trace.c:111)
      trace_call_bpf+0x62                   (include/linux/bpf.h:1955)             -> migrate_disable+0x0                   (kernel/sched/core.c:2408)
      migrate_disable+0x45                  (kernel/sched/core.c:2420)             -> trace_call_bpf+0x67                   (include/linux/bpf.h:1919)
      trace_call_bpf+0xa5                   (include/linux/bpf.h:1201)             -> kprobe_skb_1+0x8                      (bpf/kprobe_pwru.c:0)
      kprobe_skb_1+0x4e                     (bpf/kprobe_pwru.c:17)                 -> bpf_get_smp_processor_id+0x0          (kernel/bpf/helpers.c:151)
      bpf_get_smp_processor_id+0x13         (kernel/bpf/helpers.c:151)             -> kprobe_skb_1+0x53                     (bpf/kprobe_pwru.c:17)
```

This is a function call stack from callers to callees based on LBR records provided by `bpf_get_branch_snapshot()`, [bpf: Introduce helper bpf_get_branch_snapshot](https://github.com/torvalds/linux/commit/856c02dbce4f).

In this LBR stack, there is a detail of [cilium/pwru](https://github.com/cilium/pwru): it called `bpf_get_smp_processor_id()`.

## Dependencies

- *libcapstone-dev*: for disassembling machine native instructions.

## Build

With *libcapstone-dev*, build `bpflbr` by running:

```bash
make
```

## Usage

```bash
# ./bpflbr -h
Usage of bpflbr:
      --dump-jited     dump native insn info of bpf prog, the one prog ID must be provided by --prog (its function name will be ignored)
  -p, --prog strings   bpf prog info for bpflbr in format PROG[,PROG,..], PROG: <prog ID>[:<prog function name>]; all bpf progs will be traced by default
```

## Feature: dump jited insns of bpf prog

`bpflbr` is able to dump jited insns of bpf prog with att asm syntax:

```bash
# bpftool p
4483: kprobe  name kprobe_skb_3  tag 780473885099d6ae  gpl
      loaded_at 2024-10-29T14:46:13+0000  uid 0
      xlated 7544B  jited 3997B  memlock 12288B  map_ids 5449,5446,5447,5451,5450,5448,5444
      btf_id 6017

# ./bpflbr -p 4483 --dump-jited
; bpf/kprobe_pwru.c:532:0 PWRU_ADD_KPROBE(3)
0xffffffffc00c0e64: 0f 1f 44 00 00        nopl  (%rax, %rax)
0xffffffffc00c0e69: 66 90                 nop
0xffffffffc00c0e6b: 55                    pushq %rbp
0xffffffffc00c0e6c: 48 89 e5              movq  %rsp, %rbp
0xffffffffc00c0e6f: 48 81 ec 98 00 00 00  subq  $0x98, %rsp
...

# echo "If want to show intel asm syntax"
# BPFLBR_DUMP_INTEL_SYNTAX=1 ./bpflbr -p 4483 --dump-jited
; bpf/kprobe_pwru.c:532:0 PWRU_ADD_KPROBE(3)
0xffffffffc00bde9c: 0f 1f 44 00 00        nop   dword ptr [rax + rax]
0xffffffffc00bdea1: 66 90                 nop
0xffffffffc00bdea3: 55                    push  rbp
0xffffffffc00bdea4: 48 89 e5              mov   rbp, rsp
0xffffffffc00bdea7: 48 81 ec 98 00 00 00  sub   rsp, 0x98
...
```

## TODO list

- [ ] Improve [cilium/ebpf](https://github.com/cilium/ebpf) to retrieve JITed info of bpf prog.
- [ ] Fork [daludaluking/addr2line](https://github.com/daludaluking/addr2line) to refactor its code.
- [ ] ~~Fix minor issue of [knightsc/gapstone](https://github.com/knightsc/gapstone)~~.
- [ ] Develop `bpflbr` based on PoC code to trace bpf prog with LBR.
- [ ] Develop `bpflbr` feature to trace kernel functions with kprobe.multi, [bpf: Add multi kprobe link](https://github.com/torvalds/linux/commit/0dcac2725406).
- [ ] Develop `bpflbr` feature to trace userspace functions with uretprobe (**HELP WANTED**).

## Acknowledgments

- [cilium/ebpf](https://github.com/cilium/ebpf) for interacting with bpf subsystem.
- [daludaluking/addr2line](https://github.com/daludaluking/addr2line) for translating addresses to file and line number by parsing debug info from vmlinux.
- [knightsc/gapstone](https://github.com/knightsc/gapstone) for disassembling machine native instructions.

## License

This project is licensed under the Apache-2.0 License - see the [LICENSE](LICENSE) file for details.
