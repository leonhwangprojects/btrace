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

## bpflbr output example

```bash
# ./bpflbr -p n:kprobe_multi_skb_1,n:kprobe_multi_skb_2,n:kprobe_multi_skb_3,n:kprobe_multi_skb_4,n:kprobe_multi_skb_5
2024/12/05 09:57:02 bpflbr is running..
Recv a record for kprobe_multi_skb_1[bpf] with retval=0/0x0 cpu=0 process=(0:swapper/0) :
LBR stack:
[#31] 0xffffffffb4cafa14:bpf_get_func_ip_kprobe_multi+0x14 (kernel/trace/bpf_trace.c:1089)     -> 0xffffffffc018a2d4:kprobe_multi_skb_1+0xa4         (bpf/kprobe_pwru.c:502)
      0xffffffffc018a317:kprobe_multi_skb_1+0xe7           (bpf/kprobe_pwru.c:508)             -> 0xffffffffb4d187c0:queue_stack_map_push_elem+0x0   (kernel/bpf/queue_stack_maps.c:191)
      0xffffffffb4d1880f:queue_stack_map_push_elem+0x4f    (kernel/bpf/queue_stack_maps.c:210) -> 0xffffffffb5ab1e90:_raw_spin_lock_irqsave+0x0      (kernel/locking/spinlock.c:161)
      0xffffffffb5ab1e99:_raw_spin_lock_irqsave+0x9        (kernel/locking/spinlock.c:162)     -> 0xffffffffb4b800f0:__raw_spin_lock_irqsave+0x0
      0xffffffffb4b80131:__raw_spin_lock_irqsave+0x41                                          -> 0xffffffffb5ab1e9e:_raw_spin_lock_irqsave+0xe      (kernel/locking/spinlock.c:163)
      0xffffffffb5ab1ea1:_raw_spin_lock_irqsave+0x11       (kernel/locking/spinlock.c:163)     -> 0xffffffffb4d18814:queue_stack_map_push_elem+0x54  (kernel/bpf/queue_stack_maps.c:210)
      0xffffffffb4d1884d:queue_stack_map_push_elem+0x8d    (kernel/bpf/queue_stack_maps.c:224) -> 0xffffffffb5a9bc70:__memcpy+0x0                    (arch/x86/lib/memcpy_64.S:34)
      0xffffffffb5a9bc70:__memcpy+0x0                      (arch/x86/lib/memcpy_64.S:34)       -> 0xffffffffb5a9bc90:memcpy_orig+0x0                 (arch/x86/lib/memcpy_64.S:47)
      0xffffffffb5a9bc9c:memcpy_orig+0xc                   (arch/x86/lib/memcpy_64.S:57)       -> 0xffffffffb5a9bcd3:memcpy_orig+0x43                (arch/x86/lib/memcpy_64.S:84)
      0xffffffffb5a9bd0c:memcpy_orig+0x7c                  (arch/x86/lib/memcpy_64.S:104)      -> 0xffffffffb5a9bce0:memcpy_orig+0x50                (arch/x86/lib/memcpy_64.S:93)
      0xffffffffb5a9bd0c:memcpy_orig+0x7c                  (arch/x86/lib/memcpy_64.S:104)      -> 0xffffffffb5a9bce0:memcpy_orig+0x50                (arch/x86/lib/memcpy_64.S:93)
      0xffffffffb5a9bd0c:memcpy_orig+0x7c                  (arch/x86/lib/memcpy_64.S:104)      -> 0xffffffffb5a9bce0:memcpy_orig+0x50                (arch/x86/lib/memcpy_64.S:93)
      0xffffffffb5a9bd3e:memcpy_orig+0xae                  (arch/x86/lib/memcpy_64.S:127)      -> 0xffffffffb4d18852:queue_stack_map_push_elem+0x92  (kernel/bpf/queue_stack_maps.c:226)
      0xffffffffb4d18876:queue_stack_map_push_elem+0xb6    (kernel/bpf/queue_stack_maps.c:230) -> 0xffffffffb5ab1da0:_raw_spin_unlock_irqrestore+0x0 (kernel/locking/spinlock.c:193)
      0xffffffffb5ab1dcf:_raw_spin_unlock_irqrestore+0x2f  (kernel/locking/spinlock.c:195)     -> 0xffffffffb4d1887b:queue_stack_map_push_elem+0xbb  (kernel/bpf/queue_stack_maps.c:232)
      0xffffffffb4d18894:queue_stack_map_push_elem+0xd4    (kernel/bpf/queue_stack_maps.c:232) -> 0xffffffffc018a31c:kprobe_multi_skb_1+0xec         (bpf/kprobe_pwru.c:526)
      0xffffffffc018a322:kprobe_multi_skb_1+0xf2           (bpf/kprobe_pwru.c:526)             -> 0xffffffffc1b8103f:+0x0
```

This is a function call stack from callers to callees based on LBR records provided by `bpf_get_branch_snapshot()`, [bpf: Introduce helper bpf_get_branch_snapshot](https://github.com/torvalds/linux/commit/856c02dbce4f).

In this LBR stack, there is two details of [cilium/pwru](https://github.com/cilium/pwru): it called `bpf_get_func_ip()` and `bpf_map_push_elem()`.

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
  -d, --disasm                disasm bpf prog or kernel function
  -B, --disasm-bytes uint     disasm bytes of kernel function, must not 0
      --disasm-intel-syntax   use Intel asm syntax for disasm, ATT asm syntax by default
      --dump-jited            dump native insn info of bpf prog, the one bpf prog must be provided by --prog (its function name will be ignored) [Deprecated, use --disasm instead]
  -k, --kfunc strings         kernel functions for bpflbr
  -m, --mode string           mode of lbr tracing, exit or entry (default "exit")
  -o, --output string         output file for the result, default is stdout
      --output-stack          output function call stack
  -p, --prog strings          bpf prog info for bpflbr in format PROG[,PROG,..], PROG: PROGID[:<prog function name>], PROGID: <prog ID> or 'i/id:<prog ID>' or 'p/pinned:<pinned file>' or 't/tag:<prog tag>' or 'n/name:<prog full name>'; all bpf progs will be traced by default
      --suppress-lbr          suppress LBR perf event
  -v, --verbose               output verbose log
```

## Feature: dump LBR stack of kernel functions

`bpflbr` is able to dump LBR stack of kernel functions by `-k` option.

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

## Feature: trace target with fentry

By default, `bpflbr` traces targets with fexit. If you want to trace targets with fentry, you can use `--mode entry`.

It is really useful to trace the details before calling the target function/bpf-prog.

## Feature: dump function stack without LBR

As `bpflbr` is able to provide line info for an kernel address, it can provide line info for the addresses of function stack:

```bash
# ./bpflbr --suppress-lbr -k icmp_rcv --output-stack --mode entry
2024/12/04 14:11:34 bpflbr is running..
Recv a record for icmp_rcv with cpu=6 process=(0:swapper/6) :
Func stack:
  icmp_rcv+0x5                                        ; net/ipv4/icmp.c:1180
  ip_local_deliver_finish+0x77                        ; net/ipv4/ip_input.c:233
  ip_local_deliver+0x6e                               ; include/linux/netfilter.h:314
  ip_sublist_rcv_finish+0x6f                          ; include/net/dst.h:461
  ip_sublist_rcv+0x178                                ; net/ipv4/ip_input.c:640
  ip_list_rcv+0x102                                   ; net/ipv4/ip_input.c:675
  __netif_receive_skb_list_core+0x22d                 ; net/core/dev.c:5577
  netif_receive_skb_list_internal+0x1a3               ; net/core/dev.c:5679
  napi_complete_done+0x74                             ; include/net/gro.h:439
  e1000_clean+0x7c
  __napi_poll+0x30                                    ; net/core/dev.c:6576
  net_rx_action+0x181                                 ; net/core/dev.c:6647
  __do_softirq+0xde
  __irq_exit_rcu+0xd7                                 ; kernel/softirq.c:427
  irq_exit_rcu+0xe                                    ; kernel/softirq.c:647
  common_interrupt+0xa4
  asm_common_interrupt+0x27                           ; arch/x86/include/asm/idtentry.h:640
  pv_native_safe_halt+0xb                             ; arch/x86/kernel/paravirt.c:128
  acpi_idle_do_entry+0x40                             ; arch/x86/include/asm/perf_event.h:619
  acpi_idle_enter+0xb6                                ; drivers/acpi/processor_idle.c:709
  cpuidle_enter_state+0x8e                            ; drivers/cpuidle/cpuidle.c:267
  cpuidle_enter+0x2e
  call_cpuidle+0x23                                   ; kernel/sched/idle.c:135
  cpuidle_idle_call+0x11d                             ; kernel/sched/idle.c:219
  do_idle+0x87                                        ; kernel/sched/idle.c:314
  cpu_startup_entry+0x2a                              ; kernel/sched/idle.c:409
  start_secondary+0x129                               ; arch/x86/kernel/smpboot.c:224
  secondary_startup_64_no_verify+0x184                ; arch/x86/kernel/head_64.S:461
```

## TODO list

- [ ] Develop `bpflbr` feature to filter kernel function with regexp.
- [ ] Develop `bpflbr` feature to trace kernel functions with kprobe.multi, [bpf: Add multi kprobe link](https://github.com/torvalds/linux/commit/0dcac2725406).
- [ ] Develop `bpflbr` feature to trace userspace functions with uretprobe (**HELP WANTED**).

## Acknowledgments

- [cilium/ebpf](https://github.com/cilium/ebpf) for interacting with bpf subsystem.
- [daludaluking/addr2line](https://github.com/daludaluking/addr2line) for translating addresses to file and line number by parsing debug info from vmlinux.
- [knightsc/gapstone](https://github.com/knightsc/gapstone) for disassembling machine native instructions.

## License

This project is licensed under the Apache-2.0 License - see the [LICENSE](LICENSE) file for details.
