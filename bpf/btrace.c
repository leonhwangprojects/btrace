// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2024 Leon Hwang */
#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_map_helpers.h"

#include "btrace.h"
#include "btrace_lbr.h"
#include "btrace_arg.h"
#include "btrace_pkt_filter.h"

__u32 ready SEC(".data.ready") = 0;

#define MAX_STACK_DEPTH 50
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 256);
    __uint(key_size, sizeof(u32));
    __uint(value_size, MAX_STACK_DEPTH * sizeof(u64));
} btrace_stacks SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096<<8);
} btrace_events SEC(".maps");

struct event btrace_evt_buff[1] SEC(".data.events");

static __always_inline bool
filter(void *ctx, __u64 session_id)
{
    return filter_fnarg(ctx) && filter_pkt(ctx, session_id);
}

static __always_inline __u64
get_tracee_caller_fp(void)
{
    u64 fp, fp_caller;

    /* get frame pointer */
    asm volatile ("%[fp] = r10" : [fp] "+r"(fp) :); /* fp of current bpf prog */
    (void) bpf_probe_read_kernel(&fp_caller, sizeof(fp_caller), (void *) fp); /* fp of trampoline */
    (void) bpf_probe_read_kernel(&fp_caller, sizeof(fp_caller), (void *) fp_caller); /* fp of tracee caller */
    return fp_caller;
}

static __always_inline __u64
gen_session_id(void)
{
    __u64 fp = get_tracee_caller_fp();
    __u32 rnd = bpf_get_prandom_u32();

    return ((__u64) rnd) << 32 | (fp & 0xFFFFFFFF);
}

static __always_inline int
emit_btrace_event(void *ctx)
{
    struct btrace_lbr_data *lbr;
    struct btrace_str_data *str;
    struct event *evt;
    __u64 retval;
    __u32 cpu;

    if (!ready)
        return BPF_OK;

    cpu = bpf_get_smp_processor_id();
    lbr = &btrace_lbr_buff[cpu];
    str = &btrace_str_buff[cpu];
    evt = &btrace_evt_buff[cpu];

    if (cfg->output_lbr)
        lbr->nr_bytes = bpf_get_branch_snapshot(lbr->entries, sizeof(lbr->entries), 0); /* required 5.16 kernel. */

    /* Other filters must be after bpf_get_branch_snapshot() to avoid polluting
     * LBR entries.
     */

    evt->pid = bpf_get_current_pid_tgid() >> 32;
    if (cfg->pid && evt->pid != cfg->pid)
        return BPF_OK;

    evt->session_id = gen_session_id();
    if (!filter(ctx, evt->session_id))
        return BPF_OK;

    bpf_get_func_ret(ctx, (void *) &retval); /* required 5.17 kernel. */
    evt->func_ret = retval;
    evt->func_ip = bpf_get_func_ip(ctx); /* required 5.17 kernel. */
    evt->cpu = cpu;
    bpf_get_current_comm(evt->comm, sizeof(evt->comm));
    evt->func_stack_id = -1;
    if (cfg->output_stack)
        evt->func_stack_id = bpf_get_stackid(ctx, &btrace_stacks, BPF_F_FAST_STACK_CMP);
    output_fn_data(evt, ctx, (void *) retval, str);
    if (cfg->output_lbr)
        output_lbr_data(lbr, evt->session_id);

    bpf_ringbuf_output(&btrace_events, evt, sizeof(*evt), 0);

    return BPF_OK;
}

SEC("fexit")
int BPF_PROG(fexit_fn)
{
    return emit_btrace_event(ctx);
}

SEC("fentry")
int BPF_PROG(fentry_fn)
{
    return emit_btrace_event(ctx);
}

char __license[] SEC("license") = "GPL";
