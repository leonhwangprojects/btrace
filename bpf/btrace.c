// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2024 Leon Hwang */
#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_map_helpers.h"

#include "btrace.h"
#include "btrace_arg.h"
#include "btrace_lbr.h"
#include "btrace_str.h"
#include "btrace_pkt_filter.h"
#include "btrace_pkt_output.h"

__u32 ready SEC(".data.ready") = 0;

volatile const __u64 FUNC_IP = 0;

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
emit_btrace_event(void *ctx, volatile __u64 *args, const bool use_args)
{
    struct btrace_lbr_data *lbr;
    struct btrace_str_data *str;
    struct btrace_pkt_data *pkt;
    struct btrace_arg_data *arg;
    struct event *evt;
    __u64 retval = 0;
    __u64 session_id;
    size_t event_sz;
    __u32 cpu, pid;

    if (!ready)
        return BPF_OK;

    cpu = bpf_get_smp_processor_id();
    lbr = &btrace_lbr_buff[cpu];
    pkt = &btrace_pkt_buff[cpu];
    str = &btrace_str_buff[cpu];
    arg = &btrace_arg_buff[cpu];
    evt = &btrace_evt_buff[cpu];

    if (cfg->output_lbr)
        lbr->nr_bytes = bpf_get_branch_snapshot(lbr->entries, sizeof(lbr->entries), 0); /* required 5.16 kernel. */

    /* Other filters must be after bpf_get_branch_snapshot() to avoid polluting
     * LBR entries.
     */

    pid = bpf_get_current_pid_tgid() >> 32;
    if (cfg->pid && pid != cfg->pid)
        return BPF_OK;

    session_id = gen_session_id();
    if (!filter(use_args ? (void *) args : ctx, session_id))
        return BPF_OK;

    evt->session_id = session_id;
    if (!use_args) {
        bpf_get_func_ret(ctx, (void *) &retval); /* required 5.17 kernel. */
        evt->func_ret = retval;
    }
    evt->func_ip = FUNC_IP ? FUNC_IP : bpf_get_func_ip(ctx); /* required 5.17 kernel. */
    evt->cpu = cpu;
    evt->pid = pid;
    bpf_get_current_comm(evt->comm, sizeof(evt->comm));
    evt->func_stack_id = -1;
    if (cfg->output_stack)
        evt->func_stack_id = bpf_get_stackid(ctx, &btrace_stacks, BPF_F_FAST_STACK_CMP);
    if (cfg->output_lbr)
        output_lbr_data(lbr, session_id);
    if (use_args) {
        output_fn_data_vol(evt, str, args);
        if (cfg->output_pkt)
            output_pkt_tuple((void *) args, pkt, session_id);
        if (cfg->output_arg)
            output_arg_data((void *) args, arg, session_id);
    } else {
        output_fn_data(evt, ctx, (void *) retval, str);
        if (cfg->output_pkt)
            output_pkt_tuple(ctx, pkt, session_id);
        if (cfg->output_arg)
            output_arg_data(ctx, arg, session_id);
    }

    event_sz  = offsetof(struct event, fn_data);
    event_sz += sizeof(struct btrace_fn_arg_data) * cfg->fn_args.nr_fn_args;
    bpf_ringbuf_output(&btrace_events, evt, event_sz, 0);

    return BPF_OK;
}

SEC("fexit")
int BPF_PROG(fexit_fn)
{
    return emit_btrace_event(ctx, NULL, false);
}

SEC("fentry")
int BPF_PROG(fentry_fn)
{
    return emit_btrace_event(ctx, NULL, false);
}

static __noinline int
handle_tp_event(void *ctx, volatile __u64 *args)
{
    return emit_btrace_event(ctx, args, true);
}

SEC("tp_btf")
int BPF_PROG(tp_btf_fn)
{
    /* This function will be rewrote by Go totally. */
    volatile __u64 args[MAX_FN_ARGS] = {};

    return handle_tp_event(ctx, args);
}

char __license[] SEC("license") = "GPL";
