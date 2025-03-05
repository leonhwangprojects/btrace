// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2024 Leon Hwang */
#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_map_helpers.h"

#include "btrace.h"
#include "btrace_lbr.h"

__u32 ready SEC(".data.ready") = 0;

struct btrace_fn_arg_flags {
    bool is_number_ptr;
    bool is_str;
};

#define MAX_FN_ARGS 6
struct btrace_fn_args {
    struct btrace_fn_arg_flags args[MAX_FN_ARGS];
    __u32 nr_fn_args;
} __attribute__((packed));

struct btrace_config {
    __u32 output_lbr:1;
    __u32 output_stack:1;
    __u32 is_ret_str:1;
    __u32 pad:29;
    __u32 pid;

    struct btrace_fn_args fn_args;
} __attribute__((packed));

volatile const struct btrace_config btrace_config = {};
#define cfg (&btrace_config)

#define MAX_STACK_DEPTH 50
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 256);
    __uint(key_size, sizeof(u32));
    __uint(value_size, MAX_STACK_DEPTH * sizeof(u64));
} btrace_stacks SEC(".maps");

struct btrace_str_data {
    __u8 arg[32];
    __u8 ret[32];
};

struct btrace_str_data btrace_str_buff[1] SEC(".data.strs");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, BTRACE_MAX_ENTRIES);
    __type(key, __u64);
    __type(value, struct btrace_str_data);
} btrace_strs SEC(".maps");

struct btrace_fn_arg_data {
    __u64 raw_data;
    __u64 ptr_data;
};

struct btrace_fn_data {
    struct btrace_fn_arg_data args[MAX_FN_ARGS];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096<<8);
} btrace_events SEC(".maps");

struct event {
    __u64 session_id;
    __s64 func_ret;
    __u64 func_ip;
    __u32 cpu;
    __u32 pid;
    __u8 comm[16];
    __s64 func_stack_id;
    struct btrace_fn_data fn_data;
} __attribute__((packed));

struct event btrace_evt_buff[1] SEC(".data.events");

static __always_inline void
output_fn_data(struct event *event, void *ctx, void *retval, struct btrace_str_data *str)
{
    bool is_str, is_number_ptr, use_str = false;
    __u64 arg;
    __u32 i;

    for (i = 0; i < MAX_FN_ARGS; i++) {
        if (i >= cfg->fn_args.nr_fn_args)
            break;

        (void) bpf_get_func_arg(ctx, i, &arg); /* required 5.17 kernel. */
        event->fn_data.args[i].raw_data = arg;

        if (!arg)
            continue;

        is_str = cfg->fn_args.args[i].is_str;
        is_number_ptr = cfg->fn_args.args[i].is_number_ptr;
        if (is_str) {
            use_str = true;
            bpf_probe_read_kernel_str(&str->arg, sizeof(str->arg), (void *) arg);
        } else if (is_number_ptr) {
            bpf_probe_read_kernel(&event->fn_data.args[i].ptr_data, sizeof(event->fn_data.args[i].ptr_data), (void *) arg);
        }
    }

    if (cfg->is_ret_str && retval) {
        use_str = true;
        bpf_probe_read_kernel_str(&str->ret, sizeof(str->ret), (void *) retval);
    }

    if (use_str)
        bpf_map_update_elem(&btrace_strs, &event->session_id, str, BPF_ANY);
}

static __noinline bool
filter_fnarg(void *ctx)
{
    return ctx != NULL;
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
    if (!filter_fnarg(ctx))
        return BPF_OK;

    evt->session_id = gen_session_id();
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
