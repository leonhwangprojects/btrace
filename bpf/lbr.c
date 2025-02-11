// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2024 Leon Hwang */
#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

__u32 ready SEC(".data.ready") = 0;

#define MAX_LBR_ENTRIES 32

struct lbr_config {
    __u32 suppress_lbr:1;
    __u32 output_stack:1;
    __u32 have_read_branch_snapshot:1;
    __u32 pad:29;
    __u32 pid;
};

volatile const struct lbr_config lbr_config = {};
#define cfg (&lbr_config)

#define MAX_STACK_DEPTH 50
struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, 256);
	__uint(key_size, sizeof(u32));
	__uint(value_size, MAX_STACK_DEPTH * sizeof(u64));
} func_stacks SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096<<8);
} events SEC(".maps");

struct event {
    struct perf_branch_entry lbr[MAX_LBR_ENTRIES];
    __s64 nr_bytes;
    __s64 func_ret;
    __u64 func_ip;
    __u32 cpu;
    __u32 pid;
    __u8 comm[16];
    __s64 func_stack_id;
} __attribute__((packed));

struct event lbr_events[1] SEC(".data.lbrs");

static __always_inline int
emit_lbr_event(void *ctx)
{
    struct event *event;
    __u64 retval;
    __u32 cpu;

    if (!ready)
        return BPF_OK;

    cpu = bpf_get_smp_processor_id();
    event = &lbr_events[cpu];

    if (!cfg->suppress_lbr) {
        if (cfg->have_read_branch_snapshot)
            event->nr_bytes = bpf_read_branch_snapshot(ctx, event->lbr, sizeof(event->lbr));
        else
            event->nr_bytes = bpf_get_branch_snapshot(event->lbr, sizeof(event->lbr), 0);
    } else {
        event->nr_bytes = 0;
    }

    /* Other filters must be after bpf_get_branch_snapshot() to avoid polluting
     * LBR entries.
     */

    event->pid = bpf_get_current_pid_tgid() >> 32;
    if (cfg->pid && event->pid != cfg->pid)
        return BPF_OK;

    bpf_get_func_ret(ctx, (void *) &retval); /* required 5.17 kernel. */
    event->func_ret = retval;
    event->func_ip = bpf_get_func_ip(ctx); /* required 5.17 kernel. */
    event->cpu = cpu;
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    event->func_stack_id = -1;
    if (cfg->output_stack)
        event->func_stack_id = bpf_get_stackid(ctx, &func_stacks, BPF_F_FAST_STACK_CMP);

    bpf_ringbuf_output(&events, event, sizeof(*event), 0);

    return BPF_OK;
}

SEC("fexit")
int BPF_PROG(fexit_fn)
{
    return emit_lbr_event(ctx);
}

SEC("fentry")
int BPF_PROG(fentry_fn)
{
    return emit_lbr_event(ctx);
}

char __license[] SEC("license") = "GPL";
