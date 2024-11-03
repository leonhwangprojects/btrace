// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2024 Leon Hwang */
#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_cleanup.h"

#define MAX_LBR_ENTRIES 32

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096<<8);
} events SEC(".maps");

struct event {
    struct perf_branch_entry lbr[MAX_LBR_ENTRIES];
    __s64 nr_bytes;
    __s64 func_ret;
    __u64 func_ip;
} __attribute__((packed));

SEC("fexit")
int BPF_PROG(fexit_fn)
{
    struct event *event;
    __u64 retval;
    int err = 0;

    guard_ringbuf(&events, event, &err);
    if (!event)
        return BPF_OK;

    event->nr_bytes = bpf_get_branch_snapshot(event->lbr, sizeof(event->lbr), 0); /* required 5.16 kernel. */
    bpf_get_func_ret(ctx, (void *) &retval); /* required 5.17 kernel. */
    event->func_ret = retval;
    event->func_ip = bpf_get_func_ip(ctx); /* required 5.17 kernel. */

    return BPF_OK;
}

char __license[] SEC("license") = "GPL";
