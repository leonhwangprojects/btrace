// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2025 Leon Hwang */

#ifndef __BTRACE_LBR_H_
#define __BTRACE_LBR_H_

#include "vmlinux.h"
#include "bpf_helpers.h"

#include "btrace.h"

#define MAX_LBR_ENTRIES 32
struct btrace_lbr_data {
    struct perf_branch_entry entries[MAX_LBR_ENTRIES];
    __s64 nr_bytes;
};

struct btrace_lbr_data btrace_lbr_buff[1] SEC(".data.lbrs");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, BTRACE_MAX_ENTRIES);
    __type(key, __u64);
    __type(value, struct btrace_lbr_data);
} btrace_lbrs SEC(".maps");

static __always_inline void
output_lbr_data(struct btrace_lbr_data *lbr, __u64 session_id)
{
    if (lbr->nr_bytes > 0)
        (void) bpf_map_update_elem(&btrace_lbrs, &session_id, lbr, BPF_ANY);
}

#endif // __BTRACE_LBR_H_
