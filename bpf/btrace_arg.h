// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2025 Leon Hwang */

#ifndef __BTRACE_ARG_H_
#define __BTRACE_ARG_H_

#include "vmlinux.h"

#include "bpf_helpers.h"

#include "btrace.h"

struct btrace_arg_data {
    __u64 data[4][2]; /* 4 attrs */
    __u8 str[32];  /* 1 string */
};

struct btrace_arg_data btrace_arg_buff[1] SEC(".data.args");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, BTRACE_MAX_ENTRIES);
    __type(key, __u64);
    __type(value, struct btrace_arg_data);
} btrace_args SEC(".maps");

static __noinline void
__output_arg_data(struct btrace_arg_data *data, __u64 session_id)
{
    (void) bpf_map_update_elem(&btrace_args, &session_id, data, BPF_ANY);
}

static __noinline void
output_arg_data(void *ctx, struct btrace_arg_data *data, __u64 session_id)
{
    /* This function will be rewrote by Go totally. */
    /* Keeping one line is to show in `btrace -d -p`. */
    if (ctx) __output_arg_data(data, session_id);
}

#endif // __BTRACE_ARG_H_
