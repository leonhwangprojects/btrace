// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2025 Leon Hwang */

#ifndef __BTRACE_PKT_OUTPUT_H_
#define __BTRACE_PKT_OUTPUT_H_

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "bpf_core_read.h"

#include "btrace.h"
#include "if_ether.h"

struct btrace_pkt_data {
    __u64 addrs;
    __u32 ports;
    __u8 protocol;
    __u8 tcp_flags;
    __u8 pad[2];
};

struct btrace_pkt_data btrace_pkt_buff[1] SEC(".data.pkts");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, BTRACE_MAX_ENTRIES);
    __type(key, __u64);
    __type(value, struct btrace_pkt_data);
} btrace_pkts SEC(".maps");

static __always_inline void
output_tuple(struct btrace_pkt_data *pkt, __u64 session_id, struct iphdr *iph)
{
    struct udphdr *udp;
    struct tcphdr *tcp;
    __u8 b;

    (void) bpf_probe_read_kernel(&b, sizeof(b), (void *) iph);
    if (((b >> 4) & 0x7) != 4)
        return;

    switch (BPF_CORE_READ(iph, protocol)) {
    case IPPROTO_TCP:
        (void) bpf_probe_read_kernel(&pkt->addrs, sizeof(pkt->addrs), (void *) (&iph->saddr));
        tcp = (void *) iph + ((b & 0x7) << 2);
        (void) bpf_probe_read_kernel(&pkt->ports, sizeof(pkt->ports), (void *) (&tcp->source));
        pkt->protocol = IPPROTO_TCP;
        (void) bpf_probe_read_kernel(&pkt->tcp_flags, sizeof(pkt->tcp_flags), (void *) (&tcp->window) - 1);
        break;

    case IPPROTO_UDP:
        (void) bpf_probe_read_kernel(&pkt->addrs, sizeof(pkt->addrs), (void *) (&iph->saddr));
        udp = (void *) iph + ((b & 0x7) << 2);
        (void) bpf_probe_read_kernel(&pkt->ports, sizeof(pkt->ports), (void *) (&udp->source));
        pkt->protocol = IPPROTO_UDP;
        break;

    case IPPROTO_ICMP:
        (void) bpf_probe_read_kernel(&pkt->addrs, sizeof(pkt->addrs), (void *) (&iph->saddr));
        pkt->protocol = IPPROTO_ICMP;
        break;

    default:
        return;
    }

    (void) bpf_map_update_elem(&btrace_pkts, &session_id, pkt, BPF_ANY);
}

static __noinline void
output_skb_tuple(struct btrace_pkt_data *pkt, __u64 session_id, void *ptr)
{
    struct sk_buff *skb;
    struct iphdr *iph;
    void *head;

    skb = (typeof(skb)) ptr;
    head = BPF_CORE_READ(skb, head);
    iph = (typeof(iph)) (head + BPF_CORE_READ(skb, network_header));

    output_tuple(pkt, session_id, iph);
}

static __noinline void
output_xdp_tuple(struct btrace_pkt_data *pkt, __u64 session_id, void *ptr)
{
    struct xdp_buff *xdp;
    struct vlan_hdr *vh;
    struct ethhdr *eth;
    struct iphdr *iph;
    void *data;

    xdp = (typeof(xdp)) ptr;
    data = BPF_CORE_READ(xdp, data);
    eth = (typeof(eth)) data;

    switch (BPF_CORE_READ(eth, h_proto)) {
    case bpf_htons(ETH_P_IP):
        iph = (typeof(iph))(void *) (eth + 1);
        break;

    case bpf_htons(ETH_P_8021Q):
        vh = (typeof(vh))(void *) (eth + 1);
        if (BPF_CORE_READ(vh, h_vlan_encapsulated_proto) != bpf_htons(ETH_P_IP))
            return;
        iph = (typeof(iph))(void *) (vh + 1);
        break;

    default:
        return;
    }

    output_tuple(pkt, session_id, iph);
}

static __noinline void
output_pkt_tuple(void *ctx, struct btrace_pkt_data *pkt, __u64 session_id)
{
    /* This function will be rewrote by Go totally. */
    void *ptr = (void *) session_id;

    return ctx ? output_skb_tuple(pkt, session_id, ptr) : output_xdp_tuple(pkt, session_id, ptr);
}

#endif // __BTRACE_PKT_OUTPUT_H_
