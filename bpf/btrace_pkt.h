#ifndef __BTRACE_PKT_H
#define __BTRACE_PKT_H

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_endian.h"

#include "btrace_common.h"
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

    if (iph->version != 4)
        return;

    switch (iph->protocol) {
    case IPPROTO_TCP:
        pkt->addrs = *(__u64 *)(void *) (&iph->saddr);
        tcp = (void *) iph + (iph->ihl << 2);
        pkt->ports = *(__u32 *)(void *) (&tcp->source);
        pkt->protocol = IPPROTO_TCP;
        pkt->tcp_flags = *(__u8 *)(void *) (((void *) &tcp->window) - 1);
        break;

    case IPPROTO_UDP:
        pkt->addrs = *(__u64 *)(void *) (&iph->saddr);
        udp = (void *) iph + (iph->ihl << 2);
        pkt->ports = *(__u32 *)(void *) (&udp->source);
        pkt->protocol = IPPROTO_UDP;
        break;

    case IPPROTO_ICMP:
        pkt->addrs = *(__u64 *)(void *) (&iph->saddr);
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
    head = skb->head;
    iph = (typeof(iph)) (head + skb->network_header);

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
    data = xdp->data;
    eth = (typeof(eth)) data;

    switch (eth->h_proto) {
    case bpf_htons(ETH_P_IP):
        iph = (typeof(iph))(void *) (eth + 1);
        break;

    case bpf_htons(ETH_P_8021Q):
        vh = (typeof(vh))(void *) (eth + 1);
        if (vh->h_vlan_encapsulated_proto != bpf_htons(ETH_P_IP))
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

    return ptr ? output_skb_tuple(pkt, session_id, ptr) : output_xdp_tuple(pkt, session_id, ptr);
}

#endif
