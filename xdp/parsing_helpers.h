#ifndef __PARSING_HELPERS_H
#define __PARSING_HELPERS_H

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

struct hdr_cursor {
    void *pos;
};

static __always_inline int parse_ethhdr(
    struct hdr_cursor *nh,
    void *data_end,
    struct ethhdr **ethhdr
)
{
    struct ethhdr *eth = nh->pos;

    if ((void *)(eth + 1) > data_end)
        return -1;

    nh->pos = eth + 1;
    *ethhdr = eth;

    return eth->h_proto;
}

static __always_inline int parse_iphdr(
    struct hdr_cursor *nh,
    void *data_end,
    struct iphdr **iphdr
)
{
    struct iphdr *iph = nh->pos;

    if ((void *)(iph + 1) > data_end)
        return -1;

    int hdrsize = iph->ihl * 4;

    if (hdrsize < (int)sizeof(*iph))
        return -1;

    if ((void *)iph + hdrsize > data_end)
        return -1;

    nh->pos = (void *)iph + hdrsize;
    *iphdr = iph;

    return iph->protocol;
}

static __always_inline int parse_ip6hdr(
    struct hdr_cursor *nh,
    void *data_end,
    struct ipv6hdr **ip6hdr
)
{
    struct ipv6hdr *ip6h = nh->pos;

    if ((void *)(ip6h + 1) > data_end)
        return -1;

    nh->pos = ip6h + 1;
    *ip6hdr = ip6h;

    return ip6h->nexthdr;
}

static __always_inline int parse_tcphdr(
    struct hdr_cursor *nh,
    void *data_end,
    struct tcphdr **tcphdr
)
{
    struct tcphdr *tcph = nh->pos;

    if ((void *)(tcph + 1) > data_end)
        return -1;

    int hdrsize = tcph->doff * 4;

    if (hdrsize < (int)sizeof(*tcph))
        return -1;

    if ((void *)tcph + hdrsize > data_end)
        return -1;

    nh->pos = (void *)tcph + hdrsize;
    *tcphdr = tcph;

    return hdrsize;
}

static __always_inline int parse_udphdr(
    struct hdr_cursor *nh,
    void *data_end,
    struct udphdr **udphdr
)
{
    struct udphdr *udph = nh->pos;

    if ((void *)(udph + 1) > data_end)
        return -1;

    nh->pos = udph + 1;
    *udphdr = udph;

    return sizeof(*udph);
}

#endif
