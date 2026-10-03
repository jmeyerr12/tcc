#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_INTERVALS 16
#define MAX_PAYLOAD_BYTES 2048
#define BLOCK_BYTES 256
#define MAX_COPY_BLOCKS ((MAX_PAYLOAD_BYTES + BLOCK_BYTES - 1) / BLOCK_BYTES)

struct interval {
    __u32 start;
    __u32 end;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_INTERVALS);
    __type(key, __u32);
    __type(value, struct interval);
} intervals_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} interval_cnt SEC(".maps");

/* Helpers ausentes nos headers de libbpf mais antigos. Kernel >= 5.18. */
static long (* const loop)(__u32, void *, void *, __u64) = (void *)181;
static long (* const load)(struct xdp_md *, __u32, void *, __u32) = (void *)189;
static long (* const store)(struct xdp_md *, __u32, const void *, __u32) = (void *)190;

struct copy_ctx {
    struct xdp_md *xdp;
    __u32 src, dst, length;
    int error;
};

static long copy_block(__u32 i, void *opaque)
{
    struct copy_ctx *c = opaque;
    __u8 bytes[BLOCK_BYTES] = {};
    __u32 pos;
    __u32 size;

    i &= 63;
    if (i >= MAX_COPY_BLOCKS) {
        c->error = 1;
        return 1;
    }
    pos = i * BLOCK_BYTES;
    if (pos >= c->length) return 1;
    size = c->length - pos;
    if (size > BLOCK_BYTES) size = BLOCK_BYTES;
    asm volatile("" : "+r"(size));
    size &= (BLOCK_BYTES * 2 - 1);
    if (!size || size > BLOCK_BYTES) {
        c->error = 1;
        return 1;
    }
    if (load(c->xdp, c->src + pos, bytes, size) < 0 ||
        store(c->xdp, c->dst + pos, bytes, size) < 0) {
        c->error = 1;
        return 1;
    }
    return 0;
}

/* Um unico load/store e mais barato que entrar em bpf_loop para intervalos de
 * ate 256 bytes, incluindo o intervalo 4-183 das regras de aplicacao.
 */
static __noinline int copy_once(struct copy_ctx *c)
{
    __u8 bytes[BLOCK_BYTES] = {};
    __u32 size = c->length;

    asm volatile("" : "+r"(size));
    size &= (BLOCK_BYTES * 2 - 1);
    if (!size || size > BLOCK_BYTES)
        return -1;
    if (load(c->xdp, c->src, bytes, size) < 0 ||
        store(c->xdp, c->dst, bytes, size) < 0)
        return -1;
    return 0;
}

static __always_inline int copy_bytes(struct xdp_md *ctx, __u32 src,
                                      __u32 dst, __u32 length)
{
    if (!length || src == dst) return 0;
    if (length > MAX_PAYLOAD_BYTES) return -1;
    struct copy_ctx copy = {
        .xdp = ctx,
        .src = src,
        .dst = dst,
        .length = length,
    };
    if (length <= BLOCK_BYTES)
        return copy_once(&copy);
    if (loop((length + BLOCK_BYTES - 1) / BLOCK_BYTES,
             copy_block, &copy, 0) < 0 || copy.error)
        return -1;
    return 0;
}

struct interval_check_ctx {
    __u32 previous_end;
    int error;
};

static long check_interval(__u32 j, void *opaque)
{
    struct interval_check_ctx *check = opaque;
    struct interval *r = bpf_map_lookup_elem(&intervals_map, &j);
    if (!r || r->end < r->start || r->end >= MAX_PAYLOAD_BYTES ||
        (j && r->start <= check->previous_end)) {
        check->error = 1;
        return 1;
    }
    check->previous_end = r->end;
    return 0;
}

struct compact_ctx {
    struct xdp_md *xdp;
    __u32 offset, length, written;
    int error;
};

static long copy_interval(__u32 j, void *opaque)
{
    struct compact_ctx *compact = opaque;
    struct interval *r = bpf_map_lookup_elem(&intervals_map, &j);
    if (!r) goto error;
    __u32 start = r->start, end = r->end;
    if (start >= compact->length) return 1;
    if (end >= compact->length) end = compact->length - 1;
    if (end < start || compact->written > start) goto error;
    __u32 size = end - start + 1;
    if (size > MAX_PAYLOAD_BYTES) goto error;
    /* O primeiro intervalo normalmente ja esta no destino correto. */
    if (copy_bytes(compact->xdp, compact->offset + start,
                   compact->offset + compact->written, size) < 0)
        goto error;
    compact->written += size;
    return 0;
error:
    compact->error = 1;
    return 1;
}

static __always_inline int compact_payload(struct xdp_md *ctx, __u32 offset,
                                            __u32 length, __u32 count)
{
    struct compact_ctx compact = { .xdp = ctx, .offset = offset, .length = length };
    if (loop(count, copy_interval, &compact, 0) < 0 || compact.error) return -1;
    return compact.written;
}

static __always_inline int append_range(struct xdp_md *ctx, __u32 offset,
                                        __u32 length, struct interval range,
                                        __u32 written)
{
    __u32 start = range.start;
    __u32 end = range.end;

    if (start >= length) return written;
    if (end >= length) end = length - 1;
    if (end < start || written > start) return -1;
    __u32 size = end - start + 1;
    if (size > MAX_PAYLOAD_BYTES) return -1;
    if (copy_bytes(ctx, offset + start, offset + written, size) < 0) return -1;
    return written + size;
}

/* Evita os loops externos e consultas duplicadas ao mapa nos casos usados
 * pelos experimentos: um intervalo (aplicacao/rede) ou dois (transporte).
 */
static __always_inline int compact_single(struct xdp_md *ctx, __u32 offset,
                                          __u32 length, struct interval range)
{
    return append_range(ctx, offset, length, range, 0);
}

static __always_inline int compact_pair(struct xdp_md *ctx, __u32 offset,
                                        __u32 length, struct interval first,
                                        struct interval second)
{
    int written = append_range(ctx, offset, length, first, 0);
    if (written < 0) return -1;
    return append_range(ctx, offset, length, second, (__u32)written);
}

SEC("xdp")
int xdp_ids_func(struct xdp_md *ctx)
{
    __u32 zero = 0;
    __u32 *count_ptr = bpf_map_lookup_elem(&interval_cnt, &zero);
    if (!count_ptr || *count_ptr > MAX_INTERVALS)
        return XDP_ABORTED;
    __u32 count = *count_ptr;
    /* Mantem o comportamento original: zero intervalos desativa os cortes.
     * Configure os dois mapas antes de enviar trafego, nunca durante o teste.
     * Fragmentos, extensoes IPv6 e pacotes fora dos limites passam sem corte.
     * A compactacao e por pacote; sequencia/ACK e reassembly TCP nao sao adaptados.
     */
    if (!count) return XDP_PASS;
    /* Valide TODOS os intervalos antes de modificar o primeiro byte.
     * Use bpf_loop tambem nos intervalos: dois for convencionais em sequencia
     * multiplicavam os caminhos examinados pelo verifier (8193 jumps).
     */
    struct interval first_range = {};
    struct interval second_range = {};
    if (count <= 2) {
        struct interval *range = bpf_map_lookup_elem(&intervals_map, &zero);
        if (!range || range->end < range->start ||
            range->end >= MAX_PAYLOAD_BYTES)
            return XDP_ABORTED;
        first_range = *range;
        if (count == 2) {
            __u32 one = 1;
            range = bpf_map_lookup_elem(&intervals_map, &one);
            if (!range || range->end < range->start ||
                range->end >= MAX_PAYLOAD_BYTES ||
                range->start <= first_range.end)
                return XDP_ABORTED;
            second_range = *range;
        }
    } else {
        struct interval_check_ctx check = {};
        if (loop(count, check_interval, &check, 0) < 0 || check.error)
            return XDP_ABORTED;
    }

    __u32 frame_len = ctx->data_end - ctx->data;
    struct ethhdr eth;
    if (load(ctx, 0, &eth, sizeof(eth)) < 0)
        return XDP_PASS;
    __u16 type = bpf_ntohs(eth.h_proto);
    __u32 ipoff = sizeof(eth);
    if (type != ETH_P_IP && type != ETH_P_IPV6)
        return XDP_PASS;

    __u32 iphlen, iplen, protocol;
    if (type == ETH_P_IP) {
        struct iphdr ip;
        if (load(ctx, ipoff, &ip, sizeof(ip)) < 0 || ip.version != 4 || ip.ihl < 5)
            return XDP_PASS;
        iphlen = ip.ihl * 4;
        iplen = bpf_ntohs(ip.tot_len);
        if (iplen < iphlen || (bpf_ntohs(ip.frag_off) & 0x3fff))
            return XDP_PASS;
        protocol = ip.protocol;
    } else {
        struct ipv6hdr ip;
        if (load(ctx, ipoff, &ip, sizeof(ip)) < 0 || ip.version != 6)
            return XDP_PASS;
        iphlen = sizeof(ip);
        iplen = iphlen + bpf_ntohs(ip.payload_len);
        protocol = ip.nexthdr;
        /* Nao interpretar extensoes/fragmentos como cabecalho TCP/UDP. */
        if (protocol == 0 || protocol == 43 || protocol == 44 || protocol == 50 ||
            protocol == 51 || protocol == 60 || protocol == 135 || protocol == 139 || protocol == 140)
            return XDP_PASS;
    }
    if (ipoff + iplen > frame_len)
        return XDP_PASS;
    /* Preserve ICMP e outros protocolos: suas regras podem inspecionar headers. */
    if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP)
        return XDP_PASS;

    __u32 l4off = ipoff + iphlen, l4len = iplen - iphlen, l4hlen;
    if (protocol == IPPROTO_TCP) {
        struct tcphdr tcp;
        if (l4len < sizeof(tcp) || load(ctx, l4off, &tcp, sizeof(tcp)) < 0 || tcp.doff < 5)
            return XDP_PASS;
        l4hlen = tcp.doff * 4;
    } else {
        struct udphdr udp;
        if (l4len < sizeof(udp) || load(ctx, l4off, &udp, sizeof(udp)) < 0 ||
            bpf_ntohs(udp.len) != l4len)
            return XDP_PASS;
        l4hlen = sizeof(udp);
    }
    if (l4len < l4hlen || l4len - l4hlen > MAX_PAYLOAD_BYTES)
        return XDP_PASS;
    __u32 payloadlen = l4len - l4hlen;
    int kept;
    if (count == 1)
        kept = compact_single(ctx, l4off + l4hlen, payloadlen, first_range);
    else if (count == 2)
        kept = compact_pair(ctx, l4off + l4hlen, payloadlen,
                            first_range, second_range);
    else
        kept = compact_payload(ctx, l4off + l4hlen, payloadlen, count);
    if (kept < 0 || (__u32)kept > payloadlen)
        return XDP_ABORTED;
    /* Sem corte, preserve todos os campos e o padding originais. */
    if ((__u32)kept == payloadlen) return XDP_PASS;
    __u32 newl4len = l4hlen + (__u32)kept;
    __u32 newframe = l4off + newl4len;
    if (bpf_xdp_adjust_tail(ctx, (int)newframe - (int)frame_len) < 0)
        return XDP_ABORTED;

    __be16 value;
    if (type == ETH_P_IP) {
        value = bpf_htons((__u16)(iphlen + newl4len));
        if (store(ctx, ipoff + 2, &value, 2) < 0) return XDP_ABORTED;
    } else {
        value = bpf_htons((__u16)newl4len);
        if (store(ctx, ipoff + 4, &value, 2) < 0) return XDP_ABORTED;
    }
    if (protocol == IPPROTO_UDP) {
        value = bpf_htons((__u16)newl4len);
        if (store(ctx, l4off + 4, &value, 2) < 0) return XDP_ABORTED;
    }
    /* Os checksums permanecem com o valor recebido. As regras que os avaliam
     * foram retiradas, e os experimentos executam o Suricata com -k none. */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
