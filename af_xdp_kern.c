#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "xdp/parsing_helpers.h" //alterei includes tambem

#define MAX_CHECKING 4
#define MAX_CSUM_WORDS 750

#undef bpf_printk
#define bpf_printk(fmt, ...)                            \
({                                                      \
        static const char ____fmt[] = fmt;              \
        bpf_trace_printk(____fmt, sizeof(____fmt),      \
                         ##__VA_ARGS__);                \
})

/* jmm23 */
#define MAX_INTERVALS 16
#define MAX_PAYLOAD_BYTES 2048

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
} interval_cnt SEC(".maps"); // amount of intervals
/* jmm23 */

/*
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} time_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} xsks_map SEC(".maps");
*/

static inline __u16 csum_fold_helper(__u64 csum) {
    __u32 sum = (csum >> 16) + (csum & 0xffff);
    sum += (sum >> 16);
    return ~sum; // Retorna o complemento de um
}

static inline __u16 iph_csum(struct iphdr *iph) {
    iph->check = 0;
    __u32 csum = 0;
    __u16 *next_iph_u16 = (__u16 *)iph;

    // Cabeçalho IP padrão tem 5 palavras de 32 bits (10 palavras de 16 bits)
    #pragma clang loop unroll(full)
    for (int i = 0; i < 10; i++) {
        csum += *next_iph_u16++;
    }
    return csum_fold_helper(csum);
}

static __always_inline void tcp_checksum(struct tcphdr *tcph)
{
	struct tcphdr tcph_old;
	__u32 csum = tcph->check;
	tcph_old = *tcph;
	csum = bpf_csum_diff((__be32 *)&tcph_old, 4, (__be32 *)tcph, 4, ~csum);
	tcph->check = csum_fold_helper(csum);
}

static __always_inline int cut_packet(struct xdp_md* ctx, struct hdr_cursor* nh, int delta){
	__u16 new_size;
	int eth_type;
	struct ethhdr *eth;
	struct iphdr *iph;
	struct ipv6hdr *ip6h;
	struct tcphdr *tcph;

	if(bpf_xdp_adjust_tail(ctx, 0-delta) < 0){
		bpf_printk("Deu pau 1\n");
		return XDP_ABORTED;
	}
	// After Adjusting packet size, every check must be performed again!
	void* data = (void *)(long)ctx->data;
	void* data_end = (void *)(long)ctx->data_end;

	nh->pos = data;
	eth_type = parse_ethhdr(nh, data_end, &eth);

	if (eth_type == bpf_htons(ETH_P_IP)) {
		iph = nh->pos;
		if (iph + 1 > data_end) return -1;

		// Update IP total length
		new_size = bpf_ntohs(iph->tot_len) - delta;
		iph->tot_len = bpf_htons(new_size);
		iph->check = iph_csum(iph);

		int ip_type = parse_iphdr(nh, data_end, &iph);
		if (ip_type == IPPROTO_TCP) {
			if (parse_tcphdr(nh, data_end, &tcph) > 0) {
				tcp_checksum(tcph);
			}
			else return -1;
		}
		
	}
	else if (eth_type == bpf_htons(ETH_P_IPV6)){
		ip6h = nh->pos;
		if (ip6h + 1 > data_end) return -1;

		//PRECISA DESCOBRIR COMO ATUALIZAR O TAMANHO DO	CABEÇALHO IPv6
		new_size = 1;
		ip6h->payload_len = bpf_htons(new_size);
	}
	return 1;
}

/* jmm23 */
static long (* const jmm_bpf_loop)(
    __u32 nr_loops,
    void *callback_fn,
    void *callback_ctx,
    __u64 flags
) = (void *)181;

static long (* const jmm_bpf_xdp_load_bytes)(
    struct xdp_md *ctx,
    __u32 offset,
    void *buf,
    __u32 len
) = (void *)189;

static long (* const jmm_bpf_xdp_store_bytes)(
    struct xdp_md *ctx,
    __u32 offset,
    void *buf,
    __u32 len
) = (void *)190;

struct copy_ctx {
    struct xdp_md *xdp;
    __u32 payload_offset;
    __u32 start;
    __u32 write_pos;
    int error;
};

static long copy_payload_byte(__u64 i, void *data)
{
    struct copy_ctx *copy = data;
    __u8 byte;

    __u32 src_offset =
        copy->payload_offset +
        copy->start +
        (__u32)i;

    __u32 dst_offset =
        copy->payload_offset +
        copy->write_pos +
        (__u32)i;

    if (jmm_bpf_xdp_load_bytes(
            copy->xdp,
            src_offset,
            &byte,
            1
        ) < 0) {

        copy->error = 1;
        return 1;
    }

    if (jmm_bpf_xdp_store_bytes(
            copy->xdp,
            dst_offset,
            &byte,
            1
        ) < 0) {

        copy->error = 1;
        return 1;
    }

    return 0;
}

static __always_inline int compact_payload(
    struct xdp_md *ctx,
    void *data,
    void *payload,
    void *data_end
)
{
    __u32 count_key = 0;
    __u32 *count_ptr;
    __u32 payload_len;
    __u32 payload_offset;
    __u32 write_pos = 0;

    payload_len =
        (__u32)((char *)data_end -
                (char *)payload);

    payload_offset =
        (__u32)((char *)payload -
                (char *)data);

    if (payload_len == 0)
        return 0;

    if (payload_len > MAX_PAYLOAD_BYTES)
        return -1;

    count_ptr = bpf_map_lookup_elem(
        &interval_cnt,
        &count_key
    );

    if (!count_ptr)
        return -1;

    __u32 count = *count_ptr;

    if (count > MAX_INTERVALS)
        return -1;

    if (count == 0)
        return payload_len;

    #pragma clang loop unroll(disable)
    for (__u32 j = 0; j < MAX_INTERVALS; j++) {
        if (j >= count)
            break;

        __u32 key = j;

        struct interval *current =
            bpf_map_lookup_elem(
                &intervals_map,
                &key
            );

        if (!current)
            return -1;

        __u32 start = current->start;
        __u32 end = current->end;

        if (end < start)
            return -1;

        if (start >= payload_len)
            break;

        if (end >= payload_len)
            end = payload_len - 1;

        __u32 length =
            end - start + 1;

        if (length > MAX_PAYLOAD_BYTES)
            return -1;

        struct copy_ctx copy = {
            .xdp = ctx,
            .payload_offset = payload_offset,
            .start = start,
            .write_pos = write_pos,
            .error = 0
        };

        long ret = jmm_bpf_loop(
            length,
            copy_payload_byte,
            &copy,
            0
        );

        if (ret < 0 || copy.error)
            return -1;

        write_pos += length;

        if (write_pos > payload_len)
            return -1;
    }

    return write_pos;
}
/* jmm23 */


SEC("xdp")
int xdp_ids_func(struct xdp_md *ctx)
{
    //__u64 time;
    //time = bpf_ktime_get_ns();

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct hdr_cursor nh;
    int eth_type = 0, ip_type = 0;
    struct ethhdr *eth;
    struct iphdr *iph;
    struct ipv6hdr *ip6h;
    struct tcphdr *tcph;
    struct udphdr *udph;

    void* end_ip;
    void* end_ip6;

    nh.pos = data;
    eth_type = parse_ethhdr(&nh, data_end, &eth);

    if (eth_type == bpf_htons(ETH_P_IP)) {
        ip_type = parse_iphdr(&nh, data_end, &iph);
	    end_ip = nh.pos;
    } else if (eth_type == bpf_htons(ETH_P_IPV6)) {
        ip_type = parse_ip6hdr(&nh, data_end, &ip6h);
	    end_ip6 = nh.pos;
    }
    else{
	    //bpf_printk("Jesus");
        // Se não for nem IP nem IPv6 (ARP, por exemplo), descarta
        return XDP_DROP;
    }

    void *end_tcp = NULL;
    void *end_udp = NULL;
    char* letter;
    char method[3];
    int delta;

    if (ip_type == IPPROTO_TCP) {
        if (parse_tcphdr(&nh, data_end, &tcph) > 0) {

            /* jmm23 */
            void *payload = nh.pos;

            __u32 old_payload_len =
                (__u32)((char *)data_end - (char *)payload);

            int new_payload_len =
                compact_payload(
                    ctx,
                    data,
                    payload,
                    data_end
                );

            if (new_payload_len < 0) {
                return XDP_ABORTED;
            }

            __u32 new_len =
                (__u32)new_payload_len;

            if (new_len > old_payload_len) {
                return XDP_ABORTED;
            }

            if (new_len > MAX_PAYLOAD_BYTES) {
                return XDP_ABORTED;
            }

            __u32 shrink =
                old_payload_len - new_len;

            delta = (int)shrink;

            if (delta > 0) {
                if (cut_packet(ctx, &nh, delta) < 0) {
                    return XDP_ABORTED;
                }
            }

            goto success;
            /* jmm23 */
        }
	    else{
		    bpf_printk("Error while parsing!");
		    return XDP_ABORTED;
	    }
    }

    // UDP packet
    else if (ip_type == IPPROTO_UDP) {
	    if (parse_udphdr(&nh, data_end, &udph) > 0) {

            /* jmm23 */
            void *payload = nh.pos;

            __u32 old_payload_len =
                (__u32)((char *)data_end - (char *)payload);

            int new_payload_len =
                compact_payload(
                    ctx,
                    data,
                    payload,
                    data_end
                );

            if (new_payload_len < 0) {
                return XDP_ABORTED;
            }

            __u32 new_len =
                (__u32)new_payload_len;

            if (new_len > old_payload_len) {
                return XDP_ABORTED;
            }

            if (new_len > MAX_PAYLOAD_BYTES) {
                return XDP_ABORTED;
            }

            __u32 shrink =
                old_payload_len - new_len;

            delta = (int)shrink;

            if (delta > 0) {
                if (cut_packet(ctx, &nh, delta) < 0) {
                    return XDP_ABORTED;
                }
            }

            goto success;
            /* jmm23 */
	    }
    }

    // non TCP nor UDP packet
    else {
	    if (eth_type == bpf_htons(ETH_P_IP)) {
		    delta = data_end - end_ip;
		    if(cut_packet(ctx, &nh, delta) < 0){
			    bpf_printk("Failed while cutting packets - TCP without HTTP!");
			    return XDP_ABORTED;

		    }
		    goto success;
	    }
	    else if (eth_type == bpf_htons(ETH_P_IPV6)){
		    delta = data_end - end_ip6;
		    if(cut_packet(ctx, &nh, delta) < 0){
			    bpf_printk("Failed while cutting packets - TCP without HTTP!");
			    return XDP_ABORTED;

		    }
		    goto success;
	    }
		
	}

success:
	/*
    __u32 k = 0;
    __u64 *v, diff;
    v = bpf_map_lookup_elem(&time_map, &k);
    if (v) {
	    *v = *v + 1;
    }
	*/
    return XDP_PASS;
}

char _license [] SEC ("license") = "GPL";