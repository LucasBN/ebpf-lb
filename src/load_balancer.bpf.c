#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <netinet/in.h>

#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>

#include <string.h>
#include "common.h"

#define NUM_SERVERS 2
#define HASH_SEED 0xDEADBEEF

#define MAX_OPT_WORDS 10 // 40 bytes for options
#define MAX_TARGET_COUNT 64
#define CHECK_OUT_OF_BOUNDS(PTR, OFFSET, END)                                  \
	(((void *)PTR) + OFFSET > ((void *)END))

struct ipv4_psd_header {
	uint32_t src_addr; /* IP address of source host. */
	uint32_t dst_addr; /* IP address of destination host. */
	uint8_t zero;	   /* zero. */
	uint8_t proto;	   /* L4 protocol type. */
	uint16_t len;	   /* L4 length. */
};

/**
 * Map that holds the information for the target servers
 * You can assume that this map will always have two elements populated when
 * loading the XDP program
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct ip_mac_pair);
	__uint(max_entries, MAX_TARGET_COUNT);
} targets_map SEC(".maps");

/**
 * Map that holds the IP and MAC address of the load balancer and the client.
 * The IP and MAC of the load balancer are in the first cell
 * and the information for the client are in the second cell.
 * This map is also populated when loading the XDP program.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct ip_mac_pair);
	__uint(max_entries, MAX_TARGET_COUNT);
} config_map SEC(".maps");


/**
 * Helper function for computing checksum
 */
static __always_inline __u16 csum_reduce_helper(__u32 csum)
{
	csum = ((csum & 0xffff0000) >> 16) + (csum & 0xffff);
	csum = ((csum & 0xffff0000) >> 16) + (csum & 0xffff);

	return csum;
}

/**
 * Compute the checksum for tcp header
 */
static __always_inline int compute_tcp_csum(struct iphdr *ip, struct tcphdr *tcp, void * data_end)
{
  struct ipv4_psd_header psdh;
  uint32_t csum;
  int ret = 0;

  tcp->check = 0;
  csum = bpf_csum_diff(0, 0, (__be32 *)tcp, sizeof(struct tcphdr), 0);
  psdh.src_addr = ip->saddr;
	psdh.dst_addr = ip->daddr;
	psdh.zero = 0;
	psdh.proto = IPPROTO_TCP;
	psdh.len = htons(ntohs(ip->tot_len) - sizeof(struct iphdr));
	csum = bpf_csum_diff(0, 0, (__be32*)&psdh, sizeof(struct ipv4_psd_header),
			csum);
  uint32_t tcphdrlen = tcp->doff * 4;

  if (tcphdrlen == sizeof(struct tcphdr))
    goto OUT;

  /* There are TCP options */
  uint32_t *opt = (uint32_t *)(tcp + 1);
  uint32_t parsed = sizeof(struct tcphdr);
  for (int i=0;i<MAX_OPT_WORDS;i++) {
    if ((void *)(opt + 1) > data_end) {
      ret = -1;
      goto OUT;
    }

    csum = bpf_csum_diff(0, 0, (__be32 *)opt, sizeof(uint32_t), csum);

    parsed += sizeof(uint32_t);
    if (parsed == tcphdrlen)
      break;
    opt++;
  }

OUT:
  tcp->check = ~csum_reduce_helper(csum);
  return ret;
}

static uint32_t get_target_key(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port,
							  uint16_t dst_port, uint8_t protocol)
{
	/* Create "5 tuple" of function arguments, */
	uint64_t hash = ((uint64_t) src_ip << 32) | ((uint64_t) dst_ip << 16) | ((uint64_t) src_port << 8) | ((uint64_t) dst_port << 4) | ((uint64_t) protocol);
	
	/* Perform a simple hashing function. */
	hash ^= HASH_SEED;
    hash *= 0xc6a4a7935bd1e995ULL;
    hash ^= hash >> 47;
    hash *= 0xc6a4a7935bd1e995ULL;
    hash ^= hash >> 47;
    hash *= 0xc6a4a7935bd1e995ULL;

	/* Mod number of servers over which we are balancing the load. */
	return hash % NUM_SERVERS;
}


SEC("xdp")
int xdp_lb(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	if (CHECK_OUT_OF_BOUNDS(data, sizeof(struct ethhdr), data_end))
		return XDP_DROP;

	/* Extract the ethernet header. */
	struct ethhdr *eth = data;

	/* Extract the IP header. */
	struct iphdr *ip = data + sizeof(struct ethhdr);
	if (CHECK_OUT_OF_BOUNDS(ip, sizeof(struct iphdr), data_end))
		return XDP_DROP;

	/* Allow the packet to pass if not TCP. */
	if (ip->protocol != IPPROTO_TCP)
		return XDP_PASS;

	/* Extract the TCP header. */
	struct tcphdr *tcph = data + sizeof(struct ethhdr) + (ip->ihl * 4);
	if (CHECK_OUT_OF_BOUNDS(tcph, sizeof(struct tcphdr), data_end))
		return XDP_DROP;

	/* Lookup IP and MAC addresses for client, load balancer and severs. */
	__u32 local_config_key = 0;
	__u32 client_config_key = 1;
	__u32 server_config_key = get_target_key(ip->saddr, ip->daddr, tcph->source, tcph->dest, ip->protocol);

    struct ip_mac_pair *local_config = bpf_map_lookup_elem(&config_map, &local_config_key);
	struct ip_mac_pair *client_config = bpf_map_lookup_elem(&config_map, &client_config_key);
	struct ip_mac_pair *server_config = bpf_map_lookup_elem(&targets_map, &server_config_key);

	/* If any of the maps don't contain the elements we're searching for, drop the packet. */
	if (!local_config || !client_config || !server_config)
		return XDP_DROP;

	/* Set the destination IP and ethernet addresses. */
	if (ip->saddr == htonl(client_config->ip)) {
		ip->daddr = htonl(server_config->ip);
		memcpy(&eth->h_dest, server_config->mac.addr, 6);

	} else {
		ip->daddr = htonl(client_config->ip);
		memcpy(&eth->h_dest, client_config->mac.addr, 6);
	}

	/* Set the source IP and ethernet addresses. */
	ip->saddr = htonl(local_config->ip);
	memcpy(&eth->h_source, local_config->mac.addr, 6);
	
	/* Recalculate IP header checksum. */
	ip->check = 0;
	uint32_t csum = 0;
	__u16 *next_iph_u16 = (__u16 *)ip;
	for (int i = 0; i < sizeof(struct iphdr) / 2; i++) {
		csum += *next_iph_u16++;
	}
	ip->check = ~((csum & 0xffff) + (csum >> 16));

	/* Recalculate TCP header checksum. */
	compute_tcp_csum(ip, tcph, data_end);


	return XDP_TX;
}

char LICENSE[] SEC("license") = "GPL";