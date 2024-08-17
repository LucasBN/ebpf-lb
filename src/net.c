#include <rte_arp.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>

#include <base.h>
#include <net-config.h>
#include <zlib.h>

#define NUM_SERVERS 2
#define CLIENT_IP 0xA000001

static int eth_out(struct rte_mbuf *pkt_buf, uint16_t h_proto,
				   struct rte_ether_addr *dst_haddr, uint16_t iplen)
{
	/* fill the ethernet header */
	struct rte_ether_hdr *hdr =
		rte_pktmbuf_mtod(pkt_buf, struct rte_ether_hdr *);

	hdr->dst_addr = *dst_haddr;
	memcpy(&hdr->src_addr, local_mac, 6);
	hdr->ether_type = rte_cpu_to_be_16(h_proto);

	/* Print the packet */
	// pkt_dump(pkt_buf);

	/* enqueue the packet */
	pkt_buf->data_len = iplen + sizeof(struct rte_ether_hdr);
	pkt_buf->pkt_len = pkt_buf->data_len;
	dpdk_out(pkt_buf);

	return 0;
}

static void arp_reply(struct rte_mbuf *pkt, struct rte_arp_hdr *arph)
{
	arph->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);

	/* fill arp body */
	arph->arp_data.arp_tip = arph->arp_data.arp_sip;
	arph->arp_data.arp_sip = rte_cpu_to_be_32(local_ip);

	arph->arp_data.arp_tha = arph->arp_data.arp_sha;
	memcpy(&arph->arp_data.arp_sha, local_mac, 6);

	eth_out(pkt, RTE_ETHER_TYPE_ARP, &arph->arp_data.arp_tha,
			sizeof(struct rte_arp_hdr));
}

static void arp_in(struct rte_mbuf *pkt)
{
	struct rte_arp_hdr *arph = rte_pktmbuf_mtod_offset(
		pkt, struct rte_arp_hdr *, sizeof(struct rte_ether_hdr));

	/* process only arp for this address */
	if (rte_be_to_cpu_32(arph->arp_data.arp_tip) != local_ip)
		goto OUT;

	switch (rte_be_to_cpu_16(arph->arp_opcode))
	{
	case RTE_ARP_OP_REQUEST:
		arp_reply(pkt, arph);
		break;
	default:
		fprintf(stderr, "apr: Received unknown ARP op");
		goto OUT;
	}

	return;

OUT:
	rte_pktmbuf_free(pkt);
	return;
}

static struct rte_ether_addr *get_mac_for_ip(uint32_t ip)
{
	return &mac_addresses[(ip & 0xf) - 1];
}

static uint32_t get_target_ip(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port,
							  uint16_t dst_port, uint8_t protocol)
{
	/* Create "5 tuple" of function arguments, */
	uint64_t hash = ((uint64_t)src_ip << 32) | ((uint64_t)dst_ip << 16) | ((uint64_t)src_port << 8) | ((uint64_t)dst_port << 4) | ((uint64_t)protocol);

	uint8_t bytes[8];
	memcpy(bytes, &hash, sizeof(uint64_t));
	uint32_t crc = crc32(0L, Z_NULL, 0);

	/* Hash on 5 tuple (mod number of servers over which we are balancing the load). */
	return targets[crc32(crc, bytes, sizeof(uint64_t)) % NUM_SERVERS];
}

static void lb_in(struct rte_mbuf *pkt_buf)
{
	/* Extract IPv4 header. */
	struct rte_ipv4_hdr *iph = rte_pktmbuf_mtod_offset(
		pkt_buf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));

	/* Extract TCP header. */
	struct rte_tcp_hdr *tcp_hdr = (struct rte_tcp_hdr *)((char *)iph + sizeof(struct rte_ipv4_hdr));

	/* Set the destination IP address. */
	uint32_t target_ip = 0x0;
	if (iph->src_addr == rte_cpu_to_be_32(CLIENT_IP))
	{
		target_ip = get_target_ip(iph->src_addr, iph->dst_addr, tcp_hdr->src_port, tcp_hdr->dst_port, iph->next_proto_id);
	}
	else
	{
		target_ip = CLIENT_IP;
	}
	iph->dst_addr = rte_cpu_to_be_32(target_ip);

	/* Set source IP address to our own address. */
	iph->src_addr = rte_cpu_to_be_32(local_ip);

	/* Fix the tcp and ip checksums */
	iph->hdr_checksum = 0;
	iph->hdr_checksum = rte_ipv4_cksum(iph);

	tcp_hdr->cksum = 0;
	tcp_hdr->cksum = rte_ipv4_udptcp_cksum(iph, tcp_hdr);

	/* Send the packet out */
	eth_out(pkt_buf, RTE_ETHER_TYPE_IPV4, get_mac_for_ip(target_ip), pkt_buf->data_len);
}

void eth_in(struct rte_mbuf *pkt_buf)
{
	unsigned char *payload = rte_pktmbuf_mtod(pkt_buf, unsigned char *);
	struct rte_ether_hdr *hdr = (struct rte_ether_hdr *)payload;

	if (hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP))
	{
		arp_in(pkt_buf);
	}
	else if (hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
	{
		lb_in(pkt_buf);
	}
	else
	{
		// printf("Unknown ether type: %" PRIu16 "\n",
		//	   rte_be_to_cpu_16(hdr->ether_type));
		rte_pktmbuf_free(pkt_buf);
	}
}
