#include "pktgen.h"

#include "pktgen-tcp.h"

/**
 *
 * pktgen_tcp_hdr_ctor - TCP header constructor routine.
 *
 * DESCRIPTION
 * Construct a TCP header in the packet buffer provided.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
void * pktgen_tcp_hdr_ctor(pkt_seq_t * pkt, void * hdr) {
	uint16_t tlen;
    struct rte_ipv4_hdr * ipv4 = (struct rte_ipv4_hdr *)hdr;
    struct rte_tcp_hdr * tcp = (struct rte_tcp_hdr *)&ipv4[1];

    /* Create the TCP header */
    ipv4->src_addr = htonl(pkt->ip_src_addr.s_addr);
    ipv4->dst_addr = htonl(pkt->ip_dst_addr.s_addr);

    ipv4->version_ihl = (IPv4_VERSION << 4) | (sizeof(struct rte_ipv4_hdr) / 4);
    tlen = pkt->pktSize - pkt->ether_hdr_size;
    ipv4->total_length = htons(tlen);
    ipv4->next_proto_id = pkt->ipProto;

    tcp->src_port = htons(pkt->sport);
    tcp->dst_port = htons(pkt->dport);
    tcp->sent_seq = htonl(pkt->tcp_seq);
    tcp->recv_ack = htonl(pkt->tcp_ack);
    tcp->data_off = ((sizeof(struct rte_tcp_hdr) / sizeof(uint32_t)) << 4);	/* Offset in words */
    tcp->tcp_flags = pkt->tcp_flags;
    tcp->rx_win = htons(DEFAULT_WND_SIZE);
    tcp->tcp_urp = 0;

    tcp->cksum = 0;
    tcp->cksum = rte_ipv4_udptcp_cksum(ipv4, (const void *)tcp);
}