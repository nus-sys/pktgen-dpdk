#include "pktgen.h"

#include "pktgen-udp.h"

/**
 *
 * pktgen_udp_hdr_ctor - UDP header constructor routine.
 *
 * DESCRIPTION
 * Construct the UDP header in a packer buffer.
 *
 * RETURNS: next header location
 *
 * SEE ALSO:
 */
void * pktgen_udp_hdr_ctor(pkt_seq_t * pkt, void * hdr) {
	uint16_t tlen;
    struct rte_ipv4_hdr * ipv4 = (struct rte_ipv4_hdr *)hdr;
    struct rte_udp_hdr * udp = (struct rte_udp_hdr *)&ipv4[1];

    /* Create the UDP header */
    ipv4->src_addr = htonl(pkt->ip_src_addr.s_addr);
    ipv4->dst_addr = htonl(pkt->ip_dst_addr.s_addr);

    ipv4->version_ihl = (IPv4_VERSION << 4) | (sizeof(struct rte_ipv4_hdr) / 4);
    tlen = pkt->pktSize - pkt->ether_hdr_size;
    ipv4->total_length = htons(tlen);
    ipv4->next_proto_id = pkt->ipProto;

    tlen = pkt->pktSize - (pkt->ether_hdr_size + sizeof(struct rte_ipv4_hdr));
    udp->dgram_len = htons(tlen);
    udp->src_port = htons(pkt->sport);
    udp->dst_port = htons(pkt->dport);

    udp->dgram_cksum = 0;
    udp->dgram_cksum = rte_ipv4_udptcp_cksum(ipv4, (const void *)udp);
    if (udp->dgram_cksum == 0) {
        udp->dgram_cksum = 0xFFFF;
    }

	/* Return the original pointer for IP ctor */
	return hdr;
}
