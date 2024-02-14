#include <arpa/inet.h>

#include "pktgen.h"
#include "pktgen-ipv4.h"

/**
 *
 * pktgen_ipv4_ctor - Construct the IPv4 header for a packet
 *
 * DESCRIPTION
 * Constructor for the IPv4 header for a given packet.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
void pktgen_ipv4_ctor(pkt_seq_t * pkt, void * hdr) {
    uint16_t tlen;
    struct rte_ipv4_hdr * ip = (struct rte_ipv4_hdr *)hdr;

    /* IPv4 Header constructor */
    tlen = pkt->pktSize - pkt->ether_hdr_size;

    /* Zero out the header space */
    memset((char *)ip, 0, sizeof(struct rte_ipv4_hdr));

    ip->version_ihl = (IPv4_VERSION << 4) | (sizeof(struct rte_ipv4_hdr) / 4);

    ip->total_length    = htons(tlen);
    ip->time_to_live    = pkt->ttl;
    ip->type_of_service = pkt->tos;

    pktgen.ident        += 27; /* bump by a prime number */
    ip->packet_id       = htons(pktgen.ident);
    ip->fragment_offset = 0;
    ip->next_proto_id   = pkt->ipProto;
    ip->src_addr        = htonl(pkt->ip_src_addr.s_addr);
    ip->dst_addr        = htonl(pkt->ip_dst_addr.s_addr);
    ip->hdr_checksum    = 0;
    ip->hdr_checksum    = rte_ipv4_cksum((const struct rte_ipv4_hdr *)ip);
}