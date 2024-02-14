#include "pktgen-ether.h"
#include "pktgen-seq.h"
#include "pktgen-port-cfg.h"

/**
 *
 * pktgen_ether_hdr_ctor - Ethernet header constructor routine.
 *
 * DESCRIPTION
 * Construct the ethernet header for a given packet buffer.
 *
 * RETURNS: Pointer to memory after the ethernet header.
 *
 * SEE ALSO:
 */

char * pktgen_ether_hdr_ctor(pkt_seq_t * pkt, struct rte_ether_hdr * eth) {
    /* src and dest addr */
    rte_ether_addr_copy(&pkt->eth_src_addr, &eth->src_addr);
    rte_ether_addr_copy(&pkt->eth_dst_addr, &eth->dst_addr);

    /* normal ethernet header */
    eth->ether_type     = htons(pkt->ethType);
    pkt->ether_hdr_size = sizeof(struct rte_ether_hdr);

    return (char *)(eth + 1);
}