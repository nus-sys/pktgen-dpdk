#ifndef _PKTGEN_SEQ_H_
#define _PKTGEN_SEQ_H_

#include <rte_ether.h>

#include "pktgen-constants.h"
#include "pktgen-inet.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct pkt_seq_s {
	uint16_t pktSize;	/**< Size of packet in bytes */

    /* Packet type and information */
	struct rte_ether_addr eth_dst_addr;	/**< Destination Ethernet address */
	struct rte_ether_addr eth_src_addr;	/**< Source Ethernet address */
	uint16_t ether_hdr_size;	/**< Size of Ethernet header in packet for VLAN ID */

    struct in_addr ip_src_addr; /**< Source IPv4 address also used for IPv6 */
    struct in_addr ip_dst_addr; /**< Destination IPv4 address */
	uint32_t ip_mask;			/**< IPv4 Netmask value */
	uint8_t tos;	/**< tos value if used */
	uint8_t ttl;	/**< TTL value for IPv4 headers */

    uint16_t sport;		/**< Source port value */
	uint16_t dport;		/**< Destination port value */
	uint16_t ethType;	/**< IPv4 or IPv6 */
	uint16_t ipProto;	/**< TCP or UDP or ICMP */

    uint32_t tcp_seq;   /**< TCP sequence number */
	uint32_t tcp_ack;   /**< TCP acknowledge number*/
	uint8_t tcp_flags;	/**< TCP flags value */

	uint64_t ol_flags;	/**< offload flags */
    pkt_hdr_t hdr __rte_cache_aligned;	/**< Packet header data */
	uint8_t pad[DEFAULT_MBUF_SIZE - sizeof(pkt_hdr_t)];
} pkt_seq_t __rte_cache_aligned;

#ifdef __cplusplus
}
#endif

#endif  // _PKTGEN_SEQ_H_