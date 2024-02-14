#ifndef _PKTGEN_INET_H_
#define _PKTGEN_INET_H_

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>

#define IPv4_VERSION    4

enum {
	URG_FLAG = 0x20, 
	ACK_FLAG = 0x10, 
	PSH_FLAG = 0x08, 
	RST_FLAG = 0x04,
	SYN_FLAG = 0x02, 
	FIN_FLAG = 0x01
};

/* IP overlay header for the pseudo header */
typedef struct ipOverlay_s {
	uint32_t node[2];
	uint8_t pad0;   /* overlays ttl */
	uint8_t proto;  /* Protocol type */
	uint16_t len;   /* Protocol length, overlays cksum */
	uint32_t src;	/* Source address */
	uint32_t dst;	/* Destination address */
} __attribute__((__packed__)) ipOverlay_t;

/* The TCP/IPv4 Pseudo header */
typedef struct tcpip_s {
	ipOverlay_t ip;	/* IPv4 overlay header */
	struct rte_tcp_hdr tcp;	/* TCP header for protocol */
} __attribute__((__packed__)) tcpip_t;

/* The UDP/IP Pseudo header */
typedef struct udpip_s {
	ipOverlay_t ip;	/* IPv4 overlay header */
	struct rte_udp_hdr udp;	/* UDP header for protocol */
} __attribute__((__packed__)) udpip_t;

typedef struct pkt_hdr_s {
	struct rte_ether_hdr eth;   /**< Ethernet header */
	union {
		struct rte_ipv4_hdr ipv4;   /**< IPv4 Header */
		tcpip_t tip;    /**< TCP + IPv4 Headers */
		udpip_t uip;    /**< UDP + IPv4 Headers */
		uint64_t pad[8];    /**< Length of structures */
	} __attribute__((packed)) u;
} pkt_hdr_t;

#endif  // _PKTGEN_INET_H_