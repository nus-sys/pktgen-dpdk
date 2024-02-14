#include <chrono>

#include <stdint.h>
#include <time.h>
#include <sys/time.h>

#include "pktgen.h"
#include "pktgen-ether.h"
#include "pktgen-ipv4.h"
#include "pktgen-tcp.h"
#include "pktgen-udp.h"

#define MSEC_PER_SEC        1000L
#define USEC_PER_MSEC       1000L
#define USEC_PER_SEC        1000000L
#define TIMEVAL_TO_MSEC(t)  ((t.tv_sec * MSEC_PER_SEC) + (t.tv_usec / USEC_PER_MSEC))
#define TIMEVAL_TO_USEC(t)  ((t.tv_sec * USEC_PER_SEC) + (t.tv_usec))

static inline uint64_t CurrentTime_nanoseconds() {
    return std::chrono::duration_cast<std::chrono::nanoseconds>
              (std::chrono::high_resolution_clock::now().time_since_epoch()).count();
}

/**
 *
 * pktgen_port_defaults - Set all ports back to the default values.
 *
 * DESCRIPTION
 * Reset the ports back to the defaults.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
void pktgen_port_defaults(void) {
    pkt_seq_t * pkt = &core_info.seq_pkt;
    struct rte_ether_addr dst_eth_addr = {
		.addr_bytes = {0xb8, 0xce, 0xf6, 0xa8, 0x82, 0xaa}
	};

    pkt->pktSize    = MIN_PKT_SIZE;
    pkt->sport      = DEFAULT_SRC_PORT;
    pkt->dport      = DEFAULT_DST_PORT;
    pkt->ttl        = DEFAULT_TTL;
    pkt->ipProto    = IPPROTO_TCP;
    pkt->ethType    = RTE_ETHER_TYPE_IPV4;
    pkt->tos        = DEFAULT_TOS;
    pkt->tcp_flags  = DEFAULT_TCP_FLAGS;
    pkt->ip_mask    = DEFAULT_NETMASK;
    pkt->ip_src_addr.s_addr = DEFAULT_SRC_IP;
    pkt->ip_dst_addr.s_addr = DEFAULT_DST_IP;

    rte_ether_addr_copy(&dst_eth_addr, &pkt->eth_dst_addr);
}

static void pg_start_lcore(uint16_t lid) {
    uint16_t pid;
    struct flow_info * f;

    /* Get port info */
	RTE_ETH_FOREACH_DEV(pid) {
        struct rte_ether_addr port_eth_addr;
        rte_eth_macaddr_get(pid, &port_eth_addr);

        rte_ether_addr_copy(&port_eth_addr, &core_info.ports[pid].eth_addr);
        rte_ether_addr_copy(&port_eth_addr, &core_info.seq_pkt.eth_src_addr);

        core_info.ports[pid].mp = mempools[lid];
        printf("CPU %02d| Port %u MAC address: " RTE_ETHER_ADDR_PRT_FMT ", MEMPOOL: %p\n", lid, pid, RTE_ETHER_ADDR_BYTES(&port_eth_addr), core_info.ports[pid].mp);

        core_info.ports[pid].tx_mbufs.len = 0;
        for (int i = 0; i < DEFAULT_PKT_BURST; i++) {
            core_info.ports[pid].tx_mbufs.m_table[i] = NULL;
        }
    }

    pktgen_port_defaults();

    /* Init flow info */
    core_info.nb_flows = pktgen.nb_flows;
    for (int i = 0; i < core_info.nb_flows; i++) {
        f = &core_info.flows[i];
        f->last_send = CurrentTime_nanoseconds();
        f->arrival = new ExponentialGenerator(pktgen.nb_cores * pktgen.nb_flows * 1.0e6 / pktgen.tx_rate);
        f->interval = f->arrival->Next();
    }

    core_info.sec_tx = core_info.sec_rx = 0;
    core_info.total_tx = core_info.total_rx = 0;

    core_info.lat_stat = &pktgen.latsamp_stats[lid];

    gettimeofday(&core_info.start, NULL);
    core_info.last_log.tv_sec = core_info.start.tv_sec;
    core_info.last_log.tv_usec = core_info.start.tv_usec;
    core_info.duration = pktgen.duration;
    core_info.stop = 0;
}

/**
 * pg_lcore_is_running - Return stop flag
 */
static inline int32_t pg_lcore_is_running(struct timeval * now) {
	return (core_info.stop == 0) && (now->tv_sec - core_info.start.tv_sec < core_info.duration);
}

/**
 * pg_lcore_time_to_log - Check if it's time to log
 */
static inline int32_t pg_lcore_time_to_log(struct timeval * now) {
	return (core_info.stop == 0) && (now->tv_sec - core_info.last_log.tv_sec >= 1);
}

static inline tstamp_t * pktgen_tstamp_pointer(struct rte_mbuf * m) {
    tstamp_t * tstamp;
    char *p;

    p = rte_pktmbuf_mtod(m, char *);

    m->data_len = m->pkt_len = ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr) + pktgen.payload_size;
    m->next = NULL;
    m->nb_segs = 1;

    p += sizeof(struct rte_ether_addr);

    p += sizeof(struct rte_ipv4_hdr);
    p += (core_info.seq_pkt.ipProto == IPPROTO_UDP) ? sizeof(struct rte_udp_hdr) : sizeof(struct rte_tcp_hdr);

    /* Force pointer to be aligned correctly */
    // p = RTE_PTR_ALIGN_CEIL(p, sizeof(uint64_t));

    tstamp = (tstamp_t *)p;

    return tstamp;
}

static inline void pktgen_tstamp_apply(struct rte_mbuf * pkt) {
    tstamp_t * tstamp;

    tstamp = pktgen_tstamp_pointer(pkt);

    tstamp->timestamp = CurrentTime_nanoseconds();
    tstamp->magic     = TSTAMP_MAGIC;
}

static void pktgen_recv_tstamp(struct rte_mbuf **pkts, uint16_t nb_pkts) {
    uint64_t now = CurrentTime_nanoseconds();
    uint64_t lat;
    latsamp_stats_t * stat = core_info.lat_stat;

    for (int i = 0; i < nb_pkts; i++) {
        tstamp_t * tstamp;
        tstamp = pktgen_tstamp_pointer(pkts[i]);
        if (tstamp->magic == TSTAMP_MAGIC) {
            lat = now - tstamp->timestamp;
            if (stat->num_samples < MAX_LATENCY_ENTRIES) {
                stat->data[(stat->num_samples)++] = lat;
            }
        }
    }
}

/**
 *
 * pktgen_packet_ctor - Construct a complete packet with all headers and data.
 *
 * DESCRIPTION
 * Construct a packet type based on the arguments passed with all headers.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
void pktgen_packet_ctor(void) {
    pkt_seq_t * pkt = &core_info.seq_pkt;
    struct rte_ether_hdr * eth = (struct rte_ether_hdr *)&pkt->hdr.eth;
    char *l3_hdr = (char *)&eth[1]; /* Point to l3 hdr location for GRE header */

    /* Fill in the pattern for data space. */
    // pktgen_fill_pattern((uint8_t *)&pkt->hdr, (sizeof(pkt_hdr_t) + sizeof(pkt->pad)), info->fill_pattern_type, info->user_pattern);

    l3_hdr = pktgen_ether_hdr_ctor(pkt, eth);

    if (likely(pkt->ethType == RTE_ETHER_TYPE_IPV4)) {
        if (likely(pkt->ipProto == IPPROTO_TCP)) {
            /* Construct the TCP header */
            pktgen_tcp_hdr_ctor(pkt, l3_hdr);

            /* IPv4 Header constructor */
            pktgen_ipv4_ctor(pkt, l3_hdr);
        } else if (pkt->ipProto == IPPROTO_UDP) {
            /* Construct the UDP header */
            pktgen_udp_hdr_ctor(pkt, l3_hdr);

            /* IPv4 Header constructor */
            pktgen_ipv4_ctor(pkt, l3_hdr);
        }
    } else if (pkt->ethType == RTE_ETHER_TYPE_ARP) {
        /* Start from Ethernet header */
        struct rte_arp_hdr * arp = (struct rte_arp_hdr *)l3_hdr;

        arp->arp_hardware = htons(1);
        arp->arp_protocol = htons(RTE_ETHER_TYPE_IPV4);
        arp->arp_hlen = RTE_ETHER_ADDR_LEN;
        arp->arp_plen = 4;

        /* make request/reply operation selectable by user */
        arp->arp_opcode = htons(2);

        rte_ether_addr_copy(&pkt->eth_src_addr, (struct rte_ether_addr *)&arp->arp_data.arp_sha);
        *((uint32_t *)&arp->arp_data.arp_sha) = htonl(pkt->ip_src_addr.s_addr);

        rte_ether_addr_copy(&pkt->eth_dst_addr, (struct rte_ether_addr *)&arp->arp_data.arp_tha);
        *((uint32_t *)&arp->arp_data.arp_tip) = htonl(pkt->ip_dst_addr.s_addr);
    } else {
        printf("Unknown EtherType 0x%04x", pkt->ethType);
    }
}

/**
 *
 * pktgen_receive_pkts - Main receive routine for packets of a port.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
static void pktgen_receive_pkts(uint16_t pid, uint16_t lid, struct rte_mbuf *pkts_burst[], uint16_t nb_pkts) {
    uint16_t qid, nb_rx;
    qid = lid;

    /*
     * Read packet from RX queues and free the mbufs
     */
    if ((nb_rx = rte_eth_rx_burst(pid, qid, pkts_burst, nb_pkts)) == 0) {
        return;
    }

    core_info.sec_rx += nb_rx;

    pktgen_recv_tstamp(pkts_burst, nb_rx);

    rte_pktmbuf_free_bulk(pkts_burst, nb_rx);
}

/**
 * pktgen_setup_packets - Setup the default packets to be sent.
 */
static int pktgen_setup_packets(uint16_t pid, uint16_t lid, struct flow_info * f) {    
    struct mbuf_table * mbuf = &core_info.ports[pid].tx_mbufs;
    struct rte_mbuf * m;
    uint8_t * pkt;

    m = rte_pktmbuf_alloc(core_info.ports[pid].mp);
    if (unlikely(m == NULL)) {
        printf("No packet buffers found\n");
        return 0;
    }

    pkt = rte_pktmbuf_mtod(m, uint8_t *);

    m->data_len = m->pkt_len = ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr) + pktgen.payload_size;
    m->next = NULL;
    m->nb_segs = 1;

    pktgen_packet_ctor();

    mbuf->m_table[mbuf->len++] = m;

    return 1;
}

/**
 *
 * pktgen_send_pkts - Main send routine for packets of a port.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
static void pktgen_send_pkts(uint16_t pid, uint16_t lid) {
    struct mbuf_table * mbuf = &core_info.ports[pid].tx_mbufs;
    uint16_t qid = lid;
    int ret;

    /* Transmit the packet. */
    if (mbuf->len > 0) {
        ret = rte_eth_tx_burst(pid, qid, mbuf->m_table, mbuf->len);
        if (ret > 0) {
            core_info.sec_tx += ret;
        }

        if (ret < mbuf->len){
            rte_pktmbuf_free_bulk(mbuf->m_table, mbuf->len - ret);
        }

        mbuf->len = 0;
    }    
}

/**
 *
 * pktgen_launch_one_lcore - Launch a single logical core thread.
 *
 * @return: N/A
 */
int pktgen_launch_one_lcore(void * arg __rte_unused) {
    uint16_t pid;
    uint16_t lid = rte_lcore_id();
    struct timeval now;
    uint64_t elapsed;
    double sec_tx_rate, sec_rx_rate;
    struct rte_mbuf *pkts_burst[DEFAULT_PKT_BURST];
    int tx_cnt;
    uint64_t curr_ns;
    struct flow_info * f;

    pg_start_lcore(lid);

    printf("CPU %02d| Start PKTGEN...\n", lid);

    do {
        tx_cnt = 0;

        gettimeofday(&now, NULL);

        if (pg_lcore_time_to_log(&now)) {
            elapsed = TIMEVAL_TO_MSEC(now) - TIMEVAL_TO_MSEC(core_info.last_log);
            sec_tx_rate = core_info.sec_tx / elapsed;
            sec_rx_rate = core_info.sec_rx / elapsed;

            printf("CPU %02d| TX: %4.2f (KPPS), RX: %4.2f (KPPS)\n", lid, sec_tx_rate, sec_rx_rate);

            core_info.total_rx += core_info.sec_rx;
            core_info.total_tx += core_info.sec_tx;

            core_info.sec_tx = core_info.sec_rx = 0;

            core_info.last_log.tv_sec = now.tv_sec;
            core_info.last_log.tv_usec = now.tv_usec;
        }

        curr_ns = CurrentTime_nanoseconds();
    	RTE_ETH_FOREACH_DEV(pid) {
            pktgen_receive_pkts(pid, lid, pkts_burst, DEFAULT_PKT_BURST);

            for (int i = 0; i < core_info.nb_flows; i++) {
                f = &core_info.flows[i];
                if (curr_ns >= f->last_send + f->interval) {
                    f->last_send = curr_ns;
                    f->interval = f->arrival->Next();
                    if (pktgen_setup_packets(pid, lid, f) > 0) {
                        tx_cnt++;
                    }
                }
            }
            if (tx_cnt) {
                pktgen_send_pkts(pid, lid);
            }
        }
    } while (pg_lcore_is_running(&now));

    return 0;
}