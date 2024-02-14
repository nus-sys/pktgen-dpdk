#include "pktgen-constants.h"
#include "pktgen-port-cfg.h"
#include "pktgen.h"

static struct rte_eth_conf port_conf = {
	.rxmode = {
        .mq_mode    = ETH_MQ_RX_NONE,
        .split_hdr_size = 0,
    },
    .txmode = {
        .mq_mode    = ETH_MQ_TX_NONE,
    },
};

struct rte_mempool * mempools[MAX_NR_CORES];

#define FULL_IP_MASK   0xffffffff /* full mask */
#define EMPTY_IP_MASK  0x0 /* empty mask */

#define FULL_PORT_MASK   0xffff /* full mask */
#define PART_PORT_MASK   0xff00 /* partial mask */
#define EMPTY_PORT_MASK  0x0 /* empty mask */

#define MAX_PATTERN_NUM		4
#define MAX_ACTION_NUM		2

static void pktgen_create_tcp_flow(int pid, uint16_t sport, uint16_t queueid) {
	struct rte_flow_error error;
	struct rte_flow_attr attr;
	struct rte_flow_item pattern[MAX_PATTERN_NUM];
	struct rte_flow_action action[MAX_ACTION_NUM];
	struct rte_flow * flow = NULL;
	struct rte_flow_action_queue queue = { .index = queueid };
	struct rte_flow_item_ipv4 ip_spec;
	struct rte_flow_item_ipv4 ip_mask;
	struct rte_flow_item_tcp tcp_spec;
	struct rte_flow_item_tcp tcp_mask;
	int res;

    memset(pattern, 0, sizeof(pattern));
    memset(action, 0, sizeof(action));

    /*
    * set the rule attribute.
    * in this case only ingress packets will be checked.
    */
    memset(&attr, 0, sizeof(struct rte_flow_attr));
    attr.ingress = 1;
    attr.priority = 0;

    /*
    * create the action sequence.
    * one action only,  move packet to queue
    */
    action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
    action[0].conf = &queue;
    action[1].type = RTE_FLOW_ACTION_TYPE_END;

    /*
    * set the first level of the pattern (ETH).
    */
    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;

    /*
    * setting the second level of the pattern (IP).
    */
    memset(&ip_spec, 0, sizeof(struct rte_flow_item_ipv4));
    memset(&ip_mask, 0, sizeof(struct rte_flow_item_ipv4));
    pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
    pattern[1].spec = &ip_spec;
    pattern[1].mask = &ip_mask;

    /*
    * setting the third level of the pattern (TCP).
    */
    memset(&tcp_spec, 0, sizeof(struct rte_flow_item_tcp));
    memset(&tcp_mask, 0, sizeof(struct rte_flow_item_tcp));
    tcp_spec.hdr.dst_port = htons(sport);
    tcp_mask.hdr.dst_port = htons(PART_PORT_MASK);
    pattern[2].type = RTE_FLOW_ITEM_TYPE_TCP;
    pattern[2].spec = &tcp_spec;
    pattern[2].mask = &tcp_mask;

    /* the final level must be always type end */
    pattern[3].type = RTE_FLOW_ITEM_TYPE_END;

    printf("Direct TCP flow to port %x via queue %d\n", sport & PART_PORT_MASK, queueid);

    res = rte_flow_validate(pid, &attr, pattern, action, &error);
    if (!res) {
retry:
        flow = rte_flow_create(pid, &attr, pattern, action, &error);
        if (!flow) {
            rte_flow_flush(pid, &error);
            goto retry;
        }
    } else {
        printf("control: invalid flow rule! msg: %s\n", error.message);
    }
}

static void pktgen_create_udp_flow(int pid, uint16_t sport, uint16_t queueid) {
	struct rte_flow_error error;
	struct rte_flow_attr attr;
	struct rte_flow_item pattern[MAX_PATTERN_NUM];
	struct rte_flow_action action[MAX_ACTION_NUM];
	struct rte_flow * flow = NULL;
	struct rte_flow_action_queue queue = { .index = queueid };
	struct rte_flow_item_ipv4 ip_spec;
	struct rte_flow_item_ipv4 ip_mask;
	struct rte_flow_item_udp udp_spec;
	struct rte_flow_item_udp udp_mask;
	int res;

    memset(pattern, 0, sizeof(pattern));
    memset(action, 0, sizeof(action));

    /*
    * set the rule attribute.
    * in this case only ingress packets will be checked.
    */
    memset(&attr, 0, sizeof(struct rte_flow_attr));
    attr.ingress = 1;
    attr.priority = 0;

    /*
    * create the action sequence.
    * one action only,  move packet to queue
    */
    action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
    action[0].conf = &queue;
    action[1].type = RTE_FLOW_ACTION_TYPE_END;

    /*
    * set the first level of the pattern (ETH).
    */
    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;

    /*
    * setting the second level of the pattern (IP).
    */
    memset(&ip_spec, 0, sizeof(struct rte_flow_item_ipv4));
    memset(&ip_mask, 0, sizeof(struct rte_flow_item_ipv4));
    pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
    pattern[1].spec = &ip_spec;
    pattern[1].mask = &ip_mask;

    /*
    * setting the third level of the pattern (UDP).
    */
    memset(&udp_spec, 0, sizeof(struct rte_flow_item_udp));
    memset(&udp_mask, 0, sizeof(struct rte_flow_item_udp));
    udp_spec.hdr.dst_port = htons(sport);
    udp_mask.hdr.dst_port = htons(PART_PORT_MASK);
    pattern[2].type = RTE_FLOW_ITEM_TYPE_UDP;
    pattern[2].spec = &udp_spec;
    pattern[2].mask = &udp_mask;

    /* the final level must be always type end */
    pattern[3].type = RTE_FLOW_ITEM_TYPE_END;

    printf("Direct UDP flow to port %x via queue %d\n", sport & PART_PORT_MASK, queueid);

    res = rte_flow_validate(pid, &attr, pattern, action, &error);
    if (!res) {
retry:
        flow = rte_flow_create(pid, &attr, pattern, action, &error);
        if (!flow) {
            rte_flow_flush(pid, &error);
            goto retry;
        }
    } else {
        printf("control: invalid flow rule! msg: %s\n", error.message);
    }
}

/**
 * pktgen_create_flow - Create a flow rule in hardware
 * 
 * @param pid: port ID
 * @param proto: Transmit layer protocol
 * @param sport: source (local) port
 * @param queueid: queue that this flow will be directed to
 * @return: N/A
 */
void pktgen_create_flow(int pid, uint16_t proto, uint16_t sport, uint16_t queueid) {
    switch (proto) {
    case IPPROTO_TCP:
        pktgen_create_tcp_flow(pid, sport, queueid);
        break;

    case IPPROTO_UDP:
        pktgen_create_udp_flow(pid, sport, queueid);
        break;

    default:
        printf("Unknown protocol! (%d)\n", proto);
        break;
    }
}

/**
 * pktgen_config_ports - Configure the ports for RX and TX
 * 
 * @param: N/A
 * @return: N/A
 */
void pktgen_config_ports(void) {
    int ret, nb_mbufs;
    uint16_t pid;
    char name[RTE_MEMZONE_NAMESIZE];
    uint16_t nb_rxd = DEFAULT_RX_DESC;
    uint16_t nb_txd = DEFAULT_TX_DESC;
    int nb_total = 0, nb_avail = 0;

    nb_total = rte_eth_dev_count_total();
    nb_avail = rte_eth_dev_count_avail();

    if (nb_total < 1) {
        perror("No available dev!");
        rte_exit(EXIT_FAILURE, "No dev detected! (total: %d)\n", nb_total);
    }

    if (nb_avail != 1) {
        rte_exit(EXIT_FAILURE, "Specify only one dev! (avail: %d)\n", nb_avail);
    }

    nb_mbufs = RTE_MAX(DEFAULT_RX_DESC + DEFAULT_TX_DESC + DEFAULT_PKT_BURST + RTE_MEMPOOL_CACHE_MAX_SIZE, 8192U);

    /* Create mbuf pool for each core */
    for (int i = 0; i < pktgen.nb_cores; i++) {
        sprintf(name, "mbuf_pool_%d", i);
        mempools[i] = rte_pktmbuf_pool_create(name, nb_mbufs,
            RTE_MEMPOOL_CACHE_MAX_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
        if (!mempools[i]) {
            rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");
        } else {
            printf("MBUF pool for CORE %u: %p...\n", i, mempools[i]);
        }
    }

    /* Initialise each port */
	RTE_ETH_FOREACH_DEV(pid) {
        struct rte_eth_rxconf rxq_conf;
		struct rte_eth_txconf txq_conf;
		struct rte_eth_conf local_port_conf = port_conf;
		struct rte_eth_dev_info dev_info;

        printf("Initializing port %u...\n", pid);
		fflush(stdout);

		ret = rte_eth_dev_info_get(pid, &dev_info);
		if (ret != 0) {
			rte_exit(EXIT_FAILURE, "Error during getting device (port %u) info: %s\n", pid, strerror(-ret));
        }

		if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE) {
			local_port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
        }

        local_port_conf.rx_adv_conf.rss_conf.rss_hf &= dev_info.flow_type_rss_offloads;
        if (local_port_conf.rx_adv_conf.rss_conf.rss_hf != port_conf.rx_adv_conf.rss_conf.rss_hf) {
            printf("Port %u modified RSS hash function based on hardware support,"
                "requested:%#lx configured:%#lx\n",
                pid,
                port_conf.rx_adv_conf.rss_conf.rss_hf,
                local_port_conf.rx_adv_conf.rss_conf.rss_hf);
        }

        /* Configure the number of queues for a port. */
		ret = rte_eth_dev_configure(pid, pktgen.nb_cores, pktgen.nb_cores, &local_port_conf);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n", ret, pid);
        }
		/* >8 End of configuration of the number of queues for a port. */

		ret = rte_eth_dev_adjust_nb_rx_tx_desc(pid, &nb_rxd, &nb_txd);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE, "Cannot adjust number of descriptors: err=%d, port=%u\n", ret, pid);
        }

		fflush(stdout);

        /* init ont RX queue and TX queue for each core */
		rxq_conf = dev_info.default_rxconf;
		rxq_conf.offloads = local_port_conf.rxmode.offloads;

        txq_conf = dev_info.default_txconf;
		txq_conf.offloads = local_port_conf.txmode.offloads;

        for (int i = 0; i < pktgen.nb_cores; i++) {
            /* RX queue setup. 8< */
            ret = rte_eth_rx_queue_setup(pid, i, nb_rxd, rte_eth_dev_socket_id(pid), &rxq_conf, mempools[i]);
            if (ret < 0) {
                rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u\n", ret, pid);
            }

            ret = rte_eth_tx_queue_setup(pid, i, nb_txd, rte_eth_dev_socket_id(pid), &txq_conf);
            if (ret < 0) {
                rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=%u\n", ret, pid);
            }
        }
		/* >8 End of queue setup. */

		fflush(stdout);

        ret = rte_eth_dev_set_ptypes(pid, RTE_PTYPE_UNKNOWN, NULL, 0);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE, "Failed to disable Ptype parsing:err=%d, port=%u\n", ret, pid);
        }

        /* Start device */
		ret = rte_eth_dev_start(pid);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n", ret, pid);
        }

		printf("Port %d initialization done\n", pid);
        ret = rte_eth_promiscuous_enable(pid);
        if (ret != 0) {
            rte_exit(EXIT_FAILURE, "rte_eth_promiscuous_enable:err=%s, port=%u\n", rte_strerror(-ret), pid);
        }
    }
}
