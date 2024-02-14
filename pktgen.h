#ifndef _PKTGEN_H_
#define _PKTGEN_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <net/if.h>
#include <fcntl.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <libgen.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <assert.h>
#include <time.h>
#include <linux/udp.h>

#include <rte_version.h>
#include <rte_config.h>

#include <rte_errno.h>
#include <rte_log.h>
#include <rte_tailq.h>
#include <rte_common.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_malloc.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_timer.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>

#include "dist/generator.h"
#include "dist/exponential_generator.h"

#include "pktgen-port-cfg.h"
#include "pktgen-constants.h"
#include "pktgen-seq.h"
#include "pktgen-inet.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	uint64_t timestamp;
	uint16_t magic;
} tstamp_t;

#define TSTAMP_MAGIC   (('T' << 8) + 's')

typedef struct {
    uint64_t * data; /**< Record for latencies */
    uint32_t num_samples;
	uint8_t pad[RTE_CACHE_LINE_SIZE - sizeof(uint64_t *) - sizeof(uint32_t)];
} latsamp_stats_t __rte_cache_aligned;

enum {
	MIN_PKT_SIZE			= 64,
	DEFAULT_NETMASK         = 0xFFFFFF00,
	DEFAULT_SRC_IP         	= (10 << 24) | (0 << 16) | (0 << 8) | 2,
	DEFAULT_DST_IP         	= (10 << 24) | (0 << 16) | (0 << 8) | 1,
	DEFAULT_SRC_PORT        = 1234,
	DEFAULT_DST_PORT        = 5678,
	DEFAULT_TTL		        = 64,
	DEFAULT_TCP_SEQ_NUMBER  = 0x012345678,
	MAX_TCP_SEQ_NUMBER      = UINT32_MAX,
	DEFAULT_TCP_ACK_NUMBER  = 0x012345690,
	MAX_TCP_ACK_NUMBER      = UINT32_MAX,
	DEFAULT_TCP_FLAGS       = ACK_FLAG,
	DEFAULT_WND_SIZE        = 8192,
	MIN_COS             	= 0,
	MAX_COS 	            = 7,
	DEFAULT_COS	         	= MIN_COS,
	MIN_TOS             	= 0,
	MAX_TOS 	            = 255,
	DEFAULT_TOS		        = MIN_TOS,
};

typedef struct pktgen_s {
	uint16_t nb_cores;  /**< Number of cores in the system */
	uint16_t nb_flows;  /**< Number of flows per core */
	
	double tx_rate; /**< Percentage rate for tx packets with fractions */

	unsigned long payload_size;

    int duration;   /**< Traffic generation duration */

    latsamp_stats_t latsamp_stats[MAX_NR_CORES];  /**< Per-core latency stats */

	uint16_t ident; /**< IPv4 ident value */
} pktgen_t;

extern pktgen_t pktgen;

struct flow_info {
	uint32_t req_id;
	uint64_t last_send; /**< Last send time */
	uint64_t interval;  /**< Interval between the last send time and the next */
	Generator<uint64_t> * arrival;  /**< Arrival interval generator */
	Generator<uint64_t> * service;  /**< Service time generator */
};

typedef struct core_info {
    int stop;
    struct timeval start;
    struct timeval last_log;
    int duration;

	struct port_info ports[RTE_MAX_ETHPORTS];   /**< Number of flows per core */

	int nb_flows;   /**< Number of flows per core */
	struct flow_info flows[MAX_NR_FLOWS];   /**< Per flow information */

    uint64_t sec_tx, sec_rx;
    uint64_t total_tx, total_rx;

    pkt_seq_t seq_pkt;  /**< Sequence of packets */

    latsamp_stats_t * lat_stat;
} core_info_t;

extern __thread core_info_t core_info;

int pktgen_launch_one_lcore(void *arg);

#ifdef __cplusplus
}
#endif

#endif  // _PKTGEN_H_ 