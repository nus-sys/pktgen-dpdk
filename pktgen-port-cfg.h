#ifndef _PKTGEN_PORT_CFG_H_
#define _PKTGEN_PORT_CFG_H_

#include <rte_ether.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>

#include "pktgen-constants.h"

#ifdef __cplusplus
extern "C" {
#endif

struct mbuf_table {
	uint16_t len;
	struct rte_mbuf *m_table[DEFAULT_PKT_BURST];
};

struct port_info {
	struct rte_ether_addr eth_addr;	/**< Port Ethernet address */

	struct rte_mempool * mp;	/**< Pool pointer for port mbufs */
	struct mbuf_table tx_mbufs;	/**< mbuf holder for transmit packets */
};

extern struct rte_mempool * mempools[MAX_NR_CORES];

void pktgen_config_ports(void);

#ifdef __cplusplus
}
#endif

#endif // _PKTGEN_PORT_CFG_H_