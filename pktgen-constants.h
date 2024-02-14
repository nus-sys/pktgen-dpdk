#ifndef _PKTGEN_CONSTANTS_H_
#define _PKTGEN_CONSTANTS_H_

#include <rte_mbuf.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
	DEFAULT_PKT_BURST       = 32,	/* Increasing this number consumes memory very fast */
	DEFAULT_RX_DESC         = 1024,
	DEFAULT_TX_DESC         = 1024,

	MAX_NR_FLOWS			= 32,
	MAX_NR_CORES			= 16,
	NUM_Q                   = 16,
	PAYLOAD_SIZE			= 128,

	MAX_LATENCY_ENTRIES		= 128 * 1024,	/**< 128K */

	BUF_SIZE            	= 2048,
	DEFAULT_MBUF_SIZE		= (BUF_SIZE + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM),
};

#ifdef __cplusplus
}
#endif

#endif  // _PKTGEN_CONSTANTS_H_