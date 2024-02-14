#ifndef _PKTGEN_ETHER_H_
#define _PKTGEN_ETHER_H_

#include <rte_ether.h>

#include "pktgen-seq.h"

#ifdef __cplusplus
extern "C" {
#endif

char * pktgen_ether_hdr_ctor(pkt_seq_t * pkt, struct rte_ether_hdr * eth);

#ifdef __cplusplus
}
#endif

#endif  // _PKTGEN_ETHER_H_