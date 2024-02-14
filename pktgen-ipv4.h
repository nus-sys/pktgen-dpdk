#ifndef _PKTGEN_IPV4_H_
#define _PKTGEN_IPV4_H_

#include "pktgen-seq.h"

#ifdef __cplusplus
extern "C" {
#endif

void pktgen_ipv4_ctor(pkt_seq_t * pkt, void * hdr);

#ifdef __cplusplus
}
#endif

#endif  // _PKTGEN_IPV4_H_