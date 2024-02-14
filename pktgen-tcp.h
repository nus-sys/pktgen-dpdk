#ifndef _PKTGEN_TCP_H_
#define _PKTGEN_TCP_H_

#include "pktgen-seq.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 *
 * pktgen_tcp_hdr_ctor - TCP header constructor routine.
 *
 * DESCRIPTION
 * Construct a TCP header in the packet buffer provided.
 *
 * RETURNS: Next header location
 *
 * SEE ALSO:
 */
void * pktgen_tcp_hdr_ctor(pkt_seq_t * pkt, void * hdr);

#ifdef __cplusplus
}
#endif

#endif  // _PKTGEN_TCP_H_