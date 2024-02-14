#ifndef _PKTGEN_UDP_H_
#define _PKTGEN_UDP_H_

#include "pktgen-seq.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 *
 * pktgen_udp_hdr_ctor - UDP header constructor routine.
 *
 * DESCRIPTION
 * Construct the UDP header in a packer buffer.
 *
 * RETURNS: Next header location
 *
 * SEE ALSO:
 */

void * pktgen_udp_hdr_ctor(pkt_seq_t *pkt, void *hdr);

#ifdef __cplusplus
}
#endif

#endif  // _PKTGEN_UDP_H_