/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <netinet/in.h>
#include <netinet/ip6.h>

#include <inet/common.h>
#include <inet/ipclassifier.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/mib2.h>
#include <inet/nd.h>
#include <inet/optcom.h>
#include <inet/ipclassifier.h>
#include "sctp_impl.h"
#include "sctp_addr.h"

/*
 * This will compute the checksum over the SCTP packet, so this
 * function should only be called after the whole packet has been
 * built.
 *
 * rptr should point to the IP / SCTP composite header.
 * len should be the length of the entire packet, including the IP
 *     header.
 */
void
sctp_add_hdr(sctp_t *sctp, uchar_t *rptr, size_t len)
{
	ipha_t *iphdr;
	short iplen;

	ASSERT(len >= sctp->sctp_hdr_len);

	/* Copy the common header from the template */
	bcopy(sctp->sctp_iphc, rptr, sctp->sctp_hdr_len);

	/* Set the total length in the IP hdr */
	iplen = (short)len;
	iphdr = (ipha_t *)rptr;
	U16_TO_ABE16(iplen, &iphdr->ipha_length);
}

/*ARGSUSED*/
size_t
sctp_supaddr_param_len(sctp_t *sctp)
{
	return (sizeof (sctp_parm_hdr_t) + sizeof (int32_t));
}

size_t
sctp_supaddr_param(sctp_t *sctp, uchar_t *p)
{
	sctp_parm_hdr_t *sph;
	uint16_t *addrtype;

	sph = (sctp_parm_hdr_t *)p;
	sph->sph_type = htons(PARM_SUPP_ADDRS);
	addrtype = (uint16_t *)(sph + 1);
	switch (sctp->sctp_ipversion) {
	case IPV4_VERSION:
		*addrtype++ = htons(PARM_ADDR4);
		*addrtype = 0;
		sph->sph_len = htons(sizeof (*sph) + sizeof (*addrtype));
		break;
	case IPV6_VERSION:
		*addrtype++ = htons(PARM_ADDR6);
		if (!sctp->sctp_connp->conn_ipv6_v6only) {
			*addrtype = htons(PARM_ADDR4);
			sph->sph_len = htons(sizeof (*sph) +
			    sizeof (*addrtype) * 2);
		} else {
			*addrtype = 0;
			sph->sph_len = htons(sizeof (*sph) +
			    sizeof (*addrtype));
		}
		break;
	default:
		break;
	}
	return (sizeof (*sph) + (sizeof (*addrtype) * 2));
}

/*
 * Currently, we support on PRSCTP option, there is more to come.
 */
/*ARGSUSED*/
size_t
sctp_options_param_len(const sctp_t *sctp, int option)
{
	size_t	optlen;

	switch (option) {
	case SCTP_PRSCTP_OPTION:
		optlen = sizeof (sctp_parm_hdr_t);
		break;
	default:
		ASSERT(0);
	}

	return (optlen);
}

/*ARGSUSED*/
size_t
sctp_options_param(const sctp_t *sctp, void *p, int option)
{
	sctp_parm_hdr_t	*sph = (sctp_parm_hdr_t *)p;

	switch (option) {
	case SCTP_PRSCTP_OPTION:
		sph->sph_type = htons(PARM_FORWARD_TSN);
		sph->sph_len = htons(sizeof (*sph));
		break;
	default:
		ASSERT(0);
	}

	return (sizeof (*sph));

}

size_t
sctp_adaptation_code_param(sctp_t *sctp, uchar_t *p)
{
	sctp_parm_hdr_t *sph;

	if (!sctp->sctp_send_adaptation) {
		return (0);
	}
	sph = (sctp_parm_hdr_t *)p;
	sph->sph_type = htons(PARM_ADAPT_LAYER_IND);
	sph->sph_len = htons(sizeof (*sph) + sizeof (uint32_t));
	*(uint32_t *)(sph + 1) = htonl(sctp->sctp_tx_adaptation_code);

	return (sizeof (*sph) + sizeof (uint32_t));
}

mblk_t *
sctp_init_mp(sctp_t *sctp)
{
	mblk_t			*mp;
	uchar_t			*p;
	size_t			initlen;
	sctp_init_chunk_t	*icp;
	sctp_chunk_hdr_t	*chp;
	uint16_t		schlen;
	int			supp_af;
	sctp_stack_t	*sctps = sctp->sctp_sctps;

	if (sctp->sctp_family == AF_INET) {
		supp_af = PARM_SUPP_V4;
	} else {
		/* Assume here that a v6 endpoint supports v4 address. */
		if (sctp->sctp_connp->conn_ipv6_v6only)
			supp_af = PARM_SUPP_V6;
		else
			supp_af = PARM_SUPP_V6 | PARM_SUPP_V4;
	}
	initlen = sizeof (*chp) + sizeof (*icp);
	if (sctp->sctp_send_adaptation) {
		initlen += (sizeof (sctp_parm_hdr_t) + sizeof (uint32_t));
	}
	initlen += sctp_supaddr_param_len(sctp);
	initlen += sctp_addr_params(sctp, supp_af, NULL, B_TRUE);
	if (sctp->sctp_prsctp_aware && sctps->sctps_prsctp_enabled)
		initlen += sctp_options_param_len(sctp, SCTP_PRSCTP_OPTION);

	/*
	 * This could be a INIT retransmission in which case sh_verf may
	 * be non-zero, zero it out just to be sure.
	 */
	sctp->sctp_sctph->sh_verf = 0;
	sctp->sctp_sctph6->sh_verf = 0;

	mp = sctp_make_mp(sctp, NULL, initlen);
	if (mp == NULL) {
		SCTP_KSTAT(sctps, sctp_send_init_failed);
		return (NULL);
	}

	/* Lay in a new INIT chunk, starting with the chunk header */
	chp = (sctp_chunk_hdr_t *)mp->b_wptr;
	chp->sch_id = CHUNK_INIT;
	chp->sch_flags = 0;
	schlen = (uint16_t)initlen;
	U16_TO_ABE16(schlen, &(chp->sch_len));

	mp->b_wptr += initlen;

	icp = (sctp_init_chunk_t *)(chp + 1);
	icp->sic_inittag = sctp->sctp_lvtag;
	U32_TO_ABE32(sctp->sctp_rwnd, &(icp->sic_a_rwnd));
	U16_TO_ABE16(sctp->sctp_num_ostr, &(icp->sic_outstr));
	U16_TO_ABE16(sctp->sctp_num_istr, &(icp->sic_instr));
	U32_TO_ABE32(sctp->sctp_ltsn, &(icp->sic_inittsn));

	p = (uchar_t *)(icp + 1);

	/* Adaptation layer param */
	p += sctp_adaptation_code_param(sctp, p);

	/* Add supported address types parameter */
	p += sctp_supaddr_param(sctp, p);

	/* Add address parameters */
	p += sctp_addr_params(sctp, supp_af, p, B_FALSE);

	/* Add Forward-TSN-Supported param */
	if (sctp->sctp_prsctp_aware && sctps->sctps_prsctp_enabled)
		p += sctp_options_param(sctp, p, SCTP_PRSCTP_OPTION);

	BUMP_LOCAL(sctp->sctp_obchunks);

	sctp_set_iplen(sctp, mp);

	return (mp);
}

/*
 * Extracts the verification tag from an INIT chunk. If the INIT
 * chunk is truncated or malformed, returns 0.
 */
uint32_t
sctp_init2vtag(sctp_chunk_hdr_t *initch)
{
	sctp_init_chunk_t *init;

	init = (sctp_init_chunk_t *)(initch + 1);
	return (init->sic_inittag);
}

size_t
sctp_addr_params(sctp_t *sctp, int af, uchar_t *p, boolean_t modify)
{
	size_t	param_len;

	ASSERT(sctp->sctp_nsaddrs > 0);

	/*
	 * If we have only one local address or it is a loopback or linklocal
	 * association, we let the peer pull the address from the IP header.
	 */
	if ((!modify && sctp->sctp_nsaddrs == 1) || sctp->sctp_loopback ||
	    sctp->sctp_linklocal) {
		return (0);
	}

	param_len = sctp_saddr_info(sctp, af, p, modify);
	return ((sctp->sctp_nsaddrs == 1) ? 0 : param_len);
}
