/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/atomic.h>
#include <sys/pattr.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <inet/common.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <ipp/dscpmk/dscpmk_impl.h>

/* Module to mark the ToS/DS field for a given packet */

/* Debug level */
int dscpmk_debug = 0;

/*
 * Given a packet, this routine marks the ToS or DSCP for IPv4 and IPv6 resp.
 * using the configured dscp_map.
 * Note that this module does not change the ECN bits.
 */
int
dscpmk_process(mblk_t **mpp, dscpmk_data_t *dscpmk_data, ip_proc_t proc)
{
	ipha_t *ipha;
	ip6_t *ip6_hdr;
	boolean_t is_v4;
	uint8_t dscp, new_dscp;
	mblk_t *mp;

	ASSERT((mpp != NULL) && (*mpp != NULL));
	mp = *mpp;

	/*
	 * The action module will receive an M_DATA or an M_CTL followed
	 * by an M_DATA. In the latter case skip the M_CTL.
	 */
	if (mp->b_datap->db_type != M_DATA) {
		if ((mp->b_cont != NULL) &&
		    (mp->b_cont->b_datap->db_type == M_DATA)) {
			mp = mp->b_cont;
		} else {
			dscpmk0dbg(("dscpmk_process: no data\n"));
			atomic_inc_64(&dscpmk_data->epackets);
			return (EINVAL);
		}
	}

	/* Pull-up needed? */
	if ((mp->b_wptr - mp->b_rptr) < IP_SIMPLE_HDR_LENGTH) {
		if (!pullupmsg(mp, IP_SIMPLE_HDR_LENGTH)) {
			dscpmk0dbg(("dscpmk_process: pullup failed\n"));
			atomic_inc_64(&dscpmk_data->epackets);
			return (EINVAL);
		}
	}
	ipha = (ipha_t *)mp->b_rptr;

	/* Update global stats */
	atomic_inc_64(&dscpmk_data->npackets);

	/*
	 * This should only be called for outgoing packets. For inbound packets
	 * proceed with the next action.
	 */
	if ((proc == IPP_LOCAL_IN) || (proc == IPP_FWD_IN)) {
		dscpmk2dbg(("dscpmk_process: cannot mark incoming packets\n"));
		atomic_inc_64(&dscpmk_data->ipackets);
		return (0);
	}

	/* Figure out the ToS or the Traffic Class from the message */
	if (IPH_HDR_VERSION(ipha) == IPV4_VERSION) {
		dscp = ipha->ipha_type_of_service;
		is_v4 = B_TRUE;
	} else {
		ip6_hdr = (ip6_t *)mp->b_rptr;
		dscp = __IPV6_TCLASS_FROM_FLOW(ip6_hdr->ip6_vcf);
		is_v4 = B_FALSE;
	}

	/*
	 * Select the new dscp from the dscp_map after ignoring the
	 * ECN/CU from dscp (hence dscp >> 2). new_dscp will be the
	 * 6-bit DSCP value.
	 */
	new_dscp = dscpmk_data->dscp_map[dscp >> 2];

	/* Update stats for this new_dscp */
	atomic_inc_64(&dscpmk_data->dscp_stats[new_dscp].npackets);

	/*
	 * if new_dscp is same as the original, update stats and
	 * return.
	 */
	if (new_dscp == (dscp >> 2)) {
		atomic_inc_64(&dscpmk_data->unchanged);
		return (0);
	}

	/* Get back the ECN/CU value from the original dscp */
	new_dscp = (new_dscp << 2) | (dscp & 0x3);

	atomic_inc_64(&dscpmk_data->changed);
	/*
	 * IPv4 : ToS structure -- RFC 791
	 *
	 *	  0   1   2   3   4   5   6   7
	 *	+---+---+---+---+---+---+---+---+
	 *	| IP Precd  | D	| T | R	| 0 | 0	|
	 *	|	    |	|   |	|   |	|
	 *	+---+---+---+---+---+---+---+---+
	 *
	 * For Backward Compatability the diff serv DSCP will be mapped
	 * to the 3-bits Precedence field. DTR is not supported. Thus,
	 * the following Class Seletor CodePoints are reserved from this
	 * purpose : xxx000; where x is 0 or 1 (note the last 2 bits are
	 * 00) -- see RFC 2474.
	 */

	if (is_v4) {
		ipha->ipha_type_of_service = new_dscp;
		/*
		 * If the hardware supports checksumming, we don't need
		 * to do anything.
		 */
		if (!(mp->b_datap->db_struioun.cksum.flags &
		    HCK_IPV4_HDRCKSUM)) {
			ipha->ipha_hdr_checksum = 0;
			ipha->ipha_hdr_checksum = ip_csum_hdr(ipha);
		}
	} else {

	/*
	 * IPv6 : DSCP field structure is as given -- RFC 2474
	 *
	 *	  0   1   2   3   4   5   6   7
	 *	+---+---+---+---+---+---+---+---+
	 *	|	DSCP		| CU	|
	 *	|			|	|
	 *	+---+---+---+---+---+---+---+---+
	 *
	 * CU -- Currently Unused
	 *
	 * the 32 bit vcf consists of version (4 bits), Traffic class (8 bits)
	 * and flow id (20 bits). Need to take care of Big/Little-Endianess.
	 */
#ifdef _BIG_ENDIAN
		ip6_hdr->ip6_vcf = (ip6_hdr->ip6_vcf & TCLASS_MASK) |
		    (new_dscp << 20);
#else
		ip6_hdr->ip6_vcf = (ip6_hdr->ip6_vcf & TCLASS_MASK) |
		    ((new_dscp >> 4) | ((new_dscp << 12) & 0xF000));
#endif
	}

	return (0);
}
