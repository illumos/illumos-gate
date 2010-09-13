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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_VSW_HIO_H
#define	_VSW_HIO_H

#ifdef	__cplusplus
extern "C" {
#endif

/* kstats for hybrid io resources */
typedef struct vsw_hio_kstats {
	kstat_named_t	hio_capable;		/* is hybrid io capable */
	kstat_named_t	hio_num_shares;		/* # of hybrid io shares */

	struct {
		kstat_named_t	assigned;	/* to which mac */
		kstat_named_t	state;		/* share state */
	} share[1];
	/* space for other shares here */
} vsw_hio_kstats_t;

typedef struct vsw_share {
	uint32_t	vs_state;	/* State of this share */
	uint32_t	vs_index;	/* Index in the shares array */
	struct vsw	*vs_vswp;	/* Back pointer to vswp */
	uint8_t		vs_req_id;	/* DDS request ID */

	/* Cached info */
	vsw_port_t	*vs_portp;	/* Corresponding port */
	uint64_t	vs_ldcid;	/* LDC to which the share is assigned */
	uint64_t	vs_macaddr;	/* Associated MAC addr */
	uint64_t	vs_cookie;	/* Share Cookie from alloc_share */

} vsw_share_t;

#define	VSW_SHARE_FREE		0x0
#define	VSW_SHARE_ASSIGNED	0x1
#define	VSW_SHARE_DDS_SENT	0x2
#define	VSW_SHARE_DDS_ACKD	0x4

/* Hybrid related info */
typedef struct vsw_hio {
	uint32_t		vh_num_shares;	/* Number of shares available */
	vsw_share_t		*vh_shares;	/* Array of Shares */
	uint32_t		vh_kstat_size;	/* size for the whole kstats */
	vsw_hio_kstats_t	*vh_kstatsp;	/* stats for vsw hio */
	kstat_t			*vh_ksp;	/* kstats */
} vsw_hio_t;


#ifdef	__cplusplus
}
#endif

#endif	/* _VSW_HIO_H */
