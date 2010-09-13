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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _IPP_DLCOSMK_DLCOSMK_IMPL_H
#define	_IPP_DLCOSMK_DLCOSMK_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <ipp/ipp.h>
#include <ipp/dlcosmk/dlcosmk.h>
#include <inet/ipp_common.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* Header file for implementation of DL CoS marker ipp action module */

#define	_DLCOSMK_DEBUG

/* The 3-MSB in the ToS/Dsfield are used to map to the 802.1D user priority */
#define	TOS_CLASS_MASK		5
/* 802.1D user priority is 3 bits - 0-7 */
#define	UPRI_MAP_COUNT		8
/* This will be used it the ToS/Dsfield needs to be mapped */
#define	MAP_TOS_TO_UPRI		8

#ifdef _DLCOSMK_DEBUG
#include <sys/debug.h>
#define	dlcosmk0dbg(a)		printf a
#define	dlcosmk1dbg(a)		if (dlcosmk_debug > 2) printf a
#define	dlcosmk2dbg(a)		if (dlcosmk_debug > 3) printf a
#else
#define	dlcosmk0dbg(a)
#define	dlcosmk1dbg(a)
#define	dlcosmk2dbg(a)
#endif /* _DLCOSMK_DEBUG */

/* dlcosmk stats info. available using kstats */
typedef struct dlcosmk_stat_s {
	ipp_named_t	npackets;	/* no. of pkts seen by this instance */
	ipp_named_t	ipackets;	/* no. of pkts not processed */
	ipp_named_t	epackets;	/* no. of pkts in error */
	ipp_named_t	usr_pri;	/* configured 802.1D priority */
	ipp_named_t	b_band;		/* Mapped b_band for the priority */
	ipp_named_t	dl_max;		/* Mapped dl_max for the priority */
} dlcosmk_stat_t;

/*
 * If the above structure is changed, the count will have to be updated
 * accordingly.
 */
#define	DLCOSMK_STATS_COUNT		6
#define	DLCOSMK_STATS_STRING		"dlcosmk statistics"

/*
 * Table containing 802.1D user_priority -> b_band/dl_max mappings.
 * The mappings have been taken from the VLAN driver.
 */
typedef struct usrpri_tbl_s {
	uchar_t b_band;
	t_scalar_t dl_max;
} usrpri_tbl_t;

extern usrpri_tbl_t usrpri_tbl[UPRI_MAP_COUNT];

#define	UPRI_TBL_SZ		sizeof (usrpri_tbl_t)

/* Per-instance data structure */
typedef struct dlcosmk_data_s {
	ipp_action_id_t next_action; 	/* action id of next action */
	ipp_stat_t 	*stats;		/* stats for this instance */
	uint8_t 	usr_pri;	/* 802.1d user priority */
	uchar_t 	b_band;		/* corresponding bband */
	t_scalar_t 	dl_max;		/* corresponding dl_max */
	boolean_t 	gather_stats;	/* stats collected or not */
	uint64_t 	npackets;	/* no. of pkts. for this instance */
	uint64_t 	epackets;	/* no. of pkts. in error */
	uint64_t 	ipackets;	/* no. of pkts. not processed */
} dlcosmk_data_t;

#define	DLCOSMK_DATA_SZ		sizeof (dlcosmk_data_t)

/*
 * ToS -> user_priority mapping. This mapping is local to this implementation
 * i.e., the ToS -> 802.1D mapping is not a standard.
 */
extern uint8_t tos_to_usrpri[UPRI_MAP_COUNT];

#ifdef _KERNEL
extern int dlcosmk_debug;
extern int dlcosmk_process(mblk_t **, dlcosmk_data_t *, uint32_t, ip_proc_t);
#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _IPP_DLCOSMK_DLCOSMK_IMPL_H */
