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

#ifndef _SYS_NXGE_NXGE_IPP_H
#define	_SYS_NXGE_NXGE_IPP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <nxge_ipp_hw.h>
#include <npi_ipp.h>

#define	IPP_MAX_PKT_SIZE	0x1FFFF
#define	IPP_MAX_ERR_SHOW	10

typedef	struct _ipp_errlog {
	boolean_t		multiple_err;
	uint16_t		dfifo_rd_ptr;
	uint32_t		state_mach;
	uint16_t		ecc_syndrome;
} ipp_errlog_t, *p_ipp_errlog_t;

typedef struct _nxge_ipp_stats {
	uint32_t 		errors;
	uint32_t 		inits;
	uint32_t 		sop_miss;
	uint32_t 		eop_miss;
	uint32_t 		dfifo_ue;
	uint32_t 		ecc_err_cnt;
	uint32_t 		pfifo_perr;
	uint32_t 		pfifo_over;
	uint32_t 		pfifo_und;
	uint32_t 		bad_cs_cnt;
	uint32_t 		pkt_dis_cnt;
	ipp_errlog_t		errlog;
} nxge_ipp_stats_t, *p_nxge_ipp_stats_t;

typedef	struct _nxge_ipp {
	uint32_t		config;
	uint32_t		iconfig;
	ipp_status_t		status;
	uint32_t		max_pkt_size;
	nxge_ipp_stats_t	*stat;
} nxge_ipp_t;

/* IPP prototypes */
nxge_status_t nxge_ipp_reset(p_nxge_t);
nxge_status_t nxge_ipp_init(p_nxge_t);
nxge_status_t nxge_ipp_disable(p_nxge_t);
nxge_status_t nxge_ipp_drain(p_nxge_t);
nxge_status_t nxge_ipp_handle_sys_errors(p_nxge_t);
nxge_status_t nxge_ipp_fatal_err_recover(p_nxge_t);
nxge_status_t nxge_ipp_eccue_valid_check(p_nxge_t, boolean_t *);
void nxge_ipp_inject_err(p_nxge_t, uint32_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_NXGE_NXGE_IPP_H */
