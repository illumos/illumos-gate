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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_NXGE_NXGE_ZCP_H
#define	_SYS_NXGE_NXGE_ZCP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <nxge_zcp_hw.h>
#include <npi_zcp.h>

typedef	struct _zcp_errlog {
	zcp_state_machine_t	state_mach;
} zcp_errlog_t, *p_zcp_errlog_t;

typedef struct _nxge_zcp_stats_t {
	uint32_t 		errors;
	uint32_t 		inits;
	uint32_t 		rrfifo_underrun;
	uint32_t 		rrfifo_overrun;
	uint32_t 		rspfifo_uncorr_err;
	uint32_t 		buffer_overflow;
	uint32_t 		stat_tbl_perr;
	uint32_t 		dyn_tbl_perr;
	uint32_t 		buf_tbl_perr;
	uint32_t 		tt_program_err;
	uint32_t 		rsp_tt_index_err;
	uint32_t 		slv_tt_index_err;
	uint32_t 		zcp_tt_index_err;
	uint32_t 		zcp_access_fail;
	uint32_t 		cfifo_ecc;
	zcp_errlog_t		errlog;
} nxge_zcp_stats_t, *p_nxge_zcp_stats_t;

typedef	struct _nxge_zcp {
	uint32_t		config;
	uint32_t		iconfig;
	nxge_zcp_stats_t	*stat;
} nxge_zcp_t;

nxge_status_t nxge_zcp_init(p_nxge_t nxgep);
void nxge_zcp_inject_err(p_nxge_t nxgep, uint32_t);
nxge_status_t nxge_zcp_fatal_err_recover(p_nxge_t nxgep);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_NXGE_NXGE_ZCP_H */
