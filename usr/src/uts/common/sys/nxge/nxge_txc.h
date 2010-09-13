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

#ifndef	_SYS_NXGE_NXGE_TXC_H
#define	_SYS_NXGE_NXGE_TXC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/nxge/nxge_txc_hw.h>
#include <npi_txc.h>

/* Suggested by hardware team 7/19/2006 */
#define	TXC_DMA_MAX_BURST_DEFAULT	1530	/* Max burst used by DRR */

typedef	struct _txc_errlog {
	txc_ro_states_t		ro_st;
	txc_sf_states_t		sf_st;
} txc_errlog_t;

typedef struct _nxge_txc_stats {
	uint32_t		pkt_stuffed;
	uint32_t		pkt_xmit;
	uint32_t		ro_correct_err;
	uint32_t		ro_uncorrect_err;
	uint32_t		sf_correct_err;
	uint32_t		sf_uncorrect_err;
	uint32_t		address_failed;
	uint32_t		dma_failed;
	uint32_t		length_failed;
	uint32_t		pkt_assy_dead;
	uint32_t		reorder_err;
	txc_errlog_t		errlog;
} nxge_txc_stats_t, *p_nxge_txc_stats_t;

typedef struct _nxge_txc {
	uint32_t		dma_max_burst;
	uint32_t		dma_length;
	uint32_t		training;
	uint8_t			debug_select;
	uint64_t		control_status;
	uint64_t		port_dma_list;
	nxge_txc_stats_t	*txc_stats;
} nxge_txc_t, *p_nxge_txc_t;

/*
 * Transmit Controller (TXC) prototypes.
 */
nxge_status_t nxge_txc_init(p_nxge_t);
nxge_status_t nxge_txc_uninit(p_nxge_t);
nxge_status_t nxge_txc_tdc_bind(p_nxge_t, int);
nxge_status_t nxge_txc_tdc_unbind(p_nxge_t, int);
nxge_status_t nxge_txc_handle_sys_errors(p_nxge_t);
void nxge_txc_inject_err(p_nxge_t, uint32_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_NXGE_NXGE_TXC_H */
