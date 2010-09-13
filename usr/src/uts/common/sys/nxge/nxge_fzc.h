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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_NXGE_NXGE_FZC_H
#define	_SYS_NXGE_NXGE_FZC_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <npi_vir.h>

nxge_status_t nxge_fzc_intr_init(p_nxge_t);
nxge_status_t nxge_fzc_intr_ldg_num_set(p_nxge_t);
nxge_status_t nxge_fzc_intr_tmres_set(p_nxge_t);
nxge_status_t nxge_fzc_intr_sid_set(p_nxge_t);

nxge_status_t nxge_fzc_dmc_rx_log_page_vld(p_nxge_t, uint16_t,
	uint32_t, boolean_t);
nxge_status_t nxge_fzc_dmc_rx_log_page_mask(p_nxge_t, uint16_t,
	uint32_t, uint32_t, uint32_t);

void nxge_init_fzc_txdma_channels(p_nxge_t);

nxge_status_t nxge_init_fzc_tdc(p_nxge_t, uint16_t);
nxge_status_t nxge_init_fzc_txdma_channel(p_nxge_t, uint16_t,
	p_tx_ring_t, p_tx_mbox_t);
nxge_status_t nxge_init_fzc_txdma_port(p_nxge_t);

nxge_status_t nxge_init_fzc_rxdma_channel(p_nxge_t, uint16_t);

nxge_status_t nxge_init_fzc_rdc(p_nxge_t, uint16_t);
nxge_status_t nxge_init_fzc_rx_common(p_nxge_t);
nxge_status_t nxge_init_fzc_rxdma_port(p_nxge_t);

nxge_status_t nxge_init_fzc_rdc_tbl(nxge_t *, nxge_rdc_grp_t *, int);

int nxge_fzc_rdc_tbl_bind(nxge_t *, int, int);
int nxge_fzc_rdc_tbl_unbind(p_nxge_t, int);

nxge_status_t nxge_init_fzc_rxdma_channel_pages(p_nxge_t,
	uint16_t, p_rx_rbr_ring_t);

nxge_status_t nxge_init_fzc_rxdma_channel_red(p_nxge_t,
	uint16_t, p_rx_rcr_ring_t);

nxge_status_t nxge_init_fzc_rxdma_channel_clrlog(p_nxge_t,
	uint16_t, p_rx_rbr_ring_t);

nxge_status_t nxge_init_fzc_txdma_channel_pages(p_nxge_t,
	uint16_t, p_tx_ring_t);

nxge_status_t nxge_init_fzc_txdma_channel_drr(p_nxge_t, uint16_t,
	p_tx_ring_t);

nxge_status_t nxge_init_fzc_txdma_port(p_nxge_t);

void nxge_init_fzc_ldg_num(p_nxge_t);
void nxge_init_fzc_sys_int_data(p_nxge_t);
void nxge_init_fzc_ldg_int_timer(p_nxge_t);
nxge_status_t nxge_fzc_sys_err_mask_set(p_nxge_t, uint64_t);

#if	defined(sun4v) && defined(NIU_LP_WORKAROUND)
nxge_status_t nxge_init_hv_fzc_rxdma_channel_pages(p_nxge_t,
	uint16_t, p_rx_rbr_ring_t);
nxge_status_t nxge_init_hv_fzc_txdma_channel_pages(p_nxge_t,
	uint16_t, p_tx_ring_t);
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_NXGE_NXGE_FZC_H */
