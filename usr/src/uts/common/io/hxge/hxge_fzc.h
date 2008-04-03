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

#ifndef	_SYS_HXGE_HXGE_FZC_H
#define	_SYS_HXGE_HXGE_FZC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <hpi_vir.h>

hxge_status_t hxge_fzc_intr_init(p_hxge_t hxgep);
hxge_status_t hxge_fzc_intr_ldg_num_set(p_hxge_t hxgep);
hxge_status_t hxge_fzc_intr_tmres_set(p_hxge_t hxgep);
hxge_status_t hxge_fzc_intr_sid_set(p_hxge_t hxgep);

hxge_status_t hxge_init_fzc_txdma_channel(p_hxge_t hxgep, uint16_t channel,
	p_tx_ring_t tx_ring_p, p_tx_mbox_t mbox_p);

hxge_status_t hxge_init_fzc_rxdma_channel(p_hxge_t hxgep, uint16_t channel,
	p_rx_rbr_ring_t rbr_p, p_rx_rcr_ring_t rcr_p, p_rx_mbox_t mbox_p);

hxge_status_t hxge_init_fzc_rx_common(p_hxge_t hxgep);

hxge_status_t hxge_init_fzc_rxdma_channel_pages(p_hxge_t hxgep,
	uint16_t channel, p_rx_rbr_ring_t rbr_p);

hxge_status_t hxge_init_fzc_txdma_channel_pages(p_hxge_t hxgep,
	uint16_t channel, p_tx_ring_t tx_ring_p);

hxge_status_t hxge_fzc_sys_err_mask_set(p_hxge_t hxgep, boolean_t mask);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_HXGE_HXGE_FZC_H */
