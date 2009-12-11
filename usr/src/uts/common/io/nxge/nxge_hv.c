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

/*
 * nxge_hv.c
 *
 * This file is Sun4v specific.  It is the NXGE interface to the
 * Sun4v Hypervisor.
 *
 */

#include <sys/nxge/nxge_impl.h>
#include <sys/nxge/nxge_hio.h>

/*
 * The HV VR functions are set up based on the
 * the version number of the NIU API group.
 * For version 2.0 and above, the NIU will be
 * be referenced from the cfg-handle.
 */

#if defined(sun4v)

void
nxge_hio_hv_init(nxge_t *nxge)
{
	nxge_hio_data_t *nhd = (nxge_hio_data_t *)nxge->nxge_hw_p->hio;

	nxhv_vr_fp_t *vr;
	nxhv_dc_fp_t *tx;
	nxhv_dc_fp_t *rx;

	/* First, the HV VR functions. */
	vr = &nhd->hio.vr;

	/* HV Major 1 interfaces */
	vr->assign = &hv_niu_vr_assign;
	/* HV Major 2 interfaces */
	vr->cfgh_assign = &hv_niu_cfgh_vr_assign;

	vr->unassign = &hv_niu_vr_unassign;
	vr->getinfo = &hv_niu_vr_getinfo;

	// -------------------------------------------------------------
	/* Find the transmit functions. */
	tx = &nhd->hio.tx;

	tx->assign = &hv_niu_tx_dma_assign;
	tx->unassign = &hv_niu_tx_dma_unassign;
	tx->get_map = &hv_niu_vr_get_txmap;

	/* HV Major 1 interfaces */
	tx->lp_conf = &hv_niu_tx_logical_page_conf;
	tx->lp_info = &hv_niu_tx_logical_page_info;
	/* HV Major 2 interfaces */
	tx->lp_cfgh_conf = &hv_niu_cfgh_tx_logical_page_conf;
	tx->lp_cfgh_info = &hv_niu_cfgh_tx_logical_page_info;

	tx->getinfo = &hv_niu_vrtx_getinfo;

	/* Now find the Receive functions. */
	rx = &nhd->hio.rx;

	rx->assign = &hv_niu_rx_dma_assign;
	rx->unassign = &hv_niu_rx_dma_unassign;
	rx->get_map = &hv_niu_vr_get_rxmap;

	/* HV Major 1 interfaces */
	rx->lp_conf = &hv_niu_rx_logical_page_conf;
	rx->lp_info = &hv_niu_rx_logical_page_info;
	/* HV Major 2 interfaces */
	rx->lp_cfgh_conf = &hv_niu_cfgh_rx_logical_page_conf;
	rx->lp_cfgh_info = &hv_niu_cfgh_rx_logical_page_info;

	rx->getinfo = &hv_niu_vrrx_getinfo;
}

#endif /* defined(sun4v) */
