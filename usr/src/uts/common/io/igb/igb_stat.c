/*
 * CDDL HEADER START
 *
 * Copyright(c) 2007-2009 Intel Corporation. All rights reserved.
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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2014 Pluribus Networks Inc.
 */

#include "igb_sw.h"

/*
 * Update driver private statistics.
 */
static int
igb_update_stats(kstat_t *ks, int rw)
{
	igb_t *igb;
	struct e1000_hw *hw;
	igb_stat_t *igb_ks;
	uint32_t val_low, val_high;
#ifdef IGB_DEBUG
	int i;
#endif

	if (rw == KSTAT_WRITE)
		return (EACCES);

	igb = (igb_t *)ks->ks_private;
	igb_ks = (igb_stat_t *)ks->ks_data;
	hw = &igb->hw;

	mutex_enter(&igb->gen_lock);

	/*
	 * Basic information.
	 */
	igb_ks->reset_count.value.ui64 = igb->reset_count;
	igb_ks->dout_sync.value.ui64 = igb->dout_sync;

#ifdef IGB_DEBUG
	igb_ks->rx_frame_error.value.ui64 = 0;
	igb_ks->rx_cksum_error.value.ui64 = 0;
	igb_ks->rx_exceed_pkt.value.ui64 = 0;
	for (i = 0; i < igb->num_rx_rings; i++) {
		igb_ks->rx_frame_error.value.ui64 +=
		    igb->rx_rings[i].stat_frame_error;
		igb_ks->rx_cksum_error.value.ui64 +=
		    igb->rx_rings[i].stat_cksum_error;
		igb_ks->rx_exceed_pkt.value.ui64 +=
		    igb->rx_rings[i].stat_exceed_pkt;
	}

	igb_ks->tx_overload.value.ui64 = 0;
	igb_ks->tx_fail_no_tbd.value.ui64 = 0;
	igb_ks->tx_fail_no_tcb.value.ui64 = 0;
	igb_ks->tx_fail_dma_bind.value.ui64 = 0;
	igb_ks->tx_reschedule.value.ui64 = 0;
	for (i = 0; i < igb->num_tx_rings; i++) {
		igb_ks->tx_overload.value.ui64 +=
		    igb->tx_rings[i].stat_overload;
		igb_ks->tx_fail_no_tbd.value.ui64 +=
		    igb->tx_rings[i].stat_fail_no_tbd;
		igb_ks->tx_fail_no_tcb.value.ui64 +=
		    igb->tx_rings[i].stat_fail_no_tcb;
		igb_ks->tx_fail_dma_bind.value.ui64 +=
		    igb->tx_rings[i].stat_fail_dma_bind;
		igb_ks->tx_reschedule.value.ui64 +=
		    igb->tx_rings[i].stat_reschedule;
	}

	/*
	 * Hardware calculated statistics.
	 */
	igb_ks->gprc.value.ul += E1000_READ_REG(hw, E1000_GPRC);
	igb_ks->gptc.value.ul += E1000_READ_REG(hw, E1000_GPTC);
	igb_ks->prc64.value.ul += E1000_READ_REG(hw, E1000_PRC64);
	igb_ks->prc127.value.ul += E1000_READ_REG(hw, E1000_PRC127);
	igb_ks->prc255.value.ul += E1000_READ_REG(hw, E1000_PRC255);
	igb_ks->prc511.value.ul += E1000_READ_REG(hw, E1000_PRC511);
	igb_ks->prc1023.value.ul += E1000_READ_REG(hw, E1000_PRC1023);
	igb_ks->prc1522.value.ul += E1000_READ_REG(hw, E1000_PRC1522);
	igb_ks->ptc64.value.ul += E1000_READ_REG(hw, E1000_PTC64);
	igb_ks->ptc127.value.ul += E1000_READ_REG(hw, E1000_PTC127);
	igb_ks->ptc255.value.ul += E1000_READ_REG(hw, E1000_PTC255);
	igb_ks->ptc511.value.ul += E1000_READ_REG(hw, E1000_PTC511);
	igb_ks->ptc1023.value.ul += E1000_READ_REG(hw, E1000_PTC1023);
	igb_ks->ptc1522.value.ul += E1000_READ_REG(hw, E1000_PTC1522);

	/*
	 * The 64-bit register will reset whenever the upper
	 * 32 bits are read. So we need to read the lower
	 * 32 bits first, then read the upper 32 bits.
	 */
	val_low = E1000_READ_REG(hw, E1000_GORCL);
	val_high = E1000_READ_REG(hw, E1000_GORCH);
	igb_ks->gor.value.ui64 += (uint64_t)val_high << 32 | (uint64_t)val_low;

	val_low = E1000_READ_REG(hw, E1000_GOTCL);
	val_high = E1000_READ_REG(hw, E1000_GOTCH);
	igb_ks->got.value.ui64 += (uint64_t)val_high << 32 | (uint64_t)val_low;
#endif
	igb_ks->symerrs.value.ui64 += E1000_READ_REG(hw, E1000_SYMERRS);
	igb_ks->mpc.value.ui64 += E1000_READ_REG(hw, E1000_MPC);
	igb_ks->rlec.value.ui64 += E1000_READ_REG(hw, E1000_RLEC);
	igb_ks->fcruc.value.ui64 += E1000_READ_REG(hw, E1000_FCRUC);
	igb_ks->rfc.value.ul += E1000_READ_REG(hw, E1000_RFC);
	igb_ks->tncrs.value.ul += E1000_READ_REG(hw, E1000_TNCRS);
	igb_ks->tsctc.value.ul += E1000_READ_REG(hw, E1000_TSCTC);
	igb_ks->tsctfc.value.ul += E1000_READ_REG(hw, E1000_TSCTFC);
	igb_ks->xonrxc.value.ui64 += E1000_READ_REG(hw, E1000_XONRXC);
	igb_ks->xontxc.value.ui64 += E1000_READ_REG(hw, E1000_XONTXC);
	igb_ks->xoffrxc.value.ui64 += E1000_READ_REG(hw, E1000_XOFFRXC);
	igb_ks->xofftxc.value.ui64 += E1000_READ_REG(hw, E1000_XOFFTXC);

	mutex_exit(&igb->gen_lock);

	if (igb_check_acc_handle(igb->osdep.reg_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(igb->dip, DDI_SERVICE_DEGRADED);
		return (EIO);
	}

	return (0);
}

/*
 * Create and initialize the driver private statistics.
 */
int
igb_init_stats(igb_t *igb)
{
	kstat_t *ks;
	igb_stat_t *igb_ks;

	/*
	 * Create and init kstat
	 */
	ks = kstat_create(MODULE_NAME, ddi_get_instance(igb->dip),
	    "statistics", "net", KSTAT_TYPE_NAMED,
	    sizeof (igb_stat_t) / sizeof (kstat_named_t), 0);

	if (ks == NULL) {
		igb_log(igb, IGB_LOG_ERROR,
		    "Could not create kernel statistics");
		return (IGB_FAILURE);
	}

	igb->igb_ks = ks;

	igb_ks = (igb_stat_t *)ks->ks_data;

	/*
	 * Initialize all the statistics.
	 */
	kstat_named_init(&igb_ks->reset_count, "reset_count",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&igb_ks->dout_sync, "DMA_out_sync",
	    KSTAT_DATA_UINT64);

#ifdef IGB_DEBUG
	kstat_named_init(&igb_ks->rx_frame_error, "rx_frame_error",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&igb_ks->rx_cksum_error, "rx_cksum_error",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&igb_ks->rx_exceed_pkt, "rx_exceed_pkt",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&igb_ks->tx_overload, "tx_overload",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&igb_ks->tx_fail_no_tbd, "tx_fail_no_tbd",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&igb_ks->tx_fail_no_tcb, "tx_fail_no_tcb",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&igb_ks->tx_fail_dma_bind, "tx_fail_dma_bind",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&igb_ks->tx_reschedule, "tx_reschedule",
	    KSTAT_DATA_UINT64);

	kstat_named_init(&igb_ks->gprc, "good_pkts_recvd",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&igb_ks->gptc, "good_pkts_xmitd",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&igb_ks->gor, "good_octets_recvd",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&igb_ks->got, "good_octets_xmitd",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&igb_ks->prc64, "pkts_recvd_(  64b)",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&igb_ks->prc127, "pkts_recvd_(  65- 127b)",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&igb_ks->prc255, "pkts_recvd_( 127- 255b)",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&igb_ks->prc511, "pkts_recvd_( 256- 511b)",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&igb_ks->prc1023, "pkts_recvd_( 511-1023b)",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&igb_ks->prc1522, "pkts_recvd_(1024-1522b)",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&igb_ks->ptc64, "pkts_xmitd_(  64b)",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&igb_ks->ptc127, "pkts_xmitd_(  65- 127b)",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&igb_ks->ptc255, "pkts_xmitd_( 128- 255b)",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&igb_ks->ptc511, "pkts_xmitd_( 255- 511b)",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&igb_ks->ptc1023, "pkts_xmitd_( 512-1023b)",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&igb_ks->ptc1522, "pkts_xmitd_(1024-1522b)",
	    KSTAT_DATA_UINT64);
#endif

	kstat_named_init(&igb_ks->symerrs, "recv_symbol_errors",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&igb_ks->mpc, "recv_missed_packets",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&igb_ks->rlec, "recv_length_errors",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&igb_ks->fcruc, "recv_unsupport_FC_pkts",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&igb_ks->rfc, "recv_frag",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&igb_ks->tncrs, "xmit_with_no_CRS",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&igb_ks->tsctc, "xmit_TCP_seg_contexts",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&igb_ks->tsctfc, "xmit_TCP_seg_contexts_fail",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&igb_ks->xonrxc, "XONs_recvd",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&igb_ks->xontxc, "XONs_xmitd",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&igb_ks->xoffrxc, "XOFFs_recvd",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&igb_ks->xofftxc, "XOFFs_xmitd",
	    KSTAT_DATA_UINT64);

	/*
	 * Function to provide kernel stat update on demand
	 */
	ks->ks_update = igb_update_stats;

	ks->ks_private = (void *)igb;

	/*
	 * Add kstat to systems kstat chain
	 */
	kstat_install(ks);

	return (IGB_SUCCESS);
}

/*
 * Retrieve a value for one of the statistics for a particular rx ring
 */
int
igb_rx_ring_stat(mac_ring_driver_t rh, uint_t stat, uint64_t *val)
{
	igb_rx_ring_t *rx_ring = (igb_rx_ring_t *)rh;

	switch (stat) {
	case MAC_STAT_RBYTES:
		*val = rx_ring->rx_bytes;
		break;

	case MAC_STAT_IPACKETS:
		*val = rx_ring->rx_pkts;
		break;

	default:
		*val = 0;
		return (ENOTSUP);
	}

	return (0);
}

/*
 * Retrieve a value for one of the statistics for a particular tx ring
 */
int
igb_tx_ring_stat(mac_ring_driver_t rh, uint_t stat, uint64_t *val)
{
	igb_tx_ring_t *tx_ring = (igb_tx_ring_t *)rh;

	switch (stat) {
	case MAC_STAT_OBYTES:
		*val = tx_ring->tx_bytes;
		break;

	case MAC_STAT_OPACKETS:
		*val = tx_ring->tx_pkts;
		break;

	default:
		*val = 0;
		return (ENOTSUP);
	}

	return (0);
}
