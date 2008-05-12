/*
 * CDDL HEADER START
 *
 * Copyright(c) 2007-2008 Intel Corporation. All rights reserved.
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at:
 *      http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When using or redistributing this file, you may do so under the
 * License only. No other modification of this header is permitted.
 *
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms of the CDDL.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "ixgbe_sw.h"

/*
 * Update driver private statistics.
 */
static int
ixgbe_update_stats(kstat_t *ks, int rw)
{
	ixgbe_t *ixgbe;
	struct ixgbe_hw *hw;
	ixgbe_stat_t *ixgbe_ks;
	int i;

	if (rw == KSTAT_WRITE)
		return (EACCES);

	ixgbe = (ixgbe_t *)ks->ks_private;
	ixgbe_ks = (ixgbe_stat_t *)ks->ks_data;
	hw = &ixgbe->hw;

	mutex_enter(&ixgbe->gen_lock);

	/*
	 * Basic information
	 */
	ixgbe_ks->link_speed.value.ui64 = ixgbe->link_speed;

#ifdef IXGBE_DEBUG
	ixgbe_ks->reset_count.value.ui64 = ixgbe->reset_count;

	ixgbe_ks->rx_frame_error.value.ui64 = 0;
	ixgbe_ks->rx_cksum_error.value.ui64 = 0;
	ixgbe_ks->rx_exceed_pkt.value.ui64 = 0;
	for (i = 0; i < ixgbe->num_rx_rings; i++) {
		ixgbe_ks->rx_frame_error.value.ui64 +=
		    ixgbe->rx_rings[i].stat_frame_error;
		ixgbe_ks->rx_cksum_error.value.ui64 +=
		    ixgbe->rx_rings[i].stat_cksum_error;
		ixgbe_ks->rx_exceed_pkt.value.ui64 +=
		    ixgbe->rx_rings[i].stat_exceed_pkt;
	}

	ixgbe_ks->tx_overload.value.ui64 = 0;
	ixgbe_ks->tx_fail_no_tbd.value.ui64 = 0;
	ixgbe_ks->tx_fail_no_tcb.value.ui64 = 0;
	ixgbe_ks->tx_fail_dma_bind.value.ui64 = 0;
	ixgbe_ks->tx_reschedule.value.ui64 = 0;
	for (i = 0; i < ixgbe->num_tx_rings; i++) {
		ixgbe_ks->tx_overload.value.ui64 +=
		    ixgbe->tx_rings[i].stat_overload;
		ixgbe_ks->tx_fail_no_tbd.value.ui64 +=
		    ixgbe->tx_rings[i].stat_fail_no_tbd;
		ixgbe_ks->tx_fail_no_tcb.value.ui64 +=
		    ixgbe->tx_rings[i].stat_fail_no_tcb;
		ixgbe_ks->tx_fail_dma_bind.value.ui64 +=
		    ixgbe->tx_rings[i].stat_fail_dma_bind;
		ixgbe_ks->tx_reschedule.value.ui64 +=
		    ixgbe->tx_rings[i].stat_reschedule;
	}

	/*
	 * Hardware calculated statistics.
	 */
	for (i = 0; i < 16; i++) {
		ixgbe_ks->gprc.value.ul += IXGBE_READ_REG(hw, IXGBE_QPRC(i));
		ixgbe_ks->gptc.value.ul += IXGBE_READ_REG(hw, IXGBE_QPTC(i));
		ixgbe_ks->tor.value.ui64 += IXGBE_READ_REG(hw, IXGBE_QBRC(i));
		ixgbe_ks->got.value.ui64 += IXGBE_READ_REG(hw, IXGBE_QBTC(i));
	}
	ixgbe_ks->gor.value.ui64 = ixgbe_ks->tor.value.ui64;

	ixgbe_ks->prc64.value.ul += IXGBE_READ_REG(hw, IXGBE_PRC64);
	ixgbe_ks->prc127.value.ul += IXGBE_READ_REG(hw, IXGBE_PRC127);
	ixgbe_ks->prc255.value.ul += IXGBE_READ_REG(hw, IXGBE_PRC255);
	ixgbe_ks->prc511.value.ul += IXGBE_READ_REG(hw, IXGBE_PRC511);
	ixgbe_ks->prc1023.value.ul += IXGBE_READ_REG(hw, IXGBE_PRC1023);
	ixgbe_ks->prc1522.value.ul += IXGBE_READ_REG(hw, IXGBE_PRC1522);
	ixgbe_ks->ptc64.value.ul += IXGBE_READ_REG(hw, IXGBE_PTC64);
	ixgbe_ks->ptc127.value.ul += IXGBE_READ_REG(hw, IXGBE_PTC127);
	ixgbe_ks->ptc255.value.ul += IXGBE_READ_REG(hw, IXGBE_PTC255);
	ixgbe_ks->ptc511.value.ul += IXGBE_READ_REG(hw, IXGBE_PTC511);
	ixgbe_ks->ptc1023.value.ul += IXGBE_READ_REG(hw, IXGBE_PTC1023);
	ixgbe_ks->ptc1522.value.ul += IXGBE_READ_REG(hw, IXGBE_PTC1522);
#endif

	ixgbe_ks->mspdc.value.ui64 += IXGBE_READ_REG(hw, IXGBE_MSPDC);
	for (i = 0; i < 8; i++)
		ixgbe_ks->mpc.value.ui64 += IXGBE_READ_REG(hw, IXGBE_MPC(i));
	ixgbe_ks->mlfc.value.ui64 += IXGBE_READ_REG(hw, IXGBE_MLFC);
	ixgbe_ks->mrfc.value.ui64 += IXGBE_READ_REG(hw, IXGBE_MRFC);
	ixgbe_ks->rlec.value.ui64 += IXGBE_READ_REG(hw, IXGBE_RLEC);
	ixgbe_ks->lxontxc.value.ui64 += IXGBE_READ_REG(hw, IXGBE_LXONTXC);
	ixgbe_ks->lxonrxc.value.ui64 += IXGBE_READ_REG(hw, IXGBE_LXONRXC);
	ixgbe_ks->lxofftxc.value.ui64 += IXGBE_READ_REG(hw, IXGBE_LXOFFTXC);
	ixgbe_ks->lxoffrxc.value.ui64 += IXGBE_READ_REG(hw, IXGBE_LXOFFRXC);
	ixgbe_ks->ruc.value.ui64 += IXGBE_READ_REG(hw, IXGBE_RUC);
	ixgbe_ks->rfc.value.ui64 += IXGBE_READ_REG(hw, IXGBE_RFC);
	ixgbe_ks->roc.value.ui64 += IXGBE_READ_REG(hw, IXGBE_ROC);
	ixgbe_ks->rjc.value.ui64 += IXGBE_READ_REG(hw, IXGBE_RJC);

	mutex_exit(&ixgbe->gen_lock);

	if (ixgbe_check_acc_handle(ixgbe->osdep.reg_handle) != DDI_FM_OK)
		ddi_fm_service_impact(ixgbe->dip, DDI_SERVICE_UNAFFECTED);

	return (0);
}

/*
 * Create and initialize the driver private statistics.
 */
int
ixgbe_init_stats(ixgbe_t *ixgbe)
{
	kstat_t *ks;
	ixgbe_stat_t *ixgbe_ks;

	/*
	 * Create and init kstat
	 */
	ks = kstat_create(MODULE_NAME, ddi_get_instance(ixgbe->dip),
	    "statistics", "net", KSTAT_TYPE_NAMED,
	    sizeof (ixgbe_stat_t) / sizeof (kstat_named_t), 0);

	if (ks == NULL) {
		ixgbe_error(ixgbe,
		    "Could not create kernel statistics");
		return (IXGBE_FAILURE);
	}

	ixgbe->ixgbe_ks = ks;

	ixgbe_ks = (ixgbe_stat_t *)ks->ks_data;

	/*
	 * Initialize all the statistics.
	 */
	kstat_named_init(&ixgbe_ks->link_speed, "link_speed",
	    KSTAT_DATA_UINT64);

#ifdef IXGBE_DEBUG
	kstat_named_init(&ixgbe_ks->reset_count, "reset_count",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ixgbe_ks->rx_frame_error, "rx_frame_error",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ixgbe_ks->rx_cksum_error, "rx_cksum_error",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ixgbe_ks->rx_exceed_pkt, "rx_exceed_pkt",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ixgbe_ks->tx_overload, "tx_overload",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ixgbe_ks->tx_fail_no_tbd, "tx_fail_no_tbd",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ixgbe_ks->tx_fail_no_tcb, "tx_fail_no_tcb",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ixgbe_ks->tx_fail_dma_bind, "tx_fail_dma_bind",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ixgbe_ks->tx_reschedule, "tx_reschedule",
	    KSTAT_DATA_UINT64);

	kstat_named_init(&ixgbe_ks->gprc, "good_pkts_recvd",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ixgbe_ks->gptc, "good_pkts_xmitd",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ixgbe_ks->gor, "good_octets_recvd",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ixgbe_ks->got, "good_octets_xmitd",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ixgbe_ks->prc64, "pkts_recvd_(  64b)",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ixgbe_ks->prc127, "pkts_recvd_(  65- 127b)",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ixgbe_ks->prc255, "pkts_recvd_( 127- 255b)",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ixgbe_ks->prc511, "pkts_recvd_( 256- 511b)",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ixgbe_ks->prc1023, "pkts_recvd_( 511-1023b)",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ixgbe_ks->prc1522, "pkts_recvd_(1024-1522b)",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ixgbe_ks->ptc64, "pkts_xmitd_(  64b)",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ixgbe_ks->ptc127, "pkts_xmitd_(  65- 127b)",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ixgbe_ks->ptc255, "pkts_xmitd_( 128- 255b)",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ixgbe_ks->ptc511, "pkts_xmitd_( 255- 511b)",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ixgbe_ks->ptc1023, "pkts_xmitd_( 512-1023b)",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ixgbe_ks->ptc1522, "pkts_xmitd_(1024-1522b)",
	    KSTAT_DATA_UINT64);
#endif

	kstat_named_init(&ixgbe_ks->mspdc, "mac_short_packet_discard",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ixgbe_ks->mpc, "missed_packets",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ixgbe_ks->mlfc, "mac_local_fault",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ixgbe_ks->mrfc, "mac_remote_fault",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ixgbe_ks->rlec, "recv_length_err",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ixgbe_ks->lxontxc, "link_xon_xmitd",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ixgbe_ks->lxonrxc, "link_xon_recvd",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ixgbe_ks->lxofftxc, "link_xoff_xmitd",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ixgbe_ks->lxoffrxc, "link_xoff_recvd",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ixgbe_ks->ruc, "recv_undersize",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ixgbe_ks->rfc, "recv_fragment",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ixgbe_ks->roc, "recv_oversize",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ixgbe_ks->rjc, "recv_jabber",
	    KSTAT_DATA_UINT64);

	/*
	 * Function to provide kernel stat update on demand
	 */
	ks->ks_update = ixgbe_update_stats;

	ks->ks_private = (void *)ixgbe;

	/*
	 * Add kstat to systems kstat chain
	 */
	kstat_install(ks);

	return (IXGBE_SUCCESS);
}
