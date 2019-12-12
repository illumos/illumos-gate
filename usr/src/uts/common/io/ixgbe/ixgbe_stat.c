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
 * Copyright(c) 2007-2010 Intel Corporation. All rights reserved.
 */

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2012 Nexenta Systems, Inc. All rights reserved.
 * Copyright 2016 OmniTI Computer Consulting, Inc. All rights reserved.
 * Copyright 2019 Joyent, Inc.
 */

#include "ixgbe_sw.h"

/*
 * The 82598 controller lacks a high/low register for the various
 * octet counters, but the common code also lacks a definition for
 * these older registers. In these cases, the high register address
 * maps to the appropriate address in the 82598 controller.
 */
#define	IXGBE_TOR	IXGBE_TORH
#define	IXGBE_GOTC	IXGBE_GOTCH
#define	IXGBE_GORC	IXGBE_GORCH

/*
 * Read total octets received.
 */
static uint64_t
ixgbe_read_tor_value(const struct ixgbe_hw *hw)
{
	uint64_t tor = 0;
	uint64_t hi = 0, lo = 0;

	switch (hw->mac.type) {
	case ixgbe_mac_82598EB:
		tor = IXGBE_READ_REG(hw, IXGBE_TOR);
		break;

	default:
		lo = IXGBE_READ_REG(hw, IXGBE_TORL);
		hi = IXGBE_READ_REG(hw, IXGBE_TORH) & 0xF;
		tor = (hi << 32) + lo;
		break;
	}

	return (tor);
}

/*
 * Read queue octets received.
 */
static uint64_t
ixgbe_read_qor_value(const struct ixgbe_hw *hw)
{
	uint64_t qor = 0;
	uint64_t hi = 0, lo = 0;

	switch (hw->mac.type) {
	case ixgbe_mac_82598EB:
		qor = IXGBE_READ_REG(hw, IXGBE_QBRC(0));
		break;

	default:
		lo = IXGBE_READ_REG(hw, IXGBE_QBRC_L(0));
		hi = IXGBE_READ_REG(hw, IXGBE_QBRC_H(0)) & 0xF;
		qor = (hi << 32) + lo;
		break;
	}

	return (qor);
}

/*
 * Read queue octets transmitted.
 */
static uint64_t
ixgbe_read_qot_value(const struct ixgbe_hw *hw)
{
	uint64_t qot = 0;
	uint64_t hi = 0, lo = 0;

	switch (hw->mac.type) {
	case ixgbe_mac_82598EB:
		qot = IXGBE_READ_REG(hw, IXGBE_QBTC(0));
		break;

	default:
		lo = IXGBE_READ_REG(hw, IXGBE_QBTC_L(0));
		hi = IXGBE_READ_REG(hw, IXGBE_QBTC_H(0)) & 0xF;
		qot = (hi << 32) + lo;
		break;
	}

	return (qot);
}

/*
 * Read good octets transmitted.
 */
static uint64_t
ixgbe_read_got_value(const struct ixgbe_hw *hw)
{
	uint64_t got = 0;
	uint64_t hi = 0, lo = 0;

	switch (hw->mac.type) {
	case ixgbe_mac_82598EB:
		got = IXGBE_READ_REG(hw, IXGBE_GOTC);
		break;

	default:
		lo = IXGBE_READ_REG(hw, IXGBE_GOTCL);
		hi = IXGBE_READ_REG(hw, IXGBE_GOTCH) & 0xF;
		got = (hi << 32) + lo;
		break;
	}

	return (got);
}

/*
 * Read good octets received.
 */
static uint64_t
ixgbe_read_gor_value(const struct ixgbe_hw *hw)
{
	uint64_t gor = 0;
	uint64_t hi = 0, lo = 0;

	switch (hw->mac.type) {
	case ixgbe_mac_82598EB:
		gor = IXGBE_READ_REG(hw, IXGBE_GORC);
		break;

	default:
		lo = IXGBE_READ_REG(hw, IXGBE_GORCL);
		hi = IXGBE_READ_REG(hw, IXGBE_GORCH) & 0xF;
		gor = (hi << 32) + lo;
		break;
	}

	return (gor);
}

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
	ixgbe_ks->reset_count.value.ui64 = ixgbe->reset_count;
	ixgbe_ks->lroc.value.ui64 = ixgbe->lro_pkt_count;

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
	ixgbe_ks->tx_break_tbd_limit.value.ui64 = 0;
	ixgbe_ks->tx_lso_header_fail.value.ui64 = 0;
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
		ixgbe_ks->tx_break_tbd_limit.value.ui64 +=
		    ixgbe->tx_rings[i].stat_break_tbd_limit;
		ixgbe_ks->tx_lso_header_fail.value.ui64 +=
		    ixgbe->tx_rings[i].stat_lso_header_fail;
	}

	/*
	 * Hardware calculated statistics.
	 */
	ixgbe_ks->gprc.value.ui64 += IXGBE_READ_REG(hw, IXGBE_GPRC);
	ixgbe_ks->gptc.value.ui64 += IXGBE_READ_REG(hw, IXGBE_GPTC);
	ixgbe_ks->gor.value.ui64 += ixgbe_read_gor_value(hw);
	ixgbe_ks->got.value.ui64 += ixgbe_read_got_value(hw);
	ixgbe_ks->qpr.value.ui64 += IXGBE_READ_REG(hw, IXGBE_QPRC(0));
	ixgbe_ks->qpt.value.ui64 += IXGBE_READ_REG(hw, IXGBE_QPTC(0));
	ixgbe_ks->qor.value.ui64 += ixgbe_read_qor_value(hw);
	ixgbe_ks->qot.value.ui64 += ixgbe_read_qot_value(hw);
	ixgbe_ks->tor.value.ui64 += ixgbe_read_tor_value(hw);
	ixgbe_ks->tot.value.ui64 = ixgbe_ks->got.value.ui64;

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

	ixgbe_ks->mspdc.value.ui64 += IXGBE_READ_REG(hw, IXGBE_MSPDC);
	for (i = 0; i < 8; i++)
		ixgbe_ks->mpc.value.ui64 += IXGBE_READ_REG(hw, IXGBE_MPC(i));
	ixgbe_ks->mlfc.value.ui64 += IXGBE_READ_REG(hw, IXGBE_MLFC);
	ixgbe_ks->mrfc.value.ui64 += IXGBE_READ_REG(hw, IXGBE_MRFC);
	ixgbe_ks->rlec.value.ui64 += IXGBE_READ_REG(hw, IXGBE_RLEC);
	ixgbe_ks->lxontxc.value.ui64 += IXGBE_READ_REG(hw, IXGBE_LXONTXC);
	switch (hw->mac.type) {
	case ixgbe_mac_82598EB:
		ixgbe_ks->lxonrxc.value.ui64 += IXGBE_READ_REG(hw,
		    IXGBE_LXONRXC);
		break;

	case ixgbe_mac_82599EB:
	case ixgbe_mac_X540:
	case ixgbe_mac_X550:
	case ixgbe_mac_X550EM_x:
	case ixgbe_mac_X550EM_a:
		ixgbe_ks->lxonrxc.value.ui64 += IXGBE_READ_REG(hw,
		    IXGBE_LXONRXCNT);
		break;

	default:
		break;
	}
	ixgbe_ks->lxofftxc.value.ui64 += IXGBE_READ_REG(hw, IXGBE_LXOFFTXC);
	switch (hw->mac.type) {
	case ixgbe_mac_82598EB:
		ixgbe_ks->lxoffrxc.value.ui64 += IXGBE_READ_REG(hw,
		    IXGBE_LXOFFRXC);
		break;

	case ixgbe_mac_82599EB:
	case ixgbe_mac_X540:
	case ixgbe_mac_X550:
	case ixgbe_mac_X550EM_x:
	case ixgbe_mac_X550EM_a:
		ixgbe_ks->lxoffrxc.value.ui64 += IXGBE_READ_REG(hw,
		    IXGBE_LXOFFRXCNT);
		break;

	default:
		break;
	}
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
	kstat_named_init(&ixgbe_ks->tx_break_tbd_limit, "tx_break_tbd_limit",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ixgbe_ks->tx_lso_header_fail, "tx_lso_header_fail",
	    KSTAT_DATA_UINT64);

	kstat_named_init(&ixgbe_ks->gprc, "good_pkts_recvd",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ixgbe_ks->gptc, "good_pkts_xmitd",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ixgbe_ks->gor, "good_octets_recvd",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ixgbe_ks->got, "good_octets_xmitd",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ixgbe_ks->qor, "queue_octets_recvd",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ixgbe_ks->qot, "queue_octets_xmitd",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ixgbe_ks->qpr, "queue_pkts_recvd",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ixgbe_ks->qpt, "queue_pkts_xmitd",
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
	kstat_named_init(&ixgbe_ks->rnbc, "recv_no_buffer",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ixgbe_ks->lroc, "lro_pkt_count",
	    KSTAT_DATA_UINT64);

	kstat_named_init(&ixgbe_ks->dev_gone, "device_gone",
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

/*
 * Retrieve a value for one of the statistics.
 */
int
ixgbe_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	ixgbe_t *ixgbe = (ixgbe_t *)arg;
	struct ixgbe_hw *hw = &ixgbe->hw;
	ixgbe_stat_t *ixgbe_ks;
	int i;
	ixgbe_link_speed speeds = 0;

	ixgbe_ks = (ixgbe_stat_t *)ixgbe->ixgbe_ks->ks_data;

	mutex_enter(&ixgbe->gen_lock);

	/*
	 * We cannot always rely on the common code maintaining
	 * hw->phy.speeds_supported, therefore we fall back to use the recorded
	 * supported speeds which were obtained during instance init in
	 * ixgbe_init_params().
	 */
	speeds = hw->phy.speeds_supported;
	if (speeds == 0)
		speeds = ixgbe->speeds_supported;

	if (ixgbe->ixgbe_state & IXGBE_SUSPENDED) {
		mutex_exit(&ixgbe->gen_lock);
		return (ECANCELED);
	}

	switch (stat) {
	case MAC_STAT_IFSPEED:
		*val = ixgbe->link_speed * 1000000ull;
		break;

	case MAC_STAT_MULTIRCV:
		ixgbe_ks->mprc.value.ui64 +=
		    IXGBE_READ_REG(hw, IXGBE_MPRC);
		*val = ixgbe_ks->mprc.value.ui64;
		break;

	case MAC_STAT_BRDCSTRCV:
		ixgbe_ks->bprc.value.ui64 +=
		    IXGBE_READ_REG(hw, IXGBE_BPRC);
		*val = ixgbe_ks->bprc.value.ui64;
		break;

	case MAC_STAT_MULTIXMT:
		ixgbe_ks->mptc.value.ui64 +=
		    IXGBE_READ_REG(hw, IXGBE_MPTC);
		*val = ixgbe_ks->mptc.value.ui64;
		break;

	case MAC_STAT_BRDCSTXMT:
		ixgbe_ks->bptc.value.ui64 +=
		    IXGBE_READ_REG(hw, IXGBE_BPTC);
		*val = ixgbe_ks->bptc.value.ui64;
		break;

	case MAC_STAT_NORCVBUF:
		/*
		 * The QPRDC[0] register maps to the same kstat as the
		 * old RNBC register because they have equivalent
		 * semantics.
		 */
		if (hw->mac.type == ixgbe_mac_82598EB) {
			for (i = 0; i < 8; i++) {
				ixgbe_ks->rnbc.value.ui64 +=
				    IXGBE_READ_REG(hw, IXGBE_RNBC(i));
			}
		} else {
			ixgbe_ks->rnbc.value.ui64 +=
			    IXGBE_READ_REG(hw, IXGBE_QPRDC(0));
		}

		*val = ixgbe_ks->rnbc.value.ui64;
		break;

	case MAC_STAT_IERRORS:
		ixgbe_ks->crcerrs.value.ui64 +=
		    IXGBE_READ_REG(hw, IXGBE_CRCERRS);
		ixgbe_ks->illerrc.value.ui64 +=
		    IXGBE_READ_REG(hw, IXGBE_ILLERRC);
		ixgbe_ks->errbc.value.ui64 +=
		    IXGBE_READ_REG(hw, IXGBE_ERRBC);
		ixgbe_ks->rlec.value.ui64 +=
		    IXGBE_READ_REG(hw, IXGBE_RLEC);
		*val = ixgbe_ks->crcerrs.value.ui64 +
		    ixgbe_ks->illerrc.value.ui64 +
		    ixgbe_ks->errbc.value.ui64 +
		    ixgbe_ks->rlec.value.ui64;
		break;

	case MAC_STAT_RBYTES:
		ixgbe_ks->tor.value.ui64 += ixgbe_read_tor_value(hw);
		*val = ixgbe_ks->tor.value.ui64;
		break;

	case MAC_STAT_OBYTES:
		/*
		 * The controller does not provide a Total Octets
		 * Transmitted statistic. The closest thing we have is
		 * Good Octets Transmitted. This makes sense, as what
		 * does it mean to transmit a packet if it didn't
		 * actually transmit.
		 */
		ixgbe_ks->got.value.ui64 += ixgbe_read_got_value(hw);
		ixgbe_ks->tot.value.ui64 = ixgbe_ks->got.value.ui64;
		*val = ixgbe_ks->tot.value.ui64;
		break;

	case MAC_STAT_IPACKETS:
		ixgbe_ks->tpr.value.ui64 +=
		    IXGBE_READ_REG(hw, IXGBE_TPR);
		*val = ixgbe_ks->tpr.value.ui64;
		break;

	case MAC_STAT_OPACKETS:
		ixgbe_ks->tpt.value.ui64 +=
		    IXGBE_READ_REG(hw, IXGBE_TPT);
		*val = ixgbe_ks->tpt.value.ui64;
		break;

	/* RFC 1643 stats */
	case ETHER_STAT_FCS_ERRORS:
		ixgbe_ks->crcerrs.value.ui64 +=
		    IXGBE_READ_REG(hw, IXGBE_CRCERRS);
		*val = ixgbe_ks->crcerrs.value.ui64;
		break;

	case ETHER_STAT_TOOLONG_ERRORS:
		ixgbe_ks->roc.value.ui64 +=
		    IXGBE_READ_REG(hw, IXGBE_ROC);
		*val = ixgbe_ks->roc.value.ui64;
		break;

	case ETHER_STAT_MACRCV_ERRORS:
		ixgbe_ks->crcerrs.value.ui64 +=
		    IXGBE_READ_REG(hw, IXGBE_CRCERRS);
		ixgbe_ks->illerrc.value.ui64 +=
		    IXGBE_READ_REG(hw, IXGBE_ILLERRC);
		ixgbe_ks->errbc.value.ui64 +=
		    IXGBE_READ_REG(hw, IXGBE_ERRBC);
		ixgbe_ks->rlec.value.ui64 +=
		    IXGBE_READ_REG(hw, IXGBE_RLEC);
		*val = ixgbe_ks->crcerrs.value.ui64 +
		    ixgbe_ks->illerrc.value.ui64 +
		    ixgbe_ks->errbc.value.ui64 +
		    ixgbe_ks->rlec.value.ui64;
		break;

	/* MII/GMII stats */
	case ETHER_STAT_XCVR_ADDR:
		/* The Internal PHY's MDI address for each MAC is 1 */
		*val = 1;
		break;

	case ETHER_STAT_XCVR_ID:
		*val = hw->phy.id;
		break;

	case ETHER_STAT_XCVR_INUSE:
		switch (ixgbe->link_speed) {
		case IXGBE_LINK_SPEED_1GB_FULL:
			*val =
			    (hw->phy.media_type == ixgbe_media_type_copper) ?
			    XCVR_1000T : XCVR_1000X;
			break;
		case IXGBE_LINK_SPEED_100_FULL:
			*val = (hw->phy.media_type == ixgbe_media_type_copper) ?
			    XCVR_100T2 : XCVR_100X;
			break;
		default:
			*val = XCVR_NONE;
			break;
		}
		break;

	case ETHER_STAT_CAP_10GFDX:
		*val = (speeds & IXGBE_LINK_SPEED_10GB_FULL) ? 1 : 0;
		break;

	case ETHER_STAT_CAP_5000FDX:
		*val = (speeds & IXGBE_LINK_SPEED_5GB_FULL) ? 1 : 0;
		break;

	case ETHER_STAT_CAP_2500FDX:
		*val = (speeds & IXGBE_LINK_SPEED_2_5GB_FULL) ? 1 : 0;
		break;

	case ETHER_STAT_CAP_1000FDX:
		*val = (speeds & IXGBE_LINK_SPEED_1GB_FULL) ? 1 : 0;
		break;

	case ETHER_STAT_CAP_100FDX:
		*val = (speeds & IXGBE_LINK_SPEED_100_FULL) ? 1 : 0;
		break;

	case ETHER_STAT_CAP_ASMPAUSE:
		*val = ixgbe->param_asym_pause_cap;
		break;

	case ETHER_STAT_CAP_PAUSE:
		*val = ixgbe->param_pause_cap;
		break;

	case ETHER_STAT_CAP_AUTONEG:
		*val = 1;
		break;

	case ETHER_STAT_ADV_CAP_10GFDX:
		*val = ixgbe->param_adv_10000fdx_cap;
		break;

	case ETHER_STAT_ADV_CAP_5000FDX:
		*val = ixgbe->param_adv_5000fdx_cap;
		break;

	case ETHER_STAT_ADV_CAP_2500FDX:
		*val = ixgbe->param_adv_2500fdx_cap;
		break;

	case ETHER_STAT_ADV_CAP_1000FDX:
		*val = ixgbe->param_adv_1000fdx_cap;
		break;

	case ETHER_STAT_ADV_CAP_100FDX:
		*val = ixgbe->param_adv_100fdx_cap;
		break;

	case ETHER_STAT_ADV_CAP_ASMPAUSE:
		*val = ixgbe->param_adv_asym_pause_cap;
		break;

	case ETHER_STAT_ADV_CAP_PAUSE:
		*val = ixgbe->param_adv_pause_cap;
		break;

	case ETHER_STAT_ADV_CAP_AUTONEG:
		*val = ixgbe->param_adv_autoneg_cap;
		break;

	case ETHER_STAT_LP_CAP_10GFDX:
		*val = ixgbe->param_lp_10000fdx_cap;
		break;

	case ETHER_STAT_LP_CAP_5000FDX:
		*val = ixgbe->param_lp_5000fdx_cap;
		break;

	case ETHER_STAT_LP_CAP_2500FDX:
		*val = ixgbe->param_lp_2500fdx_cap;
		break;

	case ETHER_STAT_LP_CAP_1000FDX:
		*val = ixgbe->param_lp_1000fdx_cap;
		break;

	case ETHER_STAT_LP_CAP_100FDX:
		*val = ixgbe->param_lp_100fdx_cap;
		break;

	case ETHER_STAT_LP_CAP_ASMPAUSE:
		*val = ixgbe->param_lp_asym_pause_cap;
		break;

	case ETHER_STAT_LP_CAP_PAUSE:
		*val = ixgbe->param_lp_pause_cap;
		break;

	case ETHER_STAT_LP_CAP_AUTONEG:
		*val = ixgbe->param_lp_autoneg_cap;
		break;

	case ETHER_STAT_LINK_ASMPAUSE:
		*val = ixgbe->param_asym_pause_cap;
		break;

	case ETHER_STAT_LINK_PAUSE:
		*val = ixgbe->param_pause_cap;
		break;

	case ETHER_STAT_LINK_AUTONEG:
		*val = ixgbe->param_adv_autoneg_cap;
		break;

	case ETHER_STAT_LINK_DUPLEX:
		*val = ixgbe->link_duplex;
		break;

	case ETHER_STAT_TOOSHORT_ERRORS:
		ixgbe_ks->ruc.value.ui64 +=
		    IXGBE_READ_REG(hw, IXGBE_RUC);
		*val = ixgbe_ks->ruc.value.ui64;
		break;

	case ETHER_STAT_CAP_REMFAULT:
		*val = ixgbe->param_rem_fault;
		break;

	case ETHER_STAT_ADV_REMFAULT:
		*val = ixgbe->param_adv_rem_fault;
		break;

	case ETHER_STAT_LP_REMFAULT:
		*val = ixgbe->param_lp_rem_fault;
		break;

	case ETHER_STAT_JABBER_ERRORS:
		ixgbe_ks->rjc.value.ui64 +=
		    IXGBE_READ_REG(hw, IXGBE_RJC);
		*val = ixgbe_ks->rjc.value.ui64;
		break;

	default:
		mutex_exit(&ixgbe->gen_lock);
		return (ENOTSUP);
	}

	mutex_exit(&ixgbe->gen_lock);

	if (ixgbe_check_acc_handle(ixgbe->osdep.reg_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(ixgbe->dip, DDI_SERVICE_DEGRADED);
		return (EIO);
	}

	return (0);
}

/*
 * Retrieve a value for one of the statistics for a particular rx ring
 */
int
ixgbe_rx_ring_stat(mac_ring_driver_t rh, uint_t stat, uint64_t *val)
{
	ixgbe_rx_ring_t	*rx_ring = (ixgbe_rx_ring_t *)rh;
	ixgbe_t *ixgbe = rx_ring->ixgbe;

	if (ixgbe->ixgbe_state & IXGBE_SUSPENDED) {
		return (ECANCELED);
	}

	switch (stat) {
	case MAC_STAT_RBYTES:
		*val = rx_ring->stat_rbytes;
		break;

	case MAC_STAT_IPACKETS:
		*val = rx_ring->stat_ipackets;
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
ixgbe_tx_ring_stat(mac_ring_driver_t rh, uint_t stat, uint64_t *val)
{
	ixgbe_tx_ring_t	*tx_ring = (ixgbe_tx_ring_t *)rh;
	ixgbe_t *ixgbe = tx_ring->ixgbe;

	if (ixgbe->ixgbe_state & IXGBE_SUSPENDED) {
		return (ECANCELED);
	}

	switch (stat) {
	case MAC_STAT_OBYTES:
		*val = tx_ring->stat_obytes;
		break;

	case MAC_STAT_OPACKETS:
		*val = tx_ring->stat_opackets;
		break;

	default:
		*val = 0;
		return (ENOTSUP);
	}

	return (0);
}
