/*
 * This file is provided under a CDDLv1 license.  When using or
 * redistributing this file, you may do so under this license.
 * In redistributing this file this license must be included
 * and no other modification of this header file is permitted.
 *
 * CDDL LICENSE SUMMARY
 *
 * Copyright(c) 1999 - 2009 Intel Corporation. All rights reserved.
 *
 * The contents of this file are subject to the terms of Version
 * 1.0 of the Common Development and Distribution License (the "License").
 *
 * You should have received a copy of the License with this software.
 * You can obtain a copy of the License at
 *	http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 */

/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Copyright 2012 David Höppner. All rights reserved.
 * Use is subject to license terms.
 */

/*
 * **********************************************************************
 *									*
 * Module Name:  e1000g_stat.c						*
 *									*
 * Abstract: Functions for processing statistics			*
 *									*
 * **********************************************************************
 */
#include "e1000g_sw.h"
#include "e1000g_debug.h"

static int e1000g_update_stats(kstat_t *ksp, int rw);
static uint32_t e1000g_read_phy_stat(struct e1000_hw *hw, int reg);

/*
 * e1000_tbi_adjust_stats
 *
 * Adjusts statistic counters when a frame is accepted
 * under the TBI workaround. This function has been
 * adapted for Solaris from shared code.
 */
void
e1000_tbi_adjust_stats(struct e1000g *Adapter,
    uint32_t frame_len, uint8_t *mac_addr)
{
	uint32_t carry_bit;
	p_e1000g_stat_t e1000g_ksp;

	e1000g_ksp = (p_e1000g_stat_t)Adapter->e1000g_ksp->ks_data;

	/* First adjust the frame length */
	frame_len--;

	/*
	 * We need to adjust the statistics counters, since the hardware
	 * counters overcount this packet as a CRC error and undercount
	 * the packet as a good packet
	 */
	/* This packet should not be counted as a CRC error */
	Adapter->fcs_errors--;
	/* This packet does count as a Good Packet Received */
	e1000g_ksp->Gprc.value.ul++;

	/*
	 * Adjust the Good Octets received counters
	 */
	carry_bit = 0x80000000 & e1000g_ksp->Gorl.value.ul;
	e1000g_ksp->Gorl.value.ul += frame_len;
	/*
	 * If the high bit of Gorcl (the low 32 bits of the Good Octets
	 * Received Count) was one before the addition,
	 * AND it is zero after, then we lost the carry out,
	 * need to add one to Gorch (Good Octets Received Count High).
	 * This could be simplified if all environments supported
	 * 64-bit integers.
	 */
	if (carry_bit && ((e1000g_ksp->Gorl.value.ul & 0x80000000) == 0)) {
		e1000g_ksp->Gorh.value.ul++;
	}
	/*
	 * Is this a broadcast or multicast?  Check broadcast first,
	 * since the test for a multicast frame will test positive on
	 * a broadcast frame.
	 */
	if ((mac_addr[0] == (uint8_t)0xff) &&
	    (mac_addr[1] == (uint8_t)0xff)) {
		/*
		 * Broadcast packet
		 */
		Adapter->brdcstrcv++;
	} else if (*mac_addr & 0x01) {
		/*
		 * Multicast packet
		 */
		Adapter->multircv++;
	}

	if (frame_len == Adapter->max_frame_size) {
		/*
		 * In this case, the hardware has overcounted the number of
		 * oversize frames.
		 */
		if (Adapter->toolong_errors > 0)
			Adapter->toolong_errors--;
	}

#ifdef E1000G_DEBUG
	/*
	 * Adjust the bin counters when the extra byte put the frame in the
	 * wrong bin. Remember that the frame_len was adjusted above.
	 */
	if (frame_len == 64) {
		e1000g_ksp->Prc64.value.ul++;
		e1000g_ksp->Prc127.value.ul--;
	} else if (frame_len == 127) {
		e1000g_ksp->Prc127.value.ul++;
		e1000g_ksp->Prc255.value.ul--;
	} else if (frame_len == 255) {
		e1000g_ksp->Prc255.value.ul++;
		e1000g_ksp->Prc511.value.ul--;
	} else if (frame_len == 511) {
		e1000g_ksp->Prc511.value.ul++;
		e1000g_ksp->Prc1023.value.ul--;
	} else if (frame_len == 1023) {
		e1000g_ksp->Prc1023.value.ul++;
		e1000g_ksp->Prc1522.value.ul--;
	} else if (frame_len == 1522) {
		e1000g_ksp->Prc1522.value.ul++;
	}
#endif
}


/*
 * e1000g_update_stats - update driver private kstat counters
 *
 * This routine will dump and reset the e1000's internal
 * statistics counters. The current stats dump values will
 * be sent to the kernel status area.
 */
static int
e1000g_update_stats(kstat_t *ksp, int rw)
{
	struct e1000g *Adapter;
	struct e1000_hw *hw;
	p_e1000g_stat_t e1000g_ksp;
	e1000g_tx_ring_t *tx_ring;
	e1000g_rx_ring_t *rx_ring;
#ifdef E1000G_DEBUG
	e1000g_rx_data_t *rx_data;
#endif
	uint64_t val;
	uint32_t low_val, high_val;

	if (rw == KSTAT_WRITE)
		return (EACCES);

	Adapter = (struct e1000g *)ksp->ks_private;
	ASSERT(Adapter != NULL);
	e1000g_ksp = (p_e1000g_stat_t)ksp->ks_data;
	ASSERT(e1000g_ksp != NULL);
	hw = &Adapter->shared;

	tx_ring = Adapter->tx_ring;
	rx_ring = Adapter->rx_ring;
#ifdef E1000G_DEBUG
	rx_data = rx_ring->rx_data;
#endif

	rw_enter(&Adapter->chip_lock, RW_WRITER);

	e1000g_ksp->reset_count.value.ul = Adapter->reset_count;

	e1000g_ksp->rx_error.value.ul = rx_ring->stat_error;
	e1000g_ksp->rx_allocb_fail.value.ul = rx_ring->stat_allocb_fail;
	e1000g_ksp->rx_size_error.value.ul = rx_ring->stat_size_error;

	e1000g_ksp->tx_no_swpkt.value.ul = tx_ring->stat_no_swpkt;
	e1000g_ksp->tx_no_desc.value.ul = tx_ring->stat_no_desc;
	e1000g_ksp->tx_send_fail.value.ul = tx_ring->stat_send_fail;
	e1000g_ksp->tx_reschedule.value.ul = tx_ring->stat_reschedule;
	e1000g_ksp->tx_over_size.value.ul = tx_ring->stat_over_size;

#ifdef E1000G_DEBUG
	e1000g_ksp->rx_none.value.ul = rx_ring->stat_none;
	e1000g_ksp->rx_multi_desc.value.ul = rx_ring->stat_multi_desc;
	e1000g_ksp->rx_no_freepkt.value.ul = rx_ring->stat_no_freepkt;
	if (rx_data != NULL)
		e1000g_ksp->rx_avail_freepkt.value.ul = rx_data->avail_freepkt;

	e1000g_ksp->tx_under_size.value.ul = tx_ring->stat_under_size;
	e1000g_ksp->tx_exceed_frags.value.ul = tx_ring->stat_exceed_frags;
	e1000g_ksp->tx_empty_frags.value.ul = tx_ring->stat_empty_frags;
	e1000g_ksp->tx_recycle.value.ul = tx_ring->stat_recycle;
	e1000g_ksp->tx_recycle_intr.value.ul = tx_ring->stat_recycle_intr;
	e1000g_ksp->tx_recycle_retry.value.ul = tx_ring->stat_recycle_retry;
	e1000g_ksp->tx_recycle_none.value.ul = tx_ring->stat_recycle_none;
	e1000g_ksp->tx_copy.value.ul = tx_ring->stat_copy;
	e1000g_ksp->tx_bind.value.ul = tx_ring->stat_bind;
	e1000g_ksp->tx_multi_copy.value.ul = tx_ring->stat_multi_copy;
	e1000g_ksp->tx_multi_cookie.value.ul = tx_ring->stat_multi_cookie;
	e1000g_ksp->tx_lack_desc.value.ul = tx_ring->stat_lack_desc;
#endif

	/*
	 * Standard Stats
	 */
	e1000g_ksp->Mpc.value.ul += E1000_READ_REG(hw, E1000_MPC);
	e1000g_ksp->Rlec.value.ul += E1000_READ_REG(hw, E1000_RLEC);
	e1000g_ksp->Xonrxc.value.ul += E1000_READ_REG(hw, E1000_XONRXC);
	e1000g_ksp->Xontxc.value.ul += E1000_READ_REG(hw, E1000_XONTXC);
	e1000g_ksp->Xoffrxc.value.ul += E1000_READ_REG(hw, E1000_XOFFRXC);
	e1000g_ksp->Xofftxc.value.ul += E1000_READ_REG(hw, E1000_XOFFTXC);
	e1000g_ksp->Fcruc.value.ul += E1000_READ_REG(hw, E1000_FCRUC);

	if ((hw->mac.type != e1000_ich8lan) &&
	    (hw->mac.type != e1000_ich9lan) &&
	    (hw->mac.type != e1000_ich10lan) &&
	    (hw->mac.type != e1000_pchlan)) {
		e1000g_ksp->Symerrs.value.ul +=
		    E1000_READ_REG(hw, E1000_SYMERRS);
#ifdef E1000G_DEBUG
		e1000g_ksp->Prc64.value.ul +=
		    E1000_READ_REG(hw, E1000_PRC64);
		e1000g_ksp->Prc127.value.ul +=
		    E1000_READ_REG(hw, E1000_PRC127);
		e1000g_ksp->Prc255.value.ul +=
		    E1000_READ_REG(hw, E1000_PRC255);
		e1000g_ksp->Prc511.value.ul +=
		    E1000_READ_REG(hw, E1000_PRC511);
		e1000g_ksp->Prc1023.value.ul +=
		    E1000_READ_REG(hw, E1000_PRC1023);
		e1000g_ksp->Prc1522.value.ul +=
		    E1000_READ_REG(hw, E1000_PRC1522);

		e1000g_ksp->Ptc64.value.ul +=
		    E1000_READ_REG(hw, E1000_PTC64);
		e1000g_ksp->Ptc127.value.ul +=
		    E1000_READ_REG(hw, E1000_PTC127);
		e1000g_ksp->Ptc255.value.ul +=
		    E1000_READ_REG(hw, E1000_PTC255);
		e1000g_ksp->Ptc511.value.ul +=
		    E1000_READ_REG(hw, E1000_PTC511);
		e1000g_ksp->Ptc1023.value.ul +=
		    E1000_READ_REG(hw, E1000_PTC1023);
		e1000g_ksp->Ptc1522.value.ul +=
		    E1000_READ_REG(hw, E1000_PTC1522);
#endif
	}

	e1000g_ksp->Gprc.value.ul += E1000_READ_REG(hw, E1000_GPRC);
	e1000g_ksp->Gptc.value.ul += E1000_READ_REG(hw, E1000_GPTC);
	e1000g_ksp->Rfc.value.ul += E1000_READ_REG(hw, E1000_RFC);
	e1000g_ksp->Tncrs.value.ul += e1000g_read_phy_stat(hw, E1000_TNCRS);
	e1000g_ksp->Tsctc.value.ul += E1000_READ_REG(hw, E1000_TSCTC);
	e1000g_ksp->Tsctfc.value.ul += E1000_READ_REG(hw, E1000_TSCTFC);

	/*
	 * Adaptive Calculations
	 */
	hw->mac.tx_packet_delta = E1000_READ_REG(hw, E1000_TPT);
	Adapter->opackets += hw->mac.tx_packet_delta;

	/*
	 * The 64-bit register will reset whenever the upper
	 * 32 bits are read. So we need to read the lower
	 * 32 bits first, then read the upper 32 bits.
	 */
	low_val = E1000_READ_REG(hw, E1000_GORCL);
	high_val = E1000_READ_REG(hw, E1000_GORCH);
	val = (uint64_t)e1000g_ksp->Gorh.value.ul << 32 |
	    (uint64_t)e1000g_ksp->Gorl.value.ul;
	val += (uint64_t)high_val << 32 | (uint64_t)low_val;
	e1000g_ksp->Gorl.value.ul = (uint32_t)val;
	e1000g_ksp->Gorh.value.ul = (uint32_t)(val >> 32);

	low_val = E1000_READ_REG(hw, E1000_GOTCL);
	high_val = E1000_READ_REG(hw, E1000_GOTCH);
	val = (uint64_t)e1000g_ksp->Goth.value.ul << 32 |
	    (uint64_t)e1000g_ksp->Gotl.value.ul;
	val += (uint64_t)high_val << 32 | (uint64_t)low_val;
	e1000g_ksp->Gotl.value.ul = (uint32_t)val;
	e1000g_ksp->Goth.value.ul = (uint32_t)(val >> 32);

	low_val = E1000_READ_REG(hw, E1000_TORL);
	high_val = E1000_READ_REG(hw, E1000_TORH);
	Adapter->rbytes +=
	    (uint64_t)high_val << 32 | (uint64_t)low_val;

	low_val = E1000_READ_REG(hw, E1000_TOTL);
	high_val = E1000_READ_REG(hw, E1000_TOTH);
	Adapter->obytes +=
	    (uint64_t)high_val << 32 | (uint64_t)low_val;

	rw_exit(&Adapter->chip_lock);

	if (e1000g_check_acc_handle(Adapter->osdep.reg_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(Adapter->dip, DDI_SERVICE_UNAFFECTED);
		return (EIO);
	}

	return (0);
}

int
e1000g_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	struct e1000g *Adapter = (struct e1000g *)arg;
	struct e1000_hw *hw = &Adapter->shared;
	p_e1000g_stat_t e1000g_ksp;
	uint32_t low_val, high_val;

	e1000g_ksp = (p_e1000g_stat_t)Adapter->e1000g_ksp->ks_data;

	rw_enter(&Adapter->chip_lock, RW_READER);

	if (Adapter->e1000g_state & E1000G_SUSPENDED) {
		rw_exit(&Adapter->chip_lock);
		return (ECANCELED);
	}

	switch (stat) {
	case MAC_STAT_IFSPEED:
		*val = Adapter->link_speed * 1000000ull;
		break;

	case MAC_STAT_MULTIRCV:
		Adapter->multircv +=
		    E1000_READ_REG(hw, E1000_MPRC);
		*val = Adapter->multircv;
		break;

	case MAC_STAT_BRDCSTRCV:
		Adapter->brdcstrcv +=
		    E1000_READ_REG(hw, E1000_BPRC);
		*val = Adapter->brdcstrcv;
		break;

	case MAC_STAT_MULTIXMT:
		Adapter->multixmt +=
		    E1000_READ_REG(hw, E1000_MPTC);
		*val = Adapter->multixmt;
		break;

	case MAC_STAT_BRDCSTXMT:
		Adapter->brdcstxmt +=
		    E1000_READ_REG(hw, E1000_BPTC);
		*val = Adapter->brdcstxmt;
		break;

	case MAC_STAT_NORCVBUF:
		Adapter->norcvbuf +=
		    E1000_READ_REG(hw, E1000_RNBC);
		*val = Adapter->norcvbuf;
		break;

	case MAC_STAT_IERRORS:
		Adapter->macrcv_errors +=
		    E1000_READ_REG(hw, E1000_RXERRC);
		Adapter->align_errors +=
		    E1000_READ_REG(hw, E1000_ALGNERRC);
		e1000g_ksp->Rlec.value.ul +=
		    E1000_READ_REG(hw, E1000_RLEC);
		Adapter->fcs_errors +=
		    E1000_READ_REG(hw, E1000_CRCERRS);
		Adapter->carrier_errors +=
		    E1000_READ_REG(hw, E1000_CEXTERR);
		*val = Adapter->macrcv_errors +
		    Adapter->align_errors +
		    e1000g_ksp->Rlec.value.ul +
		    Adapter->fcs_errors +
		    Adapter->carrier_errors;
		break;

	case MAC_STAT_NOXMTBUF:
		*val = Adapter->tx_ring->stat_no_desc;
		break;

	case MAC_STAT_OERRORS:
		Adapter->oerrors +=
		    e1000g_read_phy_stat(hw, E1000_ECOL);
		*val = Adapter->oerrors;
		break;

	case MAC_STAT_COLLISIONS:
		Adapter->collisions +=
		    e1000g_read_phy_stat(hw, E1000_COLC);
		*val = Adapter->collisions;
		break;

	case MAC_STAT_RBYTES:
		/*
		 * The 64-bit register will reset whenever the upper
		 * 32 bits are read. So we need to read the lower
		 * 32 bits first, then read the upper 32 bits.
		 */
		low_val = E1000_READ_REG(hw, E1000_TORL);
		high_val = E1000_READ_REG(hw, E1000_TORH);
		Adapter->rbytes +=
		    (uint64_t)high_val << 32 | (uint64_t)low_val;
		*val = Adapter->rbytes;
		break;

	case MAC_STAT_IPACKETS:
		Adapter->ipackets +=
		    E1000_READ_REG(hw, E1000_TPR);
		*val = Adapter->ipackets;
		break;

	case MAC_STAT_OBYTES:
		/*
		 * The 64-bit register will reset whenever the upper
		 * 32 bits are read. So we need to read the lower
		 * 32 bits first, then read the upper 32 bits.
		 */
		low_val = E1000_READ_REG(hw, E1000_TOTL);
		high_val = E1000_READ_REG(hw, E1000_TOTH);
		Adapter->obytes +=
		    (uint64_t)high_val << 32 | (uint64_t)low_val;
		*val = Adapter->obytes;
		break;

	case MAC_STAT_OPACKETS:
		Adapter->opackets +=
		    E1000_READ_REG(hw, E1000_TPT);
		*val = Adapter->opackets;
		break;

	case ETHER_STAT_ALIGN_ERRORS:
		Adapter->align_errors +=
		    E1000_READ_REG(hw, E1000_ALGNERRC);
		*val = Adapter->align_errors;
		break;

	case ETHER_STAT_FCS_ERRORS:
		Adapter->fcs_errors +=
		    E1000_READ_REG(hw, E1000_CRCERRS);
		*val = Adapter->fcs_errors;
		break;

	case ETHER_STAT_SQE_ERRORS:
		Adapter->sqe_errors +=
		    E1000_READ_REG(hw, E1000_SEC);
		*val = Adapter->sqe_errors;
		break;

	case ETHER_STAT_CARRIER_ERRORS:
		Adapter->carrier_errors +=
		    E1000_READ_REG(hw, E1000_CEXTERR);
		*val = Adapter->carrier_errors;
		break;

	case ETHER_STAT_EX_COLLISIONS:
		Adapter->ex_collisions +=
		    e1000g_read_phy_stat(hw, E1000_ECOL);
		*val = Adapter->ex_collisions;
		break;

	case ETHER_STAT_TX_LATE_COLLISIONS:
		Adapter->tx_late_collisions +=
		    e1000g_read_phy_stat(hw, E1000_LATECOL);
		*val = Adapter->tx_late_collisions;
		break;

	case ETHER_STAT_DEFER_XMTS:
		Adapter->defer_xmts +=
		    e1000g_read_phy_stat(hw, E1000_DC);
		*val = Adapter->defer_xmts;
		break;

	case ETHER_STAT_FIRST_COLLISIONS:
		Adapter->first_collisions +=
		    e1000g_read_phy_stat(hw, E1000_SCC);
		*val = Adapter->first_collisions;
		break;

	case ETHER_STAT_MULTI_COLLISIONS:
		Adapter->multi_collisions +=
		    e1000g_read_phy_stat(hw, E1000_MCC);
		*val = Adapter->multi_collisions;
		break;

	case ETHER_STAT_MACRCV_ERRORS:
		Adapter->macrcv_errors +=
		    E1000_READ_REG(hw, E1000_RXERRC);
		*val = Adapter->macrcv_errors;
		break;

	case ETHER_STAT_MACXMT_ERRORS:
		Adapter->macxmt_errors +=
		    e1000g_read_phy_stat(hw, E1000_ECOL);
		*val = Adapter->macxmt_errors;
		break;

	case ETHER_STAT_TOOLONG_ERRORS:
		Adapter->toolong_errors +=
		    E1000_READ_REG(hw, E1000_ROC);
		*val = Adapter->toolong_errors;
		break;

	case ETHER_STAT_TOOSHORT_ERRORS:
		Adapter->tooshort_errors +=
		    E1000_READ_REG(hw, E1000_RUC);
		*val = Adapter->tooshort_errors;
		break;

	case ETHER_STAT_JABBER_ERRORS:
		Adapter->jabber_errors +=
		    E1000_READ_REG(hw, E1000_RJC);
		*val = Adapter->jabber_errors;
		break;

	case ETHER_STAT_XCVR_ADDR:
		/* The Internal PHY's MDI address for each MAC is 1 */
		*val = 1;
		break;

	case ETHER_STAT_XCVR_ID:
		*val = hw->phy.id | hw->phy.revision;
		break;

	case ETHER_STAT_XCVR_INUSE:
		switch (Adapter->link_speed) {
		case SPEED_1000:
			*val =
			    (hw->phy.media_type == e1000_media_type_copper) ?
			    XCVR_1000T : XCVR_1000X;
			break;
		case SPEED_100:
			*val =
			    (hw->phy.media_type == e1000_media_type_copper) ?
			    (Adapter->phy_status & MII_SR_100T4_CAPS) ?
			    XCVR_100T4 : XCVR_100T2 : XCVR_100X;
			break;
		case SPEED_10:
			*val = XCVR_10;
			break;
		default:
			*val = XCVR_NONE;
			break;
		}
		break;

	case ETHER_STAT_CAP_1000FDX:
		*val = Adapter->param_1000fdx_cap;
		break;

	case ETHER_STAT_CAP_1000HDX:
		*val = Adapter->param_1000hdx_cap;
		break;

	case ETHER_STAT_CAP_100FDX:
		*val = Adapter->param_100fdx_cap;
		break;

	case ETHER_STAT_CAP_100HDX:
		*val = Adapter->param_100hdx_cap;
		break;

	case ETHER_STAT_CAP_10FDX:
		*val = Adapter->param_10fdx_cap;
		break;

	case ETHER_STAT_CAP_10HDX:
		*val = Adapter->param_10hdx_cap;
		break;

	case ETHER_STAT_CAP_ASMPAUSE:
		*val = Adapter->param_asym_pause_cap;
		break;

	case ETHER_STAT_CAP_PAUSE:
		*val = Adapter->param_pause_cap;
		break;

	case ETHER_STAT_CAP_AUTONEG:
		*val = Adapter->param_autoneg_cap;
		break;

	case ETHER_STAT_ADV_CAP_1000FDX:
		*val = Adapter->param_adv_1000fdx;
		break;

	case ETHER_STAT_ADV_CAP_1000HDX:
		*val = Adapter->param_adv_1000hdx;
		break;

	case ETHER_STAT_ADV_CAP_100FDX:
		*val = Adapter->param_adv_100fdx;
		break;

	case ETHER_STAT_ADV_CAP_100HDX:
		*val = Adapter->param_adv_100hdx;
		break;

	case ETHER_STAT_ADV_CAP_10FDX:
		*val = Adapter->param_adv_10fdx;
		break;

	case ETHER_STAT_ADV_CAP_10HDX:
		*val = Adapter->param_adv_10hdx;
		break;

	case ETHER_STAT_ADV_CAP_ASMPAUSE:
		*val = Adapter->param_adv_asym_pause;
		break;

	case ETHER_STAT_ADV_CAP_PAUSE:
		*val = Adapter->param_adv_pause;
		break;

	case ETHER_STAT_ADV_CAP_AUTONEG:
		*val = hw->mac.autoneg;
		break;

	case ETHER_STAT_LP_CAP_1000FDX:
		*val = Adapter->param_lp_1000fdx;
		break;

	case ETHER_STAT_LP_CAP_1000HDX:
		*val = Adapter->param_lp_1000hdx;
		break;

	case ETHER_STAT_LP_CAP_100FDX:
		*val = Adapter->param_lp_100fdx;
		break;

	case ETHER_STAT_LP_CAP_100HDX:
		*val = Adapter->param_lp_100hdx;
		break;

	case ETHER_STAT_LP_CAP_10FDX:
		*val = Adapter->param_lp_10fdx;
		break;

	case ETHER_STAT_LP_CAP_10HDX:
		*val = Adapter->param_lp_10hdx;
		break;

	case ETHER_STAT_LP_CAP_ASMPAUSE:
		*val = Adapter->param_lp_asym_pause;
		break;

	case ETHER_STAT_LP_CAP_PAUSE:
		*val = Adapter->param_lp_pause;
		break;

	case ETHER_STAT_LP_CAP_AUTONEG:
		*val = Adapter->param_lp_autoneg;
		break;

	case ETHER_STAT_LINK_ASMPAUSE:
		*val = Adapter->param_asym_pause_cap;
		break;

	case ETHER_STAT_LINK_PAUSE:
		*val = Adapter->param_pause_cap;
		break;

	case ETHER_STAT_LINK_AUTONEG:
		*val = hw->mac.autoneg;
		break;

	case ETHER_STAT_LINK_DUPLEX:
		*val = (Adapter->link_duplex == FULL_DUPLEX) ?
		    LINK_DUPLEX_FULL : LINK_DUPLEX_HALF;
		break;

	case ETHER_STAT_CAP_100T4:
		*val = Adapter->param_100t4_cap;
		break;

	case ETHER_STAT_ADV_CAP_100T4:
		*val = Adapter->param_adv_100t4;
		break;

	case ETHER_STAT_LP_CAP_100T4:
		*val = Adapter->param_lp_100t4;
		break;

	default:
		rw_exit(&Adapter->chip_lock);
		return (ENOTSUP);
	}

	rw_exit(&Adapter->chip_lock);

	if (e1000g_check_acc_handle(Adapter->osdep.reg_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(Adapter->dip, DDI_SERVICE_UNAFFECTED);
		return (EIO);
	}

	return (0);
}

/*
 * e1000g_init_stats - initialize kstat data structures
 *
 * This routine will create and initialize the driver private
 * statistics counters.
 */
int
e1000g_init_stats(struct e1000g *Adapter)
{
	kstat_t *ksp;
	p_e1000g_stat_t e1000g_ksp;

	/*
	 * Create and init kstat
	 */
	ksp = kstat_create(WSNAME, ddi_get_instance(Adapter->dip),
	    "statistics", "net", KSTAT_TYPE_NAMED,
	    sizeof (e1000g_stat_t) / sizeof (kstat_named_t), 0);

	if (ksp == NULL) {
		e1000g_log(Adapter, CE_WARN,
		    "Could not create kernel statistics\n");
		return (DDI_FAILURE);
	}

	Adapter->e1000g_ksp = ksp;	/* Fill in the Adapters ksp */

	e1000g_ksp = (p_e1000g_stat_t)ksp->ks_data;

	/*
	 * Initialize all the statistics
	 */
	kstat_named_init(&e1000g_ksp->reset_count, "Reset Count",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->rx_error, "Rx Error",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&e1000g_ksp->rx_allocb_fail, "Rx Allocb Failure",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&e1000g_ksp->rx_size_error, "Rx Size Error",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->tx_no_desc, "Tx No Desc",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&e1000g_ksp->tx_no_swpkt, "Tx No Buffer",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&e1000g_ksp->tx_send_fail, "Tx Send Failure",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&e1000g_ksp->tx_over_size, "Tx Pkt Over Size",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&e1000g_ksp->tx_reschedule, "Tx Reschedule",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->Mpc, "Recv_Missed_Packets",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&e1000g_ksp->Symerrs, "Recv_Symbol_Errors",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&e1000g_ksp->Rlec, "Recv_Length_Errors",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&e1000g_ksp->Xonrxc, "XONs_Recvd",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&e1000g_ksp->Xontxc, "XONs_Xmitd",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&e1000g_ksp->Xoffrxc, "XOFFs_Recvd",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&e1000g_ksp->Xofftxc, "XOFFs_Xmitd",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&e1000g_ksp->Fcruc, "Recv_Unsupport_FC_Pkts",
	    KSTAT_DATA_ULONG);
#ifdef E1000G_DEBUG
	kstat_named_init(&e1000g_ksp->Prc64, "Pkts_Recvd_(  64b)",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&e1000g_ksp->Prc127, "Pkts_Recvd_(  65- 127b)",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&e1000g_ksp->Prc255, "Pkts_Recvd_( 127- 255b)",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&e1000g_ksp->Prc511, "Pkts_Recvd_( 256- 511b)",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&e1000g_ksp->Prc1023, "Pkts_Recvd_( 511-1023b)",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&e1000g_ksp->Prc1522, "Pkts_Recvd_(1024-1522b)",
	    KSTAT_DATA_ULONG);
#endif
	kstat_named_init(&e1000g_ksp->Gprc, "Good_Pkts_Recvd",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&e1000g_ksp->Gptc, "Good_Pkts_Xmitd",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&e1000g_ksp->Gorl, "Good_Octets_Recvd_Lo",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&e1000g_ksp->Gorh, "Good_Octets_Recvd_Hi",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&e1000g_ksp->Gotl, "Good_Octets_Xmitd_Lo",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&e1000g_ksp->Goth, "Good_Octets_Xmitd_Hi",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&e1000g_ksp->Rfc, "Recv_Frag",
	    KSTAT_DATA_ULONG);
#ifdef E1000G_DEBUG
	kstat_named_init(&e1000g_ksp->Ptc64, "Pkts_Xmitd_(  64b)",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&e1000g_ksp->Ptc127, "Pkts_Xmitd_(  65- 127b)",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&e1000g_ksp->Ptc255, "Pkts_Xmitd_( 128- 255b)",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&e1000g_ksp->Ptc511, "Pkts_Xmitd_( 255- 511b)",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&e1000g_ksp->Ptc1023, "Pkts_Xmitd_( 512-1023b)",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&e1000g_ksp->Ptc1522, "Pkts_Xmitd_(1024-1522b)",
	    KSTAT_DATA_ULONG);
#endif
	kstat_named_init(&e1000g_ksp->Tncrs, "Xmit_with_No_CRS",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&e1000g_ksp->Tsctc, "Xmit_TCP_Seg_Contexts",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&e1000g_ksp->Tsctfc, "Xmit_TCP_Seg_Contexts_Fail",
	    KSTAT_DATA_ULONG);

#ifdef E1000G_DEBUG
	kstat_named_init(&e1000g_ksp->rx_none, "Rx No Data",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&e1000g_ksp->rx_multi_desc, "Rx Span Multi Desc",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&e1000g_ksp->rx_no_freepkt, "Rx Freelist Empty",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&e1000g_ksp->rx_avail_freepkt, "Rx Freelist Avail",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&e1000g_ksp->tx_under_size, "Tx Pkt Under Size",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&e1000g_ksp->tx_exceed_frags, "Tx Exceed Max Frags",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&e1000g_ksp->tx_empty_frags, "Tx Empty Frags",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&e1000g_ksp->tx_recycle, "Tx Recycle",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&e1000g_ksp->tx_recycle_intr, "Tx Recycle Intr",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&e1000g_ksp->tx_recycle_retry, "Tx Recycle Retry",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&e1000g_ksp->tx_recycle_none, "Tx Recycled None",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&e1000g_ksp->tx_copy, "Tx Send Copy",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&e1000g_ksp->tx_bind, "Tx Send Bind",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&e1000g_ksp->tx_multi_copy, "Tx Copy Multi Frags",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&e1000g_ksp->tx_multi_cookie, "Tx Bind Multi Cookies",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&e1000g_ksp->tx_lack_desc, "Tx Desc Insufficient",
	    KSTAT_DATA_ULONG);
#endif

	/*
	 * Function to provide kernel stat update on demand
	 */
	ksp->ks_update = e1000g_update_stats;

	/*
	 * Pointer into provider's raw statistics
	 */
	ksp->ks_private = (void *)Adapter;

	/*
	 * Add kstat to systems kstat chain
	 */
	kstat_install(ksp);

	return (DDI_SUCCESS);
}

/*
 * e1000g_read_phy_stat - read certain PHY statistics
 *
 * Certain statistics are read from MAC registers on some silicon types
 * but are read from the PHY on other silicon types.  This routine
 * handles that difference as needed.
 */
static uint32_t
e1000g_read_phy_stat(struct e1000_hw *hw, int reg)
{
	uint16_t phy_low, phy_high;
	uint32_t val;

	/* get statistic from PHY in these cases */
	if ((hw->phy.type == e1000_phy_82578) ||
	    (hw->phy.type == e1000_phy_82577)) {

		switch (reg) {
		case E1000_SCC:
			(void) e1000_read_phy_reg(hw, HV_SCC_UPPER, &phy_high);
			(void) e1000_read_phy_reg(hw, HV_SCC_LOWER, &phy_low);
			val = ((uint32_t)phy_high << 16) | (uint32_t)phy_low;
			break;

		case E1000_MCC:
			(void) e1000_read_phy_reg(hw, HV_MCC_UPPER, &phy_high);
			(void) e1000_read_phy_reg(hw, HV_MCC_LOWER, &phy_low);
			val = ((uint32_t)phy_high << 16) | (uint32_t)phy_low;
			break;

		case E1000_ECOL:
			(void) e1000_read_phy_reg(hw, HV_ECOL_UPPER, &phy_high);
			(void) e1000_read_phy_reg(hw, HV_ECOL_LOWER, &phy_low);
			val = ((uint32_t)phy_high << 16) | (uint32_t)phy_low;
			break;

		case E1000_COLC:
			(void) e1000_read_phy_reg(hw, HV_COLC_UPPER, &phy_high);
			(void) e1000_read_phy_reg(hw, HV_COLC_LOWER, &phy_low);
			val = ((uint32_t)phy_high << 16) | (uint32_t)phy_low;
			break;

		case E1000_LATECOL:
			(void) e1000_read_phy_reg(hw, HV_LATECOL_UPPER,
			    &phy_high);
			(void) e1000_read_phy_reg(hw, HV_LATECOL_LOWER,
			    &phy_low);
			val = ((uint32_t)phy_high << 16) | (uint32_t)phy_low;
			break;

		case E1000_DC:
			(void) e1000_read_phy_reg(hw, HV_DC_UPPER, &phy_high);
			(void) e1000_read_phy_reg(hw, HV_DC_LOWER, &phy_low);
			val = ((uint32_t)phy_high << 16) | (uint32_t)phy_low;
			break;

		case E1000_TNCRS:
			(void) e1000_read_phy_reg(hw, HV_TNCRS_UPPER,
			    &phy_high);
			(void) e1000_read_phy_reg(hw, HV_TNCRS_LOWER,
			    &phy_low);
			val = ((uint32_t)phy_high << 16) | (uint32_t)phy_low;
			break;

		default:
			break;
		}

	/* get statistic from MAC otherwise */
	} else {
		val = E1000_READ_REG(hw, reg);
	}

	return (val);
}

/*
 * Retrieve a value for one of the statistics for a particular rx ring
 */
int
e1000g_rx_ring_stat(mac_ring_driver_t rh, uint_t stat, uint64_t *val)
{
	e1000g_rx_ring_t *rx_ring = (e1000g_rx_ring_t *)rh;
	struct e1000g *Adapter = rx_ring->adapter;
	struct e1000_hw *hw = &Adapter->shared;
	uint32_t low_val, high_val;

	rw_enter(&Adapter->chip_lock, RW_READER);

	if (Adapter->e1000g_state & E1000G_SUSPENDED) {
		rw_exit(&Adapter->chip_lock);
		return (ECANCELED);
	}

	switch (stat) {
	case MAC_STAT_RBYTES:
		/*
		 * The 64-bit register will reset whenever the upper
		 * 32 bits are read. So we need to read the lower
		 * 32 bits first, then read the upper 32 bits.
		 */
		low_val = E1000_READ_REG(hw, E1000_TORL);
		high_val = E1000_READ_REG(hw, E1000_TORH);
		Adapter->rbytes +=
		    (uint64_t)high_val << 32 | (uint64_t)low_val;
		*val = Adapter->rbytes;
		break;

	case MAC_STAT_IPACKETS:
		Adapter->ipackets +=
		    E1000_READ_REG(hw, E1000_TPR);
		*val = Adapter->ipackets;
		break;

	default:
		*val = 0;
		rw_exit(&Adapter->chip_lock);
		return (ENOTSUP);
	}

	rw_exit(&Adapter->chip_lock);

	if (e1000g_check_acc_handle(Adapter->osdep.reg_handle) != DDI_FM_OK)
		ddi_fm_service_impact(Adapter->dip, DDI_SERVICE_UNAFFECTED);

	return (0);
}
