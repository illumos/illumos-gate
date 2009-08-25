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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "ixgbe_sw.h"

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

	ixgbe_ks = (ixgbe_stat_t *)ixgbe->ixgbe_ks->ks_data;

	mutex_enter(&ixgbe->gen_lock);

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
		for (i = 0; i < 8; i++) {
			ixgbe_ks->rnbc.value.ui64 +=
			    IXGBE_READ_REG(hw, IXGBE_RNBC(i));
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
		ixgbe_ks->tor.value.ui64 = 0;
		for (i = 0; i < 16; i++) {
			ixgbe_ks->qbrc[i].value.ui64 +=
			    IXGBE_READ_REG(hw, IXGBE_QBRC(i));
			ixgbe_ks->tor.value.ui64 +=
			    ixgbe_ks->qbrc[i].value.ui64;
		}
		*val = ixgbe_ks->tor.value.ui64;
		break;

	case MAC_STAT_OBYTES:
		ixgbe_ks->tot.value.ui64 = 0;
		for (i = 0; i < 16; i++) {
			if (hw->mac.type >= ixgbe_mac_82599EB) {
				ixgbe_ks->qbtc[i].value.ui64 +=
				    IXGBE_READ_REG(hw, IXGBE_QBTC_L(i));
				ixgbe_ks->qbtc[i].value.ui64 += ((uint64_t)
				    IXGBE_READ_REG(hw, IXGBE_QBTC_H(i))) << 32;
			} else {
				ixgbe_ks->qbtc[i].value.ui64 +=
				    IXGBE_READ_REG(hw, IXGBE_QBTC(i));
			}
			ixgbe_ks->tot.value.ui64 +=
			    ixgbe_ks->qbtc[i].value.ui64;
		}
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
		*val = 1;
		break;

	case ETHER_STAT_CAP_1000FDX:
		*val = 1;
		break;

	case ETHER_STAT_CAP_100FDX:
		*val = 1;
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
		*val = hw->mac.autoneg;
		break;
	case ETHER_STAT_LINK_DUPLEX:
		*val = LINK_DUPLEX_FULL;
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

	if (ixgbe_check_acc_handle(ixgbe->osdep.reg_handle) != DDI_FM_OK)
		ddi_fm_service_impact(ixgbe->dip, DDI_SERVICE_UNAFFECTED);

	return (0);
}

/*
 * Bring the device out of the reset/quiesced state that it
 * was in when the interface was registered.
 */
int
ixgbe_m_start(void *arg)
{
	ixgbe_t *ixgbe = (ixgbe_t *)arg;

	mutex_enter(&ixgbe->gen_lock);

	if (ixgbe->ixgbe_state & IXGBE_SUSPENDED) {
		mutex_exit(&ixgbe->gen_lock);
		return (ECANCELED);
	}

	if (ixgbe_start(ixgbe, B_TRUE) != IXGBE_SUCCESS) {
		mutex_exit(&ixgbe->gen_lock);
		return (EIO);
	}

	ixgbe->ixgbe_state |= IXGBE_STARTED;

	mutex_exit(&ixgbe->gen_lock);

	/*
	 * Enable and start the watchdog timer
	 */
	ixgbe_enable_watchdog_timer(ixgbe);

	return (0);
}

/*
 * Stop the device and put it in a reset/quiesced state such
 * that the interface can be unregistered.
 */
void
ixgbe_m_stop(void *arg)
{
	ixgbe_t *ixgbe = (ixgbe_t *)arg;

	mutex_enter(&ixgbe->gen_lock);

	if (ixgbe->ixgbe_state & IXGBE_SUSPENDED) {
		mutex_exit(&ixgbe->gen_lock);
		return;
	}

	ixgbe->ixgbe_state &= ~IXGBE_STARTED;

	ixgbe_stop(ixgbe, B_TRUE);

	mutex_exit(&ixgbe->gen_lock);

	/*
	 * Disable and stop the watchdog timer
	 */
	ixgbe_disable_watchdog_timer(ixgbe);
}

/*
 * Set the promiscuity of the device.
 */
int
ixgbe_m_promisc(void *arg, boolean_t on)
{
	ixgbe_t *ixgbe = (ixgbe_t *)arg;
	uint32_t reg_val;
	struct ixgbe_hw *hw = &ixgbe->hw;

	mutex_enter(&ixgbe->gen_lock);

	if (ixgbe->ixgbe_state & IXGBE_SUSPENDED) {
		mutex_exit(&ixgbe->gen_lock);
		return (ECANCELED);
	}
	reg_val = IXGBE_READ_REG(hw, IXGBE_FCTRL);

	if (on)
		reg_val |= (IXGBE_FCTRL_UPE | IXGBE_FCTRL_MPE);
	else
		reg_val &= (~(IXGBE_FCTRL_UPE | IXGBE_FCTRL_MPE));

	IXGBE_WRITE_REG(&ixgbe->hw, IXGBE_FCTRL, reg_val);

	mutex_exit(&ixgbe->gen_lock);

	return (0);
}

/*
 * Add/remove the addresses to/from the set of multicast
 * addresses for which the device will receive packets.
 */
int
ixgbe_m_multicst(void *arg, boolean_t add, const uint8_t *mcst_addr)
{
	ixgbe_t *ixgbe = (ixgbe_t *)arg;
	int result;

	mutex_enter(&ixgbe->gen_lock);

	if (ixgbe->ixgbe_state & IXGBE_SUSPENDED) {
		mutex_exit(&ixgbe->gen_lock);
		return (ECANCELED);
	}

	result = (add) ? ixgbe_multicst_add(ixgbe, mcst_addr)
	    : ixgbe_multicst_remove(ixgbe, mcst_addr);

	mutex_exit(&ixgbe->gen_lock);

	return (result);
}

/*
 * Pass on M_IOCTL messages passed to the DLD, and support
 * private IOCTLs for debugging and ndd.
 */
void
ixgbe_m_ioctl(void *arg, queue_t *q, mblk_t *mp)
{
	ixgbe_t *ixgbe = (ixgbe_t *)arg;
	struct iocblk *iocp;
	enum ioc_reply status;

	iocp = (struct iocblk *)(uintptr_t)mp->b_rptr;
	iocp->ioc_error = 0;

	mutex_enter(&ixgbe->gen_lock);
	if (ixgbe->ixgbe_state & IXGBE_SUSPENDED) {
		mutex_exit(&ixgbe->gen_lock);
		miocnak(q, mp, 0, EINVAL);
		return;
	}
	mutex_exit(&ixgbe->gen_lock);

	switch (iocp->ioc_cmd) {
	case LB_GET_INFO_SIZE:
	case LB_GET_INFO:
	case LB_GET_MODE:
	case LB_SET_MODE:
		status = ixgbe_loopback_ioctl(ixgbe, iocp, mp);
		break;

	default:
		status = IOC_INVAL;
		break;
	}

	/*
	 * Decide how to reply
	 */
	switch (status) {
	default:
	case IOC_INVAL:
		/*
		 * Error, reply with a NAK and EINVAL or the specified error
		 */
		miocnak(q, mp, 0, iocp->ioc_error == 0 ?
		    EINVAL : iocp->ioc_error);
		break;

	case IOC_DONE:
		/*
		 * OK, reply already sent
		 */
		break;

	case IOC_ACK:
		/*
		 * OK, reply with an ACK
		 */
		miocack(q, mp, 0, 0);
		break;

	case IOC_REPLY:
		/*
		 * OK, send prepared reply as ACK or NAK
		 */
		mp->b_datap->db_type = iocp->ioc_error == 0 ?
		    M_IOCACK : M_IOCNAK;
		qreply(q, mp);
		break;
	}
}

/*
 * Obtain the MAC's capabilities and associated data from
 * the driver.
 */
boolean_t
ixgbe_m_getcapab(void *arg, mac_capab_t cap, void *cap_data)
{
	ixgbe_t *ixgbe = (ixgbe_t *)arg;

	switch (cap) {
	case MAC_CAPAB_HCKSUM: {
		uint32_t *tx_hcksum_flags = cap_data;

		/*
		 * We advertise our capabilities only if tx hcksum offload is
		 * enabled.  On receive, the stack will accept checksummed
		 * packets anyway, even if we haven't said we can deliver
		 * them.
		 */
		if (!ixgbe->tx_hcksum_enable)
			return (B_FALSE);

		*tx_hcksum_flags = HCKSUM_INET_PARTIAL | HCKSUM_IPHDRCKSUM;
		break;
	}
	case MAC_CAPAB_LSO: {
		mac_capab_lso_t *cap_lso = cap_data;

		if (ixgbe->lso_enable) {
			cap_lso->lso_flags = LSO_TX_BASIC_TCP_IPV4;
			cap_lso->lso_basic_tcp_ipv4.lso_max = IXGBE_LSO_MAXLEN;
			break;
		} else {
			return (B_FALSE);
		}
	}
	case MAC_CAPAB_RINGS: {
		mac_capab_rings_t *cap_rings = cap_data;

		switch (cap_rings->mr_type) {
		case MAC_RING_TYPE_RX:
			cap_rings->mr_group_type = MAC_GROUP_TYPE_STATIC;
			cap_rings->mr_rnum = ixgbe->num_rx_rings;
			cap_rings->mr_gnum = ixgbe->num_rx_groups;
			cap_rings->mr_rget = ixgbe_fill_ring;
			cap_rings->mr_gget = ixgbe_fill_group;
			cap_rings->mr_gaddring = NULL;
			cap_rings->mr_gremring = NULL;
			break;
		case MAC_RING_TYPE_TX:
			cap_rings->mr_group_type = MAC_GROUP_TYPE_STATIC;
			cap_rings->mr_rnum = ixgbe->num_tx_rings;
			cap_rings->mr_gnum = 0;
			cap_rings->mr_rget = ixgbe_fill_ring;
			cap_rings->mr_gget = NULL;
			break;
		default:
			break;
		}
		break;
	}
	default:
		return (B_FALSE);
	}
	return (B_TRUE);
}

int
ixgbe_m_setprop(void *arg, const char *pr_name, mac_prop_id_t pr_num,
    uint_t pr_valsize, const void *pr_val)
{
	ixgbe_t *ixgbe = (ixgbe_t *)arg;
	struct ixgbe_hw *hw = &ixgbe->hw;
	int err = 0;
	uint32_t flow_control;
	uint32_t cur_mtu, new_mtu;
	uint32_t rx_size;
	uint32_t tx_size;

	mutex_enter(&ixgbe->gen_lock);
	if (ixgbe->ixgbe_state & IXGBE_SUSPENDED) {
		mutex_exit(&ixgbe->gen_lock);
		return (ECANCELED);
	}

	if (ixgbe->loopback_mode != IXGBE_LB_NONE &&
	    ixgbe_param_locked(pr_num)) {
		/*
		 * All en_* parameters are locked (read-only)
		 * while the device is in any sort of loopback mode.
		 */
		mutex_exit(&ixgbe->gen_lock);
		return (EBUSY);
	}

	switch (pr_num) {
	case MAC_PROP_EN_10GFDX_CAP:
		/* read/write on copper, read-only on serdes */
		if (ixgbe->hw.phy.media_type != ixgbe_media_type_copper) {
			err = ENOTSUP;
			break;
		} else {
			ixgbe->param_en_10000fdx_cap = *(uint8_t *)pr_val;
			ixgbe->param_adv_10000fdx_cap = *(uint8_t *)pr_val;
			goto setup_link;
		}
	case MAC_PROP_EN_1000FDX_CAP:
		/* read/write on copper, read-only on serdes */
		if (ixgbe->hw.phy.media_type != ixgbe_media_type_copper) {
			err = ENOTSUP;
			break;
		} else {
			ixgbe->param_en_1000fdx_cap = *(uint8_t *)pr_val;
			ixgbe->param_adv_1000fdx_cap = *(uint8_t *)pr_val;
			goto setup_link;
		}
	case MAC_PROP_EN_100FDX_CAP:
		/* read/write on copper, read-only on serdes */
		if (ixgbe->hw.phy.media_type != ixgbe_media_type_copper) {
			err = ENOTSUP;
			break;
		} else {
			ixgbe->param_en_100fdx_cap = *(uint8_t *)pr_val;
			ixgbe->param_adv_100fdx_cap = *(uint8_t *)pr_val;
			goto setup_link;
		}
	case MAC_PROP_AUTONEG:
		/* read/write on copper, read-only on serdes */
		if (ixgbe->hw.phy.media_type != ixgbe_media_type_copper) {
			err = ENOTSUP;
			break;
		} else {
			ixgbe->param_adv_autoneg_cap = *(uint8_t *)pr_val;
			goto setup_link;
		}
	case MAC_PROP_FLOWCTRL:
		bcopy(pr_val, &flow_control, sizeof (flow_control));

		switch (flow_control) {
		default:
			err = EINVAL;
			break;
		case LINK_FLOWCTRL_NONE:
			hw->fc.requested_mode = ixgbe_fc_none;
			break;
		case LINK_FLOWCTRL_RX:
			hw->fc.requested_mode = ixgbe_fc_rx_pause;
			break;
		case LINK_FLOWCTRL_TX:
			hw->fc.requested_mode = ixgbe_fc_tx_pause;
			break;
		case LINK_FLOWCTRL_BI:
			hw->fc.requested_mode = ixgbe_fc_full;
			break;
		}
setup_link:
		if (err == 0) {
			if (ixgbe_driver_setup_link(ixgbe, B_TRUE) !=
			    IXGBE_SUCCESS)
				err = EINVAL;
		}
		break;
	case MAC_PROP_ADV_10GFDX_CAP:
	case MAC_PROP_ADV_1000FDX_CAP:
	case MAC_PROP_ADV_100FDX_CAP:
	case MAC_PROP_STATUS:
	case MAC_PROP_SPEED:
	case MAC_PROP_DUPLEX:
		err = ENOTSUP; /* read-only prop. Can't set this. */
		break;
	case MAC_PROP_MTU:
		cur_mtu = ixgbe->default_mtu;
		bcopy(pr_val, &new_mtu, sizeof (new_mtu));
		if (new_mtu == cur_mtu) {
			err = 0;
			break;
		}

		if (new_mtu < DEFAULT_MTU || new_mtu > MAX_MTU) {
			err = EINVAL;
			break;
		}

		if (ixgbe->ixgbe_state & IXGBE_STARTED) {
			err = EBUSY;
			break;
		}

		err = mac_maxsdu_update(ixgbe->mac_hdl, new_mtu);
		if (err == 0) {
			ixgbe->default_mtu = new_mtu;
			ixgbe->max_frame_size = ixgbe->default_mtu +
			    sizeof (struct ether_vlan_header) + ETHERFCSL;

			/*
			 * Set rx buffer size
			 */
			rx_size = ixgbe->max_frame_size + IPHDR_ALIGN_ROOM;
			ixgbe->rx_buf_size = ((rx_size >> 10) + ((rx_size &
			    (((uint32_t)1 << 10) - 1)) > 0 ? 1 : 0)) << 10;

			/*
			 * Set tx buffer size
			 */
			tx_size = ixgbe->max_frame_size;
			ixgbe->tx_buf_size = ((tx_size >> 10) + ((tx_size &
			    (((uint32_t)1 << 10) - 1)) > 0 ? 1 : 0)) << 10;
		}
		break;
	case MAC_PROP_PRIVATE:
		err = ixgbe_set_priv_prop(ixgbe, pr_name, pr_valsize, pr_val);
		break;
	default:
		err = EINVAL;
		break;
	}
	mutex_exit(&ixgbe->gen_lock);
	return (err);
}

int
ixgbe_m_getprop(void *arg, const char *pr_name, mac_prop_id_t pr_num,
    uint_t pr_flags, uint_t pr_valsize, void *pr_val, uint_t *perm)
{
	ixgbe_t *ixgbe = (ixgbe_t *)arg;
	struct ixgbe_hw *hw = &ixgbe->hw;
	int err = 0;
	uint32_t flow_control;
	uint64_t tmp = 0;
	boolean_t is_default = (pr_flags & MAC_PROP_DEFAULT);
	mac_propval_range_t range;

	if (pr_valsize == 0)
		return (EINVAL);

	*perm = MAC_PROP_PERM_READ;

	bzero(pr_val, pr_valsize);

	switch (pr_num) {
	case MAC_PROP_DUPLEX:
		if (pr_valsize >= sizeof (link_duplex_t)) {
			bcopy(&ixgbe->link_duplex, pr_val,
			    sizeof (link_duplex_t));
		} else
			err = EINVAL;
		break;
	case MAC_PROP_SPEED:
		if (pr_valsize >= sizeof (uint64_t)) {
			tmp = ixgbe->link_speed * 1000000ull;
			bcopy(&tmp, pr_val, sizeof (tmp));
		} else
			err = EINVAL;
		break;
	case MAC_PROP_AUTONEG:
		if (ixgbe->hw.phy.media_type == ixgbe_media_type_copper)
			*perm = MAC_PROP_PERM_RW;
		*(uint8_t *)pr_val =
		    (is_default ? 1 : ixgbe->param_adv_autoneg_cap);
		break;
	case MAC_PROP_FLOWCTRL:
		*perm = MAC_PROP_PERM_RW;
		if (pr_valsize >= sizeof (uint32_t)) {
			if (is_default) {
				flow_control = LINK_FLOWCTRL_NONE;
				bcopy(&flow_control, pr_val,
				    sizeof (flow_control));
				break;
			}
			switch (hw->fc.requested_mode) {
				case ixgbe_fc_none:
					flow_control = LINK_FLOWCTRL_NONE;
					break;
				case ixgbe_fc_rx_pause:
					flow_control = LINK_FLOWCTRL_RX;
					break;
				case ixgbe_fc_tx_pause:
					flow_control = LINK_FLOWCTRL_TX;
					break;
				case ixgbe_fc_full:
					flow_control = LINK_FLOWCTRL_BI;
					break;
			}
			bcopy(&flow_control, pr_val, sizeof (flow_control));
		} else
			err = EINVAL;
		break;
	case MAC_PROP_ADV_10GFDX_CAP:
		*(uint8_t *)pr_val = (is_default ? 1 :
		    ixgbe->param_adv_10000fdx_cap);
		break;
	case MAC_PROP_EN_10GFDX_CAP:
		if (ixgbe->hw.phy.media_type == ixgbe_media_type_copper)
			*perm = MAC_PROP_PERM_RW;
		*(uint8_t *)pr_val =
		    (is_default ? 1 : ixgbe->param_en_10000fdx_cap);
		break;
	case MAC_PROP_ADV_1000FDX_CAP:
		*(uint8_t *)pr_val = (is_default ? 1 :
		    ixgbe->param_adv_1000fdx_cap);
		break;
	case MAC_PROP_EN_1000FDX_CAP:
		if (ixgbe->hw.phy.media_type == ixgbe_media_type_copper)
			*perm = MAC_PROP_PERM_RW;
		*(uint8_t *)pr_val =
		    (is_default ? 1 : ixgbe->param_en_1000fdx_cap);
		break;
	case MAC_PROP_ADV_100FDX_CAP:
		*(uint8_t *)pr_val =
		    (is_default ? 1 : ixgbe->param_adv_100fdx_cap);
		break;
	case MAC_PROP_EN_100FDX_CAP:
		if (ixgbe->hw.phy.media_type == ixgbe_media_type_copper)
			*perm = MAC_PROP_PERM_RW;
		*(uint8_t *)pr_val =
		    (is_default ? 1 : ixgbe->param_en_100fdx_cap);
		break;
	case MAC_PROP_PRIVATE:
		err = ixgbe_get_priv_prop(ixgbe, pr_name,
		    pr_flags, pr_valsize, pr_val, perm);
		break;
	case MAC_PROP_MTU:
		if (!(pr_flags & MAC_PROP_POSSIBLE))
			return (ENOTSUP);
		if (pr_valsize < sizeof (mac_propval_range_t))
			return (EINVAL);
		range.mpr_count = 1;
		range.mpr_type = MAC_PROPVAL_UINT32;
		range.range_uint32[0].mpur_min = DEFAULT_MTU;
		range.range_uint32[0].mpur_max = MAX_MTU;
		bcopy(&range, pr_val, sizeof (range));
		break;
	default:
		err = EINVAL;
		break;
	}
	return (err);
}

boolean_t
ixgbe_param_locked(mac_prop_id_t pr_num)
{
	/*
	 * All en_* parameters are locked (read-only) while
	 * the device is in any sort of loopback mode ...
	 */
	switch (pr_num) {
		case MAC_PROP_EN_10GFDX_CAP:
		case MAC_PROP_EN_1000FDX_CAP:
		case MAC_PROP_EN_100FDX_CAP:
		case MAC_PROP_AUTONEG:
		case MAC_PROP_FLOWCTRL:
			return (B_TRUE);
	}
	return (B_FALSE);
}

/* ARGSUSED */
int
ixgbe_set_priv_prop(ixgbe_t *ixgbe, const char *pr_name,
    uint_t pr_valsize, const void *pr_val)
{
	int err = 0;
	long result;
	struct ixgbe_hw *hw = &ixgbe->hw;
	int i;

	if (strcmp(pr_name, "_tx_copy_thresh") == 0) {
		if (pr_val == NULL) {
			err = EINVAL;
			return (err);
		}
		(void) ddi_strtol(pr_val, (char **)NULL, 0, &result);
		if (result < MIN_TX_COPY_THRESHOLD ||
		    result > MAX_TX_COPY_THRESHOLD)
			err = EINVAL;
		else {
			ixgbe->tx_copy_thresh = (uint32_t)result;
		}
		return (err);
	}
	if (strcmp(pr_name, "_tx_recycle_thresh") == 0) {
		if (pr_val == NULL) {
			err = EINVAL;
			return (err);
		}
		(void) ddi_strtol(pr_val, (char **)NULL, 0, &result);
		if (result < MIN_TX_RECYCLE_THRESHOLD ||
		    result > MAX_TX_RECYCLE_THRESHOLD)
			err = EINVAL;
		else {
			ixgbe->tx_recycle_thresh = (uint32_t)result;
		}
		return (err);
	}
	if (strcmp(pr_name, "_tx_overload_thresh") == 0) {
		if (pr_val == NULL) {
			err = EINVAL;
			return (err);
		}
		(void) ddi_strtol(pr_val, (char **)NULL, 0, &result);
		if (result < MIN_TX_OVERLOAD_THRESHOLD ||
		    result > MAX_TX_OVERLOAD_THRESHOLD)
			err = EINVAL;
		else {
			ixgbe->tx_overload_thresh = (uint32_t)result;
		}
		return (err);
	}
	if (strcmp(pr_name, "_tx_resched_thresh") == 0) {
		if (pr_val == NULL) {
			err = EINVAL;
			return (err);
		}
		(void) ddi_strtol(pr_val, (char **)NULL, 0, &result);
		if (result < MIN_TX_RESCHED_THRESHOLD ||
		    result > MAX_TX_RESCHED_THRESHOLD)
			err = EINVAL;
		else {
			ixgbe->tx_resched_thresh = (uint32_t)result;
		}
		return (err);
	}
	if (strcmp(pr_name, "_rx_copy_thresh") == 0) {
		if (pr_val == NULL) {
			err = EINVAL;
			return (err);
		}
		(void) ddi_strtol(pr_val, (char **)NULL, 0, &result);
		if (result < MIN_RX_COPY_THRESHOLD ||
		    result > MAX_RX_COPY_THRESHOLD)
			err = EINVAL;
		else {
			ixgbe->rx_copy_thresh = (uint32_t)result;
		}
		return (err);
	}
	if (strcmp(pr_name, "_rx_limit_per_intr") == 0) {
		if (pr_val == NULL) {
			err = EINVAL;
			return (err);
		}
		(void) ddi_strtol(pr_val, (char **)NULL, 0, &result);
		if (result < MIN_RX_LIMIT_PER_INTR ||
		    result > MAX_RX_LIMIT_PER_INTR)
			err = EINVAL;
		else {
			ixgbe->rx_limit_per_intr = (uint32_t)result;
		}
		return (err);
	}
	if (strcmp(pr_name, "_intr_throttling") == 0) {
		if (pr_val == NULL) {
			err = EINVAL;
			return (err);
		}
		(void) ddi_strtol(pr_val, (char **)NULL, 0, &result);

		if (result < ixgbe->capab->min_intr_throttle ||
		    result > ixgbe->capab->max_intr_throttle)
			err = EINVAL;
		else {
			ixgbe->intr_throttling[0] = (uint32_t)result;

			/*
			 * 82599 requires the interupt throttling rate is
			 * a multiple of 8. This is enforced by the register
			 * definiton.
			 */
			if (hw->mac.type == ixgbe_mac_82599EB)
				ixgbe->intr_throttling[0] =
				    ixgbe->intr_throttling[0] & 0xFF8;

			for (i = 0; i < MAX_INTR_VECTOR; i++)
				ixgbe->intr_throttling[i] =
				    ixgbe->intr_throttling[0];

			/* Set interrupt throttling rate */
			for (i = 0; i < ixgbe->intr_cnt; i++)
				IXGBE_WRITE_REG(hw, IXGBE_EITR(i),
				    ixgbe->intr_throttling[i]);
		}
		return (err);
	}
	return (ENOTSUP);
}

int
ixgbe_get_priv_prop(ixgbe_t *ixgbe, const char *pr_name,
    uint_t pr_flags, uint_t pr_valsize, void *pr_val, uint_t *perm)
{
	int err = ENOTSUP;
	boolean_t is_default = (pr_flags & MAC_PROP_DEFAULT);
	int value;

	*perm = MAC_PROP_PERM_RW;

	if (strcmp(pr_name, "_adv_pause_cap") == 0) {
		*perm = MAC_PROP_PERM_READ;
		value = (is_default ? 1 : ixgbe->param_adv_pause_cap);
		err = 0;
		goto done;
	}
	if (strcmp(pr_name, "_adv_asym_pause_cap") == 0) {
		*perm = MAC_PROP_PERM_READ;
		value = (is_default ? 1 : ixgbe->param_adv_asym_pause_cap);
		err = 0;
		goto done;
	}
	if (strcmp(pr_name, "_tx_copy_thresh") == 0) {
		value = (is_default ? DEFAULT_TX_COPY_THRESHOLD :
		    ixgbe->tx_copy_thresh);
		err = 0;
		goto done;
	}
	if (strcmp(pr_name, "_tx_recycle_thresh") == 0) {
		value = (is_default ? DEFAULT_TX_RECYCLE_THRESHOLD :
		    ixgbe->tx_recycle_thresh);
		err = 0;
		goto done;
	}
	if (strcmp(pr_name, "_tx_overload_thresh") == 0) {
		value = (is_default ? DEFAULT_TX_OVERLOAD_THRESHOLD :
		    ixgbe->tx_overload_thresh);
		err = 0;
		goto done;
	}
	if (strcmp(pr_name, "_tx_resched_thresh") == 0) {
		value = (is_default ? DEFAULT_TX_RESCHED_THRESHOLD :
		    ixgbe->tx_resched_thresh);
		err = 0;
		goto done;
	}
	if (strcmp(pr_name, "_rx_copy_thresh") == 0) {
		value = (is_default ? DEFAULT_RX_COPY_THRESHOLD :
		    ixgbe->rx_copy_thresh);
		err = 0;
		goto done;
	}
	if (strcmp(pr_name, "_rx_limit_per_intr") == 0) {
		value = (is_default ? DEFAULT_RX_LIMIT_PER_INTR :
		    ixgbe->rx_limit_per_intr);
		err = 0;
		goto done;
	}
	if (strcmp(pr_name, "_intr_throttling") == 0) {
		value = (is_default ? ixgbe->capab->def_intr_throttle :
		    ixgbe->intr_throttling[0]);
		err = 0;
		goto done;
	}
done:
	if (err == 0) {
		(void) snprintf(pr_val, pr_valsize, "%d", value);
	}
	return (err);
}
