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
 * Copyright (c) 2017, Joyent, Inc.
 */

#include "ixgbe_sw.h"

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

	atomic_or_32(&ixgbe->ixgbe_state, IXGBE_STARTED);

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

	atomic_and_32(&ixgbe->ixgbe_state, ~IXGBE_STARTED);

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
	case MAC_CAPAB_TRANSCEIVER: {
		mac_capab_transceiver_t *mct = cap_data;

		/*
		 * Rather than try and guess based on the media type whether or
		 * not we have a transceiver we can read, we instead will let
		 * the actual function calls figure that out for us.
		 */
		mct->mct_flags = 0;
		mct->mct_ntransceivers = 1;
		mct->mct_info = ixgbe_transceiver_info;
		mct->mct_read = ixgbe_transceiver_read;
		return (B_TRUE);
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
	ixgbe_link_speed speeds = 0;

	mutex_enter(&ixgbe->gen_lock);
	if (ixgbe->ixgbe_state & IXGBE_SUSPENDED) {
		mutex_exit(&ixgbe->gen_lock);
		return (ECANCELED);
	}

	/*
	 * We cannot always rely on the common code maintaining
	 * hw->phy.speeds_supported, therefore we fall back to use the recorded
	 * supported speeds which were obtained during instance init in
	 * ixgbe_init_params().
	 */
	speeds = hw->phy.speeds_supported;
	if (speeds == 0)
		speeds = ixgbe->speeds_supported;

	if (ixgbe->loopback_mode != IXGBE_LB_NONE &&
	    ixgbe_param_locked(pr_num)) {
		/*
		 * All en_* parameters are locked (read-only)
		 * while the device is in any sort of loopback mode.
		 */
		mutex_exit(&ixgbe->gen_lock);
		return (EBUSY);
	}

	/*
	 * We allow speed changes only on baseT PHYs. MAC_PROP_EN_* are marked
	 * read-only on non-baseT PHYs.
	 */
	switch (pr_num) {
	case MAC_PROP_EN_10GFDX_CAP:
		if (hw->phy.media_type == ixgbe_media_type_copper &&
		    speeds & IXGBE_LINK_SPEED_10GB_FULL) {
			ixgbe->param_en_10000fdx_cap = *(uint8_t *)pr_val;
			goto setup_link;
		} else {
			err = ENOTSUP;
			break;
		}
	case MAC_PROP_EN_5000FDX_CAP:
		if (hw->phy.media_type == ixgbe_media_type_copper &&
		    speeds & IXGBE_LINK_SPEED_5GB_FULL) {
			ixgbe->param_en_5000fdx_cap = *(uint8_t *)pr_val;
			goto setup_link;
		} else {
			err = ENOTSUP;
			break;
		}
	case MAC_PROP_EN_2500FDX_CAP:
		if (hw->phy.media_type == ixgbe_media_type_copper &&
		    speeds & IXGBE_LINK_SPEED_2_5GB_FULL) {
			ixgbe->param_en_2500fdx_cap = *(uint8_t *)pr_val;
			goto setup_link;
		} else {
			err = ENOTSUP;
			break;
		}
	case MAC_PROP_EN_1000FDX_CAP:
		if (hw->phy.media_type == ixgbe_media_type_copper &&
		    speeds & IXGBE_LINK_SPEED_1GB_FULL) {
			ixgbe->param_en_1000fdx_cap = *(uint8_t *)pr_val;
			goto setup_link;
		} else {
			err = ENOTSUP;
			break;
		}
	case MAC_PROP_EN_100FDX_CAP:
		if (hw->phy.media_type == ixgbe_media_type_copper &&
		    speeds & IXGBE_LINK_SPEED_100_FULL) {
			ixgbe->param_en_100fdx_cap = *(uint8_t *)pr_val;
			goto setup_link;
		} else {
			err = ENOTSUP;
			break;
		}
	case MAC_PROP_AUTONEG:
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
	case MAC_PROP_ADV_5000FDX_CAP:
	case MAC_PROP_ADV_2500FDX_CAP:
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

		if (new_mtu < DEFAULT_MTU || new_mtu > ixgbe->capab->max_mtu) {
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
		err = ENOTSUP;
		break;
	}
	mutex_exit(&ixgbe->gen_lock);
	return (err);
}

int
ixgbe_m_getprop(void *arg, const char *pr_name, mac_prop_id_t pr_num,
    uint_t pr_valsize, void *pr_val)
{
	ixgbe_t *ixgbe = (ixgbe_t *)arg;
	struct ixgbe_hw *hw = &ixgbe->hw;
	int err = 0;
	uint32_t flow_control;
	uint64_t tmp = 0;
	ixgbe_link_speed speeds = 0;

	/*
	 * We cannot always rely on the common code maintaining
	 * hw->phy.speeds_supported, therefore we fall back to use the recorded
	 * supported speeds which were obtained during instance init in
	 * ixgbe_init_params().
	 */
	speeds = hw->phy.speeds_supported;
	if (speeds == 0)
		speeds = ixgbe->speeds_supported;

	switch (pr_num) {
	case MAC_PROP_DUPLEX:
		ASSERT(pr_valsize >= sizeof (link_duplex_t));
		bcopy(&ixgbe->link_duplex, pr_val,
		    sizeof (link_duplex_t));
		break;
	case MAC_PROP_SPEED:
		ASSERT(pr_valsize >= sizeof (uint64_t));
		tmp = ixgbe->link_speed * 1000000ull;
		bcopy(&tmp, pr_val, sizeof (tmp));
		break;
	case MAC_PROP_AUTONEG:
		*(uint8_t *)pr_val = ixgbe->param_adv_autoneg_cap;
		break;
	case MAC_PROP_FLOWCTRL:
		ASSERT(pr_valsize >= sizeof (uint32_t));

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
		break;
	case MAC_PROP_ADV_10GFDX_CAP:
		if (speeds & IXGBE_LINK_SPEED_10GB_FULL)
			*(uint8_t *)pr_val = ixgbe->param_adv_10000fdx_cap;
		else
			err = ENOTSUP;
		break;
	case MAC_PROP_EN_10GFDX_CAP:
		if (speeds & IXGBE_LINK_SPEED_10GB_FULL)
			*(uint8_t *)pr_val = ixgbe->param_en_10000fdx_cap;
		else
			err = ENOTSUP;
		break;
	case MAC_PROP_ADV_5000FDX_CAP:
		if (speeds & IXGBE_LINK_SPEED_5GB_FULL)
			*(uint8_t *)pr_val = ixgbe->param_adv_5000fdx_cap;
		else
			err = ENOTSUP;
		break;
	case MAC_PROP_EN_5000FDX_CAP:
		if (speeds & IXGBE_LINK_SPEED_5GB_FULL)
			*(uint8_t *)pr_val = ixgbe->param_en_5000fdx_cap;
		else
			err = ENOTSUP;
		break;
	case MAC_PROP_ADV_2500FDX_CAP:
		if (speeds & IXGBE_LINK_SPEED_2_5GB_FULL)
			*(uint8_t *)pr_val = ixgbe->param_adv_2500fdx_cap;
		else
			err = ENOTSUP;
		break;
	case MAC_PROP_EN_2500FDX_CAP:
		if (speeds & IXGBE_LINK_SPEED_2_5GB_FULL)
			*(uint8_t *)pr_val = ixgbe->param_en_2500fdx_cap;
		else
			err = ENOTSUP;
		break;
	case MAC_PROP_ADV_1000FDX_CAP:
		if (speeds & IXGBE_LINK_SPEED_1GB_FULL)
			*(uint8_t *)pr_val = ixgbe->param_adv_1000fdx_cap;
		else
			err = ENOTSUP;
		break;
	case MAC_PROP_EN_1000FDX_CAP:
		if (speeds & IXGBE_LINK_SPEED_1GB_FULL)
			*(uint8_t *)pr_val = ixgbe->param_en_1000fdx_cap;
		else
			err = ENOTSUP;
		break;
	case MAC_PROP_ADV_100FDX_CAP:
		if (speeds & IXGBE_LINK_SPEED_100_FULL)
			*(uint8_t *)pr_val = ixgbe->param_adv_100fdx_cap;
		else
			err = ENOTSUP;
		break;
	case MAC_PROP_EN_100FDX_CAP:
		if (speeds & IXGBE_LINK_SPEED_100_FULL)
			*(uint8_t *)pr_val = ixgbe->param_en_100fdx_cap;
		else
			err = ENOTSUP;
		break;
	case MAC_PROP_PRIVATE:
		err = ixgbe_get_priv_prop(ixgbe, pr_name,
		    pr_valsize, pr_val);
		break;
	default:
		err = ENOTSUP;
		break;
	}
	return (err);
}

void
ixgbe_m_propinfo(void *arg, const char *pr_name, mac_prop_id_t pr_num,
    mac_prop_info_handle_t prh)
{
	ixgbe_t *ixgbe = (ixgbe_t *)arg;
	struct ixgbe_hw *hw = &ixgbe->hw;
	uint_t perm;
	uint8_t value;
	ixgbe_link_speed speeds = 0;

	/*
	 * We cannot always rely on the common code maintaining
	 * hw->phy.speeds_supported, therefore we fall back to use the
	 * recorded supported speeds which were obtained during instance init in
	 * ixgbe_init_params().
	 */
	speeds = hw->phy.speeds_supported;
	if (speeds == 0)
		speeds = ixgbe->speeds_supported;

	switch (pr_num) {
	case MAC_PROP_DUPLEX:
	case MAC_PROP_SPEED:
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		break;

	case MAC_PROP_ADV_100FDX_CAP:
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		value = (speeds & IXGBE_LINK_SPEED_100_FULL) ? 1 : 0;
		mac_prop_info_set_default_uint8(prh, value);
		break;

	case MAC_PROP_ADV_1000FDX_CAP:
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		value = (speeds & IXGBE_LINK_SPEED_1GB_FULL) ? 1 : 0;
		mac_prop_info_set_default_uint8(prh, value);
		break;

	case MAC_PROP_ADV_2500FDX_CAP:
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		value = (speeds & IXGBE_LINK_SPEED_2_5GB_FULL) ? 1 : 0;
		mac_prop_info_set_default_uint8(prh, value);
		break;

	case MAC_PROP_ADV_5000FDX_CAP:
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		value = (speeds & IXGBE_LINK_SPEED_5GB_FULL) ? 1 : 0;
		mac_prop_info_set_default_uint8(prh, value);
		break;

	case MAC_PROP_ADV_10GFDX_CAP:
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		value = (speeds & IXGBE_LINK_SPEED_10GB_FULL) ? 1 : 0;
		mac_prop_info_set_default_uint8(prh, value);
		break;

	/*
	 * We allow speed changes only on baseT PHYs. MAC_PROP_EN_* are marked
	 * read-only on non-baseT (SFP) PHYs.
	 */
	case MAC_PROP_AUTONEG:
		perm = (hw->phy.media_type == ixgbe_media_type_copper) ?
		    MAC_PROP_PERM_RW : MAC_PROP_PERM_READ;
		mac_prop_info_set_perm(prh, perm);
		mac_prop_info_set_default_uint8(prh, 1);
		break;

	case MAC_PROP_EN_10GFDX_CAP:
		if (speeds & IXGBE_LINK_SPEED_10GB_FULL) {
			perm = (hw->phy.media_type == ixgbe_media_type_copper) ?
			    MAC_PROP_PERM_RW : MAC_PROP_PERM_READ;
			mac_prop_info_set_perm(prh, perm);
			mac_prop_info_set_default_uint8(prh, 1);
		}
		break;

	case MAC_PROP_EN_5000FDX_CAP:
		if (speeds & IXGBE_LINK_SPEED_5GB_FULL) {
			perm = (hw->phy.media_type == ixgbe_media_type_copper) ?
			    MAC_PROP_PERM_RW : MAC_PROP_PERM_READ;
			mac_prop_info_set_perm(prh, perm);
			mac_prop_info_set_default_uint8(prh, 1);
		}
		break;

	case MAC_PROP_EN_2500FDX_CAP:
		if (speeds & IXGBE_LINK_SPEED_2_5GB_FULL) {
			perm = (hw->phy.media_type == ixgbe_media_type_copper) ?
			    MAC_PROP_PERM_RW : MAC_PROP_PERM_READ;
			mac_prop_info_set_perm(prh, perm);
			mac_prop_info_set_default_uint8(prh, 1);
		}
		break;

	case MAC_PROP_EN_1000FDX_CAP:
		if (speeds & IXGBE_LINK_SPEED_1GB_FULL) {
			perm = (hw->phy.media_type == ixgbe_media_type_copper) ?
			    MAC_PROP_PERM_RW : MAC_PROP_PERM_READ;
			mac_prop_info_set_perm(prh, perm);
			mac_prop_info_set_default_uint8(prh, 1);
		}
		break;

	case MAC_PROP_EN_100FDX_CAP:
		if (speeds & IXGBE_LINK_SPEED_100_FULL) {
			perm = (hw->phy.media_type == ixgbe_media_type_copper) ?
			    MAC_PROP_PERM_RW : MAC_PROP_PERM_READ;
			mac_prop_info_set_perm(prh, perm);
			mac_prop_info_set_default_uint8(prh, 1);
		}
		break;

	case MAC_PROP_FLOWCTRL:
		mac_prop_info_set_default_link_flowctrl(prh,
		    LINK_FLOWCTRL_NONE);
		break;

	case MAC_PROP_MTU:
		mac_prop_info_set_range_uint32(prh,
		    DEFAULT_MTU, ixgbe->capab->max_mtu);
		break;

	case MAC_PROP_PRIVATE: {
		char valstr[64];
		int value;

		bzero(valstr, sizeof (valstr));

		if (strcmp(pr_name, "_adv_pause_cap") == 0 ||
		    strcmp(pr_name, "_adv_asym_pause_cap") == 0) {
			mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
			return;
		}

		if (strcmp(pr_name, "_tx_copy_thresh") == 0) {
			value = DEFAULT_TX_COPY_THRESHOLD;
		} else if (strcmp(pr_name, "_tx_recycle_thresh") == 0) {
			value = DEFAULT_TX_RECYCLE_THRESHOLD;
		} else if (strcmp(pr_name, "_tx_overload_thresh") == 0) {
			value = DEFAULT_TX_OVERLOAD_THRESHOLD;
		} else if (strcmp(pr_name, "_tx_resched_thresh") == 0) {
			value = DEFAULT_TX_RESCHED_THRESHOLD;
		} else 	if (strcmp(pr_name, "_rx_copy_thresh") == 0) {
			value = DEFAULT_RX_COPY_THRESHOLD;
		} else 	if (strcmp(pr_name, "_rx_limit_per_intr") == 0) {
			value = DEFAULT_RX_LIMIT_PER_INTR;
		} 	if (strcmp(pr_name, "_intr_throttling") == 0) {
			value = ixgbe->capab->def_intr_throttle;
		} else {
			return;
		}

		(void) snprintf(valstr, sizeof (valstr), "%x", value);
	}
	}
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
		case MAC_PROP_EN_5000FDX_CAP:
		case MAC_PROP_EN_2500FDX_CAP:
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
			 * 82599, X540 and X550 require the interrupt throttling
			 * rate is a multiple of 8. This is enforced by the
			 * register definiton.
			 */
			if (hw->mac.type == ixgbe_mac_82599EB ||
			    hw->mac.type == ixgbe_mac_X540 ||
			    hw->mac.type == ixgbe_mac_X550 ||
			    hw->mac.type == ixgbe_mac_X550EM_x) {
				ixgbe->intr_throttling[0] =
				    ixgbe->intr_throttling[0] & 0xFF8;
			}

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
    uint_t pr_valsize, void *pr_val)
{
	int err = ENOTSUP;
	int value;

	if (strcmp(pr_name, "_adv_pause_cap") == 0) {
		value = ixgbe->param_adv_pause_cap;
		err = 0;
		goto done;
	}
	if (strcmp(pr_name, "_adv_asym_pause_cap") == 0) {
		value = ixgbe->param_adv_asym_pause_cap;
		err = 0;
		goto done;
	}
	if (strcmp(pr_name, "_tx_copy_thresh") == 0) {
		value = ixgbe->tx_copy_thresh;
		err = 0;
		goto done;
	}
	if (strcmp(pr_name, "_tx_recycle_thresh") == 0) {
		value = ixgbe->tx_recycle_thresh;
		err = 0;
		goto done;
	}
	if (strcmp(pr_name, "_tx_overload_thresh") == 0) {
		value = ixgbe->tx_overload_thresh;
		err = 0;
		goto done;
	}
	if (strcmp(pr_name, "_tx_resched_thresh") == 0) {
		value = ixgbe->tx_resched_thresh;
		err = 0;
		goto done;
	}
	if (strcmp(pr_name, "_rx_copy_thresh") == 0) {
		value = ixgbe->rx_copy_thresh;
		err = 0;
		goto done;
	}
	if (strcmp(pr_name, "_rx_limit_per_intr") == 0) {
		value = ixgbe->rx_limit_per_intr;
		err = 0;
		goto done;
	}
	if (strcmp(pr_name, "_intr_throttling") == 0) {
		value = ixgbe->intr_throttling[0];
		err = 0;
		goto done;
	}
done:
	if (err == 0) {
		(void) snprintf(pr_val, pr_valsize, "%d", value);
	}
	return (err);
}
