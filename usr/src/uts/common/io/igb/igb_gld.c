/*
 * CDDL HEADER START
 *
 * Copyright(c) 2007-2008 Intel Corporation. All rights reserved.
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at:
 *	http://www.opensolaris.org/os/licensing.
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

#include "igb_sw.h"

int
igb_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	igb_t *igb = (igb_t *)arg;
	struct e1000_hw *hw = &igb->hw;
	igb_stat_t *igb_ks;
	uint32_t low_val, high_val;

	igb_ks = (igb_stat_t *)igb->igb_ks->ks_data;

	mutex_enter(&igb->gen_lock);

	if (igb->igb_state & IGB_SUSPENDED) {
		mutex_exit(&igb->gen_lock);
		return (ECANCELED);
	}

	switch (stat) {
	case MAC_STAT_IFSPEED:
		*val = igb->link_speed * 1000000ull;
		break;

	case MAC_STAT_MULTIRCV:
		igb_ks->mprc.value.ui64 +=
		    E1000_READ_REG(hw, E1000_MPRC);
		*val = igb_ks->mprc.value.ui64;
		break;

	case MAC_STAT_BRDCSTRCV:
		igb_ks->bprc.value.ui64 +=
		    E1000_READ_REG(hw, E1000_BPRC);
		*val = igb_ks->bprc.value.ui64;
		break;

	case MAC_STAT_MULTIXMT:
		igb_ks->mptc.value.ui64 +=
		    E1000_READ_REG(hw, E1000_MPTC);
		*val = igb_ks->mptc.value.ui64;
		break;

	case MAC_STAT_BRDCSTXMT:
		igb_ks->bptc.value.ui64 +=
		    E1000_READ_REG(hw, E1000_BPTC);
		*val = igb_ks->bptc.value.ui64;
		break;

	case MAC_STAT_NORCVBUF:
		igb_ks->rnbc.value.ui64 +=
		    E1000_READ_REG(hw, E1000_RNBC);
		*val = igb_ks->rnbc.value.ui64;
		break;

	case MAC_STAT_IERRORS:
		igb_ks->rxerrc.value.ui64 +=
		    E1000_READ_REG(hw, E1000_RXERRC);
		igb_ks->algnerrc.value.ui64 +=
		    E1000_READ_REG(hw, E1000_ALGNERRC);
		igb_ks->rlec.value.ui64 +=
		    E1000_READ_REG(hw, E1000_RLEC);
		igb_ks->crcerrs.value.ui64 +=
		    E1000_READ_REG(hw, E1000_CRCERRS);
		igb_ks->cexterr.value.ui64 +=
		    E1000_READ_REG(hw, E1000_CEXTERR);
		*val = igb_ks->rxerrc.value.ui64 +
		    igb_ks->algnerrc.value.ui64 +
		    igb_ks->rlec.value.ui64 +
		    igb_ks->crcerrs.value.ui64 +
		    igb_ks->cexterr.value.ui64;
		break;

	case MAC_STAT_NOXMTBUF:
		*val = 0;
		break;

	case MAC_STAT_OERRORS:
		igb_ks->ecol.value.ui64 +=
		    E1000_READ_REG(hw, E1000_ECOL);
		*val = igb_ks->ecol.value.ui64;
		break;

	case MAC_STAT_COLLISIONS:
		igb_ks->colc.value.ui64 +=
		    E1000_READ_REG(hw, E1000_COLC);
		*val = igb_ks->colc.value.ui64;
		break;

	case MAC_STAT_RBYTES:
		/*
		 * The 64-bit register will reset whenever the upper
		 * 32 bits are read. So we need to read the lower
		 * 32 bits first, then read the upper 32 bits.
		 */
		low_val = E1000_READ_REG(hw, E1000_TORL);
		high_val = E1000_READ_REG(hw, E1000_TORH);
		igb_ks->tor.value.ui64 +=
		    (uint64_t)high_val << 32 | (uint64_t)low_val;
		*val = igb_ks->tor.value.ui64;
		break;

	case MAC_STAT_IPACKETS:
		igb_ks->tpr.value.ui64 +=
		    E1000_READ_REG(hw, E1000_TPR);
		*val = igb_ks->tpr.value.ui64;
		break;

	case MAC_STAT_OBYTES:
		/*
		 * The 64-bit register will reset whenever the upper
		 * 32 bits are read. So we need to read the lower
		 * 32 bits first, then read the upper 32 bits.
		 */
		low_val = E1000_READ_REG(hw, E1000_TOTL);
		high_val = E1000_READ_REG(hw, E1000_TOTH);
		igb_ks->tot.value.ui64 +=
		    (uint64_t)high_val << 32 | (uint64_t)low_val;
		*val = igb_ks->tot.value.ui64;
		break;

	case MAC_STAT_OPACKETS:
		igb_ks->tpt.value.ui64 +=
		    E1000_READ_REG(hw, E1000_TPT);
		*val = igb_ks->tpt.value.ui64;
		break;

	/* RFC 1643 stats */
	case ETHER_STAT_ALIGN_ERRORS:
		igb_ks->algnerrc.value.ui64 +=
		    E1000_READ_REG(hw, E1000_ALGNERRC);
		*val = igb_ks->algnerrc.value.ui64;
		break;

	case ETHER_STAT_FCS_ERRORS:
		igb_ks->crcerrs.value.ui64 +=
		    E1000_READ_REG(hw, E1000_CRCERRS);
		*val = igb_ks->crcerrs.value.ui64;
		break;

	case ETHER_STAT_FIRST_COLLISIONS:
		igb_ks->scc.value.ui64 +=
		    E1000_READ_REG(hw, E1000_SCC);
		*val = igb_ks->scc.value.ui64;
		break;

	case ETHER_STAT_MULTI_COLLISIONS:
		igb_ks->mcc.value.ui64 +=
		    E1000_READ_REG(hw, E1000_MCC);
		*val = igb_ks->mcc.value.ui64;
		break;

	case ETHER_STAT_SQE_ERRORS:
		igb_ks->sec.value.ui64 +=
		    E1000_READ_REG(hw, E1000_SEC);
		*val = igb_ks->sec.value.ui64;
		break;

	case ETHER_STAT_DEFER_XMTS:
		igb_ks->dc.value.ui64 +=
		    E1000_READ_REG(hw, E1000_DC);
		*val = igb_ks->dc.value.ui64;
		break;

	case ETHER_STAT_TX_LATE_COLLISIONS:
		igb_ks->latecol.value.ui64 +=
		    E1000_READ_REG(hw, E1000_LATECOL);
		*val = igb_ks->latecol.value.ui64;
		break;

	case ETHER_STAT_EX_COLLISIONS:
		igb_ks->ecol.value.ui64 +=
		    E1000_READ_REG(hw, E1000_ECOL);
		*val = igb_ks->ecol.value.ui64;
		break;

	case ETHER_STAT_MACXMT_ERRORS:
		igb_ks->ecol.value.ui64 +=
		    E1000_READ_REG(hw, E1000_ECOL);
		*val = igb_ks->ecol.value.ui64;
		break;

	case ETHER_STAT_CARRIER_ERRORS:
		igb_ks->cexterr.value.ui64 +=
		    E1000_READ_REG(hw, E1000_CEXTERR);
		*val = igb_ks->cexterr.value.ui64;
		break;

	case ETHER_STAT_TOOLONG_ERRORS:
		igb_ks->roc.value.ui64 +=
		    E1000_READ_REG(hw, E1000_ROC);
		*val = igb_ks->roc.value.ui64;
		break;

	case ETHER_STAT_MACRCV_ERRORS:
		igb_ks->rxerrc.value.ui64 +=
		    E1000_READ_REG(hw, E1000_RXERRC);
		*val = igb_ks->rxerrc.value.ui64;
		break;

	/* MII/GMII stats */
	case ETHER_STAT_XCVR_ADDR:
		/* The Internal PHY's MDI address for each MAC is 1 */
		*val = 1;
		break;

	case ETHER_STAT_XCVR_ID:
		*val = hw->phy.id | hw->phy.revision;
		break;

	case ETHER_STAT_XCVR_INUSE:
		switch (igb->link_speed) {
		case SPEED_1000:
			*val =
			    (hw->phy.media_type == e1000_media_type_copper) ?
			    XCVR_1000T : XCVR_1000X;
			break;
		case SPEED_100:
			*val =
			    (hw->phy.media_type == e1000_media_type_copper) ?
			    (igb->param_100t4_cap == 1) ?
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
		*val = igb->param_1000fdx_cap;
		break;

	case ETHER_STAT_CAP_1000HDX:
		*val = igb->param_1000hdx_cap;
		break;

	case ETHER_STAT_CAP_100FDX:
		*val = igb->param_100fdx_cap;
		break;

	case ETHER_STAT_CAP_100HDX:
		*val = igb->param_100hdx_cap;
		break;

	case ETHER_STAT_CAP_10FDX:
		*val = igb->param_10fdx_cap;
		break;

	case ETHER_STAT_CAP_10HDX:
		*val = igb->param_10hdx_cap;
		break;

	case ETHER_STAT_CAP_ASMPAUSE:
		*val = igb->param_asym_pause_cap;
		break;

	case ETHER_STAT_CAP_PAUSE:
		*val = igb->param_pause_cap;
		break;

	case ETHER_STAT_CAP_AUTONEG:
		*val = igb->param_autoneg_cap;
		break;

	case ETHER_STAT_ADV_CAP_1000FDX:
		*val = igb->param_adv_1000fdx_cap;
		break;

	case ETHER_STAT_ADV_CAP_1000HDX:
		*val = igb->param_adv_1000hdx_cap;
		break;

	case ETHER_STAT_ADV_CAP_100FDX:
		*val = igb->param_adv_100fdx_cap;
		break;

	case ETHER_STAT_ADV_CAP_100HDX:
		*val = igb->param_adv_100hdx_cap;
		break;

	case ETHER_STAT_ADV_CAP_10FDX:
		*val = igb->param_adv_10fdx_cap;
		break;

	case ETHER_STAT_ADV_CAP_10HDX:
		*val = igb->param_adv_10hdx_cap;
		break;

	case ETHER_STAT_ADV_CAP_ASMPAUSE:
		*val = igb->param_adv_asym_pause_cap;
		break;

	case ETHER_STAT_ADV_CAP_PAUSE:
		*val = igb->param_adv_pause_cap;
		break;

	case ETHER_STAT_ADV_CAP_AUTONEG:
		*val = hw->mac.autoneg;
		break;

	case ETHER_STAT_LP_CAP_1000FDX:
		*val = igb->param_lp_1000fdx_cap;
		break;

	case ETHER_STAT_LP_CAP_1000HDX:
		*val = igb->param_lp_1000hdx_cap;
		break;

	case ETHER_STAT_LP_CAP_100FDX:
		*val = igb->param_lp_100fdx_cap;
		break;

	case ETHER_STAT_LP_CAP_100HDX:
		*val = igb->param_lp_100hdx_cap;
		break;

	case ETHER_STAT_LP_CAP_10FDX:
		*val = igb->param_lp_10fdx_cap;
		break;

	case ETHER_STAT_LP_CAP_10HDX:
		*val = igb->param_lp_10hdx_cap;
		break;

	case ETHER_STAT_LP_CAP_ASMPAUSE:
		*val = igb->param_lp_asym_pause_cap;
		break;

	case ETHER_STAT_LP_CAP_PAUSE:
		*val = igb->param_lp_pause_cap;
		break;

	case ETHER_STAT_LP_CAP_AUTONEG:
		*val = igb->param_lp_autoneg_cap;
		break;

	case ETHER_STAT_LINK_ASMPAUSE:
		*val = igb->param_asym_pause_cap;
		break;

	case ETHER_STAT_LINK_PAUSE:
		*val = igb->param_pause_cap;
		break;

	case ETHER_STAT_LINK_AUTONEG:
		*val = hw->mac.autoneg;
		break;

	case ETHER_STAT_LINK_DUPLEX:
		*val = (igb->link_duplex == FULL_DUPLEX) ?
		    LINK_DUPLEX_FULL : LINK_DUPLEX_HALF;
		break;

	case ETHER_STAT_TOOSHORT_ERRORS:
		igb_ks->ruc.value.ui64 +=
		    E1000_READ_REG(hw, E1000_RUC);
		*val = igb_ks->ruc.value.ui64;
		break;

	case ETHER_STAT_CAP_REMFAULT:
		*val = igb->param_rem_fault;
		break;

	case ETHER_STAT_ADV_REMFAULT:
		*val = igb->param_adv_rem_fault;
		break;

	case ETHER_STAT_LP_REMFAULT:
		*val = igb->param_lp_rem_fault;
		break;

	case ETHER_STAT_JABBER_ERRORS:
		igb_ks->rjc.value.ui64 +=
		    E1000_READ_REG(hw, E1000_RJC);
		*val = igb_ks->rjc.value.ui64;
		break;

	case ETHER_STAT_CAP_100T4:
		*val = igb->param_100t4_cap;
		break;

	case ETHER_STAT_ADV_CAP_100T4:
		*val = igb->param_adv_100t4_cap;
		break;

	case ETHER_STAT_LP_CAP_100T4:
		*val = igb->param_lp_100t4_cap;
		break;

	default:
		mutex_exit(&igb->gen_lock);
		return (ENOTSUP);
	}

	mutex_exit(&igb->gen_lock);

	return (0);
}

/*
 * Bring the device out of the reset/quiesced state that it
 * was in when the interface was registered.
 */
int
igb_m_start(void *arg)
{
	igb_t *igb = (igb_t *)arg;

	mutex_enter(&igb->gen_lock);

	if (igb->igb_state & IGB_SUSPENDED) {
		mutex_exit(&igb->gen_lock);
		return (ECANCELED);
	}

	if (igb_start(igb) != IGB_SUCCESS) {
		mutex_exit(&igb->gen_lock);
		return (EIO);
	}

	igb->igb_state |= IGB_STARTED;

	mutex_exit(&igb->gen_lock);

	/*
	 * Enable and start the watchdog timer
	 */
	igb_enable_watchdog_timer(igb);

	return (0);
}

/*
 * Stop the device and put it in a reset/quiesced state such
 * that the interface can be unregistered.
 */
void
igb_m_stop(void *arg)
{
	igb_t *igb = (igb_t *)arg;

	mutex_enter(&igb->gen_lock);

	if (igb->igb_state & IGB_SUSPENDED) {
		mutex_exit(&igb->gen_lock);
		return;
	}

	igb->igb_state &= ~IGB_STARTED;

	igb_stop(igb);

	mutex_exit(&igb->gen_lock);

	/*
	 * Disable and stop the watchdog timer
	 */
	igb_disable_watchdog_timer(igb);
}

/*
 * Set the promiscuity of the device.
 */
int
igb_m_promisc(void *arg, boolean_t on)
{
	igb_t *igb = (igb_t *)arg;
	uint32_t reg_val;

	mutex_enter(&igb->gen_lock);

	if (igb->igb_state & IGB_SUSPENDED) {
		mutex_exit(&igb->gen_lock);
		return (ECANCELED);
	}

	reg_val = E1000_READ_REG(&igb->hw, E1000_RCTL);

	if (on)
		reg_val |= (E1000_RCTL_UPE | E1000_RCTL_MPE);
	else
		reg_val &= (~(E1000_RCTL_UPE | E1000_RCTL_MPE));

	E1000_WRITE_REG(&igb->hw, E1000_RCTL, reg_val);

	mutex_exit(&igb->gen_lock);

	return (0);
}

/*
 * Add/remove the addresses to/from the set of multicast
 * addresses for which the device will receive packets.
 */
int
igb_m_multicst(void *arg, boolean_t add, const uint8_t *mcst_addr)
{
	igb_t *igb = (igb_t *)arg;
	int result;

	mutex_enter(&igb->gen_lock);

	if (igb->igb_state & IGB_SUSPENDED) {
		mutex_exit(&igb->gen_lock);
		return (ECANCELED);
	}

	result = (add) ? igb_multicst_add(igb, mcst_addr)
	    : igb_multicst_remove(igb, mcst_addr);

	mutex_exit(&igb->gen_lock);

	return (result);
}

/*
 * Set a new device unicast address.
 */
int
igb_m_unicst(void *arg, const uint8_t *mac_addr)
{
	igb_t *igb = (igb_t *)arg;
	int result;

	mutex_enter(&igb->gen_lock);

	if (igb->igb_state & IGB_SUSPENDED) {
		mutex_exit(&igb->gen_lock);
		return (ECANCELED);
	}

	/*
	 * Store the new MAC address.
	 */
	bcopy(mac_addr, igb->hw.mac.addr, ETHERADDRL);

	/*
	 * Set MAC address in address slot 0, which is the default address.
	 */
	result = igb_unicst_set(igb, mac_addr, 0);

	mutex_exit(&igb->gen_lock);

	return (result);
}

/*
 * Pass on M_IOCTL messages passed to the DLD, and support
 * private IOCTLs for debugging and ndd.
 */
void
igb_m_ioctl(void *arg, queue_t *q, mblk_t *mp)
{
	igb_t *igb = (igb_t *)arg;
	struct iocblk *iocp;
	enum ioc_reply status;

	iocp = (struct iocblk *)(uintptr_t)mp->b_rptr;
	iocp->ioc_error = 0;

	switch (iocp->ioc_cmd) {
	case LB_GET_INFO_SIZE:
	case LB_GET_INFO:
	case LB_GET_MODE:
	case LB_SET_MODE:
		status = igb_loopback_ioctl(igb, iocp, mp);
		break;

	case ND_GET:
	case ND_SET:
		status = igb_nd_ioctl(igb, q, mp, iocp);
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
 * Find an unused address slot, set the address to it, reserve
 * this slot and enable the device to start filtering on the
 * new address.
 */
int
igb_m_unicst_add(void *arg, mac_multi_addr_t *maddr)
{
	igb_t *igb = (igb_t *)arg;
	mac_addr_slot_t slot;
	int err;

	mutex_enter(&igb->gen_lock);

	if (igb->igb_state & IGB_SUSPENDED) {
		mutex_exit(&igb->gen_lock);
		return (ECANCELED);
	}

	if (mac_unicst_verify(igb->mac_hdl,
	    maddr->mma_addr, maddr->mma_addrlen) == B_FALSE) {
		mutex_exit(&igb->gen_lock);
		return (EINVAL);
	}

	if (igb->unicst_avail == 0) {
		/* no slots available */
		mutex_exit(&igb->gen_lock);
		return (ENOSPC);
	}

	/*
	 * Primary/default address is in slot 0. The next addresses
	 * are the multiple MAC addresses. So multiple MAC address 0
	 * is in slot 1, 1 in slot 2, and so on. So the first multiple
	 * MAC address resides in slot 1.
	 */
	for (slot = 1; slot < igb->unicst_total; slot++) {
		if (igb->unicst_addr[slot].mac.set == 0) {
			igb->unicst_addr[slot].mac.set = 1;
			break;
		}
	}

	ASSERT((slot > 0) && (slot < igb->unicst_total));

	igb->unicst_avail--;
	mutex_exit(&igb->gen_lock);

	maddr->mma_slot = slot;

	if ((err = igb_unicst_set(igb, maddr->mma_addr, slot)) != 0) {
		mutex_enter(&igb->gen_lock);
		igb->unicst_addr[slot].mac.set = 0;
		igb->unicst_avail++;
		mutex_exit(&igb->gen_lock);
	}

	return (err);
}


/*
 * Removes a MAC address that was added before.
 */
int
igb_m_unicst_remove(void *arg, mac_addr_slot_t slot)
{
	igb_t *igb = (igb_t *)arg;
	int err;

	mutex_enter(&igb->gen_lock);

	if (igb->igb_state & IGB_SUSPENDED) {
		mutex_exit(&igb->gen_lock);
		return (ECANCELED);
	}

	if ((slot <= 0) || (slot >= igb->unicst_total)) {
		mutex_exit(&igb->gen_lock);
		return (EINVAL);
	}

	if (igb->unicst_addr[slot].mac.set == 1) {
		igb->unicst_addr[slot].mac.set = 0;
		igb->unicst_avail++;

		/* Copy the default address to the passed slot */
		if ((err = igb_unicst_set(igb,
		    igb->unicst_addr[0].mac.addr, slot)) != 0) {
			igb->unicst_addr[slot].mac.set = 1;
			igb->unicst_avail--;
		}

		mutex_exit(&igb->gen_lock);

		return (err);
	}
	mutex_exit(&igb->gen_lock);

	return (EINVAL);
}

/*
 * Modifies the value of an address that has been added before.
 * The new address length and the slot number that was returned
 * in the call to add should be passed in. mma_flags should be
 * set to 0.
 * Returns 0 on success.
 */
int
igb_m_unicst_modify(void *arg, mac_multi_addr_t *maddr)
{
	igb_t *igb = (igb_t *)arg;
	mac_addr_slot_t slot;

	mutex_enter(&igb->gen_lock);

	if (igb->igb_state & IGB_SUSPENDED) {
		mutex_exit(&igb->gen_lock);
		return (ECANCELED);
	}

	if (mac_unicst_verify(igb->mac_hdl,
	    maddr->mma_addr, maddr->mma_addrlen) == B_FALSE) {
		mutex_exit(&igb->gen_lock);
		return (EINVAL);
	}

	slot = maddr->mma_slot;

	if ((slot <= 0) || (slot >= igb->unicst_total)) {
		mutex_exit(&igb->gen_lock);
		return (EINVAL);
	}

	if (igb->unicst_addr[slot].mac.set == 1) {
		mutex_exit(&igb->gen_lock);

		return (igb_unicst_set(igb, maddr->mma_addr, slot));
	}
	mutex_exit(&igb->gen_lock);

	return (EINVAL);
}

/*
 * Get the MAC address and all other information related to
 * the address slot passed in mac_multi_addr_t.
 * mma_flags should be set to 0 in the call.
 * On return, mma_flags can take the following values:
 * 1) MMAC_SLOT_UNUSED
 * 2) MMAC_SLOT_USED | MMAC_VENDOR_ADDR
 * 3) MMAC_SLOT_UNUSED | MMAC_VENDOR_ADDR
 * 4) MMAC_SLOT_USED
 */
int
igb_m_unicst_get(void *arg, mac_multi_addr_t *maddr)
{
	igb_t *igb = (igb_t *)arg;
	mac_addr_slot_t slot;

	mutex_enter(&igb->gen_lock);

	if (igb->igb_state & IGB_SUSPENDED) {
		mutex_exit(&igb->gen_lock);
		return (ECANCELED);
	}

	slot = maddr->mma_slot;

	if ((slot <= 0) || (slot >= igb->unicst_total)) {
		mutex_exit(&igb->gen_lock);
		return (EINVAL);
	}

	if (igb->unicst_addr[slot].mac.set == 1) {
		bcopy(igb->unicst_addr[slot].mac.addr,
		    maddr->mma_addr, ETHERADDRL);
		maddr->mma_flags = MMAC_SLOT_USED;
	} else {
		maddr->mma_flags = MMAC_SLOT_UNUSED;
	}
	mutex_exit(&igb->gen_lock);

	return (0);
}

/*
 * Obtain the MAC's capabilities and associated data from
 * the driver.
 */
boolean_t
igb_m_getcapab(void *arg, mac_capab_t cap, void *cap_data)
{
	igb_t *igb = (igb_t *)arg;

	switch (cap) {
	case MAC_CAPAB_HCKSUM: {
		uint32_t *tx_hcksum_flags = cap_data;

		/*
		 * We advertise our capabilities only if tx hcksum offload is
		 * enabled.  On receive, the stack will accept checksummed
		 * packets anyway, even if we haven't said we can deliver
		 * them.
		 */
		if (!igb->tx_hcksum_enable)
			return (B_FALSE);

		*tx_hcksum_flags = HCKSUM_INET_PARTIAL | HCKSUM_IPHDRCKSUM;
		break;
	}
	case MAC_CAPAB_MULTIADDRESS: {
		multiaddress_capab_t *mmacp = cap_data;

		/*
		 * The number of MAC addresses made available by
		 * this capability is one less than the total as
		 * the primary address in slot 0 is counted in
		 * the total.
		 */
		mmacp->maddr_naddr = igb->unicst_total - 1;
		mmacp->maddr_naddrfree = igb->unicst_avail;
		/* No multiple factory addresses, set mma_flag to 0 */
		mmacp->maddr_flag = 0;
		mmacp->maddr_handle = igb;
		mmacp->maddr_add = igb_m_unicst_add;
		mmacp->maddr_remove = igb_m_unicst_remove;
		mmacp->maddr_modify = igb_m_unicst_modify;
		mmacp->maddr_get = igb_m_unicst_get;
		mmacp->maddr_reserve = NULL;
		break;
	}
	default:
		return (B_FALSE);
	}
	return (B_TRUE);
}
