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
		for (i = 0; i < 16; i++)
			ixgbe_ks->tor.value.ui64 +=
			    IXGBE_READ_REG(hw, IXGBE_QBRC(i));
		*val = ixgbe_ks->tor.value.ui64;
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

	case ETHER_STAT_CAP_1000FDX:
		*val = ixgbe->param_1000fdx_cap;
		break;

	case ETHER_STAT_CAP_100FDX:
		*val = ixgbe->param_100fdx_cap;
		break;

	case ETHER_STAT_CAP_ASMPAUSE:
		*val = ixgbe->param_asym_pause_cap;
		break;

	case ETHER_STAT_CAP_PAUSE:
		*val = ixgbe->param_pause_cap;
		break;

	case ETHER_STAT_CAP_AUTONEG:
		*val = ixgbe->param_autoneg_cap;
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
		*val = hw->mac.autoneg;
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

	if (ixgbe_start(ixgbe) != IXGBE_SUCCESS) {
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

	ixgbe_stop(ixgbe);

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
 * Set a new device unicast address.
 */
int
ixgbe_m_unicst(void *arg, const uint8_t *mac_addr)
{
	ixgbe_t *ixgbe = (ixgbe_t *)arg;
	int result;

	mutex_enter(&ixgbe->gen_lock);

	if (ixgbe->ixgbe_state & IXGBE_SUSPENDED) {
		mutex_exit(&ixgbe->gen_lock);
		return (ECANCELED);
	}

	/*
	 * Store the new MAC address.
	 */
	bcopy(mac_addr, ixgbe->hw.mac.addr, ETHERADDRL);

	/*
	 * Set MAC address in address slot 0, which is the default address.
	 */
	result = ixgbe_unicst_set(ixgbe, mac_addr, 0);

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

	switch (iocp->ioc_cmd) {
	case LB_GET_INFO_SIZE:
	case LB_GET_INFO:
	case LB_GET_MODE:
	case LB_SET_MODE:
		status = ixgbe_loopback_ioctl(ixgbe, iocp, mp);
		break;

	case ND_GET:
	case ND_SET:
		status = ixgbe_nd_ioctl(ixgbe, q, mp, iocp);
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
ixgbe_m_unicst_add(void *arg, mac_multi_addr_t *maddr)
{
	ixgbe_t *ixgbe = (ixgbe_t *)arg;
	mac_addr_slot_t slot;
	int err;

	mutex_enter(&ixgbe->gen_lock);

	if (ixgbe->ixgbe_state & IXGBE_SUSPENDED) {
		mutex_exit(&ixgbe->gen_lock);
		return (ECANCELED);
	}

	if (mac_unicst_verify(ixgbe->mac_hdl,
	    maddr->mma_addr, maddr->mma_addrlen) == B_FALSE) {
		mutex_exit(&ixgbe->gen_lock);
		return (EINVAL);
	}

	if (ixgbe->unicst_avail == 0) {
		/* no slots available */
		mutex_exit(&ixgbe->gen_lock);
		return (ENOSPC);
	}

	/*
	 * Primary/default address is in slot 0. The next addresses
	 * are the multiple MAC addresses. So multiple MAC address 0
	 * is in slot 1, 1 in slot 2, and so on. So the first multiple
	 * MAC address resides in slot 1.
	 */
	for (slot = 1; slot < ixgbe->unicst_total; slot++) {
		if (ixgbe->unicst_addr[slot].mac.set == 0)
			break;
	}

	ASSERT((slot > 0) && (slot < ixgbe->unicst_total));

	maddr->mma_slot = slot;

	if ((err = ixgbe_unicst_set(ixgbe, maddr->mma_addr, slot)) == 0) {
		ixgbe->unicst_addr[slot].mac.set = 1;
		ixgbe->unicst_avail--;
	}

	mutex_exit(&ixgbe->gen_lock);

	return (err);
}

/*
 * Removes a MAC address that was added before.
 */
int
ixgbe_m_unicst_remove(void *arg, mac_addr_slot_t slot)
{
	ixgbe_t *ixgbe = (ixgbe_t *)arg;
	int err;

	mutex_enter(&ixgbe->gen_lock);

	if (ixgbe->ixgbe_state & IXGBE_SUSPENDED) {
		mutex_exit(&ixgbe->gen_lock);
		return (ECANCELED);
	}

	if ((slot <= 0) || (slot >= ixgbe->unicst_total)) {
		mutex_exit(&ixgbe->gen_lock);
		return (EINVAL);
	}

	if (ixgbe->unicst_addr[slot].mac.set == 1) {
		/*
		 * Copy the default address to the passed slot
		 */
		if ((err = ixgbe_unicst_set(ixgbe,
		    ixgbe->unicst_addr[0].mac.addr, slot)) == 0) {
			ixgbe->unicst_addr[slot].mac.set = 0;
			ixgbe->unicst_avail++;
		}

		mutex_exit(&ixgbe->gen_lock);

		return (err);
	}

	mutex_exit(&ixgbe->gen_lock);

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
ixgbe_m_unicst_modify(void *arg, mac_multi_addr_t *maddr)
{
	ixgbe_t *ixgbe = (ixgbe_t *)arg;
	mac_addr_slot_t slot;
	int err;

	mutex_enter(&ixgbe->gen_lock);

	if (ixgbe->ixgbe_state & IXGBE_SUSPENDED) {
		mutex_exit(&ixgbe->gen_lock);
		return (ECANCELED);
	}

	if (mac_unicst_verify(ixgbe->mac_hdl,
	    maddr->mma_addr, maddr->mma_addrlen) == B_FALSE) {
		mutex_exit(&ixgbe->gen_lock);
		return (EINVAL);
	}

	slot = maddr->mma_slot;

	if ((slot <= 0) || (slot >= ixgbe->unicst_total)) {
		mutex_exit(&ixgbe->gen_lock);
		return (EINVAL);
	}

	if (ixgbe->unicst_addr[slot].mac.set == 1) {
		err = ixgbe_unicst_set(ixgbe, maddr->mma_addr, slot);
		mutex_exit(&ixgbe->gen_lock);
		return (err);
	}

	mutex_exit(&ixgbe->gen_lock);

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
ixgbe_m_unicst_get(void *arg, mac_multi_addr_t *maddr)
{
	ixgbe_t *ixgbe = (ixgbe_t *)arg;
	mac_addr_slot_t slot;

	mutex_enter(&ixgbe->gen_lock);

	if (ixgbe->ixgbe_state & IXGBE_SUSPENDED) {
		mutex_exit(&ixgbe->gen_lock);
		return (ECANCELED);
	}

	slot = maddr->mma_slot;

	if ((slot <= 0) || (slot >= ixgbe->unicst_total)) {
		mutex_exit(&ixgbe->gen_lock);
		return (EINVAL);
	}
	if (ixgbe->unicst_addr[slot].mac.set == 1) {
		bcopy(ixgbe->unicst_addr[slot].mac.addr,
		    maddr->mma_addr, ETHERADDRL);
		maddr->mma_flags = MMAC_SLOT_USED;
	} else {
		maddr->mma_flags = MMAC_SLOT_UNUSED;
	}

	mutex_exit(&ixgbe->gen_lock);

	return (0);
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
	case MAC_CAPAB_MULTIADDRESS: {
		multiaddress_capab_t *mmacp = cap_data;

		/*
		 * The number of MAC addresses made available by
		 * this capability is one less than the total as
		 * the primary address in slot 0 is counted in
		 * the total.
		 */
		mmacp->maddr_naddr = ixgbe->unicst_total - 1;
		mmacp->maddr_naddrfree = ixgbe->unicst_avail;
		/* No multiple factory addresses, set mma_flag to 0 */
		mmacp->maddr_flag = 0;
		mmacp->maddr_handle = ixgbe;
		mmacp->maddr_add = ixgbe_m_unicst_add;
		mmacp->maddr_remove = ixgbe_m_unicst_remove;
		mmacp->maddr_modify = ixgbe_m_unicst_modify;
		mmacp->maddr_get = ixgbe_m_unicst_get;
		mmacp->maddr_reserve = NULL;
		break;
	}
	default:
		return (B_FALSE);
	}
	return (B_TRUE);
}
