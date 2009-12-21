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
 * Copyright 2009 Emulex.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Source file containing the implementation of the driver entry points
 * and related helper functions
 */

#include <oce_impl.h>
#include <oce_ioctl.h>

/* array of properties supported by this driver */
mac_priv_prop_t oce_priv_props[] = {
	{"_tx_ring_size", MAC_PROP_PERM_READ},
	{"_tx_bcopy_limit", MAC_PROP_PERM_RW},
	{"_rx_ring_size", MAC_PROP_PERM_READ},
};
uint32_t oce_num_props = sizeof (oce_priv_props) / sizeof (mac_priv_prop_t);


/* ---[ static function declarations ]----------------------------------- */
static int oce_power10(int power);
static int oce_set_priv_prop(struct oce_dev *dev, const char *name,
    uint_t size, const void *val);

static int oce_get_priv_prop(struct oce_dev *dev, const char *name,
    uint_t flags, uint_t size, void *val);

/* ---[ GLD entry points ]----------------------------------------------- */
int
oce_m_start(void *arg)
{
	struct oce_dev *dev = arg;
	int ret;

	mutex_enter(&dev->dev_lock);

	if (dev->state & STATE_MAC_STARTED) {
		mutex_exit(&dev->dev_lock);
		return (0);
	}

	if (dev->suspended) {
		mutex_exit(&dev->dev_lock);
		return (EIO);
	}

	if (oce_fm_check_acc_handle(dev, dev->db_handle)) {
		ddi_fm_service_impact(dev->dip, DDI_SERVICE_DEGRADED);
		mutex_exit(&dev->dev_lock);
		return (EIO);
	}

	if (oce_fm_check_acc_handle(dev, dev->csr_handle)) {
		ddi_fm_service_impact(dev->dip, DDI_SERVICE_DEGRADED);
		mutex_exit(&dev->dev_lock);
		return (EIO);
	}

	if (oce_fm_check_acc_handle(dev, dev->cfg_handle)) {
		ddi_fm_service_impact(dev->dip, DDI_SERVICE_DEGRADED);
		mutex_exit(&dev->dev_lock);
		return (EIO);
	}

	ret = oce_start(dev);
	if (ret != DDI_SUCCESS) {
		mutex_exit(&dev->dev_lock);
		return (EIO);
	}

	dev->state |= STATE_MAC_STARTED;
	mutex_exit(&dev->dev_lock);

	/* enable interrupts */
	oce_ei(dev);

	return (DDI_SUCCESS);
}

int
oce_start(struct oce_dev *dev)
{
	int qidx = 0;
	int ret;

	ret = oce_hw_init(dev);
	if (ret != DDI_SUCCESS) {
		oce_log(dev, CE_WARN, MOD_CONFIG,
		    "Hardware initialization failed with %d", ret);
		return (ret);
	}

	ret = oce_chip_hw_init(dev);
	if (ret != DDI_SUCCESS) {
		oce_log(dev, CE_WARN, MOD_CONFIG,
		    "Chip initialization failed: %d", ret);
		oce_hw_fini(dev);
		return (ret);
	}
	ret = oce_setup_handlers(dev);
	if (ret != DDI_SUCCESS) {
		oce_log(dev, CE_WARN, MOD_CONFIG,
		    "Interrupt handler setup failed with %d", ret);
		oce_chip_hw_fini(dev);
		oce_hw_fini(dev);
		return (ret);
	}

	(void) oce_start_wq(dev->wq[0]);
	(void) oce_start_rq(dev->rq[0]);

	/* get link status */
	(void) oce_get_link_status(dev, &dev->link);

	if (dev->link.mac_speed == PHY_LINK_SPEED_ZERO) {
		oce_log(dev, CE_NOTE, MOD_CONFIG,
		    "LINK_DOWN: 0x%x", dev->link.mac_speed);
		mac_link_update(dev->mac_handle, LINK_STATE_DOWN);
	} else {
		oce_log(dev, CE_NOTE, MOD_CONFIG,
		    "(f,s,d,pp)=(0x%x, 0x%x, 0x%x, 0x%x)",
		    dev->link.mac_fault, dev->link.mac_speed,
		    dev->link.mac_duplex, dev->link.physical_port);
		mac_link_update(dev->mac_handle, LINK_STATE_UP);
	}
	/* arm the eqs */
	for (qidx = 0; qidx < dev->neqs; qidx++) {
		oce_arm_eq(dev, dev->eq[qidx]->eq_id, 0, B_TRUE, B_FALSE);
	}

	/* update state */
	return (DDI_SUCCESS);
} /* oce_start */


void
oce_m_stop(void *arg)
{
	struct oce_dev *dev = arg;

	/* disable interrupts */
	oce_di(dev);

	mutex_enter(&dev->dev_lock);

	dev->state |= STATE_MAC_STOPPING;

	if (dev->suspended) {
		mutex_exit(&dev->dev_lock);
		return;
	}

	oce_stop(dev);

	dev->state &= ~(STATE_MAC_STOPPING | STATE_MAC_STARTED);

	mutex_exit(&dev->dev_lock);
}

void
oce_stop(struct oce_dev *dev)
{
	/* complete the pending Tx */
	oce_stop_wq(dev->wq[0]);

	oce_chip_hw_fini(dev);

	OCE_MSDELAY(200);
	oce_stop_mq(dev->mq);
	oce_stop_rq(dev->rq[0]);

	/* remove interrupt handlers */
	oce_remove_handler(dev);
	/* release hw resources */
	oce_hw_fini(dev);

} /* oce_stop */

int
oce_m_multicast(void *arg, boolean_t add, const uint8_t *mca)
{

	struct oce_dev *dev = (struct oce_dev *)arg;
	struct ether_addr  *mca_drv_list;
	struct ether_addr  *mca_hw_list;
	int new_mcnt = 0;
	int ret;
	int i;

	/* check the address */
	if ((mca[0] & 0x1) == 0) {
		return (EINVAL);
	}

	/* Allocate the local array for holding the addresses temporarily */
	mca_hw_list = kmem_zalloc(OCE_MAX_MCA * sizeof (struct ether_addr),
	    KM_NOSLEEP);

	if (mca_hw_list == NULL)
		return (ENOMEM);

	mca_drv_list = &dev->multi_cast[0];
	if (add) {
		/* check if we exceeded hw max  supported */
		if (dev->num_mca >= OCE_MAX_MCA) {
			return (ENOENT);
		}
		/* copy entire dev mca to the mbx */
		bcopy((void*)mca_drv_list,
		    (void *)mca_hw_list,
		    (dev->num_mca * sizeof (struct ether_addr)));
		/* Append the new one to local list */
		bcopy(mca, &mca_hw_list[dev->num_mca],
		    sizeof (struct ether_addr));
		new_mcnt = dev->num_mca + 1;

	} else {
		struct ether_addr *hwlistp = mca_hw_list;
		for (i = 0; i < dev->num_mca; i++) {
			/* copy only if it does not match */
			if (bcmp((mca_drv_list + i), mca, ETHERADDRL)) {
				bcopy(mca_drv_list + i, hwlistp,
				    ETHERADDRL);
				hwlistp++;
			}
		}
		new_mcnt = dev->num_mca - 1;
	}

	mutex_enter(&dev->dev_lock);
	if (dev->suspended) {
		mutex_exit(&dev->dev_lock);
		goto finish;
	}
	mutex_exit(&dev->dev_lock);

	ret = oce_set_multicast_table(dev, mca_hw_list, new_mcnt, B_FALSE);
	if (ret != 0) {
		kmem_free(mca_hw_list,
		    OCE_MAX_MCA * sizeof (struct ether_addr));
		return (EIO);
	}
	/*
	 *  Copy the local structure to dev structure
	 */
finish:
	bcopy(mca_hw_list, mca_drv_list,
	    new_mcnt * sizeof (struct ether_addr));
	dev->num_mca = (uint16_t)new_mcnt;
	kmem_free(mca_hw_list, OCE_MAX_MCA * sizeof (struct ether_addr));
	return (0);
} /* oce_m_multicast */

int
oce_m_unicast(void *arg, const uint8_t *uca)
{
	struct oce_dev *dev = arg;
	int ret;

	DEV_LOCK(dev);
	if (dev->suspended) {
		bcopy(uca, dev->unicast_addr, ETHERADDRL);
		DEV_UNLOCK(dev);
		return (DDI_SUCCESS);
	}
	DEV_UNLOCK(dev);

	/* Delete previous one and add new one */
	ret = oce_del_mac(dev, &dev->pmac_id);
	if (ret != DDI_SUCCESS) {
		return (EIO);
	}

	/* Set the New MAC addr earlier is no longer valid */
	ret = oce_add_mac(dev, uca, &dev->pmac_id);
	if (ret != DDI_SUCCESS) {
		return (EIO);
	}
	return (ret);
} /* oce_m_unicast */

mblk_t *
oce_m_send(void *arg, mblk_t *mp)
{
	struct oce_dev *dev = arg;
	mblk_t *nxt_pkt;
	mblk_t *rmp = NULL;

	DEV_LOCK(dev);
	if (dev->suspended) {
		DEV_UNLOCK(dev);
		freemsg(mp);
		return (NULL);
	}
	DEV_UNLOCK(dev);

	while (mp != NULL) {
		/* Save the Pointer since mp will be freed in case of copy */
		nxt_pkt = mp->b_next;
		mp->b_next = NULL;
		/* Hardcode wq since we have only one */
		rmp = oce_send_packet(dev->wq[0], mp);
		if (rmp != NULL) {
			/* restore the chain */
			rmp->b_next = nxt_pkt;
			break;
		}
		mp  = nxt_pkt;
	}
	return (rmp);
} /* oce_send */

boolean_t
oce_m_getcap(void *arg, mac_capab_t cap, void *data)
{
	struct oce_dev *dev = arg;
	boolean_t ret = B_TRUE;
	switch (cap) {

	case MAC_CAPAB_HCKSUM: {
		uint32_t *csum_flags = u32ptr(data);
		*csum_flags = HCKSUM_ENABLE |
		    HCKSUM_INET_FULL_V4 |
		    HCKSUM_IPHDRCKSUM;
		break;
	}
	case MAC_CAPAB_LSO: {
		mac_capab_lso_t *mcap_lso = (mac_capab_lso_t *)data;
		if (dev->lso_capable) {
			mcap_lso->lso_flags = LSO_TX_BASIC_TCP_IPV4;
			mcap_lso->lso_basic_tcp_ipv4.lso_max = OCE_LSO_MAX_SIZE;
		} else {
			ret = B_FALSE;
		}
		break;
	}
	default:
		ret = B_FALSE;
		break;
	}
	return (ret);
} /* oce_m_getcap */

int
oce_m_setprop(void *arg, const char *name, mac_prop_id_t id,
    uint_t size, const void *val)
{
	struct oce_dev *dev = arg;
	int ret = 0;

	switch (id) {
	case MAC_PROP_MTU: {
		uint32_t mtu;

		bcopy(val, &mtu, sizeof (uint32_t));

		if (dev->mtu == mtu) {
			ret = 0;
			break;
		}

		if (mtu != OCE_MIN_MTU && mtu != OCE_MAX_MTU) {
			ret = EINVAL;
			break;
		}

		ret = mac_maxsdu_update(dev->mac_handle, mtu);
		if (0 == ret) {
			dev->mtu = mtu;
			break;
		}
		break;
	}

	case MAC_PROP_FLOWCTRL: {
		link_flowctrl_t flowctrl;
		uint32_t fc = 0;

		bcopy(val, &flowctrl, sizeof (link_flowctrl_t));

		switch (flowctrl) {
		case LINK_FLOWCTRL_NONE:
			fc = 0;
			break;

		case LINK_FLOWCTRL_RX:
			fc = OCE_FC_RX;
			break;

		case LINK_FLOWCTRL_TX:
			fc = OCE_FC_TX;
			break;

		case LINK_FLOWCTRL_BI:
			fc = OCE_FC_RX | OCE_FC_TX;
			break;
		default:
			ret = EINVAL;
			break;
		} /* switch flowctrl */

		if (ret)
			break;

		if (fc == dev->flow_control)
			break;

		if (dev->suspended) {
			dev->flow_control = fc;
			break;
		}
		/* call to set flow control */
		ret = oce_set_flow_control(dev, fc);
		/* store the new fc setting on success */
		if (ret == 0) {
		dev->flow_control = fc;
		}
		break;
	}

	case MAC_PROP_PRIVATE:
		ret = oce_set_priv_prop(dev, name, size, val);
		break;

	default:
		ret = ENOTSUP;
		break;
	} /* switch id */

	return (ret);
} /* oce_m_setprop */

int
oce_m_getprop(void *arg, const char *name, mac_prop_id_t id,
    uint_t flags, uint_t size, void *val, uint_t *perm)
{
	struct oce_dev *dev = arg;
	uint32_t ret = 0;

	switch (id) {
	case MAC_PROP_AUTONEG:
	case MAC_PROP_EN_AUTONEG:
	case MAC_PROP_ADV_1000FDX_CAP:
	case MAC_PROP_EN_1000FDX_CAP:
	case MAC_PROP_ADV_1000HDX_CAP:
	case MAC_PROP_EN_1000HDX_CAP:
	case MAC_PROP_ADV_100FDX_CAP:
	case MAC_PROP_EN_100FDX_CAP:
	case MAC_PROP_ADV_100HDX_CAP:
	case MAC_PROP_EN_100HDX_CAP:
	case MAC_PROP_ADV_10FDX_CAP:
	case MAC_PROP_EN_10FDX_CAP:
	case MAC_PROP_ADV_10HDX_CAP:
	case MAC_PROP_EN_10HDX_CAP:
	case MAC_PROP_ADV_100T4_CAP:
	case MAC_PROP_EN_100T4_CAP: {
		*perm = MAC_PROP_PERM_READ;
		*(uint8_t *)val = 0x0;
		break;
	}

	case MAC_PROP_ADV_10GFDX_CAP:
	case MAC_PROP_EN_10GFDX_CAP: {
		*perm = MAC_PROP_PERM_READ;
		*(uint8_t *)val = 0x01;
		break;
	}

	case MAC_PROP_DUPLEX: {
		if (size >= sizeof (link_duplex_t)) {
			uint32_t *mode = (uint32_t *)val;

			*perm = MAC_PROP_PERM_READ;
			if (dev->state & STATE_MAC_STARTED)
				*mode = LINK_DUPLEX_FULL;
			else
				*mode = LINK_DUPLEX_UNKNOWN;

		} else
			ret = EINVAL;
		break;
	}

	case MAC_PROP_SPEED: {
		if (size >= sizeof (uint64_t)) {
			uint64_t *speed = (uint64_t *)val;

			*perm = MAC_PROP_PERM_READ;
			*speed = 0;
			if ((dev->state & STATE_MAC_STARTED) &&
			    (dev->link.mac_speed != 0)) {
				*speed = 1000000ull *
				    oce_power10(dev->link.mac_speed);
			}
		} else
			ret = EINVAL;
		break;
	}

	case MAC_PROP_MTU: {
		mac_propval_range_t range;

		*perm = MAC_PROP_PERM_RW;
		if (!(flags & MAC_PROP_POSSIBLE)) {
			ret = ENOTSUP;
			break;
		}
		range.mpr_count = 1;
		range.mpr_type = MAC_PROPVAL_UINT32;
		range.range_uint32[0].mpur_min = OCE_MIN_MTU;
		range.range_uint32[0].mpur_max = OCE_MAX_MTU;
		bcopy(&range, val, sizeof (mac_propval_range_t));
		break;
	}

	case MAC_PROP_FLOWCTRL: {
		link_flowctrl_t *fc = (link_flowctrl_t *)val;

		if (size < sizeof (link_flowctrl_t)) {
			ret = EINVAL;
			break;
		}

		if (size >= sizeof (link_flowctrl_t)) {
			if (dev->flow_control & OCE_FC_TX &&
			    dev->flow_control & OCE_FC_RX)
				*fc = LINK_FLOWCTRL_BI;
			else if (dev->flow_control == OCE_FC_TX)
				*fc = LINK_FLOWCTRL_TX;
			else if (dev->flow_control == OCE_FC_RX)
				*fc = LINK_FLOWCTRL_RX;
			else if (dev->flow_control == 0)
				*fc = LINK_FLOWCTRL_NONE;
			else
				ret = EINVAL;
		}
		break;
	}

	case MAC_PROP_PRIVATE: {
		ret = oce_get_priv_prop(dev, name, flags, size, val);
		break;
	}
	default:
		break;
	} /* switch id */
	return (ret);
} /* oce_m_getprop */

/*
 * function to handle dlpi streams message from GLDv3 mac layer
 */
void
oce_m_ioctl(void *arg, queue_t *wq, mblk_t *mp)
{
	struct oce_dev *dev = arg;
	struct  iocblk *iocp;
	int cmd;
	uint32_t payload_length;
	int ret;

	iocp = (struct iocblk *)voidptr(mp->b_rptr);
	iocp->ioc_error = 0;
	cmd = iocp->ioc_cmd;

	DEV_LOCK(dev);
	if (dev->suspended) {
		miocnak(wq, mp, 0, EINVAL);
		DEV_UNLOCK(dev);
		return;
	}
	DEV_UNLOCK(dev);

	switch (cmd) {

	case OCE_ISSUE_MBOX: {
		ret = oce_issue_mbox(dev, wq, mp, &payload_length);
		if (ret != 0) {
			miocnak(wq, mp, payload_length, ret);
		} else {
			miocack(wq, mp, payload_length, 0);
		}
		break;
	}

	default:
		miocnak(wq, mp, 0, ENOTSUP);
		break;
	}
} /* oce_m_ioctl */

int
oce_m_promiscuous(void *arg, boolean_t enable)
{
	struct oce_dev *dev = arg;
	int ret = 0;

	DEV_LOCK(dev);

	if (dev->promisc == enable) {
		DEV_UNLOCK(dev);
		return (ret);
	}
	dev->promisc = enable;

	if (dev->suspended) {
		DEV_UNLOCK(dev);
		return (ret);
	}

	DEV_UNLOCK(dev);

	ret = oce_set_promiscuous(dev, enable);

	return (ret);
} /* oce_m_promiscuous */

static int
oce_power10(int power)
{
	int ret = 1;

	while (power) {
		ret *= 10;
		power--;
	}
	return (ret);
}

/*
 * function to set a private property.
 * Called from the set_prop GLD entry point
 *
 * dev - sofware handle to the device
 * name - string containing the property name
 * size - length of the string in name
 * val - pointer to a location where the value to set is stored
 *
 * return EINVAL => invalid value in val 0 => success
 */
static int
oce_set_priv_prop(struct oce_dev *dev, const char *name,
    uint_t size, const void *val)
{
	int ret = ENOTSUP;
	long result;

	_NOTE(ARGUNUSED(size));

	if (NULL == val) {
		ret = EINVAL;
		return (ret);
	}

	if (strcmp(name, "_tx_bcopy_limit") == 0) {
		(void) ddi_strtol(val, (char **)NULL, 0, &result);
		if (result <= OCE_WQ_BUF_SIZE) {
			if (result != dev->bcopy_limit)
				dev->bcopy_limit = (uint32_t)result;
			ret = 0;
		} else {
			ret = EINVAL;
		}
	}

	return (ret);
} /* oce_set_priv_prop */

/*
 * function to get the value of a private property. Called from get_prop
 *
 * dev - software handle to the device
 * name - string containing the property name
 * flags - flags sent by the OS to get_prop
 * size - length of the string contained name
 * val - [OUT] pointer to the location where the result is returned
 *
 * return EINVAL => invalid request 0 => success
 */
static int
oce_get_priv_prop(struct oce_dev *dev, const char *name,
    uint_t flags, uint_t size, void *val)
{
	int ret = ENOTSUP;
	int value;
	boolean_t is_default = (flags & MAC_PROP_DEFAULT);

	if (NULL == val) {
		ret = EINVAL;
		return (ret);
	}

	if (strcmp(name, "_tx_ring_size") == 0) {
		value = is_default ? OCE_DEFAULT_TX_RING_SIZE :
		    dev->tx_ring_size;
		ret = 0;
		goto done;
	}

	if (strcmp(name, "_tx_bcopy_limit") == 0) {
		value = dev->bcopy_limit;
		ret = 0;
		goto done;
	}

	if (strcmp(name, "_rx_ring_size") == 0) {
		value = is_default ? OCE_DEFAULT_RX_RING_SIZE :
		    dev->rx_ring_size;
		ret = 0;
		goto done;
	}

done:
	if (ret != 0) {
		(void) snprintf(val, size, "%d", value);
	}
	return (ret);
} /* oce_get_priv_prop */
