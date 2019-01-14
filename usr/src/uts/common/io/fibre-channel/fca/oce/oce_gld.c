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

/* Copyright © 2003-2011 Emulex. All rights reserved.  */

/*
 * Copyright (c) 2018, Joyent, Inc.
 */

/*
 * Source file containing the implementation of the driver entry points
 * and related helper functions
 */

#include <oce_impl.h>
#include <oce_ioctl.h>

/* array of properties supported by this driver */
char *oce_priv_props[] = {
	"_tx_ring_size",
	"_tx_bcopy_limit",
	"_rx_ring_size",
	"_rx_bcopy_limit",
	NULL
};

extern int pow10[];

/* ---[ static function declarations ]----------------------------------- */
static int oce_set_priv_prop(struct oce_dev *dev, const char *name,
    uint_t size, const void *val);

static int oce_get_priv_prop(struct oce_dev *dev, const char *name,
    uint_t size, void *val);

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
	ret = oce_start(dev);
	if (ret != DDI_SUCCESS) {
		mutex_exit(&dev->dev_lock);
		return (EIO);
	}

	dev->state |= STATE_MAC_STARTED;
	mutex_exit(&dev->dev_lock);


	return (DDI_SUCCESS);
}

int
oce_start(struct oce_dev *dev)
{
	int qidx = 0;
	struct link_status link = {0};

	/* get link status */
	(void) oce_get_link_status(dev, &link);

	dev->link_status  = (link.logical_link_status == NTWK_LOGICAL_LINK_UP) ?
	    LINK_STATE_UP : LINK_STATE_DOWN;

	dev->link_speed = link.qos_link_speed ? link.qos_link_speed * 10 :
	    pow10[link.mac_speed];

	mac_link_update(dev->mac_handle, dev->link_status);

	for (qidx = 0; qidx < dev->nwqs; qidx++) {
		(void) oce_start_wq(dev->wq[qidx]);
	}
	for (qidx = 0; qidx < dev->nrqs; qidx++) {
		(void) oce_start_rq(dev->rq[qidx]);
	}
	(void) oce_start_mq(dev->mq);
	/* enable interrupts */
	oce_ei(dev);
	/* arm the eqs */
	for (qidx = 0; qidx < dev->neqs; qidx++) {
		oce_arm_eq(dev, dev->eq[qidx]->eq_id, 0, B_TRUE, B_FALSE);
	}
	/* TODO update state */
	return (DDI_SUCCESS);
} /* oce_start */


void
oce_m_stop(void *arg)
{
	struct oce_dev *dev = arg;

	/* disable interrupts */

	mutex_enter(&dev->dev_lock);
	if (dev->suspended) {
		mutex_exit(&dev->dev_lock);
		return;
	}
	dev->state |= STATE_MAC_STOPPING;
	oce_stop(dev);
	dev->state &= ~(STATE_MAC_STOPPING | STATE_MAC_STARTED);
	mutex_exit(&dev->dev_lock);
}
/* called with Tx/Rx comp locks held */
void
oce_stop(struct oce_dev *dev)
{
	int qidx;
	/* disable interrupts */
	oce_di(dev);
	for (qidx = 0; qidx < dev->nwqs; qidx++) {
		mutex_enter(&dev->wq[qidx]->tx_lock);
	}
	mutex_enter(&dev->mq->lock);
	/* complete the pending Tx */
	for (qidx = 0; qidx < dev->nwqs; qidx++)
		oce_clean_wq(dev->wq[qidx]);
	/* Release all the locks */
	mutex_exit(&dev->mq->lock);
	for (qidx = 0; qidx < dev->nwqs; qidx++)
		mutex_exit(&dev->wq[qidx]->tx_lock);
	if (dev->link_status == LINK_STATE_UP) {
		dev->link_status = LINK_STATE_UNKNOWN;
		mac_link_update(dev->mac_handle, dev->link_status);
	}

} /* oce_stop */

int
oce_m_multicast(void *arg, boolean_t add, const uint8_t *mca)
{
	struct oce_dev *dev = (struct oce_dev *)arg;
	struct ether_addr  *mca_drv_list;
	struct ether_addr  mca_hw_list[OCE_MAX_MCA];
	uint16_t new_mcnt = dev->num_mca;
	int ret;
	int i;

	/* check the address */
	if ((mca[0] & 0x1) == 0) {
		return (EINVAL);
	}
	/* Allocate the local array for holding the addresses temporarily */
	bzero(&mca_hw_list, sizeof (&mca_hw_list));
	mca_drv_list = &dev->multi_cast[0];

	DEV_LOCK(dev);
	if (add) {
		/* check if we exceeded hw max  supported */
		if (new_mcnt < OCE_MAX_MCA) {
			/* copy entire dev mca to the mbx */
			bcopy((void*)mca_drv_list,
			    (void*)mca_hw_list,
			    (dev->num_mca * sizeof (struct ether_addr)));
			/* Append the new one to local list */
			bcopy(mca, &mca_hw_list[dev->num_mca],
			    sizeof (struct ether_addr));
		}
		new_mcnt++;
	} else {
		struct ether_addr *hwlistp = &mca_hw_list[0];
		for (i = 0; i < dev->num_mca; i++) {
			/* copy only if it does not match */
			if (bcmp((mca_drv_list + i), mca, ETHERADDRL)) {
				bcopy(mca_drv_list + i, hwlistp,
				    ETHERADDRL);
				hwlistp++;
			} else {
				new_mcnt--;
			}
		}
	}

	if (dev->suspended) {
		goto finish;
	}
	if (new_mcnt > OCE_MAX_MCA) {
		ret = oce_set_multicast_table(dev, dev->if_id, &mca_hw_list[0],
		    OCE_MAX_MCA, B_TRUE);
	} else {
		ret = oce_set_multicast_table(dev, dev->if_id,
		    &mca_hw_list[0], new_mcnt, B_FALSE);
	}
	if (ret != 0) {
		oce_log(dev, CE_WARN, MOD_CONFIG,
		    "mcast %s fails", add ? "ADD" : "DEL");
		DEV_UNLOCK(dev);
		return (EIO);
	}
	/*
	 *  Copy the local structure to dev structure
	 */
finish:
	if (new_mcnt && new_mcnt <= OCE_MAX_MCA) {
		bcopy(mca_hw_list, mca_drv_list,
		    new_mcnt * sizeof (struct ether_addr));

		dev->num_mca = (uint16_t)new_mcnt;
	}
	DEV_UNLOCK(dev);
	oce_log(dev, CE_NOTE, MOD_CONFIG,
	    "mcast %s, addr=%02x:%02x:%02x:%02x:%02x:%02x, num_mca=%d",
	    add ? "ADD" : "DEL",
	    mca[0], mca[1], mca[2], mca[3], mca[4], mca[5],
	    dev->num_mca);
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
		dev->num_smac = 0;
		DEV_UNLOCK(dev);
		return (DDI_SUCCESS);
	}

	/* Delete previous one and add new one */
	ret = oce_del_mac(dev, dev->if_id, &dev->pmac_id);
	if (ret != DDI_SUCCESS) {
		DEV_UNLOCK(dev);
		return (EIO);
	}
	dev->num_smac = 0;
	bzero(dev->unicast_addr, ETHERADDRL);

	/* Set the New MAC addr earlier is no longer valid */
	ret = oce_add_mac(dev, dev->if_id, uca, &dev->pmac_id);
	if (ret != DDI_SUCCESS) {
		DEV_UNLOCK(dev);
		return (EIO);
	}
	bcopy(uca, dev->unicast_addr, ETHERADDRL);
	dev->num_smac = 1;
	DEV_UNLOCK(dev);
	return (ret);
} /* oce_m_unicast */

/*
 * Hashing policy for load balancing over the set of TX rings
 * available to the driver.
 */
mblk_t *
oce_m_send(void *arg, mblk_t *mp)
{
	struct oce_dev *dev = arg;
	mblk_t *nxt_pkt;
	mblk_t *rmp = NULL;
	struct oce_wq *wq;

	DEV_LOCK(dev);
	if (dev->suspended || !(dev->state & STATE_MAC_STARTED)) {
		DEV_UNLOCK(dev);
		freemsg(mp);
		return (NULL);
	}
	DEV_UNLOCK(dev);
	/*
	 * Hash to pick a wq
	 */
	wq = oce_get_wq(dev, mp);

	while (mp != NULL) {
		/* Save the Pointer since mp will be freed in case of copy */
		nxt_pkt = mp->b_next;
		mp->b_next = NULL;
		/* Hardcode wq since we have only one */
		rmp = oce_send_packet(wq, mp);
		if (rmp != NULL) {
			/* reschedule Tx */
			wq->resched = B_TRUE;
			oce_arm_cq(dev, wq->cq->cq_id, 0, B_TRUE);
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

	DEV_LOCK(dev);
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

	DEV_UNLOCK(dev);
	return (ret);
} /* oce_m_setprop */

int
oce_m_getprop(void *arg, const char *name, mac_prop_id_t id,
    uint_t size, void *val)
{
	struct oce_dev *dev = arg;
	uint32_t ret = 0;

	switch (id) {
	case MAC_PROP_ADV_10GFDX_CAP:
	case MAC_PROP_EN_10GFDX_CAP:
		*(uint8_t *)val = 0x01;
		break;

	case MAC_PROP_DUPLEX: {
		uint32_t *mode = (uint32_t *)val;

		ASSERT(size >= sizeof (link_duplex_t));
		if (dev->state & STATE_MAC_STARTED)
			*mode = LINK_DUPLEX_FULL;
		else
			*mode = LINK_DUPLEX_UNKNOWN;
		break;
	}

	case MAC_PROP_SPEED: {
		uint64_t *speed = (uint64_t *)val;
		struct link_status link = {0};

		ASSERT(size >= sizeof (uint64_t));
		*speed = 0;

		if (dev->state & STATE_MAC_STARTED) {
			if (dev->link_speed < 0) {
				(void) oce_get_link_status(dev, &link);
				dev->link_speed = link.qos_link_speed ?
				    link.qos_link_speed * 10 :
				    pow10[link.mac_speed];
			}

			*speed = dev->link_speed * 1000000ull;
		}
		break;
	}

	case MAC_PROP_FLOWCTRL: {
		link_flowctrl_t *fc = (link_flowctrl_t *)val;

		ASSERT(size >= sizeof (link_flowctrl_t));
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
		break;
	}

	case MAC_PROP_PRIVATE:
		ret = oce_get_priv_prop(dev, name, size, val);
		break;

	default:
		ret = ENOTSUP;
		break;
	} /* switch id */
	return (ret);
} /* oce_m_getprop */

void
oce_m_propinfo(void *arg, const char *name, mac_prop_id_t pr_num,
    mac_prop_info_handle_t prh)
{
	_NOTE(ARGUNUSED(arg));

	switch (pr_num) {
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
	case MAC_PROP_EN_100T4_CAP:
	case MAC_PROP_ADV_10GFDX_CAP:
	case MAC_PROP_EN_10GFDX_CAP:
	case MAC_PROP_SPEED:
	case MAC_PROP_DUPLEX:
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		break;

	case MAC_PROP_MTU:
		mac_prop_info_set_range_uint32(prh, OCE_MIN_MTU, OCE_MAX_MTU);
		break;

	case MAC_PROP_PRIVATE: {
		char valstr[64];
		int value;

		if (strcmp(name, "_tx_ring_size") == 0) {
			value = OCE_DEFAULT_TX_RING_SIZE;
		} else if (strcmp(name, "_rx_ring_size") == 0) {
			value = OCE_DEFAULT_RX_RING_SIZE;
		} else {
			return;
		}

		(void) snprintf(valstr, sizeof (valstr), "%d", value);
		mac_prop_info_set_default_str(prh, valstr);
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		break;
	}
	}
} /* oce_m_propinfo */

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
		miocack(wq, mp, payload_length, ret);
		break;
	}
	case OCE_QUERY_DRIVER_DATA: {
		struct oce_driver_query *drv_query =
		    (struct oce_driver_query *)(void *)mp->b_cont->b_rptr;

		/* if the driver version does not match bail */
		if (drv_query->version != OCN_VERSION_SUPPORTED) {
			oce_log(dev, CE_NOTE, MOD_CONFIG, "%s",
			    "One Connect version mismatch");
			miocnak(wq, mp, 0, ENOTSUP);
			break;
		}

		/* fill the return values */
		bcopy(OCE_MOD_NAME, drv_query->driver_name,
		    (sizeof (OCE_MOD_NAME) > 32) ?
		    31 : sizeof (OCE_MOD_NAME));
		drv_query->driver_name[31] = '\0';

		bcopy(OCE_VERSION, drv_query->driver_version,
		    (sizeof (OCE_VERSION) > 32) ? 31 :
		    sizeof (OCE_VERSION));
		drv_query->driver_version[31] = '\0';

		if (dev->num_smac == 0) {
			drv_query->num_smac = 1;
			bcopy(dev->mac_addr, drv_query->smac_addr[0],
			    ETHERADDRL);
		} else {
			drv_query->num_smac = dev->num_smac;
			bcopy(dev->unicast_addr, drv_query->smac_addr[0],
			    ETHERADDRL);
		}

		bcopy(dev->mac_addr, drv_query->pmac_addr, ETHERADDRL);

		payload_length = sizeof (struct oce_driver_query);
		miocack(wq, mp, payload_length, 0);
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

	if (dev->suspended) {
		/* remember the setting */
		dev->promisc = enable;
		DEV_UNLOCK(dev);
		return (ret);
	}

	ret = oce_set_promiscuous(dev, enable);
	if (ret == DDI_SUCCESS)
		dev->promisc = enable;
	DEV_UNLOCK(dev);
	return (ret);
} /* oce_m_promiscuous */

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
			if (result != dev->tx_bcopy_limit)
				dev->tx_bcopy_limit = (uint32_t)result;
			ret = 0;
		} else {
			ret = EINVAL;
		}
	}
	if (strcmp(name, "_rx_bcopy_limit") == 0) {
		(void) ddi_strtol(val, (char **)NULL, 0, &result);
		if (result <= OCE_RQ_BUF_SIZE) {
			if (result != dev->rx_bcopy_limit)
				dev->rx_bcopy_limit = (uint32_t)result;
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
 * size - length of the string contained name
 * val - [OUT] pointer to the location where the result is returned
 *
 * return EINVAL => invalid request 0 => success
 */
static int
oce_get_priv_prop(struct oce_dev *dev, const char *name,
    uint_t size, void *val)
{
	int value;

	if (strcmp(name, "_tx_ring_size") == 0) {
		value = dev->tx_ring_size;
	} else if (strcmp(name, "_tx_bcopy_limit") == 0) {
		value = dev->tx_bcopy_limit;
	} else if (strcmp(name, "_rx_ring_size") == 0) {
		value = dev->rx_ring_size;
	} else if (strcmp(name, "_rx_bcopy_limit") == 0) {
		value = dev->rx_bcopy_limit;
	} else {
		return (ENOTSUP);
	}

	(void) snprintf(val, size, "%d", value);
	return (0);
} /* oce_get_priv_prop */
