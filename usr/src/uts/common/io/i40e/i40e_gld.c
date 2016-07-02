/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2015 OmniTI Computer Consulting, Inc. All rights reserved.
 * Copyright 2016 Joyent, Inc.
 */

/*
 * For more information, please see the big theory statement in i40e_main.c.
 */

#include "i40e_sw.h"

#define	I40E_PROP_RX_DMA_THRESH	"_rx_dma_threshold"
#define	I40E_PROP_TX_DMA_THRESH	"_tx_dma_threshold"
#define	I40E_PROP_RX_ITR	"_rx_intr_throttle"
#define	I40E_PROP_TX_ITR	"_tx_intr_throttle"
#define	I40E_PROP_OTHER_ITR	"_other_intr_throttle"

char *i40e_priv_props[] = {
	I40E_PROP_RX_DMA_THRESH,
	I40E_PROP_TX_DMA_THRESH,
	I40E_PROP_RX_ITR,
	I40E_PROP_TX_ITR,
	I40E_PROP_OTHER_ITR,
	NULL
};

static int
i40e_group_remove_mac(void *arg, const uint8_t *mac_addr)
{
	i40e_t *i40e = arg;
	struct i40e_aqc_remove_macvlan_element_data filt;
	struct i40e_hw *hw = &i40e->i40e_hw_space;
	int ret, i, last;
	i40e_uaddr_t *iua;

	if (I40E_IS_MULTICAST(mac_addr))
		return (EINVAL);

	mutex_enter(&i40e->i40e_general_lock);

	if (i40e->i40e_state & I40E_SUSPENDED) {
		ret = ECANCELED;
		goto done;
	}

	for (i = 0; i < i40e->i40e_resources.ifr_nmacfilt_used; i++) {
		if (bcmp(mac_addr, i40e->i40e_uaddrs[i].iua_mac,
		    ETHERADDRL) == 0)
			break;
	}

	if (i == i40e->i40e_resources.ifr_nmacfilt_used) {
		ret = ENOENT;
		goto done;
	}

	iua = &i40e->i40e_uaddrs[i];
	ASSERT(i40e->i40e_resources.ifr_nmacfilt_used > 0);

	bzero(&filt, sizeof (filt));
	bcopy(mac_addr, filt.mac_addr, ETHERADDRL);
	filt.flags = I40E_AQC_MACVLAN_DEL_PERFECT_MATCH |
	    I40E_AQC_MACVLAN_DEL_IGNORE_VLAN;

	if (i40e_aq_remove_macvlan(hw, iua->iua_vsi, &filt, 1, NULL) !=
	    I40E_SUCCESS) {
		i40e_error(i40e, "failed to remove mac address "
		    "%2x:%2x:%2x:%2x:%2x:%2x from unicast filter: %d",
		    mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3],
		    mac_addr[4], mac_addr[5], filt.error_code);
		ret = EIO;
		goto done;
	}

	last = i40e->i40e_resources.ifr_nmacfilt_used - 1;
	if (i != last) {
		i40e_uaddr_t *src = &i40e->i40e_uaddrs[last];
		bcopy(src, iua, sizeof (i40e_uaddr_t));
	}

	/*
	 * Set the multicast bit in the last one to indicate to ourselves that
	 * it's invalid.
	 */
	bzero(&i40e->i40e_uaddrs[last], sizeof (i40e_uaddr_t));
	i40e->i40e_uaddrs[last].iua_mac[0] = 0x01;
	i40e->i40e_resources.ifr_nmacfilt_used--;
	ret = 0;
done:
	mutex_exit(&i40e->i40e_general_lock);

	return (ret);
}

static int
i40e_group_add_mac(void *arg, const uint8_t *mac_addr)
{
	i40e_t *i40e = arg;
	struct i40e_hw *hw = &i40e->i40e_hw_space;
	int i, ret;
	i40e_uaddr_t *iua;
	struct i40e_aqc_add_macvlan_element_data filt;

	if (I40E_IS_MULTICAST(mac_addr))
		return (EINVAL);

	mutex_enter(&i40e->i40e_general_lock);
	if (i40e->i40e_state & I40E_SUSPENDED) {
		ret = ECANCELED;
		goto done;
	}

	if (i40e->i40e_resources.ifr_nmacfilt ==
	    i40e->i40e_resources.ifr_nmacfilt_used) {
		ret = ENOSPC;
		goto done;
	}

	for (i = 0; i < i40e->i40e_resources.ifr_nmacfilt_used; i++) {
		if (bcmp(mac_addr, i40e->i40e_uaddrs[i].iua_mac,
		    ETHERADDRL) == 0) {
			ret = EEXIST;
			goto done;
		}
	}

	/*
	 * Note, the general use of the i40e_vsi_id will have to be refactored
	 * when we have proper group support.
	 */
	bzero(&filt, sizeof (filt));
	bcopy(mac_addr, filt.mac_addr, ETHERADDRL);
	filt.flags = I40E_AQC_MACVLAN_ADD_PERFECT_MATCH	|
	    I40E_AQC_MACVLAN_ADD_IGNORE_VLAN;

	if ((ret = i40e_aq_add_macvlan(hw, i40e->i40e_vsi_id, &filt, 1,
	    NULL)) != I40E_SUCCESS) {
		i40e_error(i40e, "failed to add mac address "
		    "%2x:%2x:%2x:%2x:%2x:%2x to unicast filter: %d",
		    mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3],
		    mac_addr[4], mac_addr[5], ret);
		ret = EIO;
		goto done;
	}

	iua = &i40e->i40e_uaddrs[i40e->i40e_resources.ifr_nmacfilt_used];
	bcopy(mac_addr, iua->iua_mac, ETHERADDRL);
	iua->iua_vsi = i40e->i40e_vsi_id;
	i40e->i40e_resources.ifr_nmacfilt_used++;
	ASSERT(i40e->i40e_resources.ifr_nmacfilt_used <=
	    i40e->i40e_resources.ifr_nmacfilt);
	ret = 0;
done:
	mutex_exit(&i40e->i40e_general_lock);
	return (ret);
}

static int
i40e_m_start(void *arg)
{
	i40e_t *i40e = arg;
	int rc = 0;

	mutex_enter(&i40e->i40e_general_lock);
	if (i40e->i40e_state & I40E_SUSPENDED) {
		rc = ECANCELED;
		goto done;
	}

	if (!i40e_start(i40e, B_TRUE)) {
		rc = EIO;
		goto done;
	}

	atomic_or_32(&i40e->i40e_state, I40E_STARTED);
done:
	mutex_exit(&i40e->i40e_general_lock);

	return (rc);
}

static void
i40e_m_stop(void *arg)
{
	i40e_t *i40e = arg;

	mutex_enter(&i40e->i40e_general_lock);

	if (i40e->i40e_state & I40E_SUSPENDED)
		goto done;

	atomic_and_32(&i40e->i40e_state, ~I40E_STARTED);
	i40e_stop(i40e, B_TRUE);
done:
	mutex_exit(&i40e->i40e_general_lock);
}

/*
 * Enable and disable promiscuous mode as requested. We have to toggle both
 * unicast and multicast. Note that multicast may already be enabled due to the
 * i40e_m_multicast may toggle it itself. See i40e_main.c for more information
 * on this.
 */
static int
i40e_m_promisc(void *arg, boolean_t on)
{
	i40e_t *i40e = arg;
	struct i40e_hw *hw = &i40e->i40e_hw_space;
	int ret = 0, err = 0;

	mutex_enter(&i40e->i40e_general_lock);
	if (i40e->i40e_state & I40E_SUSPENDED) {
		ret = ECANCELED;
		goto done;
	}


	ret = i40e_aq_set_vsi_unicast_promiscuous(hw, i40e->i40e_vsi_id,
	    on, NULL);
	if (ret != I40E_SUCCESS) {
		i40e_error(i40e, "failed to %s unicast promiscuity on "
		    "the default VSI: %d", on == B_TRUE ? "enable" : "disable",
		    ret);
		err = EIO;
		goto done;
	}

	/*
	 * If we have a non-zero mcast_promisc_count, then it has already been
	 * enabled or we need to leave it that way and not touch it.
	 */
	if (i40e->i40e_mcast_promisc_count > 0) {
		i40e->i40e_promisc_on = on;
		goto done;
	}

	ret = i40e_aq_set_vsi_multicast_promiscuous(hw, i40e->i40e_vsi_id,
	    on, NULL);
	if (ret != I40E_SUCCESS) {
		i40e_error(i40e, "failed to %s multicast promiscuity on "
		    "the default VSI: %d", on == B_TRUE ? "enable" : "disable",
		    ret);

		/*
		 * Try our best to put us back into a state that MAC expects us
		 * to be in.
		 */
		ret = i40e_aq_set_vsi_unicast_promiscuous(hw, i40e->i40e_vsi_id,
		    !on, NULL);
		if (ret != I40E_SUCCESS) {
			i40e_error(i40e, "failed to %s unicast promiscuity on "
			    "the default VSI after toggling multicast failed: "
			    "%d", on == B_TRUE ? "disable" : "enable", ret);
		}

		err = EIO;
		goto done;
	} else {
		i40e->i40e_promisc_on = on;
	}

done:
	mutex_exit(&i40e->i40e_general_lock);
	return (err);
}

/*
 * See the big theory statement in i40e_main.c for multicast address management.
 */
static int
i40e_multicast_add(i40e_t *i40e, const uint8_t *multicast_address)
{
	struct i40e_hw *hw = &i40e->i40e_hw_space;
	struct i40e_aqc_add_macvlan_element_data filt;
	i40e_maddr_t *mc;
	int ret;

	ASSERT(MUTEX_HELD(&i40e->i40e_general_lock));

	if (i40e->i40e_resources.ifr_nmcastfilt_used ==
	    i40e->i40e_resources.ifr_nmcastfilt) {
		if (i40e->i40e_mcast_promisc_count == 0 &&
		    i40e->i40e_promisc_on == B_FALSE) {
			ret = i40e_aq_set_vsi_multicast_promiscuous(hw,
			    i40e->i40e_vsi_id, B_TRUE, NULL);
			if (ret != I40E_SUCCESS) {
				i40e_error(i40e, "failed to enable multicast "
				    "promiscuous mode on VSI %d: %d",
				    i40e->i40e_vsi_id, ret);
				return (EIO);
			}
		}
		i40e->i40e_mcast_promisc_count++;
		return (0);
	}

	mc = &i40e->i40e_maddrs[i40e->i40e_resources.ifr_nmcastfilt_used];
	bzero(&filt, sizeof (filt));
	bcopy(multicast_address, filt.mac_addr, ETHERADDRL);
	filt.flags = I40E_AQC_MACVLAN_ADD_HASH_MATCH |
	    I40E_AQC_MACVLAN_ADD_IGNORE_VLAN;

	if ((ret = i40e_aq_add_macvlan(hw, i40e->i40e_vsi_id, &filt, 1,
	    NULL)) != I40E_SUCCESS) {
		i40e_error(i40e, "failed to add mac address "
		    "%2x:%2x:%2x:%2x:%2x:%2x to multicast filter: %d",
		    multicast_address[0], multicast_address[1],
		    multicast_address[2], multicast_address[3],
		    multicast_address[4], multicast_address[5],
		    ret);
		return (EIO);
	}

	bcopy(multicast_address, mc->ima_mac, ETHERADDRL);
	i40e->i40e_resources.ifr_nmcastfilt_used++;
	return (0);
}

/*
 * See the big theory statement in i40e_main.c for multicast address management.
 */
static int
i40e_multicast_remove(i40e_t *i40e, const uint8_t *multicast_address)
{
	int i, ret;
	struct i40e_hw *hw = &i40e->i40e_hw_space;

	ASSERT(MUTEX_HELD(&i40e->i40e_general_lock));

	for (i = 0; i < i40e->i40e_resources.ifr_nmcastfilt_used; i++) {
		struct i40e_aqc_remove_macvlan_element_data filt;
		int last;

		if (bcmp(multicast_address, i40e->i40e_maddrs[i].ima_mac,
		    ETHERADDRL) != 0) {
			continue;
		}

		bzero(&filt, sizeof (filt));
		bcopy(multicast_address, filt.mac_addr, ETHERADDRL);
		filt.flags = I40E_AQC_MACVLAN_DEL_HASH_MATCH |
		    I40E_AQC_MACVLAN_DEL_IGNORE_VLAN;

		if (i40e_aq_remove_macvlan(hw, i40e->i40e_vsi_id,
		    &filt, 1, NULL) != I40E_SUCCESS) {
			i40e_error(i40e, "failed to remove mac address "
			    "%2x:%2x:%2x:%2x:%2x:%2x from multicast "
			    "filter: %d",
			    multicast_address[0], multicast_address[1],
			    multicast_address[2], multicast_address[3],
			    multicast_address[4], multicast_address[5],
			    filt.error_code);
			return (EIO);
		}

		last = i40e->i40e_resources.ifr_nmcastfilt_used - 1;
		if (i != last) {
			bcopy(&i40e->i40e_maddrs[last], &i40e->i40e_maddrs[i],
			    sizeof (i40e_maddr_t));
			bzero(&i40e->i40e_maddrs[last], sizeof (i40e_maddr_t));
		}

		ASSERT(i40e->i40e_resources.ifr_nmcastfilt_used > 0);
		i40e->i40e_resources.ifr_nmcastfilt_used--;
		return (0);
	}

	if (i40e->i40e_mcast_promisc_count > 0) {
		if (i40e->i40e_mcast_promisc_count == 1 &&
		    i40e->i40e_promisc_on == B_FALSE) {
			ret = i40e_aq_set_vsi_multicast_promiscuous(hw,
			    i40e->i40e_vsi_id, B_FALSE, NULL);
			if (ret != I40E_SUCCESS) {
				i40e_error(i40e, "failed to disable "
				    "multicast promiscuous mode on VSI %d: %d",
				    i40e->i40e_vsi_id, ret);
				return (EIO);
			}
		}
		i40e->i40e_mcast_promisc_count--;

		return (0);
	}

	return (ENOENT);
}

static int
i40e_m_multicast(void *arg, boolean_t add, const uint8_t *multicast_address)
{
	i40e_t *i40e = arg;
	int rc;

	mutex_enter(&i40e->i40e_general_lock);

	if (i40e->i40e_state & I40E_SUSPENDED) {
		mutex_exit(&i40e->i40e_general_lock);
		return (ECANCELED);
	}

	if (add == B_TRUE) {
		rc = i40e_multicast_add(i40e, multicast_address);
	} else {
		rc = i40e_multicast_remove(i40e, multicast_address);
	}

	mutex_exit(&i40e->i40e_general_lock);
	return (rc);
}

/* ARGSUSED */
static void
i40e_m_ioctl(void *arg, queue_t *q, mblk_t *mp)
{
	/*
	 * At this time, we don't support toggling i40e into loopback mode. It's
	 * questionable how much value this has when there's no clear way to
	 * toggle this behavior from a supported way in userland.
	 */
	miocnak(q, mp, 0, EINVAL);
}

static int
i40e_ring_start(mac_ring_driver_t rh, uint64_t gen_num)
{
	i40e_trqpair_t *itrq = (i40e_trqpair_t *)rh;

	/*
	 * GLDv3 requires we keep track of a generation number, as it uses
	 * that number to keep track of whether or not a ring is active.
	 */
	mutex_enter(&itrq->itrq_rx_lock);
	itrq->itrq_rxgen = gen_num;
	mutex_exit(&itrq->itrq_rx_lock);
	return (0);
}

/* ARGSUSED */
static int
i40e_rx_ring_intr_enable(mac_intr_handle_t intrh)
{
	i40e_trqpair_t *itrq = (i40e_trqpair_t *)intrh;
	i40e_t *i40e = itrq->itrq_i40e;

	mutex_enter(&i40e->i40e_general_lock);
	ASSERT(i40e->i40e_intr_poll == B_TRUE);
	i40e_intr_rx_queue_enable(i40e, itrq->itrq_index);
	i40e->i40e_intr_poll = B_FALSE;
	mutex_exit(&i40e->i40e_general_lock);

	return (0);
}

/* ARGSUSED */
static int
i40e_rx_ring_intr_disable(mac_intr_handle_t intrh)
{
	i40e_trqpair_t *itrq = (i40e_trqpair_t *)intrh;
	i40e_t *i40e = itrq->itrq_i40e;

	mutex_enter(&i40e->i40e_general_lock);
	i40e_intr_rx_queue_disable(i40e, itrq->itrq_index);
	i40e->i40e_intr_poll = B_TRUE;
	mutex_exit(&i40e->i40e_general_lock);

	return (0);
}

/* ARGSUSED */
static void
i40e_fill_tx_ring(void *arg, mac_ring_type_t rtype, const int group_index,
    const int ring_index, mac_ring_info_t *infop, mac_ring_handle_t rh)
{
	i40e_t *i40e = arg;
	mac_intr_t *mintr = &infop->mri_intr;
	i40e_trqpair_t *itrq = &(i40e->i40e_trqpairs[ring_index]);

	/*
	 * Note the group index here is expected to be -1 due to the fact that
	 * we're not actually grouping things tx-wise at this time.
	 */
	ASSERT(group_index == -1);
	ASSERT(ring_index < i40e->i40e_num_trqpairs);

	itrq->itrq_mactxring = rh;
	infop->mri_driver = (mac_ring_driver_t)itrq;
	infop->mri_start = NULL;
	infop->mri_stop = NULL;
	infop->mri_tx = i40e_ring_tx;
	infop->mri_stat = i40e_tx_ring_stat;

	/*
	 * We only provide the handle in cases where we have MSI-X interrupts,
	 * to indicate that we'd actually support retargetting.
	 */
	if (i40e->i40e_intr_type & DDI_INTR_TYPE_MSIX) {
		mintr->mi_ddi_handle =
		    i40e->i40e_intr_handles[itrq->itrq_tx_intrvec];
	}
}

/* ARGSUSED */
static void
i40e_fill_rx_ring(void *arg, mac_ring_type_t rtype, const int group_index,
    const int ring_index, mac_ring_info_t *infop, mac_ring_handle_t rh)
{
	i40e_t *i40e = arg;
	mac_intr_t *mintr = &infop->mri_intr;
	i40e_trqpair_t *itrq = &i40e->i40e_trqpairs[ring_index];

	/*
	 * We assert the group number and ring index to help sanity check
	 * ourselves and mark that we'll need to rework this when we have
	 * multiple groups.
	 */
	ASSERT3S(group_index, ==, 0);
	ASSERT3S(ring_index, <, i40e->i40e_num_trqpairs);

	itrq->itrq_macrxring = rh;
	infop->mri_driver = (mac_ring_driver_t)itrq;
	infop->mri_start = i40e_ring_start;
	infop->mri_stop = NULL;
	infop->mri_poll = i40e_ring_rx_poll;
	infop->mri_stat = i40e_rx_ring_stat;
	mintr->mi_handle = (mac_intr_handle_t)itrq;
	mintr->mi_enable = i40e_rx_ring_intr_enable;
	mintr->mi_disable = i40e_rx_ring_intr_disable;

	/*
	 * We only provide the handle in cases where we have MSI-X interrupts,
	 * to indicate that we'd actually support retargetting.
	 */
	if (i40e->i40e_intr_type & DDI_INTR_TYPE_MSIX) {
		mintr->mi_ddi_handle =
		    i40e->i40e_intr_handles[itrq->itrq_rx_intrvec];
	}
}

/* ARGSUSED */
static void
i40e_fill_rx_group(void *arg, mac_ring_type_t rtype, const int index,
    mac_group_info_t *infop, mac_group_handle_t gh)
{
	i40e_t *i40e = arg;

	if (rtype != MAC_RING_TYPE_RX)
		return;

	/*
	 * Note, this is a simplified view of a group, given that we only have a
	 * single group and a single ring at the moment. We'll want to expand
	 * upon this as we leverage more hardware functionality.
	 */
	i40e->i40e_rx_group_handle = gh;
	infop->mgi_driver = (mac_group_driver_t)i40e;
	infop->mgi_start = NULL;
	infop->mgi_stop = NULL;
	infop->mgi_addmac = i40e_group_add_mac;
	infop->mgi_remmac = i40e_group_remove_mac;

	ASSERT(i40e->i40e_num_rx_groups == I40E_GROUP_MAX);
	infop->mgi_count = i40e->i40e_num_trqpairs;
}

static boolean_t
i40e_m_getcapab(void *arg, mac_capab_t cap, void *cap_data)
{
	i40e_t *i40e = arg;
	mac_capab_rings_t *cap_rings;

	switch (cap) {
	case MAC_CAPAB_HCKSUM: {
		uint32_t *txflags = cap_data;

		*txflags = 0;
		if (i40e->i40e_tx_hcksum_enable == B_TRUE)
			*txflags = HCKSUM_INET_PARTIAL | HCKSUM_IPHDRCKSUM;
		break;
	}

	case MAC_CAPAB_RINGS:
		cap_rings = cap_data;
		cap_rings->mr_group_type = MAC_GROUP_TYPE_STATIC;
		switch (cap_rings->mr_type) {
		case MAC_RING_TYPE_TX:
			/*
			 * Note, saying we have no rings, but some number of
			 * groups indicates to MAC that it should create
			 * psuedo-groups with one for each TX ring. This may not
			 * be the long term behavior we want, but it'll work for
			 * now.
			 */
			cap_rings->mr_gnum = 0;
			cap_rings->mr_rnum = i40e->i40e_num_trqpairs;
			cap_rings->mr_rget = i40e_fill_tx_ring;
			cap_rings->mr_gget = NULL;
			cap_rings->mr_gaddring = NULL;
			cap_rings->mr_gremring = NULL;
			break;
		case MAC_RING_TYPE_RX:
			cap_rings->mr_rnum = i40e->i40e_num_trqpairs;
			cap_rings->mr_rget = i40e_fill_rx_ring;
			cap_rings->mr_gnum = I40E_GROUP_MAX;
			cap_rings->mr_gget = i40e_fill_rx_group;
			cap_rings->mr_gaddring = NULL;
			cap_rings->mr_gremring = NULL;
			break;
		default:
			return (B_FALSE);
		}
		break;
	default:
		return (B_FALSE);
	}

	return (B_TRUE);
}

/* ARGSUSED */
static int
i40e_m_setprop_private(i40e_t *i40e, const char *pr_name, uint_t pr_valsize,
    const void *pr_val)
{
	int ret;
	long val;
	char *eptr;

	ASSERT(MUTEX_HELD(&i40e->i40e_general_lock));

	if ((ret = ddi_strtol(pr_val, &eptr, 10, &val)) != 0 ||
	    *eptr != '\0') {
		return (ret);
	}

	if (strcmp(pr_name, I40E_PROP_RX_DMA_THRESH) == 0) {
		if (val < I40E_MIN_RX_DMA_THRESH ||
		    val > I40E_MAX_RX_DMA_THRESH) {
			return (EINVAL);
		}
		i40e->i40e_rx_dma_min = (uint32_t)val;
		return (0);
	}

	if (strcmp(pr_name, I40E_PROP_TX_DMA_THRESH) == 0) {
		if (val < I40E_MIN_TX_DMA_THRESH ||
		    val > I40E_MAX_TX_DMA_THRESH) {
			return (EINVAL);
		}
		i40e->i40e_tx_dma_min = (uint32_t)val;
		return (0);
	}

	if (strcmp(pr_name, I40E_PROP_RX_ITR) == 0) {
		if (val < I40E_MIN_ITR ||
		    val > I40E_MAX_ITR) {
			return (EINVAL);
		}
		i40e->i40e_rx_itr = (uint32_t)val;
		i40e_intr_set_itr(i40e, I40E_ITR_INDEX_RX, i40e->i40e_rx_itr);
		return (0);
	}

	if (strcmp(pr_name, I40E_PROP_TX_ITR) == 0) {
		if (val < I40E_MIN_ITR ||
		    val > I40E_MAX_ITR) {
			return (EINVAL);
		}
		i40e->i40e_tx_itr = (uint32_t)val;
		i40e_intr_set_itr(i40e, I40E_ITR_INDEX_TX, i40e->i40e_tx_itr);
		return (0);
	}

	if (strcmp(pr_name, I40E_PROP_OTHER_ITR) == 0) {
		if (val < I40E_MIN_ITR ||
		    val > I40E_MAX_ITR) {
			return (EINVAL);
		}
		i40e->i40e_tx_itr = (uint32_t)val;
		i40e_intr_set_itr(i40e, I40E_ITR_INDEX_OTHER,
		    i40e->i40e_other_itr);
		return (0);
	}

	return (ENOTSUP);
}

static int
i40e_m_getprop_private(i40e_t *i40e, const char *pr_name, uint_t pr_valsize,
    void *pr_val)
{
	uint32_t val;

	ASSERT(MUTEX_HELD(&i40e->i40e_general_lock));

	if (strcmp(pr_name, I40E_PROP_RX_DMA_THRESH) == 0) {
		val = i40e->i40e_rx_dma_min;
	} else if (strcmp(pr_name, I40E_PROP_TX_DMA_THRESH) == 0) {
		val = i40e->i40e_tx_dma_min;
	} else if (strcmp(pr_name, I40E_PROP_RX_ITR) == 0) {
		val = i40e->i40e_rx_itr;
	} else if (strcmp(pr_name, I40E_PROP_TX_ITR) == 0) {
		val = i40e->i40e_tx_itr;
	} else if (strcmp(pr_name, I40E_PROP_OTHER_ITR) == 0) {
		val = i40e->i40e_other_itr;
	} else {
		return (ENOTSUP);
	}

	if (snprintf(pr_val, pr_valsize, "%d", val) >= pr_valsize)
		return (ERANGE);
	return (0);
}

/*
 * Annoyingly for private properties MAC seems to ignore default values that
 * aren't strings. That means that we have to translate all of these into
 * uint32_t's and instead we size the buffer to be large enough to hold a
 * uint32_t.
 */
/* ARGSUSED */
static void
i40e_m_propinfo_private(i40e_t *i40e, const char *pr_name,
    mac_prop_info_handle_t prh)
{
	char buf[64];
	uint32_t def;

	if (strcmp(pr_name, I40E_PROP_RX_DMA_THRESH) == 0) {
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_RW);
		def = I40E_DEF_RX_DMA_THRESH;
		mac_prop_info_set_range_uint32(prh,
		    I40E_MIN_RX_DMA_THRESH,
		    I40E_MAX_RX_DMA_THRESH);
	} else if (strcmp(pr_name, I40E_PROP_TX_DMA_THRESH) == 0) {
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_RW);
		def = I40E_DEF_TX_DMA_THRESH;
		mac_prop_info_set_range_uint32(prh,
		    I40E_MIN_TX_DMA_THRESH,
		    I40E_MAX_TX_DMA_THRESH);
	} else if (strcmp(pr_name, I40E_PROP_RX_ITR) == 0) {
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_RW);
		def = I40E_DEF_RX_ITR;
		mac_prop_info_set_range_uint32(prh, I40E_MIN_ITR, I40E_MAX_ITR);
	} else if (strcmp(pr_name, I40E_PROP_TX_ITR) == 0) {
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_RW);
		def = I40E_DEF_TX_ITR;
		mac_prop_info_set_range_uint32(prh, I40E_MIN_ITR, I40E_MAX_ITR);
	} else if (strcmp(pr_name, I40E_PROP_OTHER_ITR) == 0) {
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_RW);
		def = I40E_DEF_OTHER_ITR;
		mac_prop_info_set_range_uint32(prh, I40E_MIN_ITR, I40E_MAX_ITR);
	} else {
		return;
	}

	(void) snprintf(buf, sizeof (buf), "%d", def);
	mac_prop_info_set_default_str(prh, buf);
}

static int
i40e_m_setprop(void *arg, const char *pr_name, mac_prop_id_t pr_num,
    uint_t pr_valsize, const void *pr_val)
{
	uint32_t new_mtu;
	i40e_t *i40e = arg;
	int ret = 0;

	mutex_enter(&i40e->i40e_general_lock);
	if (i40e->i40e_state & I40E_SUSPENDED) {
		mutex_exit(&i40e->i40e_general_lock);
		return (ECANCELED);
	}

	switch (pr_num) {
	/*
	 * These properties are always read-only across every device.
	 */
	case MAC_PROP_DUPLEX:
	case MAC_PROP_SPEED:
	case MAC_PROP_STATUS:
	case MAC_PROP_ADV_100FDX_CAP:
	case MAC_PROP_ADV_1000FDX_CAP:
	case MAC_PROP_ADV_10GFDX_CAP:
	case MAC_PROP_ADV_40GFDX_CAP:
		ret = ENOTSUP;
		break;
	/*
	 * These are read-only at this time as we don't support configuring
	 * auto-negotiation. See the theory statement in i40e_main.c.
	 */
	case MAC_PROP_EN_100FDX_CAP:
	case MAC_PROP_EN_1000FDX_CAP:
	case MAC_PROP_EN_10GFDX_CAP:
	case MAC_PROP_EN_40GFDX_CAP:
	case MAC_PROP_AUTONEG:
	case MAC_PROP_FLOWCTRL:
		ret = ENOTSUP;
		break;

	case MAC_PROP_MTU:
		bcopy(pr_val, &new_mtu, sizeof (new_mtu));
		if (new_mtu == i40e->i40e_sdu)
			break;

		if (new_mtu < I40E_MIN_MTU ||
		    new_mtu > I40E_MAX_MTU) {
			ret = EINVAL;
			break;
		}

		if (i40e->i40e_state & I40E_STARTED) {
			ret = EBUSY;
			break;
		}

		ret = mac_maxsdu_update(i40e->i40e_mac_hdl, new_mtu);
		if (ret == 0) {
			i40e->i40e_sdu = new_mtu;
			i40e_update_mtu(i40e);
		}
		break;

	case MAC_PROP_PRIVATE:
		ret = i40e_m_setprop_private(i40e, pr_name, pr_valsize, pr_val);
		break;
	default:
		ret = ENOTSUP;
		break;
	}

	mutex_exit(&i40e->i40e_general_lock);
	return (ret);
}

static int
i40e_m_getprop(void *arg, const char *pr_name, mac_prop_id_t pr_num,
    uint_t pr_valsize, void *pr_val)
{
	i40e_t *i40e = arg;
	uint64_t speed;
	int ret = 0;
	uint8_t *u8;
	link_flowctrl_t fctl;

	mutex_enter(&i40e->i40e_general_lock);

	switch (pr_num) {
	case MAC_PROP_DUPLEX:
		if (pr_valsize < sizeof (link_duplex_t)) {
			ret = EOVERFLOW;
			break;
		}
		bcopy(&i40e->i40e_link_duplex, pr_val, sizeof (link_duplex_t));
		break;
	case MAC_PROP_SPEED:
		if (pr_valsize < sizeof (uint64_t)) {
			ret = EOVERFLOW;
			break;
		}
		speed = i40e->i40e_link_speed * 1000000ULL;
		bcopy(&speed, pr_val, sizeof (speed));
		break;
	case MAC_PROP_STATUS:
		if (pr_valsize < sizeof (link_state_t)) {
			ret = EOVERFLOW;
			break;
		}
		bcopy(&i40e->i40e_link_state, pr_val, sizeof (link_state_t));
		break;
	case MAC_PROP_AUTONEG:
		if (pr_valsize < sizeof (uint8_t)) {
			ret = EOVERFLOW;
			break;
		}
		u8 = pr_val;
		*u8 = 1;
		break;
	case MAC_PROP_FLOWCTRL:
		/*
		 * Because we don't currently support hardware flow control, we
		 * just hardcode this to be none.
		 */
		if (pr_valsize < sizeof (link_flowctrl_t)) {
			ret = EOVERFLOW;
			break;
		}
		fctl = LINK_FLOWCTRL_NONE;
		bcopy(&fctl, pr_val, sizeof (link_flowctrl_t));
		break;
	case MAC_PROP_MTU:
		if (pr_valsize < sizeof (uint32_t)) {
			ret = EOVERFLOW;
			break;
		}
		bcopy(&i40e->i40e_sdu, pr_val, sizeof (uint32_t));
		break;

	/*
	 * Because we don't let users control the speeds we may auto-negotiate
	 * to, the values of the ADV_ and EN_ will always be the same.
	 */
	case MAC_PROP_ADV_100FDX_CAP:
	case MAC_PROP_EN_100FDX_CAP:
		if (pr_valsize < sizeof (uint8_t)) {
			ret = EOVERFLOW;
			break;
		}
		u8 = pr_val;
		*u8 = (i40e->i40e_phy.link_speed & I40E_LINK_SPEED_100MB) != 0;
		break;
	case MAC_PROP_ADV_1000FDX_CAP:
	case MAC_PROP_EN_1000FDX_CAP:
		if (pr_valsize < sizeof (uint8_t)) {
			ret = EOVERFLOW;
			break;
		}
		u8 = pr_val;
		*u8 = (i40e->i40e_phy.link_speed & I40E_LINK_SPEED_1GB) != 0;
		break;
	case MAC_PROP_ADV_10GFDX_CAP:
	case MAC_PROP_EN_10GFDX_CAP:
		if (pr_valsize < sizeof (uint8_t)) {
			ret = EOVERFLOW;
			break;
		}
		u8 = pr_val;
		*u8 = (i40e->i40e_phy.link_speed & I40E_LINK_SPEED_10GB) != 0;
		break;
	case MAC_PROP_ADV_40GFDX_CAP:
	case MAC_PROP_EN_40GFDX_CAP:
		if (pr_valsize < sizeof (uint8_t)) {
			ret = EOVERFLOW;
			break;
		}
		u8 = pr_val;
		*u8 = (i40e->i40e_phy.link_speed & I40E_LINK_SPEED_40GB) != 0;
		break;
	case MAC_PROP_PRIVATE:
		ret = i40e_m_getprop_private(i40e, pr_name, pr_valsize, pr_val);
		break;
	default:
		ret = ENOTSUP;
		break;
	}

	mutex_exit(&i40e->i40e_general_lock);

	return (ret);
}

static void
i40e_m_propinfo(void *arg, const char *pr_name, mac_prop_id_t pr_num,
    mac_prop_info_handle_t prh)
{
	i40e_t *i40e = arg;

	mutex_enter(&i40e->i40e_general_lock);

	switch (pr_num) {
	case MAC_PROP_DUPLEX:
	case MAC_PROP_SPEED:
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		break;
	case MAC_PROP_FLOWCTRL:
		/*
		 * At the moment, the driver doesn't support flow control, hence
		 * why this is set to read-only and none.
		 */
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		mac_prop_info_set_default_link_flowctrl(prh,
		    LINK_FLOWCTRL_NONE);
		break;
	case MAC_PROP_MTU:
		mac_prop_info_set_range_uint32(prh, I40E_MIN_MTU, I40E_MAX_MTU);
		break;

	/*
	 * We set the defaults for these based upon the phy's ability to
	 * support the speeds. Note, auto-negotiation is required for fiber,
	 * hence it is read-only and always enabled. When we have access to
	 * copper phys we can revisit this.
	 */
	case MAC_PROP_AUTONEG:
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		mac_prop_info_set_default_uint8(prh, 1);
		break;
	case MAC_PROP_ADV_100FDX_CAP:
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		mac_prop_info_set_default_uint8(prh,
		    (i40e->i40e_phy.link_speed & I40E_LINK_SPEED_100MB) != 0);
		break;
	case MAC_PROP_EN_100FDX_CAP:
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		mac_prop_info_set_default_uint8(prh,
		    (i40e->i40e_phy.link_speed & I40E_LINK_SPEED_100MB) != 0);
		break;
	case MAC_PROP_ADV_1000FDX_CAP:
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		mac_prop_info_set_default_uint8(prh,
		    (i40e->i40e_phy.link_speed & I40E_LINK_SPEED_1GB) != 0);
		break;
	case MAC_PROP_EN_1000FDX_CAP:
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		mac_prop_info_set_default_uint8(prh,
		    (i40e->i40e_phy.link_speed & I40E_LINK_SPEED_1GB) != 0);
		break;
	case MAC_PROP_ADV_10GFDX_CAP:
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		mac_prop_info_set_default_uint8(prh,
		    (i40e->i40e_phy.link_speed & I40E_LINK_SPEED_10GB) != 0);
		break;
	case MAC_PROP_EN_10GFDX_CAP:
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		mac_prop_info_set_default_uint8(prh,
		    (i40e->i40e_phy.link_speed & I40E_LINK_SPEED_10GB) != 0);
		break;
	case MAC_PROP_ADV_40GFDX_CAP:
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		mac_prop_info_set_default_uint8(prh,
		    (i40e->i40e_phy.link_speed & I40E_LINK_SPEED_40GB) != 0);
		break;
	case MAC_PROP_EN_40GFDX_CAP:
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		mac_prop_info_set_default_uint8(prh,
		    (i40e->i40e_phy.link_speed & I40E_LINK_SPEED_40GB) != 0);
		break;
	case MAC_PROP_PRIVATE:
		i40e_m_propinfo_private(i40e, pr_name, prh);
		break;
	default:
		break;
	}

	mutex_exit(&i40e->i40e_general_lock);
}

#define	I40E_M_CALLBACK_FLAGS \
	(MC_IOCTL | MC_GETCAPAB | MC_SETPROP | MC_GETPROP | MC_PROPINFO)

static mac_callbacks_t i40e_m_callbacks = {
	I40E_M_CALLBACK_FLAGS,
	i40e_m_stat,
	i40e_m_start,
	i40e_m_stop,
	i40e_m_promisc,
	i40e_m_multicast,
	NULL,
	NULL,
	NULL,
	i40e_m_ioctl,
	i40e_m_getcapab,
	NULL,
	NULL,
	i40e_m_setprop,
	i40e_m_getprop,
	i40e_m_propinfo
};

boolean_t
i40e_register_mac(i40e_t *i40e)
{
	struct i40e_hw *hw = &i40e->i40e_hw_space;
	int status;
	mac_register_t *mac = mac_alloc(MAC_VERSION);

	if (mac == NULL)
		return (B_FALSE);

	mac->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	mac->m_driver = i40e;
	mac->m_dip = i40e->i40e_dip;
	mac->m_src_addr = hw->mac.addr;
	mac->m_callbacks = &i40e_m_callbacks;
	mac->m_min_sdu = 0;
	mac->m_max_sdu = i40e->i40e_sdu;
	mac->m_margin = VLAN_TAGSZ;
	mac->m_priv_props = i40e_priv_props;
	mac->m_v12n = MAC_VIRT_LEVEL1;

	status = mac_register(mac, &i40e->i40e_mac_hdl);
	if (status != 0)
		i40e_error(i40e, "mac_register() returned %d", status);
	mac_free(mac);

	return (status == 0);
}
