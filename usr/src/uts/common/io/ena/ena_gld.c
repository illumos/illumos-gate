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
 * Copyright 2024 Oxide Computer Company
 */

#include "ena.h"

/*
 * Group/Ring callbacks
 */

/*
 * The ena driver supports only a single mac address: the one assigned
 * to it by the hypervisor. If mac requests an address besides this
 * one, then return ENOTSUP. This will prevent VNICs from being
 * created, as it should.
 */
static int
ena_group_add_mac(void *arg, const uint8_t *mac_addr)
{
	ena_t *ena = arg;

	if (ETHER_IS_MULTICAST(mac_addr)) {
		return (EINVAL);
	}

	if (bcmp(ena->ena_mac_addr, mac_addr, ETHERADDRL) == 0) {
		return (0);
	}

	return (ENOTSUP);
}

static int
ena_group_rem_mac(void *arg, const uint8_t *mac_addr)
{
	ena_t *ena = arg;

	if (ETHER_IS_MULTICAST(mac_addr)) {
		return (EINVAL);
	}

	if (bcmp(ena->ena_mac_addr, mac_addr, ETHERADDRL) == 0) {
		return (0);
	}

	return (ENOTSUP);
}

static int
ena_ring_rx_intr_disable(mac_intr_handle_t mih)
{
	ena_rxq_t *rxq = (ena_rxq_t *)mih;
	uint32_t intr_ctrl;

	mutex_enter(&rxq->er_lock);
	intr_ctrl = ena_hw_abs_read32(rxq->er_ena, rxq->er_cq_unmask_addr);
	ENAHW_REG_INTR_MASK(intr_ctrl);
	ena_hw_abs_write32(rxq->er_ena, rxq->er_cq_unmask_addr, intr_ctrl);
	rxq->er_mode = ENA_RXQ_MODE_POLLING;
	mutex_exit(&rxq->er_lock);
	return (0);
}

static int
ena_ring_rx_intr_enable(mac_intr_handle_t mih)
{
	ena_rxq_t *rxq = (ena_rxq_t *)mih;
	uint32_t intr_ctrl;

	mutex_enter(&rxq->er_lock);
	intr_ctrl = ena_hw_abs_read32(rxq->er_ena, rxq->er_cq_unmask_addr);
	ENAHW_REG_INTR_UNMASK(intr_ctrl);
	ena_hw_abs_write32(rxq->er_ena, rxq->er_cq_unmask_addr, intr_ctrl);
	rxq->er_mode = ENA_RXQ_MODE_INTR;
	mutex_exit(&rxq->er_lock);
	return (0);
}

static void
ena_fill_rx_group(void *arg, mac_ring_type_t rtype, const int index,
    mac_group_info_t *infop, mac_group_handle_t gh)
{
	ena_t *ena = arg;

	VERIFY3S(rtype, ==, MAC_RING_TYPE_RX);
	/*
	 * Typically you pass an Rx group data structure as
	 * mgi_driver, but given we should only ever have one group we
	 * just pass the top-level ena_t.
	 */
	infop->mgi_driver = (mac_group_driver_t)ena;
	infop->mgi_start = NULL;
	infop->mgi_stop = NULL;
	infop->mgi_addmac = ena_group_add_mac;
	infop->mgi_remmac = ena_group_rem_mac;
	infop->mgi_count = ena->ena_num_intrs - 1;
}

static void
ena_fill_tx_ring(void *arg, mac_ring_type_t rtype, const int group_index,
    const int ring_index, mac_ring_info_t *infop, mac_ring_handle_t rh)
{
	ena_t *ena = arg;
	ena_txq_t *txq = &ena->ena_txqs[ring_index];

	VERIFY3S(rtype, ==, MAC_RING_TYPE_TX);
	VERIFY3S(ring_index, <, ena->ena_num_txqs);
	/* Link driver Tx queue to mac ring handle and vice versa. */
	txq->et_mrh = rh;
	infop->mri_driver = (mac_ring_driver_t)txq;
	infop->mri_start = ena_ring_tx_start;
	infop->mri_stop = ena_ring_tx_stop;
	infop->mri_tx = ena_ring_tx;
	infop->mri_stat = ena_ring_tx_stat;
}

static void
ena_fill_rx_ring(void *arg, mac_ring_type_t rtype, const int group_index,
    const int ring_index, mac_ring_info_t *infop, mac_ring_handle_t rh)
{
	ena_t *ena = arg;
	ena_rxq_t *rxq = &ena->ena_rxqs[ring_index];

	VERIFY3S(rtype, ==, MAC_RING_TYPE_RX);
	VERIFY3S(ring_index, <, ena->ena_num_rxqs);
	rxq->er_mrh = rh;
	infop->mri_driver = (mac_ring_driver_t)rxq;
	infop->mri_start = ena_ring_rx_start;
	infop->mri_stop = ena_ring_rx_stop;
	infop->mri_poll = ena_ring_rx_poll;
	infop->mri_stat = ena_ring_rx_stat;
	infop->mri_intr.mi_handle = (mac_intr_handle_t)rxq;
	infop->mri_intr.mi_enable = ena_ring_rx_intr_enable;
	infop->mri_intr.mi_disable = ena_ring_rx_intr_disable;
	infop->mri_intr.mi_ddi_handle =
	    ena->ena_intr_handles[rxq->er_intr_vector];
}

static int
ena_m_start(void *arg)
{
	ena_t *ena = arg;

	atomic_or_32(&ena->ena_state, ENA_STATE_STARTED);
	ena_enable_watchdog(ena);

	return (0);
}

static void
ena_m_stop(void *arg)
{
	ena_t *ena = arg;

	ena_disable_watchdog(ena);
	atomic_and_32(&ena->ena_state, ~ENA_STATE_STARTED);
}

/*
 * As discussed in ena_group_add_mac(), ENA only supports a single MAC
 * address, and therefore we prevent VNICs from being created. That
 * means there is no chance for promisc to be used as a means for
 * implementing VNIC support on ENA, as we never allow them to be
 * created in the first place.
 *
 * As for promisc itself, returning success is about the best we can
 * do. There is no promisc API for an ENA device -- you get only the
 * exact traffic AWS wants you to see.
 */
static int
ena_m_setpromisc(void *arg, boolean_t on)
{
	return (0);
}

/*
 * Similarly to promisc, there is no multicast API for an ENA
 * device.
 */
static int
ena_m_multicast(void *arg, boolean_t add, const uint8_t *multicast_address)
{
	return (0);
}

static boolean_t
ena_m_getcapab(void *arg, mac_capab_t capab, void *cap_data)
{
	ena_t *ena = arg;
	mac_capab_rings_t *cap_rings;

	switch (capab) {
	case MAC_CAPAB_RINGS:
		cap_rings = cap_data;
		cap_rings->mr_group_type = MAC_GROUP_TYPE_STATIC;
		cap_rings->mr_gaddring = NULL;
		cap_rings->mr_gremring = NULL;
		ASSERT3U(ena->ena_num_intrs, >=, 2);

		switch (cap_rings->mr_type) {
		case MAC_RING_TYPE_TX:
			/*
			 * We use pseudo Tx groups for now.
			 */
			cap_rings->mr_gnum = 0;
			cap_rings->mr_rnum = ena->ena_num_intrs - 1;
			cap_rings->mr_rget = ena_fill_tx_ring;
			break;
		case MAC_RING_TYPE_RX:
			cap_rings->mr_rnum = ena->ena_num_intrs - 1;
			cap_rings->mr_rget = ena_fill_rx_ring;
			/*
			 * The ENA device provides no means to add mac
			 * filters or set promisc mode; it's only
			 * meant to receive its pre-designated unicast
			 * address. However, we still want rings as
			 * the device does provide multiple queues and
			 * RSS.
			 */
			cap_rings->mr_gnum = 1;
			cap_rings->mr_gget = ena_fill_rx_group;
			break;
		}

		break;

	case MAC_CAPAB_HCKSUM:
	case MAC_CAPAB_LSO:
		return (B_FALSE);
	default:
		return (B_FALSE);
	}

	return (B_TRUE);
}

static int
ena_m_setprop(void *arg, const char *pr_name, mac_prop_id_t pr_num,
    uint_t pr_valsize, const void *pr_val)
{
	return (ENOTSUP);
}

static int
ena_m_getprop(void *arg, const char *pr_name, mac_prop_id_t pr_num,
    uint_t pr_valsize, void *pr_val)
{
	ena_t *ena = arg;
	int ret = 0;
	uint64_t speed;
	uint8_t *u8;

	mutex_enter(&ena->ena_lock);

	switch (pr_num) {
	case MAC_PROP_DUPLEX:
		if (pr_valsize < sizeof (link_duplex_t)) {
			ret = EOVERFLOW;
			break;
		}

		bcopy(&ena->ena_link_duplex, pr_val, sizeof (link_duplex_t));
		break;

	case MAC_PROP_SPEED:
		if (pr_valsize < sizeof (uint64_t)) {
			ret = EOVERFLOW;
			break;
		}

		speed = ena->ena_link_speed_mbits * 1000000ULL;
		bcopy(&speed, pr_val, sizeof (speed));
		break;

	case MAC_PROP_STATUS:
		if (pr_valsize < sizeof (link_state_t)) {
			ret = EOVERFLOW;
			break;
		}

		bcopy(&ena->ena_link_state, pr_val, sizeof (link_state_t));
		break;

	case MAC_PROP_AUTONEG:
		if (pr_valsize < sizeof (uint8_t)) {
			ret = EOVERFLOW;
			break;
		}

		u8 = pr_val;
		*u8 = (ena->ena_link_autoneg ? 0 : 1);
		break;

	case MAC_PROP_MTU:
		if (pr_valsize < sizeof (uint32_t)) {
			ret = EOVERFLOW;
			break;
		}

		bcopy(&ena->ena_mtu, pr_val, sizeof (uint32_t));
		break;

	case MAC_PROP_ADV_1000FDX_CAP:
	case MAC_PROP_EN_1000FDX_CAP:
		if (pr_valsize < sizeof (uint8_t)) {
			ret = EOVERFLOW;
			break;
		}

		u8 = pr_val;
		*u8 = (ena->ena_link_speeds & ENAHW_LINK_SPEED_1G) != 0;
		break;

	case MAC_PROP_ADV_2500FDX_CAP:
	case MAC_PROP_EN_2500FDX_CAP:
		if (pr_valsize < sizeof (uint8_t)) {
			ret = EOVERFLOW;
			break;
		}

		u8 = pr_val;
		*u8 = (ena->ena_link_speeds & ENAHW_LINK_SPEED_2_HALF_G) != 0;
		break;

	case MAC_PROP_ADV_5000FDX_CAP:
	case MAC_PROP_EN_5000FDX_CAP:
		if (pr_valsize < sizeof (uint8_t)) {
			ret = EOVERFLOW;
			break;
		}

		u8 = pr_val;
		*u8 = (ena->ena_link_speeds & ENAHW_LINK_SPEED_5G) != 0;
		break;

	case MAC_PROP_ADV_10GFDX_CAP:
	case MAC_PROP_EN_10GFDX_CAP:
		if (pr_valsize < sizeof (uint8_t)) {
			ret = EOVERFLOW;
			break;
		}

		u8 = pr_val;
		*u8 = (ena->ena_link_speeds & ENAHW_LINK_SPEED_10G) != 0;
		break;

	case MAC_PROP_ADV_25GFDX_CAP:
	case MAC_PROP_EN_25GFDX_CAP:
		if (pr_valsize < sizeof (uint8_t)) {
			ret = EOVERFLOW;
			break;
		}

		u8 = pr_val;
		*u8 = (ena->ena_link_speeds & ENAHW_LINK_SPEED_25G) != 0;
		break;

	case MAC_PROP_ADV_40GFDX_CAP:
	case MAC_PROP_EN_40GFDX_CAP:
		if (pr_valsize < sizeof (uint8_t)) {
			ret = EOVERFLOW;
			break;
		}

		u8 = pr_val;
		*u8 = (ena->ena_link_speeds & ENAHW_LINK_SPEED_40G) != 0;
		break;

	case MAC_PROP_ADV_100GFDX_CAP:
	case MAC_PROP_EN_100GFDX_CAP:
		if (pr_valsize < sizeof (uint8_t)) {
			ret = EOVERFLOW;
			break;
		}

		u8 = pr_val;
		*u8 = (ena->ena_link_speeds & ENAHW_LINK_SPEED_100G) != 0;
		break;

	default:
		ret = ENOTSUP;
		break;
	}

	mutex_exit(&ena->ena_lock);
	return (ret);
}

static void
ena_m_propinfo(void *arg, const char *pr_name, mac_prop_id_t pr_num,
    mac_prop_info_handle_t prh)
{
}

static mac_callbacks_t ena_m_callbacks = {
	.mc_callbacks = MC_GETCAPAB | MC_SETPROP | MC_GETPROP | MC_PROPINFO,
	.mc_getstat = ena_m_stat,
	.mc_start = ena_m_start,
	.mc_stop = ena_m_stop,
	.mc_setpromisc = ena_m_setpromisc,
	.mc_multicst = ena_m_multicast,
	.mc_getcapab = ena_m_getcapab,
	.mc_setprop = ena_m_setprop,
	.mc_getprop = ena_m_getprop,
	.mc_propinfo = ena_m_propinfo,
};

int
ena_mac_unregister(ena_t *ena)
{
	if (ena->ena_mh == NULL) {
		return (0);
	}

	return (mac_unregister(ena->ena_mh));
}

bool
ena_mac_register(ena_t *ena)
{
	int ret;
	mac_register_t *regp;

	if ((regp = mac_alloc(MAC_VERSION)) == NULL) {
		ena_err(ena, "failed to allocate MAC handle");
		return (false);
	}

	regp->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	regp->m_driver = ena;
	regp->m_dip = ena->ena_dip;
	regp->m_instance = 0;
	regp->m_src_addr = ena->ena_mac_addr;
	regp->m_dst_addr = NULL;
	regp->m_callbacks = &ena_m_callbacks;
	regp->m_min_sdu = 0;
	regp->m_max_sdu = ena->ena_mtu;
	regp->m_pdata = NULL;
	regp->m_pdata_size = 0;
	regp->m_priv_props = NULL;
	regp->m_margin = VLAN_TAGSZ;
	regp->m_v12n = MAC_VIRT_LEVEL1;

	if ((ret = mac_register(regp, &ena->ena_mh)) != 0) {
		ena_err(ena, "failed to register ena with mac: %d", ret);
	}

	mac_free(regp);

	if (ret == 0) {
		/*
		 * Until we get the first AENQ link change event, we
		 * do not actually know the status of the link.
		 */
		mac_link_update(ena->ena_mh, LINK_STATE_UNKNOWN);
	}

	return (ret == 0);
}
