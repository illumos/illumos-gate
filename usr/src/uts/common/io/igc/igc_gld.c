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

/*
 * Intel I225/226 Ethernet Driver. This is the same MAC that is found in the
 * e1000 and igb drivers, but Intel decided it would be a different driver and
 * so here we are.
 */

#include <sys/sysmacros.h>

#include "igc.h"

typedef struct {
	enum igc_media_type imm_phy;
	uint16_t imm_speed;
	mac_ether_media_t imm_media;
} igc_media_map_t;

static const igc_media_map_t igc_media_map[] = {
	{ igc_media_type_copper, SPEED_10, ETHER_MEDIA_10BASE_T },
	{ igc_media_type_copper, SPEED_100, ETHER_MEDIA_100BASE_TX },
	{ igc_media_type_copper, SPEED_1000, ETHER_MEDIA_1000BASE_T },
	{ igc_media_type_copper, SPEED_2500, ETHER_MEDIA_2500BASE_T },
};

static mac_ether_media_t
igc_link_to_media(igc_t *igc)
{
	switch (igc->igc_link_state) {
	case LINK_STATE_UP:
		break;
	case LINK_STATE_DOWN:
		return (ETHER_MEDIA_NONE);
	default:
		return (ETHER_MEDIA_UNKNOWN);
	}

	for (size_t i = 0; i < ARRAY_SIZE(igc_media_map); i++) {
		const igc_media_map_t *map = &igc_media_map[i];
		if (igc->igc_hw.phy.media_type == map->imm_phy &&
		    igc->igc_link_speed == map->imm_speed) {
			return (map->imm_media);
		}
	}

	return (ETHER_MEDIA_UNKNOWN);
}

/*
 * The following stats are skipped because there is no good way to get it from
 * hardware or we don't know how to perform such a mapping:
 *
 *  - MAC_STAT_UNKNOWNS
 *  - MAC_STAT_UNDERFLOWS
 *  - MAC_STAT_OVERFLOWS
 *  - ETHER_STAT_SQE_ERRORS
 *  - ETHER_STAT_MACRCV_ERRORS
 */
static int
igc_m_getstat(void *drv, uint_t stat, uint64_t *valp)
{
	igc_t *igc = drv;
	igc_stats_t *stats = &igc->igc_stats;
	int ret = 0;
	uint32_t an_adv;

	mutex_enter(&igc->igc_lock);
	an_adv = igc->igc_hw.phy.autoneg_advertised;

	switch (stat) {
	/* MIB-II stats (RFC 1213 and RFC 1573) */
	case MAC_STAT_IFSPEED:
		*valp = (uint64_t)igc->igc_link_speed * 1000000;
		break;
	case MAC_STAT_MULTIRCV:
		stats->is_mprc.value.ui64 += igc_read32(igc, IGC_MPRC);
		*valp = stats->is_mprc.value.ui64;
		break;
	case MAC_STAT_BRDCSTRCV:
		stats->is_bprc.value.ui64 += igc_read32(igc, IGC_BPRC);
		*valp = stats->is_bprc.value.ui64;
		break;
	case MAC_STAT_MULTIXMT:
		stats->is_mptc.value.ui64 += igc_read32(igc, IGC_MPTC);
		*valp = stats->is_mptc.value.ui64;
		break;
	case MAC_STAT_BRDCSTXMT:
		stats->is_bptc.value.ui64 += igc_read32(igc, IGC_BPTC);
		*valp = stats->is_bptc.value.ui64;
		break;
	case MAC_STAT_NORCVBUF:
		stats->is_rnbc.value.ui64 += igc_read32(igc, IGC_RNBC);
		*valp = stats->is_rnbc.value.ui64;
		break;
	case MAC_STAT_IERRORS:
		stats->is_crcerrs.value.ui64 += igc_read32(igc, IGC_CRCERRS);
		stats->is_rlec.value.ui64 += igc_read32(igc, IGC_RLEC);
		stats->is_algnerrc.value.ui64 += igc_read32(igc, IGC_ALGNERRC);

		*valp = stats->is_crcerrs.value.ui64 +
		    stats->is_rlec.value.ui64 + stats->is_algnerrc.value.ui64;
		break;
	case MAC_STAT_OERRORS:
		stats->is_ecol.value.ui64 += igc_read32(igc, IGC_ECOL);
		stats->is_latecol.value.ui64 += igc_read32(igc, IGC_LATECOL);

		*valp = stats->is_ecol.value.ui64 +
		    stats->is_latecol.value.ui64;
		break;
	case MAC_STAT_COLLISIONS:
		stats->is_colc.value.ui64 += igc_read32(igc, IGC_COLC);
		*valp = stats->is_colc.value.ui64;
		break;
	case MAC_STAT_RBYTES:
		igc_stats_update_u64(igc, &stats->is_tor, IGC_TORL);
		*valp = stats->is_tor.value.ui64;
		break;
	case MAC_STAT_IPACKETS:
		stats->is_tpr.value.ui64 += igc_read32(igc, IGC_TPR);
		*valp = stats->is_tpr.value.ui64;
		break;
	case MAC_STAT_OBYTES:
		igc_stats_update_u64(igc, &stats->is_tor, IGC_TOTL);
		*valp = stats->is_tot.value.ui64;
		break;
	case MAC_STAT_OPACKETS:
		stats->is_tpt.value.ui64 += igc_read32(igc, IGC_TPT);
		*valp = stats->is_tpt.value.ui64;
		break;
	case MAC_STAT_UNDERFLOWS:
		stats->is_ruc.value.ui64 += igc_read32(igc, IGC_RUC);
		*valp = stats->is_ruc.value.ui64;
		break;
	case MAC_STAT_OVERFLOWS:
		stats->is_roc.value.ui64 += igc_read32(igc, IGC_ROC);
		*valp = stats->is_roc.value.ui64;
		break;
	/* RFC 1643 stats */
	case ETHER_STAT_ALIGN_ERRORS:
		stats->is_algnerrc.value.ui64 += igc_read32(igc, IGC_ALGNERRC);
		*valp = stats->is_algnerrc.value.ui64;
		break;
	case ETHER_STAT_FCS_ERRORS:
		stats->is_crcerrs.value.ui64 += igc_read32(igc, IGC_CRCERRS);
		*valp = stats->is_crcerrs.value.ui64;
		break;
	case ETHER_STAT_FIRST_COLLISIONS:
		stats->is_scc.value.ui64 += igc_read32(igc, IGC_SCC);
		*valp = stats->is_scc.value.ui64;
		break;
	case ETHER_STAT_MULTI_COLLISIONS:
		stats->is_mcc.value.ui64 += igc_read32(igc, IGC_MCC);
		*valp = stats->is_mcc.value.ui64;
		break;
	case ETHER_STAT_DEFER_XMTS:
		stats->is_dc.value.ui64 += igc_read32(igc, IGC_DC);
		*valp = stats->is_dc.value.ui64;
		break;
	case ETHER_STAT_TX_LATE_COLLISIONS:
		stats->is_latecol.value.ui64 += igc_read32(igc, IGC_LATECOL);
		*valp = stats->is_latecol.value.ui64;
		break;
	case ETHER_STAT_EX_COLLISIONS:
		stats->is_ecol.value.ui64 += igc_read32(igc, IGC_ECOL);
		*valp = stats->is_ecol.value.ui64;
		break;
	case ETHER_STAT_MACXMT_ERRORS:
		stats->is_ecol.value.ui64 += igc_read32(igc, IGC_ECOL);
		*valp = stats->is_ecol.value.ui64;
		break;
	case ETHER_STAT_CARRIER_ERRORS:
		stats->is_htdpmc.value.ui64 += igc_read32(igc, IGC_HTDPMC);
		*valp = stats->is_htdpmc.value.ui64;
		break;
	case ETHER_STAT_TOOLONG_ERRORS:
		stats->is_roc.value.ui64 += igc_read32(igc, IGC_ROC);
		*valp = stats->is_roc.value.ui64;
		break;
	/* MII/GMII stats */
	case ETHER_STAT_XCVR_ADDR:
		*valp = igc->igc_hw.phy.addr;
		break;
	case ETHER_STAT_XCVR_ID:
		*valp = igc->igc_hw.phy.id | igc->igc_hw.phy.revision;
		break;
	case ETHER_STAT_XCVR_INUSE:
		*valp = igc_link_to_media(igc);
		break;
	case ETHER_STAT_CAP_2500FDX:
	case ETHER_STAT_CAP_1000FDX:
	case ETHER_STAT_CAP_100FDX:
	case ETHER_STAT_CAP_100HDX:
	case ETHER_STAT_CAP_10FDX:
	case ETHER_STAT_CAP_10HDX:
	case ETHER_STAT_CAP_ASMPAUSE:
	case ETHER_STAT_CAP_PAUSE:
	case ETHER_STAT_CAP_AUTONEG:
		/*
		 * These are all about what the device is capable of and every
		 * device is capable of this that we support right now.
		 */
		*valp = 1;
		break;
	case ETHER_STAT_ADV_CAP_2500FDX:
		*valp = (an_adv & ADVERTISE_2500_FULL) != 0;
		break;
	case ETHER_STAT_ADV_CAP_1000FDX:
		*valp = (an_adv & ADVERTISE_1000_FULL) != 0;
		break;
	case ETHER_STAT_ADV_CAP_100FDX:
		*valp = (an_adv & ADVERTISE_100_FULL) != 0;
		break;
	case ETHER_STAT_ADV_CAP_100HDX:
		*valp = (an_adv & ADVERTISE_100_HALF) != 0;
		break;
	case ETHER_STAT_ADV_CAP_10FDX:
		*valp = (an_adv & ADVERTISE_10_FULL) != 0;
		break;
	case ETHER_STAT_ADV_CAP_10HDX:
		*valp = (an_adv & ADVERTISE_10_HALF) != 0;
		break;
	case ETHER_STAT_ADV_CAP_ASMPAUSE:
		*valp = (igc->igc_phy_an_adv & NWAY_AR_ASM_DIR) != 0;
		break;
	case ETHER_STAT_ADV_CAP_PAUSE:
		*valp = (igc->igc_phy_an_adv & NWAY_AR_PAUSE) != 0;
		break;
	case ETHER_STAT_ADV_CAP_AUTONEG:
		*valp = igc->igc_hw.mac.autoneg;
		break;
	case ETHER_STAT_LP_CAP_2500FDX:
		*valp = (igc->igc_phy_mmd_sts & MMD_AN_STS1_LP_2P5T_CAP) != 0;
		break;
	case ETHER_STAT_LP_CAP_1000FDX:
		*valp = (igc->igc_phy_1000t_status & SR_1000T_LP_FD_CAPS) != 0;
		break;
	case ETHER_STAT_LP_CAP_100FDX:
		*valp = (igc->igc_phy_lp & NWAY_LPAR_100TX_FD_CAPS) != 0;
		break;
	case ETHER_STAT_LP_CAP_100HDX:
		*valp = (igc->igc_phy_lp & NWAY_LPAR_100TX_HD_CAPS) != 0;
		break;
	case ETHER_STAT_LP_CAP_10FDX:
		*valp = (igc->igc_phy_lp & NWAY_LPAR_10T_FD_CAPS) != 0;
		break;
	case ETHER_STAT_LP_CAP_10HDX:
		*valp = (igc->igc_phy_lp & NWAY_LPAR_10T_HD_CAPS) != 0;
		break;
	case ETHER_STAT_LP_CAP_ASMPAUSE:
		*valp = (igc->igc_phy_lp & NWAY_AR_ASM_DIR) != 0;
		break;
	case ETHER_STAT_LP_CAP_PAUSE:
		*valp = (igc->igc_phy_lp & NWAY_LPAR_PAUSE) != 0;
		break;
	case ETHER_STAT_LP_CAP_AUTONEG:
		*valp = (igc->igc_phy_ext_status & NWAY_ER_LP_NWAY_CAPS) != 0;
		break;
	case ETHER_STAT_LINK_ASMPAUSE:
		*valp = (igc->igc_hw.fc.current_mode == igc_fc_full ||
		    igc->igc_hw.fc.current_mode == igc_fc_rx_pause);
		break;
	case ETHER_STAT_LINK_PAUSE:
		*valp = (igc->igc_hw.fc.current_mode == igc_fc_full ||
		    igc->igc_hw.fc.current_mode == igc_fc_tx_pause);
		break;
	case ETHER_STAT_LINK_AUTONEG:
		*valp = igc->igc_hw.mac.autoneg;
		break;
	case ETHER_STAT_LINK_DUPLEX:
		*valp = igc->igc_link_duplex;
		break;
	case ETHER_STAT_CAP_REMFAULT:
		*valp = 1;
		break;
	case ETHER_STAT_ADV_REMFAULT:
		*valp = (igc->igc_phy_an_adv & NWAY_AR_REMOTE_FAULT) != 0;
		break;
	case ETHER_STAT_LP_REMFAULT:
		*valp = (igc->igc_phy_lp & NWAY_LPAR_REMOTE_FAULT) != 0;
		break;

	case ETHER_STAT_TOOSHORT_ERRORS:
		stats->is_ruc.value.ui64 += igc_read32(igc, IGC_RUC);
		*valp = stats->is_ruc.value.ui64;
		break;

	case ETHER_STAT_JABBER_ERRORS:
		stats->is_rjc.value.ui64 += igc_read32(igc, IGC_RJC);
		*valp = stats->is_rjc.value.ui64;
		break;

	/*
	 * Unsupported speeds.
	 */
	case ETHER_STAT_CAP_100T4:
	case ETHER_STAT_CAP_1000HDX:
	case ETHER_STAT_CAP_10GFDX:
	case ETHER_STAT_CAP_40GFDX:
	case ETHER_STAT_CAP_100GFDX:
	case ETHER_STAT_CAP_5000FDX:
	case ETHER_STAT_CAP_25GFDX:
	case ETHER_STAT_CAP_50GFDX:
	case ETHER_STAT_CAP_200GFDX:
	case ETHER_STAT_CAP_400GFDX:
	case ETHER_STAT_ADV_CAP_100T4:
	case ETHER_STAT_ADV_CAP_1000HDX:
	case ETHER_STAT_ADV_CAP_10GFDX:
	case ETHER_STAT_ADV_CAP_40GFDX:
	case ETHER_STAT_ADV_CAP_100GFDX:
	case ETHER_STAT_ADV_CAP_5000FDX:
	case ETHER_STAT_ADV_CAP_25GFDX:
	case ETHER_STAT_ADV_CAP_50GFDX:
	case ETHER_STAT_ADV_CAP_200GFDX:
	case ETHER_STAT_ADV_CAP_400GFDX:
		*valp = 0;
		break;

	/*
	 * These are values that aren't supported by igc(4D); however, some of
	 * the MII registers can be used to answer this based on the
	 * MultiGBASE-T spec (and others).
	 */
	case ETHER_STAT_LP_CAP_1000HDX:
		*valp = (igc->igc_phy_1000t_status & SR_1000T_LP_HD_CAPS) != 0;
		break;
	case ETHER_STAT_LP_CAP_100T4:
		*valp = (igc->igc_phy_lp & NWAY_LPAR_100T4_CAPS) != 0;
		break;
	case ETHER_STAT_LP_CAP_10GFDX:
		*valp = (igc->igc_phy_mmd_sts & MMD_AN_STS1_LP_10T_CAP) != 0;
		break;
	case ETHER_STAT_LP_CAP_40GFDX:
		*valp = (igc->igc_phy_mmd_sts & MMD_AN_STS1_LP_40T_CAP) != 0;
		break;
	case ETHER_STAT_LP_CAP_5000FDX:
		*valp = (igc->igc_phy_mmd_sts & MMD_AN_STS1_LP_5T_CAP) != 0;
		break;
	case ETHER_STAT_LP_CAP_25GFDX:
		*valp = (igc->igc_phy_mmd_sts & MMD_AN_STS1_LP_25T_CAP) != 0;
		break;
	case ETHER_STAT_LP_CAP_50GFDX:
	case ETHER_STAT_LP_CAP_100GFDX:
	case ETHER_STAT_LP_CAP_200GFDX:
	case ETHER_STAT_LP_CAP_400GFDX:
		*valp = 0;
		break;
	default:
		ret = ENOTSUP;
	}
	mutex_exit(&igc->igc_lock);

	return (ret);
}

static void
igc_m_stop(void *drv)
{
	igc_t *igc = drv;

	igc_hw_intr_disable(igc);
	(void) igc_reset_hw(&igc->igc_hw);
	igc_rx_drain(igc);
	igc_rx_data_free(igc);
	igc_tx_data_free(igc);

	/*
	 * Now that we're fully stopped, remove all of our state tracking.
	 */
	mutex_enter(&igc->igc_lock);
	igc->igc_attach &= ~IGC_ATTACH_TX_DATA;
	igc->igc_attach &= ~IGC_ATTACH_RX_DATA;
	igc->igc_attach &= ~IGC_ATTACH_MAC_START;
	mutex_exit(&igc->igc_lock);
}

static int
igc_m_start(void *drv)
{
	int ret;
	igc_t *igc = drv;

	mutex_enter(&igc->igc_lock);
	igc->igc_attach |= IGC_ATTACH_MAC_START;
	mutex_exit(&igc->igc_lock);

	/*
	 * Ensure that the phy is powerd on.
	 */
	igc_power_up_phy(&igc->igc_hw);

	if (!igc_rx_data_alloc(igc)) {
		ret = ENOMEM;
		goto cleanup;
	}
	mutex_enter(&igc->igc_lock);
	igc->igc_attach |= IGC_ATTACH_RX_DATA;
	mutex_exit(&igc->igc_lock);

	if (!igc_tx_data_alloc(igc)) {
		ret = ENOMEM;
		goto cleanup;
	}
	mutex_enter(&igc->igc_lock);
	igc->igc_attach |= IGC_ATTACH_TX_DATA;
	mutex_exit(&igc->igc_lock);

	if (!igc_hw_common_init(igc)) {
		ret = EIO;
		goto cleanup;
	}

	/*
	 * The above hardware reset ensures that the latest requested link
	 * properties are set and that the packet sizes and related are
	 * programmed. Now we must go through and program the ring information
	 * into the hardware and enable interrupts. Once that's done we're good
	 * to go.
	 */
	igc_rx_hw_init(igc);
	igc_tx_hw_init(igc);
	igc_hw_intr_enable(igc);

	return (0);

cleanup:
	mutex_enter(&igc->igc_lock);
	if ((igc->igc_attach & IGC_ATTACH_TX_DATA) != 0) {
		igc_tx_data_free(igc);
		igc->igc_attach &= ~IGC_ATTACH_TX_DATA;
	}

	if ((igc->igc_attach & IGC_ATTACH_RX_DATA) != 0) {
		igc_rx_data_free(igc);
		igc->igc_attach &= ~IGC_ATTACH_RX_DATA;
	}

	igc->igc_attach &= ~IGC_ATTACH_MAC_START;
	mutex_exit(&igc->igc_lock);

	return (ret);
}

static int
igc_m_setpromisc(void *drv, boolean_t en)
{
	igc_t *igc = drv;
	uint32_t reg;

	mutex_enter(&igc->igc_lock);

	reg = igc_read32(igc, IGC_RCTL);
	if (en) {
		reg |= IGC_RCTL_UPE | IGC_RCTL_MPE;
		igc->igc_promisc = true;
	} else {
		reg &= ~(IGC_RCTL_UPE | IGC_RCTL_MPE);
		igc->igc_promisc = false;
	}
	igc_write32(igc, IGC_RCTL, reg);
	mutex_exit(&igc->igc_lock);

	return (0);
}

static int
igc_m_multicast(void *drv, boolean_t add, const uint8_t *mac)
{
	int ret = 0;
	igc_t *igc = drv;

	if ((mac[0] & 0x01) == 0) {
		return (EINVAL);
	}

	mutex_enter(&igc->igc_lock);
	if (add) {
		bool space = false;

		for (uint16_t i = 0; i < igc->igc_nmcast; i++) {
			if (igc->igc_mcast[i].ia_valid)
				continue;

			bcopy(mac, igc->igc_mcast[i].ia_mac, ETHERADDRL);
			igc->igc_mcast[i].ia_valid = true;
			space = true;
			break;
		}

		if (!space) {
			ret = ENOSPC;
		}
	} else {
		bool found = false;

		for (uint16_t i = 0; i < igc->igc_nmcast; i++) {
			if (!igc->igc_mcast[i].ia_valid || bcmp(mac,
			    igc->igc_mcast[i].ia_mac, ETHERADDRL) != 0) {
				continue;
			}

			bzero(igc->igc_mcast[i].ia_mac, ETHERADDRL);
			igc->igc_mcast[i].ia_valid = false;
			found = true;
			break;
		}

		if (!found) {
			ret = ENOENT;
		}
	}
	igc_multicast_sync(igc);
	mutex_exit(&igc->igc_lock);

	return (ret);
}

static int
igc_group_add_mac(void *gr_drv, const uint8_t *mac)
{
	igc_t *igc = gr_drv;

	ASSERT3U(mac[0] & 0x01, ==, 0);

	mutex_enter(&igc->igc_lock);
	for (uint16_t i = 0; i < igc->igc_nucast; i++) {
		int ret;

		if (igc->igc_ucast[i].ia_valid)
			continue;

		bcopy(mac, igc->igc_ucast[i].ia_mac, ETHERADDRL);
		igc->igc_ucast[i].ia_valid = true;
		ret = igc_rar_set(&igc->igc_hw, igc->igc_ucast[i].ia_mac, i);
		VERIFY3S(ret, ==, IGC_SUCCESS);
		mutex_exit(&igc->igc_lock);
		return (0);
	}
	mutex_exit(&igc->igc_lock);

	return (ENOSPC);
}

static int
igc_group_rem_mac(void *gr_drv, const uint8_t *mac)
{
	igc_t *igc = gr_drv;

	ASSERT3U(mac[0] & 0x01, ==, 0);

	mutex_enter(&igc->igc_lock);
	for (uint16_t i = 0; i < igc->igc_nucast; i++) {
		int ret;

		if (!igc->igc_ucast[i].ia_valid || bcmp(mac,
		    igc->igc_ucast[i].ia_mac, ETHERADDRL) != 0) {
			continue;
		}

		bzero(igc->igc_ucast[i].ia_mac, ETHERADDRL);
		igc->igc_ucast[i].ia_valid = false;
		ret = igc_rar_set(&igc->igc_hw, igc->igc_ucast[i].ia_mac, i);
		VERIFY3S(ret, ==, IGC_SUCCESS);
		mutex_exit(&igc->igc_lock);
		return (0);
	}
	mutex_exit(&igc->igc_lock);

	return (ENOENT);
}

int
igc_tx_ring_stat(mac_ring_driver_t rh, uint_t stat, uint64_t *val)
{
	igc_tx_ring_t *tx_ring = (igc_tx_ring_t *)rh;

	switch (stat) {
	case MAC_STAT_OBYTES:
		*val = tx_ring->itr_stat.its_obytes.value.ui64;
		break;
	case MAC_STAT_OPACKETS:
		*val = tx_ring->itr_stat.its_opackets.value.ui64;
		break;
	default:
		*val = 0;
		return (ENOTSUP);
	}

	return (0);
}

int
igc_rx_ring_start(mac_ring_driver_t rh, uint64_t gen)
{
	igc_rx_ring_t *rx_ring = (igc_rx_ring_t *)rh;

	mutex_enter(&rx_ring->irr_lock);
	rx_ring->irr_gen = gen;
	mutex_exit(&rx_ring->irr_lock);

	return (0);
}

mblk_t *
igc_rx_ring_poll(void *drv, int nbytes)
{
	mblk_t *mp;
	igc_rx_ring_t *ring = drv;

	ASSERT3S(nbytes, >, 0);
	if (nbytes == 0) {
		return (NULL);
	}

	mutex_enter(&ring->irr_lock);
	mp = igc_ring_rx(ring, nbytes);
	mutex_exit(&ring->irr_lock);

	return (mp);
}

int
igc_rx_ring_stat(mac_ring_driver_t rh, uint_t stat, uint64_t *val)
{
	igc_rx_ring_t *rx_ring = (igc_rx_ring_t *)rh;

	switch (stat) {
	case MAC_STAT_RBYTES:
		*val = rx_ring->irr_stat.irs_rbytes.value.ui64;
		break;
	case MAC_STAT_IPACKETS:
		*val = rx_ring->irr_stat.irs_ipackets.value.ui64;
		break;
	default:
		*val = 0;
		return (ENOTSUP);
	}

	return (0);
}

int
igc_rx_ring_intr_enable(mac_intr_handle_t ih)
{
	igc_rx_ring_t *ring = (igc_rx_ring_t *)ih;
	igc_t *igc = ring->irr_igc;

	/*
	 * Disabling a ring requires us updating shared device registers. So we
	 * use the igc_lock to protect that. We also grab the irr_lock, so we
	 * can synchronize with the I/O path.
	 */
	mutex_enter(&igc->igc_lock);
	mutex_enter(&ring->irr_lock);
	ring->irr_flags &= ~IGC_RXR_F_POLL;
	mutex_exit(&ring->irr_lock);

	/*
	 * Re-enable interrupts. We update our EIMS value and then update both
	 * the EIMS and EIAC. We update the whole set with the EIMS just to
	 * simplify things.
	 */
	igc->igc_eims |= 1 << ring->irr_intr_idx;
	igc_write32(igc, IGC_EIMS, igc->igc_eims);
	igc_write32(igc, IGC_EIAC, igc->igc_eims);
	mutex_exit(&igc->igc_lock);
	return (0);
}

int
igc_rx_ring_intr_disable(mac_intr_handle_t ih)
{
	igc_rx_ring_t *ring = (igc_rx_ring_t *)ih;
	igc_t *igc = ring->irr_igc;

	/*
	 * Disabling a ring requires us updating shared device registers. So we
	 * use the igc_lock to protect that. We also grab the irr_lock, so we
	 * can synchronize with the I/O path.
	 */
	mutex_enter(&igc->igc_lock);
	mutex_enter(&ring->irr_lock);
	ring->irr_flags |= IGC_RXR_F_POLL;
	mutex_exit(&ring->irr_lock);

	/*
	 * Writing to the EIMC register masks off interrupts for this. We also
	 * clear this from EIAC as a means of making sure it also won't
	 * retrigger. We remove this queue from our global tracking set of what
	 * the eims value should be to simplify tracking.
	 */
	igc_write32(igc, IGC_EIMC, 1 << ring->irr_intr_idx);
	igc->igc_eims &= ~ (1 << ring->irr_intr_idx);
	igc_write32(igc, IGC_EIAC, igc->igc_eims);
	mutex_exit(&igc->igc_lock);

	return (0);
}

static void
igc_fill_tx_ring(void *arg, mac_ring_type_t rtype, const int group_idx,
    const int ring_idx, mac_ring_info_t *infop, mac_ring_handle_t rh)
{
	igc_t *igc = arg;
	igc_tx_ring_t *ring;

	ASSERT3S(group_idx, ==, -1);
	ASSERT3S(ring_idx, <, igc->igc_ntx_rings);

	ring = &igc->igc_tx_rings[ring_idx];
	ring->itr_rh = rh;

	infop->mri_driver = (mac_ring_driver_t)ring;
	infop->mri_start = NULL;
	infop->mri_stop = NULL;
	infop->mri_tx = igc_ring_tx;
	infop->mri_stat = igc_tx_ring_stat;

	if (igc->igc_intr_type == DDI_INTR_TYPE_MSIX) {
		infop->mri_intr.mi_ddi_handle =
		    igc->igc_intr_handles[ring->itr_intr_idx];
	}
}

static void
igc_fill_rx_ring(void *arg, mac_ring_type_t rtype, const int group_idx,
    const int ring_idx, mac_ring_info_t *infop, mac_ring_handle_t rh)
{
	igc_t *igc = arg;
	igc_rx_ring_t *ring;

	ASSERT3S(group_idx, ==, 0);
	ASSERT3S(ring_idx, <, igc->igc_nrx_rings);

	ring = &igc->igc_rx_rings[ring_idx];
	ring->irr_rh = rh;

	infop->mri_driver = (mac_ring_driver_t)ring;
	infop->mri_start = igc_rx_ring_start;
	infop->mri_stop = NULL;
	infop->mri_poll = igc_rx_ring_poll;
	infop->mri_stat = igc_rx_ring_stat;
	infop->mri_intr.mi_handle = (mac_intr_handle_t)ring;
	infop->mri_intr.mi_enable = igc_rx_ring_intr_enable;
	infop->mri_intr.mi_disable = igc_rx_ring_intr_disable;

	if (igc->igc_intr_type == DDI_INTR_TYPE_MSIX) {
		infop->mri_intr.mi_ddi_handle =
		    igc->igc_intr_handles[ring->irr_intr_idx];
	}
}

static void
igc_fill_rx_group(void *arg, mac_ring_type_t rtype, const int idx,
    mac_group_info_t *infop, mac_group_handle_t gh)
{
	igc_t *igc = arg;

	if (rtype != MAC_RING_TYPE_RX) {
		return;
	}

	igc->igc_rxg_hdl = gh;
	infop->mgi_driver = (mac_group_driver_t)igc;
	infop->mgi_start = NULL;
	infop->mgi_stop = NULL;
	infop->mgi_addmac = igc_group_add_mac;
	infop->mgi_remmac = igc_group_rem_mac;
	infop->mgi_count = igc->igc_nrx_rings;
}

static int
igc_led_set(void *drv, mac_led_mode_t mode, uint_t flags)
{
	igc_t *igc = drv;
	uint32_t led;

	if (flags != 0) {
		return (EINVAL);
	}

	switch (mode) {
	case MAC_LED_DEFAULT:
		led = igc->igc_ledctl;
		break;
	case MAC_LED_IDENT:
		led = igc->igc_ledctl_blink;
		break;
	case MAC_LED_OFF:
		led = igc->igc_ledctl_off;
		break;
	case MAC_LED_ON:
		led = igc->igc_ledctl_on;
		break;
	default:
		return (ENOTSUP);
	}

	mutex_enter(&igc->igc_lock);
	igc_write32(igc, IGC_LEDCTL, led);
	igc->igc_led_mode = mode;
	mutex_exit(&igc->igc_lock);

	return (0);
}

static boolean_t
igc_m_getcapab(void *drv, mac_capab_t capab, void *data)
{
	igc_t *igc = drv;
	mac_capab_rings_t *rings;
	mac_capab_led_t *led;
	uint32_t *cksump;

	switch (capab) {
	case MAC_CAPAB_RINGS:
		rings = data;
		rings->mr_group_type = MAC_GROUP_TYPE_STATIC;
		switch (rings->mr_type) {
		case MAC_RING_TYPE_TX:
			rings->mr_gnum = 0;
			rings->mr_rnum = igc->igc_ntx_rings;
			rings->mr_rget = igc_fill_tx_ring;
			rings->mr_gget = NULL;
			rings->mr_gaddring = NULL;
			rings->mr_gremring = NULL;
			break;
		case MAC_RING_TYPE_RX:
			rings->mr_gnum = 1;
			rings->mr_rnum = igc->igc_nrx_rings;
			rings->mr_rget = igc_fill_rx_ring;
			rings->mr_gget = igc_fill_rx_group;
			rings->mr_gaddring = NULL;
			rings->mr_gremring = NULL;
			break;
		default:
			return (B_FALSE);
		}
		break;
	case MAC_CAPAB_HCKSUM:
		cksump = data;

		/*
		 * The hardware supports computing the full checksum on receive,
		 * but on transmit needs the partial checksum pre-computed.
		 */
		*cksump = HCKSUM_INET_PARTIAL | HCKSUM_IPHDRCKSUM;
		break;
	case MAC_CAPAB_LED:
		led = data;
		led->mcl_flags = 0;
		led->mcl_modes = MAC_LED_DEFAULT | MAC_LED_OFF | MAC_LED_ON |
		    MAC_LED_IDENT;
		led->mcl_set = igc_led_set;
		return (B_TRUE);
	default:
		return (B_FALSE);
	}
	return (B_TRUE);
}

void
igc_m_propinfo(void *drv, const char *name, mac_prop_id_t prop,
    mac_prop_info_handle_t prh)
{
	igc_t *igc = drv;

	switch (prop) {
	case MAC_PROP_DUPLEX:
	case MAC_PROP_SPEED:
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		break;
	case MAC_PROP_AUTONEG:
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		mac_prop_info_set_default_uint8(prh, 1);
		break;
	case MAC_PROP_MTU:
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_RW);
		mac_prop_info_set_range_uint32(prh, ETHERMIN,
		    igc->igc_limits.il_max_mtu);
		mac_prop_info_set_default_uint32(prh, ETHERMTU);
		break;
	case MAC_PROP_FLOWCTRL:
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_RW);
		mac_prop_info_set_default_link_flowctrl(prh, LINK_FLOWCTRL_BI);
		break;
	/*
	 * Right now, all igc devices support the same set of speeds and we
	 * attempt to advertise them all.
	 */
	case MAC_PROP_ADV_10HDX_CAP:
	case MAC_PROP_ADV_10FDX_CAP:
	case MAC_PROP_ADV_100HDX_CAP:
	case MAC_PROP_ADV_100FDX_CAP:
	case MAC_PROP_ADV_1000FDX_CAP:
	case MAC_PROP_ADV_2500FDX_CAP:
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		mac_prop_info_set_default_uint8(prh, 1);
		break;
	case MAC_PROP_EN_10HDX_CAP:
	case MAC_PROP_EN_10FDX_CAP:
	case MAC_PROP_EN_100HDX_CAP:
	case MAC_PROP_EN_100FDX_CAP:
	case MAC_PROP_EN_1000FDX_CAP:
	case MAC_PROP_EN_2500FDX_CAP:
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_RW);
		mac_prop_info_set_default_uint8(prh, 1);
		break;
	default:
		break;
	}
}

int
igc_m_getprop(void *drv, const char *name, mac_prop_id_t prop,
    uint_t pr_valsize, void *pr_val)
{
	igc_t *igc = drv;
	int ret = 0;
	uint8_t *u8p;
	uint64_t u64;
	link_flowctrl_t flow;
	mac_ether_media_t media;

	mutex_enter(&igc->igc_lock);

	switch (prop) {
	case MAC_PROP_DUPLEX:
		if (pr_valsize < sizeof (link_duplex_t)) {
			ret = EOVERFLOW;
			break;
		}
		bcopy(&igc->igc_link_duplex, pr_val, sizeof (link_duplex_t));
		break;
	case MAC_PROP_SPEED:
		if (pr_valsize < sizeof (uint64_t)) {
			ret = EOVERFLOW;
			break;
		}
		u64 = (uint64_t)igc->igc_link_speed * 1000000;
		bcopy(&u64, pr_val, sizeof (uint64_t));
		break;
	case MAC_PROP_STATUS:
		if (pr_valsize < sizeof (link_state_t)) {
			ret = EOVERFLOW;
			break;
		}
		bcopy(&igc->igc_link_state, pr_val, sizeof (link_state_t));
		break;
	case MAC_PROP_MEDIA:
		if (pr_valsize < sizeof (mac_ether_media_t)) {
			ret = EOVERFLOW;
			break;
		}
		media = igc_link_to_media(igc);
		bcopy(&media, pr_val, sizeof (mac_ether_media_t));
		break;
	case MAC_PROP_AUTONEG:
		if (pr_valsize < sizeof (uint8_t)) {
			ret = EOVERFLOW;
			break;
		}
		u8p = pr_val;
		*u8p = igc->igc_hw.mac.autoneg;
		break;
	case MAC_PROP_MTU:
		if (pr_valsize < sizeof (uint32_t)) {
			ret = EOVERFLOW;
			break;
		}
		bcopy(&igc->igc_mtu, pr_val, sizeof (uint32_t));
		break;
	case MAC_PROP_FLOWCTRL:
		switch (igc->igc_hw.fc.requested_mode) {
		case igc_fc_none:
			flow = LINK_FLOWCTRL_NONE;
			break;
		case igc_fc_rx_pause:
			flow = LINK_FLOWCTRL_RX;
			break;
		case igc_fc_tx_pause:
			flow = LINK_FLOWCTRL_TX;
			break;
		case igc_fc_full:
			flow = LINK_FLOWCTRL_BI;
			break;
		/*
		 * We don't expect to get this value here; however, for
		 * completeness of the switch's valid options we include it and
		 * set it to the common firmware default of enabling
		 * bi-direcitonal pause frames.
		 */
		case igc_fc_default:
			flow = LINK_FLOWCTRL_BI;
			break;
		}
		bcopy(&flow, pr_val, sizeof (link_flowctrl_t));
		break;
	case MAC_PROP_ADV_10HDX_CAP:
	case MAC_PROP_ADV_10FDX_CAP:
	case MAC_PROP_ADV_100HDX_CAP:
	case MAC_PROP_ADV_100FDX_CAP:
	case MAC_PROP_ADV_1000FDX_CAP:
	case MAC_PROP_ADV_2500FDX_CAP:
		ret = ENOTSUP;
		break;
	case MAC_PROP_EN_10HDX_CAP:
		if (pr_valsize < sizeof (uint8_t)) {
			ret = EOVERFLOW;
			break;
		}
		u8p = pr_val;
		*u8p = (igc->igc_hw.phy.autoneg_advertised &
		    ADVERTISE_10_HALF) != 0;
		break;
	case MAC_PROP_EN_10FDX_CAP:
		if (pr_valsize < sizeof (uint8_t)) {
			ret = EOVERFLOW;
			break;
		}
		u8p = pr_val;
		*u8p = (igc->igc_hw.phy.autoneg_advertised &
		    ADVERTISE_10_FULL) != 0;
		break;
	case MAC_PROP_EN_100HDX_CAP:
		if (pr_valsize < sizeof (uint8_t)) {
			ret = EOVERFLOW;
			break;
		}
		u8p = pr_val;
		*u8p = (igc->igc_hw.phy.autoneg_advertised &
		    ADVERTISE_100_HALF) != 0;
		break;
	case MAC_PROP_EN_100FDX_CAP:
		if (pr_valsize < sizeof (uint8_t)) {
			ret = EOVERFLOW;
			break;
		}
		u8p = pr_val;
		*u8p = (igc->igc_hw.phy.autoneg_advertised &
		    ADVERTISE_100_FULL) != 0;
		break;
	case MAC_PROP_EN_1000FDX_CAP:
		if (pr_valsize < sizeof (uint8_t)) {
			ret = EOVERFLOW;
			break;
		}
		u8p = pr_val;
		*u8p = (igc->igc_hw.phy.autoneg_advertised &
		    ADVERTISE_1000_FULL) != 0;
		break;
	case MAC_PROP_EN_2500FDX_CAP:
		if (pr_valsize < sizeof (uint8_t)) {
			ret = EOVERFLOW;
			break;
		}
		u8p = pr_val;
		*u8p = (igc->igc_hw.phy.autoneg_advertised &
		    ADVERTISE_2500_FULL) != 0;
		break;
	default:
		ret = ENOTSUP;
		break;
	}

	mutex_exit(&igc->igc_lock);
	return (ret);
}

int
igc_m_setprop(void *drv, const char *name, mac_prop_id_t prop, uint_t size,
    const void *val)
{
	int ret = 0;
	bool update_link = true;
	igc_t *igc = drv;
	uint32_t fc, mtu;
	uint8_t en;

	mutex_enter(&igc->igc_lock);
	switch (prop) {
	/*
	 * The following properties are always read-only. Note, auto-negotiation
	 * is here because we don't support turning it off right now. We leave
	 * out unsupported speeds.
	 */
	case MAC_PROP_DUPLEX:
	case MAC_PROP_SPEED:
	case MAC_PROP_STATUS:
	case MAC_PROP_AUTONEG:
	case MAC_PROP_ADV_2500FDX_CAP:
	case MAC_PROP_ADV_1000FDX_CAP:
	case MAC_PROP_ADV_1000HDX_CAP:
	case MAC_PROP_ADV_100FDX_CAP:
	case MAC_PROP_ADV_100HDX_CAP:
	case MAC_PROP_ADV_10HDX_CAP:
	case MAC_PROP_ADV_10FDX_CAP:
	case MAC_PROP_MEDIA:
		ret = ENOTSUP;
		break;
	/*
	 * This is a property that we should support, but don't today.
	 */
	case MAC_PROP_MTU:
		/*
		 * Unfortunately, like our siblings igb and e1000g, we do not
		 * currently support changing the MTU dynamically.
		 */
		if ((igc->igc_attach & IGC_ATTACH_MAC_START) != 0) {
			ret = EBUSY;
			break;
		}

		/*
		 * Changing the MTU does not require us to update the link right
		 * now as this can only be done while the device is stopped.
		 */
		update_link = false;

		bcopy(val, &mtu, sizeof (mtu));
		if (mtu < ETHERMIN || mtu > igc->igc_limits.il_max_mtu) {
			ret = EINVAL;
			break;
		}

		/*
		 * Verify that MAC will let us perform this operation. Once we
		 * have confirmed that we will need to update our various buffer
		 * sizes. Right now the driver requires that we increase the rx
		 * buffer size to match the MTU. The tx buffer size is capped at
		 * a page size and will be chained together if required. See the
		 * theory statement for more information.
		 */
		ret = mac_maxsdu_update(igc->igc_mac_hdl, mtu);
		if (ret == 0) {
			igc->igc_mtu = mtu;
			igc_hw_buf_update(igc);
		}
		break;
	case MAC_PROP_FLOWCTRL:
		bcopy(val, &fc, sizeof (uint32_t));

		switch (fc) {
		case LINK_FLOWCTRL_NONE:
			igc->igc_hw.fc.requested_mode = igc_fc_none;
			break;
		case LINK_FLOWCTRL_RX:
			igc->igc_hw.fc.requested_mode = igc_fc_rx_pause;
			break;
		case LINK_FLOWCTRL_TX:
			igc->igc_hw.fc.requested_mode = igc_fc_tx_pause;
			break;
		case LINK_FLOWCTRL_BI:
			igc->igc_hw.fc.requested_mode = igc_fc_full;
			break;
		default:
			ret = EINVAL;
			break;
		}
		break;
	case MAC_PROP_EN_2500FDX_CAP:
		bcopy(val, &en, sizeof (uint8_t));
		if (en != 0) {
			igc->igc_hw.phy.autoneg_advertised |=
			    ADVERTISE_2500_FULL;
		} else {
			igc->igc_hw.phy.autoneg_advertised &=
			    ~ADVERTISE_2500_FULL;
		}
		break;
	case MAC_PROP_EN_1000FDX_CAP:
		bcopy(val, &en, sizeof (uint8_t));
		if (en != 0) {
			igc->igc_hw.phy.autoneg_advertised |=
			    ADVERTISE_1000_FULL;
		} else {
			igc->igc_hw.phy.autoneg_advertised &=
			    ~ADVERTISE_1000_FULL;
		}
		break;
	case MAC_PROP_EN_100FDX_CAP:
		bcopy(val, &en, sizeof (uint8_t));
		if (en != 0) {
			igc->igc_hw.phy.autoneg_advertised |=
			    ADVERTISE_100_FULL;
		} else {
			igc->igc_hw.phy.autoneg_advertised &=
			    ~ADVERTISE_100_FULL;
		}
		break;
	case MAC_PROP_EN_100HDX_CAP:
		bcopy(val, &en, sizeof (uint8_t));
		if (en != 0) {
			igc->igc_hw.phy.autoneg_advertised |=
			    ADVERTISE_100_HALF;
		} else {
			igc->igc_hw.phy.autoneg_advertised &=
			    ~ADVERTISE_100_HALF;
		}
		break;
	case MAC_PROP_EN_10FDX_CAP:
		bcopy(val, &en, sizeof (uint8_t));
		if (en != 0) {
			igc->igc_hw.phy.autoneg_advertised |=
			    ADVERTISE_10_FULL;
		} else {
			igc->igc_hw.phy.autoneg_advertised &=
			    ~ADVERTISE_10_FULL;
		}
		break;
	case MAC_PROP_EN_10HDX_CAP:
		bcopy(val, &en, sizeof (uint8_t));
		if (en != 0) {
			igc->igc_hw.phy.autoneg_advertised |=
			    ADVERTISE_10_HALF;
		} else {
			igc->igc_hw.phy.autoneg_advertised &=
			    ~ADVERTISE_10_HALF;
		}
		break;
	default:
		ret = ENOTSUP;
		break;
	}

	if (ret == 0 && update_link) {
		if (igc_setup_link(&igc->igc_hw) != IGC_SUCCESS) {
			ret = EIO;
		}
	}
	mutex_exit(&igc->igc_lock);

	return (ret);
}

static mac_callbacks_t igc_mac_callbacks = {
	.mc_callbacks = MC_GETCAPAB | MC_GETPROP | MC_SETPROP | MC_PROPINFO,
	.mc_getstat = igc_m_getstat,
	.mc_start = igc_m_start,
	.mc_stop = igc_m_stop,
	.mc_setpromisc = igc_m_setpromisc,
	.mc_multicst = igc_m_multicast,
	.mc_getcapab = igc_m_getcapab,
	.mc_setprop = igc_m_setprop,
	.mc_getprop = igc_m_getprop,
	.mc_propinfo = igc_m_propinfo
};

bool
igc_mac_register(igc_t *igc)
{
	int ret;
	mac_register_t *mac = mac_alloc(MAC_VERSION);

	if (mac == NULL) {
		dev_err(igc->igc_dip, CE_WARN, "failed to allocate mac "
		    "registration handle");
		return (false);
	}

	mac->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	mac->m_driver = igc;
	mac->m_dip = igc->igc_dip;
	mac->m_src_addr = igc->igc_hw.mac.addr;
	mac->m_callbacks = &igc_mac_callbacks;
	mac->m_min_sdu = 0;
	mac->m_max_sdu = igc->igc_mtu;
	mac->m_margin = VLAN_TAGSZ;
	mac->m_priv_props = NULL;
	mac->m_v12n = MAC_VIRT_LEVEL1;

	ret = mac_register(mac, &igc->igc_mac_hdl);
	mac_free(mac);
	if (ret != 0) {
		dev_err(igc->igc_dip, CE_WARN, "failed to register with MAC: "
		    "%d", ret);
		return (false);
	}

	return (true);
}
