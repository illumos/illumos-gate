/*
 * Copyright 2014-2017 Cavium, Inc.
 * The contents of this file are subject to the terms of the Common Development
 * and Distribution License, v.1,  (the "License").
 *
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the License at available
 * at http://opensource.org/licenses/CDDL-1.0
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2019, Joyent, Inc.
 */

#include "bnxgld.h"
#include "bnxhwi.h"
#include "bnxsnd.h"
#include "bnxrcv.h"
#include "bnxcfg.h"

#include <sys/mac_provider.h>
#include <sys/mac_ether.h>
#include <sys/dlpi.h>
#include <sys/policy.h>

/*
 * Name:    bnx_m_start
 *
 * Input:   ptr to driver device structure.
 *
 * Return:  DDI_SUCCESS or DDI_FAILURE
 *
 * Description:
 *          This routine is called by GLD to enable device for
 *          packet reception and enable interrupts.
 */
static int
bnx_m_start(void *arg)
{
	int rc;
	um_device_t *umdevice;

	umdevice = (um_device_t *)arg;

	mutex_enter(&umdevice->os_param.gld_mutex);

	if (umdevice->dev_start == B_TRUE) {
		/* We're already started.  Success! */
		rc = 0;
		goto done;
	}

	/* Always report the initial link state as unknown. */
	bnx_gld_link(umdevice, LINK_STATE_UNKNOWN);

	umdevice->link_updates_ok = B_TRUE;

	if (bnx_hdwr_acquire(umdevice)) {
		rc = EIO;
		goto done;
	}

	umdevice->dev_start = B_TRUE;

	rc = 0;

done:
	mutex_exit(&umdevice->os_param.gld_mutex);

	return (rc);
}

/*
 * Name:    bnx_m_stop
 *
 * Input:   ptr to driver device structure.
 *
 * Return:  DDI_SUCCESS or DDI_FAILURE
 *
 * Description:
 *          This routine stops packet reception by clearing RX MASK
 *          register. Also interrupts are disabled for this device.
 */
static void
bnx_m_stop(void *arg)
{
	um_device_t *umdevice;

	umdevice = (um_device_t *)arg;

	mutex_enter(&umdevice->os_param.gld_mutex);

	if (umdevice->dev_start == B_TRUE) {
		umdevice->dev_start = B_FALSE;
		umdevice->link_updates_ok = B_FALSE;

		bnx_hdwr_release(umdevice);

		/* Report the link state back to unknown. */
		bnx_gld_link(umdevice, LINK_STATE_UNKNOWN);

		umdevice->dev_var.indLink   = 0;
		umdevice->dev_var.indMedium = 0;
	}

	mutex_exit(&umdevice->os_param.gld_mutex);
}



/*
 * Name:    bnx_m_unicast
 *
 * Input:   ptr to driver device structure,
 *          pointer to buffer containing MAC address.
 *
 * Return:  DDI_SUCCESS or DDI_FAILURE
 *
 * Description:
 */
static int
bnx_m_unicast(void *arg, const uint8_t *macaddr)
{
	int rc;
	um_device_t *umdevice;
	lm_device_t *lmdevice;

	umdevice = (um_device_t *)arg;
	lmdevice = &(umdevice->lm_dev);

	mutex_enter(&umdevice->os_param.gld_mutex);

	/* Validate MAC address */
	if (IS_ETH_MULTICAST(macaddr)) {
		cmn_err(CE_WARN, "%s: Attempt to program a multicast / "
		    "broadcast address as a MAC address.", umdevice->dev_name);
		rc = EINVAL;
		goto done;
	}

	if (umdevice->dev_start == B_TRUE) {
		if (lm_set_mac_addr(lmdevice, 0,
		    &(lmdevice->params.mac_addr[0])) != LM_STATUS_SUCCESS) {
			cmn_err(CE_WARN, "%s: failed to program MAC address.",
			    umdevice->dev_name);
			rc = EIO;
			goto done;
		}
	}

	bcopy(macaddr, &(lmdevice->params.mac_addr[0]), ETHERADDRL);

	rc = 0;

done:
	mutex_exit(&umdevice->os_param.gld_mutex);

	return (rc);
}

static int
bnx_mc_add(um_device_t *umdevice, const uint8_t *const mc_addr)
{
	int rc;
	int index;
	lm_status_t   lmstatus;
	lm_device_t *lmdevice;

	lmdevice = &(umdevice->lm_dev);

	index = bnx_find_mchash_collision(&(lmdevice->mc_table), mc_addr);
	if (index == -1) {
		lmstatus = lm_add_mc(lmdevice, (u8_t *)mc_addr);
		if (lmstatus == LM_STATUS_SUCCESS) {
			umdevice->dev_var.rx_filter_mask |=
			    LM_RX_MASK_ACCEPT_MULTICAST;
			rc = 0;
		} else {
			rc = ENOMEM;
		}
	} else {
		lmdevice->mc_table.addr_arr[index].ref_cnt++;
		rc = 0;
	}

	return (rc);
}

static int
bnx_mc_del(um_device_t *umdevice, const uint8_t *const mc_addr)
{
	int rc;
	int index;
	lm_status_t lmstatus;
	lm_device_t *lmdevice;

	lmdevice = &(umdevice->lm_dev);

	index = bnx_find_mchash_collision(&(lmdevice->mc_table), mc_addr);
	if (index == -1) {
		rc = ENXIO;
	} else {
		lmstatus = lm_del_mc(lmdevice,
		    lmdevice->mc_table.addr_arr[index].mc_addr);
		if (lmstatus == LM_STATUS_SUCCESS) {
			if (lmdevice->mc_table.entry_cnt == 0) {
				umdevice->dev_var.rx_filter_mask &=
				    ~LM_RX_MASK_ACCEPT_MULTICAST;
			}

			rc = 0;
		} else {
			rc = ENXIO;
		}
	}

	return (rc);
}



/*
 * Name:    bnx_m_multicast
 *
 * Input:   ptr to driver device structure,
 *          boolean describing whether to enable or disable this address,
 *          pointer to buffer containing multicast address.
 *
 * Return:  DDI_SUCCESS or DDI_FAILURE
 *
 * Description:
 *          This function is used to enable or disable multicast packet
 *          reception for particular multicast addresses.
 */
static int
bnx_m_multicast(void * arg, boolean_t multiflag, const uint8_t *multicastaddr)
{
	um_device_t *umdevice;
	int rc;

	umdevice = (um_device_t *)arg;

	mutex_enter(&umdevice->os_param.gld_mutex);

	if (umdevice->dev_start != B_TRUE) {
		rc = EAGAIN;
		goto done;
	}

	switch (multiflag) {
		case B_TRUE:
			rc = bnx_mc_add(umdevice, multicastaddr);
			break;

		case B_FALSE:
			rc = bnx_mc_del(umdevice, multicastaddr);
			break;

		default:
			rc = EINVAL;
			break;
	}

done:
	mutex_exit(&umdevice->os_param.gld_mutex);

	return (rc);
}



/*
 * Name:    bnx_m_promiscuous
 *
 * Input:   ptr to driver device structure,
 *          boolean describing whether to enable or disable promiscuous mode.
 *
 * Return:  DDI_SUCCESS or DDI_FAILURE
 *
 * Description:
 *          This function enables promiscuous mode for this device.
 *		'flags' argument determines the type of mode being set,
 *		"PROMISC_PHY" enables reception of all packet types including
 *		bad/error packets. "PROMISC_MULTI" mode will enable all
 *		multicast packets, unicasts and broadcast packets to be
 *		received. "PROMISC_NONE" will enable only broadcast and
 *		unicast packets.
 */
static int
bnx_m_promiscuous(void *arg, boolean_t promiscflag)
{
	int rc;
	um_device_t *umdevice;

	umdevice = (um_device_t *)arg;

	mutex_enter(&umdevice->os_param.gld_mutex);

	if (umdevice->dev_start != B_TRUE) {
		rc = EAGAIN;
		goto done;
	}

	switch (promiscflag) {
		case B_TRUE:
			umdevice->dev_var.rx_filter_mask |=
			    LM_RX_MASK_PROMISCUOUS_MODE;
			break;

		case B_FALSE:
			umdevice->dev_var.rx_filter_mask &=
			    ~LM_RX_MASK_PROMISCUOUS_MODE;
			break;

		default:
			rc = EINVAL;
			goto done;
	}

	(void) lm_set_rx_mask(&(umdevice->lm_dev), RX_FILTER_USER_IDX0,
	    umdevice->dev_var.rx_filter_mask);

	rc = 0;

done:
	mutex_exit(&umdevice->os_param.gld_mutex);

	return (rc);
}


static mblk_t *
bnx_m_tx(void *arg, mblk_t *mp)
{
	int rc;
	mblk_t *nmp;
	um_device_t *umdevice;

	umdevice = (um_device_t *)arg;

	rw_enter(&umdevice->os_param.gld_snd_mutex, RW_READER);

	if (umdevice->dev_start != B_TRUE ||
	    umdevice->nddcfg.link_speed == 0) {
		freemsgchain(mp);
		mp = NULL;
		goto done;
	}

	nmp = NULL;

	while (mp) {
		/* Save the next pointer, in case we do double copy. */
		nmp = mp->b_next;
		mp->b_next = NULL;

		rc = bnx_xmit_ring_xmit_mblk(umdevice, 0, mp);

		if (rc == BNX_SEND_GOODXMIT) {
			mp = nmp;
			continue;
		}

		if (rc == BNX_SEND_DEFERPKT)
			mp = nmp;
		else
			mp->b_next = nmp;

		break;
	}

done:
	rw_exit(&umdevice->os_param.gld_snd_mutex);

	return (mp);
}


static u64_t
shift_left32(u32_t val)
{
	lm_u64_t tmp;

	/* FIXME -- Get rid of shift_left32() */

	tmp.as_u32.low = 0;
	tmp.as_u32.high = val;

	return (tmp.as_u64);
}



/*
 * Name:    bnx_m_stats
 *
 * Input:   ptr to mac info structure, ptr to gld_stats struct
 *
 * Return:  DDI_SUCCESS or DDI_FAILURE
 *
 * Description: bnx_m_stats() populates gld_stats structure elements
 *              from latest data from statistic block.
 */
static int
bnx_m_stats(void * arg, uint_t stat, uint64_t *val)
{
	int rc;
	um_device_t *umdevice;
	lm_device_t *lmdevice;
	const bnx_lnk_cfg_t *linkconf;

	umdevice = (um_device_t *)arg;

	if (umdevice == NULL || val == NULL) {
		return (EINVAL);
	}

	lmdevice = &(umdevice->lm_dev);

	/* FIXME -- Fix STATS collections */

	if (umdevice->dev_var.isfiber) {
		linkconf = &bnx_serdes_config;
	} else {
		linkconf = &bnx_copper_config;
	}

	mutex_enter(&umdevice->os_param.gld_mutex);

	if (umdevice->dev_start != B_TRUE) {
		rc = EAGAIN;
		goto done;
	}

	*val = 0;
	switch (stat) {
	case MAC_STAT_IFSPEED:
		*val = umdevice->nddcfg.link_speed * 1000000ull;
		break;
	case MAC_STAT_MULTIRCV:
		*val += shift_left32(
		    lmdevice->vars.stats_virt->stat_IfHCInMulticastPkts_hi);
		*val +=
		    lmdevice->vars.stats_virt->stat_IfHCInMulticastPkts_lo;
		break;
	case MAC_STAT_BRDCSTRCV:
		*val += shift_left32(
		    lmdevice->vars.stats_virt->stat_IfHCInBroadcastPkts_hi);
		*val +=
		    lmdevice->vars.stats_virt->stat_IfHCInBroadcastPkts_lo;
		break;
	case MAC_STAT_MULTIXMT:
		*val += shift_left32(
		    lmdevice->vars.stats_virt->stat_IfHCOutMulticastPkts_hi);
		*val +=
		    lmdevice->vars.stats_virt->stat_IfHCOutMulticastPkts_lo;
		break;
	case MAC_STAT_BRDCSTXMT:
		*val += shift_left32(
		    lmdevice->vars.stats_virt->stat_IfHCOutBroadcastPkts_hi);
		*val +=
		    lmdevice->vars.stats_virt->stat_IfHCOutBroadcastPkts_lo;
		break;
	case MAC_STAT_NORCVBUF:
		*val = lmdevice->vars.stats_virt->stat_IfInMBUFDiscards;
		break;
	case ETHER_STAT_MACRCV_ERRORS:
	case MAC_STAT_IERRORS:
		*val = lmdevice->vars.stats_virt->stat_Dot3StatsFCSErrors +
		    lmdevice->vars.stats_virt->stat_Dot3StatsAlignmentErrors +
		    lmdevice->vars.stats_virt->stat_EtherStatsUndersizePkts +
		    lmdevice->vars.stats_virt->stat_EtherStatsOverrsizePkts;
		break;
	case MAC_STAT_OERRORS:
		*val = lmdevice->vars.stats_virt->
		    stat_emac_tx_stat_dot3statsinternalmactransmiterrors;
		break;
	case MAC_STAT_COLLISIONS:
		*val = lmdevice->vars.stats_virt->stat_EtherStatsCollisions;
		break;
	case MAC_STAT_RBYTES:
		*val += shift_left32(
		    lmdevice->vars.stats_virt->stat_IfHCInOctets_hi);
		*val +=
		    lmdevice->vars.stats_virt->stat_IfHCInOctets_lo;
		break;
	case MAC_STAT_IPACKETS:
		*val += shift_left32(lmdevice->vars.stats_virt->
		    stat_IfHCInUcastPkts_hi);
		*val += lmdevice->vars.stats_virt->stat_IfHCInUcastPkts_lo;

		*val += shift_left32(lmdevice->vars.stats_virt->
		    stat_IfHCInMulticastPkts_hi);
		*val += lmdevice->vars.stats_virt->stat_IfHCInMulticastPkts_lo;

		*val += shift_left32(lmdevice->vars.stats_virt->
		    stat_IfHCInBroadcastPkts_hi);
		*val += lmdevice->vars.stats_virt->stat_IfHCInBroadcastPkts_lo;
		break;
	case MAC_STAT_OBYTES:
		*val += shift_left32(
		    lmdevice->vars.stats_virt->stat_IfHCOutOctets_hi);
		*val +=
		    lmdevice->vars.stats_virt->stat_IfHCOutOctets_lo;
		break;
	case MAC_STAT_OPACKETS:
		*val += shift_left32(lmdevice->vars.stats_virt->
		    stat_IfHCOutUcastPkts_hi);
		*val += lmdevice->vars.stats_virt->stat_IfHCOutUcastPkts_lo;

		*val += shift_left32(lmdevice->vars.stats_virt->
		    stat_IfHCOutMulticastPkts_hi);
		*val += lmdevice->vars.stats_virt->stat_IfHCOutMulticastPkts_lo;

		*val += shift_left32(lmdevice->vars.stats_virt->
		    stat_IfHCOutBroadcastPkts_hi);
		*val += lmdevice->vars.stats_virt->stat_IfHCOutBroadcastPkts_lo;
		break;
	case ETHER_STAT_ALIGN_ERRORS:
		*val = lmdevice->vars.stats_virt->stat_Dot3StatsAlignmentErrors;
		break;
	case ETHER_STAT_FCS_ERRORS:
		*val = lmdevice->vars.stats_virt->stat_Dot3StatsFCSErrors;
		break;
	case ETHER_STAT_FIRST_COLLISIONS:
		*val = lmdevice->vars.stats_virt->
		    stat_Dot3StatsSingleCollisionFrames;
		break;
	case ETHER_STAT_MULTI_COLLISIONS:
		*val = lmdevice->vars.stats_virt->
		    stat_Dot3StatsMultipleCollisionFrames;
		break;
	case ETHER_STAT_DEFER_XMTS:
		*val = lmdevice->vars.stats_virt->
		    stat_Dot3StatsDeferredTransmissions;
		break;
	case ETHER_STAT_TX_LATE_COLLISIONS:
		*val = lmdevice->vars.stats_virt->
		    stat_Dot3StatsLateCollisions;
		break;
	case ETHER_STAT_EX_COLLISIONS:
		*val = lmdevice->vars.stats_virt->
		    stat_Dot3StatsExcessiveCollisions;
		break;
	case ETHER_STAT_MACXMT_ERRORS:
		*val = lmdevice->vars.stats_virt->
		    stat_emac_tx_stat_dot3statsinternalmactransmiterrors;
		break;
	case ETHER_STAT_CARRIER_ERRORS:
		*val = lmdevice->vars.stats_virt->
		    stat_Dot3StatsCarrierSenseErrors;
		break;
	case ETHER_STAT_TOOLONG_ERRORS:
		*val = lmdevice->vars.stats_virt->
		    stat_EtherStatsOverrsizePkts;
		break;
#if (MAC_VERSION > 1)
	case ETHER_STAT_TOOSHORT_ERRORS:
		*val = lmdevice->vars.stats_virt->
		    stat_EtherStatsUndersizePkts;
		break;
#endif
	case ETHER_STAT_XCVR_ADDR:
		*val = lmdevice->params.phy_addr;
		break;
	case ETHER_STAT_XCVR_ID:
		*val = lmdevice->hw_info.phy_id;
		break;
	case ETHER_STAT_XCVR_INUSE:
		switch (umdevice->nddcfg.link_speed) {
		case 1000:
			*val = (umdevice->dev_var.isfiber) ?
			    XCVR_1000X : XCVR_1000T;
			break;
		case 100:
			*val = XCVR_100X;
			break;
		case 10:
			*val = XCVR_10;
			break;
		default:
			*val = XCVR_NONE;
			break;
		}
		break;
	case ETHER_STAT_CAP_1000FDX:
		*val = 1;
		break;
	case ETHER_STAT_CAP_1000HDX:
		*val = linkconf->param_1000hdx;
		break;
	case ETHER_STAT_CAP_100FDX:
		*val = linkconf->param_100fdx;
		break;
	case ETHER_STAT_CAP_100HDX:
		*val = linkconf->param_100hdx;
		break;
	case ETHER_STAT_CAP_10FDX:
		*val = linkconf->param_10fdx;
		break;
	case ETHER_STAT_CAP_10HDX:
		*val = linkconf->param_10hdx;
		break;
	case ETHER_STAT_CAP_ASMPAUSE:
		*val = 1;
		break;
	case ETHER_STAT_CAP_PAUSE:
		*val = 1;
		break;
	case ETHER_STAT_CAP_AUTONEG:
		*val = 1;
		break;
#if (MAC_VERSION > 1)
	case ETHER_STAT_CAP_REMFAULT:
		*val = 1;
		break;
#endif
	case ETHER_STAT_ADV_CAP_1000FDX:
		*val = umdevice->curcfg.lnkcfg.param_1000fdx;
		break;
	case ETHER_STAT_ADV_CAP_1000HDX:
		*val = umdevice->curcfg.lnkcfg.param_1000hdx;
		break;
	case ETHER_STAT_ADV_CAP_100FDX:
		*val = umdevice->curcfg.lnkcfg.param_100fdx;
		break;
	case ETHER_STAT_ADV_CAP_100HDX:
		*val = umdevice->curcfg.lnkcfg.param_100hdx;
		break;
	case ETHER_STAT_ADV_CAP_10FDX:
		*val = umdevice->curcfg.lnkcfg.param_10fdx;
		break;
	case ETHER_STAT_ADV_CAP_10HDX:
		*val = umdevice->curcfg.lnkcfg.param_10hdx;
		break;
	case ETHER_STAT_ADV_CAP_ASMPAUSE:
		*val = 1;
		break;
	case ETHER_STAT_ADV_CAP_PAUSE:
		*val = 1;
		break;
	case ETHER_STAT_ADV_CAP_AUTONEG:
		*val = umdevice->curcfg.lnkcfg.link_autoneg;
		break;
#if (MAC_VERSION > 1)
	case ETHER_STAT_ADV_REMFAULT:
		*val = 1;
		break;
#endif
	case ETHER_STAT_LP_CAP_1000FDX:
		*val = umdevice->remote.param_1000fdx;
		break;
	case ETHER_STAT_LP_CAP_1000HDX:
		*val = umdevice->remote.param_1000hdx;
		break;
	case ETHER_STAT_LP_CAP_100FDX:
		*val = umdevice->remote.param_100fdx;
		break;
	case ETHER_STAT_LP_CAP_100HDX:
		*val = umdevice->remote.param_100hdx;
		break;
	case ETHER_STAT_LP_CAP_10FDX:
		*val = umdevice->remote.param_10fdx;
		break;
	case ETHER_STAT_LP_CAP_10HDX:
		*val = umdevice->remote.param_10hdx;
		break;
	case ETHER_STAT_LP_CAP_ASMPAUSE:
		/* FIXME -- Implement LP_ASYM_PAUSE stat */
		break;
	case ETHER_STAT_LP_CAP_PAUSE:
		/* FIXME -- Implement LP_PAUSE stat */
		break;
	case ETHER_STAT_LP_CAP_AUTONEG:
		*val = umdevice->remote.link_autoneg;
		break;
#if (MAC_VERSION > 1)
	case ETHER_STAT_LP_REMFAULT:
		/* FIXME -- Implement LP_REMFAULT stat */
		break;
#endif
	case ETHER_STAT_LINK_ASMPAUSE:
		/* FIXME -- Implement ASMPAUSE stat */
		break;
	case ETHER_STAT_LINK_PAUSE:
		/* FIXME -- Implement PAUSE stat */
		break;
	case ETHER_STAT_LINK_AUTONEG:
		*val = umdevice->curcfg.lnkcfg.link_autoneg;
		break;
	case ETHER_STAT_LINK_DUPLEX:
		*val = umdevice->nddcfg.link_duplex == B_TRUE ?
		    LINK_DUPLEX_FULL: LINK_DUPLEX_HALF;
		break;
	default:
		rc = ENOTSUP;
	}

	rc = 0;

done:
	mutex_exit(&umdevice->os_param.gld_mutex);

	return (rc);
}

static boolean_t
bnx_m_getcapab(void *arg, mac_capab_t cap, void *cap_data)
{
	um_device_t *umdevice;

	umdevice = (um_device_t *)arg;

	switch (cap) {
	case MAC_CAPAB_HCKSUM: {
		uint32_t *txflags = cap_data;

		*txflags = 0;

		if (umdevice->dev_var.enabled_oflds &
		    (LM_OFFLOAD_TX_IP_CKSUM | LM_OFFLOAD_RX_IP_CKSUM)) {
			*txflags |= HCKSUM_IPHDRCKSUM;
		}

		if (umdevice->dev_var.enabled_oflds &
		    (LM_OFFLOAD_TX_TCP_CKSUM | LM_OFFLOAD_TX_UDP_CKSUM |
		    LM_OFFLOAD_RX_TCP_CKSUM | LM_OFFLOAD_RX_UDP_CKSUM)) {
			*txflags |= HCKSUM_INET_FULL_V4;
		}
		break;
	}
	default:
		return (B_FALSE);
	}

	return (B_TRUE);
}

static int
bnx_refresh_rx_tx_pkts(um_device_t *umdevice)
{
	if (umdevice->os_param.active_resc_flag & DRV_RESOURCE_HDWR_REGISTER) {
		bnx_hdwr_fini(umdevice);
		/*
		 * Initialize the adapter resource.  Mainly allocating memory
		 * needed by the driver, such as packet descriptors, shared
		 * memory, etc.
		 */
		if (lm_init_resc(&(umdevice->lm_dev)) != LM_STATUS_SUCCESS) {
			return (EIO);
		}

		if (bnx_txpkts_init(umdevice)) {
			return (EIO);
		}

		if (bnx_rxpkts_init(umdevice)) {
			return (EIO);
		}
	}
	return (0);
}

static int
bnx_set_priv_prop(um_device_t *umdevice, const char *pr_name,
    uint_t pr_valsize, const void *pr_val)
{
	boolean_t refresh = B_FALSE;
	long result;
	int err = 0;

	if (strcmp(pr_name, "_adv_2500fdx_cap") == 0) {
		if (lm_get_medium(&umdevice->lm_dev) != LM_MEDIUM_TYPE_FIBER) {
			return (ENOTSUP);
		}
		if (ddi_strtol(pr_val, (char **)NULL, 0, &result)) {
			return (EINVAL);
		}
		if (result != 1 && result != 0) {
			return (EINVAL);
		}
		if (umdevice->hwinit.lnkcfg.param_2500fdx != (uint32_t)result) {
			umdevice->hwinit.lnkcfg.param_2500fdx =
			    (uint32_t)result;
			umdevice->curcfg.lnkcfg.param_2500fdx =
			    (uint32_t)result;
			bnx_update_phy(umdevice);
		}
	} else if (strcmp(pr_name, "_checksum") == 0) {
		if (umdevice->dev_start == B_TRUE) {
			return (EBUSY);
		}
		if (ddi_strtol(pr_val, (char **)NULL, 0, &result)) {
			return (EINVAL);
		}
		switch (result) {
			case USER_OPTION_CKSUM_TX_ONLY:
				umdevice->dev_var.enabled_oflds =
				    LM_OFFLOAD_TX_IP_CKSUM |
				    LM_OFFLOAD_TX_TCP_CKSUM |
				    LM_OFFLOAD_TX_UDP_CKSUM;
				break;

			case USER_OPTION_CKSUM_RX_ONLY:
				umdevice->dev_var.enabled_oflds =
				    LM_OFFLOAD_RX_IP_CKSUM |
				    LM_OFFLOAD_RX_TCP_CKSUM |
				    LM_OFFLOAD_RX_UDP_CKSUM;
				break;

			case USER_OPTION_CKSUM_TX_RX:
				umdevice->dev_var.enabled_oflds =
				    LM_OFFLOAD_TX_IP_CKSUM |
				    LM_OFFLOAD_RX_IP_CKSUM |
				    LM_OFFLOAD_TX_TCP_CKSUM |
				    LM_OFFLOAD_RX_TCP_CKSUM |
				    LM_OFFLOAD_TX_UDP_CKSUM |
				    LM_OFFLOAD_RX_UDP_CKSUM;
				break;

			case USER_OPTION_CKSUM_NONE:
				umdevice->dev_var.enabled_oflds =
				    LM_OFFLOAD_NONE;
				break;

			default:
				return (EINVAL);
		}
	} else if (strcmp(pr_name, "_tx_descriptor_count") == 0) {
		if (umdevice->dev_start == B_TRUE) {
			return (EBUSY);
		}
		if (ddi_strtol(pr_val, (char **)NULL, 0, &result)) {
			return (EINVAL);
		}
		if (result < USER_OPTION_TX_DESC_CNT_MIN ||
		    result > USER_OPTION_TX_DESC_CNT_MAX) {
			return (EINVAL);
		}
		_TX_QINFO(umdevice, 0).desc_cnt = result;
		umdevice->lm_dev.params.l2_tx_bd_page_cnt[0] =
		    result / MAX_BD_PER_PAGE;
		if (result % MAX_BD_PER_PAGE) {
			umdevice->lm_dev.params.l2_tx_bd_page_cnt[0]++;
		}
		if (umdevice->lm_dev.params.l2_tx_bd_page_cnt[0] > 127) {
			umdevice->lm_dev.params.l2_tx_bd_page_cnt[0] = 127;
		}
		refresh = B_TRUE;
	} else if (strcmp(pr_name, "_rx_descriptor_count") == 0) {
		if (umdevice->dev_start == B_TRUE) {
			return (EBUSY);
		}
		if (ddi_strtol(pr_val, (char **)NULL, 0, &result)) {
			return (EINVAL);
		}
		if (result < USER_OPTION_RX_DESC_CNT_MIN ||
		    result > USER_OPTION_RX_DESC_CNT_MAX) {
			return (EINVAL);
		}
		umdevice->lm_dev.params.l2_rx_desc_cnt[0] = result;
		result = (result * BNX_RECV_MAX_FRAGS) / MAX_BD_PER_PAGE;
		umdevice->lm_dev.params.l2_rx_bd_page_cnt[0] = result;
		if (result % MAX_BD_PER_PAGE) {
			umdevice->lm_dev.params.l2_rx_bd_page_cnt[0]++;
		}
		refresh = B_TRUE;
	}
#if 0
	/* Initialized by init_hc() */
	else if (strcmp(pr_name, "_tx_coalesce_ticks") == 0) {
		if (umdevice->dev_start == B_TRUE) {
			return (EBUSY);
		}
		if (ddi_strtol(pr_val, (char **)NULL, 0, &result)) {
			return (EINVAL);
		}
		if (result < USER_OPTION_TICKS_MIN ||
		    result > USER_OPTION_TICKS_MAX) {
			return (EINVAL);
		}
		umdevice->lm_dev.params.tx_ticks = result;
	} else if (strcmp(pr_name, "_tx_coalesce_ticks_int") == 0) {
		if (umdevice->dev_start == B_TRUE) {
			return (EBUSY);
		}
		if (ddi_strtol(pr_val, (char **)NULL, 0, &result)) {
			return (EINVAL);
		}
		if (result < USER_OPTION_TICKS_INT_MIN ||
		    result > USER_OPTION_TICKS_INT_MAX) {
			return (EINVAL);
		}
		umdevice->lm_dev.params.tx_ticks_int = result;
	} else if (strcmp(pr_name, "_rx_coalesce_ticks") == 0) {
		if (umdevice->dev_start == B_TRUE) {
			return (EBUSY);
		}
		if (ddi_strtol(pr_val, (char **)NULL, 0, &result)) {
			return (EINVAL);
		}
		if (result < USER_OPTION_TICKS_MIN ||
		    result > USER_OPTION_TICKS_MAX) {
			return (EINVAL);
		}
		umdevice->lm_dev.params.rx_ticks = result;
	} else if (strcmp(pr_name, "_rx_coalesce_ticks_int") == 0) {
		if (umdevice->dev_start == B_TRUE) {
			return (EBUSY);
		}
		if (ddi_strtol(pr_val, (char **)NULL, 0, &result)) {
			return (EINVAL);
		}
		if (result < USER_OPTION_TICKS_INT_MIN ||
		    result > USER_OPTION_TICKS_INT_MAX) {
			return (EINVAL);
		}
		umdevice->lm_dev.params.rx_ticks_int = result;
	} else if (strcmp(pr_name, "_tx_coalesce_frames") == 0) {
		if (umdevice->dev_start == B_TRUE) {
			return (EBUSY);
		}
		if (ddi_strtol(pr_val, (char **)NULL, 0, &result)) {
			return (EINVAL);
		}
		if (result < USER_OPTION_FRAMES_MIN ||
		    result > USER_OPTION_FRAMES_MAX) {
			return (EINVAL);
		}
		umdevice->lm_dev.params.tx_quick_cons_trip = result;
	} else if (strcmp(pr_name, "_tx_coalesce_frames_int") == 0) {
		if (umdevice->dev_start == B_TRUE) {
			return (EBUSY);
		}
		if (ddi_strtol(pr_val, (char **)NULL, 0, &result)) {
			return (EINVAL);
		}
		if (result < USER_OPTION_FRAMES_MIN ||
		    result > USER_OPTION_FRAMES_MAX) {
			return (EINVAL);
		}
		umdevice->lm_dev.params.tx_quick_cons_trip_int = result;
	} else if (strcmp(pr_name, "_rx_coalesce_frames") == 0) {
		if (umdevice->dev_start == B_TRUE) {
			return (EBUSY);
		}
		if (ddi_strtol(pr_val, (char **)NULL, 0, &result)) {
			return (EINVAL);
		}
		if (result < USER_OPTION_FRAMES_MIN ||
		    result > USER_OPTION_FRAMES_MAX) {
			return (EINVAL);
		}
		umdevice->lm_dev.params.rx_quick_cons_trip = result;
	} else if (strcmp(pr_name, "_rx_coalesce_frames_int") == 0) {
		if (umdevice->dev_start == B_TRUE) {
			return (EBUSY);
		}
		if (ddi_strtol(pr_val, (char **)NULL, 0, &result)) {
			return (EINVAL);
		}
		if (result < USER_OPTION_FRAMES_MIN ||
		    result > USER_OPTION_FRAMES_MAX) {
			return (EINVAL);
		}
		umdevice->lm_dev.params.rx_quick_cons_trip_int = result;
	} else if (strcmp(pr_name, "_statticks") == 0) {
		if (umdevice->dev_start == B_TRUE) {
			return (EBUSY);
		}
		if (ddi_strtol(pr_val, (char **)NULL, 0, &result)) {
			return (EINVAL);
		}
		if (result < USER_OPTION_STATSTICKS_MIN ||
		    result > USER_OPTION_STATSTICKS_MAX) {
			return (EINVAL);
		}
		umdevice->lm_dev.params.stats_ticks = result;
	}
#endif
	else if (strcmp(pr_name, "_disable_msix") == 0) {
		err = ENOTSUP;
	} else {
		err = ENOTSUP;
	}

	if (!err && refresh) {
		err = bnx_refresh_rx_tx_pkts(umdevice);
	}
	return (err);
}


static int
bnx_m_setprop(void *arg, const char *pr_name, mac_prop_id_t pr_num,
    uint_t pr_valsize, const void *pr_val)
{
	um_device_t *umdevice = arg;
	boolean_t reprogram = B_FALSE;
	boolean_t rxpause;
	boolean_t txpause;
	uint32_t mtu;
	link_flowctrl_t fl;
	int err = 0;

	mutex_enter(&umdevice->os_param.gld_mutex);

	if (lm_get_medium(&umdevice->lm_dev) == LM_MEDIUM_TYPE_FIBER) {
		if (pr_num == MAC_PROP_EN_100FDX_CAP ||
		    pr_num == MAC_PROP_EN_100HDX_CAP ||
		    pr_num == MAC_PROP_EN_10FDX_CAP ||
		    pr_num == MAC_PROP_EN_10HDX_CAP) {
			mutex_exit(&umdevice->os_param.gld_mutex);
			return (ENOTSUP);
		}
	}

	switch (pr_num) {
		/* read-only properties */
		case MAC_PROP_ADV_1000FDX_CAP:
		case MAC_PROP_ADV_1000HDX_CAP:
		case MAC_PROP_ADV_100FDX_CAP:
		case MAC_PROP_ADV_100HDX_CAP:
		case MAC_PROP_ADV_10FDX_CAP:
		case MAC_PROP_ADV_10HDX_CAP:
		case MAC_PROP_STATUS:
		case MAC_PROP_SPEED:
		case MAC_PROP_DUPLEX:
		default:

			err = ENOTSUP;
			break;


/* BEGIN CSTYLED */
#define	BNX_SETPROP_CASE(cap, param)							\
		case cap:								\
			if (umdevice->hwinit.lnkcfg.param != *(uint8_t *)pr_val) {	\
				umdevice->hwinit.lnkcfg.param = *(uint8_t *)pr_val;	\
				umdevice->curcfg.lnkcfg.param = *(uint8_t *)pr_val;	\
				reprogram = B_TRUE;					\
			}								\
			break
/* END CSTYLED */


		BNX_SETPROP_CASE(MAC_PROP_EN_1000FDX_CAP, param_1000fdx);
		BNX_SETPROP_CASE(MAC_PROP_EN_1000HDX_CAP, param_1000hdx);
		BNX_SETPROP_CASE(MAC_PROP_EN_100FDX_CAP, param_100fdx);
		BNX_SETPROP_CASE(MAC_PROP_EN_100HDX_CAP, param_100hdx);
		BNX_SETPROP_CASE(MAC_PROP_EN_10FDX_CAP, param_10fdx);
		BNX_SETPROP_CASE(MAC_PROP_EN_10HDX_CAP, param_10hdx);
		BNX_SETPROP_CASE(MAC_PROP_AUTONEG, link_autoneg);

		case MAC_PROP_FLOWCTRL:
			bcopy(pr_val, &fl, sizeof (fl));
			switch (fl) {
				case LINK_FLOWCTRL_NONE:

					rxpause = B_FALSE;
					txpause = B_FALSE;
					break;

				case LINK_FLOWCTRL_RX:

					rxpause = B_TRUE;
					txpause = B_FALSE;
					break;

				case LINK_FLOWCTRL_TX:

					rxpause = B_FALSE;
					txpause = B_TRUE;
					break;

				case LINK_FLOWCTRL_BI:

					rxpause = B_TRUE;
					txpause = B_TRUE;
					break;

				default:

					err = ENOTSUP;
					break;
			}

			if (err == 0) {
				if (umdevice->hwinit.lnkcfg.param_tx_pause !=
				    txpause ||
				    umdevice->hwinit.lnkcfg.param_rx_pause !=
				    rxpause) {
					umdevice->hwinit.lnkcfg.param_tx_pause =
					    txpause;
					umdevice->hwinit.lnkcfg.param_rx_pause =
					    rxpause;
					umdevice->curcfg.lnkcfg.param_tx_pause =
					    txpause;
					umdevice->curcfg.lnkcfg.param_rx_pause =
					    rxpause;
					reprogram = B_TRUE;
				}
			}

			break;

		case MAC_PROP_MTU:
			if (umdevice->dev_start == B_TRUE) {
				err = EBUSY;
				break;
			}

			bcopy(pr_val, &mtu, sizeof (mtu));

			if (mtu < USER_OPTION_MTU_MIN ||
			    mtu > USER_OPTION_MTU_MAX) {
				err = EINVAL;
				break;
			}

			if (umdevice->dev_var.mtu == mtu) {
				break;
			}

			umdevice->dev_var.mtu = mtu;
			umdevice->lm_dev.params.mtu = umdevice->dev_var.mtu
			    + sizeof (struct ether_header) + VLAN_TAGSZ;

			if (bnx_refresh_rx_tx_pkts(umdevice) != 0) {
				err = EIO;
			} else {
				reprogram = B_TRUE;
			}
			break;

		case MAC_PROP_PRIVATE:
			err = bnx_set_priv_prop(umdevice, pr_name, pr_valsize,
			    pr_val);
			reprogram = B_TRUE;
			break;
	}

	if (!err && reprogram) {
		bnx_update_phy(umdevice);
	}

	mutex_exit(&umdevice->os_param.gld_mutex);

	return (err);
}

static int
bnx_get_priv_prop(um_device_t *umdevice, const char *pr_name,
    uint_t pr_valsize, void *pr_val)
{
	int value;

	if (strcmp(pr_name, "_adv_2500fdx_cap") == 0) {
		if (lm_get_medium(&umdevice->lm_dev) !=
		    LM_MEDIUM_TYPE_FIBER) {
			return (ENOTSUP);
		}
		value = umdevice->curcfg.lnkcfg.param_2500fdx;
	} else if (strcmp(pr_name, "_checksum") == 0) {
		value = umdevice->dev_var.enabled_oflds;
	} else if (strcmp(pr_name, "_tx_descriptor_count") == 0) {
		value = _TX_QINFO(umdevice, 0).desc_cnt;
	} else if (strcmp(pr_name, "_rx_descriptor_count") == 0) {
		value = umdevice->lm_dev.params.l2_rx_desc_cnt[0];
	} else if (strcmp(pr_name, "_tx_coalesce_ticks") == 0) {
		value = umdevice->lm_dev.params.tx_ticks;
	} else if (strcmp(pr_name, "_tx_coalesce_ticks_int") == 0) {
		value = umdevice->lm_dev.params.tx_ticks_int;
	} else if (strcmp(pr_name, "_rx_coalesce_ticks") == 0) {
		value = umdevice->lm_dev.params.rx_ticks;
	} else if (strcmp(pr_name, "_rx_coalesce_ticks_int") == 0) {
		value = umdevice->lm_dev.params.rx_ticks_int;
	} else if (strcmp(pr_name, "_tx_coalesce_frames") == 0) {
		value = umdevice->lm_dev.params.tx_quick_cons_trip;
	} else if (strcmp(pr_name, "_tx_coalesce_frames_int") == 0) {
		value = umdevice->lm_dev.params.tx_quick_cons_trip_int;
	} else if (strcmp(pr_name, "_rx_coalesce_frames") == 0) {
		value = umdevice->lm_dev.params.rx_quick_cons_trip;
	} else if (strcmp(pr_name, "_rx_coalesce_frames_int") == 0) {
		value = umdevice->lm_dev.params.rx_quick_cons_trip_int;
	} else if (strcmp(pr_name, "_statticks") == 0) {
		value = umdevice->lm_dev.params.stats_ticks;
	} else if (strcmp(pr_name, "_disable_msix") == 0) {
		value = umdevice->dev_var.disableMsix;
	} else {
		return (ENOTSUP);
	}

	(void) snprintf(pr_val, pr_valsize, "%d", value);
	return (0);

}

static int
bnx_m_getprop(void *arg, const char *pr_name, mac_prop_id_t pr_num,
    uint_t pr_valsize, void *pr_val)
{
	um_device_t *umdevice = arg;
	link_duplex_t link_duplex;
	uint64_t link_speed;
	link_state_t link_state;
	link_flowctrl_t fl;

	if (lm_get_medium(&umdevice->lm_dev) == LM_MEDIUM_TYPE_FIBER) {
		if (pr_num == MAC_PROP_EN_100FDX_CAP ||
		    pr_num == MAC_PROP_EN_100HDX_CAP ||
		    pr_num == MAC_PROP_EN_10FDX_CAP ||
		    pr_num == MAC_PROP_EN_10HDX_CAP) {
			return (ENOTSUP);
		}
	}

	switch (pr_num) {
		case MAC_PROP_DUPLEX:
			link_duplex = umdevice->nddcfg.link_duplex == B_TRUE ?
			    LINK_DUPLEX_FULL: LINK_DUPLEX_HALF;

			ASSERT(pr_valsize >= sizeof (link_duplex_t));

			bcopy(&link_duplex, pr_val, sizeof (link_duplex_t));
			break;

		case MAC_PROP_SPEED:
			link_speed = umdevice->nddcfg.link_speed * 1000000ull;

			ASSERT(pr_valsize >= sizeof (link_speed));

			bcopy(&link_speed, pr_val, sizeof (link_speed));
			break;

		case MAC_PROP_STATUS:
			link_state = umdevice->nddcfg.link_speed ?
			    LINK_STATE_UP : LINK_STATE_DOWN;

			ASSERT(pr_valsize >= sizeof (link_state_t));

			bcopy(&link_state, pr_val, sizeof (link_state));
			break;

		case MAC_PROP_AUTONEG:
			*(uint8_t *)pr_val =
			    umdevice->curcfg.lnkcfg.link_autoneg;
			break;

		case MAC_PROP_FLOWCTRL:
			ASSERT(pr_valsize >= sizeof (fl));

			boolean_t txpause =
			    umdevice->curcfg.lnkcfg.param_tx_pause;
			boolean_t rxpause =
			    umdevice->curcfg.lnkcfg.param_rx_pause;
			if (txpause) {
				if (rxpause) {
					fl = LINK_FLOWCTRL_BI;
				} else {
					fl = LINK_FLOWCTRL_TX;
				}
			} else {
				if (rxpause) {
					fl = LINK_FLOWCTRL_RX;
				} else {
					fl = LINK_FLOWCTRL_NONE;
				}
			}
			bcopy(&fl, pr_val, sizeof (fl));
			break;

		case MAC_PROP_ADV_1000FDX_CAP:
			*(uint8_t *)pr_val =
			    umdevice->curcfg.lnkcfg.param_1000fdx;
			break;

		case MAC_PROP_EN_1000FDX_CAP:
			*(uint8_t *)pr_val =
			    umdevice->curcfg.lnkcfg.param_1000fdx;
			break;

		case MAC_PROP_ADV_1000HDX_CAP:
			*(uint8_t *)pr_val =
			    umdevice->curcfg.lnkcfg.param_1000hdx;
			break;

		case MAC_PROP_EN_1000HDX_CAP:
			*(uint8_t *)pr_val =
			    umdevice->curcfg.lnkcfg.param_1000hdx;
			break;

		case MAC_PROP_ADV_100FDX_CAP:
			*(uint8_t *)pr_val =
			    umdevice->curcfg.lnkcfg.param_100fdx;
			break;

		case MAC_PROP_EN_100FDX_CAP:
			*(uint8_t *)pr_val =
			    umdevice->curcfg.lnkcfg.param_100fdx;
			break;

		case MAC_PROP_ADV_100HDX_CAP:
			*(uint8_t *)pr_val =
			    umdevice->curcfg.lnkcfg.param_100hdx;
			break;

		case MAC_PROP_EN_100HDX_CAP:
			*(uint8_t *)pr_val =
			    umdevice->curcfg.lnkcfg.param_100hdx;
			break;

		case MAC_PROP_ADV_10FDX_CAP:
			*(uint8_t *)pr_val =
			    umdevice->curcfg.lnkcfg.param_10fdx;
			break;

		case MAC_PROP_EN_10FDX_CAP:
			*(uint8_t *)pr_val =
			    umdevice->curcfg.lnkcfg.param_10fdx;
			break;

		case MAC_PROP_ADV_10HDX_CAP:
			*(uint8_t *)pr_val =
			    umdevice->curcfg.lnkcfg.param_10hdx;
			break;

		case MAC_PROP_EN_10HDX_CAP:
			*(uint8_t *)pr_val =
			    umdevice->curcfg.lnkcfg.param_10hdx;
			break;

		case MAC_PROP_PRIVATE:
			return (bnx_get_priv_prop(umdevice, pr_name, pr_valsize,
			    pr_val));

		default:

			return (ENOTSUP);

	}

	return (0);

}

static void
bnx_priv_propinfo(um_device_t *umdevice, const char *pr_name,
    mac_prop_info_handle_t prh)
{
	char valstr[64];
	int value;

	if (strcmp(pr_name, "_adv_2500fdx_cap") == 0) {
		if (lm_get_medium(&umdevice->lm_dev) != LM_MEDIUM_TYPE_FIBER) {
			return;
		}
		value = umdevice->curcfg.lnkcfg.param_2500fdx;
	} else if (strcmp(pr_name, "_checksum") == 0) {
		value = umdevice->dev_var.enabled_oflds;
	} else if (strcmp(pr_name, "_tx_descriptor_count") == 0) {
		value = _TX_QINFO(umdevice, 0).desc_cnt;
	} else if (strcmp(pr_name, "_rx_descriptor_count") == 0) {
		value = umdevice->lm_dev.params.l2_rx_desc_cnt[0];
	} else if (strcmp(pr_name, "_tx_coalesce_ticks") == 0) {
		value = umdevice->lm_dev.params.tx_ticks;
	} else if (strcmp(pr_name, "_tx_coalesce_ticks_int") == 0) {
		value = umdevice->lm_dev.params.tx_ticks_int;
	} else if (strcmp(pr_name, "_rx_coalesce_ticks") == 0) {
		value = umdevice->lm_dev.params.rx_ticks;
	} else if (strcmp(pr_name, "_rx_coalesce_ticks_int") == 0) {
		value = umdevice->lm_dev.params.rx_ticks_int;
	} else if (strcmp(pr_name, "_tx_coalesce_frames") == 0) {
		value = umdevice->lm_dev.params.tx_quick_cons_trip;
	} else if (strcmp(pr_name, "_tx_coalesce_frames_int") == 0) {
		value = umdevice->lm_dev.params.tx_quick_cons_trip_int;
	} else if (strcmp(pr_name, "_rx_coalesce_frames") == 0) {
		value = umdevice->lm_dev.params.rx_quick_cons_trip;
	} else if (strcmp(pr_name, "_rx_coalesce_frames_int") == 0) {
		value = umdevice->lm_dev.params.rx_quick_cons_trip_int;
	} else if (strcmp(pr_name, "_statticks") == 0) {
		value = umdevice->lm_dev.params.stats_ticks;
	} else if (strcmp(pr_name, "_disable_msix") == 0) {
		value = umdevice->dev_var.disableMsix;
	} else {
		return;
	}

	(void) snprintf(valstr, sizeof (valstr), "%d", value);
	mac_prop_info_set_default_str(prh, valstr);

}

static void
bnx_m_propinfo(void *arg, const char *pr_name, mac_prop_id_t pr_num,
    mac_prop_info_handle_t prh)
{
	um_device_t *umdevice = arg;

	if (lm_get_medium(&umdevice->lm_dev) == LM_MEDIUM_TYPE_FIBER) {
		if (pr_num == MAC_PROP_EN_100FDX_CAP ||
		    pr_num == MAC_PROP_ADV_100FDX_CAP ||
		    pr_num == MAC_PROP_EN_100HDX_CAP ||
		    pr_num == MAC_PROP_ADV_100HDX_CAP ||
		    pr_num == MAC_PROP_EN_10FDX_CAP ||
		    pr_num == MAC_PROP_ADV_10FDX_CAP ||
		    pr_num == MAC_PROP_EN_10HDX_CAP ||
		    pr_num == MAC_PROP_ADV_10HDX_CAP) {
			mac_prop_info_set_default_uint8(prh, 0);
			return;
		}
	}
	switch (pr_num) {
		case MAC_PROP_ADV_1000FDX_CAP:
		case MAC_PROP_ADV_1000HDX_CAP:
		case MAC_PROP_ADV_100FDX_CAP:
		case MAC_PROP_ADV_100HDX_CAP:
		case MAC_PROP_ADV_10FDX_CAP:
		case MAC_PROP_ADV_10HDX_CAP:
		case MAC_PROP_STATUS:
		case MAC_PROP_SPEED:
		case MAC_PROP_DUPLEX:

			mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
			break;

		case MAC_PROP_EN_1000FDX_CAP:

			mac_prop_info_set_default_uint8(prh, 1);
			break;

		case MAC_PROP_EN_1000HDX_CAP:
		case MAC_PROP_EN_100FDX_CAP:
		case MAC_PROP_EN_100HDX_CAP:
		case MAC_PROP_EN_10FDX_CAP:
		case MAC_PROP_EN_10HDX_CAP:

			if (lm_get_medium(&umdevice->lm_dev) ==
			    LM_MEDIUM_TYPE_FIBER) {
				mac_prop_info_set_default_uint8(prh, 0);
			} else {
				mac_prop_info_set_default_uint8(prh, 1);
			}
			break;

		case MAC_PROP_AUTONEG:

			mac_prop_info_set_default_uint8(prh, 1);
			break;

		case MAC_PROP_FLOWCTRL:

			mac_prop_info_set_default_link_flowctrl(prh,
			    LINK_FLOWCTRL_BI);
			break;

		case MAC_PROP_MTU:

			mac_prop_info_set_range_uint32(prh,
			    USER_OPTION_MTU_MIN, USER_OPTION_MTU_MAX);
			break;

		case MAC_PROP_PRIVATE:

			bnx_priv_propinfo(umdevice, pr_name, prh);
			break;
		default:
			break;
	}
}

static mac_callbacks_t bnx_callbacks = {
	(MC_GETCAPAB | MC_SETPROP | MC_GETPROP| MC_PROPINFO),
	bnx_m_stats,
	bnx_m_start,
	bnx_m_stop,
	bnx_m_promiscuous,
	bnx_m_multicast,
	bnx_m_unicast,
	bnx_m_tx,
	NULL,
	NULL,
	bnx_m_getcapab,
	NULL,
	NULL,
	bnx_m_setprop,
	bnx_m_getprop,
	bnx_m_propinfo
};



/*
 * Name:    bnx_gld_init
 *
 * Input:   ptr to device structure.
 *
 * Return:  DDI_SUCCESS or DDI_FAILURE
 *
 * Description:
 *          This routine populates mac info structure for this device
 *          instance and registers device with GLD.
 */
int
bnx_gld_init(um_device_t *const umdevice)
{
	mac_register_t *macp;
	int rc;

	umdevice->dev_start = B_FALSE;

	mutex_init(&umdevice->os_param.gld_mutex, NULL,
	    MUTEX_DRIVER, DDI_INTR_PRI(umdevice->intrPriority));

	rw_init(&umdevice->os_param.gld_snd_mutex, NULL, RW_DRIVER, NULL);

	macp = mac_alloc(MAC_VERSION);
	if (macp == NULL) {
		cmn_err(CE_WARN,
		    "%s: Failed to allocate GLD MAC memory.\n",
		    umdevice->dev_name);
		goto error;
	}

	macp->m_driver = umdevice;
	macp->m_dip = umdevice->os_param.dip;
	macp->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	macp->m_callbacks = &bnx_callbacks;
	macp->m_min_sdu = 0;
	macp->m_max_sdu = umdevice->dev_var.mtu;
	macp->m_src_addr  = &(umdevice->lm_dev.params.mac_addr[0]);

	macp->m_margin = VLAN_TAG_SIZE;

	/*
	 * Call mac_register() after initializing all
	 * the required elements of mac_t struct.
	 */
	rc = mac_register(macp, &umdevice->os_param.macp);

	mac_free(macp);

	if (rc != 0) {
		cmn_err(CE_WARN,
		    "%s: Failed to register with GLD.\n",
		    umdevice->dev_name);
		goto error;
	}

	/* Always report the initial link state as unknown. */
	bnx_gld_link(umdevice, LINK_STATE_UNKNOWN);

	return (0);

error:
	rw_destroy(&umdevice->os_param.gld_snd_mutex);
	mutex_destroy(&umdevice->os_param.gld_mutex);

	return (-1);
}

void
bnx_gld_link(um_device_t * const umdevice, const link_state_t linkup)
{
	mac_link_update(umdevice->os_param.macp, linkup);
}

int
bnx_gld_fini(um_device_t * const umdevice)
{
	if (umdevice->dev_start != B_FALSE) {
		cmn_err(CE_WARN,
		    "%s: Detaching device from GLD that is still started!!!\n",
		    umdevice->dev_name);
		return (-1);
	}

	if (mac_unregister(umdevice->os_param.macp)) {
		cmn_err(CE_WARN,
		    "%s: Failed to unregister with the GLD.\n",
		    umdevice->dev_name);
		return (-1);
	}

	rw_destroy(&umdevice->os_param.gld_snd_mutex);
	mutex_destroy(&umdevice->os_param.gld_mutex);

	return (0);
}
