/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source. A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * This file is part of the Chelsio T4 support code.
 *
 * Copyright (C) 2010-2013 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

/*
 * Copyright 2020 RackTop Systems, Inc.
 * Copyright 2023 Oxide Computer Company
 */

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/dlpi.h>
#include <sys/mac_provider.h>
#include <sys/mac_ether.h>
#include <sys/strsubr.h>
#include <sys/queue.h>

#include "common/common.h"
#include "common/t4_regs.h"

static int t4_mc_getstat(void *arg, uint_t stat, uint64_t *val);
static int t4_mc_start(void *arg);
static void t4_mc_stop(void *arg);
static int t4_mc_setpromisc(void *arg, boolean_t on);
static int t4_mc_multicst(void *arg, boolean_t add, const uint8_t *mcaddr);
static int t4_mc_unicst(void *arg, const uint8_t *ucaddr);
static boolean_t t4_mc_getcapab(void *arg, mac_capab_t cap, void *data);
static int t4_mc_setprop(void *arg, const char *name, mac_prop_id_t id,
    uint_t size, const void *val);
static int t4_mc_getprop(void *arg, const char *name, mac_prop_id_t id,
    uint_t size, void *val);
static void t4_mc_propinfo(void *arg, const char *name, mac_prop_id_t id,
    mac_prop_info_handle_t ph);

static int t4_init_synchronized(struct port_info *pi);
static int t4_uninit_synchronized(struct port_info *pi);
static void propinfo(struct port_info *pi, const char *name,
    mac_prop_info_handle_t ph);
static int getprop(struct port_info *pi, const char *name, uint_t size,
    void *val);
static int setprop(struct port_info *pi, const char *name, const void *val);

mac_callbacks_t t4_m_callbacks = {
	.mc_callbacks	= MC_GETCAPAB | MC_PROPERTIES,
	.mc_getstat	= t4_mc_getstat,
	.mc_start	= t4_mc_start,
	.mc_stop	= t4_mc_stop,
	.mc_setpromisc	= t4_mc_setpromisc,
	.mc_multicst	= t4_mc_multicst,
	.mc_unicst	= t4_mc_unicst,
	.mc_tx		= t4_mc_tx,
	.mc_getcapab	= t4_mc_getcapab,
	.mc_setprop	= t4_mc_setprop,
	.mc_getprop	= t4_mc_getprop,
	.mc_propinfo	= t4_mc_propinfo,
};

mac_callbacks_t t4_m_ring_callbacks = {
	.mc_callbacks	= MC_GETCAPAB | MC_PROPERTIES,
	.mc_getstat	= t4_mc_getstat,
	.mc_start	= t4_mc_start,
	.mc_stop	= t4_mc_stop,
	.mc_setpromisc	= t4_mc_setpromisc,
	.mc_multicst	= t4_mc_multicst,
	.mc_unicst	= NULL, /* t4_addmac */
	.mc_tx		= NULL, /* t4_eth_tx */
	.mc_getcapab	= t4_mc_getcapab,
	.mc_setprop	= t4_mc_setprop,
	.mc_getprop	= t4_mc_getprop,
	.mc_propinfo	= t4_mc_propinfo,
};

#define	T4PROP_TMR_IDX		"_holdoff_timer_idx"
#define	T4PROP_PKTC_IDX		"_holdoff_pktc_idx"
#define	T4PROP_MTU		"_mtu"
#define	T4PROP_HW_CSUM		"_hw_csum"
#define	T4PROP_HW_LSO		"_hw_lso"
#define	T4PROP_TX_PAUSE		"_tx_pause"
#define	T4PROP_RX_PAUSE		"_rx_pause"

char *t4_priv_props[] = {
	T4PROP_TMR_IDX,
	T4PROP_PKTC_IDX,
#if MAC_VERSION == 1
	/* MAC_VERSION 1 doesn't seem to use MAC_PROP_MTU, hmmmm */
	T4PROP_MTU,
#endif
	T4PROP_HW_CSUM,
	T4PROP_HW_LSO,
	T4PROP_TX_PAUSE,
	T4PROP_RX_PAUSE,
	NULL
};

/*
 * To determine the actual Ethernet mode that we're in we need to look at the
 * port type. That will tell us whether we're using a BASE-T PHY, have an
 * external SFP connection whose module type we also need to use to qualify
 * this, and then the link speed itself. Combining that tuple we can then get
 * the current media.
 *
 * Our tables below assume we have gotten it down so the last thing we need to
 * consider is a single speed. If port types end up supporting the same class of
 * transceiver at a given speed, then this will need to be changed to use
 * additional information to disambiguate that (which will require additional
 * logic from the firmware).
 */
typedef struct {
	fw_port_cap32_t tmm_speed;
	mac_ether_media_t tmm_ether;
} t4nex_media_map_t;

static const t4nex_media_map_t t4nex_map_baset[] = {
	/*
	 * We're assuming that the 100 Mb/s mode is 100BASE-TX. It's hard to say
	 * for certain what the phy would have done, but given the rest of the
	 * market, that seems the most likely one.
	 */
	{ FW_PORT_CAP32_SPEED_100M, ETHER_MEDIA_100BASE_TX },
	{ FW_PORT_CAP32_SPEED_1G, ETHER_MEDIA_1000BASE_T },
	{ FW_PORT_CAP32_SPEED_10G, ETHER_MEDIA_10GBASE_T }
};

static const t4nex_media_map_t t4nex_map_kx[] = {
	{ FW_PORT_CAP32_SPEED_1G, ETHER_MEDIA_1000BASE_KX },
	{ FW_PORT_CAP32_SPEED_10G, ETHER_MEDIA_10GBASE_KX4 }
};

static const t4nex_media_map_t t4nex_map_cx[] = {
	{ FW_PORT_CAP32_SPEED_10G, ETHER_MEDIA_10GBASE_CX4 }
};

static const t4nex_media_map_t t4nex_map_kr[] = {
	{ FW_PORT_CAP32_SPEED_1G, ETHER_MEDIA_1000BASE_KX },
	{ FW_PORT_CAP32_SPEED_10G, ETHER_MEDIA_10GBASE_KR },
	{ FW_PORT_CAP32_SPEED_25G, ETHER_MEDIA_25GBASE_KR },
	{ FW_PORT_CAP32_SPEED_40G, ETHER_MEDIA_40GBASE_KR4 },
	{ FW_PORT_CAP32_SPEED_50G, ETHER_MEDIA_50GBASE_KR2 },
	{ FW_PORT_CAP32_SPEED_100G, ETHER_MEDIA_100GBASE_KR4 },
};

static const t4nex_media_map_t t4nex_map_lr[] = {
	{ FW_PORT_CAP32_SPEED_1G, ETHER_MEDIA_1000BASE_LX },
	{ FW_PORT_CAP32_SPEED_10G, ETHER_MEDIA_10GBASE_LR },
	{ FW_PORT_CAP32_SPEED_25G, ETHER_MEDIA_25GBASE_LR },
	{ FW_PORT_CAP32_SPEED_40G, ETHER_MEDIA_40GBASE_LR4 },
	{ FW_PORT_CAP32_SPEED_50G, ETHER_MEDIA_50GBASE_LR2 },
	{ FW_PORT_CAP32_SPEED_100G, ETHER_MEDIA_100GBASE_LR4 },
};

static const t4nex_media_map_t t4nex_map_sr[] = {
	{ FW_PORT_CAP32_SPEED_1G, ETHER_MEDIA_1000BASE_SX },
	{ FW_PORT_CAP32_SPEED_10G, ETHER_MEDIA_10GBASE_SR },
	{ FW_PORT_CAP32_SPEED_25G, ETHER_MEDIA_25GBASE_SR },
	{ FW_PORT_CAP32_SPEED_40G, ETHER_MEDIA_40GBASE_SR4 },
	{ FW_PORT_CAP32_SPEED_50G, ETHER_MEDIA_50GBASE_SR2 },
	{ FW_PORT_CAP32_SPEED_100G, ETHER_MEDIA_100GBASE_SR4 },
};

static const t4nex_media_map_t t4nex_map_er[] = {
	{ FW_PORT_CAP32_SPEED_10G, ETHER_MEDIA_10GBASE_ER },
	{ FW_PORT_CAP32_SPEED_25G, ETHER_MEDIA_25GBASE_ER },
	{ FW_PORT_CAP32_SPEED_40G, ETHER_MEDIA_40GBASE_ER4 },
	{ FW_PORT_CAP32_SPEED_100G, ETHER_MEDIA_100GBASE_ER4 },
};

static const t4nex_media_map_t t4nex_map_cr[] = {
	{ FW_PORT_CAP32_SPEED_1G, ETHER_MEDIA_1000BASE_CX },
	{ FW_PORT_CAP32_SPEED_10G, ETHER_MEDIA_10GBASE_CR },
	{ FW_PORT_CAP32_SPEED_25G, ETHER_MEDIA_25GBASE_CR },
	{ FW_PORT_CAP32_SPEED_40G, ETHER_MEDIA_40GBASE_CR4 },
	{ FW_PORT_CAP32_SPEED_50G, ETHER_MEDIA_50GBASE_CR2 },
	{ FW_PORT_CAP32_SPEED_100G, ETHER_MEDIA_100GBASE_CR4 },
};

static const t4nex_media_map_t t4nex_map_acc[] = {
	{ FW_PORT_CAP32_SPEED_1G, ETHER_MEDIA_1000BASE_CX },
	{ FW_PORT_CAP32_SPEED_10G, ETHER_MEDIA_10GBASE_ACC },
	{ FW_PORT_CAP32_SPEED_25G, ETHER_MEDIA_25GBASE_ACC },
	{ FW_PORT_CAP32_SPEED_40G, ETHER_MEDIA_40GBASE_ACC4 },
	{ FW_PORT_CAP32_SPEED_50G, ETHER_MEDIA_50GBASE_ACC2 },
	{ FW_PORT_CAP32_SPEED_100G, ETHER_MEDIA_100GBASE_ACC4 },
};

static const t4nex_media_map_t t4nex_map_lrm[] = {
	{ FW_PORT_CAP32_SPEED_10G, ETHER_MEDIA_10GBASE_LRM },
};

static mac_ether_media_t
t4_port_to_media(struct port_info *pi)
{
	fw_port_cap32_t speed;
	struct link_config *lc = &pi->link_cfg;
	const t4nex_media_map_t *map = NULL;
	size_t count = 0;

	if (lc->link_ok != 0) {
		speed = t4_link_fwcap_to_fwspeed(lc->link_caps);
	} else {
		return (ETHER_MEDIA_UNKNOWN);
	}

	switch (pi->port_type) {
	case FW_PORT_TYPE_FIBER_XFI:
	case FW_PORT_TYPE_FIBER_XAUI:
	case FW_PORT_TYPE_SFP:
	case FW_PORT_TYPE_QSFP_10G:
	case FW_PORT_TYPE_QSA:
	case FW_PORT_TYPE_QSFP:
	case FW_PORT_TYPE_CR4_QSFP:
	case FW_PORT_TYPE_CR_QSFP:
	case FW_PORT_TYPE_CR2_QSFP:
	case FW_PORT_TYPE_SFP28:
		switch (pi->mod_type) {
		case FW_PORT_MOD_TYPE_LR:
			map = t4nex_map_lr;
			count = ARRAY_SIZE(t4nex_map_lr);
			break;
		case FW_PORT_MOD_TYPE_SR:
			map = t4nex_map_sr;
			count = ARRAY_SIZE(t4nex_map_sr);
			break;
		case FW_PORT_MOD_TYPE_ER:
			map = t4nex_map_er;
			count = ARRAY_SIZE(t4nex_map_er);
			break;
		case FW_PORT_MOD_TYPE_TWINAX_PASSIVE:
			map = t4nex_map_cr;
			count = ARRAY_SIZE(t4nex_map_cr);
			break;
		case FW_PORT_MOD_TYPE_TWINAX_ACTIVE:
			map = t4nex_map_acc;
			count = ARRAY_SIZE(t4nex_map_acc);
			break;
		case FW_PORT_MOD_TYPE_LRM:
			map = t4nex_map_lrm;
			count = ARRAY_SIZE(t4nex_map_lrm);
			break;
		case FW_PORT_MOD_TYPE_ERROR:
		case FW_PORT_MOD_TYPE_UNKNOWN:
		case FW_PORT_MOD_TYPE_NOTSUPPORTED:
		case FW_PORT_MOD_TYPE_NONE:
		case FW_PORT_MOD_TYPE_NA:
		default:
			break;
		}
		break;
	case FW_PORT_TYPE_KX4:
	case FW_PORT_TYPE_KX:
		map = t4nex_map_kx;
		count = ARRAY_SIZE(t4nex_map_kx);
		break;
	case FW_PORT_TYPE_CX4:
		map = t4nex_map_cx;
		count = ARRAY_SIZE(t4nex_map_cx);
		break;
	case FW_PORT_TYPE_KR:
	case FW_PORT_TYPE_BP_AP:
	case FW_PORT_TYPE_BP4_AP:
	case FW_PORT_TYPE_BP40_BA:
	case FW_PORT_TYPE_KR4_100G:
	case FW_PORT_TYPE_KR_SFP28:
	case FW_PORT_TYPE_KR_XLAUI:
		map = t4nex_map_kr;
		count = ARRAY_SIZE(t4nex_map_kr);
		break;
	case FW_PORT_TYPE_BT_SGMII:
	case FW_PORT_TYPE_BT_XFI:
	case FW_PORT_TYPE_BT_XAUI:
		map = t4nex_map_baset;
		count = ARRAY_SIZE(t4nex_map_baset);
		break;
	case FW_PORT_TYPE_NONE:
	default:
		break;
	}

	for (size_t i = 0; i < count; i++) {
		if (map[i].tmm_speed == speed) {
			return (map[i].tmm_ether);
		}
	}

	/*
	 * At this point we return unknown as we already checked for a down link
	 * earlier.
	 */
	return (ETHER_MEDIA_UNKNOWN);
}

static int
t4_mc_getstat(void *arg, uint_t stat, uint64_t *val)
{
	struct port_info *pi = arg;
	struct adapter *sc = pi->adapter;
	struct link_config *lc = &pi->link_cfg;

#define	GET_STAT(name) \
	t4_read_reg64(sc, PORT_REG(pi->tx_chan, A_MPS_PORT_STAT_##name##_L))

	switch (stat) {
	case MAC_STAT_IFSPEED:
		if (lc->link_ok != 0) {
			*val = t4_link_fwcap_to_speed(lc->link_caps);
			*val *= 1000000;
		} else
			*val = 0;
		break;

	case MAC_STAT_MULTIRCV:
		*val = GET_STAT(RX_PORT_MCAST);
		break;

	case MAC_STAT_BRDCSTRCV:
		*val = GET_STAT(RX_PORT_BCAST);
		break;

	case MAC_STAT_MULTIXMT:
		*val = GET_STAT(TX_PORT_MCAST);
		break;

	case MAC_STAT_BRDCSTXMT:
		*val = GET_STAT(TX_PORT_BCAST);
		break;

	case MAC_STAT_NORCVBUF:
		*val = 0;	/* TODO should come from rxq->nomem */
		break;

	case MAC_STAT_IERRORS:
		*val = GET_STAT(RX_PORT_MTU_ERROR) +
		    GET_STAT(RX_PORT_MTU_CRC_ERROR) +
		    GET_STAT(RX_PORT_CRC_ERROR) +
		    GET_STAT(RX_PORT_LEN_ERROR) +
		    GET_STAT(RX_PORT_SYM_ERROR) +
		    GET_STAT(RX_PORT_LESS_64B);
		break;

	case MAC_STAT_UNKNOWNS:
		return (ENOTSUP);

	case MAC_STAT_NOXMTBUF:
		*val = GET_STAT(TX_PORT_DROP);
		break;

	case MAC_STAT_OERRORS:
		*val = GET_STAT(TX_PORT_ERROR);
		break;

	case MAC_STAT_COLLISIONS:
		return (ENOTSUP);

	case MAC_STAT_RBYTES:
		*val = GET_STAT(RX_PORT_BYTES);
		break;

	case MAC_STAT_IPACKETS:
		*val = GET_STAT(RX_PORT_FRAMES);
		break;

	case MAC_STAT_OBYTES:
		*val = GET_STAT(TX_PORT_BYTES);
		break;

	case MAC_STAT_OPACKETS:
		*val = GET_STAT(TX_PORT_FRAMES);
		break;

	case ETHER_STAT_ALIGN_ERRORS:
		return (ENOTSUP);

	case ETHER_STAT_FCS_ERRORS:
		*val = GET_STAT(RX_PORT_CRC_ERROR);
		break;

	case ETHER_STAT_FIRST_COLLISIONS:
	case ETHER_STAT_MULTI_COLLISIONS:
	case ETHER_STAT_SQE_ERRORS:
	case ETHER_STAT_DEFER_XMTS:
	case ETHER_STAT_TX_LATE_COLLISIONS:
	case ETHER_STAT_EX_COLLISIONS:
		return (ENOTSUP);

	case ETHER_STAT_MACXMT_ERRORS:
		*val = GET_STAT(TX_PORT_ERROR);
		break;

	case ETHER_STAT_CARRIER_ERRORS:
		return (ENOTSUP);

	case ETHER_STAT_TOOLONG_ERRORS:
		*val = GET_STAT(RX_PORT_MTU_ERROR);
		break;

	case ETHER_STAT_MACRCV_ERRORS:
		*val = GET_STAT(RX_PORT_MTU_ERROR) +
		    GET_STAT(RX_PORT_MTU_CRC_ERROR) +
		    GET_STAT(RX_PORT_CRC_ERROR) +
		    GET_STAT(RX_PORT_LEN_ERROR) +
		    GET_STAT(RX_PORT_SYM_ERROR) +
		    GET_STAT(RX_PORT_LESS_64B);
		break;

	case ETHER_STAT_XCVR_ADDR:
	case ETHER_STAT_XCVR_ID:
		return (ENOTSUP);
	case ETHER_STAT_XCVR_INUSE:
		*val = t4_port_to_media(pi);
		break;

	case ETHER_STAT_CAP_100GFDX:
		*val = !!(lc->pcaps & FW_PORT_CAP32_SPEED_100G);
		break;

	case ETHER_STAT_CAP_50GFDX:
		*val = !!(lc->pcaps & FW_PORT_CAP32_SPEED_50G);
		break;

	case ETHER_STAT_CAP_40GFDX:
		*val = !!(lc->pcaps & FW_PORT_CAP32_SPEED_40G);
		break;

	case ETHER_STAT_CAP_25GFDX:
		*val = !!(lc->pcaps & FW_PORT_CAP32_SPEED_25G);
		break;

	case ETHER_STAT_CAP_10GFDX:
		*val = !!(lc->pcaps & FW_PORT_CAP32_SPEED_10G);
		break;

	case ETHER_STAT_CAP_1000FDX:
		*val = !!(lc->pcaps & FW_PORT_CAP32_SPEED_1G);
		break;

	case ETHER_STAT_CAP_100FDX:
		*val = !!(lc->pcaps & FW_PORT_CAP32_SPEED_100M);
		break;

	case ETHER_STAT_CAP_1000HDX:
	case ETHER_STAT_CAP_100HDX:
	case ETHER_STAT_CAP_10FDX:
	case ETHER_STAT_CAP_10HDX:
		return (ENOTSUP);

	case ETHER_STAT_CAP_ASMPAUSE:
		*val = !!(lc->pcaps & FW_PORT_CAP32_FC_RX);
		break;

	case ETHER_STAT_CAP_PAUSE:
		*val = !!(lc->pcaps & FW_PORT_CAP32_FC_TX);
		break;

	case ETHER_STAT_CAP_AUTONEG:
		*val = !!(lc->pcaps & FW_PORT_CAP32_ANEG);
		break;

	/*
	 * We have set flow control configuration based on tx_pause and rx_pause
	 * values supported through ndd. Now, we need to translate the settings
	 * we have in link_config structure to adv_cap_asmpause and
	 * adv_cap_pause.
	 *
	 * There are 4 combinations possible and the translation is as below:
	 * tx_pause = 0 => We don't send pause frames during Rx congestion
	 * tx_pause = 1 => We send pause frames during Rx congestion
	 * rx_pause = 0 => We ignore received pause frames
	 * rx_pause = 1 => We pause transmission when we receive pause frames
	 *
	 * +----------------------------+----------------------------------+
	 * |  tx_pause	|    rx_pause	| adv_cap_asmpause | adv_cap_pause |
	 * +-------------------------+-------------------------------------+
	 * |	0	|	0	|	0	   |	0	   |
	 * |	0	|	1	|	1	   |	0	   |
	 * |	1	|	0	|	1	   |	1	   |
	 * |	1	|	1	|	0	   |	1	   |
	 * +----------------------------+----------------------------------+
	 */

	/* Advertised asymmetric pause capability */
	case ETHER_STAT_ADV_CAP_ASMPAUSE:
		if (lc->pcaps & FW_PORT_CAP32_802_3_ASM_DIR)
			*val = !!(lc->admin_caps & FW_PORT_CAP32_802_3_ASM_DIR);
		else
			*val = (!!(lc->admin_caps & FW_PORT_CAP32_FC_TX)) ^
			    (!!(lc->admin_caps & FW_PORT_CAP32_FC_RX));
		break;

	/* Advertised pause capability */
	case ETHER_STAT_ADV_CAP_PAUSE:
		if (lc->pcaps & FW_PORT_CAP32_802_3_PAUSE)
			*val = !!(lc->admin_caps & FW_PORT_CAP32_802_3_PAUSE);
		else
			*val = !!(lc->admin_caps & FW_PORT_CAP32_FC_TX);
		break;

	case ETHER_STAT_ADV_CAP_100GFDX:
		*val = !!(lc->admin_caps & FW_PORT_CAP32_SPEED_100G);
		break;

	case ETHER_STAT_ADV_CAP_50GFDX:
		*val = !!(lc->admin_caps & FW_PORT_CAP32_SPEED_50G);
		break;

	case ETHER_STAT_ADV_CAP_40GFDX:
		*val = !!(lc->admin_caps & FW_PORT_CAP32_SPEED_40G);
		break;

	case ETHER_STAT_ADV_CAP_25GFDX:
		*val = !!(lc->admin_caps & FW_PORT_CAP32_SPEED_25G);
		break;

	case ETHER_STAT_ADV_CAP_10GFDX:
		*val = !!(lc->admin_caps & FW_PORT_CAP32_SPEED_10G);
		break;

	case ETHER_STAT_ADV_CAP_1000FDX:
		*val = !!(lc->admin_caps & FW_PORT_CAP32_SPEED_1G);
		break;

	case ETHER_STAT_ADV_CAP_100FDX:
		*val = !!(lc->admin_caps & FW_PORT_CAP32_SPEED_100M);
		break;

	case ETHER_STAT_ADV_CAP_AUTONEG:
		*val = !!(lc->admin_caps & FW_PORT_CAP32_ANEG);
		break;

	case ETHER_STAT_ADV_CAP_1000HDX:
	case ETHER_STAT_ADV_CAP_100HDX:
	case ETHER_STAT_ADV_CAP_10FDX:
	case ETHER_STAT_ADV_CAP_10HDX:
		return (ENOTSUP);	/* TODO */

	case ETHER_STAT_LP_CAP_ASMPAUSE:
		if (!(lc->acaps & FW_PORT_CAP32_ANEG))
			return (ENOTSUP);

		if (lc->pcaps & FW_PORT_CAP32_802_3_ASM_DIR)
			*val = !!(lc->lpacaps & FW_PORT_CAP32_802_3_ASM_DIR);
		else
			*val = (!!(lc->lpacaps & FW_PORT_CAP32_FC_TX)) ^
			    (!!(lc->lpacaps & FW_PORT_CAP32_FC_RX));
		break;

	case ETHER_STAT_LP_CAP_PAUSE:
		if (!(lc->acaps & FW_PORT_CAP32_ANEG))
			return (ENOTSUP);

		if (lc->pcaps & FW_PORT_CAP32_802_3_PAUSE)
			*val = !!(lc->lpacaps & FW_PORT_CAP32_802_3_PAUSE);
		else
			*val = !!(lc->lpacaps & FW_PORT_CAP32_FC_TX);
		break;

	case ETHER_STAT_LP_CAP_100GFDX:
		if (!(lc->acaps & FW_PORT_CAP32_ANEG))
			return (ENOTSUP);

		*val = !!(lc->lpacaps & FW_PORT_CAP32_SPEED_100G);
		break;

	case ETHER_STAT_LP_CAP_50GFDX:
		if (!(lc->acaps & FW_PORT_CAP32_ANEG))
			return (ENOTSUP);

		*val = !!(lc->lpacaps & FW_PORT_CAP32_SPEED_50G);
		break;

	case ETHER_STAT_LP_CAP_40GFDX:
		if (!(lc->acaps & FW_PORT_CAP32_ANEG))
			return (ENOTSUP);

		*val = !!(lc->lpacaps & FW_PORT_CAP32_SPEED_40G);
		break;

	case ETHER_STAT_LP_CAP_25GFDX:
		if (!(lc->acaps & FW_PORT_CAP32_ANEG))
			return (ENOTSUP);

		*val = !!(lc->lpacaps & FW_PORT_CAP32_SPEED_25G);
		break;

	case ETHER_STAT_LP_CAP_10GFDX:
		if (!(lc->acaps & FW_PORT_CAP32_ANEG))
			return (ENOTSUP);

		*val = !!(lc->lpacaps & FW_PORT_CAP32_SPEED_10G);
		break;

	case ETHER_STAT_LP_CAP_1000FDX:
		if (!(lc->acaps & FW_PORT_CAP32_ANEG))
			return (ENOTSUP);

		*val = !!(lc->lpacaps & FW_PORT_CAP32_SPEED_1G);
		break;

	case ETHER_STAT_LP_CAP_100FDX:
		if (!(lc->acaps & FW_PORT_CAP32_ANEG))
			return (ENOTSUP);

		*val = !!(lc->lpacaps & FW_PORT_CAP32_SPEED_100M);
		break;

	case ETHER_STAT_LP_CAP_AUTONEG:
		if (!(lc->acaps & FW_PORT_CAP32_ANEG))
			return (ENOTSUP);

		*val = !!(lc->lpacaps & FW_PORT_CAP32_ANEG);
		break;

	case ETHER_STAT_LP_CAP_1000HDX:
	case ETHER_STAT_LP_CAP_100HDX:
	case ETHER_STAT_LP_CAP_10FDX:
	case ETHER_STAT_LP_CAP_10HDX:
		return (ENOTSUP);

	case ETHER_STAT_LINK_ASMPAUSE:
		*val = (!!(lc->link_caps & FW_PORT_CAP32_FC_TX)) ^
		    (!!(lc->link_caps & FW_PORT_CAP32_FC_RX));
		break;

	case ETHER_STAT_LINK_PAUSE:
		*val = !!(lc->link_caps & FW_PORT_CAP32_FC_TX);
		break;

	case ETHER_STAT_LINK_AUTONEG:
		*val = !!(lc->link_caps & FW_PORT_CAP32_ANEG);
		break;

	case ETHER_STAT_LINK_DUPLEX:
		if (lc->link_ok != 0)
			*val = LINK_DUPLEX_FULL;
		else
			*val = LINK_DUPLEX_UNKNOWN;
		break;

	default:
		return (ENOTSUP);
	}
#undef GET_STAT

	return (0);
}

static int
t4_mc_start(void *arg)
{
	struct port_info *pi = arg;
	int rc;

	rc = begin_synchronized_op(pi, 0, 1);
	if (rc != 0)
		return (rc);
	rc = t4_init_synchronized(pi);
	end_synchronized_op(pi, 0);

	return (rc);
}

static void
t4_mc_stop(void *arg)
{
	struct port_info *pi = arg;

	while (begin_synchronized_op(pi, 0, 1) != 0)
		continue;
	(void) t4_uninit_synchronized(pi);
	end_synchronized_op(pi, 0);
}

static int
t4_mc_setpromisc(void *arg, boolean_t on)
{
	struct port_info *pi = arg;
	struct adapter *sc = pi->adapter;
	int rc;

	rc = begin_synchronized_op(pi, 1, 1);
	if (rc != 0)
		return (rc);
	rc = -t4_set_rxmode(sc, sc->mbox, pi->viid, -1, on ? 1 : 0, -1, -1, -1,
	    false);
	end_synchronized_op(pi, 1);

	return (rc);
}

/*
 * TODO: Starts failing as soon as the 336 entry table fills up.  Need to use
 * hash in that case.
 */
static int
t4_mc_multicst(void *arg, boolean_t add, const uint8_t *mcaddr)
{
	struct port_info *pi = arg;
	struct adapter *sc = pi->adapter;
	struct fw_vi_mac_cmd c;
	int len16, rc;

	len16 = howmany(sizeof (c.op_to_viid) + sizeof (c.freemacs_to_len16) +
	    sizeof (c.u.exact[0]), 16);
	c.op_to_viid = htonl(V_FW_CMD_OP(FW_VI_MAC_CMD) | F_FW_CMD_REQUEST |
	    F_FW_CMD_WRITE | V_FW_VI_MAC_CMD_VIID(pi->viid));
	c.freemacs_to_len16 = htonl(V_FW_CMD_LEN16(len16));
	c.u.exact[0].valid_to_idx = htons(F_FW_VI_MAC_CMD_VALID |
	    V_FW_VI_MAC_CMD_IDX(add ? FW_VI_MAC_ADD_MAC :
	    FW_VI_MAC_MAC_BASED_FREE));
	bcopy(mcaddr, &c.u.exact[0].macaddr, ETHERADDRL);

	rc = begin_synchronized_op(pi, 1, 1);
	if (rc != 0)
		return (rc);
	rc = -t4_wr_mbox_meat(sc, sc->mbox, &c, len16 * 16, &c, true);
	end_synchronized_op(pi, 1);
	if (rc != 0)
		return (rc);
#ifdef DEBUG
	/*
	 * TODO: Firmware doesn't seem to return the correct index on removal
	 * (it gives back 0x3fd FW_VI_MAC_MAC_BASED_FREE unchanged. Remove this
	 * code once it is fixed.
	 */
	else {
		uint16_t idx;

		idx = G_FW_VI_MAC_CMD_IDX(ntohs(c.u.exact[0].valid_to_idx));
		cxgb_printf(pi->dip, CE_NOTE,
		    "%02x:%02x:%02x:%02x:%02x:%02x %s %d", mcaddr[0],
		    mcaddr[1], mcaddr[2], mcaddr[3], mcaddr[4], mcaddr[5],
		    add ? "added at index" : "removed from index", idx);
	}
#endif

	return (0);
}

int
t4_mc_unicst(void *arg, const uint8_t *ucaddr)
{
	struct port_info *pi = arg;
	struct adapter *sc = pi->adapter;
	int rc;

	if (ucaddr == NULL)
		return (EINVAL);

	rc = begin_synchronized_op(pi, 1, 1);
	if (rc != 0)
		return (rc);

	/* We will support adding only one mac address */
	if (pi->adapter->props.multi_rings && pi->macaddr_cnt) {
		end_synchronized_op(pi, 1);
		return (ENOSPC);
	}
	rc = t4_change_mac(sc, sc->mbox, pi->viid, pi->xact_addr_filt, ucaddr,
	    true, &pi->smt_idx);
	if (rc < 0) {
		rc = -rc;
	} else {
		pi->macaddr_cnt++;
		pi->xact_addr_filt = rc;
		rc = 0;
	}
	end_synchronized_op(pi, 1);

	return (rc);
}

int
t4_addmac(void *arg, const uint8_t *ucaddr)
{
	return (t4_mc_unicst(arg, ucaddr));
}

static int
t4_remmac(void *arg, const uint8_t *mac_addr)
{
	struct port_info *pi = arg;
	int rc;

	rc = begin_synchronized_op(pi, 1, 1);
	if (rc != 0)
		return (rc);

	pi->macaddr_cnt--;
	end_synchronized_op(pi, 1);

	return (0);
}

/*
 * Callback funtion for MAC layer to register all groups.
 */
void
t4_fill_group(void *arg, mac_ring_type_t rtype, const int rg_index,
    mac_group_info_t *infop, mac_group_handle_t gh)
{
	struct port_info *pi = arg;

	switch (rtype) {
	case MAC_RING_TYPE_RX: {
		infop->mgi_driver = (mac_group_driver_t)arg;
		infop->mgi_start = NULL;
		infop->mgi_stop = NULL;
		infop->mgi_addmac = t4_addmac;
		infop->mgi_remmac = t4_remmac;
		infop->mgi_count = pi->nrxq;
		break;
	}
	case MAC_RING_TYPE_TX:
	default:
		ASSERT(0);
		break;
	}
}

static int
t4_ring_start(mac_ring_driver_t rh, uint64_t mr_gen_num)
{
	struct sge_rxq *rxq = (struct sge_rxq *)rh;

	RXQ_LOCK(rxq);
	rxq->ring_gen_num = mr_gen_num;
	RXQ_UNLOCK(rxq);
	return (0);
}

/*
 * Enable interrupt on the specificed rx ring.
 */
int
t4_ring_intr_enable(mac_intr_handle_t intrh)
{
	struct sge_rxq *rxq = (struct sge_rxq *)intrh;
	struct adapter *sc = rxq->port->adapter;
	struct sge_iq *iq;

	iq = &rxq->iq;
	RXQ_LOCK(rxq);
	iq->polling = 0;
	iq->state = IQS_IDLE;
	t4_write_reg(sc, MYPF_REG(A_SGE_PF_GTS),
	    V_SEINTARM(iq->intr_params) | V_INGRESSQID(iq->cntxt_id));
	RXQ_UNLOCK(rxq);
	return (0);
}

/*
 * Disable interrupt on the specificed rx ring.
 */
int
t4_ring_intr_disable(mac_intr_handle_t intrh)
{
	struct sge_rxq *rxq = (struct sge_rxq *)intrh;
	struct sge_iq *iq;

	/*
	 * Nothing to be done here wrt interrupt, as it will not fire, until we
	 * write back to A_SGE_PF_GTS.SEIntArm in t4_ring_intr_enable.
	 */

	iq = &rxq->iq;
	RXQ_LOCK(rxq);
	iq->polling = 1;
	iq->state = IQS_BUSY;
	RXQ_UNLOCK(rxq);

	return (0);
}

mblk_t *
t4_poll_ring(void *arg, int n_bytes)
{
	struct sge_rxq *rxq = (struct sge_rxq *)arg;
	mblk_t *mp = NULL;

	ASSERT(n_bytes >= 0);
	if (n_bytes == 0)
		return (NULL);

	RXQ_LOCK(rxq);
	mp = t4_ring_rx(rxq, n_bytes);
	RXQ_UNLOCK(rxq);

	return (mp);
}

/*
 * Retrieve a value for one of the statistics for a particular rx ring
 */
int
t4_rx_stat(mac_ring_driver_t rh, uint_t stat, uint64_t *val)
{
	struct sge_rxq *rxq = (struct sge_rxq *)rh;

	switch (stat) {
	case MAC_STAT_RBYTES:
		*val = rxq->rxbytes;
		break;

	case MAC_STAT_IPACKETS:
		*val = rxq->rxpkts;
		break;

	default:
		*val = 0;
		return (ENOTSUP);
	}

	return (0);
}

/*
 * Retrieve a value for one of the statistics for a particular tx ring
 */
int
t4_tx_stat(mac_ring_driver_t rh, uint_t stat, uint64_t *val)
{
	struct sge_txq *txq = (struct sge_txq *)rh;

	switch (stat) {
	case MAC_STAT_RBYTES:
		*val = txq->txbytes;
		break;

	case MAC_STAT_IPACKETS:
		*val = txq->txpkts;
		break;

	default:
		*val = 0;
		return (ENOTSUP);
	}

	return (0);
}

/*
 * Callback funtion for MAC layer to register all rings
 * for given ring_group, noted by group_index.
 * Since we have only one group, ring index becomes
 * absolute index.
 */
void
t4_fill_ring(void *arg, mac_ring_type_t rtype, const int group_index,
    const int ring_index, mac_ring_info_t *infop, mac_ring_handle_t rh)
{
	struct port_info *pi = arg;
	mac_intr_t *mintr;

	switch (rtype) {
	case MAC_RING_TYPE_RX: {
		struct sge_rxq *rxq;

		rxq = &pi->adapter->sge.rxq[pi->first_rxq + ring_index];
		rxq->ring_handle = rh;

		infop->mri_driver = (mac_ring_driver_t)rxq;
		infop->mri_start = t4_ring_start;
		infop->mri_stop = NULL;
		infop->mri_poll = t4_poll_ring;
		infop->mri_stat = t4_rx_stat;

		mintr = &infop->mri_intr;
		mintr->mi_handle = (mac_intr_handle_t)rxq;
		mintr->mi_enable = t4_ring_intr_enable;
		mintr->mi_disable = t4_ring_intr_disable;

		break;
	}
	case MAC_RING_TYPE_TX: {
		struct sge_txq *txq =
		    &pi->adapter->sge.txq[pi->first_txq + ring_index];
		txq->ring_handle = rh;
		infop->mri_driver = (mac_ring_driver_t)txq;
		infop->mri_start = NULL;
		infop->mri_stop = NULL;
		infop->mri_tx = t4_eth_tx;
		infop->mri_stat = t4_tx_stat;
		break;
	}
	default:
		ASSERT(0);
		break;
	}
}

mblk_t *
t4_mc_tx(void *arg, mblk_t *m)
{
	struct port_info *pi = arg;
	struct adapter *sc = pi->adapter;
	struct sge_txq *txq = &sc->sge.txq[pi->first_txq];

	return (t4_eth_tx(txq, m));
}

static int
t4_mc_transceiver_info(void *arg, uint_t id, mac_transceiver_info_t *infop)
{
	struct port_info *pi = arg;

	if (id != 0 || infop == NULL)
		return (EINVAL);

	switch (pi->mod_type) {
	case FW_PORT_MOD_TYPE_NONE:
		mac_transceiver_info_set_present(infop, B_FALSE);
		break;
	case FW_PORT_MOD_TYPE_NOTSUPPORTED:
		mac_transceiver_info_set_present(infop, B_TRUE);
		mac_transceiver_info_set_usable(infop, B_FALSE);
		break;
	default:
		mac_transceiver_info_set_present(infop, B_TRUE);
		mac_transceiver_info_set_usable(infop, B_TRUE);
		break;
	}

	return (0);
}

static int
t4_mc_transceiver_read(void *arg, uint_t id, uint_t page, void *bp,
    size_t nbytes, off_t offset, size_t *nread)
{
	struct port_info *pi = arg;
	struct adapter *sc = pi->adapter;
	int rc;
	size_t i, maxread;
	/* LINTED: E_FUNC_VAR_UNUSED */
	struct fw_ldst_cmd ldst __unused;

	if (id != 0 || bp == NULL || nbytes == 0 || nread == NULL ||
	    (page != 0xa0 && page != 0xa2) || offset < 0)
		return (EINVAL);

	if (nbytes > 256 || offset >= 256 || (offset + nbytes > 256))
		return (EINVAL);

	rc = begin_synchronized_op(pi, 0, 1);
	if (rc != 0)
		return (rc);

	/*
	 * Firmware has a maximum size that we can read. Don't read more than it
	 * allows.
	 */
	maxread = sizeof (ldst.u.i2c.data);
	for (i = 0; i < nbytes; i += maxread) {
		size_t toread = MIN(maxread, nbytes - i);
		rc = -t4_i2c_rd(sc, sc->mbox, pi->port_id, page, offset, toread,
		    bp);
		if (rc != 0)
			break;
		offset += toread;
		bp = (void *)((uintptr_t)bp + toread);
	}
	end_synchronized_op(pi, 0);
	if (rc == 0)
		*nread = nbytes;
	return (rc);
}

static int
t4_port_led_set(void *arg, mac_led_mode_t mode, uint_t flags)
{
	struct port_info *pi = arg;
	struct adapter *sc = pi->adapter;
	int val, rc;

	if (flags != 0)
		return (EINVAL);

	switch (mode) {
	case MAC_LED_DEFAULT:
		val = 0;
		break;
	case MAC_LED_IDENT:
		val = 0xffff;
		break;

	default:
		return (ENOTSUP);
	}

	rc = begin_synchronized_op(pi, 1, 1);
	if (rc != 0)
		return (rc);
	rc = -t4_identify_port(sc, sc->mbox, pi->viid, val);
	end_synchronized_op(pi, 1);

	return (rc);
}

static boolean_t
t4_mc_getcapab(void *arg, mac_capab_t cap, void *data)
{
	struct port_info *pi = arg;
	boolean_t status = B_TRUE;
	mac_capab_transceiver_t *mct;
	mac_capab_led_t *mcl;

	switch (cap) {
	case MAC_CAPAB_HCKSUM:
		if (pi->features & CXGBE_HW_CSUM) {
			uint32_t *d = data;
			*d = HCKSUM_INET_FULL_V4 | HCKSUM_IPHDRCKSUM |
			    HCKSUM_INET_FULL_V6;
		} else
			status = B_FALSE;
		break;

	case MAC_CAPAB_LSO:
		/* Enabling LSO requires Checksum offloading */
		if (pi->features & CXGBE_HW_LSO &&
		    pi->features & CXGBE_HW_CSUM) {
			mac_capab_lso_t *d = data;

			d->lso_flags = LSO_TX_BASIC_TCP_IPV4 |
			    LSO_TX_BASIC_TCP_IPV6;
			d->lso_basic_tcp_ipv4.lso_max = 65535;
			d->lso_basic_tcp_ipv6.lso_max = 65535;
		} else
			status = B_FALSE;
		break;

	case MAC_CAPAB_RINGS: {
		mac_capab_rings_t *cap_rings = data;

		if (!pi->adapter->props.multi_rings) {
			status = B_FALSE;
			break;
		}
		switch (cap_rings->mr_type) {
		case MAC_RING_TYPE_RX:
			cap_rings->mr_group_type = MAC_GROUP_TYPE_STATIC;
			cap_rings->mr_rnum = pi->nrxq;
			cap_rings->mr_gnum = 1;
			cap_rings->mr_rget = t4_fill_ring;
			cap_rings->mr_gget = t4_fill_group;
			cap_rings->mr_gaddring = NULL;
			cap_rings->mr_gremring = NULL;
			break;
		case MAC_RING_TYPE_TX:
			cap_rings->mr_group_type = MAC_GROUP_TYPE_STATIC;
			cap_rings->mr_rnum = pi->ntxq;
			cap_rings->mr_gnum = 0;
			cap_rings->mr_rget = t4_fill_ring;
			cap_rings->mr_gget = NULL;
			break;
		}
		break;
	}

	case MAC_CAPAB_TRANSCEIVER:
		mct = data;

		mct->mct_flags = 0;
		mct->mct_ntransceivers = 1;
		mct->mct_info = t4_mc_transceiver_info;
		mct->mct_read = t4_mc_transceiver_read;
		break;
	case MAC_CAPAB_LED:
		mcl = data;
		mcl->mcl_flags = 0;
		mcl->mcl_modes = MAC_LED_DEFAULT | MAC_LED_IDENT;
		mcl->mcl_set = t4_port_led_set;
		break;

	default:
		status = B_FALSE; /* cap not supported */
	}

	return (status);
}

static void
t4_mac_link_caps_to_flowctrl(fw_port_cap32_t caps, link_flowctrl_t *fc)
{
	u8 pause_tx = 0, pause_rx = 0;

	if (caps & FW_PORT_CAP32_FC_TX)
		pause_tx = 1;

	if (caps & FW_PORT_CAP32_FC_RX)
		pause_rx = 1;

	if (pause_rx & pause_tx)
		*fc = LINK_FLOWCTRL_BI;
	else if (pause_tx)
		*fc = LINK_FLOWCTRL_TX;
	else if (pause_rx)
		*fc = LINK_FLOWCTRL_RX;
	else
		*fc = LINK_FLOWCTRL_NONE;
}

static int
t4_mac_flowctrl_to_link_caps(struct port_info *pi, link_flowctrl_t fc,
    fw_port_cap32_t *new_caps)
{
	cc_pause_t pause = 0;

	switch (fc) {
	case LINK_FLOWCTRL_BI:
		pause |= PAUSE_TX | PAUSE_RX;
		break;
	case LINK_FLOWCTRL_TX:
		pause |= PAUSE_TX;
		break;
	case LINK_FLOWCTRL_RX:
		pause |= PAUSE_RX;
		break;
	default:
		break;
	}

	if (pi->link_cfg.admin_caps & FW_PORT_CAP32_ANEG)
		pause |= PAUSE_AUTONEG;

	return (t4_link_set_pause(pi, pause, new_caps));
}

static link_fec_t
t4_mac_port_caps_to_fec_cap(fw_port_cap32_t caps)
{
	link_fec_t link_fec = 0;

	if (caps & FW_PORT_CAP32_FEC_RS)
		link_fec |= LINK_FEC_RS;

	if (caps & FW_PORT_CAP32_FEC_BASER_RS)
		link_fec |= LINK_FEC_BASE_R;

	if (caps & FW_PORT_CAP32_FEC_NO_FEC)
		link_fec |= LINK_FEC_NONE;

	if ((link_fec & (link_fec - 1)) &&
	    !(caps & FW_PORT_CAP32_FORCE_FEC))
		return (LINK_FEC_AUTO);

	return (link_fec);
}

static void
t4_mac_admin_caps_to_fec_cap(fw_port_cap32_t caps, link_fec_t *fec)
{
	*fec = t4_mac_port_caps_to_fec_cap(caps);
}

static void
t4_mac_link_caps_to_fec_cap(fw_port_cap32_t caps, link_fec_t *fec)
{
	link_fec_t link_fec;

	caps &= ~FW_PORT_CAP32_FEC_NO_FEC;
	link_fec = t4_mac_port_caps_to_fec_cap(caps);
	*fec = link_fec ? link_fec : LINK_FEC_NONE;
}

static int
t4_mac_fec_cap_to_link_caps(struct port_info *pi, link_fec_t v,
    fw_port_cap32_t *new_caps)
{
	cc_fec_t fec = 0;

	if (v == LINK_FEC_AUTO) {
		fec = FEC_AUTO;
		goto out;
	}

	if (v & LINK_FEC_NONE) {
		v &= ~LINK_FEC_NONE;
		fec |= FEC_NONE;
	}

	if (v & LINK_FEC_RS) {
		v &= ~LINK_FEC_RS;
		fec |= FEC_RS;
	}

	if (v & LINK_FEC_BASE_R) {
		v &= ~LINK_FEC_BASE_R;
		fec |= FEC_BASER_RS;
	}

	if (v != 0)
		return (-1);

	ASSERT3S(fec, !=, 0);

	fec |= FEC_FORCE;

out:
	return (t4_link_set_fec(pi, fec, new_caps));
}

/* ARGSUSED */
static int
t4_mc_setprop(void *arg, const char *name, mac_prop_id_t id, uint_t size,
    const void *val)
{
	struct port_info *pi = arg;
	struct adapter *sc = pi->adapter;
	struct link_config *lc = &pi->link_cfg;
	fw_port_cap32_t new_caps = lc->admin_caps;
	int relink = 0, rx_mode = 0, rc = 0;
	uint32_t v32 = *(uint32_t *)val;
	uint8_t v8 = *(uint8_t *)val;
	link_flowctrl_t fc;
	link_fec_t fec;

	switch (id) {
	case MAC_PROP_AUTONEG:
		rc = t4_link_set_autoneg(pi, v8, &new_caps);
		relink = 1;
		break;

	case MAC_PROP_MTU:
		if (v32 < 46 || v32 > MAX_MTU) {
			rc = EINVAL;
		} else if (v32 != pi->mtu) {
			pi->mtu = v32;
			(void) mac_maxsdu_update(pi->mh, v32);
			rx_mode = 1;
		}

		break;

	case MAC_PROP_FLOWCTRL:
		fc = *(link_flowctrl_t *)val;
		rc = t4_mac_flowctrl_to_link_caps(pi, fc, &new_caps);
		relink = 1;
		break;

	case MAC_PROP_EN_FEC_CAP:
		fec = *(link_fec_t *)val;
		rc = t4_mac_fec_cap_to_link_caps(pi, fec, &new_caps);
		relink = 1;
		break;

	case MAC_PROP_EN_100GFDX_CAP:
		rc = t4_link_set_speed(pi, FW_PORT_CAP32_SPEED_100G, v8,
		    &new_caps);
		relink = 1;
		break;

	case MAC_PROP_EN_50GFDX_CAP:
		rc = t4_link_set_speed(pi, FW_PORT_CAP32_SPEED_50G, v8,
		    &new_caps);
		relink = 1;
		break;

	case MAC_PROP_EN_40GFDX_CAP:
		rc = t4_link_set_speed(pi, FW_PORT_CAP32_SPEED_40G, v8,
		    &new_caps);
		relink = 1;
		break;

	case MAC_PROP_EN_25GFDX_CAP:
		rc = t4_link_set_speed(pi, FW_PORT_CAP32_SPEED_25G, v8,
		    &new_caps);
		relink = 1;
		break;

	case MAC_PROP_EN_10GFDX_CAP:
		rc = t4_link_set_speed(pi, FW_PORT_CAP32_SPEED_10G, v8,
		    &new_caps);
		relink = 1;
		break;

	case MAC_PROP_EN_1000FDX_CAP:
		rc = t4_link_set_speed(pi, FW_PORT_CAP32_SPEED_1G, v8,
		    &new_caps);
		relink = 1;
		break;

	case MAC_PROP_EN_100FDX_CAP:
		rc = t4_link_set_speed(pi, FW_PORT_CAP32_SPEED_100M, v8,
		    &new_caps);
		relink = 1;
		break;

	case MAC_PROP_PRIVATE:
		rc = setprop(pi, name, val);
		break;

	default:
		rc = ENOTSUP;
		break;
	}

	if (rc != 0)
		return (rc);

	if (isset(&sc->open_device_map, pi->port_id) != 0) {
		if (relink != 0) {
			rc = begin_synchronized_op(pi, 1, 1);
			if (rc != 0)
				return (rc);
			rc = -t4_link_l1cfg(sc, sc->mbox, pi->tx_chan, lc,
			    new_caps);
			end_synchronized_op(pi, 1);
			if (rc != 0) {
				cxgb_printf(pi->dip, CE_WARN,
				    "%s link config failed: %d", __func__, rc);
				return (rc);
			}
		}

		if (rx_mode != 0) {
			rc = begin_synchronized_op(pi, 1, 1);
			if (rc != 0)
				return (rc);
			rc = -t4_set_rxmode(sc, sc->mbox, pi->viid, v32, -1,
			    -1, -1, -1, false);
			end_synchronized_op(pi, 1);
			if (rc != 0) {
				cxgb_printf(pi->dip, CE_WARN,
				    "set_rxmode failed: %d", rc);
				return (rc);
			}
		}
	}

	if (relink != 0)
		lc->admin_caps = new_caps;

	return (0);
}

static int
t4_mc_getprop(void *arg, const char *name, mac_prop_id_t id, uint_t size,
    void *val)
{
	struct port_info *pi = arg;
	struct link_config *lc = &pi->link_cfg;
	uint8_t *u = val;
	int rc = 0;

	switch (id) {
	case MAC_PROP_DUPLEX:
		*(link_duplex_t *)val = lc->link_ok ? LINK_DUPLEX_FULL :
		    LINK_DUPLEX_UNKNOWN;
		break;

	case MAC_PROP_SPEED:
		if (lc->link_ok != 0) {
			*(uint64_t *)val =
			    t4_link_fwcap_to_speed(lc->link_caps);
			*(uint64_t *)val *= 1000000;
		} else {
			*(uint64_t *)val = 0;
		}
		break;

	case MAC_PROP_STATUS:
		*(link_state_t *)val = lc->link_ok ? LINK_STATE_UP :
		    LINK_STATE_DOWN;
		break;

	case MAC_PROP_MEDIA:
		*(mac_ether_media_t *)val = t4_port_to_media(pi);
		break;

	case MAC_PROP_AUTONEG:
		*u = !!(lc->link_caps & FW_PORT_CAP32_ANEG);
		break;

	case MAC_PROP_MTU:
		*(uint32_t *)val = pi->mtu;
		break;

	case MAC_PROP_FLOWCTRL:
		t4_mac_link_caps_to_flowctrl(lc->link_caps, val);
		break;

	case MAC_PROP_ADV_FEC_CAP:
		t4_mac_link_caps_to_fec_cap(lc->link_caps, val);
		break;

	case MAC_PROP_EN_FEC_CAP:
		t4_mac_admin_caps_to_fec_cap(lc->admin_caps, val);
		break;

	case MAC_PROP_ADV_100GFDX_CAP:
		*u = !!(lc->link_caps & FW_PORT_CAP32_SPEED_100G);
		break;

	case MAC_PROP_EN_100GFDX_CAP:
		*u = !!(lc->admin_caps & FW_PORT_CAP32_SPEED_100G);
		break;

	case MAC_PROP_ADV_50GFDX_CAP:
		*u = !!(lc->link_caps & FW_PORT_CAP32_SPEED_50G);
		break;

	case MAC_PROP_EN_50GFDX_CAP:
		*u = !!(lc->admin_caps & FW_PORT_CAP32_SPEED_50G);
		break;

	case MAC_PROP_ADV_40GFDX_CAP:
		*u = !!(lc->link_caps & FW_PORT_CAP32_SPEED_40G);
		break;

	case MAC_PROP_EN_40GFDX_CAP:
		*u = !!(lc->admin_caps & FW_PORT_CAP32_SPEED_40G);
		break;

	case MAC_PROP_ADV_25GFDX_CAP:
		*u = !!(lc->link_caps & FW_PORT_CAP32_SPEED_25G);
		break;

	case MAC_PROP_EN_25GFDX_CAP:
		*u = !!(lc->admin_caps & FW_PORT_CAP32_SPEED_25G);
		break;

	case MAC_PROP_ADV_10GFDX_CAP:
		*u = !!(lc->link_caps & FW_PORT_CAP32_SPEED_10G);
		break;

	case MAC_PROP_EN_10GFDX_CAP:
		*u = !!(lc->admin_caps & FW_PORT_CAP32_SPEED_10G);
		break;

	case MAC_PROP_ADV_1000FDX_CAP:
		*u = !!(lc->link_caps & FW_PORT_CAP32_SPEED_1G);
		break;

	case MAC_PROP_EN_1000FDX_CAP:
		*u = !!(lc->admin_caps & FW_PORT_CAP32_SPEED_1G);
		break;

	case MAC_PROP_ADV_100FDX_CAP:
		*u = !!(lc->link_caps & FW_PORT_CAP32_SPEED_100M);
		break;

	case MAC_PROP_EN_100FDX_CAP:
		*u = !!(lc->admin_caps & FW_PORT_CAP32_SPEED_100M);
		break;

	case MAC_PROP_PRIVATE:
		return (getprop(pi, name, size, val));

	default:
		return (ENOTSUP);
	}

	return (rc);
}

static void
t4_mc_propinfo(void *arg, const char *name, mac_prop_id_t id,
    mac_prop_info_handle_t ph)
{
	struct port_info *pi = arg;
	struct link_config *lc = &pi->link_cfg;

	switch (id) {
	case MAC_PROP_DUPLEX:
	case MAC_PROP_SPEED:
	case MAC_PROP_STATUS:
		mac_prop_info_set_perm(ph, MAC_PROP_PERM_READ);
		break;

	case MAC_PROP_AUTONEG:
		if (lc->pcaps & FW_PORT_CAP32_ANEG)
			mac_prop_info_set_default_uint8(ph, 1);
		else
			mac_prop_info_set_perm(ph, MAC_PROP_PERM_READ);
		break;

	case MAC_PROP_MTU:
		mac_prop_info_set_range_uint32(ph, 46, MAX_MTU);
		break;

	case MAC_PROP_FLOWCTRL:
		mac_prop_info_set_default_link_flowctrl(ph, LINK_FLOWCTRL_BI);
		break;

	case MAC_PROP_EN_FEC_CAP:
		mac_prop_info_set_default_fec(ph, LINK_FEC_AUTO);
		break;

	case MAC_PROP_ADV_FEC_CAP:
		mac_prop_info_set_perm(ph, MAC_PROP_PERM_READ);
		mac_prop_info_set_default_fec(ph, LINK_FEC_AUTO);
		break;

	case MAC_PROP_EN_100GFDX_CAP:
		if (lc->pcaps & FW_PORT_CAP32_SPEED_100G)
			mac_prop_info_set_default_uint8(ph, 1);
		else
			mac_prop_info_set_perm(ph, MAC_PROP_PERM_READ);
		break;

	case MAC_PROP_EN_50GFDX_CAP:
		if (lc->pcaps & FW_PORT_CAP32_SPEED_50G)
			mac_prop_info_set_default_uint8(ph, 1);
		else
			mac_prop_info_set_perm(ph, MAC_PROP_PERM_READ);
		break;

	case MAC_PROP_EN_40GFDX_CAP:
		if (lc->pcaps & FW_PORT_CAP32_SPEED_40G)
			mac_prop_info_set_default_uint8(ph, 1);
		else
			mac_prop_info_set_perm(ph, MAC_PROP_PERM_READ);
		break;

	case MAC_PROP_EN_25GFDX_CAP:
		if (lc->pcaps & FW_PORT_CAP32_SPEED_25G)
			mac_prop_info_set_default_uint8(ph, 1);
		else
			mac_prop_info_set_perm(ph, MAC_PROP_PERM_READ);
		break;

	case MAC_PROP_EN_10GFDX_CAP:
		if (lc->pcaps & FW_PORT_CAP32_SPEED_10G)
			mac_prop_info_set_default_uint8(ph, 1);
		else
			mac_prop_info_set_perm(ph, MAC_PROP_PERM_READ);
		break;

	case MAC_PROP_EN_1000FDX_CAP:
		if (lc->pcaps & FW_PORT_CAP32_SPEED_1G)
			mac_prop_info_set_default_uint8(ph, 1);
		else
			mac_prop_info_set_perm(ph, MAC_PROP_PERM_READ);
		break;

	case MAC_PROP_EN_100FDX_CAP:
		if (lc->pcaps & FW_PORT_CAP32_SPEED_100M)
			mac_prop_info_set_default_uint8(ph, 1);
		else
			mac_prop_info_set_perm(ph, MAC_PROP_PERM_READ);
		break;

	case MAC_PROP_ADV_100GFDX_CAP:
	case MAC_PROP_ADV_50GFDX_CAP:
	case MAC_PROP_ADV_40GFDX_CAP:
	case MAC_PROP_ADV_25GFDX_CAP:
	case MAC_PROP_ADV_10GFDX_CAP:
	case MAC_PROP_ADV_1000FDX_CAP:
	case MAC_PROP_ADV_100FDX_CAP:
		mac_prop_info_set_perm(ph, MAC_PROP_PERM_READ);
		break;

	case MAC_PROP_PRIVATE:
		propinfo(pi, name, ph);
		break;

	default:
		break;
	}
}

int
begin_synchronized_op(struct port_info *pi, int hold, int waitok)
{
	struct adapter *sc = pi->adapter;
	int rc = 0;

	ADAPTER_LOCK(sc);
	while (!IS_DOOMED(pi) && IS_BUSY(sc)) {
		if (!waitok) {
			rc = EBUSY;
			goto failed;
		} else if (cv_wait_sig(&sc->cv, &sc->lock) == 0) {
			rc = EINTR;
			goto failed;
		}
	}
	if (IS_DOOMED(pi) != 0) {	/* shouldn't happen on Solaris */
		rc = ENXIO;
		goto failed;
	}
	ASSERT(!IS_BUSY(sc));
	/* LINTED: E_CONSTANT_CONDITION */
	SET_BUSY(sc);

	if (!hold)
		ADAPTER_UNLOCK(sc);

	return (0);
failed:
	ADAPTER_UNLOCK(sc);
	return (rc);
}

void
end_synchronized_op(struct port_info *pi, int held)
{
	struct adapter *sc = pi->adapter;

	if (!held)
		ADAPTER_LOCK(sc);

	ADAPTER_LOCK_ASSERT_OWNED(sc);
	ASSERT(IS_BUSY(sc));
	/* LINTED: E_CONSTANT_CONDITION */
	CLR_BUSY(sc);
	cv_signal(&sc->cv);
	ADAPTER_UNLOCK(sc);
}

static int
t4_init_synchronized(struct port_info *pi)
{
	struct adapter *sc = pi->adapter;
	int rc = 0;

	ADAPTER_LOCK_ASSERT_NOTOWNED(sc);

	if (isset(&sc->open_device_map, pi->port_id) != 0)
		return (0);	/* already running */

	if (!(sc->flags & FULL_INIT_DONE) &&
	    ((rc = adapter_full_init(sc)) != 0))
		return (rc);	/* error message displayed already */

	if (!(pi->flags & PORT_INIT_DONE)) {
		rc = port_full_init(pi);
		if (rc != 0)
			return (rc); /* error message displayed already */
	} else
		enable_port_queues(pi);

	rc = -t4_set_rxmode(sc, sc->mbox, pi->viid, pi->mtu, 0, 0, 1, 0, false);
	if (rc != 0) {
		cxgb_printf(pi->dip, CE_WARN, "set_rxmode failed: %d", rc);
		goto done;
	}
	rc = t4_change_mac(sc, sc->mbox, pi->viid, pi->xact_addr_filt,
	    pi->hw_addr, true, &pi->smt_idx);
	if (rc < 0) {
		cxgb_printf(pi->dip, CE_WARN, "change_mac failed: %d", rc);
		rc = -rc;
		goto done;
	} else
		/* LINTED: E_ASSIGN_NARROW_CONV */
		pi->xact_addr_filt = rc;

	rc = -t4_link_l1cfg(sc, sc->mbox, pi->tx_chan, &pi->link_cfg,
	    pi->link_cfg.admin_caps);
	if (rc != 0) {
		cxgb_printf(pi->dip, CE_WARN, "start_link failed: %d", rc);
		goto done;
	}

	rc = -t4_enable_vi(sc, sc->mbox, pi->viid, true, true);
	if (rc != 0) {
		cxgb_printf(pi->dip, CE_WARN, "enable_vi failed: %d", rc);
		goto done;
	}

	/* all ok */
	setbit(&sc->open_device_map, pi->port_id);
done:
	if (rc != 0)
		(void) t4_uninit_synchronized(pi);

	return (rc);
}

/*
 * Idempotent.
 */
static int
t4_uninit_synchronized(struct port_info *pi)
{
	struct adapter *sc = pi->adapter;
	int rc;

	ADAPTER_LOCK_ASSERT_NOTOWNED(sc);

	/*
	 * Disable the VI so that all its data in either direction is discarded
	 * by the MPS.  Leave everything else (the queues, interrupts, and 1Hz
	 * tick) intact as the TP can deliver negative advice or data that it's
	 * holding in its RAM (for an offloaded connection) even after the VI is
	 * disabled.
	 */
	rc = -t4_enable_vi(sc, sc->mbox, pi->viid, false, false);
	if (rc != 0) {
		cxgb_printf(pi->dip, CE_WARN, "disable_vi failed: %d", rc);
		return (rc);
	}

	disable_port_queues(pi);

	clrbit(&sc->open_device_map, pi->port_id);

	pi->link_cfg.link_ok = 0;
	mac_link_update(pi->mh, LINK_STATE_UNKNOWN);

	return (0);
}

static void
propinfo(struct port_info *pi, const char *name, mac_prop_info_handle_t ph)
{
	struct adapter *sc = pi->adapter;
	struct driver_properties *p = &sc->props;
	struct link_config *lc = &pi->link_cfg;
	int v;
	char str[16];

	if (strcmp(name, T4PROP_TMR_IDX) == 0)
		v = is_10G_port(pi) ? p->tmr_idx_10g : p->tmr_idx_1g;
	else if (strcmp(name, T4PROP_PKTC_IDX) == 0)
		v = is_10G_port(pi) ? p->pktc_idx_10g : p->pktc_idx_1g;
	else if (strcmp(name, T4PROP_HW_CSUM) == 0)
		v = (pi->features & CXGBE_HW_CSUM) ? 1 : 0;
	else if (strcmp(name, T4PROP_HW_LSO) == 0)
		v = (pi->features & CXGBE_HW_LSO) ? 1 : 0;
	else if (strcmp(name, T4PROP_TX_PAUSE) == 0)
		v = (lc->pcaps & FW_PORT_CAP32_FC_TX) ? 1 : 0;
	else if (strcmp(name, T4PROP_RX_PAUSE) == 0)
		v = (lc->pcaps & FW_PORT_CAP32_FC_RX) ? 1 : 0;
#if MAC_VERSION == 1
	else if (strcmp(name, T4PROP_MTU) == 0)
		v = ETHERMTU;
#endif
	else
		return;

	(void) snprintf(str, sizeof (str), "%d", v);
	mac_prop_info_set_default_str(ph, str);
}

static int
getprop(struct port_info *pi, const char *name, uint_t size, void *val)
{
	struct link_config *lc = &pi->link_cfg;
	int v;

	if (strcmp(name, T4PROP_TMR_IDX) == 0)
		v = pi->tmr_idx;
	else if (strcmp(name, T4PROP_PKTC_IDX) == 0)
		v = pi->pktc_idx;
	else if (strcmp(name, T4PROP_HW_CSUM) == 0)
		v = (pi->features & CXGBE_HW_CSUM) ? 1 : 0;
	else if (strcmp(name, T4PROP_HW_LSO) == 0)
		v = (pi->features & CXGBE_HW_LSO) ? 1 : 0;
	else if (strcmp(name, T4PROP_TX_PAUSE) == 0)
		v = (lc->link_caps & FW_PORT_CAP32_FC_TX) ? 1 : 0;
	else if (strcmp(name, T4PROP_RX_PAUSE) == 0)
		v = (lc->link_caps & FW_PORT_CAP32_FC_RX) ? 1 : 0;
#if MAC_VERSION == 1
	else if (strcmp(name, T4PROP_MTU) == 0)
		v = pi->mtu;
#endif
	else
		return (ENOTSUP);

	(void) snprintf(val, size, "%d", v);
	return (0);
}

static int
setprop(struct port_info *pi, const char *name, const void *val)
{
	struct link_config *lc = &pi->link_cfg;
	fw_port_cap32_t new_caps = lc->admin_caps;
	int i, rc = 0, relink = 0, rx_mode = 0;
	struct adapter *sc = pi->adapter;
	struct sge_rxq *rxq;
	cc_pause_t fc = 0;
	long v;

	(void) ddi_strtol(val, NULL, 0, &v);

	if (strcmp(name, T4PROP_TMR_IDX) == 0) {
		if (v < 0 || v >= SGE_NTIMERS)
			return (EINVAL);
		if (v == pi->tmr_idx)
			return (0);

		/* LINTED: E_ASSIGN_NARROW_CONV */
		pi->tmr_idx = v;
		for_each_rxq(pi, i, rxq) {
			rxq->iq.intr_params = V_QINTR_TIMER_IDX(v) |
			    V_QINTR_CNT_EN(pi->pktc_idx >= 0);
		}

	} else if (strcmp(name, T4PROP_PKTC_IDX) == 0) {
		if (v >= SGE_NCOUNTERS)
			return (EINVAL);
		if (v == pi->pktc_idx || (v < 0 && pi->pktc_idx == -1))
			return (0);

		/* LINTED: E_ASSIGN_NARROW_CONV */
		pi->pktc_idx = v < 0 ? -1 : v;
		for_each_rxq(pi, i, rxq) {
			rxq->iq.intr_params = V_QINTR_TIMER_IDX(pi->tmr_idx) |
			    /* takes effect right away */
			    V_QINTR_CNT_EN(v >= 0);
			/* LINTED: E_ASSIGN_NARROW_CONV */
			rxq->iq.intr_pktc_idx = v; /* this needs fresh plumb */
		}
	} else if (strcmp(name, T4PROP_HW_CSUM) == 0) {
		if (v != 0 && v != 1)
			return (EINVAL);
		if (v == 1)
			pi->features |= CXGBE_HW_CSUM;
		else
			pi->features &= ~CXGBE_HW_CSUM;
	} else if (strcmp(name, T4PROP_HW_LSO) == 0) {
		if (v != 0 && v != 1)
			return (EINVAL);
		if (v == 1)
			pi->features |= CXGBE_HW_LSO;
		else
			pi->features &= ~CXGBE_HW_LSO;
	} else if (strcmp(name, T4PROP_TX_PAUSE) == 0) {
		if (v != 0 && v != 1)
			return (EINVAL);

		if ((new_caps & FW_PORT_CAP32_FC_TX) && (v == 1))
			fc |= PAUSE_TX;
		if (new_caps & FW_PORT_CAP32_FC_RX)
			fc |= PAUSE_RX;
		if (lc->admin_caps & FW_PORT_CAP32_ANEG)
			fc |= PAUSE_AUTONEG;

		t4_link_set_pause(pi, fc, &new_caps);
		relink = 1;

	} else if (strcmp(name, T4PROP_RX_PAUSE) == 0) {
		if (v != 0 && v != 1)
			return (EINVAL);

		if (new_caps & FW_PORT_CAP32_FC_TX)
			fc |= PAUSE_TX;
		if ((new_caps & FW_PORT_CAP32_FC_RX) && (v == 1))
			fc |= PAUSE_RX;
		if (lc->admin_caps & FW_PORT_CAP32_ANEG)
			fc |= PAUSE_AUTONEG;

		t4_link_set_pause(pi, fc, &new_caps);
		relink = 1;
	}
#if MAC_VERSION == 1
	else if (strcmp(name, T4PROP_MTU) == 0) {
		if (v < 46 || v > MAX_MTU)
			return (EINVAL);
		if (v == pi->mtu)
			return (0);

		pi->mtu = (int)v;
		(void) mac_maxsdu_update(pi->mh, v);
		rx_mode = 1;
	}
#endif
	else
		return (ENOTSUP);

	if (!(relink || rx_mode))
		return (0);

	/* If we are here, either relink or rx_mode is 1 */
	if (isset(&sc->open_device_map, pi->port_id) != 0) {
		if (relink != 0) {
			rc = begin_synchronized_op(pi, 1, 1);
			if (rc != 0)
				return (rc);
			rc = -t4_link_l1cfg(sc, sc->mbox, pi->tx_chan, lc,
			    new_caps);
			end_synchronized_op(pi, 1);
			if (rc != 0) {
				cxgb_printf(pi->dip, CE_WARN,
				    "%s link config failed: %d",
				    __func__, rc);
				return (rc);
			}
		} else if (rx_mode != 0) {
			rc = begin_synchronized_op(pi, 1, 1);
			if (rc != 0)
				return (rc);
			rc = -t4_set_rxmode(sc, sc->mbox, pi->viid, v, -1, -1,
			    -1, -1, false);
			end_synchronized_op(pi, 1);
			if (rc != 0)  {
				cxgb_printf(pi->dip, CE_WARN,
				    "set_rxmode failed: %d", rc);
				return (rc);
			}
		}
	}

	if (relink != 0)
		lc->admin_caps = new_caps;

	return (0);
}

void
t4_mc_init(struct port_info *pi)
{
	pi->props = t4_priv_props;
}

void
t4_mc_cb_init(struct port_info *pi)
{
	if (pi->adapter->props.multi_rings)
		pi->mc = &t4_m_ring_callbacks;
	else
		pi->mc = &t4_m_callbacks;
}

void
t4_os_link_changed(struct adapter *sc, int idx, int link_stat)
{
	struct port_info *pi = sc->port[idx];

	mac_link_update(pi->mh, link_stat ? LINK_STATE_UP : LINK_STATE_DOWN);
}

/* ARGSUSED */
void
t4_mac_rx(struct port_info *pi, struct sge_rxq *rxq, mblk_t *m)
{
	mac_rx(pi->mh, NULL, m);
}

void
t4_mac_tx_update(struct port_info *pi, struct sge_txq *txq)
{
	if (pi->adapter->props.multi_rings)
		mac_tx_ring_update(pi->mh, txq->ring_handle);
	else
		mac_tx_update(pi->mh);
}
