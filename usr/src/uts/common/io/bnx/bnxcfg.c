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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2019, Joyent, Inc.
 */

#include "bnxcfg.h"

const bnx_lnk_cfg_t bnx_copper_config = {
	B_TRUE,  /* link_autoneg   */
	B_FALSE, /* param_2500fdx  */
	B_TRUE,  /* param_1000fdx  */
	B_TRUE,  /* param_1000hdx  */
	B_TRUE,  /* param_100fdx   */
	B_TRUE,  /* param_100hdx   */
	B_TRUE,  /* param_10fdx    */
	B_TRUE,  /* param_10hdx    */
	B_TRUE,  /* param_tx_pause */
	B_TRUE   /* param_rx_pause */
};

const bnx_lnk_cfg_t bnx_serdes_config = {
	B_TRUE,  /* link_autoneg   */
	B_TRUE,  /* param_2500fdx  */
	B_TRUE,  /* param_1000fdx  */
	B_TRUE,  /* param_1000hdx  */
	B_FALSE, /* param_100fdx   */
	B_FALSE, /* param_100hdx   */
	B_FALSE, /* param_10fdx    */
	B_FALSE, /* param_10hdx    */
	B_TRUE,  /* param_tx_pause */
	B_TRUE   /* param_rx_pause */
};

static void
bnx_cfg_readbool(dev_info_t *dip, char *paramname, boolean_t *paramval)
{
	int rc;
	int *option;
	uint_t num_options;

	if (ddi_prop_exists(DDI_DEV_T_ANY, dip, DDI_PROP_NOTPROM, paramname) ==
	    1) {
		rc = ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS, paramname, &option, &num_options);

		if (rc == DDI_PROP_SUCCESS) {
			int inst = ddi_get_instance(dip);

			if (num_options >= inst) {
				if (option[inst] == 1) {
					*paramval = B_TRUE;
				} else {
					*paramval = B_FALSE;
				}
			}
		}

		ddi_prop_free(option);
	}
} /* bnx_cfg_readbool */

static void
bnx_cfg_readint(dev_info_t *dip, char *paramname, int *paramval)
{
	int rc;
	int *option;
	uint_t num_options;

	rc = ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    paramname, &option, &num_options);
	if (rc == DDI_PROP_SUCCESS) {
		int inst = ddi_get_instance(dip);

		if (num_options >= inst) {
			*paramval = option[inst];
		}

		ddi_prop_free(option);
	}
} /* bnx_cfg_readint */

void
bnx_cfg_msix(um_device_t * const umdevice)
{
	umdevice->dev_var.disableMsix = B_FALSE;

	bnx_cfg_readbool(umdevice->os_param.dip, "disable_msix",
	    &(umdevice->dev_var.disableMsix));
}

void
bnx_cfg_init(um_device_t *const umdevice)
{
	int option;
	lm_medium_t lmmedium;
	lm_device_t *lmdevice;

	lmdevice = &(umdevice->lm_dev);

	lmmedium = lm_get_medium(lmdevice);
	if (lmmedium == LM_MEDIUM_TYPE_FIBER) {
		umdevice->dev_var.isfiber = B_TRUE;

		bcopy(&bnx_serdes_config,
		    &(umdevice->hwinit.lnkcfg),
		    sizeof (bnx_serdes_config));
	} else {
		umdevice->dev_var.isfiber = B_FALSE;

		bcopy(&bnx_copper_config, &(umdevice->hwinit.lnkcfg),
		    sizeof (bnx_copper_config));
	}

	umdevice->hwinit.flow_autoneg = B_TRUE;
	umdevice->hwinit.wirespeed    = B_TRUE;

	bnx_cfg_readbool(umdevice->os_param.dip, "adv_autoneg_cap",
	    &(umdevice->hwinit.lnkcfg.link_autoneg));

	bnx_cfg_readbool(umdevice->os_param.dip, "adv_1000fdx_cap",
	    &(umdevice->hwinit.lnkcfg.param_1000fdx));

	bnx_cfg_readbool(umdevice->os_param.dip, "adv_1000hdx_cap",
	    &(umdevice->hwinit.lnkcfg.param_1000hdx));

	bnx_cfg_readbool(umdevice->os_param.dip, "tx_pause_cap",
	    &(umdevice->hwinit.lnkcfg.param_tx_pause));

	bnx_cfg_readbool(umdevice->os_param.dip, "rx_pause_cap",
	    &(umdevice->hwinit.lnkcfg.param_rx_pause));

	if (umdevice->dev_var.isfiber) {
		bnx_cfg_readbool(umdevice->os_param.dip, "adv_2500fdx_cap",
		    &(umdevice->hwinit.lnkcfg.param_2500fdx));
	} else {
		bnx_cfg_readbool(umdevice->os_param.dip, "adv_100fdx_cap",
		    &(umdevice->hwinit.lnkcfg.param_100fdx));

		bnx_cfg_readbool(umdevice->os_param.dip, "adv_100hdx_cap",
		    &(umdevice->hwinit.lnkcfg.param_100hdx));

		bnx_cfg_readbool(umdevice->os_param.dip, "adv_10fdx_cap",
		    &(umdevice->hwinit.lnkcfg.param_10fdx));

		bnx_cfg_readbool(umdevice->os_param.dip, "adv_10hdx_cap",
		    &(umdevice->hwinit.lnkcfg.param_10hdx));
	}

	bnx_cfg_readbool(umdevice->os_param.dip, "autoneg_flow",
	    &(umdevice->hwinit.flow_autoneg));

	bnx_cfg_readbool(umdevice->os_param.dip, "wirespeed",
	    &(umdevice->hwinit.wirespeed));

#if 1
	/* FIXME -- Do we really need "transfer-speed"? */
	/*
	 * The link speed may be forced to 10, 100 or 1000 Mbps using
	 * the property "transfer-speed". This may be done in OBP by
	 * using the command "apply transfer-speed=<speed> <device>".
	 * The speed may be 10, 100 or 1000 - any other value will be
	 * ignored.  Note that this *enables* autonegotiation, but
	 * restricts it to the speed specified by the property.
	 */
	option = 0;
	bnx_cfg_readint(umdevice->os_param.dip,
	    "transfer-speed", &option);
	switch (option) {
		case 1000:
			umdevice->hwinit.lnkcfg.link_autoneg  = B_TRUE;
			umdevice->hwinit.lnkcfg.param_1000fdx = B_TRUE;
			umdevice->hwinit.lnkcfg.param_1000hdx = B_TRUE;
			umdevice->hwinit.lnkcfg.param_100fdx  = B_FALSE;
			umdevice->hwinit.lnkcfg.param_100hdx  = B_FALSE;
			umdevice->hwinit.lnkcfg.param_10fdx   = B_FALSE;
			umdevice->hwinit.lnkcfg.param_10hdx   = B_FALSE;
			break;

		case 100:
			umdevice->hwinit.lnkcfg.link_autoneg  = B_TRUE;
			umdevice->hwinit.lnkcfg.param_1000fdx = B_FALSE;
			umdevice->hwinit.lnkcfg.param_1000hdx = B_FALSE;
			umdevice->hwinit.lnkcfg.param_100fdx  = B_TRUE;
			umdevice->hwinit.lnkcfg.param_100hdx  = B_TRUE;
			umdevice->hwinit.lnkcfg.param_10fdx   = B_FALSE;
			umdevice->hwinit.lnkcfg.param_10hdx   = B_FALSE;
			break;

		case 10:
			umdevice->hwinit.lnkcfg.link_autoneg  = B_TRUE;
			umdevice->hwinit.lnkcfg.param_1000fdx = B_FALSE;
			umdevice->hwinit.lnkcfg.param_1000hdx = B_FALSE;
			umdevice->hwinit.lnkcfg.param_100fdx  = B_FALSE;
			umdevice->hwinit.lnkcfg.param_100hdx  = B_FALSE;
			umdevice->hwinit.lnkcfg.param_10fdx   = B_TRUE;
			umdevice->hwinit.lnkcfg.param_10hdx   = B_TRUE;
			break;
	}
#endif


	/* FIXME -- Make the MAC address hwconf configurable. */

	/* Checksum configuration */
	option = USER_OPTION_CKSUM_DEFAULT;
	bnx_cfg_readint(umdevice->os_param.dip,
	    "checksum", &option);
	switch (option) {
		case USER_OPTION_CKSUM_TX_ONLY:
			umdevice->dev_var.enabled_oflds = LM_OFFLOAD_TX_IP_CKSUM
			    | LM_OFFLOAD_TX_TCP_CKSUM
			    | LM_OFFLOAD_TX_UDP_CKSUM;
			break;

		case USER_OPTION_CKSUM_RX_ONLY:
			umdevice->dev_var.enabled_oflds = LM_OFFLOAD_RX_IP_CKSUM
			    | LM_OFFLOAD_RX_TCP_CKSUM
			    | LM_OFFLOAD_RX_UDP_CKSUM;
			break;

		case USER_OPTION_CKSUM_TX_RX:
			umdevice->dev_var.enabled_oflds = LM_OFFLOAD_TX_IP_CKSUM
			    | LM_OFFLOAD_RX_IP_CKSUM
			    | LM_OFFLOAD_TX_TCP_CKSUM
			    | LM_OFFLOAD_RX_TCP_CKSUM
			    | LM_OFFLOAD_TX_UDP_CKSUM
			    | LM_OFFLOAD_RX_UDP_CKSUM;
			break;

		case USER_OPTION_CKSUM_NONE:
		default:
			umdevice->dev_var.enabled_oflds = LM_OFFLOAD_NONE;
			break;
	}

	/* Ticks interval between statistics block updates. */
	option = USER_OPTION_STATSTICKS_DEFAULT;
	bnx_cfg_readint(umdevice->os_param.dip,
	    USER_OPTION_KEYWORD_STATSTICKS, &option);
	if (option >= USER_OPTION_STATSTICKS_MIN &&
	    option <= USER_OPTION_STATSTICKS_MAX) {
		lmdevice->params.stats_ticks = option;
	} else {
		lmdevice->params.stats_ticks = USER_OPTION_STATSTICKS_DEFAULT;
	}

	/* Tx ticks for interrupt coalescing */
	option = USER_OPTION_TXTICKS_DEFAULT;
	bnx_cfg_readint(umdevice->os_param.dip,
	    "tx_coalesce_ticks", &option);
	if (option >= USER_OPTION_TICKS_MIN &&
	    option <= USER_OPTION_TICKS_MAX) {
		lmdevice->params.tx_ticks = option;
	} else {
		lmdevice->params.tx_ticks = USER_OPTION_TXTICKS_DEFAULT;
	}

	/* Interrupt mode Tx ticks for interrupt coalescing */
	option = USER_OPTION_TXTICKS_INT_DEFAULT;
	bnx_cfg_readint(umdevice->os_param.dip,
	    "tx_coalesce_ticks_int", &option);
	if (option >= USER_OPTION_TICKS_MIN &&
	    option <= USER_OPTION_TICKS_MAX) {
		lmdevice->params.tx_ticks_int = option;
	} else {
		lmdevice->params.tx_ticks_int = USER_OPTION_TXTICKS_INT_DEFAULT;
	}

	/* Rx ticks for interrupt coalescing */
	option = USER_OPTION_RXTICKS_DEFAULT;
	bnx_cfg_readint(umdevice->os_param.dip,
	    "rx_coalesce_ticks", &option);
	if (option >= USER_OPTION_TICKS_MIN &&
	    option <= USER_OPTION_TICKS_MAX) {
		lmdevice->params.rx_ticks = option;
	} else {
		lmdevice->params.rx_ticks = USER_OPTION_RXTICKS_DEFAULT;
	}

	/* Interrupt mode Rx ticks for interrupt coalescing */
	option = USER_OPTION_RXTICKS_INT_DEFAULT;
	bnx_cfg_readint(umdevice->os_param.dip,
	    "rx_coalesce_ticks_int", &option);
	if (option >= USER_OPTION_TICKS_INT_MIN &&
	    option <= USER_OPTION_TICKS_INT_MAX) {
		lmdevice->params.rx_ticks_int = option;
	} else {
		lmdevice->params.rx_ticks_int = USER_OPTION_RXTICKS_INT_DEFAULT;
	}


	/* Tx frames for interrupt coalescing */
	option = USER_OPTION_TXFRAMES_DEFAULT;
	bnx_cfg_readint(umdevice->os_param.dip,
	    "tx_coalesce_frames", &option);
	if (option >= USER_OPTION_FRAMES_MIN &&
	    option <= USER_OPTION_FRAMES_MAX) {
		lmdevice->params.tx_quick_cons_trip = option;
	} else {
		lmdevice->params.tx_quick_cons_trip =
		    USER_OPTION_TXFRAMES_DEFAULT;
	}

	/* Interrupt mode Tx frames for interrupt coalescing */
	option = USER_OPTION_TXFRAMES_INT_DEFAULT;
	bnx_cfg_readint(umdevice->os_param.dip,
	    "tx_coalesce_frames_int", &option);
	if (option >= USER_OPTION_FRAMES_MIN &&
	    option <= USER_OPTION_FRAMES_MAX) {
		lmdevice->params.tx_quick_cons_trip_int = option;
	} else {
		lmdevice->params.tx_quick_cons_trip_int =
		    USER_OPTION_TXFRAMES_INT_DEFAULT;
	}

	/* Rx frames for interrupt coalescing */
	option = USER_OPTION_RXFRAMES_DEFAULT;
	bnx_cfg_readint(umdevice->os_param.dip,
	    "rx_coalesce_frames", &option);
	if (option >= USER_OPTION_FRAMES_MIN &&
	    option <= USER_OPTION_FRAMES_MAX) {
		lmdevice->params.rx_quick_cons_trip = option;
	} else {
		lmdevice->params.rx_quick_cons_trip =
		    USER_OPTION_RXFRAMES_DEFAULT;
	}

	/* Interrupt mode Rx frames for interrupt coalescing */
	option = USER_OPTION_RXFRAMES_INT_DEFAULT;
	bnx_cfg_readint(umdevice->os_param.dip,
	    "rx_coalesce_frames_int", &option);
	if (option >= USER_OPTION_FRAMES_MIN &&
	    option <= USER_OPTION_FRAMES_MAX) {
		lmdevice->params.rx_quick_cons_trip_int = option;
	} else {
		lmdevice->params.rx_quick_cons_trip_int =
		    USER_OPTION_RXFRAMES_INT_DEFAULT;
	}


	option = USER_OPTION_TX_DESC_CNT_DEFAULT;
	bnx_cfg_readint(umdevice->os_param.dip,
	    "tx_descriptor_count", &option);
	if (option < USER_OPTION_TX_DESC_CNT_MIN ||
	    option > USER_OPTION_TX_DESC_CNT_MAX) {
		option = USER_OPTION_TX_DESC_CNT_DEFAULT;
	}

	/* FIXME -- tx bd pages assumes 1 pd === 1 bd */
	_TX_QINFO(umdevice, 0).desc_cnt = option;
	lmdevice->params.l2_tx_bd_page_cnt[0] = option / MAX_BD_PER_PAGE;
	if (option % MAX_BD_PER_PAGE) {
		lmdevice->params.l2_tx_bd_page_cnt[0]++;
	}
	if (lmdevice->params.l2_tx_bd_page_cnt[0] > 127) {
		lmdevice->params.l2_tx_bd_page_cnt[0] = 127;
	}


	option = USER_OPTION_RX_DESC_CNT_DEFAULT;
	bnx_cfg_readint(umdevice->os_param.dip,
	    "rx_descriptor_count", &option);
	if (option < USER_OPTION_RX_DESC_CNT_MIN ||
	    option > USER_OPTION_RX_DESC_CNT_MAX) {
		option = USER_OPTION_RX_DESC_CNT_DEFAULT;
	}

	lmdevice->params.l2_rx_desc_cnt[0] = option;
	option = (option * BNX_RECV_MAX_FRAGS) / MAX_BD_PER_PAGE;
	lmdevice->params.l2_rx_bd_page_cnt[0] = option;
	if (option % MAX_BD_PER_PAGE) {
		lmdevice->params.l2_rx_bd_page_cnt[0]++;
	}

	option = USER_OPTION_MTU_DEFAULT;
	bnx_cfg_readint(umdevice->os_param.dip,
	    "mtu", &option);
	if (option < USER_OPTION_MTU_MIN) {
		umdevice->dev_var.mtu = USER_OPTION_MTU_MIN;
	} else if (option > USER_OPTION_MTU_MAX) {
		umdevice->dev_var.mtu = USER_OPTION_MTU_MAX;
	} else {
		umdevice->dev_var.mtu = option;
	}
	lmdevice->params.mtu = umdevice->dev_var.mtu +
	    sizeof (struct ether_header) + VLAN_TAGSZ;

	/* Flag to enable double copy of transmit payload. */
	option = USER_OPTION_TX_DCOPY_THRESH_DEFAULT;
	bnx_cfg_readint(umdevice->os_param.dip,
	    "tx_copy_thresh", &option);
	if (option < MIN_ETHERNET_PACKET_SIZE) {
		option = MIN_ETHERNET_PACKET_SIZE;
	}
	umdevice->tx_copy_threshold = option;

	/* Flag to enable double copy of receive packet. */
	option = USER_OPTION_RX_DCOPY_DEFAULT;
	bnx_cfg_readint(umdevice->os_param.dip, USER_OPTION_KEYWORD_RX_DCOPY,
	    &option);
	if (option) {
		umdevice->rx_copy_threshold = 0xffffffff;
	} else {
		umdevice->rx_copy_threshold = 0;
	}
} /* bnx_cfg_init */


void
bnx_cfg_reset(um_device_t *const umdevice)
{
	/* Reset the link status. */
	umdevice->nddcfg.link_speed = 0;
	umdevice->nddcfg.link_duplex = B_FALSE;
	umdevice->nddcfg.link_tx_pause = B_FALSE;
	umdevice->nddcfg.link_rx_pause = B_FALSE;

	/* Reset the link partner status. */
	umdevice->remote.link_autoneg   = B_FALSE;
	umdevice->remote.param_2500fdx  = B_FALSE;
	umdevice->remote.param_1000fdx  = B_FALSE;
	umdevice->remote.param_1000hdx  = B_FALSE;
	umdevice->remote.param_100fdx   = B_FALSE;
	umdevice->remote.param_100hdx   = B_FALSE;
	umdevice->remote.param_10fdx    = B_FALSE;
	umdevice->remote.param_10hdx    = B_FALSE;
	umdevice->remote.param_tx_pause = B_FALSE;
	umdevice->remote.param_rx_pause = B_FALSE;

	/* Reset the configuration to the hardware default. */
	bcopy(&(umdevice->hwinit), &(umdevice->curcfg), sizeof (bnx_phy_cfg_t));
} /* bnx_cfg_reset */



static lm_medium_t
bnx_cfg_map_serdes(um_device_t *const umdevice)
{
	lm_medium_t lmmedium;
	lm_device_t *lmdevice;

	lmdevice = &(umdevice->lm_dev);

	lmmedium = LM_MEDIUM_TYPE_FIBER;

	if (umdevice->curcfg.lnkcfg.link_autoneg) {
		if (umdevice->curcfg.lnkcfg.param_2500fdx &&
		    umdevice->curcfg.lnkcfg.param_1000fdx &&
		    umdevice->curcfg.lnkcfg.param_1000hdx) {
			/*
			 * All autoneg speeds are advertised.
			 * Don't specify a speed so we get the full range.
			 */
			lmmedium |= LM_MEDIUM_SPEED_AUTONEG;
		} else {
			lmdevice->params.selective_autoneg =
			    SELECTIVE_AUTONEG_SINGLE_SPEED;

			if (umdevice->curcfg.lnkcfg.param_2500fdx) {
				lmmedium |= LM_MEDIUM_SPEED_2500MBPS
				    | LM_MEDIUM_FULL_DUPLEX;
			} else if (umdevice->curcfg.lnkcfg.param_1000fdx) {
				lmmedium |= LM_MEDIUM_SPEED_1000MBPS
				    | LM_MEDIUM_FULL_DUPLEX;
			} else if (umdevice->curcfg.lnkcfg.param_1000hdx) {
				lmmedium |= LM_MEDIUM_SPEED_1000MBPS
				    | LM_MEDIUM_HALF_DUPLEX;
			} else {
				/* Configuration error. */
				lmdevice->params.selective_autoneg =
				    SELECTIVE_AUTONEG_OFF;
				goto error;
			}
		}

		/*
		 * Enable serdes fallback for all but one particular HP
		 * platform.
		 */
		if (CHIP_NUM(lmdevice) == CHIP_NUM_5706 &&
		    !(lmdevice->hw_info.svid == 0x103c &&
		    lmdevice->hw_info.ssid == 0x310c)) {
			if (umdevice->curcfg.lnkcfg.param_2500fdx) {
				lmmedium |=
				    LM_MEDIUM_SPEED_AUTONEG_2_5G_FALLBACK;
			} else {
				lmmedium |= LM_MEDIUM_SPEED_AUTONEG_1G_FALLBACK;
			}
		}
	} else {
		if (umdevice->curcfg.lnkcfg.param_2500fdx) {
			lmmedium |= LM_MEDIUM_SPEED_2500MBPS
			    | LM_MEDIUM_FULL_DUPLEX;
		} else if (umdevice->curcfg.lnkcfg.param_1000fdx) {
			lmmedium |= LM_MEDIUM_SPEED_1000MBPS
			    | LM_MEDIUM_FULL_DUPLEX;
		} else {
			/* Configuration error. */
			goto error;
		}
	}

	return (lmmedium);

error:
	/* Just give them full autoneg with no fallback capabilities. */
	lmmedium |= LM_MEDIUM_SPEED_AUTONEG;

	return (lmmedium);
} /* bnx_cfg_map_serdes */



static lm_medium_t
bnx_cfg_map_copper(um_device_t *const umdevice)
{
	lm_medium_t lmmedium;
	lm_device_t *lmdevice;

	lmdevice = &(umdevice->lm_dev);

	lmmedium = LM_MEDIUM_TYPE_UTP;

	if (umdevice->curcfg.lnkcfg.link_autoneg) {
		if (umdevice->curcfg.lnkcfg.param_1000fdx == B_TRUE &&
		    umdevice->curcfg.lnkcfg.param_1000hdx == B_TRUE &&
		    umdevice->curcfg.lnkcfg.param_100fdx == B_TRUE &&
		    umdevice->curcfg.lnkcfg.param_100hdx == B_TRUE &&
		    umdevice->curcfg.lnkcfg.param_10fdx == B_TRUE &&
		    umdevice->curcfg.lnkcfg.param_10hdx == B_TRUE) {
			/*
			 * All autoneg speeds are advertised.
			 * Don't specify a speed so we get the full range.
			 */
			lmmedium |= LM_MEDIUM_SPEED_AUTONEG;
		} else {
			lmdevice->params.selective_autoneg =
			    SELECTIVE_AUTONEG_SINGLE_SPEED;

			if (umdevice->curcfg.lnkcfg.param_1000fdx) {
				lmmedium |= LM_MEDIUM_SPEED_1000MBPS
				    | LM_MEDIUM_FULL_DUPLEX;
			} else if (umdevice->curcfg.lnkcfg.param_1000hdx) {
				lmmedium |= LM_MEDIUM_SPEED_1000MBPS
				    | LM_MEDIUM_HALF_DUPLEX;

				if (umdevice->curcfg.lnkcfg.param_100fdx ==
				    B_TRUE &&
				    umdevice->curcfg.lnkcfg.param_100hdx ==
				    B_TRUE &&
				    umdevice->curcfg.lnkcfg.param_10fdx ==
				    B_TRUE &&
				    umdevice->curcfg.lnkcfg.param_10hdx ==
				    B_TRUE) {
					lmdevice->params.selective_autoneg =
					    SELECTIVE_AUTONEG_ENABLE_SLOWER_SPEEDS;
				}
			} else if (umdevice->curcfg.lnkcfg.param_100fdx) {
				lmmedium |= LM_MEDIUM_SPEED_100MBPS
				    | LM_MEDIUM_FULL_DUPLEX;

				if (umdevice->curcfg.lnkcfg.param_100hdx ==
				    B_TRUE &&
				    umdevice->curcfg.lnkcfg.param_10fdx ==
				    B_TRUE &&
				    umdevice->curcfg.lnkcfg.param_10hdx ==
				    B_TRUE) {
					lmdevice->params.selective_autoneg =
					    SELECTIVE_AUTONEG_ENABLE_SLOWER_SPEEDS;
				}
			} else if (umdevice->curcfg.lnkcfg.param_100hdx) {
				lmmedium |= LM_MEDIUM_SPEED_100MBPS
				    | LM_MEDIUM_HALF_DUPLEX;

				if (umdevice->curcfg.lnkcfg.param_10fdx ==
				    B_TRUE &&
				    umdevice->curcfg.lnkcfg.param_10hdx ==
				    B_TRUE) {
					lmdevice->params.selective_autoneg =
					    SELECTIVE_AUTONEG_ENABLE_SLOWER_SPEEDS;
				}
			} else if (umdevice->curcfg.lnkcfg.param_10fdx) {
				lmmedium |= LM_MEDIUM_SPEED_10MBPS
				    | LM_MEDIUM_FULL_DUPLEX;

				if (umdevice->curcfg.lnkcfg.param_10hdx ==
				    B_TRUE) {
					lmdevice->params.selective_autoneg =
					    SELECTIVE_AUTONEG_ENABLE_SLOWER_SPEEDS;
				}
			} else if (umdevice->curcfg.lnkcfg.param_10hdx) {
				lmmedium |= LM_MEDIUM_SPEED_10MBPS
				    | LM_MEDIUM_HALF_DUPLEX;
			} else {
				/* Configuration error. */
				lmdevice->params.selective_autoneg =
				    SELECTIVE_AUTONEG_OFF;
				goto error;
			}
		}
	} else {
		/*
		 * Forced speeds greater than 100Mbps intentionally omitted.
		 * Forcing speeds greater than 100Mbps on copper media is
		 * illegal.
		 */
		if (umdevice->curcfg.lnkcfg.param_100fdx) {
			lmmedium |= LM_MEDIUM_SPEED_100MBPS
			    | LM_MEDIUM_FULL_DUPLEX;
		} else if (umdevice->curcfg.lnkcfg.param_100hdx) {
			lmmedium |= LM_MEDIUM_SPEED_100MBPS
			    | LM_MEDIUM_HALF_DUPLEX;
		} else if (umdevice->curcfg.lnkcfg.param_10fdx) {
			lmmedium |= LM_MEDIUM_SPEED_10MBPS
			    | LM_MEDIUM_FULL_DUPLEX;
		} else if (umdevice->curcfg.lnkcfg.param_10hdx) {
			lmmedium |= LM_MEDIUM_SPEED_10MBPS
			    | LM_MEDIUM_HALF_DUPLEX;
		} else {
			/* Configuration error. */
			goto error;
		}
	}

	return (lmmedium);

error:
	/* Just give them full autoneg. */
	lmmedium |= LM_MEDIUM_SPEED_AUTONEG;

	return (lmmedium);
} /* bnx_cfg_map_copper */



/*
 * Name:	bnx_cfg_map_phy
 *
 * Input:	ptr to device structure
 *
 * Return:	None
 *
 * Description:	This function is translates user configuration parameter,
 *		ones accessible through 'ndd' commands to LM driver settings.
 *		Driver chooses best possible parameters if conflicting ones
 *		are set by the user.
 */
void
bnx_cfg_map_phy(um_device_t *const umdevice)
{
	lm_medium_t lmmedium;
	lm_device_t *lmdevice;
	lm_flow_control_t flowctrl;

	lmdevice = &(umdevice->lm_dev);

	/* Disable the remote PHY. */
	lmdevice->params.enable_remote_phy = 0;

	/* Assume selective autonegotiation is turned off. */
	lmdevice->params.selective_autoneg = SELECTIVE_AUTONEG_OFF;

	/* FIXME -- Clean up configuration parameters. */
	if (umdevice->dev_var.isfiber) {
		lmmedium = bnx_cfg_map_serdes(umdevice);
	} else {
		lmmedium = bnx_cfg_map_copper(umdevice);
	}

	lmdevice->params.req_medium = lmmedium;


	flowctrl = LM_FLOW_CONTROL_NONE;

	if (umdevice->curcfg.lnkcfg.param_tx_pause) {
		flowctrl |= LM_FLOW_CONTROL_TRANSMIT_PAUSE;
	}

	if (umdevice->curcfg.lnkcfg.param_rx_pause) {
		flowctrl |= LM_FLOW_CONTROL_RECEIVE_PAUSE;
	}

	if (umdevice->curcfg.flow_autoneg == B_TRUE &&
	    flowctrl != LM_FLOW_CONTROL_NONE) {
		/*
		 * FIXME -- LM Flow control constraint.
		 * LM_FLOW_CONTROL_AUTO_PAUSE ==
		 * (LM_FLOW_CONTROL_AUTO_PAUSE |
		 * LM_FLOW_CONTROL_TRANSMIT_PAUSE |
		 * LM_FLOW_CONTROL_RECEIVE_PAUSE)
		 * The LM does not allow us finer selection of what
		 * pause features to autoneg.
		 */
		flowctrl |= LM_FLOW_CONTROL_AUTO_PAUSE;
	}

	lmdevice->params.flow_ctrl_cap = flowctrl;

	lmdevice->params.wire_speed = umdevice->curcfg.wirespeed;
} /* bnx_cfg_map_phy */
