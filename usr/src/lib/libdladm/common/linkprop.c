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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2014, Joyent, Inc. All rights reserved.
 * Copyright 2015 Garrett D'Amore <garrett@damore.org>
 */

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <ctype.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/dld.h>
#include <sys/zone.h>
#include <fcntl.h>
#include <unistd.h>
#include <libdevinfo.h>
#include <zone.h>
#include <libdllink.h>
#include <libdladm_impl.h>
#include <libdlwlan_impl.h>
#include <libdlwlan.h>
#include <libdlvlan.h>
#include <libdlvnic.h>
#include <libdlib.h>
#include <libintl.h>
#include <dlfcn.h>
#include <link.h>
#include <inet/wifi_ioctl.h>
#include <libdladm.h>
#include <libdlstat.h>
#include <sys/param.h>
#include <sys/debug.h>
#include <sys/dld.h>
#include <inttypes.h>
#include <sys/ethernet.h>
#include <inet/iptun.h>
#include <net/wpa.h>
#include <sys/sysmacros.h>
#include <sys/vlan.h>
#include <libdlbridge.h>
#include <stp_in.h>
#include <netinet/dhcp.h>
#include <netinet/dhcp6.h>
#include <net/if_types.h>
#include <libinetutil.h>
#include <pool.h>
#include <libdlaggr.h>

/*
 * The linkprop get() callback.
 * - pd: 	pointer to the prop_desc_t
 * - propstrp:	a property string array to keep the returned property.
 *		Caller allocated.
 * - cntp:	number of returned properties.
 *		Caller also uses it to indicate how many it expects.
 */
struct prop_desc;
typedef struct prop_desc prop_desc_t;

typedef dladm_status_t	pd_getf_t(dladm_handle_t, prop_desc_t *pdp,
			datalink_id_t, char **propstp, uint_t *cntp,
			datalink_media_t, uint_t, uint_t *);

/*
 * The linkprop set() callback.
 * - propval:	a val_desc_t array which keeps the property values to be set.
 * - cnt:	number of properties to be set.
 * - flags: 	additional flags passed down the system call.
 *
 * pd_set takes val_desc_t given by pd_check(), translates it into
 * a format suitable for kernel consumption. This may require allocation
 * of ioctl buffers etc. pd_set() may call another common routine (used
 * by all other pd_sets) which invokes the ioctl.
 */
typedef dladm_status_t	pd_setf_t(dladm_handle_t, prop_desc_t *, datalink_id_t,
			    val_desc_t *propval, uint_t cnt, uint_t flags,
			    datalink_media_t);

/*
 * The linkprop check() callback.
 * - propstrp:	property string array which keeps the property to be checked.
 * - cnt:	number of properties.
 * - propval:	return value; the property values of the given property strings.
 *
 * pd_check checks that the input values are valid. It does so by
 * iteraring through the pd_modval list for the property. If
 * the modifiable values cannot be expressed as a list, a pd_check
 * specific to this property can be used. If the input values are
 * verified to be valid, pd_check allocates a val_desc_t and fills it
 * with either a val_desc_t found on the pd_modval list or something
 * generated on the fly.
 */
typedef dladm_status_t	pd_checkf_t(dladm_handle_t, prop_desc_t *pdp,
			    datalink_id_t, char **propstrp, uint_t *cnt,
			    uint_t flags, val_desc_t **propval,
			    datalink_media_t);

typedef struct link_attr_s {
	mac_prop_id_t	pp_id;
	size_t		pp_valsize;
	char		*pp_name;
} link_attr_t;

typedef struct dladm_linkprop_args_s {
	dladm_status_t	dla_status;
	uint_t		dla_flags;
} dladm_linkprop_args_t;

static dld_ioc_macprop_t *i_dladm_buf_alloc_by_name(size_t, datalink_id_t,
			    const char *, uint_t, dladm_status_t *);
static dld_ioc_macprop_t *i_dladm_buf_alloc_by_id(size_t, datalink_id_t,
			    mac_prop_id_t, uint_t, dladm_status_t *);
static dladm_status_t	i_dladm_get_public_prop(dladm_handle_t, datalink_id_t,
			    char *, uint_t, uint_t *, void *, size_t);

static dladm_status_t	i_dladm_set_private_prop(dladm_handle_t, datalink_id_t,
			    const char *, char **, uint_t, uint_t);
static dladm_status_t	i_dladm_get_priv_prop(dladm_handle_t, datalink_id_t,
			    const char *, char **, uint_t *, dladm_prop_type_t,
			    uint_t);
static dladm_status_t	i_dladm_macprop(dladm_handle_t, void *, boolean_t);
static const char	*dladm_perm2str(uint_t, char *);
static link_attr_t	*dladm_name2prop(const char *);
static link_attr_t	*dladm_id2prop(mac_prop_id_t);

static pd_getf_t	get_zone, get_autopush, get_rate_mod, get_rate,
			get_speed, get_channel, get_powermode, get_radio,
			get_duplex, get_link_state, get_binary, get_uint32,
			get_flowctl, get_maxbw, get_cpus, get_priority,
			get_tagmode, get_range, get_stp, get_bridge_forward,
			get_bridge_pvid, get_protection, get_rxrings,
			get_txrings, get_cntavail, get_secondary_macs,
			get_allowedips, get_allowedcids, get_pool,
			get_rings_range, get_linkmode_prop,
			get_promisc_filtered;

static pd_setf_t	set_zone, set_rate, set_powermode, set_radio,
			set_public_prop, set_resource, set_stp_prop,
			set_bridge_forward, set_bridge_pvid, set_secondary_macs,
			set_promisc_filtered;

static pd_checkf_t	check_zone, check_autopush, check_rate, check_hoplimit,
			check_encaplim, check_uint32, check_maxbw, check_cpus,
			check_stp_prop, check_bridge_pvid, check_allowedips,
			check_allowedcids, check_secondary_macs, check_rings,
			check_pool, check_prop;

struct prop_desc {
	/*
	 * link property name
	 */
	char			*pd_name;

	/*
	 * default property value, can be set to { "", NULL }
	 */
	val_desc_t		pd_defval;

	/*
	 * list of optional property values, can be NULL.
	 *
	 * This is set to non-NULL if there is a list of possible property
	 * values.  pd_optval would point to the array of possible values.
	 */
	val_desc_t		*pd_optval;

	/*
	 * count of the above optional property values. 0 if pd_optval is NULL.
	 */
	uint_t			pd_noptval;

	/*
	 * callback to set link property; set to NULL if this property is
	 * read-only and may be called before or after permanent update; see
	 * flags.
	 */
	pd_setf_t		*pd_set;

	/*
	 * callback to get modifiable link property
	 */
	pd_getf_t		*pd_getmod;

	/*
	 * callback to get current link property
	 */
	pd_getf_t		*pd_get;

	/*
	 * callback to validate link property value, set to NULL if pd_optval
	 * is not NULL. In that case, validate the value by comparing it with
	 * the pd_optval. Return a val_desc_t array pointer if the value is
	 * valid.
	 */
	pd_checkf_t		*pd_check;

	uint_t			pd_flags;
#define	PD_TEMPONLY	0x1	/* property is temporary only */
#define	PD_CHECK_ALLOC	0x2	/* alloc vd_val as part of pd_check */
#define	PD_AFTER_PERM	0x4	/* pd_set after db update; no temporary */
	/*
	 * indicate link classes this property applies to.
	 */
	datalink_class_t	pd_class;

	/*
	 * indicate link media type this property applies to.
	 */
	datalink_media_t	pd_dmedia;
};

#define	MAC_PROP_BUFSIZE(v)	sizeof (dld_ioc_macprop_t) + (v) - 1

/*
 * Supported link properties enumerated in the prop_table[] array are
 * computed using the callback functions in that array. To compute the
 * property value, multiple distinct system calls may be needed (e.g.,
 * for wifi speed, we need to issue system calls to get desired/supported
 * rates). The link_attr[] table enumerates the interfaces to the kernel,
 * and the type/size of the data passed in the user-kernel interface.
 */
static link_attr_t link_attr[] = {
	{ MAC_PROP_DUPLEX,	sizeof (link_duplex_t),	"duplex"},

	{ MAC_PROP_SPEED,	sizeof (uint64_t),	"speed"},

	{ MAC_PROP_STATUS,	sizeof (link_state_t),	"state"},

	{ MAC_PROP_AUTONEG,	sizeof (uint8_t),	"adv_autoneg_cap"},

	{ MAC_PROP_MTU,		sizeof (uint32_t),	"mtu"},

	{ MAC_PROP_FLOWCTRL,	sizeof (link_flowctrl_t), "flowctrl"},

	{ MAC_PROP_ZONE,	sizeof (dld_ioc_zid_t),	"zone"},

	{ MAC_PROP_AUTOPUSH,	sizeof (struct dlautopush), "autopush"},

	{ MAC_PROP_ADV_5000FDX_CAP, sizeof (uint8_t),	"adv_5000fdx_cap"},

	{ MAC_PROP_EN_5000FDX_CAP, sizeof (uint8_t),	"en_5000fdx_cap"},

	{ MAC_PROP_ADV_2500FDX_CAP, sizeof (uint8_t),	"adv_2500fdx_cap"},

	{ MAC_PROP_EN_2500FDX_CAP, sizeof (uint8_t),	"en_2500fdx_cap"},

	{ MAC_PROP_ADV_100GFDX_CAP, sizeof (uint8_t),	"adv_100gfdx_cap"},

	{ MAC_PROP_EN_100GFDX_CAP, sizeof (uint8_t),	"en_100gfdx_cap"},

	{ MAC_PROP_ADV_40GFDX_CAP, sizeof (uint8_t),	"adv_40gfdx_cap"},

	{ MAC_PROP_EN_40GFDX_CAP, sizeof (uint8_t),	"en_40gfdx_cap"},

	{ MAC_PROP_ADV_10GFDX_CAP, sizeof (uint8_t),	"adv_10gfdx_cap"},

	{ MAC_PROP_EN_10GFDX_CAP, sizeof (uint8_t),	"en_10gfdx_cap"},

	{ MAC_PROP_ADV_1000FDX_CAP, sizeof (uint8_t),	"adv_1000fdx_cap"},

	{ MAC_PROP_EN_1000FDX_CAP, sizeof (uint8_t),	"en_1000fdx_cap"},

	{ MAC_PROP_ADV_1000HDX_CAP, sizeof (uint8_t),	"adv_1000hdx_cap"},

	{ MAC_PROP_EN_1000HDX_CAP, sizeof (uint8_t),	"en_1000hdx_cap"},

	{ MAC_PROP_ADV_100FDX_CAP, sizeof (uint8_t),	"adv_100fdx_cap"},

	{ MAC_PROP_EN_100FDX_CAP, sizeof (uint8_t),	"en_100fdx_cap"},

	{ MAC_PROP_ADV_100HDX_CAP, sizeof (uint8_t),	"adv_100hdx_cap"},

	{ MAC_PROP_EN_100HDX_CAP, sizeof (uint8_t),	"en_100hdx_cap"},

	{ MAC_PROP_ADV_10FDX_CAP, sizeof (uint8_t),	"adv_10fdx_cap"},

	{ MAC_PROP_EN_10FDX_CAP, sizeof (uint8_t),	"en_10fdx_cap"},

	{ MAC_PROP_ADV_10HDX_CAP, sizeof (uint8_t),	"adv_10hdx_cap"},

	{ MAC_PROP_EN_10HDX_CAP, sizeof (uint8_t),	"en_10hdx_cap"},

	{ MAC_PROP_WL_ESSID,	sizeof (wl_linkstatus_t), "essid"},

	{ MAC_PROP_WL_BSSID,	sizeof (wl_bssid_t),	"bssid"},

	{ MAC_PROP_WL_BSSTYPE,	sizeof (wl_bss_type_t),	"bsstype"},

	{ MAC_PROP_WL_LINKSTATUS, sizeof (wl_linkstatus_t), "wl_linkstatus"},

	/* wl_rates_t has variable length */
	{ MAC_PROP_WL_DESIRED_RATES, sizeof (wl_rates_t), "desired_rates"},

	/* wl_rates_t has variable length */
	{ MAC_PROP_WL_SUPPORTED_RATES, sizeof (wl_rates_t), "supported_rates"},

	{ MAC_PROP_WL_AUTH_MODE, sizeof (wl_authmode_t), "authmode"},

	{ MAC_PROP_WL_ENCRYPTION, sizeof (wl_encryption_t), "encryption"},

	{ MAC_PROP_WL_RSSI,	sizeof (wl_rssi_t),	"signal"},

	{ MAC_PROP_WL_PHY_CONFIG, sizeof (wl_phy_conf_t), "phy_conf"},

	{ MAC_PROP_WL_CAPABILITY, sizeof (wl_capability_t), "capability"},

	{ MAC_PROP_WL_WPA,	sizeof (wl_wpa_t),	"wpa"},

	/*  wl_wpa_ess_t has variable length */
	{ MAC_PROP_WL_SCANRESULTS, sizeof (wl_wpa_ess_t), "scan_results"},

	{ MAC_PROP_WL_POWER_MODE, sizeof (wl_ps_mode_t), "powermode"},

	{ MAC_PROP_WL_RADIO,	sizeof (dladm_wlan_radio_t), "wl_radio"},

	{ MAC_PROP_WL_ESS_LIST, sizeof (wl_ess_list_t),	"wl_ess_list"},

	{ MAC_PROP_WL_KEY_TAB,	sizeof (wl_wep_key_tab_t), "wl_wep_key"},

	{ MAC_PROP_WL_CREATE_IBSS, sizeof (wl_create_ibss_t), "createibss"},

	/* wl_wpa_ie_t has variable length */
	{ MAC_PROP_WL_SETOPTIE,	sizeof (wl_wpa_ie_t),	"set_ie"},

	{ MAC_PROP_WL_DELKEY,	sizeof (wl_del_key_t),	"wpa_del_key"},

	{ MAC_PROP_WL_KEY,	sizeof (wl_key_t),	"wl_key"},

	{ MAC_PROP_WL_MLME,	sizeof (wl_mlme_t),	"mlme"},

	{ MAC_PROP_TAGMODE,	sizeof (link_tagmode_t),	"tagmode"},

	{ MAC_PROP_IPTUN_HOPLIMIT, sizeof (uint32_t),	"hoplimit"},

	{ MAC_PROP_IPTUN_ENCAPLIMIT, sizeof (uint32_t),	"encaplimit"},

	{ MAC_PROP_PVID,	sizeof (uint16_t),	"default_tag"},

	{ MAC_PROP_LLIMIT,	sizeof (uint32_t),	"learn_limit"},

	{ MAC_PROP_LDECAY,	sizeof (uint32_t),	"learn_decay"},

	{ MAC_PROP_RESOURCE,	sizeof (mac_resource_props_t),	"resource"},

	{ MAC_PROP_RESOURCE_EFF, sizeof (mac_resource_props_t),
	    "resource-effective"},

	{ MAC_PROP_RXRINGSRANGE, sizeof (mac_propval_range_t),	"rxrings"},

	{ MAC_PROP_TXRINGSRANGE, sizeof (mac_propval_range_t),	"txrings"},

	{ MAC_PROP_MAX_TX_RINGS_AVAIL,	sizeof (uint_t),
	    "txrings-available"},

	{ MAC_PROP_MAX_RX_RINGS_AVAIL,	sizeof (uint_t),
	    "rxrings-available"},

	{ MAC_PROP_MAX_RXHWCLNT_AVAIL,	sizeof (uint_t), "rxhwclnt-available"},

	{ MAC_PROP_MAX_TXHWCLNT_AVAIL,	sizeof (uint_t), "txhwclnt-available"},

	{ MAC_PROP_IB_LINKMODE,	sizeof (uint32_t),	"linkmode"},

	{ MAC_PROP_VN_PROMISC_FILTERED,	sizeof (boolean_t), "promisc-filtered"},

	{ MAC_PROP_SECONDARY_ADDRS, sizeof (mac_secondary_addr_t),
	    "secondary-macs"},

	{ MAC_PROP_PRIVATE,	0,			"driver-private"}
};

typedef struct bridge_public_prop_s {
	const char	*bpp_name;
	int		bpp_code;
} bridge_public_prop_t;

static const bridge_public_prop_t bridge_prop[] = {
	{ "stp", PT_CFG_NON_STP },
	{ "stp_priority", PT_CFG_PRIO },
	{ "stp_cost", PT_CFG_COST },
	{ "stp_edge", PT_CFG_EDGE },
	{ "stp_p2p", PT_CFG_P2P },
	{ "stp_mcheck", PT_CFG_MCHECK },
	{ NULL, 0 }
};

static  val_desc_t	link_duplex_vals[] = {
	{ "half", 	LINK_DUPLEX_HALF	},
	{ "full", 	LINK_DUPLEX_HALF	}
};
static  val_desc_t	link_status_vals[] = {
	{ "up",		LINK_STATE_UP		},
	{ "down",	LINK_STATE_DOWN		}
};
static  val_desc_t	link_01_vals[] = {
	{ "1",		1			},
	{ "0",		0			}
};
static  val_desc_t	link_flow_vals[] = {
	{ "no",		LINK_FLOWCTRL_NONE	},
	{ "tx",		LINK_FLOWCTRL_TX	},
	{ "rx",		LINK_FLOWCTRL_RX	},
	{ "bi",		LINK_FLOWCTRL_BI	}
};
static  val_desc_t	link_priority_vals[] = {
	{ "low",	MPL_LOW	},
	{ "medium",	MPL_MEDIUM	},
	{ "high",	MPL_HIGH	}
};

static val_desc_t	link_tagmode_vals[] = {
	{ "normal",	LINK_TAGMODE_NORMAL	},
	{ "vlanonly",	LINK_TAGMODE_VLANONLY	}
};

static  val_desc_t	link_protect_vals[] = {
	{ "mac-nospoof",	MPT_MACNOSPOOF	},
	{ "restricted",		MPT_RESTRICTED	},
	{ "ip-nospoof",		MPT_IPNOSPOOF	},
	{ "dhcp-nospoof",	MPT_DHCPNOSPOOF	},
};

static  val_desc_t	link_promisc_filtered_vals[] = {
	{ "off",	B_FALSE },
	{ "on",		B_TRUE },
};

static val_desc_t	dladm_wlan_radio_vals[] = {
	{ "on",		DLADM_WLAN_RADIO_ON	},
	{ "off",	DLADM_WLAN_RADIO_OFF	}
};

static val_desc_t	dladm_wlan_powermode_vals[] = {
	{ "off",	DLADM_WLAN_PM_OFF	},
	{ "fast",	DLADM_WLAN_PM_FAST	},
	{ "max",	DLADM_WLAN_PM_MAX	}
};

static  val_desc_t	stp_p2p_vals[] = {
	{ "true",	P2P_FORCE_TRUE		},
	{ "false",	P2P_FORCE_FALSE		},
	{ "auto",	P2P_AUTO		}
};

static  val_desc_t	dladm_part_linkmode_vals[] = {
	{ "cm",		DLADM_PART_CM_MODE	},
	{ "ud",		DLADM_PART_UD_MODE	},
};

#define	VALCNT(vals)    (sizeof ((vals)) / sizeof (val_desc_t))
#define	RESET_VAL	((uintptr_t)-1)
#define	UNSPEC_VAL	((uintptr_t)-2)

/*
 * For the default, if defaults are not defined for the property,
 * pd_defval.vd_name should be null. If the driver has to be contacted for the
 * value, vd_name should be the empty string (""). Otherwise, dladm will
 * just print whatever is in the table.
 */
static prop_desc_t	prop_table[] = {
	{ "channel",	{ NULL, 0 },
	    NULL, 0, NULL, NULL,
	    get_channel, NULL, 0,
	    DATALINK_CLASS_PHYS, DL_WIFI },

	{ "powermode",	{ "off", DLADM_WLAN_PM_OFF },
	    dladm_wlan_powermode_vals, VALCNT(dladm_wlan_powermode_vals),
	    set_powermode, NULL,
	    get_powermode, NULL, 0,
	    DATALINK_CLASS_PHYS, DL_WIFI },

	{ "radio",	{ "on", DLADM_WLAN_RADIO_ON },
	    dladm_wlan_radio_vals, VALCNT(dladm_wlan_radio_vals),
	    set_radio, NULL,
	    get_radio, NULL, 0,
	    DATALINK_CLASS_PHYS, DL_WIFI },

	{ "linkmode",	{ "cm", DLADM_PART_CM_MODE },
	    dladm_part_linkmode_vals, VALCNT(dladm_part_linkmode_vals),
	    set_public_prop, NULL, get_linkmode_prop, NULL, 0,
	    DATALINK_CLASS_PART, DL_IB },

	{ "speed",	{ "", 0 }, NULL, 0,
	    set_rate, get_rate_mod,
	    get_rate, check_rate, 0,
	    DATALINK_CLASS_PHYS, DATALINK_ANY_MEDIATYPE },

	{ "autopush",	{ "", 0 }, NULL, 0,
	    set_public_prop, NULL,
	    get_autopush, check_autopush, PD_CHECK_ALLOC,
	    DATALINK_CLASS_ALL, DATALINK_ANY_MEDIATYPE },

	{ "zone",	{ "", 0 }, NULL, 0,
	    set_zone, NULL,
	    get_zone, check_zone, PD_TEMPONLY|PD_CHECK_ALLOC,
	    DATALINK_CLASS_ALL, DATALINK_ANY_MEDIATYPE },

	{ "duplex",	{ "", 0 },
	    link_duplex_vals, VALCNT(link_duplex_vals),
	    NULL, NULL, get_duplex, NULL,
	    0, DATALINK_CLASS_PHYS, DL_ETHER },

	{ "state",	{ "up", LINK_STATE_UP },
	    link_status_vals, VALCNT(link_status_vals),
	    NULL, NULL, get_link_state, NULL,
	    0, DATALINK_CLASS_ALL, DATALINK_ANY_MEDIATYPE },

	{ "adv_autoneg_cap", { "", 0 },
	    link_01_vals, VALCNT(link_01_vals),
	    set_public_prop, NULL, get_binary, NULL,
	    0, DATALINK_CLASS_PHYS, DL_ETHER },

	{ "mtu", { "", 0 }, NULL, 0,
	    set_public_prop, get_range,
	    get_uint32, check_uint32, 0, DATALINK_CLASS_ALL,
	    DATALINK_ANY_MEDIATYPE },

	{ "flowctrl", { "", 0 },
	    link_flow_vals, VALCNT(link_flow_vals),
	    set_public_prop, NULL, get_flowctl, NULL,
	    0, DATALINK_CLASS_PHYS, DL_ETHER },

	{ "secondary-macs", { "--", 0 }, NULL, 0,
	    set_secondary_macs, NULL,
	    get_secondary_macs, check_secondary_macs, PD_CHECK_ALLOC,
	    DATALINK_CLASS_VNIC, DL_ETHER },

	{ "adv_100gfdx_cap", { "", 0 },
	    link_01_vals, VALCNT(link_01_vals),
	    NULL, NULL, get_binary, NULL,
	    0, DATALINK_CLASS_PHYS, DL_ETHER },

	{ "en_100gfdx_cap", { "", 0 },
	    link_01_vals, VALCNT(link_01_vals),
	    set_public_prop, NULL, get_binary, NULL,
	    0, DATALINK_CLASS_PHYS, DL_ETHER },

	{ "adv_40gfdx_cap", { "", 0 },
	    link_01_vals, VALCNT(link_01_vals),
	    NULL, NULL, get_binary, NULL,
	    0, DATALINK_CLASS_PHYS, DL_ETHER },

	{ "en_40gfdx_cap", { "", 0 },
	    link_01_vals, VALCNT(link_01_vals),
	    set_public_prop, NULL, get_binary, NULL,
	    0, DATALINK_CLASS_PHYS, DL_ETHER },

	{ "adv_10gfdx_cap", { "", 0 },
	    link_01_vals, VALCNT(link_01_vals),
	    NULL, NULL, get_binary, NULL,
	    0, DATALINK_CLASS_PHYS, DL_ETHER },

	{ "en_10gfdx_cap", { "", 0 },
	    link_01_vals, VALCNT(link_01_vals),
	    set_public_prop, NULL, get_binary, NULL,
	    0, DATALINK_CLASS_PHYS, DL_ETHER },

	{ "adv_5000fdx_cap", { "", 0 },
	    link_01_vals, VALCNT(link_01_vals),
	    NULL, NULL, get_binary, NULL,
	    0, DATALINK_CLASS_PHYS, DL_ETHER },

	{ "en_5000fdx_cap", { "", 0 },
	    link_01_vals, VALCNT(link_01_vals),
	    set_public_prop, NULL, get_binary, NULL,
	    0, DATALINK_CLASS_PHYS, DL_ETHER },

	{ "adv_2500fdx_cap", { "", 0 },
	    link_01_vals, VALCNT(link_01_vals),
	    NULL, NULL, get_binary, NULL,
	    0, DATALINK_CLASS_PHYS, DL_ETHER },

	{ "en_2500fdx_cap", { "", 0 },
	    link_01_vals, VALCNT(link_01_vals),
	    set_public_prop, NULL, get_binary, NULL,
	    0, DATALINK_CLASS_PHYS, DL_ETHER },

	{ "adv_1000fdx_cap", { "", 0 },
	    link_01_vals, VALCNT(link_01_vals),
	    NULL, NULL, get_binary, NULL,
	    0, DATALINK_CLASS_PHYS, DL_ETHER },

	{ "en_1000fdx_cap", { "", 0 },
	    link_01_vals, VALCNT(link_01_vals),
	    set_public_prop, NULL, get_binary, NULL,
	    0, DATALINK_CLASS_PHYS, DL_ETHER },

	{ "adv_1000hdx_cap", { "", 0 },
	    link_01_vals, VALCNT(link_01_vals),
	    NULL, NULL, get_binary, NULL,
	    0, DATALINK_CLASS_PHYS, DL_ETHER },

	{ "en_1000hdx_cap", { "", 0 },
	    link_01_vals, VALCNT(link_01_vals),
	    set_public_prop, NULL, get_binary, NULL,
	    0, DATALINK_CLASS_PHYS, DL_ETHER },

	{ "adv_100fdx_cap", { "", 0 },
	    link_01_vals, VALCNT(link_01_vals),
	    NULL, NULL, get_binary, NULL,
	    0, DATALINK_CLASS_PHYS, DL_ETHER },

	{ "en_100fdx_cap", { "", 0 },
	    link_01_vals, VALCNT(link_01_vals),
	    set_public_prop, NULL, get_binary, NULL,
	    0, DATALINK_CLASS_PHYS, DL_ETHER },

	{ "adv_100hdx_cap", { "", 0 },
	    link_01_vals, VALCNT(link_01_vals),
	    NULL, NULL, get_binary, NULL,
	    0, DATALINK_CLASS_PHYS, DL_ETHER },

	{ "en_100hdx_cap", { "", 0 },
	    link_01_vals, VALCNT(link_01_vals),
	    set_public_prop, NULL, get_binary, NULL,
	    0, DATALINK_CLASS_PHYS, DL_ETHER },

	{ "adv_10fdx_cap", { "", 0 },
	    link_01_vals, VALCNT(link_01_vals),
	    NULL, NULL, get_binary, NULL,
	    0, DATALINK_CLASS_PHYS, DL_ETHER },

	{ "en_10fdx_cap", { "", 0 },
	    link_01_vals, VALCNT(link_01_vals),
	    set_public_prop, NULL, get_binary, NULL,
	    0, DATALINK_CLASS_PHYS, DL_ETHER },

	{ "adv_10hdx_cap", { "", 0 },
	    link_01_vals, VALCNT(link_01_vals),
	    NULL, NULL, get_binary, NULL,
	    0, DATALINK_CLASS_PHYS, DL_ETHER },

	{ "en_10hdx_cap", { "", 0 },
	    link_01_vals, VALCNT(link_01_vals),
	    set_public_prop, NULL, get_binary, NULL,
	    0, DATALINK_CLASS_PHYS, DL_ETHER },

	{ "maxbw", { "--", RESET_VAL }, NULL, 0,
	    set_resource, NULL,
	    get_maxbw, check_maxbw, PD_CHECK_ALLOC,
	    DATALINK_CLASS_ALL, DATALINK_ANY_MEDIATYPE },

	{ "cpus", { "--", RESET_VAL }, NULL, 0,
	    set_resource, NULL,
	    get_cpus, check_cpus, 0,
	    DATALINK_CLASS_ALL, DATALINK_ANY_MEDIATYPE },

	{ "cpus-effective", { "--", 0 },
	    NULL, 0, NULL, NULL,
	    get_cpus, 0, 0,
	    DATALINK_CLASS_ALL, DATALINK_ANY_MEDIATYPE },

	{ "pool", { "--", RESET_VAL }, NULL, 0,
	    set_resource, NULL,
	    get_pool, check_pool, 0,
	    DATALINK_CLASS_ALL, DATALINK_ANY_MEDIATYPE },

	{ "pool-effective", { "--", 0 },
	    NULL, 0, NULL, NULL,
	    get_pool, 0, 0,
	    DATALINK_CLASS_ALL, DATALINK_ANY_MEDIATYPE },

	{ "priority", { "high", MPL_RESET },
	    link_priority_vals, VALCNT(link_priority_vals), set_resource,
	    NULL, get_priority, check_prop, 0,
	    DATALINK_CLASS_ALL, DATALINK_ANY_MEDIATYPE },

	{ "tagmode", { "vlanonly", LINK_TAGMODE_VLANONLY },
	    link_tagmode_vals, VALCNT(link_tagmode_vals),
	    set_public_prop, NULL, get_tagmode,
	    NULL, 0,
	    DATALINK_CLASS_PHYS | DATALINK_CLASS_AGGR | DATALINK_CLASS_VNIC,
	    DL_ETHER },

	{ "hoplimit", { "", 0 }, NULL, 0,
	    set_public_prop, get_range, get_uint32,
	    check_hoplimit, 0, DATALINK_CLASS_IPTUN, DATALINK_ANY_MEDIATYPE},

	{ "encaplimit", { "", 0 }, NULL, 0,
	    set_public_prop, get_range, get_uint32,
	    check_encaplim, 0, DATALINK_CLASS_IPTUN, DL_IPV6},

	{ "forward", { "1", 1 },
	    link_01_vals, VALCNT(link_01_vals),
	    set_bridge_forward, NULL, get_bridge_forward, NULL, PD_AFTER_PERM,
	    DATALINK_CLASS_ALL & ~DATALINK_CLASS_VNIC, DL_ETHER },

	{ "default_tag", { "1", 1 }, NULL, 0,
	    set_bridge_pvid, NULL, get_bridge_pvid, check_bridge_pvid,
	    0, DATALINK_CLASS_PHYS|DATALINK_CLASS_AGGR|
	    DATALINK_CLASS_ETHERSTUB|DATALINK_CLASS_SIMNET, DL_ETHER },

	{ "learn_limit", { "1000", 1000 }, NULL, 0,
	    set_public_prop, NULL, get_uint32,
	    check_uint32, 0,
	    DATALINK_CLASS_PHYS|DATALINK_CLASS_AGGR|
	    DATALINK_CLASS_ETHERSTUB|DATALINK_CLASS_SIMNET, DL_ETHER },

	{ "learn_decay", { "200", 200 }, NULL, 0,
	    set_public_prop, NULL, get_uint32,
	    check_uint32, 0,
	    DATALINK_CLASS_PHYS|DATALINK_CLASS_AGGR|
	    DATALINK_CLASS_ETHERSTUB|DATALINK_CLASS_SIMNET, DL_ETHER },

	{ "stp", { "1", 1 },
	    link_01_vals, VALCNT(link_01_vals),
	    set_stp_prop, NULL, get_stp, NULL, PD_AFTER_PERM,
	    DATALINK_CLASS_PHYS|DATALINK_CLASS_AGGR|
	    DATALINK_CLASS_ETHERSTUB|DATALINK_CLASS_SIMNET, DL_ETHER },

	{ "stp_priority", { "128", 128 }, NULL, 0,
	    set_stp_prop, NULL, get_stp, check_stp_prop, PD_AFTER_PERM,
	    DATALINK_CLASS_PHYS|DATALINK_CLASS_AGGR|
	    DATALINK_CLASS_ETHERSTUB|DATALINK_CLASS_SIMNET, DL_ETHER },

	{ "stp_cost", { "auto", 0 }, NULL, 0,
	    set_stp_prop, NULL, get_stp, check_stp_prop, PD_AFTER_PERM,
	    DATALINK_CLASS_PHYS|DATALINK_CLASS_AGGR|
	    DATALINK_CLASS_ETHERSTUB|DATALINK_CLASS_SIMNET, DL_ETHER },

	{ "stp_edge", { "1", 1 },
	    link_01_vals, VALCNT(link_01_vals),
	    set_stp_prop, NULL, get_stp, NULL, PD_AFTER_PERM,
	    DATALINK_CLASS_PHYS|DATALINK_CLASS_AGGR|
	    DATALINK_CLASS_ETHERSTUB|DATALINK_CLASS_SIMNET, DL_ETHER },

	{ "stp_p2p", { "auto", P2P_AUTO },
	    stp_p2p_vals, VALCNT(stp_p2p_vals),
	    set_stp_prop, NULL, get_stp, NULL, PD_AFTER_PERM,
	    DATALINK_CLASS_PHYS|DATALINK_CLASS_AGGR|
	    DATALINK_CLASS_ETHERSTUB|DATALINK_CLASS_SIMNET, DL_ETHER },

	{ "stp_mcheck", { "0", 0 },
	    link_01_vals, VALCNT(link_01_vals),
	    set_stp_prop, NULL, get_stp, check_stp_prop, PD_AFTER_PERM,
	    DATALINK_CLASS_PHYS|DATALINK_CLASS_AGGR|
	    DATALINK_CLASS_ETHERSTUB|DATALINK_CLASS_SIMNET, DL_ETHER },

	{ "protection", { "--", RESET_VAL },
	    link_protect_vals, VALCNT(link_protect_vals),
	    set_resource, NULL, get_protection, check_prop, 0,
	    DATALINK_CLASS_ALL, DATALINK_ANY_MEDIATYPE },

	{ "promisc-filtered", { "on", 1 },
	    link_promisc_filtered_vals, VALCNT(link_promisc_filtered_vals),
	    set_promisc_filtered, NULL, get_promisc_filtered, check_prop, 0,
	    DATALINK_CLASS_VNIC, DATALINK_ANY_MEDIATYPE },


	{ "allowed-ips", { "--", 0 },
	    NULL, 0, set_resource, NULL,
	    get_allowedips, check_allowedips, PD_CHECK_ALLOC,
	    DATALINK_CLASS_ALL, DATALINK_ANY_MEDIATYPE },

	{ "allowed-dhcp-cids", { "--", 0 },
	    NULL, 0, set_resource, NULL,
	    get_allowedcids, check_allowedcids, PD_CHECK_ALLOC,
	    DATALINK_CLASS_ALL, DATALINK_ANY_MEDIATYPE },

	{ "rxrings", { "--", RESET_VAL }, NULL, 0,
	    set_resource, get_rings_range, get_rxrings, check_rings, 0,
	    DATALINK_CLASS_ALL, DATALINK_ANY_MEDIATYPE },

	{ "rxrings-effective", { "--", 0 },
	    NULL, 0, NULL, NULL,
	    get_rxrings, NULL, 0,
	    DATALINK_CLASS_ALL, DATALINK_ANY_MEDIATYPE },

	{ "txrings", { "--", RESET_VAL }, NULL, 0,
	    set_resource, get_rings_range, get_txrings, check_rings, 0,
	    DATALINK_CLASS_ALL, DATALINK_ANY_MEDIATYPE },

	{ "txrings-effective", { "--", 0 },
	    NULL, 0, NULL, NULL,
	    get_txrings, NULL, 0,
	    DATALINK_CLASS_ALL, DATALINK_ANY_MEDIATYPE },

	{ "txrings-available", { "", 0 }, NULL, 0,
	    NULL, NULL, get_cntavail, NULL, 0,
	    DATALINK_CLASS_ALL, DATALINK_ANY_MEDIATYPE },

	{ "rxrings-available", { "", 0 }, NULL, 0,
	    NULL, NULL, get_cntavail, NULL, 0,
	    DATALINK_CLASS_ALL, DATALINK_ANY_MEDIATYPE },

	{ "rxhwclnt-available", { "", 0 }, NULL, 0,
	    NULL, NULL, get_cntavail, NULL, 0,
	    DATALINK_CLASS_ALL, DATALINK_ANY_MEDIATYPE },

	{ "txhwclnt-available", { "", 0 }, NULL, 0,
	    NULL, NULL, get_cntavail, NULL, 0,
	    DATALINK_CLASS_ALL, DATALINK_ANY_MEDIATYPE },

};

#define	DLADM_MAX_PROPS	(sizeof (prop_table) / sizeof (prop_desc_t))

static resource_prop_t rsrc_prop_table[] = {
	{"maxbw",		extract_maxbw},
	{"priority",		extract_priority},
	{"cpus",		extract_cpus},
	{"cpus-effective",	extract_cpus},
	{"pool",		extract_pool},
	{"pool-effective",	extract_pool},
	{"protection",		extract_protection},
	{"allowed-ips",		extract_allowedips},
	{"allowed-dhcp-cids",	extract_allowedcids},
	{"rxrings",		extract_rxrings},
	{"rxrings-effective",	extract_rxrings},
	{"txrings",		extract_txrings},
	{"txrings-effective",	extract_txrings}
};
#define	DLADM_MAX_RSRC_PROP (sizeof (rsrc_prop_table) / \
	sizeof (resource_prop_t))

/*
 * when retrieving  private properties, we pass down a buffer with
 * DLADM_PROP_BUF_CHUNK of space for the driver to return the property value.
 */
#define	DLADM_PROP_BUF_CHUNK	1024

static dladm_status_t	i_dladm_set_linkprop_db(dladm_handle_t, datalink_id_t,
			    const char *, char **, uint_t);
static dladm_status_t	i_dladm_get_linkprop_db(dladm_handle_t, datalink_id_t,
			    const char *, char **, uint_t *);
static dladm_status_t	i_dladm_walk_linkprop_priv_db(dladm_handle_t,
			    datalink_id_t, void *, int (*)(dladm_handle_t,
			    datalink_id_t, const char *, void *));
static dladm_status_t	i_dladm_set_single_prop(dladm_handle_t, datalink_id_t,
			    datalink_class_t, uint32_t, prop_desc_t *, char **,
			    uint_t, uint_t);
static dladm_status_t	i_dladm_set_linkprop(dladm_handle_t, datalink_id_t,
			    const char *, char **, uint_t, uint_t);
static dladm_status_t	i_dladm_getset_defval(dladm_handle_t, prop_desc_t *,
			    datalink_id_t, datalink_media_t, uint_t);

/*
 * Unfortunately, MAX_SCAN_SUPPORT_RATES is too small to allow all
 * rates to be retrieved. However, we cannot increase it at this
 * time because it will break binary compatibility with unbundled
 * WiFi drivers and utilities. So for now we define an additional
 * constant, MAX_SUPPORT_RATES, to allow all rates to be retrieved.
 */
#define	MAX_SUPPORT_RATES	64

#define	AP_ANCHOR	"[anchor]"
#define	AP_DELIMITER	'.'

/* ARGSUSED */
static dladm_status_t
check_prop(dladm_handle_t handle, prop_desc_t *pdp, datalink_id_t linkid,
    char **prop_val, uint_t *val_cntp, uint_t flags, val_desc_t **vdpp,
    datalink_media_t media)
{
	int		i, j;
	uint_t		val_cnt = *val_cntp;
	val_desc_t	*vdp = *vdpp;

	for (j = 0; j < val_cnt; j++) {
		for (i = 0; i < pdp->pd_noptval; i++) {
			if (strcasecmp(prop_val[j],
			    pdp->pd_optval[i].vd_name) == 0) {
				break;
			}
		}
		if (i == pdp->pd_noptval)
			return (DLADM_STATUS_BADVAL);

		(void) memcpy(&vdp[j], &pdp->pd_optval[i], sizeof (val_desc_t));
	}
	return (DLADM_STATUS_OK);
}

static dladm_status_t
i_dladm_set_single_prop(dladm_handle_t handle, datalink_id_t linkid,
    datalink_class_t class, uint32_t media, prop_desc_t *pdp, char **prop_val,
    uint_t val_cnt, uint_t flags)
{
	dladm_status_t	status = DLADM_STATUS_OK;
	val_desc_t	*vdp = NULL;
	boolean_t	needfree = B_FALSE;
	uint_t		cnt, i;

	if (!(pdp->pd_class & class))
		return (DLADM_STATUS_BADARG);

	if (!DATALINK_MEDIA_ACCEPTED(pdp->pd_dmedia, media))
		return (DLADM_STATUS_BADARG);

	if ((flags & DLADM_OPT_PERSIST) && (pdp->pd_flags & PD_TEMPONLY))
		return (DLADM_STATUS_TEMPONLY);

	if (!(flags & DLADM_OPT_ACTIVE))
		return (DLADM_STATUS_OK);

	if (pdp->pd_set == NULL)
		return (DLADM_STATUS_PROPRDONLY);

	if (prop_val != NULL) {
		vdp = calloc(val_cnt, sizeof (val_desc_t));
		if (vdp == NULL)
			return (DLADM_STATUS_NOMEM);

		if (pdp->pd_check != NULL) {
			needfree = ((pdp->pd_flags & PD_CHECK_ALLOC) != 0);
			status = pdp->pd_check(handle, pdp, linkid, prop_val,
			    &val_cnt, flags, &vdp, media);
		} else if (pdp->pd_optval != NULL) {
			status = check_prop(handle, pdp, linkid, prop_val,
			    &val_cnt, flags, &vdp, media);
		} else {
			status = DLADM_STATUS_BADARG;
		}

		if (status != DLADM_STATUS_OK)
			goto done;

		cnt = val_cnt;
	} else {
		boolean_t	defval;

		if (pdp->pd_defval.vd_name == NULL)
			return (DLADM_STATUS_NOTSUP);

		cnt = 1;
		defval = (strlen(pdp->pd_defval.vd_name) > 0);
		if ((pdp->pd_flags & PD_CHECK_ALLOC) == 0 && !defval) {
			status = i_dladm_getset_defval(handle, pdp, linkid,
			    media, flags);
			return (status);
		}

		vdp = calloc(1, sizeof (val_desc_t));
		if (vdp == NULL)
			return (DLADM_STATUS_NOMEM);

		if (defval) {
			(void) memcpy(vdp, &pdp->pd_defval,
			    sizeof (val_desc_t));
		} else if (pdp->pd_check != NULL) {
			needfree = ((pdp->pd_flags & PD_CHECK_ALLOC) != 0);
			status = pdp->pd_check(handle, pdp, linkid, prop_val,
			    &cnt, flags, &vdp, media);
			if (status != DLADM_STATUS_OK)
				goto done;
		}
	}
	if (pdp->pd_flags & PD_AFTER_PERM)
		status = (flags & DLADM_OPT_PERSIST) ? DLADM_STATUS_OK :
		    DLADM_STATUS_PERMONLY;
	else
		status = pdp->pd_set(handle, pdp, linkid, vdp, cnt, flags,
		    media);
	if (needfree) {
		for (i = 0; i < cnt; i++)
			free((void *)((val_desc_t *)vdp + i)->vd_val);
	}
done:
	free(vdp);
	return (status);
}

static dladm_status_t
i_dladm_set_linkprop(dladm_handle_t handle, datalink_id_t linkid,
    const char *prop_name, char **prop_val, uint_t val_cnt, uint_t flags)
{
	int			i;
	boolean_t		found = B_FALSE;
	datalink_class_t	class;
	uint32_t		media;
	dladm_status_t		status = DLADM_STATUS_OK;

	status = dladm_datalink_id2info(handle, linkid, NULL, &class, &media,
	    NULL, 0);
	if (status != DLADM_STATUS_OK)
		return (status);

	for (i = 0; i < DLADM_MAX_PROPS; i++) {
		prop_desc_t	*pdp = &prop_table[i];
		dladm_status_t	s;

		if (prop_name != NULL &&
		    (strcasecmp(prop_name, pdp->pd_name) != 0))
			continue;
		found = B_TRUE;
		s = i_dladm_set_single_prop(handle, linkid, class, media, pdp,
		    prop_val, val_cnt, flags);

		if (prop_name != NULL) {
			status = s;
			break;
		} else {
			if (s != DLADM_STATUS_OK &&
			    s != DLADM_STATUS_NOTSUP)
				status = s;
		}
	}
	if (!found) {
		if (prop_name[0] == '_') {
			/* other private properties */
			status = i_dladm_set_private_prop(handle, linkid,
			    prop_name, prop_val, val_cnt, flags);
		} else  {
			status = DLADM_STATUS_NOTFOUND;
		}
	}
	return (status);
}

/*
 * Set/reset link property for specific link
 */
dladm_status_t
dladm_set_linkprop(dladm_handle_t handle, datalink_id_t linkid,
    const char *prop_name, char **prop_val, uint_t val_cnt, uint_t flags)
{
	dladm_status_t	status = DLADM_STATUS_OK;

	if ((linkid == DATALINK_INVALID_LINKID) || (flags == 0) ||
	    (prop_val == NULL && val_cnt > 0) ||
	    (prop_val != NULL && val_cnt == 0) ||
	    (prop_name == NULL && prop_val != NULL)) {
		return (DLADM_STATUS_BADARG);
	}

	/*
	 * Check for valid link property against the flags passed
	 * and set the link property when active flag is passed.
	 */
	status = i_dladm_set_linkprop(handle, linkid, prop_name, prop_val,
	    val_cnt, flags);
	if (status != DLADM_STATUS_OK)
		return (status);

	if (flags & DLADM_OPT_PERSIST) {
		status = i_dladm_set_linkprop_db(handle, linkid, prop_name,
		    prop_val, val_cnt);

		if (status == DLADM_STATUS_OK && (flags & DLADM_OPT_ACTIVE)) {
			prop_desc_t *pdp = prop_table;
			int i;

			for (i = 0; i < DLADM_MAX_PROPS; i++, pdp++) {
				if (!(pdp->pd_flags & PD_AFTER_PERM))
					continue;
				if (prop_name != NULL &&
				    strcasecmp(prop_name, pdp->pd_name) != 0)
					continue;
				status = pdp->pd_set(handle, pdp, linkid, NULL,
				    0, flags, 0);
			}
		}
	}
	return (status);
}

/*
 * Walk all link properties of the given specific link.
 *
 * Note: this function currently lacks the ability to walk _all_ private
 * properties if the link, because there is no kernel interface to
 * retrieve all known private property names. Once such an interface
 * is added, this function should be fixed accordingly.
 */
dladm_status_t
dladm_walk_linkprop(dladm_handle_t handle, datalink_id_t linkid, void *arg,
    int (*func)(dladm_handle_t, datalink_id_t, const char *, void *))
{
	dladm_status_t		status;
	datalink_class_t	class;
	uint_t			media;
	int			i;

	if (linkid == DATALINK_INVALID_LINKID || func == NULL)
		return (DLADM_STATUS_BADARG);

	status = dladm_datalink_id2info(handle, linkid, NULL, &class, &media,
	    NULL, 0);
	if (status != DLADM_STATUS_OK)
		return (status);

	/* public */
	for (i = 0; i < DLADM_MAX_PROPS; i++) {
		if (!(prop_table[i].pd_class & class))
			continue;

		if (!DATALINK_MEDIA_ACCEPTED(prop_table[i].pd_dmedia, media))
			continue;

		if (func(handle, linkid, prop_table[i].pd_name, arg) ==
		    DLADM_WALK_TERMINATE) {
			break;
		}
	}

	/* private */
	status = i_dladm_walk_linkprop_priv_db(handle, linkid, arg, func);

	return (status);
}

/*
 * Get linkprop of the given specific link.
 */
dladm_status_t
dladm_get_linkprop(dladm_handle_t handle, datalink_id_t linkid,
    dladm_prop_type_t type, const char *prop_name, char **prop_val,
    uint_t *val_cntp)
{
	dladm_status_t		status = DLADM_STATUS_OK;
	datalink_class_t	class;
	uint_t			media;
	prop_desc_t		*pdp;
	uint_t			cnt, dld_flags = 0;
	int			i;
	uint_t			perm_flags;

	if (type == DLADM_PROP_VAL_DEFAULT)
		dld_flags |= DLD_PROP_DEFAULT;
	else if (type == DLADM_PROP_VAL_MODIFIABLE)
		dld_flags |= DLD_PROP_POSSIBLE;

	if (linkid == DATALINK_INVALID_LINKID || prop_name == NULL ||
	    prop_val == NULL || val_cntp == NULL || *val_cntp == 0)
		return (DLADM_STATUS_BADARG);

	for (i = 0; i < DLADM_MAX_PROPS; i++)
		if (strcasecmp(prop_name, prop_table[i].pd_name) == 0)
			break;

	if (i == DLADM_MAX_PROPS) {
		if (prop_name[0] == '_') {
			/*
			 * private property.
			 */
			if (type == DLADM_PROP_VAL_PERSISTENT)
				return (i_dladm_get_linkprop_db(handle, linkid,
				    prop_name, prop_val, val_cntp));
			else
				return (i_dladm_get_priv_prop(handle, linkid,
				    prop_name, prop_val, val_cntp, type,
				    dld_flags));
		} else {
			return (DLADM_STATUS_NOTFOUND);
		}
	}

	pdp = &prop_table[i];

	status = dladm_datalink_id2info(handle, linkid, NULL, &class, &media,
	    NULL, 0);
	if (status != DLADM_STATUS_OK)
		return (status);

	if (!(pdp->pd_class & class))
		return (DLADM_STATUS_BADARG);

	if (!DATALINK_MEDIA_ACCEPTED(pdp->pd_dmedia, media))
		return (DLADM_STATUS_BADARG);

	switch (type) {
	case DLADM_PROP_VAL_CURRENT:
		status = pdp->pd_get(handle, pdp, linkid, prop_val, val_cntp,
		    media, dld_flags, &perm_flags);
		break;

	case DLADM_PROP_VAL_PERM:
		if (pdp->pd_set == NULL) {
			perm_flags = MAC_PROP_PERM_READ;
		} else {
			status = pdp->pd_get(handle, pdp, linkid, prop_val,
			    val_cntp, media, dld_flags, &perm_flags);
		}

		*prop_val[0] = '\0';
		*val_cntp = 1;
		if (status == DLADM_STATUS_OK)
			(void) dladm_perm2str(perm_flags, *prop_val);
		break;

	case DLADM_PROP_VAL_DEFAULT:
		/*
		 * If defaults are not defined for the property,
		 * pd_defval.vd_name should be null. If the driver
		 * has to be contacted for the value, vd_name should
		 * be the empty string (""). Otherwise, dladm will
		 * just print whatever is in the table.
		 */
		if (pdp->pd_defval.vd_name == NULL) {
			status = DLADM_STATUS_NOTSUP;
			break;
		}

		if (strlen(pdp->pd_defval.vd_name) == 0) {
			status = pdp->pd_get(handle, pdp, linkid, prop_val,
			    val_cntp, media, dld_flags, &perm_flags);
		} else {
			(void) strcpy(*prop_val, pdp->pd_defval.vd_name);
		}
		*val_cntp = 1;
		break;

	case DLADM_PROP_VAL_MODIFIABLE:
		if (pdp->pd_getmod != NULL) {
			status = pdp->pd_getmod(handle, pdp, linkid, prop_val,
			    val_cntp, media, dld_flags, &perm_flags);
			break;
		}
		cnt = pdp->pd_noptval;
		if (cnt == 0) {
			status = DLADM_STATUS_NOTSUP;
		} else if (cnt > *val_cntp) {
			status = DLADM_STATUS_TOOSMALL;
		} else {
			for (i = 0; i < cnt; i++) {
				(void) strcpy(prop_val[i],
				    pdp->pd_optval[i].vd_name);
			}
			*val_cntp = cnt;
		}
		break;
	case DLADM_PROP_VAL_PERSISTENT:
		if (pdp->pd_flags & PD_TEMPONLY)
			return (DLADM_STATUS_TEMPONLY);
		status = i_dladm_get_linkprop_db(handle, linkid, prop_name,
		    prop_val, val_cntp);
		break;
	default:
		status = DLADM_STATUS_BADARG;
		break;
	}

	return (status);
}

/*
 * Get linkprop of the given specific link and run any possible conversion
 * of the values using the check function for the property. Fails if the
 * check function doesn't succeed for the property value.
 */
dladm_status_t
dladm_get_linkprop_values(dladm_handle_t handle, datalink_id_t linkid,
    dladm_prop_type_t type, const char *prop_name, uint_t *ret_val,
    uint_t *val_cntp)
{
	dladm_status_t		status;
	datalink_class_t	class;
	uint_t			media;
	prop_desc_t		*pdp;
	uint_t			dld_flags;
	int			valc, i;
	char			**prop_val;
	uint_t			perm_flags;

	if (linkid == DATALINK_INVALID_LINKID || prop_name == NULL ||
	    ret_val == NULL || val_cntp == NULL || *val_cntp == 0)
		return (DLADM_STATUS_BADARG);

	for (pdp = prop_table; pdp < prop_table + DLADM_MAX_PROPS; pdp++)
		if (strcasecmp(prop_name, pdp->pd_name) == 0)
			break;

	if (pdp == prop_table + DLADM_MAX_PROPS)
		return (DLADM_STATUS_NOTFOUND);

	if (pdp->pd_flags & PD_CHECK_ALLOC)
		return (DLADM_STATUS_BADARG);

	status = dladm_datalink_id2info(handle, linkid, NULL, &class, &media,
	    NULL, 0);
	if (status != DLADM_STATUS_OK)
		return (status);

	if (!(pdp->pd_class & class))
		return (DLADM_STATUS_BADARG);

	if (!DATALINK_MEDIA_ACCEPTED(pdp->pd_dmedia, media))
		return (DLADM_STATUS_BADARG);

	prop_val = malloc(*val_cntp * sizeof (*prop_val) +
	    *val_cntp * DLADM_PROP_VAL_MAX);
	if (prop_val == NULL)
		return (DLADM_STATUS_NOMEM);
	for (valc = 0; valc < *val_cntp; valc++)
		prop_val[valc] = (char *)(prop_val + *val_cntp) +
		    valc * DLADM_PROP_VAL_MAX;

	dld_flags = (type == DLADM_PROP_VAL_DEFAULT) ? DLD_PROP_DEFAULT : 0;

	switch (type) {
	case DLADM_PROP_VAL_CURRENT:
		status = pdp->pd_get(handle, pdp, linkid, prop_val, val_cntp,
		    media, dld_flags, &perm_flags);
		break;

	case DLADM_PROP_VAL_DEFAULT:
		/*
		 * If defaults are not defined for the property,
		 * pd_defval.vd_name should be null. If the driver
		 * has to be contacted for the value, vd_name should
		 * be the empty string (""). Otherwise, dladm will
		 * just print whatever is in the table.
		 */
		if (pdp->pd_defval.vd_name == NULL) {
			status = DLADM_STATUS_NOTSUP;
			break;
		}

		if (pdp->pd_defval.vd_name[0] != '\0') {
			*val_cntp = 1;
			*ret_val = pdp->pd_defval.vd_val;
			free(prop_val);
			return (DLADM_STATUS_OK);
		}
		status = pdp->pd_get(handle, pdp, linkid, prop_val, val_cntp,
		    media, dld_flags, &perm_flags);
		break;

	case DLADM_PROP_VAL_PERSISTENT:
		if (pdp->pd_flags & PD_TEMPONLY)
			status = DLADM_STATUS_TEMPONLY;
		else
			status = i_dladm_get_linkprop_db(handle, linkid,
			    prop_name, prop_val, val_cntp);
		break;

	default:
		status = DLADM_STATUS_BADARG;
		break;
	}

	if (status == DLADM_STATUS_OK) {
		if (pdp->pd_check != NULL) {
			val_desc_t *vdp;

			vdp = malloc(sizeof (val_desc_t) * *val_cntp);
			if (vdp == NULL)
				status = DLADM_STATUS_NOMEM;
			else
				status = pdp->pd_check(handle, pdp, linkid,
				    prop_val, val_cntp, 0, &vdp, media);
			if (status == DLADM_STATUS_OK) {
				for (valc = 0; valc < *val_cntp; valc++)
					ret_val[valc] = vdp[valc].vd_val;
			}
			free(vdp);
		} else {
			for (valc = 0; valc < *val_cntp; valc++) {
				for (i = 0; i < pdp->pd_noptval; i++) {
					if (strcmp(pdp->pd_optval[i].vd_name,
					    prop_val[valc]) == 0) {
						ret_val[valc] =
						    pdp->pd_optval[i].vd_val;
						break;
					}
				}
				if (i == pdp->pd_noptval) {
					status = DLADM_STATUS_FAILED;
					break;
				}
			}
		}
	}

	free(prop_val);

	return (status);
}

/*ARGSUSED*/
static int
i_dladm_init_one_prop(dladm_handle_t handle, datalink_id_t linkid,
    const char *prop_name, void *arg)
{
	char			*buf, **propvals;
	uint_t			i, valcnt = DLADM_MAX_PROP_VALCNT;
	dladm_status_t		status;
	dladm_linkprop_args_t	*dla = arg;

	if ((buf = malloc((sizeof (char *) + DLADM_PROP_VAL_MAX) *
	    DLADM_MAX_PROP_VALCNT)) == NULL) {
		return (DLADM_WALK_CONTINUE);
	}

	propvals = (char **)(void *)buf;
	for (i = 0; i < valcnt; i++) {
		propvals[i] = buf +
		    sizeof (char *) * DLADM_MAX_PROP_VALCNT +
		    i * DLADM_PROP_VAL_MAX;
	}

	if (dladm_get_linkprop(handle, linkid, DLADM_PROP_VAL_PERSISTENT,
	    prop_name, propvals, &valcnt) != DLADM_STATUS_OK) {
		goto done;
	}

	status = dladm_set_linkprop(handle, linkid, prop_name, propvals,
	    valcnt, dla->dla_flags | DLADM_OPT_ACTIVE);

	if (status != DLADM_STATUS_OK)
		dla->dla_status = status;

done:
	if (buf != NULL)
		free(buf);

	return (DLADM_WALK_CONTINUE);
}

/*ARGSUSED*/
static int
i_dladm_init_linkprop(dladm_handle_t handle, datalink_id_t linkid, void *arg)
{
	datalink_class_t	class;
	dladm_status_t		status;

	status = dladm_datalink_id2info(handle, linkid, NULL, &class, NULL,
	    NULL, 0);
	if (status != DLADM_STATUS_OK)
		return (DLADM_WALK_TERMINATE);

	if ((class & (DATALINK_CLASS_VNIC | DATALINK_CLASS_VLAN)) == 0)
		(void) dladm_init_linkprop(handle, linkid, B_TRUE);

	return (DLADM_WALK_CONTINUE);
}

dladm_status_t
dladm_init_linkprop(dladm_handle_t handle, datalink_id_t linkid,
    boolean_t any_media)
{
	dladm_status_t		status = DLADM_STATUS_OK;
	datalink_media_t	dmedia;
	uint32_t		media;
	dladm_linkprop_args_t	*dla;

	dmedia = any_media ? DATALINK_ANY_MEDIATYPE : DL_WIFI;

	dla = malloc(sizeof (dladm_linkprop_args_t));
	if (dla == NULL)
		return (DLADM_STATUS_NOMEM);
	dla->dla_flags = DLADM_OPT_BOOT;
	dla->dla_status = DLADM_STATUS_OK;

	if (linkid == DATALINK_ALL_LINKID) {
		(void) dladm_walk_datalink_id(i_dladm_init_linkprop, handle,
		    NULL, DATALINK_CLASS_ALL, dmedia, DLADM_OPT_PERSIST);
	} else if (any_media ||
	    ((dladm_datalink_id2info(handle, linkid, NULL, NULL, &media, NULL,
	    0) == DLADM_STATUS_OK) &&
	    DATALINK_MEDIA_ACCEPTED(dmedia, media))) {
		(void) dladm_walk_linkprop(handle, linkid, (void *)dla,
		    i_dladm_init_one_prop);
		status = dla->dla_status;
	}
	free(dla);
	return (status);
}

/* ARGSUSED */
static dladm_status_t
get_zone(dladm_handle_t handle, prop_desc_t *pdp, datalink_id_t linkid,
    char **prop_val, uint_t *val_cnt, datalink_media_t media,
    uint_t flags, uint_t *perm_flags)
{
	char			zone_name[ZONENAME_MAX];
	zoneid_t		zid;
	dladm_status_t		status;

	if (flags != 0)
		return (DLADM_STATUS_NOTSUP);

	status = i_dladm_get_public_prop(handle, linkid, pdp->pd_name, flags,
	    perm_flags, &zid, sizeof (zid));
	if (status != DLADM_STATUS_OK)
		return (status);

	*val_cnt = 1;
	if (zid != GLOBAL_ZONEID) {
		if (getzonenamebyid(zid, zone_name, sizeof (zone_name)) < 0) {
			return (dladm_errno2status(errno));
		}

		(void) strncpy(*prop_val, zone_name, DLADM_PROP_VAL_MAX);
	} else {
		*prop_val[0] = '\0';
	}

	return (DLADM_STATUS_OK);
}

typedef int (*zone_get_devroot_t)(char *, char *, size_t);

static int
i_dladm_get_zone_dev(char *zone_name, char *dev, size_t devlen)
{
	char			root[MAXPATHLEN];
	zone_get_devroot_t	real_zone_get_devroot;
	void			*dlhandle;
	void			*sym;
	int			ret;

	if ((dlhandle = dlopen("libzonecfg.so.1", RTLD_LAZY)) == NULL)
		return (-1);

	if ((sym = dlsym(dlhandle, "zone_get_devroot")) == NULL) {
		(void) dlclose(dlhandle);
		return (-1);
	}

	real_zone_get_devroot = (zone_get_devroot_t)sym;

	if ((ret = real_zone_get_devroot(zone_name, root, sizeof (root))) == 0)
		(void) snprintf(dev, devlen, "%s%s", root, "/dev");
	(void) dlclose(dlhandle);
	return (ret);
}

static dladm_status_t
i_dladm_update_deventry(dladm_handle_t handle, zoneid_t zid,
    datalink_id_t linkid, boolean_t add)
{
	char		path[MAXPATHLEN];
	char		name[MAXLINKNAMELEN];
	di_prof_t	prof = NULL;
	char		zone_name[ZONENAME_MAX];
	dladm_status_t	status;
	int		ret;

	if (getzonenamebyid(zid, zone_name, sizeof (zone_name)) < 0)
		return (dladm_errno2status(errno));
	if (i_dladm_get_zone_dev(zone_name, path, sizeof (path)) != 0)
		return (dladm_errno2status(errno));
	if (di_prof_init(path, &prof) != 0)
		return (dladm_errno2status(errno));

	status = dladm_linkid2legacyname(handle, linkid, name, MAXLINKNAMELEN);
	if (status != DLADM_STATUS_OK)
		goto cleanup;

	if (add)
		ret = di_prof_add_dev(prof, name);
	else
		ret = di_prof_add_exclude(prof, name);

	if (ret != 0) {
		status = dladm_errno2status(errno);
		goto cleanup;
	}

	if (di_prof_commit(prof) != 0)
		status = dladm_errno2status(errno);
cleanup:
	if (prof)
		di_prof_fini(prof);

	return (status);
}

/* ARGSUSED */
static dladm_status_t
set_zone(dladm_handle_t handle, prop_desc_t *pdp, datalink_id_t linkid,
    val_desc_t *vdp, uint_t val_cnt, uint_t flags, datalink_media_t media)
{
	dladm_status_t		status = DLADM_STATUS_OK;
	zoneid_t		zid_old, zid_new;
	dld_ioc_zid_t		*dzp;

	if (val_cnt != 1)
		return (DLADM_STATUS_BADVALCNT);

	dzp = (dld_ioc_zid_t *)vdp->vd_val;

	status = i_dladm_get_public_prop(handle, linkid, pdp->pd_name, flags,
	    NULL, &zid_old, sizeof (zid_old));
	if (status != DLADM_STATUS_OK)
		return (status);

	zid_new = dzp->diz_zid;
	if (zid_new == zid_old)
		return (DLADM_STATUS_OK);

	if ((status = set_public_prop(handle, pdp, linkid, vdp, val_cnt,
	    flags, media)) != DLADM_STATUS_OK)
		return (status);

	/*
	 * It is okay to fail to update the /dev entry (some vanity-named
	 * links do not have a /dev entry).
	 */
	if (zid_old != GLOBAL_ZONEID) {
		(void) i_dladm_update_deventry(handle, zid_old, linkid,
		    B_FALSE);
	}
	if (zid_new != GLOBAL_ZONEID)
		(void) i_dladm_update_deventry(handle, zid_new, linkid, B_TRUE);

	return (DLADM_STATUS_OK);
}

/* ARGSUSED */
static dladm_status_t
check_zone(dladm_handle_t handle, prop_desc_t *pdp, datalink_id_t linkid,
    char **prop_val, uint_t *val_cntp, uint_t flags, val_desc_t **vdpp,
    datalink_media_t media)
{
	char		*zone_name;
	zoneid_t	zoneid;
	dladm_status_t	status = DLADM_STATUS_OK;
	dld_ioc_zid_t	*dzp;
	uint_t		val_cnt = *val_cntp;
	val_desc_t	*vdp = *vdpp;

	if (val_cnt != 1)
		return (DLADM_STATUS_BADVALCNT);

	dzp = malloc(sizeof (dld_ioc_zid_t));
	if (dzp == NULL)
		return (DLADM_STATUS_NOMEM);

	zone_name = (prop_val != NULL) ? *prop_val : GLOBAL_ZONENAME;
	if ((zoneid = getzoneidbyname(zone_name)) == -1) {
		status = DLADM_STATUS_BADVAL;
		goto done;
	}

	if (zoneid != GLOBAL_ZONEID) {
		ushort_t	flags;

		if (zone_getattr(zoneid, ZONE_ATTR_FLAGS, &flags,
		    sizeof (flags)) < 0) {
			status = dladm_errno2status(errno);
			goto done;
		}

		if (!(flags & ZF_NET_EXCL)) {
			status = DLADM_STATUS_BADVAL;
			goto done;
		}
	}

	(void) memset(dzp, 0, sizeof (dld_ioc_zid_t));

	dzp->diz_zid = zoneid;
	dzp->diz_linkid = linkid;

	vdp->vd_val = (uintptr_t)dzp;
	return (DLADM_STATUS_OK);
done:
	free(dzp);
	return (status);
}

/* ARGSUSED */
static dladm_status_t
get_maxbw(dladm_handle_t handle, prop_desc_t *pdp, datalink_id_t linkid,
    char **prop_val, uint_t *val_cnt, datalink_media_t media,
    uint_t flags, uint_t *perm_flags)
{
	mac_resource_props_t	mrp;
	dladm_status_t		status;

	status = i_dladm_get_public_prop(handle, linkid, "resource", flags,
	    perm_flags, &mrp, sizeof (mrp));
	if (status != DLADM_STATUS_OK)
		return (status);

	if ((mrp.mrp_mask & MRP_MAXBW) == 0) {
		*val_cnt = 0;
		return (DLADM_STATUS_OK);
	}

	(void) dladm_bw2str(mrp.mrp_maxbw, prop_val[0]);
	*val_cnt = 1;
	return (DLADM_STATUS_OK);
}

/* ARGSUSED */
static dladm_status_t
check_maxbw(dladm_handle_t handle, prop_desc_t *pdp, datalink_id_t linkid,
    char **prop_val, uint_t *val_cntp, uint_t flags, val_desc_t **vdpp,
    datalink_media_t media)
{
	uint64_t	*maxbw;
	dladm_status_t	status = DLADM_STATUS_OK;
	uint_t		val_cnt = *val_cntp;
	val_desc_t	*vdp = *vdpp;

	if (val_cnt != 1)
		return (DLADM_STATUS_BADVALCNT);

	maxbw = malloc(sizeof (uint64_t));
	if (maxbw == NULL)
		return (DLADM_STATUS_NOMEM);

	status = dladm_str2bw(*prop_val, maxbw);
	if (status != DLADM_STATUS_OK) {
		free(maxbw);
		return (status);
	}

	if ((*maxbw < MRP_MAXBW_MINVAL) && (*maxbw != 0)) {
		free(maxbw);
		return (DLADM_STATUS_MINMAXBW);
	}

	vdp->vd_val = (uintptr_t)maxbw;
	return (DLADM_STATUS_OK);
}

/* ARGSUSED */
dladm_status_t
extract_maxbw(val_desc_t *vdp, uint_t cnt, void *arg)
{
	mac_resource_props_t *mrp = arg;

	if (vdp->vd_val == RESET_VAL) {
		mrp->mrp_maxbw = MRP_MAXBW_RESETVAL;
	} else {
		bcopy((char *)vdp->vd_val, &mrp->mrp_maxbw, sizeof (uint64_t));
	}
	mrp->mrp_mask |= MRP_MAXBW;

	return (DLADM_STATUS_OK);
}

/* ARGSUSED */
static dladm_status_t
get_cpus(dladm_handle_t handle, prop_desc_t *pdp, datalink_id_t linkid,
    char **prop_val, uint_t *val_cnt, datalink_media_t media,
    uint_t flags, uint_t *perm_flags)
{
	dladm_status_t		status;
	mac_resource_props_t	mrp;
	mac_propval_range_t	*pv_range;
	int			err;

	if (strcmp(pdp->pd_name, "cpus-effective") == 0) {
		status = i_dladm_get_public_prop(handle, linkid,
		    "resource-effective", flags, perm_flags, &mrp,
		    sizeof (mrp));
	} else {
		status = i_dladm_get_public_prop(handle, linkid,
		    "resource", flags, perm_flags, &mrp, sizeof (mrp));
	}

	if (status != DLADM_STATUS_OK)
		return (status);

	if (mrp.mrp_ncpus > *val_cnt)
		return (DLADM_STATUS_TOOSMALL);

	if (mrp.mrp_ncpus == 0) {
		*val_cnt = 0;
		return (DLADM_STATUS_OK);
	}

	/* Sort CPU list and convert it to a mac_propval_range */
	status = dladm_list2range(mrp.mrp_cpu, mrp.mrp_ncpus,
	    MAC_PROPVAL_UINT32, &pv_range);
	if (status != DLADM_STATUS_OK)
		return (status);

	/* Write CPU ranges and individual CPUs */
	err = dladm_range2strs(pv_range, prop_val);
	if (err != 0) {
		free(pv_range);
		return (dladm_errno2status(err));
	}

	*val_cnt = pv_range->mpr_count;
	free(pv_range);

	return (DLADM_STATUS_OK);
}

/* ARGSUSED */
static dladm_status_t
check_cpus(dladm_handle_t handle, prop_desc_t *pdp, datalink_id_t linkid,
    char **prop_val, uint_t *val_cntp, uint_t flags, val_desc_t **vdpp,
    datalink_media_t media)
{
	int			i, j, rc;
	long			nproc = sysconf(_SC_NPROCESSORS_CONF);
	mac_resource_props_t	mrp;
	mac_propval_range_t	*pv_range;
	uint_t			perm_flags;
	uint32_t		ncpus;
	uint32_t		*cpus = mrp.mrp_cpu;
	val_desc_t		*vdp = *vdpp;
	val_desc_t		*newvdp;
	uint_t			val_cnt = *val_cntp;
	dladm_status_t		status = DLADM_STATUS_OK;

	/* Get the current pool property */
	status = i_dladm_get_public_prop(handle, linkid, "resource", 0,
	    &perm_flags, &mrp, sizeof (mrp));

	if (status == DLADM_STATUS_OK) {
		/* Can't set cpus if a pool is set */
		if (strlen(mrp.mrp_pool) != 0)
			return (DLADM_STATUS_POOLCPU);
	}

	/* Read ranges and convert to mac_propval_range */
	status = dladm_strs2range(prop_val, val_cnt, MAC_PROPVAL_UINT32,
	    &pv_range);
	if (status != DLADM_STATUS_OK)
		goto done1;

	/* Convert mac_propval_range to a single CPU list */
	ncpus = MRP_NCPUS;
	status = dladm_range2list(pv_range, cpus, &ncpus);
	if (status != DLADM_STATUS_OK)
		goto done1;

	/*
	 * If a range of CPUs was entered, update value count and reallocate
	 * the array of val_desc_t's.  The array allocated was sized for
	 * indvidual elements, but needs to be reallocated to accomodate the
	 * expanded list of CPUs.
	 */
	if (val_cnt < ncpus) {
		newvdp = calloc(*val_cntp, sizeof (val_desc_t));
		if (newvdp == NULL) {
			status = DLADM_STATUS_NOMEM;
			goto done1;
		}
		vdp = newvdp;
	}

	/* Check if all CPUs in the list are online */
	for (i = 0; i < ncpus; i++) {
		if (cpus[i] >= nproc) {
			status = DLADM_STATUS_BADCPUID;
			goto done2;
		}

		rc = p_online(cpus[i], P_STATUS);
		if (rc < 1) {
			status = DLADM_STATUS_CPUERR;
			goto done2;
		}

		if (rc != P_ONLINE) {
			status = DLADM_STATUS_CPUNOTONLINE;
			goto done2;
		}

		vdp[i].vd_val = (uintptr_t)cpus[i];
	}

	/* Check for duplicate CPUs */
	for (i = 0; i < *val_cntp; i++) {
		for (j = 0; j < *val_cntp; j++) {
			if (i != j && vdp[i].vd_val == vdp[j].vd_val) {
				status = DLADM_STATUS_BADVAL;
				goto done2;
			}
		}
	}

	/* Update *val_cntp and *vdpp if everything was OK */
	if (val_cnt < ncpus) {
		*val_cntp = ncpus;
		free(*vdpp);
		*vdpp = newvdp;
	}

	status = DLADM_STATUS_OK;
	goto done1;

done2:
	free(newvdp);
done1:
	free(pv_range);
	return (status);
}

/* ARGSUSED */
dladm_status_t
extract_cpus(val_desc_t *vdp, uint_t cnt, void *arg)
{
	mac_resource_props_t	*mrp = arg;
	int			i;

	if (vdp[0].vd_val == RESET_VAL) {
		bzero(&mrp->mrp_cpus, sizeof (mac_cpus_t));
		mrp->mrp_mask |= MRP_CPUS;
		return (DLADM_STATUS_OK);
	}

	for (i = 0; i < cnt; i++)
		mrp->mrp_cpu[i] = (uint32_t)vdp[i].vd_val;

	mrp->mrp_ncpus = cnt;
	mrp->mrp_mask |= (MRP_CPUS|MRP_CPUS_USERSPEC);
	mrp->mrp_fanout_mode = MCM_CPUS;
	mrp->mrp_rx_intr_cpu = -1;

	return (DLADM_STATUS_OK);
}

/*
 * Get the pool datalink property from the kernel.  This is used
 * for both the user specified pool and effective pool properties.
 */
/* ARGSUSED */
static dladm_status_t
get_pool(dladm_handle_t handle, prop_desc_t *pdp, datalink_id_t linkid,
    char **prop_val, uint_t *val_cnt, datalink_media_t media,
    uint_t flags, uint_t *perm_flags)
{
	mac_resource_props_t	mrp;
	dladm_status_t		status;

	if (strcmp(pdp->pd_name, "pool-effective") == 0) {
		status = i_dladm_get_public_prop(handle, linkid,
		    "resource-effective", flags, perm_flags, &mrp,
		    sizeof (mrp));
	} else {
		status = i_dladm_get_public_prop(handle, linkid,
		    "resource", flags, perm_flags, &mrp, sizeof (mrp));
	}

	if (status != DLADM_STATUS_OK)
		return (status);

	if (strlen(mrp.mrp_pool) == 0) {
		(*prop_val)[0] = '\0';
	} else {
		(void) snprintf(*prop_val, DLADM_PROP_VAL_MAX,
		    "%s", mrp.mrp_pool);
	}
	*val_cnt = 1;

	return (DLADM_STATUS_OK);
}

/* ARGSUSED */
static dladm_status_t
check_pool(dladm_handle_t handle, prop_desc_t *pdp, datalink_id_t linkid,
    char **prop_val, uint_t *val_cntp, uint_t flags, val_desc_t **vdpp,
    datalink_media_t media)
{
	pool_conf_t		*poolconf;
	pool_t			*pool;
	mac_resource_props_t	mrp;
	dladm_status_t		status;
	uint_t			perm_flags;
	char			*poolname;
	val_desc_t		*vdp = *vdpp;

	/* Get the current cpus property */
	status = i_dladm_get_public_prop(handle, linkid, "resource", 0,
	    &perm_flags, &mrp, sizeof (mrp));

	if (status == DLADM_STATUS_OK) {
		/* Can't set pool if cpus are set */
		if (mrp.mrp_ncpus != 0)
			return (DLADM_STATUS_POOLCPU);
	}

	poolname = malloc(sizeof (mrp.mrp_pool));
	if (poolname == NULL)
		return (DLADM_STATUS_NOMEM);

	/* Check for pool's availability if not booting */
	if ((flags & DLADM_OPT_BOOT) == 0) {

		/* Allocate and open pool configuration */
		if ((poolconf = pool_conf_alloc()) == NULL)
			return (DLADM_STATUS_BADVAL);

		if (pool_conf_open(poolconf, pool_dynamic_location(), PO_RDONLY)
		    != PO_SUCCESS) {
			pool_conf_free(poolconf);
			return (DLADM_STATUS_BADVAL);
		}

		/* Look for pool name */
		if ((pool = pool_get_pool(poolconf, *prop_val)) == NULL) {
			pool_conf_free(poolconf);
			return (DLADM_STATUS_BADVAL);
		}

		pool_conf_free(poolconf);
		free(pool);
	}

	(void) strlcpy(poolname, *prop_val, sizeof (mrp.mrp_pool));
	vdp->vd_val = (uintptr_t)poolname;

	return (DLADM_STATUS_OK);
}

/* ARGSUSED */
dladm_status_t
extract_pool(val_desc_t *vdp, uint_t cnt, void *arg)
{
	mac_resource_props_t	*mrp = (mac_resource_props_t *)arg;

	if (vdp->vd_val == RESET_VAL) {
		bzero(&mrp->mrp_pool, sizeof (mrp->mrp_pool));
		mrp->mrp_mask |= MRP_POOL;
		return (DLADM_STATUS_OK);
	}

	(void) strlcpy(mrp->mrp_pool, (char *)vdp->vd_val,
	    sizeof (mrp->mrp_pool));
	mrp->mrp_mask |= MRP_POOL;
	/*
	 * Use MCM_CPUS since the fanout count is not user specified
	 * and will be determined by the cpu list generated from the
	 * pool.
	 */
	mrp->mrp_fanout_mode = MCM_CPUS;

	return (DLADM_STATUS_OK);
}

/* ARGSUSED */
static dladm_status_t
get_priority(dladm_handle_t handle, prop_desc_t *pdp,
    datalink_id_t linkid, char **prop_val, uint_t *val_cnt,
    datalink_media_t media, uint_t flags, uint_t *perm_flags)
{
	mac_resource_props_t	mrp;
	mac_priority_level_t	pri;
	dladm_status_t		status;

	status = i_dladm_get_public_prop(handle, linkid, "resource", flags,
	    perm_flags, &mrp, sizeof (mrp));
	if (status != DLADM_STATUS_OK)
		return (status);

	pri = ((mrp.mrp_mask & MRP_PRIORITY) == 0) ? MPL_HIGH :
	    mrp.mrp_priority;

	(void) dladm_pri2str(pri, prop_val[0]);
	*val_cnt = 1;
	return (DLADM_STATUS_OK);
}

/* ARGSUSED */
dladm_status_t
extract_priority(val_desc_t *vdp, uint_t cnt, void *arg)
{
	mac_resource_props_t *mrp = arg;

	if (cnt != 1)
		return (DLADM_STATUS_BADVAL);

	mrp->mrp_priority = (mac_priority_level_t)vdp->vd_val;
	mrp->mrp_mask |= MRP_PRIORITY;

	return (DLADM_STATUS_OK);
}

/*
 * Determines the size of the structure that needs to be sent to drivers
 * for retrieving the property range values.
 */
static int
i_dladm_range_size(mac_propval_range_t *r, size_t *sz, uint_t *rcount)
{
	uint_t count = r->mpr_count;

	*sz = sizeof (mac_propval_range_t);
	*rcount = count;
	--count;

	switch (r->mpr_type) {
	case MAC_PROPVAL_UINT32:
		*sz += (count * sizeof (mac_propval_uint32_range_t));
		return (0);
	default:
		break;
	}
	*sz = 0;
	*rcount = 0;
	return (EINVAL);
}


/* ARGSUSED */
static dladm_status_t
check_rings(dladm_handle_t handle, prop_desc_t *pdp,
    datalink_id_t linkid, char **prop_val, uint_t *val_cntp, uint_t flags,
    val_desc_t **vp, datalink_media_t media)
{
	uint_t		val_cnt = *val_cntp;
	val_desc_t	*v = *vp;

	if (val_cnt != 1)
		return (DLADM_STATUS_BADVAL);
	if (strncasecmp(prop_val[0], "hw", strlen("hw")) == 0) {
		v->vd_val = UNSPEC_VAL;
	} else if (strncasecmp(prop_val[0], "sw", strlen("sw")) == 0) {
		v->vd_val = 0;
	} else {
		v->vd_val = strtoul(prop_val[0], NULL, 0);
		if (v->vd_val == 0)
			return (DLADM_STATUS_BADVAL);
	}
	return (DLADM_STATUS_OK);
}

/* ARGSUSED */
static dladm_status_t
get_rings_range(dladm_handle_t handle, prop_desc_t *pdp,
    datalink_id_t linkid, char **prop_val, uint_t *val_cnt,
    datalink_media_t media, uint_t flags, uint_t *perm_flags)
{
	dld_ioc_macprop_t *dip;
	dladm_status_t status = DLADM_STATUS_OK;
	mac_propval_range_t *rangep;
	size_t	sz;
	mac_propval_uint32_range_t *ur;

	sz = sizeof (mac_propval_range_t);

	if ((dip = i_dladm_buf_alloc_by_name(sz, linkid, pdp->pd_name, flags,
	    &status)) == NULL)
		return (status);

	status = i_dladm_macprop(handle, dip, B_FALSE);
	if (status != DLADM_STATUS_OK)
		return (status);

	rangep = (mac_propval_range_t *)(void *)&dip->pr_val;
	*val_cnt = 1;
	ur = &rangep->mpr_range_uint32[0];
	/* This is the case where the dev doesn't have any rings/groups */
	if (rangep->mpr_count == 0) {
		(*prop_val)[0] = '\0';
	/*
	 * This is the case where the dev supports rings, but static
	 * grouping.
	 */
	} else if (ur->mpur_min == ur->mpur_max &&
	    ur->mpur_max == 0) {
		(void) snprintf(prop_val[0], DLADM_PROP_VAL_MAX, "sw,hw");
	/*
	 * This is the case where the dev supports rings and dynamic
	 * grouping, but has only one value (say 2 rings and 2 groups).
	 */
	} else if (ur->mpur_min == ur->mpur_max) {
		(void) snprintf(prop_val[0], DLADM_PROP_VAL_MAX, "sw,hw,%d",
		    ur->mpur_min);
	/*
	 * This is the case where the dev supports rings and dynamic
	 * grouping and has a range of rings.
	 */
	} else {
		(void) snprintf(prop_val[0], DLADM_PROP_VAL_MAX,
		    "sw,hw,<%ld-%ld>", ur->mpur_min, ur->mpur_max);
	}
	free(dip);
	return (status);
}


/* ARGSUSED */
static dladm_status_t
get_rxrings(dladm_handle_t handle, prop_desc_t *pdp, datalink_id_t linkid,
    char **prop_val, uint_t *val_cnt, datalink_media_t media,
    uint_t flags, uint_t *perm_flags)
{
	mac_resource_props_t	mrp;
	dladm_status_t		status;
	uint32_t		nrings = 0;

	/*
	 * Get the number of (effective-)rings from the resource property.
	 */
	if (strcmp(pdp->pd_name, "rxrings-effective") == 0) {
		status = i_dladm_get_public_prop(handle, linkid,
		    "resource-effective", flags, perm_flags, &mrp,
		    sizeof (mrp));
	} else {
		/*
		 * Get the permissions from the "rxrings" property.
		 */
		status = i_dladm_get_public_prop(handle, linkid, "rxrings",
		    flags, perm_flags, NULL, 0);
		if (status != DLADM_STATUS_OK)
			return (status);

		status = i_dladm_get_public_prop(handle, linkid,
		    "resource", flags, NULL, &mrp, sizeof (mrp));
	}

	if (status != DLADM_STATUS_OK)
		return (status);

	if ((mrp.mrp_mask & MRP_RX_RINGS) == 0) {
		*val_cnt = 0;
		return (DLADM_STATUS_OK);
	}
	nrings = mrp.mrp_nrxrings;
	*val_cnt = 1;
	if (mrp.mrp_mask & MRP_RXRINGS_UNSPEC)
		(void) snprintf(*prop_val, DLADM_PROP_VAL_MAX, "hw");
	else if (nrings == 0)
		(void) snprintf(*prop_val, DLADM_PROP_VAL_MAX, "sw");
	else
		(void) snprintf(*prop_val, DLADM_PROP_VAL_MAX, "%ld", nrings);
	return (DLADM_STATUS_OK);
}

/* ARGSUSED */
dladm_status_t
extract_rxrings(val_desc_t *vdp, uint_t cnt, void *arg)
{
	mac_resource_props_t	*mrp = (mac_resource_props_t *)arg;

	mrp->mrp_nrxrings = 0;
	if (vdp->vd_val == RESET_VAL)
		mrp->mrp_mask = MRP_RINGS_RESET;
	else if (vdp->vd_val == UNSPEC_VAL)
		mrp->mrp_mask = MRP_RXRINGS_UNSPEC;
	else
		mrp->mrp_nrxrings = vdp->vd_val;
	mrp->mrp_mask |= MRP_RX_RINGS;

	return (DLADM_STATUS_OK);
}

/* ARGSUSED */
static dladm_status_t
get_txrings(dladm_handle_t handle, prop_desc_t *pdp, datalink_id_t linkid,
    char **prop_val, uint_t *val_cnt, datalink_media_t media,
    uint_t flags, uint_t *perm_flags)
{
	mac_resource_props_t	mrp;
	dladm_status_t		status;
	uint32_t		nrings = 0;


	/*
	 * Get the number of (effective-)rings from the resource property.
	 */
	if (strcmp(pdp->pd_name, "txrings-effective") == 0) {
		status = i_dladm_get_public_prop(handle, linkid,
		    "resource-effective", flags, perm_flags, &mrp,
		    sizeof (mrp));
	} else {
		/*
		 * Get the permissions from the "txrings" property.
		 */
		status = i_dladm_get_public_prop(handle, linkid, "txrings",
		    flags, perm_flags, NULL, 0);
		if (status != DLADM_STATUS_OK)
			return (status);

		/*
		 * Get the number of rings from the "resource" property.
		 */
		status = i_dladm_get_public_prop(handle, linkid, "resource",
		    flags, NULL, &mrp, sizeof (mrp));
	}

	if (status != DLADM_STATUS_OK)
		return (status);

	if ((mrp.mrp_mask & MRP_TX_RINGS) == 0) {
		*val_cnt = 0;
		return (DLADM_STATUS_OK);
	}
	nrings = mrp.mrp_ntxrings;
	*val_cnt = 1;
	if (mrp.mrp_mask & MRP_TXRINGS_UNSPEC)
		(void) snprintf(*prop_val, DLADM_PROP_VAL_MAX, "hw");
	else if (nrings == 0)
		(void) snprintf(*prop_val, DLADM_PROP_VAL_MAX, "sw");
	else
		(void) snprintf(*prop_val, DLADM_PROP_VAL_MAX, "%ld", nrings);
	return (DLADM_STATUS_OK);
}

/* ARGSUSED */
dladm_status_t
extract_txrings(val_desc_t *vdp, uint_t cnt, void *arg)
{
	mac_resource_props_t	*mrp = (mac_resource_props_t *)arg;

	mrp->mrp_ntxrings = 0;
	if (vdp->vd_val == RESET_VAL)
		mrp->mrp_mask = MRP_RINGS_RESET;
	else if (vdp->vd_val == UNSPEC_VAL)
		mrp->mrp_mask = MRP_TXRINGS_UNSPEC;
	else
		mrp->mrp_ntxrings = vdp->vd_val;
	mrp->mrp_mask |= MRP_TX_RINGS;

	return (DLADM_STATUS_OK);
}

/* ARGSUSED */
static dladm_status_t
get_cntavail(dladm_handle_t handle, prop_desc_t *pdp, datalink_id_t linkid,
    char **prop_val, uint_t *val_cnt, datalink_media_t media, uint_t flags,
    uint_t *perm_flags)
{
	if (flags & DLD_PROP_DEFAULT)
		return (DLADM_STATUS_NOTDEFINED);

	return (get_uint32(handle, pdp, linkid, prop_val, val_cnt, media,
	    flags, perm_flags));
}

/* ARGSUSED */
static dladm_status_t
set_resource(dladm_handle_t handle, prop_desc_t *pdp,
    datalink_id_t linkid, val_desc_t *vdp, uint_t val_cnt,
    uint_t flags, datalink_media_t media)
{
	mac_resource_props_t	mrp;
	dladm_status_t		status = DLADM_STATUS_OK;
	dld_ioc_macprop_t	*dip;
	int			i;

	bzero(&mrp, sizeof (mac_resource_props_t));
	dip = i_dladm_buf_alloc_by_name(0, linkid, "resource",
	    flags, &status);

	if (dip == NULL)
		return (status);

	for (i = 0; i < DLADM_MAX_RSRC_PROP; i++) {
		resource_prop_t	*rp = &rsrc_prop_table[i];

		if (strcmp(pdp->pd_name, rp->rp_name) != 0)
			continue;

		status = rp->rp_extract(vdp, val_cnt, &mrp);
		if (status != DLADM_STATUS_OK)
			goto done;

		break;
	}

	(void) memcpy(dip->pr_val, &mrp, dip->pr_valsize);
	status = i_dladm_macprop(handle, dip, B_TRUE);

done:
	free(dip);
	return (status);
}

/* ARGSUSED */
static dladm_status_t
get_protection(dladm_handle_t handle, prop_desc_t *pdp,
    datalink_id_t linkid, char **prop_val, uint_t *val_cnt,
    datalink_media_t media, uint_t flags, uint_t *perm_flags)
{
	mac_resource_props_t	mrp;
	mac_protect_t		*p;
	dladm_status_t		status;
	uint32_t		i, cnt = 0, setbits[32];

	status = i_dladm_get_public_prop(handle, linkid, "resource", flags,
	    perm_flags, &mrp, sizeof (mrp));
	if (status != DLADM_STATUS_OK)
		return (status);

	p = &mrp.mrp_protect;
	if ((mrp.mrp_mask & MRP_PROTECT) == 0) {
		*val_cnt = 0;
		return (DLADM_STATUS_OK);
	}
	dladm_find_setbits32(p->mp_types, setbits, &cnt);
	if (cnt > *val_cnt)
		return (DLADM_STATUS_BADVALCNT);

	for (i = 0; i < cnt; i++)
		(void) dladm_protect2str(setbits[i], prop_val[i]);

	*val_cnt = cnt;
	return (DLADM_STATUS_OK);
}

/* ARGSUSED */
static dladm_status_t
get_allowedips(dladm_handle_t handle, prop_desc_t *pdp,
    datalink_id_t linkid, char **prop_val, uint_t *val_cnt,
    datalink_media_t media, uint_t flags, uint_t *perm_flags)
{
	mac_resource_props_t	mrp;
	mac_protect_t		*p;
	dladm_status_t		status;
	int			i;

	status = i_dladm_get_public_prop(handle, linkid, "resource", flags,
	    perm_flags, &mrp, sizeof (mrp));
	if (status != DLADM_STATUS_OK)
		return (status);

	p = &mrp.mrp_protect;
	if (p->mp_ipaddrcnt == 0) {
		*val_cnt = 0;
		return (DLADM_STATUS_OK);
	}
	if (p->mp_ipaddrcnt > *val_cnt)
		return (DLADM_STATUS_BADVALCNT);

	for (i = 0; i < p->mp_ipaddrcnt; i++) {
		int len;
		if (p->mp_ipaddrs[i].ip_version == IPV4_VERSION) {
			ipaddr_t	v4addr;

			v4addr = V4_PART_OF_V6(p->mp_ipaddrs[i].ip_addr);
			(void) dladm_ipv4addr2str(&v4addr, prop_val[i]);
		} else {
			(void) dladm_ipv6addr2str(&p->mp_ipaddrs[i].ip_addr,
			    prop_val[i]);
		}
		len = strlen(prop_val[i]);
		(void) sprintf(prop_val[i] + len, "/%d",
		    p->mp_ipaddrs[i].ip_netmask);
	}
	*val_cnt = p->mp_ipaddrcnt;
	return (DLADM_STATUS_OK);
}

dladm_status_t
extract_protection(val_desc_t *vdp, uint_t cnt, void *arg)
{
	mac_resource_props_t	*mrp = arg;
	uint32_t		types = 0;
	int			i;

	for (i = 0; i < cnt; i++)
		types |= (uint32_t)vdp[i].vd_val;

	mrp->mrp_protect.mp_types = types;
	mrp->mrp_mask |= MRP_PROTECT;
	return (DLADM_STATUS_OK);
}

dladm_status_t
extract_allowedips(val_desc_t *vdp, uint_t cnt, void *arg)
{
	mac_resource_props_t	*mrp = arg;
	mac_protect_t		*p = &mrp->mrp_protect;
	int			i;

	if (vdp->vd_val == 0) {
		cnt = (uint_t)-1;
	} else {
		for (i = 0; i < cnt; i++) {
			bcopy((void *)vdp[i].vd_val, &p->mp_ipaddrs[i],
			    sizeof (mac_ipaddr_t));
		}
	}
	p->mp_ipaddrcnt = cnt;
	mrp->mrp_mask |= MRP_PROTECT;
	return (DLADM_STATUS_OK);
}

static dladm_status_t
check_single_ip(char *buf, mac_ipaddr_t *addr)
{
	dladm_status_t	status;
	ipaddr_t	v4addr;
	in6_addr_t	v6addr;
	boolean_t	isv4 = B_TRUE;
	char		*p;
	uint32_t	mask = 0;

	/*
	 * If the IP address is in CIDR format, parse the bits component
	 * seperately. An address in this style will be used to indicate an
	 * entire subnet, so it must be a network number with no host address.
	 */
	if ((p = strchr(buf, '/')) != NULL) {
		char *end = NULL;

		*p++ = '\0';
		if (!isdigit(*p))
			return (DLADM_STATUS_INVALID_IP);
		mask = strtol(p, &end, 10);
		if (end != NULL && *end != '\0')
			return (DLADM_STATUS_INVALID_IP);
		if (mask > 128|| mask < 1)
			return (DLADM_STATUS_INVALID_IP);
	}

	status = dladm_str2ipv4addr(buf, &v4addr);
	if (status == DLADM_STATUS_INVALID_IP) {
		status = dladm_str2ipv6addr(buf, &v6addr);
		if (status == DLADM_STATUS_OK)
			isv4 = B_FALSE;
	}
	if (status != DLADM_STATUS_OK)
		return (status);

	if (isv4) {
		if (v4addr == INADDR_ANY)
			return (DLADM_STATUS_INVALID_IP);

		IN6_IPADDR_TO_V4MAPPED(v4addr, &addr->ip_addr);
		addr->ip_version = IPV4_VERSION;
		if (p != NULL) {
			uint32_t smask;

			/*
			 * Validate the netmask is in the proper range for v4
			 */
			if (mask > 32 || mask < 1)
				return (DLADM_STATUS_INVALID_IP);

			/*
			 * We have a CIDR style address, confirm that only the
			 * network number is set.
			 */
			smask = 0xFFFFFFFFu << (32 - mask);
			if (htonl(v4addr) & ~smask)
				return (DLADM_STATUS_INVALID_IP);
		} else {
			mask = 32;
		}
		addr->ip_netmask = mask;
	} else {
		if (IN6_IS_ADDR_UNSPECIFIED(&v6addr))
			return (DLADM_STATUS_INVALID_IP);

		if (IN6_IS_ADDR_V4MAPPED_ANY(&v6addr))
			return (DLADM_STATUS_INVALID_IP);

		if (p != NULL) {
			int i, off, high;

			/*
			 * Note that the address in our buffer is stored in
			 * network byte order.
			 */
			off = 0;
			for (i = 3; i >= 0; i--) {
				high = ffsl(ntohl(v6addr._S6_un._S6_u32[i]));
				if (high != 0)
					break;
				off += 32;
			}
			off += high;
			if (128 - off >= mask)
				return (DLADM_STATUS_INVALID_IP);
		} else {
			mask = 128;
		}

		addr->ip_addr = v6addr;
		addr->ip_version = IPV6_VERSION;
		addr->ip_netmask = mask;
	}
	return (DLADM_STATUS_OK);
}

/* ARGSUSED */
static dladm_status_t
check_allowedips(dladm_handle_t handle, prop_desc_t *pdp,
    datalink_id_t linkid, char **prop_val, uint_t *val_cntp, uint_t flags,
    val_desc_t **vdpp, datalink_media_t media)
{
	dladm_status_t	status;
	mac_ipaddr_t	*addr;
	int		i;
	uint_t		val_cnt = *val_cntp;
	val_desc_t	*vdp = *vdpp;

	if (val_cnt > MPT_MAXIPADDR)
		return (DLADM_STATUS_BADVALCNT);

	for (i = 0; i < val_cnt; i++) {
		if ((addr = calloc(1, sizeof (mac_ipaddr_t))) == NULL) {
			status = DLADM_STATUS_NOMEM;
			goto fail;
		}
		vdp[i].vd_val = (uintptr_t)addr;

		status = check_single_ip(prop_val[i], addr);
		if (status != DLADM_STATUS_OK)
			goto fail;
	}
	return (DLADM_STATUS_OK);

fail:
	for (i = 0; i < val_cnt; i++) {
		free((void *)vdp[i].vd_val);
		vdp[i].vd_val = NULL;
	}
	return (status);
}

static void
dladm_cid2str(mac_dhcpcid_t *cid, char *buf)
{
	char	tmp_buf[DLADM_STRSIZE];
	uint_t	hexlen;

	switch (cid->dc_form) {
	case CIDFORM_TYPED: {
		uint16_t	duidtype, hwtype;
		uint32_t	timestamp, ennum;
		char		*lladdr;

		if (cid->dc_len < sizeof (duidtype))
			goto fail;

		bcopy(cid->dc_id, &duidtype, sizeof (duidtype));
		duidtype = ntohs(duidtype);
		switch (duidtype) {
		case DHCPV6_DUID_LLT: {
			duid_llt_t	llt;

			if (cid->dc_len < sizeof (llt))
				goto fail;

			bcopy(cid->dc_id, &llt, sizeof (llt));
			hwtype = ntohs(llt.dllt_hwtype);
			timestamp = ntohl(llt.dllt_time);
			lladdr = _link_ntoa(cid->dc_id + sizeof (llt),
			    NULL, cid->dc_len - sizeof (llt), IFT_OTHER);
			if (lladdr == NULL)
				goto fail;

			(void) snprintf(buf, DLADM_STRSIZE, "%d.%d.%d.%s",
			    duidtype, hwtype, timestamp, lladdr);
			free(lladdr);
			break;
		}
		case DHCPV6_DUID_EN: {
			duid_en_t	en;

			if (cid->dc_len < sizeof (en))
				goto fail;

			bcopy(cid->dc_id, &en, sizeof (en));
			ennum = DHCPV6_GET_ENTNUM(&en);
			hexlen = sizeof (tmp_buf);
			if (octet_to_hexascii(cid->dc_id + sizeof (en),
			    cid->dc_len - sizeof (en), tmp_buf, &hexlen) != 0)
				goto fail;

			(void) snprintf(buf, DLADM_STRSIZE, "%d.%d.%s",
			    duidtype, ennum, tmp_buf);
			break;
		}
		case DHCPV6_DUID_LL: {
			duid_ll_t	ll;

			if (cid->dc_len < sizeof (ll))
				goto fail;

			bcopy(cid->dc_id, &ll, sizeof (ll));
			hwtype = ntohs(ll.dll_hwtype);
			lladdr = _link_ntoa(cid->dc_id + sizeof (ll),
			    NULL, cid->dc_len - sizeof (ll), IFT_OTHER);
			if (lladdr == NULL)
				goto fail;

			(void) snprintf(buf, DLADM_STRSIZE, "%d.%d.%s",
			    duidtype, hwtype, lladdr);
			free(lladdr);
			break;
		}
		default: {
			hexlen = sizeof (tmp_buf);
			if (octet_to_hexascii(cid->dc_id + sizeof (duidtype),
			    cid->dc_len - sizeof (duidtype),
			    tmp_buf, &hexlen) != 0)
				goto fail;

			(void) snprintf(buf, DLADM_STRSIZE, "%d.%s",
			    duidtype, tmp_buf);
		}
		}
		break;
	}
	case CIDFORM_HEX: {
		hexlen = sizeof (tmp_buf);
		if (octet_to_hexascii(cid->dc_id, cid->dc_len,
		    tmp_buf, &hexlen) != 0)
			goto fail;

		(void) snprintf(buf, DLADM_STRSIZE, "0x%s", tmp_buf);
		break;
	}
	case CIDFORM_STR: {
		int	i;

		for (i = 0; i < cid->dc_len; i++) {
			if (!isprint(cid->dc_id[i]))
				goto fail;
		}
		(void) snprintf(buf, DLADM_STRSIZE, "%s", cid->dc_id);
		break;
	}
	default:
		goto fail;
	}
	return;

fail:
	(void) snprintf(buf, DLADM_STRSIZE, "<unknown>");
}

static dladm_status_t
dladm_str2cid(char *buf, mac_dhcpcid_t *cid)
{
	char	*ptr = buf;
	char	tmp_buf[DLADM_STRSIZE];
	uint_t	hexlen, cidlen;

	bzero(cid, sizeof (*cid));
	if (isdigit(*ptr) &&
	    ptr[strspn(ptr, "0123456789")] == '.') {
		char	*cp;
		ulong_t	duidtype;
		ulong_t	subtype;
		ulong_t	timestamp;
		uchar_t	*lladdr;
		int	addrlen;

		errno = 0;
		duidtype = strtoul(ptr, &cp, 0);
		if (ptr == cp || errno != 0 || *cp != '.' ||
		    duidtype > USHRT_MAX)
			return (DLADM_STATUS_BADARG);
		ptr = cp + 1;

		if (duidtype != 0 && duidtype <= DHCPV6_DUID_LL) {
			errno = 0;
			subtype = strtoul(ptr, &cp, 0);
			if (ptr == cp || errno != 0 || *cp != '.')
				return (DLADM_STATUS_BADARG);
			ptr = cp + 1;
		}
		switch (duidtype) {
		case DHCPV6_DUID_LLT: {
			duid_llt_t	llt;

			errno = 0;
			timestamp = strtoul(ptr, &cp, 0);
			if (ptr == cp || errno != 0 || *cp != '.')
				return (DLADM_STATUS_BADARG);

			ptr = cp + 1;
			lladdr = _link_aton(ptr, &addrlen);
			if (lladdr == NULL)
				return (DLADM_STATUS_BADARG);

			cidlen = sizeof (llt) + addrlen;
			if (cidlen > sizeof (cid->dc_id)) {
				free(lladdr);
				return (DLADM_STATUS_TOOSMALL);
			}
			llt.dllt_dutype = htons(duidtype);
			llt.dllt_hwtype = htons(subtype);
			llt.dllt_time = htonl(timestamp);
			bcopy(&llt, cid->dc_id, sizeof (llt));
			bcopy(lladdr, cid->dc_id + sizeof (llt), addrlen);
			free(lladdr);
			break;
		}
		case DHCPV6_DUID_LL: {
			duid_ll_t	ll;

			lladdr = _link_aton(ptr, &addrlen);
			if (lladdr == NULL)
				return (DLADM_STATUS_BADARG);

			cidlen = sizeof (ll) + addrlen;
			if (cidlen > sizeof (cid->dc_id)) {
				free(lladdr);
				return (DLADM_STATUS_TOOSMALL);
			}
			ll.dll_dutype = htons(duidtype);
			ll.dll_hwtype = htons(subtype);
			bcopy(&ll, cid->dc_id, sizeof (ll));
			bcopy(lladdr, cid->dc_id + sizeof (ll), addrlen);
			free(lladdr);
			break;
		}
		default: {
			hexlen = sizeof (tmp_buf);
			if (hexascii_to_octet(ptr, strlen(ptr),
			    tmp_buf, &hexlen) != 0)
				return (DLADM_STATUS_BADARG);

			if (duidtype == DHCPV6_DUID_EN) {
				duid_en_t	en;

				en.den_dutype = htons(duidtype);
				DHCPV6_SET_ENTNUM(&en, subtype);

				cidlen = sizeof (en) + hexlen;
				if (cidlen > sizeof (cid->dc_id))
					return (DLADM_STATUS_TOOSMALL);

				bcopy(&en, cid->dc_id, sizeof (en));
				bcopy(tmp_buf, cid->dc_id + sizeof (en),
				    hexlen);
			} else {
				uint16_t	dutype = htons(duidtype);

				cidlen = sizeof (dutype) + hexlen;
				if (cidlen > sizeof (cid->dc_id))
					return (DLADM_STATUS_TOOSMALL);

				bcopy(&dutype, cid->dc_id, sizeof (dutype));
				bcopy(tmp_buf, cid->dc_id + sizeof (dutype),
				    hexlen);
			}
			break;
		}
		}
		cid->dc_form = CIDFORM_TYPED;
	} else if (strncasecmp("0x", ptr, 2) == 0 && ptr[2] != '\0') {
		ptr += 2;
		hexlen = sizeof (tmp_buf);
		if (hexascii_to_octet(ptr, strlen(ptr), tmp_buf,
		    &hexlen) != 0) {
			return (DLADM_STATUS_BADARG);
		}
		cidlen = hexlen;
		if (cidlen > sizeof (cid->dc_id))
			return (DLADM_STATUS_TOOSMALL);

		bcopy(tmp_buf, cid->dc_id, cidlen);
		cid->dc_form = CIDFORM_HEX;
	} else {
		cidlen = strlen(ptr);
		if (cidlen > sizeof (cid->dc_id))
			return (DLADM_STATUS_TOOSMALL);

		bcopy(ptr, cid->dc_id, cidlen);
		cid->dc_form = CIDFORM_STR;
	}
	cid->dc_len = cidlen;
	return (DLADM_STATUS_OK);
}

/* ARGSUSED */
static dladm_status_t
get_allowedcids(dladm_handle_t handle, prop_desc_t *pdp,
    datalink_id_t linkid, char **prop_val, uint_t *val_cnt,
    datalink_media_t media, uint_t flags, uint_t *perm_flags)
{
	mac_resource_props_t	mrp;
	mac_protect_t		*p;
	dladm_status_t		status;
	int			i;

	status = i_dladm_get_public_prop(handle, linkid, "resource", flags,
	    perm_flags, &mrp, sizeof (mrp));
	if (status != DLADM_STATUS_OK)
		return (status);

	p = &mrp.mrp_protect;
	if (p->mp_cidcnt == 0) {
		*val_cnt = 0;
		return (DLADM_STATUS_OK);
	}
	if (p->mp_cidcnt > *val_cnt)
		return (DLADM_STATUS_BADVALCNT);

	for (i = 0; i < p->mp_cidcnt; i++) {
		mac_dhcpcid_t	*cid = &p->mp_cids[i];

		dladm_cid2str(cid, prop_val[i]);
	}
	*val_cnt = p->mp_cidcnt;
	return (DLADM_STATUS_OK);
}

dladm_status_t
extract_allowedcids(val_desc_t *vdp, uint_t cnt, void *arg)
{
	mac_resource_props_t	*mrp = arg;
	mac_protect_t		*p = &mrp->mrp_protect;
	int			i;

	if (vdp->vd_val == 0) {
		cnt = (uint_t)-1;
	} else {
		for (i = 0; i < cnt; i++) {
			bcopy((void *)vdp[i].vd_val, &p->mp_cids[i],
			    sizeof (mac_dhcpcid_t));
		}
	}
	p->mp_cidcnt = cnt;
	mrp->mrp_mask |= MRP_PROTECT;
	return (DLADM_STATUS_OK);
}

/* ARGSUSED */
static dladm_status_t
check_allowedcids(dladm_handle_t handle, prop_desc_t *pdp,
    datalink_id_t linkid, char **prop_val, uint_t *val_cntp,
    uint_t flags, val_desc_t **vdpp, datalink_media_t media)
{
	dladm_status_t	status;
	mac_dhcpcid_t	*cid;
	int		i;
	uint_t		val_cnt = *val_cntp;
	val_desc_t	*vdp = *vdpp;

	if (val_cnt > MPT_MAXCID)
		return (DLADM_STATUS_BADVALCNT);

	for (i = 0; i < val_cnt; i++) {
		if ((cid = calloc(1, sizeof (mac_dhcpcid_t))) == NULL) {
			status = DLADM_STATUS_NOMEM;
			goto fail;
		}
		vdp[i].vd_val = (uintptr_t)cid;

		status = dladm_str2cid(prop_val[i], cid);
		if (status != DLADM_STATUS_OK)
			goto fail;
	}
	return (DLADM_STATUS_OK);

fail:
	for (i = 0; i < val_cnt; i++) {
		free((void *)vdp[i].vd_val);
		vdp[i].vd_val = NULL;
	}
	return (status);
}

/* ARGSUSED */
static dladm_status_t
get_secondary_macs(dladm_handle_t handle, prop_desc_t *pdp,
    datalink_id_t linkid, char **prop_val, uint_t *val_cnt,
    datalink_media_t media, uint_t flags, uint_t *perm_flags)
{
	mac_secondary_addr_t	sa;
	dladm_status_t		status;
	int			i;

	status = i_dladm_get_public_prop(handle, linkid, pdp->pd_name, flags,
	    perm_flags, &sa, sizeof (sa));
	if (status != DLADM_STATUS_OK)
		return (status);

	if (sa.ms_addrcnt > *val_cnt)
		return (DLADM_STATUS_BADVALCNT);

	for (i = 0; i < sa.ms_addrcnt; i++) {
		if (dladm_aggr_macaddr2str(
		    (const unsigned char *)&sa.ms_addrs[i], prop_val[i]) ==
		    NULL) {
			*val_cnt = i;
			return (DLADM_STATUS_NOMEM);
		}
	}
	*val_cnt = sa.ms_addrcnt;
	return (DLADM_STATUS_OK);
}

/* ARGSUSED */
static dladm_status_t
check_secondary_macs(dladm_handle_t handle, prop_desc_t *pdp,
    datalink_id_t linkid, char **prop_val, uint_t *val_cntp, uint_t flags,
    val_desc_t **vdpp, datalink_media_t media)
{
	dladm_status_t	status;
	uchar_t		*addr;
	uint_t		len = 0;
	int		i;
	uint_t		val_cnt = *val_cntp;
	val_desc_t	*vdp = *vdpp;

	if (val_cnt >= MPT_MAXMACADDR)
		return (DLADM_STATUS_BADVALCNT);

	for (i = 0; i < val_cnt; i++) {
		addr = _link_aton(prop_val[i], (int *)&len);
		if (addr == NULL) {
			if (len == (uint_t)-1)
				status = DLADM_STATUS_MACADDRINVAL;
			else
				status = DLADM_STATUS_NOMEM;
			goto fail;
		}

		vdp[i].vd_val = (uintptr_t)addr;
	}
	return (DLADM_STATUS_OK);

fail:
	for (i = 0; i < val_cnt; i++) {
		free((void *)vdp[i].vd_val);
		vdp[i].vd_val = NULL;
	}
	return (status);
}

/* ARGSUSED */
static dladm_status_t
set_secondary_macs(dladm_handle_t handle, prop_desc_t *pd, datalink_id_t linkid,
    val_desc_t *vdp, uint_t val_cnt, uint_t flags, datalink_media_t media)
{
	dladm_status_t status;
	dld_ioc_macprop_t *dip;
	int i;
	mac_secondary_addr_t msa;

	dip = i_dladm_buf_alloc_by_name(0, linkid, "secondary-macs", 0,
	    &status);
	if (dip == NULL)
		return (status);

	if (vdp->vd_val == 0) {
		val_cnt = (uint_t)-1;
	} else {
		for (i = 0; i < val_cnt; i++) {
			bcopy((void *)vdp[i].vd_val, msa.ms_addrs[i],
			    MAXMACADDRLEN);
		}
	}
	msa.ms_addrcnt = val_cnt;
	bcopy(&msa, dip->pr_val, dip->pr_valsize);

	status = i_dladm_macprop(handle, dip, B_TRUE);

	free(dip);
	return (status);
}

/* ARGSUSED */
static dladm_status_t
get_autopush(dladm_handle_t handle, prop_desc_t *pdp, datalink_id_t linkid,
    char **prop_val, uint_t *val_cnt, datalink_media_t media,
    uint_t flags, uint_t *perm_flags)
{
	struct		dlautopush dlap;
	int		i, len;
	dladm_status_t	status;

	if (flags & DLD_PROP_DEFAULT)
		return (DLADM_STATUS_NOTDEFINED);

	status = i_dladm_get_public_prop(handle, linkid, pdp->pd_name, flags,
	    perm_flags, &dlap, sizeof (dlap));
	if (status != DLADM_STATUS_OK)
		return (status);

	if (dlap.dap_npush == 0) {
		*val_cnt = 0;
		return (DLADM_STATUS_OK);
	}
	for (i = 0, len = 0; i < dlap.dap_npush; i++) {
		if (i != 0) {
			(void) snprintf(*prop_val + len,
			    DLADM_PROP_VAL_MAX - len, "%c", AP_DELIMITER);
			len += 1;
		}
		(void) snprintf(*prop_val + len, DLADM_PROP_VAL_MAX - len,
		    "%s", dlap.dap_aplist[i]);
		len += strlen(dlap.dap_aplist[i]);
		if (dlap.dap_anchor - 1 == i) {
			(void) snprintf(*prop_val + len,
			    DLADM_PROP_VAL_MAX - len, "%c%s", AP_DELIMITER,
			    AP_ANCHOR);
			len += (strlen(AP_ANCHOR) + 1);
		}
	}
	*val_cnt = 1;
	return (DLADM_STATUS_OK);
}

/*
 * Add the specified module to the dlautopush structure; returns a
 * DLADM_STATUS_* code.
 */
dladm_status_t
i_dladm_add_ap_module(const char *module, struct dlautopush *dlap)
{
	if ((strlen(module) == 0) || (strlen(module) > FMNAMESZ))
		return (DLADM_STATUS_BADVAL);

	if (strncasecmp(module, AP_ANCHOR, strlen(AP_ANCHOR)) == 0) {
		/*
		 * We don't allow multiple anchors, and the anchor must
		 * be after at least one module.
		 */
		if (dlap->dap_anchor != 0)
			return (DLADM_STATUS_BADVAL);
		if (dlap->dap_npush == 0)
			return (DLADM_STATUS_BADVAL);

		dlap->dap_anchor = dlap->dap_npush;
		return (DLADM_STATUS_OK);
	}
	if (dlap->dap_npush >= MAXAPUSH)
		return (DLADM_STATUS_BADVALCNT);

	(void) strlcpy(dlap->dap_aplist[dlap->dap_npush++], module,
	    FMNAMESZ + 1);

	return (DLADM_STATUS_OK);
}

/*
 * Currently, both '.' and ' '(space) can be used as the delimiters between
 * autopush modules. The former is used in dladm set-linkprop, and the
 * latter is used in the autopush(1M) file.
 */
/* ARGSUSED */
static dladm_status_t
check_autopush(dladm_handle_t handle, prop_desc_t *pdp, datalink_id_t linkid,
    char **prop_val, uint_t *val_cntp, uint_t flags, val_desc_t **vdpp,
    datalink_media_t media)
{
	char			*module;
	struct dlautopush	*dlap;
	dladm_status_t		status;
	char			val[DLADM_PROP_VAL_MAX];
	char			delimiters[4];
	uint_t			val_cnt = *val_cntp;
	val_desc_t		*vdp = *vdpp;

	if (val_cnt != 1)
		return (DLADM_STATUS_BADVALCNT);

	if (prop_val != NULL) {
		dlap = malloc(sizeof (struct dlautopush));
		if (dlap == NULL)
			return (DLADM_STATUS_NOMEM);

		(void) memset(dlap, 0, sizeof (struct dlautopush));
		(void) snprintf(delimiters, 4, " %c\n", AP_DELIMITER);
		bcopy(*prop_val, val, DLADM_PROP_VAL_MAX);
		module = strtok(val, delimiters);
		while (module != NULL) {
			status = i_dladm_add_ap_module(module, dlap);
			if (status != DLADM_STATUS_OK)
				return (status);
			module = strtok(NULL, delimiters);
		}

		vdp->vd_val = (uintptr_t)dlap;
	} else {
		vdp->vd_val = 0;
	}
	return (DLADM_STATUS_OK);
}

#define	WLDP_BUFSIZE (MAX_BUF_LEN - WIFI_BUF_OFFSET)

/* ARGSUSED */
static dladm_status_t
get_rate_common(dladm_handle_t handle, prop_desc_t *pdp,
    datalink_id_t linkid, char **prop_val, uint_t *val_cnt, uint_t id,
    uint_t *perm_flags)
{
	wl_rates_t	*wrp;
	uint_t		i;
	dladm_status_t	status = DLADM_STATUS_OK;

	wrp = malloc(WLDP_BUFSIZE);
	if (wrp == NULL)
		return (DLADM_STATUS_NOMEM);

	status = i_dladm_wlan_param(handle, linkid, wrp, id, WLDP_BUFSIZE,
	    B_FALSE);
	if (status != DLADM_STATUS_OK)
		goto done;

	if (wrp->wl_rates_num > *val_cnt) {
		status = DLADM_STATUS_TOOSMALL;
		goto done;
	}

	if (wrp->wl_rates_rates[0] == 0) {
		prop_val[0][0] = '\0';
		*val_cnt = 1;
		goto done;
	}

	for (i = 0; i < wrp->wl_rates_num; i++) {
		(void) snprintf(prop_val[i], DLADM_STRSIZE, "%.*f",
		    wrp->wl_rates_rates[i] % 2,
		    (float)wrp->wl_rates_rates[i] / 2);
	}
	*val_cnt = wrp->wl_rates_num;
	*perm_flags = MAC_PROP_PERM_RW;

done:
	free(wrp);
	return (status);
}

static dladm_status_t
get_rate(dladm_handle_t handle, prop_desc_t *pdp, datalink_id_t linkid,
    char **prop_val, uint_t *val_cnt, datalink_media_t media,
    uint_t flags, uint_t *perm_flags)
{
	if (media != DL_WIFI) {
		return (get_speed(handle, pdp, linkid, prop_val,
		    val_cnt, media, flags, perm_flags));
	}

	return (get_rate_common(handle, pdp, linkid, prop_val, val_cnt,
	    MAC_PROP_WL_DESIRED_RATES, perm_flags));
}

/* ARGSUSED */
static dladm_status_t
get_rate_mod(dladm_handle_t handle, prop_desc_t *pdp, datalink_id_t linkid,
    char **prop_val, uint_t *val_cnt, datalink_media_t media,
    uint_t flags, uint_t *perm_flags)
{
	switch (media) {
	case DL_ETHER:
		/*
		 * Speed for ethernet links is unbounded. E.g., 802.11b
		 * links can have a speed of 5.5 Gbps.
		 */
		return (DLADM_STATUS_NOTSUP);

	case DL_WIFI:
		return (get_rate_common(handle, pdp, linkid, prop_val,
		    val_cnt, MAC_PROP_WL_SUPPORTED_RATES, perm_flags));
	default:
		return (DLADM_STATUS_BADARG);
	}
}

static dladm_status_t
set_wlan_rate(dladm_handle_t handle, datalink_id_t linkid,
    dladm_wlan_rates_t *rates)
{
	int		i;
	uint_t		len;
	wl_rates_t	*wrp;
	dladm_status_t	status = DLADM_STATUS_OK;

	wrp = malloc(WLDP_BUFSIZE);
	if (wrp == NULL)
		return (DLADM_STATUS_NOMEM);

	bzero(wrp, WLDP_BUFSIZE);
	for (i = 0; i < rates->wr_cnt; i++)
		wrp->wl_rates_rates[i] = rates->wr_rates[i];
	wrp->wl_rates_num = rates->wr_cnt;

	len = offsetof(wl_rates_t, wl_rates_rates) +
	    (rates->wr_cnt * sizeof (char)) + WIFI_BUF_OFFSET;
	status = i_dladm_wlan_param(handle, linkid, wrp,
	    MAC_PROP_WL_DESIRED_RATES, len, B_TRUE);

	free(wrp);
	return (status);
}

/* ARGSUSED */
static dladm_status_t
set_rate(dladm_handle_t handle, prop_desc_t *pdp, datalink_id_t linkid,
    val_desc_t *vdp, uint_t val_cnt, uint_t flags, datalink_media_t media)
{
	dladm_wlan_rates_t	rates;
	dladm_status_t		status;

	/*
	 * can currently set rate on WIFI links only.
	 */
	if (media != DL_WIFI)
		return (DLADM_STATUS_PROPRDONLY);

	if (val_cnt != 1)
		return (DLADM_STATUS_BADVALCNT);

	rates.wr_cnt = 1;
	rates.wr_rates[0] = vdp[0].vd_val;

	status = set_wlan_rate(handle, linkid, &rates);

	return (status);
}

/* ARGSUSED */
static dladm_status_t
check_rate(dladm_handle_t handle, prop_desc_t *pdp, datalink_id_t linkid,
    char **prop_val, uint_t *val_cntp, uint_t flags, val_desc_t **vdpp,
    datalink_media_t media)
{
	int		i;
	uint_t		modval_cnt = MAX_SUPPORT_RATES;
	char		*buf, **modval;
	dladm_status_t	status;
	uint_t 		perm_flags;
	uint_t		val_cnt = *val_cntp;
	val_desc_t	*vdp = *vdpp;

	if (val_cnt != 1)
		return (DLADM_STATUS_BADVALCNT);

	buf = malloc((sizeof (char *) + DLADM_STRSIZE) *
	    MAX_SUPPORT_RATES);
	if (buf == NULL) {
		status = DLADM_STATUS_NOMEM;
		goto done;
	}

	modval = (char **)(void *)buf;
	for (i = 0; i < MAX_SUPPORT_RATES; i++) {
		modval[i] = buf + sizeof (char *) * MAX_SUPPORT_RATES +
		    i * DLADM_STRSIZE;
	}

	status = get_rate_mod(handle, NULL, linkid, modval, &modval_cnt,
	    media, 0, &perm_flags);
	if (status != DLADM_STATUS_OK)
		goto done;

	for (i = 0; i < modval_cnt; i++) {
		if (strcasecmp(*prop_val, modval[i]) == 0) {
			vdp->vd_val = (uintptr_t)(uint_t)
			    (atof(*prop_val) * 2);
			status = DLADM_STATUS_OK;
			break;
		}
	}
	if (i == modval_cnt)
		status = DLADM_STATUS_BADVAL;
done:
	free(buf);
	return (status);
}

static dladm_status_t
get_phyconf(dladm_handle_t handle, datalink_id_t linkid, void *buf,
    int buflen)
{
	return (i_dladm_wlan_param(handle, linkid, buf, MAC_PROP_WL_PHY_CONFIG,
	    buflen, B_FALSE));
}

/* ARGSUSED */
static dladm_status_t
get_channel(dladm_handle_t handle, prop_desc_t *pdp,
    datalink_id_t linkid, char **prop_val, uint_t *val_cnt,
    datalink_media_t media, uint_t flags, uint_t *perm_flags)
{
	uint32_t	channel;
	char		buf[WLDP_BUFSIZE];
	dladm_status_t	status;
	wl_phy_conf_t	wl_phy_conf;

	if ((status = get_phyconf(handle, linkid, buf, sizeof (buf)))
	    != DLADM_STATUS_OK)
		return (status);

	(void) memcpy(&wl_phy_conf, buf, sizeof (wl_phy_conf));
	if (!i_dladm_wlan_convert_chan(&wl_phy_conf, &channel))
		return (DLADM_STATUS_NOTFOUND);

	(void) snprintf(*prop_val, DLADM_STRSIZE, "%u", channel);
	*val_cnt = 1;
	*perm_flags = MAC_PROP_PERM_READ;
	return (DLADM_STATUS_OK);
}

/* ARGSUSED */
static dladm_status_t
get_powermode(dladm_handle_t handle, prop_desc_t *pdp,
    datalink_id_t linkid, char **prop_val, uint_t *val_cnt,
    datalink_media_t media, uint_t flags, uint_t *perm_flags)
{
	wl_ps_mode_t	mode;
	const char	*s;
	char		buf[WLDP_BUFSIZE];
	dladm_status_t	status;

	if ((status = i_dladm_wlan_param(handle, linkid, buf,
	    MAC_PROP_WL_POWER_MODE, sizeof (buf), B_FALSE)) != DLADM_STATUS_OK)
		return (status);

	(void) memcpy(&mode, buf, sizeof (mode));
	switch (mode.wl_ps_mode) {
	case WL_PM_AM:
		s = "off";
		break;
	case WL_PM_MPS:
		s = "max";
		break;
	case WL_PM_FAST:
		s = "fast";
		break;
	default:
		return (DLADM_STATUS_NOTFOUND);
	}
	(void) snprintf(*prop_val, DLADM_STRSIZE, "%s", s);
	*val_cnt = 1;
	*perm_flags = MAC_PROP_PERM_RW;
	return (DLADM_STATUS_OK);
}

/* ARGSUSED */
static dladm_status_t
set_powermode(dladm_handle_t handle, prop_desc_t *pdp,
    datalink_id_t linkid, val_desc_t *vdp, uint_t val_cnt, uint_t flags,
    datalink_media_t media)
{
	dladm_wlan_powermode_t	powermode = vdp->vd_val;
	wl_ps_mode_t		ps_mode;

	if (val_cnt != 1)
		return (DLADM_STATUS_BADVALCNT);

	(void) memset(&ps_mode, 0xff, sizeof (ps_mode));

	switch (powermode) {
	case DLADM_WLAN_PM_OFF:
		ps_mode.wl_ps_mode = WL_PM_AM;
		break;
	case DLADM_WLAN_PM_MAX:
		ps_mode.wl_ps_mode = WL_PM_MPS;
		break;
	case DLADM_WLAN_PM_FAST:
		ps_mode.wl_ps_mode = WL_PM_FAST;
		break;
	default:
		return (DLADM_STATUS_NOTSUP);
	}
	return (i_dladm_wlan_param(handle, linkid, &ps_mode,
	    MAC_PROP_WL_POWER_MODE, sizeof (ps_mode), B_TRUE));
}

/* ARGSUSED */
static dladm_status_t
get_radio(dladm_handle_t handle, prop_desc_t *pdp, datalink_id_t linkid,
    char **prop_val, uint_t *val_cnt, datalink_media_t media,
    uint_t flags, uint_t *perm_flags)
{
	wl_radio_t	radio;
	const char	*s;
	char		buf[WLDP_BUFSIZE];
	dladm_status_t	status;

	if ((status = i_dladm_wlan_param(handle, linkid, buf,
	    MAC_PROP_WL_RADIO, sizeof (buf), B_FALSE)) != DLADM_STATUS_OK)
		return (status);

	(void) memcpy(&radio, buf, sizeof (radio));
	switch (radio) {
	case B_TRUE:
		s = "on";
		break;
	case B_FALSE:
		s = "off";
		break;
	default:
		return (DLADM_STATUS_NOTFOUND);
	}
	(void) snprintf(*prop_val, DLADM_STRSIZE, "%s", s);
	*val_cnt = 1;
	*perm_flags = MAC_PROP_PERM_RW;
	return (DLADM_STATUS_OK);
}

/* ARGSUSED */
static dladm_status_t
set_radio(dladm_handle_t handle, prop_desc_t *pdp, datalink_id_t linkid,
    val_desc_t *vdp, uint_t val_cnt, uint_t flags, datalink_media_t media)
{
	dladm_wlan_radio_t	radio = vdp->vd_val;
	wl_radio_t		r;

	if (val_cnt != 1)
		return (DLADM_STATUS_BADVALCNT);

	switch (radio) {
	case DLADM_WLAN_RADIO_ON:
		r = B_TRUE;
		break;
	case DLADM_WLAN_RADIO_OFF:
		r = B_FALSE;
		break;
	default:
		return (DLADM_STATUS_NOTSUP);
	}
	return (i_dladm_wlan_param(handle, linkid, &r, MAC_PROP_WL_RADIO,
	    sizeof (r), B_TRUE));
}

/* ARGSUSED */
static dladm_status_t
check_hoplimit(dladm_handle_t handle, prop_desc_t *pdp,
    datalink_id_t linkid, char **prop_val, uint_t *val_cntp, uint_t flags,
    val_desc_t **vdpp, datalink_media_t media)
{
	int32_t		hlim;
	char		*ep;
	uint_t		val_cnt = *val_cntp;
	val_desc_t	*vdp = *vdpp;

	if (val_cnt != 1)
		return (DLADM_STATUS_BADVALCNT);

	errno = 0;
	hlim = strtol(*prop_val, &ep, 10);
	if (errno != 0 || ep == *prop_val || hlim < 1 ||
	    hlim > (int32_t)UINT8_MAX)
		return (DLADM_STATUS_BADVAL);
	vdp->vd_val = hlim;
	return (DLADM_STATUS_OK);
}

/* ARGSUSED */
static dladm_status_t
check_encaplim(dladm_handle_t handle, prop_desc_t *pdp, datalink_id_t linkid,
    char **prop_val, uint_t *val_cntp, uint_t flags, val_desc_t **vdpp,
    datalink_media_t media)
{
	int32_t		elim;
	char		*ep;
	uint_t		val_cnt = *val_cntp;
	val_desc_t	*vdp = *vdpp;

	if (media != DL_IPV6)
		return (DLADM_STATUS_BADARG);

	if (val_cnt != 1)
		return (DLADM_STATUS_BADVALCNT);

	errno = 0;
	elim = strtol(*prop_val, &ep, 10);
	if (errno != 0 || ep == *prop_val || elim < 0 ||
	    elim > (int32_t)UINT8_MAX)
		return (DLADM_STATUS_BADVAL);
	vdp->vd_val = elim;
	return (DLADM_STATUS_OK);
}

static dladm_status_t
i_dladm_set_linkprop_db(dladm_handle_t handle, datalink_id_t linkid,
    const char *prop_name, char **prop_val, uint_t val_cnt)
{
	char		buf[MAXLINELEN];
	int		i;
	dladm_conf_t	conf;
	dladm_status_t	status;

	status = dladm_open_conf(handle, linkid, &conf);
	if (status != DLADM_STATUS_OK)
		return (status);

	/*
	 * reset case.
	 */
	if (val_cnt == 0) {
		status = dladm_unset_conf_field(handle, conf, prop_name);
		if (status == DLADM_STATUS_OK)
			status = dladm_write_conf(handle, conf);
		goto done;
	}

	buf[0] = '\0';
	for (i = 0; i < val_cnt; i++) {
		(void) strlcat(buf, prop_val[i], MAXLINELEN);
		if (i != val_cnt - 1)
			(void) strlcat(buf, ",", MAXLINELEN);
	}

	status = dladm_set_conf_field(handle, conf, prop_name, DLADM_TYPE_STR,
	    buf);
	if (status == DLADM_STATUS_OK)
		status = dladm_write_conf(handle, conf);

done:
	dladm_destroy_conf(handle, conf);
	return (status);
}

static dladm_status_t
i_dladm_get_linkprop_db(dladm_handle_t handle, datalink_id_t linkid,
    const char *prop_name, char **prop_val, uint_t *val_cntp)
{
	char		buf[MAXLINELEN], *str;
	uint_t		cnt = 0;
	dladm_conf_t	conf;
	dladm_status_t	status;

	status = dladm_getsnap_conf(handle, linkid, &conf);
	if (status != DLADM_STATUS_OK)
		return (status);

	status = dladm_get_conf_field(handle, conf, prop_name, buf, MAXLINELEN);
	if (status != DLADM_STATUS_OK)
		goto done;

	str = strtok(buf, ",");
	while (str != NULL) {
		if (cnt == *val_cntp) {
			status = DLADM_STATUS_TOOSMALL;
			goto done;
		}
		(void) strlcpy(prop_val[cnt++], str, DLADM_PROP_VAL_MAX);
		str = strtok(NULL, ",");
	}

	*val_cntp = cnt;

done:
	dladm_destroy_conf(handle, conf);
	return (status);
}

/*
 * Walk persistent private link properties of a link.
 */
static dladm_status_t
i_dladm_walk_linkprop_priv_db(dladm_handle_t handle, datalink_id_t linkid,
    void *arg, int (*func)(dladm_handle_t, datalink_id_t, const char *, void *))
{
	dladm_status_t		status;
	dladm_conf_t		conf;
	char			last_attr[MAXLINKATTRLEN];
	char			attr[MAXLINKATTRLEN];
	char			attrval[MAXLINKATTRVALLEN];
	size_t			attrsz;

	if (linkid == DATALINK_INVALID_LINKID || func == NULL)
		return (DLADM_STATUS_BADARG);

	status = dladm_getsnap_conf(handle, linkid, &conf);
	if (status != DLADM_STATUS_OK)
		return (status);

	last_attr[0] = '\0';
	while ((status = dladm_getnext_conf_linkprop(handle, conf, last_attr,
	    attr, attrval, MAXLINKATTRVALLEN, &attrsz)) == DLADM_STATUS_OK) {
		if (attr[0] == '_') {
			if (func(handle, linkid, attr, arg) ==
			    DLADM_WALK_TERMINATE)
				break;
		}
		(void) strlcpy(last_attr, attr, MAXLINKATTRLEN);
	}

	dladm_destroy_conf(handle, conf);
	return (DLADM_STATUS_OK);
}

static link_attr_t *
dladm_name2prop(const char *prop_name)
{
	link_attr_t *p;

	for (p = link_attr; p->pp_id != MAC_PROP_PRIVATE; p++) {
		if (strcmp(p->pp_name, prop_name) == 0)
			break;
	}
	return (p);
}

static link_attr_t *
dladm_id2prop(mac_prop_id_t propid)
{
	link_attr_t *p;

	for (p = link_attr; p->pp_id != MAC_PROP_PRIVATE; p++) {
		if (p->pp_id == propid)
			break;
	}
	return (p);
}

static dld_ioc_macprop_t *
i_dladm_buf_alloc_impl(size_t valsize, datalink_id_t linkid,
    const char *prop_name, mac_prop_id_t propid, uint_t flags,
    dladm_status_t *status)
{
	int dsize;
	dld_ioc_macprop_t *dip;

	*status = DLADM_STATUS_OK;
	dsize = MAC_PROP_BUFSIZE(valsize);
	dip = malloc(dsize);
	if (dip == NULL) {
		*status = DLADM_STATUS_NOMEM;
		return (NULL);
	}
	bzero(dip, dsize);
	dip->pr_valsize = valsize;
	(void) strlcpy(dip->pr_name, prop_name, sizeof (dip->pr_name));
	dip->pr_linkid = linkid;
	dip->pr_num = propid;
	dip->pr_flags = flags;
	return (dip);
}

static dld_ioc_macprop_t *
i_dladm_buf_alloc_by_name(size_t valsize, datalink_id_t linkid,
    const char *prop_name, uint_t flags, dladm_status_t *status)
{
	link_attr_t *p;

	p = dladm_name2prop(prop_name);
	valsize = MAX(p->pp_valsize, valsize);
	return (i_dladm_buf_alloc_impl(valsize, linkid, prop_name, p->pp_id,
	    flags, status));
}

static dld_ioc_macprop_t *
i_dladm_buf_alloc_by_id(size_t valsize, datalink_id_t linkid,
    mac_prop_id_t propid, uint_t flags, dladm_status_t *status)
{
	link_attr_t *p;

	p = dladm_id2prop(propid);
	valsize = MAX(p->pp_valsize, valsize);
	return (i_dladm_buf_alloc_impl(valsize, linkid, p->pp_name, propid,
	    flags, status));
}

/* ARGSUSED */
static dladm_status_t
set_public_prop(dladm_handle_t handle, prop_desc_t *pdp,
    datalink_id_t linkid, val_desc_t *vdp, uint_t val_cnt, uint_t flags,
    datalink_media_t media)
{
	dld_ioc_macprop_t	*dip;
	dladm_status_t	status = DLADM_STATUS_OK;
	uint8_t		u8;
	uint16_t	u16;
	uint32_t	u32;
	void		*val;

	dip = i_dladm_buf_alloc_by_name(0, linkid, pdp->pd_name, 0, &status);
	if (dip == NULL)
		return (status);

	if (pdp->pd_flags & PD_CHECK_ALLOC)
		val = (void *)vdp->vd_val;
	else {
		/*
		 * Currently all 1/2/4-byte size properties are byte/word/int.
		 * No need (yet) to distinguish these from arrays of same size.
		 */
		switch (dip->pr_valsize) {
		case 1:
			u8 = vdp->vd_val;
			val = &u8;
			break;
		case 2:
			u16 = vdp->vd_val;
			val = &u16;
			break;
		case 4:
			u32 = vdp->vd_val;
			val = &u32;
			break;
		default:
			val = &vdp->vd_val;
			break;
		}
	}

	if (val != NULL)
		(void) memcpy(dip->pr_val, val, dip->pr_valsize);
	else
		dip->pr_valsize = 0;

	status = i_dladm_macprop(handle, dip, B_TRUE);

done:
	free(dip);
	return (status);
}

dladm_status_t
i_dladm_macprop(dladm_handle_t handle, void *dip, boolean_t set)
{
	dladm_status_t status = DLADM_STATUS_OK;

	if (ioctl(dladm_dld_fd(handle),
	    (set ? DLDIOC_SETMACPROP : DLDIOC_GETMACPROP), dip))
		status = dladm_errno2status(errno);

	return (status);
}

static dladm_status_t
i_dladm_get_public_prop(dladm_handle_t handle, datalink_id_t linkid,
    char *prop_name, uint_t flags, uint_t *perm_flags, void *arg, size_t size)
{
	dld_ioc_macprop_t	*dip;
	dladm_status_t		status;

	dip = i_dladm_buf_alloc_by_name(0, linkid, prop_name, flags, &status);
	if (dip == NULL)
		return (DLADM_STATUS_NOMEM);

	status = i_dladm_macprop(handle, dip, B_FALSE);
	if (status != DLADM_STATUS_OK) {
		free(dip);
		return (status);
	}

	if (perm_flags != NULL)
		*perm_flags = dip->pr_perm_flags;

	if (arg != NULL)
		(void) memcpy(arg, dip->pr_val, size);
	free(dip);
	return (DLADM_STATUS_OK);
}

/* ARGSUSED */
static dladm_status_t
check_uint32(dladm_handle_t handle, prop_desc_t *pdp,
    datalink_id_t linkid, char **prop_val, uint_t *val_cntp, uint_t flags,
    val_desc_t **vp, datalink_media_t media)
{
	uint_t		val_cnt = *val_cntp;
	val_desc_t	*v = *vp;

	if (val_cnt != 1)
		return (DLADM_STATUS_BADVAL);
	v->vd_val = strtoul(prop_val[0], NULL, 0);
	return (DLADM_STATUS_OK);
}

/* ARGSUSED */
static dladm_status_t
get_duplex(dladm_handle_t handle, prop_desc_t *pdp,
    datalink_id_t linkid, char **prop_val, uint_t *val_cnt,
    datalink_media_t media, uint_t flags, uint_t *perm_flags)
{
	link_duplex_t   link_duplex;
	dladm_status_t  status;

	if ((status = dladm_get_single_mac_stat(handle, linkid, "link_duplex",
	    KSTAT_DATA_UINT32, &link_duplex)) != 0)
		return (status);

	switch (link_duplex) {
	case LINK_DUPLEX_FULL:
		(void) strcpy(*prop_val, "full");
		break;
	case LINK_DUPLEX_HALF:
		(void) strcpy(*prop_val, "half");
		break;
	default:
		(void) strcpy(*prop_val, "unknown");
		break;
	}
	*val_cnt = 1;
	return (DLADM_STATUS_OK);
}

/* ARGSUSED */
static dladm_status_t
get_speed(dladm_handle_t handle, prop_desc_t *pdp, datalink_id_t linkid,
    char **prop_val, uint_t *val_cnt, datalink_media_t media, uint_t flags,
    uint_t *perm_flags)
{
	uint64_t	ifspeed = 0;
	dladm_status_t status;

	if ((status = dladm_get_single_mac_stat(handle, linkid, "ifspeed",
	    KSTAT_DATA_UINT64, &ifspeed)) != 0)
		return (status);

	if ((ifspeed % 1000000) != 0) {
		(void) snprintf(*prop_val, DLADM_PROP_VAL_MAX,
		    "%llf", ifspeed / (float)1000000); /* Mbps */
	} else {
		(void) snprintf(*prop_val, DLADM_PROP_VAL_MAX,
		    "%llu", ifspeed / 1000000); /* Mbps */
	}
	*val_cnt = 1;
	*perm_flags = MAC_PROP_PERM_READ;
	return (DLADM_STATUS_OK);
}

/* ARGSUSED */
static dladm_status_t
get_link_state(dladm_handle_t handle, prop_desc_t *pdp,
    datalink_id_t linkid, char **prop_val, uint_t *val_cnt,
    datalink_media_t media, uint_t flags, uint_t *perm_flags)
{
	link_state_t		link_state;
	dladm_status_t		status;

	status = dladm_get_state(handle, linkid, &link_state);
	if (status != DLADM_STATUS_OK)
		return (status);

	switch (link_state) {
	case LINK_STATE_UP:
		(void) strcpy(*prop_val, "up");
		break;
	case LINK_STATE_DOWN:
		(void) strcpy(*prop_val, "down");
		break;
	default:
		(void) strcpy(*prop_val, "unknown");
		break;
	}
	*val_cnt = 1;
	*perm_flags = MAC_PROP_PERM_READ;
	return (DLADM_STATUS_OK);
}

/* ARGSUSED */
static dladm_status_t
get_binary(dladm_handle_t handle, prop_desc_t *pdp,
    datalink_id_t linkid, char **prop_val, uint_t *val_cnt,
    datalink_media_t media, uint_t flags, uint_t *perm_flags)
{
	dladm_status_t	status;
	uint_t		v = 0;

	status = i_dladm_get_public_prop(handle, linkid, pdp->pd_name, flags,
	    perm_flags, &v, sizeof (v));
	if (status != DLADM_STATUS_OK)
		return (status);

	(void) snprintf(*prop_val, DLADM_PROP_VAL_MAX, "%d", (uint_t)(v > 0));
	*val_cnt = 1;
	return (DLADM_STATUS_OK);
}

/* ARGSUSED */
static dladm_status_t
get_uint32(dladm_handle_t handle, prop_desc_t *pdp,
    datalink_id_t linkid, char **prop_val, uint_t *val_cnt,
    datalink_media_t media, uint_t flags, uint_t *perm_flags)
{
	dladm_status_t	status;
	uint32_t	v = 0;

	status = i_dladm_get_public_prop(handle, linkid, pdp->pd_name, flags,
	    perm_flags, &v, sizeof (v));
	if (status != DLADM_STATUS_OK)
		return (status);

	(void) snprintf(*prop_val, DLADM_PROP_VAL_MAX, "%ld", v);
	*val_cnt = 1;
	return (DLADM_STATUS_OK);
}

/* ARGSUSED */
static dladm_status_t
get_range(dladm_handle_t handle, prop_desc_t *pdp,
    datalink_id_t linkid, char **prop_val, uint_t *val_cnt,
    datalink_media_t media, uint_t flags, uint_t *perm_flags)
{
	dld_ioc_macprop_t *dip;
	dladm_status_t status = DLADM_STATUS_OK;
	size_t	sz;
	uint_t	rcount;
	mac_propval_range_t *rangep;

	/*
	 * As caller we don't know number of value ranges, the driver
	 * supports. To begin with we assume that number to be 1. If the
	 * buffer size is insufficient, driver returns back with the
	 * actual count of value ranges. See mac.h for more details.
	 */
	sz = sizeof (mac_propval_range_t);
	rcount = 1;
retry:
	if ((dip = i_dladm_buf_alloc_by_name(sz, linkid, pdp->pd_name, flags,
	    &status)) == NULL)
		return (status);

	rangep = (mac_propval_range_t *)(void *)&dip->pr_val;
	rangep->mpr_count = rcount;

	status = i_dladm_macprop(handle, dip, B_FALSE);
	if (status != DLADM_STATUS_OK) {
		if (status == DLADM_STATUS_TOOSMALL) {
			int err;

			if ((err = i_dladm_range_size(rangep, &sz, &rcount))
			    == 0) {
				free(dip);
				goto retry;
			} else {
				status = dladm_errno2status(err);
			}
		}
		free(dip);
		return (status);
	}

	if (rangep->mpr_count == 0) {
		*val_cnt = 1;
		(void) snprintf(prop_val[0], DLADM_PROP_VAL_MAX, "--");
		goto done;
	}

	switch (rangep->mpr_type) {
	case MAC_PROPVAL_UINT32: {
		mac_propval_uint32_range_t *ur;
		uint_t	count = rangep->mpr_count, i;

		ur = &rangep->mpr_range_uint32[0];

		for (i = 0; i < count; i++, ur++) {
			if (ur->mpur_min == ur->mpur_max) {
				(void) snprintf(prop_val[i], DLADM_PROP_VAL_MAX,
				    "%ld", ur->mpur_min);
			} else {
				(void) snprintf(prop_val[i], DLADM_PROP_VAL_MAX,
				    "%ld-%ld", ur->mpur_min, ur->mpur_max);
			}
		}
		*val_cnt = count;
		break;
	}
	default:
		status = DLADM_STATUS_BADARG;
		break;
	}
done:
	free(dip);
	return (status);
}

/* ARGSUSED */
static dladm_status_t
get_tagmode(dladm_handle_t handle, prop_desc_t *pdp,
    datalink_id_t linkid, char **prop_val, uint_t *val_cnt,
    datalink_media_t media, uint_t flags, uint_t *perm_flags)
{
	link_tagmode_t		mode;
	dladm_status_t		status;

	status = i_dladm_get_public_prop(handle, linkid, pdp->pd_name, flags,
	    perm_flags, &mode, sizeof (mode));
	if (status != DLADM_STATUS_OK)
		return (status);

	switch (mode) {
	case LINK_TAGMODE_NORMAL:
		(void) strlcpy(*prop_val, "normal", DLADM_PROP_VAL_MAX);
		break;
	case LINK_TAGMODE_VLANONLY:
		(void) strlcpy(*prop_val, "vlanonly", DLADM_PROP_VAL_MAX);
		break;
	default:
		(void) strlcpy(*prop_val, "unknown", DLADM_PROP_VAL_MAX);
	}
	*val_cnt = 1;
	return (DLADM_STATUS_OK);
}

/* ARGSUSED */
static dladm_status_t
get_flowctl(dladm_handle_t handle, prop_desc_t *pdp,
    datalink_id_t linkid, char **prop_val, uint_t *val_cnt,
    datalink_media_t media, uint_t flags, uint_t *perm_flags)
{
	link_flowctrl_t	v;
	dladm_status_t	status;

	status = i_dladm_get_public_prop(handle, linkid, pdp->pd_name, flags,
	    perm_flags, &v, sizeof (v));
	if (status != DLADM_STATUS_OK)
		return (status);

	switch (v) {
	case LINK_FLOWCTRL_NONE:
		(void) sprintf(*prop_val, "no");
		break;
	case LINK_FLOWCTRL_RX:
		(void) sprintf(*prop_val, "rx");
		break;
	case LINK_FLOWCTRL_TX:
		(void) sprintf(*prop_val, "tx");
		break;
	case LINK_FLOWCTRL_BI:
		(void) sprintf(*prop_val, "bi");
		break;
	}
	*val_cnt = 1;
	return (DLADM_STATUS_OK);
}


/* ARGSUSED */
static dladm_status_t
i_dladm_set_private_prop(dladm_handle_t handle, datalink_id_t linkid,
    const char *prop_name, char **prop_val, uint_t val_cnt, uint_t flags)
{
	int		i, slen;
	int 		bufsize = 0;
	dld_ioc_macprop_t *dip = NULL;
	uchar_t 	*dp;
	link_attr_t *p;
	dladm_status_t	status = DLADM_STATUS_OK;

	if ((prop_name == NULL && prop_val != NULL) ||
	    (prop_val != NULL && val_cnt == 0))
		return (DLADM_STATUS_BADARG);
	p = dladm_name2prop(prop_name);
	if (p->pp_id != MAC_PROP_PRIVATE)
		return (DLADM_STATUS_BADARG);

	if (!(flags & DLADM_OPT_ACTIVE))
		return (DLADM_STATUS_OK);

	/*
	 * private properties: all parsing is done in the kernel.
	 * allocate a enough space for each property + its separator (',').
	 */
	for (i = 0; i < val_cnt; i++) {
		bufsize += strlen(prop_val[i]) + 1;
	}

	if (prop_val == NULL) {
		/*
		 * getting default value. so use more buffer space.
		 */
		bufsize += DLADM_PROP_BUF_CHUNK;
	}

	dip = i_dladm_buf_alloc_by_name(bufsize + 1, linkid, prop_name,
	    (prop_val != NULL ? 0 : DLD_PROP_DEFAULT), &status);
	if (dip == NULL)
		return (status);

	dp = (uchar_t *)dip->pr_val;
	slen = 0;

	if (prop_val == NULL) {
		status = i_dladm_macprop(handle, dip, B_FALSE);
		dip->pr_flags = 0;
	} else {
		for (i = 0; i < val_cnt; i++) {
			int plen = 0;

			plen = strlen(prop_val[i]);
			bcopy(prop_val[i], dp, plen);
			slen += plen;
			/*
			 * add a "," separator and update dp.
			 */
			if (i != (val_cnt -1))
				dp[slen++] = ',';
			dp += (plen + 1);
		}
	}
	if (status == DLADM_STATUS_OK)
		status = i_dladm_macprop(handle, dip, B_TRUE);

	free(dip);
	return (status);
}

static dladm_status_t
i_dladm_get_priv_prop(dladm_handle_t handle, datalink_id_t linkid,
    const char *prop_name, char **prop_val, uint_t *val_cnt,
    dladm_prop_type_t type, uint_t dld_flags)
{
	dladm_status_t	status = DLADM_STATUS_OK;
	dld_ioc_macprop_t *dip = NULL;
	link_attr_t *p;

	if ((prop_name == NULL && prop_val != NULL) ||
	    (prop_val != NULL && val_cnt == 0))
		return (DLADM_STATUS_BADARG);

	p = dladm_name2prop(prop_name);
	if (p->pp_id != MAC_PROP_PRIVATE)
		return (DLADM_STATUS_BADARG);

	/*
	 * private properties: all parsing is done in the kernel.
	 */
	dip = i_dladm_buf_alloc_by_name(DLADM_PROP_BUF_CHUNK, linkid, prop_name,
	    dld_flags, &status);
	if (dip == NULL)
		return (status);

	if ((status = i_dladm_macprop(handle, dip, B_FALSE)) ==
	    DLADM_STATUS_OK) {
		if (type == DLADM_PROP_VAL_PERM) {
			(void) dladm_perm2str(dip->pr_perm_flags, *prop_val);
		} else if (type == DLADM_PROP_VAL_MODIFIABLE) {
			*prop_val[0] = '\0';
		} else {
			(void) strncpy(*prop_val, dip->pr_val,
			    DLADM_PROP_VAL_MAX);
		}
		*val_cnt = 1;
	} else if ((status == DLADM_STATUS_NOTSUP) &&
	    (type == DLADM_PROP_VAL_CURRENT)) {
		status = DLADM_STATUS_NOTFOUND;
	}
	free(dip);
	return (status);
}


static dladm_status_t
i_dladm_getset_defval(dladm_handle_t handle, prop_desc_t *pdp,
    datalink_id_t linkid, datalink_media_t media, uint_t flags)
{
	dladm_status_t status;
	char **prop_vals = NULL, *buf;
	size_t bufsize;
	uint_t cnt;
	int i;
	uint_t perm_flags;

	/*
	 * Allocate buffer needed for prop_vals array. We can have at most
	 * DLADM_MAX_PROP_VALCNT char *prop_vals[] entries, where
	 * each entry has max size DLADM_PROP_VAL_MAX
	 */
	bufsize =
	    (sizeof (char *) + DLADM_PROP_VAL_MAX) * DLADM_MAX_PROP_VALCNT;
	buf = malloc(bufsize);
	prop_vals = (char **)(void *)buf;
	for (i = 0; i < DLADM_MAX_PROP_VALCNT; i++) {
		prop_vals[i] = buf +
		    sizeof (char *) * DLADM_MAX_PROP_VALCNT +
		    i * DLADM_PROP_VAL_MAX;
	}

	/*
	 * For properties which have pdp->pd_defval.vd_name as a non-empty
	 * string, the "" itself is used to reset the property (exceptions
	 * are zone and autopush, which populate vdp->vd_val). So
	 * libdladm can copy pdp->pd_defval over to the val_desc_t passed
	 * down on the setprop using the global values in the table. For
	 * other cases (vd_name is ""), doing reset-linkprop will cause
	 * libdladm to do a getprop to find the default value and then do
	 * a setprop to reset the value to default.
	 */
	status = pdp->pd_get(handle, pdp, linkid, prop_vals, &cnt, media,
	    DLD_PROP_DEFAULT, &perm_flags);
	if (status == DLADM_STATUS_OK) {
		if (perm_flags == MAC_PROP_PERM_RW) {
			status = i_dladm_set_single_prop(handle, linkid,
			    pdp->pd_class, media, pdp, prop_vals, cnt, flags);
		}
		else
			status = DLADM_STATUS_NOTSUP;
	}
	free(buf);
	return (status);
}

/* ARGSUSED */
static dladm_status_t
get_stp(dladm_handle_t handle, struct prop_desc *pd, datalink_id_t linkid,
    char **prop_val, uint_t *val_cnt, datalink_media_t media, uint_t flags,
    uint_t *perm_flags)
{
	const bridge_public_prop_t *bpp;
	dladm_status_t retv;
	int val, i;

	if (flags != 0)
		return (DLADM_STATUS_NOTSUP);
	*perm_flags = MAC_PROP_PERM_RW;
	*val_cnt = 1;
	for (bpp = bridge_prop; bpp->bpp_name != NULL; bpp++)
		if (strcmp(bpp->bpp_name, pd->pd_name) == 0)
			break;
	retv = dladm_bridge_get_port_cfg(handle, linkid, bpp->bpp_code, &val);
	/* If the daemon isn't running, then return the persistent value */
	if (retv == DLADM_STATUS_NOTFOUND) {
		if (i_dladm_get_linkprop_db(handle, linkid, pd->pd_name,
		    prop_val, val_cnt) != DLADM_STATUS_OK)
			(void) strlcpy(*prop_val, pd->pd_defval.vd_name,
			    DLADM_PROP_VAL_MAX);
		return (DLADM_STATUS_OK);
	}
	if (retv != DLADM_STATUS_OK) {
		(void) strlcpy(*prop_val, "?", DLADM_PROP_VAL_MAX);
		return (retv);
	}
	if (val == pd->pd_defval.vd_val && pd->pd_defval.vd_name[0] != '\0') {
		(void) strlcpy(*prop_val, pd->pd_defval.vd_name,
		    DLADM_PROP_VAL_MAX);
		return (DLADM_STATUS_OK);
	}
	for (i = 0; i < pd->pd_noptval; i++) {
		if (val == pd->pd_optval[i].vd_val) {
			(void) strlcpy(*prop_val, pd->pd_optval[i].vd_name,
			    DLADM_PROP_VAL_MAX);
			return (DLADM_STATUS_OK);
		}
	}
	(void) snprintf(*prop_val, DLADM_PROP_VAL_MAX, "%u", (unsigned)val);
	return (DLADM_STATUS_OK);
}

/* ARGSUSED1 */
static dladm_status_t
set_stp_prop(dladm_handle_t handle, prop_desc_t *pd, datalink_id_t linkid,
    val_desc_t *vdp, uint_t val_cnt, uint_t flags, datalink_media_t media)
{
	/*
	 * Special case for mcheck: the daemon resets the value to zero, and we
	 * don't want the daemon to refresh itself; it leads to deadlock.
	 */
	if (flags & DLADM_OPT_NOREFRESH)
		return (DLADM_STATUS_OK);

	/* Tell the running daemon, if any */
	return (dladm_bridge_refresh(handle, linkid));
}

/*
 * This is used only for stp_priority, stp_cost, and stp_mcheck.
 */
/* ARGSUSED */
static dladm_status_t
check_stp_prop(dladm_handle_t handle, struct prop_desc *pd,
    datalink_id_t linkid, char **prop_val, uint_t *val_cntp, uint_t flags,
    val_desc_t **vdpp, datalink_media_t media)
{
	char		*cp;
	boolean_t	iscost;
	uint_t		val_cnt = *val_cntp;
	val_desc_t	*vdp = *vdpp;

	if (val_cnt != 1)
		return (DLADM_STATUS_BADVALCNT);

	if (prop_val == NULL) {
		vdp->vd_val = 0;
	} else {
		/* Only stp_priority and stp_cost use this function */
		iscost = strcmp(pd->pd_name, "stp_cost") == 0;

		if (iscost && strcmp(prop_val[0], "auto") == 0) {
			/* Illegal value 0 is allowed to mean "automatic" */
			vdp->vd_val = 0;
		} else {
			errno = 0;
			vdp->vd_val = strtoul(prop_val[0], &cp, 0);
			if (errno != 0 || *cp != '\0')
				return (DLADM_STATUS_BADVAL);
		}
	}

	if (iscost) {
		return (vdp->vd_val > 65535 ? DLADM_STATUS_BADVAL :
		    DLADM_STATUS_OK);
	} else {
		if (vdp->vd_val > 255)
			return (DLADM_STATUS_BADVAL);
		/*
		 * If the user is setting stp_mcheck non-zero, then (per the
		 * IEEE management standards and UNH testing) we need to check
		 * whether this link is part of a bridge that is running RSTP.
		 * If it's not, then setting the flag is an error.  Note that
		 * errors are intentionally discarded here; it's the value
		 * that's the problem -- it's not a bad value, merely one that
		 * can't be used now.
		 */
		if (strcmp(pd->pd_name, "stp_mcheck") == 0 &&
		    vdp->vd_val != 0) {
			char bridge[MAXLINKNAMELEN];
			UID_STP_CFG_T cfg;
			dladm_bridge_prot_t brprot;

			if (dladm_bridge_getlink(handle, linkid, bridge,
			    sizeof (bridge)) != DLADM_STATUS_OK ||
			    dladm_bridge_get_properties(bridge, &cfg,
			    &brprot) != DLADM_STATUS_OK)
				return (DLADM_STATUS_FAILED);
			if (cfg.force_version <= 1)
				return (DLADM_STATUS_FAILED);
		}
		return (DLADM_STATUS_OK);
	}
}

/* ARGSUSED */
static dladm_status_t
get_bridge_forward(dladm_handle_t handle, struct prop_desc *pd,
    datalink_id_t linkid, char **prop_val, uint_t *val_cnt,
    datalink_media_t media, uint_t flags, uint_t *perm_flags)
{
	dladm_status_t retv;
	uint_t val;

	if (flags != 0)
		return (DLADM_STATUS_NOTSUP);
	*perm_flags = MAC_PROP_PERM_RW;
	*val_cnt = 1;
	retv = dladm_bridge_get_forwarding(handle, linkid, &val);
	if (retv == DLADM_STATUS_NOTFOUND) {
		if (i_dladm_get_linkprop_db(handle, linkid, pd->pd_name,
		    prop_val, val_cnt) != DLADM_STATUS_OK)
			(void) strlcpy(*prop_val, pd->pd_defval.vd_name,
			    DLADM_PROP_VAL_MAX);
		return (DLADM_STATUS_OK);
	}
	if (retv == DLADM_STATUS_OK)
		(void) snprintf(*prop_val, DLADM_PROP_VAL_MAX, "%u", val);
	else
		(void) strlcpy(*prop_val, "?", DLADM_PROP_VAL_MAX);
	return (retv);
}

/* ARGSUSED */
static dladm_status_t
set_bridge_forward(dladm_handle_t handle, prop_desc_t *pd, datalink_id_t linkid,
    val_desc_t *vdp, uint_t val_cnt, uint_t flags, datalink_media_t media)
{
	/* Tell the running daemon, if any */
	return (dladm_bridge_refresh(handle, linkid));
}

/* ARGSUSED */
static dladm_status_t
get_bridge_pvid(dladm_handle_t handle, struct prop_desc *pd,
    datalink_id_t linkid, char **prop_val, uint_t *val_cnt,
    datalink_media_t media, uint_t flags, uint_t *perm_flags)
{
	dladm_status_t status;
	dld_ioc_macprop_t *dip;
	uint16_t pvid;

	if (flags != 0)
		return (DLADM_STATUS_NOTSUP);
	*perm_flags = MAC_PROP_PERM_RW;
	*val_cnt = 1;
	dip = i_dladm_buf_alloc_by_id(sizeof (uint16_t), linkid, MAC_PROP_PVID,
	    0, &status);
	if (dip == NULL)
		return (status);
	status = i_dladm_macprop(handle, dip, B_FALSE);
	if (status == DLADM_STATUS_OK) {
		(void) memcpy(&pvid, dip->pr_val, sizeof (pvid));
		(void) snprintf(*prop_val, DLADM_PROP_VAL_MAX, "%u", pvid);
	} else {
		(void) strlcpy(*prop_val, "?", DLADM_PROP_VAL_MAX);
	}
	free(dip);
	return (status);
}

/* ARGSUSED */
static dladm_status_t
set_bridge_pvid(dladm_handle_t handle, prop_desc_t *pd, datalink_id_t linkid,
    val_desc_t *vdp, uint_t val_cnt, uint_t flags, datalink_media_t media)
{
	dladm_status_t status;
	dld_ioc_macprop_t *dip;
	uint16_t pvid;

	dip = i_dladm_buf_alloc_by_id(sizeof (uint16_t), linkid, MAC_PROP_PVID,
	    0, &status);
	if (dip == NULL)
		return (status);
	pvid = vdp->vd_val;
	(void) memcpy(dip->pr_val, &pvid, sizeof (pvid));
	status = i_dladm_macprop(handle, dip, B_TRUE);
	free(dip);
	if (status != DLADM_STATUS_OK)
		return (status);

	/* Tell the running daemon, if any */
	return (dladm_bridge_refresh(handle, linkid));
}

/* ARGSUSED */
static dladm_status_t
check_bridge_pvid(dladm_handle_t handle, struct prop_desc *pd,
    datalink_id_t linkid, char **prop_val, uint_t *val_cntp, uint_t flags,
    val_desc_t **vdpp, datalink_media_t media)
{
	char		*cp;
	uint_t		val_cnt = *val_cntp;
	val_desc_t	*vdp = *vdpp;

	if (val_cnt != 1)
		return (DLADM_STATUS_BADVALCNT);

	if (prop_val == NULL) {
		vdp->vd_val = 1;
	} else {
		errno = 0;
		vdp->vd_val = strtoul(prop_val[0], &cp, 0);
		if (errno != 0 || *cp != '\0')
			return (DLADM_STATUS_BADVAL);
	}

	return (vdp->vd_val > VLAN_ID_MAX ? DLADM_STATUS_BADVAL :
	    DLADM_STATUS_OK);
}

dladm_status_t
i_dladm_wlan_param(dladm_handle_t handle, datalink_id_t linkid, void *buf,
    mac_prop_id_t cmd, size_t len, boolean_t set)
{
	uint32_t		flags;
	dladm_status_t		status;
	uint32_t		media;
	dld_ioc_macprop_t	*dip;
	void			*dp;

	if ((status = dladm_datalink_id2info(handle, linkid, &flags, NULL,
	    &media, NULL, 0)) != DLADM_STATUS_OK) {
		return (status);
	}

	if (media != DL_WIFI)
		return (DLADM_STATUS_BADARG);

	if (!(flags & DLADM_OPT_ACTIVE))
		return (DLADM_STATUS_TEMPONLY);

	if (len == (MAX_BUF_LEN - WIFI_BUF_OFFSET))
		len = MAX_BUF_LEN - sizeof (dld_ioc_macprop_t) - 1;

	dip = i_dladm_buf_alloc_by_id(len, linkid, cmd, 0, &status);
	if (dip == NULL)
		return (DLADM_STATUS_NOMEM);

	dp = (uchar_t *)dip->pr_val;
	if (set)
		(void) memcpy(dp, buf, len);

	status = i_dladm_macprop(handle, dip, set);
	if (status == DLADM_STATUS_OK) {
		if (!set)
			(void) memcpy(buf, dp, len);
	}

	free(dip);
	return (status);
}

dladm_status_t
dladm_parse_link_props(char *str, dladm_arg_list_t **listp, boolean_t novalues)
{
	return (dladm_parse_args(str, listp, novalues));
}

/*
 * Retrieve the one link property from the database
 */
/*ARGSUSED*/
static int
i_dladm_get_one_prop(dladm_handle_t handle, datalink_id_t linkid,
    const char *prop_name, void *arg)
{
	dladm_arg_list_t	*proplist = arg;
	dladm_arg_info_t	*aip = NULL;

	aip = &proplist->al_info[proplist->al_count];
	/*
	 * it is fine to point to prop_name since prop_name points to the
	 * prop_table[n].pd_name.
	 */
	aip->ai_name = prop_name;

	(void) dladm_get_linkprop(handle, linkid, DLADM_PROP_VAL_PERSISTENT,
	    prop_name, aip->ai_val, &aip->ai_count);

	if (aip->ai_count != 0)
		proplist->al_count++;

	return (DLADM_WALK_CONTINUE);
}


/*
 * Retrieve all link properties for a link from the database and
 * return a property list.
 */
dladm_status_t
dladm_link_get_proplist(dladm_handle_t handle, datalink_id_t linkid,
    dladm_arg_list_t **listp)
{
	dladm_arg_list_t	*list;
	dladm_status_t		status = DLADM_STATUS_OK;

	list = calloc(1, sizeof (dladm_arg_list_t));
	if (list == NULL)
		return (dladm_errno2status(errno));

	status = dladm_walk_linkprop(handle, linkid, list,
	    i_dladm_get_one_prop);

	*listp = list;
	return (status);
}

/*
 * Retrieve the named property from a proplist, check the value and
 * convert to a kernel structure.
 */
static dladm_status_t
i_dladm_link_proplist_extract_one(dladm_handle_t handle,
    dladm_arg_list_t *proplist, const char *name, uint_t flags, void *arg)
{
	dladm_status_t		status;
	dladm_arg_info_t	*aip = NULL;
	int			i, j;

	/* Find named property in proplist */
	for (i = 0; i < proplist->al_count; i++) {
		aip = &proplist->al_info[i];
		if (strcasecmp(aip->ai_name, name) == 0)
			break;
	}

	/* Property not in list */
	if (i == proplist->al_count)
		return (DLADM_STATUS_OK);

	for (i = 0; i < DLADM_MAX_PROPS; i++) {
		prop_desc_t	*pdp = &prop_table[i];
		val_desc_t	*vdp;

		vdp = malloc(sizeof (val_desc_t) * aip->ai_count);
		if (vdp == NULL)
			return (DLADM_STATUS_NOMEM);

		if (strcasecmp(aip->ai_name, pdp->pd_name) != 0)
			continue;

		if (aip->ai_val == NULL)
			return (DLADM_STATUS_BADARG);

		/* Check property value */
		if (pdp->pd_check != NULL) {
			status = pdp->pd_check(handle, pdp, 0, aip->ai_val,
			    &(aip->ai_count), flags, &vdp, 0);
		} else {
			status = DLADM_STATUS_BADARG;
		}

		if (status != DLADM_STATUS_OK)
			return (status);

		for (j = 0; j < DLADM_MAX_RSRC_PROP; j++) {
			resource_prop_t	*rpp = &rsrc_prop_table[j];

			if (strcasecmp(aip->ai_name, rpp->rp_name) != 0)
				continue;

			/* Extract kernel structure */
			if (rpp->rp_extract != NULL) {
				status = rpp->rp_extract(vdp,
				    aip->ai_count, arg);
			} else {
				status = DLADM_STATUS_BADARG;
			}
			break;
		}

		if (status != DLADM_STATUS_OK)
			return (status);

		break;
	}
	return (status);
}

/*
 * Extract properties from a proplist and convert to mac_resource_props_t.
 */
dladm_status_t
dladm_link_proplist_extract(dladm_handle_t handle, dladm_arg_list_t *proplist,
    mac_resource_props_t *mrp, uint_t flags)
{
	dladm_status_t	status;
	int		i;

	for (i = 0; i < DLADM_MAX_RSRC_PROP; i++) {
		status = i_dladm_link_proplist_extract_one(handle,
		    proplist, rsrc_prop_table[i].rp_name, flags, mrp);
		if (status != DLADM_STATUS_OK)
			return (status);
	}
	return (status);
}

static const char *
dladm_perm2str(uint_t perm, char *buf)
{
	(void) snprintf(buf, DLADM_STRSIZE, "%c%c",
	    ((perm & MAC_PROP_PERM_READ) != 0) ? 'r' : '-',
	    ((perm & MAC_PROP_PERM_WRITE) != 0) ? 'w' : '-');
	return (buf);
}

dladm_status_t
dladm_get_state(dladm_handle_t handle, datalink_id_t linkid,
    link_state_t *state)
{
	uint_t			perms;

	return (i_dladm_get_public_prop(handle, linkid, "state", 0,
	    &perms, state, sizeof (*state)));
}

boolean_t
dladm_attr_is_linkprop(const char *name)
{
	/* non-property attribute names */
	const char *nonprop[] = {
		/* dlmgmtd core attributes */
		"name",
		"class",
		"media",
		FPHYMAJ,
		FPHYINST,
		FDEVNAME,

		/* other attributes for vlan, aggr, etc */
		DLADM_ATTR_NAMES
	};
	boolean_t	is_nonprop = B_FALSE;
	int		i;

	for (i = 0; i < sizeof (nonprop) / sizeof (nonprop[0]); i++) {
		if (strcmp(name, nonprop[i]) == 0) {
			is_nonprop = B_TRUE;
			break;
		}
	}

	return (!is_nonprop);
}

dladm_status_t
dladm_linkprop_is_set(dladm_handle_t handle, datalink_id_t linkid,
    dladm_prop_type_t type, const char *prop_name, boolean_t *is_set)
{
	char		*buf, **propvals;
	uint_t		valcnt = DLADM_MAX_PROP_VALCNT;
	int		i;
	dladm_status_t	status = DLADM_STATUS_OK;
	size_t		bufsize;

	*is_set = B_FALSE;

	bufsize = (sizeof (char *) + DLADM_PROP_VAL_MAX) *
	    DLADM_MAX_PROP_VALCNT;
	if ((buf = calloc(1, bufsize)) == NULL)
		return (DLADM_STATUS_NOMEM);

	propvals = (char **)(void *)buf;
	for (i = 0; i < valcnt; i++) {
		propvals[i] = buf +
		    sizeof (char *) * DLADM_MAX_PROP_VALCNT +
		    i * DLADM_PROP_VAL_MAX;
	}

	if (dladm_get_linkprop(handle, linkid, type, prop_name, propvals,
	    &valcnt) != DLADM_STATUS_OK) {
		goto done;
	}

	/*
	 * valcnt is always set to 1 by get_pool(), hence we need to check
	 * for a non-null string to see if it is set. For protection,
	 * secondary-macs and allowed-ips, we can check either the *propval
	 * or the valcnt.
	 */
	if ((strcmp(prop_name, "pool") == 0 ||
	    strcmp(prop_name, "protection") == 0 ||
	    strcmp(prop_name, "secondary-macs") == 0 ||
	    strcmp(prop_name, "allowed-ips") == 0) &&
	    (strlen(*propvals) != 0)) {
		*is_set = B_TRUE;
	} else if ((strcmp(prop_name, "cpus") == 0) && (valcnt != 0)) {
		*is_set = B_TRUE;
	} else if ((strcmp(prop_name, "_softmac") == 0) && (valcnt != 0) &&
	    (strcmp(propvals[0], "true") == 0)) {
		*is_set = B_TRUE;
	}

done:
	if (buf != NULL)
		free(buf);
	return (status);
}

/* ARGSUSED */
static dladm_status_t
get_linkmode_prop(dladm_handle_t handle, prop_desc_t *pdp,
    datalink_id_t linkid, char **prop_val, uint_t *val_cnt,
    datalink_media_t media, uint_t flags, uint_t *perm_flags)
{
	char			*s;
	uint32_t		v;
	dladm_status_t		status;

	status = i_dladm_get_public_prop(handle, linkid, pdp->pd_name, flags,
	    perm_flags, &v, sizeof (v));
	if (status != DLADM_STATUS_OK)
		return (status);

	switch (v) {
	case DLADM_PART_CM_MODE:
		s = "cm";
		break;
	case DLADM_PART_UD_MODE:
		s = "ud";
		break;
	default:
		s = "";
		break;
	}
	(void) snprintf(prop_val[0], DLADM_STRSIZE, "%s", s);

	*val_cnt = 1;
	return (DLADM_STATUS_OK);
}

/*ARGSUSED*/
static dladm_status_t
get_promisc_filtered(dladm_handle_t handle, prop_desc_t *pdp,
    datalink_id_t linkid, char **prop_val, uint_t *val_cnt,
    datalink_media_t media, uint_t flags, uint_t *perm_flags)
{
	char			*s;
	dladm_status_t		status;
	boolean_t		filt;

	status = i_dladm_get_public_prop(handle, linkid, pdp->pd_name, flags,
	    perm_flags, &filt, sizeof (filt));
	if (status != DLADM_STATUS_OK)
		return (status);

	if (filt != 0)
		s = link_promisc_filtered_vals[1].vd_name;
	else
		s = link_promisc_filtered_vals[0].vd_name;
	(void) snprintf(prop_val[0], DLADM_STRSIZE, "%s", s);

	*val_cnt = 1;
	return (DLADM_STATUS_OK);
}

/* ARGSUSED */
static dladm_status_t
set_promisc_filtered(dladm_handle_t handle, prop_desc_t *pdp,
    datalink_id_t linkid, val_desc_t *vdp, uint_t val_cnt, uint_t flags,
    datalink_media_t media)
{
	dld_ioc_macprop_t	*dip;
	dladm_status_t		status = DLADM_STATUS_OK;

	dip = i_dladm_buf_alloc_by_name(0, linkid, pdp->pd_name,
	    0, &status);

	if (dip == NULL)
		return (status);

	(void) memcpy(dip->pr_val, &vdp->vd_val, dip->pr_valsize);
	status = i_dladm_macprop(handle, dip, B_TRUE);

	free(dip);
	return (status);
}
