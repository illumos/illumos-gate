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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
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
#include <dlfcn.h>
#include <link.h>
#include <inet/wifi_ioctl.h>
#include <libdladm.h>
#include <sys/param.h>
#include <sys/dld.h>
#include <inttypes.h>
#include <sys/ethernet.h>

/*
 * The linkprop get() callback.
 * - pd: 	pointer to the struct prop_desc
 * - propstrp:	a property string array to keep the returned property.
 *		Caller allocated.
 * - cntp:	number of returned properties.
 *		Caller also uses it to indicate how many it expects.
 */
struct prop_desc;

typedef dladm_status_t	pd_getf_t(struct prop_desc *pd,
			datalink_id_t, char **propstp, uint_t *cntp,
			datalink_media_t, uint_t);

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
typedef dladm_status_t	pd_setf_t(struct prop_desc *, datalink_id_t,
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
typedef dladm_status_t	pd_checkf_t(struct prop_desc *pd,
			    datalink_id_t, char **propstrp,
			    uint_t cnt, val_desc_t *propval,
			    datalink_media_t);

typedef struct dld_public_prop_s {
	dld_prop_id_t	pp_id;
	size_t		pp_valsize;
	char		*pp_name;
	char		*pp_desc;
} dld_public_prop_t;

static dld_ioc_prop_t *dld_buf_alloc(size_t, datalink_id_t, const char *,
					uint_t, dladm_status_t *);
static dladm_status_t dld_set_prop(datalink_id_t, const char *, char **,
					uint_t, uint_t);
static dladm_status_t dld_get_prop(datalink_id_t, const char *, char **,
					uint_t *, dladm_prop_type_t, uint_t);
static pd_getf_t	do_get_zone, do_get_autopush, do_get_rate_mod,
			do_get_rate_prop, do_get_channel_prop,
			do_get_powermode_prop, do_get_radio_prop,
			dld_duplex_get, dld_status_get,
			dld_binary_get, dld_uint32_get, dld_flowctl_get;
static pd_setf_t	do_set_zone, do_set_autopush, do_set_rate_prop,
			do_set_powermode_prop, do_set_radio_prop,
			dld_set_public_prop;
static pd_checkf_t	do_check_zone, do_check_autopush, do_check_rate,
			dld_defmtu_check;

static dladm_status_t	dld_speed_get(struct prop_desc *, datalink_id_t,
			char **, uint_t *, uint_t);

typedef struct prop_desc {
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
	 * callback to set link property;
	 * set to NULL if this property is read-only
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
#define	PD_EMPTY_RESET	0x4	/* Use "" to reset the link property */
	/*
	 * indicate link classes this property applies to.
	 */
	datalink_class_t	pd_class;

	/*
	 * indicate link media type this property applies to.
	 */
	datalink_media_t	pd_dmedia;
} prop_desc_t;

#define	DLD_PROPBUF_SIZE(v)	sizeof (dld_ioc_prop_t) + (v) - 1


static dld_public_prop_t dld_prop[] = {
	{ DLD_PROP_DUPLEX,	sizeof (link_duplex_t),
	    "duplex",		"link duplex mode" },

	{DLD_PROP_SPEED,	sizeof (uint64_t),
	    "speed",		"link speed (bps)" },

	{ DLD_PROP_STATUS,	sizeof (link_state_t),
	    "state",		"link up/down" },

	{ DLD_PROP_AUTONEG,	sizeof (uint8_t),
	    "adv_autoneg_cap",	"Advertised auto-negotiation" },

	{ DLD_PROP_MTU,		sizeof (uint32_t),
	    "mtu",		"current link mtu" },

	{ DLD_PROP_FLOWCTRL,	sizeof (link_flowctrl_t),
	    "flowctrl",		"flowcontrol" },

	{ DLD_PROP_ADV_1000FDX_CAP, sizeof (uint8_t),
	    "adv_1000fdx_cap",	"Adv 1000 Mbps fdx" },

	{ DLD_PROP_EN_1000FDX_CAP, sizeof (uint8_t),
	    "en_1000fdx_cap",	"Enable 1000 Mbps fdx" },

	{ DLD_PROP_ADV_1000HDX_CAP, sizeof (uint8_t),
	    "adv_1000hdx_cap", "Adv 1000 Mbps hdx" },

	{ DLD_PROP_EN_1000HDX_CAP, sizeof (uint8_t),
	    "en_1000hdx_cap",	"Enable 1000 Mbps hdx" },

	{ DLD_PROP_ADV_100FDX_CAP, sizeof (uint8_t),
	    "adv_100fdx_cap",	"Adv 100 Mbps fdx" },

	{ DLD_PROP_EN_100FDX_CAP, sizeof (uint8_t),
	    "en_100fdx_cap",	"Enable 100 Mbps fdx" },

	{ DLD_PROP_ADV_100HDX_CAP, sizeof (uint8_t),
	    "adv_100hdx_cap",	"Adv 100 Mbps hdx" },

	{ DLD_PROP_EN_100HDX_CAP, sizeof (uint8_t),
	    "en_100hdx_cap",	"Enable 100 Mbps hdx" },

	{ DLD_PROP_ADV_10FDX_CAP, sizeof (uint8_t),
	    "adv_10fdx_cap",	"Adv 10 Mbps fdx" },

	{ DLD_PROP_EN_10FDX_CAP, sizeof (uint8_t),
	    "en_10fdx_cap",	"Enable 10 Mbps fdx" },

	{ DLD_PROP_ADV_10HDX_CAP, sizeof (uint8_t),
	    "adv_10hdx_cap",	"Adv 10 Mbps hdx" },

	{ DLD_PROP_EN_10HDX_CAP, sizeof (uint8_t),
	    "en_10hdx_cap",	"Enable 10 Mbps hdx" },

	{ DLD_PROP_PRIVATE, 0,
	    "driver-private",	"" }
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

#define	VALCNT(vals)    (sizeof ((vals)) / sizeof (val_desc_t))

static val_desc_t	dladm_wlan_radio_vals[] = {
	{ "on",		DLADM_WLAN_RADIO_ON	},
	{ "off",	DLADM_WLAN_RADIO_OFF	}
};

static val_desc_t	dladm_wlan_powermode_vals[] = {
	{ "off",	DLADM_WLAN_PM_OFF	},
	{ "fast",	DLADM_WLAN_PM_FAST	},
	{ "max",	DLADM_WLAN_PM_MAX	}
};

static prop_desc_t	prop_table[] = {

	{ "channel",	{ NULL, 0 },
	    NULL, 0, NULL, NULL,
	    do_get_channel_prop, NULL, 0,
	    DATALINK_CLASS_PHYS, DL_WIFI },

	{ "powermode",	{ "off", DLADM_WLAN_PM_OFF },
	    dladm_wlan_powermode_vals, VALCNT(dladm_wlan_powermode_vals),
	    do_set_powermode_prop, NULL,
	    do_get_powermode_prop, NULL, 0,
	    DATALINK_CLASS_PHYS, DL_WIFI },

	{ "radio",	{ "on", DLADM_WLAN_RADIO_ON },
	    dladm_wlan_radio_vals, VALCNT(dladm_wlan_radio_vals),
	    do_set_radio_prop, NULL,
	    do_get_radio_prop, NULL, 0,
	    DATALINK_CLASS_PHYS, DL_WIFI },

	{ "speed",	{ "", 0 }, NULL, 0,
	    do_set_rate_prop, do_get_rate_mod,
	    do_get_rate_prop, do_check_rate, 0,
	    DATALINK_CLASS_PHYS, DATALINK_ANY_MEDIATYPE },

	{ "autopush",	{ "", 0 }, NULL, 0,
	    do_set_autopush, NULL,
	    do_get_autopush, do_check_autopush, PD_CHECK_ALLOC|PD_EMPTY_RESET,
	    DATALINK_CLASS_ALL, DATALINK_ANY_MEDIATYPE },

	{ "zone",	{ "", 0 }, NULL, 0,
	    do_set_zone, NULL,
	    do_get_zone, do_check_zone, PD_TEMPONLY|PD_EMPTY_RESET,
	    DATALINK_CLASS_ALL, DATALINK_ANY_MEDIATYPE },

	{ "duplex", { "", 0 },
	    link_duplex_vals, VALCNT(link_duplex_vals),
	    NULL, NULL, dld_duplex_get, NULL,
	    0, DATALINK_CLASS_PHYS, DL_ETHER },

	{ "state", { "up", LINK_STATE_UP },
	    link_status_vals, VALCNT(link_status_vals),
	    NULL, NULL, dld_status_get, NULL,
	    0, DATALINK_CLASS_ALL, DATALINK_ANY_MEDIATYPE },

	{ "adv_autoneg_cap", { "1", 1 },
	    link_01_vals, VALCNT(link_01_vals),
	    dld_set_public_prop, NULL, dld_binary_get, NULL,
	    0, DATALINK_CLASS_PHYS, DL_ETHER },

	{ "mtu", { "", 0 }, NULL, 0,
	    dld_set_public_prop, NULL, dld_uint32_get,
	    dld_defmtu_check, 0, DATALINK_CLASS_ALL, DATALINK_ANY_MEDIATYPE },

	{ "flowctrl", { "", 0 },
	    link_flow_vals, VALCNT(link_flow_vals),
	    dld_set_public_prop, NULL, dld_flowctl_get, NULL,
	    0, DATALINK_CLASS_PHYS, DL_ETHER },

	{ "adv_1000fdx_cap", { "", 0 },
	    link_01_vals, VALCNT(link_01_vals),
	    NULL, NULL, dld_binary_get, NULL,
	    0, DATALINK_CLASS_PHYS, DL_ETHER },

	{ "en_1000fdx_cap", { "", 0 },
	    link_01_vals, VALCNT(link_01_vals),
	    dld_set_public_prop, NULL, dld_binary_get, NULL,
	    0, DATALINK_CLASS_PHYS, DL_ETHER },

	{ "adv_1000hdx_cap", { "", 0 },
	    link_01_vals, VALCNT(link_01_vals),
	    NULL, NULL, dld_binary_get, NULL,
	    0, DATALINK_CLASS_PHYS, DL_ETHER },

	{ "en_1000hdx_cap", { "", 0 },
	    link_01_vals, VALCNT(link_01_vals),
	    dld_set_public_prop, NULL, dld_binary_get, NULL,
	    0, DATALINK_CLASS_PHYS, DL_ETHER },

	{ "adv_100fdx_cap", { "", 0 },
	    link_01_vals, VALCNT(link_01_vals),
	    NULL, NULL, dld_binary_get, NULL,
	    0, DATALINK_CLASS_PHYS, DL_ETHER },

	{ "en_100fdx_cap", { "", 0 },
	    link_01_vals, VALCNT(link_01_vals),
	    dld_set_public_prop, NULL, dld_binary_get, NULL,
	    0, DATALINK_CLASS_PHYS, DL_ETHER },

	{ "adv_100hdx_cap", { "", 0 },
	    link_01_vals, VALCNT(link_01_vals),
	    NULL, NULL, dld_binary_get, NULL,
	    0, DATALINK_CLASS_PHYS, DL_ETHER },

	{ "en_100hdx_cap", { "", 0 },
	    link_01_vals, VALCNT(link_01_vals),
	    dld_set_public_prop, NULL, dld_binary_get, NULL,
	    0, DATALINK_CLASS_PHYS, DL_ETHER },

	{ "adv_10fdx_cap", { "", 0 },
	    link_01_vals, VALCNT(link_01_vals),
	    NULL, NULL, dld_binary_get, NULL,
	    0, DATALINK_CLASS_PHYS, DL_ETHER },

	{ "en_10fdx_cap", { "", 0 },
	    link_01_vals, VALCNT(link_01_vals),
	    dld_set_public_prop, NULL, dld_binary_get, NULL,
	    0, DATALINK_CLASS_PHYS, DL_ETHER },

	{ "adv_10hdx_cap", { "", 0 },
	    link_01_vals, VALCNT(link_01_vals),
	    NULL, NULL, dld_binary_get, NULL,
	    0, DATALINK_CLASS_PHYS, DL_ETHER },

	{ "en_10hdx_cap", { "", 0 },
	    link_01_vals, VALCNT(link_01_vals),
	    dld_set_public_prop, NULL, dld_binary_get, NULL,
	    0, DATALINK_CLASS_PHYS, DL_ETHER }

};

#define	DLADM_MAX_PROPS	(sizeof (prop_table) / sizeof (prop_desc_t))

static dladm_status_t	i_dladm_set_linkprop_db(datalink_id_t, const char *,
			    char **, uint_t);
static dladm_status_t	i_dladm_get_linkprop_db(datalink_id_t, const char *,
			    char **, uint_t *);
static dladm_status_t	i_dladm_set_single_prop(datalink_id_t, datalink_class_t,
			    uint32_t, prop_desc_t *, char **, uint_t, uint_t);
static dladm_status_t	i_dladm_set_linkprop(datalink_id_t, const char *,
			    char **, uint_t, uint_t);
static dladm_status_t	i_dladm_getset_defval(prop_desc_t *, datalink_id_t,
			    datalink_media_t, uint_t);
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

static dladm_status_t
do_check_prop(prop_desc_t *pdp, char **prop_val, uint_t val_cnt,
    val_desc_t *vdp)
{
	int		i, j;
	dladm_status_t	status = DLADM_STATUS_OK;

	for (j = 0; j < val_cnt; j++) {
		for (i = 0; i < pdp->pd_noptval; i++) {
			if (strcasecmp(*prop_val,
			    pdp->pd_optval[i].vd_name) == 0) {
				break;
			}
		}
		if (i == pdp->pd_noptval) {
			status = DLADM_STATUS_BADVAL;
			goto done;
		}
		(void) memcpy(vdp + j, &pdp->pd_optval[i], sizeof (val_desc_t));
	}

done:
	return (status);
}

static dladm_status_t
i_dladm_set_single_prop(datalink_id_t linkid, datalink_class_t class,
    uint32_t media, prop_desc_t *pdp, char **prop_val, uint_t val_cnt,
    uint_t flags)
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

	if (pdp->pd_flags & PD_CHECK_ALLOC)
		needfree = B_TRUE;
	else
		needfree = B_FALSE;
	if (prop_val != NULL) {
		vdp = malloc(sizeof (val_desc_t) * val_cnt);
		if (vdp == NULL)
			return (DLADM_STATUS_NOMEM);


		if (pdp->pd_check != NULL) {
			status = pdp->pd_check(pdp, linkid, prop_val, val_cnt,
			    vdp, media);
		} else if (pdp->pd_optval != NULL) {
			status = do_check_prop(pdp, prop_val, val_cnt, vdp);
		} else {
			status = DLADM_STATUS_BADARG;
		}

		if (status != DLADM_STATUS_OK)
			goto done;

		cnt = val_cnt;
	} else {
		if (pdp->pd_defval.vd_name == NULL)
			return (DLADM_STATUS_NOTSUP);

		if ((pdp->pd_flags & PD_EMPTY_RESET) != 0 ||
		    strlen(pdp->pd_defval.vd_name) > 0) {
			if ((vdp = malloc(sizeof (val_desc_t))) == NULL)
				return (DLADM_STATUS_NOMEM);
			(void) memcpy(vdp, &pdp->pd_defval,
			    sizeof (val_desc_t));
		} else {
			status = i_dladm_getset_defval(pdp, linkid,
			    media, flags);
			return (status);
		}
		cnt = 1;
	}
	status = pdp->pd_set(pdp, linkid, vdp, cnt, flags, media);
	if (needfree) {
		for (i = 0; i < cnt; i++)
			free((void *)((val_desc_t *)vdp + i)->vd_val);
	}
done:
	free(vdp);
	return (status);
}

static dladm_status_t
i_dladm_set_linkprop(datalink_id_t linkid, const char *prop_name,
    char **prop_val, uint_t val_cnt, uint_t flags)
{
	int			i;
	boolean_t		found = B_FALSE;
	datalink_class_t	class;
	uint32_t		media;
	dladm_status_t		status = DLADM_STATUS_OK;

	status = dladm_datalink_id2info(linkid, NULL, &class, &media, NULL, 0);
	if (status != DLADM_STATUS_OK)
		return (status);

	for (i = 0; i < DLADM_MAX_PROPS; i++) {
		prop_desc_t	*pdp = &prop_table[i];
		dladm_status_t	s;

		if (prop_name != NULL &&
		    (strcasecmp(prop_name, pdp->pd_name) != 0))
			continue;

		found = B_TRUE;
		s = i_dladm_set_single_prop(linkid, class, media, pdp, prop_val,
		    val_cnt, flags);

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
			status = dld_set_prop(linkid, prop_name, prop_val,
			    val_cnt, flags);
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
dladm_set_linkprop(datalink_id_t linkid, const char *prop_name, char **prop_val,
    uint_t val_cnt, uint_t flags)
{
	dladm_status_t	status = DLADM_STATUS_OK;

	if ((linkid == DATALINK_INVALID_LINKID) || (flags == 0) ||
	    (prop_val == NULL && val_cnt > 0) ||
	    (prop_val != NULL && val_cnt == 0) ||
	    (prop_name == NULL && prop_val != NULL)) {
		return (DLADM_STATUS_BADARG);
	}

	status = i_dladm_set_linkprop(linkid, prop_name, prop_val,
	    val_cnt, flags);
	if (status != DLADM_STATUS_OK)
		return (status);

	if (flags & DLADM_OPT_PERSIST) {
		status = i_dladm_set_linkprop_db(linkid, prop_name,
		    prop_val, val_cnt);
	}
	return (status);
}

/*
 * Walk link properties of the given specific link.
 */
dladm_status_t
dladm_walk_linkprop(datalink_id_t linkid, void *arg,
    int (*func)(datalink_id_t, const char *, void *))
{
	dladm_status_t		status;
	datalink_class_t	class;
	uint_t			media;
	int			i;

	if (linkid == DATALINK_INVALID_LINKID || func == NULL)
		return (DLADM_STATUS_BADARG);

	status = dladm_datalink_id2info(linkid, NULL, &class, &media, NULL, 0);
	if (status != DLADM_STATUS_OK)
		return (status);

	for (i = 0; i < DLADM_MAX_PROPS; i++) {
		if (!(prop_table[i].pd_class & class))
			continue;

		if (!DATALINK_MEDIA_ACCEPTED(prop_table[i].pd_dmedia, media))
			continue;

		if (func(linkid, prop_table[i].pd_name, arg) ==
		    DLADM_WALK_TERMINATE) {
			break;
		}
	}

	return (DLADM_STATUS_OK);
}

/*
 * Get linkprop of the given specific link.
 */
dladm_status_t
dladm_get_linkprop(datalink_id_t linkid, dladm_prop_type_t type,
    const char *prop_name, char **prop_val, uint_t *val_cntp)
{
	dladm_status_t		status = DLADM_STATUS_OK;
	datalink_class_t	class;
	uint_t			media;
	prop_desc_t		*pdp;
	uint_t			cnt, dld_flags = 0;
	int			i;

	if (type == DLADM_PROP_VAL_DEFAULT)
		dld_flags = DLD_DEFAULT;

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
			return (dld_get_prop(linkid, prop_name,
			    prop_val, val_cntp, type, dld_flags));
		} else {
			return (DLADM_STATUS_NOTFOUND);
		}
	}

	pdp = &prop_table[i];

	status = dladm_datalink_id2info(linkid, NULL, &class, &media, NULL, 0);
	if (status != DLADM_STATUS_OK)
		return (status);

	if (!(pdp->pd_class & class))
		return (DLADM_STATUS_BADARG);

	if (!DATALINK_MEDIA_ACCEPTED(pdp->pd_dmedia, media))
		return (DLADM_STATUS_BADARG);

	switch (type) {
	case DLADM_PROP_VAL_CURRENT:
		status = pdp->pd_get(pdp, linkid, prop_val, val_cntp, media,
		    dld_flags);
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
			status = pdp->pd_get(pdp, linkid, prop_val, val_cntp,
			    media, dld_flags);
		} else {
			(void) strcpy(*prop_val, pdp->pd_defval.vd_name);
		}
		*val_cntp = 1;
		break;

	case DLADM_PROP_VAL_MODIFIABLE:
		if (pdp->pd_getmod != NULL) {
			status = pdp->pd_getmod(pdp, linkid, prop_val,
			    val_cntp, media, dld_flags);
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
		status = i_dladm_get_linkprop_db(linkid, prop_name,
		    prop_val, val_cntp);
		break;
	default:
		status = DLADM_STATUS_BADARG;
		break;
	}

	return (status);
}

/*ARGSUSED*/
static int
i_dladm_init_one_prop(datalink_id_t linkid, const char *prop_name, void *arg)
{
	char	*buf, **propvals;
	uint_t	i, valcnt = DLADM_MAX_PROP_VALCNT;

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

	if (dladm_get_linkprop(linkid, DLADM_PROP_VAL_PERSISTENT, prop_name,
	    propvals, &valcnt) != DLADM_STATUS_OK) {
		goto done;
	}

	(void) dladm_set_linkprop(linkid, prop_name, propvals, valcnt,
	    DLADM_OPT_ACTIVE);

done:
	if (buf != NULL)
		free(buf);

	return (DLADM_WALK_CONTINUE);
}

/*ARGSUSED*/
static int
i_dladm_init_linkprop(datalink_id_t linkid, void *arg)
{
	(void) dladm_init_linkprop(linkid);
	return (DLADM_WALK_CONTINUE);
}

dladm_status_t
dladm_init_linkprop(datalink_id_t linkid)
{
	if (linkid == DATALINK_ALL_LINKID) {
		(void) dladm_walk_datalink_id(i_dladm_init_linkprop, NULL,
		    DATALINK_CLASS_ALL, DATALINK_ANY_MEDIATYPE,
		    DLADM_OPT_PERSIST);
	} else {
		(void) dladm_walk_linkprop(linkid, NULL, i_dladm_init_one_prop);
	}
	return (DLADM_STATUS_OK);
}

/* ARGSUSED */
static dladm_status_t
do_get_zone(struct prop_desc *pd, datalink_id_t linkid,
    char **prop_val, uint_t *val_cnt, datalink_media_t media, uint_t flags)
{
	char		zone_name[ZONENAME_MAX];
	zoneid_t	zid;
	dladm_status_t	status;

	if (flags != 0)
		return (DLADM_STATUS_NOTSUP);

	status = dladm_getzid(linkid, &zid);
	if (status != DLADM_STATUS_OK)
		return (status);

	*val_cnt = 1;
	if (zid != GLOBAL_ZONEID) {
		if (getzonenamebyid(zid, zone_name, sizeof (zone_name)) < 0)
			return (dladm_errno2status(errno));

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
i_dladm_update_deventry(zoneid_t zid, datalink_id_t linkid, boolean_t add)
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

	status = dladm_linkid2legacyname(linkid, name, MAXLINKNAMELEN);
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
do_set_zone(prop_desc_t *pd, datalink_id_t linkid, val_desc_t *vdp,
    uint_t val_cnt, uint_t flags, datalink_media_t media)
{
	dladm_status_t	status;
	zoneid_t	zid_old, zid_new;
	char		link[MAXLINKNAMELEN];

	if (val_cnt != 1)
		return (DLADM_STATUS_BADVALCNT);

	status = dladm_getzid(linkid, &zid_old);
	if (status != DLADM_STATUS_OK)
		return (status);

	/* Do nothing if setting to current value */
	zid_new = vdp->vd_val;
	if (zid_new == zid_old)
		return (DLADM_STATUS_OK);

	if ((status = dladm_datalink_id2info(linkid, NULL, NULL, NULL,
	    link, MAXLINKNAMELEN)) != DLADM_STATUS_OK) {
		return (status);
	}

	if (zid_new != GLOBAL_ZONEID) {
		/*
		 * If the new zoneid is the global zone, we could destroy
		 * the link (in the case of an implicitly-created VLAN) as a
		 * result of the dladm_setzid() operation. In that case,
		 * we defer the operation to the end of this function to avoid
		 * recreating the VLAN and getting a different linkid during
		 * the rollback if other operation fails.
		 *
		 * Otherwise, dladm_setzid() will hold a reference to the
		 * link and prevent a link renaming, so we need to do it
		 * before other operations.
		 */
		status = dladm_setzid(link, zid_new);
		if (status != DLADM_STATUS_OK)
			return (status);
	}

	if (zid_old != GLOBAL_ZONEID) {
		if (zone_remove_datalink(zid_old, link) != 0 &&
		    errno != ENXIO) {
			status = dladm_errno2status(errno);
			goto rollback1;
		}

		/*
		 * It is okay to fail to update the /dev entry (some
		 * vanity-named links do not have a /dev entry).
		 */
		(void) i_dladm_update_deventry(zid_old, linkid, B_FALSE);
	}

	if (zid_new != GLOBAL_ZONEID) {
		if (zone_add_datalink(zid_new, link) != 0) {
			status = dladm_errno2status(errno);
			goto rollback2;
		}

		(void) i_dladm_update_deventry(zid_new, linkid, B_TRUE);
	} else {
		status = dladm_setzid(link, zid_new);
		if (status != DLADM_STATUS_OK)
			goto rollback2;
	}

	return (DLADM_STATUS_OK);

rollback2:
	if (zid_old != GLOBAL_ZONEID)
		(void) i_dladm_update_deventry(zid_old, linkid, B_TRUE);
	if (zid_old != GLOBAL_ZONEID)
		(void) zone_add_datalink(zid_old, link);
rollback1:
	if (zid_new != GLOBAL_ZONEID)
		(void) dladm_setzid(link, zid_old);
	return (status);
}

/* ARGSUSED */
static dladm_status_t
do_check_zone(struct prop_desc *pd, datalink_id_t linkid, char **prop_val,
    uint_t val_cnt, val_desc_t *vdp, datalink_media_t media)
{
	zoneid_t	zid;

	if (val_cnt != 1)
		return (DLADM_STATUS_BADVALCNT);

	if ((zid = getzoneidbyname(*prop_val)) == -1)
		return (DLADM_STATUS_BADVAL);

	if (zid != GLOBAL_ZONEID) {
		ushort_t	flags;

		if (zone_getattr(zid, ZONE_ATTR_FLAGS, &flags,
		    sizeof (flags)) < 0) {
			return (dladm_errno2status(errno));
		}

		if (!(flags & ZF_NET_EXCL)) {
			return (DLADM_STATUS_BADVAL);
		}
	}

	vdp->vd_val = zid;
	return (DLADM_STATUS_OK);
}

/* ARGSUSED */
static dladm_status_t
do_get_autopush(struct prop_desc *pd, datalink_id_t linkid,
    char **prop_val, uint_t *val_cnt, datalink_media_t media, uint_t flags)
{
	dld_ioc_ap_t	dia;
	int		fd, i, len;

	if (flags & DLD_DEFAULT)
		return (DLADM_STATUS_NOTSUP);

	if ((fd = open(DLD_CONTROL_DEV, O_RDWR)) < 0)
		return (dladm_errno2status(errno));

	*val_cnt = 1;
	dia.dia_linkid = linkid;
	if (i_dladm_ioctl(fd, DLDIOC_GETAUTOPUSH, &dia, sizeof (dia)) < 0) {
		(*prop_val)[0] = '\0';
		goto done;
	}

	for (i = 0, len = 0; i < dia.dia_npush; i++) {
		if (i != 0) {
			(void) snprintf(*prop_val + len,
			    DLADM_PROP_VAL_MAX - len, "%c", AP_DELIMITER);
			len += 1;
		}
		(void) snprintf(*prop_val + len, DLADM_PROP_VAL_MAX - len,
		    "%s", dia.dia_aplist[i]);
		len += strlen(dia.dia_aplist[i]);
		if (dia.dia_anchor - 1 == i) {
			(void) snprintf(*prop_val + len,
			    DLADM_PROP_VAL_MAX - len, "%c%s", AP_DELIMITER,
			    AP_ANCHOR);
			len += (strlen(AP_ANCHOR) + 1);
		}
	}

done:
	(void) close(fd);
	return (DLADM_STATUS_OK);
}

/* ARGSUSED */
static dladm_status_t
do_set_autopush(prop_desc_t *pd, datalink_id_t linkid, val_desc_t *vdp,
    uint_t val_cnt, uint_t flags, datalink_media_t media)
{
	dld_ioc_ap_t		dia;
	struct dlautopush	*dlap = (struct dlautopush *)vdp->vd_val;
	dladm_status_t		status = DLADM_STATUS_OK;
	int			fd, i;
	int			ic_cmd;

	if (val_cnt != 1)
		return (DLADM_STATUS_BADVALCNT);

	if ((fd = open(DLD_CONTROL_DEV, O_RDWR)) < 0)
		return (dladm_errno2status(errno));

	dia.dia_linkid = linkid;
	if (dlap != NULL) {
		dia.dia_anchor = dlap->dap_anchor;
		dia.dia_npush = dlap->dap_npush;
		for (i = 0; i < dia.dia_npush; i++) {
			(void) strlcpy(dia.dia_aplist[i], dlap->dap_aplist[i],
			    FMNAMESZ+1);
		}
		ic_cmd = DLDIOC_SETAUTOPUSH;
	} else {
		ic_cmd = DLDIOC_CLRAUTOPUSH;
	}

	if (i_dladm_ioctl(fd, ic_cmd, &dia, sizeof (dia)) < 0)
		status = dladm_errno2status(errno);

	(void) close(fd);
	return (status);
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
	if (dlap->dap_npush > MAXAPUSH)
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
do_check_autopush(struct prop_desc *pd, datalink_id_t linkid, char **prop_val,
    uint_t val_cnt, val_desc_t *vdp, datalink_media_t media)
{
	char			*module;
	struct dlautopush	*dlap;
	dladm_status_t		status;
	char			val[DLADM_PROP_VAL_MAX];
	char			delimiters[4];

	if (val_cnt != 1)
		return (DLADM_STATUS_BADVALCNT);

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
	return (DLADM_STATUS_OK);
}

/* ARGSUSED */
static dladm_status_t
do_get_rate_common(struct prop_desc *pd, datalink_id_t linkid,
    char **prop_val, uint_t *val_cnt, uint_t id)
{
	wl_rates_t	*wrp;
	uint_t		i;
	wldp_t		*gbuf = NULL;
	dladm_status_t	status = DLADM_STATUS_OK;

	if ((gbuf = malloc(MAX_BUF_LEN)) == NULL) {
		status = DLADM_STATUS_NOMEM;
		goto done;
	}

	status = i_dladm_wlan_get_ioctl(linkid, gbuf, id);
	if (status != DLADM_STATUS_OK)
		goto done;

	wrp = (wl_rates_t *)gbuf->wldp_buf;
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

done:
	free(gbuf);
	return (status);
}

static dladm_status_t
do_get_rate_prop(struct prop_desc *pd, datalink_id_t linkid,
    char **prop_val, uint_t *val_cnt, datalink_media_t media, uint_t flags)
{
	if (media != DL_WIFI)
		return (dld_speed_get(pd, linkid, prop_val, val_cnt, flags));

	return (do_get_rate_common(pd, linkid, prop_val, val_cnt,
	    WL_DESIRED_RATES));
}

/* ARGSUSED */
static dladm_status_t
do_get_rate_mod(struct prop_desc *pd, datalink_id_t linkid,
    char **prop_val, uint_t *val_cnt, datalink_media_t media, uint_t flags)
{
	switch (media) {
	case DL_ETHER:
		/*
		 * Speed for ethernet links is unbounded. E.g., 802.11b
		 * links can have a speed of 5.5 Gbps.
		 */
		return (DLADM_STATUS_NOTSUP);

	case DL_WIFI:
		return (do_get_rate_common(pd, linkid, prop_val, val_cnt,
		    WL_SUPPORTED_RATES));
	default:
		return (DLADM_STATUS_BADARG);
	}
}

static dladm_status_t
do_set_rate(datalink_id_t linkid, dladm_wlan_rates_t *rates)
{
	int		i;
	uint_t		len;
	wldp_t		*gbuf;
	wl_rates_t	*wrp;
	dladm_status_t	status = DLADM_STATUS_OK;

	if ((gbuf = malloc(MAX_BUF_LEN)) == NULL)
		return (DLADM_STATUS_NOMEM);

	(void) memset(gbuf, 0, MAX_BUF_LEN);

	wrp = (wl_rates_t *)gbuf->wldp_buf;
	for (i = 0; i < rates->wr_cnt; i++)
		wrp->wl_rates_rates[i] = rates->wr_rates[i];
	wrp->wl_rates_num = rates->wr_cnt;

	len = offsetof(wl_rates_t, wl_rates_rates) +
	    (rates->wr_cnt * sizeof (char)) + WIFI_BUF_OFFSET;
	status = i_dladm_wlan_ioctl(linkid, gbuf, WL_DESIRED_RATES, len,
	    WLAN_SET_PARAM, len);

	free(gbuf);
	return (status);
}

/* ARGSUSED */
static dladm_status_t
do_set_rate_prop(prop_desc_t *pd, datalink_id_t linkid,
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

	status = do_set_rate(linkid, &rates);

done:
	return (status);
}

/* ARGSUSED */
static dladm_status_t
do_check_rate(struct prop_desc *pd, datalink_id_t linkid, char **prop_val,
    uint_t val_cnt, val_desc_t *vdp, datalink_media_t media)
{
	int		i;
	uint_t		modval_cnt = MAX_SUPPORT_RATES;
	char		*buf, **modval;
	dladm_status_t	status;

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

	status = do_get_rate_mod(NULL, linkid, modval, &modval_cnt, media, 0);
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
do_get_phyconf(datalink_id_t linkid, wldp_t *gbuf)
{
	return (i_dladm_wlan_get_ioctl(linkid, gbuf, WL_PHY_CONFIG));
}

/* ARGSUSED */
static dladm_status_t
do_get_channel_prop(struct prop_desc *pd, datalink_id_t linkid,
    char **prop_val, uint_t *val_cnt, datalink_media_t media, uint_t flags)
{
	uint32_t	channel;
	wldp_t		*gbuf;
	dladm_status_t	status = DLADM_STATUS_OK;

	if ((gbuf = malloc(MAX_BUF_LEN)) == NULL)
		return (DLADM_STATUS_NOMEM);

	if ((status = do_get_phyconf(linkid, gbuf)) != DLADM_STATUS_OK)
		goto done;

	if (!i_dladm_wlan_convert_chan((wl_phy_conf_t *)gbuf->wldp_buf,
	    &channel)) {
		status = DLADM_STATUS_NOTFOUND;
		goto done;
	}

	(void) snprintf(*prop_val, DLADM_STRSIZE, "%u", channel);
	*val_cnt = 1;

done:
	free(gbuf);
	return (status);
}

static dladm_status_t
do_get_powermode(datalink_id_t linkid, wldp_t *gbuf)
{
	return (i_dladm_wlan_get_ioctl(linkid, gbuf, WL_POWER_MODE));
}

/* ARGSUSED */
static dladm_status_t
do_get_powermode_prop(struct prop_desc *pd, datalink_id_t linkid,
    char **prop_val, uint_t *val_cnt, datalink_media_t media, uint_t flags)
{
	wl_ps_mode_t	*mode;
	const char	*s;
	wldp_t		*gbuf;
	dladm_status_t	status = DLADM_STATUS_OK;

	if ((gbuf = malloc(MAX_BUF_LEN)) == NULL)
		return (DLADM_STATUS_NOMEM);

	if ((status = do_get_powermode(linkid, gbuf)) != DLADM_STATUS_OK)
		goto done;

	mode = (wl_ps_mode_t *)(gbuf->wldp_buf);
	switch (mode->wl_ps_mode) {
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
		status = DLADM_STATUS_NOTFOUND;
		goto done;
	}
	(void) snprintf(*prop_val, DLADM_STRSIZE, "%s", s);
	*val_cnt = 1;

done:
	free(gbuf);
	return (status);
}

static dladm_status_t
do_set_powermode(datalink_id_t linkid, dladm_wlan_powermode_t *pm)
{
	wl_ps_mode_t    ps_mode;

	(void) memset(&ps_mode, 0xff, sizeof (ps_mode));

	switch (*pm) {
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
	return (i_dladm_wlan_set_ioctl(linkid, WL_POWER_MODE, &ps_mode,
	    sizeof (ps_mode)));
}

/* ARGSUSED */
static dladm_status_t
do_set_powermode_prop(prop_desc_t *pd, datalink_id_t linkid,
    val_desc_t *vdp, uint_t val_cnt, uint_t flags, datalink_media_t media)
{
	dladm_wlan_powermode_t powermode = (dladm_wlan_powermode_t)vdp->vd_val;
	dladm_status_t status;

	if (val_cnt != 1)
		return (DLADM_STATUS_BADVALCNT);

	status = do_set_powermode(linkid, &powermode);

	return (status);
}

static dladm_status_t
do_get_radio(datalink_id_t linkid, wldp_t *gbuf)
{
	return (i_dladm_wlan_get_ioctl(linkid, gbuf, WL_RADIO));
}

/* ARGSUSED */
static dladm_status_t
do_get_radio_prop(struct prop_desc *pd, datalink_id_t linkid,
    char **prop_val, uint_t *val_cnt, datalink_media_t media, uint_t flags)
{
	wl_radio_t	radio;
	const char	*s;
	wldp_t		*gbuf;
	dladm_status_t	status = DLADM_STATUS_OK;

	if ((gbuf = malloc(MAX_BUF_LEN)) == NULL)
		return (DLADM_STATUS_NOMEM);

	if ((status = do_get_radio(linkid, gbuf)) != DLADM_STATUS_OK)
		goto done;

	radio = *(wl_radio_t *)(gbuf->wldp_buf);
	switch (radio) {
	case B_TRUE:
		s = "on";
		break;
	case B_FALSE:
		s = "off";
		break;
	default:
		status = DLADM_STATUS_NOTFOUND;
		goto done;
	}
	(void) snprintf(*prop_val, DLADM_STRSIZE, "%s", s);
	*val_cnt = 1;

done:
	free(gbuf);
	return (status);
}

static dladm_status_t
do_set_radio(datalink_id_t linkid, dladm_wlan_radio_t *radio)
{
	wl_radio_t r;

	switch (*radio) {
	case DLADM_WLAN_RADIO_ON:
		r = B_TRUE;
		break;
	case DLADM_WLAN_RADIO_OFF:
		r = B_FALSE;
		break;
	default:
		return (DLADM_STATUS_NOTSUP);
	}
	return (i_dladm_wlan_set_ioctl(linkid, WL_RADIO, &r, sizeof (r)));
}

/* ARGSUSED */
static dladm_status_t
do_set_radio_prop(prop_desc_t *pd, datalink_id_t linkid,
    val_desc_t *vdp, uint_t val_cnt, uint_t fags, datalink_media_t media)
{
	dladm_wlan_radio_t radio = (dladm_wlan_radio_t)vdp->vd_val;
	dladm_status_t status;

	if (val_cnt != 1)
		return (DLADM_STATUS_BADVALCNT);

	status = do_set_radio(linkid, &radio);

	return (status);
}

static dladm_status_t
i_dladm_set_linkprop_db(datalink_id_t linkid, const char *prop_name,
    char **prop_val, uint_t val_cnt)
{
	char		buf[MAXLINELEN];
	int		i;
	dladm_conf_t	conf;
	dladm_status_t	status;

	status = dladm_read_conf(linkid, &conf);
	if (status != DLADM_STATUS_OK)
		return (status);

	/*
	 * reset case.
	 */
	if (val_cnt == 0) {
		status = dladm_unset_conf_field(conf, prop_name);
		if (status == DLADM_STATUS_OK)
			status = dladm_write_conf(conf);
		goto done;
	}

	buf[0] = '\0';
	for (i = 0; i < val_cnt; i++) {
		(void) strlcat(buf, prop_val[i], MAXLINELEN);
		if (i != val_cnt - 1)
			(void) strlcat(buf, ",", MAXLINELEN);
	}

	status = dladm_set_conf_field(conf, prop_name, DLADM_TYPE_STR, buf);
	if (status == DLADM_STATUS_OK)
		status = dladm_write_conf(conf);

done:
	dladm_destroy_conf(conf);
	return (status);
}

static dladm_status_t
i_dladm_get_linkprop_db(datalink_id_t linkid, const char *prop_name,
    char **prop_val, uint_t *val_cntp)
{
	char		buf[MAXLINELEN], *str;
	uint_t		cnt = 0;
	dladm_conf_t	conf;
	dladm_status_t	status;

	status = dladm_read_conf(linkid, &conf);
	if (status != DLADM_STATUS_OK)
		return (status);

	status = dladm_get_conf_field(conf, prop_name, buf, MAXLINELEN);
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
	dladm_destroy_conf(conf);
	return (status);
}

static dld_public_prop_t *
dladm_name2prop(const char *prop_name)
{
	dld_public_prop_t *p;

	for (p = dld_prop; p->pp_id != DLD_PROP_PRIVATE; p++) {
		if (strcmp(p->pp_name, prop_name) == 0)
			break;
	}
	return (p);
}


static dld_ioc_prop_t *
dld_buf_alloc(size_t valsize, datalink_id_t linkid, const char *prop_name,
    uint_t flags, dladm_status_t *status)
{
	int dsize;
	dld_ioc_prop_t *dip;
	dld_public_prop_t *p;

	*status = DLADM_STATUS_OK;
	p = dladm_name2prop(prop_name);
	if (p->pp_id != DLD_PROP_PRIVATE)
		valsize = p->pp_valsize;

	dsize = DLD_PROPBUF_SIZE(valsize);
	dip = malloc(dsize);
	if (dip == NULL) {
		*status = DLADM_STATUS_NOMEM;
		return (NULL);
	}
	bzero(dip, dsize);
	dip->pr_valsize = valsize;
	(void) strlcpy(dip->pr_name, prop_name, sizeof (dip->pr_name));
	dip->pr_version = DLD_PROP_VERSION;
	dip->pr_linkid = linkid;
	dip->pr_num = p->pp_id;
	dip->pr_flags = flags;
	return (dip);
}

/* ARGSUSED */
static dladm_status_t
dld_set_public_prop(prop_desc_t *pd, datalink_id_t linkid,
    val_desc_t *vdp, uint_t val_cnt, uint_t flags, datalink_media_t media)
{
	dld_ioc_prop_t	*dip;
	int		fd, dsize;
	dladm_status_t	status = DLADM_STATUS_OK;
	uint8_t		u8;
	uint16_t	u16;
	uint32_t	u32;
	void		*val;

	dip = dld_buf_alloc(0, linkid, pd->pd_name, 0, &status);
	if (dip == NULL)
		return (status);

	if (pd->pd_flags & PD_CHECK_ALLOC)
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

	(void) memcpy(dip->pr_val, val, dip->pr_valsize);
	dsize = DLD_PROPBUF_SIZE(dip->pr_valsize);
	if ((fd = open(DLD_CONTROL_DEV, O_RDWR)) < 0) {
		status = dladm_errno2status(errno);
		goto done;
	}
	if (i_dladm_ioctl(fd, DLDIOCSETPROP, dip, dsize) < 0)
		status = dladm_errno2status(errno);

	(void) close(fd);
done:
	free(dip);
	return (status);
}

static dld_ioc_prop_t *
dld_get_public_prop(datalink_id_t linkid, char *prop_name, uint_t flags,
    dladm_status_t *status)
{
	int fd, dsize;
	dld_ioc_prop_t *dip = NULL;

	*status = DLADM_STATUS_OK;

	dip = dld_buf_alloc(0, linkid, prop_name, flags, status);
	if (dip == NULL)
		return (NULL);

	dsize = DLD_PROPBUF_SIZE(dip->pr_valsize);

	if ((fd = open(DLD_CONTROL_DEV, O_RDWR)) < 0) {
		*status = dladm_errno2status(errno);
		goto done;
	}
	if (i_dladm_ioctl(fd, DLDIOCGETPROP, dip, dsize) < 0) {
		*status = dladm_errno2status(errno);
	}

	(void) close(fd);
done:
	if (*status != DLADM_STATUS_OK) {
		free(dip);
		return (NULL);
	}
	return (dip);
}

/* ARGSUSED */
static dladm_status_t
dld_defmtu_check(struct prop_desc *pd, datalink_id_t linkid, char **prop_val,
    uint_t val_cnt, val_desc_t *v, datalink_media_t media)
{
	if (val_cnt != 1)
		return (DLADM_STATUS_BADVAL);
	v->vd_val = atoi(prop_val[0]);
	return (DLADM_STATUS_OK);
}

/* ARGSUSED */
static dladm_status_t
dld_duplex_get(struct prop_desc *pd, datalink_id_t linkid,
    char **prop_val, uint_t *val_cnt, datalink_media_t media, uint_t flags)
{
	link_duplex_t   link_duplex;
	dladm_status_t  status;

	if (flags & DLD_DEFAULT)
		return (DLADM_STATUS_NOTSUP);

	if ((status = dladm_get_single_mac_stat(linkid, "link_duplex",
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
dld_speed_get(struct prop_desc *pd, datalink_id_t linkid,
    char **prop_val, uint_t *val_cnt, uint_t flags)
{
	uint64_t	ifspeed = 0;
	dladm_status_t status;

	if (flags & DLD_DEFAULT)
		return (DLADM_STATUS_NOTSUP);

	if ((status = dladm_get_single_mac_stat(linkid, "ifspeed",
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
	return (DLADM_STATUS_OK);
}

/* ARGSUSED */
static dladm_status_t
dld_status_get(struct prop_desc *pd, datalink_id_t linkid,
    char **prop_val, uint_t *val_cnt, datalink_media_t media, uint_t flags)
{
	link_state_t	link_state;
	dladm_status_t	status;
	uchar_t 	*cp;
	dld_ioc_prop_t  *dip;

	if (flags & DLD_DEFAULT)
		return (DLADM_STATUS_NOTSUP);
	dip = dld_get_public_prop(linkid, pd->pd_name, flags, &status);
	if (status != DLADM_STATUS_OK)
		return (status);
	cp = (uchar_t *)dip->pr_val;
	(void) memcpy(&link_state, cp, sizeof (link_state));

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
	free(dip);
	return (DLADM_STATUS_OK);
}

/* ARGSUSED */
static dladm_status_t
dld_binary_get(struct prop_desc *pd, datalink_id_t linkid,
    char **prop_val, uint_t *val_cnt, datalink_media_t media, uint_t flags)
{
	dld_ioc_prop_t *dip;
	dladm_status_t status;

	dip = dld_get_public_prop(linkid, pd->pd_name, flags, &status);
	if (dip == NULL)
		return (status);
	(void) snprintf(*prop_val, DLADM_PROP_VAL_MAX, "%x", dip->pr_val[0]);
	free(dip);
	*val_cnt = 1;
	return (DLADM_STATUS_OK);
}

/* ARGSUSED */
static dladm_status_t
dld_uint32_get(struct prop_desc *pd, datalink_id_t linkid,
    char **prop_val, uint_t *val_cnt, datalink_media_t media, uint_t flags)
{
	dld_ioc_prop_t *dip;
	uint32_t v  = 0;
	uchar_t *cp;
	dladm_status_t status;

	dip = dld_get_public_prop(linkid, pd->pd_name, flags, &status);
	if (dip == NULL)
		return (status);
	cp = (uchar_t *)dip->pr_val;
	(void) memcpy(&v, cp, sizeof (v));
	(void) snprintf(*prop_val, DLADM_PROP_VAL_MAX, "%ld", v);
	free(dip);
	*val_cnt = 1;
	return (DLADM_STATUS_OK);
}

/* ARGSUSED */
static dladm_status_t
dld_flowctl_get(struct prop_desc *pd, datalink_id_t linkid,
    char **prop_val, uint_t *val_cnt, datalink_media_t media, uint_t flags)
{
	dld_ioc_prop_t *dip;
	link_flowctrl_t v;
	dladm_status_t status;
	uchar_t *cp;

	dip = dld_get_public_prop(linkid, pd->pd_name, flags, &status);
	if (dip == NULL)
		return (status);
	cp = (uchar_t *)dip->pr_val;
	(void) memcpy(&v, cp, sizeof (v));
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
	free(dip);
	*val_cnt = 1;
	return (DLADM_STATUS_OK);
}


/* ARGSUSED */
static dladm_status_t
dld_set_prop(datalink_id_t linkid, const char *prop_name,
    char **prop_val, uint_t val_cnt, uint_t flags)
{
	int		fd, i, slen;
	int 		bufsize = 0, dsize;
	dld_ioc_prop_t *dip = NULL;
	uchar_t 	*dp;
	dld_public_prop_t *p;
	dladm_status_t	status = DLADM_STATUS_OK;

	if ((prop_name == NULL && prop_val != NULL) ||
	    (prop_val != NULL && val_cnt == 0))
		return (DLADM_STATUS_BADARG);
	p = dladm_name2prop(prop_name);
	if (p->pp_id != DLD_PROP_PRIVATE)
		return (DLADM_STATUS_BADARG);

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
		bufsize += 1024;
	}

	dip = dld_buf_alloc(bufsize + 1, linkid, prop_name,
	    (prop_val != NULL ? 0 : DLD_DEFAULT), &status);
	if (dip == NULL)
		return (status);

	dp = (uchar_t *)dip->pr_val;
	dsize = sizeof (dld_ioc_prop_t) + bufsize;
	slen = 0;
	if ((fd = open(DLD_CONTROL_DEV, O_RDWR)) < 0) {
		status = dladm_errno2status(errno);
		goto done;
	}
	if (prop_val == NULL) {
		if (i_dladm_ioctl(fd, DLDIOCGETPROP, dip, dsize) < 0) {
			status = dladm_errno2status(errno);
			goto done;
		}
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
	if (i_dladm_ioctl(fd, DLDIOCSETPROP, dip, dsize) < 0) {
		status = dladm_errno2status(errno);
	}

done:
	if (fd > 0)
		(void) close(fd);
	free(dip);
	return (status);
}

static dladm_status_t
dld_get_prop(datalink_id_t linkid, const char *prop_name,
    char **prop_val, uint_t *val_cnt, dladm_prop_type_t type, uint_t dld_flags)
{
	int		fd;
	dladm_status_t  status = DLADM_STATUS_OK;
	uint_t 		dsize;
	dld_ioc_prop_t *dip = NULL;
	dld_public_prop_t *p;
	char tmp = '\0';

	if ((prop_name == NULL && prop_val != NULL) ||
	    (prop_val != NULL && val_cnt == 0))
		return (DLADM_STATUS_BADARG);

	p = dladm_name2prop(prop_name);
	if (p->pp_id != DLD_PROP_PRIVATE)
		return (DLADM_STATUS_BADARG);

	if (type == DLADM_PROP_VAL_MODIFIABLE) {
		*prop_val = &tmp;
		*val_cnt = 1;
		return (DLADM_STATUS_OK);
	}

	/*
	 * private properties: all parsing is done in the kernel.
	 */
	dip = dld_buf_alloc(1024, linkid, prop_name, dld_flags, &status);
	if (dip == NULL)
		return (status);
	dsize = DLD_PROPBUF_SIZE(dip->pr_valsize);

	if ((fd = open(DLD_CONTROL_DEV, O_RDWR)) < 0) {
		free(dip);
		return (DLADM_STATUS_BADARG);
	}

	if ((status = i_dladm_ioctl(fd, DLDIOCGETPROP, dip, dsize)) < 0) {
		status = dladm_errno2status(errno);
	} else {
		(void) strncpy(*prop_val, dip->pr_val, DLADM_PROP_VAL_MAX);
		*val_cnt = 1;
	}

	(void) close(fd);
	free(dip);
	return (status);
}


static dladm_status_t
i_dladm_getset_defval(prop_desc_t *pdp, datalink_id_t linkid,
    datalink_media_t media, uint_t flags)
{
	dladm_status_t status;
	char **prop_vals = NULL, *buf;
	size_t bufsize;
	uint_t cnt;
	int i;

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
	 * PD_EMPTY_RESET is used for properties like zone where the
	 * "" itself is used to reset the property. So libdladm can
	 * copy pdp->pd_defval over to the val_desc_t passed down on
	 * the setprop using the global values in the table. For other
	 * cases (PD_EMPTY_RESET is not set, vd_name is ""), doing
	 * reset-linkprop will cause libdladm to do a getprop to find
	 * the default value and then do a setprop to reset the value
	 * to default.
	 */
	status = pdp->pd_get(pdp, linkid, prop_vals, &cnt, media, DLD_DEFAULT);
	if (status == DLADM_STATUS_OK) {
		status = i_dladm_set_single_prop(linkid, pdp->pd_class,
		    media, pdp, prop_vals, cnt, flags);
	}
	free(buf);
	return (status);
}
