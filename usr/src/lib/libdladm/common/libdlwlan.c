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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <libintl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stddef.h>
#include <string.h>
#include <stropts.h>
#include <libdevinfo.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <libdlpi.h>
#include <libdllink.h>
#include <libscf.h>
#include <libdlwlan.h>
#include <libdladm_impl.h>
#include <libdlwlan_impl.h>
#include <net/wpa.h>

static dladm_status_t	wpa_instance_create(dladm_handle_t, datalink_id_t,
			    void *);
static dladm_status_t	wpa_instance_delete(dladm_handle_t, datalink_id_t);

static dladm_status_t	do_get_bsstype(dladm_handle_t, datalink_id_t, void *,
			    int);
static dladm_status_t	do_get_essid(dladm_handle_t, datalink_id_t, void *,
			    int);
static dladm_status_t	do_get_bssid(dladm_handle_t, datalink_id_t, void *,
			    int);
static dladm_status_t	do_get_signal(dladm_handle_t, datalink_id_t, void *,
			    int);
static dladm_status_t	do_get_encryption(dladm_handle_t, datalink_id_t, void *,
			    int);
static dladm_status_t	do_get_authmode(dladm_handle_t, datalink_id_t, void *,
			    int);
static dladm_status_t	do_get_linkstatus(dladm_handle_t, datalink_id_t, void *,
			    int);
static dladm_status_t	do_get_esslist(dladm_handle_t, datalink_id_t, void  *,
			    int);
static dladm_status_t	do_get_rate(dladm_handle_t, datalink_id_t, void *, int);
static dladm_status_t	do_get_mode(dladm_handle_t, datalink_id_t, void *, int);
static dladm_status_t	do_get_capability(dladm_handle_t, datalink_id_t, void *,
			    int);
static dladm_status_t	do_get_wpamode(dladm_handle_t, datalink_id_t, void *,
			    int);

static dladm_status_t	do_set_bsstype(dladm_handle_t, datalink_id_t,
			    dladm_wlan_bsstype_t *);
static dladm_status_t	do_set_authmode(dladm_handle_t, datalink_id_t,
			    dladm_wlan_auth_t *);
static dladm_status_t	do_set_encryption(dladm_handle_t, datalink_id_t,
			    dladm_wlan_secmode_t *);
static dladm_status_t	do_set_essid(dladm_handle_t, datalink_id_t,
			    dladm_wlan_essid_t *);
static dladm_status_t	do_set_createibss(dladm_handle_t, datalink_id_t,
			    boolean_t *);
static dladm_status_t	do_set_key(dladm_handle_t, datalink_id_t,
			    dladm_wlan_key_t *, uint_t);
static dladm_status_t	do_set_channel(dladm_handle_t, datalink_id_t,
			    dladm_wlan_channel_t *);

static dladm_status_t	do_scan(dladm_handle_t, datalink_id_t, void *, int);
static dladm_status_t	do_connect(dladm_handle_t, datalink_id_t, void *, int,
			    dladm_wlan_attr_t *, boolean_t, void *, uint_t,
			    int);
static dladm_status_t	do_disconnect(dladm_handle_t, datalink_id_t, void *,
			    int);
static boolean_t	find_val_by_name(const char *, val_desc_t *,
			    uint_t, uint_t *);
static boolean_t	find_name_by_val(uint_t, val_desc_t *, uint_t, char **);
static void		generate_essid(dladm_wlan_essid_t *);

static dladm_status_t	dladm_wlan_wlresult2status(wldp_t *);
static dladm_status_t	dladm_wlan_validate(dladm_handle_t, datalink_id_t);

static val_desc_t	linkstatus_vals[] = {
	{ "disconnected", DLADM_WLAN_LINK_DISCONNECTED	},
	{ "connected",    DLADM_WLAN_LINK_CONNECTED	}
};

static val_desc_t	secmode_vals[] = {
	{ "none",	DLADM_WLAN_SECMODE_NONE		},
	{ "wep",	DLADM_WLAN_SECMODE_WEP		},
	{ "wpa",	DLADM_WLAN_SECMODE_WPA		}
};

static val_desc_t	strength_vals[] = {
	{ "very weak",	DLADM_WLAN_STRENGTH_VERY_WEAK	},
	{ "weak",	DLADM_WLAN_STRENGTH_WEAK	},
	{ "good",	DLADM_WLAN_STRENGTH_GOOD	},
	{ "very good",	DLADM_WLAN_STRENGTH_VERY_GOOD	},
	{ "excellent",	DLADM_WLAN_STRENGTH_EXCELLENT	}
};

static val_desc_t	mode_vals[] = {
	{ "a",		DLADM_WLAN_MODE_80211A		},
	{ "b",		DLADM_WLAN_MODE_80211B		},
	{ "g",		DLADM_WLAN_MODE_80211G		},
	{ "n",		DLADM_WLAN_MODE_80211GN		},
	{ "n",		DLADM_WLAN_MODE_80211AN		}
};

static val_desc_t	auth_vals[] = {
	{ "open",	DLADM_WLAN_AUTH_OPEN		},
	{ "shared",	DLADM_WLAN_AUTH_SHARED		}
};

static val_desc_t	bsstype_vals[] = {
	{ "bss",	DLADM_WLAN_BSSTYPE_BSS		},
	{ "ibss",	DLADM_WLAN_BSSTYPE_IBSS		},
	{ "any",	DLADM_WLAN_BSSTYPE_ANY		}
};

#define	WLDP_BUFSIZE (MAX_BUF_LEN - WIFI_BUF_OFFSET)

static dladm_status_t
dladm_wlan_wlresult2status(wldp_t *gbuf)
{
	switch (gbuf->wldp_result) {
	case WL_SUCCESS:
		return (DLADM_STATUS_OK);

	case WL_NOTSUPPORTED:
	case WL_LACK_FEATURE:
		return (DLADM_STATUS_NOTSUP);

	case WL_READONLY:
		return (DLADM_STATUS_PROPRDONLY);

	default:
		break;
	}

	return (DLADM_STATUS_FAILED);
}

static dladm_wlan_mode_t
do_convert_mode(wl_phy_conf_t *phyp)
{
	wl_erp_t *wlep = &phyp->wl_phy_erp_conf;
	wl_ofdm_t *wlop = &phyp->wl_phy_ofdm_conf;

	switch (phyp->wl_phy_fhss_conf.wl_fhss_subtype) {
	case WL_ERP:
		return (wlep->wl_erp_ht_enabled ?
		    DLADM_WLAN_MODE_80211GN : DLADM_WLAN_MODE_80211G);
	case WL_OFDM:
		return (wlop->wl_ofdm_ht_enabled ?
		    DLADM_WLAN_MODE_80211AN : DLADM_WLAN_MODE_80211A);
	case WL_DSSS:
	case WL_FHSS:
		return (DLADM_WLAN_MODE_80211B);
	default:
		break;
	}

	return (DLADM_WLAN_MODE_NONE);
}

boolean_t
i_dladm_wlan_convert_chan(wl_phy_conf_t *phyp, uint32_t *channelp)
{
	wl_fhss_t *wlfp = &phyp->wl_phy_fhss_conf;
	wl_ofdm_t *wlop = &phyp->wl_phy_ofdm_conf;

	switch (wlfp->wl_fhss_subtype) {
	case WL_FHSS:
	case WL_DSSS:
	case WL_IRBASE:
	case WL_HRDS:
	case WL_ERP:
		*channelp = wlfp->wl_fhss_channel;
		break;
	case WL_OFDM:
		*channelp = DLADM_WLAN_OFDM2CHAN(wlop->wl_ofdm_frequency);
		break;
	default:
		return (B_FALSE);
	}
	return (B_TRUE);
}

#define	IEEE80211_RATE	0x7f
static void
fill_wlan_attr(wl_ess_conf_t *wlp, dladm_wlan_attr_t *attrp)
{
	int		i;

	(void) memset(attrp, 0, sizeof (*attrp));

	(void) snprintf(attrp->wa_essid.we_bytes, DLADM_WLAN_MAX_ESSID_LEN,
	    "%s", wlp->wl_ess_conf_essid.wl_essid_essid);
	attrp->wa_valid |= DLADM_WLAN_ATTR_ESSID;

	(void) memcpy(attrp->wa_bssid.wb_bytes, wlp->wl_ess_conf_bssid,
	    DLADM_WLAN_BSSID_LEN);
	attrp->wa_valid |= DLADM_WLAN_ATTR_BSSID;

	attrp->wa_secmode = (wlp->wl_ess_conf_wepenabled ==
	    WL_ENC_WEP ? DLADM_WLAN_SECMODE_WEP : DLADM_WLAN_SECMODE_NONE);
	if (wlp->wl_ess_conf_reserved[0] > 0)
		attrp->wa_secmode = DLADM_WLAN_SECMODE_WPA;
	attrp->wa_valid |= DLADM_WLAN_ATTR_SECMODE;

	attrp->wa_bsstype = (wlp->wl_ess_conf_bsstype == WL_BSS_BSS ?
	    DLADM_WLAN_BSSTYPE_BSS : DLADM_WLAN_BSSTYPE_IBSS);
	attrp->wa_valid |= DLADM_WLAN_ATTR_BSSTYPE;

	attrp->wa_auth = (wlp->wl_ess_conf_authmode == 0 ?
	    DLADM_WLAN_AUTH_OPEN : DLADM_WLAN_AUTH_SHARED);
	attrp->wa_valid |= DLADM_WLAN_ATTR_AUTH;

	attrp->wa_strength = DLADM_WLAN_SIGNAL2STRENGTH(wlp->wl_ess_conf_sl);
	attrp->wa_valid |= DLADM_WLAN_ATTR_STRENGTH;

	attrp->wa_mode = do_convert_mode((wl_phy_conf_t *)&wlp->wl_phy_conf);
	attrp->wa_valid |= DLADM_WLAN_ATTR_MODE;

	for (i = 0; i < MAX_SCAN_SUPPORT_RATES; i++) {
		wlp->wl_supported_rates[i] &= IEEE80211_RATE;
		if ((uint_t)wlp->wl_supported_rates[i] > attrp->wa_speed)
			attrp->wa_speed = wlp->wl_supported_rates[i];
	}
	if (attrp->wa_speed > 0)
		attrp->wa_valid |= DLADM_WLAN_ATTR_SPEED;

	if (i_dladm_wlan_convert_chan((wl_phy_conf_t *)&wlp->wl_phy_conf,
	    &attrp->wa_channel))
		attrp->wa_valid |= DLADM_WLAN_ATTR_CHANNEL;
}

dladm_status_t
dladm_wlan_scan(dladm_handle_t handle, datalink_id_t linkid, void *arg,
    boolean_t (*func)(void *, dladm_wlan_attr_t *))
{
	uint_t			i;
	uint32_t		count;
	wl_ess_conf_t		*wlp;
	wl_ess_list_t		*wls = NULL;
	char			buf[WLDP_BUFSIZE];
	wl_linkstatus_t		wl_status;
	dladm_wlan_attr_t	wlattr;
	dladm_status_t		status;

	if ((status = dladm_wlan_validate(handle, linkid)) != DLADM_STATUS_OK)
		goto done;

	status = do_get_linkstatus(handle, linkid, &wl_status,
	    sizeof (wl_status));
	if (status != DLADM_STATUS_OK)
		goto done;

	if ((status = do_scan(handle, linkid, buf, sizeof (buf))) !=
	    DLADM_STATUS_OK)
		goto done;

	if (func == NULL) {
		status = DLADM_STATUS_OK;
		goto done;
	}

	wls = malloc(WLDP_BUFSIZE);
	if (wls == NULL) {
		status = DLADM_STATUS_NOMEM;
		goto done;
	}

	if ((status = do_get_esslist(handle, linkid, wls, WLDP_BUFSIZE))
	    != DLADM_STATUS_OK)
		goto done;

	wlp = wls->wl_ess_list_ess;
	count = wls->wl_ess_list_num;

	for (i = 0; i < count; i++, wlp++) {
		fill_wlan_attr(wlp, &wlattr);
		if (!func(arg, &wlattr))
			break;
	}

	if (wl_status != WL_CONNECTED) {
		status = do_get_linkstatus(handle, linkid, &wl_status,
		    sizeof (&wl_status));
		if (status != DLADM_STATUS_OK)
			goto done;
		if (wl_status == WL_CONNECTED)
			(void) do_disconnect(handle, linkid, buf, sizeof (buf));
	}

	status = DLADM_STATUS_OK;
done:
	free(wls);
	return (status);
}

/*
 * Structures used in building the list of eligible WLANs to connect to.
 * Specifically, `connect_state' has the WLAN attributes that must be matched
 * (in `cs_attr') and a growing list of WLANs that matched those attributes
 * chained through `cs_list'.  Each element in the list is of type `attr_node'
 * and has the matching WLAN's attributes and a pointer to the next element.
 * For convenience, `cs_count' tracks the number of elements in the list.
 */
typedef struct attr_node {
	dladm_wlan_attr_t	an_attr;
	struct attr_node	*an_next;
} attr_node_t;

typedef struct connect_state {
	dladm_wlan_attr_t	*cs_attr;
	uint_t			cs_count;
	attr_node_t		*cs_list;
} connect_state_t;

/*
 * Compare two sets of WLAN attributes.  For now, we only consider strength
 * and speed (in that order), which matches the documented default policy for
 * dladm_wlan_connect().
 */
static int
attr_compare(const void *p1, const void *p2)
{
	dladm_wlan_attr_t *attrp1, *attrp2;

	attrp1 = (*(dladm_wlan_attr_t **)p1);
	attrp2 = (*(dladm_wlan_attr_t **)p2);

	if (attrp1->wa_strength < attrp2->wa_strength)
		return (1);

	if (attrp1->wa_strength > attrp2->wa_strength)
		return (-1);

	return (attrp2->wa_speed - attrp1->wa_speed);
}

/*
 * Callback function used by dladm_wlan_connect() to filter out unwanted
 * WLANs when scanning for available WLANs.  Always returns B_TRUE to
 * continue the scan.
 */
static boolean_t
connect_cb(void *arg, dladm_wlan_attr_t *attrp)
{
	attr_node_t		*nodep;
	dladm_wlan_attr_t	*fattrp;
	connect_state_t		*statep = (connect_state_t *)arg;

	fattrp = statep->cs_attr;
	if (fattrp == NULL)
		goto append;

	if ((fattrp->wa_valid & attrp->wa_valid) != fattrp->wa_valid)
		return (B_TRUE);

	if ((fattrp->wa_valid & DLADM_WLAN_ATTR_ESSID) != 0 &&
	    strncmp(fattrp->wa_essid.we_bytes, attrp->wa_essid.we_bytes,
	    DLADM_WLAN_MAX_ESSID_LEN) != 0)
		return (B_TRUE);

	if ((fattrp->wa_valid & DLADM_WLAN_ATTR_SECMODE) != 0 &&
	    fattrp->wa_secmode != attrp->wa_secmode)
		return (B_TRUE);

	if ((fattrp->wa_valid & DLADM_WLAN_ATTR_MODE) != 0 &&
	    fattrp->wa_mode != attrp->wa_mode)
		return (B_TRUE);

	if ((fattrp->wa_valid & DLADM_WLAN_ATTR_STRENGTH) != 0 &&
	    fattrp->wa_strength != attrp->wa_strength)
		return (B_TRUE);

	if ((fattrp->wa_valid & DLADM_WLAN_ATTR_SPEED) != 0 &&
	    fattrp->wa_speed != attrp->wa_speed)
		return (B_TRUE);

	if ((fattrp->wa_valid & DLADM_WLAN_ATTR_AUTH) != 0) {
		attrp->wa_auth = fattrp->wa_auth;
		attrp->wa_valid |= DLADM_WLAN_ATTR_AUTH;
	}

	if ((fattrp->wa_valid & DLADM_WLAN_ATTR_BSSTYPE) != 0 &&
	    fattrp->wa_bsstype != attrp->wa_bsstype)
		return (B_TRUE);

	if ((fattrp->wa_valid & DLADM_WLAN_ATTR_BSSID) != 0 &&
	    memcmp(fattrp->wa_bssid.wb_bytes, attrp->wa_bssid.wb_bytes,
	    DLADM_WLAN_BSSID_LEN) != 0)
		return (B_TRUE);
append:
	nodep = malloc(sizeof (attr_node_t));
	if (nodep == NULL)
		return (B_TRUE);

	(void) memcpy(&nodep->an_attr, attrp, sizeof (dladm_wlan_attr_t));
	nodep->an_next = statep->cs_list;
	statep->cs_list = nodep;
	statep->cs_count++;

	return (B_TRUE);
}

#define	IEEE80211_C_WPA		0x01800000

static dladm_status_t
do_connect(dladm_handle_t handle, datalink_id_t linkid, void *buf, int bufsize,
    dladm_wlan_attr_t *attrp, boolean_t create_ibss, void *keys,
    uint_t key_count, int timeout)
{
	dladm_wlan_secmode_t	secmode;
	dladm_wlan_auth_t	authmode;
	dladm_wlan_bsstype_t	bsstype;
	dladm_wlan_essid_t	essid;
	boolean_t		essid_valid = B_FALSE;
	dladm_status_t		status;
	dladm_wlan_channel_t	channel;
	hrtime_t		start;
	wl_capability_t		*caps;
	wl_linkstatus_t		wl_status;

	if ((attrp->wa_valid & DLADM_WLAN_ATTR_CHANNEL) != 0) {
		channel = attrp->wa_channel;
		status = do_set_channel(handle, linkid, &channel);
		if (status != DLADM_STATUS_OK)
			goto fail;
	}

	secmode = ((attrp->wa_valid & DLADM_WLAN_ATTR_SECMODE) != 0) ?
	    attrp->wa_secmode : DLADM_WLAN_SECMODE_NONE;

	if ((status = do_set_encryption(handle, linkid, &secmode)) !=
	    DLADM_STATUS_OK)
		goto fail;

	authmode = ((attrp->wa_valid & DLADM_WLAN_ATTR_AUTH) != 0) ?
	    attrp->wa_auth : DLADM_WLAN_AUTH_OPEN;

	if ((status = do_set_authmode(handle, linkid, &authmode)) !=
	    DLADM_STATUS_OK)
		goto fail;

	bsstype = ((attrp->wa_valid & DLADM_WLAN_ATTR_BSSTYPE) != 0) ?
	    attrp->wa_bsstype : DLADM_WLAN_BSSTYPE_BSS;

	if ((status = do_set_bsstype(handle, linkid, &bsstype)) !=
	    DLADM_STATUS_OK)
		goto fail;

	if (secmode == DLADM_WLAN_SECMODE_WEP) {
		if (keys == NULL || key_count == 0 ||
		    key_count > MAX_NWEPKEYS) {
			status = DLADM_STATUS_BADARG;
			goto fail;
		}
		status = do_set_key(handle, linkid, keys, key_count);
		if (status != DLADM_STATUS_OK)
			goto fail;
	} else if (secmode == DLADM_WLAN_SECMODE_WPA) {
		if (keys == NULL || key_count == 0 ||
		    key_count > MAX_NWEPKEYS) {
			status = DLADM_STATUS_BADARG;
			goto fail;
		}
		status = do_get_capability(handle, linkid, buf, bufsize);
		if (status != DLADM_STATUS_OK)
			goto fail;
		caps = (wl_capability_t *)buf;
		if ((caps->caps & IEEE80211_C_WPA) == 0)
			return (DLADM_STATUS_NOTSUP);
	}

	if (create_ibss) {
		status = do_set_channel(handle, linkid, &channel);
		if (status != DLADM_STATUS_OK)
			goto fail;

		status = do_set_createibss(handle, linkid, &create_ibss);
		if (status != DLADM_STATUS_OK)
			goto fail;

		if ((attrp->wa_valid & DLADM_WLAN_ATTR_ESSID) == 0) {
			generate_essid(&essid);
			essid_valid = B_TRUE;
		}
	}

	if ((attrp->wa_valid & DLADM_WLAN_ATTR_ESSID) != 0) {
		essid = attrp->wa_essid;
		essid_valid = B_TRUE;
	}

	if (!essid_valid) {
		status = DLADM_STATUS_FAILED;
		goto fail;
	}

	if ((status = do_set_essid(handle, linkid, &essid)) != DLADM_STATUS_OK)
		goto fail;

	/*
	 * Because wpa daemon needs getting essid from driver,
	 * we need call do_set_essid() first, then call wpa_instance_create().
	 */
	if (secmode == DLADM_WLAN_SECMODE_WPA && keys != NULL)
		(void) wpa_instance_create(handle, linkid, keys);

	start = gethrtime();
	for (;;) {
		status = do_get_linkstatus(handle, linkid, &wl_status,
		    sizeof (wl_status));
		if (status != DLADM_STATUS_OK)
			goto fail;

		if (wl_status == WL_CONNECTED)
			break;

		(void) poll(NULL, 0, DLADM_WLAN_CONNECT_POLLRATE);
		if ((timeout >= 0) && (gethrtime() - start) /
		    NANOSEC >= timeout) {
			status = DLADM_STATUS_TIMEDOUT;
			goto fail;
		}
	}
	status = DLADM_STATUS_OK;
fail:
	return (status);
}

dladm_status_t
dladm_wlan_connect(dladm_handle_t handle, datalink_id_t linkid,
    dladm_wlan_attr_t *attrp, int timeout, void *keys, uint_t key_count,
    uint_t flags)
{
	uint_t			i;
	char			buf[WLDP_BUFSIZE];
	connect_state_t		state = {0, 0, NULL};
	attr_node_t		*nodep = NULL;
	boolean_t		create_ibss, set_authmode;
	dladm_wlan_attr_t	**wl_list = NULL;
	dladm_status_t		status;
	wl_linkstatus_t		wl_status;

	if ((status = dladm_wlan_validate(handle, linkid)) != DLADM_STATUS_OK)
		return (status);

	if ((status = do_get_linkstatus(handle, linkid, &wl_status,
	    sizeof (wl_status))) != DLADM_STATUS_OK)
		goto done;

	if (wl_status == WL_CONNECTED) {
		status = DLADM_STATUS_ISCONN;
		goto done;
	}

	set_authmode = ((attrp != NULL) &&
	    (attrp->wa_valid & DLADM_WLAN_ATTR_MODE) != 0);
	create_ibss = ((flags & DLADM_WLAN_CONNECT_CREATEIBSS) != 0 &&
	    attrp != NULL &&
	    (attrp->wa_valid & DLADM_WLAN_ATTR_BSSTYPE) != 0 &&
	    attrp->wa_bsstype == DLADM_WLAN_BSSTYPE_IBSS);

	if ((flags & DLADM_WLAN_CONNECT_NOSCAN) != 0 ||
	    (create_ibss && attrp != NULL &&
	    (attrp->wa_valid & DLADM_WLAN_ATTR_ESSID) == 0)) {
		status = do_connect(handle, linkid, buf, sizeof (buf), attrp,
		    create_ibss, keys, key_count, timeout);
		goto done;
	}

	state.cs_attr = attrp;
	state.cs_list = NULL;
	state.cs_count = 0;

	status = dladm_wlan_scan(handle, linkid, &state, connect_cb);
	if (status != DLADM_STATUS_OK)
		goto done;

	if (state.cs_count == 0) {
		if (!create_ibss) {
			status = DLADM_STATUS_NOTFOUND;
			goto done;
		}
		status = do_connect(handle, linkid, buf, sizeof (buf),
		    attrp, create_ibss, keys, key_count, timeout);
		goto done;
	}

	wl_list = malloc(state.cs_count * sizeof (dladm_wlan_attr_t *));
	if (wl_list == NULL) {
		status = DLADM_STATUS_NOMEM;
		goto done;
	}

	nodep = state.cs_list;
	for (i = 0; i < state.cs_count; i++) {
		wl_list[i] = &nodep->an_attr;
		nodep = nodep->an_next;
	}
	qsort(wl_list, state.cs_count, sizeof (dladm_wlan_attr_t *),
	    attr_compare);

	for (i = 0; i < state.cs_count; i++) {
		dladm_wlan_attr_t	*ap = wl_list[i];

		status = do_connect(handle, linkid, buf, sizeof (buf),
		    ap, create_ibss, keys, key_count, timeout);
		if (status == DLADM_STATUS_OK)
			break;

		if (!set_authmode) {
			ap->wa_auth = DLADM_WLAN_AUTH_SHARED;
			ap->wa_valid |= DLADM_WLAN_ATTR_AUTH;
			status = do_connect(handle, linkid, buf, sizeof (buf),
			    ap, create_ibss, keys, key_count, timeout);
			if (status == DLADM_STATUS_OK)
				break;
		}
	}
done:
	if ((status != DLADM_STATUS_OK) && (status != DLADM_STATUS_ISCONN))
		(void) do_disconnect(handle, linkid, buf, sizeof (buf));

	while (state.cs_list != NULL) {
		nodep = state.cs_list;
		state.cs_list = nodep->an_next;
		free(nodep);
	}
	free(wl_list);
	return (status);
}

dladm_status_t
dladm_wlan_disconnect(dladm_handle_t handle, datalink_id_t linkid)
{
	char		buf[WLDP_BUFSIZE];
	dladm_status_t	status;
	wl_linkstatus_t	wl_status;

	if ((status = dladm_wlan_validate(handle, linkid)) != DLADM_STATUS_OK)
		return (status);

	if ((status = do_get_linkstatus(handle, linkid, &wl_status,
	    sizeof (wl_status))) != DLADM_STATUS_OK)
		goto done;

	if (wl_status != WL_CONNECTED) {
		status = DLADM_STATUS_NOTCONN;
		goto done;
	}

	if ((status = do_disconnect(handle, linkid, buf, sizeof (buf)))
	    != DLADM_STATUS_OK)
		goto done;

	if ((status = do_get_linkstatus(handle, linkid, &wl_status,
	    sizeof (wl_status))) != DLADM_STATUS_OK)
		goto done;

	if (wl_status == WL_CONNECTED) {
		status = DLADM_STATUS_FAILED;
		goto done;
	}

	status = DLADM_STATUS_OK;
done:
	return (status);
}

dladm_status_t
dladm_wlan_get_linkattr(dladm_handle_t handle, datalink_id_t linkid,
    dladm_wlan_linkattr_t *attrp)
{
	wl_rssi_t		signal;
	wl_bss_type_t		bsstype;
	wl_authmode_t		authmode;
	wl_encryption_t		encryption;
	wl_rates_t		*ratesp = NULL;
	dladm_wlan_attr_t	*wl_attrp;
	dladm_status_t		status;
	char			buf[WLDP_BUFSIZE];
	wl_essid_t		wls;
	wl_phy_conf_t		wl_phy_conf;
	wl_linkstatus_t		wl_status;

	if (attrp == NULL)
		return (DLADM_STATUS_BADARG);

	if ((status = dladm_wlan_validate(handle, linkid)) != DLADM_STATUS_OK)
		goto done;

	(void) memset(attrp, 0, sizeof (*attrp));
	wl_attrp = &attrp->la_wlan_attr;

	if ((status = do_get_linkstatus(handle, linkid, &wl_status,
	    sizeof (wl_status))) != DLADM_STATUS_OK)
		goto done;

	attrp->la_valid |= DLADM_WLAN_LINKATTR_STATUS;
	if (wl_status != WL_CONNECTED)
		attrp->la_status = DLADM_WLAN_LINK_DISCONNECTED;
	else
		attrp->la_status = DLADM_WLAN_LINK_CONNECTED;

	if ((status = do_get_essid(handle, linkid, &wls, sizeof (wls)))
	    != DLADM_STATUS_OK)
		goto done;

	(void) strlcpy(wl_attrp->wa_essid.we_bytes, wls.wl_essid_essid,
	    DLADM_WLAN_MAX_ESSID_LEN);

	wl_attrp->wa_valid |= DLADM_WLAN_ATTR_ESSID;

	if ((status = do_get_bssid(handle, linkid, buf, sizeof (buf)))
	    != DLADM_STATUS_OK)
		goto done;

	(void) memcpy(wl_attrp->wa_bssid.wb_bytes, buf, DLADM_WLAN_BSSID_LEN);

	wl_attrp->wa_valid |= DLADM_WLAN_ATTR_BSSID;

	if (attrp->la_status == DLADM_WLAN_LINK_DISCONNECTED) {
		attrp->la_valid |= DLADM_WLAN_LINKATTR_WLAN;
		status = DLADM_STATUS_OK;
		goto done;
	}

	if ((status = do_get_encryption(handle, linkid, &encryption,
	    sizeof (encryption))) != DLADM_STATUS_OK)
		goto done;

	wl_attrp->wa_valid |= DLADM_WLAN_ATTR_SECMODE;

	switch (encryption) {
	case WL_NOENCRYPTION:
		wl_attrp->wa_secmode = DLADM_WLAN_SECMODE_NONE;
		break;
	case WL_ENC_WEP:
		wl_attrp->wa_secmode = DLADM_WLAN_SECMODE_WEP;
		break;
	case WL_ENC_WPA:
		wl_attrp->wa_secmode = DLADM_WLAN_SECMODE_WPA;
		break;
	default:
		wl_attrp->wa_valid &= ~DLADM_WLAN_ATTR_SECMODE;
		break;
	}

	if ((status = do_get_signal(handle, linkid, &signal, sizeof (signal)))
	    != DLADM_STATUS_OK)
		goto done;

	wl_attrp->wa_valid |= DLADM_WLAN_ATTR_STRENGTH;
	wl_attrp->wa_strength = DLADM_WLAN_SIGNAL2STRENGTH(signal);

	ratesp = malloc(WLDP_BUFSIZE);
	if (ratesp == NULL) {
		status = DLADM_STATUS_NOMEM;
		goto done;
	}

	if ((status = do_get_rate(handle, linkid, ratesp, WLDP_BUFSIZE))
	    != DLADM_STATUS_OK)
		goto done;

	if (ratesp->wl_rates_num > 0) {
		uint_t	i;
		int r = 0;

		for (i = 0; i < ratesp->wl_rates_num; i++) {
			if (ratesp->wl_rates_rates[i] > r)
				r = ratesp->wl_rates_rates[i];
		}
		wl_attrp->wa_speed = r;
		wl_attrp->wa_valid |= DLADM_WLAN_ATTR_SPEED;
	}

	if ((status = do_get_authmode(handle, linkid, &authmode,
	    sizeof (authmode))) != DLADM_STATUS_OK)
		goto done;

	wl_attrp->wa_valid |= DLADM_WLAN_ATTR_AUTH;

	switch (authmode) {
	case WL_OPENSYSTEM:
		wl_attrp->wa_auth = DLADM_WLAN_AUTH_OPEN;
		break;
	case WL_SHAREDKEY:
		wl_attrp->wa_auth = DLADM_WLAN_AUTH_SHARED;
		break;
	default:
		wl_attrp->wa_valid &= ~DLADM_WLAN_ATTR_AUTH;
		break;
	}

	if ((status = do_get_bsstype(handle, linkid, &bsstype,
	    sizeof (bsstype))) != DLADM_STATUS_OK)
		goto done;

	wl_attrp->wa_valid |= DLADM_WLAN_ATTR_BSSTYPE;

	switch (bsstype) {
	case WL_BSS_BSS:
		wl_attrp->wa_bsstype = DLADM_WLAN_BSSTYPE_BSS;
		break;
	case WL_BSS_IBSS:
		wl_attrp->wa_bsstype = DLADM_WLAN_BSSTYPE_IBSS;
		break;
	case WL_BSS_ANY:
		wl_attrp->wa_bsstype = DLADM_WLAN_BSSTYPE_ANY;
		break;
	default:
		wl_attrp->wa_valid &= ~DLADM_WLAN_ATTR_BSSTYPE;
		break;
	}

	if ((status = do_get_mode(handle, linkid, &wl_phy_conf,
	    sizeof (wl_phy_conf))) != DLADM_STATUS_OK)
		goto done;

	wl_attrp->wa_mode = do_convert_mode(&wl_phy_conf);
	wl_attrp->wa_valid |= DLADM_WLAN_ATTR_MODE;
	if (wl_attrp->wa_mode != DLADM_WLAN_MODE_NONE)
		wl_attrp->wa_valid |= DLADM_WLAN_ATTR_MODE;

	attrp->la_valid |= DLADM_WLAN_LINKATTR_WLAN;
	status = DLADM_STATUS_OK;

done:
	free(ratesp);
	return (status);
}

/*
 * Check to see if the link is wireless.
 */
static dladm_status_t
dladm_wlan_validate(dladm_handle_t handle, datalink_id_t linkid)
{
	uint32_t	media;
	dladm_status_t	status;

	status = dladm_datalink_id2info(handle, linkid, NULL, NULL, &media,
	    NULL, 0);
	if (status == DLADM_STATUS_OK) {
		if (media != DL_WIFI)
			status = DLADM_STATUS_LINKINVAL;
	}
	return (status);
}

static boolean_t
find_val_by_name(const char *str, val_desc_t *vdp, uint_t cnt, uint_t *valp)
{
	uint_t	i;

	for (i = 0; i < cnt; i++) {
		if (strcasecmp(str, vdp[i].vd_name) == 0) {
			*valp = vdp[i].vd_val;
			return (B_TRUE);
		}
	}
	return (B_FALSE);
}

static boolean_t
find_name_by_val(uint_t val, val_desc_t *vdp, uint_t cnt, char **strp)
{
	uint_t	i;

	for (i = 0; i < cnt; i++) {
		if (val == vdp[i].vd_val) {
			*strp = vdp[i].vd_name;
			return (B_TRUE);
		}
	}
	return (B_FALSE);
}

const char *
dladm_wlan_essid2str(dladm_wlan_essid_t *essid, char *buf)
{
	(void) snprintf(buf, DLADM_STRSIZE, "%s", essid->we_bytes);
	return (buf);
}

const char *
dladm_wlan_bssid2str(dladm_wlan_bssid_t *bssid, char *buf)
{
	return (_link_ntoa(bssid->wb_bytes, buf, DLADM_WLAN_BSSID_LEN,
	    IFT_OTHER));
}

static const char *
dladm_wlan_val2str(uint_t val, val_desc_t *vdp, uint_t cnt, char *buf)
{
	char	*s;

	if (!find_name_by_val(val, vdp, cnt, &s))
		s = "";

	(void) snprintf(buf, DLADM_STRSIZE, "%s", s);
	return (buf);
}

const char *
dladm_wlan_secmode2str(dladm_wlan_secmode_t *secmode, char *buf)
{
	return (dladm_wlan_val2str((uint_t)*secmode, secmode_vals,
	    VALCNT(secmode_vals), buf));
}

const char *
dladm_wlan_strength2str(dladm_wlan_strength_t *strength, char *buf)
{
	return (dladm_wlan_val2str((uint_t)*strength, strength_vals,
	    VALCNT(strength_vals), buf));
}

const char *
dladm_wlan_mode2str(dladm_wlan_mode_t *mode, char *buf)
{
	return (dladm_wlan_val2str((uint_t)*mode, mode_vals,
	    VALCNT(mode_vals), buf));
}

const char *
dladm_wlan_speed2str(dladm_wlan_speed_t *speed, char *buf)
{
	(void) snprintf(buf, DLADM_STRSIZE, "%.*f", *speed % 2,
	    (float)(*speed) / 2);
	return (buf);
}

const char *
dladm_wlan_auth2str(dladm_wlan_auth_t *auth, char *buf)
{
	return (dladm_wlan_val2str((uint_t)*auth, auth_vals,
	    VALCNT(auth_vals), buf));
}

const char *
dladm_wlan_bsstype2str(dladm_wlan_bsstype_t *bsstype, char *buf)
{
	return (dladm_wlan_val2str((uint_t)*bsstype, bsstype_vals,
	    VALCNT(bsstype_vals), buf));
}

const char *
dladm_wlan_linkstatus2str(dladm_wlan_linkstatus_t *linkstatus, char *buf)
{
	return (dladm_wlan_val2str((uint_t)*linkstatus, linkstatus_vals,
	    VALCNT(linkstatus_vals), buf));
}

dladm_status_t
dladm_wlan_str2essid(const char *str, dladm_wlan_essid_t *essid)
{
	if (str[0] == '\0' || strlen(str) > DLADM_WLAN_MAX_ESSID_LEN - 1)
		return (DLADM_STATUS_BADARG);

	(void) strlcpy(essid->we_bytes, str, DLADM_WLAN_MAX_ESSID_LEN);
	return (DLADM_STATUS_OK);
}

dladm_status_t
dladm_wlan_str2bssid(const char *str, dladm_wlan_bssid_t *bssid)
{
	int	len;
	uchar_t	*buf;

	buf = _link_aton(str, &len);
	if (buf == NULL)
		return (DLADM_STATUS_BADARG);

	if (len != DLADM_WLAN_BSSID_LEN) {
		free(buf);
		return (DLADM_STATUS_BADARG);
	}

	(void) memcpy(bssid->wb_bytes, buf, len);
	free(buf);
	return (DLADM_STATUS_OK);
}

dladm_status_t
dladm_wlan_str2secmode(const char *str, dladm_wlan_secmode_t *secmode)
{
	uint_t	val;

	if (!find_val_by_name(str, secmode_vals, VALCNT(secmode_vals), &val))
		return (DLADM_STATUS_BADARG);

	*secmode = (dladm_wlan_secmode_t)val;
	return (DLADM_STATUS_OK);
}

dladm_status_t
dladm_wlan_str2strength(const char *str, dladm_wlan_strength_t *strength)
{
	uint_t	val;

	if (!find_val_by_name(str, strength_vals, VALCNT(strength_vals), &val))
		return (DLADM_STATUS_BADARG);

	*strength = (dladm_wlan_strength_t)val;
	return (DLADM_STATUS_OK);
}

dladm_status_t
dladm_wlan_str2mode(const char *str, dladm_wlan_mode_t *mode)
{
	uint_t	val;

	if (!find_val_by_name(str, mode_vals, VALCNT(mode_vals), &val))
		return (DLADM_STATUS_BADARG);

	*mode = (dladm_wlan_mode_t)val;
	return (DLADM_STATUS_OK);
}

dladm_status_t
dladm_wlan_str2speed(const char *str, dladm_wlan_speed_t *speed)
{
	*speed = (dladm_wlan_speed_t)(atof(str) * 2);
	return (DLADM_STATUS_OK);
}

dladm_status_t
dladm_wlan_str2auth(const char *str, dladm_wlan_auth_t *auth)
{
	uint_t	val;

	if (!find_val_by_name(str, auth_vals, VALCNT(auth_vals), &val))
		return (DLADM_STATUS_BADARG);

	*auth = (dladm_wlan_auth_t)val;
	return (DLADM_STATUS_OK);
}

dladm_status_t
dladm_wlan_str2bsstype(const char *str, dladm_wlan_bsstype_t *bsstype)
{
	uint_t	val;

	if (!find_val_by_name(str, bsstype_vals, VALCNT(bsstype_vals), &val))
		return (DLADM_STATUS_BADARG);

	*bsstype = (dladm_wlan_bsstype_t)val;
	return (DLADM_STATUS_OK);
}

dladm_status_t
dladm_wlan_str2linkstatus(const char *str, dladm_wlan_linkstatus_t *linkstatus)
{
	uint_t	val;

	if (!find_val_by_name(str, linkstatus_vals,
	    VALCNT(linkstatus_vals), &val)) {
		return (DLADM_STATUS_BADARG);
	}

	*linkstatus = (dladm_wlan_linkstatus_t)val;
	return (DLADM_STATUS_OK);
}

dladm_status_t
i_dladm_wlan_legacy_ioctl(dladm_handle_t handle, datalink_id_t linkid,
    wldp_t *gbuf, uint_t id, size_t len, uint_t cmd, size_t cmdlen)
{
	char			linkname[MAXPATHLEN];
	int			fd, rc;
	struct	strioctl	stri;
	uint32_t		flags;
	dladm_status_t		status;
	uint32_t		media;
	char			link[MAXLINKNAMELEN];

	if ((status = dladm_datalink_id2info(handle, linkid, &flags, NULL,
	    &media, link, MAXLINKNAMELEN)) != DLADM_STATUS_OK) {
		return (status);
	}

	if (media != DL_WIFI)
		return (DLADM_STATUS_BADARG);

	if (!(flags & DLADM_OPT_ACTIVE))
		return (DLADM_STATUS_TEMPONLY);

	/*
	 * dlpi_open() is not used here because libdlpi depends on libdladm,
	 * and we do not want to introduce recursive dependencies.
	 */
	(void) snprintf(linkname, MAXPATHLEN, "/dev/net/%s", link);
	if ((fd = open(linkname, O_RDWR)) < 0)
		return (dladm_errno2status(errno));

	gbuf->wldp_type = NET_802_11;
	gbuf->wldp_id	= id;
	gbuf->wldp_length = len;

	stri.ic_timout	= 0;
	stri.ic_dp	= (char *)gbuf;
	stri.ic_cmd	= cmd;
	stri.ic_len	= cmdlen;

	if ((rc = ioctl(fd, I_STR, &stri)) != 0) {
		if (rc > 0) {
			/*
			 * Non-negative return value indicates the specific
			 * operation failed and the reason for the failure
			 * was stored in gbuf->wldp_result.
			 */
			status = dladm_wlan_wlresult2status(gbuf);
		} else {
			/*
			 * Negative return value indicates the ioctl failed.
			 */
			status = dladm_errno2status(errno);
		}
	}
	(void) close(fd);
	return (status);
}

static dladm_status_t
do_cmd_ioctl(dladm_handle_t handle, datalink_id_t linkid, void *buf,
    int buflen, uint_t cmd)
{
	wldp_t *gbuf;
	dladm_status_t status = DLADM_STATUS_OK;

	if ((gbuf = malloc(MAX_BUF_LEN)) == NULL)
		return (DLADM_STATUS_NOMEM);

	(void) memset(gbuf, 0, MAX_BUF_LEN);
	status = i_dladm_wlan_legacy_ioctl(handle, linkid, gbuf, cmd,
	    WLDP_BUFSIZE, WLAN_COMMAND, sizeof (wldp_t));
	(void) memcpy(buf, gbuf->wldp_buf, buflen);
	free(gbuf);
	return (status);
}

static dladm_status_t
do_scan(dladm_handle_t handle, datalink_id_t linkid, void *buf, int buflen)
{
	return (do_cmd_ioctl(handle, linkid, buf, buflen, WL_SCAN));
}

static dladm_status_t
do_disconnect(dladm_handle_t handle, datalink_id_t linkid, void *buf,
    int buflen)
{
	if (do_get_wpamode(handle, linkid, buf, buflen) == 0 &&
	    ((wl_wpa_t *)(buf))->wpa_flag > 0)
		(void) wpa_instance_delete(handle, linkid);

	return (do_cmd_ioctl(handle, linkid, buf, buflen, WL_DISASSOCIATE));
}

static dladm_status_t
do_get_esslist(dladm_handle_t handle, datalink_id_t linkid, void *buf,
    int buflen)
{
	return (i_dladm_wlan_param(handle, linkid, buf, MAC_PROP_WL_ESS_LIST,
	    buflen, B_FALSE));
}

static dladm_status_t
do_get_bssid(dladm_handle_t handle, datalink_id_t linkid, void *buf, int buflen)
{
	return (i_dladm_wlan_param(handle, linkid, buf, MAC_PROP_WL_BSSID,
	    buflen, B_FALSE));
}

static dladm_status_t
do_get_essid(dladm_handle_t handle, datalink_id_t linkid, void *buf, int buflen)
{
	return (i_dladm_wlan_param(handle, linkid, buf, MAC_PROP_WL_ESSID,
	    buflen, B_FALSE));
}

static dladm_status_t
do_get_bsstype(dladm_handle_t handle, datalink_id_t linkid, void *buf,
    int buflen)
{
	return (i_dladm_wlan_param(handle, linkid, buf, MAC_PROP_WL_BSSTYPE,
	    buflen, B_FALSE));
}

static dladm_status_t
do_get_linkstatus(dladm_handle_t handle, datalink_id_t linkid, void *buf,
    int buflen)
{
	return (i_dladm_wlan_param(handle, linkid, buf, MAC_PROP_WL_LINKSTATUS,
	    buflen, B_FALSE));
}

static dladm_status_t
do_get_rate(dladm_handle_t handle, datalink_id_t linkid, void *buf, int buflen)
{
	return (i_dladm_wlan_param(handle, linkid, buf,
	    MAC_PROP_WL_DESIRED_RATES, buflen, B_FALSE));
}

static dladm_status_t
do_get_authmode(dladm_handle_t handle, datalink_id_t linkid, void *buf,
    int buflen)
{
	return (i_dladm_wlan_param(handle, linkid, buf,
	    MAC_PROP_WL_AUTH_MODE, buflen, B_FALSE));
}

static dladm_status_t
do_get_encryption(dladm_handle_t handle, datalink_id_t linkid, void *buf,
    int buflen)
{
	return (i_dladm_wlan_param(handle, linkid, buf,
	    MAC_PROP_WL_ENCRYPTION, buflen, B_FALSE));
}

static dladm_status_t
do_get_signal(dladm_handle_t handle, datalink_id_t linkid, void *buf,
    int buflen)
{
	return (i_dladm_wlan_param(handle, linkid, buf, MAC_PROP_WL_RSSI,
	    buflen, B_FALSE));
}

static dladm_status_t
do_get_mode(dladm_handle_t handle, datalink_id_t linkid, void *buf, int buflen)
{
	return (i_dladm_wlan_param(handle, linkid, buf, MAC_PROP_WL_PHY_CONFIG,
	    buflen, B_FALSE));
}

static dladm_status_t
do_set_bsstype(dladm_handle_t handle, datalink_id_t linkid,
    dladm_wlan_bsstype_t *bsstype)
{
	wl_bss_type_t	ibsstype;

	switch (*bsstype) {
	case DLADM_WLAN_BSSTYPE_BSS:
		ibsstype = WL_BSS_BSS;
		break;
	case DLADM_WLAN_BSSTYPE_IBSS:
		ibsstype = WL_BSS_IBSS;
		break;
	default:
		ibsstype = WL_BSS_ANY;
		break;
	}
	return (i_dladm_wlan_param(handle, linkid, &ibsstype,
	    MAC_PROP_WL_BSSTYPE, sizeof (ibsstype), B_TRUE));
}

static dladm_status_t
do_set_authmode(dladm_handle_t handle, datalink_id_t linkid,
    dladm_wlan_auth_t *auth)
{
	wl_authmode_t	auth_mode;

	switch (*auth) {
	case DLADM_WLAN_AUTH_OPEN:
		auth_mode = WL_OPENSYSTEM;
		break;
	case DLADM_WLAN_AUTH_SHARED:
		auth_mode = WL_SHAREDKEY;
		break;
	default:
		return (DLADM_STATUS_NOTSUP);
	}
	return (i_dladm_wlan_param(handle, linkid, &auth_mode,
	    MAC_PROP_WL_AUTH_MODE, sizeof (auth_mode), B_TRUE));
}

static dladm_status_t
do_set_encryption(dladm_handle_t handle, datalink_id_t linkid,
    dladm_wlan_secmode_t *secmode)
{
	wl_encryption_t	encryption;

	switch (*secmode) {
	case DLADM_WLAN_SECMODE_NONE:
		encryption = WL_NOENCRYPTION;
		break;
	case DLADM_WLAN_SECMODE_WEP:
		encryption = WL_ENC_WEP;
		break;
	case DLADM_WLAN_SECMODE_WPA:
		return (0);
	default:
		return (DLADM_STATUS_NOTSUP);
	}
	return (i_dladm_wlan_param(handle, linkid, &encryption,
	    MAC_PROP_WL_ENCRYPTION, sizeof (encryption), B_TRUE));
}

static dladm_status_t
do_set_key(dladm_handle_t handle, datalink_id_t linkid, dladm_wlan_key_t *keys,
    uint_t key_count)
{
	uint_t			i;
	wl_wep_key_t		*wkp;
	wl_wep_key_tab_t	wepkey_tab;
	dladm_wlan_key_t	*kp;

	if (key_count == 0 || key_count > MAX_NWEPKEYS || keys == NULL)
		return (DLADM_STATUS_BADARG);

	(void) memset(wepkey_tab, 0, sizeof (wepkey_tab));
	for (i = 0; i < MAX_NWEPKEYS; i++)
		wepkey_tab[i].wl_wep_operation = WL_NUL;

	for (i = 0; i < key_count; i++) {
		kp = &keys[i];
		if (kp->wk_idx == 0 || kp->wk_idx > MAX_NWEPKEYS)
			return (DLADM_STATUS_BADARG);
		if (kp->wk_len != DLADM_WLAN_WEPKEY64_LEN &&
		    kp->wk_len != DLADM_WLAN_WEPKEY128_LEN)
			return (DLADM_STATUS_BADARG);

		wkp = &wepkey_tab[kp->wk_idx - 1];
		wkp->wl_wep_operation = WL_ADD;
		wkp->wl_wep_length = kp->wk_len;
		(void) memcpy(wkp->wl_wep_key, kp->wk_val, kp->wk_len);
	}

	return (i_dladm_wlan_param(handle, linkid, &wepkey_tab,
	    MAC_PROP_WL_KEY_TAB, sizeof (wepkey_tab), B_TRUE));
}

static dladm_status_t
do_set_essid(dladm_handle_t handle, datalink_id_t linkid,
    dladm_wlan_essid_t *essid)
{
	wl_essid_t	iessid;

	(void) memset(&iessid, 0, sizeof (essid));

	if (essid != NULL && essid->we_bytes[0] != '\0') {
		iessid.wl_essid_length = strlen(essid->we_bytes);
		(void) strlcpy(iessid.wl_essid_essid, essid->we_bytes,
		    sizeof (iessid.wl_essid_essid));
	} else {
		return (DLADM_STATUS_BADARG);
	}
	return (i_dladm_wlan_param(handle, linkid, &iessid, MAC_PROP_WL_ESSID,
	    sizeof (iessid), B_TRUE));
}

static dladm_status_t
do_set_channel(dladm_handle_t handle, datalink_id_t linkid,
    dladm_wlan_channel_t *channel)
{
	wl_phy_conf_t phy_conf;

	if (*channel > MAX_CHANNEL_NUM)
		return (DLADM_STATUS_BADVAL);

	(void) memset(&phy_conf, 0xff, sizeof (phy_conf));
	phy_conf.wl_phy_dsss_conf.wl_dsss_channel = *channel;

	return (i_dladm_wlan_param(handle, linkid, &phy_conf,
	    MAC_PROP_WL_PHY_CONFIG, sizeof (phy_conf), B_TRUE));
}

static dladm_status_t
do_set_createibss(dladm_handle_t handle, datalink_id_t linkid,
    boolean_t *create_ibss)
{
	wl_create_ibss_t cr = (wl_create_ibss_t)(*create_ibss);

	return (i_dladm_wlan_param(handle, linkid, &cr, MAC_PROP_WL_CREATE_IBSS,
	    sizeof (cr), B_TRUE));
}

static void
generate_essid(dladm_wlan_essid_t *essid)
{
	srandom(gethrtime());
	(void) snprintf(essid->we_bytes, DLADM_WLAN_MAX_ESSID_LEN, "%d",
	    random());
}

static dladm_status_t
do_get_capability(dladm_handle_t handle, datalink_id_t linkid, void *buf,
    int buflen)
{
	return (i_dladm_wlan_param(handle, linkid, buf, MAC_PROP_WL_CAPABILITY,
	    buflen, B_FALSE));
}

static dladm_status_t
do_get_wpamode(dladm_handle_t handle, datalink_id_t linkid, void *buf,
    int buflen)
{
	return (i_dladm_wlan_param(handle, linkid, buf, MAC_PROP_WL_WPA, buflen,
	    B_FALSE));
}

dladm_status_t
dladm_wlan_wpa_get_sr(dladm_handle_t handle, datalink_id_t linkid,
    dladm_wlan_ess_t *sr, uint_t escnt, uint_t *estot)
{
	int		i, n;
	wl_wpa_ess_t	*es;
	dladm_status_t	status;

	es = malloc(WLDP_BUFSIZE);
	if (es == NULL)
		return (DLADM_STATUS_NOMEM);

	status = i_dladm_wlan_param(handle, linkid, es, MAC_PROP_WL_SCANRESULTS,
	    WLDP_BUFSIZE, B_FALSE);

	if (status == DLADM_STATUS_OK) {
		n = (es->count > escnt) ? escnt : es->count;
		for (i = 0; i < n; i ++) {
			(void) memcpy(sr[i].we_bssid.wb_bytes, es->ess[i].bssid,
			    DLADM_WLAN_BSSID_LEN);
			sr[i].we_ssid_len = es->ess[i].ssid_len;
			(void) memcpy(sr[i].we_ssid.we_bytes, es->ess[i].ssid,
			    es->ess[i].ssid_len);
			sr[i].we_wpa_ie_len = es->ess[i].wpa_ie_len;
			(void) memcpy(sr[i].we_wpa_ie, es->ess[i].wpa_ie,
			    es->ess[i].wpa_ie_len);
			sr[i].we_freq = es->ess[i].freq;
		}
		*estot = n;
	}

	free(es);
	return (status);
}

dladm_status_t
dladm_wlan_wpa_set_ie(dladm_handle_t handle, datalink_id_t linkid,
    uint8_t *wpa_ie, uint_t wpa_ie_len)
{
	wl_wpa_ie_t *ie;
	uint_t len;
	dladm_status_t	status;

	if (wpa_ie_len > DLADM_WLAN_MAX_WPA_IE_LEN)
		return (DLADM_STATUS_BADARG);
	len = sizeof (wl_wpa_ie_t) + wpa_ie_len;
	ie = malloc(len);
	if (ie == NULL)
		return (DLADM_STATUS_NOMEM);

	(void) memset(ie, 0, len);
	ie->wpa_ie_len = wpa_ie_len;
	(void) memcpy(ie->wpa_ie, wpa_ie, wpa_ie_len);

	status = i_dladm_wlan_param(handle, linkid, ie, MAC_PROP_WL_SETOPTIE,
	    len, B_TRUE);
	free(ie);

	return (status);
}

dladm_status_t
dladm_wlan_wpa_set_wpa(dladm_handle_t handle, datalink_id_t linkid,
    boolean_t flag)
{
	wl_wpa_t	wpa;

	wpa.wpa_flag = flag;
	return (i_dladm_wlan_param(handle, linkid, &wpa, MAC_PROP_WL_WPA,
	    sizeof (wpa), B_TRUE));
}

dladm_status_t
dladm_wlan_wpa_del_key(dladm_handle_t handle, datalink_id_t linkid,
    uint_t key_idx, const dladm_wlan_bssid_t *addr)
{
	wl_del_key_t	wk;

	wk.idk_keyix = key_idx;
	if (addr != NULL)
		(void) memcpy((char *)wk.idk_macaddr, addr->wb_bytes,
		    DLADM_WLAN_BSSID_LEN);

	return (i_dladm_wlan_param(handle, linkid, &wk, MAC_PROP_WL_DELKEY,
	    sizeof (wk), B_TRUE));
}

dladm_status_t
dladm_wlan_wpa_set_key(dladm_handle_t handle, datalink_id_t linkid,
    dladm_wlan_cipher_t cipher, const dladm_wlan_bssid_t *addr,
    boolean_t set_tx, uint64_t seq, uint_t key_idx, uint8_t *key,
    uint_t key_len)
{
	wl_key_t	wk;

	(void) memset(&wk, 0, sizeof (wl_key_t));
	switch (cipher) {
	case DLADM_WLAN_CIPHER_WEP:
		wk.ik_type = IEEE80211_CIPHER_WEP;
		break;
	case DLADM_WLAN_CIPHER_TKIP:
		wk.ik_type = IEEE80211_CIPHER_TKIP;
		break;
	case DLADM_WLAN_CIPHER_AES_OCB:
		wk.ik_type = IEEE80211_CIPHER_AES_OCB;
		break;
	case DLADM_WLAN_CIPHER_AES_CCM:
		wk.ik_type = IEEE80211_CIPHER_AES_CCM;
		break;
	case DLADM_WLAN_CIPHER_CKIP:
		wk.ik_type = IEEE80211_CIPHER_CKIP;
		break;
	case DLADM_WLAN_CIPHER_NONE:
		wk.ik_type = IEEE80211_CIPHER_NONE;
		break;
	default:
		return (DLADM_STATUS_BADARG);
	}
	wk.ik_flags = IEEE80211_KEY_RECV;
	if (set_tx) {
		wk.ik_flags |= IEEE80211_KEY_XMIT | IEEE80211_KEY_DEFAULT;
		(void) memcpy(wk.ik_macaddr, addr->wb_bytes,
		    DLADM_WLAN_BSSID_LEN);
	} else
		(void) memset(wk.ik_macaddr, 0, DLADM_WLAN_BSSID_LEN);
	wk.ik_keyix = key_idx;
	wk.ik_keylen = key_len;
	(void) memcpy(&wk.ik_keyrsc, &seq, 6);	/* only use 48-bit of seq */
	(void) memcpy(wk.ik_keydata, key, key_len);

	return (i_dladm_wlan_param(handle, linkid, &wk, MAC_PROP_WL_KEY,
	    sizeof (wk), B_TRUE));
}

dladm_status_t
dladm_wlan_wpa_set_mlme(dladm_handle_t handle, datalink_id_t linkid,
    dladm_wlan_mlme_op_t op, dladm_wlan_reason_t reason,
    dladm_wlan_bssid_t *bssid)
{
	wl_mlme_t mlme;

	(void) memset(&mlme, 0, sizeof (wl_mlme_t));
	switch (op) {
	case DLADM_WLAN_MLME_ASSOC:
		mlme.im_op = IEEE80211_MLME_ASSOC;
		break;
	case DLADM_WLAN_MLME_DISASSOC:
		mlme.im_op = IEEE80211_MLME_DISASSOC;
		break;
	default:
		return (DLADM_STATUS_BADARG);
	}
	mlme.im_reason = reason;
	if (bssid != NULL)
		(void) memcpy(mlme.im_macaddr, bssid->wb_bytes,
		    DLADM_WLAN_BSSID_LEN);

	return (i_dladm_wlan_param(handle, linkid, &mlme, MAC_PROP_WL_MLME,
	    sizeof (mlme), B_TRUE));
}

/*
 * routines of create instance
 */
static scf_propertygroup_t *
add_property_group_to_instance(scf_handle_t *handle, scf_instance_t *instance,
    const char *pg_name, const char *pg_type)
{
	scf_propertygroup_t *pg;

	pg = scf_pg_create(handle);
	if (pg == NULL)
		return (NULL);

	if (scf_instance_add_pg(instance, pg_name, pg_type, 0, pg) != 0) {
		scf_pg_destroy(pg);
		return (NULL);
	}

	return (pg);
}

static dladm_status_t
add_new_property(scf_handle_t *handle, const char *prop_name,
    scf_type_t type, const char *val, scf_transaction_t *tx)
{
	scf_value_t *value = NULL;
	scf_transaction_entry_t *entry = NULL;

	entry = scf_entry_create(handle);
	if (entry == NULL)
		goto out;

	value = scf_value_create(handle);
	if (value == NULL)
		goto out;

	if (scf_transaction_property_new(tx, entry, prop_name, type) != 0)
		goto out;

	if (scf_value_set_from_string(value, type, val) != 0)
		goto out;

	if (scf_entry_add_value(entry, value) != 0)
		goto out;

	return (DLADM_STATUS_OK);

out:
	if (value != NULL)
		scf_value_destroy(value);
	if (entry != NULL)
		scf_entry_destroy(entry);

	return (DLADM_STATUS_FAILED);
}

static dladm_status_t
add_pg_method(scf_handle_t *handle, scf_instance_t *instance,
    const char *pg_name, const char *flags)
{
	int			rv, size;
	dladm_status_t		status = DLADM_STATUS_FAILED;
	char			*command = NULL;
	scf_transaction_t	*tran = NULL;
	scf_propertygroup_t	*pg;

	pg = add_property_group_to_instance(handle, instance,
	    pg_name, SCF_GROUP_METHOD);
	if (pg == NULL)
		goto out;

	tran = scf_transaction_create(handle);
	if (tran == NULL)
		goto out;

	size = strlen(SVC_METHOD) + strlen("  ") + strlen(flags) + 1;
	command = malloc(size);
	if (command == NULL) {
		status = DLADM_STATUS_NOMEM;
		goto out;
	}
	(void) snprintf(command, size, "%s %s", SVC_METHOD, flags);

	do {
		if (scf_transaction_start(tran, pg) != 0)
			goto out;

		if (add_new_property(handle, SCF_PROPERTY_EXEC,
		    SCF_TYPE_ASTRING, command, tran) != DLADM_STATUS_OK) {
			goto out;
		}

		rv = scf_transaction_commit(tran);
		switch (rv) {
		case 1:
			status = DLADM_STATUS_OK;
			goto out;
		case 0:
			scf_transaction_destroy_children(tran);
			if (scf_pg_update(pg) == -1) {
				goto out;
			}
			break;
		case -1:
		default:
			goto out;
		}
	} while (rv == 0);

out:
	if (tran != NULL) {
		scf_transaction_destroy_children(tran);
		scf_transaction_destroy(tran);
	}

	if (pg != NULL)
		scf_pg_destroy(pg);

	if (command != NULL)
		free(command);

	return (status);
}

static dladm_status_t
do_create_instance(scf_handle_t *handle, scf_service_t *svc,
    const char *instance_name, const char *command)
{
	dladm_status_t status = DLADM_STATUS_FAILED;
	char *buf;
	ssize_t max_fmri_len;
	scf_instance_t *instance;

	instance = scf_instance_create(handle);
	if (instance == NULL)
		goto out;

	if (scf_service_add_instance(svc, instance_name, instance) != 0) {
		if (scf_error() == SCF_ERROR_EXISTS)
			/* Let the caller deal with the duplicate instance */
			status = DLADM_STATUS_EXIST;
		goto out;
	}

	if (add_pg_method(handle, instance, "start",
	    command) != DLADM_STATUS_OK) {
		goto out;
	}

	/* enabling the instance */
	max_fmri_len = scf_limit(SCF_LIMIT_MAX_FMRI_LENGTH);
	if ((buf = malloc(max_fmri_len + 1)) == NULL)
		goto out;

	if (scf_instance_to_fmri(instance, buf, max_fmri_len + 1) > 0) {
		if ((smf_disable_instance(buf, 0) != 0) ||
		    (smf_enable_instance(buf, SMF_TEMPORARY) != 0)) {
			goto out;
		}
		status = DLADM_STATUS_OK;
	}

out:
	if (instance != NULL)
		scf_instance_destroy(instance);
	return (status);
}

static dladm_status_t
create_instance(const char *instance_name, const char *command)
{
	dladm_status_t status = DLADM_STATUS_FAILED;
	scf_service_t *svc = NULL;
	scf_handle_t *handle = NULL;

	handle = scf_handle_create(SCF_VERSION);
	if (handle == NULL)
		goto out;

	if (scf_handle_bind(handle) == -1)
		goto out;

	if ((svc = scf_service_create(handle)) == NULL)
		goto out;

	if (scf_handle_decode_fmri(handle, SERVICE_NAME, NULL, svc,
	    NULL, NULL, NULL, SCF_DECODE_FMRI_EXACT) != 0)
		goto out;

	status = do_create_instance(handle, svc, instance_name, command);

out:
	if (svc != NULL)
		scf_service_destroy(svc);

	if (handle != NULL) {
		(void) scf_handle_unbind(handle);
		scf_handle_destroy(handle);
	}

	return (status);
}

/*
 * routines of delete instance
 */
#define	DEFAULT_TIMEOUT	60000000
#define	INIT_WAIT_USECS	50000

static void
wait_until_disabled(scf_handle_t *handle, char *fmri)
{
	char		*state;
	useconds_t	max;
	useconds_t	usecs;
	uint64_t	*cp = NULL;
	scf_simple_prop_t *sp = NULL;

	max = DEFAULT_TIMEOUT;

	if (((sp = scf_simple_prop_get(handle, fmri, "stop",
	    SCF_PROPERTY_TIMEOUT)) != NULL) &&
	    ((cp = scf_simple_prop_next_count(sp)) != NULL) && (*cp != 0))
		max = (*cp) * 1000000;	/* convert to usecs */

	if (sp != NULL)
		scf_simple_prop_free(sp);

	for (usecs = INIT_WAIT_USECS; max > 0; max -= usecs) {
		/* incremental wait */
		usecs *= 2;
		usecs = (usecs > max) ? max : usecs;

		(void) usleep(usecs);

		/* Check state after the wait */
		if ((state = smf_get_state(fmri)) != NULL) {
			if (strcmp(state, "disabled") == 0)
				return;
		}
	}
}

static dladm_status_t
delete_instance(const char *instance_name)
{
	dladm_status_t	status = DLADM_STATUS_FAILED;
	char		*buf;
	ssize_t		max_fmri_len;
	scf_scope_t	*scope = NULL;
	scf_service_t	*svc = NULL;
	scf_handle_t	*handle = NULL;
	scf_instance_t	*instance;

	handle = scf_handle_create(SCF_VERSION);
	if (handle == NULL)
		goto out;

	if (scf_handle_bind(handle) == -1)
		goto out;

	if ((scope = scf_scope_create(handle)) == NULL)
		goto out;

	if ((svc = scf_service_create(handle)) == NULL)
		goto out;

	if (scf_handle_get_scope(handle, SCF_SCOPE_LOCAL, scope) == -1)
		goto out;

	if (scf_scope_get_service(scope, SERVICE_NAME, svc) < 0)
		goto out;

	instance = scf_instance_create(handle);
	if (instance == NULL)
		goto out;

	if (scf_service_get_instance(svc, instance_name, instance) != 0) {
		scf_error_t scf_errnum = scf_error();

		if (scf_errnum == SCF_ERROR_NOT_FOUND)
			status = DLADM_STATUS_OK;

		scf_instance_destroy(instance);
		goto out;
	}

	max_fmri_len = scf_limit(SCF_LIMIT_MAX_FMRI_LENGTH);
	if ((buf = malloc(max_fmri_len + 1)) == NULL) {
		scf_instance_destroy(instance);
		goto out;
	}

	if (scf_instance_to_fmri(instance, buf, max_fmri_len + 1) > 0) {
		char *state;

		state = smf_get_state(buf);
		if (state && (strcmp(state, SCF_STATE_STRING_ONLINE) == 0 ||
		    strcmp(state, SCF_STATE_STRING_DEGRADED) == 0)) {
			if (smf_disable_instance(buf, 0) == 0) {
				/*
				 * Wait for some time till timeout to avoid
				 * a race with scf_instance_delete() below.
				 */
				wait_until_disabled(handle, buf);
			}
		}
	}

	if (scf_instance_delete(instance) != 0) {
		scf_instance_destroy(instance);
		goto out;
	}

	scf_instance_destroy(instance);

	status = DLADM_STATUS_OK;

out:
	if (svc != NULL)
		scf_service_destroy(svc);

	if (scope != NULL)
		scf_scope_destroy(scope);

	if (handle != NULL) {
		(void) scf_handle_unbind(handle);
		scf_handle_destroy(handle);
	}

	return (status);
}

static dladm_status_t
wpa_instance_create(dladm_handle_t handle, datalink_id_t linkid, void *key)
{
	dladm_status_t	status = DLADM_STATUS_FAILED;
	char		*command = NULL;
	char		*wk_name = ((dladm_wlan_key_t *)key)->wk_name;
	int		size;
	char		instance_name[MAXLINKNAMELEN];

	/*
	 * Use the link name as the instance name of the network/wpad service.
	 */
	status = dladm_datalink_id2info(handle, linkid, NULL, NULL, NULL,
	    instance_name, sizeof (instance_name));
	if (status != DLADM_STATUS_OK)
		goto out;

	size = strlen(instance_name) + strlen(" -i  -k ") + strlen(wk_name) + 1;
	command = malloc(size);
	if (command == NULL) {
		status = DLADM_STATUS_NOMEM;
		goto out;
	}
	(void) snprintf(command, size, "-i %s -k %s", instance_name, wk_name);

	status = create_instance(instance_name, command);
	if (status == DLADM_STATUS_EXIST) {
		/*
		 * Delete the existing instance and create a new instance
		 * with the supplied arguments.
		 */
		if ((status = delete_instance(instance_name)) ==
		    DLADM_STATUS_OK) {
			status = create_instance(instance_name, command);
		}
	}

out:
	if (command != NULL)
		free(command);

	return (status);
}

static dladm_status_t
wpa_instance_delete(dladm_handle_t handle, datalink_id_t linkid)
{
	char	instance_name[MAXLINKNAMELEN];

	/*
	 * Get the instance name of the network/wpad service (the same as
	 * the link name).
	 */
	if (dladm_datalink_id2info(handle, linkid, NULL, NULL, NULL,
	    instance_name, sizeof (instance_name)) != DLADM_STATUS_OK)
		return (DLADM_STATUS_FAILED);

	return (delete_instance(instance_name));
}
