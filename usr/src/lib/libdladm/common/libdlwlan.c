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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <libintl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stropts.h>
#include <libdevinfo.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <libdlwlan.h>
#include <libdlwlan_impl.h>
#include <inet/wifi_ioctl.h>

typedef struct val_desc {
	char		*vd_name;
	uint_t		vd_val;
} val_desc_t;

struct prop_desc;

typedef dladm_status_t	wl_pd_getf_t(int, wldp_t *, char **, uint_t *);
typedef dladm_status_t	wl_pd_setf_t(int, wldp_t *, val_desc_t *, uint_t);
typedef dladm_status_t	wl_pd_checkf_t(int, wldp_t *, struct prop_desc *,
			    char **, uint_t, val_desc_t **);
typedef struct prop_desc {
	char		*pd_name;
	val_desc_t	pd_defval;
	val_desc_t	*pd_modval;
	uint_t		pd_nmodval;
	wl_pd_setf_t	*pd_set;
	wl_pd_getf_t	*pd_getmod;
	wl_pd_getf_t	*pd_get;
	wl_pd_checkf_t	*pd_check;
} prop_desc_t;

static int 	do_get_bsstype(int, wldp_t *);
static int 	do_get_essid(int, wldp_t *);
static int 	do_get_bssid(int, wldp_t *);
static int 	do_get_signal(int, wldp_t *);
static int 	do_get_encryption(int, wldp_t *);
static int 	do_get_authmode(int, wldp_t *);
static int 	do_get_linkstatus(int, wldp_t *);
static int	do_get_esslist(int, wldp_t *);
static int 	do_get_rate(int, wldp_t *);
static int	do_get_phyconf(int, wldp_t *);
static int	do_get_powermode(int, wldp_t *);
static int	do_get_radio(int, wldp_t *);
static int	do_get_mode(int, wldp_t *);

static int	do_set_bsstype(int, wldp_t *, dladm_wlan_bsstype_t *);
static int	do_set_authmode(int, wldp_t *, dladm_wlan_auth_t *);
static int	do_set_encryption(int, wldp_t *, dladm_wlan_secmode_t *);
static int	do_set_essid(int, wldp_t *, dladm_wlan_essid_t *);
static int	do_set_createibss(int, wldp_t *, boolean_t *);
static int	do_set_wepkey(int, wldp_t *, dladm_wlan_wepkey_t *, uint_t);
static int	do_set_rate(int, wldp_t *, dladm_wlan_rates_t *);
static int	do_set_powermode(int, wldp_t *, dladm_wlan_powermode_t *);
static int	do_set_radio(int, wldp_t *, dladm_wlan_radio_t *);
static int	do_set_channel(int, wldp_t *, dladm_wlan_channel_t *);

static int	open_link(const char *);
static int	do_scan(int, wldp_t *);
static int	do_disconnect(int, wldp_t *);
static boolean_t find_val_by_name(const char *, val_desc_t *, uint_t, uint_t *);
static boolean_t find_name_by_val(uint_t, val_desc_t *, uint_t, char **);
static void	generate_essid(dladm_wlan_essid_t *);

static dladm_status_t	dladm_wlan_wlresult2status(wldp_t *);

static wl_pd_getf_t	do_get_rate_mod, do_get_rate_prop, do_get_channel_prop,
			do_get_powermode_prop, do_get_radio_prop;
static wl_pd_setf_t 	do_set_rate_prop, do_set_powermode_prop,
			do_set_radio_prop;
static wl_pd_checkf_t	do_check_prop, do_check_rate;

static val_desc_t	linkstatus_vals[] = {
	{ "disconnected", 	DLADM_WLAN_LINKSTATUS_DISCONNECTED	},
	{ "connected",		DLADM_WLAN_LINKSTATUS_CONNECTED	}
};

static val_desc_t 	secmode_vals[] = {
	{ "none",	DLADM_WLAN_SECMODE_NONE		},
	{ "wep",	DLADM_WLAN_SECMODE_WEP		}
};

static val_desc_t 	strength_vals[] = {
	{ "very weak",	DLADM_WLAN_STRENGTH_VERY_WEAK 	},
	{ "weak",	DLADM_WLAN_STRENGTH_WEAK		},
	{ "good", 	DLADM_WLAN_STRENGTH_GOOD		},
	{ "very good",	DLADM_WLAN_STRENGTH_VERY_GOOD	},
	{ "excellent",	DLADM_WLAN_STRENGTH_EXCELLENT	}
};

static val_desc_t	mode_vals[] = {
	{ "a",		DLADM_WLAN_MODE_80211A		},
	{ "b",		DLADM_WLAN_MODE_80211B		},
	{ "g",		DLADM_WLAN_MODE_80211G		},
};

static val_desc_t	auth_vals[] = {
	{ "open",	DLADM_WLAN_AUTH_OPEN			},
	{ "shared",	DLADM_WLAN_AUTH_SHARED		}
};

static val_desc_t	bsstype_vals[] = {
	{ "bss",	DLADM_WLAN_BSSTYPE_BSS		},
	{ "ibss",	DLADM_WLAN_BSSTYPE_IBSS		},
	{ "any",	DLADM_WLAN_BSSTYPE_ANY		}
};

static val_desc_t	radio_vals[] = {
	{ "on",		DLADM_WLAN_RADIO_ON			},
	{ "off",	DLADM_WLAN_RADIO_OFF			}
};

static val_desc_t	powermode_vals[] = {
	{ "off",	DLADM_WLAN_PM_OFF			},
	{ "fast",	DLADM_WLAN_PM_FAST			},
	{ "max",	DLADM_WLAN_PM_MAX			}
};

#define	VALCNT(vals)	(sizeof ((vals)) / sizeof (val_desc_t))
static	prop_desc_t	prop_table[] = {

	{ "channel",	{ NULL, 0 }, NULL, 0,
	    NULL, NULL, do_get_channel_prop, do_check_prop},

	{ "powermode",	{ "off", DLADM_WLAN_PM_OFF }, powermode_vals,
	    VALCNT(powermode_vals),
	    do_set_powermode_prop, NULL,
	    do_get_powermode_prop, do_check_prop},

	{ "radio", 	{ "on", DLADM_WLAN_RADIO_ON }, radio_vals,
	    VALCNT(radio_vals),
	    do_set_radio_prop, NULL,
	    do_get_radio_prop, do_check_prop},

	{ "speed",	{ "", 0 }, NULL, 0,
	    do_set_rate_prop, do_get_rate_mod,
	    do_get_rate_prop, do_check_rate}
};
/*
 * Unfortunately, MAX_SCAN_SUPPORT_RATES is too small to allow all
 * rates to be retrieved. However, we cannot increase it at this
 * time because it will break binary comatibility with unbundled
 * WiFi drivers and utilities. So for now we define an additional
 * constant, MAX_SUPPORT_RATES, to allow all rates to be retrieved.
 */
#define	MAX_SUPPORT_RATES	64
#define	DLADM_WLAN_MAX_PROPS	(sizeof (prop_table) / sizeof (prop_desc_t))
#define	IS_CONNECTED(gbuf) \
	((*(wl_linkstatus_t *)((gbuf)->wldp_buf) == WL_CONNECTED))

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

static int
open_link(const char *link)
{
	char	linkname[MAXPATHLEN];
	wldp_t	*gbuf;
	int	fd;

	if (link == NULL)
		return (-1);

	(void) snprintf(linkname, MAXPATHLEN, "/dev/%s", link);
	if ((fd = open(linkname, O_RDWR)) < 0)
		return (-1);

	if ((gbuf = malloc(MAX_BUF_LEN)) == NULL) {
		(void) close(fd);
		return (-1);
	}

	/*
	 * Check to see if the link is wireless.
	 */
	if (do_get_bsstype(fd, gbuf) < 0) {
		free(gbuf);
		(void) close(fd);
		return (-1);
	}

	free(gbuf);
	return (fd);
}

static dladm_wlan_mode_t
do_convert_mode(wl_phy_conf_t *phyp)
{
	switch (phyp->wl_phy_fhss_conf.wl_fhss_subtype) {
	case WL_ERP:
		return (DLADM_WLAN_MODE_80211G);
	case WL_OFDM:
		return (DLADM_WLAN_MODE_80211A);
	case WL_DSSS:
	case WL_FHSS:
		return (DLADM_WLAN_MODE_80211B);
	default:
		break;
	}

	return (DLADM_WLAN_MODE_NONE);
}

static boolean_t
do_convert_chan(wl_phy_conf_t *phyp, uint32_t *channelp)
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
		if (wlp->wl_supported_rates[i] > attrp->wa_speed)
			attrp->wa_speed = wlp->wl_supported_rates[i];
	}
	if (attrp->wa_speed > 0)
		attrp->wa_valid |= DLADM_WLAN_ATTR_SPEED;

	if (do_convert_chan((wl_phy_conf_t *)&wlp->wl_phy_conf,
	    &attrp->wa_channel))
		attrp->wa_valid |= DLADM_WLAN_ATTR_CHANNEL;
}

dladm_status_t
dladm_wlan_scan(const char *link, void *arg,
    boolean_t (*func)(void *, dladm_wlan_attr_t *))
{
	int			fd, i;
	uint32_t		count;
	wl_ess_conf_t		*wlp;
	wldp_t 			*gbuf;
	dladm_wlan_attr_t	wlattr;
	dladm_status_t		status;
	boolean_t		connected;

	if ((fd = open_link(link)) < 0)
		return (DLADM_STATUS_LINKINVAL);

	if ((gbuf = malloc(MAX_BUF_LEN)) == NULL) {
		status = DLADM_STATUS_NOMEM;
		goto done;
	}

	if (do_get_linkstatus(fd, gbuf) < 0) {
		status = DLADM_STATUS_FAILED;
		goto done;
	}
	connected = IS_CONNECTED(gbuf);

	if (do_scan(fd, gbuf) < 0) {
		status = DLADM_STATUS_FAILED;
		goto done;
	}

	if (do_get_esslist(fd, gbuf) < 0) {
		status = DLADM_STATUS_FAILED;
		goto done;
	}

	wlp = ((wl_ess_list_t *)gbuf->wldp_buf)->wl_ess_list_ess;
	count = ((wl_ess_list_t *)(gbuf->wldp_buf))->wl_ess_list_num;

	for (i = 0; i < count; i++, wlp++) {
		fill_wlan_attr(wlp, &wlattr);
		if (!func(arg, &wlattr))
			break;
	}

	if (!connected) {
		if (do_get_linkstatus(fd, gbuf) < 0) {
			status = DLADM_STATUS_FAILED;
			goto done;
		}
		if (IS_CONNECTED(gbuf))
			(void) do_disconnect(fd, gbuf);
	}

	status = DLADM_STATUS_OK;
done:
	free(gbuf);
	(void) close(fd);
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

static dladm_status_t
do_connect(int fd, wldp_t *gbuf, dladm_wlan_attr_t *attrp,
    boolean_t create_ibss, void *keys, uint_t key_count, int timeout)
{
	dladm_wlan_secmode_t		secmode;
	dladm_wlan_auth_t		authmode;
	dladm_wlan_bsstype_t		bsstype;
	dladm_wlan_essid_t		essid;
	boolean_t		essid_valid = B_FALSE;
	dladm_wlan_channel_t		channel;
	hrtime_t		start;

	if ((attrp->wa_valid & DLADM_WLAN_ATTR_CHANNEL) != 0) {
		channel = attrp->wa_channel;
		if (do_set_channel(fd, gbuf, &channel) < 0)
			goto fail;
	}

	secmode = ((attrp->wa_valid & DLADM_WLAN_ATTR_SECMODE) != 0) ?
	    attrp->wa_secmode : DLADM_WLAN_SECMODE_NONE;

	if (do_set_encryption(fd, gbuf, &secmode) < 0)
		goto fail;

	authmode = ((attrp->wa_valid & DLADM_WLAN_ATTR_AUTH) != 0) ?
	    attrp->wa_auth : DLADM_WLAN_AUTH_OPEN;

	if (do_set_authmode(fd, gbuf, &authmode) < 0)
		goto fail;

	bsstype = ((attrp->wa_valid & DLADM_WLAN_ATTR_BSSTYPE) != 0) ?
	    attrp->wa_bsstype : DLADM_WLAN_BSSTYPE_BSS;

	if (do_set_bsstype(fd, gbuf, &bsstype) < 0)
		goto fail;

	if (secmode == DLADM_WLAN_SECMODE_WEP) {
		if (keys == NULL || key_count == 0 || key_count > MAX_NWEPKEYS)
			return (DLADM_STATUS_BADARG);
		if (do_set_wepkey(fd, gbuf, keys, key_count) < 0)
			goto fail;
	}

	if (create_ibss) {
		if (do_set_channel(fd, gbuf, &channel) < 0)
			goto fail;

		if (do_set_createibss(fd, gbuf, &create_ibss) < 0)
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

	if (!essid_valid)
		return (DLADM_STATUS_FAILED);
	if (do_set_essid(fd, gbuf, &essid) < 0)
		goto fail;

	start = gethrtime();
	for (;;) {
		if (do_get_linkstatus(fd, gbuf) < 0)
			goto fail;

		if (IS_CONNECTED(gbuf))
			break;

		(void) poll(NULL, 0, DLADM_WLAN_CONNECT_POLLRATE);
		if ((timeout >= 0) && (gethrtime() - start) /
		    NANOSEC >= timeout)
			return (DLADM_STATUS_TIMEDOUT);
	}
	return (DLADM_STATUS_OK);
fail:
	return (dladm_wlan_wlresult2status(gbuf));
}

dladm_status_t
dladm_wlan_connect(const char *link, dladm_wlan_attr_t *attrp,
    int timeout, void *keys, uint_t key_count, uint_t flags)
{
	int			fd, i;
	wldp_t 			*gbuf = NULL;
	connect_state_t		state = {0, NULL, NULL};
	attr_node_t		*nodep = NULL;
	boolean_t		create_ibss, set_authmode;
	dladm_wlan_attr_t	**wl_list = NULL;
	dladm_status_t		status = DLADM_STATUS_FAILED;

	if ((fd = open_link(link)) < 0)
		return (DLADM_STATUS_LINKINVAL);

	if ((gbuf = malloc(MAX_BUF_LEN)) == NULL) {
		status = DLADM_STATUS_NOMEM;
		goto done;
	}

	if (do_get_linkstatus(fd, gbuf) < 0) {
		status = DLADM_STATUS_FAILED;
		goto done;
	}

	if (IS_CONNECTED(gbuf)) {
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
		status = do_connect(fd, gbuf, attrp,
		    create_ibss, keys, key_count, timeout);
		goto done;
	}

	state.cs_attr = attrp;
	state.cs_list = NULL;
	state.cs_count = 0;

	status = dladm_wlan_scan(link, &state, connect_cb);
	if (status != DLADM_STATUS_OK)
		goto done;

	if (state.cs_count == 0) {
		if (!create_ibss) {
			status = DLADM_STATUS_NOTFOUND;
			goto done;
		}
		status = do_connect(fd, gbuf, attrp, create_ibss,
		    keys, key_count, timeout);
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

		status = do_connect(fd, gbuf, ap, create_ibss, keys,
		    key_count, timeout);
		if (status == DLADM_STATUS_OK)
			break;

		if (!set_authmode) {
			ap->wa_auth = DLADM_WLAN_AUTH_SHARED;
			ap->wa_valid |= DLADM_WLAN_ATTR_AUTH;
			status = do_connect(fd, gbuf, ap, create_ibss, keys,
			    key_count, timeout);
			if (status == DLADM_STATUS_OK)
				break;
		}
	}
done:
	if ((status != DLADM_STATUS_OK) && (status != DLADM_STATUS_ISCONN))
		(void) do_disconnect(fd, gbuf);

	while (state.cs_list != NULL) {
		nodep = state.cs_list;
		state.cs_list = nodep->an_next;
		free(nodep);
	}
	free(gbuf);
	free(wl_list);
	(void) close(fd);
	return (status);
}

dladm_status_t
dladm_wlan_disconnect(const char *link)
{
	int		fd;
	wldp_t		*gbuf;
	dladm_status_t	status;

	if ((fd = open_link(link)) < 0)
		return (DLADM_STATUS_BADARG);

	if ((gbuf = malloc(MAX_BUF_LEN)) == NULL) {
		status = DLADM_STATUS_NOMEM;
		goto done;
	}

	if (do_get_linkstatus(fd, gbuf) < 0) {
		status = DLADM_STATUS_FAILED;
		goto done;
	}

	if (!IS_CONNECTED(gbuf)) {
		status = DLADM_STATUS_NOTCONN;
		goto done;
	}

	if (do_disconnect(fd, gbuf) < 0) {
		status = DLADM_STATUS_FAILED;
		goto done;
	}

	if (do_get_linkstatus(fd, gbuf) < 0) {
		status = DLADM_STATUS_FAILED;
		goto done;
	}

	if (IS_CONNECTED(gbuf)) {
		status = DLADM_STATUS_FAILED;
		goto done;
	}

	status = DLADM_STATUS_OK;
done:
	free(gbuf);
	(void) close(fd);
	return (status);
}

typedef struct dladm_wlan_linkname {
	char			wl_name[MAXNAMELEN];
	struct dladm_wlan_linkname	*wl_next;
} dladm_wlan_linkname_t;

typedef struct dladm_wlan_walk {
	dladm_wlan_linkname_t	*ww_list;
	dladm_status_t		ww_status;
} dladm_wlan_walk_t;

/* ARGSUSED */
static int
append_linkname(di_node_t node, di_minor_t minor, void *arg)
{
	dladm_wlan_walk_t		*statep = arg;
	dladm_wlan_linkname_t	**lastp = &statep->ww_list;
	dladm_wlan_linkname_t	*wlp = *lastp;
	char			name[MAXNAMELEN];

	(void) snprintf(name, MAXNAMELEN, "%s%d",
	    di_driver_name(node), di_instance(node));

	while (wlp != NULL) {
		if (strcmp(wlp->wl_name, name) == 0)
			return (DI_WALK_CONTINUE);

		lastp = &wlp->wl_next;
		wlp = wlp->wl_next;
	}
	if ((wlp = malloc(sizeof (*wlp))) == NULL) {
		statep->ww_status = DLADM_STATUS_NOMEM;
		return (DI_WALK_CONTINUE);
	}

	(void) strlcpy(wlp->wl_name, name, MAXNAMELEN);
	wlp->wl_next = NULL;
	*lastp = wlp;

	return (DI_WALK_CONTINUE);
}

dladm_status_t
dladm_wlan_walk(void *arg, boolean_t (*func)(void *, const char *))
{
	di_node_t		root;
	dladm_wlan_walk_t		state;
	dladm_wlan_linkname_t	*wlp, *wlp_next;
	boolean_t		cont = B_TRUE;

	if ((root = di_init("/", DINFOCACHE)) == DI_NODE_NIL)
		return (DLADM_STATUS_FAILED);

	state.ww_list = NULL;
	state.ww_status = DLADM_STATUS_OK;
	(void) di_walk_minor(root, DDI_NT_NET_WIFI, DI_CHECK_ALIAS,
	    &state, append_linkname);
	di_fini(root);

	for (wlp = state.ww_list; wlp != NULL; wlp = wlp_next) {
		/*
		 * NOTE: even if (*func)() returns B_FALSE, the loop continues
		 * since all memory must be freed.
		 */
		if (cont)
			cont = (*func)(arg, wlp->wl_name);
		wlp_next = wlp->wl_next;
		free(wlp);
	}
	return (state.ww_status);
}

dladm_status_t
dladm_wlan_get_linkattr(const char *link, dladm_wlan_linkattr_t *attrp)
{
	int			fd;
	wldp_t			*gbuf;
	wl_rssi_t		signal;
	wl_bss_type_t		bsstype;
	wl_authmode_t		authmode;
	wl_encryption_t		encryption;
	wl_rates_t		*ratesp;
	dladm_wlan_attr_t	*wl_attrp;
	dladm_status_t		status = DLADM_STATUS_FAILED;

	if (attrp == NULL)
		return (DLADM_STATUS_BADARG);

	if ((fd = open_link(link)) < 0)
		return (DLADM_STATUS_LINKINVAL);

	if ((gbuf = malloc(MAX_BUF_LEN)) == NULL) {
		status = DLADM_STATUS_NOMEM;
		goto done;
	}

	(void) memset(attrp, 0, sizeof (*attrp));
	wl_attrp = &attrp->la_wlan_attr;

	if (do_get_linkstatus(fd, gbuf) < 0)
		goto done;

	attrp->la_valid |= DLADM_WLAN_LINKATTR_STATUS;
	if (!IS_CONNECTED(gbuf)) {
		attrp->la_status = DLADM_WLAN_LINKSTATUS_DISCONNECTED;
		status = DLADM_STATUS_OK;
		goto done;
	}
	attrp->la_status = DLADM_WLAN_LINKSTATUS_CONNECTED;

	if (do_get_essid(fd, gbuf) < 0)
		goto done;

	(void) strlcpy(wl_attrp->wa_essid.we_bytes,
	    ((wl_essid_t *)(gbuf->wldp_buf))->wl_essid_essid,
	    DLADM_WLAN_MAX_ESSID_LEN);

	wl_attrp->wa_valid |= DLADM_WLAN_ATTR_ESSID;

	if (do_get_bssid(fd, gbuf) < 0)
		goto done;

	(void) memcpy(wl_attrp->wa_bssid.wb_bytes, gbuf->wldp_buf,
	    DLADM_WLAN_BSSID_LEN);

	wl_attrp->wa_valid |= DLADM_WLAN_ATTR_BSSID;

	if (do_get_encryption(fd, gbuf) < 0)
		goto done;

	encryption = *(wl_encryption_t *)(gbuf->wldp_buf);
	wl_attrp->wa_valid |= DLADM_WLAN_ATTR_SECMODE;

	switch (encryption) {
	case WL_NOENCRYPTION:
		wl_attrp->wa_secmode = DLADM_WLAN_SECMODE_NONE;
		break;
	case WL_ENC_WEP:
		wl_attrp->wa_secmode = DLADM_WLAN_SECMODE_WEP;
		break;
	default:
		wl_attrp->wa_valid &= ~DLADM_WLAN_ATTR_SECMODE;
		break;
	}

	if (do_get_signal(fd, gbuf) < 0)
		goto done;

	signal = *(wl_rssi_t *)(gbuf->wldp_buf);
	wl_attrp->wa_valid |= DLADM_WLAN_ATTR_STRENGTH;
	wl_attrp->wa_strength = DLADM_WLAN_SIGNAL2STRENGTH(signal);

	if (do_get_rate(fd, gbuf) < 0)
		goto done;

	ratesp = (wl_rates_t *)(gbuf->wldp_buf);
	if (ratesp->wl_rates_num > 0) {
		uint_t	i, r = 0;

		for (i = 0; i < ratesp->wl_rates_num; i++) {
			if (ratesp->wl_rates_rates[i] > r)
				r = ratesp->wl_rates_rates[i];
		}
		wl_attrp->wa_speed = r;
		wl_attrp->wa_valid |= DLADM_WLAN_ATTR_SPEED;
	}

	if (do_get_authmode(fd, gbuf) < 0)
		goto done;

	authmode = *(wl_authmode_t *)(gbuf->wldp_buf);
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

	if (do_get_bsstype(fd, gbuf) < 0)
		goto done;

	bsstype = *(wl_bss_type_t *)(gbuf->wldp_buf);
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

	if (do_get_mode(fd, gbuf) < 0)
		goto done;

	wl_attrp->wa_mode = do_convert_mode((wl_phy_conf_t *)(gbuf->wldp_buf));
	wl_attrp->wa_valid |= DLADM_WLAN_ATTR_MODE;
	if (wl_attrp->wa_mode != DLADM_WLAN_MODE_NONE)
		wl_attrp->wa_valid |= DLADM_WLAN_ATTR_MODE;

	attrp->la_valid |= DLADM_WLAN_LINKATTR_WLAN;
	status = DLADM_STATUS_OK;

done:
	free(gbuf);
	(void) close(fd);
	return (status);
}

boolean_t
dladm_wlan_is_valid(const char *link)
{
	int fd = open_link(link);

	if (fd < 0)
		return (B_FALSE);

	(void) close(fd);
	return (B_TRUE);
}

/* ARGSUSED */
static dladm_status_t
do_check_prop(int fd, wldp_t *guf, prop_desc_t *pdp, char **prop_val,
    uint_t val_cnt, val_desc_t **vdpp)
{
	int		i;
	val_desc_t	*vdp;

	if (pdp->pd_nmodval == 0)
		return (DLADM_STATUS_PROPRDONLY);

	if (val_cnt != 1)
		return (DLADM_STATUS_BADVALCNT);

	for (i = 0; i < pdp->pd_nmodval; i++)
		if (strcasecmp(*prop_val, pdp->pd_modval[i].vd_name) == 0)
			break;

	if (i == pdp->pd_nmodval)
		return (DLADM_STATUS_BADVAL);

	vdp = malloc(sizeof (val_desc_t));
	if (vdp == NULL)
		return (DLADM_STATUS_NOMEM);

	(void) memcpy(vdp, &pdp->pd_modval[i], sizeof (val_desc_t));
	*vdpp = vdp;
	return (DLADM_STATUS_OK);
}

static dladm_status_t
do_set_prop(int fd, wldp_t *gbuf, prop_desc_t *pdp,
    char **prop_val, uint_t val_cnt)
{
	dladm_status_t	status;
	val_desc_t	*vdp = NULL;
	uint_t		cnt;

	if (pdp->pd_set == NULL)
		return (DLADM_STATUS_PROPRDONLY);

	if (prop_val != NULL) {
		status = pdp->pd_check(fd, gbuf, pdp, prop_val,
		    val_cnt, &vdp);

		if (status != DLADM_STATUS_OK)
			return (status);

		cnt = val_cnt;
	} else {
		if (pdp->pd_defval.vd_name == NULL)
			return (DLADM_STATUS_NOTSUP);

		if ((vdp = malloc(sizeof (val_desc_t))) == NULL)
			return (DLADM_STATUS_NOMEM);

		*vdp = pdp->pd_defval;
		cnt = 1;
	}
	status = pdp->pd_set(fd, gbuf, vdp, cnt);
	if (status == DLADM_STATUS_OK) {
		/*
		 * Some ioctls return 0 but store error code in
		 * wldp_result. Need to fix them.
		 */
		if (gbuf->wldp_result != WL_SUCCESS)
			status = dladm_wlan_wlresult2status(gbuf);
	}
	free(vdp);
	return (status);
}

dladm_status_t
dladm_wlan_set_prop(const char *link, const char *prop_name,
    char **prop_val, uint_t val_cnt, char **errprop)
{
	int		fd, i;
	wldp_t		*gbuf = NULL;
	boolean_t	found = B_FALSE;
	dladm_status_t	status = DLADM_STATUS_OK;

	if ((prop_name == NULL && prop_val != NULL) ||
	    (prop_val != NULL && val_cnt == 0))
		return (DLADM_STATUS_BADARG);

	if ((fd = open_link(link)) < 0)
		return (DLADM_STATUS_LINKINVAL);

	if ((gbuf = malloc(MAX_BUF_LEN)) == NULL) {
		status = DLADM_STATUS_NOMEM;
		goto done;
	}

	for (i = 0; i < DLADM_WLAN_MAX_PROPS; i++) {
		prop_desc_t	*pdp = &prop_table[i];
		dladm_status_t	s;

		if (prop_name != NULL &&
		    (strcasecmp(prop_name, pdp->pd_name) != 0))
			continue;

		found = B_TRUE;
		s = do_set_prop(fd, gbuf, pdp, prop_val, val_cnt);

		if (prop_name != NULL) {
			status = s;
			break;
		} else {
			if (s != DLADM_STATUS_OK &&
			    s != DLADM_STATUS_NOTSUP) {
				if (errprop != NULL)
					*errprop = pdp->pd_name;
				status = s;
				break;
			}
		}
	}
	if (!found)
		status = DLADM_STATUS_NOTFOUND;
done:
	free(gbuf);
	(void) close(fd);
	return (status);
}

/* ARGSUSED */
dladm_status_t
dladm_wlan_walk_prop(const char *link, void *arg,
    boolean_t (*func)(void *, const char *))
{
	int	i;

	for (i = 0; i < DLADM_WLAN_MAX_PROPS; i++) {
		if (!func(arg, prop_table[i].pd_name))
			break;
	}
	return (DLADM_STATUS_OK);
}

dladm_status_t
dladm_wlan_get_prop(const char *link, dladm_prop_type_t type,
    const char *prop_name, char **prop_val, uint_t *val_cnt)
{
	int		fd;
	int		i;
	wldp_t		*gbuf;
	dladm_status_t	status;
	uint_t		cnt;
	prop_desc_t	*pdp;

	if (prop_val == NULL || val_cnt == NULL || *val_cnt == 0)
		return (DLADM_STATUS_BADARG);

	for (i = 0; i < DLADM_WLAN_MAX_PROPS; i++)
		if (strcasecmp(prop_name, prop_table[i].pd_name) == 0)
			break;

	if (i == DLADM_WLAN_MAX_PROPS)
		return (DLADM_STATUS_NOTFOUND);

	if ((fd = open_link(link)) < 0)
		return (DLADM_STATUS_LINKINVAL);

	if ((gbuf = malloc(MAX_BUF_LEN)) == NULL) {
		status = DLADM_STATUS_NOMEM;
		goto done;
	}
	pdp = &prop_table[i];
	status = DLADM_STATUS_OK;

	switch (type) {
	case DLADM_PROP_VAL_CURRENT:
		status = pdp->pd_get(fd, gbuf, prop_val, val_cnt);
		break;

	case DLADM_PROP_VAL_DEFAULT:
		if (pdp->pd_defval.vd_name == NULL) {
			status = DLADM_STATUS_NOTSUP;
			break;
		}
		(void) strcpy(*prop_val, pdp->pd_defval.vd_name);
		*val_cnt = 1;
		break;

	case DLADM_PROP_VAL_MODIFIABLE:
		if (pdp->pd_getmod != NULL) {
			status = pdp->pd_getmod(fd, gbuf, prop_val, val_cnt);
			break;
		}
		cnt = pdp->pd_nmodval;
		if (cnt == 0) {
			status = DLADM_STATUS_NOTSUP;
		} else if (cnt > *val_cnt) {
			status = DLADM_STATUS_TOOSMALL;
		} else {
			for (i = 0; i < cnt; i++) {
				(void) strcpy(prop_val[i],
				    pdp->pd_modval[i].vd_name);
			}
			*val_cnt = cnt;
		}
		break;
	default:
		status = DLADM_STATUS_BADARG;
		break;
	}
done:
	free(gbuf);
	(void) close(fd);
	return (status);
}

static boolean_t
find_val_by_name(const char *str, val_desc_t *vdp, uint_t cnt, uint_t *valp)
{
	int	i;

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
	int	i;

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
	if (str[0] == '\0')
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

	if (!find_val_by_name(str, linkstatus_vals, VALCNT(linkstatus_vals),
	    &val))
		return (DLADM_STATUS_BADARG);

	*linkstatus = (dladm_wlan_linkstatus_t)val;
	return (DLADM_STATUS_OK);
}

static int
do_ioctl(int fd, wldp_t *gbuf, uint_t id, size_t len, uint_t cmd, size_t cmdlen)
{
	int			rc;
	struct	strioctl	stri;

	gbuf->wldp_type = NET_802_11;
	gbuf->wldp_id	= id;
	gbuf->wldp_length = len;

	stri.ic_timout	= 0;
	stri.ic_dp	= (char *)gbuf;
	stri.ic_cmd	= cmd;
	stri.ic_len	= cmdlen;

	if ((rc = ioctl(fd, I_STR, &stri)) != 0) {
		if (rc > 0)
			errno = rc;
		return (-1);
	}
	return (0);
}

static int
do_get_ioctl(int fd, wldp_t *gbuf, uint_t id)
{
	(void) memset(gbuf, 0, MAX_BUF_LEN);
	return (do_ioctl(fd, gbuf, id, MAX_BUF_LEN, WLAN_GET_PARAM,
	    MAX_BUF_LEN));
}

static int
do_set_ioctl(int fd, wldp_t *gbuf, uint_t id, void *buf, uint_t buflen)
{
	(void) memset(gbuf, 0, MAX_BUF_LEN);
	(void) memcpy(gbuf->wldp_buf, buf, buflen);
	buflen += WIFI_BUF_OFFSET;
	return (do_ioctl(fd, gbuf, id, buflen, WLAN_SET_PARAM, buflen));
}

static int
do_cmd_ioctl(int fd, wldp_t *gbuf, uint_t cmd)
{
	(void) memset(gbuf, 0, MAX_BUF_LEN);
	return (do_ioctl(fd, gbuf, cmd, sizeof (wldp_t), WLAN_COMMAND,
	    sizeof (wldp_t)));
}

static int
do_scan(int fd, wldp_t *gbuf)
{
	return (do_cmd_ioctl(fd, gbuf, WL_SCAN));
}

static int
do_disconnect(int fd, wldp_t *gbuf)
{
	return (do_cmd_ioctl(fd, gbuf, WL_DISASSOCIATE));
}

static int
do_get_esslist(int fd, wldp_t *gbuf)
{
	(void) memset(gbuf, 0, MAX_BUF_LEN);
	return (do_ioctl(fd, gbuf, WL_ESS_LIST, MAX_BUF_LEN,
	    WLAN_GET_PARAM, sizeof (wldp_t)));
}

static int
do_get_bssid(int fd, wldp_t *gbuf)
{
	return (do_get_ioctl(fd, gbuf, WL_BSSID));
}

static int
do_get_essid(int fd, wldp_t *gbuf)
{
	return (do_get_ioctl(fd, gbuf, WL_ESSID));
}

static int
do_get_bsstype(int fd, wldp_t *gbuf)
{
	return (do_get_ioctl(fd, gbuf, WL_BSS_TYPE));
}

static int
do_get_linkstatus(int fd, wldp_t *gbuf)
{
	return (do_get_ioctl(fd, gbuf, WL_LINKSTATUS));
}

static int
do_get_rate(int fd, wldp_t *gbuf)
{
	return (do_get_ioctl(fd, gbuf, WL_DESIRED_RATES));
}

static int
do_get_phyconf(int fd, wldp_t *gbuf)
{
	return (do_get_ioctl(fd, gbuf, WL_PHY_CONFIG));
}

static int
do_get_powermode(int fd, wldp_t *gbuf)
{
	return (do_get_ioctl(fd, gbuf, WL_POWER_MODE));
}

static int
do_get_radio(int fd, wldp_t *gbuf)
{
	return (do_get_ioctl(fd, gbuf, WL_RADIO));
}

static int
do_get_authmode(int fd, wldp_t *gbuf)
{
	return (do_get_ioctl(fd, gbuf, WL_AUTH_MODE));
}

static int
do_get_encryption(int fd, wldp_t *gbuf)
{
	return (do_get_ioctl(fd, gbuf, WL_ENCRYPTION));
}

static int
do_get_signal(int fd, wldp_t *gbuf)
{
	return (do_get_ioctl(fd, gbuf, WL_RSSI));
}

static int
do_get_mode(int fd, wldp_t *gbuf)
{
	return (do_get_ioctl(fd, gbuf, WL_PHY_CONFIG));
}

static dladm_status_t
do_get_rate_common(wldp_t *gbuf, char **prop_val, uint_t *val_cnt)
{
	wl_rates_t	*wrp = (wl_rates_t *)gbuf->wldp_buf;
	uint_t		cnt = wrp->wl_rates_num;
	uint_t		i;

	if (cnt > *val_cnt)
		return (DLADM_STATUS_TOOSMALL);
	if (wrp->wl_rates_rates[0] == 0) {
		prop_val[0][0] = '\0';
		*val_cnt = 1;
		return (DLADM_STATUS_OK);
	}

	for (i = 0; i < cnt; i++) {
		(void) snprintf(prop_val[i], DLADM_STRSIZE, "%.*f",
		    wrp->wl_rates_rates[i] % 2,
		    (float)wrp->wl_rates_rates[i] / 2);
	}
	*val_cnt = cnt;
	return (DLADM_STATUS_OK);
}

static dladm_status_t
do_get_rate_prop(int fd, wldp_t *gbuf, char **prop_val, uint_t *val_cnt)
{
	if (do_get_rate(fd, gbuf) < 0)
		return (dladm_wlan_wlresult2status(gbuf));

	return (do_get_rate_common(gbuf, prop_val, val_cnt));
}

static dladm_status_t
do_get_rate_mod(int fd, wldp_t *gbuf, char **prop_val, uint_t *val_cnt)
{
	if (do_get_ioctl(fd, gbuf, WL_SUPPORTED_RATES) < 0)
		return (DLADM_STATUS_FAILED);

	return (do_get_rate_common(gbuf, prop_val, val_cnt));
}

static dladm_status_t
do_get_channel_prop(int fd, wldp_t *gbuf, char **prop_val, uint_t *val_cnt)
{
	uint32_t	channel;

	if (do_get_phyconf(fd, gbuf) < 0)
		return (dladm_wlan_wlresult2status(gbuf));

	if (!do_convert_chan((wl_phy_conf_t *)gbuf->wldp_buf, &channel))
		return (DLADM_STATUS_NOTFOUND);

	(void) snprintf(*prop_val, DLADM_STRSIZE, "%u", channel);
	*val_cnt = 1;

	return (DLADM_STATUS_OK);
}

static dladm_status_t
do_get_powermode_prop(int fd, wldp_t *gbuf, char **prop_val, uint_t *val_cnt)
{
	wl_ps_mode_t	*mode;
	const char	*s;

	if (do_get_powermode(fd, gbuf) < 0)
		return (dladm_wlan_wlresult2status(gbuf));

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
		return (DLADM_STATUS_NOTFOUND);
	}
	(void) snprintf(*prop_val, DLADM_STRSIZE, "%s", s);
	*val_cnt = 1;

	return (DLADM_STATUS_OK);
}

static dladm_status_t
do_get_radio_prop(int fd, wldp_t *gbuf, char **prop_val, uint_t *val_cnt)
{
	wl_radio_t	radio;
	const char	*s;

	if (do_get_radio(fd, gbuf) < 0)
		return (dladm_wlan_wlresult2status(gbuf));

	radio = *(wl_radio_t *)(gbuf->wldp_buf);
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

	return (DLADM_STATUS_OK);
}

static int
do_set_bsstype(int fd, wldp_t *gbuf, dladm_wlan_bsstype_t *bsstype)
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
	return (do_set_ioctl(fd, gbuf, WL_BSS_TYPE, &ibsstype,
	    sizeof (ibsstype)));
}

static int
do_set_authmode(int fd, wldp_t *gbuf, dladm_wlan_auth_t *auth)
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
		return (-1);
	}
	return (do_set_ioctl(fd, gbuf, WL_AUTH_MODE, &auth_mode,
	    sizeof (auth_mode)));
}

static int
do_set_encryption(int fd, wldp_t *gbuf, dladm_wlan_secmode_t *secmode)
{
	wl_encryption_t	encryption;

	switch (*secmode) {
	case DLADM_WLAN_SECMODE_NONE:
		encryption = WL_NOENCRYPTION;
		break;
	case DLADM_WLAN_SECMODE_WEP:
		encryption = WL_ENC_WEP;
		break;
	default:
		return (-1);
	}
	return (do_set_ioctl(fd, gbuf, WL_ENCRYPTION, &encryption,
	    sizeof (encryption)));
}

static int
do_set_wepkey(int fd, wldp_t *gbuf, dladm_wlan_wepkey_t *keys,
    uint_t key_count)
{
	int			i;
	wl_wep_key_t		*wkp;
	wl_wep_key_tab_t	wepkey_tab;
	dladm_wlan_wepkey_t	*kp;

	if (key_count == 0 || key_count > MAX_NWEPKEYS || keys == NULL)
		return (-1);

	(void) memset(wepkey_tab, 0, sizeof (wepkey_tab));
	for (i = 0; i < MAX_NWEPKEYS; i++)
		wepkey_tab[i].wl_wep_operation = WL_NUL;

	for (i = 0; i < key_count; i++) {
		kp = &keys[i];
		if (kp->wk_idx == 0 || kp->wk_idx > MAX_NWEPKEYS)
			return (-1);
		if (kp->wk_len != DLADM_WLAN_WEPKEY64_LEN &&
		    kp->wk_len != DLADM_WLAN_WEPKEY128_LEN)
			return (-1);

		wkp = &wepkey_tab[kp->wk_idx - 1];
		wkp->wl_wep_operation = WL_ADD;
		wkp->wl_wep_length = kp->wk_len;
		(void) memcpy(wkp->wl_wep_key, kp->wk_val, kp->wk_len);
	}

	return (do_set_ioctl(fd, gbuf, WL_WEP_KEY_TAB, &wepkey_tab,
	    sizeof (wepkey_tab)));
}

static int
do_set_essid(int fd, wldp_t *gbuf, dladm_wlan_essid_t *essid)
{
	wl_essid_t	iessid;

	(void) memset(&iessid, 0, sizeof (essid));

	if (essid != NULL && essid->we_bytes[0] != '\0') {
		iessid.wl_essid_length = strlen(essid->we_bytes);
		(void) strlcpy(iessid.wl_essid_essid, essid->we_bytes,
		    sizeof (iessid.wl_essid_essid));
	} else {
		return (-1);
	}
	return (do_set_ioctl(fd, gbuf, WL_ESSID, &iessid, sizeof (iessid)));
}

/* ARGSUSED */
static dladm_status_t
do_check_rate(int fd, wldp_t *gbuf, prop_desc_t *pdp, char **prop_val,
    uint_t val_cnt, val_desc_t **vdpp)
{
	int		i;
	uint_t		modval_cnt = MAX_SUPPORT_RATES;
	char		*buf, **modval;
	dladm_status_t	status;
	val_desc_t	*vdp = NULL;

	if (val_cnt != 1)
		return (DLADM_STATUS_BADVALCNT);

	buf = malloc((sizeof (char *) + DLADM_STRSIZE) * MAX_SUPPORT_RATES);
	if (buf == NULL)
		goto done;

	modval = (char **)(void *)buf;
	for (i = 0; i < MAX_SUPPORT_RATES; i++) {
		modval[i] = buf + sizeof (char *) * MAX_SUPPORT_RATES +
		    i * DLADM_STRSIZE;
	}

	status = do_get_rate_mod(fd, gbuf, modval, &modval_cnt);
	if (status != DLADM_STATUS_OK)
		goto done;

	vdp = malloc(sizeof (val_desc_t));
	if (vdp == NULL) {
		status = DLADM_STATUS_NOMEM;
		goto done;
	}

	for (i = 0; i < modval_cnt; i++) {
		if (strcasecmp(*prop_val, modval[i]) == 0) {
			vdp->vd_val = (uint_t)(atof(*prop_val) * 2);
			status = DLADM_STATUS_OK;
			*vdpp = vdp;
			vdp = NULL;
			break;
		}
	}
	if (i == modval_cnt)
		status = DLADM_STATUS_BADVAL;
done:
	free(buf);
	free(vdp);
	return (status);
}

static dladm_status_t
do_set_rate_prop(int fd, wldp_t *gbuf, val_desc_t *vdp, uint_t val_cnt)
{
	dladm_wlan_rates_t	rates;

	if (val_cnt != 1)
		return (DLADM_STATUS_BADVALCNT);

	rates.wr_cnt = 1;
	rates.wr_rates[0] = vdp[0].vd_val;

	if (do_set_rate(fd, gbuf, &rates) < 0)
		return (dladm_wlan_wlresult2status(gbuf));

	return (DLADM_STATUS_OK);
}

static int
do_set_rate(int fd, wldp_t *gbuf, dladm_wlan_rates_t *rates)
{
	int		i;
	uint_t		len;
	wl_rates_t	*wrp = (wl_rates_t *)gbuf->wldp_buf;

	(void) memset(gbuf, 0, MAX_BUF_LEN);

	for (i = 0; i < rates->wr_cnt; i++)
		wrp->wl_rates_rates[i] = rates->wr_rates[i];
	wrp->wl_rates_num = rates->wr_cnt;

	len = offsetof(wl_rates_t, wl_rates_rates) +
	    (rates->wr_cnt * sizeof (char)) + WIFI_BUF_OFFSET;
	return (do_ioctl(fd, gbuf, WL_DESIRED_RATES, len, WLAN_SET_PARAM, len));
}

/* ARGSUSED */
static dladm_status_t
do_set_powermode_prop(int fd, wldp_t *gbuf, val_desc_t *vdp, uint_t val_cnt)
{
	dladm_wlan_powermode_t powermode = (dladm_wlan_powermode_t)vdp->vd_val;

	if (do_set_powermode(fd, gbuf, &powermode) < 0)
		return (dladm_wlan_wlresult2status(gbuf));

	return (DLADM_STATUS_OK);
}

static int
do_set_powermode(int fd, wldp_t *gbuf, dladm_wlan_powermode_t *pm)
{
	wl_ps_mode_t	ps_mode;

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
		return (-1);
	}
	return (do_set_ioctl(fd, gbuf, WL_POWER_MODE, &ps_mode,
	    sizeof (ps_mode)));
}

/* ARGSUSED */
static dladm_status_t
do_set_radio_prop(int fd, wldp_t *gbuf, val_desc_t *vdp, uint_t val_cnt)
{
	dladm_wlan_radio_t	radio = (dladm_wlan_radio_t)vdp->vd_val;

	if (do_set_radio(fd, gbuf, &radio) < 0)
		return (dladm_wlan_wlresult2status(gbuf));

	return (DLADM_STATUS_OK);
}

static int
do_set_radio(int fd, wldp_t *gbuf, dladm_wlan_radio_t *radio)
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
		return (-1);
	}
	return (do_set_ioctl(fd, gbuf, WL_RADIO, &r, sizeof (r)));
}

static int
do_set_channel(int fd, wldp_t *gbuf, dladm_wlan_channel_t *channel)
{
	wl_phy_conf_t phy_conf;

	if (*channel > MAX_CHANNEL_NUM)
		return (-1);

	(void) memset(&phy_conf, 0xff, sizeof (phy_conf));
	phy_conf.wl_phy_dsss_conf.wl_dsss_channel = *channel;

	return (do_set_ioctl(fd, gbuf, WL_PHY_CONFIG, &phy_conf,
	    sizeof (phy_conf)));
}

static int
do_set_createibss(int fd, wldp_t *gbuf, boolean_t *create_ibss)
{
	wl_create_ibss_t cr = (wl_create_ibss_t)(*create_ibss);

	return (do_set_ioctl(fd, gbuf, WL_CREATE_IBSS, &cr, sizeof (cr)));
}

static void
generate_essid(dladm_wlan_essid_t *essid)
{
	srandom(gethrtime());
	(void) snprintf(essid->we_bytes, DLADM_WLAN_MAX_ESSID_LEN, "%d",
	    random());
}
