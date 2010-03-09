/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#include <sys/param.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/strsun.h>
#include <sys/policy.h>
#include <inet/common.h>
#include <inet/nd.h>
#include <inet/mi.h>
#include <sys/note.h>
#include <sys/mac_provider.h>
#include <inet/wifi_ioctl.h>
#include "net80211_impl.h"

static int wl_set_essid(struct ieee80211com *, const void *);
static void wl_get_essid(struct ieee80211com *, void *);
static int wl_set_bssid(struct ieee80211com *, const void *);
static void wl_get_bssid(struct ieee80211com *, void *);
static int wl_set_bsstype(struct ieee80211com *, const void *);
static void wl_get_bsstype(struct ieee80211com *, void *);
static void wl_get_linkstatus(struct ieee80211com *, void *);
static int wl_set_desrates(struct ieee80211com *, const void *);
static void wl_get_desrates(struct ieee80211com *, void *);
static int wl_set_authmode(struct ieee80211com *, const void *);
static void wl_get_authmode(struct ieee80211com *, void *);
static int wl_set_encrypt(struct ieee80211com *, const void *);
static void wl_get_encrypt(struct ieee80211com *, void *);
static void wl_get_rssi(struct ieee80211com *, void *);
static int wl_set_phy(struct ieee80211com *, const void *);
static int wl_get_phy(struct ieee80211com *, void *);
static void wl_get_capability(struct ieee80211com *, void *);
static int wl_set_wpa(struct ieee80211com *, const void *);
static void wl_get_wpa(struct ieee80211com *, void *);
static void wl_get_scanresults(struct ieee80211com *, void *);
static void wl_get_esslist(struct ieee80211com *, void *);
static int wl_set_wepkey(struct ieee80211com *, const void *);
static int wl_set_optie(struct ieee80211com *, const void *);
static int wl_set_delkey(struct ieee80211com *, const void *);
static int wl_set_mlme(struct ieee80211com *, const void *);
static int wl_set_wpakey(struct ieee80211com *, const void *);
static void wl_get_suprates(struct ieee80211com *, void *);
static int wl_set_createibss(struct ieee80211com *, const void *);
static void wl_get_createibss(struct ieee80211com *, void *);

static size_t
wifi_strnlen(const char *s, size_t n)
{
	size_t i;

	for (i = 0; i < n && s[i] != '\0'; i++)
		/* noop */;
	return (i);
}

/*
 * Initialize an output message block by copying from an
 * input message block. The message is of type wldp_t.
 *    mp     input message block
 *    buflen length of wldp_buf
 */
static void
wifi_setupoutmsg(mblk_t *mp, int buflen)
{
	wldp_t *wp;

	wp = (wldp_t *)mp->b_rptr;
	wp->wldp_length = WIFI_BUF_OFFSET + buflen;
	wp->wldp_result = WL_SUCCESS;
	mp->b_wptr = mp->b_rptr + wp->wldp_length;
}

/*
 * Allocate and initialize an output message.
 */
static mblk_t *
wifi_getoutmsg(mblk_t *mp, uint32_t cmd, int buflen)
{
	mblk_t *mp1;
	int size;

	size = WIFI_BUF_OFFSET;
	if (cmd == WLAN_GET_PARAM)
		size += buflen;	/* to hold output parameters */
	mp1 = allocb(size, BPRI_HI);
	if (mp1 == NULL) {
		ieee80211_err("wifi_getoutbuf: allocb %d bytes failed!\n",
		    size);
		return (NULL);
	}

	bzero(mp1->b_rptr, size);
	bcopy(mp->b_rptr, mp1->b_rptr, WIFI_BUF_OFFSET);
	wifi_setupoutmsg(mp1, size - WIFI_BUF_OFFSET);

	return (mp1);
}

static int
wifi_cfg_essid(struct ieee80211com *ic, uint32_t cmd, mblk_t **mp)
{
	mblk_t *omp;
	wldp_t *inp = (wldp_t *)(*mp)->b_rptr;
	wldp_t *outp;
	wl_essid_t *iw_essid = (wl_essid_t *)inp->wldp_buf;
	wl_essid_t *ow_essid;
	int err = 0;

	if ((omp = wifi_getoutmsg(*mp, cmd, sizeof (wl_essid_t))) == NULL)
		return (ENOMEM);
	outp = (wldp_t *)omp->b_rptr;
	ow_essid = (wl_essid_t *)outp->wldp_buf;

	switch (cmd) {
	case WLAN_GET_PARAM:
		wl_get_essid(ic, ow_essid);
		break;
	case WLAN_SET_PARAM:
		err = wl_set_essid(ic, iw_essid);
		break;
	default:
		ieee80211_err("wifi_cfg_essid: unknown command %x\n", cmd);
		outp->wldp_result = WL_NOTSUPPORTED;
		err = EINVAL;
		break;
	}

	freemsg(*mp);
	*mp = omp;
	return (err);
}

static int
wifi_cfg_bssid(struct ieee80211com *ic, uint32_t cmd, mblk_t **mp)
{
	mblk_t *omp;
	wldp_t *inp = (wldp_t *)(*mp)->b_rptr;
	wldp_t *outp;
	int err = 0;

	if ((omp = wifi_getoutmsg(*mp, cmd, sizeof (wl_bssid_t))) == NULL)
		return (ENOMEM);
	outp = (wldp_t *)omp->b_rptr;

	switch (cmd) {
	case  WLAN_GET_PARAM:
		wl_get_bssid(ic, outp->wldp_buf);
		break;
	case WLAN_SET_PARAM:
		err = wl_set_bssid(ic, inp->wldp_buf);
		ieee80211_dbg(IEEE80211_MSG_CONFIG, "wifi_cfg_bssid: "
		    "set bssid=%s\n",
		    ieee80211_macaddr_sprintf(inp->wldp_buf));
		break;
	default:
		ieee80211_err("wifi_cfg_bssid: unknown command %x\n", cmd);
		outp->wldp_result = WL_NOTSUPPORTED;
		err = EINVAL;
		break;
	}

	freemsg(*mp);
	*mp = omp;
	return (err);
}

static int
wifi_cfg_nodename(struct ieee80211com *ic, uint32_t cmd, mblk_t **mp)
{
	mblk_t *omp;
	wldp_t *inp = (wldp_t *)(*mp)->b_rptr;
	wldp_t *outp;
	wl_nodename_t *iw_name = (wl_nodename_t *)inp->wldp_buf;
	wl_nodename_t *ow_name;
	char *nodename;
	int len, err;

	err = 0;
	if ((omp = wifi_getoutmsg(*mp, cmd, sizeof (wl_nodename_t))) == NULL)
		return (ENOMEM);
	outp = (wldp_t *)omp->b_rptr;
	ow_name = (wl_nodename_t *)outp->wldp_buf;

	switch (cmd) {
	case WLAN_GET_PARAM:
		len = wifi_strnlen((const char *)ic->ic_nickname,
		    IEEE80211_NWID_LEN);
		ow_name->wl_nodename_length = len;
		bcopy(ic->ic_nickname, ow_name->wl_nodename_name, len);
		break;
	case WLAN_SET_PARAM:
		if (iw_name->wl_nodename_length > IEEE80211_NWID_LEN) {
			ieee80211_err("wifi_cfg_nodename: "
			    "node name too long, %u\n",
			    iw_name->wl_nodename_length);
			outp->wldp_result = WL_NOTSUPPORTED;
			err = EINVAL;
			break;
		}
		nodename = iw_name->wl_nodename_name;
		nodename[IEEE80211_NWID_LEN] = 0;
		ieee80211_dbg(IEEE80211_MSG_CONFIG,
		    "wifi_cfg_nodename: set nodename %s, len=%d\n",
		    nodename, iw_name->wl_nodename_length);

		len = iw_name->wl_nodename_length;
		if (len > 0)
			bcopy(nodename, ic->ic_nickname, len);
		if (len < IEEE80211_NWID_LEN)
			ic->ic_nickname[len] = 0;
		break;
	default:
		ieee80211_err("wifi_cfg_nodename: unknown command %x\n", cmd);
		outp->wldp_result = WL_NOTSUPPORTED;
		err = EINVAL;
		break;
	}

	freemsg(*mp);
	*mp = omp;
	return (err);
}

static int
wifi_cfg_phy(struct ieee80211com *ic, uint32_t cmd, mblk_t **mp)
{
	mblk_t *omp;
	wldp_t *inp = (wldp_t *)(*mp)->b_rptr;
	wldp_t *outp;
	wl_phy_conf_t *iw_phy = (wl_phy_conf_t *)inp->wldp_buf;
	wl_phy_conf_t *ow_phy;
	int err = 0;

	if ((omp = wifi_getoutmsg(*mp, cmd, sizeof (wl_phy_conf_t))) == NULL)
		return (ENOMEM);
	outp = (wldp_t *)omp->b_rptr;
	ow_phy = (wl_phy_conf_t *)outp->wldp_buf;

	switch (cmd) {
	case WLAN_GET_PARAM:
		err = wl_get_phy(ic, ow_phy);
		break;

	case WLAN_SET_PARAM:
		err = wl_set_phy(ic, iw_phy);
		break;

	default:
		ieee80211_err("wifi_cfg_phy: unknown command %x\n", cmd);
		outp->wldp_result = WL_NOTSUPPORTED;
		err = EINVAL;
		break;
	} /* switch (cmd) */

	freemsg(*mp);
	*mp = omp;
	return (err);
}

static int
wifi_cfg_wepkey(struct ieee80211com *ic, uint32_t cmd, mblk_t **mp)
{
	mblk_t *omp;
	wldp_t *inp = (wldp_t *)(*mp)->b_rptr;
	wldp_t *outp;
	wl_wep_key_t *iw_wepkey = (wl_wep_key_t *)inp->wldp_buf;
	int err = 0;

	if ((omp = wifi_getoutmsg(*mp, cmd, 0)) == NULL)
		return (ENOMEM);
	outp = (wldp_t *)omp->b_rptr;

	switch (cmd) {
	case WLAN_GET_PARAM:
		outp->wldp_result = WL_WRITEONLY;
		err = EINVAL;
		break;
	case WLAN_SET_PARAM:
		if (inp->wldp_length < sizeof (wl_wep_key_tab_t)) {
			ieee80211_err("wifi_cfg_wepkey: "
			    "parameter too short, %d, expected %d\n",
			    inp->wldp_length, sizeof (wl_wep_key_tab_t));
			outp->wldp_result = WL_NOTSUPPORTED;
			err = EINVAL;
			break;
		}

		err = wl_set_wepkey(ic, iw_wepkey);
		break;
	default:
		ieee80211_err("wifi_cfg_wepkey: unknown command %x\n", cmd);
		outp->wldp_result = WL_NOTSUPPORTED;
		err = EINVAL;
		break;
	}

	freemsg(*mp);
	*mp = omp;
	return (err);
}

static int
wifi_cfg_keyid(struct ieee80211com *ic, uint32_t cmd, mblk_t **mp)
{
	mblk_t *omp;
	wldp_t *inp = (wldp_t *)(*mp)->b_rptr;
	wldp_t *outp;
	wl_wep_key_id_t *iw_kid = (wl_wep_key_id_t *)inp->wldp_buf;
	wl_wep_key_id_t *ow_kid;
	int err = 0;

	if ((omp = wifi_getoutmsg(*mp, cmd, sizeof (wl_wep_key_id_t))) == NULL)
		return (ENOMEM);
	outp = (wldp_t *)omp->b_rptr;
	ow_kid = (wl_wep_key_id_t *)outp->wldp_buf;

	switch (cmd) {
	case WLAN_GET_PARAM:
		*ow_kid = (ic->ic_def_txkey == IEEE80211_KEYIX_NONE) ?
		    0 : ic->ic_def_txkey;
		break;
	case  WLAN_SET_PARAM:
		if (*iw_kid >= MAX_NWEPKEYS) {
			ieee80211_err("wifi_cfg_keyid: "
			    "keyid too large, %u\n", *iw_kid);
			outp->wldp_result = WL_NOTSUPPORTED;
			err = EINVAL;
		} else {
			ieee80211_dbg(IEEE80211_MSG_CONFIG, "wifi_cfg_keyid: "
			    "set keyid=%u\n", *iw_kid);
			ic->ic_def_txkey = *iw_kid;
			err = ENETRESET;
		}
		break;
	default:
		ieee80211_err("wifi_cfg_keyid: unknown command %x\n", cmd);
		outp->wldp_result = WL_NOTSUPPORTED;
		err = EINVAL;
		break;
	}

	freemsg(*mp);
	*mp = omp;
	return (err);
}

static int
wifi_cfg_authmode(struct ieee80211com *ic, uint32_t cmd, mblk_t **mp)
{
	mblk_t *omp;
	wldp_t *inp = (wldp_t *)(*mp)->b_rptr;
	wldp_t *outp;
	wl_authmode_t *iw_auth = (wl_authmode_t *)inp->wldp_buf;
	wl_authmode_t *ow_auth;
	int err = 0;

	if ((omp = wifi_getoutmsg(*mp, cmd, sizeof (wl_authmode_t))) == NULL)
		return (ENOMEM);
	outp = (wldp_t *)omp->b_rptr;
	ow_auth = (wl_authmode_t *)outp->wldp_buf;

	switch (cmd) {
	case WLAN_GET_PARAM:
		wl_get_authmode(ic, ow_auth);
		break;
	case WLAN_SET_PARAM:
		err = wl_set_authmode(ic, iw_auth);
		break;
	default:
		ieee80211_err("wifi_cfg_authmode: unknown command %x\n", cmd);
		outp->wldp_result = WL_NOTSUPPORTED;
		err = EINVAL;
		break;
	}

	freemsg(*mp);
	*mp = omp;
	return (err);
}

static int
wifi_cfg_encrypt(struct ieee80211com *ic, uint32_t cmd, mblk_t **mp)
{
	mblk_t *omp;
	wldp_t *inp = (wldp_t *)(*mp)->b_rptr;
	wldp_t *outp;
	wl_encryption_t *iw_encryp = (wl_encryption_t *)inp->wldp_buf;
	wl_encryption_t *ow_encryp;
	int err = 0;

	if ((omp = wifi_getoutmsg(*mp, cmd, sizeof (wl_encryption_t))) == NULL)
		return (ENOMEM);
	outp = (wldp_t *)omp->b_rptr;
	ow_encryp = (wl_encryption_t *)outp->wldp_buf;

	switch (cmd) {
	case WLAN_GET_PARAM:
		wl_get_encrypt(ic, ow_encryp);
		break;
	case WLAN_SET_PARAM:
		err = wl_set_encrypt(ic, iw_encryp);
		break;
	default:
		ieee80211_err("wifi_cfg_encrypt: unknown command %x\n", cmd);
		outp->wldp_result = WL_NOTSUPPORTED;
		err = EINVAL;
		break;
	}

	freemsg(*mp);
	*mp = omp;
	return (err);
}

static int
wifi_cfg_bsstype(struct ieee80211com *ic, uint32_t cmd, mblk_t **mp)
{
	mblk_t *omp;
	wldp_t *inp = (wldp_t *)(*mp)->b_rptr;
	wldp_t *outp;
	wl_bss_type_t *iw_opmode = (wl_bss_type_t *)inp->wldp_buf;
	wl_bss_type_t *ow_opmode;
	int err = 0;

	if ((omp = wifi_getoutmsg(*mp, cmd, sizeof (wl_bss_type_t))) == NULL)
		return (ENOMEM);
	outp = (wldp_t *)omp->b_rptr;
	ow_opmode = (wl_bss_type_t *)outp->wldp_buf;

	switch (cmd) {
	case WLAN_GET_PARAM:
		wl_get_bsstype(ic, ow_opmode);
		break;
	case  WLAN_SET_PARAM:
		if (*iw_opmode == ic->ic_opmode)
			break;

		err = wl_set_bsstype(ic, iw_opmode);
		break;
	default:
		ieee80211_err("wifi_cfg_bsstype: unknown command %x\n", cmd);
		outp->wldp_result = WL_NOTSUPPORTED;
		err = EINVAL;
		break;
	}

	freemsg(*mp);
	*mp = omp;
	return (err);
}

static int
wifi_cfg_createibss(struct ieee80211com *ic, uint32_t cmd, mblk_t **mp)
{
	mblk_t *omp;
	wldp_t *inp = (wldp_t *)(*mp)->b_rptr;
	wldp_t *outp;
	wl_create_ibss_t *iw_ibss = (wl_create_ibss_t *)inp->wldp_buf;
	wl_create_ibss_t *ow_ibss;
	int err = 0;

	if ((omp = wifi_getoutmsg(*mp, cmd, sizeof (wl_create_ibss_t))) == NULL)
		return (ENOMEM);
	outp = (wldp_t *)omp->b_rptr;
	ow_ibss = (wl_create_ibss_t *)outp->wldp_buf;

	switch (cmd) {
	case WLAN_GET_PARAM:
		wl_get_createibss(ic, ow_ibss);
		break;
	case  WLAN_SET_PARAM:
		err = wl_set_createibss(ic, iw_ibss);
		break;
	default:
		ieee80211_err("wifi_cfg_bsstype: unknown command %x\n", cmd);
		outp->wldp_result = WL_NOTSUPPORTED;
		err = EINVAL;
		break;
	}

	freemsg(*mp);
	*mp = omp;
	return (err);
}

static int
wifi_cfg_linkstatus(struct ieee80211com *ic, uint32_t cmd, mblk_t **mp)
{
	mblk_t *omp;
	wldp_t *outp;
	wl_linkstatus_t *ow_linkstat;
	int err = 0;

	if ((omp = wifi_getoutmsg(*mp, cmd, sizeof (wl_linkstatus_t))) == NULL)
		return (ENOMEM);
	outp = (wldp_t *)omp->b_rptr;
	ow_linkstat = (wl_linkstatus_t *)outp->wldp_buf;

	switch (cmd) {
	case WLAN_GET_PARAM:
		wl_get_linkstatus(ic, ow_linkstat);
		break;
	case WLAN_SET_PARAM:
		outp->wldp_result = WL_READONLY;
		err = EINVAL;
		break;
	default:
		ieee80211_err("wifi_cfg_linkstatus: unknown command %x\n", cmd);
		outp->wldp_result = WL_NOTSUPPORTED;
		err = EINVAL;
		break;
	}

	freemsg(*mp);
	*mp = omp;
	return (err);
}

static int
wifi_cfg_suprates(struct ieee80211com *ic, uint32_t cmd, mblk_t **mp)
{
	mblk_t *omp;
	wldp_t *outp;
	wl_rates_t *ow_rates;
	int err, buflen;

	err = 0;
	/* rate value (wl_rates_rates) is of type char */
	buflen = offsetof(wl_rates_t, wl_rates_rates) +
	    sizeof (char) * IEEE80211_MODE_MAX * IEEE80211_RATE_MAXSIZE;
	if ((omp = wifi_getoutmsg(*mp, cmd, buflen)) == NULL)
		return (ENOMEM);
	outp = (wldp_t *)omp->b_rptr;
	ow_rates = (wl_rates_t *)outp->wldp_buf;

	switch (cmd) {
	case WLAN_GET_PARAM:
		(void) wl_get_suprates(ic, ow_rates);
		break;
	case WLAN_SET_PARAM:
		outp->wldp_result = WL_READONLY;
		err = EINVAL;
		break;
	default:
		ieee80211_err("wifi_cfg_suprates: unknown command %x\n", cmd);
		outp->wldp_result = WL_NOTSUPPORTED;
		err = EINVAL;
		break;
	}

	freemsg(*mp);
	*mp = omp;
	return (err);
}

static int
wifi_cfg_desrates(struct ieee80211com *ic, uint32_t cmd, mblk_t **mp)
{
	wldp_t *inp = (wldp_t *)(*mp)->b_rptr;
	wl_rates_t *iw_rates = (wl_rates_t *)inp->wldp_buf;
	mblk_t *omp;
	wldp_t *outp;
	wl_rates_t *ow_rates;
	int err;

	err = 0;
	if ((omp = wifi_getoutmsg(*mp, cmd, sizeof (wl_rates_t))) == NULL)
		return (ENOMEM);
	outp = (wldp_t *)omp->b_rptr;
	ow_rates = (wl_rates_t *)outp->wldp_buf;

	switch (cmd) {
	case  WLAN_GET_PARAM:
		wl_get_desrates(ic, ow_rates);
		break;
	case  WLAN_SET_PARAM:
		err = wl_set_desrates(ic, iw_rates);
		break;
	default:
		ieee80211_err("wifi_cfg_desrates: unknown command %x\n", cmd);
		outp->wldp_result = WL_NOTSUPPORTED;
		err = EINVAL;
		break;
	}

	freemsg(*mp);
	*mp = omp;
	return (err);
}

/*
 * Rescale device's RSSI value to (0, 15) as required by WiFi
 * driver IOCTLs (PSARC/2003/722)
 */
static wl_rssi_t
wifi_getrssi(struct ieee80211_node *in)
{
	struct ieee80211com *ic = in->in_ic;
	wl_rssi_t rssi, max_rssi;

	rssi = ic->ic_node_getrssi(in);
	max_rssi = (ic->ic_maxrssi == 0) ? IEEE80211_MAXRSSI : ic->ic_maxrssi;
	if (rssi == 0)
		rssi = 0;
	else if (rssi >= max_rssi)
		rssi = MAX_RSSI;
	else
		rssi = rssi * MAX_RSSI / max_rssi + 1;

	return (rssi);
}

static int
wifi_cfg_rssi(struct ieee80211com *ic, uint32_t cmd, mblk_t **mp)
{
	mblk_t *omp;
	wldp_t *outp;
	wl_rssi_t *ow_rssi;
	int err = 0;

	if ((omp = wifi_getoutmsg(*mp, cmd, sizeof (wl_rssi_t))) == NULL)
		return (ENOMEM);
	outp = (wldp_t *)omp->b_rptr;
	ow_rssi = (wl_rssi_t *)outp->wldp_buf;

	switch (cmd) {
	case  WLAN_GET_PARAM:
		*ow_rssi = wifi_getrssi(ic->ic_bss);
		break;
	case  WLAN_SET_PARAM:
		outp->wldp_result = WL_READONLY;
		err = EINVAL;
		break;
	default:
		ieee80211_err("wifi_cfg_rssi: unknown command %x\n", cmd);
		outp->wldp_result = WL_NOTSUPPORTED;
		return (EINVAL);
	}

	freemsg(*mp);
	*mp = omp;
	return (err);
}

/*
 * maximum scan wait time in second.
 * Time spent on scaning one channel is usually 100~200ms. The maximum
 * number of channels defined in wifi_ioctl.h is 99 (MAX_CHANNEL_NUM).
 * As a result the maximum total scan time is defined as below in ms.
 */
#define	WAIT_SCAN_MAX	(200 * MAX_CHANNEL_NUM)

static void
wifi_wait_scan(struct ieee80211com *ic)
{
	ieee80211_impl_t *im = ic->ic_private;
	clock_t delta = drv_usectohz(WAIT_SCAN_MAX * 1000);

	while ((ic->ic_flags & (IEEE80211_F_SCAN | IEEE80211_F_ASCAN)) != 0) {
		if (cv_reltimedwait_sig(&im->im_scan_cv, &ic->ic_genlock,
		    delta, TR_CLOCK_TICK) != 0) {
			break;
		}
	}
}

#define	WIFI_HAVE_CAP(in, flag)	(((in)->in_capinfo & (flag)) ? 1 : 0)
#define	WIFI_HAVE_HTCAP(in)	(((in)->in_htcap != 0) ? 1 : 0)

/*
 * Callback function used by ieee80211_iterate_nodes() in
 * wifi_cfg_esslist() to get info of each node in a node table
 *    arg  output buffer, pointer to wl_ess_list_t
 *    in   each node in the node table
 */
static void
wifi_read_ap(void *arg, struct ieee80211_node *in)
{
	wl_ess_list_t *aps = arg;
	ieee80211com_t *ic = in->in_ic;
	struct ieee80211_channel *chan = in->in_chan;
	struct ieee80211_rateset *rates = &(in->in_rates);
	wl_ess_conf_t *conf;
	uint8_t *end;
	uint_t i, nrates;

	end = (uint8_t *)aps - WIFI_BUF_OFFSET + MAX_BUF_LEN -
	    sizeof (wl_ess_list_t);
	conf = &aps->wl_ess_list_ess[aps->wl_ess_list_num];
	if ((uint8_t *)conf > end)
		return;

	conf->wl_ess_conf_length = sizeof (struct wl_ess_conf);

	/* skip newly allocated NULL bss node */
	if (IEEE80211_ADDR_EQ(in->in_macaddr, ic->ic_macaddr))
		return;

	conf->wl_ess_conf_essid.wl_essid_length = in->in_esslen;
	bcopy(in->in_essid, conf->wl_ess_conf_essid.wl_essid_essid,
	    in->in_esslen);
	bcopy(in->in_bssid, conf->wl_ess_conf_bssid, IEEE80211_ADDR_LEN);
	conf->wl_ess_conf_wepenabled =
	    (in->in_capinfo & IEEE80211_CAPINFO_PRIVACY ?
	    WL_ENC_WEP : WL_NOENCRYPTION);
	conf->wl_ess_conf_bsstype =
	    (in->in_capinfo & IEEE80211_CAPINFO_ESS ?
	    WL_BSS_BSS : WL_BSS_IBSS);
	conf->wl_ess_conf_sl = wifi_getrssi(in);
	conf->wl_ess_conf_reserved[0] = (in->in_wpa_ie == NULL? 0 : 1);

	/* physical (FH, DS, ERP) parameters */
	if (IEEE80211_IS_CHAN_A(chan) || IEEE80211_IS_CHAN_T(chan)) {
		wl_ofdm_t *ofdm =
		    (wl_ofdm_t *)&((conf->wl_phy_conf).wl_phy_ofdm_conf);
		ofdm->wl_ofdm_subtype = WL_OFDM;
		ofdm->wl_ofdm_frequency = chan->ich_freq;
		ofdm->wl_ofdm_ht_enabled = WIFI_HAVE_HTCAP(in);
	} else {
		switch (in->in_phytype) {
		case IEEE80211_T_FH: {
			wl_fhss_t *fhss = (wl_fhss_t *)
			    &((conf->wl_phy_conf).wl_phy_fhss_conf);

			fhss->wl_fhss_subtype = WL_FHSS;
			fhss->wl_fhss_channel = ieee80211_chan2ieee(ic, chan);
			fhss->wl_fhss_dwelltime = in->in_fhdwell;
			break;
		}
		case IEEE80211_T_DS: {
			wl_dsss_t *dsss = (wl_dsss_t *)
			    &((conf->wl_phy_conf).wl_phy_dsss_conf);

			dsss->wl_dsss_subtype = WL_DSSS;
			dsss->wl_dsss_channel = ieee80211_chan2ieee(ic, chan);
			dsss->wl_dsss_have_short_preamble = WIFI_HAVE_CAP(in,
			    IEEE80211_CAPINFO_SHORT_PREAMBLE);
			dsss->wl_dsss_agility_enabled = WIFI_HAVE_CAP(in,
			    IEEE80211_CAPINFO_CHNL_AGILITY);
			dsss->wl_dsss_have_pbcc = dsss->wl_dsss_pbcc_enable =
			    WIFI_HAVE_CAP(in, IEEE80211_CAPINFO_PBCC);
			break;
		}
		case IEEE80211_T_OFDM: {
			wl_erp_t *erp = (wl_erp_t *)
			    &((conf->wl_phy_conf).wl_phy_erp_conf);

			erp->wl_erp_subtype = WL_ERP;
			erp->wl_erp_channel = ieee80211_chan2ieee(ic, chan);
			erp->wl_erp_have_short_preamble = WIFI_HAVE_CAP(in,
			    IEEE80211_CAPINFO_SHORT_PREAMBLE);
			erp->wl_erp_have_agility = erp->wl_erp_agility_enabled =
			    WIFI_HAVE_CAP(in, IEEE80211_CAPINFO_CHNL_AGILITY);
			erp->wl_erp_have_pbcc = erp->wl_erp_pbcc_enabled =
			    WIFI_HAVE_CAP(in, IEEE80211_CAPINFO_PBCC);
			erp->wl_erp_dsss_ofdm_enabled =
			    WIFI_HAVE_CAP(in, IEEE80211_CAPINFO_DSSSOFDM);
			erp->wl_erp_sst_enabled = WIFI_HAVE_CAP(in,
			    IEEE80211_CAPINFO_SHORT_SLOTTIME);
			erp->wl_erp_ht_enabled = WIFI_HAVE_HTCAP(in);
			break;
		} /* case IEEE80211_T_OFDM */
		} /* switch in->in_phytype */
	}

	/* supported rates */
	nrates = MIN(rates->ir_nrates, MAX_SCAN_SUPPORT_RATES);
	/*
	 * The number of supported rates might exceed
	 * MAX_SCAN_SUPPORT_RATES. Fill in highest rates
	 * first so userland command could properly show
	 * maximum speed of AP
	 */
	for (i = 0; i < nrates; i++) {
		conf->wl_supported_rates[i] =
		    rates->ir_rates[rates->ir_nrates - i - 1];
	}

	aps->wl_ess_list_num++;
}

static int
wifi_cfg_esslist(struct ieee80211com *ic, uint32_t cmd, mblk_t **mp)
{
	mblk_t *omp;
	wldp_t *outp;
	wl_ess_list_t *ow_aps;
	int err = 0;

	if ((omp = wifi_getoutmsg(*mp, cmd, MAX_BUF_LEN - WIFI_BUF_OFFSET)) ==
	    NULL) {
		return (ENOMEM);
	}
	outp = (wldp_t *)omp->b_rptr;
	ow_aps = (wl_ess_list_t *)outp->wldp_buf;

	switch (cmd) {
	case WLAN_GET_PARAM:
		ow_aps->wl_ess_list_num = 0;
		ieee80211_iterate_nodes(&ic->ic_scan, wifi_read_ap, ow_aps);
		outp->wldp_length = WIFI_BUF_OFFSET +
		    offsetof(wl_ess_list_t, wl_ess_list_ess) +
		    ow_aps->wl_ess_list_num * sizeof (wl_ess_conf_t);
		omp->b_wptr = omp->b_rptr + outp->wldp_length;
		break;
	case WLAN_SET_PARAM:
		outp->wldp_result = WL_READONLY;
		err = EINVAL;
		break;
	default:
		ieee80211_err("wifi_cfg_esslist: unknown command %x\n", cmd);
		outp->wldp_result = WL_NOTSUPPORTED;
		err = EINVAL;
		break;
	}

	freemsg(*mp);
	*mp = omp;
	return (err);
}

/*
 * Scan the network for all available ESSs.
 * IEEE80211_F_SCANONLY is set when current state is INIT. And
 * with this flag, after scan the state will be changed back to
 * INIT. The reason is at the end of SCAN stage, the STA will
 * consequently connect to an AP. Then it looks unreasonable that
 * for a disconnected device, A SCAN command causes it connected.
 * So the state is changed back to INIT.
 */
static int
wifi_cmd_scan(struct ieee80211com *ic, mblk_t *mp)
{
	int ostate = ic->ic_state;

	/*
	 * Do not scan when current state is RUN. The reason is
	 * when connected, STA is on the same channel as AP. But
	 * to do scan, STA have to switch to each available channel,
	 * send probe request and wait certian time for probe
	 * response/beacon. Then when the STA switches to a channel
	 * different than AP's, as a result it cannot send/receive
	 * data packets to/from the connected WLAN. This eventually
	 * will cause data loss.
	 */
	if (ostate == IEEE80211_S_RUN)
		return (0);

	IEEE80211_UNLOCK(ic);

	ieee80211_new_state(ic, IEEE80211_S_SCAN, -1);
	IEEE80211_LOCK(ic);
	if (ostate == IEEE80211_S_INIT)
		ic->ic_flags |= IEEE80211_F_SCANONLY;

	/* Don't wait on WPA mode */
	if ((ic->ic_flags & IEEE80211_F_WPA) == 0) {
		/* wait scan complete */
		wifi_wait_scan(ic);
	}

	wifi_setupoutmsg(mp, 0);
	return (0);
}

static void
wifi_loaddefdata(struct ieee80211com *ic)
{
	struct ieee80211_node *in = ic->ic_bss;
	int i;

	ic->ic_des_esslen = 0;
	bzero(ic->ic_des_essid, IEEE80211_NWID_LEN);
	ic->ic_flags &= ~IEEE80211_F_DESBSSID;
	bzero(ic->ic_des_bssid, IEEE80211_ADDR_LEN);
	bzero(ic->ic_bss->in_bssid, IEEE80211_ADDR_LEN);
	ic->ic_des_chan = IEEE80211_CHAN_ANYC;
	ic->ic_fixed_rate = IEEE80211_FIXED_RATE_NONE;
	bzero(ic->ic_nickname, IEEE80211_NWID_LEN);
	in->in_authmode = IEEE80211_AUTH_OPEN;
	ic->ic_flags &= ~IEEE80211_F_PRIVACY;
	ic->ic_flags &= ~IEEE80211_F_WPA;	/* mask WPA mode */
	ic->ic_evq_head = ic->ic_evq_tail = 0;	/* reset Queue */
	ic->ic_def_txkey = 0;
	for (i = 0; i < MAX_NWEPKEYS; i++) {
		ic->ic_nw_keys[i].wk_keylen = 0;
		bzero(ic->ic_nw_keys[i].wk_key, IEEE80211_KEYBUF_SIZE);
	}
	ic->ic_curmode = IEEE80211_MODE_AUTO;
	ic->ic_flags &= ~IEEE80211_F_IBSSON;
	ic->ic_opmode = IEEE80211_M_STA;
}

static int
wifi_cmd_loaddefaults(struct ieee80211com *ic, mblk_t *mp)
{
	wifi_loaddefdata(ic);
	wifi_setupoutmsg(mp, 0);
	return (ENETRESET);
}

static int
wifi_cmd_disassoc(struct ieee80211com *ic, mblk_t *mp)
{
	if (ic->ic_state != IEEE80211_S_INIT) {
		IEEE80211_UNLOCK(ic);
		(void) ieee80211_new_state(ic, IEEE80211_S_INIT, -1);
		IEEE80211_LOCK(ic);
	}
	wifi_loaddefdata(ic);
	wifi_setupoutmsg(mp, 0);
	return (0);
}

/*
 * Get the capabilities of drivers.
 */
static int
wifi_cfg_caps(struct ieee80211com *ic, uint32_t cmd, mblk_t **mp)
{
	mblk_t *omp;
	wldp_t *outp;
	wl_capability_t *o_caps;
	int err = 0;

	if ((omp = wifi_getoutmsg(*mp, cmd, sizeof (wl_capability_t))) == NULL)
		return (ENOMEM);
	outp = (wldp_t *)omp->b_rptr;
	o_caps = (wl_capability_t *)outp->wldp_buf;

	switch (cmd) {
	case WLAN_GET_PARAM:
		wl_get_capability(ic, o_caps);
		break;
	case WLAN_SET_PARAM:
		outp->wldp_result = WL_READONLY;
		err = EINVAL;
		break;
	default:
		ieee80211_err("wifi_cfg_caps: unknown command %x\n", cmd);
		outp->wldp_result = WL_NOTSUPPORTED;
		err = EINVAL;
		break;
	}

	freemsg(*mp);
	*mp = omp;
	return (err);
}

/*
 * Operating on WPA mode.
 */
static int
wifi_cfg_wpa(struct ieee80211com *ic, uint32_t cmd, mblk_t **mp)
{
	mblk_t *omp;
	wldp_t *outp;
	wldp_t *inp = (wldp_t *)(*mp)->b_rptr;
	wl_wpa_t *wpa = (wl_wpa_t *)inp->wldp_buf;
	wl_wpa_t *o_wpa;
	int err = 0;

	if ((omp = wifi_getoutmsg(*mp, cmd, sizeof (wl_wpa_t))) == NULL)
		return (ENOMEM);
	outp = (wldp_t *)omp->b_rptr;
	o_wpa = (wl_wpa_t *)outp->wldp_buf;

	switch (cmd) {
	case WLAN_GET_PARAM:
		wl_get_wpa(ic, o_wpa);
		break;
	case WLAN_SET_PARAM:
		err = wl_set_wpa(ic, wpa);
		break;
	default:
		ieee80211_err("wifi_cfg_wpa: unknown command %x\n", cmd);
		outp->wldp_result = WL_NOTSUPPORTED;
		err = EINVAL;
		break;
	}

	freemsg(*mp);
	*mp = omp;
	return (err);
}

/*
 * WPA daemon set the WPA keys.
 * The WPA keys are negotiated with APs through wpa service.
 */
static int
wifi_cfg_wpakey(struct ieee80211com *ic, uint32_t cmd, mblk_t **mp)
{
	mblk_t *omp;
	wldp_t *outp;
	wldp_t *inp = (wldp_t *)(*mp)->b_rptr;
	wl_key_t *ik = (wl_key_t *)(inp->wldp_buf);
	int err = 0;

	if ((omp = wifi_getoutmsg(*mp, cmd, 0)) == NULL)
		return (ENOMEM);
	outp = (wldp_t *)omp->b_rptr;

	switch (cmd) {
	case WLAN_GET_PARAM:
		outp->wldp_result = WL_WRITEONLY;
		err = EINVAL;
		break;
	case WLAN_SET_PARAM:
		err = wl_set_wpakey(ic, ik);
		break;
	default:
		ieee80211_err("wifi_cfg_wpakey: unknown command %x\n", cmd);
		outp->wldp_result = WL_NOTSUPPORTED;
		err = EINVAL;
		break;
	}

	freemsg(*mp);
	*mp = omp;
	return (err);
}

/*
 * Delete obsolete keys - keys are dynamically exchanged between APs
 * and wpa daemon.
 */
static int
wifi_cfg_delkey(struct ieee80211com *ic, uint32_t cmd, mblk_t **mp)
{
	mblk_t *omp;
	wldp_t *outp;
	wldp_t *inp = (wldp_t *)(*mp)->b_rptr;
	wl_del_key_t *dk = (wl_del_key_t *)inp->wldp_buf;
	int err = 0;

	if ((omp = wifi_getoutmsg(*mp, cmd, 0)) == NULL)
		return (ENOMEM);
	outp = (wldp_t *)omp->b_rptr;

	switch (cmd) {
	case WLAN_GET_PARAM:
		outp->wldp_result = WL_WRITEONLY;
		err = EINVAL;
		break;
	case WLAN_SET_PARAM:
		err = wl_set_delkey(ic, dk);
		break;
	default:
		ieee80211_err("wifi_cfg_delkey: unknown command %x\n", cmd);
		outp->wldp_result = WL_NOTSUPPORTED;
		err = EINVAL;
		break;
	}

	freemsg(*mp);
	*mp = omp;
	return (err);
}

/*
 * The OPTIE will be used in the association request.
 */
static int
wifi_cfg_setoptie(struct ieee80211com *ic, uint32_t cmd, mblk_t **mp)
{
	mblk_t *omp;
	wldp_t *outp;
	wldp_t *inp = (wldp_t *)(*mp)->b_rptr;
	wl_wpa_ie_t *ie_in = (wl_wpa_ie_t *)inp->wldp_buf;
	int err = 0;

	if ((omp = wifi_getoutmsg(*mp, cmd, 0)) == NULL)
		return (ENOMEM);
	outp = (wldp_t *)omp->b_rptr;

	switch (cmd) {
	case WLAN_GET_PARAM:
		outp->wldp_result = WL_WRITEONLY;
		err = EINVAL;
		break;
	case WLAN_SET_PARAM:
		if ((err = wl_set_optie(ic, ie_in)) == EINVAL)
			outp->wldp_result = WL_NOTSUPPORTED;
		break;
	default:
		ieee80211_err("wifi_cfg_setoptie: unknown command %x\n", cmd);
		outp->wldp_result = WL_NOTSUPPORTED;
		err = EINVAL;
		break;
	}

	freemsg(*mp);
	*mp = omp;
	return (err);
}

/*
 * To be compatible with drivers/tools of OpenSolaris.org,
 * we use a different ID to filter out those APs of WPA mode.
 */
static int
wifi_cfg_scanresults(struct ieee80211com *ic, uint32_t cmd, mblk_t **mp)
{
	mblk_t *omp;
	wldp_t *outp;
	wl_wpa_ess_t *sr;
	ieee80211_node_t *in;
	ieee80211_node_table_t *nt;
	int len, ap_num = 0;
	int err = 0;

	if ((omp = wifi_getoutmsg(*mp, cmd, MAX_BUF_LEN - WIFI_BUF_OFFSET)) ==
	    NULL) {
		return (ENOMEM);
	}
	outp = (wldp_t *)omp->b_rptr;
	sr = (wl_wpa_ess_t *)outp->wldp_buf;
	sr->count = 0;

	switch (cmd) {
	case WLAN_GET_PARAM:
		ieee80211_dbg(IEEE80211_MSG_WPA, "wifi_cfg_scanresults\n");
		nt = &ic->ic_scan;
		IEEE80211_NODE_LOCK(nt);
		in = list_head(&nt->nt_node);
		while (in != NULL) {
			/* filter out non-WPA APs */
			if (in->in_wpa_ie == NULL) {
				in = list_next(&nt->nt_node, in);
				continue;
			}
			bcopy(in->in_bssid, sr->ess[ap_num].bssid,
			    IEEE80211_ADDR_LEN);
			sr->ess[ap_num].ssid_len = in->in_esslen;
			bcopy(in->in_essid, sr->ess[ap_num].ssid,
			    in->in_esslen);
			sr->ess[ap_num].freq = in->in_chan->ich_freq;

			len = in->in_wpa_ie[1] + 2;
			bcopy(in->in_wpa_ie, sr->ess[ap_num].wpa_ie, len);
			sr->ess[ap_num].wpa_ie_len = len;

			ap_num ++;
			in = list_next(&nt->nt_node, in);
		}
		IEEE80211_NODE_UNLOCK(nt);
		sr->count = ap_num;
		outp->wldp_length = WIFI_BUF_OFFSET +
		    offsetof(wl_wpa_ess_t, ess) +
		    sr->count * sizeof (struct wpa_ess);
		omp->b_wptr = omp->b_rptr + outp->wldp_length;
		break;
	case WLAN_SET_PARAM:
		outp->wldp_result = WL_READONLY;
		err = EINVAL;
		break;
	default:
		ieee80211_err("wifi_cfg_scanresults: unknown cmmand %x\n", cmd);
		outp->wldp_result = WL_NOTSUPPORTED;
		err = EINVAL;
		break;
	}

	freemsg(*mp);
	*mp = omp;
	return (err);
}

/*
 * Manually control the state of AUTH | DEAUTH | DEASSOC | ASSOC
 */
static int
wifi_cfg_setmlme(struct ieee80211com *ic, uint32_t cmd, mblk_t **mp)
{
	mblk_t *omp;
	wldp_t *outp;
	wldp_t *inp = (wldp_t *)(*mp)->b_rptr;
	wl_mlme_t *mlme = (wl_mlme_t *)inp->wldp_buf;
	int err = 0;

	if ((omp = wifi_getoutmsg(*mp, cmd, 0)) == NULL)
		return (ENOMEM);
	outp = (wldp_t *)omp->b_rptr;

	switch (cmd) {
	case WLAN_GET_PARAM:
		outp->wldp_result = WL_WRITEONLY;
		err = EINVAL;
		break;
	case WLAN_SET_PARAM:
		err = wl_set_mlme(ic, mlme);
		break;
	default:
		ieee80211_err("wifi_cfg_delkey: unknown command %x\n", cmd);
		outp->wldp_result = WL_NOTSUPPORTED;
		err = EINVAL;
		break;
	}

	freemsg(*mp);
	*mp = omp;
	return (err);
}

static int
wifi_cfg_getset(struct ieee80211com *ic, mblk_t **mp, uint32_t cmd)
{
	mblk_t *mp1 = *mp;
	wldp_t *wp = (wldp_t *)mp1->b_rptr;
	int err = 0;

	ASSERT(ic != NULL && mp1 != NULL);
	IEEE80211_LOCK_ASSERT(ic);
	if (MBLKL(mp1) < WIFI_BUF_OFFSET) {
		ieee80211_err("wifi_cfg_getset: "
		    "invalid input buffer, size=%d\n", MBLKL(mp1));
		return (EINVAL);
	}

	switch (wp->wldp_id) {
	/* Commands */
	case WL_SCAN:
		err = wifi_cmd_scan(ic, mp1);
		break;
	case WL_LOAD_DEFAULTS:
		err = wifi_cmd_loaddefaults(ic, mp1);
		break;
	case WL_DISASSOCIATE:
		err = wifi_cmd_disassoc(ic, mp1);
		break;
	/* Parameters */
	case WL_ESSID:
		err = wifi_cfg_essid(ic, cmd, mp);
		break;
	case WL_BSSID:
		err = wifi_cfg_bssid(ic, cmd, mp);
		break;
	case WL_NODE_NAME:
		err = wifi_cfg_nodename(ic, cmd, mp);
		break;
	case WL_PHY_CONFIG:
		err = wifi_cfg_phy(ic, cmd, mp);
		break;
	case WL_WEP_KEY_TAB:
		err = wifi_cfg_wepkey(ic, cmd, mp);
		break;
	case WL_WEP_KEY_ID:
		err = wifi_cfg_keyid(ic, cmd, mp);
		break;
	case WL_AUTH_MODE:
		err = wifi_cfg_authmode(ic, cmd, mp);
		break;
	case WL_ENCRYPTION:
		err = wifi_cfg_encrypt(ic, cmd, mp);
		break;
	case WL_BSS_TYPE:
		err = wifi_cfg_bsstype(ic, cmd, mp);
		break;
	case WL_CREATE_IBSS:
		err = wifi_cfg_createibss(ic, cmd, mp);
		break;
	case WL_DESIRED_RATES:
		err = wifi_cfg_desrates(ic, cmd, mp);
		break;
	case WL_LINKSTATUS:
		err = wifi_cfg_linkstatus(ic, cmd, mp);
		break;
	case WL_ESS_LIST:
		err = wifi_cfg_esslist(ic, cmd, mp);
		break;
	case WL_SUPPORTED_RATES:
		err = wifi_cfg_suprates(ic, cmd, mp);
		break;
	case WL_RSSI:
		err = wifi_cfg_rssi(ic, cmd, mp);
		break;
	/*
	 * WPA IOCTLs
	 */
	case WL_CAPABILITY:
		err = wifi_cfg_caps(ic, cmd, mp);
		break;
	case WL_WPA:
		err = wifi_cfg_wpa(ic, cmd, mp);
		break;
	case WL_KEY:
		err = wifi_cfg_wpakey(ic, cmd, mp);
		break;
	case WL_DELKEY:
		err = wifi_cfg_delkey(ic, cmd, mp);
		break;
	case WL_SETOPTIE:
		err = wifi_cfg_setoptie(ic, cmd, mp);
		break;
	case WL_SCANRESULTS:
		err = wifi_cfg_scanresults(ic, cmd, mp);
		break;
	case WL_MLME:
		err = wifi_cfg_setmlme(ic, cmd, mp);
		break;
	default:
		wifi_setupoutmsg(mp1, 0);
		wp->wldp_result = WL_LACK_FEATURE;
		err = ENOTSUP;
		break;
	}

	return (err);
}

/*
 * Typically invoked by drivers in response to requests for
 * information or to change settings from the userland.
 *
 * Return value should be checked by WiFi drivers. Return 0
 * on success. Otherwise, return non-zero value to indicate
 * the error. Driver should operate as below when the return
 * error is:
 * ENETRESET	Reset wireless network and re-start to join a
 *		WLAN. ENETRESET is returned when a configuration
 *		parameter has been changed.
 *		When acknowledge a M_IOCTL message, thie error
 *		is ignored.
 */
int
ieee80211_ioctl(struct ieee80211com *ic, queue_t *wq, mblk_t *mp)
{
	struct iocblk *iocp;
	int32_t cmd, err, len;
	boolean_t need_privilege;
	mblk_t *mp1;

	if (MBLKL(mp) < sizeof (struct iocblk)) {
		ieee80211_err("ieee80211_ioctl: ioctl buffer too short, %u\n",
		    MBLKL(mp));
		miocnak(wq, mp, 0, EINVAL);
		return (EINVAL);
	}

	/*
	 * Validate the command
	 */
	iocp = (struct iocblk *)mp->b_rptr;
	iocp->ioc_error = 0;
	cmd = iocp->ioc_cmd;
	need_privilege = B_TRUE;
	switch (cmd) {
	case WLAN_SET_PARAM:
	case WLAN_COMMAND:
		break;
	case WLAN_GET_PARAM:
		need_privilege = B_FALSE;
		break;
	default:
		ieee80211_dbg(IEEE80211_MSG_ANY, "ieee80211_ioctl(): "
		    "unknown cmd 0x%x\n", cmd);
		miocnak(wq, mp, 0, EINVAL);
		return (EINVAL);
	}

	if (need_privilege && (err = secpolicy_dl_config(iocp->ioc_cr)) != 0) {
		miocnak(wq, mp, 0, err);
		return (err);
	}

	IEEE80211_LOCK(ic);

	/* sanity check */
	mp1 = mp->b_cont;
	if (iocp->ioc_count == 0 || iocp->ioc_count < sizeof (wldp_t) ||
	    mp1 == NULL) {
		miocnak(wq, mp, 0, EINVAL);
		IEEE80211_UNLOCK(ic);
		return (EINVAL);
	}

	/* assuming single data block */
	if (mp1->b_cont != NULL) {
		freemsg(mp1->b_cont);
		mp1->b_cont = NULL;
	}

	err = wifi_cfg_getset(ic, &mp1, cmd);
	mp->b_cont = mp1;
	IEEE80211_UNLOCK(ic);

	len = msgdsize(mp1);
	/* ignore ENETRESET when acknowledge the M_IOCTL message */
	if (err == 0 || err == ENETRESET)
		miocack(wq, mp, len, 0);
	else
		miocack(wq, mp, len, err);

	return (err);
}

/*
 * The following routines are for brussels support
 */

/*
 * MAC_PROP_WL_ESSID
 */
static int
wl_set_essid(struct ieee80211com *ic, const void *wldp_buf)
{
	int err = 0;
	char *essid;
	wl_essid_t *iw_essid = (wl_essid_t *)wldp_buf;

	if (iw_essid->wl_essid_length > IEEE80211_NWID_LEN) {
		ieee80211_err("wl_set_essid: "
		    "essid too long, %u, max %u\n",
		    iw_essid->wl_essid_length, IEEE80211_NWID_LEN);

		err = EINVAL;
		return (err);
	}

	essid = iw_essid->wl_essid_essid;
	essid[IEEE80211_NWID_LEN] = 0;

	ieee80211_dbg(IEEE80211_MSG_CONFIG, "wl_set_essid: "
	    "set essid=%s length=%d\n",
	    essid, iw_essid->wl_essid_length);

	ic->ic_des_esslen = iw_essid->wl_essid_length;
	if (ic->ic_des_esslen != 0)
		bcopy(essid, ic->ic_des_essid, ic->ic_des_esslen);
	if (ic->ic_des_esslen < IEEE80211_NWID_LEN)
		ic->ic_des_essid[ic->ic_des_esslen] = 0;

	err = ENETRESET;

	return (err);
}

static void
wl_get_essid(struct ieee80211com *ic, void *wldp_buf)
{
	char *essid;
	wl_essid_t ow_essid;

	essid = (char *)ic->ic_des_essid;
	if (essid[0] == '\0')
		essid = (char *)ic->ic_bss->in_essid;

	bzero(&ow_essid, sizeof (wl_essid_t));
	ow_essid.wl_essid_length = wifi_strnlen((const char *)essid,
	    IEEE80211_NWID_LEN);
	bcopy(essid, ow_essid.wl_essid_essid,
	    ow_essid.wl_essid_length);
	bcopy(&ow_essid, wldp_buf, sizeof (wl_essid_t));

}

/*
 * MAC_PROP_WL_BSSID
 */
static int
wl_set_bssid(struct ieee80211com *ic, const void* wldp_buf)
{

	ieee80211_dbg(IEEE80211_MSG_CONFIG, "wl_set_bssid: "
	    "set bssid=%s\n",
	    ieee80211_macaddr_sprintf(wldp_buf));

	bcopy(wldp_buf, ic->ic_des_bssid, sizeof (wl_bssid_t));
	ic->ic_flags |= IEEE80211_F_DESBSSID;

	return (ENETRESET);
}

static void
wl_get_bssid(struct ieee80211com *ic, void *wldp_buf)
{
	uint8_t *bssid;

	if (ic->ic_flags & IEEE80211_F_DESBSSID)
		bssid = ic->ic_des_bssid;
	else
		bssid = ic->ic_bss->in_bssid;
	bcopy(bssid, wldp_buf, sizeof (wl_bssid_t));

}

/*
 * MAC_PROP_WL_BSSTYP
 */
static int
wl_set_bsstype(struct ieee80211com *ic, const void *wldp_buf)
{
	int err = 0;
	wl_bss_type_t *iw_opmode = (wl_bss_type_t *)wldp_buf;

	ieee80211_dbg(IEEE80211_MSG_CONFIG, "wl_set_bsstype: "
	    "set bsstype=%u\n", *iw_opmode);

	switch (*iw_opmode) {
	case WL_BSS_BSS:
		ic->ic_flags &= ~IEEE80211_F_IBSSON;
		ic->ic_opmode = IEEE80211_M_STA;
		err = ENETRESET;
		break;
	case WL_BSS_IBSS:
		if ((ic->ic_caps & IEEE80211_C_IBSS) == 0) {
			err = ENOTSUP;
			break;
		}

		ic->ic_opmode = IEEE80211_M_IBSS;
		err = ENETRESET;
		break;
	default:
		ieee80211_err("wl_set_bsstype: "
		    "unknown opmode\n");
		err = EINVAL;
		break;
	}
	return (err);
}

static void
wl_get_bsstype(struct ieee80211com *ic, void *wldp_buf)
{
	wl_bss_type_t ow_opmode;

	switch (ic->ic_opmode) {
	case IEEE80211_M_STA:
		ow_opmode = WL_BSS_BSS;
		break;
	case IEEE80211_M_IBSS:
		ow_opmode = WL_BSS_IBSS;
		break;
	default:
		ow_opmode = WL_BSS_ANY;
		break;
	}

	bcopy(&ow_opmode, wldp_buf, sizeof (wl_bss_type_t));
}

/*
 * MAC_PROP_WL_LINKSTATUS
 */
static void
wl_get_linkstatus(struct ieee80211com *ic, void *wldp_buf)
{
	wl_linkstatus_t ow_linkstat;

	ow_linkstat = (ic->ic_state == IEEE80211_S_RUN) ?
	    WL_CONNECTED : WL_NOTCONNECTED;
	if ((ic->ic_flags & IEEE80211_F_WPA) &&
	    (ieee80211_crypto_getciphertype(ic) != WIFI_SEC_WPA)) {
		ow_linkstat = WL_NOTCONNECTED;
	}

	bcopy(&ow_linkstat, wldp_buf, sizeof (wl_linkstatus_t));
}

/*
 * MAC_PROP_WL_DESIRED_RATESa
 */
static int
wl_set_desrates(struct ieee80211com *ic, const void *wldp_buf)
{
	int err = 0;
	int i, j;
	uint8_t drate;
	boolean_t isfound;
	wl_rates_t *iw_rates = (wl_rates_t *)wldp_buf;
	struct ieee80211_node *in = ic->ic_bss;
	struct ieee80211_rateset *rs = &in->in_rates;

	drate = iw_rates->wl_rates_rates[0];
	if (ic->ic_fixed_rate == drate)
		return (err);

	ieee80211_dbg(IEEE80211_MSG_CONFIG, "wl_set_desrates: "
	    "set desired rate=%u\n", drate);

	if (drate == 0) {
		ic->ic_fixed_rate = IEEE80211_FIXED_RATE_NONE;
		if (ic->ic_state == IEEE80211_S_RUN) {
			IEEE80211_UNLOCK(ic);
			ieee80211_new_state(ic, IEEE80211_S_ASSOC, 0);
			IEEE80211_LOCK(ic);
		}
		return (err);
	}

	/*
	 * Set desired rate. The desired rate is for data transfer
	 * and usally is checked and used when driver changes to
	 * RUN state.
	 * If the driver is in AUTH | ASSOC | RUN state, desired
	 * rate is checked anainst rates supported by current ESS.
	 * If it's supported and current state is AUTH|ASSOC, nothing
	 * needs to be done by driver since the desired rate will
	 * be enabled when the device changes to RUN state. And
	 * when current state is RUN, Re-associate with the ESS to
	 * enable the desired rate.
	 */

	if (ic->ic_state != IEEE80211_S_INIT &&
	    ic->ic_state != IEEE80211_S_SCAN) {
		for (i = 0; i < rs->ir_nrates; i++) {
			if (drate == IEEE80211_RV(rs->ir_rates[i]))
				break;
		}
		/* supported */
		if (i < rs->ir_nrates) {
			ic->ic_fixed_rate = drate;
			if (ic->ic_state == IEEE80211_S_RUN) {
				IEEE80211_UNLOCK(ic);
				ieee80211_new_state(ic,
				    IEEE80211_S_ASSOC, 0);
				IEEE80211_LOCK(ic);
			}
			return (err);
		}
	}

	/*
	 * In INIT or SCAN state
	 * check if the desired rate is supported by device
	 */
	isfound = B_FALSE;
	for (i = 0; i < IEEE80211_MODE_MAX; i++) {
		rs = &ic->ic_sup_rates[i];
		for (j = 0; j < rs->ir_nrates; j++) {
			if (drate ==  IEEE80211_RV(rs->ir_rates[j])) {
				isfound = B_TRUE;
				break;
			}
		}
		if (isfound)
			break;
	}
	if (!isfound) {
		ieee80211_err("wl_set_desrates: "
		    "invald rate %d\n", drate);
		err = EINVAL;
		return (err);
	}
	ic->ic_fixed_rate = drate;
	if (ic->ic_state != IEEE80211_S_SCAN)
		err = ENETRESET;

	return (err);
}

static void
wl_get_desrates(struct ieee80211com *ic, void *wldp_buf)
{
	uint8_t srate;
	wl_rates_t ow_rates;
	struct ieee80211_node *in = ic->ic_bss;
	struct ieee80211_rateset *rs = &in->in_rates;

	srate = rs->ir_rates[in->in_txrate] & IEEE80211_RATE_VAL;
	ow_rates.wl_rates_num = 1;
	ow_rates.wl_rates_rates[0] =
	    (ic->ic_fixed_rate == IEEE80211_FIXED_RATE_NONE) ?
	    srate : ic->ic_fixed_rate;
	bcopy(&ow_rates, wldp_buf, sizeof (wl_rates_t));

}

/*
 * MAC_PROP_AUTH_MODE
 */
static int
wl_set_authmode(struct ieee80211com *ic, const void *wldp_buf)
{
	int err = 0;
	wl_authmode_t *iw_auth = (wl_authmode_t *)wldp_buf;

	if (*iw_auth == ic->ic_bss->in_authmode)
		return (err);

	ieee80211_dbg(IEEE80211_MSG_CONFIG, "wl_set_authmode: "
	    "set authmode=%u\n", *iw_auth);

	switch (*iw_auth) {
	case WL_OPENSYSTEM:
	case WL_SHAREDKEY:
		ic->ic_bss->in_authmode = *iw_auth;
		err = ENETRESET;
		break;
	default:
		ieee80211_err("wl_set_authmode: "
		    "unknown authmode %u\n", *iw_auth);
		err = EINVAL;
		break;
	}

	return (err);
}

static void
wl_get_authmode(struct ieee80211com *ic, void *wldp_buf)
{
	wl_authmode_t ow_auth;

	ow_auth = ic->ic_bss->in_authmode;
	bcopy(&ow_auth, wldp_buf, sizeof (wl_authmode_t));

}

/*
 * MAC_PROP_WL_ENCRYPTION
 */
static int
wl_set_encrypt(struct ieee80211com *ic, const void *wldp_buf)
{
	int err = 0;
	uint32_t flags;
	wl_encryption_t *iw_encryp = (wl_encryption_t *)wldp_buf;

	ieee80211_dbg(IEEE80211_MSG_CONFIG, "wl_set_encrypt: "
	    "set encryption=%u\n", *iw_encryp);

	flags = ic->ic_flags;
	if (*iw_encryp == WL_NOENCRYPTION)
		flags &= ~IEEE80211_F_PRIVACY;
	else
		flags |= IEEE80211_F_PRIVACY;

	if (ic->ic_flags != flags) {
		ic->ic_flags = flags;
		err = ENETRESET;
	}

	return (err);
}

static void
wl_get_encrypt(struct ieee80211com *ic, void *wldp_buf)
{
	wl_encryption_t *ow_encryp;

	ow_encryp = (wl_encryption_t *)wldp_buf;
	*ow_encryp = (ic->ic_flags & IEEE80211_F_PRIVACY) ? 1 : 0;
	if (ic->ic_flags & IEEE80211_F_WPA)
		*ow_encryp = WL_ENC_WPA;

}

/*
 * MAC_PROP_WL_RSSI
 */
static void
wl_get_rssi(struct ieee80211com *ic, void *wldp_buf)
{
	wl_rssi_t *ow_rssi;

	ow_rssi = (wl_rssi_t *)wldp_buf;
	*ow_rssi = wifi_getrssi(ic->ic_bss);

}

/*
 * MAC_PROP_WL_PHY_CONFIG
 */

static int
wl_set_phy(struct ieee80211com *ic, const void* wldp_buf)
{
	int err = 0;
	int16_t ch;
	wl_dsss_t *dsss;
	wl_phy_conf_t *iw_phy = (wl_phy_conf_t *)wldp_buf;

	dsss = (wl_dsss_t *)iw_phy;
	ch = dsss->wl_dsss_channel;

	ieee80211_dbg(IEEE80211_MSG_CONFIG, "wl_set_phy: "
	    "set channel=%d\n", ch);

	if (ch == 0 || ch == (int16_t)IEEE80211_CHAN_ANY) {
		ic->ic_des_chan = IEEE80211_CHAN_ANYC;
	} else if ((uint_t)ch > IEEE80211_CHAN_MAX ||
	    ieee80211_isclr(ic->ic_chan_active, ch)) {
		err = EINVAL;
		return (err);
	} else {
		ic->ic_des_chan = ic->ic_ibss_chan =
		    &ic->ic_sup_channels[ch];
	}

	switch (ic->ic_state) {
	case IEEE80211_S_INIT:
	case IEEE80211_S_SCAN:
		err = ENETRESET;
		break;
	default:
		/*
		 * If hte desired channel has changed (to something
		 * other than any) and we're not already scanning,
		 * then kick the state machine.
		 */
		if (ic->ic_des_chan != IEEE80211_CHAN_ANYC &&
		    ic->ic_bss->in_chan != ic->ic_des_chan &&
		    (ic->ic_flags & IEEE80211_F_SCAN) == 0)
			err = ENETRESET;
		break;
	}

	return (err);
}

#define	WIFI_HT_MODE(in)	(((in)->in_flags & IEEE80211_NODE_HT) ? 1 : 0)

static int
wl_get_phy(struct ieee80211com *ic, void *wldp_buf)
{
	int err = 0;
	wl_phy_conf_t *ow_phy;
	struct ieee80211_channel *ch = ic->ic_curchan;
	struct ieee80211_node *in = ic->ic_bss;

	ow_phy = (wl_phy_conf_t *)wldp_buf;
	bzero(wldp_buf, sizeof (wl_phy_conf_t));

	/* get current phy parameters: FH|DS|ERP */
	if (IEEE80211_IS_CHAN_A(ch) || IEEE80211_IS_CHAN_T(ch)) {
		wl_ofdm_t *ofdm = (wl_ofdm_t *)ow_phy;
		ofdm->wl_ofdm_subtype = WL_OFDM;
		ofdm->wl_ofdm_frequency = ch->ich_freq;
		ofdm->wl_ofdm_ht_enabled = WIFI_HT_MODE(in);
	} else {
		switch (ic->ic_phytype) {
		case IEEE80211_T_FH: {
			wl_fhss_t *fhss = (wl_fhss_t *)ow_phy;
			fhss->wl_fhss_subtype = WL_FHSS;
			fhss->wl_fhss_channel =
			    ieee80211_chan2ieee(ic, ch);
			break;
		}
		case IEEE80211_T_DS: {
			wl_dsss_t *dsss = (wl_dsss_t *)ow_phy;
			dsss->wl_dsss_subtype = WL_DSSS;
			dsss->wl_dsss_channel =
			    ieee80211_chan2ieee(ic, ch);
			break;
		}
		case IEEE80211_T_OFDM: {
			wl_erp_t *erp = (wl_erp_t *)ow_phy;
			erp->wl_erp_subtype = WL_ERP;
			erp->wl_erp_channel =
			    ieee80211_chan2ieee(ic, ch);
			erp->wl_erp_ht_enabled = WIFI_HT_MODE(in);
			break;
		}
		default:
			ieee80211_err("wl_get_phy: "
			    "unknown phy type, %x\n", ic->ic_phytype);
			err = EIO;
			break;
		}
	}

	return (err);
}

/*
 * MAC_PROP_WL_CAPABILITY
 */
static void
wl_get_capability(struct ieee80211com *ic, void *wldp_buf)
{
	wl_capability_t ow_caps;

	ow_caps.caps = ic->ic_caps;
	bcopy(&ow_caps, wldp_buf, sizeof (wl_capability_t));

}

/*
 * MAC_PROP_WL_WPA
 */
static int
wl_set_wpa(struct ieee80211com *ic, const void *wldp_buf)
{
	int err = 0;
	wl_wpa_t *wpa = (wl_wpa_t *)wldp_buf;

	ieee80211_dbg(IEEE80211_MSG_BRUSSELS, "wl_set_wpa: "
	    "set wpa=%u\n", wpa->wpa_flag);

	if (wpa->wpa_flag > 0) {
		/* enable wpa mode */
		ic->ic_flags |= IEEE80211_F_PRIVACY;
		ic->ic_flags |= IEEE80211_F_WPA;
	} else {
		ic->ic_flags &= ~IEEE80211_F_PRIVACY;
		ic->ic_flags &= ~IEEE80211_F_WPA;
	}

	return (err);
}

static void
wl_get_wpa(struct ieee80211com *ic, void *wldp_buf)
{
	wl_wpa_t *wpa;

	wpa = (wl_wpa_t *)wldp_buf;
	wpa->wpa_flag = ((ic->ic_flags & IEEE80211_F_WPA) ? 1 : 0);

	ieee80211_dbg(IEEE80211_MSG_BRUSSELS, "wl_get_wpa: "
	    "get wpa=%u\n", wpa->wpa_flag);

}

/*
 * MAC_PROP_WL_SCANRESULTS
 */

static void
wl_get_scanresults(struct ieee80211com *ic, void *wldp_buf)
{
	wl_wpa_ess_t *sr;
	ieee80211_node_t *in;
	ieee80211_node_table_t *nt;
	int ap_num;
	int len;

	sr = (wl_wpa_ess_t *)wldp_buf;
	sr->count = 0;
	ap_num = 0;

	ieee80211_dbg(IEEE80211_MSG_WPA, "wl_get_scanrelults\n");

	nt = &ic->ic_scan;
	IEEE80211_NODE_LOCK(nt);
	in = list_head(&nt->nt_node);

	while (in != NULL) {
		/* filter out non-wpa APs */
		if (in->in_wpa_ie == NULL) {
			in = list_next(&nt->nt_node, in);
			continue;
		}
		bcopy(in->in_bssid, sr->ess[ap_num].bssid,
		    IEEE80211_ADDR_LEN);
		sr->ess[ap_num].ssid_len = in->in_esslen;
		bcopy(in->in_essid, sr->ess[ap_num].ssid,
		    in->in_esslen);
		sr->ess[ap_num].freq = in->in_chan->ich_freq;

		len = in->in_wpa_ie[1] + 2;
		bcopy(in->in_wpa_ie, sr->ess[ap_num].wpa_ie, len);
		sr->ess[ap_num].wpa_ie_len = len;

		ap_num++;
		in = list_next(&nt->nt_node, in);
	}
	IEEE80211_NODE_UNLOCK(nt);
	sr->count = ap_num;

}

/*
 * MAC_PROP_WL_ESS_LIST
 */
static void
wl_get_esslist(struct ieee80211com *ic, void *wldp_buf)
{
	wl_ess_list_t *ess_list;

	ess_list = (wl_ess_list_t *)wldp_buf;

	ess_list->wl_ess_list_num = 0;
	ieee80211_iterate_nodes(&ic->ic_scan, wifi_read_ap, ess_list);

}

/*
 * MAC_PROP_WL_WEP_KEY
 */
static int
wl_set_wepkey(struct ieee80211com *ic, const void *wldp_buf)
{
	int	 err = 0;
	uint16_t i;
	uint32_t klen;
	struct ieee80211_key *key;
	wl_wep_key_t *wepkey = (wl_wep_key_t *)wldp_buf;

	/* set all valid keys */
	for (i = 0; i < MAX_NWEPKEYS; i++) {
		if (wepkey[i].wl_wep_operation != WL_ADD)
			continue;
		klen = wepkey[i].wl_wep_length;
		if (klen > IEEE80211_KEYBUF_SIZE) {
			ieee80211_err("wl_set_wepkey: "
			    "invalid wepkey length, %u\n", klen);
			err = EINVAL;
			continue;  /* continue to set other keys */
		}
		if (klen == 0)
			continue;

		/*
		 *  Set key contents. Only WEP is supported
		 */
		ieee80211_dbg(IEEE80211_MSG_CONFIG, "wl_set_wepkey: "
		    "set key %u, len=%u\n", i, klen);
		key = &ic->ic_nw_keys[i];
		if (ieee80211_crypto_newkey(ic, IEEE80211_CIPHER_WEP,
		    IEEE80211_KEY_XMIT | IEEE80211_KEY_RECV, key) == 0) {
			ieee80211_err("wl_set_wepkey: "
			    "abort, create key failed. id=%u\n", i);
			err = EIO;
			continue;
		}

		key->wk_keyix = i;
		key->wk_keylen = (uint8_t)klen;
		key->wk_flags |= IEEE80211_KEY_XMIT | IEEE80211_KEY_RECV;
		bzero(key->wk_key, IEEE80211_KEYBUF_SIZE);
		bcopy(wepkey[i].wl_wep_key, key->wk_key, klen);
		if (ieee80211_crypto_setkey(ic, key, ic->ic_macaddr)
		    == 0) {
			ieee80211_err("wl_set_wepkey: "
			    "set key failed len=%u\n", klen);
			err = EIO;
		}
	}
	if (err == 0)
		err = ENETRESET;

	return (err);
}

/*
 * MAC_PROP_WL_SETOPTIE
 */
static int
wl_set_optie(struct ieee80211com *ic, const void *wldp_buf)
{
	int err = 0;
	char *ie;
	wl_wpa_ie_t *ie_in = (wl_wpa_ie_t *)wldp_buf;

	if (ic->ic_opmode != IEEE80211_M_STA) {
		ieee80211_err("wl_set_optie: opmode err\n");
		err = EINVAL;
		return (err);
	}
	if (ie_in->wpa_ie_len > IEEE80211_MAX_OPT_IE) {

		ieee80211_err("wl_set_optie: optie is too long\n");

		err = EINVAL;
		return (err);
	}

	ie = ieee80211_malloc(ie_in->wpa_ie_len);
	(void) memcpy(ie, ie_in->wpa_ie, ie_in->wpa_ie_len);
	if (ic->ic_opt_ie != NULL) {
		ieee80211_dbg(IEEE80211_MSG_BRUSSELS,
		    "wl_set_optie:ic_opt_ie!=NULL\n");
		ieee80211_free(ic->ic_opt_ie);
	}
	ic->ic_opt_ie = ie;
	ic->ic_opt_ie_len = ie_in->wpa_ie_len;

	return (err);
}

/*
 * MAC_PROP_WL_DELKEY
 */
static int
wl_set_delkey(struct ieee80211com *ic, const void *wldp_buf)
{
	int err = 0;
	int kid;
	wl_del_key_t *dk = (wl_del_key_t *)wldp_buf;

	ieee80211_dbg(IEEE80211_MSG_BRUSSELS, "wl_set_delkey(): "
	    "keyix=%d\n", dk->idk_keyix);

	kid = dk->idk_keyix;

	if (kid == IEEE80211_KEYIX_NONE ||
	    kid >= IEEE80211_WEP_NKID) {
		ieee80211_err("wl_set_delkey: incorrect keyix\n");
		err = EINVAL;
		return (err);
	} else {
		(void) ieee80211_crypto_delkey(ic,
		    &ic->ic_nw_keys[kid]);
		ieee80211_mac_update(ic);
	}

	return (err);
}

/*
 * MAC_PROP_WL_MLME
 */

static int
wl_set_mlme(struct ieee80211com *ic, const void *wldp_buf)
{
	int err = 0;
	uint32_t flags;
	ieee80211_node_t *in;
	wl_mlme_t *mlme = (wl_mlme_t *)wldp_buf;

	ieee80211_dbg(IEEE80211_MSG_WPA, "wl_set_mlme: "
	    "op=%d\n", mlme->im_op);

	switch (mlme->im_op) {
	case IEEE80211_MLME_DISASSOC:
	case IEEE80211_MLME_DEAUTH:
		if (ic->ic_opmode == IEEE80211_M_STA) {
			/*
			 * Mask ic_flags of IEEE80211_F_WPA to disable
			 * ieee80211_notify temporarily.
			 */
			flags = ic->ic_flags;
			ic->ic_flags &= ~IEEE80211_F_WPA;

			IEEE80211_UNLOCK(ic);
			ieee80211_new_state(ic, IEEE80211_S_INIT,
			    mlme->im_reason);
			IEEE80211_LOCK(ic);

			ic->ic_flags = flags;
		}
		break;
	case IEEE80211_MLME_ASSOC:
		if (ic->ic_opmode != IEEE80211_M_STA) {
			ieee80211_err("wifi_cfg_setmlme: opmode err\n");
			err = EINVAL;
			break;
		}
		if (ic->ic_des_esslen != 0) {
		/*
		 * Desired ssid specified; must match both bssid and
		 * ssid to distinguish ap advertising multiple ssid's.
		 */
			in = ieee80211_find_node_with_ssid(&ic->ic_scan,
			    mlme->im_macaddr,
			    ic->ic_des_esslen,
			    ic->ic_des_essid);
		} else {
		/*
		 * Normal case; just match bssid.
		 */
			in = ieee80211_find_node(&ic->ic_scan,
			    mlme->im_macaddr);
		}
		if (in == NULL) {
			ieee80211_err("wifi_cfg_setmlme: "
			    "no matched node\n");
			err = EINVAL;
			break;
		}
		IEEE80211_UNLOCK(ic);
		ieee80211_sta_join(ic, in);
		IEEE80211_LOCK(ic);
		break;
	default:
		err = EINVAL;
		break;
	}

	return (err);
}

/*
 * MAC_PROP_WL_WPA_KEY
 */
static int
wl_set_wpakey(struct ieee80211com *ic, const void *wldp_buf)
{
	int err = 0;
	uint16_t kid;
	struct ieee80211_node *in;
	struct ieee80211_key *wk;
	wl_key_t ik;

	bcopy(wldp_buf, &ik, sizeof (wl_key_t));

	ieee80211_dbg(IEEE80211_MSG_BRUSSELS, "wl_set_wpakey: "
	    "idx=%d\n", ik.ik_keyix);

	/*
	 * cipher support is verified by ieee80211_crypt_newkey
	 * this also checks ik.ik_keylen > sizeof(wk->wk_key)
	 */
	if (ik.ik_keylen > sizeof (ik.ik_keydata)) {
		ieee80211_err("wl_set_wpakey: key is too long\n");
		err = EINVAL;
		return (err);
	}
	kid = ik.ik_keyix;
	if (kid == IEEE80211_KEYIX_NONE || kid >= IEEE80211_WEP_NKID) {
		ieee80211_err("wl_set_wpakey: incorrect keyix\n");
		err = EINVAL;
		return (err);
	} else {
		wk = &ic->ic_nw_keys[kid];
		/*
		 * Globle slots start off w/o any assigned key index.
		 * Force one here for consistency with WEPKEY.
		 */
		if (wk->wk_keyix == IEEE80211_KEYIX_NONE)
			wk->wk_keyix = kid;
		in = NULL;
	}

	KEY_UPDATE_BEGIN(ic);
	if (ieee80211_crypto_newkey(ic, ik.ik_type,
	    ik.ik_flags, wk)) {
		wk->wk_keylen = ik.ik_keylen;
		/* MIC presence is implied by cipher type */
		if (wk->wk_keylen > IEEE80211_KEYBUF_SIZE)
			wk->wk_keylen = IEEE80211_KEYBUF_SIZE;
		wk->wk_keyrsc = ik.ik_keyrsc;
		wk->wk_keytsc = 0;
		wk->wk_flags |= ik.ik_flags &
		    (IEEE80211_KEY_XMIT | IEEE80211_KEY_RECV);
		(void) memset(wk->wk_key, 0, sizeof (wk->wk_key));
		(void) memcpy(wk->wk_key, ik.ik_keydata,
		    ik.ik_keylen);
		if (!ieee80211_crypto_setkey(ic, wk,
		    in != NULL ? in->in_macaddr : ik.ik_macaddr)) {
			err = EIO;
		} else if ((ik.ik_flags & IEEE80211_KEY_DEFAULT)) {
			ic->ic_def_txkey = kid;
			ieee80211_mac_update(ic);
		}
	} else {
		err = EIO;
	}
	KEY_UPDATE_END(ic);

	return (err);
}

/*
 * MAC_PROP_WL_SUP_RATE
 */
static void
wl_get_suprates(struct ieee80211com *ic, void *wldp_buf)
{
	int i, j, k, l;
	uint8_t srates;
	uint8_t *drates;
	wl_rates_t *wl_rates;
	const struct ieee80211_rateset *srs;

	wl_rates = (wl_rates_t *)wldp_buf;

	wl_rates->wl_rates_num = 0;
	drates = (uint8_t *)wl_rates->wl_rates_rates;
	for (i = 0; i < IEEE80211_MODE_MAX; i++) {
		srs = &ic->ic_sup_rates[i];
		if (srs->ir_nrates == 0)
			continue;
		for (j = 0; j < srs->ir_nrates; j++) {
			srates = IEEE80211_RV(srs->ir_rates[j]);
			/* sort & skip duplicated rates */
			for (k = 0; k < wl_rates->wl_rates_num; k++) {
				if (srates <= drates[k])
					break;
			}
			if (srates == drates[k])
				/* skip duplicated rates */
				continue;
			/* sort */
			for (l = wl_rates->wl_rates_num; l > k; l--)
				drates[l] = drates[l-1];
			drates[k] = srates;
			wl_rates->wl_rates_num++;
		}
	}

}

/*
 * MAC_PROP_WL_CREATE_IBSS
 */
static int
wl_set_createibss(struct ieee80211com *ic, const void *wldp_buf)
{
	wl_create_ibss_t *iw_ibss = (wl_create_ibss_t *)wldp_buf;
	int err = 0;

	ieee80211_dbg(IEEE80211_MSG_CONFIG, "wl_set_ibss: "
	    "set createibss=%u\n", *iw_ibss);

	if ((ic->ic_caps & IEEE80211_C_IBSS) == 0) {
		err = ENOTSUP;
		return (err);
	}
	if (*iw_ibss) {
		if ((ic->ic_flags & IEEE80211_F_IBSSON) == 0) {
			ic->ic_flags |= IEEE80211_F_IBSSON;
			ic->ic_opmode = IEEE80211_M_IBSS;
			/*
			 * Yech, slot time may change depending on the
			 * operating mode so reset it to be sure
			 * everything is setup appropriately.
			 */
			ieee80211_reset_erp(ic);
			err = ENETRESET;
		}
	} else {
		if (ic->ic_flags & IEEE80211_F_IBSSON) {
			ic->ic_flags &= ~IEEE80211_F_IBSSON;
			err = ENETRESET;
		}
	}

	return (err);
}

static void
wl_get_createibss(struct ieee80211com *ic, void *wldp_buf)
{
	wl_create_ibss_t *ow_ibss = (wl_create_ibss_t *)wldp_buf;

	*ow_ibss = (ic->ic_flags & IEEE80211_F_IBSSON)? 1 : 0;
}

/*
 * Typically invoked by drivers in response to request for
 * information or to change settings from the userland.
 *
 * Return value should be checked by WiFI drivers. Return 0
 * on success. Otherwise, return non-zero value to indicate
 * the error. Driver should operate as below when the return
 * error is:
 * ENETRESET	Reset wireless network and re-start to join a
 * 		WLAN, ENETRESET is returned when a configuration
 * 		parameter has been changed.
 * 		When acknowledge a M_IOCTL message, this error
 * 		is ignored
 */
/* ARGSUSED */
int
ieee80211_setprop(void *ic_arg, const char *pr_name, mac_prop_id_t wldp_pr_num,
    uint_t wldp_length, const void *wldp_buf)
{
	int err = 0;
	struct ieee80211com *ic = ic_arg;

	ASSERT(ic != NULL);
	IEEE80211_LOCK(ic);

	switch (wldp_pr_num) {
	/* mac_prop_id */
	case MAC_PROP_WL_ESSID:
		err = wl_set_essid(ic, wldp_buf);
		break;
	case MAC_PROP_WL_BSSID:
		err = wl_set_bssid(ic, wldp_buf);
		break;
	case MAC_PROP_WL_PHY_CONFIG:
		err = wl_set_phy(ic, wldp_buf);
		break;
	case MAC_PROP_WL_KEY_TAB:
		err = wl_set_wepkey(ic, wldp_buf);
		break;
	case MAC_PROP_WL_AUTH_MODE:
		err = wl_set_authmode(ic, wldp_buf);
		break;
	case MAC_PROP_WL_ENCRYPTION:
		err = wl_set_encrypt(ic, wldp_buf);
		break;
	case MAC_PROP_WL_BSSTYPE:
		err = wl_set_bsstype(ic, wldp_buf);
		break;
	case MAC_PROP_WL_DESIRED_RATES:
		err = wl_set_desrates(ic, wldp_buf);
		break;
	case MAC_PROP_WL_WPA:
		err = wl_set_wpa(ic, wldp_buf);
		break;
	case MAC_PROP_WL_KEY:
		err = wl_set_wpakey(ic, wldp_buf);
		break;
	case MAC_PROP_WL_DELKEY:
		err = wl_set_delkey(ic, wldp_buf);
		break;
	case MAC_PROP_WL_SETOPTIE:
		err = wl_set_optie(ic, wldp_buf);
		break;
	case MAC_PROP_WL_MLME:
		err = wl_set_mlme(ic, wldp_buf);
		break;
	case MAC_PROP_WL_CREATE_IBSS:
		err = wl_set_createibss(ic, wldp_buf);
		break;
	case MAC_PROP_WL_LINKSTATUS:
	case MAC_PROP_WL_ESS_LIST:
	case MAC_PROP_WL_SUPPORTED_RATES:
	case MAC_PROP_WL_RSSI:
	case MAC_PROP_WL_CAPABILITY:
	case MAC_PROP_WL_SCANRESULTS:
		ieee80211_err("ieee80211_setprop: opmode err\n");
		err = EINVAL;
		break;
	default:
		ieee80211_err("ieee80211_setprop: opmode not support\n");
		err = ENOTSUP;
		break;
	}

	IEEE80211_UNLOCK(ic);

	return (err);
}

/* ARGSUSED */
int
ieee80211_getprop(void *ic_arg, const char *pr_name, mac_prop_id_t wldp_pr_num,
    uint_t wldp_length, void *wldp_buf)
{
	int err = 0;
	struct ieee80211com *ic = ic_arg;

	ASSERT(ic != NULL);
	IEEE80211_LOCK(ic);

	switch (wldp_pr_num) {
	/* mac_prop_id */
	case MAC_PROP_WL_ESSID:
		wl_get_essid(ic, wldp_buf);
		break;
	case MAC_PROP_WL_BSSID:
		wl_get_bssid(ic, wldp_buf);
		break;
	case MAC_PROP_WL_PHY_CONFIG:
		err = wl_get_phy(ic, wldp_buf);
		break;
	case MAC_PROP_WL_AUTH_MODE:
		wl_get_authmode(ic, wldp_buf);
		break;
	case MAC_PROP_WL_ENCRYPTION:
		wl_get_encrypt(ic, wldp_buf);
		break;
	case MAC_PROP_WL_BSSTYPE:
		wl_get_bsstype(ic, wldp_buf);
		break;
	case MAC_PROP_WL_DESIRED_RATES:
		wl_get_desrates(ic, wldp_buf);
		break;
	case MAC_PROP_WL_LINKSTATUS:
		wl_get_linkstatus(ic, wldp_buf);
		break;
	case MAC_PROP_WL_ESS_LIST:
		wl_get_esslist(ic, wldp_buf);
		break;
	case MAC_PROP_WL_SUPPORTED_RATES:
		wl_get_suprates(ic, wldp_buf);
		break;
	case MAC_PROP_WL_RSSI:
		wl_get_rssi(ic, wldp_buf);
		break;
	case MAC_PROP_WL_CAPABILITY:
		wl_get_capability(ic, wldp_buf);
		break;
	case MAC_PROP_WL_WPA:
		wl_get_wpa(ic, wldp_buf);
		break;
	case MAC_PROP_WL_SCANRESULTS:
		wl_get_scanresults(ic, wldp_buf);
		break;
	case MAC_PROP_WL_CREATE_IBSS:
		wl_get_createibss(ic, wldp_buf);
		break;
	case MAC_PROP_WL_KEY_TAB:
	case MAC_PROP_WL_KEY:
	case MAC_PROP_WL_DELKEY:
	case MAC_PROP_WL_SETOPTIE:
	case MAC_PROP_WL_MLME:
		ieee80211_err("ieee80211_setprop: opmode err\n");
		err = EINVAL;
		break;
	default:
		ieee80211_err("ieee80211_setprop: opmode not support\n");
		err = ENOTSUP;
		break;
	}

	IEEE80211_UNLOCK(ic);

	return (err);
}

void ieee80211_propinfo(void *ic_arg, const char *pr_name,
    mac_prop_id_t wldp_pr_num, mac_prop_info_handle_t prh)
{
        _NOTE(ARGUNUSED(pr_name, ic_arg));

	/*
	 * By default permissions are read/write unless specified
	 * otherwise by the driver.
	 */

	switch (wldp_pr_num) {
	case MAC_PROP_WL_LINKSTATUS:
	case MAC_PROP_WL_ESS_LIST:
	case MAC_PROP_WL_SUPPORTED_RATES:
	case MAC_PROP_WL_RSSI:
	case MAC_PROP_WL_CAPABILITY:
	case MAC_PROP_WL_SCANRESULTS:
	case MAC_PROP_WL_CREATE_IBSS:
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
	}
}
