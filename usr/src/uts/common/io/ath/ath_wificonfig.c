/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer,
 * without modification.
 * 2. Redistributions in binary form must reproduce at minimum a disclaimer
 * similar to the "NO WARRANTY" disclaimer below ("Disclaimer") and any
 * redistribution must be conditioned upon including a substantially
 * similar Disclaimer requirement for further binary redistribution.
 * 3. Neither the names of the above-listed copyright holders nor the names
 * of any contributors may be used to endorse or promote products derived
 * from this software without specific prior written permission.
 *
 * NO WARRANTY
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF NONINFRINGEMENT, MERCHANTIBILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGES.
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/types.h>
#include <sys/signal.h>
#include <sys/stream.h>
#include <sys/termio.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/cmn_err.h>
#include <sys/stropts.h>
#include <sys/strsubr.h>
#include <sys/strtty.h>
#include <sys/kbio.h>
#include <sys/cred.h>
#include <sys/stat.h>
#include <sys/consdev.h>
#include <sys/kmem.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/pci.h>
#include <sys/errno.h>
#include <sys/gld.h>
#include <sys/dlpi.h>
#include <sys/ethernet.h>
#include <sys/note.h>
#include <sys/strsun.h>
#include <sys/list.h>
#include <inet/common.h>
#include <inet/nd.h>
#include <inet/mi.h>
#include <inet/wifi_ioctl.h>
#include "ath_impl.h"
#include "ath_hal.h"
#include "ath_ieee80211.h"

extern int
ath_gld_start(gld_mac_info_t *gld_p);

static int
ath_wificfg_essid(ath_t *asc, mblk_t *mp, uint32_t cmd)
{
	uint32_t i;
	char *value, *buf;
	int len;
	wldp_t *infp, *outfp;
	ieee80211com_t *isc = (ieee80211com_t *)asc;

	buf = kmem_zalloc(MAX_BUF_LEN, KM_SLEEP);

	outfp = (wldp_t *)buf;
	infp = (wldp_t *)mp->b_rptr;

	bcopy(mp->b_rptr, buf,  sizeof (wldp_t));

	if (cmd == WLAN_GET_PARAM) {
		if (mi_strlen((const char *)isc->isc_des_essid) == 0) {
			outfp->wldp_length = offsetof(wldp_t, wldp_buf) +
			    offsetof(wl_essid_t, wl_essid_essid) +
			    mi_strlen((const char *)
			    isc->isc_bss->in_essid);
			((wl_essid_t *)(outfp->wldp_buf))->wl_essid_length =
			    mi_strlen((const char *)
			    isc->isc_bss->in_essid);
			bcopy(isc->isc_bss->in_essid,
			    buf + offsetof(wldp_t, wldp_buf) +
			    offsetof(wl_essid_t, wl_essid_essid),
			    mi_strlen((const char *)
			    isc->isc_bss->in_essid));
		} else {
			outfp->wldp_length = offsetof(wldp_t, wldp_buf) +
			    offsetof(wl_essid_t, wl_essid_essid) +
			    mi_strlen((const char *)isc->isc_des_essid);
			((wl_essid_t *)(outfp->wldp_buf))->wl_essid_length =
			    mi_strlen((const char *)isc->isc_des_essid);
			bcopy(isc->isc_des_essid,
			    buf + offsetof(wldp_t, wldp_buf) +
			    offsetof(wl_essid_t, wl_essid_essid),
			    mi_strlen((const char *)
			    isc->isc_des_essid));
		}
	} else if (cmd == WLAN_SET_PARAM) {
		value = ((wl_essid_t *)(infp->wldp_buf))->wl_essid_essid;
		bzero(isc->isc_des_essid, IEEE80211_NWID_LEN);
		if (mi_strlen(value) == 0)
			isc->isc_des_esslen = 0;
		else {
			len = mi_strlen((const char *)value);
			if (len > IEEE80211_NWID_LEN)
				len = IEEE80211_NWID_LEN;
			bcopy(value, isc->isc_des_essid, len);
			isc->isc_des_esslen = len;
			ATH_DEBUG((ATH_DBG_WIFICFG,
			    "ath: ath_wificfg_essid(): "
			    "set essid=%s len=%d\n", value, len));
		}
		if (asc->asc_invalid == 0) {
			(void) ath_gld_start(isc->isc_dev);
			(void) _ieee80211_new_state(isc, IEEE80211_S_SCAN, -1);
		}
	}

	outfp->wldp_result = WL_SUCCESS;
	for (i = 0; i < (outfp->wldp_length); i++)
		(void) mi_mpprintf_putc((char *)mp, buf[i]);
	kmem_free(buf, MAX_BUF_LEN);
	return (WL_SUCCESS);
}

static int
ath_wificfg_bssid(ath_t *asc, mblk_t *mp, uint32_t cmd)
{
	uint32_t i;
	char *buf;
	wldp_t *outfp;
	ieee80211com_t *isc = (ieee80211com_t *)asc;

	buf = kmem_zalloc(MAX_BUF_LEN, KM_SLEEP);
	outfp = (wldp_t *)buf;
	bcopy(mp->b_rptr, buf,  sizeof (wldp_t));

	outfp->wldp_length = WIFI_BUF_OFFSET + sizeof (wl_bssid_t);
	if (cmd == WLAN_GET_PARAM) {
		if (isc->isc_flags & IEEE80211_F_DESBSSID)
			bcopy(isc->isc_des_bssid,
			    buf + WIFI_BUF_OFFSET, sizeof (wl_bssid_t));
		else
			bcopy(isc->isc_bss->in_bssid,
			    buf + WIFI_BUF_OFFSET, sizeof (wl_bssid_t));
		outfp->wldp_result = WL_SUCCESS;

		ATH_DEBUG((ATH_DBG_WIFICFG, "ath: ath_wificfg_bssid(): "
		    "get bssid=%x %x %x %x %x %x\n",
		    buf[WIFI_BUF_OFFSET+0], buf[WIFI_BUF_OFFSET+1],
		    buf[WIFI_BUF_OFFSET+2], buf[WIFI_BUF_OFFSET+3],
		    buf[WIFI_BUF_OFFSET+4], buf[WIFI_BUF_OFFSET+5]));
	} else if (cmd == WLAN_SET_PARAM) {
		outfp->wldp_result = WL_READONLY;
	}

	for (i = 0; i < (outfp->wldp_length); i++)
		(void) mi_mpprintf_putc((char *)mp, buf[i]);
	kmem_free(buf, MAX_BUF_LEN);
	return (WL_SUCCESS);
}

static int
ath_wificfg_nodename(ath_t *asc, mblk_t *mp, uint32_t cmd)
{
	char *value, *buf;
	int iret, nickname_len;
	uint32_t i;
	wldp_t *infp, *outfp;
	ieee80211com_t *isc = (ieee80211com_t *)asc;

	ATH_DEBUG((ATH_DBG_WIFICFG, "ath: ath_wificfg_nodename(): "
	    "nodename entry\n"));
	buf = kmem_zalloc(MAX_BUF_LEN, KM_SLEEP);
	outfp = (wldp_t *)buf;
	bcopy(mp->b_rptr, buf,  sizeof (wldp_t));
	infp = (wldp_t *)mp->b_rptr;

	nickname_len = MIN(isc->isc_nicknamelen, IEEE80211_NWID_LEN);

	if (cmd == WLAN_GET_PARAM) {
		outfp->wldp_length = WIFI_BUF_OFFSET +
		    offsetof(wl_nodename_t, wl_nodename_name) + nickname_len;
		((wl_nodename_t *)(buf + WIFI_BUF_OFFSET))->wl_nodename_length =
		    nickname_len;
		bcopy(isc->isc_nickname, buf + WIFI_BUF_OFFSET +
		    offsetof(wl_nodename_t, wl_nodename_name), nickname_len);
		outfp->wldp_result = WL_SUCCESS;
		ATH_DEBUG((ATH_DBG_WIFICFG, "ath: ath_wificfg_nodename(): "
		    "get nodename=%s\n", isc->isc_nickname));
	} else if (cmd == WLAN_SET_PARAM) {
		value = ((wl_nodename_t *)(infp->wldp_buf))->wl_nodename_name;
		(void) strncpy((char *)isc->isc_nickname, value,
		    MIN(32, strlen(value)));
		isc->isc_nickname[strlen(value)] = '\0';
		isc->isc_nicknamelen =
		    ((wl_nodename_t *)(infp->wldp_buf))->wl_nodename_length;
		outfp->wldp_length = WIFI_BUF_OFFSET;
		outfp->wldp_result = WL_SUCCESS;
		ATH_DEBUG((ATH_DBG_WIFICFG, "ath: ath_wificfg_nodename(): "
		    "set nodename=%s\n", value));
		ATH_DEBUG((ATH_DBG_WIFICFG, "ath: ath_wificfg_nodename(): "
		    "set nodename_len=%d\n", isc->isc_nicknamelen));
	}

	for (i = 0; i < (outfp->wldp_length); i++)
		(void) mi_mpprintf_putc((char *)mp, buf[i]);
	iret = (int)(outfp->wldp_result);
	kmem_free(buf, MAX_BUF_LEN);
	return (iret);
}

static int
ath_wificfg_encryption(ath_t *asc, mblk_t *mp, uint32_t cmd)
{
	uint32_t i;
	char *buf;
	int iret;
	wldp_t *infp, *outfp;
	ieee80211com_t *isc = (ieee80211com_t *)asc;

	buf = kmem_zalloc(MAX_BUF_LEN, KM_SLEEP);
	outfp = (wldp_t *)buf;
	bcopy(mp->b_rptr, buf,  sizeof (wldp_t));
	infp = (wldp_t *)mp->b_rptr;
	outfp->wldp_length = offsetof(wldp_t, wldp_buf) +
	    sizeof (wl_encryption_t);
	if (cmd == WLAN_GET_PARAM) {
		*(wl_encryption_t *)(outfp->wldp_buf) =
		    (isc->isc_flags & IEEE80211_F_WEPON) ? 1 : 0;
		outfp->wldp_result = WL_SUCCESS;
	} else if (cmd == WLAN_SET_PARAM) {
		if (*(wl_encryption_t *)(infp->wldp_buf) ==
		    WL_NOENCRYPTION) {
			isc->isc_flags &= ~IEEE80211_F_WEPON;
		} else if (*(wl_encryption_t *)(infp->wldp_buf) ==
		    WL_ENC_WEP) {
			isc->isc_flags |= IEEE80211_F_WEPON;
		}
		ATH_DEBUG((ATH_DBG_WIFICFG, "ath: "
		    "ath_wificfg_encryption(): set encryption=%d\n",
		    (isc->isc_flags & IEEE80211_F_WEPON) ? 1 : 0));
		if (asc->asc_invalid == 0) {
			(void) ath_gld_start(isc->isc_dev);
			(void) _ieee80211_new_state(isc, IEEE80211_S_SCAN, -1);
		}
		outfp->wldp_result = WL_SUCCESS;
	}

	for (i = 0; i < (outfp->wldp_length); i++)
		(void) mi_mpprintf_putc((char *)mp, buf[i]);
	iret = (int)(outfp->wldp_result);
	kmem_free(buf, MAX_BUF_LEN);
	return (iret);
}

static int
ath_wificfg_wepkey(ath_t *asc, mblk_t *mp, uint32_t cmd)
{
	uint32_t i;
	wldp_t *infp, *outfp;
	char *buf;
	int iret;
	wl_wep_key_t *p_wepkey_tab;
	ieee80211com_t *isc = (ieee80211com_t *)asc;

	buf = kmem_zalloc(MAX_BUF_LEN, KM_SLEEP);
	outfp = (wldp_t *)buf;
	bcopy(mp->b_rptr, buf,  sizeof (wldp_t));
	infp = (wldp_t *)mp->b_rptr;

	outfp->wldp_length = offsetof(wldp_t, wldp_buf) +
	    sizeof (wl_wep_key_tab_t);

	if (cmd == WLAN_GET_PARAM) {
		outfp->wldp_result = WL_WRITEONLY;
	} else if (cmd == WLAN_SET_PARAM) {
		p_wepkey_tab = (wl_wep_key_t *)(infp->wldp_buf);
		for (i = 0; i < MAX_NWEPKEYS; i++) {
			if (p_wepkey_tab[i].wl_wep_operation == WL_ADD) {
				isc->isc_nw_keys[i].iwk_len =
				    p_wepkey_tab[i].wl_wep_length;
				bcopy(p_wepkey_tab[i].wl_wep_key,
				    isc->isc_nw_keys[i].iwk_key,
				    p_wepkey_tab[i].wl_wep_length);
			}
		}
		if (asc->asc_invalid == 0) {
			(void) ath_gld_start(isc->isc_dev);
			(void) _ieee80211_new_state(isc, IEEE80211_S_SCAN, -1);
		}
		outfp->wldp_result = WL_SUCCESS;
	}

	for (i = 0; i < (outfp->wldp_length); i++)
		(void) mi_mpprintf_putc((char *)mp, buf[i]);
	iret = (int)(outfp->wldp_result);
	kmem_free(buf, MAX_BUF_LEN);
	return (iret);

}

static int
ath_wificfg_keyid(ath_t *asc, mblk_t *mp, uint32_t cmd)
{
	uint32_t i;
	char *buf;
	int iret;
	wldp_t *infp, *outfp;
	ieee80211com_t *isc = (ieee80211com_t *)asc;
	wl_wep_key_id_t keyid;

	buf = kmem_zalloc(MAX_BUF_LEN, KM_SLEEP);
	outfp = (wldp_t *)buf;
	bcopy(mp->b_rptr, buf,  sizeof (wldp_t));
	infp = (wldp_t *)mp->b_rptr;

	outfp->wldp_length = offsetof(wldp_t, wldp_buf) +
	    sizeof (wl_wep_key_id_t);

	if (cmd == WLAN_GET_PARAM) {
		*(wl_wep_key_id_t *)(outfp->wldp_buf) =
		    isc->isc_wep_txkey;
		outfp->wldp_result = WL_SUCCESS;
	} else if (cmd == WLAN_SET_PARAM) {
		keyid = *(wl_wep_key_id_t *)(infp->wldp_buf);
		if (keyid >= MAX_NWEPKEYS) {
			outfp->wldp_result = WL_NOTSUPPORTED;
		} else {
			isc->isc_wep_txkey = keyid;
			ATH_DEBUG((ATH_DBG_WIFICFG,
			    "ath: ath_wificfg_keyid(): set wepkeyid=%d\n",
			    isc->isc_wep_txkey));
			if (asc->asc_invalid == 0) {
				(void) ath_gld_start(isc->isc_dev);
				(void) _ieee80211_new_state(isc,
				    IEEE80211_S_SCAN, -1);
			}
			outfp->wldp_result = WL_SUCCESS;
		}
	}

	for (i = 0; i < (outfp->wldp_length); i++)
		(void) mi_mpprintf_putc((char *)mp, buf[i]);
	iret = (int)(outfp->wldp_result);
	kmem_free(buf, MAX_BUF_LEN);
	return (iret);
}

/*
 * Units are in db above the noise floor. That means the
 * rssi values reported in the tx/rx descriptors in the
 * driver are the SNR expressed in db.
 */
static void
ath_getrssi(struct ieee80211_node *in, wl_rssi_t *rssi)
{
	wl_rssi_t val, max_val;

	max_val = 63; /* Max rssi */
	val = (wl_rssi_t)in->in_recv_hist[in->in_hist_cur].irh_rssi;
	ATH_DEBUG((ATH_DBG_WIFICFG, "ath: ath_getrssi(): "
	    "rssi: %d\n", val));
	if (val > max_val)
		val = max_val;	/* Max rssi */
	if (max_val > MAX_RSSI)
		*rssi = (wl_rssi_t)((val + (double)max_val / MAX_RSSI - 1) /
			max_val * MAX_RSSI);
	else
		*rssi = (wl_rssi_t)((double)val / max_val * MAX_RSSI);
}

static void
ath_wait_scan(ath_t *asc)
{
	ieee80211com_t *isc = (ieee80211com_t *)asc;

	while (isc->isc_flags & IEEE80211_F_ASCAN) {
		if (cv_timedwait(&isc->isc_scan_cv, &isc->isc_genlock,
		    ddi_get_lbolt() + drv_usectohz(6000000)) != 0)
			break;
	}
}

static int
ath_wificfg_esslist(ath_t *asc, mblk_t *mp, uint32_t cmd)
{
	_NOTE(ARGUNUSED(cmd))

	char *buf;
	int iret;
	uint32_t i, essid_num;
	struct ieee80211_node *in;
	wldp_t *outfp;
	wl_ess_conf_t *p_ess_conf;
	ieee80211com_t *isc = (ieee80211com_t *)asc;

	/* Wait scan finish */
	ath_wait_scan(asc);

	buf = kmem_zalloc(MAX_BUF_LEN, KM_SLEEP);
	outfp = (wldp_t *)buf;
	bcopy(mp->b_rptr, buf,  sizeof (wldp_t));

	essid_num = 0;
	in = list_head(&isc->isc_in_list);
	while (in != NULL) {
		p_ess_conf = (wl_ess_conf_t *)
		    (buf + offsetof(wldp_t, wldp_buf) +
		    offsetof(wl_ess_list_t, wl_ess_list_ess) +
		    essid_num * sizeof (wl_ess_conf_t));

		if (p_ess_conf > (wl_ess_conf_t *)
		    (buf + MAX_BUF_LEN - sizeof (wl_ess_conf_t)))
			break;

		bcopy(in->in_essid,
		    p_ess_conf->wl_ess_conf_essid.wl_essid_essid,
		    in->in_esslen);
		bcopy(in->in_bssid, p_ess_conf->wl_ess_conf_bssid, 6);
		(p_ess_conf->wl_phy_conf).wl_phy_dsss_conf.wl_dsss_subtype =
		    WL_DSSS;
		p_ess_conf->wl_ess_conf_wepenabled =
		    (in->in_capinfo & IEEE80211_CAPINFO_PRIVACY ?
		    WL_ENC_WEP : WL_NOENCRYPTION);
		p_ess_conf->wl_ess_conf_bsstype =
		    (in->in_capinfo & IEEE80211_CAPINFO_ESS ?
		    WL_BSS_BSS : WL_BSS_IBSS);
		ath_getrssi(in, &(p_ess_conf->wl_ess_conf_sl));

		essid_num++;
		in = list_next(&isc->isc_in_list, in);
	}

	((wl_ess_list_t *)(outfp->wldp_buf))->wl_ess_list_num = essid_num;
	outfp->wldp_length = offsetof(wldp_t, wldp_buf) +
	    offsetof(wl_ess_list_t, wl_ess_list_ess) +
	    essid_num * sizeof (wl_ess_conf_t);
	outfp->wldp_result = WL_SUCCESS;

	for (i = 0; i < (outfp->wldp_length); i++)
		(void) mi_mpprintf_putc((char *)mp, buf[i]);
	iret = (int)(outfp->wldp_result);
	kmem_free(buf, MAX_BUF_LEN);
	return (iret);
}

static int
ath_wificfg_supportrates(ath_t *asc, mblk_t *mp, uint32_t cmd)
{
	_NOTE(ARGUNUSED(asc))

	uint16_t i;
	wldp_t *outfp;
	char *buf;
	ieee80211com_t *isc = (ieee80211com_t *)asc;
	struct ieee80211_node *in = isc->isc_bss;
	const struct ieee80211_rateset *rs;
	wl_rates_t *rates;

	buf = kmem_zalloc(MAX_BUF_LEN, KM_SLEEP);
	outfp = (wldp_t *)buf;
	bcopy(mp->b_rptr, buf,  sizeof (wldp_t));

	rs = &isc->isc_sup_rates[ieee80211_chan2mode(isc, in->in_chan)];
	rates = (wl_rates_t *)(outfp->wldp_buf);
	if (cmd == WLAN_GET_PARAM) {
		rates->wl_rates_num = rs->ir_nrates;
		for (i = 0; i < rs->ir_nrates; i++) {
			rates->wl_rates_rates[i] = rs->ir_rates[i] &
				IEEE80211_RATE_VAL;
		}
		outfp->wldp_length = WIFI_BUF_OFFSET +
			offsetof(wl_rates_t, wl_rates_rates) +
			rs->ir_nrates * sizeof (char);
		outfp->wldp_result = WL_SUCCESS;
		for (i = 0; i < (outfp->wldp_length); i++)
			(void) mi_mpprintf_putc((char *)mp, buf[i]);
	}

	kmem_free(buf, MAX_BUF_LEN);
	return (WL_SUCCESS);
}

static int
ath_wificfg_desiredrates(ath_t *asc, mblk_t *mp, uint32_t cmd)
{
	uint32_t i;
	int rate, iret;
	char *buf;
	wldp_t *outfp;

	ieee80211com_t *isc = (ieee80211com_t *)asc;
	struct ieee80211_node *in = isc->isc_bss;
	struct ieee80211_rateset *rs = &in->in_rates;

	/*
	 * Here rate is a full duplex speed, wificonfig will divide it
	 * by 2 when display to user. From the wificonfig point of view,
	 * 'rate' is just a transmiting rate.
	 */
	rate = (rs->ir_rates[in->in_txrate] & IEEE80211_RATE_VAL);

	buf = kmem_zalloc(MAX_BUF_LEN, KM_SLEEP);
	outfp = (wldp_t *)buf;
	bcopy(mp->b_rptr, buf,  sizeof (wldp_t));

	if (cmd == WLAN_GET_PARAM) {
		((wl_rates_t *)(outfp->wldp_buf))->wl_rates_num = 1;
		(((wl_rates_t *)(outfp->wldp_buf))->wl_rates_rates)[0] = rate;
		outfp->wldp_length = WIFI_BUF_OFFSET +
			offsetof(wl_rates_t, wl_rates_rates) + sizeof (char);
		ATH_DEBUG((ATH_DBG_WIFICFG, "ath: "
		    "ath_wificfg_desiredrates(): current rate=%dM\n", rate));
		outfp->wldp_result = WL_SUCCESS;
	} else if (cmd == WLAN_SET_PARAM) {
		outfp->wldp_length = WIFI_BUF_OFFSET;
		outfp->wldp_result = WL_SUCCESS;
	}

	for (i = 0; i < (outfp->wldp_length); i++)
		(void) mi_mpprintf_putc((char *)mp, buf[i]);
	iret = (int)(outfp->wldp_result);
	kmem_free(buf, MAX_BUF_LEN);
	return (iret);
}

static int
ath_wificfg_authmode(ath_t *asc, mblk_t *mp, uint32_t cmd)
{
	_NOTE(ARGUNUSED(asc))

	uint32_t i, authmode;
	char *buf;
	int iret;
	wldp_t *infp, *outfp;

	buf = kmem_zalloc(MAX_BUF_LEN, KM_SLEEP);
	outfp = (wldp_t *)buf;
	bcopy(mp->b_rptr, buf,  sizeof (wldp_t));
	infp = (wldp_t *)mp->b_rptr;

	outfp->wldp_length = WIFI_BUF_OFFSET + sizeof (wl_authmode_t);
	outfp->wldp_result = WL_SUCCESS;
	if (cmd == WLAN_GET_PARAM) {
		*(wl_authmode_t *)(outfp->wldp_buf) = WL_OPENSYSTEM;
	} else if (cmd == WLAN_SET_PARAM) {
		authmode = *(wl_authmode_t *)(infp->wldp_buf);
		if (authmode != WL_OPENSYSTEM) {
			outfp->wldp_length = WIFI_BUF_OFFSET;
			outfp->wldp_result = WL_LACK_FEATURE;
		}
	}

	for (i = 0; i < (outfp->wldp_length); i++)
		(void) mi_mpprintf_putc((char *)mp, buf[i]);
	iret = (int)(outfp->wldp_result);
	kmem_free(buf, MAX_BUF_LEN);
	return (iret);
}

static int
ath_wificfg_bsstype(ath_t *asc, mblk_t *mp, uint32_t cmd)
{
	_NOTE(ARGUNUSED(asc))

	uint32_t i, bss_type;
	char *buf;
	int iret;
	wldp_t *infp, *outfp;

	buf = kmem_zalloc(MAX_BUF_LEN, KM_SLEEP);
	outfp = (wldp_t *)buf;
	bcopy(mp->b_rptr, buf,  sizeof (wldp_t));
	infp = (wldp_t *)mp->b_rptr;
	outfp->wldp_length = WIFI_BUF_OFFSET + sizeof (wl_bss_type_t);
	outfp->wldp_result = WL_SUCCESS;
	if (cmd == WLAN_GET_PARAM) {
		*(wl_bss_type_t *)(outfp->wldp_buf) = WL_BSS_BSS;
	} else if (cmd == WLAN_SET_PARAM) {
		bss_type = (uint16_t)(*(wl_bss_type_t *)(infp->wldp_buf));
		if (bss_type != WL_BSS_BSS) {
			outfp->wldp_length = WIFI_BUF_OFFSET;
			outfp->wldp_result = WL_LACK_FEATURE;
		}
	}

	for (i = 0; i < (outfp->wldp_length); i++)
		(void) mi_mpprintf_putc((char *)mp, buf[i]);
	iret = (int)(outfp->wldp_result);
	kmem_free(buf, MAX_BUF_LEN);
	return (iret);
}

static int
ath_wificfg_linkstatus(ath_t *asc, mblk_t *mp, uint32_t cmd)
{
	uint32_t i;
	char *buf;
	int iret;
	wldp_t *outfp;
	ieee80211com_t *isc = (ieee80211com_t *)asc;

	buf = kmem_zalloc(MAX_BUF_LEN, KM_SLEEP);
	outfp = (wldp_t *)buf;
	bcopy(mp->b_rptr, buf,  sizeof (wldp_t));

	outfp->wldp_length = WIFI_BUF_OFFSET + sizeof (wl_linkstatus_t);
	outfp->wldp_result = WL_SUCCESS;

	if (cmd == WLAN_GET_PARAM) {
		*(wl_linkstatus_t *)(outfp->wldp_buf) =
		    (IEEE80211_S_RUN == isc->isc_state) ?
		    WL_CONNECTED : WL_NOTCONNECTED;
	} else if (cmd == WLAN_SET_PARAM) {
		outfp->wldp_length = WIFI_BUF_OFFSET;
		outfp->wldp_result = WL_NOTSUPPORTED;
	}

	for (i = 0; i < (outfp->wldp_length); i++)
		(void) mi_mpprintf_putc((char *)mp, buf[i]);
	iret = (int)(outfp->wldp_result);
	kmem_free(buf, MAX_BUF_LEN);
	return (iret);
}

static int
ath_wificfg_rssi(ath_t *asc, mblk_t *mp, uint32_t cmd)
{
	uint32_t i;
	char *buf;
	int iret;
	wldp_t *outfp;

	ieee80211com_t *isc = (ieee80211com_t *)asc;
	struct ieee80211_node *in = isc->isc_bss;

	buf = kmem_zalloc(MAX_BUF_LEN, KM_SLEEP);
	outfp = (wldp_t *)buf;
	bcopy(mp->b_rptr, buf,  sizeof (wldp_t));

	outfp->wldp_length = WIFI_BUF_OFFSET + sizeof (wl_rssi_t);
	outfp->wldp_result = WL_SUCCESS;

	if (cmd == WLAN_GET_PARAM) {
		ath_getrssi(in, (wl_rssi_t *)(outfp->wldp_buf));
	} else if (cmd == WLAN_SET_PARAM) {
		outfp->wldp_length = WIFI_BUF_OFFSET;
		outfp->wldp_result = WL_NOTSUPPORTED;
	}

	for (i = 0; i < (outfp->wldp_length); i++)
		(void) mi_mpprintf_putc((char *)mp, buf[i]);
	iret = (int)(outfp->wldp_result);
	kmem_free(buf, MAX_BUF_LEN);
	return (iret);
}

static int
ath_wificfg_scan(ath_t *asc)
{
	int iret = WL_SUCCESS;
	ieee80211com_t *isc = (ieee80211com_t *)asc;

	if (asc->asc_invalid == 0 && isc->isc_state == IEEE80211_S_INIT) {
		(void) _ieee80211_new_state(isc, IEEE80211_S_SCAN, -1);
		ath_wait_scan(asc);
		(void) _ieee80211_new_state(isc, IEEE80211_S_INIT, -1);
	}
	return (iret);
}

static void
ath_loaddefdata(ath_t *asc)
{
	int i;
	ieee80211com_t *isc = (ieee80211com_t *)asc;
	struct ieee80211_node *in = isc->isc_bss;
	struct ieee80211_rateset *rs = &in->in_rates;

	if (isc->isc_flags & IEEE80211_F_DESBSSID)
		bzero(isc->isc_des_bssid, IEEE80211_ADDR_LEN);
	else
		bzero(isc->isc_bss->in_bssid, IEEE80211_ADDR_LEN);
	isc->isc_des_esslen = 0;
	isc->isc_des_essid[0] = 0;
	isc->isc_bss->in_essid[0] = 0;
	rs->ir_rates[in->in_txrate] = 0;	/* rate */
	isc->isc_flags &= ~IEEE80211_F_WEPON;	/* encryption */
	isc->isc_wep_txkey = 0;			/* wepkey id */
	for (i = 0; i < MAX_NWEPKEYS; i++)	/* wepkey */
		isc->isc_nw_keys[i].iwk_len = 0;
	for (i = 0; i < IEEE80211_RECV_HIST_LEN; ++i)
		in->in_recv_hist[i].irh_rssi = 0;
	in->in_hist_cur = IEEE80211_RECV_HIST_LEN - 1;
}

static int
ath_wificfg_loaddefaults(ath_t *asc)
{
	ieee80211com_t *isc = (ieee80211com_t *)asc;

	ath_loaddefdata(asc);

	if (asc->asc_invalid == 0) {
		(void) ath_gld_start(isc->isc_dev);
		(void) _ieee80211_new_state(isc, IEEE80211_S_SCAN, -1);
	}

	return (WL_SUCCESS);
}

static int
ath_wificfg_disassoc(ath_t *asc)
{
	ieee80211com_t *isc = (ieee80211com_t *)asc;

	if (! asc->asc_invalid) {
		(void) _ieee80211_new_state(isc, IEEE80211_S_INIT, -1);
		ath_loaddefdata(asc);
	}
	return (WL_SUCCESS);
}

int32_t
ath_getset(ath_t *asc, mblk_t *mp, uint32_t cmd)
{
	uint32_t i, id;
	char *buf;
	int ret;
	wldp_t *infp, *outfp;

	ret = WL_SUCCESS;
	infp = (wldp_t *)mp->b_rptr;
	id = infp->wldp_id;

	switch (id) {
	case WL_ESSID:
		ret = ath_wificfg_essid(asc, mp, cmd);
		break;
	case WL_BSSID:
		ret = ath_wificfg_bssid(asc, mp, cmd);
		break;
	case WL_NODE_NAME:
		ret = ath_wificfg_nodename(asc, mp, cmd);
		break;
	case WL_ENCRYPTION:
		ret = ath_wificfg_encryption(asc, mp, cmd);
		break;
	case WL_WEP_KEY_TAB:
		ret = ath_wificfg_wepkey(asc, mp, cmd);
		break;
	case WL_WEP_KEY_ID:
		ret = ath_wificfg_keyid(asc, mp, cmd);
		break;
	case WL_ESS_LIST:
		ret = ath_wificfg_esslist(asc, mp, cmd);
		break;
	case WL_SUPPORTED_RATES:
		ret = ath_wificfg_supportrates(asc, mp, cmd);
		break;
	case WL_DESIRED_RATES:
		ret = ath_wificfg_desiredrates(asc, mp, cmd);
		break;
	case WL_AUTH_MODE:
		ret = ath_wificfg_authmode(asc, mp, cmd);
		break;
	case WL_BSS_TYPE:
		ret = ath_wificfg_bsstype(asc, mp, cmd);
		break;
	case WL_LINKSTATUS:
		ret = ath_wificfg_linkstatus(asc, mp, cmd);
		break;
	case WL_RSSI:
		ret = ath_wificfg_rssi(asc, mp, cmd);
		break;
	case WL_SCAN:
		ret = ath_wificfg_scan(asc);
		break;
	case WL_LOAD_DEFAULTS:
		ret = ath_wificfg_loaddefaults(asc);
		break;
	case WL_DISASSOCIATE:
		ret = ath_wificfg_disassoc(asc);
		break;
	default:
		buf = kmem_zalloc(MAX_BUF_LEN, KM_SLEEP);
		outfp = (wldp_t *)buf;
		bcopy(mp->b_rptr, buf,  sizeof (wldp_t));
		outfp->wldp_length = offsetof(wldp_t, wldp_buf);
		outfp->wldp_result = WL_LACK_FEATURE;
		for (i = 0; i < (outfp->wldp_length); i++)
			(void) mi_mpprintf_putc((char *)mp, buf[i]);
		kmem_free(buf, MAX_BUF_LEN);
		break;
	}
	return (ret);
}
