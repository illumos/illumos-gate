/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2001 Atsushi Onoe
 * Copyright (c) 2002-2005 Sam Leffler, Errno Consulting
 * All rights reserved.
 *
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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * IEEE 802.11 protocol support
 */

#include "net80211_impl.h"

const char *ieee80211_mgt_subtype_name[] = {
	"assoc_req",	"assoc_resp",	"reassoc_req",	"reassoc_resp",
	"probe_req",	"probe_resp",	"reserved#6",	"reserved#7",
	"beacon",	"atim",		"disassoc",	"auth",
	"deauth",	"reserved#13",	"reserved#14",	"reserved#15"
};
const char *ieee80211_ctl_subtype_name[] = {
	"reserved#0",	"reserved#1",	"reserved#2",	"reserved#3",
	"reserved#3",	"reserved#5",	"reserved#6",	"reserved#7",
	"reserved#8",	"reserved#9",	"ps_poll",	"rts",
	"cts",		"ack",		"cf_end",	"cf_end_ack"
};
const char *ieee80211_state_name[IEEE80211_S_MAX] = {
	"INIT",		/* IEEE80211_S_INIT */
	"SCAN",		/* IEEE80211_S_SCAN */
	"AUTH",		/* IEEE80211_S_AUTH */
	"ASSOC",	/* IEEE80211_S_ASSOC */
	"RUN"		/* IEEE80211_S_RUN */
};

static int ieee80211_newstate(ieee80211com_t *, enum ieee80211_state, int);

/*
 * Initialize the interface softc, ic, with protocol management
 * related data structures and functions.
 */
void
ieee80211_proto_attach(ieee80211com_t *ic)
{
	struct ieee80211_impl *im = ic->ic_private;

	ic->ic_rtsthreshold = IEEE80211_RTS_DEFAULT;
	ic->ic_fragthreshold = IEEE80211_FRAG_DEFAULT;
	ic->ic_fixed_rate = IEEE80211_FIXED_RATE_NONE;
	ic->ic_mcast_rate = IEEE80211_MCAST_RATE_DEFAULT;
	ic->ic_protmode = IEEE80211_PROT_CTSONLY;
	im->im_bmiss_max = IEEE80211_BMISS_MAX;

	/* protocol state change handler */
	ic->ic_newstate = ieee80211_newstate;

	/* initialize management frame handlers */
	ic->ic_recv_mgmt = ieee80211_recv_mgmt;
	ic->ic_send_mgmt = ieee80211_send_mgmt;
}

/*
 * Print a 802.11 frame header
 */
void
ieee80211_dump_pkt(const uint8_t *buf, int32_t len, int32_t rate, int32_t rssi)
{
	struct ieee80211_frame *wh;
	int8_t buf1[100];
	int8_t buf2[25];
	int i;

	bzero(buf1, sizeof (buf1));
	bzero(buf2, sizeof (buf2));
	wh = (struct ieee80211_frame *)buf;
	switch (wh->i_fc[1] & IEEE80211_FC1_DIR_MASK) {
	case IEEE80211_FC1_DIR_NODS:
		(void) snprintf(buf2, sizeof (buf2), "NODS %s",
			ieee80211_macaddr_sprintf(wh->i_addr2));
		(void) strncat(buf1, buf2, sizeof (buf2));
		(void) snprintf(buf2, sizeof (buf2), "->%s",
			ieee80211_macaddr_sprintf(wh->i_addr1));
		(void) strncat(buf1, buf2, sizeof (buf2));
		(void) snprintf(buf2, sizeof (buf2), "(%s)",
			ieee80211_macaddr_sprintf(wh->i_addr3));
		(void) strncat(buf1, buf2, sizeof (buf2));
		break;
	case IEEE80211_FC1_DIR_TODS:
		(void) snprintf(buf2, sizeof (buf2), "TODS %s",
			ieee80211_macaddr_sprintf(wh->i_addr2));
		(void) strncat(buf1, buf2, sizeof (buf2));
		(void) snprintf(buf2, sizeof (buf2), "->%s",
			ieee80211_macaddr_sprintf(wh->i_addr3));
		(void) strncat(buf1, buf2, sizeof (buf2));
		(void) snprintf(buf2, sizeof (buf2), "(%s)",
			ieee80211_macaddr_sprintf(wh->i_addr1));
		(void) strncat(buf1, buf2, sizeof (buf2));
		break;
	case IEEE80211_FC1_DIR_FROMDS:
		(void) snprintf(buf2, sizeof (buf2), "FRDS %s",
			ieee80211_macaddr_sprintf(wh->i_addr3));
		(void) strncat(buf1, buf2, sizeof (buf2));
		(void) snprintf(buf2, sizeof (buf2), "->%s",
			ieee80211_macaddr_sprintf(wh->i_addr1));
		(void) strncat(buf1, buf2, sizeof (buf2));
		(void) snprintf(buf2, sizeof (buf2), "(%s)",
			ieee80211_macaddr_sprintf(wh->i_addr2));
		(void) strncat(buf1, buf2, sizeof (buf2));
		break;
	case IEEE80211_FC1_DIR_DSTODS:
		(void) snprintf(buf2, sizeof (buf2), "DSDS %s",
			ieee80211_macaddr_sprintf((uint8_t *)&wh[1]));
		(void) strncat(buf1, buf2, sizeof (buf2));
		(void) snprintf(buf2, sizeof (buf2), "->%s  ",
			ieee80211_macaddr_sprintf(wh->i_addr3));
		(void) strncat(buf1, buf2, sizeof (buf2));
		(void) snprintf(buf2, sizeof (buf2), "%s",
			ieee80211_macaddr_sprintf(wh->i_addr2));
		(void) strncat(buf1, buf2, sizeof (buf2));
		(void) snprintf(buf2, sizeof (buf2), "->%s",
			ieee80211_macaddr_sprintf(wh->i_addr1));
		(void) strncat(buf1, buf2, sizeof (buf2));
		break;
	}
	ieee80211_dbg(IEEE80211_MSG_ANY, "ieee80211_dump_pkt(): %s", buf1);
	bzero(buf1, sizeof (buf1));

	switch (wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) {
	case IEEE80211_FC0_TYPE_DATA:
		(void) sprintf(buf2, "data");
		break;
	case IEEE80211_FC0_TYPE_MGT:
		(void) snprintf(buf2, sizeof (buf2), "%s",
			ieee80211_mgt_subtype_name[
				(wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK)
				>> IEEE80211_FC0_SUBTYPE_SHIFT]);
		break;
	default:
		(void) snprintf(buf2, sizeof (buf2), "type#%d",
			wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK);
		break;
	}
	(void) strncat(buf1, buf2, sizeof (buf2));
	if (wh->i_fc[1] & IEEE80211_FC1_WEP) {
		(void) sprintf(buf2, " WEP");
		(void) strcat(buf1, buf2);
	}
	if (rate >= 0) {
		(void) snprintf(buf2,  sizeof (buf2), " %dM", rate / 2);
		(void) strncat(buf1, buf2, sizeof (buf2));
	}
	if (rssi >= 0) {
		(void) snprintf(buf2,  sizeof (buf2), " +%d", rssi);
		(void) strncat(buf1, buf2, sizeof (buf2));
	}
	ieee80211_dbg(IEEE80211_MSG_ANY, "ieee80211_dump_pkt(): %s", buf1);
	bzero(buf1, sizeof (buf1));

	if (len > 0) {
		for (i = 0; i < (len > 40 ? 40 : len); i++) {
			if ((i & 0x03) == 0)
				(void) strcat(buf1, " ");
			(void) snprintf(buf2, 3, "%02x", buf[i]);
			(void) strncat(buf1, buf2, 3);
		}
		ieee80211_dbg(IEEE80211_MSG_ANY, "ieee80211_dump_pkt(): %s",
			buf1);
	}
}

/*
 * Adjust/Fix the specified node's rate table
 *
 * in   node
 * flag IEEE80211_F_DOSORT : sort the node's rate table
 *      IEEE80211_F_DONEGO : mark a rate as basic rate if it is
 *                           a device's basic rate
 *      IEEE80211_F_DODEL  : delete rates not supported by the device
 *      IEEE80211_F_DOFRATE: check if the fixed rate is supported by
 *                           the device
 *
 * The highest bit of returned rate value is set to 1 on failure.
 */
int
ieee80211_fix_rate(ieee80211_node_t *in, int flags)
{
	ieee80211com_t *ic = in->in_ic;
	struct ieee80211_rateset *srs;
	struct ieee80211_rateset *nrs;
	boolean_t ignore;
	int i;
	int okrate;
	int badrate;
	int fixedrate;
	uint8_t r;

	/*
	 * If the fixed rate check was requested but no
	 * fixed has been defined then just remove it.
	 */
	if ((flags & IEEE80211_F_DOFRATE) &&
	    (ic->ic_fixed_rate == IEEE80211_FIXED_RATE_NONE)) {
		flags &= ~IEEE80211_F_DOFRATE;
	}
	if (in->in_chan == IEEE80211_CHAN_ANYC) {
		return (IEEE80211_RATE_BASIC);
	}
	okrate = badrate = fixedrate = 0;
	srs = &ic->ic_sup_rates[ieee80211_chan2mode(ic, in->in_chan)];
	nrs = &in->in_rates;
	for (i = 0; i < nrs->ir_nrates; ) {
		int j;

		ignore = B_FALSE;
		if (flags & IEEE80211_F_DOSORT) {
			/*
			 * Sort rates.
			 */
			for (j = i + 1; j < nrs->ir_nrates; j++) {
				if (IEEE80211_RV(nrs->ir_rates[i]) >
				    IEEE80211_RV(nrs->ir_rates[j])) {
					r = nrs->ir_rates[i];
					nrs->ir_rates[i] = nrs->ir_rates[j];
					nrs->ir_rates[j] = r;
				}
			}
		}
		r = IEEE80211_RV(nrs->ir_rates[i]);
		badrate = r;

		/*
		 * Check against supported rates.
		 */
		for (j = 0; j < srs->ir_nrates; j++) {
			if (r == IEEE80211_RV(srs->ir_rates[j])) {
				/*
				 * Overwrite with the supported rate
				 * value so any basic rate bit is set.
				 * This insures that response we send
				 * to stations have the necessary basic
				 * rate bit set.
				 */
				if (flags & IEEE80211_F_DONEGO)
					nrs->ir_rates[i] = srs->ir_rates[j];
				break;
			}
		}
		if (j == srs->ir_nrates) {
			/*
			 * A rate in the node's rate set is not
			 * supported. We just discard/ignore the rate.
			 * Note that this is important for 11b stations
			 * when they want to associate with an 11g AP.
			 */
			ignore = B_TRUE;
		}

		if (flags & IEEE80211_F_DODEL) {
			/*
			 * Delete unacceptable rates.
			 */
			if (ignore) {
				nrs->ir_nrates--;
				for (j = i; j < nrs->ir_nrates; j++)
					nrs->ir_rates[j] = nrs->ir_rates[j + 1];
				nrs->ir_rates[j] = 0;
				continue;
			}
		}
		if (flags & IEEE80211_F_DOFRATE) {
			/*
			 * Check any fixed rate is included.
			 */
			if (r == ic->ic_fixed_rate)
				fixedrate = r;
		}
		if (!ignore)
			okrate = nrs->ir_rates[i];
		i++;
	}
	if (okrate == 0 || ((flags & IEEE80211_F_DOFRATE) && fixedrate == 0))
		return (badrate | IEEE80211_RATE_BASIC);
	else
		return (IEEE80211_RV(okrate));
}

/*
 * Reset 11g-related state.
 */
void
ieee80211_reset_erp(ieee80211com_t *ic)
{
	ic->ic_flags &= ~IEEE80211_F_USEPROT;
	/*
	 * Short slot time is enabled only when operating in 11g
	 * and not in an IBSS.  We must also honor whether or not
	 * the driver is capable of doing it.
	 */
	ieee80211_set_shortslottime(ic,
		ic->ic_curmode == IEEE80211_MODE_11A);
	/*
	 * Set short preamble and ERP barker-preamble flags.
	 */
	if (ic->ic_curmode == IEEE80211_MODE_11A ||
	    (ic->ic_caps & IEEE80211_C_SHPREAMBLE)) {
		ic->ic_flags |= IEEE80211_F_SHPREAMBLE;
		ic->ic_flags &= ~IEEE80211_F_USEBARKER;
	} else {
		ic->ic_flags &= ~IEEE80211_F_SHPREAMBLE;
		ic->ic_flags |= IEEE80211_F_USEBARKER;
	}
}

/*
 * Change current channel to be the next available channel
 */
void
ieee80211_reset_chan(ieee80211com_t *ic)
{
	struct ieee80211_channel *ch = ic->ic_curchan;

	IEEE80211_LOCK(ic);
	do {
		if (++ch > &ic->ic_sup_channels[IEEE80211_CHAN_MAX])
			ch = &ic->ic_sup_channels[0];
		if (ieee80211_isset(ic->ic_chan_active,
		    ieee80211_chan2ieee(ic, ch))) {
			break;
		}
	} while (ch != ic->ic_curchan);
	ic->ic_curchan = ch;
	IEEE80211_UNLOCK(ic);
}

/*
 * Set the short slot time state and notify the driver.
 */
void
ieee80211_set_shortslottime(ieee80211com_t *ic, boolean_t on)
{
	if (on)
		ic->ic_flags |= IEEE80211_F_SHSLOT;
	else
		ic->ic_flags &= ~IEEE80211_F_SHSLOT;
	/* notify driver */
	if (ic->ic_set_shortslot != NULL)
		ic->ic_set_shortslot(ic, on);
}

/*
 * Mark the basic rates for the 11g rate table based on the
 * operating mode.  For real 11g we mark all the 11b rates
 * and 6, 12, and 24 OFDM.  For 11b compatibility we mark only
 * 11b rates.  There's also a pseudo 11a-mode used to mark only
 * the basic OFDM rates.
 */
void
ieee80211_setbasicrates(struct ieee80211_rateset *rs,
    enum ieee80211_phymode mode)
{
	static const struct ieee80211_rateset basic[] = {
		{ 0 },			/* IEEE80211_MODE_AUTO */
		{ 3, { 12, 24, 48 } },	/* IEEE80211_MODE_11A */
		{ 2, { 2, 4} },		/* IEEE80211_MODE_11B */
		{ 4, { 2, 4, 11, 22 } }, /* IEEE80211_MODE_11G mixed b/g */
		{ 0 },			/* IEEE80211_MODE_FH */
		{ 3, { 12, 24, 48 } },	/* IEEE80211_MODE_TURBO_A */
		{ 4, { 2, 4, 11, 22 } }	/* IEEE80211_MODE_TURBO_G (mixed b/g) */
	};
	int i, j;

	ASSERT(mode < IEEE80211_MODE_MAX);
	for (i = 0; i < rs->ir_nrates; i++) {
		rs->ir_rates[i] &= IEEE80211_RATE_VAL;
		for (j = 0; j < basic[mode].ir_nrates; j++) {
			if (basic[mode].ir_rates[j] == rs->ir_rates[i]) {
				rs->ir_rates[i] |= IEEE80211_RATE_BASIC;
				break;
			}
		}
	}
}

/*
 * Process STA mode beacon miss events. Send a direct probe request
 * frame to the current ap bmiss_max times (w/o answer) before
 * scanning for a new ap.
 */
void
ieee80211_beacon_miss(ieee80211com_t *ic)
{
	ieee80211_impl_t *im = ic->ic_private;

	if (ic->ic_flags & IEEE80211_F_SCAN)
		return;
	ieee80211_dbg(IEEE80211_MSG_STATE | IEEE80211_MSG_DEBUG,
		"%s\n", "beacon miss");

	/*
	 * Our handling is only meaningful for stations that are
	 * associated; any other conditions else will be handled
	 * through different means (e.g. the tx timeout on mgt frames).
	 */
	if (ic->ic_opmode != IEEE80211_M_STA ||
	    ic->ic_state != IEEE80211_S_RUN) {
		return;
	}

	IEEE80211_LOCK(ic);
	if (++im->im_bmiss_count < im->im_bmiss_max) {
		/*
		 * Send a directed probe req before falling back to a scan;
		 * if we receive a response ic_bmiss_count will be reset.
		 * Some cards mistakenly report beacon miss so this avoids
		 * the expensive scan if the ap is still there.
		 */
		IEEE80211_UNLOCK(ic);
		(void) ieee80211_send_probereq(ic->ic_bss, ic->ic_macaddr,
			ic->ic_bss->in_bssid, ic->ic_bss->in_bssid,
			ic->ic_bss->in_essid, ic->ic_bss->in_esslen,
			ic->ic_opt_ie, ic->ic_opt_ie_len);
		return;
	}
	im->im_bmiss_count = 0;
	IEEE80211_UNLOCK(ic);
	ieee80211_new_state(ic, IEEE80211_S_SCAN, 0);
}

/*
 * Manage state transition between INIT | AUTH | ASSOC | RUN.
 */
static int
ieee80211_newstate(ieee80211com_t *ic, enum ieee80211_state nstate, int arg)
{
	struct ieee80211_impl *im = ic->ic_private;
	ieee80211_node_t *in;
	enum ieee80211_state ostate;
	wifi_data_t wd = { 0 };

	IEEE80211_LOCK(ic);
	ostate = ic->ic_state;
	ieee80211_dbg(IEEE80211_MSG_STATE, "ieee80211_newstate(): "
		"%s -> %s\n",
		ieee80211_state_name[ostate], ieee80211_state_name[nstate]);
	ic->ic_state = nstate;
	in = ic->ic_bss;
	im->im_swbmiss_period = 0;	/* Reset software beacon miss period */

	switch (nstate) {
	case IEEE80211_S_INIT:
		IEEE80211_UNLOCK(ic);
		switch (ostate) {
		case IEEE80211_S_INIT:
			return (0);
		case IEEE80211_S_SCAN:
			ieee80211_cancel_scan(ic);
			break;
		case IEEE80211_S_AUTH:
			break;
		case IEEE80211_S_ASSOC:
			if (ic->ic_opmode == IEEE80211_M_STA) {
				IEEE80211_SEND_MGMT(ic, in,
					IEEE80211_FC0_SUBTYPE_DEAUTH,
					IEEE80211_REASON_AUTH_LEAVE);
			}
			break;
		case IEEE80211_S_RUN:
			if (ic->ic_opmode == IEEE80211_M_STA) {
				IEEE80211_SEND_MGMT(ic, in,
					IEEE80211_FC0_SUBTYPE_DISASSOC,
					IEEE80211_REASON_ASSOC_LEAVE);
				ieee80211_sta_leave(ic, in);
			}
			break;
		}
		IEEE80211_LOCK(ic);
		im->im_mgt_timer = 0;
		ieee80211_reset_bss(ic);
		break;
	case IEEE80211_S_SCAN:
		switch (ostate) {
		case IEEE80211_S_INIT:
			if (ic->ic_opmode == IEEE80211_M_IBSS &&
			    ic->ic_des_chan != IEEE80211_CHAN_ANYC) {
				/*
				 * AP operation and we already have a channel;
				 * bypass the scan and startup immediately.
				 */
				ieee80211_create_ibss(ic, ic->ic_des_chan);
			} else {
				IEEE80211_UNLOCK(ic);
				ieee80211_begin_scan(ic,
					(arg == 0) ? B_FALSE : B_TRUE);
				return (0);
			}
			break;
		case IEEE80211_S_SCAN:
			/*
			 * Scan next. If doing an active scan and the
			 * channel is not marked passive-only then send
			 * a probe request.  Otherwise just listen for
			 * beacons on the channel.
			 */
			if ((ic->ic_flags & IEEE80211_F_ASCAN) &&
			    !IEEE80211_IS_CHAN_PASSIVE(ic->ic_curchan)) {
				IEEE80211_UNLOCK(ic);
				(void) ieee80211_send_probereq(in,
					ic->ic_macaddr, wifi_bcastaddr,
					wifi_bcastaddr,
					ic->ic_des_essid, ic->ic_des_esslen,
					ic->ic_opt_ie, ic->ic_opt_ie_len);
				return (0);
			}
			break;
		case IEEE80211_S_RUN:
			/* beacon miss */
			ieee80211_dbg(IEEE80211_MSG_STATE,
				"no recent beacons from %s, rescanning\n",
				ieee80211_macaddr_sprintf(in->in_macaddr));
			IEEE80211_UNLOCK(ic);
			ieee80211_sta_leave(ic, in);
			IEEE80211_LOCK(ic);
			ic->ic_flags &= ~IEEE80211_F_SIBSS;
			/* FALLTHRU */
		case IEEE80211_S_AUTH:
		case IEEE80211_S_ASSOC:
			/* timeout restart scan */
			in = ieee80211_find_node(&ic->ic_scan,
				ic->ic_bss->in_macaddr);
			if (in != NULL) {
				in->in_fails++;
				ieee80211_unref_node(&in);
			}
			break;
		}
		break;
	case IEEE80211_S_AUTH:
		switch (ostate) {
		case IEEE80211_S_INIT:
		case IEEE80211_S_SCAN:
			IEEE80211_UNLOCK(ic);
			IEEE80211_SEND_MGMT(ic, in, IEEE80211_FC0_SUBTYPE_AUTH,
				1);
			return (0);
		case IEEE80211_S_AUTH:
		case IEEE80211_S_ASSOC:
			switch (arg) {
			case IEEE80211_FC0_SUBTYPE_AUTH:
				IEEE80211_UNLOCK(ic);
				IEEE80211_SEND_MGMT(ic, in,
					IEEE80211_FC0_SUBTYPE_AUTH, 2);
				return (0);
			case IEEE80211_FC0_SUBTYPE_DEAUTH:
				/* ignore and retry scan on timeout */
				break;
			}
			break;
		case IEEE80211_S_RUN:
			switch (arg) {
			case IEEE80211_FC0_SUBTYPE_AUTH:
				ic->ic_state = ostate;	/* stay RUN */
				IEEE80211_UNLOCK(ic);
				IEEE80211_SEND_MGMT(ic, in,
					IEEE80211_FC0_SUBTYPE_AUTH, 2);
				return (0);
			case IEEE80211_FC0_SUBTYPE_DEAUTH:
				IEEE80211_UNLOCK(ic);
				ieee80211_sta_leave(ic, in);
				/* try to re-auth */
				IEEE80211_SEND_MGMT(ic, in,
					IEEE80211_FC0_SUBTYPE_AUTH, 1);
				return (0);
			}
			break;
		}
		break;
	case IEEE80211_S_ASSOC:
		switch (ostate) {
		case IEEE80211_S_INIT:
		case IEEE80211_S_SCAN:
		case IEEE80211_S_ASSOC:
			ieee80211_dbg(IEEE80211_MSG_ANY, "ieee80211_newstate: "
				"invalid transition\n");
			break;
		case IEEE80211_S_AUTH:
			IEEE80211_UNLOCK(ic);
			IEEE80211_SEND_MGMT(ic, in,
				IEEE80211_FC0_SUBTYPE_ASSOC_REQ, 0);
			return (0);
		case IEEE80211_S_RUN:
			IEEE80211_UNLOCK(ic);
			ieee80211_sta_leave(ic, in);
			IEEE80211_SEND_MGMT(ic, in,
				IEEE80211_FC0_SUBTYPE_ASSOC_REQ, 1);
			return (0);
		}
		break;
	case IEEE80211_S_RUN:
		switch (ostate) {
		case IEEE80211_S_INIT:
			ieee80211_err("ieee80211_newstate: "
				"invalid transition\n");
			break;
		case IEEE80211_S_AUTH:
			ieee80211_err("ieee80211_newstate: "
				"invalid transition\n");
			break;
		case IEEE80211_S_SCAN:		/* adhoc/hostap mode */
		case IEEE80211_S_ASSOC:		/* infra mode */
			ASSERT(in->in_txrate < in->in_rates.ir_nrates);
			im->im_mgt_timer = 0;
			if (ic->ic_opmode == IEEE80211_M_STA)
				ieee80211_notify_node_join(ic, in);

			/*
			 * We can send data now; update the fastpath with our
			 * current associated BSSID and other relevant settings.
			 */
			wd.wd_secalloc = ieee80211_crypto_getciphertype(ic);
			wd.wd_opmode = ic->ic_opmode;
			IEEE80211_ADDR_COPY(wd.wd_bssid, in->in_bssid);
			(void) mac_pdata_update(ic->ic_mach, &wd, sizeof (wd));
			break;
		}

		/*
		 * When 802.1x is not in use mark the port authorized
		 * at this point so traffic can flow.
		 */
		if (in->in_authmode != IEEE80211_AUTH_8021X)
			ieee80211_node_authorize(in);
		/*
		 * Enable inactivity processing.
		 */
		ic->ic_scan.nt_inact_timer = IEEE80211_INACT_WAIT;
		ic->ic_sta.nt_inact_timer = IEEE80211_INACT_WAIT;
		break;	/* IEEE80211_S_RUN */
	} /* switch nstate */
	IEEE80211_UNLOCK(ic);

	return (0);
}
