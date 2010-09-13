/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2001 Atsushi Onoe
 * Copyright (c) 2002-2008 Sam Leffler, Errno Consulting
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

/*
 * Node management routines
 */

#include "net80211_impl.h"

static ieee80211_node_t *ieee80211_node_alloc(ieee80211com_t *);
static void ieee80211_node_cleanup(ieee80211_node_t *);
static void ieee80211_node_free(ieee80211_node_t *);
static uint8_t ieee80211_node_getrssi(const ieee80211_node_t *);
static void ieee80211_setup_node(ieee80211com_t *, ieee80211_node_table_t *,
    ieee80211_node_t *, const uint8_t *);
static void ieee80211_node_reclaim(ieee80211_node_table_t *,
    ieee80211_node_t *);
static void ieee80211_free_node_locked(ieee80211_node_t *);
static void ieee80211_free_allnodes(ieee80211_node_table_t *);
static void ieee80211_node_leave(ieee80211com_t *, ieee80211_node_t *);
static void ieee80211_timeout_scan_candidates(ieee80211_node_table_t *);
static void ieee80211_timeout_stations(ieee80211_node_table_t *);
static void ieee80211_node_table_init(ieee80211com_t *,
    ieee80211_node_table_t *, const char *, int, int,
    void (*timeout)(ieee80211_node_table_t *));
static void ieee80211_node_table_cleanup(ieee80211_node_table_t *);

/*
 * association failures before ignored
 * The failure may be caused by the response frame is lost for
 * environmental reason. So Try associate more than once before
 * ignore the node
 */
#define	IEEE80211_STA_FAILS_MAX	2

/*
 * Initialize node database management callbacks for the interface.
 * This function is called by ieee80211_attach(). These callback
 * functions may be overridden in special circumstances, as long as
 * as this is done after calling ieee80211_attach() and prior to any
 * other call which may allocate a node
 */
void
ieee80211_node_attach(ieee80211com_t *ic)
{
	struct ieee80211_impl *im = ic->ic_private;

	ic->ic_node_alloc = ieee80211_node_alloc;
	ic->ic_node_free = ieee80211_node_free;
	ic->ic_node_cleanup = ieee80211_node_cleanup;
	ic->ic_node_getrssi = ieee80211_node_getrssi;

	/* default station inactivity timer setings */
	im->im_inact_init = IEEE80211_INACT_INIT;
	im->im_inact_assoc = IEEE80211_INACT_ASSOC;
	im->im_inact_run = IEEE80211_INACT_RUN;
	im->im_inact_probe = IEEE80211_INACT_PROBE;
}

/*
 * Initialize node databases and the ic_bss node element.
 */
void
ieee80211_node_lateattach(ieee80211com_t *ic)
{
	/*
	 * Calculate ic_tim_bitmap size in bytes
	 * IEEE80211_AID_MAX defines maximum bits in ic_tim_bitmap
	 */
	ic->ic_tim_len = howmany(IEEE80211_AID_MAX, 8) * sizeof (uint8_t);

	ieee80211_node_table_init(ic, &ic->ic_sta, "station",
	    IEEE80211_INACT_INIT, IEEE80211_WEP_NKID,
	    ieee80211_timeout_stations);
	ieee80211_node_table_init(ic, &ic->ic_scan, "scan",
	    IEEE80211_INACT_SCAN, 0, ieee80211_timeout_scan_candidates);

	ieee80211_reset_bss(ic);
}

/*
 * Destroy all node databases and is usually called during device detach
 */
void
ieee80211_node_detach(ieee80211com_t *ic)
{
	/* Node Detach */
	if (ic->ic_bss != NULL) {
		ieee80211_free_node(ic->ic_bss);
		ic->ic_bss = NULL;
	}
	ieee80211_node_table_cleanup(&ic->ic_scan);
	ieee80211_node_table_cleanup(&ic->ic_sta);
}

/*
 * Increase a node's reference count
 *
 * Return pointer to the node
 */
ieee80211_node_t *
ieee80211_ref_node(ieee80211_node_t *in)
{
	ieee80211_node_incref(in);
	return (in);
}

/*
 * Dexrease a node's reference count
 */
void
ieee80211_unref_node(ieee80211_node_t **in)
{
	ieee80211_node_decref(*in);
	*in = NULL;			/* guard against use */
}

/*
 * Mark ports authorized for data traffic. This function is usually
 * used by 802.1x authenticator.
 */
void
ieee80211_node_authorize(ieee80211_node_t *in)
{
	ieee80211_impl_t *im = in->in_ic->ic_private;

	in->in_flags |= IEEE80211_NODE_AUTH;
	in->in_inact_reload = im->im_inact_run;
	in->in_inact = in->in_inact_reload;
}

/*
 * Mark ports unauthorized for data traffic. This function is usually
 * used by 802.1x authenticator.
 */
void
ieee80211_node_unauthorize(ieee80211_node_t *in)
{
	in->in_flags &= ~IEEE80211_NODE_AUTH;
}

/*
 * Set/change the channel.  The rate set is also updated as
 * to insure a consistent view by drivers.
 */
static void
ieee80211_node_setchan(ieee80211com_t *ic, ieee80211_node_t *in,
    struct ieee80211_channel *chan)
{
	if (chan == IEEE80211_CHAN_ANYC)
		chan = ic->ic_curchan;
	in->in_chan = chan;
	if (IEEE80211_IS_CHAN_HT(chan)) {
		/*
		 * Gotta be careful here; the rate set returned by
		 * ieee80211_get_suprates is actually any HT rate
		 * set so blindly copying it will be bad.  We must
		 * install the legacy rate est in ni_rates and the
		 * HT rate set in ni_htrates.
		 */
		in->in_htrates = *ieee80211_get_suphtrates(ic, chan);
	}
	in->in_rates = *ieee80211_get_suprates(ic, chan);
	/* in->in_rates = ic->ic_sup_rates[ieee80211_chan2mode(ic, chan)]; */
}

/*
 * Initialize the channel set to scan based on the available channels
 * and the current PHY mode.
 */
static void
ieee80211_reset_scan(ieee80211com_t *ic)
{
	ieee80211_impl_t	*im = ic->ic_private;

	if (ic->ic_des_chan != IEEE80211_CHAN_ANYC) {
		(void) memset(im->im_chan_scan, 0, sizeof (im->im_chan_scan));
		ieee80211_setbit(im->im_chan_scan,
		    ieee80211_chan2ieee(ic, ic->ic_des_chan));
	} else {
		bcopy(ic->ic_chan_active, im->im_chan_scan,
		    sizeof (ic->ic_chan_active));
	}
	ieee80211_dbg(IEEE80211_MSG_SCAN, "ieee80211_reset_scan(): "
	    "start chan %u\n", ieee80211_chan2ieee(ic, ic->ic_curchan));
}

/*
 * Begin an active scan. Initialize the node cache. The scan
 * begins on the next radio channel by calling ieee80211_next_scan().
 * The actual scanning is not automated. The driver itself
 * only handles setting the radio frequency and stepping through
 * the channels.
 */
void
ieee80211_begin_scan(ieee80211com_t *ic, boolean_t reset)
{
	IEEE80211_LOCK(ic);

	if (ic->ic_opmode != IEEE80211_M_HOSTAP)
		ic->ic_flags |= IEEE80211_F_ASCAN;
	ieee80211_dbg(IEEE80211_MSG_SCAN,
	    "begin %s scan in %s mode on channel %u\n",
	    (ic->ic_flags & IEEE80211_F_ASCAN) ?  "active" : "passive",
	    ieee80211_phymode_name[ic->ic_curmode],
	    ieee80211_chan2ieee(ic, ic->ic_curchan));

	/*
	 * Clear scan state and flush any previously seen AP's.
	 */
	ieee80211_reset_scan(ic);
	if (reset)
		ieee80211_free_allnodes(&ic->ic_scan);

	ic->ic_flags |= IEEE80211_F_SCAN;
	IEEE80211_UNLOCK(ic);

	/* Scan the next channel. */
	ieee80211_next_scan(ic);
}

/*
 * Switch to the next channel marked for scanning.
 * A driver is expected to first call ieee80211_begin_scan(),
 * to initialize the node cache, then set the radio channel
 * on the device. And then after a certain time has elapsed,
 * call ieee80211_next_scan() to move to the next channel.
 * Typically, a timeout routine is used to automate this process.
 */
void
ieee80211_next_scan(ieee80211com_t *ic)
{
	ieee80211_impl_t *im = ic->ic_private;
	struct ieee80211_channel *chan;

	IEEE80211_LOCK(ic);
	/*
	 * Insure any previous mgt frame timeouts don't fire.
	 * This assumes the driver does the right thing in
	 * flushing anything queued in the driver and below.
	 */
	im->im_mgt_timer = 0;

	chan = ic->ic_curchan;
	do {
		if (++chan > &ic->ic_sup_channels[IEEE80211_CHAN_MAX])
			chan = &ic->ic_sup_channels[0];
		if (ieee80211_isset(im->im_chan_scan,
		    ieee80211_chan2ieee(ic, chan))) {
			ieee80211_clrbit(im->im_chan_scan,
			    ieee80211_chan2ieee(ic, chan));
			ieee80211_dbg(IEEE80211_MSG_SCAN,
			    "ieee80211_next_scan: chan %d->%d\n",
			    ieee80211_chan2ieee(ic, ic->ic_curchan),
			    ieee80211_chan2ieee(ic, chan));
			ic->ic_curchan = chan;
			/*
			 * drivers should do this as needed,
			 * for now maintain compatibility
			 */
			ic->ic_bss->in_rates =
			    ic->ic_sup_rates[ieee80211_chan2mode(ic, chan)];
			IEEE80211_UNLOCK(ic);
			ieee80211_new_state(ic, IEEE80211_S_SCAN, -1);
			return;
		}
	} while (chan != ic->ic_curchan);
	IEEE80211_UNLOCK(ic);
	ieee80211_end_scan(ic);
}

/*
 * Copy useful state from node obss into nbss.
 */
static void
ieee80211_copy_bss(ieee80211_node_t *nbss, const ieee80211_node_t *obss)
{
	/* propagate useful state */
	nbss->in_authmode = obss->in_authmode;
	nbss->in_txpower = obss->in_txpower;
	nbss->in_vlan = obss->in_vlan;
}

/*
 * Setup the net80211 specific portion of an interface's softc, ic,
 * for use in IBSS mode
 */
void
ieee80211_create_ibss(ieee80211com_t *ic, struct ieee80211_channel *chan)
{
	ieee80211_impl_t *im = ic->ic_private;
	ieee80211_node_table_t *nt;
	ieee80211_node_t *in;

	IEEE80211_LOCK_ASSERT(ic);
	ieee80211_dbg(IEEE80211_MSG_SCAN, "ieee80211_create_ibss: "
	    "creating ibss\n");

	/*
	 * Create the station/neighbor table.  Note that for adhoc
	 * mode we make the initial inactivity timer longer since
	 * we create nodes only through discovery and they typically
	 * are long-lived associations.
	 */
	nt = &ic->ic_sta;
	IEEE80211_NODE_LOCK(nt);
	nt->nt_name = "neighbor";
	nt->nt_inact_init = im->im_inact_run;
	IEEE80211_NODE_UNLOCK(nt);

	in = ieee80211_alloc_node(ic, &ic->ic_sta, ic->ic_macaddr);
	if (in == NULL) {
		ieee80211_err("ieee80211_create_ibss(): alloc node failed\n");
		return;
	}
	IEEE80211_ADDR_COPY(in->in_bssid, ic->ic_macaddr);
	in->in_esslen = ic->ic_des_esslen;
	(void) memcpy(in->in_essid, ic->ic_des_essid, in->in_esslen);
	ieee80211_copy_bss(in, ic->ic_bss);
	in->in_intval = ic->ic_bintval;
	if (ic->ic_flags & IEEE80211_F_PRIVACY)
		in->in_capinfo |= IEEE80211_CAPINFO_PRIVACY;
	if (ic->ic_phytype == IEEE80211_T_FH) {
		in->in_fhdwell = 200;
		in->in_fhindex = 1;
	}
	switch (ic->ic_opmode) {
	case IEEE80211_M_IBSS:
		ic->ic_flags |= IEEE80211_F_SIBSS;
		in->in_capinfo |= IEEE80211_CAPINFO_IBSS;
		if (ic->ic_flags & IEEE80211_F_DESBSSID)
			IEEE80211_ADDR_COPY(in->in_bssid, ic->ic_des_bssid);
		else
			in->in_bssid[0] |= 0x02;	/* local bit for IBSS */
		break;
	case IEEE80211_M_AHDEMO:
		if (ic->ic_flags & IEEE80211_F_DESBSSID)
			IEEE80211_ADDR_COPY(in->in_bssid, ic->ic_des_bssid);
		else
			(void) memset(in->in_bssid, 0, IEEE80211_ADDR_LEN);
		break;
	default:
		ieee80211_err("ieee80211_create_ibss(): "
		    "wrong opmode %u to creat IBSS, abort\n",
		    ic->ic_opmode);
		ieee80211_free_node(in);
		return;
	}

	/*
	 * Fix the channel and related attributes.
	 */
	ieee80211_node_setchan(ic, in, chan);
	ic->ic_curchan = chan;
	ic->ic_curmode = ieee80211_chan2mode(ic, chan);
	/*
	 * Do mode-specific rate setup.
	 */
	ieee80211_setbasicrates(&in->in_rates, ic->ic_curmode);
	IEEE80211_UNLOCK(ic);
	ieee80211_sta_join(ic, ieee80211_ref_node(in));
	IEEE80211_LOCK(ic);
}

void
ieee80211_reset_bss(ieee80211com_t *ic)
{
	ieee80211_node_t *in;
	ieee80211_node_t *obss;

	ieee80211_node_table_reset(&ic->ic_sta);
	ieee80211_reset_erp(ic);

	in = ieee80211_alloc_node(ic, &ic->ic_scan, ic->ic_macaddr);
	ASSERT(in != NULL);
	obss = ic->ic_bss;
	ic->ic_bss = ieee80211_ref_node(in);
	if (obss != NULL) {
		ieee80211_copy_bss(in, obss);
		in->in_intval = ic->ic_bintval;
		ieee80211_free_node(obss);
	}
}

static int
ieee80211_match_bss(ieee80211com_t *ic, ieee80211_node_t *in)
{
	uint8_t rate;
	int fail;

	fail = 0;
	if (ieee80211_isclr(ic->ic_chan_active,
	    ieee80211_chan2ieee(ic, in->in_chan))) {
		fail |= IEEE80211_BADCHAN;
	}
	if (ic->ic_des_chan != IEEE80211_CHAN_ANYC &&
	    in->in_chan != ic->ic_des_chan) {
		fail |= IEEE80211_BADCHAN;
	}
	if (ic->ic_opmode == IEEE80211_M_IBSS) {
		if (!(in->in_capinfo & IEEE80211_CAPINFO_IBSS))
			fail |= IEEE80211_BADOPMODE;
	} else {
		if (!(in->in_capinfo & IEEE80211_CAPINFO_ESS))
			fail |= IEEE80211_BADOPMODE;
	}
	if (ic->ic_flags & IEEE80211_F_PRIVACY) {
		if (!(in->in_capinfo & IEEE80211_CAPINFO_PRIVACY))
			fail |= IEEE80211_BADPRIVACY;
	} else {
		if (in->in_capinfo & IEEE80211_CAPINFO_PRIVACY)
			fail |= IEEE80211_BADPRIVACY;
	}
	rate = ieee80211_fix_rate(in, &in->in_rates,
	    IEEE80211_F_DONEGO | IEEE80211_F_DOFRATE);
	if (rate & IEEE80211_RATE_BASIC)
		fail |= IEEE80211_BADRATE;
	if (ic->ic_des_esslen != 0 &&
	    (in->in_esslen != ic->ic_des_esslen ||
	    memcmp(in->in_essid, ic->ic_des_essid, ic->ic_des_esslen) != 0)) {
		fail |= IEEE80211_BADESSID;
	}
	if ((ic->ic_flags & IEEE80211_F_DESBSSID) &&
	    !IEEE80211_ADDR_EQ(ic->ic_des_bssid, in->in_bssid)) {
		fail |= IEEE80211_BADBSSID;
	}
	if (in->in_fails >= IEEE80211_STA_FAILS_MAX)
		fail |= IEEE80211_NODEFAIL;

	return (fail);
}

#define	IEEE80211_MAXRATE(_rs) \
	((_rs).ir_rates[(_rs).ir_nrates - 1] & IEEE80211_RATE_VAL)

/*
 * Compare the capabilities of node a with node b and decide which is
 * more desirable (return b if b is considered better than a).  Note
 * that we assume compatibility/usability has already been checked
 * so we don't need to (e.g. validate whether privacy is supported).
 * Used to select the best scan candidate for association in a BSS.
 *
 * Return desired node
 */
static ieee80211_node_t *
ieee80211_node_compare(ieee80211com_t *ic, ieee80211_node_t *a,
    ieee80211_node_t *b)
{
	uint8_t maxa;
	uint8_t maxb;
	uint8_t rssia;
	uint8_t rssib;

	/* privacy support preferred */
	if ((a->in_capinfo & IEEE80211_CAPINFO_PRIVACY) &&
	    !(b->in_capinfo & IEEE80211_CAPINFO_PRIVACY)) {
		return (a);
	}
	if (!(a->in_capinfo & IEEE80211_CAPINFO_PRIVACY) &&
	    (b->in_capinfo & IEEE80211_CAPINFO_PRIVACY)) {
		return (b);
	}

	/* compare count of previous failures */
	if (b->in_fails != a->in_fails)
		return ((a->in_fails > b->in_fails) ? b : a);

	rssia = ic->ic_node_getrssi(a);
	rssib = ic->ic_node_getrssi(b);
	if (ABS(rssib - rssia) < IEEE80211_RSSI_CMP_THRESHOLD) {
		/* best/max rate preferred if signal level close enough */
		maxa = IEEE80211_MAXRATE(a->in_rates);
		maxb = IEEE80211_MAXRATE(b->in_rates);
		if (maxa != maxb)
			return ((maxb > maxa) ? b : a);
		/* for now just prefer 5Ghz band to all other bands */
		if (IEEE80211_IS_CHAN_5GHZ(a->in_chan) &&
		    !IEEE80211_IS_CHAN_5GHZ(b->in_chan)) {
			return (a);
		}
		if (!IEEE80211_IS_CHAN_5GHZ(a->in_chan) &&
		    IEEE80211_IS_CHAN_5GHZ(b->in_chan)) {
			return (b);
		}
	}
	/* all things being equal, compare signal level */
	return ((rssib > rssia) ? b : a);
}

/*
 * Mark an ongoing scan stopped.
 */
void
ieee80211_cancel_scan(ieee80211com_t *ic)
{
	IEEE80211_LOCK(ic);
	ieee80211_dbg(IEEE80211_MSG_SCAN, "ieee80211_cancel_scan()"
	    "end %s scan\n",
	    (ic->ic_flags & IEEE80211_F_ASCAN) ?  "active" : "passive");
	ic->ic_flags &= ~(IEEE80211_F_SCAN | IEEE80211_F_ASCAN);
	cv_broadcast(&((ieee80211_impl_t *)ic->ic_private)->im_scan_cv);
	IEEE80211_UNLOCK(ic);
}

/*
 * Complete a scan of potential channels. It is called by
 * ieee80211_next_scan() when the state machine has performed
 * a full cycle of scaning on all available radio channels.
 * ieee80211_end_scan() will inspect the node cache for suitable
 * APs found during scaning, and associate with one, should
 * the parameters of the node match those of the configuration
 * requested from userland.
 */
void
ieee80211_end_scan(ieee80211com_t *ic)
{
	ieee80211_node_table_t *nt = &ic->ic_scan;
	ieee80211_node_t *in;
	ieee80211_node_t *selbs;

	ieee80211_cancel_scan(ic);
	/* notify SCAN done */
	ieee80211_notify(ic, EVENT_SCAN_RESULTS);
	IEEE80211_LOCK(ic);

	/*
	 * Automatic sequencing; look for a candidate and
	 * if found join the network.
	 */
	/* NB: unlocked read should be ok */
	in = list_head(&nt->nt_node);
	if (in == NULL && (ic->ic_flags & IEEE80211_F_WPA) == 0) {
		ieee80211_dbg(IEEE80211_MSG_SCAN, "ieee80211_end_scan: "
		    "no scan candidate\n");
	notfound:
		if (ic->ic_opmode == IEEE80211_M_IBSS &&
		    (ic->ic_flags & IEEE80211_F_IBSSON) &&
		    ic->ic_des_esslen != 0) {
			ieee80211_create_ibss(ic, ic->ic_ibss_chan);
			IEEE80211_UNLOCK(ic);
			return;
		}

		/*
		 * Reset the list of channels to scan and start again.
		 */
		ieee80211_reset_scan(ic);
		ic->ic_flags |= IEEE80211_F_SCAN | IEEE80211_F_ASCAN;
		IEEE80211_UNLOCK(ic);

		ieee80211_next_scan(ic);
		return;
	}

	if (ic->ic_flags & IEEE80211_F_SCANONLY ||
	    ic->ic_flags & IEEE80211_F_WPA) {	/* scan only */
		ic->ic_flags &= ~IEEE80211_F_SCANONLY;
		IEEE80211_UNLOCK(ic);
		ieee80211_new_state(ic, IEEE80211_S_INIT, -1);
		return;
	}

	selbs = NULL;
	IEEE80211_NODE_LOCK(nt);
	while (in != NULL) {
		if (in->in_fails >= IEEE80211_STA_FAILS_MAX) {
			ieee80211_node_t *tmpin = in;

			/*
			 * The configuration of the access points may change
			 * during my scan.  So delete the entry for the AP
			 * and retry to associate if there is another beacon.
			 */
			in = list_next(&nt->nt_node, tmpin);
			ieee80211_node_reclaim(nt, tmpin);
			continue;
		}
		/*
		 * It's possible at some special moments, the in_chan will
		 * be none. Need to skip the null node.
		 */
		if (in->in_chan == IEEE80211_CHAN_ANYC) {
			in = list_next(&nt->nt_node, in);
			continue;
		}
		if (ieee80211_match_bss(ic, in) == 0) {
			if (selbs == NULL)
				selbs = in;
			else
				selbs = ieee80211_node_compare(ic, selbs, in);
		}
		in = list_next(&nt->nt_node, in);
	}
	if (selbs != NULL)	/* grab ref while dropping lock */
		(void) ieee80211_ref_node(selbs);
	IEEE80211_NODE_UNLOCK(nt);
	if (selbs == NULL)
		goto notfound;
	IEEE80211_UNLOCK(ic);
	ieee80211_sta_join(ic, selbs);
}


/*
 * Handle 802.11 ad hoc network merge.  The convention, set by the
 * Wireless Ethernet Compatibility Alliance (WECA), is that an 802.11
 * station will change its BSSID to match the "oldest" 802.11 ad hoc
 * network, on the same channel, that has the station's desired SSID.
 * The "oldest" 802.11 network sends beacons with the greatest TSF
 * timestamp.
 * The caller is assumed to validate TSF's before attempting a merge.
 *
 * Return B_TRUE if the BSSID changed, B_FALSE otherwise.
 */
boolean_t
ieee80211_ibss_merge(ieee80211_node_t *in)
{
	ieee80211com_t *ic = in->in_ic;

	if (in == ic->ic_bss ||
	    IEEE80211_ADDR_EQ(in->in_bssid, ic->ic_bss->in_bssid)) {
		/* unchanged, nothing to do */
		return (B_FALSE);
	}
	if (ieee80211_match_bss(ic, in) != 0) {	/* capabilities mismatch */
		ieee80211_dbg(IEEE80211_MSG_ASSOC, "ieee80211_ibss_merge: "
		    " merge failed, capabilities mismatch\n");
		return (B_FALSE);
	}
	ieee80211_dbg(IEEE80211_MSG_ASSOC, "ieee80211_ibss_merge: "
	    "new bssid %s: %s preamble, %s slot time%s\n",
	    ieee80211_macaddr_sprintf(in->in_bssid),
	    (ic->ic_flags & IEEE80211_F_SHPREAMBLE) ? "short" : "long",
	    (ic->ic_flags & IEEE80211_F_SHSLOT) ? "short" : "long",
	    (ic->ic_flags&IEEE80211_F_USEPROT) ? ", protection" : "");
	ieee80211_sta_join(ic, ieee80211_ref_node(in));
	return (B_TRUE);
}

/*
 * Change the bss channel.
 */
void
ieee80211_setcurchan(ieee80211com_t *ic, struct ieee80211_channel *c)
{
	ic->ic_curchan = c;
	ic->ic_curmode = ieee80211_chan2mode(ic, ic->ic_curchan);
	if (ic->ic_set_channel != NULL)
		ic->ic_set_channel(ic);
}

/*
 * Join the specified IBSS/BSS network.  The node is assumed to
 * be passed in with a held reference.
 */
void
ieee80211_sta_join(ieee80211com_t *ic, ieee80211_node_t *selbs)
{
	ieee80211_impl_t *im = ic->ic_private;
	ieee80211_node_t *obss;

	IEEE80211_LOCK(ic);
	if (ic->ic_opmode == IEEE80211_M_IBSS) {
		ieee80211_node_table_t *nt;

		/*
		 * Delete unusable rates; we've already checked
		 * that the negotiated rate set is acceptable.
		 */
		(void) ieee80211_fix_rate(selbs, &selbs->in_rates,
		    IEEE80211_F_DODEL);
		/*
		 * Fillin the neighbor table
		 */
		nt = &ic->ic_sta;
		IEEE80211_NODE_LOCK(nt);
		nt->nt_name = "neighbor";
		nt->nt_inact_init = im->im_inact_run;
		IEEE80211_NODE_UNLOCK(nt);
	}

	/*
	 * Committed to selbs, setup state.
	 */
	obss = ic->ic_bss;
	ic->ic_bss = selbs;	/* caller assumed to bump refcnt */
	if (obss != NULL) {
		ieee80211_copy_bss(selbs, obss);
		ieee80211_free_node(obss);
	}
	ic->ic_curmode = ieee80211_chan2mode(ic, selbs->in_chan);
	ic->ic_curchan = selbs->in_chan;
	ic->ic_phytype = selbs->in_phytype;
	/*
	 * Set the erp state (mostly the slot time) to deal with
	 * the auto-select case; this should be redundant if the
	 * mode is locked.
	 */
	ieee80211_reset_erp(ic);
	ieee80211_wme_initparams(ic);

	IEEE80211_UNLOCK(ic);
	if (ic->ic_opmode == IEEE80211_M_STA)
		ieee80211_new_state(ic, IEEE80211_S_AUTH, -1);
	else
		ieee80211_new_state(ic, IEEE80211_S_RUN, -1);
}

/*
 * Leave the specified IBSS/BSS network.  The node is assumed to
 * be passed in with a held reference.
 */
void
ieee80211_sta_leave(ieee80211com_t *ic, ieee80211_node_t *in)
{
	IEEE80211_LOCK(ic);
	ic->ic_node_cleanup(in);
	ieee80211_notify_node_leave(ic, in);
	IEEE80211_UNLOCK(ic);
}

/*
 * Allocate a node. This is the default callback function for
 * ic_node_alloc. This function may be overridden by the driver
 * to allocate device specific node structure.
 */
/* ARGSUSED */
static ieee80211_node_t *
ieee80211_node_alloc(ieee80211com_t *ic)
{
	return (kmem_zalloc(sizeof (ieee80211_node_t), KM_SLEEP));
}

/*
 * Cleanup a node, free any memory associated with the node.
 * This is the default callback function for ic_node_cleanup
 * and may be overridden by the driver.
 */
static void
ieee80211_node_cleanup(ieee80211_node_t *in)
{
	in->in_associd = 0;
	in->in_rssi = 0;
	in->in_rstamp = 0;
	if (in->in_challenge != NULL) {
		kmem_free(in->in_challenge, IEEE80211_CHALLENGE_LEN);
		in->in_challenge = NULL;
	}
	if (in->in_rxfrag != NULL) {
		freemsg(in->in_rxfrag);
		in->in_rxfrag = NULL;
	}
}

/*
 * Free a node. This is the default callback function for ic_node_free
 * and may be overridden by the driver to free memory used by device
 * specific node structure
 */
static void
ieee80211_node_free(ieee80211_node_t *in)
{
	ieee80211com_t *ic = in->in_ic;

	ic->ic_node_cleanup(in);
	if (in->in_wpa_ie != NULL)
		ieee80211_free(in->in_wpa_ie);
	if (in->in_wme_ie != NULL)
		ieee80211_free(in->in_wme_ie);
	if (in->in_htcap_ie != NULL)
		ieee80211_free(in->in_htcap_ie);
	kmem_free(in, sizeof (ieee80211_node_t));
}

/*
 * Get a node current RSSI value. This is the default callback function
 * for ic_node_getrssi and may be overridden by the driver to provide
 * device specific RSSI calculation algorithm.
 */
static uint8_t
ieee80211_node_getrssi(const ieee80211_node_t *in)
{
	return (in->in_rssi);
}

/* Free fragment if not needed anymore */
static void
node_cleanfrag(ieee80211_node_t *in)
{
	clock_t ticks;

	ticks = ddi_get_lbolt();
	if (in->in_rxfrag != NULL && ticks > (in->in_rxfragstamp + hz)) {
		freemsg(in->in_rxfrag);
		in->in_rxfrag = NULL;
	}
}

/*
 * Setup a node. Initialize the node with specified macaddr. Associate
 * with the interface softc, ic, and add it to the specified node
 * database.
 */
static void
ieee80211_setup_node(ieee80211com_t *ic, ieee80211_node_table_t *nt,
    ieee80211_node_t *in, const uint8_t *macaddr)
{
	int32_t hash;

	ieee80211_dbg(IEEE80211_MSG_NODE, "ieee80211_setup_node(): "
	    "%p<%s> in %s table\n", in,
	    ieee80211_macaddr_sprintf(macaddr),
	    (nt != NULL) ? nt->nt_name : "NULL");

	in->in_ic = ic;
	IEEE80211_ADDR_COPY(in->in_macaddr, macaddr);
	hash = ieee80211_node_hash(macaddr);
	ieee80211_node_initref(in);		/* mark referenced */
	in->in_authmode = IEEE80211_AUTH_OPEN;
	in->in_txpower = ic->ic_txpowlimit;	/* max power */
	in->in_chan = IEEE80211_CHAN_ANYC;
	in->in_inact_reload = IEEE80211_INACT_INIT;
	in->in_inact = in->in_inact_reload;
	ieee80211_crypto_resetkey(ic, &in->in_ucastkey, IEEE80211_KEYIX_NONE);

	if (nt != NULL) {
		IEEE80211_NODE_LOCK(nt);
		list_insert_tail(&nt->nt_node, in);
		list_insert_tail(&nt->nt_hash[hash], in);
		in->in_table = nt;
		in->in_inact_reload = nt->nt_inact_init;
		IEEE80211_NODE_UNLOCK(nt);
	}
}

/*
 * Allocates and initialize a node with specified MAC address.
 * Associate the node with the interface ic. If the allocation
 * is successful, the node structure is initialized by
 * ieee80211_setup_node(); otherwise, NULL is returned
 */
ieee80211_node_t *
ieee80211_alloc_node(ieee80211com_t *ic, ieee80211_node_table_t *nt,
    const uint8_t *macaddr)
{
	ieee80211_node_t *in;

	in = ic->ic_node_alloc(ic);
	if (in != NULL)
		ieee80211_setup_node(ic, nt, in, macaddr);
	return (in);
}

/*
 * Craft a temporary node suitable for sending a management frame
 * to the specified station.  We craft only as much state as we
 * need to do the work since the node will be immediately reclaimed
 * once the send completes.
 */
ieee80211_node_t *
ieee80211_tmp_node(ieee80211com_t *ic, const uint8_t *macaddr)
{
	ieee80211_node_t *in;

	in = ic->ic_node_alloc(ic);
	if (in != NULL) {
		ieee80211_dbg(IEEE80211_MSG_NODE, "ieee80211_tmp_node: "
		    "%p<%s>\n", in, ieee80211_macaddr_sprintf(macaddr));

		IEEE80211_ADDR_COPY(in->in_macaddr, macaddr);
		IEEE80211_ADDR_COPY(in->in_bssid, ic->ic_bss->in_bssid);
		ieee80211_node_initref(in);		/* mark referenced */
		in->in_txpower = ic->ic_bss->in_txpower;
		/* NB: required by ieee80211_fix_rate */
		ieee80211_node_setchan(ic, in, ic->ic_bss->in_chan);
		ieee80211_crypto_resetkey(ic, &in->in_ucastkey,
		    IEEE80211_KEYIX_NONE);

		in->in_table = NULL;		/* NB: pedantic */
		in->in_ic = ic;
	}

	return (in);
}

/*
 * ieee80211_dup_bss() is similar to ieee80211_alloc_node(),
 * but is instead used to create a node database entry for
 * the specified BSSID. If the allocation is successful, the
 * node is initialized,  otherwise, NULL is returned.
 */
ieee80211_node_t *
ieee80211_dup_bss(ieee80211_node_table_t *nt, const uint8_t *macaddr)
{
	ieee80211com_t *ic = nt->nt_ic;
	ieee80211_node_t *in;

	in = ieee80211_alloc_node(ic, nt, macaddr);
	if (in != NULL) {
		/*
		 * Inherit from ic_bss.
		 */
		ieee80211_copy_bss(in, ic->ic_bss);
		IEEE80211_ADDR_COPY(in->in_bssid, ic->ic_bss->in_bssid);
		ieee80211_node_setchan(ic, in, ic->ic_bss->in_chan);
	}

	return (in);
}

/*
 * Iterate through the node table, searching for a node entry which
 * matches macaddr. If the entry is found, its reference count is
 * incremented, and a pointer to the node is returned; otherwise,
 * NULL will be returned.
 * The node table lock is acquired by the caller.
 */
static ieee80211_node_t *
ieee80211_find_node_locked(ieee80211_node_table_t *nt, const uint8_t *macaddr)
{
	ieee80211_node_t *in;
	int hash;

	ASSERT(IEEE80211_NODE_IS_LOCKED(nt));

	hash = ieee80211_node_hash(macaddr);
	in = list_head(&nt->nt_hash[hash]);
	while (in != NULL) {
		if (IEEE80211_ADDR_EQ(in->in_macaddr, macaddr))
			return (ieee80211_ref_node(in)); /* mark referenced */
		in = list_next(&nt->nt_hash[hash], in);
	}
	return (NULL);
}

/*
 * Iterate through the node table, searching for a node entry
 * which match specified mac address.
 * Return NULL if no matching node found.
 */
ieee80211_node_t *
ieee80211_find_node(ieee80211_node_table_t *nt, const uint8_t *macaddr)
{
	ieee80211_node_t *in;

	IEEE80211_NODE_LOCK(nt);
	in = ieee80211_find_node_locked(nt, macaddr);
	IEEE80211_NODE_UNLOCK(nt);
	return (in);
}

/*
 * Like find but search based on the ssid too.
 */
ieee80211_node_t *
ieee80211_find_node_with_ssid(ieee80211_node_table_t *nt,
	const uint8_t *macaddr, uint32_t ssidlen, const uint8_t *ssid)
{
	ieee80211_node_t *in;
	int hash;

	IEEE80211_NODE_LOCK(nt);

	hash = ieee80211_node_hash(macaddr);
	in = list_head(&nt->nt_hash[hash]);
	while (in != NULL) {
		if (IEEE80211_ADDR_EQ(in->in_macaddr, macaddr) &&
		    in->in_esslen == ssidlen &&
		    memcmp(in->in_essid, ssid, ssidlen) == 0)
			break;
		in = list_next(&nt->nt_hash[hash], in);
	}
	if (in != NULL) {
		(void) ieee80211_ref_node(in); /* mark referenced */
	}
	IEEE80211_NODE_UNLOCK(nt);

	return (in);
}

/*
 * Fake up a node; this handles node discovery in adhoc mode.
 * Note that for the driver's benefit we treat this like an
 * association so the driver has an opportunity to setup it's
 * private state.
 */
ieee80211_node_t *
ieee80211_fakeup_adhoc_node(ieee80211_node_table_t *nt, const uint8_t *macaddr)
{
	ieee80211com_t *ic = nt->nt_ic;
	ieee80211_node_t *in;

	ieee80211_dbg(IEEE80211_MSG_NODE, "ieee80211_fakeup_adhoc_node: "
	    "mac<%s>\n", ieee80211_macaddr_sprintf(macaddr));
	in = ieee80211_dup_bss(nt, macaddr);
	if (in != NULL) {
		/* no rate negotiation; just dup */
		in->in_rates = ic->ic_bss->in_rates;
		if (ic->ic_node_newassoc != NULL)
			ic->ic_node_newassoc(in, 1);
		ieee80211_node_authorize(in);
	}
	return (in);
}

static void
ieee80211_saveie(uint8_t **iep, const uint8_t *ie)
{
	uint_t ielen = ie[1]+2;
	/*
	 * Record information element for later use.
	 */
	if (*iep == NULL || (*iep)[1] != ie[1]) {
		if (*iep != NULL)
			ieee80211_free(*iep);
		*iep = ieee80211_malloc(ielen);
	}
	if (*iep != NULL)
		(void) memcpy(*iep, ie, ielen);
}

static void
saveie(uint8_t **iep, const uint8_t *ie)
{
	if (ie == NULL) {
		if (*iep != NULL)
			ieee80211_free(*iep);
		*iep = NULL;
	}
	else
		ieee80211_saveie(iep, ie);
}

/*
 * Process a beacon or probe response frame.
 */
void
ieee80211_add_scan(ieee80211com_t *ic, const struct ieee80211_scanparams *sp,
    const struct ieee80211_frame *wh, int subtype, int rssi, int rstamp)
{
	ieee80211_node_table_t *nt = &ic->ic_scan;
	ieee80211_node_t *in;
	boolean_t newnode = B_FALSE;

	in = ieee80211_find_node(nt, wh->i_addr3);
	if (in == NULL) {
		/*
		 * Create a new entry.
		 */
		in = ieee80211_alloc_node(ic, nt, wh->i_addr3);
		if (in == NULL) {
			ieee80211_dbg(IEEE80211_MSG_ANY, "ieee80211_add_scan: "
			    "alloc node failed\n");
			return;
		}
		/*
		 * inherit from ic_bss.
		 */
		ieee80211_copy_bss(in, ic->ic_bss);
		ieee80211_node_setchan(ic, in, ic->ic_curchan);
		newnode = B_TRUE;
	}

	/* ap beaconing multiple ssid w/ same bssid */

	/*
	 * sp->ssid[0] - element ID
	 * sp->ssid[1] - length
	 * sp->ssid[2]... - ssid
	 */
	if (sp->ssid[1] != 0 &&
	    subtype == IEEE80211_FC0_SUBTYPE_PROBE_RESP ||
	    in->in_esslen == 0) {
		in->in_esslen = sp->ssid[1];
		bzero(in->in_essid, sizeof (in->in_essid));
		bcopy(sp->ssid + 2, in->in_essid, sp->ssid[1]);
	}
	IEEE80211_ADDR_COPY(in->in_bssid, wh->i_addr3);
	in->in_rssi = (uint8_t)rssi;
	in->in_rstamp = rstamp;
	bcopy(sp->tstamp, in->in_tstamp.data, sizeof (in->in_tstamp));
	in->in_intval = sp->bintval;
	in->in_capinfo = sp->capinfo;
	in->in_chan = &ic->ic_sup_channels[sp->chan];
	in->in_phytype = sp->phytype;
	in->in_fhdwell = sp->fhdwell;
	in->in_fhindex = sp->fhindex;
	in->in_erp = sp->erp;
	if (sp->tim != NULL) {
		struct ieee80211_tim_ie *ie;

		ie = (struct ieee80211_tim_ie *)sp->tim;
		in->in_dtim_count = ie->tim_count;
		in->in_dtim_period = ie->tim_period;
	}
	/*
	 * Record the byte offset from the mac header to
	 * the start of the TIM information element for
	 * use by hardware and/or to speedup software
	 * processing of beacon frames.
	 */
	in->in_tim_off = sp->timoff;
	/*
	 * Record optional information elements that might be
	 * used by applications or drivers.
	 */
	saveie(&in->in_wme_ie, sp->wme);
	saveie(&in->in_wpa_ie, sp->wpa);
	saveie(&in->in_htcap_ie, sp->htcap);
	/* parsed in ieee80211_sta_join() */
	if (sp->htcap != NULL)
		ieee80211_parse_htcap(in, in->in_htcap_ie);

	/* NB: must be after in_chan is setup */
	(void) ieee80211_setup_rates(in, sp->rates, sp->xrates,
	    IEEE80211_F_DOSORT);

	if (!newnode)
		ieee80211_free_node(in);
}

/*
 * Initialize/update an ad-hoc node with contents from a received
 * beacon frame.
 */
void
ieee80211_init_neighbor(ieee80211_node_t *in, const struct ieee80211_frame *wh,
    const struct ieee80211_scanparams *sp)
{
	in->in_esslen = sp->ssid[1];
	(void) memcpy(in->in_essid, sp->ssid + 2, sp->ssid[1]);
	IEEE80211_ADDR_COPY(in->in_bssid, wh->i_addr3);
	(void) memcpy(in->in_tstamp.data, sp->tstamp, sizeof (in->in_tstamp));
	in->in_intval = sp->bintval;
	in->in_capinfo = sp->capinfo;
	in->in_chan = in->in_ic->ic_curchan;
	in->in_fhdwell = sp->fhdwell;
	in->in_fhindex = sp->fhindex;
	in->in_erp = sp->erp;
	in->in_tim_off = sp->timoff;
	if (sp->wme != NULL)
		ieee80211_saveie(&in->in_wme_ie, sp->wme);

	/* NB: must be after in_chan is setup */
	(void) ieee80211_setup_rates(in, sp->rates, sp->xrates,
	    IEEE80211_F_DOSORT);
}

/*
 * Do node discovery in adhoc mode on receipt of a beacon
 * or probe response frame.  Note that for the driver's
 * benefit we we treat this like an association so the
 * driver has an opportuinty to setup it's private state.
 */
ieee80211_node_t *
ieee80211_add_neighbor(ieee80211com_t *ic, const struct ieee80211_frame *wh,
    const struct ieee80211_scanparams *sp)
{
	ieee80211_node_t *in;

	in = ieee80211_dup_bss(&ic->ic_sta, wh->i_addr2);
	if (in != NULL) {
		ieee80211_init_neighbor(in, wh, sp);
		if (ic->ic_node_newassoc != NULL)
			ic->ic_node_newassoc(in, 1);
	}
	return (in);
}

#define	IEEE80211_IS_CTL(wh)	\
	((wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) == IEEE80211_FC0_TYPE_CTL)

#define	IEEE80211_IS_PSPOLL(wh)	\
	((wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK) ==	\
	    IEEE80211_FC0_SUBTYPE_PS_POLL)

#define	IEEE80211_IS_BAR(wh)	\
	((wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK) ==	\
	    IEEE80211_FC0_SUBTYPE_BAR)

/*
 * Locate the node for sender, track state, and then pass the
 * (referenced) node up to the 802.11 layer for its use.  We
 * are required to pass some node so we fall back to ic_bss
 * when this frame is from an unknown sender.  The 802.11 layer
 * knows this means the sender wasn't in the node table and
 * acts accordingly.
 */
ieee80211_node_t *
ieee80211_find_rxnode(ieee80211com_t *ic, const struct ieee80211_frame *wh)
{
	ieee80211_node_table_t *nt;
	ieee80211_node_t *in;

	/* may want scanned nodes in the neighbor table for adhoc */
	if (ic->ic_opmode == IEEE80211_M_STA ||
	    (ic->ic_flags & IEEE80211_F_SCAN)) {
		nt = &ic->ic_scan;
	} else {
		nt = &ic->ic_sta;
	}

	IEEE80211_NODE_LOCK(nt);
	if (IEEE80211_IS_CTL(wh) &&
	    !IEEE80211_IS_PSPOLL(wh) && !IEEE80211_IS_BAR(wh))
		in = ieee80211_find_node_locked(nt, wh->i_addr1);
	else
		in = ieee80211_find_node_locked(nt, wh->i_addr2);
	IEEE80211_NODE_UNLOCK(nt);

	if (in == NULL)
		in = ieee80211_ref_node(ic->ic_bss);

	return (in);
}

#undef IEEE80211_IS_BAR
#undef IEEE80211_IS_PSPOLL
#undef IEEE80211_IS_CTL

/*
 * Return a reference to the appropriate node for sending
 * a data frame.  This handles node discovery in adhoc networks.
 */
ieee80211_node_t *
ieee80211_find_txnode(ieee80211com_t *ic, const uint8_t *daddr)
{
	ieee80211_node_table_t *nt = &ic->ic_sta;
	ieee80211_node_t *in;

	/*
	 * The destination address should be in the node table
	 * unless this is a multicast/broadcast frame.  We can
	 * also optimize station mode operation, all frames go
	 * to the bss node.
	 */
	IEEE80211_NODE_LOCK(nt);
	if (ic->ic_opmode == IEEE80211_M_STA || IEEE80211_IS_MULTICAST(daddr))
		in = ieee80211_ref_node(ic->ic_bss);
	else
		in = ieee80211_find_node_locked(nt, daddr);
	IEEE80211_NODE_UNLOCK(nt);

	if (in == NULL) {
		if (ic->ic_opmode == IEEE80211_M_IBSS) {
			/*
			 * In adhoc mode cons up a node for the destination.
			 * Note that we need an additional reference for the
			 * caller to be consistent with
			 * ieee80211_find_node_locked
			 * can't hold lock across ieee80211_dup_bss 'cuz of
			 * recursive locking
			 */
			in = ieee80211_fakeup_adhoc_node(nt, daddr);
			if (in != NULL)
				(void) ieee80211_ref_node(in);
		} else {
			ieee80211_dbg(IEEE80211_MSG_OUTPUT,
			    "ieee80211_find_txnode: "
			    "[%s] no node, discard frame\n",
			    ieee80211_macaddr_sprintf(daddr));
		}
	}
	return (in);
}

/*
 * Remove a node from the node database entries and free memory
 * associated with the node. The node table lock is acquired by
 * the caller.
 */
static void
ieee80211_free_node_locked(ieee80211_node_t *in)
{
	ieee80211com_t *ic = in->in_ic;
	ieee80211_node_table_t *nt = in->in_table;
	int32_t hash;

	if (nt != NULL) {
		hash = ieee80211_node_hash(in->in_macaddr);
		list_remove(&nt->nt_hash[hash], in);
		list_remove(&nt->nt_node, in);
	}
	ic->ic_node_free(in);
}

/*
 * Remove a node from the node database entries and free any
 * memory associated with the node.
 * This method can be overridden in ieee80211_attach()
 */
void
ieee80211_free_node(ieee80211_node_t *in)
{
	ieee80211_node_table_t *nt = in->in_table;

	if (nt != NULL)
		IEEE80211_NODE_LOCK(nt);
	if (ieee80211_node_decref_nv(in) == 0)
		ieee80211_free_node_locked(in);
	if (nt != NULL)
		IEEE80211_NODE_UNLOCK(nt);
}

/*
 * Reclaim a node.  If this is the last reference count then
 * do the normal free work.  Otherwise remove it from the node
 * table and mark it gone by clearing the back-reference.
 */
static void
ieee80211_node_reclaim(ieee80211_node_table_t *nt, ieee80211_node_t *in)
{
	int32_t hash;

	IEEE80211_NODE_LOCK_ASSERT(nt);
	ieee80211_dbg(IEEE80211_MSG_NODE, "node_reclaim: "
	    " remove %p<%s> from %s table, refcnt %d\n",
	    in, ieee80211_macaddr_sprintf(in->in_macaddr), nt->nt_name,
	    ieee80211_node_refcnt(in));

	if (ieee80211_node_decref_nv(in) != 0) {
		/*
		 * Clear any entry in the unicast key mapping table.
		 * We need to do it here so rx lookups don't find it
		 * in the mapping table even if it's not in the hash
		 * table.  We cannot depend on the mapping table entry
		 * being cleared because the node may not be free'd.
		 */
		hash = ieee80211_node_hash(in->in_macaddr);
		list_remove(&nt->nt_hash[hash], in);
		list_remove(&nt->nt_node, in);
		in->in_table = NULL;
	} else {
		ieee80211_free_node_locked(in);
	}
}

/*
 * Iterate through the node list and reclaim all node in the node table.
 * The node table lock is acquired by the caller
 */
static void
ieee80211_free_allnodes_locked(ieee80211_node_table_t *nt)
{
	ieee80211_node_t *in;

	ieee80211_dbg(IEEE80211_MSG_NODE, "ieee80211_free_allnodes_locked(): "
	    "free all nodes in %s table\n", nt->nt_name);

	in = list_head(&nt->nt_node);
	while (in != NULL) {
		ieee80211_node_reclaim(nt, in);
		in = list_head(&nt->nt_node);
	}
	ieee80211_reset_erp(nt->nt_ic);
}

/*
 * Iterate through the node list, calling ieee80211_node_reclaim() for
 * all nodes associated with the interface.
 */
static void
ieee80211_free_allnodes(ieee80211_node_table_t *nt)
{
	IEEE80211_NODE_LOCK(nt);
	ieee80211_free_allnodes_locked(nt);
	IEEE80211_NODE_UNLOCK(nt);
}

/*
 * Timeout entries in the scan cache. This is the timeout callback
 * function of node table ic_scan which is called when the inactivity
 * timer expires.
 */
static void
ieee80211_timeout_scan_candidates(ieee80211_node_table_t *nt)
{
	ieee80211com_t *ic = nt->nt_ic;
	ieee80211_node_t *in;

	IEEE80211_NODE_LOCK(nt);
	in = ic->ic_bss;
	node_cleanfrag(in);	/* Free fragment if not needed */
	nt->nt_inact_timer = IEEE80211_INACT_WAIT;
	IEEE80211_NODE_UNLOCK(nt);
}

/*
 * Timeout inactive stations and do related housekeeping.
 * Note that we cannot hold the node lock while sending a
 * frame as this would lead to a LOR.  Instead we use a
 * generation number to mark nodes that we've scanned and
 * drop the lock and restart a scan if we have to time out
 * a node.  Since we are single-threaded by virtue of
 * controlling the inactivity timer we can be sure this will
 * process each node only once.
 */
static void
ieee80211_timeout_stations(ieee80211_node_table_t *nt)
{
	ieee80211com_t *ic = nt->nt_ic;
	ieee80211_impl_t *im = ic->ic_private;
	ieee80211_node_t *in = NULL;
	uint32_t gen;
	boolean_t isadhoc;

	IEEE80211_LOCK_ASSERT(ic);
	isadhoc = (ic->ic_opmode == IEEE80211_M_IBSS ||
	    ic->ic_opmode == IEEE80211_M_AHDEMO);
	IEEE80211_SCAN_LOCK(nt);
	gen = ++nt->nt_scangen;
restart:
	IEEE80211_NODE_LOCK(nt);
	for (in = list_head(&nt->nt_node); in != NULL;
	    in = list_next(&nt->nt_node, in)) {
		if (in->in_scangen == gen)	/* previously handled */
			continue;
		in->in_scangen = gen;
		node_cleanfrag(in);	/* free fragment if not needed */

		/*
		 * Special case ourself; we may be idle for extended periods
		 * of time and regardless reclaiming our state is wrong.
		 */
		if (in == ic->ic_bss)
			continue;
		in->in_inact--;
		if (in->in_associd != 0 || isadhoc) {
			/*
			 * Probe the station before time it out.  We
			 * send a null data frame which may not be
			 * uinversally supported by drivers (need it
			 * for ps-poll support so it should be...).
			 */
			if (0 < in->in_inact &&
			    in->in_inact <= im->im_inact_probe) {
				ieee80211_dbg(IEEE80211_MSG_NODE, "net80211: "
				    "probe station due to inactivity\n");
				IEEE80211_NODE_UNLOCK(nt);
				IEEE80211_UNLOCK(ic);
				(void) ieee80211_send_nulldata(in);
				IEEE80211_LOCK(ic);
				goto restart;
			}
		}
		if (in->in_inact <= 0) {
			ieee80211_dbg(IEEE80211_MSG_NODE, "net80211: "
			    "station timed out due to inact (refcnt %u)\n",
			    ieee80211_node_refcnt(in));
			/*
			 * Send a deauthenticate frame and drop the station.
			 * This is somewhat complicated due to reference counts
			 * and locking.  At this point a station will typically
			 * have a reference count of 1.  ieee80211_node_leave
			 * will do a "free" of the node which will drop the
			 * reference count.  But in the meantime a reference
			 * wil be held by the deauth frame.  The actual reclaim
			 * of the node will happen either after the tx is
			 * completed or by ieee80211_node_leave.
			 *
			 * Separately we must drop the node lock before sending
			 * in case the driver takes a lock, as this will result
			 * in  LOR between the node lock and the driver lock.
			 */
			IEEE80211_NODE_UNLOCK(nt);
			if (in->in_associd != 0) {
				IEEE80211_UNLOCK(ic);
				IEEE80211_SEND_MGMT(ic, in,
				    IEEE80211_FC0_SUBTYPE_DEAUTH,
				    IEEE80211_REASON_AUTH_EXPIRE);
				IEEE80211_LOCK(ic);
			}
			ieee80211_node_leave(ic, in);
			goto restart;
		}
	}
	IEEE80211_NODE_UNLOCK(nt);

	IEEE80211_SCAN_UNLOCK(nt);

	nt->nt_inact_timer = IEEE80211_INACT_WAIT;
}

/*
 * Call the user-defined call back function for all nodes in
 * the node cache. The callback is invoked with the user-supplied
 * value and a pointer to the current node.
 */
void
ieee80211_iterate_nodes(ieee80211_node_table_t *nt, ieee80211_iter_func *f,
    void *arg)
{
	ieee80211_node_t *in;

	IEEE80211_NODE_LOCK(nt);
	in = list_head(&nt->nt_node);
	while (in != NULL) {
		if (in->in_chan == IEEE80211_CHAN_ANYC) {
			in = list_next(&nt->nt_node, in);
			continue;
		}
		(void) ieee80211_ref_node(in);
		IEEE80211_NODE_UNLOCK(nt);
		(*f)(arg, in);
		ieee80211_free_node(in);
		IEEE80211_NODE_LOCK(nt);
		in = list_next(&nt->nt_node, in);
	}
	IEEE80211_NODE_UNLOCK(nt);
}

/*
 * Handle bookkeeping for station deauthentication/disassociation
 * when operating as an ap.
 */
static void
ieee80211_node_leave(ieee80211com_t *ic, ieee80211_node_t *in)
{
	ieee80211_node_table_t *nt = in->in_table;

	ASSERT(ic->ic_opmode == IEEE80211_M_IBSS);

	/*
	 * Remove the node from any table it's recorded in and
	 * drop the caller's reference.  Removal from the table
	 * is important to insure the node is not reprocessed
	 * for inactivity.
	 */
	if (nt != NULL) {
		IEEE80211_NODE_LOCK(nt);
		ieee80211_node_reclaim(nt, in);
		IEEE80211_NODE_UNLOCK(nt);
	} else {
		ieee80211_free_node(in);
	}
}

/*
 * Initialize a node table with specified name, inactivity timer value
 * and callback inactivity timeout function. Associate the node table
 * with interface softc, ic.
 */
static void
ieee80211_node_table_init(ieee80211com_t *ic, ieee80211_node_table_t *nt,
    const char *name, int inact, int keyixmax,
    void (*timeout)(ieee80211_node_table_t *))
{
	int i;

	ieee80211_dbg(IEEE80211_MSG_NODE, "ieee80211_node_table_init():"
	    "%s table, inact %d\n", name, inact);

	nt->nt_ic = ic;
	nt->nt_name = name;
	nt->nt_inact_timer = 0;
	nt->nt_inact_init = inact;
	nt->nt_timeout = timeout;
	nt->nt_keyixmax = keyixmax;
	nt->nt_scangen = 1;
	mutex_init(&nt->nt_scanlock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&nt->nt_nodelock, NULL, MUTEX_DRIVER, NULL);

	list_create(&nt->nt_node, sizeof (ieee80211_node_t),
	    offsetof(ieee80211_node_t, in_node));
	for (i = 0; i < IEEE80211_NODE_HASHSIZE; i++) {
		list_create(&nt->nt_hash[i], sizeof (ieee80211_node_t),
		    offsetof(ieee80211_node_t, in_hash));
	}
}

/*
 * Reset a node table. Clean its inactivity timer and call
 * ieee80211_free_allnodes_locked() to free all nodes in the
 * node table.
 */
void
ieee80211_node_table_reset(ieee80211_node_table_t *nt)
{
	ieee80211_dbg(IEEE80211_MSG_NODE, "ieee80211_node_table_reset(): "
	    "%s table\n", nt->nt_name);

	IEEE80211_NODE_LOCK(nt);
	nt->nt_inact_timer = 0;
	ieee80211_free_allnodes_locked(nt);
	IEEE80211_NODE_UNLOCK(nt);
}

/*
 * Destroy a node table. Free all nodes in the node table.
 * This function is usually called by node detach function.
 */
static void
ieee80211_node_table_cleanup(ieee80211_node_table_t *nt)
{
	ieee80211_dbg(IEEE80211_MSG_NODE, "ieee80211_node_table_cleanup(): "
	    "%s table\n", nt->nt_name);

	IEEE80211_NODE_LOCK(nt);
	ieee80211_free_allnodes_locked(nt);
	IEEE80211_NODE_UNLOCK(nt);
	mutex_destroy(&nt->nt_nodelock);
	mutex_destroy(&nt->nt_scanlock);
}
