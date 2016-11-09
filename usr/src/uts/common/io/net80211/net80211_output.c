/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2016 Hans Rosenfeld <rosenfeld@grumpf.hope-2000.org>
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
 * Send out 802.11 frames
 */

#include <sys/byteorder.h>
#include <sys/strsun.h>
#include "net80211_impl.h"

/*
 * Set the direction field and address fields of an outgoing
 * non-QoS frame.  Note this should be called early on in
 * constructing a frame as it sets i_fc[1]; other bits can
 * then be or'd in.
 */
static void
ieee80211_send_setup(ieee80211com_t *ic, ieee80211_node_t *in,
    struct ieee80211_frame *wh, int type, const uint8_t *sa, const uint8_t *da,
    const uint8_t *bssid)
{
	wh->i_fc[0] = (uint8_t)(IEEE80211_FC0_VERSION_0 | type);
	if ((type & IEEE80211_FC0_TYPE_MASK) == IEEE80211_FC0_TYPE_DATA) {
		switch (ic->ic_opmode) {
		case IEEE80211_M_STA:
			wh->i_fc[1] = IEEE80211_FC1_DIR_TODS;
			IEEE80211_ADDR_COPY(wh->i_addr1, bssid);
			IEEE80211_ADDR_COPY(wh->i_addr2, sa);
			IEEE80211_ADDR_COPY(wh->i_addr3, da);
			break;
		case IEEE80211_M_IBSS:
		case IEEE80211_M_AHDEMO:
			wh->i_fc[1] = IEEE80211_FC1_DIR_NODS;
			IEEE80211_ADDR_COPY(wh->i_addr1, da);
			IEEE80211_ADDR_COPY(wh->i_addr2, sa);
			IEEE80211_ADDR_COPY(wh->i_addr3, bssid);
			break;
		default:
			ieee80211_err("ieee80211_send_setup: "
			    "Invalid mode %u\n", ic->ic_opmode);
			return;
		}
	} else {
		wh->i_fc[1] = IEEE80211_FC1_DIR_NODS;
		IEEE80211_ADDR_COPY(wh->i_addr1, da);
		IEEE80211_ADDR_COPY(wh->i_addr2, sa);
		IEEE80211_ADDR_COPY(wh->i_addr3, bssid);
	}
	*(uint16_t *)&wh->i_dur[0] = 0;	/* set duration */
	/* NB: use non-QoS tid */
	*(uint16_t *)&wh->i_seq[0] =
	    LE_16(in->in_txseqs[IEEE80211_NONQOS_TID] <<
	    IEEE80211_SEQ_SEQ_SHIFT);
	in->in_txseqs[IEEE80211_NONQOS_TID]++;
}

/*
 * Send a management frame to the specified node.  The node pointer
 * must have a reference as the pointer will be passed to the driver
 * and potentially held for a long time.  If the frame is successfully
 * dispatched to the driver, then it is responsible for freeing the
 * reference (and potentially free'ing up any associated storage).
 *
 * Return 0 on success
 */
int
ieee80211_mgmt_output(ieee80211com_t *ic, ieee80211_node_t *in, mblk_t *mp,
    int type, int timer)
{
	ieee80211_impl_t *im = ic->ic_private;
	struct ieee80211_frame *wh;

	ASSERT(in != NULL);

	wh = (struct ieee80211_frame *)mp->b_rptr;
	ieee80211_send_setup(ic, in, wh, IEEE80211_FC0_TYPE_MGT | type,
	    ic->ic_macaddr, in->in_macaddr, in->in_bssid);
	if (in->in_challenge != NULL)
		wh->i_fc[1] |= IEEE80211_FC1_WEP;

	if (timer > 0) {
		/*
		 * Set the mgt frame timeout.
		 */
		im->im_mgt_timer = timer;
		ieee80211_start_watchdog(ic, 1);
	}
	return ((*ic->ic_xmit)(ic, mp, IEEE80211_FC0_TYPE_MGT));
}

/*
 * Send a null data frame to the specified node.
 *
 * NB: the caller is assumed to have setup a node reference
 *     for use; this is necessary to deal with a race condition
 *     when probing for inactive stations.
 */
int
ieee80211_send_nulldata(ieee80211_node_t *in)
{
	ieee80211com_t *ic = in->in_ic;
	mblk_t *m;
	struct ieee80211_frame *wh;
	uint8_t *frm;

	m = ieee80211_getmgtframe(&frm, 0);
	if (m == NULL) {
		ic->ic_stats.is_tx_nobuf++;
		return (ENOMEM);
	}

	wh = (struct ieee80211_frame *)m->b_rptr;
	ieee80211_send_setup(ic, in, wh,
	    IEEE80211_FC0_TYPE_DATA | IEEE80211_FC0_SUBTYPE_NODATA,
	    ic->ic_macaddr, in->in_macaddr, in->in_bssid);
	/* NB: power management bit is never sent by an AP */
	if ((in->in_flags & IEEE80211_NODE_PWR_MGT) &&
	    ic->ic_opmode != IEEE80211_M_HOSTAP)
		wh->i_fc[1] |= IEEE80211_FC1_PWR_MGT;
	m->b_wptr = m->b_rptr + sizeof (struct ieee80211_frame);

	ieee80211_dbg(IEEE80211_MSG_DEBUG | IEEE80211_MSG_DUMPPKTS, "net80211: "
	    "send null data frame on channel %u, pwr mgt %s\n",
	    ieee80211_macaddr_sprintf(in->in_macaddr),
	    ieee80211_chan2ieee(ic, ic->ic_curchan),
	    wh->i_fc[1] & IEEE80211_FC1_PWR_MGT ? "ena" : "dis");

	(void) (*ic->ic_xmit)(ic, m, IEEE80211_FC0_TYPE_MGT);

	return (0);
}

/*
 * Encapsulate an outbound data frame for GLDv3 based driver.
 * Fill in the variable part of the 80211 frame
 */
/* ARGSUSED */
mblk_t *
ieee80211_encap(ieee80211com_t *ic, mblk_t *mp, ieee80211_node_t *in)
{
	struct ieee80211_frame	*wh;
	struct ieee80211_key *key;
	int addqos, ac, tid;

	ASSERT(mp != NULL && MBLKL(mp) >= sizeof (struct ieee80211_frame));
	/*
	 * Some ap's don't handle QoS-encapsulated EAPOL
	 * frames so suppress use.  This may be an issue if other
	 * ap's require all data frames to be QoS-encapsulated
	 * once negotiated in which case we'll need to make this
	 * configurable.
	 */
	addqos = in->in_flags & (IEEE80211_NODE_QOS | IEEE80211_NODE_HT);
	wh = (struct ieee80211_frame *)mp->b_rptr;
	*(uint16_t *)wh->i_dur = 0;
	if (addqos) {
		struct ieee80211_qosframe *qwh =
		    (struct ieee80211_qosframe *)wh;

		ac = ieee80211_classify(ic, mp, in);
		/* map from access class/queue to 11e header priorty value */
		tid = WME_AC_TO_TID(ac);
		qwh->i_qos[0] = tid & IEEE80211_QOS_TID;
		/*
		 * Check if A-MPDU tx aggregation is setup or if we
		 * should try to enable it.  The sta must be associated
		 * with HT and A-MPDU enabled for use.  On the first
		 * frame that goes out We issue an ADDBA request and
		 * wait for a reply.  The frame being encapsulated
		 * will go out w/o using A-MPDU, or possibly it might
		 * be collected by the driver and held/retransmit.
		 * ieee80211_ampdu_request handles staggering requests
		 * in case the receiver NAK's us or we are otherwise
		 * unable to establish a BA stream.
		 */
		if ((in->in_flags & IEEE80211_NODE_AMPDU_TX) &&
		    (ic->ic_flags_ext & IEEE80211_FEXT_AMPDU_TX)) {
			struct ieee80211_tx_ampdu *tap = &in->in_tx_ampdu[ac];

			if (IEEE80211_AMPDU_RUNNING(tap)) {
				/*
				 * Operational, mark frame for aggregation.
				 */
				qwh->i_qos[0] |= IEEE80211_QOS_ACKPOLICY_BA;
			} else if (!IEEE80211_AMPDU_REQUESTED(tap)) {
				/*
				 * Not negotiated yet, request service.
				 */
				(void) ieee80211_ampdu_request(in, tap);
			}
		}
		/* works even when BA marked above */
		if (ic->ic_wme.wme_wmeChanParams.cap_wmeParams[ac].
		    wmep_noackPolicy) {
			qwh->i_qos[0] |= IEEE80211_QOS_ACKPOLICY_NOACK;
		}

		*(uint16_t *)wh->i_seq =
		    LE_16(in->in_txseqs[tid] << IEEE80211_SEQ_SEQ_SHIFT);
		in->in_txseqs[tid]++;
	} else {
		*(uint16_t *)wh->i_seq =
		    LE_16(in->in_txseqs[IEEE80211_NONQOS_TID] <<
		    IEEE80211_SEQ_SEQ_SHIFT);
		in->in_txseqs[IEEE80211_NONQOS_TID]++;
	}

	if (ic->ic_flags & IEEE80211_F_PRIVACY)
		key = ieee80211_crypto_getkey(ic);
	else
		key = NULL;

	/*
	 * IEEE 802.1X: send EAPOL frames always in the clear.
	 * WPA/WPA2: encrypt EAPOL keys when pairwise keys are set.
	 */
	if (key != NULL && (ic->ic_flags & IEEE80211_F_WPA)) {
		wh->i_fc[1] |= IEEE80211_FC1_WEP;
		if (!ieee80211_crypto_enmic(isc, key, mp, 0))
			ieee80211_err("ieee80211_crypto_enmic failed.\n");
	}

	return (mp);
}

/*
 * Add supported rates information element to a frame.
 */
static uint8_t *
ieee80211_add_rates(uint8_t *frm, const struct ieee80211_rateset *rs)
{
	uint8_t nrates;

	*frm++ = IEEE80211_ELEMID_RATES;
	nrates = rs->ir_nrates;
	if (nrates > IEEE80211_RATE_SIZE)
		nrates = IEEE80211_RATE_SIZE;
	*frm++ = nrates;
	bcopy(rs->ir_rates, frm, nrates);
	return (frm + nrates);
}

/*
 * Add extended supported rates element to a frame, usually for 11g mode
 */
static uint8_t *
ieee80211_add_xrates(uint8_t *frm, const struct ieee80211_rateset *rs)
{
	if (rs->ir_nrates > IEEE80211_RATE_SIZE) {
		uint8_t nrates = rs->ir_nrates - IEEE80211_RATE_SIZE;

		*frm++ = IEEE80211_ELEMID_XRATES;
		*frm++ = nrates;
		bcopy(rs->ir_rates + IEEE80211_RATE_SIZE, frm, nrates);
		frm += nrates;
	}
	return (frm);
}

#define	WME_OUI_BYTES		0x00, 0x50, 0xf2
/*
 * Add a WME information element to a frame.
 */
/* ARGSUSED */
static uint8_t *
ieee80211_add_wme_info(uint8_t *frm, struct ieee80211_wme_state *wme)
{
	static const struct ieee80211_wme_info info = {
		.wme_id		= IEEE80211_ELEMID_VENDOR,
		.wme_len	= sizeof (struct ieee80211_wme_info) - 2,
		.wme_oui	= { WME_OUI_BYTES },
		.wme_type	= WME_OUI_TYPE,
		.wme_subtype	= WME_INFO_OUI_SUBTYPE,
		.wme_version	= WME_VERSION,
		.wme_info	= 0,
	};
	(void) memcpy(frm, &info, sizeof (info));
	return (frm + sizeof (info));
}

/*
 * Add a WME parameters element to a frame.
 */
static uint8_t *
ieee80211_add_wme_param(uint8_t *frm, struct ieee80211_wme_state *wme)
{
#define	SM(_v, _f)	(((_v) << _f##_S) & _f)
#define	ADDSHORT(frm, v) do {			\
	_NOTE(CONSTCOND)			\
	frm[0] = (v) & 0xff;			\
	frm[1] = (v) >> 8;			\
	frm += 2;				\
	_NOTE(CONSTCOND)			\
} while (0)
	/* NB: this works 'cuz a param has an info at the front */
	static const struct ieee80211_wme_info param = {
		.wme_id		= IEEE80211_ELEMID_VENDOR,
		.wme_len	= sizeof (struct ieee80211_wme_param) - 2,
		.wme_oui	= { WME_OUI_BYTES },
		.wme_type	= WME_OUI_TYPE,
		.wme_subtype	= WME_PARAM_OUI_SUBTYPE,
		.wme_version	= WME_VERSION,
	};
	int i;

	(void) memcpy(frm, &param, sizeof (param));
	frm += offsetof(struct ieee80211_wme_info, wme_info);
	*frm++ = wme->wme_bssChanParams.cap_info;	/* AC info */
	*frm++ = 0;					/* reserved field */
	for (i = 0; i < WME_NUM_AC; i++) {
		const struct wmeParams *ac =
		    &wme->wme_bssChanParams.cap_wmeParams[i];
		*frm++ = SM(i, WME_PARAM_ACI)
		    | SM(ac->wmep_acm, WME_PARAM_ACM)
		    | SM(ac->wmep_aifsn, WME_PARAM_AIFSN);
		*frm++ = SM(ac->wmep_logcwmax, WME_PARAM_LOGCWMAX)
		    | SM(ac->wmep_logcwmin, WME_PARAM_LOGCWMIN);
		ADDSHORT(frm, ac->wmep_txopLimit);
	}
	return (frm);
#undef SM
#undef ADDSHORT
}
#undef WME_OUI_BYTES

/*
 * Add SSID element to a frame
 */
static uint8_t *
ieee80211_add_ssid(uint8_t *frm, const uint8_t *ssid, uint32_t len)
{
	*frm++ = IEEE80211_ELEMID_SSID;
	*frm++ = (uint8_t)len;
	bcopy(ssid, frm, len);
	return (frm + len);
}

/*
 * Add an erp element to a frame.
 */
static uint8_t *
ieee80211_add_erp(uint8_t *frm, ieee80211com_t *ic)
{
	uint8_t erp;

	*frm++ = IEEE80211_ELEMID_ERP;
	*frm++ = 1;
	erp = 0;
	if (ic->ic_flags & IEEE80211_F_USEPROT)
		erp |= IEEE80211_ERP_USE_PROTECTION;
	if (ic->ic_flags & IEEE80211_F_USEBARKER)
		erp |= IEEE80211_ERP_LONG_PREAMBLE;
	*frm++ = erp;
	return (frm);
}

/*
 * Get capability information from the interface softc, ic.
 */
static uint16_t
ieee80211_get_capinfo(ieee80211com_t *ic)
{
	uint16_t capinfo;

	if (ic->ic_opmode == IEEE80211_M_IBSS)
		capinfo = IEEE80211_CAPINFO_IBSS;
	else
		capinfo = IEEE80211_CAPINFO_ESS;
	if (ic->ic_flags & IEEE80211_F_PRIVACY)
		capinfo |= IEEE80211_CAPINFO_PRIVACY;
	if ((ic->ic_flags & IEEE80211_F_SHPREAMBLE) &&
	    IEEE80211_IS_CHAN_2GHZ(ic->ic_curchan)) {
		capinfo |= IEEE80211_CAPINFO_SHORT_PREAMBLE;
	}
	if (ic->ic_flags & IEEE80211_F_SHSLOT)
		capinfo |= IEEE80211_CAPINFO_SHORT_SLOTTIME;

	return (capinfo);
}

/*
 * Send a probe request frame with the specified ssid
 * and any optional information element data.
 */
int
ieee80211_send_probereq(ieee80211_node_t *in,
    const uint8_t *sa, const uint8_t *da, const uint8_t *bssid,
    const uint8_t *ssid, size_t ssidlen, const void *optie, size_t optielen)
{
	mblk_t *mp;
	ieee80211com_t *ic = in->in_ic;
	enum ieee80211_phymode mode;
	struct ieee80211_frame *wh;
	uint8_t *frm;

	/*
	 * prreq frame format ([tlv] - 1 byte element ID + 1 byte length)
	 *	[tlv] ssid
	 *	[tlv] supported rates
	 *	[tlv] extended supported rates
	 *	[tlv] user-specified ie's
	 */
	mp = ieee80211_getmgtframe(&frm,
	    2 + IEEE80211_NWID_LEN
	    + 2 + IEEE80211_RATE_SIZE +
	    + 2 + IEEE80211_XRATE_SIZE
	    + optielen);
	if (mp == NULL)
		return (ENOMEM);

	frm = ieee80211_add_ssid(frm, ssid, ssidlen);
	mode = ieee80211_chan2mode(ic, ic->ic_curchan);
	frm = ieee80211_add_rates(frm, &ic->ic_sup_rates[mode]);
	frm = ieee80211_add_xrates(frm, &ic->ic_sup_rates[mode]);
	if (optie != NULL) {
		(void) memcpy(frm, optie, optielen);
		frm += optielen;
	}
	mp->b_wptr = frm;

	wh = (struct ieee80211_frame *)mp->b_rptr;
	ieee80211_send_setup(ic, in, wh,
	    IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_PROBE_REQ,
	    sa, da, bssid);

	ieee80211_dbg(IEEE80211_MSG_DEBUG | IEEE80211_MSG_DUMPPKTS,
	    "[%s] send probe req on channel %u\n",
	    ieee80211_macaddr_sprintf(wh->i_addr1),
	    ieee80211_chan2ieee(ic, ic->ic_curchan));

	(void) (*ic->ic_xmit)(ic, mp, IEEE80211_FC0_TYPE_MGT);
	return (0);
}

/*
 * Send a management frame.  The node is for the destination (or ic_bss
 * when in station mode).  Nodes other than ic_bss have their reference
 * count bumped to reflect our use for an indeterminant time.
 */
int
ieee80211_send_mgmt(ieee80211com_t *ic, ieee80211_node_t *in, int type, int arg)
{
	mblk_t *mp;
	uint8_t *frm;
	uint16_t capinfo;
	struct ieee80211_key *key;
	boolean_t has_challenge;
	boolean_t is_shared_key;
	int ret;
	int timer;
	int status;

	ASSERT(in != NULL);

	timer = 0;
	switch (type) {
	case IEEE80211_FC0_SUBTYPE_PROBE_RESP:
		/*
		 * probe response frame format
		 *	[8] time stamp
		 *	[2] beacon interval
		 *	[2] capability information
		 *	[tlv] ssid
		 *	[tlv] supported rates
		 *	[tlv] parameter set (FH/DS)
		 *	[tlv] parameter set (IBSS)
		 *	[tlv] extended rate phy (ERP)
		 *	[tlv] extended supported rates
		 *	[tlv] WPA
		 *	[tlv] WME (optional)
		 *	[tlv] HT capabilities
		 *	[tlv] HT information
		 *	[tlv] Vendor OUI HT capabilities (optional)
		 *	[tlv] Vendor OUI HT information (optional)
		 */
		mp = ieee80211_getmgtframe(&frm,
		    8			/* time stamp  */
		    + sizeof (uint16_t)	/* beacon interval  */
		    + sizeof (uint16_t)	/* capability  */
		    + 2 + IEEE80211_NWID_LEN
		    + 2 + IEEE80211_RATE_SIZE
		    + 2 + IEEE80211_FH_LEN
		    + 2 + IEEE80211_IBSS_LEN
		    + 2 + IEEE80211_ERP_LEN
		    + 2 + IEEE80211_XRATE_SIZE
		    + (ic->ic_flags & IEEE80211_F_WPA ?
		    2 * sizeof (struct ieee80211_ie_wpa) : 0)
					/* [tlv] WPA  */
		    + (ic->ic_flags & IEEE80211_F_WME ?
		    sizeof (struct ieee80211_wme_param) : 0)
					/* [tlv] WME  */
		    /* check for cluster requirement */
		    + 2 * sizeof (struct ieee80211_ie_htcap) + 4
		    + 2 * sizeof (struct ieee80211_ie_htinfo) + 4);

		if (mp == NULL)
			return (ENOMEM);

		bzero(frm, 8);	/* timestamp should be filled later */
		frm += 8;
		*(uint16_t *)frm = LE_16(ic->ic_bss->in_intval);
		frm += 2;
		capinfo = ieee80211_get_capinfo(ic);
		*(uint16_t *)frm = LE_16(capinfo);
		frm += 2;

		/* ssid */
		frm = ieee80211_add_ssid(frm, ic->ic_bss->in_essid,
		    ic->ic_bss->in_esslen);
		/* supported rates */
		frm = ieee80211_add_rates(frm, &in->in_rates);

		if (IEEE80211_IS_CHAN_FHSS(ic->ic_curchan)) {
			*frm++ = IEEE80211_ELEMID_FHPARMS;
			*frm++ = IEEE80211_FH_LEN;
			*frm++ = in->in_fhdwell & 0x00ff;
			*frm++ = (in->in_fhdwell >> 8) & 0x00ff;
			*frm++ = IEEE80211_FH_CHANSET(
			    ieee80211_chan2ieee(ic, ic->ic_curchan));
			*frm++ = IEEE80211_FH_CHANPAT(
			    ieee80211_chan2ieee(ic, ic->ic_curchan));
			*frm++ = in->in_fhindex;
		} else {
			*frm++ = IEEE80211_ELEMID_DSPARMS;
			*frm++ = IEEE80211_DS_LEN;
			*frm++ = ieee80211_chan2ieee(ic, ic->ic_curchan);
		}

		if (ic->ic_opmode == IEEE80211_M_IBSS) {
			*frm++ = IEEE80211_ELEMID_IBSSPARMS;
			*frm++ = IEEE80211_IBSS_LEN;
			*frm++ = 0; *frm++ = 0;		/* ATIM window */
		}
		if (IEEE80211_IS_CHAN_ANYG(ic->ic_curchan))
			frm = ieee80211_add_erp(frm, ic);
		frm = ieee80211_add_xrates(frm, &in->in_rates);
		/*
		 * NB: legacy 11b clients do not get certain ie's.
		 * The caller identifies such clients by passing
		 * a token in arg to us.  Could expand this to be
		 * any legacy client for stuff like HT ie's.
		 */
		if (IEEE80211_IS_CHAN_HT(ic->ic_curchan) &&
		    arg != IEEE80211_SEND_LEGACY_11B) {
			frm = ieee80211_add_htcap(frm, in);
			frm = ieee80211_add_htinfo(frm, in);
		}
		if (ic->ic_flags & IEEE80211_F_WME)
			frm = ieee80211_add_wme_param(frm, &ic->ic_wme);
		if (IEEE80211_IS_CHAN_HT(ic->ic_curchan) &&
		    (ic->ic_flags_ext & IEEE80211_FEXT_HTCOMPAT) &&
		    arg != IEEE80211_SEND_LEGACY_11B) {
			frm = ieee80211_add_htcap_vendor(frm, in);
			frm = ieee80211_add_htinfo_vendor(frm, in);
		}
		mp->b_wptr = frm;	/* allocated is greater than used */

		break;

	case IEEE80211_FC0_SUBTYPE_AUTH:
		status = arg >> 16;
		arg &= 0xffff;
		has_challenge = ((arg == IEEE80211_AUTH_SHARED_CHALLENGE ||
		    arg == IEEE80211_AUTH_SHARED_RESPONSE) &&
		    in->in_challenge != NULL);

		/*
		 * Deduce whether we're doing open authentication or
		 * shared key authentication.  We do the latter if
		 * we're in the middle of a shared key authentication
		 * handshake or if we're initiating an authentication
		 * request and configured to use shared key.
		 */
		is_shared_key = has_challenge ||
		    arg >= IEEE80211_AUTH_SHARED_RESPONSE ||
		    (arg == IEEE80211_AUTH_SHARED_REQUEST &&
		    ic->ic_bss->in_authmode == IEEE80211_AUTH_SHARED);

		if (has_challenge && status == IEEE80211_STATUS_SUCCESS)
			key = ieee80211_crypto_getkey(ic);
		else
			key = NULL;

		mp = ieee80211_getmgtframe(&frm,
		    3 * sizeof (uint16_t)
		    + (has_challenge && status == IEEE80211_STATUS_SUCCESS ?
		    sizeof (uint16_t) + IEEE80211_CHALLENGE_LEN : 0)
		    + (key != NULL ? key->wk_cipher->ic_header : 0));
		if (mp == NULL)
			return (ENOMEM);

		if (key != NULL)
			frm += key->wk_cipher->ic_header;

		((uint16_t *)frm)[0] =
		    (is_shared_key) ? LE_16(IEEE80211_AUTH_ALG_SHARED)
		    : LE_16(IEEE80211_AUTH_ALG_OPEN);
		((uint16_t *)frm)[1] = LE_16(arg);	/* sequence number */
		((uint16_t *)frm)[2] = LE_16(status);	/* status */

		if (has_challenge && status == IEEE80211_STATUS_SUCCESS) {
			frm += IEEE80211_AUTH_ELEM_MIN;
			*frm = IEEE80211_ELEMID_CHALLENGE;
			frm++;
			*frm = IEEE80211_CHALLENGE_LEN;
			frm++;
			bcopy(in->in_challenge, frm, IEEE80211_CHALLENGE_LEN);
		}

		if (ic->ic_opmode == IEEE80211_M_STA)
			timer = IEEE80211_TRANS_WAIT;
		break;

	case IEEE80211_FC0_SUBTYPE_DEAUTH:
		mp = ieee80211_getmgtframe(&frm, sizeof (uint16_t));
		if (mp == NULL)
			return (ENOMEM);

		*(uint16_t *)frm = LE_16(arg);	/* reason */

		ieee80211_node_unauthorize(in);	/* port closed */
		break;

	case IEEE80211_FC0_SUBTYPE_ASSOC_REQ:
	case IEEE80211_FC0_SUBTYPE_REASSOC_REQ:
		/*
		 * asreq frame format
		 *	[2] capability information
		 *	[2] listen interval
		 *	[6*] current AP address (reassoc only)
		 *	[tlv] ssid
		 *	[tlv] supported rates
		 *	[tlv] extended supported rates
		 *	[tlv] WME
		 *	[tlv] HT capabilities
		 *	[tlv] Vendor OUI HT capabilities (optional)
		 *	[tlv] user-specified ie's
		 */
		mp = ieee80211_getmgtframe(&frm,
		    sizeof (uint16_t)
		    + sizeof (uint16_t) + IEEE80211_ADDR_LEN
		    + 2 + IEEE80211_NWID_LEN
		    + 2 + IEEE80211_RATE_SIZE
		    + 2 + IEEE80211_XRATE_SIZE
		    + sizeof (struct ieee80211_wme_info)
		    + 2 * sizeof (struct ieee80211_ie_htcap) + 4
		    + ic->ic_opt_ie_len);
		if (mp == NULL)
			return (ENOMEM);

		capinfo = ieee80211_get_capinfo(ic);
		if (!(in->in_capinfo & IEEE80211_CAPINFO_SHORT_SLOTTIME) ||
		    !(ic->ic_caps & IEEE80211_C_SHSLOT)) {
			capinfo &= ~IEEE80211_CAPINFO_SHORT_SLOTTIME;
		} else {
			capinfo |= IEEE80211_CAPINFO_SHORT_SLOTTIME;
		}
		if (!(in->in_capinfo & IEEE80211_CAPINFO_SHORT_PREAMBLE) ||
		    !(ic->ic_caps & IEEE80211_C_SHPREAMBLE)) {
			capinfo &= ~IEEE80211_CAPINFO_SHORT_PREAMBLE;
		} else {
			capinfo |= IEEE80211_CAPINFO_SHORT_PREAMBLE;
		}
		*(uint16_t *)frm = LE_16(capinfo);
		frm += 2;

		*(uint16_t *)frm = LE_16(ic->ic_lintval);
		frm += 2;

		if (type == IEEE80211_FC0_SUBTYPE_REASSOC_REQ) {
			IEEE80211_ADDR_COPY(frm, ic->ic_bss->in_bssid);
			frm += IEEE80211_ADDR_LEN;
		}

		frm = ieee80211_add_ssid(frm, in->in_essid, in->in_esslen);
		frm = ieee80211_add_rates(frm, &in->in_rates);
		frm = ieee80211_add_xrates(frm, &in->in_rates);
		if ((ic->ic_flags_ext & IEEE80211_FEXT_HT) &&
		    in->in_htcap_ie != NULL &&
		    in->in_htcap_ie[0] == IEEE80211_ELEMID_HTCAP)
			frm = ieee80211_add_htcap(frm, in);
		if ((ic->ic_flags & IEEE80211_F_WME) && in->in_wme_ie != NULL)
			frm = ieee80211_add_wme_info(frm, &ic->ic_wme);
		if ((ic->ic_flags_ext & IEEE80211_FEXT_HT) &&
		    in->in_htcap_ie != NULL &&
		    in->in_htcap_ie[0] == IEEE80211_ELEMID_VENDOR)
			frm = ieee80211_add_htcap_vendor(frm, in);
		if (ic->ic_opt_ie != NULL) {
			bcopy(ic->ic_opt_ie, frm, ic->ic_opt_ie_len);
			frm += ic->ic_opt_ie_len;
		}
		mp->b_wptr = frm;	/* allocated is greater than used */

		timer = IEEE80211_TRANS_WAIT;
		break;

	case IEEE80211_FC0_SUBTYPE_ASSOC_RESP:
	case IEEE80211_FC0_SUBTYPE_REASSOC_RESP:
		/*
		 * asreq frame format
		 *	[2] capability information
		 *	[2] status
		 *	[2] association ID
		 *	[tlv] supported rates
		 *	[tlv] extended supported rates
		 *	[tlv] WME (if enabled and STA enabled)
		 *	[tlv] HT capabilities (standard or vendor OUI)
		 *	[tlv] HT information (standard or vendor OUI)
		 */
		mp = ieee80211_getmgtframe(&frm,
		    3 * sizeof (uint16_t)
		    + 2 + IEEE80211_RATE_SIZE
		    + 2 + IEEE80211_XRATE_SIZE);
		if (mp == NULL)
			return (ENOMEM);

		capinfo = ieee80211_get_capinfo(ic);
		*(uint16_t *)frm = LE_16(capinfo);
		frm += 2;

		*(uint16_t *)frm = LE_16(arg);	/* status */
		frm += 2;

		if (arg == IEEE80211_STATUS_SUCCESS)
			*(uint16_t *)frm = LE_16(in->in_associd);
		else
			*(uint16_t *)frm = LE_16(0);
		frm += 2;

		frm = ieee80211_add_rates(frm, &in->in_rates);
		frm = ieee80211_add_xrates(frm, &in->in_rates);
		mp->b_wptr = frm;
		break;

	case IEEE80211_FC0_SUBTYPE_DISASSOC:
		mp = ieee80211_getmgtframe(&frm, sizeof (uint16_t));
		if (mp == NULL)
			return (ENOMEM);
		*(uint16_t *)frm = LE_16(arg);	/* reason */
		break;

	default:
		ieee80211_dbg(IEEE80211_MSG_ANY,
		    "[%s] invalid mgmt frame type %u\n",
		    ieee80211_macaddr_sprintf(in->in_macaddr), type);
		return (EINVAL);
	} /* type */
	ret = ieee80211_mgmt_output(ic, in, mp, type, timer);
	return (ret);
}

/*
 * Allocate a beacon frame and fillin the appropriate bits.
 */
mblk_t *
ieee80211_beacon_alloc(ieee80211com_t *ic, ieee80211_node_t *in,
    struct ieee80211_beacon_offsets *bo)
{
	struct ieee80211_frame *wh;
	struct ieee80211_rateset *rs;
	mblk_t *m;
	uint8_t *frm;
	int pktlen;
	uint16_t capinfo;

	IEEE80211_LOCK(ic);
	/*
	 * beacon frame format
	 *	[8] time stamp
	 *	[2] beacon interval
	 *	[2] cabability information
	 *	[tlv] ssid
	 *	[tlv] supported rates
	 *	[3] parameter set (DS)
	 *	[tlv] parameter set (IBSS/TIM)
	 *	[tlv] extended rate phy (ERP)
	 *	[tlv] extended supported rates
	 *	[tlv] WME parameters
	 *	[tlv] WPA/RSN parameters
	 *	[tlv] HT capabilities
	 *	[tlv] HT information
	 *	[tlv] Vendor OUI HT capabilities (optional)
	 *	[tlv] Vendor OUI HT information (optional)
	 * Vendor-specific OIDs (e.g. Atheros)
	 * NB: we allocate the max space required for the TIM bitmap.
	 */
	rs = &in->in_rates;
	pktlen =  8			/* time stamp */
	    + sizeof (uint16_t)		/* beacon interval */
	    + sizeof (uint16_t)		/* capabilities */
	    + 2 + in->in_esslen		/* ssid */
	    + 2 + IEEE80211_RATE_SIZE	/* supported rates */
	    + 2 + 1			/* DS parameters */
	    + 2 + 4 + ic->ic_tim_len	/* DTIM/IBSSPARMS */
	    + 2 + 1			/* ERP */
	    + 2 + IEEE80211_XRATE_SIZE
	    + (ic->ic_caps & IEEE80211_C_WME ?	/* WME */
	    sizeof (struct ieee80211_wme_param) : 0)
	    /* conditional? */
	    + 4 + 2 * sizeof (struct ieee80211_ie_htcap)	/* HT caps */
	    + 4 + 2 * sizeof (struct ieee80211_ie_htinfo);	/* HT info */

	m = ieee80211_getmgtframe(&frm, pktlen);
	if (m == NULL) {
		ieee80211_dbg(IEEE80211_MSG_ANY, "ieee80211_beacon_alloc: "
		    "cannot get buf; size %u\n", pktlen);
		IEEE80211_UNLOCK(ic);
		return (NULL);
	}

	/* timestamp is set by hardware/driver */
	(void) memset(frm, 0, 8);
	frm += 8;
	*(uint16_t *)frm = LE_16(in->in_intval);
	frm += 2;
	capinfo = ieee80211_get_capinfo(ic);
	bo->bo_caps = (uint16_t *)frm;
	*(uint16_t *)frm = LE_16(capinfo);
	frm += 2;
	*frm++ = IEEE80211_ELEMID_SSID;
	if (!(ic->ic_flags & IEEE80211_F_HIDESSID)) {
		*frm++ = in->in_esslen;
		bcopy(in->in_essid, frm, in->in_esslen);
		frm += in->in_esslen;
	} else {
		*frm++ = 0;
	}
	frm = ieee80211_add_rates(frm, rs);
	if (ic->ic_curmode != IEEE80211_MODE_FH) {
		*frm++ = IEEE80211_ELEMID_DSPARMS;
		*frm++ = 1;
		*frm++ = ieee80211_chan2ieee(ic, in->in_chan);
	}
	bo->bo_tim = frm;
	if (ic->ic_opmode == IEEE80211_M_IBSS) {
		*frm++ = IEEE80211_ELEMID_IBSSPARMS;
		*frm++ = 2;
		*frm++ = 0; *frm++ = 0;		/* TODO: ATIM window */
		bo->bo_tim_len = 0;
	} else {
		struct ieee80211_tim_ie *tie =
		    (struct ieee80211_tim_ie *)frm;

		tie->tim_ie = IEEE80211_ELEMID_TIM;
		tie->tim_len = 4;	/* length */
		tie->tim_count = 0;	/* DTIM count */
		tie->tim_period = IEEE80211_DTIM_DEFAULT;
		tie->tim_bitctl = 0;	/* bitmap control */
		tie->tim_bitmap[0] = 0;	/* Partial Virtual Bitmap */
		frm += sizeof (struct ieee80211_tim_ie);
		bo->bo_tim_len = 1;
	}
	bo->bo_trailer = frm;

	if (ic->ic_curmode == IEEE80211_MODE_11G) {
		bo->bo_erp = frm;
		frm = ieee80211_add_erp(frm, ic);
	}
	frm = ieee80211_add_xrates(frm, rs);
	if (IEEE80211_IS_CHAN_HT(ic->ic_curchan)) {
		frm = ieee80211_add_htcap(frm, in);
		bo->bo_htinfo = frm;
		frm = ieee80211_add_htinfo(frm, in);
	}
	if (ic->ic_flags & IEEE80211_F_WME) {
		bo->bo_wme = frm;
		frm = ieee80211_add_wme_param(frm, &ic->ic_wme);
	}
	if (IEEE80211_IS_CHAN_HT(ic->ic_curchan) &&
	    (ic->ic_flags_ext & IEEE80211_FEXT_HTCOMPAT)) {
		frm = ieee80211_add_htcap_vendor(frm, in);
		frm = ieee80211_add_htinfo_vendor(frm, in);
	}
	bo->bo_trailer_len = _PTRDIFF(frm, bo->bo_trailer);
	m->b_wptr = frm;

	wh = (struct ieee80211_frame *)m->b_rptr;
	wh->i_fc[0] = IEEE80211_FC0_VERSION_0 | IEEE80211_FC0_TYPE_MGT |
	    IEEE80211_FC0_SUBTYPE_BEACON;
	wh->i_fc[1] = IEEE80211_FC1_DIR_NODS;
	*(uint16_t *)wh->i_dur = 0;
	IEEE80211_ADDR_COPY(wh->i_addr1, wifi_bcastaddr);
	IEEE80211_ADDR_COPY(wh->i_addr2, ic->ic_macaddr);
	IEEE80211_ADDR_COPY(wh->i_addr3, in->in_bssid);
	*(uint16_t *)wh->i_seq = 0;

	IEEE80211_UNLOCK(ic);
	return (m);
}

/*
 * Update the dynamic parts of a beacon frame based on the current state.
 */
/* ARGSUSED */
int
ieee80211_beacon_update(ieee80211com_t *ic, ieee80211_node_t *in,
    struct ieee80211_beacon_offsets *bo, mblk_t *mp, int mcast)
{
	uint16_t capinfo;

	IEEE80211_LOCK(ic);

	capinfo = ieee80211_get_capinfo(ic);
	*bo->bo_caps = LE_16(capinfo);

	IEEE80211_UNLOCK(ic);
	return (0);
}

/*
 * Assign priority to a frame based on any vlan tag assigned
 * to the station and/or any Diffserv setting in an IP header.
 * Finally, if an ACM policy is setup (in station mode) it's
 * applied.
 */
/* ARGSUSED */
int
ieee80211_classify(struct ieee80211com *ic, mblk_t *m,
    struct ieee80211_node *ni)
{
	int ac;

	if ((ni->in_flags & IEEE80211_NODE_QOS) == 0)
		return (WME_AC_BE);

	/* Process VLan */
	/* Process IPQoS */

	ac = WME_AC_BE;

	/*
	 * Apply ACM policy.
	 */
	if (ic->ic_opmode == IEEE80211_M_STA) {
		static const int acmap[4] = {
			WME_AC_BK,	/* WME_AC_BE */
			WME_AC_BK,	/* WME_AC_BK */
			WME_AC_BE,	/* WME_AC_VI */
			WME_AC_VI,	/* WME_AC_VO */
		};
		while (ac != WME_AC_BK &&
		    ic->ic_wme.wme_wmeBssChanParams.cap_wmeParams[ac].
		    wmep_acm) {
			ac = acmap[ac];
		}
	}

	return (ac);
}
