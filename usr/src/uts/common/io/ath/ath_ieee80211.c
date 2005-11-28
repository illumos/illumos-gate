/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright (c) 2002, 2003 Sam Leffler, Errno Consulting
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer,
 *    without modification.
 * 2. Redistributions in binary form must reproduce at minimum a disclaimer
 *    similar to the "NO WARRANTY" disclaimer below ("Disclaimer") and any
 *    redistribution must be conditioned upon including a substantially
 *    similar Disclaimer requirement for further binary redistribution.
 * 3. Neither the names of the above-listed copyright holders nor the names
 *    of any contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
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

/*
 * IEEE 802.11 generic handler
 *
 * This code is derived from NetBSD code; their copyright notice follows.
 */

/*
 * Copyright (c) 2001 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Atsushi Onoe.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *        This product includes software developed by the NetBSD
 *        Foundation, Inc. and its contributors.
 * 4. Neither the name of The NetBSD Foundation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

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
#include <sys/byteorder.h>
#include <sys/proc.h>
#include <sys/note.h>
#include <sys/strsun.h>
#include <sys/list.h>
#include <sys/byteorder.h>
#include <inet/common.h>
#include <inet/nd.h>
#include <inet/mi.h>
#include <inet/wifi_ioctl.h>
#include "ath_ieee80211.h"
#include "ath_impl.h"

#define	list_empty(a) ((a)->list_head.list_next == &(a)->list_head)

static const char *ieee80211_mgt_subtype_name[] = {
	"assoc_req",	"assoc_resp",	"reassoc_req",	"reassoc_resp",
	"probe_req",	"probe_resp",	"reserved#6",	"reserved#7",
	"beacon",	"atim",		"disassoc",	"auth",
	"deauth",	"reserved#13",	"reserved#14",	"reserved#15"
};

extern pri_t minclsyspri;

static void
ieee80211_unref_node(struct ieee80211_node **in)
{
	*in = NULL;
}

static uint8_t
ieee80211_get_rssi(struct ieee80211_node *in)
{
	/* no recent samples, use last known value */
	return (in->in_recv_hist[in->in_hist_cur].irh_rssi);
}

static void
ieee80211_reset_recvhist(struct ieee80211_node *in)
{
	int i;

	for (i = 0; i < IEEE80211_RECV_HIST_LEN; ++i) {
		in->in_recv_hist[i].irh_jiffies = IEEE80211_JIFFIES_NONE;
		in->in_recv_hist[i].irh_rssi = 0;
		in->in_recv_hist[i].irh_rstamp = 0;
		in->in_recv_hist[i].irh_rantenna = 0;
	}
	in->in_hist_cur = IEEE80211_RECV_HIST_LEN - 1;
}


static void
ieee80211_add_recvhist(struct ieee80211_node *in, uint8_t rssi,
    uint32_t rstamp, uint8_t rantenna)
{
	if (++in->in_hist_cur >= IEEE80211_RECV_HIST_LEN)
		in->in_hist_cur = 0;
	in->in_recv_hist[in->in_hist_cur].irh_rssi = rssi;
	in->in_recv_hist[in->in_hist_cur].irh_rstamp = rstamp;
	in->in_recv_hist[in->in_hist_cur].irh_rantenna = rantenna;
}

/*
 * Convert MHz frequency to IEEE channel number.
 */
uint32_t
ieee80211_mhz2ieee(uint32_t freq, uint32_t flags)
{
	if (flags & IEEE80211_CHAN_2GHZ) {	/* 2GHz band */
		if (freq == 2484)
			return (14);
		if (freq < 2484)
			return ((freq - 2407) / 5);
		else
			return (15 + ((freq - 2512) / 20));
	} else if (flags & IEEE80211_CHAN_5GHZ) {	/* 5Ghz band */
		return ((freq - 5000) / 5);
	} else {				/* either, guess */
		if (freq == 2484)
			return (14);
		if (freq < 2484)
			return ((freq - 2407) / 5);
		if (freq < 5000)
			return (15 + ((freq - 2512) / 20));
		return ((freq - 5000) / 5);
	}
}

/*
 * Convert channel to IEEE channel number.
 */
uint32_t
ieee80211_chan2ieee(ieee80211com_t *isc, struct ieee80211channel *ch)
{
	if (isc->isc_channels <= ch &&
	    ch <= &isc->isc_channels[IEEE80211_CHAN_MAX])
		return (ch - isc->isc_channels);
	else if (ch == IEEE80211_CHAN_ANYC)
		return (IEEE80211_CHAN_ANY);
	else {
		ATH_DEBUG((ATH_DBG_80211, "ath: ieee80211_chan2ieee(): "
		    "invalid channel freq %u flags %x\n",
		    ch->ich_freq, ch->ich_flags));
		return (0);
	}
}

/*
 * Convert IEEE channel number to MHz frequency.
 */
uint32_t
ieee80211_ieee2mhz(uint32_t chan, uint32_t flags)
{
	if (flags & IEEE80211_CHAN_2GHZ) {	/* 2GHz band */
		if (chan == 14)
			return (2484);
		if (chan < 14)
			return (2407 + chan * 5);
		else
			return (2512 + ((chan-15) * 20));
	} else if (flags & IEEE80211_CHAN_5GHZ) {	/* 5Ghz band */
		return (5000 + (chan * 5));
	} else {				/* either, guess */
		if (chan == 14)
			return (2484);
		if (chan < 14)			/* 0-13 */
			return (2407 + chan * 5);
		if (chan < 27)			/* 15-26 */
			return (2512 + ((chan-15) * 20));
		return (5000 + (chan * 5));
	}
}

static void
ieee80211_free_node(ieee80211com_t *isc, struct ieee80211_node *in)
{
	int32_t i, done;
	struct ieee80211_node *in1;

	/* remove in from list of isc->isc_in_list */
	list_remove(&isc->isc_in_list, in);

	/* remove in from list of isc->isc_inhash_list */
	done = 0;
	for (i = 0; i < IEEE80211_NODE_HASHSIZE; i++) {
		in1 = list_head(&isc->isc_inhash_list[i]);
		while (in1 != NULL) {
			if (in1 == in) {
				list_remove(&isc->isc_inhash_list[i], in);
				done = 1;
				break;
			}
			in1 = list_next(&isc->isc_inhash_list[i], in1);
		}
		if (done)
			break;
	}

	if (list_empty(&isc->isc_in_list))
		isc->isc_inact_timeout = 0;
	if (isc->isc_node_free != NULL)
		(*isc->isc_node_free)(isc, in);
}

/*
 * This function is only running in software interrupt thread,
 * and it will probably call back to LLD by isc_mgmt_send() or isc_new_state(),
 * to avoid recursive mutex entry, we must make sure that
 * the callers have release all LLD mutexs before calling ieee80211_input().
 */
void
ieee80211_input(ieee80211com_t *isc, mblk_t *mp,
	int32_t rssi, uint32_t rstamp, uint32_t rantenna)
{
	struct ieee80211_node *in;
	gld_mac_info_t *gld_p = isc->isc_dev;
	struct ieee80211_frame *wh;
	void (*rh)(ieee80211com_t *, mblk_t *, int32_t, uint32_t, uint32_t);
	uint8_t dir, subtype;
	uint8_t *bssid;
	uint16_t rxseq;

	wh = (struct ieee80211_frame *)mp->b_rptr;
	if ((wh->ifrm_fc[0] & IEEE80211_FC0_VERSION_MASK) !=
	    IEEE80211_FC0_VERSION_0) {
		ATH_DEBUG((ATH_DBG_80211, "ath: ieee80211_input(): "
		    "discard pkt with wrong version"));
		goto out;
	}

	dir = wh->ifrm_fc[1] & IEEE80211_FC1_DIR_MASK;

	mutex_enter(&isc->isc_genlock);
	if (isc->isc_state != IEEE80211_S_SCAN) {
		switch (isc->isc_opmode) {
		case IEEE80211_M_STA:
			in = isc->isc_bss;
			if (!IEEE80211_ADDR_EQ(wh->ifrm_addr2, in->in_bssid))
				goto out_with_mutex;
			break;
		case IEEE80211_M_IBSS:
		case IEEE80211_M_AHDEMO:
		case IEEE80211_M_HOSTAP:
			if (dir == IEEE80211_FC1_DIR_NODS)
				bssid = wh->ifrm_addr3;
			else
				bssid = wh->ifrm_addr1;
			if (!IEEE80211_ADDR_EQ(bssid, isc->isc_bss->in_bssid) &&
			    !IEEE80211_ADDR_EQ(bssid,
			    gld_p->gldm_broadcast_addr)) {
				/* not interested in */
				ATH_DEBUG((ATH_DBG_80211, "ath: "
				    "ieee80211_input(): other bss %s\n",
				    ieee80211_ether_sprintf(wh->ifrm_addr3)));
				goto out_with_mutex;
			}
			in = ieee80211_find_node(isc, wh->ifrm_addr2);
			if (in == NULL) {
				ATH_DEBUG((ATH_DBG_80211, "ath: "
				    "ieee80211_input(): unknown src %s\n",
				    ieee80211_ether_sprintf(wh->ifrm_addr2)));
				/*
				 * NB: Node allocation is handled in the
				 * management handling routines.  Just fake
				 * up a reference to the hosts's node to do
				 * the stuff below.
				 */
				in = isc->isc_bss;
			}
			break;
		default:
			/* catch bad values */
			break;
		}
		ieee80211_add_recvhist(in, rssi, rstamp, rantenna);
		rxseq = in->in_rxseq;
		in->in_rxseq = LE_16(*(uint16_t *)wh->ifrm_seq)
		    >> IEEE80211_SEQ_SEQ_SHIFT;
		/* fragment */
		if ((wh->ifrm_fc[1] & IEEE80211_FC1_RETRY) &&
		    rxseq == in->in_rxseq) {
			/* duplicate, silently discarded */
			goto out_with_mutex;
		}
		in->in_inact = 0;
	}

	switch (wh->ifrm_fc[0] & IEEE80211_FC0_TYPE_MASK) {
	case IEEE80211_FC0_TYPE_DATA:
		switch (isc->isc_opmode) {
		case IEEE80211_M_STA:
			if (dir != IEEE80211_FC1_DIR_FROMDS) {
				ATH_DEBUG((ATH_DBG_80211, "ath: ",
				    "ieee80211_input(): discard frame "
				    "with invalid direction %x\n", dir));
				goto out_with_mutex;
			}
			if (IEEE80211_IS_MULTICAST(wh->ifrm_addr1) &&
			    IEEE80211_ADDR_EQ(wh->ifrm_addr3,
			    gld_p->gldm_vendor_addr)) {
				/*
				 * In IEEE802.11 network, multicast packet
				 * sent from me is broadcasted from AP.
				 * It should be silently discarded for
				 * SIMPLEX interface.
				 */
				ATH_DEBUG((ATH_DBG_80211, "ath: "
				    "ieee80211_input(): "
				    "discard multicast echo\n"));
				goto out_with_mutex;
			}
			break;
		case IEEE80211_M_IBSS:
		case IEEE80211_M_AHDEMO:
			if (dir != IEEE80211_FC1_DIR_NODS)
				goto out_with_mutex;
			break;
		case IEEE80211_M_HOSTAP:
			/* need more work to support HOSTAP */
			break;
		}

		mutex_exit(&isc->isc_genlock);
		/* copy to listener after decrypt */
		mp = ieee80211_decap(mp);
		if (mp == NULL) {
			ATH_DEBUG((ATH_DBG_80211, "ath: ",
			    "ieee80211_input(): decapsulation failed\n"));
			goto out;
		}
		gld_recv(gld_p, mp);
		return;

	case IEEE80211_FC0_TYPE_MGT:
		if (dir != IEEE80211_FC1_DIR_NODS)
			goto out_with_mutex;
		if (isc->isc_opmode == IEEE80211_M_AHDEMO)
			goto out_with_mutex;
		subtype = wh->ifrm_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;

		/* drop uninteresting frames */
		if (isc->isc_state == IEEE80211_S_SCAN) {
			if (subtype != IEEE80211_FC0_SUBTYPE_BEACON &&
			    subtype != IEEE80211_FC0_SUBTYPE_PROBE_RESP)
				goto out_with_mutex;
		} else {
			if (isc->isc_opmode != IEEE80211_M_IBSS &&
			    subtype == IEEE80211_FC0_SUBTYPE_BEACON)
				goto out_with_mutex;
		}

		rh = isc->isc_recv_mgmt[subtype >> IEEE80211_FC0_SUBTYPE_SHIFT];
		if (rh != NULL)
			(*rh)(isc, mp, rssi, rstamp, rantenna);
		goto out_with_mutex;

	case IEEE80211_FC0_TYPE_CTL:
	default:
		ATH_DEBUG((ATH_DBG_80211, "ath: ieee80211_input(): "
		    "bad type %x\n", wh->ifrm_fc[0]));
		break;
	}
out_with_mutex:
	mutex_exit(&isc->isc_genlock);
out:
	if (mp != NULL)
		freemsg(mp);	/* free the buffer alloced in ath_rx_handler */
}

static void
ieee80211_free_allnodes(ieee80211com_t *isc)
{
	struct ieee80211_node *in;

	in = list_head(&isc->isc_in_list);
	while (in != NULL) {
		ieee80211_free_node(isc, in);
		in = list_head(&isc->isc_in_list);
	}
}

/*
 * Begin an active scan.
 */
static void
ieee80211_begin_scan(ieee80211com_t *isc, struct ieee80211_node *in)
{
	ATH_DEBUG((ATH_DBG_80211, "ath: "
	    "ieee80211_begin_scan(): begin %s scan\n",
	    isc->isc_opmode != IEEE80211_M_HOSTAP ? "active" : "passive"));

	/*
	 * Initialize the active channel set based on the set
	 * of available channels and the current PHY mode.
	 */
	bcopy(isc->isc_chan_active, isc->isc_chan_scan,
	    sizeof (isc->isc_chan_active));

	/*
	 * Flush any previously seen AP's.  Note that this
	 * assumes we don't act as both an AP and a station,
	 * otherwise we'll potentially flush state of stations
	 * associated with us.
	 */
	ieee80211_free_allnodes(isc);

	clrbit(isc->isc_chan_scan, ieee80211_chan2ieee(isc, in->in_chan));
	if (isc->isc_opmode != IEEE80211_M_HOSTAP) {
		isc->isc_flags |= IEEE80211_F_ASCAN;
		IEEE80211_SEND_MGMT(isc, in,
		    IEEE80211_FC0_SUBTYPE_PROBE_REQ, 0);
	}
}

static void
ieee80211_create_ibss(ieee80211com_t *isc, struct ieee80211channel *chan)
{
	struct ieee80211_node *in;

	in = isc->isc_bss;
	ATH_DEBUG((ATH_DBG_80211, "ath: "
	    "ieee80211_create_ibss(): creating ibss\n"));
	isc->isc_flags |= IEEE80211_F_SIBSS;
	in->in_chan = chan;
	in->in_rates = isc->isc_sup_rates[
	    ieee80211_chan2mode(isc, in->in_chan)];
	IEEE80211_ADDR_COPY(in->in_macaddr, isc->isc_macaddr);
	IEEE80211_ADDR_COPY(in->in_bssid, isc->isc_macaddr);

	if (isc->isc_opmode == IEEE80211_M_IBSS)
		in->in_bssid[0] |= 0x02;	/* local bit for IBSS */
	in->in_esslen = isc->isc_des_esslen;
	bcopy(isc->isc_des_essid, in->in_essid, in->in_esslen);
	ieee80211_reset_recvhist(in);
	bzero(in->in_tstamp, sizeof (in->in_tstamp));
	in->in_intval = isc->isc_lintval;
	in->in_capinfo = IEEE80211_CAPINFO_IBSS;
	if (isc->isc_flags & IEEE80211_F_WEPON)
		in->in_capinfo |= IEEE80211_CAPINFO_PRIVACY;
	if (isc->isc_phytype == IEEE80211_T_FH) {
		in->in_fhdwell = 200;
		in->in_fhindex = 1;
	}
	(void) _ieee80211_new_state(isc, IEEE80211_S_RUN, -1);
}


/*
 * The difference between _ieee80211_new_state() and ieee80211_new_state()
 * is the former asserts isc_genlock is already held.
 * _ieee80211_new_state() is called from Multi-func thread and GLD thread,
 * because ic_genlock is already owned at its entry in those 2 types of thread.
 * ieee80211_new_state() is just for software interrupt thread in LLD.
 *
 * Because of the reason to avoid recursive mutex entry, the caller can't hold
 * any other LLD mutexs before calling ieee80211_new_state().
 */
int
_ieee80211_new_state(ieee80211com_t *isc, enum ieee80211_state nstate,
    int32_t mgt)
{
	gld_mac_info_t *gld_p = isc->isc_dev;
	struct ieee80211_node *in;
	int error, ostate;

	ASSERT(mutex_owned(&isc->isc_genlock));

	ostate = isc->isc_state;
	if (isc->isc_new_state) {
		error = (*isc->isc_new_state)(isc, nstate);
		if (error == EINPROGRESS)
			return (0);
		if (error != 0)
			return (error);
	}

	isc->isc_state = nstate;
	in = isc->isc_bss;

	/* state transition */
	switch (nstate) {
	case IEEE80211_S_INIT:
		switch (ostate) {
		case IEEE80211_S_INIT:
			break;
		case IEEE80211_S_RUN:
			switch (isc->isc_opmode) {
			case IEEE80211_M_STA:
				IEEE80211_SEND_MGMT(isc, in,
				    IEEE80211_FC0_SUBTYPE_DISASSOC,
				    IEEE80211_REASON_ASSOC_LEAVE);
				break;
			default:
				break;
			}
		case IEEE80211_S_ASSOC:
			switch (isc->isc_opmode) {
			case IEEE80211_M_STA:
				IEEE80211_SEND_MGMT(isc, in,
				    IEEE80211_FC0_SUBTYPE_DEAUTH,
				    IEEE80211_REASON_AUTH_LEAVE);
				break;
			default:
				break;
			}
		case IEEE80211_S_AUTH:
		case IEEE80211_S_SCAN:
			break;
		}
		isc->isc_mgt_timeout = 0;
		isc->isc_inact_timeout = 0;
		break;
	case IEEE80211_S_SCAN:
		isc->isc_flags &= ~IEEE80211_F_SIBSS;
		/* initialize bss for probe request */
		IEEE80211_ADDR_COPY(in->in_macaddr, gld_p->gldm_broadcast_addr);
		IEEE80211_ADDR_COPY(in->in_bssid, gld_p->gldm_broadcast_addr);
		in->in_rates = isc->isc_sup_rates[
		    ieee80211_chan2mode(isc, in->in_chan)];
		in->in_associd = 0;
		ieee80211_reset_recvhist(in);
		switch (ostate) {
		case IEEE80211_S_INIT:
			if ((isc->isc_opmode == IEEE80211_M_HOSTAP ||
			    isc->isc_opmode == IEEE80211_M_IBSS) &&
			    isc->isc_des_chan != IEEE80211_CHAN_ANYC) {
				/*
				 * AP operation and we already have a channel;
				 * bypass the scan and startup immediately.
				 * Same applies to ad-hoc mode.
				 */
				ieee80211_create_ibss(isc, isc->isc_des_chan);
			} else {
				ieee80211_begin_scan(isc, in);
			}
			break;
		case IEEE80211_S_SCAN:
			/* scan next */
			if (isc->isc_flags & IEEE80211_F_ASCAN) {
				IEEE80211_SEND_MGMT(isc, in,
				    IEEE80211_FC0_SUBTYPE_PROBE_REQ, 0);
			}
			break;
		case IEEE80211_S_RUN:
			/* beacon miss */
			ATH_DEBUG((ATH_DBG_80211, "ath: "
			    "_ieee80211_new_state(): no recent beacons"
			    " from %s; rescanning\n",
			    ieee80211_ether_sprintf(isc->isc_bss->in_bssid)));
			ieee80211_free_allnodes(isc);
			break;
		case IEEE80211_S_AUTH:
		case IEEE80211_S_ASSOC:
			/* timeout, restart scan */
			in = ieee80211_find_node(isc, isc->isc_bss->in_macaddr);
			if (in != NULL) {
				in->in_fails++;
			}
			ieee80211_begin_scan(isc, isc->isc_bss);
			break;
		default:
			break;
		}
		break;
	case IEEE80211_S_AUTH:
		switch (ostate) {
		case IEEE80211_S_INIT:
			ATH_DEBUG((ATH_DBG_80211, "ath(): "
			    "_ieee80211_new_state(): invalid transition\n"));
			break;
		case IEEE80211_S_SCAN:
			IEEE80211_SEND_MGMT(isc, in,
			    IEEE80211_FC0_SUBTYPE_AUTH, 1);
			break;
		case IEEE80211_S_AUTH:
		case IEEE80211_S_ASSOC:
			switch (mgt) {
			case IEEE80211_FC0_SUBTYPE_AUTH:
				IEEE80211_SEND_MGMT(isc, in,
				    IEEE80211_FC0_SUBTYPE_AUTH, 2);
				break;
			case IEEE80211_FC0_SUBTYPE_DEAUTH:
				/* ignore and retry scan on timeout */
				break;
			}
			break;
		case IEEE80211_S_RUN:
			switch (mgt) {
			case IEEE80211_FC0_SUBTYPE_AUTH:
				IEEE80211_SEND_MGMT(isc, in,
				    IEEE80211_FC0_SUBTYPE_AUTH, 2);
				isc->isc_state = ostate;	/* stay RUN */
				break;
			case IEEE80211_FC0_SUBTYPE_DEAUTH:
				/* try to reauth */
				IEEE80211_SEND_MGMT(isc, in,
				    IEEE80211_FC0_SUBTYPE_AUTH, 1);
				break;
			}
			break;
		}
		break;
	case IEEE80211_S_ASSOC:
		switch (ostate) {
		case IEEE80211_S_INIT:
		case IEEE80211_S_SCAN:
		case IEEE80211_S_ASSOC:
			ATH_DEBUG((ATH_DBG_80211, "ath: "
			    "_ieee80211_new_state(): invalid transition\n"));
			break;
		case IEEE80211_S_AUTH:
			IEEE80211_SEND_MGMT(isc, in,
			    IEEE80211_FC0_SUBTYPE_ASSOC_REQ, 0);
			break;
		case IEEE80211_S_RUN:
			IEEE80211_SEND_MGMT(isc, in,
			    IEEE80211_FC0_SUBTYPE_ASSOC_REQ, 1);
			break;
		}
		break;
	case IEEE80211_S_RUN:
		switch (ostate) {
		case IEEE80211_S_INIT:
		case IEEE80211_S_AUTH:
		case IEEE80211_S_RUN:
			ATH_DEBUG((ATH_DBG_80211, "ath: "
			    "_ieee80211_new_state(): invalid transition\n"));
			break;
		case IEEE80211_S_SCAN:		/* adhoc/hostap mode */
		case IEEE80211_S_ASSOC:		/* infra mode */
			if (isc->isc_opmode == IEEE80211_M_STA)
				ATH_DEBUG((ATH_DBG_80211, "ath: "
				    "_ieee80211_new_state(): "
				    "associated with %s\n",
				    ieee80211_ether_sprintf(in->in_bssid)));
			else
				ATH_DEBUG((ATH_DBG_80211, "ath: "
				    "_ieee80211_new_state(): "
				    "asynchronized with %s\n",
				    ieee80211_ether_sprintf(in->in_bssid)));
			ATH_DEBUG((ATH_DBG_80211, "ath: "
			    "_ieee80211_new_state(): "
			    "essid %s, channel %d, start %uMb\n",
			    ieee80211_essid_sprintf(in->in_essid,
			    in->in_esslen),
			    ieee80211_chan2ieee(isc, in->in_chan),
			    IEEE80211_RATE2MBS(in->in_rates.ir_rates[
			    in->in_txrate])));
			isc->isc_mgt_timeout = 0;
			break;
		}
		break;
	}
	return (0);
}

int
ieee80211_new_state(ieee80211com_t *isc, enum ieee80211_state nstate,
    int32_t mgt)
{
	int result;

	mutex_enter(&isc->isc_genlock);
	result = _ieee80211_new_state(isc, nstate, mgt);
	mutex_exit(&isc->isc_genlock);

	return (result);
}

static void
ieee80211_timeout_nodes(ieee80211com_t *isc)
{
	struct ieee80211_node *in, *nextbs;

	for (in = list_head(&isc->isc_in_list); in != NULL; ) {
		if (++in->in_inact <= IEEE80211_INACT_MAX) {
			in = list_next(&isc->isc_in_list, in);
			continue;
		}
		ATH_DEBUG((ATH_DBG_80211, "ath: "
		    "station %s timed out due to inactivity"
		    " (%u secs)\n", ieee80211_ether_sprintf(in->in_macaddr),
		    in->in_inact));
		nextbs = list_next(&isc->isc_in_list, in);
		IEEE80211_SEND_MGMT(isc, in,
		    IEEE80211_FC0_SUBTYPE_DEAUTH,
		    IEEE80211_REASON_AUTH_EXPIRE);
		ieee80211_free_node(isc, in);
		in = nextbs;
	}
	if (!list_empty(&isc->isc_in_list))
		isc->isc_inact_timeout = IEEE80211_INACT_WAIT;
}

int
ieee80211_mgmt_output(ieee80211com_t *isc, struct ieee80211_node *in,
    mblk_t *mp, int type)
{
	struct ieee80211_frame *wh;

	ASSERT(mutex_owned(&isc->isc_genlock));
	ASSERT(in != NULL);

	in->in_inact = 0;
	mp->b_rptr -= sizeof (struct ieee80211_frame);
	wh = (struct ieee80211_frame *)mp->b_rptr;
	wh->ifrm_fc[0] = IEEE80211_FC0_VERSION_0 |
	    IEEE80211_FC0_TYPE_MGT | type;
	wh->ifrm_fc[1] = IEEE80211_FC1_DIR_NODS;
	*(uint16_t *)wh->ifrm_dur = 0;
	*(uint16_t *)wh->ifrm_seq =
	    LE_16(in->in_txseq << IEEE80211_SEQ_SEQ_SHIFT);
	in->in_txseq++;
	IEEE80211_ADDR_COPY(wh->ifrm_addr1, in->in_macaddr);
	IEEE80211_ADDR_COPY(wh->ifrm_addr2, isc->isc_macaddr);
	IEEE80211_ADDR_COPY(wh->ifrm_addr3, in->in_bssid);

	(void) (*isc->isc_mgmt_send)(isc, mp);
	return (0);
}

mblk_t *
ieee80211_fill_header(ieee80211com_t *isc, mblk_t *mp_gld,
	int32_t wep_txkey, struct ieee80211_node *in)
{
	struct ieee80211_frame *wh;
	struct ieee80211_llc *llc;
	struct ether_header *eh;
	mblk_t *mp_header;
	uint32_t iv;
	uint8_t *ivp;

	ASSERT(mutex_owned(&isc->isc_genlock));

	/*
	 * Alloc a new mblk struct for the whole IEEE80211 header.
	 */
	if ((mp_header = allocb(HEADERSPACE, BPRI_MED)) == NULL) {
		ath_problem("ath: ieee80211_encap(): can't alloc mblk!\n");
		return (NULL);
	}
	mp_header->b_wptr = mp_header->b_rptr +
		sizeof (struct ieee80211_frame);

	eh = (struct ether_header *)mp_gld->b_rptr;

	/*
	 * Fill 802.11 field.
	 */
	wh = (struct ieee80211_frame *)mp_header->b_rptr;
	wh->ifrm_fc[0] = IEEE80211_FC0_VERSION_0 | IEEE80211_FC0_TYPE_DATA;
	*(uint16_t *)wh->ifrm_dur = 0;
	*(uint16_t *)wh->ifrm_seq =
	    LE_16(in->in_txseq << IEEE80211_SEQ_SEQ_SHIFT);
	in->in_txseq++;
	switch (isc->isc_opmode) {
	case IEEE80211_M_STA:
		wh->ifrm_fc[1] = IEEE80211_FC1_DIR_TODS;
		IEEE80211_ADDR_COPY(wh->ifrm_addr1, in->in_bssid);
		IEEE80211_ADDR_COPY(wh->ifrm_addr2,
		    eh->ether_shost.ether_addr_octet);
		IEEE80211_ADDR_COPY(wh->ifrm_addr3,
		    eh->ether_dhost.ether_addr_octet);
		break;
	case IEEE80211_M_IBSS:
	case IEEE80211_M_AHDEMO:
		wh->ifrm_fc[1] = IEEE80211_FC1_DIR_NODS;
		IEEE80211_ADDR_COPY(wh->ifrm_addr1,
		    eh->ether_dhost.ether_addr_octet);
		IEEE80211_ADDR_COPY(wh->ifrm_addr2,
		    eh->ether_shost.ether_addr_octet);
		IEEE80211_ADDR_COPY(wh->ifrm_addr3, in->in_bssid);
		break;
	case IEEE80211_M_HOSTAP:
		wh->ifrm_fc[1] = IEEE80211_FC1_DIR_FROMDS;
		IEEE80211_ADDR_COPY(wh->ifrm_addr1,
		    eh->ether_dhost.ether_addr_octet);
		IEEE80211_ADDR_COPY(wh->ifrm_addr2, in->in_bssid);
		IEEE80211_ADDR_COPY(wh->ifrm_addr3,
		    eh->ether_shost.ether_addr_octet);
		break;
	}

	if (isc->isc_flags & IEEE80211_F_WEPON) {
		wh->ifrm_fc[1] |= IEEE80211_FC1_WEP;
		ivp = mp_header->b_rptr + sizeof (struct ieee80211_frame);
		/*
		 * IV must not duplicate during the lifetime of the key.
		 * But no mechanism to renew keys is defined in IEEE 802.11
		 * WEP.  And IV may be duplicated between other stations
		 * because of the session key itself is shared.
		 * So we use pseudo random IV for now, though it is not the
		 * right way.
		 */
		iv = isc->isc_iv;
		/*
		 * Skip 'bad' IVs from Fluhrer/Mantin/Shamir:
		 * (B, 255, N) with 3 <= B < 8
		 */
		if ((iv & 0xff00) == 0xff00) {
			int B = (iv & 0xff0000) >> 16;
			if (3 <= B && B < 16)
				iv = (B+1) << 16;
		}
		isc->isc_iv = iv + 1;

#ifdef ATH_HOST_BIG_ENDIAN
		ivp[0] = iv >> 0;
		ivp[1] = iv >> 8;
		ivp[2] = iv >> 16;
#else
		ivp[2] = iv >> 0;
		ivp[1] = iv >> 8;
		ivp[0] = iv >> 16;
#endif /* ATH_HOST_BIG_ENDIAN */

		/* Key ID and pad */
		ivp[IEEE80211_WEP_IVLEN] = wep_txkey << 6;
		/*
		 * The ICV length must be included into hdrlen and pktlen.
		 */
		mp_header->b_wptr +=
			IEEE80211_WEP_IVLEN + IEEE80211_WEP_KIDLEN;
	}

	/*
	 * CRC are added by H/W, not encaped by driver,
	 * but we must count it in pkt length.
	 */

	/*
	 * fill LLC and SNAP fields.
	 */
	llc = (struct ieee80211_llc *)mp_header->b_wptr;
	llc->illc_dsap = LLC_DSAP;
	llc->illc_ssap = LLC_SSAP;
	llc->illc_control = LLC_CONTROL;
	llc->illc_oc[0] = SNAP_OC0;
	llc->illc_oc[1] = SNAP_OC1;
	llc->illc_oc[2] = SNAP_OC2;
	llc->illc_ether_type = eh->ether_type;
	mp_header->b_wptr += sizeof (struct ieee80211_llc);

	return (mp_header);
}

mblk_t *
ieee80211_decap(mblk_t *mp)
{
	struct ether_header *eh;
	struct ieee80211_frame wh;
	struct ieee80211_llc *llc;

	if ((mp->b_wptr - mp->b_rptr) < (sizeof (wh) + sizeof (*llc))) {
		freemsg(mp);
		return (NULL);
	}

	bcopy(mp->b_rptr, &wh, sizeof (struct ieee80211_frame));
	mp->b_rptr += sizeof (struct ieee80211_frame);
	llc = (struct ieee80211_llc *)mp->b_rptr;

	if (llc->illc_dsap == LLC_DSAP && llc->illc_ssap == LLC_SSAP &&
	    llc->illc_control == LLC_CONTROL && llc->illc_oc[0] == SNAP_OC0 &&
	    llc->illc_oc[1] == SNAP_OC1 && llc->illc_oc[2] == SNAP_OC2) {
		mp->b_rptr += sizeof (struct ieee80211_llc);
		llc = NULL;
	}
	/*
	 * we are sure that the size of ieee80211_frame plus llc is
	 * larger than the size of ether_header,
	 * so there has enough space to encap ether_header in this mblk.
	 */
	mp->b_rptr -= sizeof (struct ether_header);
	eh = (struct ether_header *)mp->b_rptr;
	switch (wh.ifrm_fc[1] & IEEE80211_FC1_DIR_MASK) {
	case IEEE80211_FC1_DIR_NODS:
		IEEE80211_ADDR_COPY(eh->ether_dhost.ether_addr_octet,
		    wh.ifrm_addr1);
		IEEE80211_ADDR_COPY(eh->ether_shost.ether_addr_octet,
		    wh.ifrm_addr2);
		break;
	case IEEE80211_FC1_DIR_TODS:
		IEEE80211_ADDR_COPY(eh->ether_dhost.ether_addr_octet,
		    wh.ifrm_addr3);
		IEEE80211_ADDR_COPY(eh->ether_shost.ether_addr_octet,
		    wh.ifrm_addr2);
		break;
	case IEEE80211_FC1_DIR_FROMDS:
		IEEE80211_ADDR_COPY(eh->ether_dhost.ether_addr_octet,
		    wh.ifrm_addr1);
		IEEE80211_ADDR_COPY(eh->ether_shost.ether_addr_octet,
		    wh.ifrm_addr3);
		break;
	case IEEE80211_FC1_DIR_DSTODS:
		/* not yet supported */
		ATH_DEBUG((ATH_DBG_80211, "ath: "
		    "ieee80211_decap(): DS to DS\n"));
		freemsg(mp);
		return (NULL);
	}

	if (llc != NULL)
		eh->ether_type = htons(mp->b_wptr - mp->b_rptr - sizeof (*eh));

	return (mp);
}

/*
 * This function doesn't need mutex protection.
 */
void
ieee80211_dump_pkt(uint8_t *buf, int32_t len, int32_t rate, int32_t rssi)
{
	struct ieee80211_frame *wh;
	int32_t i;
	int8_t buf1[100], buf2[25];

	bzero(buf1, sizeof (buf1));
	bzero(buf2, sizeof (buf2));
	wh = (struct ieee80211_frame *)buf;
	switch (wh->ifrm_fc[1] & IEEE80211_FC1_DIR_MASK) {
	case IEEE80211_FC1_DIR_NODS:
		(void) sprintf(buf2, "NODS %s",
		    ieee80211_ether_sprintf(wh->ifrm_addr2));
		(void) strcat(buf1, buf2);
		(void) sprintf(buf2, "->%s",
		    ieee80211_ether_sprintf(wh->ifrm_addr1));
		(void) strcat(buf1, buf2);
		(void) sprintf(buf2, "(%s)",
		    ieee80211_ether_sprintf(wh->ifrm_addr3));
		(void) strcat(buf1, buf2);
		break;
	case IEEE80211_FC1_DIR_TODS:
		(void) sprintf(buf2, "TODS %s",
		    ieee80211_ether_sprintf(wh->ifrm_addr2));
		(void) strcat(buf1, buf2);
		(void) sprintf(buf2, "->%s",
		    ieee80211_ether_sprintf(wh->ifrm_addr3));
		(void) strcat(buf1, buf2);
		(void) sprintf(buf2, "(%s)",
		    ieee80211_ether_sprintf(wh->ifrm_addr1));
		(void) strcat(buf1, buf2);
		break;
	case IEEE80211_FC1_DIR_FROMDS:
		(void) sprintf(buf2, "FRDS %s",
		    ieee80211_ether_sprintf(wh->ifrm_addr3));
		(void) strcat(buf1, buf2);
		(void) sprintf(buf2, "->%s",
		    ieee80211_ether_sprintf(wh->ifrm_addr1));
		(void) strcat(buf1, buf2);
		(void) sprintf(buf2, "(%s)",
		    ieee80211_ether_sprintf(wh->ifrm_addr2));
		(void) strcat(buf1, buf2);
		break;
	case IEEE80211_FC1_DIR_DSTODS:
		(void) sprintf(buf2, "DSDS %s",
		    ieee80211_ether_sprintf((uint8_t *)&wh[1]));
		(void) strcat(buf1, buf2);
		(void) sprintf(buf2, "->%s  ",
		    ieee80211_ether_sprintf(wh->ifrm_addr3));
		(void) strcat(buf1, buf2);
		(void) sprintf(buf2, "%s",
		    ieee80211_ether_sprintf(wh->ifrm_addr2));
		(void) strcat(buf1, buf2);
		(void) sprintf(buf2, "->%s",
		    ieee80211_ether_sprintf(wh->ifrm_addr1));
		(void) strcat(buf1, buf2);
		break;
	}
	ATH_DEBUG((ATH_DBG_80211, "ath: ieee80211_dump_pkt(): %s", buf1));
	bzero(buf1, sizeof (buf1));

	switch (wh->ifrm_fc[0] & IEEE80211_FC0_TYPE_MASK) {
	case IEEE80211_FC0_TYPE_DATA:
		(void) sprintf(buf2, "data");
		break;
	case IEEE80211_FC0_TYPE_MGT:
		(void) sprintf(buf2, "%s",
		    ieee80211_mgt_subtype_name[
		    (wh->ifrm_fc[0] & IEEE80211_FC0_SUBTYPE_MASK)
		    >> IEEE80211_FC0_SUBTYPE_SHIFT]);
		break;
	default:
		(void) sprintf(buf2, "type#%d",
		    wh->ifrm_fc[0] & IEEE80211_FC0_TYPE_MASK);
		break;
	}
	(void) strcat(buf1, buf2);
	if (wh->ifrm_fc[1] & IEEE80211_FC1_WEP) {
		(void) sprintf(buf2, " WEP");
		(void) strcat(buf1, buf2);
	}
	if (rate >= 0) {
		(void) sprintf(buf2, " %dM", rate / 2);
		(void) strcat(buf1, buf2);
	}
	if (rssi >= 0) {
		(void) sprintf(buf2, " +%d", rssi);
		(void) strcat(buf1, buf2);
	}
	ATH_DEBUG((ATH_DBG_80211, "ath: ieee80211_dump_pkt(): %s", buf1));
	bzero(buf1, sizeof (buf1));

	if (len > 0) {
		for (i = 0; i < (len > 40 ? 40 : len); i++) {
			if ((i & 0x03) == 0)
				(void) strcat(buf1, " ");
			(void) sprintf(buf2, "%02x", buf[i]);
			(void) strcat(buf1, buf2);
		}
		ATH_DEBUG((ATH_DBG_80211, "ath: ieee80211_dump_pkt(): %s",
		    buf1));
	}
}

/*
 * Mark the basic rates for the 11g rate table based on the
 * operating mode.  For real 11g we mark all the 11b rates
 * and 6, 12, and 24 OFDM.  For 11b compatibility we mark only
 * 11b rates.  There's also a pseudo 11a-mode used to mark only
 * the basic OFDM rates.
 */
static void
ieee80211_set11gbasicrates(struct ieee80211_rateset *rs,
    enum ieee80211_phymode mode)
{
	static const struct ieee80211_rateset basic[] = {
	    { 3, { 12, 24, 48 } },		/* IEEE80211_MODE_11A */
	    { 4, { 2, 4, 11, 22 } },		/* IEEE80211_MODE_11B */
	    { 7, { 2, 4, 11, 22, 12, 24, 48 } },	/* IEEE80211_MODE_11G */
	    { 0 },				/* IEEE80211_MODE_TURBO	*/
	};
	int32_t i, j;

	for (i = 0; i < rs->ir_nrates; i++) {
		rs->ir_rates[i] &= IEEE80211_RATE_VAL;
		for (j = 0; j < basic[mode].ir_nrates; j++)
			if (basic[mode].ir_rates[j] == rs->ir_rates[i]) {
				rs->ir_rates[i] |= IEEE80211_RATE_BASIC;
				break;
			}
	}
}

/*
 * Set the current phy mode and recalculate the active channel
 * set based on the available channels for this mode.  Also
 * select a new default/current channel if the current one is
 * inappropriate for this mode.
 */
static int
ieee80211_setmode(ieee80211com_t *isc, enum ieee80211_phymode mode)
{
	static const uint32_t chanflags[] = {
		0,			/* IEEE80211_MODE_AUTO */
		IEEE80211_CHAN_A,	/* IEEE80211_MODE_11A */
		IEEE80211_CHAN_B,	/* IEEE80211_MODE_11B */
		IEEE80211_CHAN_PUREG,	/* IEEE80211_MODE_11G */
		IEEE80211_CHAN_T,	/* IEEE80211_MODE_TURBO	*/
	};
	struct ieee80211channel *ch;
	uint32_t modeflags;
	int32_t i;

	/* validate new mode */
	if ((isc->isc_modecaps & (1 << mode)) == 0) {
		ath_problem("ath: ieee80211_setmode(): mode %u not supported"
		    " (caps 0x%x)\n", mode, isc->isc_modecaps);
		return (EINVAL);
	}

	/*
	 * Verify at least one channel is present in the available
	 * channel list before committing to the new mode.
	 */
	ASSERT(mode < ATH_N(chanflags));

	modeflags = chanflags[mode];
	/* isc_channels size is IEEE80211_CHAN_MAX + 1, so no problem */
	for (i = 0; i <= IEEE80211_CHAN_MAX; i++) {
		ch = &isc->isc_channels[i];
		if (mode == IEEE80211_MODE_AUTO) {
			/* ignore turbo channels for autoselect */
			if ((ch->ich_flags & ~IEEE80211_CHAN_TURBO) != 0)
				break;
		} else {
			if ((ch->ich_flags & modeflags) == modeflags)
				break;
		}
	}
	if (i > IEEE80211_CHAN_MAX) {
		ath_problem("ath: ieee80211_setmode(): "
		    "no channel found for mode %u\n", mode);
		return (EINVAL);
	}

	/*
	 * Calculate the active channel set.
	 */
	bzero(isc->isc_chan_active, sizeof (isc->isc_chan_active));
	for (i = 0; i <= IEEE80211_CHAN_MAX; i++) {
		ch = &isc->isc_channels[i];
		if (mode == IEEE80211_MODE_AUTO) {
			/* take anything but pure turbo channels */
			if ((ch->ich_flags & ~IEEE80211_CHAN_TURBO) != 0)
				setbit(isc->isc_chan_active, i);
		} else {
			if ((ch->ich_flags & modeflags) == modeflags)
				setbit(isc->isc_chan_active, i);
		}
	}
	/*
	 * If no current/default channel is setup or the current
	 * channel is wrong for the mode then pick the first
	 * available channel from the active list.  This is likely
	 * not the right one.
	 */
	if (isc->isc_ibss_chan == NULL ||
	    isclr(isc->isc_chan_active,
	    ieee80211_chan2ieee(isc, isc->isc_ibss_chan))) {
		for (i = 0; i <= IEEE80211_CHAN_MAX; i++)
			if (isset(isc->isc_chan_active, i)) {
				isc->isc_ibss_chan = &isc->isc_channels[i];
				break;
			}
	}

	/*
	 * Set/reset state flags that influence beacon contents, etc.
	 */

	if (isc->isc_caps & IEEE80211_C_SHPREAMBLE)
		isc->isc_flags |= IEEE80211_F_SHPREAMBLE;
	if (mode == IEEE80211_MODE_11G) {
		if (isc->isc_caps & IEEE80211_C_SHSLOT)
			isc->isc_flags |= IEEE80211_F_SHSLOT;
		ieee80211_set11gbasicrates(&isc->isc_sup_rates[mode],
		    IEEE80211_MODE_11G);
	} else {
		isc->isc_flags &= ~(IEEE80211_F_SHSLOT);
	}

	/*
	 * Setup an initial rate set according to the
	 * current/default channel.  This will be changed
	 * when scanning but must exist now so drivers have
	 * consistent state of ic_ibss_chan.
	 */
	if (isc->isc_bss)
		isc->isc_bss->in_rates = isc->isc_sup_rates[mode];
	isc->isc_curmode = mode;

	return (0);
}

/*
 * If (its return value & IEEE80211_RATE_BASIC != 0),
 * the rate negotiation or fix rate is failed.
 */
static int
ieee80211_fix_rate(ieee80211com_t *isc,
    struct ieee80211_node *in, int32_t flags)
{
	int32_t i, j, ignore, error;
	int32_t okrate, badrate;
	struct ieee80211_rateset *srs, *nrs;
	uint8_t r;

	error = 0;
	okrate = badrate = 0;
	srs = &isc->isc_sup_rates[ieee80211_chan2mode(isc, in->in_chan)];
	nrs = &in->in_rates;
	for (i = 0; i < in->in_rates.ir_nrates; ) {
		ignore = 0;
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
		r = nrs->ir_rates[i] & IEEE80211_RATE_VAL;
		badrate = r;
		if (flags & IEEE80211_F_DOFRATE) {
			/*
			 * Apply fixed rate constraint.  Note that we do
			 * not apply the constraint to basic rates as
			 * otherwise we may not be able to associate if
			 * the rate set we submit to the AP is invalid
			 * (e.g. fix rate at 36Mb/s which is not a basic
			 * rate for 11a operation).
			 */
			if ((nrs->ir_rates[i] & IEEE80211_RATE_BASIC) == 0 &&
			    isc->isc_fixed_rate >= 0 &&
			    r != IEEE80211_RV(srs->ir_rates
			    [isc->isc_fixed_rate]))
				ignore++;
		}
		if (flags & IEEE80211_F_DONEGO) {
			/*
			 * Check against supported rates.
			 */
			for (j = 0; j < srs->ir_nrates; j++) {
				if (r == IEEE80211_RV(srs->ir_rates[j]))
					break;
			}
			if (j == srs->ir_nrates) {
				if (nrs->ir_rates[i] & IEEE80211_RATE_BASIC)
					error++;
				ignore++;
			}
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
		if (!ignore)
			okrate = nrs->ir_rates[i];
		i++;
	}
	if (okrate == 0 || error != 0)
		return (badrate | IEEE80211_RATE_BASIC);
	else
		return (IEEE80211_RV(okrate));
}

/*
 * Complete a scan of potential channels.
 */
static void
ieee80211_end_scan(ieee80211com_t *isc)
{
	struct ieee80211_node *in, *selbs;
	uint8_t rate;
	int32_t fail;

	ASSERT(isc->isc_state == IEEE80211_S_SCAN);
	ASSERT(mutex_owned(&isc->isc_genlock));

	isc->isc_flags &= ~IEEE80211_F_ASCAN;
	cv_broadcast(&isc->isc_scan_cv);
	in = list_head(&isc->isc_in_list);

	if (in == NULL) {
		ATH_DEBUG((ATH_DBG_80211, "ath: ieee80211_end_scan(): "
		    "no scan candidate\n"));
notfound:
		if (isc->isc_opmode == IEEE80211_M_IBSS &&
		    (isc->isc_flags & IEEE80211_F_IBSSON) &&
		    isc->isc_des_esslen != 0) {
			ieee80211_create_ibss(isc, isc->isc_ibss_chan);
			return;
		}
		mutex_exit(&isc->isc_genlock);
		delay(drv_usectohz(200000));
		mutex_enter(&isc->isc_genlock);
		ieee80211_begin_scan(isc, isc->isc_bss);
		return;
	}

	selbs = NULL;
	for (; in != NULL; in = list_next(&isc->isc_in_list, in)) {
		ATH_DEBUG((ATH_DBG_80211, "ath: "
		    "ieee80211_end_scan(): isc_bss->in_bssid=%s",
		    ieee80211_ether_sprintf(in->in_bssid)));
		if (in->in_fails) {
			/*
			 * The configuration of the access points may change
			 * during my scan.  So delete the entry for the AP
			 * and retry to associate if there is another beacon.
			 */
			if (in->in_fails++ > 2)
				ieee80211_free_node(isc, in);
			continue;
		}
		fail = 0;
		if (in->in_chan == NULL || in->in_chan->ich_flags == 0)
			fail |= 0x01;
		if (isc->isc_des_chan !=
		    (struct ieee80211channel *)IEEE80211_CHAN_ANY &&
		    in->in_chan != isc->isc_des_chan)
			fail |= 0x01;
		if (isc->isc_opmode == IEEE80211_M_IBSS) {
			if ((in->in_capinfo & IEEE80211_CAPINFO_IBSS) == 0)
				fail |= 0x02;
		} else {
			if ((in->in_capinfo & IEEE80211_CAPINFO_ESS) == 0)
				fail |= 0x02;
		}

		if (isc->isc_flags & IEEE80211_F_WEPON) {
			if ((in->in_capinfo & IEEE80211_CAPINFO_PRIVACY) == 0)
				fail |= 0x04;
		} else {
			if (in->in_capinfo & IEEE80211_CAPINFO_PRIVACY)
				fail |= 0x04;
		}

		rate = ieee80211_fix_rate(isc, in, IEEE80211_F_DONEGO);
		if (rate & IEEE80211_RATE_BASIC)
			fail |= 0x08;
		if (isc->isc_des_esslen != 0 &&
		    (in->in_esslen != isc->isc_des_esslen ||
		    bcmp(in->in_essid, isc->isc_des_essid,
		    isc->isc_des_esslen) != 0))
			fail |= 0x10;
		if ((isc->isc_flags & IEEE80211_F_DESBSSID) &&
		    !IEEE80211_ADDR_EQ(isc->isc_des_bssid, in->in_bssid))
			fail |= 0x20;
		if (!fail) {
			if (selbs == NULL)
				selbs = in;
			else if (ieee80211_get_rssi(in) >
			    ieee80211_get_rssi(selbs))
				selbs = in;
		}
	}
	if (selbs == NULL)
		goto notfound;
	bcopy(selbs, isc->isc_bss, sizeof (struct ieee80211_node));
	if (isc->isc_opmode == IEEE80211_M_IBSS) {
		(void) ieee80211_fix_rate(isc, isc->isc_bss,
		    IEEE80211_F_DOFRATE | IEEE80211_F_DONEGO |
		    IEEE80211_F_DODEL);
		if (isc->isc_bss->in_rates.ir_nrates == 0) {
			selbs->in_fails++;
			goto notfound;
		}
		(void) _ieee80211_new_state(isc, IEEE80211_S_RUN, -1);
	} else
		(void) _ieee80211_new_state(isc, IEEE80211_S_AUTH, -1);
}


/*
 * Switch to the next channel marked for scanning.
 * This one is only called by multi-func thread.
 */
static void
ieee80211_next_scan(ieee80211com_t *isc)
{
	struct ieee80211channel *chan;

	ASSERT(isc->isc_state == IEEE80211_S_SCAN);
	ASSERT(mutex_owned(&isc->isc_genlock));

	chan = isc->isc_bss->in_chan;
	for (;;) {
		if (++chan > &isc->isc_channels[IEEE80211_CHAN_MAX])
			chan = &isc->isc_channels[0];
		if (isset(isc->isc_chan_scan, ieee80211_chan2ieee(isc, chan))) {
			/*
			 * Honor channels marked passive-only
			 * during an active scan.
			 */
			if ((isc->isc_flags & IEEE80211_F_ASCAN) == 0 ||
			    (chan->ich_flags & IEEE80211_CHAN_PASSIVE) == 0)
				break;
		}
		if (chan == isc->isc_bss->in_chan) {
			ieee80211_end_scan(isc);
			return;
		}
	}
	clrbit(isc->isc_chan_scan, ieee80211_chan2ieee(isc, chan));

	isc->isc_bss->in_chan = chan;
	(void) _ieee80211_new_state(isc, IEEE80211_S_SCAN, -1);
}


static void
ieee80211_setup_node(ieee80211com_t *isc,
	struct ieee80211_node *in, uint8_t *macaddr)
{
	int32_t hash;

	ASSERT(mutex_owned(&isc->isc_genlock));

	IEEE80211_ADDR_COPY(in->in_macaddr, macaddr);
	hash = IEEE80211_NODE_HASH(macaddr);
	list_insert_tail(&isc->isc_in_list, in);
	list_insert_tail(&isc->isc_inhash_list[hash], in);
	/*
	 * Note we don't enable the inactive timer when acting
	 * as a station.  Nodes created in this mode represent
	 * AP's identified while scanning.  If we time them out
	 * then several things happen: we can't return the data
	 * to users to show the list of AP's we encountered, and
	 * more importantly, we'll incorrectly deauthenticate
	 * ourself because the inactivity timer will kick us off.
	 */
	if (isc->isc_opmode != IEEE80211_M_STA)
		isc->isc_inact_timeout = IEEE80211_INACT_WAIT;
}

static struct ieee80211_node *
ieee80211_alloc_node(ieee80211com_t *isc, uint8_t *macaddr)
{
	struct ieee80211_node *in = (*isc->isc_node_alloc)(isc);
	bzero(in, sizeof (struct ieee80211_node));
	ieee80211_setup_node(isc, in, macaddr);
	return (in);
}

static struct ieee80211_node *
ieee80211_dup_bss(ieee80211com_t *isc, uint8_t *macaddr)
{
	struct ieee80211_node *in;

	in = kmem_zalloc(sizeof (struct ieee80211_node), KM_SLEEP);
	ieee80211_setup_node(isc, in, macaddr);
	return (in);
}

/*
 * Find a node state block given the mac address.  Note that
 * this returns the first node found with the mac address.
 */
struct ieee80211_node *
ieee80211_find_node(ieee80211com_t *isc, uint8_t *macaddr)
{
	struct ieee80211_node *in;
	int32_t hash;

	hash = IEEE80211_NODE_HASH(macaddr);
	in = list_head(&isc->isc_inhash_list[hash]);
	while (in != NULL) {
		if (IEEE80211_ADDR_EQ(in->in_macaddr, macaddr))
			break;
		in = list_next(&isc->isc_inhash_list[hash], in);
	}
	return (in);
}

/*
 * Like find but search based on the channel too.
 */
struct ieee80211_node *
ieee80211_lookup_node(ieee80211com_t *isc, uint8_t *macaddr,
    struct ieee80211channel *chan)
{
	struct ieee80211_node *in;
	int32_t hash;

	hash = IEEE80211_NODE_HASH(macaddr);
	in = list_head(&isc->isc_inhash_list[hash]);
	while (in != NULL) {
		if (IEEE80211_ADDR_EQ(in->in_macaddr, macaddr) &&
		    (in->in_chan == chan))
			break;
		in = list_next(&isc->isc_inhash_list[hash], in);
	}
	return (in);
}



/*
 * Install received rate set information in the node's state block.
 * If (its return value & IEEE80211_RATE_BASIC != 0),
 * the rate negotiation or fix rate is failed.
 */
static int32_t
ieee80211_setup_rates(ieee80211com_t *isc, struct ieee80211_node *in,
	uint8_t *rates, uint8_t *xrates, int32_t flags)
{
	struct ieee80211_rateset *rs = &in->in_rates;

	bzero(rs, sizeof (*rs));
	rs->ir_nrates = rates[1];
	bcopy(rates + 2, rs->ir_rates, rs->ir_nrates);
	if (xrates != NULL) {
		uint8_t nxrates;
		/*
		 * Tack on 11g extended supported rate element.
		 */
		nxrates = xrates[1];
		if (rs->ir_nrates + nxrates > IEEE80211_RATE_MAXSIZE) {
			nxrates = IEEE80211_RATE_MAXSIZE - rs->ir_nrates;
			ATH_DEBUG((ATH_DBG_80211, "ath: "
			    "ieee80211_setup_rates(): extended rate set"
			    " too large; only using %u of %u rates\n",
			    nxrates, xrates[1]));
		}
		bcopy(xrates + 2, rs->ir_rates + rs->ir_nrates, nxrates);
		rs->ir_nrates += nxrates;
	}
	return (ieee80211_fix_rate(isc, in, flags));
}


/*
 * Misc management frame encapsulation functions.
 */
static uint8_t *
ieee80211_add_rates(uint8_t *frm, const struct ieee80211_rateset *rs)
{
	int32_t nrates;

	*frm++ = IEEE80211_ELEMID_RATES;
	nrates = rs->ir_nrates;
	if (nrates > IEEE80211_RATE_SIZE)
		nrates = IEEE80211_RATE_SIZE;
	*frm++ = nrates;
	bcopy(rs->ir_rates, frm, nrates);
	return (frm + nrates);
}

static uint8_t *
ieee80211_add_xrates(uint8_t *frm, const struct ieee80211_rateset *rs)
{
	/*
	 * Add an extended supported rates element if operating in 11g mode.
	 */
	if (rs->ir_nrates > IEEE80211_RATE_SIZE) {
		int32_t nrates = rs->ir_nrates - IEEE80211_RATE_SIZE;
		*frm++ = IEEE80211_ELEMID_XRATES;
		*frm++ = nrates;
		bcopy(rs->ir_rates + IEEE80211_RATE_SIZE, frm, nrates);
		frm += nrates;
	}
	return (frm);
}

static uint8_t *
ieee80211_add_ssid(uint8_t *frm, const uint8_t *ssid, uint32_t len)
{
	*frm++ = IEEE80211_ELEMID_SSID;
	*frm++ = len;
	bcopy(ssid, frm, len);
	return (frm + len);
}

/*
 * Following functions are responsible for management frame encapsulation.
 */
static int32_t
ieee80211_send_prreq(ieee80211com_t *isc, struct ieee80211_node *in,
    int32_t type, int32_t dummy)
{
	int32_t ret, pktlen;
	mblk_t *mp;
	uint8_t *frm;
	enum ieee80211_phymode mode;

	_NOTE(ARGUNUSED(dummy));

	ASSERT(mutex_owned(&isc->isc_genlock));
	/*
	 * prreq frame format
	 *	[tlv] ssid
	 *	[tlv] supported rates
	 *	[tlv] extended supported rates
	 */
	pktlen = sizeof (struct ieee80211_frame) +
	    2 + isc->isc_des_esslen +
	    2 + IEEE80211_RATE_SIZE +
	    2 + (IEEE80211_RATE_MAXSIZE - IEEE80211_RATE_SIZE);
	mp = allocb(pktlen, BPRI_MED);
	if (mp == NULL) {
		ath_problem("ath: ieee80211_send_prreq(): no space\n");
		return (ENOMEM);
	}
	mp->b_rptr += sizeof (struct ieee80211_frame);

	frm = mp->b_rptr;
	frm = ieee80211_add_ssid(frm, isc->isc_des_essid, isc->isc_des_esslen);
	mode = ieee80211_chan2mode(isc, in->in_chan);
	frm = ieee80211_add_rates(frm, &isc->isc_sup_rates[mode]);
	frm = ieee80211_add_xrates(frm, &isc->isc_sup_rates[mode]);
	mp->b_wptr = frm;

	ret = ieee80211_mgmt_output(isc, in, mp, type);
	isc->isc_mgt_timeout = IEEE80211_TRANS_WAIT;

	ATH_DEBUG((ATH_DBG_80211, "ath: ieee80211_send_prreq() "
	    "channel=%u\n", ieee80211_chan2ieee(isc, in->in_chan)));

	return (ret);
}

static int32_t
ieee80211_send_prresp(ieee80211com_t *isc, struct ieee80211_node *bs0,
    int32_t type, int32_t dummy)
{
	mblk_t *mp;
	uint8_t *frm;
	struct ieee80211_node *in = isc->isc_bss;
	uint16_t capinfo;
	int32_t pktlen;

	_NOTE(ARGUNUSED(dummy));

	ASSERT(mutex_owned(&isc->isc_genlock));
	/*
	 * probe response frame format
	 *	[8] time stamp
	 *	[2] beacon interval
	 *	[2] cabability information
	 *	[tlv] ssid
	 *	[tlv] supported rates
	 *	[tlv] parameter set (IBSS)
	 *	[tlv] extended supported rates
	 */
	pktlen = sizeof (struct ieee80211_frame) +
	    8 + 2 + 2 + 2 +
	    2 + in->in_esslen +
	    2 + IEEE80211_RATE_SIZE +
	    6 +
	    2 + (IEEE80211_RATE_MAXSIZE - IEEE80211_RATE_SIZE);
	mp = allocb(pktlen, BPRI_MED);
	if (mp == NULL) {
		ath_problem("ath: ieee80211_send_prresp(): alloc failed.\n");
		return (ENOMEM);
	}
	mp->b_rptr += sizeof (struct ieee80211_frame);
	frm = mp->b_rptr;

	bzero(frm, 8);	/* timestamp */
	frm += 8;

	*(uint16_t *)frm = LE_16(in->in_intval);
	frm += 2;

	if (isc->isc_opmode == IEEE80211_M_IBSS)
		capinfo = IEEE80211_CAPINFO_IBSS;
	else
		capinfo = IEEE80211_CAPINFO_ESS;
	if (isc->isc_flags & IEEE80211_F_WEPON)
		capinfo |= IEEE80211_CAPINFO_PRIVACY;
	*(uint16_t *)frm = LE_16(capinfo);
	frm += 2;

	frm = ieee80211_add_ssid(frm, in->in_essid, in->in_esslen);
	frm = ieee80211_add_rates(frm, &in->in_rates);

	if (isc->isc_opmode == IEEE80211_M_IBSS) {
		*frm++ = IEEE80211_ELEMID_IBSSPARMS;
		*frm++ = 2;
		*frm++ = 0; *frm++ = 0;		/* ATIM window */
	} else {	/* IEEE80211_M_HOSTAP */
		/* TIM */
		*frm++ = IEEE80211_ELEMID_TIM;
		*frm++ = 4;	/* length */
		*frm++ = 0;	/* DTIM count */
		*frm++ = 1;	/* DTIM period */
		*frm++ = 0;	/* bitmap control */
		*frm++ = 0;	/* Partial Virtual Bitmap (variable length) */
	}
	frm = ieee80211_add_xrates(frm, &in->in_rates);
	mp->b_wptr = frm;

	return (ieee80211_mgmt_output(isc, bs0, mp, type));
}

static int32_t
ieee80211_send_auth(ieee80211com_t *isc, struct ieee80211_node *in,
    int32_t type, int32_t seq)
{
	mblk_t *mp;
	uint16_t *frm;
	int32_t ret, pktlen;

	ASSERT(mutex_owned(&isc->isc_genlock));

	pktlen = sizeof (struct ieee80211_frame) + 3 * sizeof (uint16_t);
	mp = allocb(pktlen, BPRI_MED);
	if (mp == NULL) {
		ath_problem("ath: ieee80211_send_auth(): allocb failed\n");
		return (ENOMEM);
	}
	mp->b_wptr = mp->b_rptr + pktlen;
	mp->b_rptr += sizeof (struct ieee80211_frame);

	frm = (uint16_t *)mp->b_rptr;
	/* shared key auth */
	frm[0] = LE_16(IEEE80211_AUTH_ALG_OPEN);
	frm[1] = LE_16(seq);
	frm[2] = 0;	/* status */
	ret = ieee80211_mgmt_output(isc, in, mp, type);
	if (isc->isc_opmode == IEEE80211_M_STA)
		isc->isc_mgt_timeout = IEEE80211_TRANS_WAIT;
	return (ret);
}

static int32_t
ieee80211_send_deauth(ieee80211com_t *isc, struct ieee80211_node *in,
    int32_t type, int32_t reason)
{
	mblk_t *mp;
	uint16_t *frm;
	int32_t pktlen;

	ASSERT(mutex_owned(&isc->isc_genlock));
	ATH_DEBUG((ATH_DBG_80211, "ath: "
	    "ieee80211_send_deauth(): station %s deauthenticate",
	    " (reason %d)\n", ieee80211_ether_sprintf(in->in_macaddr), reason));
	pktlen = sizeof (struct ieee80211_frame) + sizeof (uint16_t);
	mp = allocb(pktlen, BPRI_MED);
	if (mp == NULL) {
		ath_problem("ath: ieee80211_send_deauth(): allocb failed\n");
		return (ENOMEM);
	}
	mp->b_wptr = mp->b_rptr + pktlen;
	mp->b_rptr += sizeof (struct ieee80211_frame);

	frm = (uint16_t *)mp->b_rptr;
	frm[0] = LE_16(reason);

	return (ieee80211_mgmt_output(isc, in, mp, type));
}

static int32_t
ieee80211_send_asreq(ieee80211com_t *isc, struct ieee80211_node *in,
    int32_t type, int32_t dummy)
{
	mblk_t *mp;
	uint8_t *frm;
	uint16_t capinfo = 0;
	int32_t ret, pktlen;

	_NOTE(ARGUNUSED(dummy));

	ASSERT(mutex_owned(&isc->isc_genlock));
	/*
	 * asreq frame format
	 *	[2] capability information
	 *	[2] listen interval
	 *	[6*] current AP address (reassoc only)
	 *	[tlv] ssid
	 *	[tlv] supported rates
	 *	[tlv] extended supported rates
	 */
	pktlen = sizeof (struct ieee80211_frame) +
	    sizeof (capinfo) + sizeof (uint16_t) + IEEE80211_ADDR_LEN +
	    2 + in->in_esslen + 2 + IEEE80211_RATE_SIZE +
	    2 + (IEEE80211_RATE_MAXSIZE - IEEE80211_RATE_SIZE);
	mp = allocb(pktlen, BPRI_MED);
	if (mp == NULL) {
		ath_problem("ath: ieee80211_send_asreq: allocb failed\n");
		return (ENOMEM);
	}
	mp->b_rptr += sizeof (struct ieee80211_frame);

	frm = (uint8_t *)mp->b_rptr;

	capinfo = 0;
	if (isc->isc_opmode == IEEE80211_M_IBSS)
		capinfo |= IEEE80211_CAPINFO_IBSS;
	else	/* IEEE80211_M_STA */
		capinfo |= IEEE80211_CAPINFO_ESS;
	if (isc->isc_flags & IEEE80211_F_WEPON)
		capinfo |= IEEE80211_CAPINFO_PRIVACY;
	if (isc->isc_flags & IEEE80211_F_SHPREAMBLE)
		capinfo |= IEEE80211_CAPINFO_SHORT_PREAMBLE;
	if (isc->isc_flags & IEEE80211_F_SHSLOT)
		capinfo |= IEEE80211_CAPINFO_SHORT_SLOTTIME;
	capinfo |= 0x0020;
	*(uint16_t *)frm = LE_16(capinfo);
	frm += 2;

	*(uint16_t *)frm = LE_16(isc->isc_lintval);
	frm += 2;

	if (type == IEEE80211_FC0_SUBTYPE_REASSOC_REQ) {
		IEEE80211_ADDR_COPY(frm, isc->isc_bss->in_bssid);
		frm += IEEE80211_ADDR_LEN;
	}

	frm = ieee80211_add_ssid(frm, in->in_essid, in->in_esslen);
	frm = ieee80211_add_rates(frm, &in->in_rates);
	frm = ieee80211_add_xrates(frm, &in->in_rates);
	mp->b_wptr = frm;
	ret = ieee80211_mgmt_output(isc, in, mp, type);
	isc->isc_mgt_timeout = IEEE80211_TRANS_WAIT;
	return (ret);
}

static int32_t
ieee80211_send_asresp(ieee80211com_t *isc, struct ieee80211_node *in,
    int32_t type, int32_t status)
{
	mblk_t *mp;
	uint8_t *frm;
	uint16_t capinfo;
	int32_t pktlen;

	ASSERT(mutex_owned(&isc->isc_genlock));
	/*
	 * asreq frame format
	 *	[2] capability information
	 *	[2] status
	 *	[2] association ID
	 *	[tlv] supported rates
	 *	[tlv] extended supported rates
	 */
	pktlen = sizeof (struct ieee80211_frame) +
	    sizeof (capinfo) +
	    sizeof (uint16_t) +
	    sizeof (uint16_t) +
	    2 + IEEE80211_RATE_SIZE +
	    2 + (IEEE80211_RATE_MAXSIZE - IEEE80211_RATE_SIZE);
	mp = allocb(pktlen, BPRI_MED);
	if (mp == NULL) {
		ath_problem("ath: ieee80211_send_asresp: allocb failed\n");
		return (ENOMEM);
	}
	mp->b_rptr += sizeof (struct ieee80211_frame);
	frm = (uint8_t *)mp->b_rptr;

	capinfo = IEEE80211_CAPINFO_ESS;
	if (isc->isc_flags & IEEE80211_F_WEPON)
		capinfo |= IEEE80211_CAPINFO_PRIVACY;
	*(uint16_t *)frm = LE_16(capinfo);
	frm += 2;

	*(uint16_t *)frm = LE_16(status);
	frm += 2;

	if (status == IEEE80211_STATUS_SUCCESS && in != NULL)
		*(uint16_t *)frm = LE_16(in->in_associd);
	else
		*(uint16_t *)frm = LE_16(0);
	frm += 2;

	if (in != NULL) {
		frm = ieee80211_add_rates(frm, &in->in_rates);
		frm = ieee80211_add_xrates(frm, &in->in_rates);
	} else {
		frm = ieee80211_add_rates(frm, &isc->isc_bss->in_rates);
		frm = ieee80211_add_xrates(frm, &isc->isc_bss->in_rates);
	}
	mp->b_wptr = frm;

	return (ieee80211_mgmt_output(isc, in, mp, type));
}

static int32_t
ieee80211_send_disassoc(ieee80211com_t *isc, struct ieee80211_node *in,
    int32_t type, int32_t reason)
{
	mblk_t *mp;
	uint16_t *frm;
	int32_t pktlen;

	_NOTE(ARGUNUSED(type))

	ASSERT(mutex_owned(&isc->isc_genlock));

	ATH_DEBUG((ATH_DBG_80211, "ath: "
	    "ieee80211_send_disassoc(): station %s disassociate",
	    " (reason %d)\n", ieee80211_ether_sprintf(in->in_macaddr), reason));
	pktlen = sizeof (struct ieee80211_frame) + sizeof (uint16_t);
	mp = allocb(pktlen, BPRI_MED);
	if (mp == NULL) {
		ath_problem("ath: ieee80211_send_asresp: allocb failed\n");
		return (ENOMEM);
	}
	mp->b_wptr = mp->b_rptr + pktlen;
	mp->b_rptr += sizeof (struct ieee80211_frame);
	frm = (uint16_t *)mp->b_rptr;
	frm[0] = LE_16(reason);
	return (ieee80211_mgmt_output(isc, in, mp,
	    IEEE80211_FC0_SUBTYPE_DISASSOC));
}

/*
 * This handles both beacon and probe response frames.
 */
static void
ieee80211_recv_beacon(ieee80211com_t *isc, mblk_t *mp, int32_t rssi,
    uint32_t rstamp, uint32_t rantenna)
{
	struct ieee80211_frame *wh;
	struct ieee80211_node *in;
	uint8_t *frm, *efrm, *tstamp, *bintval, *capinfo, *ssid;
	uint8_t *rates, *xrates;
	uint8_t chan, bchan, fhindex, erp;
	uint16_t fhdwell;

	ASSERT(mutex_owned(&isc->isc_genlock));

	if (isc->isc_opmode != IEEE80211_M_IBSS &&
	    isc->isc_state != IEEE80211_S_SCAN) {
		return;
	}

	wh = (struct ieee80211_frame *)mp->b_rptr;
	frm = (uint8_t *)&wh[1];
	efrm = mp->b_wptr;
	/*
	 * beacon frame format
	 *	[8] time stamp
	 *	[2] beacon interval
	 *	[2] cabability information
	 *	[tlv] ssid
	 *	[tlv] supported rates
	 *	[tlv] country information
	 *	[tlv] parameter set (FH/DS)
	 *	[tlv] erp information
	 *	[tlv] extended supported rates
	 */
	tstamp = frm;
	frm += 8;
	bintval = frm;
	frm += 2;
	capinfo = frm;
	frm += 2;
	ssid = rates = xrates = NULL;
	bchan = ieee80211_chan2ieee(isc, isc->isc_bss->in_chan);
	chan = bchan;
	fhdwell = 0;
	fhindex = 0;
	erp = 0;
	while (frm < efrm) {
		switch (*frm) {
		case IEEE80211_ELEMID_SSID:
			ssid = frm;
			break;
		case IEEE80211_ELEMID_RATES:
			rates = frm;
			break;
		case IEEE80211_ELEMID_COUNTRY:
			/*
			 * don't care 'country', otherwise,
			 * just do:
			 * country = frm;
			 */
			break;
		case IEEE80211_ELEMID_FHPARMS:
			if (isc->isc_phytype == IEEE80211_T_FH) {
				fhdwell = (frm[3] << 8) | frm[2];
				chan = IEEE80211_FH_CHAN(frm[4], frm[5]);
				fhindex = frm[6];
			}
			break;
		case IEEE80211_ELEMID_DSPARMS:
			/*
			 * hack this since depending on phytype
			 * is problematic for multi-mode devices.
			 */
			if (isc->isc_phytype != IEEE80211_T_FH)
				chan = frm[2];
			break;
		case IEEE80211_ELEMID_TIM:
			break;
		case IEEE80211_ELEMID_XRATES:
			xrates = frm;
			break;
		case IEEE80211_ELEMID_ERP:
			if (frm[1] != 1) {
				ATH_DEBUG((ATH_DBG_80211, "ath: "
				    "ieee80211_recv_beacon(): "
				    "%s: invalid ERP element; "
				    "length %u, expecting 1\n",
				    "ieee80211_recv_beacon", frm[1]));
				break;
			}
			erp = frm[2];
			break;
		default:
			break;
		}
		frm += frm[1] + 2;
	}
	IEEE80211_VERIFY_ELEMENT(rates, IEEE80211_RATE_SIZE, wh);
	IEEE80211_VERIFY_ELEMENT(ssid, IEEE80211_NWID_LEN, wh);

	if (isclr(isc->isc_chan_active, chan)) {
		ATH_DEBUG((ATH_DBG_80211, "ath: ieee80211_recv_beacon(): "
		    "ignore %s with invalid channel %u\n",
		    IEEE80211_ISPROBE(wh) ? "probe response" : "beacon", chan));
		return;
	}
	if (chan != bchan && isc->isc_phytype != IEEE80211_T_FH) {
		/*
		 * Frame was received on a channel different from the
		 * one indicated in the DS/FH params element id; silently
		 * discard it.
		 *
		 * NB: this can happen due to signal leakage.
		 */
		ATH_DEBUG((ATH_DBG_80211, "ath: ieee80211_recv_beacon(): "
		    "ignore %s phytype %u on channel %u marked for %u\n",
		    IEEE80211_ISPROBE(wh) ? "probe response" : "beacon",
		    isc->isc_phytype,
		    bchan, chan));
		return;
	}

	/*
	 * Use mac and channel for lookup so we collect all
	 * potential AP's when scanning.  Otherwise we may
	 * see the same AP on multiple channels and will only
	 * record the last one.  We could filter APs here based
	 * on rssi, etc. but leave that to the end of the scan
	 * so we can keep the selection criteria in one spot.
	 * This may result in a bloat of the scanned AP list but
	 * it shouldn't be too much.
	 */
	in = ieee80211_lookup_node(isc, wh->ifrm_addr2,
	    &isc->isc_channels[chan]);
	if (in == NULL || isc->isc_state == IEEE80211_S_SCAN) {
		ATH_DEBUG((ATH_DBG_80211, "ath: "
		    "ieee80211_recv_beacon(): essid = %s\n",
		    ieee80211_essid_sprintf(ssid + 2, ssid[1])));
		ATH_DEBUG((ATH_DBG_80211, "ath: ieee80211_recv_beacon(): "
		    "from %s\n", ieee80211_ether_sprintf(wh->ifrm_addr2)));
		ATH_DEBUG((ATH_DBG_80211, "ath: "
		    "ieee80211_recv_beacon(): to %s\n",
		    ieee80211_ether_sprintf(wh->ifrm_addr1)));
		ATH_DEBUG((ATH_DBG_80211, "ath: ieee80211_recv_beacon(): "
		    "caps 0x%x bintval %u erp 0x%x\n",
		    LE_16(*(uint16_t *)capinfo),
		    LE_16(*(uint16_t *)bintval), erp));
	}

	if (in == NULL) {
		in = ieee80211_alloc_node(isc, wh->ifrm_addr2);
		if (in == NULL)
			return;
		in->in_esslen = ssid[1];
		bzero(in->in_essid, sizeof (in->in_essid));
		bcopy(ssid + 2, in->in_essid, ssid[1]);
	} else if (ssid[1] != 0 && IEEE80211_ISPROBE(wh)) {
		/*
		 * Update ESSID at probe response to adopt hidden AP by
		 * Lucent/Cisco, which announces null ESSID in beacon.
		 */
		in->in_esslen = ssid[1];
		bzero(in->in_essid, sizeof (in->in_essid));
		bcopy(ssid + 2, in->in_essid, ssid[1]);
	}

	IEEE80211_ADDR_COPY(in->in_bssid, wh->ifrm_addr3);
	ieee80211_add_recvhist(in, rssi, rstamp, rantenna);
	bcopy(tstamp, in->in_tstamp, sizeof (in->in_tstamp));
	in->in_intval = LE_16(*(uint16_t *)bintval);
	in->in_capinfo = LE_16(*(uint16_t *)capinfo);
	in->in_chan = &isc->isc_channels[chan];
	in->in_fhdwell = fhdwell;
	in->in_fhindex = fhindex;
	in->in_erp = erp;
	/* in_chan must have been setup */
	(void) ieee80211_setup_rates(isc, in, rates, xrates,
	    IEEE80211_F_DOSORT);
}

static void
ieee80211_recv_prreq(ieee80211com_t *isc, mblk_t *mp, int32_t rssi,
    uint32_t rstamp, uint32_t rantenna)
{
	struct ieee80211_frame *wh;
	struct ieee80211_node *in;
	uint8_t *frm, *efrm, *ssid, *rates, *xrates;
	uint8_t rate;
	int32_t allocbs;

	ASSERT(mutex_owned(&isc->isc_genlock));

	if (isc->isc_opmode == IEEE80211_M_STA)
		return;
	if (isc->isc_state != IEEE80211_S_RUN)
		return;

	wh = (struct ieee80211_frame *)mp->b_rptr;
	frm = (uint8_t *)&wh[1];
	efrm = mp->b_wptr;
	/*
	 * prreq frame format
	 *	[tlv] ssid
	 *	[tlv] supported rates
	 *	[tlv] extended supported rates
	 */
	ssid = rates = xrates = NULL;
	while (frm < efrm) {
		switch (*frm) {
		case IEEE80211_ELEMID_SSID:
			ssid = frm;
			break;
		case IEEE80211_ELEMID_RATES:
			rates = frm;
			break;
		case IEEE80211_ELEMID_XRATES:
			xrates = frm;
			break;
		}
		frm += frm[1] + 2;
	}
	IEEE80211_VERIFY_ELEMENT(rates, IEEE80211_RATE_SIZE, wh);
	IEEE80211_VERIFY_ELEMENT(ssid, IEEE80211_NWID_LEN, wh);
	if (ssid[1] != 0 &&
	    (ssid[1] != isc->isc_bss->in_esslen ||
	    bcmp(ssid + 2, isc->isc_bss->in_essid,
	    isc->isc_bss->in_esslen) != 0)) {
		ATH_DEBUG((ATH_DBG_80211, "ath: ieee80211_recv_prreq(): "
		    "ssid unmatch %s from %s",
		    ieee80211_essid_sprintf(ssid + 2, ssid[1]),
		    ieee80211_ether_sprintf(wh->ifrm_addr2)));
		return;
	}

	in = ieee80211_find_node(isc, wh->ifrm_addr2);
	if (in == NULL) {
		in = ieee80211_dup_bss(isc, wh->ifrm_addr2);
		if (in == NULL) {
			ath_problem("ath: ieee80211_recv_prreq(): "
			    "dup bss failed\n");
			return;
		}
		ATH_DEBUG((ATH_DBG_80211, "ath: "
		    "ieee80211_recv_prreq: new req from %s\n",
		    ieee80211_ether_sprintf(wh->ifrm_addr2)));
		allocbs = 1;
	} else
		allocbs = 0;
	ieee80211_add_recvhist(in, rssi, rstamp, rantenna);
	rate = ieee80211_setup_rates(isc, in, rates, xrates,
	    IEEE80211_F_DOSORT | IEEE80211_F_DOFRATE
	    | IEEE80211_F_DONEGO | IEEE80211_F_DODEL);
	if (rate & IEEE80211_RATE_BASIC) {
		ATH_DEBUG((ATH_DBG_80211, "ath: ieee80211_recv_prreq(): "
		    "rate negotiation fail: %s\n",
		    ieee80211_ether_sprintf(wh->ifrm_addr2)));
	} else {
		IEEE80211_SEND_MGMT(isc, in, IEEE80211_FC0_SUBTYPE_PROBE_RESP,
		    0);
	}

	if (allocbs && isc->isc_opmode == IEEE80211_M_HOSTAP)
		ieee80211_free_node(isc, in);
	else
		ieee80211_unref_node(&in);
}

static void
ieee80211_recv_auth(ieee80211com_t *isc, mblk_t *mp, int32_t rssi,
    uint32_t rstamp, uint32_t rantenna)
{
	struct ieee80211_frame *wh;
	struct ieee80211_node *in;
	uint8_t *frm, *efrm;
	uint16_t algo, seq, status;

	_NOTE(ARGUNUSED(rssi))
	_NOTE(ARGUNUSED(rstamp))
	_NOTE(ARGUNUSED(rantenna))
	_NOTE(ARGUNUSED(mp))

	ASSERT(mutex_owned(&isc->isc_genlock));

	wh = (struct ieee80211_frame *)mp->b_rptr;
	frm = (uint8_t *)&wh[1];
	efrm = mp->b_wptr;
	/*
	 * auth frame format
	 *	[2] algorithm
	 *	[2] sequence
	 *	[2] status
	 *	[tlv*] challenge
	 */
	if (frm + 6 > efrm) {
		ATH_DEBUG((ATH_DBG_80211, "ath: "
		    "ieee80211_recv_auth: too short from %s\n",
		    ieee80211_ether_sprintf(wh->ifrm_addr2)));
		return;
	}

	algo = LE_16(*(uint16_t *)frm);
	seq = LE_16(*(uint16_t *)(frm + 2));
	status = LE_16(*(uint16_t *)(frm + 4));
	if (algo != IEEE80211_AUTH_ALG_OPEN) {
		/* shared key auth */
		ath_problem("ath: ieee80211_recv_auth(): "
		    "unsupported auth %d from %s\n",
		    algo, ieee80211_ether_sprintf(wh->ifrm_addr2));
		return;
	}
	switch (isc->isc_opmode) {
	case IEEE80211_M_IBSS:
		if (isc->isc_state != IEEE80211_S_RUN || seq != 1)
			return;
		(void) _ieee80211_new_state(isc, IEEE80211_S_AUTH,
		    wh->ifrm_fc[0] & IEEE80211_FC0_SUBTYPE_MASK);
		break;

	case IEEE80211_M_AHDEMO:
		break;

	case IEEE80211_M_HOSTAP:
		break;

	case IEEE80211_M_STA:
		if (isc->isc_state != IEEE80211_S_AUTH || seq != 2)
			return;
		if (status != 0) {
			ath_log("ath: ieee80211_recv_auth(): "
			    "authentication failed (reason %d) for %s\n",
			    status, ieee80211_ether_sprintf(wh->ifrm_addr3));
			in = ieee80211_find_node(isc, wh->ifrm_addr2);
			if (in != NULL)
				in->in_fails++;
			return;
		}
		(void) _ieee80211_new_state(isc, IEEE80211_S_ASSOC,
		    wh->ifrm_fc[0] & IEEE80211_FC0_SUBTYPE_MASK);
		break;
	}
}

static void
ieee80211_recv_asreq(ieee80211com_t *isc, mblk_t *mp, int32_t rssi,
    uint32_t rstamp, uint32_t rantenna)
{
	_NOTE(ARGUNUSED(isc))
	_NOTE(ARGUNUSED(rssi))
	_NOTE(ARGUNUSED(rstamp))
	_NOTE(ARGUNUSED(rantenna))
	_NOTE(ARGUNUSED(mp))

	/* doesn't support HOST-AP mode yet */
}

static void
ieee80211_recv_asresp(ieee80211com_t *isc, mblk_t *mp, int32_t rssi,
    uint32_t rstamp, uint32_t rantenna)
{
	struct ieee80211_frame *wh;
	struct ieee80211_node *in;
	uint8_t *frm, *efrm, *rates, *xrates;
	int32_t status;

	_NOTE(ARGUNUSED(rssi))
	_NOTE(ARGUNUSED(rstamp))
	_NOTE(ARGUNUSED(rantenna))
	_NOTE(ARGUNUSED(mp))

	ASSERT(mutex_owned(&isc->isc_genlock));

	if (isc->isc_opmode != IEEE80211_M_STA ||
	    isc->isc_state != IEEE80211_S_ASSOC)
		return;

	wh = (struct ieee80211_frame *)mp->b_rptr;
	frm = (uint8_t *)&wh[1];
	efrm = mp->b_wptr;
	/*
	 * asresp frame format
	 *	[2] capability information
	 *	[2] status
	 *	[2] association ID
	 *	[tlv] supported rates
	 *	[tlv] extended supported rates
	 */
	if (frm + 6 > efrm) {
		ath_log("ath: ieee80211_recv_asresp(): too short from %s\n",
		    ieee80211_ether_sprintf(wh->ifrm_addr2));
		return;
	}

	in = isc->isc_bss;
	in->in_capinfo = LE_16(*(uint16_t *)frm);
	frm += 2;

	status = LE_16(*(uint16_t *)frm);
	frm += 2;

	if (status != 0) {
		ATH_DEBUG((ATH_DBG_80211, "ath: ieee80211_recv_asresp(): "
		    "association failed (reason %d)\n", status));
		in = ieee80211_find_node(isc, wh->ifrm_addr2);
		if (in != NULL) {
			in->in_fails++;
		}
		return;
	}

	in->in_associd = LE_16(*(uint16_t *)frm);
	frm += 2;

	rates = xrates = NULL;
	while (frm < efrm) {
		switch (*frm) {
		case IEEE80211_ELEMID_RATES:
			rates = frm;
			break;
		case IEEE80211_ELEMID_XRATES:
			xrates = frm;
			break;
		}
		frm += frm[1] + 2;
	}

	IEEE80211_VERIFY_ELEMENT(rates, IEEE80211_RATE_SIZE, wh);
	(void) ieee80211_setup_rates(isc, in, rates, xrates,
	    IEEE80211_F_DOSORT | IEEE80211_F_DOFRATE |
	    IEEE80211_F_DONEGO | IEEE80211_F_DODEL);
	if (in->in_rates.ir_nrates != 0)
		(void) _ieee80211_new_state(isc, IEEE80211_S_RUN,
			wh->ifrm_fc[0] & IEEE80211_FC0_SUBTYPE_MASK);
}

static void
ieee80211_recv_disassoc(ieee80211com_t *isc, mblk_t *mp, int32_t rssi,
    uint32_t rstamp, uint32_t rantenna)
{
	struct ieee80211_frame *wh;
	uint8_t *frm, *efrm;
	uint16_t reason;

	_NOTE(ARGUNUSED(rssi))
	_NOTE(ARGUNUSED(rstamp))
	_NOTE(ARGUNUSED(rantenna))
	_NOTE(ARGUNUSED(mp))

	ASSERT(mutex_owned(&isc->isc_genlock));

	wh = (struct ieee80211_frame *)mp->b_rptr;
	frm = (uint8_t *)&wh[1];
	efrm = mp->b_wptr;
	/*
	 * disassoc frame format
	 *	[2] reason
	 */
	if (frm + 2 > efrm) {
		ath_log("ath: ieee80211_recv_disassoc(): too short from %s\n",
		    ieee80211_ether_sprintf(wh->ifrm_addr2));
		return;
	}
	reason = LE_16(*(uint16_t *)frm);
	ATH_DEBUG((ATH_DBG_80211, "ath: ieee80211_recv_disassoc(): "
	    "disassociation packet, reason:0x%x\n", reason));
	switch (isc->isc_opmode) {
	case IEEE80211_M_STA:
		(void) _ieee80211_new_state(isc, IEEE80211_S_ASSOC,
		    wh->ifrm_fc[0] & IEEE80211_FC0_SUBTYPE_MASK);
		break;
	case IEEE80211_M_HOSTAP:
		/* don't support HOSTAP */
		break;
	default:
		break;
	}
}

static void
ieee80211_recv_deauth(ieee80211com_t *isc, mblk_t *mp, int32_t rssi,
    uint32_t rstamp, uint32_t rantenna)
{
	struct ieee80211_frame *wh;
	uint8_t *frm, *efrm;
	uint16_t reason;

	_NOTE(ARGUNUSED(rssi))
	_NOTE(ARGUNUSED(rstamp))
	_NOTE(ARGUNUSED(rantenna))
	_NOTE(ARGUNUSED(mp))

	ASSERT(mutex_owned(&isc->isc_genlock));

	wh = (struct ieee80211_frame *)mp->b_rptr;
	frm = (uint8_t *)&wh[1];
	efrm = mp->b_wptr;
	/*
	 * dauth frame format
	 *	[2] reason
	 */
	if (frm + 2 > efrm) {
		ath_log("ath: ieee80211_recv_deauth(): too short from %s\n",
		    ieee80211_ether_sprintf(wh->ifrm_addr2));
		return;
	}
	reason = LE_16(*(uint16_t *)frm);
	ATH_DEBUG((ATH_DBG_80211, "ath: ieee80211_recv_deauth(): "
	    "deauthentication packet, reason: 0x%x\n", reason));
	switch (isc->isc_opmode) {
	case IEEE80211_M_STA:
		(void) _ieee80211_new_state(isc, IEEE80211_S_AUTH,
		    wh->ifrm_fc[0] & IEEE80211_FC0_SUBTYPE_MASK);
		break;
	case IEEE80211_M_HOSTAP:
		break;
	default:
		break;
	}
}

/*
 * Return the phy mode for with the specified channel so the
 * caller can select a rate set.  This is problematic and the
 * work here assumes how things work elsewhere in this code.
 */
enum ieee80211_phymode
ieee80211_chan2mode(ieee80211com_t *isc, struct ieee80211channel *chan)
{
	/*
	 * NB: this assumes the channel would not be supplied to us
	 * unless it was already compatible with the current mode.
	 */
	if (isc->isc_curmode != IEEE80211_MODE_AUTO)
		return (isc->isc_curmode);
	/*
	 * In autoselect mode; deduce a mode based on the channel
	 * characteristics.  We assume that turbo-only channels
	 * are not considered when the channel set is constructed.
	 */
	if (IEEE80211_IS_CHAN_5GHZ(chan))
		return (IEEE80211_MODE_11A);
	else if (chan->ich_flags & (IEEE80211_CHAN_OFDM | IEEE80211_CHAN_DYN))
		return (IEEE80211_MODE_11G);
	else
		return (IEEE80211_MODE_11B);
}


/*
 * Format an Ethernet MAC for printing,
 * and this function adds NULL byte at the end of string.
 */
const char *
ieee80211_ether_sprintf(const uint8_t *mac)
{
	static char etherbuf[18];
	(void) snprintf(etherbuf, sizeof (etherbuf),
	    "%02x:%02x:%02x:%02x:%02x:%02x",
	    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return (etherbuf);
}

/*
 * Format an essid for printing,
 * and this function adds NULL byte at the end of string.
 */
const int8_t *
ieee80211_essid_sprintf(uint8_t *essid, uint32_t len)
{
	static int8_t essidbuf[IEEE80211_NWID_LEN * 2 + 1];
	uint32_t i;
	uint8_t *p;
	int8_t tmp[3];

	bzero(essidbuf, sizeof (essidbuf));
	if (len > IEEE80211_NWID_LEN)
		len = IEEE80211_NWID_LEN;
	/* determine printable or not */
	for (i = 0, p = essid; i < len; i++, p++) {
		if (*p < ' ' || *p > 0x7e)
			break;
	}
	if (i == len) {
		for (i = 0; i < len; i++)
			essidbuf[i] = essid[i];
		essidbuf[i] = '\0';
	} else {
		for (i = 0; i < len; i++) {
			(void) sprintf(tmp, "%02x", essid[i]);
			(void) strcat(essidbuf, tmp);
		}
	}
	return (essidbuf);
}

/*
 * Following fucntions are registerd to GLD and intercepting
 * the function calls from GLD to LLD to add appropriate ic_genlock protection.
 *
 * We have to protect ieee80211_gld_send() by isc_genlock,
 * because there have many references to isc struct on this transimit path,
 * and this may affect performace.
 */
static int32_t
ieee80211_gld_send(gld_mac_info_t *gld_p, mblk_t *mp)
{
	ieee80211com_t *isc = (ieee80211com_t *)gld_p->gldm_private;
	int32_t result;

	mutex_enter(&isc->isc_genlock);
	result = (*isc->isc_gld_send)(gld_p, mp);
	mutex_exit(&isc->isc_genlock);
	return (result);
}

static int32_t
ieee80211_gld_reset(gld_mac_info_t *gld_p)
{
	int32_t result;
	ieee80211com_t *isc = (ieee80211com_t *)gld_p->gldm_private;

	mutex_enter(&isc->isc_genlock);
	result = (*isc->isc_gld_reset)(gld_p);
	mutex_exit(&isc->isc_genlock);
	return (result);
}


/*
 * Following function is for Multi_func thread.
 * The smallest timing unit is 100ms.
 * It is created in ieee80211_gld_start(),
 * and destroy in ieee80211_gld_stop().
 */
void
ieee80211_mf_thread(ieee80211com_t *isc)
{
	struct ieee80211_node *in;
	uint32_t scan_ticks = 0;
	uint32_t ratectl_ticks = 0;
	uint32_t cali_ticks = 0;
	uint32_t mgt_ticks = 0;
	enum ieee80211_state ostate = IEEE80211_S_INIT;

	mutex_enter(&isc->isc_genlock);
	while (isc->isc_mfthread_switch) {
		if (isc->isc_state == IEEE80211_S_SCAN &&
		    ostate != IEEE80211_S_SCAN)
			scan_ticks = 0;

		if (isc->isc_state == IEEE80211_S_SCAN) {
			if (scan_ticks >= (isc->isc_scan_interval/100 - 1)) {
				ieee80211_next_scan(isc);
				scan_ticks = 0;
			} else
				scan_ticks++;
		}

		if (ratectl_ticks >= (isc->isc_ratectl_interval/100 - 1)) {
			if (isc->isc_opmode == IEEE80211_M_STA)
				(*isc->isc_rate_ctl)(isc, isc->isc_bss);
			else {
				in = list_head(&isc->isc_in_list);
				while (in != NULL) {
					(*isc->isc_rate_ctl)(isc, in);
					in = list_next(&isc->isc_in_list, in);
				}
			}
			ratectl_ticks = 0;
		} else
			ratectl_ticks++;

		if (cali_ticks >= (isc->isc_cali_interval/100 - 1)) {
			(*isc->isc_calibrate)(isc);
			cali_ticks = 0;
		} else
			cali_ticks++;

		if (mgt_ticks >= 10) { /* one second */
			if (isc->isc_mgt_timeout &&
			    --isc->isc_mgt_timeout == 0) {
				(void) _ieee80211_new_state(isc,
				    IEEE80211_S_SCAN, -1);
			}
			if (isc->isc_inact_timeout &&
			    --isc->isc_inact_timeout == 0)
				ieee80211_timeout_nodes(isc);
			mgt_ticks = 0;
		} else
			mgt_ticks++;

		ostate = isc->isc_state;
		mutex_exit(&isc->isc_genlock);
		delay(drv_usectohz(100000)); /* delay 100ms */
		mutex_enter(&isc->isc_genlock);
	}
	isc->isc_mf_thread = NULL;
	cv_broadcast(&isc->isc_mfthread_cv);
	mutex_exit(&isc->isc_genlock);
	thread_exit();
}

/*
 * This function is responsible for creating multi-func thread.
 */
static int32_t
ieee80211_gld_start(gld_mac_info_t *gld_p)
{
	int32_t result;
	ieee80211com_t *isc = (ieee80211com_t *)gld_p->gldm_private;

	mutex_enter(&isc->isc_genlock);
	isc->isc_mfthread_switch = 1;
	if (isc->isc_mf_thread == NULL)
		isc->isc_mf_thread = thread_create((caddr_t)NULL, 0,
		    ieee80211_mf_thread, isc, 0, &p0, TS_RUN, minclsyspri);
	result = (*isc->isc_gld_start)(gld_p);
	mutex_exit(&isc->isc_genlock);
	return (result);
}

/*
 * This function is responsible for destory multi-func thread.
 */
static int32_t
ieee80211_gld_stop(gld_mac_info_t *gld_p)
{
	int32_t result;
	ieee80211com_t *isc = (ieee80211com_t *)gld_p->gldm_private;

	mutex_enter(&isc->isc_genlock);
	isc->isc_mfthread_switch = 0;
	while (isc->isc_mf_thread != NULL) {
		if (cv_wait_sig(&isc->isc_mfthread_cv, &isc->isc_genlock) == 0)
			break;
	}
	result = (*isc->isc_gld_stop)(gld_p);
	mutex_exit(&isc->isc_genlock);
	return (result);
}

static int32_t
ieee80211_gld_saddr(gld_mac_info_t *gld_p, uint8_t *macaddr)
{
	int32_t result;
	ieee80211com_t *isc = (ieee80211com_t *)gld_p->gldm_private;

	mutex_enter(&isc->isc_genlock);
	result = (*isc->isc_gld_saddr)(gld_p, macaddr);
	mutex_exit(&isc->isc_genlock);
	return (result);
}

static int
ieee80211_gld_set_promiscuous(gld_mac_info_t *gld_p, int mode)
{
	int result;
	ieee80211com_t *isc = (ieee80211com_t *)gld_p->gldm_private;

	mutex_enter(&isc->isc_genlock);
	result = (*isc->isc_gld_set_promiscuous)(gld_p, mode);
	mutex_exit(&isc->isc_genlock);
	return (result);
}

static int32_t
ieee80211_gld_gstat(gld_mac_info_t *gld_p, struct gld_stats *glds_p)
{
	int32_t result;
	ieee80211com_t *isc = (ieee80211com_t *)gld_p->gldm_private;

	mutex_enter(&isc->isc_genlock);
	result = (*isc->isc_gld_gstat)(gld_p, glds_p);
	mutex_exit(&isc->isc_genlock);
	return (result);
}

static int32_t
ieee80211_gld_ioctl(gld_mac_info_t *gld_p, queue_t *wq, mblk_t *mp)
{
	int32_t result;
	ieee80211com_t *isc = (ieee80211com_t *)gld_p->gldm_private;

	mutex_enter(&isc->isc_genlock);
	result = (*isc->isc_gld_ioctl)(gld_p, wq, mp);
	mutex_exit(&isc->isc_genlock);
	return (result);
}

static int
ieee80211_gld_set_multicast(gld_mac_info_t *gld_p, uint8_t *eth_p, int flag)
{
	int result;
	ieee80211com_t *isc = (ieee80211com_t *)gld_p->gldm_private;

	mutex_enter(&isc->isc_genlock);
	result = (*isc->isc_gld_set_multicast)(gld_p, eth_p, flag);
	mutex_exit(&isc->isc_genlock);
	return (result);
}

static uint32_t
ieee80211_gld_intr(gld_mac_info_t *gld_p)
{
	ieee80211com_t *isc = (ieee80211com_t *)gld_p->gldm_private;
	return ((*isc->isc_gld_intr)(gld_p));
}



int32_t
ieee80211_ifattach(gld_mac_info_t *gld_p)
{
	ieee80211com_t *isc =
	    (ieee80211com_t *)gld_p->gldm_private;
	struct ieee80211channel *ch;
	int32_t i;

	mutex_init(&isc->isc_genlock, NULL, MUTEX_DRIVER, NULL);

	/*
	 * Fill in 802.11 available channel set, mark
	 * all available channels as active, and pick
	 * a default channel if not already specified.
	 */
	bzero(isc->isc_chan_avail, sizeof (isc->isc_chan_avail));
	isc->isc_modecaps |= 1 << IEEE80211_MODE_AUTO;
	for (i = 0; i <= IEEE80211_CHAN_MAX; i++) {
		ch = &isc->isc_channels[i];
		if (ch->ich_flags) {
			setbit(isc->isc_chan_avail, i);
			/*
			 * Identify mode capabilities.
			 */
			if (IEEE80211_IS_CHAN_A(ch))
				isc->isc_modecaps |= 1 << IEEE80211_MODE_11A;
			if (IEEE80211_IS_CHAN_B(ch))
				isc->isc_modecaps |= 1 << IEEE80211_MODE_11B;
			if (IEEE80211_IS_CHAN_PUREG(ch))
				isc->isc_modecaps |= 1 << IEEE80211_MODE_11G;
			if (IEEE80211_IS_CHAN_T(ch))
				isc->isc_modecaps |= 1 << IEEE80211_MODE_TURBO;
		}
	}

	/* Start from auto mode */
	(void) ieee80211_setmode(isc, IEEE80211_MODE_AUTO);

	/* Initialize WEP related variable */
	isc->isc_wep_txkey = 0;
	isc->isc_iv = (int32_t)(gethrtime() & 0x00000000ffffffff);

	/* Initialize some config variables */
	isc->isc_rtsthreshold = IEEE80211_RTS_MAX;
	isc->isc_fragthreshold = 2346;
	isc->isc_des_chan = IEEE80211_CHAN_ANYC;	/* any channel is ok */
	isc->isc_fixed_rate = -1;			/* no fixed rate */
	if (isc->isc_lintval == 0)
		isc->isc_lintval = 100;			/* default sleep */
	isc->isc_txpower = IEEE80211_TXPOWER_MAX;	/* default tx power */
	isc->isc_bmisstimeout = 7 * isc->isc_lintval;	/* default 7 beacons */

	list_create(&isc->isc_in_list,
	    sizeof (struct ieee80211_node),
	    offsetof(struct ieee80211_node, in_node));
	for (i = 0; i < IEEE80211_NODE_HASHSIZE; i++)
		list_create(&isc->isc_inhash_list[i],
		    sizeof (struct ieee80211_node),
		    offsetof(struct ieee80211_node, in_hash_node));

	/* Initialize management frame handlers */
	isc->isc_recv_mgmt[IEEE80211_FC0_SUBTYPE_PROBE_RESP
	    >> IEEE80211_FC0_SUBTYPE_SHIFT] = ieee80211_recv_beacon;
	isc->isc_recv_mgmt[IEEE80211_FC0_SUBTYPE_BEACON
	    >> IEEE80211_FC0_SUBTYPE_SHIFT] = ieee80211_recv_beacon;
	isc->isc_recv_mgmt[IEEE80211_FC0_SUBTYPE_PROBE_REQ
	    >> IEEE80211_FC0_SUBTYPE_SHIFT] = ieee80211_recv_prreq;
	isc->isc_recv_mgmt[IEEE80211_FC0_SUBTYPE_AUTH
	    >> IEEE80211_FC0_SUBTYPE_SHIFT] = ieee80211_recv_auth;
	isc->isc_recv_mgmt[IEEE80211_FC0_SUBTYPE_ASSOC_REQ
	    >> IEEE80211_FC0_SUBTYPE_SHIFT] = ieee80211_recv_asreq;
	isc->isc_recv_mgmt[IEEE80211_FC0_SUBTYPE_REASSOC_REQ
	    >> IEEE80211_FC0_SUBTYPE_SHIFT] = ieee80211_recv_asreq;
	isc->isc_recv_mgmt[IEEE80211_FC0_SUBTYPE_ASSOC_RESP
	    >> IEEE80211_FC0_SUBTYPE_SHIFT] = ieee80211_recv_asresp;
	isc->isc_recv_mgmt[IEEE80211_FC0_SUBTYPE_REASSOC_RESP
	    >> IEEE80211_FC0_SUBTYPE_SHIFT] = ieee80211_recv_asresp;
	isc->isc_recv_mgmt[IEEE80211_FC0_SUBTYPE_DEAUTH
	    >> IEEE80211_FC0_SUBTYPE_SHIFT] = ieee80211_recv_deauth;
	isc->isc_recv_mgmt[IEEE80211_FC0_SUBTYPE_DISASSOC
	    >> IEEE80211_FC0_SUBTYPE_SHIFT] = ieee80211_recv_disassoc;

	isc->isc_send_mgmt[IEEE80211_FC0_SUBTYPE_PROBE_REQ
	    >> IEEE80211_FC0_SUBTYPE_SHIFT] = ieee80211_send_prreq;
	isc->isc_send_mgmt[IEEE80211_FC0_SUBTYPE_PROBE_RESP
	    >> IEEE80211_FC0_SUBTYPE_SHIFT] = ieee80211_send_prresp;
	isc->isc_send_mgmt[IEEE80211_FC0_SUBTYPE_AUTH
	    >> IEEE80211_FC0_SUBTYPE_SHIFT] = ieee80211_send_auth;
	isc->isc_send_mgmt[IEEE80211_FC0_SUBTYPE_DEAUTH
	    >> IEEE80211_FC0_SUBTYPE_SHIFT] = ieee80211_send_deauth;
	isc->isc_send_mgmt[IEEE80211_FC0_SUBTYPE_ASSOC_REQ
	    >> IEEE80211_FC0_SUBTYPE_SHIFT] = ieee80211_send_asreq;
	isc->isc_send_mgmt[IEEE80211_FC0_SUBTYPE_REASSOC_REQ
	    >> IEEE80211_FC0_SUBTYPE_SHIFT] = ieee80211_send_asreq;
	isc->isc_send_mgmt[IEEE80211_FC0_SUBTYPE_ASSOC_RESP
	    >> IEEE80211_FC0_SUBTYPE_SHIFT] = ieee80211_send_asresp;
	isc->isc_send_mgmt[IEEE80211_FC0_SUBTYPE_REASSOC_RESP
	    >> IEEE80211_FC0_SUBTYPE_SHIFT] = ieee80211_send_asresp;
	isc->isc_send_mgmt[IEEE80211_FC0_SUBTYPE_DISASSOC
	    >> IEEE80211_FC0_SUBTYPE_SHIFT] = ieee80211_send_disassoc;

	cv_init(&isc->isc_scan_cv, NULL, CV_DRIVER, NULL);
	cv_init(&isc->isc_mfthread_cv, NULL, CV_DRIVER, NULL);
	isc->isc_mf_thread = NULL;
	isc->isc_mfthread_switch = 0;

	ASSERT(isc->isc_node_alloc != NULL);
	isc->isc_bss = (*isc->isc_node_alloc)(isc);
	isc->isc_bss->in_chan = IEEE80211_CHAN_ANYC;
	isc->isc_bss->in_txpower = IEEE80211_TXPOWER_MAX;
	isc->isc_scan_interval = 200;
	isc->isc_cali_interval = 30000;
	isc->isc_ratectl_interval = 500;

	gld_p->gldm_reset		= ieee80211_gld_reset;
	gld_p->gldm_start		= ieee80211_gld_start;
	gld_p->gldm_stop		= ieee80211_gld_stop;
	gld_p->gldm_set_mac_addr	= ieee80211_gld_saddr;
	gld_p->gldm_send		= ieee80211_gld_send;
	gld_p->gldm_set_promiscuous	= ieee80211_gld_set_promiscuous;
	gld_p->gldm_get_stats		= ieee80211_gld_gstat;
	gld_p->gldm_ioctl		= ieee80211_gld_ioctl;
	gld_p->gldm_set_multicast	= ieee80211_gld_set_multicast;
	gld_p->gldm_intr		= ieee80211_gld_intr;

	return (0);
}

void
ieee80211_ifdetach(gld_mac_info_t *gld_p)
{
	ieee80211com_t *isc = (ieee80211com_t *)gld_p->gldm_private;

	(*isc->isc_node_free)(isc, isc->isc_bss);
	ieee80211_free_allnodes(isc);
	cv_destroy(&isc->isc_mfthread_cv);
	cv_destroy(&isc->isc_scan_cv);
	mutex_destroy(&isc->isc_genlock);
}
