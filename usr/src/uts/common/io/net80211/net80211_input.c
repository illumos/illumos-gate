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
 * Process received frame
 */

#include <sys/mac_provider.h>
#include <sys/byteorder.h>
#include <sys/strsun.h>
#include "net80211_impl.h"

static mblk_t *ieee80211_defrag(ieee80211com_t *, ieee80211_node_t *,
    mblk_t *, int);

/*
 * Process a received frame.  The node associated with the sender
 * should be supplied.  If nothing was found in the node table then
 * the caller is assumed to supply a reference to ic_bss instead.
 * The RSSI and a timestamp are also supplied.  The RSSI data is used
 * during AP scanning to select a AP to associate with; it can have
 * any units so long as values have consistent units and higher values
 * mean ``better signal''.  The receive timestamp is currently not used
 * by the 802.11 layer.
 */
int
ieee80211_input(ieee80211com_t *ic, mblk_t *mp, struct ieee80211_node *in,
    int32_t rssi, uint32_t rstamp)
{
	struct ieee80211_frame *wh;
	struct ieee80211_key *key;
	uint8_t *bssid;
	int hdrspace;
	int len;
	uint16_t rxseq;
	uint8_t dir;
	uint8_t type;
	uint8_t subtype;
	uint8_t tid;
	uint8_t qos;

	if (mp->b_flag & M_AMPDU) {
		/*
		 * Fastpath for A-MPDU reorder q resubmission.  Frames
		 * w/ M_AMPDU marked have already passed through here
		 * but were received out of order and been held on the
		 * reorder queue.  When resubmitted they are marked
		 * with the M_AMPDU flag and we can bypass most of the
		 * normal processing.
		 */
		IEEE80211_LOCK(ic);
		wh = (struct ieee80211_frame *)mp->b_rptr;
		type = IEEE80211_FC0_TYPE_DATA;
		dir = wh->i_fc[1] & IEEE80211_FC1_DIR_MASK;
		subtype = IEEE80211_FC0_SUBTYPE_QOS;
		hdrspace = ieee80211_hdrspace(ic, wh);	/* optimize */
		/* clear driver/net80211 flags before passing up */
		mp->b_flag &= ~M_AMPDU;
		goto resubmit_ampdu;
	}

	ASSERT(in != NULL);
	in->in_inact = in->in_inact_reload;
	type = (uint8_t)-1;		/* undefined */
	len = MBLKL(mp);
	if (len < sizeof (struct ieee80211_frame_min)) {
		ieee80211_dbg(IEEE80211_MSG_ANY, "ieee80211_input: "
		    "too short (1): len %u", len);
		goto out;
	}
	/*
	 * Bit of a cheat here, we use a pointer for a 3-address
	 * frame format but don't reference fields past outside
	 * ieee80211_frame_min w/o first validating the data is
	 * present.
	 */
	wh = (struct ieee80211_frame *)mp->b_rptr;
	if ((wh->i_fc[0] & IEEE80211_FC0_VERSION_MASK) !=
	    IEEE80211_FC0_VERSION_0) {
		ieee80211_dbg(IEEE80211_MSG_ANY, "ieee80211_input: "
		    "discard pkt with wrong version %x", wh->i_fc[0]);
		goto out;
	}

	dir = wh->i_fc[1] & IEEE80211_FC1_DIR_MASK;
	type = wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
	subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;

	IEEE80211_LOCK(ic);
	if (!(ic->ic_flags & IEEE80211_F_SCAN)) {
		switch (ic->ic_opmode) {
		case IEEE80211_M_STA:
			bssid = wh->i_addr2;
			if (!IEEE80211_ADDR_EQ(bssid, in->in_bssid))
				goto out_exit_mutex;
			break;
		case IEEE80211_M_IBSS:
		case IEEE80211_M_AHDEMO:
			if (dir != IEEE80211_FC1_DIR_NODS) {
				bssid = wh->i_addr1;
			} else if (type == IEEE80211_FC0_TYPE_CTL) {
				bssid = wh->i_addr1;
			} else {
				if (len < sizeof (struct ieee80211_frame)) {
					ieee80211_dbg(IEEE80211_MSG_ANY,
					    "ieee80211_input: too short(2):"
					    "len %u\n", len);
					goto out_exit_mutex;
				}
				bssid = wh->i_addr3;
			}
			if (type != IEEE80211_FC0_TYPE_DATA)
				break;
			/*
			 * Data frame, validate the bssid.
			 */
			if (!IEEE80211_ADDR_EQ(bssid, ic->ic_bss->in_bssid) &&
			    !IEEE80211_ADDR_EQ(bssid, wifi_bcastaddr)) {
				/* not interested in */
				ieee80211_dbg(IEEE80211_MSG_INPUT,
				    "ieee80211_input: not to bss %s\n",
				    ieee80211_macaddr_sprintf(bssid));
				goto out_exit_mutex;
			}
			/*
			 * For adhoc mode we cons up a node when it doesn't
			 * exist. This should probably done after an ACL check.
			 */
			if (in == ic->ic_bss &&
			    ic->ic_opmode != IEEE80211_M_HOSTAP &&
			    !IEEE80211_ADDR_EQ(wh->i_addr2, in->in_macaddr)) {
				/*
				 * Fake up a node for this newly
				 * discovered member of the IBSS.
				 */
				in = ieee80211_fakeup_adhoc_node(&ic->ic_sta,
				    wh->i_addr2);
				if (in == NULL) {
					/* NB: stat kept for alloc failure */
					goto out_exit_mutex;
				}
			}
			break;
		default:
			goto out_exit_mutex;
		}
		in->in_rssi = (uint8_t)rssi;
		in->in_rstamp = rstamp;
		if (!(type & IEEE80211_FC0_TYPE_CTL)) {
			if (IEEE80211_QOS_HAS_SEQ(wh)) {
				tid = ((struct ieee80211_qosframe *)wh)->
				    i_qos[0] & IEEE80211_QOS_TID;
				if (TID_TO_WME_AC(tid) >= WME_AC_VI)
					ic->ic_wme.wme_hipri_traffic++;
				tid++;
			} else {
				tid = IEEE80211_NONQOS_TID;
			}
			rxseq = LE_16(*(uint16_t *)wh->i_seq);
			if ((in->in_flags & IEEE80211_NODE_HT) == 0 &&
			    (wh->i_fc[1] & IEEE80211_FC1_RETRY) &&
			    (rxseq - in->in_rxseqs[tid]) <= 0) {
				/* duplicate, discard */
				ieee80211_dbg(IEEE80211_MSG_INPUT,
				    "ieee80211_input: duplicate",
				    "seqno <%u,%u> fragno <%u,%u> tid %u",
				    rxseq >> IEEE80211_SEQ_SEQ_SHIFT,
				    in->in_rxseqs[tid] >>
				    IEEE80211_SEQ_SEQ_SHIFT,
				    rxseq & IEEE80211_SEQ_FRAG_MASK,
				    in->in_rxseqs[tid] &
				    IEEE80211_SEQ_FRAG_MASK,
				    tid);
				ic->ic_stats.is_rx_dups++;
				goto out_exit_mutex;
			}
			in->in_rxseqs[tid] = rxseq;
		}
	}

	switch (type) {
	case IEEE80211_FC0_TYPE_DATA:
		hdrspace = ieee80211_hdrspace(ic, wh);
		if (len < hdrspace) {
			ieee80211_dbg(IEEE80211_MSG_ANY, "ieee80211_input: "
			    "data too short: expecting %u", hdrspace);
			goto out_exit_mutex;
		}
		switch (ic->ic_opmode) {
		case IEEE80211_M_STA:
			if (dir != IEEE80211_FC1_DIR_FROMDS) {
				ieee80211_dbg(IEEE80211_MSG_INPUT,
				    "ieee80211_input: data ",
				    "unknown dir 0x%x", dir);
				goto out_exit_mutex;
			}
			if (IEEE80211_IS_MULTICAST(wh->i_addr1) &&
			    IEEE80211_ADDR_EQ(wh->i_addr3, ic->ic_macaddr)) {
				/*
				 * In IEEE802.11 network, multicast packet
				 * sent from me is broadcasted from AP.
				 * It should be silently discarded for
				 * SIMPLEX interface.
				 */
				ieee80211_dbg(IEEE80211_MSG_INPUT,
				    "ieee80211_input: multicast echo\n");
				goto out_exit_mutex;
			}
			break;
		case IEEE80211_M_IBSS:
		case IEEE80211_M_AHDEMO:
			if (dir != IEEE80211_FC1_DIR_NODS) {
				ieee80211_dbg(IEEE80211_MSG_INPUT,
				    "ieee80211_input: unknown dir 0x%x",
				    dir);
				goto out_exit_mutex;
			}
			break;
		default:
			ieee80211_err("ieee80211_input: "
			    "receive data, unknown opmode %u, skip\n",
			    ic->ic_opmode);
			goto out_exit_mutex;
		}

		/*
		 * Handle A-MPDU re-ordering.  The station must be
		 * associated and negotiated HT.  The frame must be
		 * a QoS frame (not QoS null data) and not previously
		 * processed for A-MPDU re-ordering.  If the frame is
		 * to be processed directly then ieee80211_ampdu_reorder
		 * will return 0; otherwise it has consumed the mbuf
		 * and we should do nothing more with it.
		 */
		if ((in->in_flags & IEEE80211_NODE_HT) &&
		    (subtype == IEEE80211_FC0_SUBTYPE_QOS)) {
			IEEE80211_UNLOCK(ic);
			if (ieee80211_ampdu_reorder(in, mp) != 0) {
				mp = NULL;	/* CONSUMED */
				goto out;
			}
			IEEE80211_LOCK(ic);
		}
	resubmit_ampdu:

		/*
		 * Handle privacy requirements.
		 */
		if (wh->i_fc[1] & IEEE80211_FC1_WEP) {
			if ((ic->ic_flags & IEEE80211_F_PRIVACY) == 0) {
				/*
				 * Discard encrypted frames when privacy off.
				 */
				ieee80211_dbg(IEEE80211_MSG_INPUT,
				    "ieee80211_input: ""WEP PRIVACY off");
				ic->ic_stats.is_wep_errors++;
				goto out_exit_mutex;
			}
			key = ieee80211_crypto_decap(ic, mp, hdrspace);
			if (key == NULL) {
				/* NB: stats+msgs handled in crypto_decap */
				ic->ic_stats.is_wep_errors++;
				goto out_exit_mutex;
			}
			wh = (struct ieee80211_frame *)mp->b_rptr;
			wh->i_fc[1] &= ~IEEE80211_FC1_WEP;
		} else {
			key = NULL;
		}

		/*
		 * Save QoS bits for use below--before we strip the header.
		 */
		if (subtype == IEEE80211_FC0_SUBTYPE_QOS) {
			qos = (dir == IEEE80211_FC1_DIR_DSTODS) ?
			    ((struct ieee80211_qosframe_addr4 *)wh)->i_qos[0] :
			    ((struct ieee80211_qosframe *)wh)->i_qos[0];
		} else {
			qos = 0;
		}

		/*
		 * Next up, any fragmentation
		 */
		if (!IEEE80211_IS_MULTICAST(wh->i_addr1)) {
			mp = ieee80211_defrag(ic, in, mp, hdrspace);
			if (mp == NULL) {
				/* Fragment dropped or frame not complete yet */
				goto out_exit_mutex;
			}
		}
		wh = NULL;	/* no longer valid, catch any uses */

		/*
		 * Next strip any MSDU crypto bits.
		 */
		if (key != NULL && !ieee80211_crypto_demic(ic, key, mp, 0)) {
			ieee80211_dbg(IEEE80211_MSG_INPUT, "ieee80211_input: "
			    "data demic error\n");
			goto out_exit_mutex;
		}

		if (qos & IEEE80211_QOS_AMSDU) {
			ieee80211_dbg(IEEE80211_MSG_INPUT | IEEE80211_MSG_HT,
			    "ieee80211_input: QOS_AMSDU (%x)\n", qos);

			mp = ieee80211_decap_amsdu(in, mp);
			if (mp == NULL)		/* MSDU processed by HT */
				goto out_exit_mutex;
		}

		ic->ic_stats.is_rx_frags++;
		ic->ic_stats.is_rx_bytes += len;
		IEEE80211_UNLOCK(ic);
		mac_rx(ic->ic_mach, NULL, mp);
		return (IEEE80211_FC0_TYPE_DATA);

	case IEEE80211_FC0_TYPE_MGT:
		if (dir != IEEE80211_FC1_DIR_NODS)
			goto out_exit_mutex;
		if (len < sizeof (struct ieee80211_frame))
			goto out_exit_mutex;
		if (wh->i_fc[1] & IEEE80211_FC1_WEP) {
			if (subtype != IEEE80211_FC0_SUBTYPE_AUTH) {
				/*
				 * Only shared key auth frames with a challenge
				 * should be encrypted, discard all others.
				 */
				ieee80211_dbg(IEEE80211_MSG_INPUT,
				    "ieee80211_input: "
				    "%s WEP set but not permitted",
				    IEEE80211_SUBTYPE_NAME(subtype));
				ic->ic_stats.is_wep_errors++;
				goto out_exit_mutex;
			}
			if ((ic->ic_flags & IEEE80211_F_PRIVACY) == 0) {
				/*
				 * Discard encrypted frames when privacy off.
				 */
				ieee80211_dbg(IEEE80211_MSG_INPUT,
				    "ieee80211_input: "
				    "mgt WEP set but PRIVACY off");
				ic->ic_stats.is_wep_errors++;
				goto out_exit_mutex;
			}
			hdrspace = ieee80211_hdrspace(ic, wh);
			key = ieee80211_crypto_decap(ic, mp, hdrspace);
			if (key == NULL) {
				/* NB: stats+msgs handled in crypto_decap */
				goto out_exit_mutex;
			}
			wh = (struct ieee80211_frame *)mp->b_rptr;
			wh->i_fc[1] &= ~IEEE80211_FC1_WEP;
		}
		IEEE80211_UNLOCK(ic);
		ic->ic_recv_mgmt(ic, mp, in, subtype, rssi, rstamp);
		goto out;

	case IEEE80211_FC0_TYPE_CTL:
		if (ic->ic_opmode == IEEE80211_M_HOSTAP) {
			switch (subtype) {
			case IEEE80211_FC0_SUBTYPE_BAR:
				ieee80211_recv_bar(in, mp);
				break;
			}
		}
		break;

	default:
		ieee80211_dbg(IEEE80211_MSG_ANY, "ieee80211_input: "
		    "bad frame type 0x%x", type);
		/* should not come here */
		break;
	}
out_exit_mutex:
	IEEE80211_UNLOCK(ic);
out:
	if (mp != NULL)
		freemsg(mp);

	return (type);
}

/*
 * This function reassemble fragments.
 * More fragments bit in the frame control means the packet is fragmented.
 * While the sequence control field consists of 4-bit fragment number
 * field and a 12-bit sequence number field.
 */
/* ARGSUSED */
static mblk_t *
ieee80211_defrag(ieee80211com_t *ic, struct ieee80211_node *in, mblk_t *mp,
    int hdrspace)
{
	struct ieee80211_frame *wh = (struct ieee80211_frame *)mp->b_rptr;
	struct ieee80211_frame *lwh;
	mblk_t *mfrag;
	uint16_t rxseq;
	uint8_t fragno;
	uint8_t more_frag;

	ASSERT(!IEEE80211_IS_MULTICAST(wh->i_addr1));
	more_frag = wh->i_fc[1] & IEEE80211_FC1_MORE_FRAG;
	rxseq = LE_16(*(uint16_t *)wh->i_seq);
	fragno = rxseq & IEEE80211_SEQ_FRAG_MASK;

	/* Quick way out, if there's nothing to defragment */
	if (!more_frag && fragno == 0 && in->in_rxfrag == NULL)
		return (mp);

	/*
	 * Remove frag to insure it doesn't get reaped by timer.
	 */
	if (in->in_table == NULL) {
		/*
		 * Should never happen.  If the node is orphaned (not in
		 * the table) then input packets should not reach here.
		 * Otherwise, a concurrent request that yanks the table
		 * should be blocked by other interlocking and/or by first
		 * shutting the driver down.  Regardless, be defensive
		 * here and just bail
		 */
		freemsg(mp);
		return (NULL);
	}
	IEEE80211_NODE_LOCK(in->in_table);
	mfrag = in->in_rxfrag;
	in->in_rxfrag = NULL;
	IEEE80211_NODE_UNLOCK(in->in_table);

	/*
	 * Validate new fragment is in order and
	 * related to the previous ones.
	 */
	if (mfrag != NULL) {
		uint16_t last_rxseq;

		lwh = (struct ieee80211_frame *)mfrag->b_rptr;
		last_rxseq = LE_16(*(uint16_t *)lwh->i_seq);
		/*
		 * Sequence control field contains 12-bit sequence no
		 * and 4-bit fragment number. For fragemnts, the
		 * sequence no is not changed.
		 * NB: check seq # and frag together
		 */
		if (rxseq != last_rxseq + 1 ||
		    !IEEE80211_ADDR_EQ(wh->i_addr1, lwh->i_addr1) ||
		    !IEEE80211_ADDR_EQ(wh->i_addr2, lwh->i_addr2)) {
			/*
			 * Unrelated fragment or no space for it,
			 * clear current fragments.
			 */
			freemsg(mfrag);
			mfrag = NULL;
		}
	}

	if (mfrag == NULL) {
		if (fragno != 0) {	/* !first fragment, discard */
			freemsg(mp);
			return (NULL);
		}
		mfrag = mp;
	} else {			/* concatenate */
		(void) adjmsg(mp, hdrspace);
		linkb(mfrag, mp);
		/* track last seqnum and fragno */
		lwh = (struct ieee80211_frame *)mfrag->b_rptr;
		*(uint16_t *)lwh->i_seq = *(uint16_t *)wh->i_seq;
	}
	if (more_frag != 0) {		/* more to come, save */
		in->in_rxfragstamp = ddi_get_lbolt();
		in->in_rxfrag = mfrag;
		mfrag = NULL;
	}

	return (mfrag);
}

/*
 * Install received rate set information in the node's state block.
 */
int
ieee80211_setup_rates(struct ieee80211_node *in, const uint8_t *rates,
    const uint8_t *xrates, int flags)
{
	struct ieee80211_rateset *rs = &in->in_rates;

	bzero(rs, sizeof (*rs));
	rs->ir_nrates = rates[1];
	/* skip 1 byte element ID and 1 byte length */
	bcopy(rates + 2, rs->ir_rates, rs->ir_nrates);
	if (xrates != NULL) {
		uint8_t nxrates;

		/*
		 * Tack on 11g extended supported rate element.
		 */
		nxrates = xrates[1];
		if (rs->ir_nrates + nxrates > IEEE80211_RATE_MAXSIZE) {
			nxrates = IEEE80211_RATE_MAXSIZE - rs->ir_nrates;
			ieee80211_dbg(IEEE80211_MSG_XRATE,
			    "ieee80211_setup_rates: %s",
			    "[%s] extended rate set too large;"
			    " only using %u of %u rates\n",
			    ieee80211_macaddr_sprintf(in->in_macaddr),
			    nxrates, xrates[1]);
		}
		bcopy(xrates + 2, rs->ir_rates + rs->ir_nrates, nxrates);
		rs->ir_nrates += nxrates;
	}
	return (ieee80211_fix_rate(in, &in->in_rates, flags));
}

/*
 * Process open-system authentication response frame and start
 * association if the authentication request is accepted.
 */
static void
ieee80211_auth_open(ieee80211com_t *ic, struct ieee80211_frame *wh,
    struct ieee80211_node *in, uint16_t seq, uint16_t status)
{
	IEEE80211_LOCK_ASSERT(ic);
	if (in->in_authmode == IEEE80211_AUTH_SHARED) {
		ieee80211_dbg(IEEE80211_MSG_AUTH,
		    "open auth: bad sta auth mode %u", in->in_authmode);
		return;
	}
	if (ic->ic_opmode == IEEE80211_M_STA) {
		if (ic->ic_state != IEEE80211_S_AUTH ||
		    seq != IEEE80211_AUTH_OPEN_RESPONSE) {
			return;
		}
		IEEE80211_UNLOCK(ic);
		if (status != 0) {
			ieee80211_dbg(IEEE80211_MSG_DEBUG | IEEE80211_MSG_AUTH,
			    "open auth failed (reason %d)\n", status);
			if (in != ic->ic_bss)
				in->in_fails++;
			ieee80211_new_state(ic, IEEE80211_S_SCAN, 0);
		} else {
			/* i_fc[0] - frame control's type & subtype field */
			ieee80211_new_state(ic, IEEE80211_S_ASSOC,
			    wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK);
		}
		IEEE80211_LOCK(ic);
	} else {
		ieee80211_dbg(IEEE80211_MSG_AUTH, "ieee80211_auth_open: "
		    "bad operating mode %u", ic->ic_opmode);
	}
}

/*
 * Allocate challenge text for use by shared-key authentication
 * Return B_TRUE on success, B_FALST otherwise.
 */
static boolean_t
ieee80211_alloc_challenge(struct ieee80211_node *in)
{
	if (in->in_challenge == NULL) {
		in->in_challenge = kmem_alloc(IEEE80211_CHALLENGE_LEN,
		    KM_NOSLEEP);
	}
	if (in->in_challenge == NULL) {
		ieee80211_dbg(IEEE80211_MSG_DEBUG | IEEE80211_MSG_AUTH,
		    "[%s] shared key challenge alloc failed\n",
		    ieee80211_macaddr_sprintf(in->in_macaddr));
	}
	return (in->in_challenge != NULL);
}

/*
 * Process shared-key authentication response frames. If authentication
 * succeeds, start association; otherwise, restart scan.
 */
static void
ieee80211_auth_shared(ieee80211com_t *ic, struct ieee80211_frame *wh,
    uint8_t *frm, uint8_t *efrm, struct ieee80211_node *in, uint16_t seq,
    uint16_t status)
{
	uint8_t *challenge;

	/*
	 * Pre-shared key authentication is evil; accept
	 * it only if explicitly configured (it is supported
	 * mainly for compatibility with clients like OS X).
	 */
	IEEE80211_LOCK_ASSERT(ic);
	if (in->in_authmode != IEEE80211_AUTH_AUTO &&
	    in->in_authmode != IEEE80211_AUTH_SHARED) {
		ieee80211_dbg(IEEE80211_MSG_AUTH, "ieee80211_auth_shared: "
		    "bad sta auth mode %u", in->in_authmode);
		goto bad;
	}

	challenge = NULL;
	if (frm + 1 < efrm) {
		/*
		 * Challenge text information element
		 * frm[0] - element ID
		 * frm[1] - length
		 * frm[2]... - challenge text
		 */
		if ((frm[1] + 2) > (_PTRDIFF(efrm, frm))) {
			ieee80211_dbg(IEEE80211_MSG_AUTH,
			    "ieee80211_auth_shared: ie %d%d too long\n",
			    frm[0], (frm[1] + 2) - (_PTRDIFF(efrm, frm)));
			goto bad;
		}
		if (*frm == IEEE80211_ELEMID_CHALLENGE)
			challenge = frm;
		frm += frm[1] + 2;
	}
	switch (seq) {
	case IEEE80211_AUTH_SHARED_CHALLENGE:
	case IEEE80211_AUTH_SHARED_RESPONSE:
		if (challenge == NULL) {
			ieee80211_dbg(IEEE80211_MSG_AUTH,
			    "ieee80211_auth_shared: no challenge\n");
			goto bad;
		}
		if (challenge[1] != IEEE80211_CHALLENGE_LEN) {
			ieee80211_dbg(IEEE80211_MSG_AUTH,
			    "ieee80211_auth_shared: bad challenge len %d\n",
			    challenge[1]);
			goto bad;
		}
	default:
		break;
	}
	switch (ic->ic_opmode) {
	case IEEE80211_M_STA:
		if (ic->ic_state != IEEE80211_S_AUTH)
			return;
		switch (seq) {
		case IEEE80211_AUTH_SHARED_PASS:
			if (in->in_challenge != NULL) {
				kmem_free(in->in_challenge,
				    IEEE80211_CHALLENGE_LEN);
				in->in_challenge = NULL;
			}
			if (status != 0) {
				ieee80211_dbg(IEEE80211_MSG_DEBUG |
				    IEEE80211_MSG_AUTH,
				    "shared key auth failed (reason %d)\n",
				    status);
				if (in != ic->ic_bss)
					in->in_fails++;
				return;
			}
			IEEE80211_UNLOCK(ic);
			ieee80211_new_state(ic, IEEE80211_S_ASSOC,
			    wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK);
			IEEE80211_LOCK(ic);
			break;
		case IEEE80211_AUTH_SHARED_CHALLENGE:
			if (!ieee80211_alloc_challenge(in))
				return;
			bcopy(&challenge[2], in->in_challenge, challenge[1]);
			IEEE80211_UNLOCK(ic);
			IEEE80211_SEND_MGMT(ic, in, IEEE80211_FC0_SUBTYPE_AUTH,
			    seq + 1);
			IEEE80211_LOCK(ic);
			break;
		default:
			ieee80211_dbg(IEEE80211_MSG_AUTH, "80211_auth_shared: "
			    "shared key auth: bad seq %d", seq);
			return;
		}
		break;

	default:
		ieee80211_dbg(IEEE80211_MSG_AUTH,
		    "ieee80211_auth_shared: bad opmode %u\n",
		    ic->ic_opmode);
		break;
	}
	return;
bad:
	if (ic->ic_opmode == IEEE80211_M_STA) {
		/*
		 * Kick the state machine.  This short-circuits
		 * using the mgt frame timeout to trigger the
		 * state transition.
		 */
		if (ic->ic_state == IEEE80211_S_AUTH) {
			IEEE80211_UNLOCK(ic);
			ieee80211_new_state(ic, IEEE80211_S_SCAN, 0);
			IEEE80211_LOCK(ic);
		}
	}
}

static int
iswpaoui(const uint8_t *frm)
{
	uint32_t c;
	bcopy(frm + 2, &c, 4);
	return (frm[1] > 3 && LE_32(c) == ((WPA_OUI_TYPE << 24) | WPA_OUI));
}

#define	LE_READ_4(p)							\
	((uint32_t)							\
	((((uint8_t *)(p))[0]) | (((uint8_t *)(p))[1] <<  8) |		\
	(((uint8_t *)(p))[2] << 16) | (((uint8_t *)(p))[3] << 24)))

#define	LE_READ_2(p)							\
	((uint16_t)							\
	(((uint8_t *)(p))[0]) | (((uint8_t *)(p))[1] <<  8))

static int
iswmeoui(const uint8_t *frm)
{
	return (frm[1] > 3 && LE_READ_4(frm+2) == ((WME_OUI_TYPE<<24)|WME_OUI));
}

static int
iswmeparam(const uint8_t *frm)
{
	return (frm[1] > 5 &&
	    LE_READ_4(frm+2) == ((WME_OUI_TYPE<<24)|WME_OUI) &&
	    frm[6] == WME_PARAM_OUI_SUBTYPE);
}

static int
iswmeinfo(const uint8_t *frm)
{
	return (frm[1] > 5 &&
	    LE_READ_4(frm+2) == ((WME_OUI_TYPE<<24)|WME_OUI) &&
	    frm[6] == WME_INFO_OUI_SUBTYPE);
}

static int
ishtcapoui(const uint8_t *frm)
{
	return (frm[1] > 3 &&
	    LE_READ_4(frm+2) == ((BCM_OUI_HTCAP<<24)|BCM_OUI));
}

static int
ishtinfooui(const uint8_t *frm)
{
	return (frm[1] > 3 &&
	    LE_READ_4(frm+2) == ((BCM_OUI_HTINFO<<24)|BCM_OUI));
}

/* ARGSUSED */
static int
ieee80211_parse_wmeparams(struct ieee80211com *ic, uint8_t *frm,
	const struct ieee80211_frame *wh)
{
#define	MS(_v, _f)	(((_v) & _f) >> _f##_S)
	struct ieee80211_wme_state *wme = &ic->ic_wme;
	uint_t len = frm[1];
	uint8_t qosinfo;
	int i;

	if (len < sizeof (struct ieee80211_wme_param) - 2) {
		ieee80211_dbg(IEEE80211_MSG_ELEMID | IEEE80211_MSG_WME,
		    "WME too short, len %u", len);
		return (-1);
	}
	qosinfo = frm[offsetof(struct ieee80211_wme_param, wme_qosInfo)];
	qosinfo &= WME_QOSINFO_COUNT;
	/* do proper check for wraparound */
	if (qosinfo == wme->wme_wmeChanParams.cap_info)
		return (0);
	frm += offsetof(struct ieee80211_wme_param, wme_acParams);
	for (i = 0; i < WME_NUM_AC; i++) {
		struct wmeParams *wmep =
		    &wme->wme_wmeChanParams.cap_wmeParams[i];
		/* NB: ACI not used */
		wmep->wmep_acm = MS(frm[0], WME_PARAM_ACM);
		wmep->wmep_aifsn = MS(frm[0], WME_PARAM_AIFSN);
		wmep->wmep_logcwmin = MS(frm[1], WME_PARAM_LOGCWMIN);
		wmep->wmep_logcwmax = MS(frm[1], WME_PARAM_LOGCWMAX);
		wmep->wmep_txopLimit = LE_READ_2(frm+2);
		frm += 4;
	}
	wme->wme_wmeChanParams.cap_info = qosinfo;
	return (1);
#undef MS
}

/*
 * Process a beacon/probe response frame.
 * When the device is in station mode, create a node and add it
 * to the node database for a new ESS or update node info if it's
 * already there.
 */
static void
ieee80211_recv_beacon(ieee80211com_t *ic, mblk_t *mp, struct ieee80211_node *in,
    int subtype, int rssi, uint32_t rstamp)
{
	ieee80211_impl_t *im = ic->ic_private;
	struct ieee80211_frame *wh;
	uint8_t *frm;
	uint8_t *efrm;	/* end of frame body */
	struct ieee80211_scanparams scan;

	wh = (struct ieee80211_frame *)mp->b_rptr;
	frm = (uint8_t *)&wh[1];
	efrm = (uint8_t *)mp->b_wptr;

	ic->ic_beaconmiss = 0;	/* clear beacon miss counter */

	/*
	 * We process beacon/probe response frames:
	 *    o when scanning, or
	 *    o station mode when associated (to collect state
	 *	updates such as 802.11g slot time), or
	 *    o adhoc mode (to discover neighbors)
	 * Frames otherwise received are discarded.
	 */
	if (!((ic->ic_flags & IEEE80211_F_SCAN) ||
	    (ic->ic_opmode == IEEE80211_M_STA && in->in_associd != 0) ||
	    ic->ic_opmode == IEEE80211_M_IBSS)) {
		return;
	}

	/*
	 * beacon/probe response frame format
	 *	[8] time stamp
	 *	[2] beacon interval
	 *	[2] capability information
	 *	[tlv] ssid
	 *	[tlv] supported rates
	 *	[tlv] country information
	 *	[tlv] parameter set (FH/DS)
	 *	[tlv] erp information
	 *	[tlv] extended supported rates
	 *	[tlv] WME
	 *	[tlv] WPA or RSN
	 *	[tlv] HT capabilities
	 *	[tlv] HT information
	 */
	IEEE80211_VERIFY_LENGTH(_PTRDIFF(efrm, frm),
	    IEEE80211_BEACON_ELEM_MIN, return);
	bzero(&scan, sizeof (scan));
	scan.tstamp  = frm;
	frm += 8;
	scan.bintval = LE_16(*(uint16_t *)frm);
	frm += 2;
	scan.capinfo = LE_16(*(uint16_t *)frm);
	frm += 2;
	scan.bchan = ieee80211_chan2ieee(ic, ic->ic_curchan);
	scan.chan = scan.bchan;

	while (frm < efrm) {
		/* Agere element in beacon */
		if ((*frm == IEEE80211_ELEMID_AGERE1) ||
		    (*frm == IEEE80211_ELEMID_AGERE2)) {
			frm = efrm;
			break;
		}

		IEEE80211_VERIFY_LENGTH(_PTRDIFF(efrm, frm), frm[1], return);
		switch (*frm) {
		case IEEE80211_ELEMID_SSID:
			scan.ssid = frm;
			break;
		case IEEE80211_ELEMID_RATES:
			scan.rates = frm;
			break;
		case IEEE80211_ELEMID_COUNTRY:
			scan.country = frm;
			break;
		case IEEE80211_ELEMID_FHPARMS:
			if (ic->ic_phytype == IEEE80211_T_FH) {
				scan.fhdwell = LE_16(*(uint16_t *)(frm + 2));
				scan.chan = IEEE80211_FH_CHAN(frm[4], frm[5]);
				scan.fhindex = frm[6];
				scan.phytype = IEEE80211_T_FH;
			}
			break;
		case IEEE80211_ELEMID_DSPARMS:
			if (ic->ic_phytype != IEEE80211_T_FH) {
				scan.chan = frm[2];
				scan.phytype = IEEE80211_T_DS;
			}
			break;
		case IEEE80211_ELEMID_TIM:
			scan.tim = frm;
			scan.timoff = _PTRDIFF(frm, mp->b_rptr);
			break;
		case IEEE80211_ELEMID_IBSSPARMS:
			break;
		case IEEE80211_ELEMID_XRATES:
			scan.xrates = frm;
			break;
		case IEEE80211_ELEMID_ERP:
			if (frm[1] != 1) {
				ieee80211_dbg(IEEE80211_MSG_ELEMID,
				    "ieee80211_recv_mgmt: ignore %s, "
				    "invalid ERP element; "
				    "length %u, expecting 1\n",
				    IEEE80211_SUBTYPE_NAME(subtype),
				    frm[1]);
				break;
			}
			scan.erp = frm[2];
			scan.phytype = IEEE80211_T_OFDM;
			break;
		case IEEE80211_ELEMID_HTCAP:
			scan.htcap = frm;
			break;
		case IEEE80211_ELEMID_RSN:
			scan.wpa = frm;
			break;
		case IEEE80211_ELEMID_HTINFO:
			scan.htinfo = frm;
			break;
		case IEEE80211_ELEMID_VENDOR:
			if (iswpaoui(frm))
				scan.wpa = frm;		/* IEEE802.11i D3.0 */
			else if (iswmeparam(frm) || iswmeinfo(frm))
				scan.wme = frm;
			else if (ic->ic_flags_ext & IEEE80211_FEXT_HTCOMPAT) {
				/*
				 * Accept pre-draft HT ie's if the
				 * standard ones have not been seen.
				 */
				if (ishtcapoui(frm)) {
					if (scan.htcap == NULL)
						scan.htcap = frm;
				} else if (ishtinfooui(frm)) {
					if (scan.htinfo == NULL)
						scan.htinfo = frm;
				}
			}
			break;
		default:
			ieee80211_dbg(IEEE80211_MSG_ELEMID,
			    "ieee80211_recv_mgmt: ignore %s,"
			    "unhandled id %u, len %u, totallen %u",
			    IEEE80211_SUBTYPE_NAME(subtype),
			    *frm, frm[1],
			    MBLKL(mp));
			break;
		}
		/* frm[1] - component length */
		frm += IEEE80211_ELEM_LEN(frm[1]);
	}
	IEEE80211_VERIFY_ELEMENT(scan.rates, IEEE80211_RATE_MAXSIZE, return);
	IEEE80211_VERIFY_ELEMENT(scan.ssid, IEEE80211_NWID_LEN, return);
	if (ieee80211_isclr(ic->ic_chan_active, scan.chan)) {
		ieee80211_dbg(IEEE80211_MSG_ELEMID | IEEE80211_MSG_INPUT,
		    "ieee80211_recv_mgmt: ignore %s ,"
		    "invalid channel %u\n",
		    IEEE80211_SUBTYPE_NAME(subtype), scan.chan);
		return;
	}
	if (scan.chan != scan.bchan &&
	    ic->ic_phytype != IEEE80211_T_FH) {
		/*
		 * Frame was received on a channel different from the
		 * one indicated in the DS params element id;
		 * silently discard it.
		 *
		 * NB:	this can happen due to signal leakage.
		 *	But we should take it for FH phy because
		 *	the rssi value should be correct even for
		 *	different hop pattern in FH.
		 */
		ieee80211_dbg(IEEE80211_MSG_ELEMID,
		    "ieee80211_recv_mgmt: ignore %s ,"
		    "phytype %u channel %u marked for %u\n",
		    IEEE80211_SUBTYPE_NAME(subtype),
		    ic->ic_phytype, scan.bchan, scan.chan);
		return;
	}
	if (!(IEEE80211_BINTVAL_MIN <= scan.bintval &&
	    scan.bintval <= IEEE80211_BINTVAL_MAX)) {
		ieee80211_dbg(IEEE80211_MSG_ELEMID | IEEE80211_MSG_INPUT,
		    "ieee80211_recv_mgmt: ignore %s ,"
		    "bogus beacon interval %u\n",
		    IEEE80211_SUBTYPE_NAME(subtype), scan.bintval);
		return;
	}
	/*
	 * Process HT ie's.  This is complicated by our
	 * accepting both the standard ie's and the pre-draft
	 * vendor OUI ie's that some vendors still use/require.
	 */
	if (scan.htcap != NULL) {
		IEEE80211_VERIFY_LENGTH(scan.htcap[1],
		    scan.htcap[0] == IEEE80211_ELEMID_VENDOR ?
		    4 + sizeof (struct ieee80211_ie_htcap) - 2 :
		    sizeof (struct ieee80211_ie_htcap) - 2,
		    scan.htcap = NULL);
	}
	if (scan.htinfo != NULL) {
		IEEE80211_VERIFY_LENGTH(scan.htinfo[1],
		    scan.htinfo[0] == IEEE80211_ELEMID_VENDOR ?
		    4 + sizeof (struct ieee80211_ie_htinfo) - 2 :
		    sizeof (struct ieee80211_ie_htinfo) - 2,
		    scan.htinfo = NULL);
	}

	/*
	 * When operating in station mode, check for state updates.
	 * Be careful to ignore beacons received while doing a
	 * background scan.  We consider only 11g/WMM stuff right now.
	 */
	if (ic->ic_opmode == IEEE80211_M_STA &&
	    in->in_associd != 0 &&
	    (!(ic->ic_flags & IEEE80211_F_SCAN) ||
	    IEEE80211_ADDR_EQ(wh->i_addr2, in->in_bssid))) {
		/* record tsf of last beacon */
		bcopy(scan.tstamp, in->in_tstamp.data,
		    sizeof (in->in_tstamp));
		/* count beacon frame for s/w bmiss handling */
		im->im_swbmiss_count++;
		im->im_bmiss_count = 0;

		if ((in->in_capinfo ^ scan.capinfo) &
		    IEEE80211_CAPINFO_SHORT_SLOTTIME) {
			ieee80211_dbg(IEEE80211_MSG_ASSOC,
			    "ieee80211_recv_mgmt: "
			    "[%s] cap change: before 0x%x, now 0x%x\n",
			    ieee80211_macaddr_sprintf(wh->i_addr2),
			    in->in_capinfo, scan.capinfo);
			/*
			 * NB:	we assume short preamble doesn't
			 *	change dynamically
			 */
			ieee80211_set_shortslottime(ic,
			    ic->ic_curmode == IEEE80211_MODE_11A ||
			    (scan.capinfo &
			    IEEE80211_CAPINFO_SHORT_SLOTTIME));
			in->in_capinfo = scan.capinfo;
		}
		if (scan.wme != NULL &&
		    (in->in_flags & IEEE80211_NODE_QOS) &&
		    ieee80211_parse_wmeparams(ic, scan.wme, wh) > 0) {
			ieee80211_wme_updateparams(ic);
		}
		if (scan.htcap != NULL)
			ieee80211_parse_htcap(in, scan.htcap);
		if (scan.htinfo != NULL) {
			ieee80211_parse_htinfo(in, scan.htinfo);
			if (in->in_chan != ic->ic_curchan) {
				/*
				 * Channel has been adjusted based on
				 * negotiated HT parameters; force the
				 * channel state to follow.
				 */
				ieee80211_setcurchan(ic, in->in_chan);
			}
		}
		if (scan.tim != NULL) {
			struct ieee80211_tim_ie *ie;

			ie = (struct ieee80211_tim_ie *)scan.tim;
			in->in_dtim_count = ie->tim_count;
			in->in_dtim_period = ie->tim_period;
		}
		if (ic->ic_flags & IEEE80211_F_SCAN) {
			ieee80211_add_scan(ic, &scan, wh, subtype, rssi,
			    rstamp);
		}
		return;
	}
	/*
	 * If scanning, just pass information to the scan module.
	 */
	if (ic->ic_flags & IEEE80211_F_SCAN) {
		ieee80211_add_scan(ic, &scan, wh, subtype, rssi, rstamp);
		return;
	}

	if (ic->ic_opmode == IEEE80211_M_IBSS &&
	    scan.capinfo & IEEE80211_CAPINFO_IBSS) {
		if (!IEEE80211_ADDR_EQ(wh->i_addr2, in->in_macaddr)) {
			/*
			 * Create a new entry in the neighbor table.
			 */
			in = ieee80211_add_neighbor(ic, wh, &scan);
		} else {
			/*
			 * Copy data from beacon to neighbor table.
			 * Some of this information might change after
			 * ieee80211_add_neighbor(), so we just copy
			 * everything over to be safe.
			 */
			ieee80211_init_neighbor(in, wh, &scan);
		}
		if (in != NULL) {
			in->in_rssi = (uint8_t)rssi;
			in->in_rstamp = rstamp;
		}
	}
}

/*
 * Perform input processing for 802.11 management frames.
 * It's the default ic_recv_mgmt callback function for the interface
 * softc, ic. Tipically ic_recv_mgmt is called within ieee80211_input()
 */
void
ieee80211_recv_mgmt(ieee80211com_t *ic, mblk_t *mp, struct ieee80211_node *in,
    int subtype, int rssi, uint32_t rstamp)
{
	struct ieee80211_frame *wh;
	uint8_t *frm;		/* pointer to start of the frame */
	uint8_t *efrm;		/* pointer to end of the frame */
	uint8_t *ssid;
	uint8_t *rates;
	uint8_t *xrates;	/* extended rates */
	uint8_t	*wme;
	uint8_t *htcap, *htinfo;
	boolean_t allocbs = B_FALSE;
	uint8_t rate;
	uint16_t algo;		/* authentication algorithm */
	uint16_t seq;		/* sequence no */
	uint16_t status;
	uint16_t capinfo;
	uint16_t associd;	/* association ID */
	const struct ieee80211_action *ia;

	IEEE80211_LOCK(ic);
	wh = (struct ieee80211_frame *)mp->b_rptr;
	frm = (uint8_t *)&wh[1];
	efrm = (uint8_t *)mp->b_wptr;
	switch (subtype) {
	case IEEE80211_FC0_SUBTYPE_PROBE_RESP:
	case IEEE80211_FC0_SUBTYPE_BEACON:
		ieee80211_recv_beacon(ic, mp, in, subtype, rssi, rstamp);
		break;

	case IEEE80211_FC0_SUBTYPE_PROBE_REQ:
		if (ic->ic_opmode == IEEE80211_M_STA ||
		    ic->ic_state != IEEE80211_S_RUN ||
		    IEEE80211_IS_MULTICAST(wh->i_addr2)) {
			break;
		}

		/*
		 * prreq frame format
		 *	[tlv] ssid
		 *	[tlv] supported rates
		 *	[tlv] extended supported rates
		 */
		ssid = rates = xrates = NULL;
		while (frm < efrm) {
			IEEE80211_VERIFY_LENGTH(_PTRDIFF(efrm, frm),
			    frm[1], goto out);
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
		IEEE80211_VERIFY_ELEMENT(rates, IEEE80211_RATE_MAXSIZE, break);
		if (xrates != NULL) {
			IEEE80211_VERIFY_ELEMENT(xrates,
			    IEEE80211_RATE_MAXSIZE - rates[1], break);
		}
		IEEE80211_VERIFY_ELEMENT(ssid, IEEE80211_NWID_LEN, break);
		IEEE80211_VERIFY_SSID(ic->ic_bss, ssid, break);
		if (ic->ic_flags & IEEE80211_F_HIDESSID) {
			if (ssid == NULL || ssid[1] == 0) {
				ieee80211_dbg(IEEE80211_MSG_INPUT,
				    "ieee80211_recv_mgmt: ignore %s, "
				    "no ssid with ssid suppression enabled",
				    IEEE80211_SUBTYPE_NAME(subtype));
				break;
			}
		}

		if (in == ic->ic_bss) {
			if (ic->ic_opmode != IEEE80211_M_IBSS) {
				in = ieee80211_tmp_node(ic, wh->i_addr2);
				allocbs = B_TRUE;
			} else if (!IEEE80211_ADDR_EQ(wh->i_addr2,
			    in->in_macaddr)) {
				/*
				 * Cannot tell if the sender is operating
				 * in ibss mode.  But we need a new node to
				 * send the response so blindly add them to the
				 * neighbor table.
				 */
				in = ieee80211_fakeup_adhoc_node(&ic->ic_sta,
				    wh->i_addr2);
			}
			if (in == NULL)
				break;
		}
		ieee80211_dbg(IEEE80211_MSG_ASSOC, "ieee80211_recv_mgmt: "
		    "[%s] recv probe req\n",
		    ieee80211_macaddr_sprintf(wh->i_addr2));
		in->in_rssi = (uint8_t)rssi;
		in->in_rstamp = rstamp;
		/*
		 * Adjust and check station's rate list with device's
		 * supported rate.  Send back response if there is at
		 * least one rate or the fixed rate(if being set) is
		 * supported by both station and the device
		 */
		rate = ieee80211_setup_rates(in, rates, xrates,
		    IEEE80211_F_DOSORT | IEEE80211_F_DOFRATE |
		    IEEE80211_F_DONEGO | IEEE80211_F_DODEL);
		if (rate & IEEE80211_RATE_BASIC) {
			ieee80211_dbg(IEEE80211_MSG_XRATE, "ieee80211_recv_mgmt"
			    "%s recv'd rate set invalid",
			    IEEE80211_SUBTYPE_NAME(subtype));
		} else {
			IEEE80211_UNLOCK(ic);
			IEEE80211_SEND_MGMT(ic, in,
			    IEEE80211_FC0_SUBTYPE_PROBE_RESP, 0);
			IEEE80211_LOCK(ic);
		}
		if (allocbs) {
			/*
			 * Temporary node created just to send a
			 * response, reclaim immediately.
			 */
			ieee80211_free_node(in);
		}
		break;

	case IEEE80211_FC0_SUBTYPE_AUTH:
		/*
		 * auth frame format
		 *	[2] algorithm
		 *	[2] sequence
		 *	[2] status
		 *	[tlv*] challenge
		 */
		IEEE80211_VERIFY_LENGTH(_PTRDIFF(efrm, frm),
		    IEEE80211_AUTH_ELEM_MIN, break);
		algo   = LE_16(*(uint16_t *)frm);
		seq    = LE_16(*(uint16_t *)(frm + 2));
		status = LE_16(*(uint16_t *)(frm + 4));
		ieee80211_dbg(IEEE80211_MSG_AUTH, "ieee80211_recv_mgmt: "
		    "[%s] recv auth frame with algorithm %d seq %d\n",
		    ieee80211_macaddr_sprintf(wh->i_addr2), algo, seq);

		if (ic->ic_flags & IEEE80211_F_COUNTERM) {
			ieee80211_dbg(IEEE80211_MSG_AUTH | IEEE80211_MSG_CRYPTO,
			    "ieee80211_recv_mgmt: ignore auth, %s\n",
			    "TKIP countermeasures enabled");
			break;
		}
		switch (algo) {
		case IEEE80211_AUTH_ALG_SHARED:
			ieee80211_auth_shared(ic, wh, frm + 6, efrm, in,
			    seq, status);
			break;
		case IEEE80211_AUTH_ALG_OPEN:
			ieee80211_auth_open(ic, wh, in, seq, status);
			break;
		default:
			ieee80211_dbg(IEEE80211_MSG_ANY, "ieee80211_recv_mgmt: "
			    "ignore auth, unsupported alg %d", algo);
			break;
		}
		break;

	case IEEE80211_FC0_SUBTYPE_ASSOC_RESP:
	case IEEE80211_FC0_SUBTYPE_REASSOC_RESP:
		if (ic->ic_opmode != IEEE80211_M_STA ||
		    ic->ic_state != IEEE80211_S_ASSOC)
			break;

		/*
		 * asresp frame format
		 *	[2] capability information
		 *	[2] status
		 *	[2] association ID
		 *	[tlv] supported rates
		 *	[tlv] extended supported rates
		 *	[tlv] WME
		 *	[tlv] HT capabilities
		 *	[tlv] HT info
		 */
		IEEE80211_VERIFY_LENGTH(_PTRDIFF(efrm, frm),
		    IEEE80211_ASSOC_RESP_ELEM_MIN, break);
		in = ic->ic_bss;
		capinfo = LE_16(*(uint16_t *)frm);
		frm += 2;
		status = LE_16(*(uint16_t *)frm);
		frm += 2;
		if (status != 0) {
			ieee80211_dbg(IEEE80211_MSG_ASSOC,
			    "assoc failed (reason %d)\n", status);
			in = ieee80211_find_node(&ic->ic_scan, wh->i_addr2);
			if (in != NULL) {
				in->in_fails++;
				ieee80211_free_node(in);
			}
			break;
		}
		associd = LE_16(*(uint16_t *)frm);
		frm += 2;

		rates = xrates = wme = htcap = htinfo = NULL;
		while (frm < efrm) {
			/*
			 * Do not discard frames containing proprietary Agere
			 * elements 128 and 129, as the reported element length
			 * is often wrong. Skip rest of the frame, since we can
			 * not rely on the given element length making it
			 * impossible to know where the next element starts
			 */
			if ((*frm == IEEE80211_ELEMID_AGERE1) ||
			    (*frm == IEEE80211_ELEMID_AGERE2)) {
				frm = efrm;
				break;
			}

			IEEE80211_VERIFY_LENGTH(_PTRDIFF(efrm, frm),
			    frm[1], goto out);
			switch (*frm) {
			case IEEE80211_ELEMID_RATES:
				rates = frm;
				break;
			case IEEE80211_ELEMID_XRATES:
				xrates = frm;
				break;
			case IEEE80211_ELEMID_HTCAP:
				htcap = frm;
				break;
			case IEEE80211_ELEMID_HTINFO:
				htinfo = frm;
				break;
			case IEEE80211_ELEMID_VENDOR:
				if (iswmeoui(frm))
					wme = frm;
				else if (ic->ic_flags_ext &
				    IEEE80211_FEXT_HTCOMPAT) {
					/*
					 * Accept pre-draft HT ie's if the
					 * standard ones have not been seen.
					 */
					if (ishtcapoui(frm)) {
						if (htcap == NULL)
							htcap = frm;
					} else if (ishtinfooui(frm)) {
						if (htinfo == NULL)
							htinfo = frm;
					}
				}
				break;
			}
			frm += frm[1] + 2;
		}

		IEEE80211_VERIFY_ELEMENT(rates, IEEE80211_RATE_MAXSIZE, break);
		/*
		 * Adjust and check AP's rate list with device's
		 * supported rate. Re-start scan if no rate is or the
		 * fixed rate(if being set) cannot be supported by
		 * either AP or the device.
		 */
		rate = ieee80211_setup_rates(in, rates, xrates,
		    IEEE80211_F_DOSORT | IEEE80211_F_DOFRATE |
		    IEEE80211_F_DONEGO | IEEE80211_F_DODEL);
		if (rate & IEEE80211_RATE_BASIC) {
			ieee80211_dbg(IEEE80211_MSG_ASSOC,
			    "assoc failed (rate set mismatch)\n");
			if (in != ic->ic_bss)
				in->in_fails++;
			IEEE80211_UNLOCK(ic);
			ieee80211_new_state(ic, IEEE80211_S_SCAN, 0);
			return;
		}

		in->in_capinfo = capinfo;
		in->in_associd = associd;
		if (wme != NULL &&
		    ieee80211_parse_wmeparams(ic, wme, wh) >= 0) {
			in->in_flags |= IEEE80211_NODE_QOS;
			ieee80211_wme_updateparams(ic);
		} else {
			in->in_flags &= ~IEEE80211_NODE_QOS;
		}
		/*
		 * Setup HT state according to the negotiation.
		 */
		if ((ic->ic_htcaps & IEEE80211_HTC_HT) &&
		    htcap != NULL && htinfo != NULL) {
			ieee80211_ht_node_init(in, htcap);
			ieee80211_parse_htinfo(in, htinfo);
			(void) ieee80211_setup_htrates(in,
			    htcap, IEEE80211_F_JOIN | IEEE80211_F_DOBRS);
			ieee80211_setup_basic_htrates(in, htinfo);
			if (in->in_chan != ic->ic_curchan) {
				/*
				 * Channel has been adjusted based on
				 * negotiated HT parameters; force the
				 * channel state to follow.
				 */
				ieee80211_setcurchan(ic, in->in_chan);
			}
		}
		/*
		 * Configure state now that we are associated.
		 */
		if (ic->ic_curmode == IEEE80211_MODE_11A ||
		    (in->in_capinfo & IEEE80211_CAPINFO_SHORT_PREAMBLE)) {
			ic->ic_flags |= IEEE80211_F_SHPREAMBLE;
			ic->ic_flags &= ~IEEE80211_F_USEBARKER;
		} else {
			ic->ic_flags &= ~IEEE80211_F_SHPREAMBLE;
			ic->ic_flags |= IEEE80211_F_USEBARKER;
		}
		ieee80211_set_shortslottime(ic,
		    ic->ic_curmode == IEEE80211_MODE_11A ||
		    (in->in_capinfo & IEEE80211_CAPINFO_SHORT_SLOTTIME));
		/*
		 * Honor ERP protection.
		 *
		 * NB:	in_erp should zero for non-11g operation.
		 *	check ic_curmode anyway
		 */
		if (ic->ic_curmode == IEEE80211_MODE_11G &&
		    (in->in_erp & IEEE80211_ERP_USE_PROTECTION))
			ic->ic_flags |= IEEE80211_F_USEPROT;
		else
			ic->ic_flags &= ~IEEE80211_F_USEPROT;
		ieee80211_dbg(IEEE80211_MSG_ASSOC,
		    "assoc success: %s preamble, %s slot time%s%s\n",
		    ic->ic_flags&IEEE80211_F_SHPREAMBLE ? "short" : "long",
		    ic->ic_flags&IEEE80211_F_SHSLOT ? "short" : "long",
		    ic->ic_flags&IEEE80211_F_USEPROT ? ", protection" : "",
		    in->in_flags & IEEE80211_NODE_QOS ? ", QoS" : "");
		IEEE80211_UNLOCK(ic);
		ieee80211_new_state(ic, IEEE80211_S_RUN, subtype);
		return;

	case IEEE80211_FC0_SUBTYPE_DEAUTH:
		if (ic->ic_state == IEEE80211_S_SCAN)
			break;

		/*
		 * deauth frame format
		 *	[2] reason
		 */
		IEEE80211_VERIFY_LENGTH(_PTRDIFF(efrm, frm), 2, break);
		status = LE_16(*(uint16_t *)frm);

		ieee80211_dbg(IEEE80211_MSG_AUTH,
		    "recv deauthenticate (reason %d)\n", status);
		switch (ic->ic_opmode) {
		case IEEE80211_M_STA:
			IEEE80211_UNLOCK(ic);
			ieee80211_new_state(ic, IEEE80211_S_AUTH,
			    wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK);
			return;
		default:
			break;
		}
		break;

	case IEEE80211_FC0_SUBTYPE_DISASSOC:
		if (ic->ic_state != IEEE80211_S_RUN &&
		    ic->ic_state != IEEE80211_S_ASSOC &&
		    ic->ic_state != IEEE80211_S_AUTH)
			break;
		/*
		 * disassoc frame format
		 *	[2] reason
		 */
		IEEE80211_VERIFY_LENGTH(_PTRDIFF(efrm, frm), 2, break);
		status = LE_16(*(uint16_t *)frm);

		ieee80211_dbg(IEEE80211_MSG_ASSOC,
		    "recv disassociate (reason %d)\n", status);
		switch (ic->ic_opmode) {
		case IEEE80211_M_STA:
			IEEE80211_UNLOCK(ic);
			ieee80211_new_state(ic, IEEE80211_S_ASSOC,
			    wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK);
			return;
		default:
			break;
		}
		break;

	case IEEE80211_FC0_SUBTYPE_ACTION:
		if (ic->ic_state != IEEE80211_S_RUN &&
		    ic->ic_state != IEEE80211_S_ASSOC &&
		    ic->ic_state != IEEE80211_S_AUTH)
			break;

		/*
		 * action frame format:
		 *	[1] category
		 *	[1] action
		 *	[tlv] parameters
		 */
		IEEE80211_VERIFY_LENGTH(_PTRDIFF(efrm, frm),
		    sizeof (struct ieee80211_action), break);
		ia = (const struct ieee80211_action *) frm;

		/* verify frame payloads but defer processing */
		/* maybe push this to method */
		switch (ia->ia_category) {
		case IEEE80211_ACTION_CAT_BA:
			switch (ia->ia_action) {
			case IEEE80211_ACTION_BA_ADDBA_REQUEST:
			IEEE80211_VERIFY_LENGTH(_PTRDIFF(efrm, frm),
			    sizeof (struct ieee80211_action_ba_addbarequest),
			    break);
			break;
			case IEEE80211_ACTION_BA_ADDBA_RESPONSE:
			IEEE80211_VERIFY_LENGTH(_PTRDIFF(efrm, frm),
			    sizeof (struct ieee80211_action_ba_addbaresponse),
			    break);
			break;
			case IEEE80211_ACTION_BA_DELBA:
			IEEE80211_VERIFY_LENGTH(_PTRDIFF(efrm, frm),
			    sizeof (struct ieee80211_action_ba_delba),
			    break);
			break;
			}
			break;
		case IEEE80211_ACTION_CAT_HT:
			switch (ia->ia_action) {
			case IEEE80211_ACTION_HT_TXCHWIDTH:
			IEEE80211_VERIFY_LENGTH(_PTRDIFF(efrm, frm),
			    sizeof (struct ieee80211_action_ht_txchwidth),
			    break);
			break;
			}
			break;
		}
		ic->ic_recv_action(in, frm, efrm);
		break;

	default:
		ieee80211_dbg(IEEE80211_MSG_ANY, "ieee80211_recv_mgmt: "
		    "subtype 0x%x not handled\n", subtype);
		break;
	} /* switch subtype */
out:
	IEEE80211_UNLOCK(ic);
}
