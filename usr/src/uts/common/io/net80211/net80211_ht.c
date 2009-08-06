/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2007 Sam Leffler, Errno Consulting
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
 * IEEE 802.11n protocol support.
 */
#include <sys/mac_provider.h>
#include <sys/strsun.h>
#include <sys/byteorder.h>

#include "net80211_impl.h"

/* define here, used throughout file */
#define	MS(_v, _f)	(((_v) & _f) >> _f##_S)
#define	SM(_v, _f)	(((_v) << _f##_S) & _f)

/* need max array size */
/* NB: these are for HT20 w/ long GI */
const int ieee80211_htrates[16] = {
	13,		/* IFM_IEEE80211_MCS0 */
	26,		/* IFM_IEEE80211_MCS1 */
	39,		/* IFM_IEEE80211_MCS2 */
	52,		/* IFM_IEEE80211_MCS3 */
	78,		/* IFM_IEEE80211_MCS4 */
	104,		/* IFM_IEEE80211_MCS5 */
	117,		/* IFM_IEEE80211_MCS6 */
	130,		/* IFM_IEEE80211_MCS7 */
	26,		/* IFM_IEEE80211_MCS8 */
	52,		/* IFM_IEEE80211_MCS9 */
	78,		/* IFM_IEEE80211_MCS10 */
	104,		/* IFM_IEEE80211_MCS11 */
	156,		/* IFM_IEEE80211_MCS12 */
	208,		/* IFM_IEEE80211_MCS13 */
	234,		/* IFM_IEEE80211_MCS14 */
	260,		/* IFM_IEEE80211_MCS15 */
};

struct ieee80211_htrateset ieee80211_rateset_11n =
	{ 16, {
	/* MCS: 6.5   13 19.5   26   39  52 58.5  65  13  26 */
		0,   1,   2,   3,   4,  5,   6,  7,  8,  9,
	/* 39   52   78  104  117, 130 */
		10,  11,  12,  13,  14,  15 }
	};

#define	IEEE80211_AMPDU_AGE

#define	IEEE80211_AGGR_TIMEOUT	250		/* msecs */
#define	IEEE80211_AGGR_MINRETRY	(10 * hz)	/* ticks */
#define	IEEE80211_AGGR_MAXTRIES	3

/*
 * Receive processing.
 */

/*
 * Decap the encapsulated A-MSDU frames and dispatch all but
 * the last for delivery.  The last frame is returned for
 * delivery via the normal path.
 */
#define	FF_LLC_SIZE	\
	(sizeof (struct ether_header) + sizeof (struct ieee80211_llc))
mblk_t *
ieee80211_decap_amsdu(struct ieee80211_node *in, mblk_t *mp)
{
	struct ieee80211com *ic = in->in_ic;
	struct ether_header *eh;
	struct ieee80211_frame *wh;
	int framelen, hdrspace;
	mblk_t *m0;

	/* all msdu has same ieee80211_frame header */
	wh = (struct ieee80211_frame *)mp->b_rptr;
	hdrspace = ieee80211_hdrspace(ic, wh);
	mp->b_rptr += hdrspace;	/* A-MSDU subframe follows */

	for (;;) {
		/*
		 * The frame has an 802.3 header followed by an 802.2
		 * LLC header.  The encapsulated frame length is in the
		 * first header type field;
		 */
		if (MBLKL(mp) < FF_LLC_SIZE) {
			ieee80211_err("too short, decap failed\n");
			goto out;
		}
		/*
		 * Decap frames, encapsulate to 802.11 frame then deliver.
		 * 802.3 header is first (struct ether_header)
		 * 802.2 header follows (struct ieee80211_llc)
		 * data, msdu = llc + data
		 */
		eh = (struct ether_header *)mp->b_rptr;
						/* 802.2 header follows */
		framelen = ntohs(eh->ether_type);	/* llc + data */
		m0 = allocb(hdrspace + framelen, BPRI_MED);
		if (m0 == NULL) {
			ieee80211_err("decap_msdu(): can't alloc mblk\n");
			goto out;
		}
		(void) memcpy(m0->b_wptr, (uint8_t *)wh, hdrspace);
		m0->b_wptr += hdrspace;
		(void) memcpy(m0->b_wptr,
		    mp->b_rptr + sizeof (struct ether_header), framelen);
		m0->b_wptr += framelen;

		ic->ic_stats.is_rx_frags++;
		ic->ic_stats.is_rx_bytes += MBLKL(m0);
		IEEE80211_UNLOCK(ic);
		mac_rx(ic->ic_mach, NULL, m0);	/* deliver to mac */
		IEEE80211_LOCK(ic);

		framelen += sizeof (struct ether_header);
		if (MBLKL(mp) == framelen)	/* last, no padding */
			goto out;
		/*
		 * Remove frame contents; each intermediate frame
		 * is required to be aligned to a 4-byte boundary.
		 */
		mp->b_rptr += roundup(framelen, 4);	/* padding */
	}

out:
	freemsg(mp);
	return (NULL);	/* none delivered by caller */
}
#undef FF_LLC_SIZE

/*
 * Start A-MPDU rx/re-order processing for the specified TID.
 */
static void
ampdu_rx_start(struct ieee80211_rx_ampdu *rap, int bufsiz, int start)
{
	(void) memset(rap, 0, sizeof (*rap));
	rap->rxa_wnd = (bufsiz == 0) ? IEEE80211_AGGR_BAWMAX
	    : min((uint16_t)bufsiz, IEEE80211_AGGR_BAWMAX);
	rap->rxa_start = (uint16_t)start;
	rap->rxa_flags |= IEEE80211_AGGR_XCHGPEND;
}

/*
 * Purge all frames in the A-MPDU re-order queue.
 */
static void
ampdu_rx_purge(struct ieee80211_rx_ampdu *rap)
{
	mblk_t *m;
	int i;

	for (i = 0; i < rap->rxa_wnd; i++) {
		m = rap->rxa_m[i];
		if (m != NULL) {
			rap->rxa_m[i] = NULL;
			rap->rxa_qbytes -= MBLKL(m);
			freemsg(m);
			if (--rap->rxa_qframes == 0)
				break;
		}
	}
	ASSERT(rap->rxa_qbytes == 0 && rap->rxa_qframes == 0);
}

/*
 * Stop A-MPDU rx processing for the specified TID.
 */
static void
ampdu_rx_stop(struct ieee80211_rx_ampdu *rap)
{
	rap->rxa_flags &= ~IEEE80211_AGGR_XCHGPEND;
	ampdu_rx_purge(rap);
}

/*
 * Dispatch a frame from the A-MPDU reorder queue.  The
 * frame is fed back into ieee80211_input marked with an
 * M_AMPDU flag so it doesn't come back to us (it also
 * permits ieee80211_input to optimize re-processing).
 */
static void
ampdu_dispatch(struct ieee80211_node *in, mblk_t *m)
{
	m->b_flag |= M_AMPDU;	/* bypass normal processing */
	/* NB: rssi and rstamp are ignored w/ M_AMPDU set */
	(void) ieee80211_input(in->in_ic, m, in, 0, 0);
}

/*
 * Dispatch as many frames as possible from the re-order queue.
 * Frames will always be "at the front"; we process all frames
 * up to the first empty slot in the window.  On completion we
 * cleanup state if there are still pending frames in the current
 * BA window.  We assume the frame at slot 0 is already handled
 * by the caller; we always start at slot 1.
 */
static void
ampdu_rx_dispatch(struct ieee80211_rx_ampdu *rap, struct ieee80211_node *in)
{
	mblk_t *m;
	int i;

	/* flush run of frames */
	for (i = 1; i < rap->rxa_wnd; i++) {
		m = rap->rxa_m[i];
		if (m == NULL)
			break;
		rap->rxa_m[i] = NULL;
		rap->rxa_qbytes -= MBLKL(m);
		rap->rxa_qframes--;

		ampdu_dispatch(in, m);
	}
	/*
	 * If frames remain, copy the mbuf pointers down so
	 * they correspond to the offsets in the new window.
	 */
	if (rap->rxa_qframes != 0) {
		int n = rap->rxa_qframes, j;
		for (j = i+1; j < rap->rxa_wnd; j++) {
			if (rap->rxa_m[j] != NULL) {
				rap->rxa_m[j-i] = rap->rxa_m[j];
				rap->rxa_m[j] = NULL;
				if (--n == 0)
					break;
			}
		}
		ASSERT(n == 0);
	}
	/*
	 * Adjust the start of the BA window to
	 * reflect the frames just dispatched.
	 */
	rap->rxa_start = IEEE80211_SEQ_ADD(rap->rxa_start, i);
}

#ifdef IEEE80211_AMPDU_AGE
/*
 * Dispatch all frames in the A-MPDU re-order queue.
 */
static void
ampdu_rx_flush(struct ieee80211_node *in, struct ieee80211_rx_ampdu *rap)
{
	mblk_t *m;
	int i;

	ieee80211_dbg(IEEE80211_MSG_HT,
	    "ampdu_rx_flush(%d)\n",
	    rap->rxa_wnd);

	for (i = 0; i < rap->rxa_wnd; i++) {
		m = rap->rxa_m[i];
		if (m == NULL)
			continue;
		rap->rxa_m[i] = NULL;
		rap->rxa_qbytes -= MBLKL(m);
		rap->rxa_qframes--;

		ampdu_dispatch(in, m);
		if (rap->rxa_qframes == 0)
			break;
	}
}
#endif /* IEEE80211_AMPDU_AGE */

/*
 * Dispatch all frames in the A-MPDU re-order queue
 * preceding the specified sequence number.  This logic
 * handles window moves due to a received MSDU or BAR.
 */
static void
ampdu_rx_flush_upto(struct ieee80211_node *in,
	struct ieee80211_rx_ampdu *rap, ieee80211_seq winstart)
{
	mblk_t *m;
	ieee80211_seq seqno;
	int i;

	/*
	 * Flush any complete MSDU's with a sequence number lower
	 * than winstart.  Gaps may exist.  Note that we may actually
	 * dispatch frames past winstart if a run continues; this is
	 * an optimization that avoids having to do a separate pass
	 * to dispatch frames after moving the BA window start.
	 */
	seqno = rap->rxa_start;
	for (i = 0; i < rap->rxa_wnd; i++) {
		m = rap->rxa_m[i];
		if (m != NULL) {
			rap->rxa_m[i] = NULL;
			rap->rxa_qbytes -= MBLKL(m);
			rap->rxa_qframes--;

			ampdu_dispatch(in, m);
		} else {
			if (!IEEE80211_SEQ_BA_BEFORE(seqno, winstart))
				break;
		}
		seqno = IEEE80211_SEQ_INC(seqno);
	}
	/*
	 * If frames remain, copy the mbuf pointers down so
	 * they correspond to the offsets in the new window.
	 */
	if (rap->rxa_qframes != 0) {
		int n = rap->rxa_qframes, j;
		for (j = i+1; j < rap->rxa_wnd; j++) {
			if (rap->rxa_m[j] != NULL) {
				rap->rxa_m[j-i] = rap->rxa_m[j];
				rap->rxa_m[j] = NULL;
				if (--n == 0)
					break;
			}
		}
		if (n != 0) {
			ieee80211_dbg(IEEE80211_MSG_HT,
			    "ampdu_rx_flush_upto(): "
			    "lost %d frames, qframes %d off %d "
			    "BA win <%d:%d> winstart %d\n",
			    n, rap->rxa_qframes, i, rap->rxa_start,
			    IEEE80211_SEQ_ADD(rap->rxa_start, rap->rxa_wnd-1),
			    winstart);
		}
	}
	/*
	 * Move the start of the BA window; we use the
	 * sequence number of the last MSDU that was
	 * passed up the stack+1 or winstart if stopped on
	 * a gap in the reorder buffer.
	 */
	rap->rxa_start = seqno;
}

/*
 * Process a received QoS data frame for an HT station.  Handle
 * A-MPDU reordering: if this frame is received out of order
 * and falls within the BA window hold onto it.  Otherwise if
 * this frame completes a run, flush any pending frames.  We
 * return 1 if the frame is consumed.  A 0 is returned if
 * the frame should be processed normally by the caller.
 */
int
ieee80211_ampdu_reorder(struct ieee80211_node *in, mblk_t *m)
{
#define	IEEE80211_FC0_QOSDATA \
	(IEEE80211_FC0_TYPE_DATA | IEEE80211_FC0_SUBTYPE_QOS | \
	IEEE80211_FC0_VERSION_0)

#define	PROCESS		0	/* caller should process frame */
#define	CONSUMED	1	/* frame consumed, caller does nothing */

	struct ieee80211_qosframe *wh;
	struct ieee80211_rx_ampdu *rap;
	ieee80211_seq rxseq;
	uint8_t tid;
	int off;

	ASSERT(in->in_flags & IEEE80211_NODE_HT);

	/* NB: m_len known to be sufficient */
	wh = (struct ieee80211_qosframe *)m->b_rptr;
	ASSERT(wh->i_fc[0] == IEEE80211_FC0_QOSDATA);

	if ((wh->i_fc[1] & IEEE80211_FC1_DIR_MASK) == IEEE80211_FC1_DIR_DSTODS)
		tid = ((struct ieee80211_qosframe_addr4 *)wh)->i_qos[0];
	else
		tid = wh->i_qos[0];
	tid &= IEEE80211_QOS_TID;
	rap = &in->in_rx_ampdu[tid];
	if ((rap->rxa_flags & IEEE80211_AGGR_XCHGPEND) == 0) {
		/*
		 * No ADDBA request yet, don't touch.
		 */
		return (PROCESS);
	}
	rxseq = LE_16(*(uint16_t *)wh->i_seq) >> IEEE80211_SEQ_SEQ_SHIFT;
	rap->rxa_nframes++;
again:
	if (rxseq == rap->rxa_start) {
		/*
		 * First frame in window.
		 */
		if (rap->rxa_qframes != 0) {
			/*
			 * Dispatch as many packets as we can.
			 */
			ASSERT(rap->rxa_m[0] == NULL);	/* [0] is m */
			ampdu_dispatch(in, m);
			ampdu_rx_dispatch(rap, in);
			ieee80211_dbg(IEEE80211_MSG_HT,
			    "ieee80211_ampdu_reorder(%u), CONSUMED ...\n",
			    rap->rxa_qframes);
			return (CONSUMED);
		} else {
			/*
			 * In order; advance window and notify
			 * caller to dispatch directly.
			 */
			rap->rxa_start = IEEE80211_SEQ_INC(rxseq);
			ieee80211_dbg(IEEE80211_MSG_HT,
			    "ieee80211_ampdu_reorder(%u), PROCESS ...\n",
			    rap->rxa_start);
			return (PROCESS);
		}
	}
	ieee80211_dbg(IEEE80211_MSG_HT,
	    "ieee80211_ampdu_reorder(%u, %u), out of order ...\n",
	    rxseq, rap->rxa_start);
	/*
	 * Frame is out of order; store if in the BA window.
	 */
	/* calculate offset in BA window */
	off = IEEE80211_SEQ_SUB(rxseq, rap->rxa_start);
	if (off < rap->rxa_wnd) {
#ifdef IEEE80211_AMPDU_AGE
		/*
		 * Common case (hopefully): in the BA window.
		 * Sec 9.10.7.6 a) (D2.04 p.118 line 47)
		 * --
		 * Check for frames sitting too long in the reorder queue.
		 * This should only ever happen if frames are not delivered
		 * without the sender otherwise notifying us (e.g. with a
		 * BAR to move the window).  Typically this happens because
		 * of vendor bugs that cause the sequence number to jump.
		 * When this happens we get a gap in the reorder queue that
		 * leaves frame sitting on the queue until they get pushed
		 * out due to window moves.  When the vendor does not send
		 * BAR this move only happens due to explicit packet sends
		 *
		 * NB: we only track the time of the oldest frame in the
		 * reorder q; this means that if we flush we might push
		 * frames that still "new"; if this happens then subsequent
		 * frames will result in BA window moves which cost something
		 * but is still better than a big throughput dip.
		 */
		clock_t ticks;

		ticks = ddi_get_lbolt();
		if (rap->rxa_qframes != 0) {
			/* honor batimeout? */
			if (ticks - rap->rxa_age > drv_usectohz(500*1000)) {
				/*
				 * Too long since we received the first
				 * frame; flush the reorder buffer.
				 */
				if (rap->rxa_qframes != 0) {
					ampdu_rx_flush(in, rap);
				}
				rap->rxa_start = IEEE80211_SEQ_INC(rxseq);
				return (PROCESS);
			}
		} else {
			/*
			 * First frame, start aging timer.
			 */
			rap->rxa_age = ticks;
		}
#endif /* IEEE80211_AMPDU_AGE */
		/* save packet */
		if (rap->rxa_m[off] == NULL) {
			rap->rxa_m[off] = m;
			rap->rxa_qframes++;
			rap->rxa_qbytes += MBLKL(m);
		} else {
			ieee80211_dbg(IEEE80211_MSG_INPUT | IEEE80211_MSG_HT,
			    "a-mpdu duplicate "
			    "seqno %u tid %u BA win <%u:%u>\n",
			    rxseq, tid, rap->rxa_start,
			    IEEE80211_SEQ_ADD(rap->rxa_start,
			    rap->rxa_wnd - 1));
			freemsg(m);
		}
		return (CONSUMED);
	}
	if (off < IEEE80211_SEQ_BA_RANGE) {
		/*
		 * Outside the BA window, but within range;
		 * flush the reorder q and move the window.
		 * Sec 9.10.7.6 b) (D2.04 p.118 line 60)
		 */
		ieee80211_dbg(IEEE80211_MSG_HT,
		    "move BA win <%u:%u> (%u frames) rxseq %u tid %u\n",
		    rap->rxa_start,
		    IEEE80211_SEQ_ADD(rap->rxa_start, rap->rxa_wnd - 1),
		    rap->rxa_qframes, rxseq, tid);

		/*
		 * The spec says to flush frames up to but not including:
		 * 	WinStart_B = rxseq - rap->rxa_wnd + 1
		 * Then insert the frame or notify the caller to process
		 * it immediately.  We can safely do this by just starting
		 * over again because we know the frame will now be within
		 * the BA window.
		 */
		/* NB: rxa_wnd known to be >0 */
		ampdu_rx_flush_upto(in, rap,
		    IEEE80211_SEQ_SUB(rxseq, rap->rxa_wnd-1));
		goto again;
	} else {
		/*
		 * Outside the BA window and out of range; toss.
		 * Sec 9.10.7.6 c) (D2.04 p.119 line 16)
		 */
		ieee80211_dbg(IEEE80211_MSG_HT, "MSDU"
		    "BA win <%u:%u> (%u frames) rxseq %u tid %u%s\n",
		    rap->rxa_start,
		    IEEE80211_SEQ_ADD(rap->rxa_start, rap->rxa_wnd-1),
		    rap->rxa_qframes, rxseq, tid,
		    wh->i_fc[1] & IEEE80211_FC1_RETRY ? " (retransmit)" : "");
		freemsg(m);
		return (CONSUMED);
	}

#undef CONSUMED
#undef PROCESS
#undef IEEE80211_FC0_QOSDATA
}

/*
 * Process a BAR ctl frame.  Dispatch all frames up to
 * the sequence number of the frame.  If this frame is
 * out of range it's discarded.
 */
void
ieee80211_recv_bar(struct ieee80211_node *in, mblk_t *m0)
{
	struct ieee80211_frame_bar *wh;
	struct ieee80211_rx_ampdu *rap;
	ieee80211_seq rxseq;
	int tid, off;

	wh = (struct ieee80211_frame_bar *)m0->b_rptr;
	/* check basic BAR */
	tid = MS(LE_16(wh->i_ctl), IEEE80211_BAR_TID);
	rap = &in->in_rx_ampdu[tid];
	if ((rap->rxa_flags & IEEE80211_AGGR_XCHGPEND) == 0) {
		/*
		 * No ADDBA request yet, don't touch.
		 */
		ieee80211_dbg(IEEE80211_MSG_INPUT | IEEE80211_MSG_HT,
		    "BAR no BA stream, tid %u\n", tid);
		return;
	}
	rxseq = LE_16(wh->i_seq) >> IEEE80211_SEQ_SEQ_SHIFT;
	if (rxseq == rap->rxa_start)
		return;
	/* calculate offset in BA window */
	off = IEEE80211_SEQ_SUB(rxseq, rap->rxa_start);
	if (off < IEEE80211_SEQ_BA_RANGE) {
		/*
		 * Flush the reorder q up to rxseq and move the window.
		 * Sec 9.10.7.6 a) (D2.04 p.119 line 22)
		 */
		ieee80211_dbg(IEEE80211_MSG_HT,
		    "BAR moves BA win <%u:%u> (%u frames) rxseq %u tid %u\n",
		    rap->rxa_start,
		    IEEE80211_SEQ_ADD(rap->rxa_start, rap->rxa_wnd-1),
		    rap->rxa_qframes, rxseq, tid);

		ampdu_rx_flush_upto(in, rap, rxseq);
		if (off >= rap->rxa_wnd) {
			/*
			 * BAR specifies a window start to the right of BA
			 * window; we must move it explicitly since
			 * ampdu_rx_flush_upto will not.
			 */
			rap->rxa_start = rxseq;
		}
	} else {
		/*
		 * Out of range; toss.
		 * Sec 9.10.7.6 b) (D2.04 p.119 line 41)
		 */
		ieee80211_dbg(IEEE80211_MSG_HT, "BAR "
		    "BA win <%u:%u> (%u frames) rxseq %u tid %u%s\n",
		    rap->rxa_start,
		    IEEE80211_SEQ_ADD(rap->rxa_start, rap->rxa_wnd-1),
		    rap->rxa_qframes, rxseq, tid,
		    wh->i_fc[1] & IEEE80211_FC1_RETRY ? " (retransmit)" : "");
	}
}

/*
 * Setup HT-specific state in a node.  Called only
 * when HT use is negotiated so we don't do extra
 * work for temporary and/or legacy sta's.
 */
void
ieee80211_ht_node_init(struct ieee80211_node *in, const uint8_t *htcap)
{
	struct ieee80211_tx_ampdu *tap;
	int ac;

	if (in->in_flags & IEEE80211_NODE_HT) {
		/*
		 * Clean AMPDU state on re-associate.  This handles the case
		 * where a station leaves w/o notifying us and then returns
		 * before node is reaped for inactivity.
		 */
		ieee80211_ht_node_cleanup(in);
	}
	ieee80211_parse_htcap(in, htcap);
	for (ac = 0; ac < WME_NUM_AC; ac++) {
		tap = &in->in_tx_ampdu[ac];
		tap->txa_ac = (uint8_t)ac;
		/* NB: further initialization deferred */
	}
	in->in_flags |= IEEE80211_NODE_HT | IEEE80211_NODE_AMPDU;
}

/*
 * Cleanup HT-specific state in a node.  Called only
 * when HT use has been marked.
 */
void
ieee80211_ht_node_cleanup(struct ieee80211_node *in)
{
	struct ieee80211com *ic = in->in_ic;
	int i;

	ASSERT(in->in_flags & IEEE80211_NODE_HT);

	/* optimize this */
	for (i = 0; i < WME_NUM_AC; i++) {
		struct ieee80211_tx_ampdu *tap = &in->in_tx_ampdu[i];
		if (tap->txa_flags & IEEE80211_AGGR_SETUP) {
			/*
			 * Stop BA stream if setup so driver has a chance
			 * to reclaim any resources it might have allocated.
			 */
			ic->ic_addba_stop(in, &in->in_tx_ampdu[i]);
			/* IEEE80211_TAPQ_DESTROY(tap); */
			/* NB: clearing NAK means we may re-send ADDBA */
			tap->txa_flags &=
			    ~(IEEE80211_AGGR_SETUP | IEEE80211_AGGR_NAK);
		}
	}
	for (i = 0; i < WME_NUM_TID; i++)
		ampdu_rx_stop(&in->in_rx_ampdu[i]);

	in->in_htcap = 0;
	in->in_flags &= ~(IEEE80211_NODE_HT | IEEE80211_NODE_HTCOMPAT |
	    IEEE80211_NODE_AMPDU);
}

static struct ieee80211_channel *
findhtchan(struct ieee80211com *ic, struct ieee80211_channel *c, int htflags)
{
	return ieee80211_find_channel(ic, c->ich_freq,
	    (c->ich_flags &~ IEEE80211_CHAN_HT) | htflags);
}

/*
 * Adjust a channel to be HT/non-HT according to the vap's configuration.
 */
struct ieee80211_channel *
ieee80211_ht_adjust_channel(struct ieee80211com *ic,
	struct ieee80211_channel *chan, int flags)
{
	struct ieee80211_channel *c;

	if (flags & IEEE80211_FEXT_HT) {
		/* promote to HT if possible */
		if (flags & IEEE80211_FEXT_USEHT40) {
			if (!IEEE80211_IS_CHAN_HT40(chan)) {
				/* NB: arbitrarily pick ht40+ over ht40- */
				c = findhtchan(ic, chan, IEEE80211_CHAN_HT40U);
				if (c == NULL)
					c = findhtchan(ic, chan,
					    IEEE80211_CHAN_HT40D);
				if (c == NULL)
					c = findhtchan(ic, chan,
					    IEEE80211_CHAN_HT20);
				if (c != NULL)
					chan = c;
			}
		} else if (!IEEE80211_IS_CHAN_HT20(chan)) {
			c = findhtchan(ic, chan, IEEE80211_CHAN_HT20);
			if (c != NULL)
				chan = c;
		}
	} else if (IEEE80211_IS_CHAN_HT(chan)) {
		/* demote to legacy, HT use is disabled */
		c = ieee80211_find_channel(ic, chan->ich_freq,
		    chan->ich_flags &~ IEEE80211_CHAN_HT);
		if (c != NULL)
			chan = c;
	}
	return (chan);
}

/*
 * Setup HT-specific state for a legacy WDS peer.
 */
void
ieee80211_ht_wds_init(struct ieee80211_node *in)
{
	struct ieee80211com *ic = in->in_ic;
	struct ieee80211_tx_ampdu *tap;
	int ac;

	ASSERT(ic->ic_flags_ext & IEEE80211_FEXT_HT);

	/* check scan cache in case peer has an ap and we have info */
	/*
	 * If setup with a legacy channel; locate an HT channel.
	 * Otherwise if the inherited channel (from a companion
	 * AP) is suitable use it so we use the same location
	 * for the extension channel).
	 */
	in->in_chan = ieee80211_ht_adjust_channel(ic, in->in_chan,
	    ic->ic_flags_ext);

	in->in_htcap = 0;
	if (ic->ic_flags_ext & IEEE80211_FEXT_SHORTGI20)
		in->in_htcap |= IEEE80211_HTCAP_SHORTGI20;
	if (IEEE80211_IS_CHAN_HT40(in->in_chan)) {
		in->in_htcap |= IEEE80211_HTCAP_CHWIDTH40;
		in->in_chw = 40;
		if (IEEE80211_IS_CHAN_HT40U(in->in_chan))
			in->in_ht2ndchan = IEEE80211_HTINFO_2NDCHAN_ABOVE;
		else if (IEEE80211_IS_CHAN_HT40D(in->in_chan))
			in->in_ht2ndchan = IEEE80211_HTINFO_2NDCHAN_BELOW;
		if (ic->ic_flags_ext & IEEE80211_FEXT_SHORTGI40)
			in->in_htcap |= IEEE80211_HTCAP_SHORTGI40;
	} else {
		in->in_chw = 20;
		in->in_ht2ndchan = IEEE80211_HTINFO_2NDCHAN_NONE;
	}
	in->in_htctlchan = ieee80211_chan2ieee(ic, in->in_chan);

	in->in_htopmode = 0;		/* need protection state */
	in->in_htstbc = 0;		/* need info */

	for (ac = 0; ac < WME_NUM_AC; ac++) {
		tap = &in->in_tx_ampdu[ac];
		tap->txa_ac = (uint8_t)ac;
	}
	/* NB: AMPDU tx/rx governed by IEEE80211_FEXT_AMPDU_{TX,RX} */
	in->in_flags |= IEEE80211_NODE_HT | IEEE80211_NODE_AMPDU;
}

/*
 * Notify hostap vaps of a change in the HTINFO ie.
 */
static void
htinfo_notify(struct ieee80211com *ic)
{
	if (ic->ic_opmode != IEEE80211_M_HOSTAP)
		return;
	ieee80211_dbg(IEEE80211_MSG_ASSOC | IEEE80211_MSG_HT,
	    "HT bss occupancy change: %d sta, %d ht, "
	    "%d ht40%s, HT protmode now 0x%x\n",
	    ic->ic_sta_assoc,
	    ic->ic_ht_sta_assoc,
	    ic->ic_ht40_sta_assoc,
	    (ic->ic_flags_ext & IEEE80211_FEXT_NONHT_PR) ?
	    ", non-HT sta present" : "",
	    ic->ic_curhtprotmode);
}

/*
 * Calculate HT protection mode from current
 * state and handle updates.
 */
static void
htinfo_update(struct ieee80211com *ic)
{
	uint8_t protmode;

	if (ic->ic_flags_ext & IEEE80211_FEXT_NONHT_PR) {
		protmode = IEEE80211_HTINFO_OPMODE_PROTOPT
		    | IEEE80211_HTINFO_NONHT_PRESENT;
	} else if (ic->ic_sta_assoc != ic->ic_ht_sta_assoc) {
		protmode = IEEE80211_HTINFO_OPMODE_MIXED
		    | IEEE80211_HTINFO_NONHT_PRESENT;
	} else if (IEEE80211_IS_CHAN_HT40(ic->ic_curchan) &&
	    ic->ic_sta_assoc != ic->ic_ht40_sta_assoc) {
		protmode = IEEE80211_HTINFO_OPMODE_HT20PR;
	} else {
		protmode = IEEE80211_HTINFO_OPMODE_PURE;
	}
	if (protmode != ic->ic_curhtprotmode) {
		ic->ic_curhtprotmode = protmode;
		htinfo_notify(ic);
	}
}

/*
 * Handle an HT station joining a BSS.
 */
void
ieee80211_ht_node_join(struct ieee80211_node *in)
{
	struct ieee80211com *ic = in->in_ic;

	IEEE80211_LOCK_ASSERT(ic);

	if (in->in_flags & IEEE80211_NODE_HT) {
		ic->ic_ht_sta_assoc++;
		if (in->in_chw == 40)
			ic->ic_ht40_sta_assoc++;
	}
	htinfo_update(ic);
}

/*
 * Handle an HT station leaving a BSS.
 */
void
ieee80211_ht_node_leave(struct ieee80211_node *in)
{
	struct ieee80211com *ic = in->in_ic;

	IEEE80211_LOCK_ASSERT(ic);

	if (in->in_flags & IEEE80211_NODE_HT) {
		ic->ic_ht_sta_assoc--;
		if (in->in_chw == 40)
			ic->ic_ht40_sta_assoc--;
	}
	htinfo_update(ic);
}

/*
 * Public version of htinfo_update; used for processing
 * beacon frames from overlapping bss in hostap_recv_mgmt.
 */
void
ieee80211_htinfo_update(struct ieee80211com *ic, int protmode)
{
	if (protmode != ic->ic_curhtprotmode) {
		ic->ic_curhtprotmode = (uint8_t)protmode;
		htinfo_notify(ic);
	}
}

/* unalligned little endian access */
#define	LE_READ_2(p)					\
	((uint16_t)					\
	((((const uint8_t *)(p))[0]) |			\
	(((const uint8_t *)(p))[1] <<  8)))

/*
 * Process an 802.11n HT capabilities ie.
 */
void
ieee80211_parse_htcap(struct ieee80211_node *in, const uint8_t *ie)
{
	struct ieee80211com *ic = in->in_ic;

	if (ie[0] == IEEE80211_ELEMID_VENDOR) {
		/*
		 * Station used Vendor OUI ie to associate;
		 * mark the node so when we respond we'll use
		 * the Vendor OUI's and not the standard ie's.
		 */
		in->in_flags |= IEEE80211_NODE_HTCOMPAT;
		ie += 4;
	} else
		in->in_flags &= ~IEEE80211_NODE_HTCOMPAT;

	in->in_htcap = *(uint16_t *)(ie +
	    offsetof(struct ieee80211_ie_htcap, hc_cap));
	in->in_htparam = ie[offsetof(struct ieee80211_ie_htcap, hc_param)];
	/* needed or will ieee80211_parse_htinfo always be called? */
	in->in_chw = (in->in_htcap & IEEE80211_HTCAP_CHWIDTH40) &&
	    (ic->ic_flags_ext & IEEE80211_FEXT_USEHT40) ? 40 : 20;
}

/*
 * Process an 802.11n HT info ie and update the node state.
 * Note that we handle use this information to identify the
 * correct channel (HT20, HT40+, HT40-, legacy).  The caller
 * is responsible for insuring any required channel change is
 * done (e.g. in sta mode when parsing the contents of a
 * beacon frame).
 */
void
ieee80211_parse_htinfo(struct ieee80211_node *in, const uint8_t *ie)
{
	struct ieee80211com *ic = in->in_ic;
	const struct ieee80211_ie_htinfo *htinfo;
	struct ieee80211_channel *c;
	uint16_t w;
	int htflags, chanflags;

	if (ie[0] == IEEE80211_ELEMID_VENDOR)
		ie += 4;
	htinfo = (const struct ieee80211_ie_htinfo *)ie;
	in->in_htctlchan = htinfo->hi_ctrlchannel;
	in->in_ht2ndchan = SM(htinfo->hi_byte1, IEEE80211_HTINFO_2NDCHAN);
	w = *(uint16_t *)(&htinfo->hi_byte2);
	in->in_htopmode = SM(w, IEEE80211_HTINFO_OPMODE);
	w = *(uint16_t *)(&htinfo->hi_byte45);
	in->in_htstbc = SM(w, IEEE80211_HTINFO_BASIC_STBCMCS);
	/*
	 * Handle 11n channel switch.  Use the received HT ie's to
	 * identify the right channel to use.  If we cannot locate it
	 * in the channel table then fallback to legacy operation.
	 */
	htflags = (ic->ic_flags_ext & IEEE80211_FEXT_HT) ?
	    IEEE80211_CHAN_HT20 : 0;
	/* NB: honor operating mode constraint */
	if ((htinfo->hi_byte1 & IEEE80211_HTINFO_TXWIDTH_2040) &&
	    (ic->ic_flags_ext & IEEE80211_FEXT_USEHT40)) {
		if (in->in_ht2ndchan == IEEE80211_HTINFO_2NDCHAN_ABOVE)
			htflags = IEEE80211_CHAN_HT40U;
		else if (in->in_ht2ndchan == IEEE80211_HTINFO_2NDCHAN_BELOW)
			htflags = IEEE80211_CHAN_HT40D;
	}
	chanflags = (in->in_chan->ich_flags &~ IEEE80211_CHAN_HT) | htflags;
	if (chanflags != in->in_chan->ich_flags) {
		c = ieee80211_find_channel(ic,
		    in->in_chan->ich_freq, chanflags);
		if (c == NULL && htflags != IEEE80211_CHAN_HT20) {
			/*
			 * No HT40 channel entry in our table; fall back
			 * to HT20 operation.  This should not happen.
			 */
			c = findhtchan(ic, in->in_chan, IEEE80211_CHAN_HT20);
			ieee80211_dbg(IEEE80211_MSG_ASSOC | IEEE80211_MSG_HT,
			    "no HT40 channel (freq %u), falling back to HT20\n",
			    in->in_chan->ich_freq);
			/* stat */
		}
		if (c != NULL && c != in->in_chan) {
			ieee80211_dbg(IEEE80211_MSG_ASSOC | IEEE80211_MSG_HT,
			    "switch station to HT%d channel %u/0x%x\n",
			    IEEE80211_IS_CHAN_HT40(c) ? 40 : 20,
			    c->ich_freq, c->ich_flags);
			in->in_chan = c;
		}
		/* NB: caller responsible for forcing any channel change */
	}
	/* update node's tx channel width */
	in->in_chw = IEEE80211_IS_CHAN_HT40(in->in_chan)? 40 : 20;
}

/*
 * Install received HT rate set by parsing the HT cap ie.
 */
int
ieee80211_setup_htrates(struct ieee80211_node *in, const uint8_t *ie, int flags)
{
	const struct ieee80211_ie_htcap *htcap;
	struct ieee80211_htrateset *rs;
	int i;

	rs = &in->in_htrates;
	(void) memset(rs, 0, sizeof (*rs));
	if (ie != NULL) {
		if (ie[0] == IEEE80211_ELEMID_VENDOR)
			ie += 4;
		htcap = (const struct ieee80211_ie_htcap *) ie;
		for (i = 0; i < IEEE80211_HTRATE_MAXSIZE; i++) {
			if (ieee80211_isclr(htcap->hc_mcsset, i))
				continue;
			if (rs->rs_nrates == IEEE80211_HTRATE_MAXSIZE) {
				ieee80211_dbg(
				    IEEE80211_MSG_XRATE | IEEE80211_MSG_HT,
				    "WARNING, HT rate set too large; only "
				    "using %u rates\n",
				    IEEE80211_HTRATE_MAXSIZE);
				break;
			}
			rs->rs_rates[rs->rs_nrates++] = (uint8_t)i;
		}
	}
	return (ieee80211_fix_rate(in, (struct ieee80211_rateset *)rs, flags));
}

/*
 * Mark rates in a node's HT rate set as basic according
 * to the information in the supplied HT info ie.
 */
void
ieee80211_setup_basic_htrates(struct ieee80211_node *in, const uint8_t *ie)
{
	const struct ieee80211_ie_htinfo *htinfo;
	struct ieee80211_htrateset *rs;
	int i, j;

	if (ie[0] == IEEE80211_ELEMID_VENDOR)
		ie += 4;
	htinfo = (const struct ieee80211_ie_htinfo *) ie;
	rs = &in->in_htrates;
	if (rs->rs_nrates == 0) {
		ieee80211_dbg(IEEE80211_MSG_XRATE | IEEE80211_MSG_HT,
		    "WARNING, empty HT rate set\n");
		return;
	}
	for (i = 0; i < IEEE80211_HTRATE_MAXSIZE; i++) {
		if (ieee80211_isclr(htinfo->hi_basicmcsset, i))
			continue;
		for (j = 0; j < rs->rs_nrates; j++)
			if ((rs->rs_rates[j] & IEEE80211_RATE_VAL) == i)
				rs->rs_rates[j] |= IEEE80211_RATE_BASIC;
	}
}

static void
addba_timeout(void *arg)
{
	struct ieee80211_tx_ampdu *tap = arg;

	tap->txa_flags &= ~IEEE80211_AGGR_XCHGPEND;
	tap->txa_attempts++;
}

static void
addba_start_timeout(struct ieee80211_tx_ampdu *tap)
{
	tap->txa_timer = timeout(addba_timeout, (void *)tap,
	    drv_usectohz(IEEE80211_AGGR_TIMEOUT * 1000));
	tap->txa_flags |= IEEE80211_AGGR_XCHGPEND;
	tap->txa_lastrequest = ddi_get_lbolt();
}

static void
addba_stop_timeout(struct ieee80211_tx_ampdu *tap)
{
	if (tap->txa_flags & IEEE80211_AGGR_XCHGPEND) {
		if (tap->txa_timer != NULL) {
			(void) untimeout(tap->txa_timer);
			tap->txa_timer = NULL;
		}
		tap->txa_flags &= ~IEEE80211_AGGR_XCHGPEND;
	}
}

/*
 * Default method for requesting A-MPDU tx aggregation.
 * We setup the specified state block and start a timer
 * to wait for an ADDBA response frame.
 */
/* ARGSUSED */
static int
ieee80211_addba_request(struct ieee80211_node *in,
    struct ieee80211_tx_ampdu *tap,
    int dialogtoken, int baparamset, int batimeout)
{
	int bufsiz;

	tap->txa_token = (uint8_t)dialogtoken;
	tap->txa_flags |= IEEE80211_AGGR_IMMEDIATE;
	tap->txa_start = tap->txa_seqstart = 0;
	bufsiz = MS(baparamset, IEEE80211_BAPS_BUFSIZ);
	tap->txa_wnd = (bufsiz == 0) ? IEEE80211_AGGR_BAWMAX
	    : min((uint16_t)bufsiz, IEEE80211_AGGR_BAWMAX);
	addba_start_timeout(tap);
	return (1);
}

/*
 * Default method for processing an A-MPDU tx aggregation
 * response.  We shutdown any pending timer and update the
 * state block according to the reply.
 */
/* ARGSUSED */
static int
ieee80211_addba_response(struct ieee80211_node *in,
    struct ieee80211_tx_ampdu *tap,
    int status, int baparamset, int batimeout)
{
	int bufsiz;

	addba_stop_timeout(tap);
	if (status == IEEE80211_STATUS_SUCCESS) {
		bufsiz = MS(baparamset, IEEE80211_BAPS_BUFSIZ);
		/* override our request? */
		tap->txa_wnd = (bufsiz == 0) ? IEEE80211_AGGR_BAWMAX
		    : min((uint16_t)bufsiz, IEEE80211_AGGR_BAWMAX);
		tap->txa_flags |= IEEE80211_AGGR_RUNNING;
	} else {
		/* mark tid so we don't try again */
		tap->txa_flags |= IEEE80211_AGGR_NAK;
	}
	return (1);
}

/*
 * Default method for stopping A-MPDU tx aggregation.
 * Any timer is cleared and we drain any pending frames.
 */
/* ARGSUSED */
static void
ieee80211_addba_stop(struct ieee80211_node *in, struct ieee80211_tx_ampdu *tap)
{
	addba_stop_timeout(tap);
	if (tap->txa_flags & IEEE80211_AGGR_RUNNING) {
		/* clear aggregation queue */
		tap->txa_flags &= ~IEEE80211_AGGR_RUNNING;
	}
	tap->txa_attempts = 0;
}

/*
 * Process a received action frame using the default aggregation
 * policy.  We intercept ADDBA-related frames and use them to
 * update our aggregation state.  All other frames are passed up
 * for processing by ieee80211_recv_action.
 */
static void
ieee80211_aggr_recv_action(struct ieee80211_node *in,
	const uint8_t *frm, const uint8_t *efrm)
{
	struct ieee80211com *ic = in->in_ic;
	const struct ieee80211_action *ia;
	struct ieee80211_rx_ampdu *rap;
	struct ieee80211_tx_ampdu *tap;
	uint8_t dialogtoken;
	uint16_t baparamset, batimeout, baseqctl, code;
	uint16_t args[4];
	int tid, ac, bufsiz;

	ia = (const struct ieee80211_action *) frm;
	switch (ia->ia_category) {
	case IEEE80211_ACTION_CAT_BA:
		switch (ia->ia_action) {
		case IEEE80211_ACTION_BA_ADDBA_REQUEST:
			dialogtoken = frm[2];
			baparamset = *(uint16_t *)(frm+3);
			batimeout = *(uint16_t *)(frm+5);
			baseqctl = *(uint16_t *)(frm+7);

			tid = MS(baparamset, IEEE80211_BAPS_TID);
			bufsiz = MS(baparamset, IEEE80211_BAPS_BUFSIZ);

			ieee80211_dbg(IEEE80211_MSG_ACTION | IEEE80211_MSG_HT,
			    "recv ADDBA request: dialogtoken %u "
			    "baparamset 0x%x (tid %d bufsiz %d) batimeout %d "
			    "baseqctl %d:%d\n",
			    dialogtoken, baparamset, tid, bufsiz, batimeout,
			    MS(baseqctl, IEEE80211_BASEQ_START),
			    MS(baseqctl, IEEE80211_BASEQ_FRAG));

			rap = &in->in_rx_ampdu[tid];

			/* Send ADDBA response */
			args[0] = dialogtoken;
			/*
			 * NB: We ack only if the sta associated with HT and
			 * the ap is configured to do AMPDU rx (the latter
			 * violates the 11n spec and is mostly for testing).
			 */
			if ((in->in_flags & IEEE80211_NODE_AMPDU_RX) &&
			    (ic->ic_flags_ext & IEEE80211_FEXT_AMPDU_RX)) {
				ampdu_rx_start(rap, bufsiz,
				    MS(baseqctl, IEEE80211_BASEQ_START));

				args[1] = IEEE80211_STATUS_SUCCESS;
			} else {
				ieee80211_dbg(
				    IEEE80211_MSG_ACTION | IEEE80211_MSG_HT,
				    "reject ADDBA request: %s\n",
				    in->in_flags & IEEE80211_NODE_AMPDU_RX ?
				    "administratively disabled" :
				    "not negotiated for station");
				args[1] = IEEE80211_STATUS_UNSPECIFIED;
			}
			/* honor rap flags? */
			args[2] = IEEE80211_BAPS_POLICY_IMMEDIATE
			    | SM(tid, IEEE80211_BAPS_TID)
			    | SM(rap->rxa_wnd, IEEE80211_BAPS_BUFSIZ);
			args[3] = 0;
			ic->ic_send_action(in, IEEE80211_ACTION_CAT_BA,
			    IEEE80211_ACTION_BA_ADDBA_RESPONSE, args);
			return;

		case IEEE80211_ACTION_BA_ADDBA_RESPONSE:
			dialogtoken = frm[2];
			code = *(uint16_t *)(frm+3);
			baparamset = *(uint16_t *)(frm+5);
			tid = MS(baparamset, IEEE80211_BAPS_TID);
			bufsiz = MS(baparamset, IEEE80211_BAPS_BUFSIZ);
			batimeout = *(uint16_t *)(frm+7);

			ac = TID_TO_WME_AC(tid);
			tap = &in->in_tx_ampdu[ac];
			if ((tap->txa_flags & IEEE80211_AGGR_XCHGPEND) == 0) {
				ieee80211_err("ADDBA response"
				    "no pending ADDBA, tid %d dialogtoken %u "
				    "code %d\n", tid, dialogtoken, code);
				return;
			}
			if (dialogtoken != tap->txa_token) {
				ieee80211_err("ADDBA response"
				    "dialogtoken mismatch: waiting for %d, "
				    "received %d, tid %d code %d\n",
				    tap->txa_token, dialogtoken, tid, code);
				return;
			}

			ieee80211_dbg(IEEE80211_MSG_ACTION | IEEE80211_MSG_HT,
			    "recv ADDBA response: dialogtoken %u code %d "
			    "baparamset 0x%x (tid %d bufsiz %d) batimeout %d\n",
			    dialogtoken, code, baparamset, tid, bufsiz,
			    batimeout);
			ic->ic_addba_response(in, tap,
			    code, baparamset, batimeout);
			return;

		case IEEE80211_ACTION_BA_DELBA:
			baparamset = *(uint16_t *)(frm+2);
			code = *(uint16_t *)(frm+4);

			tid = MS(baparamset, IEEE80211_DELBAPS_TID);

			ieee80211_dbg(IEEE80211_MSG_ACTION | IEEE80211_MSG_HT,
			    "recv DELBA: baparamset 0x%x (tid %d initiator %d) "
			    "code %d\n", baparamset, tid,
			    MS(baparamset, IEEE80211_DELBAPS_INIT), code);

			if ((baparamset & IEEE80211_DELBAPS_INIT) == 0) {
				ac = TID_TO_WME_AC(tid);
				tap = &in->in_tx_ampdu[ac];
				ic->ic_addba_stop(in, tap);
			} else {
				rap = &in->in_rx_ampdu[tid];
				ampdu_rx_stop(rap);
			}
			return;
		}
		break;
	}
	ieee80211_recv_action(in, frm, efrm);
}

/*
 * Process a received 802.11n action frame.
 * Aggregation-related frames are assumed to be handled
 * already; we handle any other frames we can, otherwise
 * complain about being unsupported (with debugging).
 */
/* ARGSUSED */
void
ieee80211_recv_action(struct ieee80211_node *in,
    const uint8_t *frm, const uint8_t *efrm)
{
	const struct ieee80211_action *ia;
	int chw;

	ia = (const struct ieee80211_action *) frm;
	switch (ia->ia_category) {
	case IEEE80211_ACTION_CAT_BA:
		ieee80211_dbg(IEEE80211_MSG_ACTION | IEEE80211_MSG_HT,
		    "BA action %d not implemented\n",
		    ia->ia_action);
		break;
	case IEEE80211_ACTION_CAT_HT:
		switch (ia->ia_action) {
		case IEEE80211_ACTION_HT_TXCHWIDTH:
			chw = frm[2] == IEEE80211_A_HT_TXCHWIDTH_2040 ? 40 : 20;
			if (chw != in->in_chw) {
				in->in_chw = (uint8_t)chw;
				in->in_flags |= IEEE80211_NODE_CHWUPDATE;
			}
			ieee80211_dbg(IEEE80211_MSG_ACTION | IEEE80211_MSG_HT,
			    "HT txchwidth, width %d (%s)\n",
			    chw,
			    in->in_flags & IEEE80211_NODE_CHWUPDATE ?
			    "new" : "no change");
			break;
		case IEEE80211_ACTION_HT_MIMOPWRSAVE:
			ieee80211_dbg(IEEE80211_MSG_ACTION | IEEE80211_MSG_HT,
			    "HT MIMO PS\n");
			break;
		default:
			ieee80211_dbg(IEEE80211_MSG_ACTION | IEEE80211_MSG_HT,
			    "HT action %d not implemented\n",
			    ia->ia_action);
			break;
		}
		break;
	default:
		ieee80211_dbg(IEEE80211_MSG_ACTION | IEEE80211_MSG_HT,
		    "category %d not implemented\n",
		    ia->ia_category);
		break;
	}
}

/*
 * Transmit processing.
 */

/*
 * Request A-MPDU tx aggregation.  Setup local state and
 * issue an ADDBA request.  BA use will only happen after
 * the other end replies with ADDBA response.
 */
int
ieee80211_ampdu_request(struct ieee80211_node *in,
    struct ieee80211_tx_ampdu *tap)
{
	struct ieee80211com *ic = in->in_ic;
	uint16_t args[4];
	int tid, dialogtoken;
	static int tokens = 0;	/* tokens */
	clock_t ticks;

	ticks = ddi_get_lbolt();
	if ((tap->txa_flags & IEEE80211_AGGR_SETUP) == 0) {
		/* do deferred setup of state */
		tap->txa_flags |= IEEE80211_AGGR_SETUP;
	}
	if (tap->txa_attempts >= IEEE80211_AGGR_MAXTRIES &&
	    (ticks - tap->txa_lastrequest) < IEEE80211_AGGR_MINRETRY) {
		/*
		 * Don't retry too often; IEEE80211_AGGR_MINRETRY
		 * defines the minimum interval we'll retry after
		 * IEEE80211_AGGR_MAXTRIES failed attempts to
		 * negotiate use.
		 */
		return (0);
	}
	/* hack for not doing proper locking */
	tap->txa_flags &= ~IEEE80211_AGGR_NAK;

	dialogtoken = (tokens+1) % 63;		/* algorithm */

	tid = WME_AC_TO_TID(tap->txa_ac);
	args[0] = (uint16_t)dialogtoken;
	args[1]	= IEEE80211_BAPS_POLICY_IMMEDIATE
	    | SM(tid, IEEE80211_BAPS_TID)
	    | SM(IEEE80211_AGGR_BAWMAX, IEEE80211_BAPS_BUFSIZ);
	args[2] = 0;	/* batimeout */
	args[3] = SM(0, IEEE80211_BASEQ_START)
	    | SM(0, IEEE80211_BASEQ_FRAG);
	/* NB: do first so there's no race against reply */
	if (!ic->ic_addba_request(in, tap, dialogtoken, args[1], args[2])) {
		/* unable to setup state, don't make request */
		ieee80211_dbg(IEEE80211_MSG_HT,
		    "could not setup BA stream for AC %d\n",
		    tap->txa_ac);
		/* defer next try so we don't slam the driver with requests */
		tap->txa_attempts = IEEE80211_AGGR_MAXTRIES;
		tap->txa_lastrequest = ticks;
		return (0);
	}
	tokens = dialogtoken;			/* allocate token */
	return (ic->ic_send_action(in, IEEE80211_ACTION_CAT_BA,
	    IEEE80211_ACTION_BA_ADDBA_REQUEST, args));
}

/*
 * Terminate an AMPDU tx stream. State is reclaimed
 * and the peer notified with a DelBA Action frame.
 */
void
ieee80211_ampdu_stop(struct ieee80211_node *in, struct ieee80211_tx_ampdu *tap)
{
	struct ieee80211com *ic = in->in_ic;
	uint16_t args[4];

	if (IEEE80211_AMPDU_RUNNING(tap)) {
		ieee80211_dbg(IEEE80211_MSG_ACTION | IEEE80211_MSG_HT,
		    "stop BA stream for AC %d\n", tap->txa_ac);

		ic->ic_addba_stop(in, tap);
		args[0] = WME_AC_TO_TID(tap->txa_ac);
		args[1] = IEEE80211_DELBAPS_INIT;
		args[2] = 1;				/* reason code */
		(void) ieee80211_send_action(in, IEEE80211_ACTION_CAT_BA,
		    IEEE80211_ACTION_BA_DELBA, args);
	} else {
		ieee80211_dbg(IEEE80211_MSG_ACTION | IEEE80211_MSG_HT,
		    "BA stream for AC %d not running\n",
		    tap->txa_ac);
	}
}

/*
 * Transmit a BAR frame to the specified node.  The
 * BAR contents are drawn from the supplied aggregation
 * state associated with the node.
 */
int
ieee80211_send_bar(struct ieee80211_node *in,
    const struct ieee80211_tx_ampdu *tap)
{
#define	ADDSHORT(frm, v) do {			\
        _NOTE(CONSTCOND)                        \
	frm[0] = (v) & 0xff;			\
	frm[1] = (v) >> 8;			\
	frm += 2;				\
        _NOTE(CONSTCOND)                        \
} while (0)
	struct ieee80211com *ic = in->in_ic;
	struct ieee80211_frame_min *wh;
	mblk_t *m;
	uint8_t *frm;
	uint16_t barctl, barseqctl;
	int tid;


	m = ieee80211_getmgtframe(&frm, sizeof (struct ieee80211_ba_request));
	if (m == NULL)
		return (ENOMEM);

	wh = (struct ieee80211_frame_min *)m->b_rptr;
	wh->i_fc[0] = IEEE80211_FC0_VERSION_0 |
	    IEEE80211_FC0_TYPE_CTL | IEEE80211_FC0_SUBTYPE_BAR;
	wh->i_fc[1] = 0;
	IEEE80211_ADDR_COPY(wh->i_addr1, in->in_macaddr);
	IEEE80211_ADDR_COPY(wh->i_addr2, ic->ic_macaddr);

	tid = WME_AC_TO_TID(tap->txa_ac);
	barctl 	= (tap->txa_flags & IEEE80211_AGGR_IMMEDIATE ?
	    IEEE80211_BAPS_POLICY_IMMEDIATE :
	    IEEE80211_BAPS_POLICY_DELAYED)
	    | SM(tid, IEEE80211_BAPS_TID)
	    | SM(tap->txa_wnd, IEEE80211_BAPS_BUFSIZ);
	barseqctl = SM(tap->txa_start, IEEE80211_BASEQ_START)
	    | SM(0, IEEE80211_BASEQ_FRAG);
	ADDSHORT(frm, barctl);
	ADDSHORT(frm, barseqctl);
	m->b_wptr = frm;

	ieee80211_dbg(IEEE80211_MSG_DEBUG,
	    "send bar frame (tid %u start %u) on channel %u\n",
	    tid, tap->txa_start, ieee80211_chan2ieee(ic, ic->ic_curchan));

	(void) (*ic->ic_xmit)(ic, m, IEEE80211_FC0_TYPE_CTL);	/* MGT? */

	return (0);
#undef ADDSHORT
}

/*
 * Send an action management frame.  The arguments are stuff
 * into a frame without inspection; the caller is assumed to
 * prepare them carefully (e.g. based on the aggregation state).
 */
int
ieee80211_send_action(struct ieee80211_node *in,
    int category, int action, uint16_t args[4])
{
#define	ADDSHORT(frm, v) do {			\
        _NOTE(CONSTCOND)                        \
	frm[0] = (v) & 0xff;			\
	frm[1] = (v) >> 8;			\
	frm += 2;				\
        _NOTE(CONSTCOND)                        \
} while (0)
	struct ieee80211com *ic = in->in_ic;
	mblk_t *m;
	uint8_t *frm;
	uint16_t baparamset;
	int ret;

	ASSERT(in != NULL);

	m = ieee80211_getmgtframe(&frm,
	    sizeof (uint16_t)	/* action+category */
	    /* may action payload */
	    + sizeof (struct ieee80211_action_ba_addbaresponse));
	if (m == NULL)
		return (ENOMEM);

	*frm++ = (uint8_t)category;
	*frm++ = (uint8_t)action;
	switch (category) {
	case IEEE80211_ACTION_CAT_BA:
		switch (action) {
		case IEEE80211_ACTION_BA_ADDBA_REQUEST:
			ieee80211_dbg(IEEE80211_MSG_ACTION | IEEE80211_MSG_HT,
			    "send ADDBA request: dialogtoken %d "
			    "baparamset 0x%x (tid %d) "
			    "batimeout 0x%x baseqctl 0x%x\n",
			    args[0], args[1], MS(args[1], IEEE80211_BAPS_TID),
			    args[2], args[3]);

			*frm++ = args[0];	/* dialog token */
			ADDSHORT(frm, args[1]);	/* baparamset */
			ADDSHORT(frm, args[2]);	/* batimeout */
			ADDSHORT(frm, args[3]);	/* baseqctl */
			break;
		case IEEE80211_ACTION_BA_ADDBA_RESPONSE:
			ieee80211_dbg(IEEE80211_MSG_ACTION | IEEE80211_MSG_HT,
			    "send ADDBA response: dialogtoken %d status %d "
			    "baparamset 0x%x (tid %d) batimeout %d\n",
			    args[0], args[1], args[2],
			    MS(args[2], IEEE80211_BAPS_TID), args[3]);

			*frm++ = args[0];	/* dialog token */
			ADDSHORT(frm, args[1]);	/* statuscode */
			ADDSHORT(frm, args[2]);	/* baparamset */
			ADDSHORT(frm, args[3]);	/* batimeout */
			break;
		case IEEE80211_ACTION_BA_DELBA:
			baparamset = SM(args[0], IEEE80211_DELBAPS_TID)
			    | SM(args[1], IEEE80211_DELBAPS_INIT);
			ADDSHORT(frm, baparamset);
			ADDSHORT(frm, args[2]);	/* reason code */

			ieee80211_dbg(IEEE80211_MSG_ACTION | IEEE80211_MSG_HT,
			    "send DELBA action: tid %d, initiator %d "
			    "reason %d\n",
			    args[0], args[1], args[2]);
			break;
		default:
			goto badaction;
		}
		break;
	case IEEE80211_ACTION_CAT_HT:
		switch (action) {
		case IEEE80211_ACTION_HT_TXCHWIDTH:
			ieee80211_dbg(IEEE80211_MSG_ACTION | IEEE80211_MSG_HT,
			    "send HT txchwidth: width %d\n",
			    IEEE80211_IS_CHAN_HT40(ic->ic_curchan) ? 40 : 20);
			*frm++ = IEEE80211_IS_CHAN_HT40(ic->ic_curchan) ?
			    IEEE80211_A_HT_TXCHWIDTH_2040 :
			    IEEE80211_A_HT_TXCHWIDTH_20;
			break;
		default:
			goto badaction;
		}
		break;
	default:
	badaction:
		ieee80211_dbg(IEEE80211_MSG_ACTION | IEEE80211_MSG_HT,
		    "unsupported category %d action %d\n",
		    category, action);
		return (EINVAL);
		/* NOTREACHED */
	}
	m->b_wptr = frm;

	ret = ieee80211_mgmt_output(ic, in, m, IEEE80211_FC0_SUBTYPE_ACTION, 0);

	return (ret);
#undef ADDSHORT
}

/*
 * Construct the MCS bit mask for inclusion
 * in an HT information element.
 */
static void
ieee80211_set_htrates(uint8_t *frm, const struct ieee80211_htrateset *rs)
{
	int i;

	for (i = 0; i < rs->rs_nrates; i++) {
		int r = rs->rs_rates[i] & IEEE80211_RATE_VAL;
		if (r < IEEE80211_HTRATE_MAXSIZE) {
			/* NB: this assumes a particular implementation */
			ieee80211_setbit(frm, r);
		}
	}
}

/*
 * Add body of an HTCAP information element.
 */
static uint8_t *
ieee80211_add_htcap_body(uint8_t *frm, struct ieee80211_node *in)
{
#define	ADDSHORT(frm, v) do {			\
        _NOTE(CONSTCOND)                        \
	frm[0] = (v) & 0xff;			\
	frm[1] = (v) >> 8;			\
	frm += 2;				\
        _NOTE(CONSTCOND)                        \
} while (0)
	struct ieee80211com *ic = in->in_ic;
	uint16_t caps;
	int rxmax, density;

	/* HT capabilities */
	caps = ic->ic_htcaps & 0xffff;
	/*
	 * Note channel width depends on whether we are operating as
	 * a sta or not.  When operating as a sta we are generating
	 * a request based on our desired configuration.  Otherwise
	 * we are operational and the channel attributes identify
	 * how we've been setup (which might be different if a fixed
	 * channel is specified).
	 */
	if (ic->ic_opmode == IEEE80211_M_STA) {
		/* override 20/40 use based on config */
		if (ic->ic_flags_ext & IEEE80211_FEXT_USEHT40)
			caps |= IEEE80211_HTCAP_CHWIDTH40;
		else
			caps &= ~IEEE80211_HTCAP_CHWIDTH40;
		/* use advertised setting (locally constraint) */
		rxmax = MS(in->in_htparam, IEEE80211_HTCAP_MAXRXAMPDU);
		density = MS(in->in_htparam, IEEE80211_HTCAP_MPDUDENSITY);
	} else {
		/* override 20/40 use based on current channel */
		if (IEEE80211_IS_CHAN_HT40(ic->ic_curchan))
			caps |= IEEE80211_HTCAP_CHWIDTH40;
		else
			caps &= ~IEEE80211_HTCAP_CHWIDTH40;
		rxmax = ic->ic_ampdu_rxmax;
		density = ic->ic_ampdu_density;
	}
	/* adjust short GI based on channel and config */
	if ((ic->ic_flags_ext & IEEE80211_FEXT_SHORTGI20) == 0)
		caps &= ~IEEE80211_HTCAP_SHORTGI20;
	if ((ic->ic_flags_ext & IEEE80211_FEXT_SHORTGI40) == 0 ||
	    (caps & IEEE80211_HTCAP_CHWIDTH40) == 0)
		caps &= ~IEEE80211_HTCAP_SHORTGI40;
	ADDSHORT(frm, caps);

	/* HT parameters */
	*frm = SM(rxmax, IEEE80211_HTCAP_MAXRXAMPDU)
	    | SM(density, IEEE80211_HTCAP_MPDUDENSITY);
	frm++;

	/* pre-zero remainder of ie */
	(void) memset(frm, 0, sizeof (struct ieee80211_ie_htcap) -
	    offsetof(struct ieee80211_ie_htcap, hc_mcsset));

	/* supported MCS set */
	/*
	 * it would better to get the rate set from in_htrates
	 * so we can restrict it but for sta mode in_htrates isn't
	 * setup when we're called to form an AssocReq frame so for
	 * now we're restricted to the default HT rate set.
	 */
	ieee80211_set_htrates(frm, &ieee80211_rateset_11n);

	frm += sizeof (struct ieee80211_ie_htcap) -
	    offsetof(struct ieee80211_ie_htcap, hc_mcsset);

	return (frm);
#undef ADDSHORT
}

/*
 * Add 802.11n HT capabilities information element
 */
uint8_t *
ieee80211_add_htcap(uint8_t *frm, struct ieee80211_node *in)
{
	frm[0] = IEEE80211_ELEMID_HTCAP;
	frm[1] = sizeof (struct ieee80211_ie_htcap) - 2;
	return (ieee80211_add_htcap_body(frm + 2, in));
}

/*
 * Add Broadcom OUI wrapped standard HTCAP ie; this is
 * used for compatibility w/ pre-draft implementations.
 */
uint8_t *
ieee80211_add_htcap_vendor(uint8_t *frm, struct ieee80211_node *in)
{
	frm[0] = IEEE80211_ELEMID_VENDOR;
	frm[1] = 4 + sizeof (struct ieee80211_ie_htcap) - 2;
	frm[2] = (BCM_OUI >> 0) & 0xff;
	frm[3] = (BCM_OUI >> 8) & 0xff;
	frm[4] = (BCM_OUI >> 16) & 0xff;
	frm[5] = BCM_OUI_HTCAP;
	return (ieee80211_add_htcap_body(frm + 6, in));
}

/*
 * Construct the MCS bit mask of basic rates
 * for inclusion in an HT information element.
 */
static void
ieee80211_set_basic_htrates(uint8_t *frm, const struct ieee80211_htrateset *rs)
{
	int i;

	for (i = 0; i < rs->rs_nrates; i++) {
		int r = rs->rs_rates[i] & IEEE80211_RATE_VAL;
		if ((rs->rs_rates[i] & IEEE80211_RATE_BASIC) &&
		    r < IEEE80211_HTRATE_MAXSIZE) {
			/* NB: this assumes a particular implementation */
			ieee80211_setbit(frm, r);
		}
	}
}

/*
 * Update the HTINFO ie for a beacon frame.
 */
void
ieee80211_ht_update_beacon(struct ieee80211com *ic,
    struct ieee80211_beacon_offsets *bo)
{
#define	PROTMODE	(IEEE80211_HTINFO_OPMODE|IEEE80211_HTINFO_NONHT_PRESENT)
	struct ieee80211_ie_htinfo *ht =
	    (struct ieee80211_ie_htinfo *)bo->bo_htinfo;

	/* only update on channel change */
	ht->hi_ctrlchannel = ieee80211_chan2ieee(ic, ic->ic_curchan);
	ht->hi_byte1 = IEEE80211_HTINFO_RIFSMODE_PROH;
	if (IEEE80211_IS_CHAN_HT40U(ic->ic_curchan))
		ht->hi_byte1 |= IEEE80211_HTINFO_2NDCHAN_ABOVE;
	else if (IEEE80211_IS_CHAN_HT40D(ic->ic_curchan))
		ht->hi_byte1 |= IEEE80211_HTINFO_2NDCHAN_BELOW;
	else	/* LINTED */
		ht->hi_byte1 |= IEEE80211_HTINFO_2NDCHAN_NONE;
	if (IEEE80211_IS_CHAN_HT40(ic->ic_curchan))
		ht->hi_byte1 |= IEEE80211_HTINFO_TXWIDTH_2040;

	/* protection mode */
	ht->hi_byte2 = (ht->hi_byte2 &~ PROTMODE) | ic->ic_curhtprotmode;

	/* propagate to vendor ie's */
#undef PROTMODE
}

/*
 * Add body of an HTINFO information element.
 *
 * NB: We don't use struct ieee80211_ie_htinfo because we can
 * be called to fillin both a standard ie and a compat ie that
 * has a vendor OUI at the front.
 */
static uint8_t *
ieee80211_add_htinfo_body(uint8_t *frm, struct ieee80211_node *in)
{
	struct ieee80211com *ic = in->in_ic;

	/* pre-zero remainder of ie */
	(void) memset(frm, 0, sizeof (struct ieee80211_ie_htinfo) - 2);

	/* primary/control channel center */
	*frm++ = ieee80211_chan2ieee(ic, ic->ic_curchan);

	frm[0] = IEEE80211_HTINFO_RIFSMODE_PROH;
	if (IEEE80211_IS_CHAN_HT40U(ic->ic_curchan))
		frm[0] |= IEEE80211_HTINFO_2NDCHAN_ABOVE;
	else if (IEEE80211_IS_CHAN_HT40D(ic->ic_curchan))
		frm[0] |= IEEE80211_HTINFO_2NDCHAN_BELOW;
	else	/* LINTED */
		frm[0] |= IEEE80211_HTINFO_2NDCHAN_NONE;
	if (IEEE80211_IS_CHAN_HT40(ic->ic_curchan))
		frm[0] |= IEEE80211_HTINFO_TXWIDTH_2040;

	frm[1] = ic->ic_curhtprotmode;

	frm += 5;

	/* basic MCS set */
	ieee80211_set_basic_htrates(frm, &in->in_htrates);
	frm += sizeof (struct ieee80211_ie_htinfo) -
	    offsetof(struct ieee80211_ie_htinfo, hi_basicmcsset);
	return (frm);
}

/*
 * Add 802.11n HT information information element.
 */
uint8_t *
ieee80211_add_htinfo(uint8_t *frm, struct ieee80211_node *in)
{
	frm[0] = IEEE80211_ELEMID_HTINFO;
	frm[1] = sizeof (struct ieee80211_ie_htinfo) - 2;

	return (ieee80211_add_htinfo_body(frm + 2, in));
}

/*
 * Add Broadcom OUI wrapped standard HTINFO ie; this is
 * used for compatibility w/ pre-draft implementations.
 */
uint8_t *
ieee80211_add_htinfo_vendor(uint8_t *frm, struct ieee80211_node *in)
{
	frm[0] = IEEE80211_ELEMID_VENDOR;
	frm[1] = 4 + sizeof (struct ieee80211_ie_htinfo) - 2;
	frm[2] = (BCM_OUI >> 0) & 0xff;
	frm[3] = (BCM_OUI >> 8) & 0xff;
	frm[4] = (BCM_OUI >> 16) & 0xff;
	frm[5] = BCM_OUI_HTINFO;

	return (ieee80211_add_htinfo_body(frm + 6, in));
}

void
ieee80211_ht_attach(struct ieee80211com *ic)
{
	/* setup default aggregation policy */
	ic->ic_recv_action = ieee80211_aggr_recv_action;
	ic->ic_send_action = ieee80211_send_action;
	ic->ic_addba_request = ieee80211_addba_request;
	ic->ic_addba_response = ieee80211_addba_response;
	ic->ic_addba_stop = ieee80211_addba_stop;

	ic->ic_htprotmode = IEEE80211_PROT_RTSCTS;
	ic->ic_curhtprotmode = IEEE80211_HTINFO_OPMODE_PURE;

	/* get from driver */
	ic->ic_ampdu_rxmax = IEEE80211_HTCAP_MAXRXAMPDU_8K;
	ic->ic_ampdu_density = IEEE80211_HTCAP_MPDUDENSITY_NA;
	ic->ic_ampdu_limit = ic->ic_ampdu_rxmax;
	ic->ic_amsdu_limit = IEEE80211_HTCAP_MAXAMSDU_3839;

	if (ic->ic_htcaps & IEEE80211_HTC_HT) {
		/*
		 * Device is HT capable; enable all HT-related
		 * facilities by default.
		 * these choices may be too aggressive.
		 */
		ic->ic_flags_ext |= IEEE80211_FEXT_HT | IEEE80211_FEXT_HTCOMPAT;
		if (ic->ic_htcaps & IEEE80211_HTCAP_SHORTGI20)
			ic->ic_flags_ext |= IEEE80211_FEXT_SHORTGI20;
		/* infer from channel list? */
		if (ic->ic_htcaps & IEEE80211_HTCAP_CHWIDTH40) {
			ic->ic_flags_ext |= IEEE80211_FEXT_USEHT40;
			if (ic->ic_htcaps & IEEE80211_HTCAP_SHORTGI40)
				ic->ic_flags_ext |= IEEE80211_FEXT_SHORTGI40;
		}
		/* NB: A-MPDU and A-MSDU rx are mandated, these are tx only */
		ic->ic_flags_ext |= IEEE80211_FEXT_AMPDU_RX;
		if (ic->ic_htcaps & IEEE80211_HTC_AMPDU)
			ic->ic_flags_ext |= IEEE80211_FEXT_AMPDU_TX;
		ic->ic_flags_ext |= IEEE80211_FEXT_AMSDU_RX;
		if (ic->ic_htcaps & IEEE80211_HTC_AMSDU)
			ic->ic_flags_ext |= IEEE80211_FEXT_AMSDU_TX;
	}

#define	ieee80211_isset16(a, i)	((a) & (1 << (i)))
	/* fill default rate sets for 11NA/11NG if driver has no specified */
	if (ieee80211_isset16(ic->ic_modecaps, IEEE80211_MODE_11NA) &&
	    ic->ic_sup_rates[IEEE80211_MODE_11NA].ir_nrates == 0) {
		ic->ic_sup_rates[IEEE80211_MODE_11NA] =
		    ic->ic_sup_rates[IEEE80211_MODE_11A];
	}

	if (ieee80211_isset16(ic->ic_modecaps, IEEE80211_MODE_11NG) &&
	    ic->ic_sup_rates[IEEE80211_MODE_11NG].ir_nrates == 0) {
		ic->ic_sup_rates[IEEE80211_MODE_11NG] =
		    ic->ic_sup_rates[IEEE80211_MODE_11G];
	}
#undef ieee80211_isset16
}

/* ARGSUSED */
void
ieee80211_ht_detach(struct ieee80211com *ic)
{
}

/* ARGSUSED */
static void
ht_announce(struct ieee80211com *ic, int mode,
	const struct ieee80211_htrateset *rs)
{
	int i, rate;

	ieee80211_dbg(IEEE80211_MSG_HT, "%s MCS: \n",
	    ieee80211_phymode_name[mode]);
	for (i = 0; i < rs->rs_nrates; i++) {
		rate = ieee80211_htrates[rs->rs_rates[i]];
		ieee80211_dbg(IEEE80211_MSG_HT, "%s%d%sMbps\n",
		    (i != 0 ? " " : ""),
		    rate / 2, ((rate & 0x1) != 0 ? ".5" : ""));
	}
}

void
ieee80211_ht_announce(struct ieee80211com *ic)
{
	if (ic->ic_modecaps & (1 << IEEE80211_MODE_11NA))
		ht_announce(ic, IEEE80211_MODE_11NA, &ieee80211_rateset_11n);
	if (ic->ic_modecaps & (1 << IEEE80211_MODE_11NG))
		ht_announce(ic, IEEE80211_MODE_11NG, &ieee80211_rateset_11n);
}

/* ARGSUSED */
const struct ieee80211_htrateset *
ieee80211_get_suphtrates(struct ieee80211com *ic,
	const struct ieee80211_channel *c)
{
	return (&ieee80211_rateset_11n);
}
