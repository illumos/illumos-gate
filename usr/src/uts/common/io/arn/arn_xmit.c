/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2008 Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
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
#include <sys/mac_provider.h>
#include <sys/dlpi.h>
#include <sys/ethernet.h>
#include <sys/list.h>
#include <sys/byteorder.h>
#include <sys/strsun.h>
#include <sys/policy.h>
#include <inet/common.h>
#include <inet/nd.h>
#include <inet/mi.h>
#include <inet/wifi_ioctl.h>
#include <sys/mac_wifi.h>

#include "arn_core.h"

#define	BITS_PER_BYTE		8
#define	OFDM_PLCP_BITS		22
#define	HT_RC_2_MCS(_rc)	((_rc) & 0x0f)
#define	HT_RC_2_STREAMS(_rc)	((((_rc) & 0x78) >> 3) + 1)
#define	L_STF			8
#define	L_LTF			8
#define	L_SIG			4
#define	HT_SIG			8
#define	HT_STF			4
#define	HT_LTF(_ns)		(4 * (_ns))
#define	SYMBOL_TIME(_ns)	((_ns) << 2) /* ns * 4 us */
#define	SYMBOL_TIME_HALFGI(_ns)	(((_ns) * 18 + 4) / 5)  /* ns * 3.6 us */
#define	NUM_SYMBOLS_PER_USEC(_usec)	(_usec >> 2)
#define	NUM_SYMBOLS_PER_USEC_HALFGI(_usec)	(((_usec*5)-4)/18)

#define	OFDM_SIFS_TIME	16

static uint32_t bits_per_symbol[][2] = {
	/* 20MHz 40MHz */
	{    26,  54 },		/*  0: BPSK */
	{    52,  108 },	/*  1: QPSK 1/2 */
	{    78,  162 },	/*  2: QPSK 3/4 */
	{   104,  216 },	/*  3: 16-QAM 1/2 */
	{   156,  324 },	/*  4: 16-QAM 3/4 */
	{   208,  432 },	/*  5: 64-QAM 2/3 */
	{   234,  486 },	/*  6: 64-QAM 3/4 */
	{   260,  540 },	/*  7: 64-QAM 5/6 */
	{    52,  108 },	/*  8: BPSK */
	{   104,  216 },	/*  9: QPSK 1/2 */
	{   156,  324 },	/* 10: QPSK 3/4 */
	{   208,  432 },	/* 11: 16-QAM 1/2 */
	{   312,  648 },	/* 12: 16-QAM 3/4 */
	{   416,  864 },	/* 13: 64-QAM 2/3 */
	{   468,  972 },	/* 14: 64-QAM 3/4 */
	{   520,  1080 },	/* 15: 64-QAM 5/6 */
};

#define	IS_HT_RATE(_rate)	((_rate) & 0x80)

#ifdef ARN_TX_AGGREGRATION
static void arn_tx_send_ht_normal(struct arn_softc *sc, struct ath_txq *txq,
    struct ath_atx_tid *tid, list_t *bf_list);
static void arn_tx_complete_buf(struct arn_softc *sc, struct ath_buf *bf,
    list_t *bf_q, int txok, int sendbar);
static void arn_tx_txqaddbuf(struct arn_softc *sc, struct ath_txq *txq,
    list_t *buf_list);
static void arn_buf_set_rate(struct arn_softc *sc, struct ath_buf *bf);
static int arn_tx_num_badfrms(struct arn_softc *sc,
    struct ath_buf *bf, int txok);
static void arn_tx_rc_status(struct ath_buf *bf, struct ath_desc *ds,
    int nbad, int txok, boolean_t update_rc);
#endif

static void
arn_get_beaconconfig(struct arn_softc *sc, struct ath_beacon_config *conf)
{
	ieee80211com_t *ic = (ieee80211com_t *)sc;
	struct ieee80211_node *in = ic->ic_bss;

	/* fill in beacon config data */

	conf->beacon_interval = in->in_intval ?
	    in->in_intval : ATH_DEFAULT_BINTVAL;
	conf->listen_interval = 100;
	conf->dtim_count = 1;
	conf->bmiss_timeout = ATH_DEFAULT_BMISS_LIMIT * conf->listen_interval;
}

/* Aggregation logic */

#ifdef ARN_TX_AGGREGATION

/* Check if it's okay to send out aggregates */
static int
arn_aggr_query(struct arn_softc *sc, struct ath_node *an, uint8_t tidno)
{
	struct ath_atx_tid *tid;
	tid = ATH_AN_2_TID(an, tidno);

	if (tid->state & AGGR_ADDBA_COMPLETE ||
	    tid->state & AGGR_ADDBA_PROGRESS)
		return (1);
	else
		return (0);
}

/*
 * queue up a dest/ac pair for tx scheduling
 * NB: must be called with txq lock held
 */
static void
arn_tx_queue_tid(struct ath_txq *txq, struct ath_atx_tid *tid)
{
	struct ath_atx_ac *ac = tid->ac;

	/* if tid is paused, hold off */
	if (tid->paused)
		return;

	/* add tid to ac atmost once */
	if (tid->sched)
		return;

	tid->sched = B_TRUE;
	list_insert_tail(&ac->tid_q, &tid->list);

	/* add node ac to txq atmost once */
	if (ac->sched)
		return;

	ac->sched = B_TRUE;
	list_insert_tail(&txq->axq_acq, &ac->list);
}

/* pause a tid */
static void
arn_tx_pause_tid(struct arn_softc *sc, struct ath_atx_tid *tid)
{
	struct ath_txq *txq = &sc->sc_txq[tid->ac->qnum];

	mutex_enter(&txq->axq_lock);

	tid->paused++;

	mutex_exit(&txq->axq_lock);
}

/* resume a tid and schedule aggregate */
void
arn_tx_resume_tid(struct arn_softc *sc, struct ath_atx_tid *tid)
{
	struct ath_txq *txq = &sc->sc_txq[tid->ac->qnum];

	ASSERT(tid->paused > 0);
	mutex_enter(&txq->axq_lock);

	tid->paused--;

	if (tid->paused > 0)
		goto unlock;

	if (list_empty(&tid->buf_q))
		goto unlock;

	/*
	 * Add this TID to scheduler and try to send out aggregates
	 */
	arn_tx_queue_tid(txq, tid);
	arn_txq_schedule(sc, txq);
unlock:
	mutex_exit(&txq->axq_lock);
}

/* flush tid's software queue and send frames as non-ampdu's */
static void
arn_tx_flush_tid(struct arn_softc *sc, struct ath_atx_tid *tid)
{
	struct ath_txq *txq = &sc->sc_txq[tid->ac->qnum];
	struct ath_buf *bf;

	list_t list;
	list_create(&list, sizeof (struct ath_buf),
	    offsetof(struct ath_buf, bf_node));

	ASSERT(tid->paused > 0);
	mutex_enter(&txq->axq_lock);

	tid->paused--;

	if (tid->paused > 0) {
		mutex_exit(&txq->axq_lock);
		return;
	}

	while (!list_empty(&tid->buf_q)) {
		bf = list_head(&tid->buf_q);
		ASSERT(!bf_isretried(bf));
		list_remove(&tid->buf_q, bf);
		list_insert_tail(&list, bf);
		arn_tx_send_ht_normal(sc, txq, tid, &list);
	}

	mutex_exit(&txq->axq_lock);
}

/* Update block ack window */
static void
arn_tx_update_baw(struct arn_softc *sc, struct ath_atx_tid *tid, int seqno)
{
	int index, cindex;

	index  = ATH_BA_INDEX(tid->seq_start, seqno);
	cindex = (tid->baw_head + index) & (ATH_TID_MAX_BUFS - 1);

	tid->tx_buf[cindex] = NULL;

	while (tid->baw_head != tid->baw_tail && !tid->tx_buf[tid->baw_head]) {
		INCR(tid->seq_start, IEEE80211_SEQ_MAX);
		INCR(tid->baw_head, ATH_TID_MAX_BUFS);
	}
}

/* Add a sub-frame to block ack window */
static void
arn_tx_addto_baw(struct arn_softc *sc, struct ath_atx_tid *tid,
    struct ath_buf *bf)
{
	int index, cindex;

	if (bf_isretried(bf))
		return;

	index  = ATH_BA_INDEX(tid->seq_start, bf->bf_seqno);
	cindex = (tid->baw_head + index) & (ATH_TID_MAX_BUFS - 1);

	ASSERT(tid->tx_buf[cindex] == NULL);
	tid->tx_buf[cindex] = bf;

	if (index >= ((tid->baw_tail - tid->baw_head) &
	    (ATH_TID_MAX_BUFS - 1))) {
		tid->baw_tail = cindex;
		INCR(tid->baw_tail, ATH_TID_MAX_BUFS);
	}
}

/*
 * TODO: For frame(s) that are in the retry state, we will reuse the
 * sequence number(s) without setting the retry bit. The
 * alternative is to give up on these and BAR the receiver's window
 * forward.
 */
static void
arn_tid_drain(struct arn_softc *sc,
    struct ath_txq *txq,
    struct ath_atx_tid *tid)
{
	struct ath_buf *bf;

	list_t list;
	list_create(&list, sizeof (struct ath_buf),
	    offsetof(struct ath_buf, bf_node));

	for (;;) {
		if (list_empty(&tid->buf_q))
			break;

		bf = list_head(&tid->buf_q);
		list_remove(&tid->buf_q, bf);
		list_insert_tail(&list, bf);

		if (bf_isretried(bf))
			arn_tx_update_baw(sc, tid, bf->bf_seqno);

		mutex_enter(&txq->axq_lock);
		arn_tx_complete_buf(sc, bf, &list, 0, 0);
		mutex_exit(&txq->axq_lock);
	}

	tid->seq_next = tid->seq_start;
	tid->baw_tail = tid->baw_head;
}

static void
arn_tx_set_retry(struct arn_softc *sc, struct ath_buf *bf)
{
	struct ieee80211_frame *wh;
	wh = (struct ieee80211_frame *)bf->bf_dma.mem_va;

	bf->bf_state.bf_type |= BUF_RETRY;
	bf->bf_retries++;

	*(uint16_t *)&wh->i_seq[0] |= LE_16(0x0800); /* ??? */
}

static struct ath_buf *
arn_clone_txbuf(struct arn_softc *sc, struct ath_buf *bf)
{
	struct ath_buf *tbf;

	mutex_enter(&sc->sc_txbuflock);
	ASSERT(!list_empty((&sc->sc_txbuf_list)));

	tbf = list_head(&sc->sc_txbuf_list);
	list_remove(&sc->sc_txbuf_list, tbf);
	mutex_exit(&sc->sc_txbuflock);

	ATH_TXBUF_RESET(tbf);

	tbf->bf_daddr = bf->bf_daddr; /* physical addr of desc */
	tbf->bf_dma = bf->bf_dma; /* dma area for buf */
	*(tbf->bf_desc) = *(bf->bf_desc); /* virtual addr of desc */
	tbf->bf_state = bf->bf_state; /* buffer state */

	return (tbf);
}

static void
arn_tx_complete_aggr(struct arn_softc *sc, struct ath_txq *txq,
    struct ath_buf *bf, list_t *bf_q, int txok)
{
	struct ieee80211_node *in;
	struct ath_node *an = NULL;
	struct ath_atx_tid *tid = NULL;
	struct ath_buf *bf_next, *bf_last = bf->bf_lastbf;
	struct ath_desc *ds = bf_last->bf_desc;

	list_t list, list_pending;
	uint16_t seq_st = 0, acked_cnt = 0, txfail_cnt = 0;
	uint32_t ba[WME_BA_BMP_SIZE >> 5];
	int isaggr, txfail, txpending, sendbar = 0, needreset = 0, nbad = 0;
	boolean_t rc_update = B_TRUE;

	an = ATH_NODE(in); /* Be sure in != NULL */
	tid = ATH_AN_2_TID(an, bf->bf_tidno);

	isaggr = bf_isaggr(bf);
	memset(ba, 0, WME_BA_BMP_SIZE >> 3);

	if (isaggr && txok) {
		if (ATH_DS_TX_BA(ds)) {
			seq_st = ATH_DS_BA_SEQ(ds);
			memcpy(ba, ATH_DS_BA_BITMAP(ds),
			    WME_BA_BMP_SIZE >> 3);
		} else {
			/*
			 * AR5416 can become deaf/mute when BA
			 * issue happens. Chip needs to be reset.
			 * But AP code may have sychronization issues
			 * when perform internal reset in this routine.
			 * Only enable reset in STA mode for now.
			 */
			if (sc->sc_ah->ah_opmode == ATH9K_M_STA)
				needreset = 1;
		}
	}

	list_create(&list_pending, sizeof (struct ath_buf),
	    offsetof(struct ath_buf, bf_node));
	list_create(&list, sizeof (struct ath_buf),
	    offsetof(struct ath_buf, bf_node));

	nbad = arn_tx_num_badfrms(sc, bf, txok);
	while (bf) {
		txfail = txpending = 0;
		bf_next = bf->bf_next;

		if (ATH_BA_ISSET(ba, ATH_BA_INDEX(seq_st, bf->bf_seqno))) {
			/*
			 * transmit completion, subframe is
			 * acked by block ack
			 */
			acked_cnt++;
		} else if (!isaggr && txok) {
			/* transmit completion */
			acked_cnt++;
		} else {
			if (!(tid->state & AGGR_CLEANUP) &&
			    ds->ds_txstat.ts_flags != ATH9K_TX_SW_ABORTED) {
				if (bf->bf_retries < ATH_MAX_SW_RETRIES) {
					arn_tx_set_retry(sc, bf);
					txpending = 1;
				} else {
					bf->bf_state.bf_type |= BUF_XRETRY;
					txfail = 1;
					sendbar = 1;
					txfail_cnt++;
				}
			} else {
				/*
				 * cleanup in progress, just fail
				 * the un-acked sub-frames
				 */
				txfail = 1;
			}
		}

		if (bf_next == NULL) {
			/* INIT_LIST_HEAD */
			list_create(&list, sizeof (struct ath_buf),
			    offsetof(struct ath_buf, bf_node));
		} else {
			ASSERT(!list_empty(bf_q));
			list_remove(bf_q, bf);
			list_insert_tail(&list, bf);
		}

		if (!txpending) {
			/*
			 * complete the acked-ones/xretried ones; update
			 * block-ack window
			 */
			mutex_enter(&txq->axq_lock);
			arn_tx_update_baw(sc, tid, bf->bf_seqno);
			mutex_exit(&txq->axq_lock);

			if (rc_update && (acked_cnt == 1 || txfail_cnt == 1)) {
				ath_tx_rc_status(bf, ds, nbad, txok, B_TRUE);
				rc_update = B_FALSE;
			} else {
				ath_tx_rc_status(bf, ds, nbad, txok, B_FALSE);
			}

			ath_tx_complete_buf(sc, bf, list, !txfail, sendbar);
		} else {
			/* retry the un-acked ones */
			if (bf->bf_next == NULL &&
			    bf_last->bf_status & ATH_BUFSTATUS_STALE) {
				struct ath_buf *tbf;

				tbf = arn_clone_txbuf(sc, bf_last);
				ath9k_hw_cleartxdesc(sc->sc_ah, tbf->bf_desc);
				list_insert_tail(&list, tbf);
			} else {
				/*
				 * Clear descriptor status words for
				 * software retry
				 */
				ath9k_hw_cleartxdesc(sc->sc_ah, bf->bf_desc);
			}

			/*
			 * Put this buffer to the temporary pending
			 * queue to retain ordering
			 */
			list_splice_tail_init(&list, &list_pending);
			/*
			 * Insert src list after dst list.
			 * Empty src list thereafter
			 */
			list_move_tail(&list_pending, &list);
			/* should re-initialize list here??? */
		}

		bf = bf_next;
	}

	if (tid->state & AGGR_CLEANUP) {
		if (tid->baw_head == tid->baw_tail) {
			tid->state &= ~AGGR_ADDBA_COMPLETE;
			tid->addba_exchangeattempts = 0;
			tid->state &= ~AGGR_CLEANUP;

			/* send buffered frames as singles */
			arn_tx_flush_tid(sc, tid);
		}
		return;
	}

	/*
	 * prepend un-acked frames to the beginning of
	 * the pending frame queue
	 */

	if (!list_empty(&list_pending)) {
		mutex_enter(&txq->axq_lock);
		list_move_tail(&list_pending, &tid->buf_q);
		arn_tx_queue_tid(txq, tid);
		mutex_exit(&txq->axq_lock);
	}
}

static uint32_t
arn_lookup_rate(struct arn_softc *sc, struct ath_buf *bf,
    struct ath_atx_tid *tid)
{
	struct ath_rate_table *rate_table = sc->sc_currates;
	struct ath9k_tx_rate *rates;
	struct ath_tx_info_priv *tx_info_priv;
	uint32_t max_4ms_framelen, frmlen;
	uint16_t aggr_limit, legacy = 0, maxampdu;
	int i;

	/* ???  */
	rates = (struct ath9k_tx_rate *)bf->rates;
	tx_info_priv = (struct ath_tx_info_priv *)&bf->tx_info_priv;

	/*
	 * Find the lowest frame length among the rate series that will have a
	 * 4ms transmit duration.
	 * TODO - TXOP limit needs to be considered.
	 */
	max_4ms_framelen = ATH_AMPDU_LIMIT_MAX;

	for (i = 0; i < 4; i++) {
		if (rates[i].count) {
			if (!WLAN_RC_PHY_HT
			    (rate_table->info[rates[i].idx].phy)) {
				legacy = 1;
				break;
			}

			frmlen =
			    rate_table->info[rates[i].idx].max_4ms_framelen;
			max_4ms_framelen = min(max_4ms_framelen, frmlen);
		}
	}

	/*
	 * limit aggregate size by the minimum rate if rate selected is
	 * not a probe rate, if rate selected is a probe rate then
	 * avoid aggregation of this packet.
	 */
	if (legacy)
		return (0);

	aggr_limit = min(max_4ms_framelen, (uint32_t)ATH_AMPDU_LIMIT_DEFAULT);

	/*
	 * h/w can accept aggregates upto 16 bit lengths (65535).
	 * The IE, however can hold upto 65536, which shows up here
	 * as zero. Ignore 65536 since we  are constrained by hw.
	 */
	maxampdu = tid->an->maxampdu;
	if (maxampdu)
		aggr_limit = min(aggr_limit, maxampdu);

	return (aggr_limit);
}

/*
 * Returns the number of delimiters to be added to
 * meet the minimum required mpdudensity.
 * caller should make sure that the rate is HT rate .
 */
static int
arn_compute_num_delims(struct arn_softc *sc, struct ath_atx_tid *tid,
    struct ath_buf *bf, uint16_t frmlen)
{
	struct ath_rate_table *rt = sc->sc_currates;
	struct ath9k_tx_rate *rates = (struct ath9k_tx_rate *)bf->rates;
	uint32_t nsymbits, nsymbols, mpdudensity;
	uint16_t minlen;
	uint8_t rc, flags, rix;
	int width, half_gi, ndelim, mindelim;

	/* Select standard number of delimiters based on frame length alone */
	ndelim = ATH_AGGR_GET_NDELIM(frmlen);

	/*
	 * If encryption enabled, hardware requires some more padding between
	 * subframes.
	 * TODO - this could be improved to be dependent on the rate.
	 * The hardware can keep up at lower rates, but not higher rates
	 */
	if (bf->bf_keytype != ATH9K_KEY_TYPE_CLEAR)
		ndelim += ATH_AGGR_ENCRYPTDELIM;

	/*
	 * Convert desired mpdu density from microeconds to bytes based
	 * on highest rate in rate series (i.e. first rate) to determine
	 * required minimum length for subframe. Take into account
	 * whether high rate is 20 or 40Mhz and half or full GI.
	 */
	mpdudensity = tid->an->mpdudensity;

	/*
	 * If there is no mpdu density restriction, no further calculation
	 * is needed.
	 */
	if (mpdudensity == 0)
		return (ndelim);

	rix = rates[0].idx;
	flags = rates[0].flags;
	rc = rt->info[rix].ratecode;
	width = (flags & ATH9K_TX_RC_40_MHZ_WIDTH) ? 1 : 0;
	half_gi = (flags & ATH9K_TX_RC_SHORT_GI) ? 1 : 0;

	if (half_gi)
		nsymbols = NUM_SYMBOLS_PER_USEC_HALFGI(mpdudensity);
	else
		nsymbols = NUM_SYMBOLS_PER_USEC(mpdudensity);

	if (nsymbols == 0)
		nsymbols = 1;

	nsymbits = bits_per_symbol[HT_RC_2_MCS(rc)][width];
	minlen = (nsymbols * nsymbits) / BITS_PER_BYTE;

	if (frmlen < minlen) {
		mindelim = (minlen - frmlen) / ATH_AGGR_DELIM_SZ;
		ndelim = max(mindelim, ndelim);
	}

	return (ndelim);
}

static enum ATH_AGGR_STATUS
arn_tx_form_aggr(struct arn_softc *sc, struct ath_atx_tid *tid,
    list_t *bf_q)
{
#define	PADBYTES(_len) ((4 - ((_len) % 4)) % 4)
	struct ath_buf *bf, *bf_first, *bf_prev = NULL;
	int rl = 0, nframes = 0, ndelim, prev_al = 0;
	uint16_t aggr_limit = 0, al = 0, bpad = 0,
	    al_delta, h_baw = tid->baw_size / 2;
	enum ATH_AGGR_STATUS status = ATH_AGGR_DONE;

	bf_first = list_head(&tid->buf_q);

	do {
		bf = list_head(&tid->buf_q);

		/* do not step over block-ack window */
		if (!BAW_WITHIN(tid->seq_start, tid->baw_size, bf->bf_seqno)) {
			status = ATH_AGGR_BAW_CLOSED;
			break;
		}

		if (!rl) {
			aggr_limit = arn_lookup_rate(sc, bf, tid);
			rl = 1;
		}

		/* do not exceed aggregation limit */
		al_delta = ATH_AGGR_DELIM_SZ + bf->bf_frmlen;

		if (nframes &&
		    (aggr_limit < (al + bpad + al_delta + prev_al))) {
			status = ATH_AGGR_LIMITED;
			break;
		}

		/* do not exceed subframe limit */
		if (nframes >= min((int)h_baw, ATH_AMPDU_SUBFRAME_DEFAULT)) {
			status = ATH_AGGR_LIMITED;
			break;
		}
		nframes++;

		/* add padding for previous frame to aggregation length */
		al += bpad + al_delta;

		/*
		 * Get the delimiters needed to meet the MPDU
		 * density for this node.
		 */
		ndelim =
		    arn_compute_num_delims(sc, tid, bf_first, bf->bf_frmlen);
		bpad = PADBYTES(al_delta) + (ndelim << 2);

		bf->bf_next = NULL;
		bf->bf_desc->ds_link = 0;

		/* link buffers of this frame to the aggregate */
		arn_tx_addto_baw(sc, tid, bf);
		ath9k_hw_set11n_aggr_middle(sc->sc_ah, bf->bf_desc, ndelim);
		list_remove(&tid->buf_q, bf);
		list_insert_tail(bf_q, bf);
		if (bf_prev) {
			bf_prev->bf_next = bf;
			bf_prev->bf_desc->ds_link = bf->bf_daddr;
		}
		bf_prev = bf;
	} while (!list_empty(&tid->buf_q));

	bf_first->bf_al = al;
	bf_first->bf_nframes = nframes;

	return (status);
#undef PADBYTES
}

static void
arn_tx_sched_aggr(struct arn_softc *sc, struct ath_txq *txq,
    struct ath_atx_tid *tid)
{
	struct ath_buf *bf;
	enum ATH_AGGR_STATUS status;
	list_t bf_q;

	do {
		if (list_empty(&tid->buf_q))
			return;

		/* INIT_LIST_HEAD */
		list_create(&bf_q, sizeof (struct ath_buf),
		    offsetof(struct ath_buf, bf_node));

		status = arn_tx_form_aggr(sc, tid, &bf_q);

		/*
		 * no frames picked up to be aggregated;
		 * block-ack window is not open.
		 */
		if (list_empty(&bf_q))
			break;

		bf = list_head(&bf_q);
		bf->bf_lastbf = list_object(&bf_q, bf->bf_node.list_prev);

		/* if only one frame, send as non-aggregate */
		if (bf->bf_nframes == 1) {
			bf->bf_state.bf_type &= ~BUF_AGGR;
			ath9k_hw_clr11n_aggr(sc->sc_ah, bf->bf_desc);
			ath_buf_set_rate(sc, bf);
			arn_tx_txqaddbuf(sc, txq, &bf_q);
			continue;
		}

		/* setup first desc of aggregate */
		bf->bf_state.bf_type |= BUF_AGGR;
		ath_buf_set_rate(sc, bf);
		ath9k_hw_set11n_aggr_first(sc->sc_ah, bf->bf_desc, bf->bf_al);

		/* anchor last desc of aggregate */
		ath9k_hw_set11n_aggr_last(sc->sc_ah, bf->bf_lastbf->bf_desc);

		txq->axq_aggr_depth++;
		arn_tx_txqaddbuf(sc, txq, &bf_q);

	} while (txq->axq_depth < ATH_AGGR_MIN_QDEPTH &&
	    status != ATH_AGGR_BAW_CLOSED);
}

int
arn_tx_aggr_start(struct arn_softc *sc, struct ieee80211_node *in,
    uint16_t tid, uint16_t *ssn)
{
	struct ath_atx_tid *txtid;
	struct ath_node *an;

	an = ATH_NODE(in);

	if (sc->sc_flags & SC_OP_TXAGGR) {
		txtid = ATH_AN_2_TID(an, tid);
		txtid->state |= AGGR_ADDBA_PROGRESS;
		arn_tx_pause_tid(sc, txtid);
		*ssn = txtid->seq_start;
	}

	return (0);
}

int
arn_tx_aggr_stop(struct arn_softc *sc, struct ieee80211_node *in, uint16_t tid)
{
	struct ath_node *an = ATH_NODE(in);
	struct ath_atx_tid *txtid = ATH_AN_2_TID(an, tid);
	struct ath_txq *txq = &sc->sc_txq[txtid->ac->qnum];
	struct ath_buf *bf;

	list_t list;
	list_create(&list, sizeof (struct ath_buf),
	    offsetof(struct ath_buf, bf_node));

	if (txtid->state & AGGR_CLEANUP)
		return (0);

	if (!(txtid->state & AGGR_ADDBA_COMPLETE)) {
		txtid->addba_exchangeattempts = 0;
		return (0);
	}

	arn_tx_pause_tid(sc, txtid);

	/* drop all software retried frames and mark this TID */
	mutex_enter(&txq->axq_lock);
	while (!list_empty(&txtid->buf_q)) {
		/* list_first_entry */
		bf = list_head(&txtid->buf_q);
		if (!bf_isretried(bf)) {
			/*
			 * NB: it's based on the assumption that
			 * software retried frame will always stay
			 * at the head of software queue.
			 */
			break;
		}
		list_remove(&txtid->buf_q, bf);
		list_insert_tail(&list, bf);
		arn_tx_update_baw(sc, txtid, bf->bf_seqno);
		// ath_tx_complete_buf(sc, bf, &list, 0, 0); /* to do */
	}
	mutex_exit(&txq->axq_lock);

	if (txtid->baw_head != txtid->baw_tail) {
		txtid->state |= AGGR_CLEANUP;
	} else {
		txtid->state &= ~AGGR_ADDBA_COMPLETE;
		txtid->addba_exchangeattempts = 0;
		arn_tx_flush_tid(sc, txtid);
	}

	return (0);
}

void
arn_tx_aggr_resume(struct arn_softc *sc,
    struct ieee80211_node *in,
    uint16_t tid)
{
	struct ath_atx_tid *txtid;
	struct ath_node *an;

	an = ATH_NODE(in);

	if (sc->sc_flags & SC_OP_TXAGGR) {
		txtid = ATH_AN_2_TID(an, tid);
		txtid->baw_size = (0x8) << sc->sc_ht_conf.ampdu_factor;
		txtid->state |= AGGR_ADDBA_COMPLETE;
		txtid->state &= ~AGGR_ADDBA_PROGRESS;
		arn_tx_resume_tid(sc, txtid);
	}
}

boolean_t
arn_tx_aggr_check(struct arn_softc *sc, struct ath_node *an, uint8_t tidno)
{
	struct ath_atx_tid *txtid;

	if (!(sc->sc_flags & SC_OP_TXAGGR))
		return (B_FALSE);

	txtid = ATH_AN_2_TID(an, tidno);

	if (!(txtid->state & AGGR_ADDBA_COMPLETE)) {
		if (!(txtid->state & AGGR_ADDBA_PROGRESS) &&
		    (txtid->addba_exchangeattempts < ADDBA_EXCHANGE_ATTEMPTS)) {
			txtid->addba_exchangeattempts++;
			return (B_TRUE);
		}
	}

	return (B_FALSE);
}

/* Queue Management */

static void
arn_txq_drain_pending_buffers(struct arn_softc *sc, struct ath_txq *txq)
{
	struct ath_atx_ac *ac, *ac_tmp;
	struct ath_atx_tid *tid, *tid_tmp;

	list_for_each_entry_safe(ac, ac_tmp, &txq->axq_acq) {
		list_remove(&txq->axq_acq, ac);
		ac->sched = B_FALSE;
		list_for_each_entry_safe(tid, tid_tmp, &ac->tid_q) {
			list_remove(&ac->tid_q, tid);
			tid->sched = B_FALSE;
			arn_tid_drain(sc, txq, tid);
		}
	}
}

int
arn_tx_get_qnum(struct arn_softc *sc, int qtype, int haltype)
{
	int qnum;

	switch (qtype) {
	case ATH9K_TX_QUEUE_DATA:
		if (haltype >= ARRAY_SIZE(sc->sc_haltype2q)) {
			ARN_DBG((ARN_DBG_FATAL, "arn: arn_tx_get_qnum(): "
			    "HAL AC %u out of range, max %zu!\n",
			    haltype, ARRAY_SIZE(sc->sc_haltype2q)));
			return (-1);
		}
		qnum = sc->sc_haltype2q[haltype];
		break;
	case ATH9K_TX_QUEUE_BEACON:
		qnum = sc->sc_beaconq;
		break;
	case ATH9K_TX_QUEUE_CAB:
		qnum = sc->sc_cabq->axq_qnum;
		break;
	default:
		qnum = -1;
	}
	return (qnum);
}

struct ath_txq *
arn_test_get_txq(struct arn_softc *sc, struct ieee80211_node *in,
    struct ieee80211_frame *wh, uint8_t type)
{
	struct ieee80211_qosframe *qwh = NULL;
	struct ath_txq *txq = NULL;
	int tid = -1;
	int qos_ac;
	int qnum;

	if (in->in_flags & IEEE80211_NODE_QOS) {

		if ((type & IEEE80211_FC0_TYPE_MASK) ==
		    IEEE80211_FC0_TYPE_DATA) {

			if (wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_QOS) {
				qwh = (struct ieee80211_qosframe *)wh;

				tid = qwh->i_qos[0] & IEEE80211_QOS_TID;
				switch (tid) {
				case 1:
				case 2:
					qos_ac = WME_AC_BK;
				case 0:
				case 3:
					qos_ac = WME_AC_BE;
				case 4:
				case 5:
					qos_ac = WME_AC_VI;
				case 6:
				case 7:
					qos_ac = WME_AC_VO;
				}
			}
		} else {
			qos_ac = WME_AC_VO;
		}
	} else if ((type & IEEE80211_FC0_TYPE_MASK) ==
	    IEEE80211_FC0_TYPE_MGT) {
			qos_ac = WME_AC_VO;
	} else if ((type & IEEE80211_FC0_TYPE_MASK) ==
	    IEEE80211_FC0_TYPE_CTL) {
			qos_ac = WME_AC_VO;
	} else {
			qos_ac = WME_AC_BK;
	}
	qnum = arn_get_hal_qnum(qos_ac, sc);
	txq = &sc->sc_txq[qnum];

	mutex_enter(&txq->axq_lock);

	if (txq->axq_depth >= (ATH_TXBUF - 20)) {
		ARN_DBG((ARN_DBG_XMIT,
		    "TX queue: %d is full, depth: %d\n",
		    qnum, txq->axq_depth));
		/* stop th queue */
		sc->sc_resched_needed = B_TRUE;
		txq->stopped = 1;
		mutex_exit(&txq->axq_lock);
		return (NULL);
	}

	mutex_exit(&txq->axq_lock);

	return (txq);
}

/* Called only when tx aggregation is enabled and HT is supported */
static void
assign_aggr_tid_seqno(struct arn_softc *sc,
    struct ath_buf *bf,
    struct ieee80211_frame *wh)
{
	struct ath_node *an;
	struct ath_atx_tid *tid;
	struct ieee80211_node *in;
	struct ieee80211_qosframe *qwh = NULL;
	ieee80211com_t *ic = (ieee80211com_t *)sc;

	in = ieee80211_find_txnode(ic, wh->i_addr1);
	if (in == NULL) {
		arn_problem("assign_aggr_tid_seqno():"
		    "failed to find tx node\n");
		return;
	}
	an = ATH_NODE(in);

	/* Get tidno */
	if (in->in_flags & IEEE80211_NODE_QOS) {
		if (wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_QOS) {
			qwh = (struct ieee80211_qosframe *)wh;
			bf->bf_tidno = qwh->i_qos[0] & IEEE80211_QOS_TID;
		}
	}

	/* Get seqno */
	/*
	 * For HT capable stations, we save tidno for later use.
	 * We also override seqno set by upper layer with the one
	 * in tx aggregation state.
	 *
	 * If fragmentation is on, the sequence number is
	 * not overridden, since it has been
	 * incremented by the fragmentation routine.
	 *
	 * FIXME: check if the fragmentation threshold exceeds
	 * IEEE80211 max.
	 */
	tid = ATH_AN_2_TID(an, bf->bf_tidno);

	*(uint16_t *)&wh->i_seq[0] =
	    LE_16(tid->seq_next << IEEE80211_SEQ_SEQ_SHIFT);
	bf->bf_seqno = tid->seq_next;
	/* LINTED E_CONSTANT_CONDITION */
	INCR(tid->seq_next, IEEE80211_SEQ_MAX);

	/* release node */
	ieee80211_free_node(in);
}

/* Compute the number of bad frames */
/* ARGSUSED */
static int
arn_tx_num_badfrms(struct arn_softc *sc, struct ath_buf *bf, int txok)
{
	struct ath_buf *bf_last = bf->bf_lastbf;
	struct ath_desc *ds = bf_last->bf_desc;
	uint16_t seq_st = 0;
	uint32_t ba[WME_BA_BMP_SIZE >> 5];
	int ba_index;
	int nbad = 0;
	int isaggr = 0;

	if (ds->ds_txstat.ts_flags == ATH9K_TX_SW_ABORTED)
		return (0);

	isaggr = bf_isaggr(bf);
	if (isaggr) {
		seq_st = ATH_DS_BA_SEQ(ds);
		memcpy(ba, ATH_DS_BA_BITMAP(ds), WME_BA_BMP_SIZE >> 3);
	}

	while (bf) {
		ba_index = ATH_BA_INDEX(seq_st, bf->bf_seqno);
		if (!txok || (isaggr && !ATH_BA_ISSET(ba, ba_index)))
			nbad++;

		bf = bf->bf_next;
	}

	return (nbad);
}

static void
arn_tx_send_ht_normal(struct arn_softc *sc,
    struct ath_txq *txq,
    struct ath_atx_tid *tid,
    list_t *list)
{
	struct ath_buf *bf;

	bf = list_head(list);
	bf->bf_state.bf_type &= ~BUF_AMPDU;

	/* update starting sequence number for subsequent ADDBA request */
	INCR(tid->seq_start, IEEE80211_SEQ_MAX);

	bf->bf_nframes = 1;
	bf->bf_lastbf = bf;
	ath_buf_set_rate(sc, bf);
	arn_tx_txqaddbuf(sc, txq, list);
}

/*
 * Insert a chain of ath_buf (descriptors) on a txq and
 * assume the descriptors are already chained together by caller.
 */
static void
arn_tx_txqaddbuf(struct arn_softc *sc,
    struct ath_txq *txq,
    list_t *list)
{
	struct ath_buf *bf;

	/*
	 * Insert the frame on the outbound list and
	 * pass it on to the hardware.
	 */

	if (list_empty(list))
		return;

	bf = list_head(list);

	list_splice_tail_init(list, &txq->axq_q);

	txq->axq_depth++;
	txq->axq_totalqueued++;
	txq->axq_linkbuf = list_object(list, txq->axq_q.prev);

	ARN_DBG((ARN_DBG_QUEUE,
	    "qnum: %d, txq depth: %d\n", txq->axq_qnum, txq->axq_depth));

	if (txq->axq_link == NULL) {
		ath9k_hw_puttxbuf(sc->sc_ah, txq->axq_qnum, bf->bf_daddr);
		ARN_DBG((ARN_DBG_XMIT,
		    "TXDP[%u] = %llx (%p)\n",
		    txq->axq_qnum, ito64(bf->bf_daddr), bf->bf_desc));
	} else {
		*txq->axq_link = bf->bf_daddr;
		ARN_DBG((ARN_DBG_XMIT, "link[%u] (%p)=%llx (%p)\n",
		    txq->axq_qnum, txq->axq_link,
		    ito64(bf->bf_daddr), bf->bf_desc));
	}
	txq->axq_link = &(bf->bf_lastbf->bf_desc->ds_link);
	ath9k_hw_txstart(sc->sc_ah, txq->axq_qnum);
}
#endif /* ARN_TX_AGGREGATION */

static struct ath_buf *
arn_tx_get_buffer(struct arn_softc *sc)
{
	struct ath_buf *bf = NULL;

	mutex_enter(&sc->sc_txbuflock);
	bf = list_head(&sc->sc_txbuf_list);
	/* Check if a tx buffer is available */
	if (bf != NULL)
		list_remove(&sc->sc_txbuf_list, bf);
	if (list_empty(&sc->sc_txbuf_list)) {
		ARN_DBG((ARN_DBG_XMIT, "arn: arn_tx(): "
		    "stop queue\n"));
		sc->sc_stats.ast_tx_qstop++;
	}
	mutex_exit(&sc->sc_txbuflock);

	return (bf);
}

static uint32_t
setup_tx_flags(struct arn_softc *sc,
    struct ieee80211_frame *wh,
    uint32_t pktlen)
{
	int flags = 0;
	ieee80211com_t *ic = (ieee80211com_t *)sc;

	flags |= ATH9K_TXDESC_CLRDMASK; /* needed for crypto errors */
	flags |= ATH9K_TXDESC_INTREQ;

	if (IEEE80211_IS_MULTICAST(wh->i_addr1)) {
		flags |= ATH9K_TXDESC_NOACK;	/* no ack on broad/multicast */
		sc->sc_stats.ast_tx_noack++;
	}
	if (pktlen > ic->ic_rtsthreshold) {
		flags |= ATH9K_TXDESC_RTSENA;	/* RTS based on frame length */
		sc->sc_stats.ast_tx_rts++;
	}

	return (flags);
}

static void
ath_tx_setup_buffer(struct arn_softc *sc, struct ath_buf *bf,
    struct ieee80211_node *in, struct ieee80211_frame *wh,
    uint32_t pktlen, uint32_t keytype)
{
	ieee80211com_t *ic = (ieee80211com_t *)sc;
	int i;

	/* Buf reset */
	ATH_TXBUF_RESET(bf);
	for (i = 0; i < 4; i++) {
		bf->rates[i].idx = -1;
		bf->rates[i].flags = 0;
		bf->rates[i].count = 1;
	}

	bf->bf_in = in;
	/* LINTED E_ASSIGN_NARROW_CONV */
	bf->bf_frmlen = pktlen;

	/* Frame type */
	IEEE80211_IS_DATA(wh) ?
	    (bf->bf_state.bf_type |= BUF_DATA) :
	    (bf->bf_state.bf_type &= ~BUF_DATA);
	IEEE80211_IS_BACK_REQ(wh) ?
	    (bf->bf_state.bf_type |= BUF_BAR) :
	    (bf->bf_state.bf_type &= ~BUF_BAR);
	IEEE80211_IS_PSPOLL(wh) ?
	    (bf->bf_state.bf_type |= BUF_PSPOLL) :
	    (bf->bf_state.bf_type &= ~BUF_PSPOLL);
	/*
	 * The 802.11 layer marks whether or not we should
	 * use short preamble based on the current mode and
	 * negotiated parameters.
	 */
	((ic->ic_flags & IEEE80211_F_SHPREAMBLE) &&
	    (in->in_capinfo & IEEE80211_CAPINFO_SHORT_PREAMBLE)) ?
	    (bf->bf_state.bf_type |= BUF_SHORT_PREAMBLE) :
	    (bf->bf_state.bf_type &= ~BUF_SHORT_PREAMBLE);

	bf->bf_flags = setup_tx_flags(sc, wh, pktlen);

	/* Crypto */
	bf->bf_keytype = keytype;

	/* Assign seqno, tidno for tx aggrefation */

#ifdef ARN_TX_AGGREGATION
	if (ieee80211_is_data_qos(wh) && (sc->sc_flags & SC_OP_TXAGGR))
		assign_aggr_tid_seqno(sc, bf, wh);
#endif /* ARN_TX_AGGREGATION */

}

/*
 * ath_pkt_dur - compute packet duration (NB: not NAV)
 *
 * rix - rate index
 * pktlen - total bytes (delims + data + fcs + pads + pad delims)
 * width  - 0 for 20 MHz, 1 for 40 MHz
 * half_gi - to use 4us v/s 3.6 us for symbol time
 */
static uint32_t
ath_pkt_duration(struct arn_softc *sc, uint8_t rix, struct ath_buf *bf,
    int width, int half_gi, boolean_t shortPreamble)
{
	struct ath_rate_table *rate_table = sc->sc_currates;
	uint32_t nbits, nsymbits, duration, nsymbols;
	uint8_t rc;
	int streams, pktlen;

	pktlen = bf_isaggr(bf) ? bf->bf_al : bf->bf_frmlen;
	rc = rate_table->info[rix].ratecode;

	/* for legacy rates, use old function to compute packet duration */
	if (!IS_HT_RATE(rc))
		return (ath9k_hw_computetxtime(sc->sc_ah, rate_table, pktlen,
		    rix, shortPreamble));

	/* find number of symbols: PLCP + data */
	nbits = (pktlen << 3) + OFDM_PLCP_BITS;
	nsymbits = bits_per_symbol[HT_RC_2_MCS(rc)][width];
	nsymbols = (nbits + nsymbits - 1) / nsymbits;

	if (!half_gi)
		duration = SYMBOL_TIME(nsymbols);
	else
		duration = SYMBOL_TIME_HALFGI(nsymbols);

	/* addup duration for legacy/ht training and signal fields */
	streams = HT_RC_2_STREAMS(rc);
	duration += L_STF + L_LTF + L_SIG + HT_SIG + HT_STF + HT_LTF(streams);

	return (duration);
}

/* Rate module function to set rate related fields in tx descriptor */
static void
ath_buf_set_rate(struct arn_softc *sc,
    struct ath_buf *bf,
    struct ieee80211_frame *wh)
{
	struct ath_hal *ah = sc->sc_ah;
	struct ath_rate_table *rt;
	struct ath_desc *ds = bf->bf_desc;
	struct ath_desc *lastds = bf->bf_desc; /* temp workground */
	struct ath9k_11n_rate_series series[4];
	struct ath9k_tx_rate *rates;
	int i, flags, rtsctsena = 0;
	uint32_t ctsduration = 0;
	uint8_t rix = 0, cix, ctsrate = 0;

	(void) memset(series, 0, sizeof (struct ath9k_11n_rate_series) * 4);

	rates = bf->rates;

	if (IEEE80211_HAS_MOREFRAGS(wh) ||
	    wh->i_seq[0] & IEEE80211_SEQ_FRAG_MASK) {
		rates[1].count = rates[2].count = rates[3].count = 0;
		rates[1].idx = rates[2].idx = rates[3].idx = 0;
		rates[0].count = ATH_TXMAXTRY;
	}

	/* get the cix for the lowest valid rix */
	rt = sc->sc_currates;
	for (i = 3; i >= 0; i--) {
		if (rates[i].count && (rates[i].idx >= 0)) {
			rix = rates[i].idx;
			break;
		}
	}

	flags = (bf->bf_flags & (ATH9K_TXDESC_RTSENA | ATH9K_TXDESC_CTSENA));
	cix = rt->info[rix].ctrl_rate;

	/*
	 * If 802.11g protection is enabled, determine whether to use RTS/CTS or
	 * just CTS.  Note that this is only done for OFDM/HT unicast frames.
	 */
	if (sc->sc_protmode != PROT_M_NONE &&
	    !(bf->bf_flags & ATH9K_TXDESC_NOACK) &&
	    (rt->info[rix].phy == WLAN_RC_PHY_OFDM ||
	    WLAN_RC_PHY_HT(rt->info[rix].phy))) {
		if (sc->sc_protmode == PROT_M_RTSCTS)
			flags = ATH9K_TXDESC_RTSENA;
		else if (sc->sc_protmode == PROT_M_CTSONLY)
			flags = ATH9K_TXDESC_CTSENA;

		cix = rt->info[sc->sc_protrix].ctrl_rate;
		rtsctsena = 1;
	}

	/*
	 * For 11n, the default behavior is to enable RTS for hw retried frames.
	 * We enable the global flag here and let rate series flags determine
	 * which rates will actually use RTS.
	 */
	if ((ah->ah_caps.hw_caps & ATH9K_HW_CAP_HT) && bf_isdata(bf)) {
		/* 802.11g protection not needed, use our default behavior */
		if (!rtsctsena)
			flags = ATH9K_TXDESC_RTSENA;
	}

	/* Set protection if aggregate protection on */
	if (sc->sc_config.ath_aggr_prot &&
	    (!bf_isaggr(bf) || (bf_isaggr(bf) && bf->bf_al < 8192))) {
		flags = ATH9K_TXDESC_RTSENA;
		cix = rt->info[sc->sc_protrix].ctrl_rate;
		rtsctsena = 1;
	}

	/* For AR5416 - RTS cannot be followed by a frame larger than 8K */
	if (bf_isaggr(bf) && (bf->bf_al > ah->ah_caps.rts_aggr_limit))
		flags &= ~(ATH9K_TXDESC_RTSENA);

	/*
	 * CTS transmit rate is derived from the transmit rate by looking in the
	 * h/w rate table.  We must also factor in whether or not a short
	 * preamble is to be used. NB: cix is set above where RTS/CTS is enabled
	 */
	ctsrate = rt->info[cix].ratecode |
	    (bf_isshpreamble(bf) ? rt->info[cix].short_preamble : 0);

	for (i = 0; i < 4; i++) {
		if (!rates[i].count || (rates[i].idx < 0))
			continue;

		rix = rates[i].idx;

		series[i].Rate = rt->info[rix].ratecode |
		    (bf_isshpreamble(bf) ?
		    rt->info[rix].short_preamble : 0);

		series[i].Tries = rates[i].count;

		series[i].RateFlags =
		    ((rates[i].flags & ATH9K_TX_RC_USE_RTS_CTS) ?
		    ATH9K_RATESERIES_RTS_CTS : 0) |
		    ((rates[i].flags & ATH9K_TX_RC_40_MHZ_WIDTH) ?
		    ATH9K_RATESERIES_2040 : 0) |
		    ((rates[i].flags & ATH9K_TX_RC_SHORT_GI) ?
		    ATH9K_RATESERIES_HALFGI : 0);

		series[i].PktDuration = ath_pkt_duration(sc, rix, bf,
		    (rates[i].flags & ATH9K_TX_RC_40_MHZ_WIDTH) != 0,
		    (rates[i].flags & ATH9K_TX_RC_SHORT_GI),
		    bf_isshpreamble(bf));

		series[i].ChSel = sc->sc_tx_chainmask;

		if (rtsctsena)
			series[i].RateFlags |= ATH9K_RATESERIES_RTS_CTS;

		ARN_DBG((ARN_DBG_RATE,
		    "series[%d]--flags & ATH9K_TX_RC_USE_RTS_CTS = %08x"
		    "--flags & ATH9K_TX_RC_40_MHZ_WIDTH = %08x"
		    "--flags & ATH9K_TX_RC_SHORT_GI = %08x\n",
		    rates[i].flags & ATH9K_TX_RC_USE_RTS_CTS,
		    rates[i].flags & ATH9K_TX_RC_40_MHZ_WIDTH,
		    rates[i].flags & ATH9K_TX_RC_SHORT_GI));

		ARN_DBG((ARN_DBG_RATE,
		    "series[%d]:"
		    "dot11rate:%d"
		    "index:%d"
		    "retry count:%d\n",
		    i,
		    (rt->info[rates[i].idx].ratekbps)/1000,
		    rates[i].idx,
		    rates[i].count));
	}

	/* set dur_update_en for l-sig computation except for PS-Poll frames */
	ath9k_hw_set11n_ratescenario(ah, ds, lastds, !bf_ispspoll(bf),
	    ctsrate, ctsduration,
	    series, 4, flags);

	if (sc->sc_config.ath_aggr_prot && flags)
		ath9k_hw_set11n_burstduration(ah, ds, 8192);
}

static void
ath_tx_complete(struct arn_softc *sc, struct ath_buf *bf,
    struct ath_xmit_status *tx_status)
{
	boolean_t is_data = bf_isdata(bf);

	ARN_DBG((ARN_DBG_XMIT, "TX complete\n"));

	if (tx_status->flags & ATH_TX_BAR)
		tx_status->flags &= ~ATH_TX_BAR;

	bf->rates[0].count = tx_status->retries + 1;

	arn_tx_status(sc, bf, is_data);
}

/* To complete a chain of buffers associated a frame */
static void
ath_tx_complete_buf(struct arn_softc *sc, struct ath_buf *bf,
    int txok, int sendbar)
{
	struct ath_xmit_status tx_status;

	/*
	 * Set retry information.
	 * NB: Don't use the information in the descriptor, because the frame
	 * could be software retried.
	 */
	tx_status.retries = bf->bf_retries;
	tx_status.flags = 0;

	if (sendbar)
		tx_status.flags = ATH_TX_BAR;

	if (!txok) {
		tx_status.flags |= ATH_TX_ERROR;

		if (bf_isxretried(bf))
			tx_status.flags |= ATH_TX_XRETRY;
	}

	/* complete this frame */
	ath_tx_complete(sc, bf, &tx_status);

	/*
	 * Return the list of ath_buf of this mpdu to free queue
	 */
}

static void
arn_tx_stopdma(struct arn_softc *sc, struct ath_txq *txq)
{
	struct ath_hal *ah = sc->sc_ah;

	(void) ath9k_hw_stoptxdma(ah, txq->axq_qnum);

	ARN_DBG((ARN_DBG_XMIT, "arn: arn_drain_txdataq(): "
	    "tx queue [%u] %x, link %p\n",
	    txq->axq_qnum,
	    ath9k_hw_gettxbuf(ah, txq->axq_qnum), txq->axq_link));

}

/* Drain only the data queues */
/* ARGSUSED */
static void
arn_drain_txdataq(struct arn_softc *sc, boolean_t retry_tx)
{
	struct ath_hal *ah = sc->sc_ah;
	int i, status, npend = 0;

	if (!(sc->sc_flags & SC_OP_INVALID)) {
		for (i = 0; i < ATH9K_NUM_TX_QUEUES; i++) {
			if (ARN_TXQ_SETUP(sc, i)) {
				arn_tx_stopdma(sc, &sc->sc_txq[i]);
				/*
				 * The TxDMA may not really be stopped.
				 * Double check the hal tx pending count
				 */
				npend += ath9k_hw_numtxpending(ah,
				    sc->sc_txq[i].axq_qnum);
			}
		}
	}

	if (npend) {
		/* TxDMA not stopped, reset the hal */
		ARN_DBG((ARN_DBG_XMIT, "arn: arn_drain_txdataq(): "
		    "Unable to stop TxDMA. Reset HAL!\n"));

		if (!ath9k_hw_reset(ah,
		    sc->sc_ah->ah_curchan,
		    sc->tx_chan_width,
		    sc->sc_tx_chainmask, sc->sc_rx_chainmask,
		    sc->sc_ht_extprotspacing, B_TRUE, &status)) {
			ARN_DBG((ARN_DBG_FATAL, "arn: arn_drain_txdataq(): "
			    "unable to reset hardware; hal status %u\n",
			    status));
		}
	}

	for (i = 0; i < ATH9K_NUM_TX_QUEUES; i++) {
		if (ARN_TXQ_SETUP(sc, i))
			arn_tx_draintxq(sc, &sc->sc_txq[i]);
	}
}

/* Setup a h/w transmit queue */
struct ath_txq *
arn_txq_setup(struct arn_softc *sc, int qtype, int subtype)
{
	struct ath_hal *ah = sc->sc_ah;
	struct ath9k_tx_queue_info qi;
	int qnum;

	(void) memset(&qi, 0, sizeof (qi));
	qi.tqi_subtype = subtype;
	qi.tqi_aifs = ATH9K_TXQ_USEDEFAULT;
	qi.tqi_cwmin = ATH9K_TXQ_USEDEFAULT;
	qi.tqi_cwmax = ATH9K_TXQ_USEDEFAULT;
	qi.tqi_physCompBuf = 0;

	/*
	 * Enable interrupts only for EOL and DESC conditions.
	 * We mark tx descriptors to receive a DESC interrupt
	 * when a tx queue gets deep; otherwise waiting for the
	 * EOL to reap descriptors.  Note that this is done to
	 * reduce interrupt load and this only defers reaping
	 * descriptors, never transmitting frames.  Aside from
	 * reducing interrupts this also permits more concurrency.
	 * The only potential downside is if the tx queue backs
	 * up in which case the top half of the kernel may backup
	 * due to a lack of tx descriptors.
	 *
	 * The UAPSD queue is an exception, since we take a desc-
	 * based intr on the EOSP frames.
	 */
	if (qtype == ATH9K_TX_QUEUE_UAPSD)
		qi.tqi_qflags = TXQ_FLAG_TXDESCINT_ENABLE;
	else
		qi.tqi_qflags = TXQ_FLAG_TXEOLINT_ENABLE |
		    TXQ_FLAG_TXDESCINT_ENABLE;
	qnum = ath9k_hw_setuptxqueue(ah, qtype, &qi);
	if (qnum == -1) {
		/*
		 * NB: don't print a message, this happens
		 * normally on parts with too few tx queues
		 */
		return (NULL);
	}
	if (qnum >= ARRAY_SIZE(sc->sc_txq)) {
		ARN_DBG((ARN_DBG_FATAL, "arn: arn_txq_setup(): "
		    "hal qnum %u out of range, max %u!\n",
		    qnum, (unsigned int)ARRAY_SIZE(sc->sc_txq)));
		(void) ath9k_hw_releasetxqueue(ah, qnum);
		return (NULL);
	}
	if (!ARN_TXQ_SETUP(sc, qnum)) {
		struct ath_txq *txq = &sc->sc_txq[qnum];

		txq->axq_qnum = qnum;
		txq->axq_intrcnt = 0; /* legacy */
		txq->axq_link = NULL;

		list_create(&txq->axq_list, sizeof (struct ath_buf),
		    offsetof(struct ath_buf, bf_node));
		list_create(&txq->axq_acq, sizeof (struct ath_buf),
		    offsetof(struct ath_buf, bf_node));
		mutex_init(&txq->axq_lock, NULL, MUTEX_DRIVER, NULL);

		txq->axq_depth = 0;
		txq->axq_aggr_depth = 0;
		txq->axq_totalqueued = 0;
		txq->axq_linkbuf = NULL;
		sc->sc_txqsetup |= 1<<qnum;
	}
	return (&sc->sc_txq[qnum]);
}

/* Reclaim resources for a setup queue */

void
arn_tx_cleanupq(struct arn_softc *sc, struct ath_txq *txq)
{
	(void) ath9k_hw_releasetxqueue(sc->sc_ah, txq->axq_qnum);
	sc->sc_txqsetup &= ~(1<<txq->axq_qnum);
}

/*
 * Setup a hardware data transmit queue for the specified
 * access control.  The hal may not support all requested
 * queues in which case it will return a reference to a
 * previously setup queue.  We record the mapping from ac's
 * to h/w queues for use by arn_tx_start and also track
 * the set of h/w queues being used to optimize work in the
 * transmit interrupt handler and related routines.
 */

int
arn_tx_setup(struct arn_softc *sc, int haltype)
{
	struct ath_txq *txq;

	if (haltype >= ARRAY_SIZE(sc->sc_haltype2q)) {
		ARN_DBG((ARN_DBG_FATAL, "arn: arn_tx_setup(): "
		    "HAL AC %u out of range, max %zu!\n",
		    haltype, ARRAY_SIZE(sc->sc_haltype2q)));
		return (0);
	}
	txq = arn_txq_setup(sc, ATH9K_TX_QUEUE_DATA, haltype);
	if (txq != NULL) {
		sc->sc_haltype2q[haltype] = txq->axq_qnum;
		return (1);
	} else
		return (0);
}

void
arn_tx_draintxq(struct arn_softc *sc, struct ath_txq *txq)
{
	struct ath_buf *bf;

	/*
	 * This assumes output has been stopped.
	 */
	for (;;) {
		mutex_enter(&txq->axq_lock);
		bf = list_head(&txq->axq_list);
		if (bf == NULL) {
			txq->axq_link = NULL;
			mutex_exit(&txq->axq_lock);
			break;
		}
		list_remove(&txq->axq_list, bf);
		mutex_exit(&txq->axq_lock);
		bf->bf_in = NULL;
		mutex_enter(&sc->sc_txbuflock);
		list_insert_tail(&sc->sc_txbuf_list, bf);
		mutex_exit(&sc->sc_txbuflock);
	}
}

/* Drain the transmit queues and reclaim resources */

void
arn_draintxq(struct arn_softc *sc, boolean_t retry_tx)
{
	/*
	 * stop beacon queue. The beacon will be freed when
	 * we go to INIT state
	 */
	if (!(sc->sc_flags & SC_OP_INVALID)) {
		(void) ath9k_hw_stoptxdma(sc->sc_ah, sc->sc_beaconq);
		ARN_DBG((ARN_DBG_XMIT, "arn: arn_draintxq(): "
		    "beacon queue %x\n",
		    ath9k_hw_gettxbuf(sc->sc_ah, sc->sc_beaconq)));
	}

	arn_drain_txdataq(sc, retry_tx);
}

uint32_t
arn_txq_depth(struct arn_softc *sc, int qnum)
{
	return (sc->sc_txq[qnum].axq_depth);
}

uint32_t
arn_txq_aggr_depth(struct arn_softc *sc, int qnum)
{
	return (sc->sc_txq[qnum].axq_aggr_depth);
}

/* Update parameters for a transmit queue */
int
arn_txq_update(struct arn_softc *sc, int qnum,
    struct ath9k_tx_queue_info *qinfo)
{
	struct ath_hal *ah = sc->sc_ah;
	int error = 0;
	struct ath9k_tx_queue_info qi;

	if (qnum == sc->sc_beaconq) {
		/*
		 * XXX: for beacon queue, we just save the parameter.
		 * It will be picked up by arn_beaconq_config() when
		 * it's necessary.
		 */
		sc->sc_beacon_qi = *qinfo;
		return (0);
	}

	ASSERT(sc->sc_txq[qnum].axq_qnum == qnum);

	(void) ath9k_hw_get_txq_props(ah, qnum, &qi);
	qi.tqi_aifs = qinfo->tqi_aifs;
	qi.tqi_cwmin = qinfo->tqi_cwmin;
	qi.tqi_cwmax = qinfo->tqi_cwmax;
	qi.tqi_burstTime = qinfo->tqi_burstTime;
	qi.tqi_readyTime = qinfo->tqi_readyTime;

	if (!ath9k_hw_set_txq_props(ah, qnum, &qi)) {
		ARN_DBG((ARN_DBG_FATAL,
		    "Unable to update hardware queue %u!\n", qnum));
		error = -EIO;
	} else {
		(void) ath9k_hw_resettxqueue(ah, qnum); /* push to h/w */
	}

	return (error);
}

int
ath_cabq_update(struct arn_softc *sc)
{
	struct ath9k_tx_queue_info qi;
	int qnum = sc->sc_cabq->axq_qnum;
	struct ath_beacon_config conf;

	(void) ath9k_hw_get_txq_props(sc->sc_ah, qnum, &qi);
	/*
	 * Ensure the readytime % is within the bounds.
	 */
	if (sc->sc_config.cabqReadytime < ATH9K_READY_TIME_LO_BOUND)
		sc->sc_config.cabqReadytime = ATH9K_READY_TIME_LO_BOUND;
	else if (sc->sc_config.cabqReadytime > ATH9K_READY_TIME_HI_BOUND)
		sc->sc_config.cabqReadytime = ATH9K_READY_TIME_HI_BOUND;

	arn_get_beaconconfig(sc, &conf);
	qi.tqi_readyTime =
	    (conf.beacon_interval * sc->sc_config.cabqReadytime) / 100;
	(void) arn_txq_update(sc, qnum, &qi);

	return (0);
}

static uint32_t
arn_tx_get_keytype(const struct ieee80211_cipher *cip)
{
	uint32_t index;
	static const uint8_t ciphermap[] = {
	    ATH9K_CIPHER_WEP,		/* IEEE80211_CIPHER_WEP */
	    ATH9K_CIPHER_TKIP,		/* IEEE80211_CIPHER_TKIP */
	    ATH9K_CIPHER_AES_OCB,	/* IEEE80211_CIPHER_AES_OCB */
	    ATH9K_CIPHER_AES_CCM,	/* IEEE80211_CIPHER_AES_CCM */
	    ATH9K_CIPHER_CKIP,		/* IEEE80211_CIPHER_CKIP */
	    ATH9K_CIPHER_CLR,		/* IEEE80211_CIPHER_NONE */
	};

	ASSERT(cip->ic_cipher < ARRAY_SIZE(ciphermap));
	index = cip->ic_cipher;

	if (ciphermap[index] == ATH9K_CIPHER_WEP)
		return (ATH9K_KEY_TYPE_WEP);
	else if (ciphermap[index] == ATH9K_CIPHER_TKIP)
		return (ATH9K_KEY_TYPE_TKIP);
	else if (ciphermap[index] == ATH9K_CIPHER_AES_CCM)
		return (ATH9K_KEY_TYPE_AES);

	return (ATH9K_KEY_TYPE_CLEAR);

}

/* Display buffer */
void
arn_dump_line(unsigned char *p, uint32_t len, boolean_t isaddress,
    uint32_t group)
{
	char *pnumeric = "0123456789ABCDEF";
	char hex[((2 + 1) * 16) + 1];
	char *phex = hex;
	char ascii[16 + 1];
	char *pascii = ascii;
	uint32_t grouped = 0;

	if (isaddress) {
		arn_problem("arn: %08x: ", p);
	} else {
		arn_problem("arn: ");
	}

	while (len) {
		*phex++ = pnumeric[((uint8_t)*p) / 16];
		*phex++ = pnumeric[((uint8_t)*p) % 16];
		if (++grouped >= group) {
			*phex++ = ' ';
			grouped = 0;
		}

		*pascii++ = (*p >= 32 && *p < 128) ? *p : '.';

		++p;
		--len;
	}

	*phex = '\0';
	*pascii = '\0';

	arn_problem("%-*s|%-*s|\n", (2 * 16) +
	    (16 / group), hex, 16, ascii);
}

void
arn_dump_pkg(unsigned char *p, uint32_t len, boolean_t isaddress,
    uint32_t group)
{
	uint32_t perline;
	while (len) {
		perline = (len < 16) ? len : 16;
		arn_dump_line(p, perline, isaddress, group);
		len -= perline;
		p += perline;
	}
}

/*
 * The input parameter mp has following assumption:
 * For data packets, GLDv3 mac_wifi plugin allocates and fills the
 * ieee80211 header. For management packets, net80211 allocates and
 * fills the ieee80211 header. In both cases, enough spaces in the
 * header are left for encryption option.
 */
static int32_t
arn_tx_start(struct arn_softc *sc, struct ieee80211_node *in,
    struct ath_buf *bf, mblk_t *mp)
{
	ieee80211com_t *ic = (ieee80211com_t *)sc;
	struct ieee80211_frame *wh = (struct ieee80211_frame *)mp->b_rptr;
	struct ath_hal *ah = sc->sc_ah;
	struct ath_node *an;
	struct ath_desc *ds;
	struct ath_txq *txq;
	struct ath_rate_table *rt;
	enum ath9k_pkt_type atype;
	boolean_t shortPreamble, is_padding = B_FALSE;
	uint32_t subtype, keytype = ATH9K_KEY_TYPE_CLEAR;
	int32_t keyix, iswep, hdrlen, pktlen, mblen, mbslen;
	caddr_t dest;

	/*
	 * CRC are added by H/W, not encaped by driver,
	 * but we must count it in pkt length.
	 */
	pktlen = IEEE80211_CRC_LEN;
	iswep = wh->i_fc[1] & IEEE80211_FC1_WEP;
	keyix = ATH9K_TXKEYIX_INVALID;
	hdrlen = ieee80211_hdrspace(ic, mp->b_rptr);
	if (hdrlen == 28)
		is_padding = B_TRUE;

	if (iswep != 0) {
		const struct ieee80211_cipher *cip;
		struct ieee80211_key *k;

		/*
		 * Construct the 802.11 header+trailer for an encrypted
		 * frame. The only reason this can fail is because of an
		 * unknown or unsupported cipher/key type.
		 */
		k = ieee80211_crypto_encap(ic, mp);
		if (k == NULL) {
			ARN_DBG((ARN_DBG_XMIT, "arn: arn_tx_start "
			    "crypto_encap failed\n"));
			/*
			 * This can happen when the key is yanked after the
			 * frame was queued.  Just discard the frame; the
			 * 802.11 layer counts failures and provides
			 * debugging/diagnostics.
			 */
			return (EIO);
		}
		cip = k->wk_cipher;

		keytype = arn_tx_get_keytype(cip);

		/*
		 * Adjust the packet + header lengths for the crypto
		 * additions and calculate the h/w key index.  When
		 * a s/w mic is done the frame will have had any mic
		 * added to it prior to entry so m0->m_pkthdr.len above will
		 * account for it. Otherwise we need to add it to the
		 * packet length.
		 */
		hdrlen += cip->ic_header;
		pktlen += cip->ic_trailer;
		if ((k->wk_flags & IEEE80211_KEY_SWMIC) == 0)
			pktlen += cip->ic_miclen;

		keyix = k->wk_keyix;

		/* packet header may have moved, reset our local pointer */
		wh = (struct ieee80211_frame *)mp->b_rptr;
	}

	dest = bf->bf_dma.mem_va;
	for (; mp != NULL; mp = mp->b_cont) {
		mblen = MBLKL(mp);
		bcopy(mp->b_rptr, dest, mblen);
		dest += mblen;
	}
	mbslen = (uintptr_t)dest - (uintptr_t)bf->bf_dma.mem_va;
	pktlen += mbslen;
	if (is_padding && (wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) ==
	    IEEE80211_FC0_TYPE_DATA)
		pktlen -= 2; /* real pkg len */

	/* buf setup */
	ath_tx_setup_buffer(sc, bf, in, wh, pktlen, keytype);

	/* setup descriptors */
	ds = bf->bf_desc;
	rt = sc->sc_currates;
	ASSERT(rt != NULL);

	arn_get_rate(sc, bf, wh);
	an = (struct ath_node *)(in);

	/*
	 * Calculate Atheros packet type from IEEE80211 packet header
	 * and setup for rate calculations.
	 */
	switch (wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) {
	case IEEE80211_FC0_TYPE_MGT:
		subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;
		if (subtype == IEEE80211_FC0_SUBTYPE_BEACON)
			atype = ATH9K_PKT_TYPE_BEACON;
		else if (subtype == IEEE80211_FC0_SUBTYPE_PROBE_RESP)
			atype = ATH9K_PKT_TYPE_PROBE_RESP;
		else if (subtype == IEEE80211_FC0_SUBTYPE_ATIM)
			atype = ATH9K_PKT_TYPE_ATIM;
		else
			atype = ATH9K_PKT_TYPE_NORMAL;

		/* force all ctl frames to highest queue */
		txq = &sc->sc_txq[arn_get_hal_qnum(WME_AC_VO, sc)];
		break;
	case IEEE80211_FC0_TYPE_CTL:
		atype = ATH9K_PKT_TYPE_PSPOLL;
		subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;

		/* force all ctl frames to highest queue */
		txq = &sc->sc_txq[arn_get_hal_qnum(WME_AC_VO, sc)];
		break;
	case IEEE80211_FC0_TYPE_DATA:
		// arn_dump_pkg((unsigned char *)bf->bf_dma.mem_va,
		//    pktlen, 1, 1);
		atype = ATH9K_PKT_TYPE_NORMAL;

		/* Always use background queue */
		txq = &sc->sc_txq[arn_get_hal_qnum(WME_AC_BE, sc)];
		break;
	default:
		/* Unknown 802.11 frame */
		sc->sc_stats.ast_tx_invalid++;
		return (1);
	}

	/* setup descriptor */
	ds->ds_link = 0;
	ds->ds_data = bf->bf_dma.cookie.dmac_address;

	/*
	 * Formulate first tx descriptor with tx controls.
	 */
	ath9k_hw_set11n_txdesc(ah, ds,
	    (pktlen), /* packet length */
	    atype, /* Atheros packet type */
	    MAX_RATE_POWER /* MAX_RATE_POWER */,
	    keyix /* ATH9K_TXKEYIX_INVALID */,
	    keytype /* ATH9K_KEY_TYPE_CLEAR */,
	    bf->bf_flags /* flags */);

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	ARN_DBG((ARN_DBG_XMIT, "arn: arn_tx_start(): to %s totlen=%d "
	    "an->an_tx_rate1sp=%d tx_rate2sp=%d tx_rate3sp=%d "
	    "qnum=%d sht=%d dur = %d\n",
	    ieee80211_macaddr_sprintf(wh->i_addr1), mbslen, an->an_tx_rate1sp,
	    an->an_tx_rate2sp, an->an_tx_rate3sp,
	    txq->axq_qnum, shortPreamble, *(uint16_t *)wh->i_dur));

	(void) ath9k_hw_filltxdesc(ah, ds,
	    mbslen,		/* segment length */
	    B_TRUE,		/* first segment */
	    B_TRUE,		/* last segment */
	    ds);		/* first descriptor */

	/* set rate related fields in tx descriptor */
	ath_buf_set_rate(sc, bf, wh);

	ARN_DMA_SYNC(bf->bf_dma, DDI_DMA_SYNC_FORDEV);

	mutex_enter(&txq->axq_lock);
	list_insert_tail(&txq->axq_list, bf);
	if (txq->axq_link == NULL) {
		(void) ath9k_hw_puttxbuf(ah, txq->axq_qnum, bf->bf_daddr);
	} else {
		*txq->axq_link = bf->bf_daddr;
	}
	txq->axq_link = &ds->ds_link;
	mutex_exit(&txq->axq_lock);

	// arn_dump_pkg((unsigned char *)bf->bf_dma.mem_va, pktlen, 1, 1);

	(void) ath9k_hw_txstart(ah, txq->axq_qnum);

	ic->ic_stats.is_tx_frags++;
	ic->ic_stats.is_tx_bytes += pktlen;

	return (0);
}

/*
 * Transmit a management frame.
 * Note that management frames come directly from the 802.11 layer
 * and do not honor the send queue flow control.
 */
/* Upon failure caller should free mp */
int
arn_tx(ieee80211com_t *ic, mblk_t *mp, uint8_t type)
{
	struct arn_softc *sc = (struct arn_softc *)ic;
	struct ath_hal *ah = sc->sc_ah;
	struct ieee80211_node *in = NULL;
	struct ath_buf *bf = NULL;
	struct ieee80211_frame *wh;
	int error = 0;

	ASSERT(mp->b_next == NULL);
	/* should check later */
	if (sc->sc_flags & SC_OP_INVALID) {
		if ((type & IEEE80211_FC0_TYPE_MASK) !=
		    IEEE80211_FC0_TYPE_DATA) {
			freemsg(mp);
		}
		return (ENXIO);
	}

	/* Grab a TX buffer */
	bf = arn_tx_get_buffer(sc);
	if (bf == NULL) {
		ARN_DBG((ARN_DBG_XMIT, "arn: arn_tx(): discard, "
		    "no xmit buf\n"));
		ic->ic_stats.is_tx_nobuf++;
		if ((type & IEEE80211_FC0_TYPE_MASK) ==
		    IEEE80211_FC0_TYPE_DATA) {
			sc->sc_stats.ast_tx_nobuf++;
			mutex_enter(&sc->sc_resched_lock);
			sc->sc_resched_needed = B_TRUE;
			mutex_exit(&sc->sc_resched_lock);
		} else {
			sc->sc_stats.ast_tx_nobufmgt++;
			freemsg(mp);
		}
		return (ENOMEM);
	}

	wh = (struct ieee80211_frame *)mp->b_rptr;

	/* Locate node */
	in = ieee80211_find_txnode(ic,  wh->i_addr1);
	if (in == NULL) {
		error = EIO;
		goto bad;
	}

	in->in_inact = 0;
	switch (type & IEEE80211_FC0_TYPE_MASK) {
	case IEEE80211_FC0_TYPE_DATA:
		(void) ieee80211_encap(ic, mp, in);
		break;
	default:
		if ((wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK) ==
		    IEEE80211_FC0_SUBTYPE_PROBE_RESP) {
			/* fill time stamp */
			uint64_t tsf;
			uint32_t *tstamp;

			tsf = ath9k_hw_gettsf64(ah);
			/* adjust 100us delay to xmit */
			tsf += 100;
			/* LINTED E_BAD_PTR_CAST_ALIGN */
			tstamp = (uint32_t *)&wh[1];
			tstamp[0] = LE_32(tsf & 0xffffffff);
			tstamp[1] = LE_32(tsf >> 32);
		}
		sc->sc_stats.ast_tx_mgmt++;
		break;
	}

	error = arn_tx_start(sc, in, bf, mp);

	if (error != 0) {
bad:
		ic->ic_stats.is_tx_failed++;
		if (bf != NULL) {
			mutex_enter(&sc->sc_txbuflock);
			list_insert_tail(&sc->sc_txbuf_list, bf);
			mutex_exit(&sc->sc_txbuflock);
		}
	}
	if (in != NULL)
		ieee80211_free_node(in);
	if ((type & IEEE80211_FC0_TYPE_MASK) != IEEE80211_FC0_TYPE_DATA ||
	    error == 0) {
		freemsg(mp);
	}

	return (error);
}

static void
arn_printtxbuf(struct ath_buf *bf, int done)
{
	struct ath_desc *ds = bf->bf_desc;
	const struct ath_tx_status *ts = &ds->ds_txstat;

	ARN_DBG((ARN_DBG_XMIT, "arn: T(%p %p) %08x %08x %08x %08x %08x"
	    " %08x %08x %08x %c\n",
	    ds, bf->bf_daddr,
	    ds->ds_link, ds->ds_data,
	    ds->ds_ctl0, ds->ds_ctl1,
	    ds->ds_hw[0], ds->ds_hw[1], ds->ds_hw[2], ds->ds_hw[3],
	    !done ? ' ' : (ts->ts_status == 0) ? '*' : '!'));
}

/* ARGSUSED */
static void
ath_tx_rc_status(struct ath_buf *bf,
    struct ath_desc *ds,
    int nbad,
    int txok,
    boolean_t update_rc)
{
	struct ath_tx_info_priv *tx_info_priv =
	    (struct ath_tx_info_priv *)&bf->tx_info_priv;

	tx_info_priv->update_rc = B_FALSE;

	if ((ds->ds_txstat.ts_status & ATH9K_TXERR_FILT) == 0 &&
	    (bf->bf_flags & ATH9K_TXDESC_NOACK) == 0) {
		if (bf_isdata(bf)) {
			(void) memcpy(&tx_info_priv->tx, &ds->ds_txstat,
			    sizeof (tx_info_priv->tx));
			tx_info_priv->n_frames = bf->bf_nframes;
			tx_info_priv->n_bad_frames = nbad;
			tx_info_priv->update_rc = B_TRUE;
		}
	}
}

/* Process completed xmit descriptors from the specified queue */
static int
arn_tx_processq(struct arn_softc *sc, struct ath_txq *txq)
{
	ieee80211com_t *ic = (ieee80211com_t *)sc;
	struct ath_hal *ah = sc->sc_ah;
	struct ath_buf *bf;
	struct ath_desc *ds;
	struct ieee80211_node *in;
	struct ath_tx_status *ts;
	struct ath_node *an;
	int32_t sr, lr, nacked = 0;
	int txok, nbad = 0;
	int status;

	for (;;) {
		mutex_enter(&txq->axq_lock);
		bf = list_head(&txq->axq_list);
		if (bf == NULL) {
			txq->axq_link = NULL;
			/* txq->axq_linkbuf = NULL; */
			mutex_exit(&txq->axq_lock);
			break;
		}
		ds = bf->bf_desc;	/* last decriptor */
		ts = &ds->ds_txstat;
		status = ath9k_hw_txprocdesc(ah, ds);

#ifdef DEBUG
		arn_printtxbuf(bf, status == 0);
#endif

		if (status == EINPROGRESS) {
			mutex_exit(&txq->axq_lock);
			break;
		}
		list_remove(&txq->axq_list, bf);
		mutex_exit(&txq->axq_lock);
		in = bf->bf_in;
		if (in != NULL) {
			an = ATH_NODE(in);
			/* Successful transmition */
			if (ts->ts_status == 0) {
				an->an_tx_ok++;
				an->an_tx_antenna = ts->ts_antenna;
				sc->sc_stats.ast_tx_rssidelta =
				    ts->ts_rssi - sc->sc_stats.ast_tx_rssi;
				sc->sc_stats.ast_tx_rssi = ts->ts_rssi;
			} else {
				an->an_tx_err++;
				if (ts->ts_status & ATH9K_TXERR_XRETRY) {
					sc->sc_stats.ast_tx_xretries++;
				}
				if (ts->ts_status & ATH9K_TXERR_FIFO) {
					sc->sc_stats.ast_tx_fifoerr++;
				}
				if (ts->ts_status & ATH9K_TXERR_FILT) {
					sc->sc_stats.ast_tx_filtered++;
				}
				an->an_tx_antenna = 0;	/* invalidate */
			}
			sr = ts->ts_shortretry;
			lr = ts->ts_longretry;
			sc->sc_stats.ast_tx_shortretry += sr;
			sc->sc_stats.ast_tx_longretry += lr;
			/*
			 * Hand the descriptor to the rate control algorithm.
			 */
			if ((ts->ts_status & ATH9K_TXERR_FILT) == 0 &&
			    (bf->bf_flags & ATH9K_TXDESC_NOACK) == 0) {
				/*
				 * If frame was ack'd update the last rx time
				 * used to workaround phantom bmiss interrupts.
				 */
				if (ts->ts_status == 0) {
					nacked++;
					an->an_tx_ok++;
				} else {
					an->an_tx_err++;
				}
				an->an_tx_retr += sr + lr;
			}
		}

		txok = (ds->ds_txstat.ts_status == 0);
		if (!bf_isampdu(bf)) {
			/*
			 * This frame is sent out as a single frame.
			 * Use hardware retry status for this frame.
			 */
			bf->bf_retries = ds->ds_txstat.ts_longretry;
			if (ds->ds_txstat.ts_status & ATH9K_TXERR_XRETRY)
				bf->bf_state.bf_type |= BUF_XRETRY;
			nbad = 0;
		}
		ath_tx_rc_status(bf, ds, nbad, B_TRUE, txok);

		ath_tx_complete_buf(sc, bf, txok, 0);

		// arn_dump_pkg((unsigned char *)bf->bf_dma.mem_va,
		//    bf->bf_frmlen, 1, 1);

		bf->bf_in = NULL;
		mutex_enter(&sc->sc_txbuflock);
		list_insert_tail(&sc->sc_txbuf_list, bf);
		mutex_exit(&sc->sc_txbuflock);

		/*
		 * Reschedule stalled outbound packets
		 */
		mutex_enter(&sc->sc_resched_lock);
		if (sc->sc_resched_needed) {
			sc->sc_resched_needed = B_FALSE;
			mac_tx_update(ic->ic_mach);
		}
		mutex_exit(&sc->sc_resched_lock);
	}

	return (nacked);
}

static void
arn_tx_handler(struct arn_softc *sc)
{
	int i;
	int nacked = 0;
	uint32_t qcumask = ((1 << ATH9K_NUM_TX_QUEUES) - 1);
	ath9k_hw_gettxintrtxqs(sc->sc_ah, &qcumask);

	/*
	 * Process each active queue.
	 */
	for (i = 0; i < ATH9K_NUM_TX_QUEUES; i++) {
		if (ARN_TXQ_SETUP(sc, i) && (qcumask & (1 << i))) {
			nacked += arn_tx_processq(sc, &sc->sc_txq[i]);
		}
	}

	if (nacked)
		sc->sc_lastrx = ath9k_hw_gettsf64(sc->sc_ah);
}

/* Deferred processing of transmit interrupt */

void
arn_tx_int_proc(void *arg)
{
	struct arn_softc *sc = arg;
	arn_tx_handler(sc);
}

/* Node init & cleanup functions */

#ifdef ARN_TX_AGGREGATION
void
arn_tx_node_init(struct arn_softc *sc, struct ath_node *an)
{
	struct ath_atx_tid *tid;
	struct ath_atx_ac *ac;
	int tidno, acno;

	for (tidno = 0, tid = &an->tid[tidno]; tidno < WME_NUM_TID;
	    tidno++, tid++) {
		tid->an = an;
		tid->tidno = tidno;
		tid->seq_start = tid->seq_next = 0;
		tid->baw_size  = WME_MAX_BA;
		tid->baw_head  = tid->baw_tail = 0;
		tid->sched = B_FALSE;
		tid->paused = B_FALSE;
		tid->state &= ~AGGR_CLEANUP;
		list_create(&tid->buf_q, sizeof (struct ath_buf),
		    offsetof(struct ath_buf, bf_node));
		acno = TID_TO_WME_AC(tidno);
		tid->ac = &an->ac[acno];
		tid->state &= ~AGGR_ADDBA_COMPLETE;
		tid->state &= ~AGGR_ADDBA_PROGRESS;
		tid->addba_exchangeattempts = 0;
	}

	for (acno = 0, ac = &an->ac[acno]; acno < WME_NUM_AC; acno++, ac++) {
		ac->sched = B_FALSE;
		list_create(&ac->tid_q, sizeof (struct ath_atx_tid),
		    offsetof(struct ath_atx_tid, list));

		switch (acno) {
		case WME_AC_BE:
			ac->qnum = arn_tx_get_qnum(sc,
			    ATH9K_TX_QUEUE_DATA, ATH9K_WME_AC_BE);
			break;
		case WME_AC_BK:
			ac->qnum = arn_tx_get_qnum(sc,
			    ATH9K_TX_QUEUE_DATA, ATH9K_WME_AC_BK);
			break;
		case WME_AC_VI:
			ac->qnum = arn_tx_get_qnum(sc,
			    ATH9K_TX_QUEUE_DATA, ATH9K_WME_AC_VI);
			break;
		case WME_AC_VO:
			ac->qnum = arn_tx_get_qnum(sc,
			    ATH9K_TX_QUEUE_DATA, ATH9K_WME_AC_VO);
			break;
		}
	}
}

void
arn_tx_node_cleanup(struct arn_softc *sc, struct ieee80211_node *in)
{
	int i;
	struct ath_atx_ac *ac, *ac_tmp;
	struct ath_atx_tid *tid, *tid_tmp;
	struct ath_txq *txq;
	struct ath_node *an = ATH_NODE(in);

	for (i = 0; i < ATH9K_NUM_TX_QUEUES; i++) {
		if (ARN_TXQ_SETUP(sc, i)) {
			txq = &sc->sc_txq[i];

			mutex_enter(&txq->axq_lock);

			list_for_each_entry_safe(ac, ac_tmp, &txq->axq_acq) {
				tid = list_head(&ac->tid_q);
				if (tid && tid->an != an)
					continue;
				list_remove(&txq->axq_acq, ac);
				ac->sched = B_FALSE;

				list_for_each_entry_safe(tid, tid_tmp,
				    &ac->tid_q) {
					list_remove(&ac->tid_q, tid);
					bf = list_head(&tid->buf_q);
					while (bf != NULL) {
						if (bf->bf_in == in)
							bf->bf_in = NULL;
					}
					bf = list_next(&txq->axq_list, bf);
					tid->sched = B_FALSE;
					arn_tid_drain(sc, txq, tid);
					tid->state &= ~AGGR_ADDBA_COMPLETE;
					tid->addba_exchangeattempts = 0;
					tid->state &= ~AGGR_CLEANUP;
				}
			}

			mutex_exit(&txq->axq_lock);
		}
	}
}
#endif /* ARN_TX_AGGREGATION */
