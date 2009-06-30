/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
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
#define	NUM_SYMBOLS_PER_USEC(_usec) (_usec >> 2)
#define	NUM_SYMBOLS_PER_USEC_HALFGI(_usec) (((_usec*5)-4)/18)

#define	OFDM_SIFS_TIME	16

#define	IS_HT_RATE(_rate)	((_rate) & 0x80)

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
		txq->axq_intrcnt = 0;
		txq->axq_link = NULL;

		list_create(&txq->axq_list, sizeof (struct ath_buf),
		    offsetof(struct ath_buf, bf_node));
		mutex_init(&txq->axq_lock, NULL, MUTEX_DRIVER, NULL);

		txq->axq_depth = 0;
		txq->axq_aggr_depth = 0;
		txq->axq_totalqueued = 0;
		/* txq->axq_linkbuf = NULL; */
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
	struct ieee80211_frame *wh;
	struct ath_hal *ah = sc->sc_ah;
	uint32_t flags;
	uint32_t subtype, ctsduration;
	int32_t keyix, iswep, hdrlen, pktlen, mblen, mbslen;
	/* LINTED E_FUNC_SET_NOT_USED */
	int32_t try0;
	uint8_t rix, cix, txrate, ctsrate;
	struct ath_desc *ds;
	struct ath_txq *txq;
	enum ath9k_pkt_type atype;
	struct ath_rate_table *rt;
	boolean_t shortPreamble;
	boolean_t is_pspoll;
	struct ath_node *an;
	caddr_t dest;
	uint32_t keytype = ATH9K_KEY_TYPE_CLEAR;

	/*
	 * CRC are added by H/W, not encaped by driver,
	 * but we must count it in pkt length.
	 */
	pktlen = IEEE80211_CRC_LEN;

	wh = (struct ieee80211_frame *)mp->b_rptr;
	iswep = wh->i_fc[1] & IEEE80211_FC1_WEP;
	keyix = ATH9K_TXKEYIX_INVALID;
	hdrlen = sizeof (struct ieee80211_frame);
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

	bf->bf_in = in;

	/* setup descriptors */
	ds = bf->bf_desc;
	rt = sc->sc_currates;
	ASSERT(rt != NULL);

	/*
	 * The 802.11 layer marks whether or not we should
	 * use short preamble based on the current mode and
	 * negotiated parameters.
	 */
	if ((ic->ic_flags & IEEE80211_F_SHPREAMBLE) &&
	    (in->in_capinfo & IEEE80211_CAPINFO_SHORT_PREAMBLE)) {
		shortPreamble = B_TRUE;
		sc->sc_stats.ast_tx_shortpre++;
	} else {
		shortPreamble = B_FALSE;
	}

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
		rix = 0;	/* lowest rate */
		try0 = ATH_TXMAXTRY;
		if (shortPreamble) {
			txrate = an->an_tx_mgtratesp;
		} else {
			txrate = an->an_tx_mgtrate;
		}
		/* force all ctl frames to highest queue */
		txq = &sc->sc_txq[arn_get_hal_qnum(WME_AC_VO, sc)];
		break;
	case IEEE80211_FC0_TYPE_CTL:
		atype = ATH9K_PKT_TYPE_PSPOLL;
		is_pspoll = B_TRUE;
		subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;
		rix = 0; /* lowest rate */
		try0 = ATH_TXMAXTRY;
		if (shortPreamble)
			txrate = an->an_tx_mgtratesp;
		else
			txrate = an->an_tx_mgtrate;
		/* force all ctl frames to highest queue */
		txq = &sc->sc_txq[arn_get_hal_qnum(WME_AC_VO, sc)];
		break;
	case IEEE80211_FC0_TYPE_DATA:
		atype = ATH9K_PKT_TYPE_NORMAL;
		rix = an->an_tx_rix0;
		try0 = an->an_tx_try0;
		if (shortPreamble)
			txrate = an->an_tx_rate0sp;
		else
			txrate = an->an_tx_rate0;
		/* Always use background queue */
		txq = &sc->sc_txq[arn_get_hal_qnum(WME_AC_BK, sc)];
		break;
	default:
		/* Unknown 802.11 frame */
		sc->sc_stats.ast_tx_invalid++;
		return (1);
	}

	/*
	 * Calculate miscellaneous flags.
	 */
	flags = ATH9K_TXDESC_CLRDMASK;
	if (IEEE80211_IS_MULTICAST(wh->i_addr1)) {
		flags |= ATH9K_TXDESC_NOACK;	/* no ack on broad/multicast */
		sc->sc_stats.ast_tx_noack++;
	} else if (pktlen > ic->ic_rtsthreshold) {
		flags |= ATH9K_TXDESC_RTSENA;	/* RTS based on frame length */
		sc->sc_stats.ast_tx_rts++;
	}

	/*
	 * Calculate duration.  This logically belongs in the 802.11
	 * layer but it lacks sufficient information to calculate it.
	 */
	if ((flags & ATH9K_TXDESC_NOACK) == 0 &&
	    (wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) !=
	    IEEE80211_FC0_TYPE_CTL) {
		uint16_t dur;
		dur = ath9k_hw_computetxtime(ah, rt, IEEE80211_ACK_SIZE,
		    rix, shortPreamble);
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		*(uint16_t *)wh->i_dur = LE_16(dur);
	}

	/*
	 * Calculate RTS/CTS rate and duration if needed.
	 */
	ctsduration = 0;
	if (flags & (ATH9K_TXDESC_RTSENA|ATH9K_TXDESC_CTSENA)) {
		/*
		 * CTS transmit rate is derived from the transmit rate
		 * by looking in the h/w rate table.  We must also factor
		 * in whether or not a short preamble is to be used.
		 */
		cix = rt->info[rix].ctrl_rate;
		ctsrate = rt->info[cix].ratecode;
		if (shortPreamble)
			ctsrate |= rt->info[cix].short_preamble;
		/*
		 * Compute the transmit duration based on the size
		 * of an ACK frame.  We call into the HAL to do the
		 * computation since it depends on the characteristics
		 * of the actual PHY being used.
		 */
		if (flags & ATH9K_TXDESC_RTSENA) {	/* SIFS + CTS */
			ctsduration += ath9k_hw_computetxtime(ah,
			    rt, IEEE80211_ACK_SIZE, cix, shortPreamble);
		}
		/* SIFS + data */
		ctsduration += ath9k_hw_computetxtime(ah,
		    rt, pktlen, rix, shortPreamble);
		if ((flags & ATH9K_TXDESC_NOACK) == 0) {  /* SIFS + ACK */
			ctsduration += ath9k_hw_computetxtime(ah,
			    rt, IEEE80211_ACK_SIZE, cix, shortPreamble);
		}
	} else
		ctsrate = 0;

	if (++txq->axq_intrcnt >= 5) {
		flags |= ATH9K_TXDESC_INTREQ;
		txq->axq_intrcnt = 0;
	}

	/* setup descriptor */
	ds->ds_link = 0;
	ds->ds_data = bf->bf_dma.cookie.dmac_address;

	/*
	 * Formulate first tx descriptor with tx controls.
	 */
	ath9k_hw_set11n_txdesc(ah, ds,
	    pktlen, /* packet length */
	    atype, /* Atheros packet type */
	    MAX_RATE_POWER /* MAX_RATE_POWER */,
	    keyix /* ATH9K_TXKEYIX_INVALID */,
	    keytype /* ATH9K_KEY_TYPE_CLEAR */,
	    flags /* flags */);
	bf->bf_flags = (uint16_t)flags; /* LINT */

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	ARN_DBG((ARN_DBG_XMIT, "arn: arn_tx_start(): to %s totlen=%d "
	    "an->an_tx_rate1sp=%d tx_rate2sp=%d tx_rate3sp=%d "
	    "qnum=%d rix=%d sht=%d dur = %d\n",
	    ieee80211_macaddr_sprintf(wh->i_addr1), mbslen, an->an_tx_rate1sp,
	    an->an_tx_rate2sp, an->an_tx_rate3sp,
	    txq->axq_qnum, rix, shortPreamble, *(uint16_t *)wh->i_dur));

	(void) ath9k_hw_filltxdesc(ah, ds,
	    mbslen,		/* segment length */
	    B_TRUE,		/* first segment */
	    B_TRUE,		/* last segment */
	    ds);		/* first descriptor */

	/* set rate related fields in tx descriptor */
	struct ath9k_11n_rate_series series[4];
	(void) memset(series, 0, sizeof (struct ath9k_11n_rate_series) * 4);

#ifdef MULTIRATE_RETRY
	int i;
	for (i = 1; i < 4; i++) {
		series[i].Tries = 2; /* ??? */
		series[i].ChSel = sc->sc_tx_chainmask;

		series[i].RateFlags &= ~ATH9K_RATESERIES_RTS_CTS;
		series[i].RateFlags &= ~ATH9K_RATESERIES_2040;
		series[i].RateFlags &= ~ATH9K_RATESERIES_HALFGI;

		series[i].PktDuration = ath9k_hw_computetxtime(sc->sc_ah,
		    rt, pktlen, rix, shortPreamble);
	}
#endif

	/* main rate */
	series[0].Rate = txrate;
	series[0].Tries = ATH_TXMAXTRY;
	series[0].RateFlags &= ~ATH9K_RATESERIES_RTS_CTS;
	series[0].RateFlags &= ~ATH9K_RATESERIES_2040;
	series[0].RateFlags &= ~ATH9K_RATESERIES_HALFGI;
	series[0].ChSel = sc->sc_tx_chainmask;
	series[0].PktDuration = ath9k_hw_computetxtime(sc->sc_ah, rt, pktlen,
	    rix, shortPreamble);

#ifdef MULTIRATE_RETRY
	if ((ic->ic_flags & IEEE80211_F_SHPREAMBLE) &&
	    (in->in_capinfo & IEEE80211_CAPINFO_SHORT_PREAMBLE)) {
		series[1].Rate = an->an_tx_rate1sp;
		series[2].Rate = an->an_tx_rate2sp;
		series[3].Rate = an->an_tx_rate3sp;
	}
	else
	{
		series[1].Rate = an->an_tx_rate1;
		series[2].Rate = an->an_tx_rate2;
		series[3].Rate = an->an_tx_rate3;
	}
#endif

	/* set dur_update_en for l-sig computation except for PS-Poll frames */
	ath9k_hw_set11n_ratescenario(sc->sc_ah, ds,
	    ds, !is_pspoll, ctsrate, 0, series, 4, flags);

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

/* Process completed xmit descriptors from the specified queue */

static int
arn_tx_processq(struct arn_softc *sc, struct ath_txq *txq)
{
	ieee80211com_t *ic = (ieee80211com_t *)sc;
	struct ath_hal *ah = sc->sc_ah;
	struct ath_buf *bf;
	struct ath_desc *ds;
	struct ieee80211_node *in;
	int32_t sr, lr, nacked = 0;
	struct ath_tx_status *ts;
	int status;
	struct ath_node *an;

	for (;;) {
		mutex_enter(&txq->axq_lock);
		bf = list_head(&txq->axq_list);
		if (bf == NULL) {
			txq->axq_link = NULL;
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
