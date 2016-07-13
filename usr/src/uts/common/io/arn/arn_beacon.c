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
#include <sys/strsun.h>
#include <inet/common.h>
#include <inet/nd.h>
#include <inet/mi.h>
#include <inet/wifi_ioctl.h>

#include "arn_core.h"

/*
 * Associates the beacon frame buffer with a transmit descriptor.  Will set
 * up all required antenna switch parameters, rate codes, and channel flags.
 * Beacons are always sent out at the lowest rate, and are not retried.
 */
#ifdef ARN_IBSS
static void
arn_beacon_setup(struct arn_softc *sc, struct ath_buf *bf)
{
#define	USE_SHPREAMBLE(_ic) \
	(((_ic)->ic_flags & (IEEE80211_F_SHPREAMBLE | IEEE80211_F_USEBARKER))\
	    == IEEE80211_F_SHPREAMBLE)
	mblk_t *mp = bf->bf_m;
	struct ath_hal *ah = sc->sc_ah;
	struct ath_desc *ds;
	/* LINTED E_FUNC_SET_NOT_USED */
	int flags, antenna = 0;
	struct ath_rate_table *rt;
	uint8_t rix, rate;
	struct ath9k_11n_rate_series series[4];
	int ctsrate = 0;
	int ctsduration = 0;

	/* set up descriptors */
	ds = bf->bf_desc;

	flags = ATH9K_TXDESC_NOACK;
	if (sc->sc_ah->ah_opmode == ATH9K_M_IBSS &&
	    (ah->ah_caps.hw_caps & ATH9K_HW_CAP_VEOL)) {
		ds->ds_link = bf->bf_daddr;	/* self-linked */
		flags |= ATH9K_TXDESC_VEOL;
		/*
		 * Let hardware handle antenna switching.
		 */
		antenna = 0;
	} else {
		ds->ds_link = 0;
		/*
		 * Switch antenna every 4 beacons.
		 * NB: assumes two antenna
		 */
		antenna = ((sc->ast_be_xmit / sc->sc_nbcnvaps) & 1 ? 2 : 1);
	}

	ds->ds_data = bf->bf_dma.cookie.dmac_address;
	/*
	 * Calculate rate code.
	 * XXX everything at min xmit rate
	 */
	rix = 0;
	rt = sc->hw_rate_table[sc->sc_curmode];
	rate = rt->info[rix].ratecode;
	if (sc->sc_flags & SC_OP_PREAMBLE_SHORT)
		rate |= rt->info[rix].short_preamble;

	ath9k_hw_set11n_txdesc(ah, ds,
	    MBLKL(mp) + IEEE80211_CRC_LEN, /* frame length */
	    ATH9K_PKT_TYPE_BEACON,	/* Atheros packet type */
	    MAX_RATE_POWER,		/* FIXME */
	    ATH9K_TXKEYIX_INVALID,	/* no encryption */
	    ATH9K_KEY_TYPE_CLEAR,	/* no encryption */
	    flags);			/* no ack, veol for beacons */

	/* NB: beacon's BufLen must be a multiple of 4 bytes */
	(void) ath9k_hw_filltxdesc(ah, ds,
	    roundup(MBLKL(mp), 4),	/* buffer length */
	    B_TRUE,			/* first segment */
	    B_TRUE,			/* last segment */
	    ds);			/* first descriptor */

	(void) memset(series, 0, sizeof (struct ath9k_11n_rate_series) * 4);
	series[0].Tries = 1;
	series[0].Rate = rate;
	series[0].ChSel = sc->sc_tx_chainmask;
	series[0].RateFlags = (ctsrate) ? ATH9K_RATESERIES_RTS_CTS : 0;
	ath9k_hw_set11n_ratescenario(ah, ds, ds, 0,
	    ctsrate, ctsduration, series, 4, 0);
#undef	USE_SHPREAMBLE
}
#endif

/*
 * Startup beacon transmission for adhoc mode when they are sent entirely
 * by the hardware using the self-linked descriptor + veol trick.
 */
#ifdef ARN_IBSS
static void
arn_beacon_start_adhoc(struct arn_softc *sc)
{
	struct ath_buf *bf = list_head(&sc->sc_bcbuf_list);
	struct ieee80211_node *in = bf->bf_in;
	struct ieee80211com *ic = in->in_ic;
	struct ath_hal *ah = sc->sc_ah;
	mblk_t *mp;

	mp = bf->bf_m;
	if (ieee80211_beacon_update(ic, bf->bf_in, &sc->asc_boff, mp, 0))
		bcopy(mp->b_rptr, bf->bf_dma.mem_va, MBLKL(mp));

	/* Construct tx descriptor. */
	arn_beacon_setup(sc, bf);

	/*
	 * Stop any current dma and put the new frame on the queue.
	 * This should never fail since we check above that no frames
	 * are still pending on the queue.
	 */
	if (!ath9k_hw_stoptxdma(ah, sc->sc_beaconq)) {
		arn_problem("ath: beacon queue %d did not stop?\n",
		    sc->sc_beaconq);
	}
	ARN_DMA_SYNC(bf->bf_dma, DDI_DMA_SYNC_FORDEV);

	/* NB: caller is known to have already stopped tx dma */
	(void) ath9k_hw_puttxbuf(ah, sc->sc_beaconq, bf->bf_daddr);
	(void) ath9k_hw_txstart(ah, sc->sc_beaconq);

	ARN_DBG((ARN_DBG_BEACON, "arn: arn_bstuck_process(): "
	    "TXDP%u = %llx (%p)\n", sc->sc_beaconq,
	    ito64(bf->bf_daddr), bf->bf_desc));
}
#endif /* ARN_IBSS */

uint32_t
arn_beaconq_setup(struct ath_hal *ah)
{
	struct ath9k_tx_queue_info qi;

	(void) memset(&qi, 0, sizeof (qi));
	qi.tqi_aifs = 1;
	qi.tqi_cwmin = 0;
	qi.tqi_cwmax = 0;
	/* NB: don't enable any interrupts */
	return (ath9k_hw_setuptxqueue(ah, ATH9K_TX_QUEUE_BEACON, &qi));
}

int
arn_beacon_alloc(struct arn_softc *sc, struct ieee80211_node *in)
{
	ieee80211com_t	*ic = in->in_ic;
	struct ath_buf *bf;
	mblk_t *mp;

	mutex_enter(&sc->sc_bcbuflock);
	bf = list_head(&sc->sc_bcbuf_list);
	if (bf == NULL) {
		arn_problem("arn: arn_beacon_alloc():"
		    "no dma buffers");
		mutex_exit(&sc->sc_bcbuflock);
		return (ENOMEM);
	}

	mp = ieee80211_beacon_alloc(ic, in, &sc->asc_boff);
	if (mp == NULL) {
		arn_problem("ath: arn_beacon_alloc():"
		    "cannot get mbuf\n");
		mutex_exit(&sc->sc_bcbuflock);
		return (ENOMEM);
	}
	ASSERT(mp->b_cont == NULL);
	bf->bf_m = mp;
	bcopy(mp->b_rptr, bf->bf_dma.mem_va, MBLKL(mp));
	bf->bf_in = ieee80211_ref_node(in);
	mutex_exit(&sc->sc_bcbuflock);

	return (0);
}


void
arn_beacon_return(struct arn_softc *sc)
{
	struct ath_buf *bf;

	mutex_enter(&sc->sc_bcbuflock);
	bf = list_head(&sc->sc_bcbuf_list);
	while (bf != NULL) {
		if (bf->bf_m != NULL) {
			freemsg(bf->bf_m);
			bf->bf_m = NULL;
		}
		if (bf->bf_in != NULL) {
			ieee80211_free_node(bf->bf_in);
			bf->bf_in = NULL;
		}
		bf = list_next(&sc->sc_bcbuf_list, bf);
	}
	mutex_exit(&sc->sc_bcbuflock);
}

void
arn_beacon_config(struct arn_softc *sc)
{
	struct ath_beacon_config conf;
	ieee80211com_t *ic = (ieee80211com_t *)sc;
	struct ieee80211_node *in = ic->ic_bss;

	/* New added */
	struct ath9k_beacon_state bs;
	int dtimperiod, dtimcount, sleepduration;
	int cfpperiod, cfpcount;
	uint32_t nexttbtt = 0, intval, tsftu;
	uint64_t tsf;

	(void) memset(&conf, 0, sizeof (struct ath_beacon_config));

	/* XXX fix me */
	conf.beacon_interval = in->in_intval ?
	    in->in_intval : ATH_DEFAULT_BINTVAL;
	ARN_DBG((ARN_DBG_BEACON, "arn: arn_beacon_config():"
	    "conf.beacon_interval = %d\n", conf.beacon_interval));
	conf.listen_interval = 1;
	conf.dtim_period = conf.beacon_interval;
	conf.dtim_count = 1;
	conf.bmiss_timeout = ATH_DEFAULT_BMISS_LIMIT * conf.beacon_interval;

	(void) memset(&bs, 0, sizeof (bs));
	intval = conf.beacon_interval & ATH9K_BEACON_PERIOD;

	/*
	 * Setup dtim and cfp parameters according to
	 * last beacon we received (which may be none).
	 */
	dtimperiod = conf.dtim_period;
	if (dtimperiod <= 0)		/* NB: 0 if not known */
		dtimperiod = 1;
	dtimcount = conf.dtim_count;
	if (dtimcount >= dtimperiod)	/* NB: sanity check */
		dtimcount = 0;
	cfpperiod = 1;			/* NB: no PCF support yet */
	cfpcount = 0;

	sleepduration = conf.listen_interval * intval;
	if (sleepduration <= 0)
		sleepduration = intval;

	/*
	 * Pull nexttbtt forward to reflect the current
	 * TSF and calculate dtim+cfp state for the result.
	 */
	tsf = ath9k_hw_gettsf64(sc->sc_ah);
	tsftu = TSF_TO_TU(tsf>>32, tsf) + FUDGE;
	do {
		nexttbtt += intval;
		if (--dtimcount < 0) {
			dtimcount = dtimperiod - 1;
			if (--cfpcount < 0)
				cfpcount = cfpperiod - 1;
		}
	} while (nexttbtt < tsftu);

	bs.bs_intval = intval;
	bs.bs_nexttbtt = nexttbtt;
	bs.bs_dtimperiod = dtimperiod*intval;
	bs.bs_nextdtim = bs.bs_nexttbtt + dtimcount*intval;
	bs.bs_cfpperiod = cfpperiod*bs.bs_dtimperiod;
	bs.bs_cfpnext = bs.bs_nextdtim + cfpcount*bs.bs_dtimperiod;
	bs.bs_cfpmaxduration = 0;

	/*
	 * Calculate the number of consecutive beacons to miss* before taking
	 * a BMISS interrupt. The configuration is specified in TU so we only
	 * need calculate based	on the beacon interval.  Note that we clamp the
	 * result to at most 15 beacons.
	 */
	if (sleepduration > intval) {
		bs.bs_bmissthreshold = conf.listen_interval *
		    ATH_DEFAULT_BMISS_LIMIT / 2;
	} else {
		bs.bs_bmissthreshold = DIV_ROUND_UP(conf.bmiss_timeout, intval);
		if (bs.bs_bmissthreshold > 15)
			bs.bs_bmissthreshold = 15;
		else if (bs.bs_bmissthreshold == 0)
			bs.bs_bmissthreshold = 1;
	}

	/*
	 * Calculate sleep duration. The configuration is given in ms.
	 * We ensure a multiple of the beacon period is used. Also, if the sleep
	 * duration is greater than the DTIM period then it makes senses
	 * to make it a multiple of that.
	 *
	 * XXX fixed at 100ms
	 */

	bs.bs_sleepduration = roundup(IEEE80211_MS_TO_TU(100), sleepduration);
	if (bs.bs_sleepduration > bs.bs_dtimperiod)
		bs.bs_sleepduration = bs.bs_dtimperiod;

	/* TSF out of range threshold fixed at 1 second */
	bs.bs_tsfoor_threshold = ATH9K_TSFOOR_THRESHOLD;

	ARN_DBG((ARN_DBG_BEACON, "arn: arn_beacon_config(): "
	    "tsf %llu "
	    "tsf:tu %u "
	    "intval %u "
	    "nexttbtt %u "
	    "dtim %u "
	    "nextdtim %u "
	    "bmiss %u "
	    "sleep %u "
	    "cfp:period %u "
	    "maxdur %u "
	    "next %u "
	    "timoffset %u\n",
	    (unsigned long long)tsf, tsftu,
	    bs.bs_intval,
	    bs.bs_nexttbtt,
	    bs.bs_dtimperiod,
	    bs.bs_nextdtim,
	    bs.bs_bmissthreshold,
	    bs.bs_sleepduration,
	    bs.bs_cfpperiod,
	    bs.bs_cfpmaxduration,
	    bs.bs_cfpnext,
	    bs.bs_timoffset));

	/* Set the computed STA beacon timers */

	(void) ath9k_hw_set_interrupts(sc->sc_ah, 0);
	ath9k_hw_set_sta_beacon_timers(sc->sc_ah, &bs);
	sc->sc_imask |= ATH9K_INT_BMISS;
	(void) ath9k_hw_set_interrupts(sc->sc_ah, sc->sc_imask);
}

void
ath_beacon_sync(struct arn_softc *sc)
{
	/*
	 * Resync beacon timers using the tsf of the
	 * beacon frame we just received.
	 */
	arn_beacon_config(sc);
	sc->sc_flags |= SC_OP_BEACONS;
}

void
arn_bmiss_proc(void *arg)
{
	struct arn_softc *sc = (struct arn_softc *)arg;
	ieee80211com_t *ic = (ieee80211com_t *)sc;
	uint64_t tsf, lastrx;
	uint_t  bmisstimeout;

	if (ic->ic_opmode != IEEE80211_M_STA ||
	    ic->ic_state != IEEE80211_S_RUN) {
		return;
	}

	ARN_LOCK(sc);
	lastrx = sc->sc_lastrx;
	tsf = ath9k_hw_gettsf64(sc->sc_ah);
	bmisstimeout = ic->ic_bmissthreshold * ic->ic_bss->in_intval * 1024;

	ARN_DBG((ARN_DBG_BEACON, "arn_bmiss_proc():"
	    " tsf %llu, lastrx %llu (%lld), bmiss %u\n",
	    (unsigned long long)tsf, (unsigned long long)sc->sc_lastrx,
	    (long long)(tsf - lastrx), bmisstimeout));
	ARN_UNLOCK(sc);

	/* temp workaround */
	if ((tsf - lastrx) > bmisstimeout)
		ieee80211_beacon_miss(ic);
}
