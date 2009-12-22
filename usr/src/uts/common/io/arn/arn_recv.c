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

#include <sys/byteorder.h>

#include "arn_core.h"

void
arn_setdefantenna(struct arn_softc *sc, uint32_t antenna)
{
	/* XXX block beacon interrupts */
	ath9k_hw_setantenna(sc->sc_ah, antenna);
	sc->sc_defant = (uint8_t)antenna; /* LINT */
	sc->sc_rxotherant = 0;
}

/*
 *  Extend 15-bit time stamp from rx descriptor to
 *  a full 64-bit TSF using the current h/w TSF.
 */

static uint64_t
arn_extend_tsf(struct arn_softc *sc, uint32_t rstamp)
{
	uint64_t tsf;

	tsf = ath9k_hw_gettsf64(sc->sc_ah);
	if ((tsf & 0x7fff) < rstamp)
		tsf -= 0x8000;
	return ((tsf & ~0x7fff) | rstamp);
}

static void
arn_opmode_init(struct arn_softc *sc)
{
	struct ath_hal *ah = sc->sc_ah;
	uint32_t rfilt;
	uint32_t mfilt[2];
	ieee80211com_t *ic = (ieee80211com_t *)sc;

	/* configure rx filter */
	rfilt = arn_calcrxfilter(sc);
	ath9k_hw_setrxfilter(ah, rfilt);

	/* configure bssid mask */
	if (ah->ah_caps.hw_caps & ATH9K_HW_CAP_BSSIDMASK)
		(void) ath9k_hw_setbssidmask(ah, sc->sc_bssidmask);

	/* configure operational mode */
	ath9k_hw_setopmode(ah);

	/* Handle any link-level address change. */
	(void) ath9k_hw_setmac(ah, sc->sc_myaddr);

	/* calculate and install multicast filter */
	mfilt[0] = ~((uint32_t)0); /* LINT */
	mfilt[1] = ~((uint32_t)0); /* LINT */

	ath9k_hw_setmcastfilter(ah, mfilt[0], mfilt[1]);

	ARN_DBG((ARN_DBG_RECV, "arn: arn_opmode_init(): "
	    "mode = %d RX filter 0x%x, MC filter %08x:%08x\n",
	    ic->ic_opmode, rfilt, mfilt[0], mfilt[1]));
}

/*
 * Calculate the receive filter according to the
 * operating mode and state:
 *
 * o always accept unicast, broadcast, and multicast traffic
 * o maintain current state of phy error reception (the hal
 *   may enable phy error frames for noise immunity work)
 * o probe request frames are accepted only when operating in
 *   hostap, adhoc, or monitor modes
 * o enable promiscuous mode according to the interface state
 * o accept beacons:
 * - when operating in adhoc mode so the 802.11 layer creates
 * node table entries for peers,
 * - when operating in station mode for collecting rssi data when
 * the station is otherwise quiet, or
 * - when operating as a repeater so we see repeater-sta beacons
 * - when scanning
 */

uint32_t
arn_calcrxfilter(struct arn_softc *sc)
{
#define	RX_FILTER_PRESERVE	(ATH9K_RX_FILTER_PHYERR |	\
	ATH9K_RX_FILTER_PHYRADAR)

	uint32_t rfilt;

	rfilt = (ath9k_hw_getrxfilter(sc->sc_ah) & RX_FILTER_PRESERVE) |
	    ATH9K_RX_FILTER_UCAST | ATH9K_RX_FILTER_BCAST |
	    ATH9K_RX_FILTER_MCAST;

	/* If not a STA, enable processing of Probe Requests */
	if (sc->sc_ah->ah_opmode != ATH9K_M_STA)
		rfilt |= ATH9K_RX_FILTER_PROBEREQ;

	/* Can't set HOSTAP into promiscous mode */
	if (((sc->sc_ah->ah_opmode != ATH9K_M_HOSTAP) &&
	    (sc->sc_promisc)) ||
	    (sc->sc_ah->ah_opmode == ATH9K_M_MONITOR)) {
		rfilt |= ATH9K_RX_FILTER_PROM;
		/* ??? To prevent from sending ACK */
		rfilt &= ~ATH9K_RX_FILTER_UCAST;
	}

	if (sc->sc_ah->ah_opmode == ATH9K_M_STA ||
	    sc->sc_ah->ah_opmode == ATH9K_M_IBSS)
		rfilt |= ATH9K_RX_FILTER_BEACON;

	/*
	 * If in HOSTAP mode, want to enable reception of PSPOLL
	 * frames & beacon frames
	 */
	if (sc->sc_ah->ah_opmode == ATH9K_M_HOSTAP)
		rfilt |= (ATH9K_RX_FILTER_BEACON | ATH9K_RX_FILTER_PSPOLL);

	return (rfilt);

#undef RX_FILTER_PRESERVE
}

int
arn_startrecv(struct arn_softc *sc)
{
	struct ath_hal *ah = sc->sc_ah;
	struct ath_buf *bf;

	/* clean up rx link firstly */
	sc->sc_rxlink = NULL;

	/* rx descriptor link set up */
	bf = list_head(&sc->sc_rxbuf_list);
	while (bf != NULL) {
		arn_rx_buf_link(sc, bf);
		bf = list_next(&sc->sc_rxbuf_list, bf);
	}

	bf = list_head(&sc->sc_rxbuf_list);

	ath9k_hw_putrxbuf(ah, bf->bf_daddr);
	ath9k_hw_rxena(ah);

	arn_opmode_init(sc);
	ath9k_hw_startpcureceive(ah);

	return (0);
}

boolean_t
arn_stoprecv(struct arn_softc *sc)
{
	struct ath_hal *ah = sc->sc_ah;
	boolean_t stopped;

	ath9k_hw_stoppcurecv(ah);
	ath9k_hw_setrxfilter(ah, 0);
	stopped = ath9k_hw_stopdmarecv(ah);

	/* 3ms is long enough for 1 frame ??? */
	drv_usecwait(3000);

	sc->sc_rxlink = NULL;

	return (stopped);
}

/*
 * Intercept management frames to collect beacon rssi data
 * and to do ibss merges.
 */

void
arn_recv_mgmt(struct ieee80211com *ic, mblk_t *mp, struct ieee80211_node *in,
    int subtype, int rssi, uint32_t rstamp)
{
	struct arn_softc *sc = (struct arn_softc *)ic;

	/*
	 * Call up first so subsequent work can use information
	 * potentially stored in the node (e.g. for ibss merge).
	 */
	sc->sc_recv_mgmt(ic, mp, in, subtype, rssi, rstamp);

	ARN_LOCK(sc);
	switch (subtype) {
	case IEEE80211_FC0_SUBTYPE_BEACON:
		/* update rssi statistics */
		if (sc->sc_bsync && in == ic->ic_bss &&
		    ic->ic_state == IEEE80211_S_RUN) {
			/*
			 * Resync beacon timers using the tsf of the beacon
			 * frame we just received.
			 */
			arn_beacon_config(sc);
		}
		/* FALLTHRU */
	case IEEE80211_FC0_SUBTYPE_PROBE_RESP:
		if (ic->ic_opmode == IEEE80211_M_IBSS &&
		    ic->ic_state == IEEE80211_S_RUN &&
		    (in->in_capinfo & IEEE80211_CAPINFO_IBSS)) {
			uint64_t tsf = arn_extend_tsf(sc, rstamp);
			/*
			 * Handle ibss merge as needed; check the tsf on the
			 * frame before attempting the merge.  The 802.11 spec
			 * says the station should change it's bssid to match
			 * the oldest station with the same ssid, where oldest
			 * is determined by the tsf.  Note that hardware
			 * reconfiguration happens through callback to
			 * ath_newstate as the state machine will go from
			 * RUN -> RUN when this happens.
			 */
			if (LE_64(in->in_tstamp.tsf) >= tsf) {
				ARN_DBG((ARN_DBG_BEACON, "arn: arn_recv_mgmt:"
				    "ibss merge, rstamp %u tsf %lu "
				    "tstamp %lu\n", rstamp, tsf,
				    in->in_tstamp.tsf));
				ARN_UNLOCK(sc);
				ARN_DBG((ARN_DBG_BEACON, "arn_recv_mgmt():"
				    "ibss_merge: rstamp=%d in_tstamp=%02x %02x"
				    " %02x %02x %02x %02x %02x %02x\n",
				    rstamp, in->in_tstamp.data[0],
				    in->in_tstamp.data[1],
				    in->in_tstamp.data[2],
				    in->in_tstamp.data[3],
				    in->in_tstamp.data[4],
				    in->in_tstamp.data[5],
				    in->in_tstamp.data[6],
				    in->in_tstamp.data[7]));
				(void) ieee80211_ibss_merge(in);
				return;
			}
		}
		break;
	}
	ARN_UNLOCK(sc);
}

static void
arn_printrxbuf(struct ath_buf *bf, int32_t done)
{
	struct ath_desc *ds = bf->bf_desc;
	const struct ath_rx_status *rs = &ds->ds_rxstat;

	ARN_DBG((ARN_DBG_RECV, "arn: R (%p %p) %08x %08x %08x "
	    "%08x %08x %08x %c\n",
	    ds, bf->bf_daddr,
	    ds->ds_link, ds->ds_data,
	    ds->ds_ctl0, ds->ds_ctl1,
	    ds->ds_hw[0], ds->ds_hw[1],
	    !done ? ' ' : (rs->rs_status == 0) ? '*' : '!'));
}

static void
arn_rx_handler(struct arn_softc *sc)
{
#define	PA2DESC(_sc, _pa) \
		((struct ath_desc *)((caddr_t)(_sc)->sc_desc + \
		((_pa) - (_sc)->sc_desc_dma.cookie.dmac_address)))

	ieee80211com_t *ic = (ieee80211com_t *)sc;
	struct ath_buf *bf;
	struct ath_hal *ah = sc->sc_ah;
	struct ath_desc *ds;
	struct ath_rx_status *rs;
	mblk_t *rx_mp;
	struct ieee80211_frame *wh;
	int32_t len, ngood, loop = 1;
	uint8_t phyerr;
	int status;
	struct ieee80211_node *in;
	uint32_t cur_signal;
	uint32_t subtype;

	ngood = 0;
	do {
		mutex_enter(&sc->sc_rxbuflock);
		bf = list_head(&sc->sc_rxbuf_list);
		if (bf == NULL) {
			ARN_DBG((ARN_DBG_RECV, "arn: arn_rx_handler(): "
			    "no buffer\n"));
			mutex_exit(&sc->sc_rxbuflock);
			break;
		}
		ASSERT(bf->bf_dma.cookie.dmac_address != NULL);
		ds = bf->bf_desc;
		if (ds->ds_link == bf->bf_daddr) {
			/*
			 * Never process the self-linked entry at the end,
			 * this may be met at heavy load.
			 */
			mutex_exit(&sc->sc_rxbuflock);
			break;
		}

		/*
		 * Must provide the virtual address of the current
		 * descriptor, the physical address, and the virtual
		 * address of the next descriptor in the h/w chain.
		 * This allows the HAL to look ahead to see if the
		 * hardware is done with a descriptor by checking the
		 * done bit in the following descriptor and the address
		 * of the current descriptor the DMA engine is working
		 * on.  All this is necessary because of our use of
		 * a self-linked list to avoid rx overruns.
		 */
		status = ath9k_hw_rxprocdesc(ah, ds,
		    bf->bf_daddr,
		    PA2DESC(sc, ds->ds_link), 0);
		if (status == EINPROGRESS) {
			mutex_exit(&sc->sc_rxbuflock);
			break;
		}
		list_remove(&sc->sc_rxbuf_list, bf);
		mutex_exit(&sc->sc_rxbuflock);

		rs = &ds->ds_rxstat;
		if (rs->rs_status != 0) {
			if (rs->rs_status & ATH9K_RXERR_CRC) {
				sc->sc_stats.ast_rx_crcerr++;
			}
			if (rs->rs_status & ATH9K_RXERR_FIFO) {
				sc->sc_stats.ast_rx_fifoerr++;
			}
			if (rs->rs_status & ATH9K_RXERR_DECRYPT) {
				sc->sc_stats.ast_rx_badcrypt++;
			}
			if (rs->rs_status & ATH9K_RXERR_PHY) {
				sc->sc_stats.ast_rx_phyerr++;
				phyerr = rs->rs_phyerr & 0x1f;
				sc->sc_stats.ast_rx_phy[phyerr]++;
			}
			goto rx_next;
		}
		len = rs->rs_datalen;

		/* less than sizeof(struct ieee80211_frame) */
		if (len < 20) {
			sc->sc_stats.ast_rx_tooshort++;
			goto rx_next;
		}

		if ((rx_mp = allocb(sc->sc_dmabuf_size, BPRI_MED)) == NULL) {
			arn_problem("arn: arn_rx_handler(): "
			    "allocing mblk buffer failed.\n");
			return;
		}

		ARN_DMA_SYNC(bf->bf_dma, DDI_DMA_SYNC_FORCPU);
		bcopy(bf->bf_dma.mem_va, rx_mp->b_rptr, len);

		rx_mp->b_wptr += len;
		wh = (struct ieee80211_frame *)rx_mp->b_rptr;

		if ((wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) ==
		    IEEE80211_FC0_TYPE_CTL) {
			/*
			 * Ignore control frame received in promisc mode.
			 */
			freemsg(rx_mp);
			goto rx_next;
		}

		/* Remove the CRC at the end of IEEE80211 frame */
		rx_mp->b_wptr -= IEEE80211_CRC_LEN;

		/*
		 * Locate the node for sender, track state, and then
		 * pass the (referenced) node up to the 802.11 layer
		 * for its use.
		 */
		in = ieee80211_find_rxnode(ic, wh);

		if (ds->ds_rxstat.rs_rssi < 0)
			ds->ds_rxstat.rs_rssi = 0;

		if ((wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) ==
		    IEEE80211_FC0_TYPE_MGT) {
			subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;
			/* Update Beacon RSSI, this is used by ANI. */
			if (subtype == IEEE80211_FC0_SUBTYPE_BEACON)
				sc->sc_halstats.ns_avgbrssi =
				    ds->ds_rxstat.rs_rssi;
		}

#ifdef DEBUG
		arn_printrxbuf(bf, status == 0);
#endif

		/*
		 * signal 13-15 DLADM_WLAN_STRENGTH_EXCELLENT
		 * signal 10-12 DLADM_WLAN_STRENGTH_VERY_GOOD
		 * signal 6-9   DLADM_WLAN_STRENGTH_GOOD
		 * signal 3-5   DLADM_WLAN_STRENGTH_WEAK
		 * signal 0-2   DLADM_WLAN_STRENGTH_VERY_WEAK
		 */
		if (rs->rs_rssi == 0)
			cur_signal = 0;
		else if (rs->rs_rssi >= 45)
			cur_signal = MAX_RSSI;
		else
			cur_signal = rs->rs_rssi * MAX_RSSI / 45 + 1;

		/*
		 * Send the frame to net80211 for processing
		 */
		if (cur_signal <= 2 && ic->ic_state == IEEE80211_S_RUN)
			(void) ieee80211_input(ic, rx_mp, in,
			    (rs->rs_rssi + 10), rs->rs_tstamp);
		else
			(void) ieee80211_input(ic, rx_mp, in,
			    rs->rs_rssi, rs->rs_tstamp);

		/* release node */
		ieee80211_free_node(in);

		/*
		 * Arrange to update the last rx timestamp only for
		 * frames from our ap when operating in station mode.
		 * This assumes the rx key is always setup when associated.
		 */
		if (ic->ic_opmode == IEEE80211_M_STA &&
		    rs->rs_keyix != ATH9K_RXKEYIX_INVALID) {
			ngood++;
		}

		/*
		 * change the default rx antenna if rx diversity chooses the
		 * other antenna 3 times in a row.
		 */
		if (sc->sc_defant != ds->ds_rxstat.rs_antenna) {
			if (++sc->sc_rxotherant >= 3) {
				ath9k_hw_setantenna(sc->sc_ah,
				    ds->ds_rxstat.rs_antenna);
				sc->sc_defant = ds->ds_rxstat.rs_antenna;
				sc->sc_rxotherant = 0;
			}
		} else {
			sc->sc_rxotherant = 0;
		}

rx_next:
		mutex_enter(&sc->sc_rxbuflock);
		list_insert_tail(&sc->sc_rxbuf_list, bf);
		mutex_exit(&sc->sc_rxbuflock);
		arn_rx_buf_link(sc, bf);
	} while (loop);

	if (ngood)
		sc->sc_lastrx = ath9k_hw_gettsf64(ah);

#undef PA2DESC
}

uint_t
arn_softint_handler(caddr_t data)
{
	struct arn_softc *sc = (struct arn_softc *)data;

	ARN_LOCK(sc);

	if (sc->sc_rx_pend) {
		/* Soft interrupt for this driver */
		sc->sc_rx_pend = 0;
		ARN_UNLOCK(sc);
		arn_rx_handler(sc);
		return (DDI_INTR_CLAIMED);
	}

	ARN_UNLOCK(sc);

	return (DDI_INTR_UNCLAIMED);
}
