/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2002-2004 Sam Leffler, Errno Consulting
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer,
 * without modification.
 * 2. Redistributions in binary form must reproduce at minimum a disclaimer
 * similar to the "NO WARRANTY" disclaimer below ("Disclaimer") and any
 * redistribution must be conditioned upon including a substantially
 * similar Disclaimer requirement for further binary redistribution.
 * 3. Neither the names of the above-listed copyright holders nor the names
 * of any contributors may be used to endorse or promote products derived
 * from this software without specific prior written permission.
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
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
#include <sys/list.h>
#include <sys/byteorder.h>
#include <sys/strsun.h>
#include <inet/common.h>
#include <inet/nd.h>
#include <inet/mi.h>
#include <inet/wifi_ioctl.h>
#include "ath_hal.h"
#include "ath_impl.h"
#include "ath_ieee80211.h"

static const char *acnames[] = {
	"WME_AC_BE",
	"WME_AC_BK",
	"WME_AC_VI",
	"WME_AC_VO",
	"WME_UPSD"
};

extern void ath_setup_desc(ath_t *asc, struct ath_buf *bf);

uint32_t
ath_calcrxfilter(ath_t *asc)
{
	ieee80211com_t *isc = (ieee80211com_t *)asc;
	struct ath_hal *ah = asc->asc_ah;
	uint32_t rfilt;

	rfilt = (ATH_HAL_GETRXFILTER(ah) & HAL_RX_FILTER_PHYERR)
	    | HAL_RX_FILTER_UCAST | HAL_RX_FILTER_BCAST | HAL_RX_FILTER_MCAST;
	if (isc->isc_opmode != IEEE80211_M_STA)
		rfilt |= HAL_RX_FILTER_PROBEREQ;
	if (isc->isc_opmode != IEEE80211_M_HOSTAP &&
	    (asc->asc_promisc & GLD_MAC_PROMISC_PHYS))	/* promiscuous */
		rfilt |= HAL_RX_FILTER_PROM;
	if (isc->isc_opmode == IEEE80211_M_STA ||
	    isc->isc_opmode == IEEE80211_M_IBSS ||
	    isc->isc_state == IEEE80211_S_SCAN)
		rfilt |= HAL_RX_FILTER_BEACON;
	return (rfilt);
}

static int
ath_set_data_queue(ath_t *asc, int ac, int haltype)
{
	HAL_TXQ_INFO qi;
	int qnum;
	struct ath_hal *ah = asc->asc_ah;
	struct ath_txq *txq;

	if (ac >= ATH_N(asc->asc_ac2q)) {
		ATH_DEBUG((ATH_DBG_AUX, "ath: ath_set_data_queue(): "
		    "ac %u out of range, max %u!\n",
		    ac, ATH_N(asc->asc_ac2q)));
		return (1);
	}
	(void) memset(&qi, 0, sizeof (qi));
	qi.tqi_subtype = haltype;
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
	 */
	qi.tqi_qflags = TXQ_FLAG_TXEOLINT_ENABLE | TXQ_FLAG_TXDESCINT_ENABLE;
	qnum = ATH_HAL_SETUPTXQUEUE(ah, HAL_TX_QUEUE_DATA, &qi);
	if (qnum == -1) {
		ATH_DEBUG((ATH_DBG_AUX, "ath: ath_set_data_queue(): "
		    "Unable to setup hardware queue for %s traffic!\n",
		    acnames[ac]));
		return (1);
	}
	if (qnum >= ATH_N(asc->asc_txq)) {
		ATH_DEBUG((ATH_DBG_AUX, "ath: ath_set_data_queue(): "
		    "hal qnum %u out of range, max %u!\n",
		    qnum, ATH_N(asc->asc_txq)));
		return (1);
	}
	if (!ATH_TXQ_SETUP(asc, qnum)) {
		txq = &asc->asc_txq[qnum];
		txq->axq_qnum = qnum;
		txq->axq_depth = 0;
		txq->axq_intrcnt = 0;
		txq->axq_link = NULL;
		list_create(&txq->axq_list, sizeof (struct ath_buf),
		    offsetof(struct ath_buf, bf_node));
		mutex_init(&txq->axq_lock, NULL, MUTEX_DRIVER, NULL);
		asc->asc_txqsetup |= 1<<qnum;
	}
	asc->asc_ac2q[ac] = &asc->asc_txq[qnum];
	return (0);
}

int
ath_txq_setup(ath_t *asc)
{
	if (ath_set_data_queue(asc, WME_AC_BE, HAL_WME_AC_BK) ||
	    ath_set_data_queue(asc, WME_AC_BK, HAL_WME_AC_BE) ||
	    ath_set_data_queue(asc, WME_AC_VI, HAL_WME_AC_VI) ||
	    ath_set_data_queue(asc, WME_AC_VO, HAL_WME_AC_VO)) {
		return (1);
	}

	return (0);
}

void
ath_setcurmode(ath_t *asc, enum ieee80211_phymode mode)
{
	const HAL_RATE_TABLE *rt;
	int i;

	for (i = 0; i < sizeof (asc->asc_rixmap); i++)
		asc->asc_rixmap[i] = 0xff;

	rt = asc->asc_rates[mode];
	ASSERT(rt != NULL);

	for (i = 0; i < rt->rateCount; i++)
		asc->asc_rixmap[rt->info[i].dot11Rate & IEEE80211_RATE_VAL] = i;

	asc->asc_currates = rt;
	asc->asc_curmode = mode;
}

/* Set correct parameters for a certain mode */
void
ath_mode_init(ath_t *asc)
{
	ieee80211com_t *isc = (ieee80211com_t *)asc;
	struct ath_hal *ah = asc->asc_ah;
	uint32_t rfilt;

	/* configure rx filter */
	rfilt = ath_calcrxfilter(asc);
	ATH_HAL_SETRXFILTER(ah, rfilt);
	ATH_HAL_SETOPMODE(ah);
	ATH_HAL_SETMCASTFILTER(ah, asc->asc_mfilt[0], asc->asc_mfilt[1]);
	ATH_DEBUG((ATH_DBG_AUX, "ath: ath_mode_init(): "
	    "mode =%d RX filter 0x%x, MC filter %08x:%08x\n",
	    isc->isc_opmode, rfilt,
	    asc->asc_mfilt[0], asc->asc_mfilt[1]));
}


/*
 * Disable the receive h/w in preparation for a reset.
 */
void
ath_stoprecv(ath_t *asc)
{
	ATH_HAL_STOPPCURECV(asc->asc_ah);	/* disable PCU */
	ATH_HAL_SETRXFILTER(asc->asc_ah, 0);	/* clear recv filter */
	ATH_HAL_STOPDMARECV(asc->asc_ah);	/* disable DMA engine */
	drv_usecwait(3000);

	ATH_DEBUG((ATH_DBG_AUX, "ath: ath_stoprecv(): rx queue %p, link %p\n",
	    ATH_HAL_GETRXBUF(asc->asc_ah), asc->asc_rxlink));
	asc->asc_rxlink = NULL;
}

uint32_t
ath_chan2flags(ieee80211com_t *isc, struct ieee80211channel *chan)
{
	static const uint32_t modeflags[] = {
	    0,				/* IEEE80211_MODE_AUTO */
	    CHANNEL_A,			/* IEEE80211_MODE_11A */
	    CHANNEL_B,			/* IEEE80211_MODE_11B */
	    CHANNEL_PUREG,		/* IEEE80211_MODE_11G */
	    CHANNEL_T			/* IEEE80211_MODE_TURBO */
	};
	return (modeflags[ieee80211_chan2mode(isc, chan)]);
}


int
ath_getchannels(ath_t *asc, uint32_t cc, HAL_BOOL outdoor, HAL_BOOL xchanmode)
{
	ieee80211com_t *isc = (ieee80211com_t *)asc;
	struct ath_hal *ah = asc->asc_ah;
	HAL_CHANNEL *chans;
	int i, ix;
	uint32_t nchan;

	chans = (HAL_CHANNEL *)
	    kmem_zalloc(IEEE80211_CHAN_MAX * sizeof (HAL_CHANNEL), KM_SLEEP);

	if (!ath_hal_init_channels(ah, chans, IEEE80211_CHAN_MAX, &nchan,
	    cc, HAL_MODE_ALL, outdoor, xchanmode)) {
		ATH_DEBUG((ATH_DBG_AUX, "ath: ath_getchannels(): "
		    "unable to get channel list\n");
		kmem_free(chans, IEEE80211_CHAN_MAX * sizeof (HAL_CHANNEL)));
		return (EINVAL);
	}

	/*
	 * Convert HAL channels to ieee80211 ones and insert
	 * them in the table according to their channel number.
	 */
	for (i = 0; i < nchan; i++) {
		HAL_CHANNEL *c = &chans[i];
		ix = ath_hal_mhz2ieee(c->channel, c->channelFlags);
		if (ix > IEEE80211_CHAN_MAX) {
			ATH_DEBUG((ATH_DBG_AUX, "ath: ath_getchannels(): "
			    "bad hal channel %u (%u/%x) ignored\n",
			    ix, c->channel, c->channelFlags));
			continue;
		}
		/* NB: flags are known to be compatible */
		if (isc->isc_channels[ix].ich_freq == 0) {
			isc->isc_channels[ix].ich_freq = c->channel;
			isc->isc_channels[ix].ich_flags = c->channelFlags;
		} else {
			/* channels overlap; e.g. 11g and 11b */
			isc->isc_channels[ix].ich_flags |= c->channelFlags;
		}
		if ((c->channelFlags & CHANNEL_G) == CHANNEL_G)
			asc->asc_have11g = 1;
	}
	kmem_free(chans, IEEE80211_CHAN_MAX * sizeof (HAL_CHANNEL));
	return (0);
}

static void
ath_drainq(ath_t *asc, struct ath_txq *txq)
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
		mutex_enter(&asc->asc_txbuflock);
		list_insert_tail(&asc->asc_txbuf_list, bf);
		mutex_exit(&asc->asc_txbuflock);
	}
}


/*
 * Drain the transmit queues and reclaim resources.
 */
void
ath_draintxq(ath_t *asc)
{
	struct ath_hal *ah = asc->asc_ah;
	struct ath_txq *txq;
	int i;

	if (!asc->asc_invalid) {
		for (i = 0; i < HAL_NUM_TX_QUEUES; i++) {
			if (ATH_TXQ_SETUP(asc, i)) {
				txq = &asc->asc_txq[i];
				(void) ATH_HAL_STOPTXDMA(ah, txq->axq_qnum);
			}
		}
	}
	for (i = 0; i < HAL_NUM_TX_QUEUES; i++) {
		if (ATH_TXQ_SETUP(asc, i)) {
			ath_drainq(asc, &asc->asc_txq[i]);
		}
	}
}


/* Enable the receive h/w following a reset */
int
ath_startrecv(ath_t *asc)
{
	struct ath_buf *bf;

	asc->asc_rxlink = NULL;

	bf = list_head(&asc->asc_rxbuf_list);
	while (bf != NULL) {
		ath_setup_desc(asc, bf);
		bf = list_next(&asc->asc_rxbuf_list, bf);
	}

	bf = list_head(&asc->asc_rxbuf_list);
	ATH_HAL_PUTRXBUF(asc->asc_ah, bf->bf_daddr);
	ATH_HAL_RXENA(asc->asc_ah);		/* enable recv descriptors */
	ath_mode_init(asc);			/* set filters, etc. */
	ATH_HAL_STARTPCURECV(asc->asc_ah);	/* re-enable PCU/DMA engine */
	return (0);
}

/*
 * Set/change channels.  If the channel is really being changed,
 * it's done by resetting the chip.  To accomplish this we must
 * first cleanup any pending DMA.
 */
int
ath_chan_set(ath_t *asc, struct ieee80211channel *chan)
{
	struct ath_hal *ah = asc->asc_ah;
	ieee80211com_t *isc = &asc->asc_isc;

	if (chan != isc->isc_ibss_chan) {
		HAL_STATUS status;
		HAL_CHANNEL hchan;
		enum ieee80211_phymode mode;

		/*
		 * To switch channels clear any pending DMA operations;
		 * wait long enough for the RX fifo to drain, reset the
		 * hardware at the new frequency, and then re-enable
		 * the relevant bits of the h/w.
		 */
		ATH_HAL_INTRSET(ah, 0);		/* disable interrupts */
		ath_draintxq(asc);		/* clear pending tx frames */
		ath_stoprecv(asc);		/* turn off frame recv */
		/*
		 * Convert to a HAL channel description with
		 * the flags constrained to reflect the current
		 * operating mode.
		 */
		hchan.channel = chan->ich_freq;
		hchan.channelFlags = ath_chan2flags(isc, chan);
		if (!ATH_HAL_RESET(ah, (HAL_OPMODE)isc->isc_opmode,
		    &hchan, AH_TRUE, &status)) {
			ATH_DEBUG((ATH_DBG_AUX, "ath: ath_chan_set():"
			    "unable to reset channel %u (%uMhz)\n",
			    ieee80211_chan2ieee(isc, chan), chan->ich_freq));
			return (EIO);
		}

		/*
		 * Re-enable rx framework.
		 */
		if (ath_startrecv(asc) != 0) {
			ath_problem("ath: ath_chan_set(): "
			    "restarting receiving logic failed\n");
			return (EIO);
		}

		/*
		 * Change channels and update the h/w rate map
		 * if we're switching; e.g. 11a to 11b/g.
		 */
		isc->isc_ibss_chan = chan;
		mode = ieee80211_chan2mode(isc, chan);
		if (mode != asc->asc_curmode)
			ath_setcurmode(asc, mode);
		/*
		 * Re-enable interrupts.
		 */
		ATH_HAL_INTRSET(ah, asc->asc_imask);
	}
	return (0);
}


/*
 * Configure the beacon and sleep timers.
 *
 * When operating as an AP this resets the TSF and sets
 * up the hardware to notify us when we need to issue beacons.
 *
 * When operating in station mode this sets up the beacon
 * timers according to the timestamp of the last received
 * beacon and the current TSF, configures PCF and DTIM
 * handling, programs the sleep registers so the hardware
 * will wakeup in time to receive beacons, and configures
 * the beacon miss handling so we'll receive a BMISS
 * interrupt when we stop seeing beacons from the AP
 * we've associated with.
 */
void
ath_beacon_config(ath_t *asc)
{
	struct ath_hal *ah = asc->asc_ah;
	ieee80211com_t *isc = (ieee80211com_t *)asc;
	struct ieee80211_node *in = isc->isc_bss;
	uint32_t nexttbtt;

	nexttbtt = (ATH_LE_READ_4(in->in_tstamp + 4) << 22) |
	    (ATH_LE_READ_4(in->in_tstamp) >> 10);
	nexttbtt += in->in_intval;
	if (isc->isc_opmode != IEEE80211_M_HOSTAP) {
		HAL_BEACON_STATE bs;
		uint32_t bmisstime;

		/* NB: no PCF support right now */
		bzero(&bs, sizeof (bs));
		bs.bs_intval = in->in_intval;
		bs.bs_nexttbtt = nexttbtt;
		bs.bs_dtimperiod = bs.bs_intval;
		bs.bs_nextdtim = nexttbtt;

		/*
		 * Calculate the number of consecutive beacons to miss
		 * before taking a BMISS interrupt.  The configuration
		 * is specified in ms, so we need to convert that to
		 * TU's and then calculate based on the beacon interval.
		 * Note that we clamp the result to at most 10 beacons.
		 */
		bmisstime = (isc->isc_bmisstimeout * 1000) / 1024;
		bs.bs_bmissthreshold = howmany(bmisstime, in->in_intval);
		if (bs.bs_bmissthreshold > 10)
			bs.bs_bmissthreshold = 10;
		else if (bs.bs_bmissthreshold <= 0)
			bs.bs_bmissthreshold = 1;
		/*
		 * Calculate sleep duration.  The configuration is
		 * given in ms.  We insure a multiple of the beacon
		 * period is used.  Also, if the sleep duration is
		 * greater than the DTIM period then it makes senses
		 * to make it a multiple of that.
		 */
		bs.bs_sleepduration =
		    roundup((100 * 1000) / 1024, bs.bs_intval);
		if (bs.bs_sleepduration > bs.bs_dtimperiod)
			bs.bs_sleepduration =
			    roundup(bs.bs_sleepduration, bs.bs_dtimperiod);


		ATH_DEBUG((ATH_DBG_AUX, "ath: ath_beacon_config(): "
		    "intval %u nexttbtt %u dtim %u"
		    " nextdtim %u bmiss %u sleep %u\n",
		    bs.bs_intval,
		    bs.bs_nexttbtt,
		    bs.bs_dtimperiod,
		    bs.bs_nextdtim,
		    bs.bs_bmissthreshold,
		    bs.bs_sleepduration));
		ATH_HAL_INTRSET(ah, 0);
		/*
		 * Reset our tsf so the hardware will update the
		 * tsf register to reflect timestamps found in
		 * received beacons.
		 */
		ATH_HAL_RESETTSF(ah);
		ATH_HAL_BEACONTIMERS(ah, &bs);
		asc->asc_imask |= HAL_INT_BMISS;
		ATH_HAL_INTRSET(ah, asc->asc_imask);
	} else {
		ATH_HAL_INTRSET(ah, 0);
		ATH_HAL_BEACONINIT(ah, nexttbtt, in->in_intval);
		asc->asc_imask |= HAL_INT_SWBA;	/* beacon prepare */
		ATH_HAL_INTRSET(ah, asc->asc_imask);
	}
}



/*
 * Fill the hardware key cache with key entries.
 */
void
ath_initkeytable(ath_t *asc)
{
	ieee80211com_t *isc = (ieee80211com_t *)asc;
	struct ath_hal *ah = asc->asc_ah;
	int32_t i;

	for (i = 0; i < IEEE80211_WEP_NKID; i++) {
		struct ieee80211_wepkey *k = &isc->isc_nw_keys[i];
		if (k->iwk_len == 0)
			ATH_HAL_KEYRESET(ah, i);
		else {
			HAL_KEYVAL hk;

#ifdef DEBUG
			char tmp[200], stmp[10];
			int j;
			bzero(tmp, 200);
			bzero(stmp, 10);
			for (j = 0; j < k->iwk_len; j++) {
				(void) sprintf(stmp, "0x%02x ", k->iwk_key[j]);
				(void) strcat(tmp, stmp);
			}
			ATH_DEBUG((ATH_DBG_AUX, "ath: ath_initkeytable(): "
			    "key%d val=%s\n", i, tmp));
#endif /* DEBUG */
			bzero(&hk, sizeof (hk));
			hk.kv_type = HAL_CIPHER_WEP;
			hk.kv_len = k->iwk_len;
			bcopy(k->iwk_key, hk.kv_val, k->iwk_len);
			ATH_HAL_KEYSET(ah, i, &hk);
		}
	}
}

void
ath_reset(ath_t *asc)
{
	ieee80211com_t *isc = (ieee80211com_t *)asc;
	struct ath_hal *ah = asc->asc_ah;
	struct ieee80211channel *ch;
	HAL_STATUS status;
	HAL_CHANNEL hchan;

	/*
	 * Convert to a HAL channel description with the flags
	 * constrained to reflect the current operating mode.
	 */
	ch = isc->isc_ibss_chan;
	hchan.channel = ch->ich_freq;
	hchan.channelFlags = ath_chan2flags(isc, ch);

	ATH_HAL_INTRSET(ah, 0);		/* disable interrupts */
	ath_draintxq(asc);		/* stop xmit side */
	if (asc->asc_invalid == 0)
		ath_stoprecv(asc);		/* stop recv side */
	/* indicate channel change so we do a full reset */
	if (!ATH_HAL_RESET(ah, (HAL_OPMODE)isc->isc_opmode, &hchan,
	    AH_TRUE, &status)) {
		ath_problem("ath: ath_reset(): "
		    "reseting hardware failed, HAL status %u\n", status);
	}
	if (asc->asc_invalid == 0) {
		ath_initkeytable(asc);
		if (ath_startrecv(asc) != 0)	/* restart recv */
			ath_problem("ath: ath_reset(): "
			    "starting receiving logic failed\n");
		if (isc->isc_state == IEEE80211_S_RUN) {
			ath_beacon_config(asc);	/* restart beacons */
		}
		ATH_HAL_INTRSET(ah, asc->asc_imask);
	}
}
