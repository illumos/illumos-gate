/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
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

static const char *acnames[] = {
	"WME_AC_BE",
	"WME_AC_BK",
	"WME_AC_VI",
	"WME_AC_VO",
	"WME_UPSD"
};

extern void ath_setup_desc(ath_t *asc, struct ath_buf *bf);


const char *
ath_get_hal_status_desc(HAL_STATUS status)
{
	static const char *hal_status_desc[] = {
	    "No error",
	    "No hardware present or device not yet supported",
	    "Memory allocation failed",
	    "Hardware didn't respond as expected",
	    "EEPROM magic number invalid",
	    "EEPROM version invalid",
	    "EEPROM unreadable",
	    "EEPROM checksum invalid",
	    "EEPROM read problem",
	    "EEPROM mac address invalid",
	    "EEPROM size not supported",
	    "Attempt to change write-locked EEPROM",
	    "Invalid parameter to function",
	    "Hardware revision not supported",
	    "Hardware self-test failed",
	    "Operation incomplete"
	};

	if (status >= 0 && status < sizeof (hal_status_desc)/sizeof (char *))
		return (hal_status_desc[status]);
	else
		return ("");
}

uint32_t
ath_calcrxfilter(ath_t *asc)
{
	ieee80211com_t *ic = (ieee80211com_t *)asc;
	struct ath_hal *ah = asc->asc_ah;
	uint32_t rfilt;

	rfilt = (ATH_HAL_GETRXFILTER(ah) & HAL_RX_FILTER_PHYERR)
	    | HAL_RX_FILTER_UCAST | HAL_RX_FILTER_BCAST | HAL_RX_FILTER_MCAST;
	if (ic->ic_opmode != IEEE80211_M_STA)
		rfilt |= HAL_RX_FILTER_PROBEREQ;
	if (ic->ic_opmode != IEEE80211_M_HOSTAP && asc->asc_promisc)
		rfilt |= HAL_RX_FILTER_PROM;	/* promiscuous */
	if (ic->ic_opmode == IEEE80211_M_STA ||
	    ic->ic_opmode == IEEE80211_M_IBSS ||
	    ic->ic_state == IEEE80211_S_SCAN)
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
	qi.tqi_qflags = HAL_TXQ_TXEOLINT_ENABLE | HAL_TXQ_TXDESCINT_ENABLE;
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
ath_txq_cleanup(ath_t *asc)
{
	int i;

	mutex_destroy(&asc->asc_txbuflock);
	for (i = 0; i < HAL_NUM_TX_QUEUES; i++) {
		if (ATH_TXQ_SETUP(asc, i)) {
			struct ath_txq *txq = &asc->asc_txq[i];

			ATH_HAL_RELEASETXQUEUE(asc->asc_ah, txq->axq_qnum);
			mutex_destroy(&txq->axq_lock);
			asc->asc_txqsetup &= ~(1 << txq->axq_qnum);
		}
	}
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
		asc->asc_rixmap[rt->info[i].dot11Rate & IEEE80211_RATE_VAL] =
		    (uint8_t)i;

	asc->asc_currates = rt;
	asc->asc_curmode = mode;

	/*
	 * All protection frames are transmitted at 2Mb/s for
	 * 11g, otherwise at 1Mb/s.
	 * select protection rate index from rate table.
	 */
	asc->asc_protrix = (mode == IEEE80211_MODE_11G ? 1 : 0);
}

/* Set correct parameters for a certain mode */
void
ath_mode_init(ath_t *asc)
{
	ieee80211com_t *ic = (ieee80211com_t *)asc;
	struct ath_hal *ah = asc->asc_ah;
	uint32_t rfilt;

	/* configure rx filter */
	rfilt = ath_calcrxfilter(asc);
	ATH_HAL_SETRXFILTER(ah, rfilt);
	ATH_HAL_SETOPMODE(ah);
	ATH_HAL_SETMCASTFILTER(ah, asc->asc_mcast_hash[0],
	    asc->asc_mcast_hash[1]);
	ATH_DEBUG((ATH_DBG_AUX, "ath: ath_mode_init(): "
	    "mode =%d RX filter 0x%x, MC filter %08x:%08x\n",
	    ic->ic_opmode, rfilt,
	    asc->asc_mcast_hash[0], asc->asc_mcast_hash[1]));
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
ath_chan2flags(ieee80211com_t *isc, struct ieee80211_channel *chan)
{
	static const uint32_t modeflags[] = {
	    0,				/* IEEE80211_MODE_AUTO */
	    CHANNEL_A,			/* IEEE80211_MODE_11A */
	    CHANNEL_B,			/* IEEE80211_MODE_11B */
	    CHANNEL_PUREG,		/* IEEE80211_MODE_11G */
	    0,				/* IEEE80211_MODE_FH */
	    CHANNEL_108A,		/* IEEE80211_MODE_TURBO_A */
	    CHANNEL_108G		/* IEEE80211_MODE_TURBO_G */
	};
	return (modeflags[ieee80211_chan2mode(isc, chan)]);
}


int
ath_getchannels(ath_t *asc, uint32_t cc, HAL_BOOL outdoor, HAL_BOOL xchanmode)
{
	ieee80211com_t *ic = (ieee80211com_t *)asc;
	struct ath_hal *ah = asc->asc_ah;
	HAL_CHANNEL *chans;
	int i, ix;
	uint32_t nchan;

	chans = (HAL_CHANNEL *)
	    kmem_zalloc(IEEE80211_CHAN_MAX * sizeof (HAL_CHANNEL), KM_SLEEP);

	if (!ath_hal_init_channels(ah, chans, IEEE80211_CHAN_MAX, &nchan,
	    NULL, 0, NULL, cc, HAL_MODE_ALL, outdoor, xchanmode)) {
		ATH_DEBUG((ATH_DBG_AUX, "ath: ath_getchannels(): "
		    "unable to get channel list\n"));
		kmem_free(chans, IEEE80211_CHAN_MAX * sizeof (HAL_CHANNEL));
		return (EINVAL);
	}

	/*
	 * Convert HAL channels to ieee80211 ones and insert
	 * them in the table according to their channel number.
	 */
	for (i = 0; i < nchan; i++) {
		HAL_CHANNEL *c = &chans[i];
		uint16_t flags;
		ix = ath_hal_mhz2ieee(ah, c->channel, c->channelFlags);
		if (ix > IEEE80211_CHAN_MAX) {
			ATH_DEBUG((ATH_DBG_AUX, "ath: ath_getchannels(): "
			    "bad hal channel %d (%u/%x) ignored\n",
			    ix, c->channel, c->channelFlags));
			continue;
		}
		/* NB: flags are known to be compatible */
		if (ix < 0) {
			/*
			 * can't handle frequency <2400MHz (negative
			 * channels) right now
			 */
			ATH_DEBUG((ATH_DBG_AUX, "ath:ath_getchannels(): "
			    "hal channel %d (%u/%x) "
			    "cannot be handled, ignored\n",
			    ix, c->channel, c->channelFlags));
			continue;
		}
		/*
		 * Calculate net80211 flags; most are compatible
		 * but some need massaging.  Note the static turbo
		 * conversion can be removed once net80211 is updated
		 * to understand static vs. dynamic turbo.
		 */
		flags = c->channelFlags & CHANNEL_COMPAT;
		if (c->channelFlags & CHANNEL_STURBO)
			flags |= IEEE80211_CHAN_TURBO;
		if (ic->ic_sup_channels[ix].ich_freq == 0) {
			ic->ic_sup_channels[ix].ich_freq = c->channel;
			ic->ic_sup_channels[ix].ich_flags = flags;
		} else {
			/* channels overlap; e.g. 11g and 11b */
			ic->ic_sup_channels[ix].ich_flags |= flags;
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
 * Update internal state after a channel change.
 */
void
ath_chan_change(ath_t *asc, struct ieee80211_channel *chan)
{
	struct ieee80211com *ic = &asc->asc_isc;
	enum ieee80211_phymode mode;

	/*
	 * Change channels and update the h/w rate map
	 * if we're switching; e.g. 11a to 11b/g.
	 */
	mode = ieee80211_chan2mode(ic, chan);
	if (mode != asc->asc_curmode)
		ath_setcurmode(asc, mode);
}

/*
 * Set/change channels.  If the channel is really being changed,
 * it's done by resetting the chip.  To accomplish this we must
 * first cleanup any pending DMA.
 */
int
ath_chan_set(ath_t *asc, struct ieee80211_channel *chan)
{
	struct ath_hal *ah = asc->asc_ah;
	ieee80211com_t *ic = &asc->asc_isc;

	if (chan != ic->ic_ibss_chan) {
		HAL_STATUS status;
		HAL_CHANNEL hchan;

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
		hchan.channelFlags = ath_chan2flags(ic, chan);
		if (!ATH_HAL_RESET(ah, (HAL_OPMODE)ic->ic_opmode,
		    &hchan, AH_TRUE, &status)) {
			ATH_DEBUG((ATH_DBG_AUX, "ath: ath_chan_set():"
			    "unable to reset channel %u (%uMhz)\n"
			    "flags 0x%x: '%s' (HAL status %u)\n",
			    ieee80211_chan2ieee(ic, chan), hchan.channel,
			    hchan.channelFlags,
			    ath_get_hal_status_desc(status), status));
			return (EIO);
		}
		asc->asc_curchan = hchan;

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
		ic->ic_ibss_chan = chan;
		ath_chan_change(asc, chan);
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
	ieee80211com_t *ic = (ieee80211com_t *)asc;
	struct ieee80211_node *in = ic->ic_bss;
	uint32_t nexttbtt;

	/* extract tstamp from last beacon and convert to TU */
	nexttbtt = (ATH_LE_READ_4(in->in_tstamp.data + 4) << 22) |
	    (ATH_LE_READ_4(in->in_tstamp.data) >> 10);
	nexttbtt += in->in_intval;
	if (ic->ic_opmode != IEEE80211_M_HOSTAP) {
		HAL_BEACON_STATE bs;

		/* NB: no PCF support right now */
		bzero(&bs, sizeof (bs));
		bs.bs_intval = in->in_intval;
		bs.bs_nexttbtt = nexttbtt;
		bs.bs_dtimperiod = bs.bs_intval;
		bs.bs_nextdtim = nexttbtt;

		/*
		 * Setup the number of consecutive beacons to miss
		 * before taking a BMISS interrupt.
		 * Note that we clamp the result to at most 10 beacons.
		 */
		bs.bs_bmissthreshold = ic->ic_bmissthreshold;
		if (bs.bs_bmissthreshold > 10)
			bs.bs_bmissthreshold = 10;
		else if (bs.bs_bmissthreshold < 1)
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
 * Allocate tx/rx key slots for TKIP.  We allocate one slot for
 * each key. MIC is right after the decrypt/encrypt key.
 */
static uint16_t
key_alloc_pair(ath_t *asc, ieee80211_keyix *txkeyix,
    ieee80211_keyix *rxkeyix)
{
	uint16_t i, keyix;

	ASSERT(!asc->asc_splitmic);
	for (i = 0; i < ATH_N(asc->asc_keymap)/4; i++) {
		uint8_t b = asc->asc_keymap[i];
		if (b == 0xff)
			continue;
		for (keyix = i * NBBY; keyix < (i + 1) * NBBY;
		    keyix++, b >>= 1) {
			if ((b & 1) || isset(asc->asc_keymap, keyix+64)) {
				/* full pair unavailable */
				continue;
			}
			setbit(asc->asc_keymap, keyix);
			setbit(asc->asc_keymap, keyix+64);
			ATH_DEBUG((ATH_DBG_AUX,
			    "key_alloc_pair: key pair %u,%u\n",
			    keyix, keyix+64));
			*txkeyix = *rxkeyix = keyix;
			return (1);
		}
	}
	ATH_DEBUG((ATH_DBG_AUX, "key_alloc_pair:"
	    " out of pair space\n"));
	return (0);
}

/*
 * Allocate tx/rx key slots for TKIP.  We allocate two slots for
 * each key, one for decrypt/encrypt and the other for the MIC.
 */
static int
key_alloc_2pair(ath_t *asc, ieee80211_keyix *txkeyix, ieee80211_keyix *rxkeyix)
{
	uint16_t i, keyix;

	ASSERT(asc->asc_splitmic);
	for (i = 0; i < ATH_N(asc->asc_keymap)/4; i++) {
		uint8_t b = asc->asc_keymap[i];
		if (b != 0xff) {
			/*
			 * One or more slots in this byte are free.
			 */
			keyix = i*NBBY;
			while (b & 1) {
		again:
				keyix++;
				b >>= 1;
			}
			/* XXX IEEE80211_KEY_XMIT | IEEE80211_KEY_RECV */
			if (isset(asc->asc_keymap, keyix+32) ||
			    isset(asc->asc_keymap, keyix+64) ||
			    isset(asc->asc_keymap, keyix+32+64)) {
				/* full pair unavailable */
				if (keyix == (i+1)*NBBY) {
					/* no slots were appropriate, advance */
					continue;
				}
				goto again;
			}
			setbit(asc->asc_keymap, keyix);
			setbit(asc->asc_keymap, keyix+64);
			setbit(asc->asc_keymap, keyix+32);
			setbit(asc->asc_keymap, keyix+32+64);
			ATH_DEBUG((ATH_DBG_AUX,
			    "key_alloc_2pair: key pair %u,%u %u,%u\n",
			    keyix, keyix+64,
			    keyix+32, keyix+32+64));
			*txkeyix = *rxkeyix = keyix;
			return (1);
		}
	}
	ATH_DEBUG((ATH_DBG_AUX, "key_alloc_2pair:"
	    " out of pair space\n"));
	return (0);
}
/*
 * Allocate a single key cache slot.
 */
static int
key_alloc_single(ath_t *asc, ieee80211_keyix *txkeyix, ieee80211_keyix *rxkeyix)
{
	uint16_t i, keyix;

	/* try i,i+32,i+64,i+32+64 to minimize key pair conflicts */
	for (i = 0; i < ATH_N(asc->asc_keymap); i++) {
		uint8_t b = asc->asc_keymap[i];

		if (b != 0xff) {
			/*
			 * One or more slots are free.
			 */
			keyix = i*NBBY;
			while (b & 1)
				keyix++, b >>= 1;
			setbit(asc->asc_keymap, keyix);
			ATH_DEBUG((ATH_DBG_AUX, "key_alloc_single:"
			    " key %u\n", keyix));
			*txkeyix = *rxkeyix = keyix;
			return (1);
		}
	}
	return (0);
}

/*
 * Allocate one or more key cache slots for a unicast key.  The
 * key itself is needed only to identify the cipher.  For hardware
 * TKIP with split cipher+MIC keys we allocate two key cache slot
 * pairs so that we can setup separate TX and RX MIC keys.  Note
 * that the MIC key for a TKIP key at slot i is assumed by the
 * hardware to be at slot i+64.  This limits TKIP keys to the first
 * 64 entries.
 */
/* ARGSUSED */
int
ath_key_alloc(ieee80211com_t *ic, const struct ieee80211_key *k,
    ieee80211_keyix *keyix, ieee80211_keyix *rxkeyix)
{
	ath_t *asc = (ath_t *)ic;

	/*
	 * We allocate two pair for TKIP when using the h/w to do
	 * the MIC.  For everything else, including software crypto,
	 * we allocate a single entry.  Note that s/w crypto requires
	 * a pass-through slot on the 5211 and 5212.  The 5210 does
	 * not support pass-through cache entries and we map all
	 * those requests to slot 0.
	 */
	if (k->wk_flags & IEEE80211_KEY_SWCRYPT) {
		return (key_alloc_single(asc, keyix, rxkeyix));
	} else if (k->wk_cipher->ic_cipher == IEEE80211_CIPHER_TKIP &&
	    (k->wk_flags & IEEE80211_KEY_SWMIC) == 0) {
		if (asc->asc_splitmic)
			return (key_alloc_2pair(asc, keyix, rxkeyix));
		else
			return (key_alloc_pair(asc, keyix, rxkeyix));
	} else {
		return (key_alloc_single(asc, keyix, rxkeyix));
	}
}

/*
 * Delete an entry in the key cache allocated by ath_key_alloc.
 */
int
ath_key_delete(ieee80211com_t *ic, const struct ieee80211_key *k)
{
	ath_t *asc = (ath_t *)ic;
	struct ath_hal *ah = asc->asc_ah;
	const struct ieee80211_cipher *cip = k->wk_cipher;
	ieee80211_keyix keyix = k->wk_keyix;

	ATH_DEBUG((ATH_DBG_AUX, "ath_key_delete:"
	    " delete key %u ic_cipher=0x%x\n", keyix, cip->ic_cipher));

	ATH_HAL_KEYRESET(ah, keyix);
	/*
	 * Handle split tx/rx keying required for TKIP with h/w MIC.
	 */
	if (cip->ic_cipher == IEEE80211_CIPHER_TKIP &&
	    (k->wk_flags & IEEE80211_KEY_SWMIC) == 0 && asc->asc_splitmic)
		ATH_HAL_KEYRESET(ah, keyix+32);		/* RX key */

	if (keyix >= IEEE80211_WEP_NKID) {
		/*
		 * Don't touch keymap entries for global keys so
		 * they are never considered for dynamic allocation.
		 */
		clrbit(asc->asc_keymap, keyix);
		if (cip->ic_cipher == IEEE80211_CIPHER_TKIP &&
		    (k->wk_flags & IEEE80211_KEY_SWMIC) == 0) {
			/*
			 * If splitmic is true +64 is TX key MIC,
			 * else +64 is RX key + RX key MIC.
			 */
			clrbit(asc->asc_keymap, keyix+64);
			if (asc->asc_splitmic) {
				/* Rx key */
				clrbit(asc->asc_keymap, keyix+32);
				/* RX key MIC */
				clrbit(asc->asc_keymap, keyix+32+64);
			}
		}
	}
	return (1);
}

static void
ath_keyprint(ath_t *asc, const char *tag, uint_t ix,
    const HAL_KEYVAL *hk, const uint8_t mac[IEEE80211_ADDR_LEN])
{
	static const char *ciphers[] = {
		"WEP",
		"AES-OCB",
		"AES-CCM",
		"CKIP",
		"TKIP",
		"CLR",
	};
	int i, n;
	char buf[MAX_IEEE80211STR], buft[32];

	(void) snprintf(buf, sizeof (buf), "%s: [%02u] %s ",
	    tag, ix, ciphers[hk->kv_type]);
	for (i = 0, n = hk->kv_len; i < n; i++) {
		(void) snprintf(buft, sizeof (buft), "%02x", hk->kv_val[i]);
		(void) strlcat(buf, buft, sizeof (buf));
	}
	(void) snprintf(buft, sizeof (buft), " mac %s",
	    ieee80211_macaddr_sprintf(mac));
	(void) strlcat(buf, buft, sizeof (buf));
	if (hk->kv_type == HAL_CIPHER_TKIP) {
		(void) snprintf(buft, sizeof (buft), " %s ",
		    asc->asc_splitmic ? "mic" : "rxmic");
		(void) strlcat(buf, buft, sizeof (buf));
		for (i = 0; i < sizeof (hk->kv_mic); i++) {
			(void) snprintf(buft, sizeof (buft), "%02x",
			    hk->kv_mic[i]);
			(void) strlcat(buf, buft, sizeof (buf));
		}
		if (!asc->asc_splitmic) {
			(void) snprintf(buft, sizeof (buft), " txmic ");
			(void) strlcat(buf, buft, sizeof (buf));
			for (i = 0; i < sizeof (hk->kv_txmic); i++) {
				(void) snprintf(buft, sizeof (buft), "%02x",
				    hk->kv_txmic[i]);
				(void) strlcat(buf, buft, sizeof (buf));
			}
		}
	}
	ATH_DEBUG((ATH_DBG_AUX, "%s", buf));
}

/*
 * Set a TKIP key into the hardware.  This handles the
 * potential distribution of key state to multiple key
 * cache slots for TKIP.
 */
static int
ath_keyset_tkip(ath_t *asc, const struct ieee80211_key *k,
	HAL_KEYVAL *hk, const uint8_t mac[IEEE80211_ADDR_LEN])
{
#define	IEEE80211_KEY_XR	(IEEE80211_KEY_XMIT | IEEE80211_KEY_RECV)
	static const uint8_t zerobssid[IEEE80211_ADDR_LEN] = {0, 0, 0, 0, 0, 0};
	struct ath_hal *ah = asc->asc_ah;

	ASSERT(k->wk_cipher->ic_cipher == IEEE80211_CIPHER_TKIP);
	if ((k->wk_flags & IEEE80211_KEY_XR) == IEEE80211_KEY_XR) {
		if (asc->asc_splitmic) {
			/*
			 * TX key goes at first index, RX key at +32.
			 * The hal handles the MIC keys at index+64.
			 */
			(void) memcpy(hk->kv_mic, k->wk_txmic,
			    sizeof (hk->kv_mic));
			ath_keyprint(asc, "ath_keyset_tkip:", k->wk_keyix, hk,
			    zerobssid);
			if (!ATH_HAL_KEYSET(ah, k->wk_keyix, hk, zerobssid))
				return (0);

			(void) memcpy(hk->kv_mic, k->wk_rxmic,
			    sizeof (hk->kv_mic));
			ath_keyprint(asc, "ath_keyset_tkip:", k->wk_keyix+32,
			    hk, mac);
			return (ATH_HAL_KEYSET(ah, k->wk_keyix+32, hk, mac));
		} else {
			/*
			 * Room for both TX+RX MIC keys in one key cache
			 * slot, just set key at the first index; the hal
			 * will handle the reset.
			 */
			(void) memcpy(hk->kv_mic, k->wk_rxmic,
			    sizeof (hk->kv_mic));
			(void) memcpy(hk->kv_txmic, k->wk_txmic,
			    sizeof (hk->kv_txmic));
			ath_keyprint(asc, "ath_keyset_tkip", k->wk_keyix, hk,
			    mac);
			return (ATH_HAL_KEYSET(ah, k->wk_keyix, hk, mac));
		}
	} else if (k->wk_flags & IEEE80211_KEY_XR) {
		/*
		 * TX/RX key goes at first index.
		 * The hal handles the MIC keys are index+64.
		 */
		(void) memcpy(hk->kv_mic, k->wk_flags & IEEE80211_KEY_XMIT ?
		    k->wk_txmic : k->wk_rxmic, sizeof (hk->kv_mic));
		ath_keyprint(asc, "ath_keyset_tkip:", k->wk_keyix, hk,
		    zerobssid);
		return (ATH_HAL_KEYSET(ah, k->wk_keyix, hk, zerobssid));
	}
	return (0);
#undef IEEE80211_KEY_XR
}

/*
 * Set the key cache contents for the specified key.  Key cache
 * slot(s) must already have been allocated by ath_key_alloc.
 */
int
ath_key_set(ieee80211com_t *ic, const struct ieee80211_key *k,
    const uint8_t mac[IEEE80211_ADDR_LEN])
{
	static const uint8_t ciphermap[] = {
		HAL_CIPHER_WEP,		/* IEEE80211_CIPHER_WEP */
		HAL_CIPHER_TKIP,	/* IEEE80211_CIPHER_TKIP */
		HAL_CIPHER_AES_OCB,	/* IEEE80211_CIPHER_AES_OCB */
		HAL_CIPHER_AES_CCM,	/* IEEE80211_CIPHER_AES_CCM */
		HAL_CIPHER_CKIP,	/* IEEE80211_CIPHER_CKIP */
		HAL_CIPHER_CLR,		/* IEEE80211_CIPHER_NONE */
	};
	ath_t *asc = (ath_t *)ic;
	struct ath_hal *ah = asc->asc_ah;
	const struct ieee80211_cipher *cip = k->wk_cipher;
	HAL_KEYVAL hk;

	bzero(&hk, sizeof (hk));
	/*
	 * Software crypto uses a "clear key" so non-crypto
	 * state kept in the key cache are maintainedd so that
	 * rx frames have an entry to match.
	 */
	if ((k->wk_flags & IEEE80211_KEY_SWCRYPT) == 0) {
		ASSERT(cip->ic_cipher < ATH_N(ciphermap));
		hk.kv_type = ciphermap[cip->ic_cipher];
		hk.kv_len = k->wk_keylen;
		bcopy(k->wk_key, hk.kv_val, k->wk_keylen);
	} else {
		hk.kv_type = HAL_CIPHER_CLR;
	}

	if (hk.kv_type == HAL_CIPHER_TKIP &&
	    (k->wk_flags & IEEE80211_KEY_SWMIC) == 0) {
		return (ath_keyset_tkip(asc, k, &hk, mac));
	} else {
		ath_keyprint(asc, "ath_keyset:", k->wk_keyix, &hk, mac);
		return (ATH_HAL_KEYSET(ah, k->wk_keyix, &hk, mac));
	}
}

/*
 * Enable/Disable short slot timing
 */
void
ath_set_shortslot(ieee80211com_t *ic, int onoff)
{
	struct ath_hal *ah = ((ath_t *)ic)->asc_ah;

	if (onoff)
		ATH_HAL_SETSLOTTIME(ah, HAL_SLOT_TIME_9);
	else
		ATH_HAL_SETSLOTTIME(ah, HAL_SLOT_TIME_20);
}

int
ath_reset(ieee80211com_t *ic)
{
	ath_t *asc = (ath_t *)ic;
	struct ath_hal *ah = asc->asc_ah;
	struct ieee80211_channel *ch;
	HAL_STATUS status;

	/*
	 * Convert to a HAL channel description with the flags
	 * constrained to reflect the current operating mode.
	 */
	ch = ic->ic_curchan;
	asc->asc_curchan.channel = ch->ich_freq;
	asc->asc_curchan.channelFlags = ath_chan2flags(ic, ch);

	ATH_HAL_INTRSET(ah, 0);		/* disable interrupts */
	ath_draintxq(asc);		/* stop xmit side */
	if (ATH_IS_RUNNING(asc)) {
		ath_stoprecv(asc);		/* stop recv side */
		/* indicate channel change so we do a full reset */
		if (!ATH_HAL_RESET(ah, (HAL_OPMODE)ic->ic_opmode,
		    &asc->asc_curchan, AH_TRUE, &status)) {
			ath_problem("ath: ath_reset(): "
			    "resetting hardware failed, '%s' (HAL status %u)\n",
			    ath_get_hal_status_desc(status), status);
		}
		ath_chan_change(asc, ch);
	}
	if (ATH_IS_RUNNING(asc)) {
		if (ath_startrecv(asc) != 0)	/* restart recv */
			ath_problem("ath: ath_reset(): "
			    "starting receiving logic failed\n");
		if (ic->ic_state == IEEE80211_S_RUN) {
			ath_beacon_config(asc);	/* restart beacons */
		}
		ATH_HAL_INTRSET(ah, asc->asc_imask);
	}
	return (0);
}
