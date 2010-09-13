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
#include "ath_rate.h"

void
ath_rate_update(ath_t *asc, struct ieee80211_node *in, int32_t rate)
{
	struct ath_node *an = ATH_NODE(in);
	const HAL_RATE_TABLE *rt = asc->asc_currates;
	uint8_t rix;

	ASSERT(rt != NULL);

	in->in_txrate = rate;

	/* management/control frames always go at the lowest speed */
	an->an_tx_mgtrate = rt->info[0].rateCode;
	an->an_tx_mgtratesp = an->an_tx_mgtrate | rt->info[0].shortPreamble;
	ATH_DEBUG((ATH_DBG_RATE, "ath: ath_rate_update(): "
	    "mgtrate=%d mgtratesp=%d\n",
	    an->an_tx_mgtrate, an->an_tx_mgtratesp));
	/*
	 * Before associating a node has no rate set setup
	 * so we can't calculate any transmit codes to use.
	 * This is ok since we should never be sending anything
	 * but management frames and those always go at the
	 * lowest hardware rate.
	 */
	if (in->in_rates.ir_nrates == 0)
		goto done;
	an->an_tx_rix0 = asc->asc_rixmap[
	    in->in_rates.ir_rates[rate] & IEEE80211_RATE_VAL];
	an->an_tx_rate0 = rt->info[an->an_tx_rix0].rateCode;
	an->an_tx_rate0sp = an->an_tx_rate0 |
	    rt->info[an->an_tx_rix0].shortPreamble;
	if (asc->asc_mrretry) {
		/*
		 * Hardware supports multi-rate retry; setup two
		 * step-down retry rates and make the lowest rate
		 * be the ``last chance''.  We use 4, 2, 2, 2 tries
		 * respectively (4 is set here, the rest are fixed
		 * in the xmit routine).
		 */
		an->an_tx_try0 = 1 + 3;		/* 4 tries at rate 0 */
		if (--rate >= 0) {
			rix = asc->asc_rixmap[
			    in->in_rates.ir_rates[rate]&IEEE80211_RATE_VAL];
			an->an_tx_rate1 = rt->info[rix].rateCode;
			an->an_tx_rate1sp = an->an_tx_rate1 |
			    rt->info[rix].shortPreamble;
		} else {
			an->an_tx_rate1 = an->an_tx_rate1sp = 0;
		}
		if (--rate >= 0) {
			rix = asc->asc_rixmap[
			    in->in_rates.ir_rates[rate]&IEEE80211_RATE_VAL];
			an->an_tx_rate2 = rt->info[rix].rateCode;
			an->an_tx_rate2sp = an->an_tx_rate2 |
			    rt->info[rix].shortPreamble;
		} else {
			an->an_tx_rate2 = an->an_tx_rate2sp = 0;
		}
		if (rate > 0) {
			an->an_tx_rate3 = rt->info[0].rateCode;
			an->an_tx_rate3sp =
			    an->an_tx_mgtrate | rt->info[0].shortPreamble;
		} else {
			an->an_tx_rate3 = an->an_tx_rate3sp = 0;
		}
	} else {
		an->an_tx_try0 = ATH_TXMAXTRY;  /* max tries at rate 0 */
		an->an_tx_rate1 = an->an_tx_rate1sp = 0;
		an->an_tx_rate2 = an->an_tx_rate2sp = 0;
		an->an_tx_rate3 = an->an_tx_rate3sp = 0;
	}
done:
	an->an_tx_ok = an->an_tx_err = an->an_tx_retr = an->an_tx_upper = 0;
}


/*
 * Set the starting transmit rate for a node.
 */
void
ath_rate_ctl_start(ath_t *asc, struct ieee80211_node *in)
{
	ieee80211com_t *ic = (ieee80211com_t *)asc;
	int32_t srate;

	if (ic->ic_fixed_rate == IEEE80211_FIXED_RATE_NONE) {
		/*
		 * No fixed rate is requested. For 11b start with
		 * the highest negotiated rate; otherwise, for 11g
		 * and 11a, we start "in the middle" at 24Mb or 36Mb.
		 */
		srate = in->in_rates.ir_nrates - 1;
		if (asc->asc_curmode != IEEE80211_MODE_11B) {
			/*
			 * Scan the negotiated rate set to find the
			 * closest rate.
			 */
			/* NB: the rate set is assumed sorted */
			for (; srate >= 0 && IEEE80211_RATE(srate) > 72;
			    srate--) {}
		}
	} else {
		/*
		 * A fixed rate is to be used; We know the rate is
		 * there because the rate set is checked when the
		 * station associates.
		 */
		/* NB: the rate set is assumed sorted */
		srate = in->in_rates.ir_nrates - 1;
		for (; srate >= 0 && IEEE80211_RATE(srate) != ic->ic_fixed_rate;
		    srate--) {}
	}
	ATH_DEBUG((ATH_DBG_RATE, "ath: ath_rate_ctl_start(): "
	    "srate=%d rate=%d\n", srate, IEEE80211_RATE(srate)));
	ath_rate_update(asc, in, srate);
}

void
ath_rate_cb(void *arg, struct ieee80211_node *in)
{
	ath_rate_update((ath_t *)arg, in, 0);
}

/*
 * Reset the rate control state for each 802.11 state transition.
 */
void
ath_rate_ctl_reset(ath_t *asc, enum ieee80211_state state)
{
	ieee80211com_t *ic = (ieee80211com_t *)asc;
	struct ieee80211_node *in;

	if (ic->ic_opmode == IEEE80211_M_STA) {
		/*
		 * Reset local xmit state; this is really only
		 * meaningful when operating in station mode.
		 */
		in = (struct ieee80211_node *)ic->ic_bss;
		if (state == IEEE80211_S_RUN) {
			ath_rate_ctl_start(asc, in);
		} else {
			ath_rate_update(asc, in, 0);
		}
	} else {
		/*
		 * When operating as a station the node table holds
		 * the AP's that were discovered during scanning.
		 * For any other operating mode we want to reset the
		 * tx rate state of each node.
		 */
		ieee80211_iterate_nodes(&ic->ic_sta, ath_rate_cb, asc);
		ath_rate_update(asc, ic->ic_bss, 0);
	}
}


/*
 * Examine and potentially adjust the transmit rate.
 */
void
ath_rate_ctl(void *arg, struct ieee80211_node *in)
{
	ath_t *asc = arg;
	struct ath_node *an = ATH_NODE(in);
	struct ieee80211_rateset *rs = &in->in_rates;
	int32_t mod = 0, nrate, enough;

	/*
	 * Rate control(very primitive version).
	 */
	asc->asc_stats.ast_rate_calls++;

	enough = (an->an_tx_ok + an->an_tx_err >= 10);

	/* no packet reached -> down */
	if (an->an_tx_err > 0 && an->an_tx_ok == 0)
		mod = -1;

	/* all packets needs retry in average -> down */
	if (enough && an->an_tx_ok < an->an_tx_retr)
		mod = -1;

	/* no error and less than 10% of packets needs retry -> up */
	if (enough && an->an_tx_err == 0 && an->an_tx_ok > an->an_tx_retr * 10)
		mod = 1;

	nrate = in->in_txrate;
	switch (mod) {
	case 0:
		if (enough && an->an_tx_upper > 0)
			an->an_tx_upper--;
		break;
	case -1:
		if (nrate > 0) {
			nrate--;
			asc->asc_stats.ast_rate_drop++;
		}
		an->an_tx_upper = 0;
		break;
	case 1:
		if (++an->an_tx_upper < 10)
			break;
		an->an_tx_upper = 0;
		if (nrate + 1 < rs->ir_nrates) {
			nrate++;
			asc->asc_stats.ast_rate_raise++;
		}
		break;
	}

	if (nrate != in->in_txrate) {
		ATH_DEBUG((ATH_DBG_RATE, "ath: ath_rate_ctl(): %dM -> %dM "
		    "(%d ok, %d err, %d retr)\n",
		    (rs->ir_rates[in->in_txrate] & IEEE80211_RATE_VAL) / 2,
		    (rs->ir_rates[nrate] & IEEE80211_RATE_VAL) / 2,
		    an->an_tx_ok, an->an_tx_err, an->an_tx_retr));
		ath_rate_update(asc, in, nrate);
	} else if (enough)
		an->an_tx_ok = an->an_tx_err = an->an_tx_retr = 0;
}


/*
 * Read rate table from the HAL, and then
 * copy the table to the driver's data structure.
 */
void
ath_rate_setup(ath_t *asc, uint32_t mode)
{
	int32_t i;
	uint8_t maxrates;
	struct ieee80211_rateset *rs;
	struct ath_hal *ah = asc->asc_ah;
	ieee80211com_t *ic = (ieee80211com_t *)asc;
	const HAL_RATE_TABLE *rt;

	switch (mode) {
	case IEEE80211_MODE_11A:
		asc->asc_rates[mode] = ATH_HAL_GETRATETABLE(ah, HAL_MODE_11A);
		break;
	case IEEE80211_MODE_11B:
		asc->asc_rates[mode] = ATH_HAL_GETRATETABLE(ah, HAL_MODE_11B);
		break;
	case IEEE80211_MODE_11G:
		asc->asc_rates[mode] = ATH_HAL_GETRATETABLE(ah, HAL_MODE_11G);
		break;
	case IEEE80211_MODE_TURBO_A:
		asc->asc_rates[mode] = ATH_HAL_GETRATETABLE(ah, HAL_MODE_TURBO);
		break;
	case IEEE80211_MODE_TURBO_G:
		asc->asc_rates[mode] = ATH_HAL_GETRATETABLE(ah, HAL_MODE_108G);
		break;
	default:
		ATH_DEBUG((ATH_DBG_RATE, "ath: ath_rate_setup(): "
		    "invalid mode %u\n", mode));
		return;
	}

	rt = asc->asc_rates[mode];
	if (rt == NULL)
		return;
	if (rt->rateCount > IEEE80211_RATE_MAXSIZE) {
		ATH_DEBUG((ATH_DBG_RATE, "ath: ath_rate_setup(): "
		    "rate table too small (%u > %u)\n",
		    rt->rateCount, IEEE80211_RATE_MAXSIZE));
		maxrates = IEEE80211_RATE_MAXSIZE;
	} else
		maxrates = rt->rateCount;
	rs = &ic->ic_sup_rates[mode];
	for (i = 0; i < maxrates; i++)
		rs->ir_rates[i] = rt->info[i].dot11Rate;
	rs->ir_nrates = maxrates;
}
