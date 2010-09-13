/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2003, 2004 David Young.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or
 * without modification, are permitted provided that the following
 * conditions are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials provided
 *    with the distribution.
 * 3. The name of David Young may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY David Young ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL David
 * Young BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/byteorder.h>
#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/modctl.h>
#include <sys/devops.h>
#include <sys/dlpi.h>
#include <sys/gld.h>
#include <sys/varargs.h>
#include <sys/pci.h>
#include <sys/net80211.h>

#include "ral_rate.h"

#define	MAX(a, b) ((a) > (b) ? (a) : (b))

#ifdef interpolate
#undef interpolate
#endif
#define	interpolate(parm, old, new)	\
	((parm##_old * (old) + \
	(parm##_denom - parm##_old) * (new)) /	\
	parm##_denom)

static struct ral_rssadapt_expavgctl master_expavgctl;

void
ral_rate_init(void)
{
	master_expavgctl.rc_decay_denom = 16;
	master_expavgctl.rc_decay_old = 15;
	master_expavgctl.rc_thresh_denom = 8;
	master_expavgctl.rc_thresh_old = 4;
	master_expavgctl.rc_avgrssi_denom = 8;
	master_expavgctl.rc_avgrssi_old = 4;
}

/* ARGSUSED */
int
ral_rssadapt_choose(struct ral_rssadapt *ra, struct ieee80211_rateset *rs,
    struct ieee80211_frame *wh, uint32_t len,
    const char *dvname, int do_not_adapt)
{
	uint16_t (*thrs)[IEEE80211_RATE_SIZE];
	int flags = 0, i, rateidx = 0, thridx, top;

	if ((wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) == IEEE80211_FC0_TYPE_CTL)
		flags |= IEEE80211_RATE_BASIC;

	for (i = 0, top = RAL_RSSADAPT_BKT0;
	    i < RAL_RSSADAPT_BKTS;
	    i++, top <<= RAL_RSSADAPT_BKTPOWER) {
		thridx = i;
		if (len <= top)
			break;
	}

	thrs = &ra->ra_rate_thresh[thridx];

	i = rs->ir_nrates;
	while (--i >= 0) {
		rateidx = i;
		if ((rs->ir_rates[i] & flags) != flags)
			continue;
		if (do_not_adapt)
			break;
		if ((*thrs)[i] < ra->ra_avg_rssi)
			break;
	}

	return (rateidx);
}

void
ral_rssadapt_updatestats(struct ral_rssadapt *ra)
{
	long interval;

	ra->ra_pktrate =
	    (ra->ra_pktrate + 10 * (ra->ra_nfail + ra->ra_nok)) / 2;
	ra->ra_nfail = ra->ra_nok = 0;

	/*
	 * a node is eligible for its rate to be raised every 1/10 to 10
	 * seconds, more eligible in proportion to recent packet rates.
	 */
	interval = MAX(100000, 10000000 / MAX(1, 10 * ra->ra_pktrate));
	ra->ra_raise_interval.tv_sec = interval / (1000 * 1000);
	ra->ra_raise_interval.tv_usec = interval % (1000 * 1000);
}

/* ARGSUSED */
void
ral_rssadapt_input(struct ieee80211com *ic, struct ieee80211_node *ni,
    struct ral_rssadapt *ra, int rssi)
{
	ra->ra_avg_rssi = interpolate(master_expavgctl.rc_avgrssi,
	    ra->ra_avg_rssi, (rssi << 8));
}

/*
 * Adapt the data rate to suit the conditions.  When a transmitted
 * packet is dropped after RAL_RSSADAPT_RETRY_LIMIT retransmissions,
 * raise the RSS threshold for transmitting packets of similar length at
 * the same data rate.
 */
/* ARGSUSED */
void
ral_rssadapt_lower_rate(struct ieee80211com *ic, struct ieee80211_node *ni,
    struct ral_rssadapt *ra, struct ral_rssdesc *id)
{
	struct ieee80211_rateset *rs = &ni->in_rates;
	uint16_t last_thr;
	uint32_t i, thridx, top;

	ra->ra_nfail++;

	if (id->id_rateidx >= rs->ir_nrates)
		return;

	for (i = 0, top = RAL_RSSADAPT_BKT0;
	    i < RAL_RSSADAPT_BKTS;
	    i++, top <<= RAL_RSSADAPT_BKTPOWER) {
		thridx = i;
		if (id->id_len <= top)
			break;
	}

	last_thr = ra->ra_rate_thresh[thridx][id->id_rateidx];
	ra->ra_rate_thresh[thridx][id->id_rateidx] =
	    interpolate(master_expavgctl.rc_thresh, last_thr,
	    (id->id_rssi << 8));
}

/* ARGSUSED */
void
ral_rssadapt_raise_rate(struct ieee80211com *ic, struct ral_rssadapt *ra,
    struct ral_rssdesc *id)
{
	uint16_t (*thrs)[IEEE80211_RATE_SIZE], newthr, oldthr;
	struct ieee80211_node *ni = id->id_node;
	struct ieee80211_rateset *rs = &ni->in_rates;
	int i, top;

	ra->ra_nok++;

	for (i = 0, top = RAL_RSSADAPT_BKT0;
	    i < RAL_RSSADAPT_BKTS;
	    i++, top <<= RAL_RSSADAPT_BKTPOWER) {
		thrs = &ra->ra_rate_thresh[i];
		if (id->id_len <= top)
			break;
	}

	if (id->id_rateidx + 1 < rs->ir_nrates &&
	    (*thrs)[id->id_rateidx + 1] > (*thrs)[id->id_rateidx]) {
		oldthr = (*thrs)[id->id_rateidx + 1];
		if ((*thrs)[id->id_rateidx] == 0)
			newthr = ra->ra_avg_rssi;
		else
			newthr = (*thrs)[id->id_rateidx];
		(*thrs)[id->id_rateidx + 1] =
		    interpolate(master_expavgctl.rc_decay, oldthr, newthr);
	}
}
