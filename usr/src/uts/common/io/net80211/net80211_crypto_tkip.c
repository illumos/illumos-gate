/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2001 Atsushi Onoe
 * Copyright (c) 2002-2005 Sam Leffler, Errno Consulting
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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * IEEE 802.11i TKIP crypto support.
 */
#include <sys/byteorder.h>
#include <sys/crypto/common.h>
#include <sys/crypto/api.h>
#include <sys/crc32.h>
#include <sys/random.h>
#include "net80211_impl.h"

static void *tkip_attach(struct ieee80211com *, struct ieee80211_key *);
static void tkip_detach(struct ieee80211_key *);
static int tkip_setkey(struct ieee80211_key *);
static int tkip_encap(struct ieee80211_key *, mblk_t *, uint8_t);
static int tkip_decap(struct ieee80211_key *, mblk_t *, int);
static int tkip_enmic(struct ieee80211_key *, mblk_t *, int);
static int tkip_demic(struct ieee80211_key *, mblk_t *, int);

const struct ieee80211_cipher tkip  = {
	"TKIP",
	IEEE80211_CIPHER_TKIP,
	IEEE80211_WEP_IVLEN + IEEE80211_WEP_KIDLEN +
	    IEEE80211_WEP_EXTIVLEN,
	IEEE80211_WEP_CRCLEN,
	IEEE80211_WEP_MICLEN,
	tkip_attach,
	tkip_detach,
	tkip_setkey,
	tkip_encap,
	tkip_decap,
	tkip_enmic,
	tkip_demic,
};

struct tkip_ctx {
	struct ieee80211com	*tc_ic;		/* for diagnostics */
	uint16_t		tx_ttak[5];
	int			tx_phase1_done;
	uint8_t			tx_rc4key[16];
	uint16_t		rx_ttak[5];
	int			rx_phase1_done;
	uint8_t			rx_rc4key[16];
	uint64_t		rx_rsc;		/* held until MIC verified */
};

/* ARGSUSED */
static void *
tkip_attach(struct ieee80211com *ic, struct ieee80211_key *k)
{
	struct tkip_ctx *ctx;

	ctx = kmem_zalloc(sizeof (struct tkip_ctx), KM_SLEEP);
	if (ctx == NULL)
		return (NULL);

	ctx->tc_ic = ic;
	return (ctx);
}

static void
tkip_detach(struct ieee80211_key *k)
{
	struct tkip_ctx *ctx = k->wk_private;

	if (ctx != NULL)
		kmem_free(ctx, sizeof (struct tkip_ctx));
}

static int
tkip_setkey(struct ieee80211_key *k)
{
	if (k->wk_keylen != (128/NBBY))
		return (0);

	k->wk_keytsc = 1;		/* TSC starts at 1 */
	return (1);
}

/*
 * Add privacy headers appropriate for the specified key.
 */
static int
tkip_encap(struct ieee80211_key *k, mblk_t *mp, uint8_t keyid)
{
	struct tkip_ctx *ctx = k->wk_private;
	struct ieee80211com *ic = ctx->tc_ic;
	uint8_t *ivp;
	int hdrlen;

	/*
	 * Handle TKIP counter measures requirement.
	 */
	if (ic->ic_flags & IEEE80211_F_COUNTERM)
		return (0);

	hdrlen = ieee80211_hdrspace(mp->b_rptr);
	/*
	 * Copy down 802.11 header and add the IV, KeyID, and ExtIV.
	 */
	ivp = mp->b_rptr;
	ivp += hdrlen;

	ivp[0] = k->wk_keytsc >> 8;		/* TSC1 */
	ivp[1] = (ivp[0] | 0x20) & 0x7f;	/* WEP seed */
	ivp[2] = k->wk_keytsc >> 0;		/* TSC0 */
	ivp[3] = keyid | IEEE80211_WEP_EXTIV;	/* KeyID | ExtID */
	ivp[4] = k->wk_keytsc >> 16;		/* TSC2 */
	ivp[5] = k->wk_keytsc >> 24;		/* TSC3 */
	ivp[6] = k->wk_keytsc >> 32;		/* TSC4 */
	ivp[7] = k->wk_keytsc >> 40;		/* TSC5 */

	/*
	 * NB: software TKIP is not supported.
	 */
	if (k->wk_flags & IEEE80211_KEY_SWCRYPT)
		return (0);
	else
		k->wk_keytsc++;		/* wrap at 48 bits */

	return (1);
}

uint64_t
ieee80211_read_6(uint8_t b0, uint8_t b1, uint8_t b2,
    uint8_t b3, uint8_t b4, uint8_t b5)
{
	uint32_t iv32 = (b0 << 0) | (b1 << 8) | (b2 << 16) | (b3 << 24);
	uint16_t iv16 = (b4 << 0) | (b5 << 8);
	return ((((uint64_t)iv16) << 32) | iv32);
}

/*
 * Validate and strip privacy headers (and trailer) for a
 * received frame.  If necessary, decrypt the frame using
 * the specified key.
 */
static int
tkip_decap(struct ieee80211_key *k, mblk_t *mp, int hdrlen)
{
	struct tkip_ctx *ctx = k->wk_private;
	struct ieee80211com *ic = ctx->tc_ic;
	struct ieee80211_frame tmp;
	uint8_t *ivp;
	uint64_t pn;

	/*
	 * Header should have extended IV and sequence number;
	 * verify the former and validate the latter.
	 */
	ivp = mp->b_rptr + hdrlen;
	if ((ivp[IEEE80211_WEP_IVLEN] & IEEE80211_WEP_EXTIV) == 0) {
		/*
		 * No extended IV; discard frame.
		 */
		return (0);
	}
	/*
	 * Handle TKIP counter measures requirement.
	 */
	if (ic->ic_flags & IEEE80211_F_COUNTERM)
		return (0);

	/* NB: assume IEEEE80211_WEP_MINLEN covers the extended IV */
	pn = ieee80211_read_6(ivp[2], ivp[0], ivp[4], ivp[5], ivp[6], ivp[7]);
	ctx->rx_rsc = pn;
	if (ctx->rx_rsc <= k->wk_keyrsc)
		return (0);
	/*
	 * NB: We can't update the rsc in the key until MIC is verified.
	 *
	 * We assume we are not preempted between doing the check above
	 * and updating wk_keyrsc when stripping the MIC in tkip_demic.
	 * Otherwise we might process another packet and discard it as
	 * a replay.
	 */

	/*
	 * NB: software TKIP is not supported.
	 */
	if (k->wk_flags & IEEE80211_KEY_SWCRYPT)
		return (0);

	/*
	 * Copy up 802.11 header and strip crypto bits.
	 */
	bcopy(mp->b_rptr, &tmp, hdrlen);
	bcopy(&tmp, mp->b_rptr + tkip.ic_header, hdrlen);
	mp->b_rptr += tkip.ic_header;
	mp->b_wptr -= tkip.ic_trailer;

	return (1);
}

/*
 * Add MIC to the frame as needed.
 */
/* ARGSUSED */
static int
tkip_enmic(struct ieee80211_key *k, mblk_t *mp, int force)
{
	return (1);
}

/*
 * Verify and strip MIC from the frame.
 */
/* ARGSUSED */
static int
tkip_demic(struct ieee80211_key *k, mblk_t *mp, int force)
{
	struct tkip_ctx *ctx = k->wk_private;

	/*
	 * NB: software TKIP is not supported.
	 */
	if (k->wk_flags & IEEE80211_KEY_SWMIC)
		return (0);
	/*
	 * Strip MIC from the tail.
	 */
	mp->b_wptr -= tkip.ic_miclen;
	/*
	 * Ok to update rsc now that MIC has been verified.
	 */
	k->wk_keyrsc = ctx->rx_rsc;

	return (1);
}
