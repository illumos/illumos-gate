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
 * IEEE 802.11i CCMP crypto support.
 */
#include <sys/byteorder.h>
#include <sys/crypto/common.h>
#include <sys/crypto/api.h>
#include <sys/crc32.h>
#include <sys/random.h>
#include "net80211_impl.h"

struct ccmp_ctx {
	struct ieee80211com *cc_ic;	/* for diagnostics */
};

static void *ccmp_attach(struct ieee80211com *, struct ieee80211_key *);
static void ccmp_detach(struct ieee80211_key *);
static int ccmp_setkey(struct ieee80211_key *);
static int ccmp_encap(struct ieee80211_key *k, mblk_t *, uint8_t);
static int ccmp_decap(struct ieee80211_key *, mblk_t *, int);
static int ccmp_enmic(struct ieee80211_key *, mblk_t *, int);
static int ccmp_demic(struct ieee80211_key *, mblk_t *, int);

const struct ieee80211_cipher ccmp = {
	"AES-CCM",
	IEEE80211_CIPHER_AES_CCM,
	IEEE80211_WEP_IVLEN + IEEE80211_WEP_KIDLEN +
	    IEEE80211_WEP_EXTIVLEN,
	IEEE80211_WEP_MICLEN,
	0,
	ccmp_attach,
	ccmp_detach,
	ccmp_setkey,
	ccmp_encap,
	ccmp_decap,
	ccmp_enmic,
	ccmp_demic,
};

/* ARGSUSED */
static void *
ccmp_attach(struct ieee80211com *ic, struct ieee80211_key *k)
{
	struct ccmp_ctx *ctx;

	ctx = kmem_zalloc(sizeof (struct ccmp_ctx), KM_SLEEP);
	if (ctx == NULL)
		return (NULL);

	ctx->cc_ic = ic;
	return (ctx);
}

static void
ccmp_detach(struct ieee80211_key *k)
{
	struct ccmp_ctx *ctx = k->wk_private;

	if (ctx != NULL)
		kmem_free(ctx, sizeof (struct ccmp_ctx));
}

static int
ccmp_setkey(struct ieee80211_key *k)
{
	if (k->wk_keylen != (128/NBBY))
		return (0);

	return (1);
}

/*
 * Add privacy headers appropriate for the specified key.
 */
static int
ccmp_encap(struct ieee80211_key *k, mblk_t *mp, uint8_t keyid)
{
	uint8_t *ivp;
	int hdrlen;

	hdrlen = ieee80211_hdrspace(mp->b_rptr);
	/*
	 * Copy down 802.11 header and add the IV, KeyID, and ExtIV.
	 */
	ivp = mp->b_rptr;
	ivp += hdrlen;

	k->wk_keytsc++;				/* wrap at 48 bits */
	ivp[0] = k->wk_keytsc >> 0;		/* PN0 */
	ivp[1] = k->wk_keytsc >> 8;		/* PN1 */
	ivp[2] = 0;				/* Reserved */
	ivp[3] = keyid | IEEE80211_WEP_EXTIV;	/* KeyID | ExtID */
	ivp[4] = k->wk_keytsc >> 16;		/* PN2 */
	ivp[5] = k->wk_keytsc >> 24;		/* PN3 */
	ivp[6] = k->wk_keytsc >> 32;		/* PN4 */
	ivp[7] = k->wk_keytsc >> 40;		/* PN5 */

	/*
	 * NB: software CCMP is not supported.
	 */
	if (k->wk_flags & IEEE80211_KEY_SWCRYPT)
		return (0);

	return (1);
}

/*
 * Validate and strip privacy headers (and trailer) for a
 * received frame. The specified key should be correct but
 * is also verified.
 */
static int
ccmp_decap(struct ieee80211_key *k, mblk_t *mp, int hdrlen)
{
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

	pn = ieee80211_read_6(ivp[0], ivp[1], ivp[4], ivp[5], ivp[6], ivp[7]);
	if (pn <= k->wk_keyrsc) {
		/*
		 * Replay violation.
		 */
		return (0);
	}

	/*
	 * NB: software CCMP is not supported.
	 */
	if (k->wk_flags & IEEE80211_KEY_SWCRYPT)
		return (0);

	/*
	 * Copy up 802.11 header and strip crypto bits.
	 */
	bcopy(mp->b_rptr, &tmp, hdrlen);
	bcopy(&tmp, mp->b_rptr + ccmp.ic_header, hdrlen);
	mp->b_rptr += ccmp.ic_header;
	mp->b_wptr -= ccmp.ic_trailer;

	/*
	 * Ok to update rsc now.
	 */
	k->wk_keyrsc = pn;

	return (1);
}

/*
 * Add MIC to the frame as needed.
 */
/* ARGSUSED */
static int
ccmp_enmic(struct ieee80211_key *k, mblk_t *mp, int force)
{
	return (1);
}

/*
 * Verify and strip MIC from the frame.
 */
/* ARGSUSED */
static int
ccmp_demic(struct ieee80211_key *k, mblk_t *mp, int force)
{
	return (1);
}
