/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
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
 * IEEE 802.11 NULL crypto support.
 */
#include "net80211_impl.h"

static	void *none_attach(struct ieee80211com *, struct ieee80211_key *);
static	void none_detach(struct ieee80211_key *);
static	int none_setkey(struct ieee80211_key *);
static	int none_encap(struct ieee80211_key *, mblk_t *, uint8_t);
static	int none_decap(struct ieee80211_key *, mblk_t *, int);
static	int none_enmic(struct ieee80211_key *, mblk_t *, int);
static	int none_demic(struct ieee80211_key *, mblk_t *, int);

const struct ieee80211_cipher ieee80211_cipher_none = {
	"NONE",
	IEEE80211_CIPHER_NONE,
	0,
	0,
	0,
	none_attach,
	none_detach,
	none_setkey,
	none_encap,
	none_decap,
	none_enmic,
	none_demic,
};

/* ARGSUSED */
static void *
none_attach(struct ieee80211com *ic, struct ieee80211_key *k)
{
	return (ic);		/* for diagnostics+stats */
}

/* ARGSUSED */
static void
none_detach(struct ieee80211_key *k)
{
	/* noop */
}

/* ARGSUSED */
static int
none_setkey(struct ieee80211_key *k)
{
	return (1);
}

/* ARGSUSED */
static int
none_encap(struct ieee80211_key *k, mblk_t *mp, uint8_t keyid)
{
	/*
	 * The specified key is not setup; this can
	 * happen, at least, when changing keys.
	 */
	ieee80211_dbg(IEEE80211_MSG_CRYPTO, "none_encap: "
		"key id %u is not set (encap)\n", keyid >> 6);
	return (0);
}

/* ARGSUSED */
static int
none_decap(struct ieee80211_key *k, mblk_t *mp, int hdrlen)
{
	struct ieee80211_frame *wh = (struct ieee80211_frame *)mp->b_rptr;
	const uint8_t *ivp = (const uint8_t *)&wh[1];

	/*
	 * The specified key is not setup; this can
	 * happen, at least, when changing keys.
	 */
	ieee80211_dbg(IEEE80211_MSG_CRYPTO, "none_decap"
		"key id %u is not set (decap)\n",
		ivp[IEEE80211_WEP_IVLEN] >> 6);
	return (0);
}

/* ARGSUSED */
static int
none_enmic(struct ieee80211_key *k, mblk_t *mp, int force)
{
	return (0);
}

/* ARGSUSED */
static int
none_demic(struct ieee80211_key *k, mblk_t *mp, int force)
{
	return (0);
}
