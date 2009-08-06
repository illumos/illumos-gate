/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2001 Atsushi Onoe
 * Copyright (c) 2002-2008 Sam Leffler, Errno Consulting
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

/*
 * IEEE 802.11i TKIP crypto support.
 *
 * Part of this module is derived from similar code in the Host
 * AP driver. The code is used with the consent of the author and
 * it's license is included below.
 */

#include <sys/byteorder.h>
#include <sys/crypto/common.h>
#include <sys/crypto/api.h>
#include <sys/crc32.h>
#include <sys/random.h>
#include <sys/strsun.h>
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

static void michael_mic(struct tkip_ctx *, const uint8_t *,
    mblk_t *, uint_t, size_t, uint8_t[]);
static int tkip_encrypt(struct tkip_ctx *, struct ieee80211_key *,
    mblk_t *, int);
static int tkip_decrypt(struct tkip_ctx *, struct ieee80211_key *,
    mblk_t *, int);

extern int rc4_init(crypto_context_t *, const uint8_t *, int);
extern int rc4_crypt(crypto_context_t, const uint8_t *, uint8_t *, int);
extern int rc4_final(crypto_context_t, uint8_t *, int);

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

	hdrlen = ieee80211_hdrspace(ic, mp->b_rptr);
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
	 * Finally, do software encrypt if neeed.
	 */
	if (k->wk_flags & IEEE80211_KEY_SWCRYPT) {
		if (!tkip_encrypt(ctx, k, mp, hdrlen))
			return (0);
	} else
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
	 * Check if the device handled the decrypt in hardware.
	 * If so we just strip the header; otherwise we need to
	 * handle the decrypt in software.
	 */
	if (k->wk_flags & IEEE80211_KEY_SWCRYPT) {
		if (!tkip_decrypt(ctx, k, mp, hdrlen))
			return (0);
	}

	/*
	 * Copy up 802.11 header and strip crypto bits.
	 */
	(void) memmove(mp->b_rptr + tkip.ic_header, mp->b_rptr, hdrlen);
	mp->b_rptr += tkip.ic_header;
	mp->b_wptr -= tkip.ic_trailer;

	return (1);
}

/*
 * Add MIC to the frame as needed.
 */
static int
tkip_enmic(struct ieee80211_key *k, mblk_t *mp, int force)
{
	struct tkip_ctx *ctx = k->wk_private;

	if (force || (k->wk_flags & IEEE80211_KEY_SWMIC)) {
		int hdrlen;
		uint8_t *mic;

		hdrlen = ieee80211_hdrspace(ctx->tc_ic, mp->b_rptr);
		mic = mp->b_wptr;
		mp->b_wptr += tkip.ic_miclen;

		if ((int)(MBLKL(mp) -
		    (hdrlen + tkip.ic_header + tkip.ic_miclen)) < 0)
			return (0);	/* dead packet */

		michael_mic(ctx, k->wk_txmic, mp, (hdrlen + tkip.ic_header),
		    MBLKL(mp) -
		    (hdrlen + tkip.ic_header + tkip.ic_miclen), mic);
	}
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

	if (force || (k->wk_flags & IEEE80211_KEY_SWMIC)) {
		int hdrlen = ieee80211_hdrspace(ctx->tc_ic, mp->b_rptr);
		uint8_t mic[IEEE80211_WEP_MICLEN];
		uint8_t mic0[IEEE80211_WEP_MICLEN];

		michael_mic(ctx, k->wk_rxmic,
		    mp, hdrlen,
		    MBLKL(mp) - (hdrlen + tkip.ic_miclen),
		    mic);
		bcopy(mp->b_wptr - tkip.ic_miclen, mic0, tkip.ic_miclen);
		if (bcmp(mic, mic0, tkip.ic_miclen)) {
			ieee80211_dbg(IEEE80211_MSG_CRYPTO,
			    "tkip_demic() mic mismatch\n");
			return (0);
		}
	}
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

/*
 * For the avoidance of doubt, except that if any license choice other
 * than GPL or LGPL is available it will apply instead, Sun elects to
 * use only the General Public License version 2 (GPLv2) at this time
 * for any software where a choice of GPL license versions is made
 * available with the language indicating that GPLv2 or any later
 * version may be used, or where a choice of which version of the GPL
 * is applied is otherwise unspecified.
 */

/*
 * Host AP crypt: host-based TKIP encryption implementation for Host AP driver
 *
 * Copyright (c) 2003-2004, Jouni Malinen <jkmaline@cc.hut.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See README and COPYING for
 * more details.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 */

/* Table of CRCs of all 8-bit messages */
static uint32_t crc_table[] = { CRC32_TABLE };

static uint16_t
RotR1(uint16_t val)
{
	return ((val >> 1) | (val << 15));
}

static uint8_t
Lo8(uint16_t val)
{
	return (val & 0xff);
}

static uint8_t
Hi8(uint16_t val)
{
	return (val >> 8);
}

static uint16_t
Lo16(uint32_t val)
{
	return (val & 0xffff);
}

static uint16_t
Hi16(uint32_t val)
{
	return (val >> 16);
}

static uint16_t
Mk16(uint8_t hi, uint8_t lo)
{
	return (lo | (((uint16_t)hi) << 8));
}

static uint16_t
Mk16_le(const uint16_t *v)
{
	return (LE_16(*v));
}

static const uint16_t Sbox[256] = {
	0xC6A5, 0xF884, 0xEE99, 0xF68D, 0xFF0D, 0xD6BD, 0xDEB1, 0x9154,
	0x6050, 0x0203, 0xCEA9, 0x567D, 0xE719, 0xB562, 0x4DE6, 0xEC9A,
	0x8F45, 0x1F9D, 0x8940, 0xFA87, 0xEF15, 0xB2EB, 0x8EC9, 0xFB0B,
	0x41EC, 0xB367, 0x5FFD, 0x45EA, 0x23BF, 0x53F7, 0xE496, 0x9B5B,
	0x75C2, 0xE11C, 0x3DAE, 0x4C6A, 0x6C5A, 0x7E41, 0xF502, 0x834F,
	0x685C, 0x51F4, 0xD134, 0xF908, 0xE293, 0xAB73, 0x6253, 0x2A3F,
	0x080C, 0x9552, 0x4665, 0x9D5E, 0x3028, 0x37A1, 0x0A0F, 0x2FB5,
	0x0E09, 0x2436, 0x1B9B, 0xDF3D, 0xCD26, 0x4E69, 0x7FCD, 0xEA9F,
	0x121B, 0x1D9E, 0x5874, 0x342E, 0x362D, 0xDCB2, 0xB4EE, 0x5BFB,
	0xA4F6, 0x764D, 0xB761, 0x7DCE, 0x527B, 0xDD3E, 0x5E71, 0x1397,
	0xA6F5, 0xB968, 0x0000, 0xC12C, 0x4060, 0xE31F, 0x79C8, 0xB6ED,
	0xD4BE, 0x8D46, 0x67D9, 0x724B, 0x94DE, 0x98D4, 0xB0E8, 0x854A,
	0xBB6B, 0xC52A, 0x4FE5, 0xED16, 0x86C5, 0x9AD7, 0x6655, 0x1194,
	0x8ACF, 0xE910, 0x0406, 0xFE81, 0xA0F0, 0x7844, 0x25BA, 0x4BE3,
	0xA2F3, 0x5DFE, 0x80C0, 0x058A, 0x3FAD, 0x21BC, 0x7048, 0xF104,
	0x63DF, 0x77C1, 0xAF75, 0x4263, 0x2030, 0xE51A, 0xFD0E, 0xBF6D,
	0x814C, 0x1814, 0x2635, 0xC32F, 0xBEE1, 0x35A2, 0x88CC, 0x2E39,
	0x9357, 0x55F2, 0xFC82, 0x7A47, 0xC8AC, 0xBAE7, 0x322B, 0xE695,
	0xC0A0, 0x1998, 0x9ED1, 0xA37F, 0x4466, 0x547E, 0x3BAB, 0x0B83,
	0x8CCA, 0xC729, 0x6BD3, 0x283C, 0xA779, 0xBCE2, 0x161D, 0xAD76,
	0xDB3B, 0x6456, 0x744E, 0x141E, 0x92DB, 0x0C0A, 0x486C, 0xB8E4,
	0x9F5D, 0xBD6E, 0x43EF, 0xC4A6, 0x39A8, 0x31A4, 0xD337, 0xF28B,
	0xD532, 0x8B43, 0x6E59, 0xDAB7, 0x018C, 0xB164, 0x9CD2, 0x49E0,
	0xD8B4, 0xACFA, 0xF307, 0xCF25, 0xCAAF, 0xF48E, 0x47E9, 0x1018,
	0x6FD5, 0xF088, 0x4A6F, 0x5C72, 0x3824, 0x57F1, 0x73C7, 0x9751,
	0xCB23, 0xA17C, 0xE89C, 0x3E21, 0x96DD, 0x61DC, 0x0D86, 0x0F85,
	0xE090, 0x7C42, 0x71C4, 0xCCAA, 0x90D8, 0x0605, 0xF701, 0x1C12,
	0xC2A3, 0x6A5F, 0xAEF9, 0x69D0, 0x1791, 0x9958, 0x3A27, 0x27B9,
	0xD938, 0xEB13, 0x2BB3, 0x2233, 0xD2BB, 0xA970, 0x0789, 0x33A7,
	0x2DB6, 0x3C22, 0x1592, 0xC920, 0x8749, 0xAAFF, 0x5078, 0xA57A,
	0x038F, 0x59F8, 0x0980, 0x1A17, 0x65DA, 0xD731, 0x84C6, 0xD0B8,
	0x82C3, 0x29B0, 0x5A77, 0x1E11, 0x7BCB, 0xA8FC, 0x6DD6, 0x2C3A,
};

static uint16_t
_S_(uint16_t v)
{
	uint16_t t = Sbox[Hi8(v)];
	return (Sbox[Lo8(v)] ^ ((t << 8) | (t >> 8)));
}

#define	PHASE1_LOOP_COUNT	8

static void
tkip_mixing_phase1(uint16_t *TTAK, const uint8_t *TK,
    const uint8_t *TA, uint32_t IV32)
{
	int i, j;

	/* Initialize the 80-bit TTAK from TSC (IV32) and TA[0..5] */
	TTAK[0] = Lo16(IV32);
	TTAK[1] = Hi16(IV32);
	TTAK[2] = Mk16(TA[1], TA[0]);
	TTAK[3] = Mk16(TA[3], TA[2]);
	TTAK[4] = Mk16(TA[5], TA[4]);

	for (i = 0; i < PHASE1_LOOP_COUNT; i++) {
		j = 2 * (i & 1);
		TTAK[0] += _S_(TTAK[4] ^ Mk16(TK[1 + j], TK[0 + j]));
		TTAK[1] += _S_(TTAK[0] ^ Mk16(TK[5 + j], TK[4 + j]));
		TTAK[2] += _S_(TTAK[1] ^ Mk16(TK[9 + j], TK[8 + j]));
		TTAK[3] += _S_(TTAK[2] ^ Mk16(TK[13 + j], TK[12 + j]));
		TTAK[4] += _S_(TTAK[3] ^ Mk16(TK[1 + j], TK[0 + j])) + i;
	}
}

static void
tkip_mixing_phase2(uint8_t *WEPSeed, const uint8_t *TK,
    const uint16_t *TTAK, uint16_t IV16)
{
	/*
	 * Make temporary area overlap WEP seed so that the final copy can be
	 * avoided on little endian hosts.
	 */
	uint16_t *PPK = (uint16_t *)&WEPSeed[4];

	/* Step 1 - make copy of TTAK and bring in TSC */
	PPK[0] = TTAK[0];
	PPK[1] = TTAK[1];
	PPK[2] = TTAK[2];
	PPK[3] = TTAK[3];
	PPK[4] = TTAK[4];
	PPK[5] = TTAK[4] + IV16;

	/* Step 2 - 96-bit bijective mixing using S-box */
	PPK[0] += _S_(PPK[5] ^ Mk16_le((const uint16_t *) &TK[0]));
	PPK[1] += _S_(PPK[0] ^ Mk16_le((const uint16_t *) &TK[2]));
	PPK[2] += _S_(PPK[1] ^ Mk16_le((const uint16_t *) &TK[4]));
	PPK[3] += _S_(PPK[2] ^ Mk16_le((const uint16_t *) &TK[6]));
	PPK[4] += _S_(PPK[3] ^ Mk16_le((const uint16_t *) &TK[8]));
	PPK[5] += _S_(PPK[4] ^ Mk16_le((const uint16_t *) &TK[10]));

	PPK[0] += RotR1(PPK[5] ^ Mk16_le((const uint16_t *) &TK[12]));
	PPK[1] += RotR1(PPK[0] ^ Mk16_le((const uint16_t *) &TK[14]));
	PPK[2] += RotR1(PPK[1]);
	PPK[3] += RotR1(PPK[2]);
	PPK[4] += RotR1(PPK[3]);
	PPK[5] += RotR1(PPK[4]);

	/*
	 * Step 3 - bring in last of TK bits, assign 24-bit WEP IV value
	 * WEPSeed[0..2] is transmitted as WEP IV
	 */
	WEPSeed[0] = Hi8(IV16);
	WEPSeed[1] = (Hi8(IV16) | 0x20) & 0x7F;
	WEPSeed[2] = Lo8(IV16);
	WEPSeed[3] = Lo8((PPK[5] ^ Mk16_le((const uint16_t *) &TK[0])) >> 1);

#ifdef _BIG_ENDIAN
	int i;
	for (i = 0; i < 6; i++)
		PPK[i] = (PPK[i] << 8) | (PPK[i] >> 8);
#endif
}

static int
wep_encrypt(uint8_t *key, mblk_t *mp, uint_t off, size_t data_len,
    uint8_t icv[IEEE80211_WEP_CRCLEN])
{
	uint8_t crcbuf[IEEE80211_WEP_CRCLEN];
	uint32_t crc;
	crypto_context_t ctx;
	int rv;

	ctx = NULL;
	rv = rc4_init(&ctx, (const uint8_t *)key, 16);
	if (rv != CRYPTO_SUCCESS)
		return (0);

	/* calculate CRC over unencrypted data */
	CRC32(crc, mp->b_rptr + off, data_len, -1U, crc_table);

	/* encrypt data */
	(void) rc4_crypt(ctx, mp->b_rptr + off, mp->b_rptr + off, data_len);

	/* tack on ICV */
	*(uint32_t *)crcbuf = LE_32(~crc);
	(void) rc4_crypt(ctx, crcbuf, icv, IEEE80211_WEP_CRCLEN);

	(void) rc4_final(ctx, icv, IEEE80211_WEP_CRCLEN);

	return (1);
}

static int
wep_decrypt(uint8_t *key, mblk_t *mp, uint_t off, size_t data_len)
{
	uint8_t crcbuf[IEEE80211_WEP_CRCLEN];
	uint8_t *icv;
	uint32_t crc;
	crypto_context_t ctx;
	int rv;

	ctx = NULL;
	rv = rc4_init(&ctx, (const uint8_t *)key, 16);
	if (rv != CRYPTO_SUCCESS)
		return (0);

	/* decrypt data */
	(void) rc4_crypt(ctx, mp->b_rptr + off, mp->b_rptr + off, data_len);

	/* calculate CRC over unencrypted data */
	CRC32(crc, mp->b_rptr + off, data_len, -1U, crc_table);

	/* decrypt ICV and compare to CRC */
	icv = mp->b_wptr - IEEE80211_WEP_CRCLEN;
	(void) rc4_crypt(ctx, icv, crcbuf, IEEE80211_WEP_CRCLEN);
	(void) rc4_final(ctx, crcbuf, IEEE80211_WEP_CRCLEN);

	return (crc == ~LE_32(*(uint32_t *)crcbuf));
}

static uint32_t
rotl(uint32_t val, int bits)
{
	return ((val << bits) | (val >> (32 - bits)));
}


static uint32_t
rotr(uint32_t val, int bits)
{
	return ((val >> bits) | (val << (32 - bits)));
}


static uint32_t
xswap(uint32_t val)
{
	return (((val & 0x00ff00ff) << 8) | ((val & 0xff00ff00) >> 8));
}


#define	michael_block(l, r)	\
do {				\
	r ^= rotl(l, 17);	\
	l += r;			\
	r ^= xswap(l);		\
	l += r;			\
	r ^= rotl(l, 3);	\
	l += r;			\
	r ^= rotr(l, 2);	\
	l += r;			\
	_NOTE(CONSTANTCONDITION)\
} while (0)


static uint32_t
get_le32_split(uint8_t b0, uint8_t b1, uint8_t b2, uint8_t b3)
{
	return (b0 | (b1 << 8) | (b2 << 16) | (b3 << 24));
}

static uint32_t
get_le32(const uint8_t *p)
{
	return (get_le32_split(p[0], p[1], p[2], p[3]));
}


static void
put_le32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v;
	p[1] = v >> 8;
	p[2] = v >> 16;
	p[3] = v >> 24;
}

/*
 * Craft pseudo header used to calculate the MIC.
 */
static void
michael_mic_hdr(const struct ieee80211_frame *wh0, uint8_t hdr[16])
{
	const struct ieee80211_frame_addr4 *wh =
	    (const struct ieee80211_frame_addr4 *)wh0;

	switch (wh->i_fc[1] & IEEE80211_FC1_DIR_MASK) {
	case IEEE80211_FC1_DIR_NODS:
		IEEE80211_ADDR_COPY(hdr, wh->i_addr1); /* DA */
		IEEE80211_ADDR_COPY(hdr + IEEE80211_ADDR_LEN, wh->i_addr2);
		break;
	case IEEE80211_FC1_DIR_TODS:
		IEEE80211_ADDR_COPY(hdr, wh->i_addr3); /* DA */
		IEEE80211_ADDR_COPY(hdr + IEEE80211_ADDR_LEN, wh->i_addr2);
		break;
	case IEEE80211_FC1_DIR_FROMDS:
		IEEE80211_ADDR_COPY(hdr, wh->i_addr1); /* DA */
		IEEE80211_ADDR_COPY(hdr + IEEE80211_ADDR_LEN, wh->i_addr3);
		break;
	case IEEE80211_FC1_DIR_DSTODS:
		IEEE80211_ADDR_COPY(hdr, wh->i_addr3); /* DA */
		IEEE80211_ADDR_COPY(hdr + IEEE80211_ADDR_LEN, wh->i_addr4);
		break;
	}

	if (wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_QOS) {
		const struct ieee80211_qosframe *qwh =
		    (const struct ieee80211_qosframe *)wh;
		hdr[12] = qwh->i_qos[0] & IEEE80211_QOS_TID;
	} else
		hdr[12] = 0;
	hdr[13] = hdr[14] = hdr[15] = 0; /* reserved */
}

/* ARGSUSED */
static void
michael_mic(struct tkip_ctx *ctx, const uint8_t *key,
    mblk_t *mp, uint_t off, size_t data_len,
    uint8_t mic[IEEE80211_WEP_MICLEN])
{
	uint8_t hdr[16];
	uint32_t l, r;
	const uint8_t *data;
	int i, blocks, last;

	michael_mic_hdr((struct ieee80211_frame *)mp->b_rptr, hdr);

	l = get_le32(key);
	r = get_le32(key + 4);

	/* Michael MIC pseudo header: DA, SA, 3 x 0, Priority */
	l ^= get_le32(hdr);
	michael_block(l, r);
	l ^= get_le32(&hdr[4]);
	michael_block(l, r);
	l ^= get_le32(&hdr[8]);
	michael_block(l, r);
	l ^= get_le32(&hdr[12]);
	michael_block(l, r);

	/* first buffer has special handling */
	data = mp->b_rptr + off;

	blocks = data_len / 4;
	last = data_len % 4;

	for (i = 0; i < blocks; i++) {
		l ^= get_le32(&data[4 * i]);
		michael_block(l, r);
	}

	/* Last block and padding (0x5a, 4..7 x 0) */
	switch (last) {
	case 0:
		l ^= 0x5a;
		break;
	case 1:
		l ^= data[4 * i] | 0x5a00;
		break;
	case 2:
		l ^= data[4 * i] | (data[4 * i + 1] << 8) | 0x5a0000;
		break;
	case 3:
		l ^= data[4 * i] | (data[4 * i + 1] << 8) |
		    (data[4 * i + 2] << 16) | 0x5a000000;
		break;
	}
	michael_block(l, r);
	/* l ^= 0; */
	michael_block(l, r);

	put_le32(mic, l);
	put_le32(mic + 4, r);
}

static int
tkip_encrypt(struct tkip_ctx *ctx, struct ieee80211_key *key,
    mblk_t *mp, int hdrlen)
{
	struct ieee80211_frame *wh;
	uint8_t *icv;

	wh = (struct ieee80211_frame *)mp->b_rptr;
	if (!ctx->tx_phase1_done) {
		tkip_mixing_phase1(ctx->tx_ttak, key->wk_key, wh->i_addr2,
		    (uint32_t)(key->wk_keytsc >> 16));
		ctx->tx_phase1_done = 1;
	}
	tkip_mixing_phase2(ctx->tx_rc4key, key->wk_key, ctx->tx_ttak,
	    (uint16_t)key->wk_keytsc);

	icv = mp->b_wptr;
	mp->b_wptr += tkip.ic_trailer;

	(void) wep_encrypt(ctx->tx_rc4key,
	    mp, hdrlen + tkip.ic_header,
	    MBLKL(mp) -
	    (hdrlen + tkip.ic_header + tkip.ic_trailer),
	    icv);

	key->wk_keytsc++;
	if ((uint16_t)(key->wk_keytsc) == 0)
		ctx->tx_phase1_done = 0;
	return (1);
}

static int
tkip_decrypt(struct tkip_ctx *ctx, struct ieee80211_key *key,
    mblk_t *mp, int hdrlen)
{
	struct ieee80211_frame *wh;
	uint32_t iv32;
	uint16_t iv16;

	wh = (struct ieee80211_frame *)mp->b_rptr;
	/* tkip_decap already verified header and left seq in rx_rsc */
	iv16 = (uint16_t)ctx->rx_rsc;
	iv32 = (uint32_t)(ctx->rx_rsc >> 16);

	if (iv32 != (uint32_t)(key->wk_keyrsc >> 16) || !ctx->rx_phase1_done) {
		tkip_mixing_phase1(ctx->rx_ttak, key->wk_key,
		    wh->i_addr2, iv32);
		ctx->rx_phase1_done = 0;	/* DHCP */
	}
	tkip_mixing_phase2(ctx->rx_rc4key, key->wk_key, ctx->rx_ttak, iv16);

	/* m is unstripped; deduct headers + ICV to get payload */
	if (!wep_decrypt(ctx->rx_rc4key,
	    mp, hdrlen + tkip.ic_header,
	    MBLKL(mp) -
	    (hdrlen + tkip.ic_header + tkip.ic_trailer))) {
		if (iv32 != (uint32_t)(key->wk_keyrsc >> 16)) {
			/*
			 * Previously cached Phase1 result was already lost, so
			 * it needs to be recalculated for the next packet.
			 */
			ctx->rx_phase1_done = 0;
		}
		ieee80211_dbg(IEEE80211_MSG_CRYPTO, "tkip_decrypt() error\n");
		return (0);
	}
	return (1);
}
