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
 * IEEE 802.11 WEP crypto support.
 */
#include <sys/byteorder.h>
#include <sys/crypto/common.h>
#include <sys/crypto/api.h>
#include <sys/crc32.h>
#include <sys/random.h>
#include <sys/strsun.h>
#include "net80211_impl.h"

static  void *wep_attach(struct ieee80211com *, struct ieee80211_key *);
static  void wep_detach(struct ieee80211_key *);
static  int wep_setkey(struct ieee80211_key *);
static  int wep_encap(struct ieee80211_key *, mblk_t *, uint8_t keyid);
static  int wep_decap(struct ieee80211_key *, mblk_t *, int);
static  int wep_enmic(struct ieee80211_key *, mblk_t *, int);
static  int wep_demic(struct ieee80211_key *, mblk_t *, int);

const struct ieee80211_cipher wep = {
	"WEP",
	IEEE80211_CIPHER_WEP,
	IEEE80211_WEP_IVLEN + IEEE80211_WEP_KIDLEN,
	IEEE80211_WEP_CRCLEN,
	0,
	wep_attach,
	wep_detach,
	wep_setkey,
	wep_encap,
	wep_decap,
	wep_enmic,
	wep_demic,
};

int rc4_init(crypto_context_t *, const uint8_t *, int);
int rc4_crypt(crypto_context_t, const uint8_t *, uint8_t *, int);
int rc4_final(crypto_context_t, uint8_t *, int);

static	int wep_encrypt(struct ieee80211_key *, mblk_t *, int);
static	int wep_decrypt(struct ieee80211_key *, mblk_t *, int);

struct wep_ctx {
	ieee80211com_t *wc_ic;		/* for diagnostics */
	uint32_t	wc_iv;		/* initial vector for crypto */
};

/* Table of CRCs of all 8-bit messages */
static uint32_t crc_table[] = { CRC32_TABLE };

/* ARGSUSED */
static void *
wep_attach(struct ieee80211com *ic, struct ieee80211_key *k)
{
	struct wep_ctx *ctx;

	ctx = kmem_zalloc(sizeof (struct wep_ctx), KM_NOSLEEP);
	if (ctx == NULL)
		return (NULL);

	ctx->wc_ic = ic;
	(void) random_get_pseudo_bytes((unsigned char *)&ctx->wc_iv,
	    sizeof (uint32_t));
	return (ctx);
}

static void
wep_detach(struct ieee80211_key *k)
{
	struct wep_ctx *ctx = k->wk_private;

	if (ctx != NULL)
		kmem_free(ctx, sizeof (struct wep_ctx));
}

static int
wep_setkey(struct ieee80211_key *k)
{
	/*
	 * WEP key length is standardized to 40-bit. Many
	 * implementations support 104-bit WEP kwys.
	 */
	return (k->wk_keylen == 40/NBBY || k->wk_keylen == 104/NBBY);
}

/*
 * Add privacy headers appropriate for the specified key.
 */
static int
wep_encap(struct ieee80211_key *k, mblk_t *mp, uint8_t keyid)
{
	struct wep_ctx *ctx = k->wk_private;
	struct ieee80211_frame *wh = (struct ieee80211_frame *)mp->b_rptr;
	uint32_t iv;
	uint8_t *ivp;
	int hdrlen;

	if (mp == NULL)
		return (0);
	hdrlen = ieee80211_hdrspace(ctx->wc_ic, wh);

	ivp = (uint8_t *)wh;
	ivp += hdrlen;

	/*
	 * IV must not duplicate during the lifetime of the key.
	 * But no mechanism to renew keys is defined in IEEE 802.11
	 * WEP.  And IV may be duplicated between other stations
	 * because of the session key itself is shared.
	 * So we use pseudo random IV for now, though it is not the
	 * right way.
	 */
	iv = ctx->wc_iv;
	/*
	 * Skip 'bad' IVs from Fluhrer/Mantin/Shamir:
	 * (B, 255, N) with 3 <= B < 8
	 */
	if ((iv & 0xff00) == 0xff00) {
		int B = (iv & 0xff0000) >> 16;
		if (3 <= B && B < 16)
			iv = (B+1) << 16;
	}
	ctx->wc_iv = iv + 1;

	ivp[2] = (uint8_t)(iv >> 0);
	ivp[1] = (uint8_t)(iv >> 8);
	ivp[0] = (uint8_t)(iv >> 16);

	/* Key ID and pad */
	ivp[IEEE80211_WEP_IVLEN] = keyid;

	if ((k->wk_flags & IEEE80211_KEY_SWCRYPT) &&
	    (wep_encrypt(k, mp, hdrlen) == 0))
		return (0);

	return (1);
}

/*
 * Validate and strip privacy headers (and trailer) for a
 * received frame.  If necessary, decrypt the frame using
 * the specified key.
 */
static int
wep_decap(struct ieee80211_key *k, mblk_t *mp, int hdrlen)
{
	/*
	 * Check if the device handled the decrypt in hardware.
	 * If so we just strip the header; otherwise we need to
	 * handle the decrypt in software.
	 */
	if ((k->wk_flags & IEEE80211_KEY_SWCRYPT) &&
	    (wep_decrypt(k, mp, hdrlen) == 0)) {
		ieee80211_err("WEP ICV mismatch on decrypt\n");
		return (0);
	}

	/*
	 * Copy up 802.11 header and strip crypto bits.
	 */
	(void) memmove(mp->b_rptr + wep.ic_header, mp->b_rptr, hdrlen);
	mp->b_rptr += wep.ic_header;
	mp->b_wptr -= wep.ic_trailer;

	return (1);
}

/*
 * Add MIC to the frame as needed.
 */
/* ARGSUSED */
static int
wep_enmic(struct ieee80211_key *k, mblk_t *mp, int force)
{
	return (1);
}

/*
 * Verify and strip MIC from the frame.
 */
/* ARGSUSED */
static int
wep_demic(struct ieee80211_key *k, mblk_t *mp, int force)
{
	return (1);
}

static int
wep_encrypt(struct ieee80211_key *key, mblk_t *mp, int hdrlen)
{
	uint8_t rc4key[IEEE80211_WEP_IVLEN + IEEE80211_KEYBUF_SIZE];
	uint8_t crcbuf[IEEE80211_WEP_CRCLEN];
	uint8_t *icv;
	uint32_t crc;
	crypto_context_t ctx;
	int rv;

	ASSERT(key->wk_flags & IEEE80211_KEY_SWCRYPT);

	/* ctx->wc_ic->isc_stats.is_crypto_wep++; */

	(void) memcpy(rc4key, mp->b_rptr + hdrlen, IEEE80211_WEP_IVLEN);
	(void) memcpy(rc4key + IEEE80211_WEP_IVLEN, key->wk_key,
	    key->wk_keylen);

	ctx = NULL;
	rv = rc4_init(&ctx, (const uint8_t *)rc4key,
	    IEEE80211_WEP_IVLEN + key->wk_keylen);

	if (rv != CRYPTO_SUCCESS)
		return (0);

	/* calculate CRC over unencrypted data */
	CRC32(crc, mp->b_rptr + hdrlen + wep.ic_header,
	    MBLKL(mp) - (hdrlen + wep.ic_header),
	    -1U, crc_table);

	/* encrypt data */
	(void) rc4_crypt(ctx,
	    mp->b_rptr + hdrlen + wep.ic_header,
	    mp->b_rptr + hdrlen + wep.ic_header,
	    MBLKL(mp) - (hdrlen + wep.ic_header));

	/* tack on ICV */
	*(uint32_t *)crcbuf = LE_32(~crc);
	icv = mp->b_wptr;
	mp->b_wptr += IEEE80211_WEP_CRCLEN;
	(void) rc4_crypt(ctx, crcbuf, icv, IEEE80211_WEP_CRCLEN);

	(void) rc4_final(ctx, icv, IEEE80211_WEP_CRCLEN);

	return (1);
}

static int
wep_decrypt(struct ieee80211_key *key, mblk_t *mp, int hdrlen)
{
	uint8_t rc4key[IEEE80211_WEP_IVLEN + IEEE80211_KEYBUF_SIZE];
	uint8_t crcbuf[IEEE80211_WEP_CRCLEN];
	uint8_t *icv;
	uint32_t crc;
	crypto_context_t ctx;
	int rv;

	ASSERT(key->wk_flags & IEEE80211_KEY_SWCRYPT);

	/* ctx->wc_ic->isc_stats.is_crypto_wep++; */

	(void) memcpy(rc4key, mp->b_rptr + hdrlen, IEEE80211_WEP_IVLEN);
	(void) memcpy(rc4key + IEEE80211_WEP_IVLEN, key->wk_key,
	    key->wk_keylen);

	ctx = NULL;
	rv = rc4_init(&ctx, (const uint8_t *)rc4key,
	    IEEE80211_WEP_IVLEN + key->wk_keylen);

	if (rv != CRYPTO_SUCCESS)
		return (0);

	/* decrypt data */
	(void) rc4_crypt(ctx,
	    mp->b_rptr + hdrlen + wep.ic_header,
	    mp->b_rptr + hdrlen + wep.ic_header,
	    MBLKL(mp) -
	    (hdrlen + wep.ic_header + wep.ic_trailer));

	/* calculate CRC over unencrypted data */
	CRC32(crc, mp->b_rptr + hdrlen + wep.ic_header,
	    MBLKL(mp) -
	    (hdrlen + wep.ic_header + wep.ic_trailer),
	    -1U, crc_table);

	/* decrypt ICV and compare to CRC */
	icv = mp->b_wptr - IEEE80211_WEP_CRCLEN;
	(void) rc4_crypt(ctx, icv, crcbuf, IEEE80211_WEP_CRCLEN);

	(void) rc4_final(ctx, crcbuf, IEEE80211_WEP_CRCLEN);

	return (crc == ~LE_32(*(uint32_t *)crcbuf));
}

/*
 * rc_init() -  To init the key, for multiply encryption/decryption
 * Using the Kernel encryption framework
 */
int
rc4_init(crypto_context_t *ctx, const uint8_t *key, int keylen)
{
	crypto_mechanism_t mech;
	crypto_key_t crkey;
	int rv;

	bzero(&crkey, sizeof (crkey));

	crkey.ck_format = CRYPTO_KEY_RAW;
	crkey.ck_data   = (char *)key;
	/* keys are measured in bits, not bytes, so multiply by 8 */
	crkey.ck_length = keylen * 8;

	mech.cm_type	  = crypto_mech2id(SUN_CKM_RC4);
	mech.cm_param	  = NULL;
	mech.cm_param_len = 0;

	rv = crypto_encrypt_init(&mech, &crkey, NULL, ctx, NULL);
	if (rv != CRYPTO_SUCCESS)
		cmn_err(CE_WARN, "rc4_init failed (%x)", rv);

	return (rv);
}

/*
 * rc4_crypt
 *
 * Use the Kernel encryption framework to provide the
 * crypto operations for the indicated data.
 */
int
rc4_crypt(crypto_context_t ctx, const uint8_t *inbuf,
	uint8_t *outbuf, int buflen)
{
	int rv = CRYPTO_FAILED;

	crypto_data_t d1, d2;

	ASSERT(inbuf  != NULL);
	ASSERT(outbuf != NULL);

	bzero(&d1, sizeof (d1));
	bzero(&d2, sizeof (d2));

	d1.cd_format = CRYPTO_DATA_RAW;
	d1.cd_offset = 0;
	d1.cd_length = buflen;
	d1.cd_raw.iov_base = (char *)inbuf;
	d1.cd_raw.iov_len  = buflen;

	d2.cd_format = CRYPTO_DATA_RAW;
	d2.cd_offset = 0;
	d2.cd_length = buflen;
	d2.cd_raw.iov_base = (char *)outbuf;
	d2.cd_raw.iov_len  = buflen;

	rv = crypto_encrypt_update(ctx, &d1, &d2, NULL);

	if (rv != CRYPTO_SUCCESS)
		cmn_err(CE_WARN, "rc4_crypt failed (%x)", rv);
	return (rv);
}

/*
 * rc4_final
 *
 * Use the Kernel encryption framework to provide the
 * crypto operations for the indicated data.
 */
int
rc4_final(crypto_context_t ctx, uint8_t *outbuf, int buflen)
{
	int rv = CRYPTO_FAILED;

	crypto_data_t d2;

	ASSERT(outbuf != NULL);

	bzero(&d2, sizeof (d2));

	d2.cd_format = CRYPTO_DATA_RAW;
	d2.cd_offset = 0;
	d2.cd_length = buflen;
	d2.cd_raw.iov_base = (char *)outbuf;
	d2.cd_raw.iov_len = buflen;

	rv = crypto_encrypt_final(ctx, &d2, NULL);

	if (rv != CRYPTO_SUCCESS)
		cmn_err(CE_WARN, "rc4_final failed (%x)", rv);
	return (rv);
}
