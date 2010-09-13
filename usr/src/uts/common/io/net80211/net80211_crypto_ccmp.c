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
 * IEEE 802.11i CCMP crypto support.
 */
#include <sys/byteorder.h>
#include <sys/crypto/common.h>
#include <sys/crypto/api.h>
#include <sys/crc32.h>
#include <sys/random.h>
#include <sys/strsun.h>
#include "net80211_impl.h"

struct ccmp_ctx {
	struct ieee80211com *cc_ic;	/* for diagnostics */
};

#define	AES_BLOCK_LEN	16
#define	AES_NONCE_LEN	13

static void *ccmp_attach(struct ieee80211com *, struct ieee80211_key *);
static void ccmp_detach(struct ieee80211_key *);
static int ccmp_setkey(struct ieee80211_key *);
static int ccmp_encap(struct ieee80211_key *k, mblk_t *, uint8_t);
static int ccmp_decap(struct ieee80211_key *, mblk_t *, int);
static int ccmp_enmic(struct ieee80211_key *, mblk_t *, int);
static int ccmp_demic(struct ieee80211_key *, mblk_t *, int);

static int ccmp_encrypt(struct ieee80211_key *, mblk_t *, int);
static int ccmp_decrypt(struct ieee80211_key *, uint64_t pn, mblk_t *, int);

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
	struct ccmp_ctx *ctx = k->wk_private;
	uint8_t *ivp;
	int hdrlen;

	hdrlen = ieee80211_hdrspace(ctx->cc_ic, mp->b_rptr);
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
	 * Finally, do software encrypt if neeed.
	 */
	if ((k->wk_flags & IEEE80211_KEY_SWCRYPT) &&
	    !ccmp_encrypt(k, mp, hdrlen))
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
	 * Check if the device handled the decrypt in hardware.
	 * If so we just strip the header; otherwise we need to
	 * handle the decrypt in software.  Note that for the
	 * latter we leave the header in place for use in the
	 * decryption work.
	 */
	if ((k->wk_flags & IEEE80211_KEY_SWCRYPT) &&
	    !ccmp_decrypt(k, pn, mp, hdrlen))
		return (0);

	/*
	 * Copy up 802.11 header and strip crypto bits.
	 */
	(void) memmove(mp->b_rptr + ccmp.ic_header, mp->b_rptr, hdrlen);
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

static int
aes_ccm_encrypt(CK_AES_CCM_PARAMS *cmparam, const uint8_t *key, int keylen,
    const uint8_t *plaintext, int plain_len,
    uint8_t *ciphertext, int cipher_len)
{
	crypto_mechanism_t mech;
	crypto_key_t crkey;
	crypto_data_t d1, d2;

	int rv;

	ieee80211_dbg(IEEE80211_MSG_CRYPTO,
	    "aes_ccm_encrypt(len=%d, keylen=%d)", plain_len, keylen);

	bzero(&crkey, sizeof (crkey));

	crkey.ck_format = CRYPTO_KEY_RAW;
	crkey.ck_data   = (char *)key;
	/* keys are measured in bits, not bytes, so multiply by 8 */
	crkey.ck_length = keylen * 8;

	mech.cm_type	  = crypto_mech2id(SUN_CKM_AES_CCM);
	mech.cm_param	  = (caddr_t)cmparam;
	mech.cm_param_len = sizeof (CK_AES_CCM_PARAMS);

#if defined(__amd64) || defined(__sparc)
	ieee80211_dbg(IEEE80211_MSG_CRYPTO, "cm_type=%lx", mech.cm_type);
#else
	ieee80211_dbg(IEEE80211_MSG_CRYPTO, "cm_type=%llx", mech.cm_type);
#endif

	bzero(&d1, sizeof (d1));
	bzero(&d2, sizeof (d2));

	d1.cd_format = CRYPTO_DATA_RAW;
	d1.cd_offset = 0;
	d1.cd_length = plain_len;
	d1.cd_raw.iov_base = (char *)plaintext;
	d1.cd_raw.iov_len  = plain_len;

	d2.cd_format = CRYPTO_DATA_RAW;
	d2.cd_offset = 0;
	d2.cd_length = cipher_len;
	d2.cd_raw.iov_base = (char *)ciphertext;
	d2.cd_raw.iov_len  = cipher_len;


	rv = crypto_encrypt(&mech, &d1, &crkey, NULL, &d2, NULL);
	if (rv != CRYPTO_SUCCESS)
		ieee80211_err("aes_ccm_encrypt failed (%x)", rv);
	return (rv);
}

static int
aes_ccm_decrypt(CK_AES_CCM_PARAMS *cmparam, const uint8_t *key, int keylen,
    const uint8_t *ciphertext, int cipher_len,
    uint8_t *plaintext, int plain_len)
{
	crypto_mechanism_t mech;
	crypto_key_t crkey;
	crypto_data_t d1, d2;

	int rv;

	ieee80211_dbg(IEEE80211_MSG_CRYPTO,
	    "aes_ccm_decrypt(len=%d, keylen=%d)", cipher_len, keylen);

	bzero(&crkey, sizeof (crkey));

	crkey.ck_format = CRYPTO_KEY_RAW;
	crkey.ck_data   = (char *)key;
	/* keys are measured in bits, not bytes, so multiply by 8 */
	crkey.ck_length = keylen * 8;

	mech.cm_type	  = crypto_mech2id(SUN_CKM_AES_CCM);
	mech.cm_param	  = (caddr_t)cmparam;
	mech.cm_param_len = sizeof (CK_AES_CCM_PARAMS);

#if defined(__amd64) || defined(__sparc)
	ieee80211_dbg(IEEE80211_MSG_CRYPTO, "cm_type=%lx", mech.cm_type);
#else
	ieee80211_dbg(IEEE80211_MSG_CRYPTO, "cm_type=%llx", mech.cm_type);
#endif

	bzero(&d1, sizeof (d1));
	bzero(&d2, sizeof (d2));

	d1.cd_format = CRYPTO_DATA_RAW;
	d1.cd_offset = 0;
	d1.cd_length = cipher_len;
	d1.cd_raw.iov_base = (char *)ciphertext;
	d1.cd_raw.iov_len  = cipher_len;

	d2.cd_format = CRYPTO_DATA_RAW;
	d2.cd_offset = 0;
	d2.cd_length = plain_len;
	d2.cd_raw.iov_base = (char *)plaintext;
	d2.cd_raw.iov_len  = plain_len;


	rv = crypto_decrypt(&mech, &d1, &crkey, NULL, &d2, NULL);
	if (rv != CRYPTO_SUCCESS)
		ieee80211_err("aes_ccm_decrypt failed (%x)", rv);
	return (rv);
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
 * Host AP crypt: host-based CCMP encryption implementation for Host AP driver
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

static void
ccmp_init(struct ieee80211_frame *wh, uint64_t pn, size_t dlen,
    uint8_t b0[AES_BLOCK_LEN], uint8_t aad[2 * AES_BLOCK_LEN])
{
	/*
	 * CCM Initial Block:
	 * Flag (Include authentication header, M=3 (8-octet MIC),
	 * L=1 (2-octet Dlen))
	 * Nonce: 0x00 | A2 | PN
	 * Dlen
	 */
	b0[0] = 0x59;
	/* b0[1] set below */
	IEEE80211_ADDR_COPY(b0 + 2, wh->i_addr2);
	b0[8] = pn >> 40;
	b0[9] = pn >> 32;
	b0[10] = pn >> 24;
	b0[11] = pn >> 16;
	b0[12] = pn >> 8;
	b0[13] = (uint8_t)(pn >> 0);
	b0[14] = (dlen >> 8) & 0xff;
	b0[15] = dlen & 0xff;

	/*
	 * AAD:
	 * FC with bits 4..6 and 11..13 masked to zero; 14 is always one
	 * A1 | A2 | A3
	 * SC with bits 4..15 (seq#) masked to zero
	 * A4 (if present)
	 * QC (if present)
	 */
	aad[0] = 0;	/* AAD length >> 8 */
	/* aad[1] set below */
	aad[2] = wh->i_fc[0] & 0x8f;	/* magic #s */
	aad[3] = wh->i_fc[1] & 0xc7;	/* magic #s */
	/* we know 3 addresses are contiguous */
	(void) memcpy(aad + 4, wh->i_addr1, 3 * IEEE80211_ADDR_LEN);
	aad[22] = wh->i_seq[0] & IEEE80211_SEQ_FRAG_MASK;
	aad[23] = 0; /* all bits masked */
	/*
	 * Construct variable-length portion of AAD based
	 * on whether this is a 4-address frame/QOS frame.
	 * We always zero-pad to 32 bytes before running it
	 * through the cipher.
	 *
	 * We also fill in the priority bits of the CCM
	 * initial block as we know whether or not we have
	 * a QOS frame.
	 */
	if (IEEE80211_QOS_HAS_SEQ(wh)) {
		struct ieee80211_qosframe *qwh =
		    (struct ieee80211_qosframe *)wh;
		aad[24] = qwh->i_qos[0] & 0x0f;	/* just priority bits */
		aad[25] = 0;
		b0[1] = aad[24];
		aad[1] = 22 + 2;
	} else {
		*(uint16_t *)&aad[24] = 0;
		b0[1] = 0;
		aad[1] = 22;
	}
	*(uint16_t *)&aad[26] = 0;
	*(uint32_t *)&aad[28] = 0;
}

static int
ccmp_encrypt(struct ieee80211_key *key, mblk_t *mp, int hdrlen)
{
	struct ieee80211_frame *wh;
	int rv, data_len;
	uint8_t aad[2 * AES_BLOCK_LEN], b0[AES_BLOCK_LEN];
	uint8_t *pos;
	CK_AES_CCM_PARAMS cmparam;

	wh = (struct ieee80211_frame *)mp->b_rptr;
	data_len = MBLKL(mp) - (hdrlen + ccmp.ic_header);
	pos = mp->b_rptr + hdrlen + ccmp.ic_header;

	ccmp_init(wh, key->wk_keytsc, data_len, b0, aad);

	cmparam.ulMACSize = IEEE80211_WEP_MICLEN;
	cmparam.ulNonceSize = AES_NONCE_LEN; /* N size */
	cmparam.ulAuthDataSize = aad[1]; /* A size */
	cmparam.ulDataSize = data_len;	/* data length; */
	cmparam.nonce = &b0[1]; /* N */
	cmparam.authData = &aad[2]; /* A */

	rv = aes_ccm_encrypt(&cmparam,
	    key->wk_key, key->wk_keylen,
	    pos, data_len, pos, data_len + IEEE80211_WEP_MICLEN);

	mp->b_wptr += ccmp.ic_trailer;

	return ((rv == CRYPTO_SUCCESS)? 1 : 0);
}

static int
ccmp_decrypt(struct ieee80211_key *key, uint64_t pn, mblk_t *mp, int hdrlen)
{
	struct ieee80211_frame *wh;
	int rv, data_len;
	uint8_t aad[2 * AES_BLOCK_LEN], b0[AES_BLOCK_LEN];
	uint8_t *pos;
	CK_AES_CCM_PARAMS cmparam;

	wh = (struct ieee80211_frame *)mp->b_rptr;
	data_len = MBLKL(mp) - (hdrlen + ccmp.ic_header);
	pos = mp->b_rptr + hdrlen + ccmp.ic_header;

	ccmp_init(wh, pn, data_len, b0, aad);

	cmparam.ulMACSize = IEEE80211_WEP_MICLEN; /* MIC = 8 */
	cmparam.ulNonceSize = AES_NONCE_LEN; /* N size */
	cmparam.ulAuthDataSize = aad[1]; /* A size */
	cmparam.ulDataSize = data_len;
	cmparam.nonce = &b0[1]; /* N */
	cmparam.authData = &aad[2]; /* A */

	rv = aes_ccm_decrypt(&cmparam,
	    key->wk_key, key->wk_keylen, pos, data_len, pos, data_len);

	return ((rv == CRYPTO_SUCCESS)? 1 : 0);
}
