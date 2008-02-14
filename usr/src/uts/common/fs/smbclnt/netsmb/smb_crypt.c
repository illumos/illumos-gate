/*
 * Copyright (c) 2000-2001, Boris Popov
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
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by Boris Popov.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: smb_crypt.c,v 1.13 2005/01/26 23:50:50 lindak Exp $
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/proc.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <sys/md4.h>
#include <sys/md5.h>
#include <sys/des.h>
#include <sys/kmem.h>
#include <sys/crypto/api.h>
#include <sys/crypto/common.h>
#include <sys/cmn_err.h>

#include <netsmb/smb_osdep.h>
#include <netsmb/smb.h>
#include <netsmb/smb_conn.h>
#include <netsmb/smb_subr.h>
#include <netsmb/smb_dev.h>

static uchar_t N8[] = {0x4b, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25};

static void
smb_E(const uchar_t *key, uchar_t *data, uchar_t *dest)
{
	int rv;
	uchar_t kk[8];
	crypto_mechanism_t mech;
	crypto_data_t	d1, d2;
	crypto_key_t keyt;


	bzero(&d1, sizeof (crypto_data_t));
	bzero(&d2, sizeof (crypto_data_t));
	/*
	 * 'Key' here is the username - 7-bytes. Convert that to
	 * to a 8-byte string.
	 */
	kk[0] = key[0] & 0xfe;
	kk[1] = key[0] << 7 | (key[1] >> 1 & 0xfe);
	kk[2] = key[1] << 6 | (key[2] >> 2 & 0xfe);
	kk[3] = key[2] << 5 | (key[3] >> 3 & 0xfe);
	kk[4] = key[3] << 4 | (key[4] >> 4 & 0xfe);
	kk[5] = key[4] << 3 | (key[5] >> 5 & 0xfe);
	kk[6] = key[5] << 2 | (key[6] >> 6 & 0xfe);
	kk[7] = key[6] << 1;

	keyt.ck_format = CRYPTO_KEY_RAW;
	keyt.ck_length = 8 * 8;
	keyt.ck_data = (void *)kk;

	d1.cd_format = CRYPTO_DATA_RAW;
	d1.cd_length = 8;
	d1.cd_offset = 0;
	d1.cd_raw.iov_len = 8;
	d1.cd_raw.iov_base = (void *)data;

	d2.cd_format = CRYPTO_DATA_RAW;
	d2.cd_length = 8;
	d2.cd_offset = 0;
	d2.cd_raw.iov_len = 8;
	d2.cd_raw.iov_base = (void *)dest;

	mech.cm_type = crypto_mech2id(SUN_CKM_DES_ECB);
	if (mech.cm_type == CRYPTO_MECH_INVALID)
		cmn_err(CE_NOTE, "Invalid algorithm\n");
	mech.cm_param = NULL;
	mech.cm_param_len = 0;

	rv = crypto_encrypt(&mech, &d1, &keyt, NULL, &d2, NULL);
	if (rv != CRYPTO_SUCCESS)
		SMBSDEBUG("crypto_encrypt failed.\n");
}

/*
 * Compute the LM hash, which is used to compute the LM response.
 */
void
smb_oldlm_hash(const char *apwd, uchar_t *lmhash)
{
	uchar_t P14[14+1];

	/* Convert apwd to upper case, zero extend. */
	bzero(P14, sizeof (P14));
	smb_toupper(apwd, (char *)P14, 14);

	/*
	 * lmhash = concat(Ex(P14, N8), zeros(5));
	 */
	bzero(lmhash, 21);
	smb_E(P14, N8, lmhash);
	smb_E(P14 + 7, N8, lmhash + 8);
}

/*
 * Compute an LM or NTLM response given the LM or NTLM hash and a
 * challenge.  Note: This now replaces smb_ntlmresponse which
 * used to compute a different hash and then do the same
 * response computation as found here.  Now that the hash
 * is computed by the caller, this is used for both.
 */
int
smb_lmresponse(const uchar_t *hash, uchar_t *C8, uchar_t *RN)
{

	smb_E(hash, C8, RN);
	smb_E(hash + 7, C8, RN + 8);
	smb_E(hash + 14, C8, RN + 16);

	return (0);
}

/*
 * Compute the NTLMv1 hash, which is used to compute both NTLMv1 and
 * NTLMv2 responses.
 */
void
smb_ntlmv1hash(const char *apwd, uchar_t *v1hash)
{
	u_int16_t *unipwd;
	MD4_CTX *ctxp;
	size_t alen, unilen;

	alen = strlen(apwd);
	unipwd = kmem_alloc(alen * 2, KM_SLEEP);
	/*
	 * v1hash = concat(MD4(U(apwd)), zeros(5));
	 */
	unilen = smb_strtouni(unipwd, apwd, alen, UCONV_IGNORE_NULL);

	ctxp = kmem_alloc(sizeof (MD4_CTX), KM_SLEEP);
	MD4Init(ctxp);
	MD4Update(ctxp, unipwd, unilen);
	bzero(v1hash, 21);
	MD4Final(v1hash, ctxp);

	kmem_free(ctxp, sizeof (MD4_CTX));
	kmem_free(unipwd, alen * 2);
}

/*
 * Note: smb_ntlmresponse() is gone.
 * Use: smb_lmresponse() instead.
 */

static void
HMACT64(const uchar_t *key, size_t key_len, const uchar_t *data,
    size_t data_len, uchar_t *digest)
{
	MD5_CTX context;
	uchar_t k_ipad[64];	/* inner padding - key XORd with ipad */
	uchar_t k_opad[64];	/* outer padding - key XORd with opad */
	int i;

	/* if key is longer than 64 bytes use only the first 64 bytes */
	if (key_len > 64)
		key_len = 64;

	/*
	 * The HMAC-MD5 (and HMACT64) transform looks like:
	 *
	 * MD5(K XOR opad, MD5(K XOR ipad, data))
	 *
	 * where K is an n byte key
	 * ipad is the byte 0x36 repeated 64 times
	 * opad is the byte 0x5c repeated 64 times
	 * and data is the data being protected.
	 */

	/* start out by storing key in pads */
	bzero(k_ipad, sizeof (k_ipad));
	bzero(k_opad, sizeof (k_opad));
	bcopy(key, k_ipad, key_len);
	bcopy(key, k_opad, key_len);

	/* XOR key with ipad and opad values */
	for (i = 0; i < 64; i++) {
		k_ipad[i] ^= 0x36;
		k_opad[i] ^= 0x5c;
	}

	/*
	 * perform inner MD5
	 */
	MD5Init(&context);			/* init context for 1st pass */
	MD5Update(&context, k_ipad, 64);	/* start with inner pad */
	MD5Update(&context, data, data_len);	/* then data of datagram */
	MD5Final(digest, &context);		/* finish up 1st pass */

	/*
	 * perform outer MD5
	 */
	MD5Init(&context);			/* init context for 2nd pass */
	MD5Update(&context, k_opad, 64);	/* start with outer pad */
	MD5Update(&context, digest, 16);	/* then results of 1st hash */
	MD5Final(digest, &context);		/* finish up 2nd pass */
}

/*
 * Compute an NTLMv2 response given the 21 byte NTLM(v1) hash,
 * the user name, the destination workgroup/domain name,
 * a challenge, and the blob.
 */
int
smb_ntlmv2response(const uchar_t *v1hash, const uchar_t *user,
    const uchar_t *destination, uchar_t *C8, const uchar_t *blob,
    size_t bloblen, uchar_t **RN, size_t *RNlen)
{
	u_int16_t *uniuser, *unidest;
	size_t uniuserlen, unidestlen;
	uchar_t v2hash[16];
	size_t len;
	size_t datalen;
	uchar_t *data, *data1;
	size_t v2resplen;
	uchar_t *v2resp;

	/*
	 * v2hash=HMACT64(v1hash, 16, concat(upcase(user), upcase(destination))
	 * We assume that user and destination are supplied to us as
	 * upper-case UTF-8.
	 */
	len = strlen((char *)user);
	uniuser = kmem_alloc(len * sizeof (u_int16_t) + 1, KM_SLEEP);
	uniuserlen = smb_strtouni(uniuser, (char *)user, len,
	    UCONV_IGNORE_NULL);
	len = strlen((char *)destination);
	unidest = kmem_alloc(len * sizeof (u_int16_t) + 1, KM_SLEEP);
	unidestlen = smb_strtouni(unidest, (char *)destination, len,
	    UCONV_IGNORE_NULL);
	datalen = uniuserlen + unidestlen;
	data = kmem_alloc(datalen, KM_SLEEP);
	bcopy(uniuser, data, uniuserlen);
	bcopy(unidest, data + uniuserlen, unidestlen);
	kmem_free(uniuser, strlen((char *)user) * sizeof (u_int16_t) + 1);
	kmem_free(unidest, len * sizeof (u_int16_t) + 1);
	HMACT64(v1hash, 16, data, datalen, v2hash);
	kmem_free(data, datalen);

	datalen = 8 + bloblen;
	data1 = kmem_alloc(datalen, KM_SLEEP);
	bcopy(C8, data1, 8);
	bcopy(blob, data1 + 8, bloblen);
	v2resplen = 16 + bloblen;
	v2resp = kmem_alloc(v2resplen, KM_SLEEP);
	HMACT64(v2hash, 16, data1, datalen, v2resp);
	kmem_free(data1, datalen);
	bcopy(blob, v2resp + 16, bloblen);
	*RN = v2resp;
	*RNlen = v2resplen;
	return (0);
}
