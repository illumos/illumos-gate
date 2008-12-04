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

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

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
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/sdt.h>

#include <netsmb/smb_osdep.h>
#include <netsmb/smb.h>
#include <netsmb/smb_conn.h>
#include <netsmb/smb_subr.h>
#include <netsmb/smb_dev.h>
#include <netsmb/smb_rq.h>

#ifdef DEBUG
/*
 * Set this to a small number to debug sequence numbers
 * that seem to get out of step.
 */
int nsmb_signing_fudge = 0;
#endif

/* Mechanism definitions */
static  crypto_mechanism_t crypto_mech_md5 = { CRYPTO_MECH_INVALID };
static  crypto_mechanism_t crypto_mech_des = { CRYPTO_MECH_INVALID };

void
smb_crypto_mech_init(void)
{
	crypto_mech_des.cm_type = crypto_mech2id(SUN_CKM_DES_ECB);
	crypto_mech_md5.cm_type = crypto_mech2id(SUN_CKM_MD5);
}

static void
smb_E(const uchar_t *key, const uchar_t *data, uchar_t *dest)
{
	int rv;
	uchar_t kk[8];
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

	/* Checked this in callers */
	ASSERT(crypto_mech_des.cm_type != CRYPTO_MECH_INVALID);

	rv = crypto_encrypt(&crypto_mech_des, &d1, &keyt, NULL, &d2, NULL);
	if (rv != CRYPTO_SUCCESS)
		SMBSDEBUG("crypto_encrypt failed.\n");
}

/*
 * Compute the LM hash, which is used to compute the LM response.
 */
void
smb_oldlm_hash(const char *apwd, uchar_t *lmhash)
{
	static const uchar_t N8[] = "KGS!@#$%";
	uchar_t P14[14+1];

	/* In case we error out. */
	bzero(lmhash, 21);

	/* Note ASSERT in smb_E */
	if (crypto_mech_des.cm_type == CRYPTO_MECH_INVALID) {
		SMBSDEBUG("crypto_mech_des invalid\n");
		return;
	}

	/* Convert apwd to upper case, zero extend. */
	bzero(P14, sizeof (P14));
	smb_toupper(apwd, (char *)P14, 14);

	/*
	 * lmhash = concat(Ex(P14, N8), zeros(5));
	 */
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
smb_lmresponse(const uchar_t *hash, const uchar_t *C8, uchar_t *RN)
{

	/* In case we error out. */
	bzero(RN, 24);

	/* Note ASSERT in smb_E */
	if (crypto_mech_des.cm_type == CRYPTO_MECH_INVALID) {
		SMBSDEBUG("crypto_mech_des invalid\n");
		return (ENOTSUP);
	}

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
 * Compute an NTLMv2 hash given the NTLMv1 hash, the user name,
 * the destination machine or domain name, and a challenge.
 */
void
smb_ntlmv2hash(const uchar_t *v1hash, const char *user,
    const char *destination, uchar_t *v2hash)
{
	u_int16_t *uniuser, *unidest;
	size_t uniuserlen, unidestlen;
	size_t uniuser_sz, unidest_sz;
	int len;
	size_t datalen;
	uchar_t *data;

	/*
	 * v2hash = HMACT64(v1hash, 16, concat(upcase(user), upcase(dest))
	 * where "dest" is the domain or server name ("target name")
	 * We assume that user and destination are supplied to us as
	 * upper-case UTF-8.
	 */
	len = strlen((char *)user);
	uniuser_sz = (len + 1) * sizeof (u_int16_t);
	uniuser = kmem_alloc(uniuser_sz, KM_SLEEP);
	uniuserlen = smb_strtouni(uniuser, (char *)user, len,
	    UCONV_IGNORE_NULL);

	len = strlen((char *)destination);
	unidest_sz = (len + 1) * sizeof (u_int16_t);
	unidest = kmem_alloc(unidest_sz, KM_SLEEP);
	unidestlen = smb_strtouni(unidest, (char *)destination, len,
	    UCONV_IGNORE_NULL);

	datalen = uniuserlen + unidestlen;
	data = kmem_alloc(datalen, KM_SLEEP);
	bcopy(uniuser, data, uniuserlen);
	bcopy(unidest, data + uniuserlen, unidestlen);
	kmem_free(uniuser, uniuser_sz);
	kmem_free(unidest, unidest_sz);

	HMACT64(v1hash, 16, data, datalen, v2hash);
	kmem_free(data, datalen);
}

/*
 * Compute an NTLMv2 response given the 16 byte NTLMv2 hash,
 * a challenge, and the blob.
 */
int
smb_ntlmv2response(const uchar_t *v2hash, const uchar_t *C8,
    const uchar_t *blob, size_t bloblen, uchar_t **RN, size_t *RNlen)
{
	size_t datalen;
	uchar_t *data;
	size_t v2resplen;
	uchar_t *v2resp;

	datalen = 8 + bloblen;
	data = kmem_alloc(datalen, KM_SLEEP);
	bcopy(C8, data, 8);
	bcopy(blob, data + 8, bloblen);
	v2resplen = 16 + bloblen;
	v2resp = kmem_alloc(v2resplen, KM_SLEEP);
	HMACT64(v2hash, 16, data, datalen, v2resp);
	kmem_free(data, datalen);
	bcopy(blob, v2resp + 16, bloblen);
	*RN = v2resp;
	*RNlen = v2resplen;

	return (0);
}

/*
 * Calculate NTLMv2 message authentication code (MAC) key for
 * this VC and store it in vc_mackey (allocated here).
 *
 * The MAC key is the concatenation of the 16 byte session key
 * and the NT response.
 *
 * XXX: Should factor out computation of the session key
 * from both this and the next function, and then use a
 * common function to compute the MAC key (which then
 * can do simple concatenation).  Later.
 */
int
smb_calcv2mackey(struct smb_vc *vcp, const uchar_t *v2hash,
    const uchar_t *ntresp, size_t resplen)
{
	uchar_t sesskey[16];

	if (vcp->vc_mackey != NULL) {
		SMBSDEBUG("Already have MAC key!\n");
		return (0);
	}

	/* session key uses only 1st 16 bytes of ntresp */
	HMACT64(v2hash, 16, ntresp, (size_t)16, sesskey);

	vcp->vc_mackeylen = 16 + resplen;
	vcp->vc_mackey = kmem_alloc(vcp->vc_mackeylen, KM_SLEEP);
	/* Free in: smb_vc_free, smb_smb_negotiate */

	bcopy(sesskey, vcp->vc_mackey, 16);
	bcopy(ntresp, vcp->vc_mackey + 16, (int)resplen);

#ifdef DTRACE_PROBE
	DTRACE_PROBE2(smb_mac_key, (char *), vcp->vc_mackey,
	    int, vcp->vc_mackeylen);
#endif

	return (0);
}

/*
 * Calculate message authentication code (MAC) key for virtual circuit.
 * The MAC key is the concatenation of the 16 byte session key
 * and the 24 byte challenge response.
 */
/*ARGSUSED*/
int
smb_calcmackey(struct smb_vc *vcp, const uchar_t *v2hash,
    const uchar_t *ntresp, size_t resplen)
{
	MD4_CTX md4;

	if (vcp->vc_mackey != NULL) {
		SMBSDEBUG("Already have MAC key!\n");
		return (0);
	}

	vcp->vc_mackeylen = 16 + 24;
	vcp->vc_mackey = kmem_alloc(vcp->vc_mackeylen, KM_SLEEP);
	/* Free in: smb_vc_free, smb_smb_negotiate */

	/*
	 * Calculate session key:
	 */
	MD4Init(&md4);
	MD4Update(&md4, vcp->vc_nthash, 16);
	MD4Final(vcp->vc_mackey, &md4);

	/* Response to challenge. */
	bcopy(ntresp, vcp->vc_mackey + 16, 24);

#ifdef DTRACE_PROBE
	DTRACE_PROBE2(smb_mac_key, (char *), vcp->vc_mackey,
	    int, vcp->vc_mackeylen);
#endif

	return (0);
}

#define	SMBSIGLEN	8	/* SMB signature length */
#define	SMBSIGOFF	14	/* SMB signature offset */

/*
 * Compute HMAC-MD5 of packet data, using the stored MAC key.
 *
 * See similar code for the server side:
 * uts/common/fs/smbsrv/smb_signing.c : smb_sign_calc
 */
static int
smb_compute_MAC(struct smb_vc *vcp, mblk_t *mp,
	uint32_t seqno, uchar_t *signature)
{
	crypto_context_t crypto_ctx;
	crypto_data_t key;
	crypto_data_t data;
	crypto_data_t digest;
	uchar_t mac[16];
	int status;
	/*
	 * This union is a little bit of trickery to:
	 * (1) get the sequence number int aligned, and
	 * (2) reduce the number of digest calls, at the
	 * cost of a copying 32 bytes instead of 8.
	 * Both sides of this union are 2+32 bytes.
	 */
	union {
		struct {
			uint8_t skip[2]; /* not used - just alignment */
			uint8_t raw[SMB_HDRLEN];  /* header length (32) */
		} r;
		struct {
			uint8_t skip[2]; /* not used - just alignment */
			uint8_t hdr[SMBSIGOFF]; /* sig. offset (14) */
			uint32_t sig[2]; /* MAC signature, aligned! */
			uint16_t ids[5]; /* pad, Tid, Pid, Uid, Mid */
		} s;
	} smbhdr;

	ASSERT(mp != NULL);
	ASSERT(MBLKL(mp) >= SMB_HDRLEN);
	ASSERT(vcp->vc_mackey != NULL);

	/*
	 * Make an aligned copy of the SMB header
	 * and fill in the sequence number.
	 */
	bcopy(mp->b_rptr, smbhdr.r.raw, SMB_HDRLEN);
	smbhdr.s.sig[0] = htolel(seqno);
	smbhdr.s.sig[1] = 0;

	/*
	 * Compute the MAC: MD5(concat(Key, message))
	 */
	if (crypto_mech_md5.cm_type == CRYPTO_MECH_INVALID) {
		SMBSDEBUG("crypto_mech_md5 invalid\n");
		return (CRYPTO_MECHANISM_INVALID);
	}
	status = crypto_digest_init(&crypto_mech_md5, &crypto_ctx, 0);
	if (status != CRYPTO_SUCCESS)
		return (status);

	/* Digest the MAC Key */
	key.cd_format = CRYPTO_DATA_RAW;
	key.cd_offset = 0;
	key.cd_length = vcp->vc_mackeylen;
	key.cd_miscdata = 0;
	key.cd_raw.iov_base = (char *)vcp->vc_mackey;
	key.cd_raw.iov_len = vcp->vc_mackeylen;
	status = crypto_digest_update(crypto_ctx, &key, 0);
	if (status != CRYPTO_SUCCESS)
		return (status);

	/* Digest the (copied) SMB header */
	data.cd_format = CRYPTO_DATA_RAW;
	data.cd_offset = 0;
	data.cd_length = SMB_HDRLEN;
	data.cd_miscdata = 0;
	data.cd_raw.iov_base = (char *)smbhdr.r.raw;
	data.cd_raw.iov_len = SMB_HDRLEN;
	status = crypto_digest_update(crypto_ctx, &data, 0);
	if (status != CRYPTO_SUCCESS)
		return (status);

	/* Digest rest of the SMB message. */
	data.cd_format = CRYPTO_DATA_MBLK;
	data.cd_offset = SMB_HDRLEN;
	data.cd_length = msgdsize(mp) - SMB_HDRLEN;
	data.cd_miscdata = 0;
	data.cd_mp = mp;
	status = crypto_digest_update(crypto_ctx, &data, 0);
	if (status != CRYPTO_SUCCESS)
		return (status);

	/* Final */
	digest.cd_format = CRYPTO_DATA_RAW;
	digest.cd_offset = 0;
	digest.cd_length = sizeof (mac);
	digest.cd_miscdata = 0;
	digest.cd_raw.iov_base = (char *)mac;
	digest.cd_raw.iov_len = sizeof (mac);
	status = crypto_digest_final(crypto_ctx, &digest, 0);
	if (status != CRYPTO_SUCCESS)
		return (status);

	/*
	 * Finally, store the signature.
	 * (first 8 bytes of the mac)
	 */
	if (signature)
		bcopy(mac, signature, SMBSIGLEN);

	return (0);
}

/*
 * Sign a request with HMAC-MD5.
 */
int
smb_rq_sign(struct smb_rq *rqp)
{
	struct smb_vc *vcp = rqp->sr_vc;
	mblk_t *mp = rqp->sr_rq.mb_top;
	uint8_t *sigloc;
	int status;

	/*
	 * Our mblk allocation ensures this,
	 * but just in case...
	 */
	if (MBLKL(mp) < SMB_HDRLEN) {
		if (!pullupmsg(mp, SMB_HDRLEN))
			return (0);
	}
	sigloc = mp->b_rptr + SMBSIGOFF;

	if (vcp->vc_mackey == NULL) {
		/*
		 * Signing is required, but we have no key yet
		 * fill in with the magic fake signing value.
		 * This happens with SPNEGO, NTLMSSP, ...
		 */
		bcopy("BSRSPLY", sigloc, 8);
		return (0);
	}

	/*
	 * This will compute the MAC and store it
	 * directly into the message at sigloc.
	 */
	status = smb_compute_MAC(vcp, mp, rqp->sr_seqno, sigloc);
	if (status != CRYPTO_SUCCESS) {
		SMBSDEBUG("Crypto error %d", status);
		bzero(sigloc, SMBSIGLEN);
		return (ENOTSUP);
	}
	return (0);
}

/*
 * Verify reply signature.
 */
int
smb_rq_verify(struct smb_rq *rqp)
{
	struct smb_vc *vcp = rqp->sr_vc;
	mblk_t *mp = rqp->sr_rp.md_top;
	uint8_t sigbuf[SMBSIGLEN];
	uint8_t *sigloc;
	int status;
	int fudge;

	/*
	 * Note vc_mackey and vc_mackeylen gets initialized by
	 * smb_smb_ssnsetup.
	 */
	if (vcp->vc_mackey == NULL) {
		SMBSDEBUG("no mac key\n");
		return (0);
	}

	/*
	 * Let caller deal with empty reply or short messages by
	 * returning zero.  Caller will fail later, in parsing.
	 */
	if (mp == NULL) {
		SMBSDEBUG("empty reply\n");
		return (0);
	}
	if (MBLKL(mp) < SMB_HDRLEN) {
		if (!pullupmsg(mp, SMB_HDRLEN))
			return (0);
	}
	sigloc = mp->b_rptr + SMBSIGOFF;

	SMBSDEBUG("sr_rseqno = 0x%x\n", rqp->sr_rseqno);

	status = smb_compute_MAC(vcp, mp, rqp->sr_rseqno, sigbuf);
	if (status != CRYPTO_SUCCESS) {
		SMBSDEBUG("Crypto error %d", status);
		/*
		 * If we can't compute a MAC, then there's
		 * no point trying other seqno values.
		 */
		return (EBADRPC);
	}

	/*
	 * Compare the computed signature with the
	 * one found in the message (at sigloc)
	 */
	if (bcmp(sigbuf, sigloc, SMBSIGLEN) == 0)
		return (0);

	SMBSDEBUG("BAD signature, MID=0x%x\n", rqp->sr_mid);

#ifdef DEBUG
	/*
	 * For diag purposes, we check whether the client/server idea
	 * of the sequence # has gotten a bit out of sync.
	 */
	for (fudge = 1; fudge <= nsmb_signing_fudge; fudge++) {
		smb_compute_MAC(vcp, mp, rqp->sr_rseqno + fudge, sigbuf);
		if (bcmp(sigbuf, sigloc, SMBSIGLEN) == 0)
			break;
		smb_compute_MAC(vcp, mp, rqp->sr_rseqno - fudge, sigbuf);
		if (bcmp(sigbuf, sigloc, SMBSIGLEN) == 0) {
			fudge = -fudge;
			break;
		}
	}
	if (fudge <= nsmb_signing_fudge) {
		SMBSDEBUG("sr_rseqno=%d, but %d would have worked\n",
		    rqp->sr_rseqno, rqp->sr_rseqno + fudge);
	}
#endif
	return (EBADRPC);
}
