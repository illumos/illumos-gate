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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * NTLM support functions
 *
 * Some code from the driver: smb_smb.c, smb_crypt.c
 */

#include <sys/errno.h>
#include <sys/types.h>
#include <sys/md4.h>
#include <sys/md5.h>

#include <ctype.h>
#include <stdlib.h>
#include <strings.h>

#include <netsmb/smb_lib.h>

#include "private.h"
#include "charsets.h"
#include "smb_crypt.h"
#include "ntlm.h"


/*
 * ntlm_compute_lm_hash
 *
 * Given a password, compute the LM hash.
 * a.k.a. ResponseKeyLM in [MS-NLMP]
 *
 * Output:
 *	hash: 16-byte "LanMan" (LM) hash (normally ctx->ct_lmhash)
 * Inputs:
 *	ucpw: User's password, upper-case UTF-8 string.
 *
 * Source: Implementing CIFS (Chris Hertel)
 *
 * P14 = UCPW padded to 14-bytes, or truncated (as needed)
 * result = Encrypt(Key=P14, Data=MagicString)
 */
int
ntlm_compute_lm_hash(uchar_t *hash, const char *pass)
{
	static const uchar_t M8[8] = "KGS!@#$%";
	uchar_t P14[14 + 1];
	int err;
	char *ucpw;

	/* First, convert the p/w to upper case. */
	ucpw = utf8_str_toupper(pass);
	if (ucpw == NULL)
		return (ENOMEM);

	/* Pad or truncate the upper-case P/W as needed. */
	bzero(P14, sizeof (P14));
	(void) strncpy((char *)P14, ucpw, 14);

	/* Compute the hash. */
	err = smb_encrypt_DES(hash, NTLM_HASH_SZ,
	    P14, 14, M8, 8);

	free(ucpw);
	return (err);
}

/*
 * ntlm_compute_nt_hash
 *
 * Given a password, compute the NT hash.
 * a.k.a. the ResponseKeyNT in [MS-NLMP]
 *
 * Output:
 *	hash: 16-byte "NT" hash (normally ctx->ct_nthash)
 * Inputs:
 *	upw: User's password, mixed-case UCS-2LE.
 *	pwlen: Size (in bytes) of upw
 */
int
ntlm_compute_nt_hash(uchar_t *hash, const char *pass)
{
	MD4_CTX ctx;
	uint16_t *unipw = NULL;
	int pwsz;

	/* First, convert the password to unicode. */
	unipw = convert_utf8_to_leunicode(pass);
	if (unipw == NULL)
		return (ENOMEM);
	pwsz = unicode_strlen(unipw) << 1;

	/* Compute the hash. */
	MD4Init(&ctx);
	MD4Update(&ctx, unipw, pwsz);
	MD4Final(hash, &ctx);

	free(unipw);
	return (0);
}

/*
 * ntlm_v1_response
 * a.k.a. DESL() in [MS-NLMP]
 *
 * Create an LM response from the given LM hash and challenge,
 * or an NTLM repsonse from a given NTLM hash and challenge.
 * Both response types are 24 bytes (NTLM_V1_RESP_SZ)
 */
static int
ntlm_v1_response(uchar_t *resp,
    const uchar_t *hash,
    const uchar_t *chal, int clen)
{
	uchar_t S21[21];
	int err;

	/*
	 * 14-byte LM Hash should be padded with 5 nul bytes to create
	 * a 21-byte string to be used in producing LM response
	 */
	bzero(&S21, sizeof (S21));
	bcopy(hash, S21, NTLM_HASH_SZ);

	/* padded LM Hash -> LM Response */
	err = smb_encrypt_DES(resp, NTLM_V1_RESP_SZ,
	    S21, 21, chal, clen);
	return (err);
}

/*
 * Calculate an NTLMv1 session key (16 bytes).
 */
static void
ntlm_v1_session_key(uchar_t *ssn_key, const uchar_t *nt_hash)
{
	MD4_CTX md4;

	MD4Init(&md4);
	MD4Update(&md4, nt_hash, NTLM_HASH_SZ);
	MD4Final(ssn_key, &md4);
}

/*
 * Compute both the LM(v1) response and the NTLM(v1) response,
 * and put them in the mbdata chains passed.  This allocates
 * mbuf chains in the output args, which the caller frees.
 */
int
ntlm_put_v1_responses(struct smb_ctx *ctx,
	struct mbdata *lm_mbp, struct mbdata *nt_mbp)
{
	uchar_t *lmresp, *ntresp;
	int err;

	/* Get mbuf chain for the LM response. */
	if ((err = mb_init_sz(lm_mbp, NTLM_V1_RESP_SZ)) != 0)
		return (err);

	/* Get mbuf chain for the NT response. */
	if ((err = mb_init_sz(nt_mbp, NTLM_V1_RESP_SZ)) != 0)
		return (err);

	/*
	 * Compute the NTLM response, derived from
	 * the challenge and the NT hash (a.k.a ResponseKeyNT)
	 */
	err = mb_fit(nt_mbp, NTLM_V1_RESP_SZ, (char **)&ntresp);
	if (err)
		return (err);
	bzero(ntresp, NTLM_V1_RESP_SZ);
	err = ntlm_v1_response(ntresp, ctx->ct_nthash,
	    ctx->ct_srv_chal, NTLM_CHAL_SZ);

	/*
	 * Compute the LM response, derived from
	 * the challenge and the ASCII password.
	 * Per. [MS-NLMP 3.3.1] if NoLmResponse,
	 * send the NT response for both NT+LM.
	 */
	err = mb_fit(lm_mbp, NTLM_V1_RESP_SZ, (char **)&lmresp);
	if (err)
		return (err);
	memcpy(lmresp, ntresp, NTLM_V1_RESP_SZ);
	if (ctx->ct_authflags & SMB_AT_LM1) {
		/* They asked to send the LM hash too. */
		err = ntlm_v1_response(lmresp, ctx->ct_lmhash,
		    ctx->ct_srv_chal, NTLM_CHAL_SZ);
		if (err)
			return (err);
	}

	/*
	 * Compute the session key
	 */
	ntlm_v1_session_key(ctx->ct_ssn_key, ctx->ct_nthash);

	return (err);
}

/*
 * Compute both the LM(v1x) response and the NTLM(v1x) response,
 * and put them in the mbdata chains passed.  "v1x" here refers to
 * NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY used with NTLMSSP,
 * also known by its shorter alias NTLMSSP_NEGOTIATE_NTLM2.
 * [MS-NLMP 3.3.1]
 *
 * This allocates mbuf chains in the output args (caller frees).
 */
int
ntlm_put_v1x_responses(struct smb_ctx *ctx,
	struct mbdata *lm_mbp, struct mbdata *nt_mbp)
{
	MD5_CTX context;
	uchar_t challenges[2 * NTLM_CHAL_SZ];
	uchar_t digest[NTLM_HASH_SZ];
	uchar_t *lmresp, *ntresp;
	int err;

	/* Get mbuf chain for the LM response. */
	if ((err = mb_init_sz(lm_mbp, NTLM_V1_RESP_SZ)) != 0)
		return (err);

	/* Get mbuf chain for the NT response. */
	if ((err = mb_init_sz(nt_mbp, NTLM_V1_RESP_SZ)) != 0)
		return (err);

	/*
	 * challenges = ConcatenationOf(ServerChallenge, ClientChallenge)
	 */
	memcpy(challenges, ctx->ct_srv_chal, NTLM_CHAL_SZ);
	memcpy(challenges + NTLM_CHAL_SZ, ctx->ct_clnonce, NTLM_CHAL_SZ);

	/*
	 * digest = MD5(challenges)
	 */
	MD5Init(&context);
	MD5Update(&context, challenges, sizeof (challenges));
	MD5Final(digest, &context);

	/*
	 * Compute the NTLM response, derived from the
	 * NT hash (a.k.a ResponseKeyNT) and the first
	 * 8 bytes of the MD5 digest of the challenges.
	 */
	err = mb_fit(nt_mbp, NTLM_V1_RESP_SZ, (char **)&ntresp);
	if (err)
		return (err);
	bzero(ntresp, NTLM_V1_RESP_SZ);
	err = ntlm_v1_response(ntresp, ctx->ct_nthash,
	    digest, NTLM_CHAL_SZ);

	/*
	 * With "Extended Session Security", the LM response
	 * is simply the client challenge (nonce) padded out.
	 */
	err = mb_fit(lm_mbp, NTLM_V1_RESP_SZ, (char **)&lmresp);
	if (err)
		return (err);
	bzero(lmresp, NTLM_V1_RESP_SZ);
	memcpy(lmresp, ctx->ct_clnonce, NTLM_CHAL_SZ);

	/*
	 * Compute the session key
	 */
	ntlm_v1_session_key(ctx->ct_ssn_key, ctx->ct_nthash);

	return (err);
}

/*
 * A variation on HMAC-MD5 known as HMACT64 is used by Windows systems.
 * The HMACT64() function is the same as the HMAC-MD5() except that
 * it truncates the input key to 64 bytes rather than hashing it down
 * to 16 bytes using the MD5() function.
 *
 * Output: digest (16-bytes)
 */
static void
HMACT64(uchar_t *digest,
    const uchar_t *key, size_t key_len,
    const uchar_t *data, size_t data_len)
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
 * and the destination (machine or domain name).
 *
 * Output:
 *	v2hash: 16-byte NTLMv2 hash.
 * Inputs:
 *	v1hash: 16-byte NTLMv1 hash.
 *	user: User name, UPPER-case UTF-8 string.
 *	destination: Domain or server, MIXED-case UTF-8 string.
 */
static int
ntlm_v2_hash(uchar_t *v2hash, const uchar_t *v1hash,
    const char *user, const char *destination)
{
	int ulen, dlen;
	size_t ucs2len;
	uint16_t *ucs2data = NULL;
	char *utf8data = NULL;
	int err = ENOMEM;

	/*
	 * v2hash = HMACT64(v1hash, 16, concat(upcase(user), dest))
	 * where "dest" is the domain or server name ("target name")
	 * Note: user name is converted to upper-case by the caller.
	 */

	/* utf8data = concat(user, dest) */
	ulen = strlen(user);
	dlen = strlen(destination);
	utf8data = malloc(ulen + dlen + 1);
	if (utf8data == NULL)
		goto out;
	bcopy(user, utf8data, ulen);
	bcopy(destination, utf8data + ulen, dlen + 1);

	/* Convert to UCS-2LE */
	ucs2data = convert_utf8_to_leunicode(utf8data);
	if (ucs2data == NULL)
		goto out;
	ucs2len = 2 * unicode_strlen(ucs2data);

	HMACT64(v2hash, v1hash, NTLM_HASH_SZ,
	    (uchar_t *)ucs2data, ucs2len);
	err = 0;
out:
	if (ucs2data)
		free(ucs2data);
	if (utf8data)
		free(utf8data);
	return (err);
}

/*
 * Compute a partial LMv2 or NTLMv2 response (first 16-bytes).
 * The full response is composed by the caller by
 * appending the client_data to the returned hash.
 *
 * Output:
 *	rhash: _partial_ LMv2/NTLMv2 response (first 16-bytes)
 * Inputs:
 *	v2hash: 16-byte NTLMv2 hash.
 *	C8: Challenge from server (8 bytes)
 *	client_data: client nonce (for LMv2) or the
 *	  "blob" from ntlm_build_target_info (NTLMv2)
 */
static int
ntlm_v2_resp_hash(uchar_t *rhash,
    const uchar_t *v2hash, const uchar_t *C8,
    const uchar_t *client_data, size_t cdlen)
{
	size_t dlen;
	uchar_t *data = NULL;

	/* data = concat(C8, client_data) */
	dlen = 8 + cdlen;
	data = malloc(dlen);
	if (data == NULL)
		return (ENOMEM);
	bcopy(C8, data, 8);
	bcopy(client_data, data + 8, cdlen);

	HMACT64(rhash, v2hash, NTLM_HASH_SZ, data, dlen);

	free(data);
	return (0);
}

/*
 * Calculate an NTLMv2 session key (16 bytes).
 */
static void
ntlm_v2_session_key(uchar_t *ssn_key,
	const uchar_t *v2hash,
	const uchar_t *ntresp)
{

	/* session key uses only 1st 16 bytes of ntresp */
	HMACT64(ssn_key, v2hash, NTLM_HASH_SZ, ntresp, NTLM_HASH_SZ);
}


/*
 * Compute both the LMv2 response and the NTLMv2 response,
 * and put them in the mbdata chains passed.  This allocates
 * mbuf chains in the output args, which the caller frees.
 * Also computes the session key.
 */
int
ntlm_put_v2_responses(struct smb_ctx *ctx, struct mbdata *ti_mbp,
	struct mbdata *lm_mbp, struct mbdata *nt_mbp)
{
	uchar_t *lmresp, *ntresp;
	int err;
	char *ucuser = NULL;	/* upper-case user name */
	uchar_t v2hash[NTLM_HASH_SZ];
	struct mbuf *tim = ti_mbp->mb_top;

	/*
	 * Convert the user name to upper-case, as
	 * that's what's used when computing LMv2
	 * and NTLMv2 responses.  Note that the
	 * domain name is NOT upper-cased!
	 */
	if (ctx->ct_user[0] == '\0')
		return (EINVAL);
	ucuser = utf8_str_toupper(ctx->ct_user);
	if (ucuser == NULL)
		return (ENOMEM);

	if ((err = mb_init(lm_mbp)) != 0)
		goto out;
	if ((err = mb_init(nt_mbp)) != 0)
		goto out;

	/*
	 * Compute the NTLMv2 hash
	 */
	err = ntlm_v2_hash(v2hash, ctx->ct_nthash,
	    ucuser, ctx->ct_domain);
	if (err)
		goto out;

	/*
	 * Compute the LMv2 response, derived from
	 * the v2hash, the server challenge, and
	 * the client nonce (random bits).
	 *
	 * We compose it from two parts:
	 *	1: 16-byte response hash
	 *	2: Client nonce
	 */
	lmresp = mb_reserve(lm_mbp, NTLM_HASH_SZ);
	err = ntlm_v2_resp_hash(lmresp,
	    v2hash, ctx->ct_srv_chal,
	    ctx->ct_clnonce, NTLM_CHAL_SZ);
	if (err)
		goto out;
	mb_put_mem(lm_mbp, ctx->ct_clnonce, NTLM_CHAL_SZ, MB_MSYSTEM);

	/*
	 * Compute the NTLMv2 response, derived
	 * from the server challenge and the
	 * "target info." blob passed in.
	 *
	 * Again composed from two parts:
	 *	1: 16-byte response hash
	 *	2: "target info." blob
	 */
	ntresp = mb_reserve(nt_mbp, NTLM_HASH_SZ);
	err = ntlm_v2_resp_hash(ntresp,
	    v2hash, ctx->ct_srv_chal,
	    (uchar_t *)tim->m_data, tim->m_len);
	if (err)
		goto out;
	mb_put_mem(nt_mbp, tim->m_data, tim->m_len, MB_MSYSTEM);

	/*
	 * Compute the session key
	 */
	ntlm_v2_session_key(ctx->ct_ssn_key, v2hash, ntresp);

out:
	if (err) {
		mb_done(lm_mbp);
		mb_done(nt_mbp);
	}
	free(ucuser);

	return (err);
}

/*
 * Helper for ntlm_build_target_info below.
 * Put a name in the NTLMv2 "target info." blob.
 */
static void
smb_put_blob_name(struct mbdata *mbp, char *name, int type)
{
	uint16_t *ucs = NULL;
	int nlen;

	if (name)
		ucs = convert_utf8_to_leunicode(name);
	if (ucs)
		nlen = unicode_strlen(ucs);
	else
		nlen = 0;

	nlen <<= 1;	/* length in bytes, without null. */

	mb_put_uint16le(mbp, type);
	mb_put_uint16le(mbp, nlen);
	mb_put_mem(mbp, (char *)ucs, nlen, MB_MSYSTEM);

	if (ucs)
		free(ucs);
}

/*
 * Build an NTLMv2 "target info." blob.  When called from NTLMSSP,
 * the list of names comes from the Type 2 message.  Otherwise,
 * we create the name list here.
 */
int
ntlm_build_target_info(struct smb_ctx *ctx, struct mbuf *names,
	struct mbdata *mbp)
{
	struct timeval now;
	uint64_t nt_time;

	char *ucdom = NULL;	/* user's domain */
	int err;

	/* Get mbuf chain for the "target info". */
	if ((err = mb_init(mbp)) != 0)
		return (err);

	/*
	 * Get the "NT time" for the target info header.
	 */
	(void) gettimeofday(&now, 0);
	smb_time_local2NT(&now, 0, &nt_time);

	/*
	 * Build the "target info." block.
	 *
	 * Based on information at:
	 * http://davenport.sourceforge.net/ntlm.html#theNtlmv2Response
	 *
	 * First the fixed-size part.
	 */
	mb_put_uint32le(mbp, 0x101);	/* Blob signature */
	mb_put_uint32le(mbp, 0);		/* reserved */
	mb_put_uint64le(mbp, nt_time);	/* NT time stamp */
	mb_put_mem(mbp, ctx->ct_clnonce, NTLM_CHAL_SZ, MB_MSYSTEM);
	mb_put_uint32le(mbp, 0);		/* unknown */

	/*
	 * Now put the list of names, either from the
	 * NTLMSSP Type 2 message or composed here.
	 */
	if (names) {
		err = mb_put_mem(mbp, names->m_data, names->m_len, MB_MSYSTEM);
	} else {
		/* Get upper-case names. */
		ucdom  = utf8_str_toupper(ctx->ct_domain);
		if (ucdom == NULL) {
			err = ENOMEM;
			goto out;
		}
		smb_put_blob_name(mbp, ucdom, NAMETYPE_DOMAIN_NB);
		smb_put_blob_name(mbp, NULL, NAMETYPE_EOL);
		/* OK, that's the whole "target info." blob! */
	}
	err = 0;

out:
	free(ucdom);
	return (err);
}

/*
 * Build the MAC key (for SMB signing)
 */
int
ntlm_build_mac_key(struct smb_ctx *ctx, struct mbdata *ntresp_mbp)
{
	struct mbuf *m;
	size_t len;
	char *p;

	/*
	 * MAC_key = concat(session_key, nt_response)
	 */
	m = ntresp_mbp->mb_top;
	len = NTLM_HASH_SZ + m->m_len;
	if ((p = malloc(len)) == NULL)
		return (ENOMEM);
	ctx->ct_mackeylen = len;
	ctx->ct_mackey = p;
	memcpy(p, ctx->ct_ssn_key, NTLM_HASH_SZ);
	memcpy(p + NTLM_HASH_SZ, m->m_data, m->m_len);

	return (0);
}

/*
 * Helper for ntlmssp_put_type3 - Build the "key exchange key"
 * used when we have both NTLM(v1) and NTLMSSP_NEGOTIATE_NTLM2.
 * HMAC_MD5(SessionBaseKey, concat(ServerChallenge, LmResponse[0..7]))
 */
void
ntlm2_kxkey(struct smb_ctx *ctx, struct mbdata *lm_mbp, uchar_t *kxkey)
{
	uchar_t data[NTLM_HASH_SZ];
	uchar_t *p = mtod(lm_mbp->mb_top, uchar_t *);

	/* concat(ServerChallenge, LmResponse[0..7]) */
	memcpy(data, ctx->ct_srv_chal, NTLM_CHAL_SZ);
	memcpy(data + NTLM_CHAL_SZ, p, NTLM_CHAL_SZ);

	/* HMAC_MD5(SessionBaseKey, concat(...)) */
	HMACT64(kxkey, ctx->ct_ssn_key, NTLM_HASH_SZ,
	    data, NTLM_HASH_SZ);
}
