/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2018, Joyent, Inc.
 */

#include <fcntl.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/sha1.h>
#include <sys/md5.h>
#include <sys/sysmacros.h>
#include <security/cryptoki.h>
#include "softGlobal.h"
#include "softKeys.h"
#include "softKeystore.h"
#include "softMAC.h"
#include "softObject.h"
#include "softSession.h"
#include "softSSL.h"

/*
 * This files contains the implementation of the following PKCS#11
 * mechanisms needed by SSL:
 * CKM_SSL3_MASTER_KEY_DERIVE
 * CKM_SSL3_MASTER_KEY_DERIVE_DH
 * CKM_SSL3_KEY_AND_DERIVE
 * CKM_TLS_MASTER_KEY_DERIVE
 * CKM_TLS_MASTER_KEY_DERIVE_DH
 * CKM_TLS_KEY_AND_DERIVE
 *
 * SSL refers to common functions between SSL v3.0 and SSL v3.1 (a.k.a TLS.)
 */

#define	MAX_KEYBLOCK	160	/* should be plenty for all known cipherspecs */

#define	MAX_DEFAULT_ATTRS	10	/* Enough for major applicarions */

static	char *ssl3_const_vals[] = {
	"A",
	"BB",
	"CCC",
	"DDDD",
	"EEEEE",
	"FFFFFF",
	"GGGGGGG",
	"HHHHHHHH",
	"IIIIIIIII",
	"JJJJJJJJJJ",
};
static	uint_t ssl3_const_lens[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10};

static uchar_t TLS_MASTER_SECRET_LABEL[] = {"master secret"};
#define	TLS_MASTER_SECRET_LABEL_LEN	13

static uchar_t TLS_KEY_EXPANSION_LABEL[] = {"key expansion"};
#define	TLS_KEY_EXPANSION_LABEL_LEN	13

static uchar_t TLS_CLIENT_KEY_LABEL[] = {"client write key"};
#define	TLS_CLIENT_KEY_LABEL_LEN	16

static uchar_t TLS_SERVER_KEY_LABEL[] = {"server write key"};
#define	TLS_SERVER_KEY_LABEL_LEN	16

static uchar_t TLS_IV_BLOCK_LABEL[] = {"IV block"};
#define	TLS_IV_BLOCK_LABEL_LEN	8

static void P_MD5(uchar_t *, uint_t, uchar_t *, uint_t, uchar_t *, uint_t,
    uchar_t *, uint_t, uchar_t *, uint_t, boolean_t);
static void P_SHA1(uchar_t *, uint_t, uchar_t *, uint_t, uchar_t *, uint_t,
    uchar_t *, uint_t, uchar_t *, uint_t, boolean_t);

static CK_RV soft_add_derived_key(CK_ATTRIBUTE_PTR, CK_ULONG,
    CK_OBJECT_HANDLE_PTR, soft_session_t *, soft_object_t *);
static void soft_delete_derived_key(soft_session_t *, soft_object_t *);
static void soft_ssl_weaken_key(CK_MECHANISM_PTR, uchar_t *, uint_t,
    uchar_t *, uint_t, uchar_t *, uint_t, uchar_t *, boolean_t);

/*
 * soft_ssl3_churn()
 * Called for derivation of the master secret from the pre-master secret,
 * and for the derivation of the key_block in an SSL3 handshake
 * result is assumed to be larger than rounds * MD5_HASH_SIZE.
 */
static void
soft_ssl3_churn(uchar_t *secret, uint_t secretlen, uchar_t *rand1,
    uint_t rand1len, uchar_t *rand2, uint_t rand2len, int rounds,
    uchar_t *result)
{
	SHA1_CTX sha1_ctx;
	MD5_CTX	md5_ctx;
	uchar_t sha1_digest[SHA1_HASH_SIZE];
	int i;
	uchar_t *ms = result;
	for (i = 0; i < rounds; i++) {
		SHA1Init(&sha1_ctx);
		SHA1Update(&sha1_ctx, (const uint8_t *)ssl3_const_vals[i],
		    ssl3_const_lens[i]);
		SHA1Update(&sha1_ctx, secret, secretlen);
		SHA1Update(&sha1_ctx, rand1, rand1len);
		SHA1Update(&sha1_ctx, rand2, rand2len);
		SHA1Final(sha1_digest, &sha1_ctx);

		MD5Init(&md5_ctx);
		MD5Update(&md5_ctx, secret, secretlen);
		MD5Update(&md5_ctx, sha1_digest, SHA1_HASH_SIZE);
		MD5Final(ms, &md5_ctx);
		ms += MD5_HASH_SIZE;
	}
}

/*
 * This TLS generic Pseudo Random Function expands a triplet
 * {secret, label, seed} into any arbitrary length string of pseudo
 * random bytes.
 * Here, it is called for the derivation of the master secret from the
 * pre-master secret, and for the derivation of the key_block in a TLS
 * handshake
 */
static void
soft_tls_prf(uchar_t *secret, uint_t secretlen, uchar_t *label, uint_t labellen,
    uchar_t *rand1, uint_t rand1len, uchar_t *rand2, uint_t rand2len,
    uchar_t *result, uint_t resultlen)
{
	uchar_t *S1, *S2;
	uchar_t md5_digested_key[MD5_HASH_SIZE];
	uchar_t sha1_digested_key[SHA1_HASH_SIZE];
	uint_t L_S, L_S1, L_S2;

	/* secret is NULL for IV's in exportable ciphersuites */
	if (secret == NULL) {
		L_S = 0;
		L_S2 = L_S1 = 0;
		S1 = NULL;
		S2 = NULL;
		goto do_P_HASH;
	}

	L_S = roundup(secretlen, 2) / 2;
	L_S1 = L_S;
	L_S2 = L_S;
	S1 = secret;
	S2 = secret + (secretlen / 2);	/* Possible overlap of S1 and S2. */

	/* Reduce the half secrets if bigger than the HASH's block size */
	if (L_S > MD5_HMAC_BLOCK_SIZE) {
		MD5_CTX	md5_ctx;
		SHA1_CTX sha1_ctx;

		MD5Init(&md5_ctx);
		MD5Update(&md5_ctx, S1, L_S);
		MD5Final(md5_digested_key, &md5_ctx);
		S1 = md5_digested_key;
		L_S1 = MD5_HASH_SIZE;

		SHA1Init(&sha1_ctx);
		SHA1Update(&sha1_ctx, S2, L_S);
		SHA1Final(sha1_digested_key, &sha1_ctx);
		S2 = sha1_digested_key;
		L_S2 = SHA1_HASH_SIZE;
	}

	/*
	 * PRF(secret, label, seed) = P_MD5(S1, label + seed) XOR
	 *				P_SHA-1(S2, label + seed);
	 * the 'seed' here is rand1 + rand2
	 */
do_P_HASH:
	/* The first one writes directly to the result */
	P_MD5(S1, L_S1, label, labellen, rand1, rand1len, rand2, rand2len,
	    result, resultlen, B_FALSE);

	/* The second one XOR's with the result. */
	P_SHA1(S2, L_S2, label, labellen, rand1, rand1len, rand2, rand2len,
	    result, resultlen, B_TRUE);
}

/*
 * These two expansion routines are very similar. (they can merge one day).
 * They implement the P_HASH() function for MD5 and for SHA1, as defined in
 * RFC2246:
 *
 *	P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
 *				HMAC_hash(secret, A(2) + seed) +
 *				HMAC_hash(secret, A(3) + seed) + ...
 * Where + indicates concatenation.
 * A() is defined as:
 *	A(0) = seed
 *	A(i) = HMAC_hash(secret, A(i-1))
 *
 * The seed is the concatenation of 'babel', 'rand1', and 'rand2'.
 */
static void
P_MD5(uchar_t *secret, uint_t secretlen, uchar_t *label, uint_t labellen,
    uchar_t *rand1, uint_t rand1len, uchar_t *rand2, uint_t rand2len,
    uchar_t *result, uint_t resultlen, boolean_t xor_it)
{
	uint32_t md5_ipad[MD5_HMAC_INTS_PER_BLOCK];
	uint32_t md5_opad[MD5_HMAC_INTS_PER_BLOCK];
	uchar_t	md5_hmac[MD5_HASH_SIZE];
	uchar_t	A[MD5_HASH_SIZE];
	md5_hc_ctx_t md5_hmac_ctx;
	uchar_t *res, *cur;
	uint_t left = resultlen;
	int i;

	/* good compilers will leverage the aligment */
	bzero(md5_ipad, MD5_HMAC_BLOCK_SIZE);
	bzero(md5_opad, MD5_HMAC_BLOCK_SIZE);

	if (secretlen > 0) {
		bcopy(secret, md5_ipad, secretlen);
		bcopy(secret, md5_opad, secretlen);
	}

	/* A(1) = HMAC_MD5(secret, rand1 + rand2) */
	md5_hmac_ctx_init(&md5_hmac_ctx, md5_ipad, md5_opad);
	SOFT_MAC_UPDATE(MD5, &md5_hmac_ctx, label, labellen);
	SOFT_MAC_UPDATE(MD5, &md5_hmac_ctx, rand1, rand1len);
	SOFT_MAC_UPDATE(MD5, &md5_hmac_ctx, rand2, rand2len);
	SOFT_MAC_FINAL(MD5, &md5_hmac_ctx, A);

	if (xor_it) {
		res = md5_hmac;
		cur = result;
	} else {
		res = result;
	}

	while (left > 0) {
		/*
		 * Compute HMAC_MD5(secret, A(i) + seed);
		 * The secret is already expanded in the ictx and octx, so
		 * we can call the SOFT_MAC_INIT_CTX() directly.
		 */
		SOFT_MAC_INIT_CTX(MD5, &md5_hmac_ctx, md5_ipad, md5_opad,
		    MD5_HMAC_BLOCK_SIZE);
		SOFT_MAC_UPDATE(MD5, &md5_hmac_ctx, A, MD5_HASH_SIZE);
		SOFT_MAC_UPDATE(MD5, &md5_hmac_ctx, label, labellen);
		SOFT_MAC_UPDATE(MD5, &md5_hmac_ctx, rand1, rand1len);
		SOFT_MAC_UPDATE(MD5, &md5_hmac_ctx, rand2, rand2len);

		if (left > MD5_HASH_SIZE) {
			SOFT_MAC_FINAL(MD5, &md5_hmac_ctx, res);
			if (xor_it) {
				for (i = 0; i < MD5_HASH_SIZE; i++) {
					*cur ^= res[i];
					cur++;
				}
			} else {
				res += MD5_HASH_SIZE;
			}
			left -= MD5_HASH_SIZE;
		} else {
			SOFT_MAC_FINAL(MD5, &md5_hmac_ctx, md5_hmac);
			if (xor_it) {
				for (i = 0; i < left; i++) {
					*cur ^= md5_hmac[i];
					cur++;
				}
			} else {
				bcopy(md5_hmac, res, left);
			}
			break;
		}
		/* A(i) = HMAC_MD5(secret, A(i-1) */
		SOFT_MAC_INIT_CTX(MD5, &md5_hmac_ctx, md5_ipad, md5_opad,
		    MD5_HMAC_BLOCK_SIZE);
		SOFT_MAC_UPDATE(MD5, &md5_hmac_ctx, A, MD5_HASH_SIZE);
		SOFT_MAC_FINAL(MD5, &md5_hmac_ctx, A);
	}
}
static void
P_SHA1(uchar_t *secret, uint_t secretlen, uchar_t *label, uint_t labellen,
    uchar_t *rand1, uint_t rand1len, uchar_t *rand2, uint_t rand2len,
    uchar_t *result, uint_t resultlen, boolean_t xor_it)
{
	uint32_t sha1_ipad[SHA1_HMAC_INTS_PER_BLOCK];
	uint32_t sha1_opad[SHA1_HMAC_INTS_PER_BLOCK];
	uchar_t	sha1_hmac[SHA1_HASH_SIZE];
	uchar_t	A[SHA1_HASH_SIZE];
	sha1_hc_ctx_t sha1_hmac_ctx;
	uchar_t *res, *cur;
	uint_t left = resultlen;
	int i;

	/* good compilers will leverage the aligment */
	bzero(sha1_ipad, SHA1_HMAC_BLOCK_SIZE);
	bzero(sha1_opad, SHA1_HMAC_BLOCK_SIZE);

	if (secretlen > 0) {
		bcopy(secret, sha1_ipad, secretlen);
		bcopy(secret, sha1_opad, secretlen);
	}

	/* A(1) = HMAC_SHA1(secret, rand1 + rand2) */
	sha1_hmac_ctx_init(&sha1_hmac_ctx, sha1_ipad, sha1_opad);
	SOFT_MAC_UPDATE(SHA1, &sha1_hmac_ctx, label, labellen);
	SOFT_MAC_UPDATE(SHA1, &sha1_hmac_ctx, rand1, rand1len);
	SOFT_MAC_UPDATE(SHA1, &sha1_hmac_ctx, rand2, rand2len);
	SOFT_MAC_FINAL(SHA1, &sha1_hmac_ctx, A);

	if (xor_it) {
		res = sha1_hmac;
		cur = result;
	} else {
		res = result;
	}

	while (left > 0) {
		/*
		 * Compute HMAC_SHA1(secret, A(i) + seed);
		 * The secret is already expanded in the ictx and octx, so
		 * we can call the SOFT_MAC_INIT_CTX() directly.
		 */
		SOFT_MAC_INIT_CTX(SHA1, &sha1_hmac_ctx,
		    (const uchar_t *)sha1_ipad, (const uchar_t *)sha1_opad,
		    SHA1_HMAC_BLOCK_SIZE);
		SOFT_MAC_UPDATE(SHA1, &sha1_hmac_ctx, A, SHA1_HASH_SIZE);
		SOFT_MAC_UPDATE(SHA1, &sha1_hmac_ctx, label, labellen);
		SOFT_MAC_UPDATE(SHA1, &sha1_hmac_ctx, rand1, rand1len);
		SOFT_MAC_UPDATE(SHA1, &sha1_hmac_ctx, rand2, rand2len);

		if (left > SHA1_HASH_SIZE) {
			SOFT_MAC_FINAL(SHA1, &sha1_hmac_ctx, res);
			if (xor_it) {
				for (i = 0; i < SHA1_HASH_SIZE; i++) {
					*cur ^= res[i];
					cur++;
				}
			} else {
				res += SHA1_HASH_SIZE;
			}
			left -= SHA1_HASH_SIZE;
		} else {
			SOFT_MAC_FINAL(SHA1, &sha1_hmac_ctx, sha1_hmac);
			if (xor_it) {
				for (i = 0; i < left; i++) {
					*cur ^= sha1_hmac[i];
					cur++;
				}
			} else {
				bcopy(sha1_hmac, res, left);
			}
			break;
		}
		/* A(i) = HMAC_SHA1(secret, A(i-1) */
		SOFT_MAC_INIT_CTX(SHA1, &sha1_hmac_ctx,
		    (const uchar_t *)sha1_ipad, (const uchar_t *)sha1_opad,
		    SHA1_HMAC_BLOCK_SIZE);
		SOFT_MAC_UPDATE(SHA1, &sha1_hmac_ctx, A, SHA1_HASH_SIZE);
		SOFT_MAC_FINAL(SHA1, &sha1_hmac_ctx, A);
	}
}

/* This function handles the call from C_DeriveKey for CKM_TLS_PRF */
CK_RV
derive_tls_prf(CK_TLS_PRF_PARAMS_PTR param, soft_object_t *basekey_p)
{

	if (param->pOutput == NULL || param->pulOutputLen == 0)
		return (CKR_BUFFER_TOO_SMALL);

	(void) soft_tls_prf(OBJ_SEC_VALUE(basekey_p),
	    OBJ_SEC_VALUE_LEN(basekey_p), param->pLabel, param->ulLabelLen,
	    param->pSeed, param->ulSeedLen, NULL, 0, param->pOutput,
	    *param->pulOutputLen);

	return (CKR_OK);
}


/*
 * soft_ssl_master_key_derive()
 *
 * Arguments:
 * . session_p
 * . mech_p:	key derivation mechanism. the mechanism parameter carries the
 *		client and master random from the Hello handshake messages.
 * . basekey_p: The pre-master secret key.
 * . pTemplate & ulAttributeCount: Any extra attributes for the key to be
 *		created.
 * . phKey:	store for handle to the derived key.
 *
 * Description:
 *	Derive the SSL master secret from the pre-master secret, the client
 *	and server random.
 *	In SSL 3.0, master_secret =
 *	    MD5(pre_master_secret + SHA('A' + pre_master_secret +
 *	        ClientHello.random + ServerHello.random)) +
 *	    MD5(pre_master_secret + SHA('BB' + pre_master_secret +
 *	        ClientHello.random + ServerHello.random)) +
 *	    MD5(pre_master_secret + SHA('CCC' + pre_master_secret +
 *	        ClientHello.random + ServerHello.random));
 *
 *	In TLS 1.0 (a.k.a. SSL 3.1), master_secret =
 *	    PRF(pre_master_secret, "master secret",
 *		ClientHello.random + ServerHello.random)
 */
CK_RV
soft_ssl_master_key_derive(soft_session_t *sp, CK_MECHANISM_PTR mech,
    soft_object_t *basekey_p, CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	uchar_t	*pmsecret = OBJ_SEC_VALUE(basekey_p);
#ifdef	__sparcv9
	/* LINTED */
	uint_t pmlen = (uint_t)OBJ_SEC_VALUE_LEN(basekey_p);
#else	/* __sparcv9 */
	uint_t pmlen = OBJ_SEC_VALUE_LEN(basekey_p);
#endif	/* __sparcv9 */
	CK_SSL3_MASTER_KEY_DERIVE_PARAMS *mkd_params;
	CK_SSL3_RANDOM_DATA *random_data;
	CK_VERSION_PTR	pVersion;
	uchar_t	ssl_master_secret[48];
	CK_OBJECT_CLASS class = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = CKK_GENERIC_SECRET;
	CK_BBOOL true = TRUE;
	CK_ATTRIBUTE obj_tmpl[MAX_DEFAULT_ATTRS];
	CK_ATTRIBUTE_PTR new_tmpl;
	CK_ULONG newattrcount;
	boolean_t new_tmpl_allocated = B_FALSE, is_tls = B_FALSE;
	ulong_t i;
	CK_RV rv = CKR_OK;
	uint_t ClientRandomLen, ServerRandomLen;

	/* Check the validity of the mechanism's parameter */

	mkd_params = (CK_SSL3_MASTER_KEY_DERIVE_PARAMS *)mech->pParameter;

	if (mkd_params == NULL ||
	    mech->ulParameterLen != sizeof (CK_SSL3_MASTER_KEY_DERIVE_PARAMS))
		return (CKR_MECHANISM_PARAM_INVALID);

	pVersion = mkd_params->pVersion;

	switch (mech->mechanism) {
	case CKM_TLS_MASTER_KEY_DERIVE:
		is_tls = B_TRUE;
	/* FALLTHRU */
	case CKM_SSL3_MASTER_KEY_DERIVE:
		/* Invalid pre-master key length. What else to return? */
		if (pmlen != 48)
			return (CKR_ARGUMENTS_BAD);

		/* Get the SSL version number from the premaster secret */
		if (pVersion == NULL_PTR)
			return (CKR_MECHANISM_PARAM_INVALID);

		bcopy(pmsecret, pVersion, sizeof (CK_VERSION));

		break;
	case CKM_TLS_MASTER_KEY_DERIVE_DH:
		is_tls = B_TRUE;
	/* FALLTHRU */
	case CKM_SSL3_MASTER_KEY_DERIVE_DH:
		if (pVersion != NULL_PTR)
			return (CKR_MECHANISM_PARAM_INVALID);
	}

	random_data = &mkd_params->RandomInfo;
#ifdef	__sparcv9
	/* LINTED */
	ClientRandomLen = (uint_t)random_data->ulClientRandomLen;
	/* LINTED */
	ServerRandomLen = (uint_t)random_data->ulServerRandomLen;
#else	/* __sparcv9 */
	ClientRandomLen = random_data->ulClientRandomLen;
	ServerRandomLen = random_data->ulServerRandomLen;
#endif	/* __sparcv9 */

	if (random_data->pClientRandom == NULL_PTR || ClientRandomLen == 0 ||
	    random_data->pServerRandom == NULL_PTR || ServerRandomLen == 0) {
		return (CKR_MECHANISM_PARAM_INVALID);
	}

	/* Now the actual secret derivation */
	if (!is_tls) {
		soft_ssl3_churn(pmsecret, pmlen, random_data->pClientRandom,
		    ClientRandomLen, random_data->pServerRandom,
		    ServerRandomLen, 3, ssl_master_secret);
	} else {
		soft_tls_prf(pmsecret, pmlen, TLS_MASTER_SECRET_LABEL,
		    TLS_MASTER_SECRET_LABEL_LEN, random_data->pClientRandom,
		    ClientRandomLen, random_data->pServerRandom,
		    ServerRandomLen, ssl_master_secret, 48);
	}

	/*
	 * The object creation attributes need to be in one contiguous
	 * array. In addition to the attrs from the application supplied
	 * pTemplates, We need to add the class, type, value, valuelen and
	 * CKA_DERIVE.
	 * In the most likely case, the application passes between zero and
	 * handful of attributes, We optimize for that case by allocating
	 * the new template on the stack. Oherwise we malloc() it.
	 */

	newattrcount = ulAttributeCount + 4;
	if (newattrcount > MAX_DEFAULT_ATTRS) {
		new_tmpl = malloc(sizeof (CK_ATTRIBUTE) * newattrcount);

		if (new_tmpl == NULL)
			return (CKR_HOST_MEMORY);

		new_tmpl_allocated = B_TRUE;
	} else
		new_tmpl = obj_tmpl;

	/*
	 * Fill in the new template.
	 * We put the attributes contributed by the mechanism first
	 * so that they override the application supplied ones.
	 */
	new_tmpl[0].type = CKA_CLASS;
	new_tmpl[0].pValue = &class;
	new_tmpl[0].ulValueLen = sizeof (class);
	new_tmpl[1].type = CKA_KEY_TYPE;
	new_tmpl[1].pValue = &keyType;
	new_tmpl[1].ulValueLen = sizeof (keyType);
	new_tmpl[2].type = CKA_DERIVE;
	new_tmpl[2].pValue = &true;
	new_tmpl[2].ulValueLen = sizeof (true);
	new_tmpl[3].type = CKA_VALUE;
	new_tmpl[3].pValue = ssl_master_secret;
	new_tmpl[3].ulValueLen = 48;

	/* Any attributes left? */
	if (ulAttributeCount > 0) {

		/* Validate the default class and type attributes */
		for (i = 0; i < ulAttributeCount; i++) {
			/* The caller is responsible for proper alignment */
			if ((pTemplate[i].type == CKA_CLASS) &&
			    (*((CK_OBJECT_CLASS *)pTemplate[i].pValue) !=
			    CKO_SECRET_KEY)) {
				rv = CKR_TEMPLATE_INCONSISTENT;
				goto out;
			}
			if ((pTemplate[i].type == CKA_KEY_TYPE) &&
			    (*((CK_KEY_TYPE *)pTemplate[i].pValue) !=
			    CKK_GENERIC_SECRET)) {
				rv = CKR_TEMPLATE_INCONSISTENT;
				goto out;
			}
		}
		bcopy(pTemplate, &new_tmpl[4],
		    ulAttributeCount * sizeof (CK_ATTRIBUTE));
	}

	rv = soft_add_derived_key(new_tmpl, newattrcount, phKey, sp, basekey_p);
out:
	if (new_tmpl_allocated)
		free(new_tmpl);

	return (rv);
}

/*
 * soft_ssl3_key_and_mac_derive()
 *
 * Arguments:
 * . session_p
 * . mech_p:	key derivation mechanism. the mechanism parameter carries the
 *		client and mastter random from the Hello handshake messages,
 *		the specification of the key and IV sizes, and the location
 *		for the resulting keys and IVs.
 * . basekey_p: The master secret key.
 * . pTemplate & ulAttributeCount: Any extra attributes for the key to be
 *		created.
 *
 * Description:
 *	Derive the SSL key material (Client and server MAC secrets, symmetric
 *	keys and IVs), from the master secret and the client
 *	and server random.
 *	First a keyblock is generated usining the following formula:
 *	key_block =
 *		MD5(master_secret + SHA(`A' + master_secret +
 *					ServerHello.random +
 *					ClientHello.random)) +
 *		MD5(master_secret + SHA(`BB' + master_secret +
 *					ServerHello.random +
 *					ClientHello.random)) +
 *		MD5(master_secret + SHA(`CCC' + master_secret +
 *					ServerHello.random +
 *					ClientHello.random)) + [...];
 *
 *	In TLS 1.0 (a.k.a. SSL 3.1), key_block =
 *	    PRF(master_secret, "key expansion",
 *		ServerHello.random + ClientHello.random)
 *
 *	Then the keys materials are taken from the keyblock.
 */

CK_RV
soft_ssl_key_and_mac_derive(soft_session_t *sp, CK_MECHANISM_PTR mech,
    soft_object_t *basekey_p, CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulAttributeCount)
{
	uchar_t	*msecret = OBJ_SEC_VALUE(basekey_p);
#ifdef	__sparcv9
	/* LINTED */
	uint_t mslen = (uint_t)OBJ_SEC_VALUE_LEN(basekey_p);
#else	/* __sparcv9 */
	uint_t mslen = OBJ_SEC_VALUE_LEN(basekey_p);
#endif	/* __sparcv9 */
	CK_SSL3_KEY_MAT_PARAMS *km_params;
	CK_SSL3_RANDOM_DATA *random_data;
	CK_SSL3_KEY_MAT_OUT *kmo;
	uchar_t key_block[MAX_KEYBLOCK], *kb, *export_keys = NULL;
	CK_OBJECT_CLASS class = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = CKK_GENERIC_SECRET;
	CK_BBOOL true = TRUE;
	CK_ATTRIBUTE obj_tmpl[MAX_DEFAULT_ATTRS];
	CK_ATTRIBUTE_PTR new_tmpl;
	ulong_t newattrcount, mac_key_bytes, secret_key_bytes, iv_bytes;
	ulong_t extra_attr_count;
	uint_t size;
	int rounds, n = 0;
	boolean_t new_tmpl_allocated = B_FALSE, isExport;
	CK_RV rv = CKR_OK;
	uint_t ClientRandomLen, ServerRandomLen;

	/* Check the validity of the mechanism's parameter */

	km_params = (CK_SSL3_KEY_MAT_PARAMS *)mech->pParameter;

	if (km_params == NULL ||
	    mech->ulParameterLen != sizeof (CK_SSL3_KEY_MAT_PARAMS) ||
	    (kmo = km_params->pReturnedKeyMaterial) == NULL)
		return (CKR_MECHANISM_PARAM_INVALID);

	isExport = (km_params->bIsExport == TRUE);

	random_data = &km_params->RandomInfo;
#ifdef	__sparcv9
	/* LINTED */
	ClientRandomLen = (uint_t)random_data->ulClientRandomLen;
	/* LINTED */
	ServerRandomLen = (uint_t)random_data->ulServerRandomLen;
#else	/* __sparcv9 */
	ClientRandomLen = random_data->ulClientRandomLen;
	ServerRandomLen = random_data->ulServerRandomLen;
#endif	/* __sparcv9 */

	if (random_data->pClientRandom == NULL_PTR || ClientRandomLen == 0 ||
	    random_data->pServerRandom == NULL_PTR || ServerRandomLen == 0) {
		return (CKR_MECHANISM_PARAM_INVALID);
	}

	mac_key_bytes = km_params->ulMacSizeInBits / 8;
	secret_key_bytes = km_params->ulKeySizeInBits / 8;
	iv_bytes = km_params->ulIVSizeInBits / 8;

	if ((iv_bytes > 0) &&
	    ((kmo->pIVClient == NULL) || (kmo->pIVServer == NULL)))
		return (CKR_MECHANISM_PARAM_INVALID);

	/*
	 * For exportable ciphersuites, the IV's aren't taken from the
	 * key block. They are directly derived from the client and
	 * server random data.
	 * For SSL3.0:
	 *	client_write_IV = MD5(ClientHello.random + ServerHello.random);
	 *	server_write_IV = MD5(ServerHello.random + ClientHello.random);
	 * For TLS1.0:
	 *	iv_block = PRF("", "IV block", client_random +
	 *			server_random)[0..15]
	 *	client_write_IV = iv_block[0..7]
	 *	server_write_IV = iv_block[8..15]
	 */
	if ((isExport) && (iv_bytes > 0)) {

		if (mech->mechanism == CKM_SSL3_KEY_AND_MAC_DERIVE) {
			MD5_CTX	exp_md5_ctx;

			if (iv_bytes > MD5_HASH_SIZE)
				return (CKR_MECHANISM_PARAM_INVALID);

			MD5Init(&exp_md5_ctx);
			MD5Update(&exp_md5_ctx, random_data->pClientRandom,
			    ClientRandomLen);
			MD5Update(&exp_md5_ctx, random_data->pServerRandom,
			    ServerRandomLen);

			/* there's room in key_block. use it */
			MD5Final(key_block, &exp_md5_ctx);
			bcopy(key_block, kmo->pIVClient, iv_bytes);

			MD5Init(&exp_md5_ctx);
			MD5Update(&exp_md5_ctx, random_data->pServerRandom,
			    ServerRandomLen);
			MD5Update(&exp_md5_ctx, random_data->pClientRandom,
			    ClientRandomLen);
			MD5Final(key_block, &exp_md5_ctx);
			bcopy(key_block, kmo->pIVServer, iv_bytes);
		} else {
			uchar_t	iv_block[16];

			if (iv_bytes != 8)
				return (CKR_MECHANISM_PARAM_INVALID);

			soft_tls_prf(NULL, 0, TLS_IV_BLOCK_LABEL,
			    TLS_IV_BLOCK_LABEL_LEN,
			    random_data->pClientRandom, ClientRandomLen,
			    random_data->pServerRandom, ServerRandomLen,
			    iv_block, 16);
			bcopy(iv_block, kmo->pIVClient, 8);
			bcopy(iv_block + 8, kmo->pIVServer, 8);
		}
		/* so we won't allocate a key_block bigger than needed */
		iv_bytes = 0;
	}

	/* Now the actual secret derivation */

#ifdef	__sparcv9
	/* LINTED */
	size = (uint_t)((mac_key_bytes + secret_key_bytes + iv_bytes) * 2);
#else	/* __sparcv9 */
	size = (mac_key_bytes + secret_key_bytes + iv_bytes) * 2;
#endif	/* __sparcv9 */

	/* Need to handle this better */
	if (size > MAX_KEYBLOCK)
		return (CKR_MECHANISM_PARAM_INVALID);

	rounds = howmany(size, MD5_HASH_SIZE);

	kb = key_block;

	if (mech->mechanism == CKM_SSL3_KEY_AND_MAC_DERIVE) {
		soft_ssl3_churn(msecret, mslen, random_data->pServerRandom,
		    ServerRandomLen, random_data->pClientRandom,
		    ClientRandomLen, rounds, kb);
	} else {
		soft_tls_prf(msecret, mslen, TLS_KEY_EXPANSION_LABEL,
		    TLS_KEY_EXPANSION_LABEL_LEN,
		    random_data->pServerRandom, ServerRandomLen,
		    random_data->pClientRandom, ClientRandomLen,
		    kb, size);
	}

	/* Now create the objects */

	kmo->hClientMacSecret = CK_INVALID_HANDLE;
	kmo->hServerMacSecret = CK_INVALID_HANDLE;
	kmo->hClientKey = CK_INVALID_HANDLE;
	kmo->hServerKey = CK_INVALID_HANDLE;

	/* First the MAC secrets */
	if (mac_key_bytes > 0) {
		obj_tmpl[0].type = CKA_CLASS;
		obj_tmpl[0].pValue = &class;	/* CKO_SECRET_KEY */
		obj_tmpl[0].ulValueLen = sizeof (class);
		obj_tmpl[1].type = CKA_KEY_TYPE;
		obj_tmpl[1].pValue = &keyType;	/* CKK_GENERIC_SECRET */
		obj_tmpl[1].ulValueLen = sizeof (keyType);
		obj_tmpl[2].type = CKA_DERIVE;
		obj_tmpl[2].pValue = &true;
		obj_tmpl[2].ulValueLen = sizeof (true);
		obj_tmpl[3].type = CKA_SIGN;
		obj_tmpl[3].pValue = &true;
		obj_tmpl[3].ulValueLen = sizeof (true);
		obj_tmpl[4].type = CKA_VERIFY;
		obj_tmpl[4].pValue = &true;
		obj_tmpl[4].ulValueLen = sizeof (true);
		obj_tmpl[5].type = CKA_VALUE;
		obj_tmpl[5].pValue = kb;
		obj_tmpl[5].ulValueLen = mac_key_bytes;

		rv = soft_add_derived_key(obj_tmpl, 6,
		    &(kmo->hClientMacSecret), sp, basekey_p);

		if (rv != CKR_OK)
			goto out_err;

		kb += mac_key_bytes;

		obj_tmpl[5].pValue = kb;
		rv = soft_add_derived_key(obj_tmpl, 6,
		    &(kmo->hServerMacSecret), sp, basekey_p);

		if (rv != CKR_OK)
			goto out_err;

		kb += mac_key_bytes;
	}

	/* Then the symmetric ciphers keys */

	extra_attr_count = (secret_key_bytes == 0) ? 6 : 5;
	newattrcount = ulAttributeCount + extra_attr_count;
	if (newattrcount > MAX_DEFAULT_ATTRS) {
		new_tmpl = malloc(sizeof (CK_ATTRIBUTE) * newattrcount);

		if (new_tmpl == NULL)
			return (CKR_HOST_MEMORY);

		new_tmpl_allocated = B_TRUE;
	} else
		new_tmpl = obj_tmpl;

	new_tmpl[n].type = CKA_CLASS;
	new_tmpl[n].pValue = &class;	/* CKO_SECRET_KEY */
	new_tmpl[n].ulValueLen = sizeof (class);
	++n;
	/*
	 * The keyType comes from the application's template, and depends
	 * on the ciphersuite. The only exception is authentication only
	 * ciphersuites which do not use cipher keys.
	 */
	if (secret_key_bytes == 0) {
		new_tmpl[n].type = CKA_KEY_TYPE;
		new_tmpl[n].pValue = &keyType;	/* CKK_GENERIC_SECRET */
		new_tmpl[n].ulValueLen = sizeof (keyType);
		n++;
	}
	new_tmpl[n].type = CKA_DERIVE;
	new_tmpl[n].pValue = &true;
	new_tmpl[n].ulValueLen = sizeof (true);
	n++;
	new_tmpl[n].type = CKA_ENCRYPT;
	new_tmpl[n].pValue = &true;
	new_tmpl[n].ulValueLen = sizeof (true);
	n++;
	new_tmpl[n].type = CKA_DECRYPT;
	new_tmpl[n].pValue = &true;
	new_tmpl[n].ulValueLen = sizeof (true);
	n++;
	new_tmpl[n].type = CKA_VALUE;
	new_tmpl[n].pValue = NULL;
	new_tmpl[n].ulValueLen = 0;

	if (secret_key_bytes > 0) {
		if (isExport) {
			if (secret_key_bytes > MD5_HASH_SIZE) {
				rv = CKR_MECHANISM_PARAM_INVALID;
				goto out_err;
			}
			if ((export_keys = malloc(2 * MD5_HASH_SIZE)) == NULL) {
				rv = CKR_HOST_MEMORY;
				goto out_err;
			}
#ifdef	__sparcv9
			/* LINTED */
			soft_ssl_weaken_key(mech, kb, (uint_t)secret_key_bytes,
			    random_data->pClientRandom, ClientRandomLen,
			    random_data->pServerRandom, ServerRandomLen,
			    export_keys, B_TRUE);
#else	/* __sparcv9 */
			soft_ssl_weaken_key(mech, kb, secret_key_bytes,
			    random_data->pClientRandom, ClientRandomLen,
			    random_data->pServerRandom, ServerRandomLen,
			    export_keys, B_TRUE);
#endif	/* __sparcv9 */
			new_tmpl[n].pValue = export_keys;
			new_tmpl[n].ulValueLen = MD5_HASH_SIZE;
		} else {
			new_tmpl[n].pValue = kb;
			new_tmpl[n].ulValueLen = secret_key_bytes;
		}
	}

	if (ulAttributeCount > 0)
		bcopy(pTemplate, &new_tmpl[extra_attr_count],
		    ulAttributeCount * sizeof (CK_ATTRIBUTE));

	rv = soft_add_derived_key(new_tmpl, newattrcount,
	    &(kmo->hClientKey), sp, basekey_p);

	if (rv != CKR_OK)
		goto out_err;

	kb += secret_key_bytes;

	if (secret_key_bytes > 0) {
		if (isExport) {
#ifdef	__sparcv9
			/* LINTED */
			soft_ssl_weaken_key(mech, kb, (uint_t)secret_key_bytes,
			    random_data->pServerRandom, ServerRandomLen,
			    random_data->pClientRandom, ClientRandomLen,
			    export_keys + MD5_HASH_SIZE, B_FALSE);
#else	/* __sparcv9 */
			soft_ssl_weaken_key(mech, kb, secret_key_bytes,
			    random_data->pServerRandom, ServerRandomLen,
			    random_data->pClientRandom, ClientRandomLen,
			    export_keys + MD5_HASH_SIZE, B_FALSE);
#endif	/* __sparcv9 */
			new_tmpl[n].pValue = export_keys + MD5_HASH_SIZE;
		} else
			new_tmpl[n].pValue = kb;
	}

	rv = soft_add_derived_key(new_tmpl, newattrcount,
	    &(kmo->hServerKey), sp, basekey_p);

	if (rv != CKR_OK)
		goto out_err;

	kb += secret_key_bytes;

	/* Finally, the IVs */
	if (iv_bytes > 0) {
		bcopy(kb, kmo->pIVClient, iv_bytes);
		kb += iv_bytes;
		bcopy(kb, kmo->pIVServer, iv_bytes);
	}

	if (new_tmpl_allocated)
		free(new_tmpl);

	freezero(export_keys, 2 * MD5_HASH_SIZE);

	return (rv);

out_err:
	if (kmo->hClientMacSecret != CK_INVALID_HANDLE) {
		(void) soft_delete_derived_key(sp,
		    (soft_object_t *)(kmo->hClientMacSecret));
		kmo->hClientMacSecret = CK_INVALID_HANDLE;
	}
	if (kmo->hServerMacSecret != CK_INVALID_HANDLE) {
		(void) soft_delete_derived_key(sp,
		    (soft_object_t *)(kmo->hServerMacSecret));
		kmo->hServerMacSecret = CK_INVALID_HANDLE;
	}
	if (kmo->hClientKey != CK_INVALID_HANDLE) {
		(void) soft_delete_derived_key(sp,
		    (soft_object_t *)(kmo->hClientKey));
		kmo->hClientKey = CK_INVALID_HANDLE;
	}
	if (kmo->hServerKey != CK_INVALID_HANDLE) {
		(void) soft_delete_derived_key(sp,
		    (soft_object_t *)(kmo->hServerKey));
		kmo->hServerKey = CK_INVALID_HANDLE;
	}

	if (new_tmpl_allocated)
		free(new_tmpl);

	freezero(export_keys, 2 * MD5_HASH_SIZE);

	return (rv);
}

/*
 * Add the derived key to the session, and, if it's a token object,
 * write it to the token.
 */
static CK_RV
soft_add_derived_key(CK_ATTRIBUTE_PTR tmpl, CK_ULONG attrcount,
    CK_OBJECT_HANDLE_PTR phKey, soft_session_t *sp, soft_object_t *basekey_p)
{
	CK_RV rv;
	soft_object_t *secret_key;

	if ((secret_key = calloc(1, sizeof (soft_object_t))) == NULL) {
		return (CKR_HOST_MEMORY);
	}

	if (((rv = soft_build_secret_key_object(tmpl, attrcount, secret_key,
	    SOFT_CREATE_OBJ_INT, 0, (CK_KEY_TYPE)~0UL)) != CKR_OK) ||
	    ((rv = soft_pin_expired_check(secret_key)) != CKR_OK) ||
	    ((rv = soft_object_write_access_check(sp, secret_key)) != CKR_OK)) {

		free(secret_key);
		return (rv);
	}

	/* Set the sensitivity and extractability attributes as a needed */
	soft_derive_enforce_flags(basekey_p, secret_key);

	/* Initialize the rest of stuffs in soft_object_t. */
	(void) pthread_mutex_init(&secret_key->object_mutex, NULL);
	secret_key->magic_marker = SOFTTOKEN_OBJECT_MAGIC;

	/* ... and, if it needs to persist, write on the token */
	if (IS_TOKEN_OBJECT(secret_key)) {
		secret_key->session_handle = (CK_SESSION_HANDLE)NULL;
		soft_add_token_object_to_slot(secret_key);
		rv = soft_put_object_to_keystore(secret_key);
		if (rv != CKR_OK) {
			soft_delete_token_object(secret_key, B_FALSE, B_FALSE);
			return (rv);
		}
		*phKey = (CK_OBJECT_HANDLE)secret_key;

		return (CKR_OK);
	}

	/* Add the new object to the session's object list. */
	soft_add_object_to_session(secret_key, sp);
	secret_key->session_handle = (CK_SESSION_HANDLE)sp;

	*phKey = (CK_OBJECT_HANDLE)secret_key;

	return (rv);
}

/*
 * Delete the derived key from the session, and, if it's a token object,
 * remove it from the token.
 */
static void
soft_delete_derived_key(soft_session_t *sp, soft_object_t *key)
{
	/* session_handle is the creating session. It's NULL for token objs */

	if (IS_TOKEN_OBJECT(key))
		soft_delete_token_object(key, B_FALSE, B_FALSE);
	else
		soft_delete_object(sp, key, B_FALSE, B_FALSE);
}

/*
 * soft_ssl_weaken_key()
 * Reduce the key length to an exportable size.
 * For SSL3.0:
 *	final_client_write_key = MD5(client_write_key +
 *                                ClientHello.random +
 *                                ServerHello.random);
 *	final_server_write_key = MD5(server_write_key +
 *                                ServerHello.random +
 *                                ClientHello.random);
 * For TLS1.0:
 *	final_client_write_key = PRF(SecurityParameters.client_write_key,
 *				    "client write key",
 *				    SecurityParameters.client_random +
 *				    SecurityParameters.server_random)[0..15];
 *	final_server_write_key = PRF(SecurityParameters.server_write_key,
 *				    "server write key",
 *				    SecurityParameters.client_random +
 *				    SecurityParameters.server_random)[0..15];
 */
static void
soft_ssl_weaken_key(CK_MECHANISM_PTR mech, uchar_t *secret, uint_t secretlen,
    uchar_t *rand1, uint_t rand1len, uchar_t *rand2, uint_t rand2len,
    uchar_t *result, boolean_t isclient)
{
	MD5_CTX exp_md5_ctx;
	uchar_t *label;
	uint_t labellen;

	if (mech->mechanism == CKM_SSL3_KEY_AND_MAC_DERIVE) {
		MD5Init(&exp_md5_ctx);
		MD5Update(&exp_md5_ctx, secret, secretlen);
		MD5Update(&exp_md5_ctx, rand1, rand1len);
		MD5Update(&exp_md5_ctx, rand2, rand2len);
		MD5Final(result, &exp_md5_ctx);
	} else {
		if (isclient) {
			label = TLS_CLIENT_KEY_LABEL;
			labellen = TLS_CLIENT_KEY_LABEL_LEN;
			soft_tls_prf(secret, secretlen, label, labellen,
			    rand1, rand1len, rand2, rand2len, result, 16);
		} else {
			label = TLS_SERVER_KEY_LABEL;
			labellen = TLS_SERVER_KEY_LABEL_LEN;
			soft_tls_prf(secret, secretlen, label, labellen,
			    rand2, rand2len, rand1, rand1len, result, 16);
		}
	}
}
