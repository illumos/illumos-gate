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
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/systm.h>
#include <sys/sha1.h>
#include <sys/crypto/common.h>
#include <sys/cmn_err.h>
#ifndef _KERNEL
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <security/cryptoki.h>
#include <cryptoutil.h>
#include "softMAC.h"
#endif
#include <sha1/sha1_impl.h>

/*
 * fips_sha1_build_context()
 *
 * Description:
 *	This function allocates and initializes SHA1 context
 *	context.
 */
SHA1_CTX *
fips_sha1_build_context(void)
{
	SHA1_CTX *sha1_context;


#ifndef _KERNEL
	if ((sha1_context = malloc(sizeof (SHA1_CTX))) == NULL)
#else
	if ((sha1_context = kmem_zalloc(sizeof (SHA1_CTX),
	    KM_SLEEP)) == NULL)
#endif
		return (NULL);

	SHA1Init(sha1_context);

	return (sha1_context);

}

/*
 * fips_sha1_hash()
 *
 * Arguments:
 *	sha1_context:	pointer to SHA1 context
 *	in:	pointer to the input data to be hashed
 *	inlen:	length of the input data
 *	out:	pointer to the output data after hashing
 *
 * Description:
 *	This function calls the low-level SHA1 routines for hashing.
 *
 */
int
fips_sha1_hash(SHA1_CTX *sha1_context, uchar_t *in, ulong_t inlen, uchar_t *out)
{

	int rv;

	if (in != NULL) {
#ifdef	__sparcv9
		SHA1Update((SHA1_CTX *)sha1_context, in, (uint_t)inlen);
#else	/* !__sparcv9 */
		SHA1Update((SHA1_CTX *)sha1_context, in, inlen);
#endif	/* __sparcv9 */
		SHA1Final(out, (SHA1_CTX *)sha1_context);
		rv = CKR_OK;
	} else
		rv = CKR_ARGUMENTS_BAD;

	if (sha1_context)
#ifdef _KERNEL
		kmem_free(sha1_context, sizeof (SHA1_CTX));
#else
		free(sha1_context);
#endif
	return (rv);
}


#ifndef _KERNEL
soft_hmac_ctx_t *
fips_sha1_hmac_build_context(uint8_t *secret_key,
	unsigned int secret_key_length)
{

	soft_hmac_ctx_t *hmac_ctx;
	uint32_t sha1_ipad[SHA1_HMAC_INTS_PER_BLOCK];
	uint32_t sha1_opad[SHA1_HMAC_INTS_PER_BLOCK];

	hmac_ctx = malloc(sizeof (soft_hmac_ctx_t));

	if (hmac_ctx == NULL) {
		return (NULL);
	}

	hmac_ctx->hmac_len = SHA1_HASH_SIZE;
	bzero(sha1_ipad, SHA1_HMAC_BLOCK_SIZE);
	bzero(sha1_opad, SHA1_HMAC_BLOCK_SIZE);

	(void) memcpy(sha1_ipad, secret_key, secret_key_length);
	(void) memcpy(sha1_opad, secret_key, secret_key_length);

	sha1_hmac_ctx_init(&hmac_ctx->hc_ctx_u.sha1_ctx, sha1_ipad,
	    sha1_opad);

	return (hmac_ctx);

}

CK_RV
fips_hmac_sha1_hash(unsigned char *hmac_computed,
	uint8_t *secret_key,
	unsigned int secret_key_length,
	uint8_t *message,
	unsigned int message_length)
{

	soft_hmac_ctx_t *hmac_ctx = NULL;

	hmac_ctx = fips_sha1_hmac_build_context(secret_key,
	    secret_key_length);

	if (hmac_ctx == NULL)
		return (CKR_HOST_MEMORY);

	if (message != NULL) {
		SOFT_MAC_UPDATE(SHA1, &(hmac_ctx->hc_ctx_u.sha1_ctx),
		    message, message_length);
	}

	SOFT_MAC_FINAL(SHA1, &(hmac_ctx->hc_ctx_u.sha1_ctx), hmac_computed);

	free(hmac_ctx);
	return (CKR_OK);
}

#else /* _KERNEL */

/*
 * Initialize a SHA1-HMAC context.
 */
void
sha1_mac_init_ctx(sha1_hmac_ctx_t *ctx, void *keyval, uint_t length_in_bytes)
{
	uint32_t ipad[SHA1_HMAC_INTS_PER_BLOCK];
	uint32_t opad[SHA1_HMAC_INTS_PER_BLOCK];
	uint_t i;

	bzero(ipad, SHA1_HMAC_BLOCK_SIZE);
	bzero(opad, SHA1_HMAC_BLOCK_SIZE);

	bcopy(keyval, ipad, length_in_bytes);
	bcopy(keyval, opad, length_in_bytes);

	/* XOR key with ipad (0x36) and opad (0x5c) */
	for (i = 0; i < SHA1_HMAC_INTS_PER_BLOCK; i++) {
		ipad[i] ^= 0x36363636;
		opad[i] ^= 0x5c5c5c5c;
	}

	/* perform SHA1 on ipad */
	SHA1Init(&ctx->hc_icontext);
	SHA1Update(&ctx->hc_icontext, (uint8_t *)ipad, SHA1_HMAC_BLOCK_SIZE);

	/* perform SHA1 on opad */
	SHA1Init(&ctx->hc_ocontext);
	SHA1Update(&ctx->hc_ocontext, (uint8_t *)opad, SHA1_HMAC_BLOCK_SIZE);
}

sha1_hmac_ctx_t *
fips_sha1_hmac_build_context(uint8_t *secret_key,
	unsigned int secret_key_length)
{
	sha1_hmac_ctx_t *sha1_hmac_ctx_tmpl;


	/*
	 * Allocate and initialize SHA1 context.
	 */
	sha1_hmac_ctx_tmpl = kmem_alloc(sizeof (sha1_hmac_ctx_t),
	    KM_SLEEP);
	if (sha1_hmac_ctx_tmpl == NULL)
		return (NULL);

	/*
	 * initialize ctx->hc_icontext and ctx->hc_ocontext
	 */
	sha1_mac_init_ctx(sha1_hmac_ctx_tmpl, secret_key,
	    secret_key_length);


	sha1_hmac_ctx_tmpl->hc_mech_type = SHA1_HMAC_MECH_INFO_TYPE;


	return (sha1_hmac_ctx_tmpl);
}

void
fips_hmac_sha1_hash(sha1_hmac_ctx_t *sha1_hmac_ctx,
	uint8_t *message, uint32_t message_len,
	uint8_t *hmac_computed)
{

	/* do a SHA1 update of the inner context using the specified data */
	SHA1Update(&((sha1_hmac_ctx)->hc_icontext), message,
	    message_len);

	/*
	 * Do a SHA1 final on the inner context.
	 */
	SHA1Final(hmac_computed, &((sha1_hmac_ctx)->hc_icontext));

	/*
	 * Do an SHA1 update on the outer context, feeding the inner
	 * digest as data.
	 */
	SHA1Update(&((sha1_hmac_ctx)->hc_ocontext), hmac_computed,
	    SHA1_HASH_SIZE);

	/*
	 * Do a SHA1 final on the outer context, storing the computed
	 * digest in the caller's buffer.
	 */
	SHA1Final(hmac_computed, &((sha1_hmac_ctx)->hc_ocontext));

	kmem_free(sha1_hmac_ctx, sizeof (sha1_hmac_ctx_t));
}

#endif

/*
 * SHA1 Power-On SelfTest(s).
 */
int
fips_sha1_post(void)
{

	/*
	 * SHA-1 Known Hash Message
	 * Source from NIST SHA1ShortMsg (L = 512-bits).
	 */
	static uint8_t sha1_known_hash_message[] = {
		0x7e, 0x3a, 0x4c, 0x32, 0x5c, 0xb9, 0xc5, 0x2b,
		0x88, 0x38, 0x7f, 0x93, 0xd0, 0x1a, 0xe8, 0x6d,
		0x42, 0x09, 0x8f, 0x5e, 0xfa, 0x7f, 0x94, 0x57,
		0x38, 0x8b, 0x5e, 0x74, 0xb6, 0xd2, 0x8b, 0x24,
		0x38, 0xd4, 0x2d, 0x8b, 0x64, 0x70, 0x33, 0x24,
		0xd4, 0xaa, 0x25, 0xab, 0x6a, 0xad, 0x15, 0x3a,
		0xe3, 0x0c, 0xd2, 0xb2, 0xaf, 0x4d, 0x5e, 0x5c,
		0x00, 0xa8, 0xa2, 0xd0, 0x22, 0x0c, 0x61, 0x16
	};

	/* SHA-1 Known Digest Message (160-bits). */
	static  uint8_t sha1_known_digest[] = {
		0xa3, 0x05, 0x44, 0x27, 0xcd, 0xb1, 0x3f, 0x16,
		0x4a, 0x61, 0x0b, 0x34, 0x87, 0x02, 0x72, 0x4c,
		0x80, 0x8a, 0x0d, 0xcc
	};

	/* Source from NIST HMAC.txt Count = 0 */
	static uint8_t HMAC_known_secret_key[] = {
		0x7b, 0x10, 0xf4, 0x12, 0x4b, 0x15, 0xc8, 0x2e
	};

	static uint8_t HMAC_known_secret_key_length
	    = sizeof (HMAC_known_secret_key);

	/* known SHA1 hmac - truncated (10 bytes) */
	static uint8_t known_SHA1_hmac[] = {
		0x4e, 0xad, 0x12, 0xc2, 0xfe, 0x3d, 0x6e, 0xa4,
		0x3a, 0xcb
	};

	static uint8_t hmac_sha1_known_hash_message[] = {
		0x27, 0xdc, 0xb5, 0xb1, 0xda, 0xf6, 0x0c, 0xfd,
		0x3e, 0x2f, 0x73, 0xd4, 0xd6, 0x4c, 0xa9, 0xc6,
		0x84, 0xf8, 0xbf, 0x71, 0xfc, 0x68, 0x2a, 0x46,
		0x79, 0x3b, 0x17, 0x90, 0xaf, 0xa4, 0xfe, 0xb1,
		0x00, 0xca, 0x7a, 0xaf, 0xf2, 0x6f, 0x58, 0xf0,
		0xe1, 0xd0, 0xed, 0x42, 0xf1, 0xcd, 0xad, 0x1f,
		0x47, 0x4a, 0xfa, 0x2e, 0x79, 0xd5, 0x3a, 0x0c,
		0x42, 0x89, 0x2c, 0x4d, 0x7b, 0x32, 0x7c, 0xbe,
		0x46, 0xb2, 0x95, 0xed, 0x8d, 0xa3, 0xb6, 0xec,
		0xab, 0x3d, 0x48, 0x51, 0x68, 0x7a, 0x6f, 0x81,
		0x2b, 0x79, 0xdf, 0x2f, 0x6b, 0x20, 0xf1, 0x1f,
		0x67, 0x06, 0xf5, 0x30, 0x17, 0x90, 0xca, 0x99,
		0x62, 0x5a, 0xad, 0x73, 0x91, 0xd8, 0x4f, 0x78,
		0x04, 0x3d, 0x2a, 0x0a, 0x23, 0x9b, 0x14, 0x77,
		0x98, 0x4c, 0x15, 0x7b, 0xbc, 0x92, 0x76, 0x06,
		0x4e, 0x7a, 0x1a, 0x40, 0x6b, 0x06, 0x12, 0xca
	};

	/* SHA-1 variables. */
	uint8_t sha1_computed_digest[SHA1_DIGEST_LENGTH];
	uint8_t hmac_computed[SHA1_HMAC_BLOCK_SIZE];
	SHA1_CTX *sha1_context = NULL;

#ifdef _KERNEL
	sha1_hmac_ctx_t *sha1_hmac_ctx = NULL;
#endif

	int rv;

	/* SHA-1 Known Answer Hashing Test. */
	sha1_context = fips_sha1_build_context();
	if (sha1_context == NULL)
		return (CKR_HOST_MEMORY);

	rv = fips_sha1_hash(sha1_context, sha1_known_hash_message,
	    FIPS_KNOWN_HMAC_MESSAGE_LENGTH, sha1_computed_digest);

	if ((rv != CKR_OK) ||
	    (memcmp(sha1_computed_digest, sha1_known_digest,
	    SHA1_DIGEST_LENGTH) != 0))
		return (CKR_DEVICE_ERROR);

#ifdef _KERNEL
	/* SHA-1 HMAC Known Answer Hashing Test */
	sha1_hmac_ctx = fips_sha1_hmac_build_context(HMAC_known_secret_key,
	    HMAC_known_secret_key_length);

	if (sha1_hmac_ctx == NULL)
		return (CKR_HOST_MEMORY);

	fips_hmac_sha1_hash(sha1_hmac_ctx, hmac_sha1_known_hash_message,
	    sizeof (hmac_sha1_known_hash_message), hmac_computed);
#else
	rv = fips_hmac_sha1_hash(hmac_computed, HMAC_known_secret_key,
	    HMAC_known_secret_key_length, hmac_sha1_known_hash_message,
	    sizeof (hmac_sha1_known_hash_message));

#endif

#ifdef _KERNEL
	if (memcmp(hmac_computed, known_SHA1_hmac,
	    sizeof (known_SHA1_hmac)) != 0)
	return (CKR_DEVICE_ERROR);
#else
	if ((rv != CKR_OK) ||
	    (memcmp(hmac_computed, known_SHA1_hmac,
	    sizeof (known_SHA1_hmac)) != 0))
	return (CKR_DEVICE_ERROR);
#endif

	return (rv);

}
