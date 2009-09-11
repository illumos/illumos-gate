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
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/systm.h>
#define	_SHA2_IMPL
#include <sys/sha2.h>
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
#include <sha2/sha2_impl.h>


/*
 * fips_sha2_build_context()
 *
 * Description:
 *	This function allocates and initializes SHA2 context.
 */
#ifndef _KERNEL
SHA2_CTX *
fips_sha2_build_context(CK_MECHANISM_TYPE mechanism)
{
	SHA2_CTX *sha2_context;

	if ((sha2_context = malloc(sizeof (SHA2_CTX))) == NULL)
		return (NULL);

	switch (mechanism) {
	case CKM_SHA256:
		SHA2Init(SHA256, sha2_context);
		break;

	case CKM_SHA384:
		SHA2Init(SHA384, sha2_context);
		break;

	case CKM_SHA512:
		SHA2Init(SHA512, sha2_context);
		break;
	}

	return (sha2_context);
}

#else
SHA2_CTX *
fips_sha2_build_context(sha2_mech_t mechanism)
{
	SHA2_CTX *sha2_context;

	if ((sha2_context = kmem_zalloc(sizeof (SHA2_CTX),
	    KM_SLEEP)) == NULL)
		return (NULL);

	switch (mechanism) {
	case SHA256_TYPE:
		SHA2Init(SHA256, sha2_context);
		break;

	case SHA384_TYPE:
		SHA2Init(SHA384, sha2_context);
		break;

	case SHA512_TYPE:
		SHA2Init(SHA512, sha2_context);
		break;
	}

	return (sha2_context);
}
#endif

/*
 * fips_sha2_hash()
 *
 * Arguments:
 *	sha2_context:	pointer to SHA2 context
 *	in:	pointer to the input data to be hashed
 *	inlen:	length of the input data
 *	out:	pointer to the output data after hashing
 *
 * Description:
 *	This function calls the low-level SHA2 routines for hashing.
 *
 */
int
fips_sha2_hash(SHA2_CTX *sha2_context, uchar_t *in,
	ulong_t inlen, uchar_t *out)
{

	if (in != NULL) {
		SHA2Update((SHA2_CTX *)sha2_context, in, inlen);
		SHA2Final(out, (SHA2_CTX *)sha2_context);
		return (CKR_OK);
	} else {
		return (CKR_ARGUMENTS_BAD);
	}
}

#ifndef _KERNEL
soft_hmac_ctx_t *
fips_sha2_hmac_build_context(CK_MECHANISM_TYPE mechanism,
	uint8_t *secret_key,
	unsigned int secret_key_length)
{

	soft_hmac_ctx_t *hmac_ctx;

	hmac_ctx = malloc(sizeof (soft_hmac_ctx_t));

	if (hmac_ctx == NULL) {
		return (NULL);
	}

	switch (mechanism) {
	case CKM_SHA256_HMAC:
	{
		uint64_t sha_ipad[SHA256_HMAC_INTS_PER_BLOCK];
		uint64_t sha_opad[SHA256_HMAC_INTS_PER_BLOCK];

		hmac_ctx->hmac_len = SHA256_DIGEST_LENGTH;
		bzero(sha_ipad, SHA256_HMAC_BLOCK_SIZE);
		bzero(sha_opad, SHA256_HMAC_BLOCK_SIZE);

		(void) memcpy(sha_ipad, secret_key, secret_key_length);
		(void) memcpy(sha_opad, secret_key, secret_key_length);

		sha2_hmac_ctx_init(CKM_TO_SHA2(mechanism),
		    &hmac_ctx->hc_ctx_u.sha2_ctx,
		    sha_ipad, sha_opad,
		    SHA256_HMAC_INTS_PER_BLOCK,
		    SHA256_HMAC_BLOCK_SIZE);

		break;
	}

	case CKM_SHA384_HMAC:
	{
		uint64_t sha_ipad[SHA512_HMAC_INTS_PER_BLOCK];
		uint64_t sha_opad[SHA512_HMAC_INTS_PER_BLOCK];

		hmac_ctx->hmac_len = SHA384_DIGEST_LENGTH;
		bzero(sha_ipad, SHA512_HMAC_BLOCK_SIZE);
		bzero(sha_opad, SHA512_HMAC_BLOCK_SIZE);

		(void) memcpy(sha_ipad, secret_key, secret_key_length);
		(void) memcpy(sha_opad, secret_key, secret_key_length);

		sha2_hmac_ctx_init(CKM_TO_SHA2(mechanism),
		    &hmac_ctx->hc_ctx_u.sha2_ctx,
		    sha_ipad, sha_opad,
		    SHA512_HMAC_INTS_PER_BLOCK,
		    SHA512_HMAC_BLOCK_SIZE);
		break;
	}

	case CKM_SHA512_HMAC:
	{
		uint64_t sha_ipad[SHA512_HMAC_INTS_PER_BLOCK];
		uint64_t sha_opad[SHA512_HMAC_INTS_PER_BLOCK];

		hmac_ctx->hmac_len = SHA512_DIGEST_LENGTH;
		bzero(sha_ipad, SHA512_HMAC_BLOCK_SIZE);
		bzero(sha_opad, SHA512_HMAC_BLOCK_SIZE);

		(void) memcpy(sha_ipad, secret_key, secret_key_length);
		(void) memcpy(sha_opad, secret_key, secret_key_length);

		sha2_hmac_ctx_init(CKM_TO_SHA2(mechanism),
		    &hmac_ctx->hc_ctx_u.sha2_ctx,
		    sha_ipad, sha_opad,
		    SHA512_HMAC_INTS_PER_BLOCK,
		    SHA512_HMAC_BLOCK_SIZE);

		break;
	}
	}

	return (hmac_ctx);
}

CK_RV
fips_hmac_sha2_hash(unsigned char *hmac_computed,
	uint8_t *secret_key,
	unsigned int secret_key_length,
	uint8_t *message,
	unsigned int message_length,
	CK_MECHANISM_TYPE mechanism)
{

	soft_hmac_ctx_t *hmac_ctx = NULL;

	hmac_ctx = fips_sha2_hmac_build_context(mechanism,
	    secret_key, secret_key_length);

	if (hmac_ctx == NULL)
		return (CKR_HOST_MEMORY);

	switch (mechanism) {
	case CKM_SHA256_HMAC:
		if (message != NULL)
			SHA2Update(&(hmac_ctx->hc_ctx_u.sha2_ctx.hc_icontext),
			    message, message_length);

		SOFT_MAC_FINAL_2(SHA256, &(hmac_ctx->hc_ctx_u.sha2_ctx),
		    hmac_computed);
		break;

	case CKM_SHA384_HMAC:
		if (message != NULL)
			SHA2Update(&(hmac_ctx->hc_ctx_u.sha2_ctx.hc_icontext),
			    message, message_length);

		SOFT_MAC_FINAL_2(SHA384, &(hmac_ctx->hc_ctx_u.sha2_ctx),
		    hmac_computed);
		break;

	case CKM_SHA512_HMAC:
		if (message != NULL)
			SHA2Update(&(hmac_ctx->hc_ctx_u.sha2_ctx.hc_icontext),
			    message, message_length);

		SOFT_MAC_FINAL_2(SHA512, &(hmac_ctx->hc_ctx_u.sha2_ctx),
		    hmac_computed);
		break;
	}

	free(hmac_ctx);
	return (CKR_OK);
}

#else

/*
 * Initialize a SHA2-HMAC context.
 */
void
sha2_mac_init_ctx(sha2_hmac_ctx_t *ctx, void *keyval, uint_t length_in_bytes)
{
	uint64_t ipad[SHA512_HMAC_BLOCK_SIZE / sizeof (uint64_t)];
	uint64_t opad[SHA512_HMAC_BLOCK_SIZE / sizeof (uint64_t)];
	int i, block_size, blocks_per_int64;

	/* Determine the block size */
	if (ctx->hc_mech_type <= SHA256_HMAC_GEN_MECH_INFO_TYPE) {
		block_size = SHA256_HMAC_BLOCK_SIZE;
		blocks_per_int64 = SHA256_HMAC_BLOCK_SIZE / sizeof (uint64_t);
	} else {
		block_size = SHA512_HMAC_BLOCK_SIZE;
		blocks_per_int64 = SHA512_HMAC_BLOCK_SIZE / sizeof (uint64_t);
	}

	(void) bzero(ipad, block_size);
	(void) bzero(opad, block_size);
	(void) bcopy(keyval, ipad, length_in_bytes);
	(void) bcopy(keyval, opad, length_in_bytes);

	/* XOR key with ipad (0x36) and opad (0x5c) */
	for (i = 0; i < blocks_per_int64; i ++) {
		ipad[i] ^= 0x3636363636363636;
		opad[i] ^= 0x5c5c5c5c5c5c5c5c;
	}

	/* perform SHA2 on ipad */
	SHA2Init(ctx->hc_mech_type, &ctx->hc_icontext);
	SHA2Update(&ctx->hc_icontext, (uint8_t *)ipad, block_size);

	/* perform SHA2 on opad */
	SHA2Init(ctx->hc_mech_type, &ctx->hc_ocontext);
	SHA2Update(&ctx->hc_ocontext, (uint8_t *)opad, block_size);

}

sha2_hmac_ctx_t *
fips_sha2_hmac_build_context(sha2_mech_t mechanism,
	uint8_t *secret_key,
	unsigned int secret_key_length)
{
	sha2_hmac_ctx_t *sha2_hmac_ctx_tmpl;

	/*
	 * Allocate and initialize SHA2 context.
	 */
	sha2_hmac_ctx_tmpl = kmem_alloc(sizeof (sha2_hmac_ctx_t),
	    KM_SLEEP);
	if (sha2_hmac_ctx_tmpl == NULL)
		return (NULL);

	switch (mechanism) {
	case SHA256_TYPE:
		sha2_hmac_ctx_tmpl->hc_mech_type =
		    SHA256_HMAC_MECH_INFO_TYPE;
		break;

	case SHA384_TYPE:
		sha2_hmac_ctx_tmpl->hc_mech_type =
		    SHA384_HMAC_MECH_INFO_TYPE;
		break;

	case SHA512_TYPE:
		sha2_hmac_ctx_tmpl->hc_mech_type =
		    SHA512_HMAC_MECH_INFO_TYPE;
		break;
	}

	/*
	 * initialize ctx->hc_icontext and ctx->hc_ocontext
	 */
	sha2_mac_init_ctx(sha2_hmac_ctx_tmpl, secret_key,
	    secret_key_length);

	return (sha2_hmac_ctx_tmpl);
}

void
fips_hmac_sha2_hash(sha2_hmac_ctx_t *sha2_hmac_ctx,
	uint8_t *message,
	uint32_t message_len,
	uint8_t *hmac_computed,
	sha2_mech_t mechanism)

{

	SHA2Update(&((sha2_hmac_ctx)->hc_icontext), message,
	    message_len);
	SHA2Final(hmac_computed, &((sha2_hmac_ctx)->hc_icontext));

	switch (mechanism) {
	case SHA256_TYPE:
		SHA2Update(&((sha2_hmac_ctx)->hc_ocontext),
		    hmac_computed, SHA256_DIGEST_LENGTH);
		break;

	case SHA384_TYPE:
		SHA2Update(&((sha2_hmac_ctx)->hc_ocontext),
		    hmac_computed, SHA384_DIGEST_LENGTH);
		break;

	case SHA512_TYPE:
		SHA2Update(&((sha2_hmac_ctx)->hc_ocontext),
			hmac_computed, SHA512_DIGEST_LENGTH);
		break;
	}

	SHA2Final(hmac_computed, &((sha2_hmac_ctx)->hc_ocontext));
}

#endif

/*
 * SHA2 Power-On SelfTest(s).
 */
int
fips_sha2_post(void)
{

	/*
	 * SHA-256 Known Hash Message (512-bits).
	 * Source from NIST SHA256ShortMsg (Len = 512)
	 */
	static uint8_t sha256_known_hash_message[] = {
		0x35, 0x92, 0xec, 0xfd, 0x1e, 0xac, 0x61, 0x8f,
		0xd3, 0x90, 0xe7, 0xa9, 0xc2, 0x4b, 0x65, 0x65,
		0x32, 0x50, 0x93, 0x67, 0xc2, 0x1a, 0x0e, 0xac,
		0x12, 0x12, 0xac, 0x83, 0xc0, 0xb2, 0x0c, 0xd8,
		0x96, 0xeb, 0x72, 0xb8, 0x01, 0xc4, 0xd2, 0x12,
		0xc5, 0x45, 0x2b, 0xbb, 0xf0, 0x93, 0x17, 0xb5,
		0x0c, 0x5c, 0x9f, 0xb1, 0x99, 0x75, 0x53, 0xd2,
		0xbb, 0xc2, 0x9b, 0xb4, 0x2f, 0x57, 0x48, 0xad
	};

	/* known SHA256 Digest Message (32 bytes) */
	static uint8_t known_sha256_digest[] = {
		0x10, 0x5a, 0x60, 0x86, 0x58, 0x30, 0xac, 0x3a,
		0x37, 0x1d, 0x38, 0x43, 0x32, 0x4d, 0x4b, 0xb5,
		0xfa, 0x8e, 0xc0, 0xe0, 0x2d, 0xda, 0xa3, 0x89,
		0xad, 0x8d, 0xa4, 0xf1, 0x02, 0x15, 0xc4, 0x54
	};

	/*
	 * SHA-384 Known Hash Message (512-bits).
	 * Source from NIST SHA384ShortMsg (Len = 512)
	 */
	static uint8_t sha384_known_hash_message[] = {
		0x58, 0xbe, 0xab, 0xf9, 0x79, 0xab, 0x35, 0xab,
		0xba, 0x29, 0x37, 0x6d, 0x5d, 0xc2, 0x27, 0xab,
		0xb3, 0xd2, 0xff, 0x4d, 0x90, 0x30, 0x49, 0x82,
		0xfc, 0x10, 0x79, 0xbc, 0x2b, 0x28, 0x80, 0xfc,
		0xb0, 0x12, 0x9e, 0x4f, 0xed, 0xf2, 0x78, 0x98,
		0xce, 0x58, 0x6a, 0x91, 0xb7, 0x68, 0x1e, 0x0d,
		0xba, 0x38, 0x5e, 0x80, 0x0e, 0x79, 0x26, 0xc0,
		0xbc, 0x5a, 0xfe, 0x0d, 0x9c, 0xa9, 0x86, 0x50
	};

	/* known SHA384 Digest Message (48 bytes) */
	static uint8_t known_sha384_digest[] = {
		0xa0, 0x88, 0x8e, 0x1c, 0x4d, 0x7e, 0x80, 0xcb,
		0xaa, 0xaf, 0xa8, 0xbb, 0x1c, 0xa1, 0xca, 0x91,
		0x2a, 0x93, 0x21, 0x75, 0xc2, 0xef, 0x98, 0x2c,
		0xe1, 0xf1, 0x23, 0xa8, 0xc1, 0xae, 0xe9, 0x63,
		0x5a, 0xd7, 0x5b, 0xe5, 0x25, 0x90, 0xa9, 0x24,
		0xbe, 0xd3, 0xf5, 0xec, 0x36, 0xc3, 0x56, 0x90
	};

	/*
	 * SHA-512 Known Hash Message (512-bits).
	 * Source from NIST SHA512ShortMsg (Len = 512)
	 */
	static uint8_t sha512_known_hash_message[] = {
		0x09, 0x5c, 0x7f, 0x30, 0x82, 0x4f, 0xc9, 0x28,
		0x58, 0xcc, 0x93, 0x47, 0xc0, 0x85, 0xd5, 0x78,
		0x88, 0x5f, 0xf3, 0x61, 0x4d, 0xd3, 0x8e, 0xe7,
		0xee, 0x94, 0xa0, 0xf4, 0x40, 0x72, 0xc8, 0x77,
		0x04, 0x7e, 0xe2, 0xad, 0x16, 0x6f, 0xdb, 0xa0,
		0xe7, 0x44, 0xc3, 0xed, 0x2c, 0x2b, 0x24, 0xc9,
		0xd8, 0xa2, 0x93, 0x46, 0x48, 0xdc, 0x84, 0xd3,
		0xbe, 0x66, 0x63, 0x02, 0x11, 0x0a, 0xe0, 0x8f
	};

	/* known SHA512 Digest Message (64 bytes) */
	static uint8_t known_sha512_digest[] = {
		0xd5, 0xcd, 0xaf, 0x83, 0xbb, 0x4a, 0x27, 0xea,
		0xad, 0x8d, 0x8f, 0x18, 0xe4, 0xbe, 0xe9, 0xc2,
		0x5b, 0xe9, 0x49, 0xa7, 0x61, 0xa0, 0xfd, 0x0f,
		0xb2, 0x28, 0x4c, 0xab, 0x14, 0x3c, 0xad, 0x60,
		0xbe, 0xb5, 0x68, 0x87, 0x34, 0xb2, 0xf8, 0x1e,
		0x9e, 0x2d, 0x64, 0x0b, 0x42, 0x5f, 0xd3, 0x2c,
		0xcb, 0x3d, 0x20, 0xd0, 0x2d, 0x63, 0xc2, 0xc9,
		0x4c, 0x03, 0xab, 0x3d, 0x9e, 0x7d, 0x9b, 0x4a
	};

	/* SHA-2 HMAC Test Vectors */

	/*
	 * SHA-256 HMAC Known Hash Message (512-bits).
	 */
	static uint8_t sha256_hmac_known_hash_message[] = {
		0x54, 0x68, 0x65, 0x20, 0x74, 0x65, 0x73, 0x74,
		0x20, 0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65,
		0x20, 0x66, 0x6F, 0x72, 0x20, 0x74, 0x68, 0x65,
		0x20, 0x4D, 0x44, 0x32, 0x2C, 0x20, 0x4D, 0x44,
		0x35, 0x2C, 0x20, 0x61, 0x6E, 0x64, 0x20, 0x53,
		0x48, 0x41, 0x2D, 0x31, 0x20, 0x68, 0x61, 0x73,
		0x68, 0x69, 0x6E, 0x67, 0x20, 0x61, 0x6C, 0x67,
		0x6F, 0x72, 0x69, 0x74, 0x68, 0x6D, 0x73, 0x2E
	};

	static uint8_t sha256_hmac_known_secret_key[] = {
		0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20,
		0x74, 0x68, 0x65, 0x20, 0x53, 0x48, 0x41, 0x2D,
		0x32, 0x35, 0x36, 0x20, 0x48, 0x4D, 0x41, 0x43,
		0x20, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x20,
		0x6B, 0x65, 0x79, 0x21
	};

	static uint8_t sha256_hmac_known_secret_key_length
	    = sizeof (sha256_hmac_known_secret_key);


	/* known SHA256 hmac (32 bytes) */
	static uint8_t known_sha256_hmac[] = {
		0x02, 0x87, 0x21, 0x93, 0x84, 0x8a, 0x35, 0xae,
		0xdb, 0xb6, 0x79, 0x26, 0x96, 0xf0, 0x50, 0xeb,
		0x33, 0x49, 0x57, 0xf1, 0xb2, 0x32, 0xd3, 0x63,
		0x03, 0x65, 0x57, 0xa2, 0xba, 0xa2, 0x5f, 0x35
	};

	/*
	 * SHA-384 HMAC Known Hash Message (512-bits).
	 * Source from NIST HMAC.txt (Count = 15, Klen = 16, Tlen = 48)
	 */
	static uint8_t sha384_hmac_known_secret_key[] = {
		0x01, 0xac, 0x59, 0xf4, 0x2f, 0x8b, 0xb9, 0x1d,
		0x1b, 0xd1, 0x0f, 0xe6, 0x99, 0x0d, 0x7a, 0x87
	};

	static uint8_t sha384_hmac_known_secret_key_length
	    = sizeof (sha384_hmac_known_secret_key);

	static uint8_t sha384_hmac_known_hash_message[] = {
		0x3c, 0xaf, 0x18, 0xc4, 0x76, 0xed, 0xd5, 0x61,
		0x5f, 0x34, 0x3a, 0xc7, 0xb7, 0xd3, 0xa9, 0xda,
		0x9e, 0xfa, 0xde, 0x75, 0x56, 0x72, 0xd5, 0xba,
		0x4b, 0x8a, 0xe8, 0xa7, 0x50, 0x55, 0x39, 0xea,
		0x2c, 0x12, 0x4f, 0xf7, 0x55, 0xec, 0x04, 0x57,
		0xfb, 0xe4, 0x9e, 0x43, 0x48, 0x0b, 0x3c, 0x71,
		0xe7, 0xf4, 0x74, 0x2e, 0xc3, 0x69, 0x3a, 0xad,
		0x11, 0x5d, 0x03, 0x9f, 0x90, 0x22, 0x2b, 0x03,
		0x0f, 0xdc, 0x94, 0x40, 0x31, 0x36, 0x91, 0x71,
		0x6d, 0x53, 0x02, 0x00, 0x58, 0x08, 0xc0, 0x76,
		0x27, 0x48, 0x3b, 0x91, 0x6f, 0xdf, 0x61, 0x98,
		0x30, 0x63, 0xc2, 0xeb, 0x12, 0x68, 0xf2, 0xde,
		0xee, 0xf4, 0x2f, 0xc7, 0x90, 0x33, 0x44, 0x56,
		0xbc, 0x6b, 0xad, 0x25, 0x6e, 0x31, 0xfc, 0x90,
		0x66, 0xde, 0x7c, 0xc7, 0xe4, 0x3d, 0x13, 0x21,
		0xb1, 0x86, 0x6d, 0xb4, 0x5e, 0x90, 0x56, 0x22
	};

	/* known SHA384 hmac (48 bytes) */
	static uint8_t known_sha384_hmac[] = {
		0x19, 0x85, 0xfa, 0x21, 0x63, 0xa5, 0x94, 0x3f,
		0xc5, 0xd9, 0x2f, 0x1f, 0xe8, 0x83, 0x12, 0x15,
		0xe7, 0xe9, 0x1f, 0x0b, 0xff, 0x53, 0x32, 0xbc,
		0x71, 0x3a, 0x07, 0x2b, 0xdb, 0x3a, 0x8f, 0x9e,
		0x5c, 0x51, 0x57, 0x46, 0x3a, 0x3b, 0xfe, 0xb3,
		0x62, 0x31, 0x41, 0x6e, 0x65, 0x97, 0x3e, 0x64
	};

	/*
	 * SHA-512 HMAC Known Hash Message (512-bits).
	 * Source from NIST HMAC.txt (Count = 30, Klen = 20, Tlen = 64)
	 */
	static uint8_t sha512_hmac_known_secret_key[] = {
		0xa7, 0x36, 0xf2, 0x74, 0xfd, 0xa6, 0x8e, 0x1b,
		0xd5, 0xf9, 0x47, 0x1e, 0x85, 0xfd, 0x41, 0x5d,
		0x7f, 0x2b, 0xa1, 0xbc
	};

	static uint8_t sha512_hmac_known_secret_key_length
	    = sizeof (sha512_hmac_known_secret_key);

	static uint8_t sha512_hmac_known_hash_message[] = {
		0xa6, 0xcc, 0xc3, 0x55, 0x2c, 0x33, 0xe9, 0x17,
		0x8b, 0x6b, 0x82, 0xc6, 0x53, 0xd6, 0x3d, 0xe2,
		0x54, 0x0f, 0x17, 0x08, 0x07, 0xc3, 0xd9, 0x6a,
		0x2a, 0xc2, 0xe2, 0x7d, 0xab, 0x55, 0x26, 0xf1,
		0xc7, 0xd3, 0x77, 0xe6, 0x73, 0x6f, 0x04, 0x5d,
		0xfb, 0x54, 0x1f, 0xec, 0xe9, 0xf4, 0x43, 0xb7,
		0x28, 0x9c, 0x55, 0x9b, 0x69, 0x4c, 0x2a, 0xac,
		0xc6, 0xc7, 0x4a, 0xe2, 0xa5, 0xe6, 0xf3, 0x0f,
		0xe0, 0x31, 0x61, 0x14, 0x23, 0xb0, 0x4d, 0x55,
		0x95, 0xff, 0xb4, 0x6a, 0xba, 0xa1, 0xd9, 0x18,
		0x98, 0x96, 0x8d, 0x7f, 0x18, 0x30, 0xae, 0x94,
		0xb0, 0x22, 0xee, 0xd2, 0x3f, 0xda, 0xd5, 0x2d,
		0x38, 0x11, 0x0a, 0x48, 0x03, 0xa0, 0xce, 0xe7,
		0xa0, 0x95, 0xc9, 0xa7, 0x8e, 0x86, 0x09, 0xed,
		0xeb, 0x25, 0x48, 0x1c, 0xdc, 0x15, 0x6d, 0x0b,
		0x2f, 0xfc, 0x56, 0xb6, 0x3f, 0xda, 0xd5, 0x33
	};

	/* known SHA512 hmac (64 bytes) */
	static uint8_t known_sha512_hmac[] = {
		0xf7, 0x18, 0x03, 0x43, 0x1e, 0x07, 0xa5, 0xa6,
		0xe5, 0xfd, 0x4a, 0xe4, 0xcf, 0xc2, 0x75, 0x3b,
		0xc8, 0x0d, 0x26, 0xe1, 0x67, 0x23, 0xd9, 0xe8,
		0x8b, 0x40, 0x5a, 0x02, 0x34, 0x8e, 0xf4, 0xb9,
		0x67, 0x92, 0xc9, 0x9c, 0xed, 0x64, 0xdc, 0x70,
		0xea, 0x47, 0x53, 0x78, 0xb7, 0x46, 0x6a, 0xc2,
		0xca, 0xf4, 0xa4, 0x20, 0xb0, 0x1f, 0xf6, 0x1e,
		0x72, 0xc5, 0xb5, 0xee, 0x8e, 0xaa, 0xd4, 0xd4
	};

	/* SHA-2 variables. */
	uint8_t sha256_computed_digest[SHA256_DIGEST_LENGTH];
	uint8_t sha384_computed_digest[SHA384_DIGEST_LENGTH];
	uint8_t sha512_computed_digest[SHA512_DIGEST_LENGTH];

	uint8_t hmac_computed[SHA512_DIGEST_LENGTH];
	SHA2_CTX *sha2_context = NULL;

#ifdef _KERNEL
	sha2_hmac_ctx_t *sha2_hmac_ctx;
#endif

	int rv;

	/*
	 * SHA-2 Known Answer Hashing Test.
	 */

	/* SHA-256 POST */

#ifdef _KERNEL
	sha2_context = fips_sha2_build_context(SHA256_TYPE);
#else
	sha2_context = fips_sha2_build_context(CKM_SHA256);
#endif

	if (sha2_context == NULL)
		return (CKR_HOST_MEMORY);

	rv = fips_sha2_hash(sha2_context,
	    sha256_known_hash_message,
	    FIPS_KNOWN_HMAC_MESSAGE_LENGTH,
	    sha256_computed_digest);

	if ((rv != CKR_OK) ||
	    (memcmp(sha256_computed_digest, known_sha256_digest,
	    SHA256_DIGEST_LENGTH) != 0))
	return (CKR_DEVICE_ERROR);

	/* SHA-384 POST */

#ifdef _KERNEL
	sha2_context = fips_sha2_build_context(SHA384_TYPE);
#else
	sha2_context = fips_sha2_build_context(CKM_SHA384);
#endif

	if (sha2_context == NULL)
		return (CKR_HOST_MEMORY);

	rv = fips_sha2_hash(sha2_context,
	    sha384_known_hash_message,
	    FIPS_KNOWN_HMAC_MESSAGE_LENGTH,
	    sha384_computed_digest);

	if ((rv != CKR_OK) ||
	    (memcmp(sha384_computed_digest, known_sha384_digest,
	    SHA384_DIGEST_LENGTH) != 0))
	return (CKR_DEVICE_ERROR);

	/* SHA-512 POST */

#ifdef _KERNEL
	sha2_context = fips_sha2_build_context(SHA512_TYPE);
#else
	sha2_context = fips_sha2_build_context(CKM_SHA512);
#endif

	if (sha2_context == NULL)
		return (CKR_HOST_MEMORY);

	rv = fips_sha2_hash(sha2_context,
	    sha512_known_hash_message,
	    FIPS_KNOWN_HMAC_MESSAGE_LENGTH,
	    sha512_computed_digest);

	if ((rv != CKR_OK) ||
	    (memcmp(sha512_computed_digest, known_sha512_digest,
	    SHA512_DIGEST_LENGTH) != 0))
	return (CKR_DEVICE_ERROR);

	/*
	 * SHA-2 HMAC Known Answer Hashing Test.
	 */

	/* HMAC SHA-256 POST */

#ifdef _KERNEL
	sha2_hmac_ctx = fips_sha2_hmac_build_context(
	    SHA256_TYPE,
	    sha256_hmac_known_secret_key,
	    sha256_hmac_known_secret_key_length);

	if (sha2_hmac_ctx == NULL)
		return (CKR_HOST_MEMORY);

	fips_hmac_sha2_hash(sha2_hmac_ctx,
	    sha256_hmac_known_hash_message,
	    FIPS_KNOWN_HMAC_MESSAGE_LENGTH,
	    hmac_computed,
	    SHA256_TYPE);

	if (memcmp(hmac_computed, known_sha256_hmac,
	    SHA256_DIGEST_LENGTH) != 0)
	return (CKR_DEVICE_ERROR);

#else
	rv = fips_hmac_sha2_hash(hmac_computed,
	    sha256_hmac_known_secret_key,
	    sha256_hmac_known_secret_key_length,
	    sha256_hmac_known_hash_message,
	    FIPS_KNOWN_HMAC_MESSAGE_LENGTH,
	    CKM_SHA256_HMAC);

	if ((rv != CKR_OK) ||
	    (memcmp(hmac_computed, known_sha256_hmac,
	    SHA256_DIGEST_LENGTH) != 0))
	return (CKR_DEVICE_ERROR);

#endif

	/* HMAC SHA-384 POST */

#ifdef _KERNEL
	sha2_hmac_ctx = fips_sha2_hmac_build_context(
	    SHA384_TYPE,
	    sha384_hmac_known_secret_key,
	    sha384_hmac_known_secret_key_length);

	if (sha2_hmac_ctx == NULL)
		return (CKR_HOST_MEMORY);

	fips_hmac_sha2_hash(sha2_hmac_ctx,
	    sha384_hmac_known_hash_message,
	    sizeof (sha384_hmac_known_hash_message),
	    hmac_computed,
	    SHA384_TYPE);

	if (memcmp(hmac_computed, known_sha384_hmac,
	    SHA384_DIGEST_LENGTH) != 0)
	return (CKR_DEVICE_ERROR);
#else
	rv = fips_hmac_sha2_hash(hmac_computed,
	    sha384_hmac_known_secret_key,
	    sha384_hmac_known_secret_key_length,
	    sha384_hmac_known_hash_message,
	    sizeof (sha384_hmac_known_hash_message),
	    CKM_SHA384_HMAC);

	if ((rv != CKR_OK) ||
	    (memcmp(hmac_computed, known_sha384_hmac,
	    SHA384_DIGEST_LENGTH) != 0))
	return (CKR_DEVICE_ERROR);

#endif

	/* HMAC SHA-512 POST */

#ifdef _KERNEL
	sha2_hmac_ctx = fips_sha2_hmac_build_context(
	    SHA512_TYPE,
	    sha512_hmac_known_secret_key,
	    sha512_hmac_known_secret_key_length);

	if (sha2_hmac_ctx == NULL)
		return (CKR_HOST_MEMORY);

	fips_hmac_sha2_hash(sha2_hmac_ctx,
	    sha512_hmac_known_hash_message,
	    sizeof (sha512_hmac_known_hash_message),
	    hmac_computed,
	    SHA512_TYPE);

	if (memcmp(hmac_computed, known_sha512_hmac,
	    SHA512_DIGEST_LENGTH) != 0)
		return (CKR_DEVICE_ERROR);

#else
	rv = fips_hmac_sha2_hash(hmac_computed,
	    sha512_hmac_known_secret_key,
	    sha512_hmac_known_secret_key_length,
	    sha512_hmac_known_hash_message,
	    sizeof (sha512_hmac_known_hash_message),
	    CKM_SHA512_HMAC);

	if ((rv != CKR_OK) ||
	    (memcmp(hmac_computed, known_sha512_hmac,
	    SHA512_DIGEST_LENGTH) != 0))
	return (CKR_DEVICE_ERROR);

#endif

	return (CKR_OK);
}
