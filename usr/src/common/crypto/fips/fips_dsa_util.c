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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/types.h>
#include <sys/sha1.h>
#define	_SHA2_IMPL
#include <sys/sha2.h>

#ifdef	_KERNEL
#include <sys/param.h>
#include <sys/kmem.h>
#else
#include <strings.h>
#include <cryptoutil.h>
#include "softMAC.h"
#endif

#include <security/cryptoki.h>
#include <sys/crypto/common.h>

#include <sha1/sha1_impl.h>
#define	_DSA_FIPS_POST
#include <dsa/dsa_impl.h>


/* DSA Known P (1024-bits), Q (160-bits), and G (1024-bits) Values. */
static uint8_t dsa_P[] = {
	0x80, 0xb0, 0xd1, 0x9d, 0x6e, 0xa4, 0xf3, 0x28,
	0x9f, 0x24, 0xa9, 0x8a, 0x49, 0xd0, 0x0c, 0x63,
	0xe8, 0x59, 0x04, 0xf9, 0x89, 0x4a, 0x5e, 0xc0,
	0x6d, 0xd2, 0x67, 0x6b, 0x37, 0x81, 0x83, 0x0c,
	0xfe, 0x3a, 0x8a, 0xfd, 0xa0, 0x3b, 0x08, 0x91,
	0x1c, 0xcb, 0xb5, 0x63, 0xb0, 0x1c, 0x70, 0xd0,
	0xae, 0xe1, 0x60, 0x2e, 0x12, 0xeb, 0x54, 0xc7,
	0xcf, 0xc6, 0xcc, 0xae, 0x97, 0x52, 0x32, 0x63,
	0xd3, 0xeb, 0x55, 0xea, 0x2f, 0x4c, 0xd5, 0xd7,
	0x3f, 0xda, 0xec, 0x49, 0x27, 0x0b, 0x14, 0x56,
	0xc5, 0x09, 0xbe, 0x4d, 0x09, 0x15, 0x75, 0x2b,
	0xa3, 0x42, 0x0d, 0x03, 0x71, 0xdf, 0x0f, 0xf4,
	0x0e, 0xe9, 0x0c, 0x46, 0x93, 0x3d, 0x3f, 0xa6,
	0x6c, 0xdb, 0xca, 0xe5, 0xac, 0x96, 0xc8, 0x64,
	0x5c, 0xec, 0x4b, 0x35, 0x65, 0xfc, 0xfb, 0x5a,
	0x1b, 0x04, 0x1b, 0xa1, 0x0e, 0xfd, 0x88, 0x15
};

static uint8_t dsa_Q[] = {
	0xad, 0x22, 0x59, 0xdf, 0xe5, 0xec, 0x4c, 0x6e,
	0xf9, 0x43, 0xf0, 0x4b, 0x2d, 0x50, 0x51, 0xc6,
	0x91, 0x99, 0x8b, 0xcf
};

static uint8_t dsa_G[] = {
	0x78, 0x6e, 0xa9, 0xd8, 0xcd, 0x4a, 0x85, 0xa4,
	0x45, 0xb6, 0x6e, 0x5d, 0x21, 0x50, 0x61, 0xf6,
	0x5f, 0xdf, 0x5c, 0x7a, 0xde, 0x0d, 0x19, 0xd3,
	0xc1, 0x3b, 0x14, 0xcc, 0x8e, 0xed, 0xdb, 0x17,
	0xb6, 0xca, 0xba, 0x86, 0xa9, 0xea, 0x51, 0x2d,
	0xc1, 0xa9, 0x16, 0xda, 0xf8, 0x7b, 0x59, 0x8a,
	0xdf, 0xcb, 0xa4, 0x67, 0x00, 0x44, 0xea, 0x24,
	0x73, 0xe5, 0xcb, 0x4b, 0xaf, 0x2a, 0x31, 0x25,
	0x22, 0x28, 0x3f, 0x16, 0x10, 0x82, 0xf7, 0xeb,
	0x94, 0x0d, 0xdd, 0x09, 0x22, 0x14, 0x08, 0x79,
	0xba, 0x11, 0x0b, 0xf1, 0xff, 0x2d, 0x67, 0xac,
	0xeb, 0xb6, 0x55, 0x51, 0x69, 0x97, 0xa7, 0x25,
	0x6b, 0x9c, 0xa0, 0x9b, 0xd5, 0x08, 0x9b, 0x27,
	0x42, 0x1c, 0x7a, 0x69, 0x57, 0xe6, 0x2e, 0xed,
	0xa9, 0x5b, 0x25, 0xe8, 0x1f, 0xd2, 0xed, 0x1f,
	0xdf, 0xe7, 0x80, 0x17, 0xba, 0x0d, 0x4d, 0x38
};

/*
 * DSA Known Random Values (known random key block is 160-bits)
 * and (known random signature block is 160-bits).
 */
static uint8_t dsa_known_random_key_block[] = {
	"This is DSA RNG key!"
};

static uint8_t dsa_known_random_signature_block[] = {
	"Random DSA Signature"
};

/* DSA Known Digest (160-bits) */
static uint8_t dsa_known_digest[] = {
	"DSA Signature Digest"
};

/* DSA Known Signature (320-bits). */
static uint8_t dsa_known_signature[] = {
	0x25, 0x7c, 0x3a, 0x79, 0x32, 0x45, 0xb7, 0x32,
	0x70, 0xca, 0x62, 0x63, 0x2b, 0xf6, 0x29, 0x2c,
	0x22, 0x2a, 0x03, 0xce, 0x65, 0x02, 0x72, 0x5a,
	0x66, 0x29, 0xcf, 0x56, 0xe6, 0xdf, 0xb0, 0xcc,
	0x53, 0x72, 0x56, 0x70, 0x92, 0xb5, 0x45, 0x75

};


static int
fips_dsa_random_func(void *buf, size_t buflen)
{
	/* should not happen */
	if (buflen != FIPS_DSA_SEED_LENGTH)
		return (-1);

	(void) memcpy(buf, dsa_known_random_key_block,
	    FIPS_DSA_SEED_LENGTH);
	return (0);
}

static int
fips_dsa_signature_func(void *buf, size_t buflen)
{
	/* should not happen */
	if (buflen != FIPS_DSA_SEED_LENGTH)
		return (-1);

	(void) memcpy(buf, dsa_known_random_signature_block,
	    FIPS_DSA_SEED_LENGTH);
	return (0);
}

int
fips_dsa_genkey_pair(DSAbytekey *bkey)
{
	return (dsa_genkey_pair(bkey));
}

int
fips_dsa_digest_sign(DSAbytekey *bkey,
	uint8_t *in, uint32_t inlen, uint8_t *out)
{
	CK_RV rv;
	SHA1_CTX *sha1_context;
	uint8_t sha1_computed_digest[FIPS_DSA_DIGEST_LENGTH];

	sha1_context = fips_sha1_build_context();
	if (sha1_context == NULL)
		return (CKR_HOST_MEMORY);

	rv = fips_sha1_hash(sha1_context, in, inlen, sha1_computed_digest);
	if (rv != CKR_OK)
		goto clean1;

	rv = dsa_sign(bkey, sha1_computed_digest, FIPS_DSA_DIGEST_LENGTH, out);

clean1:
#ifdef _KERNEL
	kmem_free(sha1_context, sizeof (SHA1_CTX));
#else
	free(sha1_context);
#endif
	return (rv);
}

int
fips_dsa_verify(DSAbytekey *bkey, uint8_t *data, uint8_t *sig)
{
	CK_RV rv;
	SHA1_CTX *sha1_context;
	uint8_t sha1_computed_digest[FIPS_DSA_DIGEST_LENGTH];

	sha1_context = fips_sha1_build_context();
	if (sha1_context == NULL)
		return (CKR_HOST_MEMORY);

	rv = fips_sha1_hash(sha1_context, data, FIPS_DSA_DIGEST_LENGTH,
	    sha1_computed_digest);
	if (rv != CKR_OK)
		goto clean1;

	rv = dsa_verify(bkey, sha1_computed_digest, sig);

clean1:
#ifdef _KERNEL
	kmem_free(sha1_context, sizeof (SHA1_CTX));
#else
	free(sha1_context);
#endif
	return (rv);
}

/*
 * DSA Power-On SelfTest(s).
 */
int
fips_dsa_post(void)
{
	DSAbytekey dsa_params;
	CK_RV rv;
	uint8_t dsa_computed_signature[FIPS_DSA_SIGNATURE_LENGTH];

	/*
	 * Generate a DSA public/private key pair.
	 */
	dsa_params.prime = dsa_P;
	dsa_params.prime_bits = CRYPTO_BYTES2BITS(FIPS_DSA_PRIME_LENGTH);
	dsa_params.subprime = dsa_Q;
	dsa_params.subprime_bits = CRYPTO_BYTES2BITS(FIPS_DSA_SUBPRIME_LENGTH);
	dsa_params.base = dsa_G;
	dsa_params.base_bytes = FIPS_DSA_BASE_LENGTH;

	dsa_params.rfunc = fips_dsa_random_func;

	rv = fips_dsa_genkey_pair(&dsa_params);
	if (rv != CKR_OK)
		return (CKR_DEVICE_ERROR);

	/*
	 * DSA Known Answer Signature Test
	 */

	dsa_params.rfunc = fips_dsa_signature_func;

	/* Perform DSA signature process. */
	rv = fips_dsa_digest_sign(&dsa_params,
	    dsa_known_digest, FIPS_DSA_DIGEST_LENGTH, dsa_computed_signature);

	if ((rv != CKR_OK) ||
	    (memcmp(dsa_computed_signature, dsa_known_signature,
	    FIPS_DSA_SIGNATURE_LENGTH) != 0)) {
		goto clean;
	}

	/*
	 * DSA Known Answer Verification Test
	 */

	/* Perform DSA verification process. */
	rv = fips_dsa_verify(&dsa_params,
	    dsa_known_digest, dsa_computed_signature);

clean:
	if (rv != CKR_OK)
		return (CKR_DEVICE_ERROR);
	else
		return (CKR_OK);
}
