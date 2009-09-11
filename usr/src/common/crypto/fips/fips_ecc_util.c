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
#include <sys/fcntl.h>
#include <sys/time.h>
#include <sys/unistd.h>
#include <sys/kmem.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/crypto/common.h>
#include <sys/cmn_err.h>
#include <sys/sha1.h>
#ifndef _KERNEL
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <security/cryptoki.h>
#include "softMAC.h"
#include "softEC.h"
#endif
#include <fips/fips_post.h>
#include <ecc/ecc_impl.h>


#define	MAX_ECKEY_LEN		72
#define	SHA1_DIGEST_SIZE	20

static int
fips_ecdsa_sign_verify(uint8_t *encodedParams,
	unsigned int encodedParamsLen,
	uint8_t *knownSignature,
	unsigned int knownSignatureLen) {

	/* ECDSA Known Seed info for curves nistp256 */
	static uint8_t ecdsa_Known_Seed[] = {
		0x6a, 0x9b, 0xf6, 0xf7, 0xce, 0xed, 0x79, 0x11,
		0xf0, 0xc7, 0xc8, 0x9a, 0xa5, 0xd1, 0x57, 0xb1,
		0x7b, 0x5a, 0x3b, 0x76, 0x4e, 0x7b, 0x7c, 0xbc,
		0xf2, 0x76, 0x1c, 0x1c, 0x7f, 0xc5, 0x53, 0x2f
	};

	static uint8_t msg[] = {
		"Sun Microsystems Solaris is awesome!"
	};

	unsigned char sha1[SHA1_DIGEST_SIZE];  /* SHA-1 hash (160 bits) */
	unsigned char sig[2*MAX_ECKEY_LEN];
	SECItem signature, digest;
	SECItem encodedparams;
	ECParams *ecparams = NULL;
	ECPrivateKey *ecdsa_private_key = NULL;
	ECPublicKey ecdsa_public_key;
	SECStatus ecdsaStatus = SECSuccess;
	SHA1_CTX *sha1_context = NULL;

	/* construct the ECDSA private/public key pair */
	encodedparams.type = siBuffer;
	encodedparams.data = (unsigned char *) encodedParams;
	encodedparams.len = encodedParamsLen;

	if (EC_DecodeParams(&encodedparams, &ecparams, 0) != SECSuccess) {
		return (CKR_ARGUMENTS_BAD);
	}

	/*
	 * Generates a new EC key pair. The private key is a supplied
	 * random value (in seed) and the public key is the result of
	 * performing a scalar point multiplication of that value with
	 * the curve's base point.
	 */

	ecdsaStatus = ec_NewKey(ecparams, &ecdsa_private_key,
	    ecdsa_Known_Seed, sizeof (ecdsa_Known_Seed), 0);

	if (ecdsaStatus != SECSuccess) {
		return (CKR_DEVICE_ERROR);
	}

	/* construct public key from private key. */
	ecdsaStatus = EC_CopyParams(ecdsa_private_key->ecParams.arena,
	    &ecdsa_public_key.ecParams, &ecdsa_private_key->ecParams);

	if (ecdsaStatus != SECSuccess) {
		goto loser;
	}

	ecdsa_public_key.publicValue = ecdsa_private_key->publicValue;

	/* validate public key value */
	ecdsaStatus = EC_ValidatePublicKey(&ecdsa_public_key.ecParams,
	    &ecdsa_public_key.publicValue, 0);

	if (ecdsaStatus != SECSuccess) {
		goto loser;
	}

	/* validate public key value */
	ecdsaStatus = EC_ValidatePublicKey(&ecdsa_private_key->ecParams,
	    &ecdsa_private_key->publicValue, 0);

	if (ecdsaStatus != SECSuccess) {
		goto loser;
	}

	/*
	 * ECDSA Known Answer Signature Test.
	 */
#ifdef _KERNEL
	if ((sha1_context = kmem_zalloc(sizeof (SHA1_CTX),
	    KM_SLEEP)) == NULL)
#else
	if ((sha1_context = malloc(sizeof (SHA1_CTX))) == NULL)
#endif
		return (CKR_HOST_MEMORY);

	SHA1Init(sha1_context);

#ifdef	__sparcv9
	SHA1Update(sha1_context, msg, (uint_t)sizeof (msg));
#else	/* !__sparcv9 */
	SHA1Update(sha1_context, msg, sizeof (msg));
#endif	/* __sparcv9 */
	SHA1Final(sha1, sha1_context);

	digest.type = siBuffer;
	digest.data = sha1;
	digest.len = SHA1_DIGEST_SIZE;

	(void) memset(sig, 0, sizeof (sig));
	signature.type = siBuffer;
	signature.data = sig;
	signature.len = sizeof (sig);

	ecdsaStatus = ECDSA_SignDigestWithSeed(ecdsa_private_key, &signature,
	    &digest, ecdsa_Known_Seed, sizeof (ecdsa_Known_Seed), 0);

	if (ecdsaStatus != SECSuccess) {
		goto loser;
	}

	if ((signature.len != knownSignatureLen) ||
	    (memcmp(signature.data, knownSignature,
	    knownSignatureLen) != 0)) {
		ecdsaStatus = SECFailure;
		goto loser;
	}

	/*
	 * ECDSA Known Answer Verification Test.
	 */
	ecdsaStatus = ECDSA_VerifyDigest(&ecdsa_public_key, &signature,
	    &digest, 0);

loser:
	if (ecdsaStatus != SECSuccess) {
		return (CKR_DEVICE_ERROR);
	}

	return (CKR_OK);
}

int
fips_ecdsa_post() {

	/* ECDSA Known curve nistp256 == SEC_OID_SECG_EC_SECP256R1 params */
	static uint8_t ecdsa_known_P256_EncodedParams[] = {
		0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03,
		0x01, 0x07
	};

	static uint8_t ecdsa_known_P256_signature[] = {
		0x07, 0xb1, 0xcb, 0x57, 0x20, 0xa7, 0x10, 0xd6,
		0x9d, 0x37, 0x4b, 0x1c, 0xdc, 0x35, 0x90, 0xff,
		0x1a, 0x2d, 0x98, 0x95, 0x1b, 0x2f, 0xeb, 0x7f,
		0xbb, 0x81, 0xca, 0xc0, 0x69, 0x75, 0xea, 0xc5,
		0x2b, 0xdb, 0x86, 0x76, 0xe7, 0x32, 0xba, 0x13,
		0x03, 0x7f, 0x7f, 0x92, 0x77, 0xd8, 0x35, 0xfe,
		0x99, 0xb4, 0xb7, 0x85, 0x5a, 0xfb, 0xfb, 0xce,
		0x5d, 0x0e, 0xbc, 0x01, 0xfa, 0x44, 0x97, 0x7e
	};

	int rv;

	/* ECDSA GF(p) prime field curve test */
	rv = fips_ecdsa_sign_verify(ecdsa_known_P256_EncodedParams,
	    sizeof (ecdsa_known_P256_EncodedParams),
	    ecdsa_known_P256_signature,
	    sizeof (ecdsa_known_P256_signature));

	if (rv != CKR_OK) {
		return (CKR_DEVICE_ERROR);
	}

	return (CKR_OK);
}
