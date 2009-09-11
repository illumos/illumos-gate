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

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <sys/types.h>
#include <security/cryptoki.h>
#include <sys/sha1.h>
#include <sys/sha2.h>
#include "softMAC.h"
#define	_AES_FIPS_POST
#define	_DES_FIPS_POST
#include "softCrypt.h"
#define	_RSA_FIPS_POST
#include <rsa_impl.h>
#include <sha1_impl.h>
#include <sha2_impl.h>
#include <fips_random.h>


extern int fips_ecdsa_post(void);
extern CK_RV soft_fips_dsa_post(void);


/*
 * FIPS Power-on SelfTest for the supported FIPS ciphers and
 * components.
 */
CK_RV
soft_fips_post(void)
{
	CK_RV rv;

	/*
	 * SHA-1 Power-On SelfTest.
	 *
	 * 1. SHA-1 POST
	 * 2. HMAC SHA-1 POST
	 */
	rv = fips_sha1_post();
	if (rv != CKR_OK)
		return (rv);

	/*
	 * SHA-2 Power-On SelfTest.
	 *
	 * 1. SHA-256 POST
	 * 2. SHA-384 POST
	 * 3. SHA-512 POST
	 * 4. HMAC SHA-256 POST
	 * 5. HMAC SHA-384 POST
	 * 6. HMAC SHA-512 POST
	 */
	rv = fips_sha2_post();

	if (rv != CKR_OK)
	return (rv);


	/*
	 * Triple DES Power-On SelfTest.
	 *
	 * 1. DES3 ECB Encryption/Decryption
	 * 2. DES3 CBC Encryption/Decryption
	 */
	rv = fips_des3_post();

	if (rv != CKR_OK)
		return (rv);

	/* AES Power-On SelfTest for 128-bit key. */
	rv = fips_aes_post(FIPS_AES_128_KEY_SIZE);

	if (rv != CKR_OK)
		return (rv);

	/* AES Power-On SelfTest for 192-bit key. */
	rv = fips_aes_post(FIPS_AES_192_KEY_SIZE);

	if (rv != CKR_OK)
		return (rv);

	/* AES Power-On SelfTest for 256-bit key. */
	rv = fips_aes_post(FIPS_AES_256_KEY_SIZE);

	if (rv != CKR_OK)
		return (rv);

	/*
	 * ECDSA Power-Up SelfTest
	 *
	 * 1. ECC Signature
	 * 2. ECC Verification
	 */
	rv = fips_ecdsa_post();

	if (rv != CKR_OK)
		return (rv);

	/*
	 * RSA Power-On SelfTest
	 *
	 * 1. RSA Encryption
	 * 2. RSA Decryption
	 * 3. RSA SHA-1 Sign/Verify
	 * 4. RSA SHA-256 Sign/Verify
	 * 5. RSA SHA-384 Sign/Verify
	 * 6. RSA SHA-512 Sign/Verify
	 *
	 */
	rv = fips_rsa_post();

	if (rv != CKR_OK)
		return (rv);

	/*
	 * DSA Power-On SelfTest
	 *
	 * 1. DSA Sign on SHA-1 digest
	 * 2. DSA Verification
	 */
	rv = soft_fips_dsa_post();

	if (rv != CKR_OK)
		return (rv);

	/* RNG Power-On SelfTest. */
	rv = fips_rng_post();

	if (rv != CKR_OK)
		return (rv);

	/* Passed Power-On SelfTest. */
	return (CKR_OK);
}
