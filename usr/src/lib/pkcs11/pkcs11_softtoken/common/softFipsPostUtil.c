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
#include <sys/sha1.h>
#define	_SHA2_IMPL
#include <sys/sha2.h>
#include <sys/crypto/common.h>
#include <modes/modes.h>
#include <bignum.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <security/cryptoki.h>
#include <cryptoutil.h>
#include "softCrypt.h"
#include "softGlobal.h"
#include "softRSA.h"
#include "softDSA.h"
#include "softRandom.h"
#include "softOps.h"
#include "softMAC.h"
#include <fips_post.h>

#define	FIPS_DSA_SIGNATURE_LENGTH	40 /*  320-bits */
#define	MAX_ECKEY_LEN		72


/*
 * FIPS 140-2 pairwise consistency check utilized to validate key pair.
 *
 * This function returns
 *   CKR_OK               if pairwise consistency check passed
 *   CKR_GENERAL_ERROR    if pairwise consistency check failed
 *   other error codes    if paiswise consistency check could not be
 *                        performed, for example, CKR_HOST_MEMORY.
 *
 *                      Key type    Mechanism type
 *                      --------------------------------
 *
 * For sign/verify:     CKK_RSA  => CKM_SHA1_RSA_PKCS
 *                      CKK_DSA  => CKM_DSA_SHA1
 *                      CKK_EC   => CKM_ECDSA_SHA1
 *                      others   => CKM_INVALID_MECHANISM
 *
 * None of these mechanisms has a parameter.
 */
CK_RV
fips_pairwise_check(soft_session_t *session_p,
	soft_object_t *publicKey, soft_object_t *privateKey,
	CK_KEY_TYPE keyType)
{

	CK_MECHANISM mech = {0, NULL, 0};
	uchar_t modulus[MAX_KEY_ATTR_BUFLEN];
	uint32_t modulus_len = sizeof (modulus);
	boolean_t can_sign_verify = B_FALSE;
	CK_RV rv;

	/* Variables used for Signature/Verification functions. */
	/* always uses SHA-1 digest */
	unsigned char *known_digest = (unsigned char *)"OpenSolarisCommunity";
	unsigned char *signature;
	CK_ULONG signature_length;

	if (keyType == CKK_RSA) {
		/* Get modulus length of private key. */
		rv = soft_get_private_value(privateKey, CKA_MODULUS,
		    modulus, &modulus_len);
		if (rv != CKR_OK) {
			return (CKR_DEVICE_ERROR);
		}
	}

	/*
	 * Pairwise Consistency Check of Sign/Verify
	 */

	/* Check to see if key object supports signature. */
	can_sign_verify = (privateKey->bool_attr_mask & SIGN_BOOL_ON);

	if (can_sign_verify) {
		/* Determine length of signature. */
		switch (keyType) {
		case CKK_RSA:
			signature_length = modulus_len;
			mech.mechanism = CKM_SHA1_RSA_PKCS;
			break;

		case CKK_DSA:
			signature_length = FIPS_DSA_SIGNATURE_LENGTH;
			mech.mechanism = CKM_DSA_SHA1;
			break;

		case CKK_EC:
			signature_length = MAX_ECKEY_LEN * 2;
			mech.mechanism = CKM_ECDSA_SHA1;
			break;

		default:
			return (CKR_DEVICE_ERROR);
		}

		/* Allocate space for signature data. */
		signature = (unsigned char *) calloc(1, signature_length);
		if (signature == NULL) {
			return (CKR_HOST_MEMORY);
		}

		/* Sign the known hash using the private key. */
		rv = soft_sign_init(session_p, &mech, privateKey);
		if (rv != CKR_OK) {
			free(signature);
			return (rv);
		}

		rv = soft_sign(session_p, known_digest, PAIRWISE_DIGEST_LENGTH,
		    signature, &signature_length);
		if (rv != CKR_OK) {
			free(signature);
			return (rv);
		}

		/* Verify the known hash using the public key. */
		rv = soft_verify_init(session_p, &mech, publicKey);
		if (rv != CKR_OK) {
			free(signature);
			return (rv);
		}

		rv = soft_verify(session_p, known_digest,
		    PAIRWISE_DIGEST_LENGTH, signature,
		    signature_length);

		/* Free signature data. */
		free(signature);
		if ((rv == CKR_SIGNATURE_LEN_RANGE) ||
		    (rv == CKR_SIGNATURE_INVALID)) {
			return (CKR_GENERAL_ERROR);
		}

		if (rv != CKR_OK) {
			return (rv);
		}
	}

	return (CKR_OK);
}
