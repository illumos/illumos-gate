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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file contains RSA helper routines common to
 * the PKCS11 soft token code and the kernel RSA code.
 */

#include <sys/types.h>
#include "rsa_impl.h"

#ifdef _KERNEL
#include <sys/param.h>
#else
#include <strings.h>
#include "softRandom.h"
#endif

/*
 * DER encoding T of the DigestInfo values for MD5, SHA1, and SHA2
 * from PKCS#1 v2.1: RSA Cryptography Standard Section 9.2 Note 1
 *
 * MD5:     (0x)30 20 30 0c 06 08 2a 86 48 86 f7 0d 02 05 05 00 04 10 || H
 * SHA-1:   (0x)30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14 || H
 * SHA-256: (0x)30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 || H.
 * SHA-384: (0x)30 41 30 0d 06 09 60 86 48 01 65 03 04 02 02 05 00 04 30 || H.
 * SHA-512: (0x)30 51 30 0d 06 09 60 86 48 01 65 03 04 02 03 05 00 04 40 || H.
 *
 * Where H is the digested output from MD5 or SHA1. We define the constant
 * byte array (the prefix) here and use it rather than doing the DER
 * encoding of the OID in a separate routine.
 */
const CK_BYTE MD5_DER_PREFIX[MD5_DER_PREFIX_Len] = {0x30, 0x20, 0x30, 0x0c,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00,
    0x04, 0x10};

const CK_BYTE SHA1_DER_PREFIX[SHA1_DER_PREFIX_Len] = {0x30, 0x21, 0x30,
    0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14};

const CK_BYTE SHA1_DER_PREFIX_OID[SHA1_DER_PREFIX_OID_Len] = {0x30, 0x1f, 0x30,
    0x07, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x04, 0x14};

const CK_BYTE SHA256_DER_PREFIX[SHA2_DER_PREFIX_Len] = {0x30, 0x31, 0x30, 0x0d,
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20};

const CK_BYTE SHA384_DER_PREFIX[SHA2_DER_PREFIX_Len] = {0x30, 0x41, 0x30, 0x0d,
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
    0x00, 0x04, 0x30};

const CK_BYTE SHA512_DER_PREFIX[SHA2_DER_PREFIX_Len] = {0x30, 0x51, 0x30, 0x0d,
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40};


/* psize and qsize are in bits */
BIG_ERR_CODE
RSA_key_init(RSAkey *key, int psize, int qsize)
{
	BIG_ERR_CODE err = BIG_OK;

/* EXPORT DELETE START */

	int plen, qlen, nlen;

	plen = BITLEN2BIGNUMLEN(psize);
	qlen = BITLEN2BIGNUMLEN(qsize);
	nlen = plen + qlen;
	key->size = psize + qsize;
	if ((err = big_init(&(key->p), plen)) != BIG_OK)
		return (err);
	if ((err = big_init(&(key->q), qlen)) != BIG_OK)
		goto ret1;
	if ((err = big_init(&(key->n), nlen)) != BIG_OK)
		goto ret2;
	if ((err = big_init(&(key->d), nlen)) != BIG_OK)
		goto ret3;
	if ((err = big_init(&(key->e), nlen)) != BIG_OK)
		goto ret4;
	if ((err = big_init(&(key->dmodpminus1), plen)) != BIG_OK)
		goto ret5;
	if ((err = big_init(&(key->dmodqminus1), qlen)) != BIG_OK)
		goto ret6;
	if ((err = big_init(&(key->pinvmodq), qlen)) != BIG_OK)
		goto ret7;
	if ((err = big_init(&(key->p_rr), plen)) != BIG_OK)
		goto ret8;
	if ((err = big_init(&(key->q_rr), qlen)) != BIG_OK)
		goto ret9;
	if ((err = big_init(&(key->n_rr), nlen)) != BIG_OK)
		goto ret10;

	return (BIG_OK);

ret10:
	big_finish(&(key->q_rr));
ret9:
	big_finish(&(key->p_rr));
ret8:
	big_finish(&(key->pinvmodq));
ret7:
	big_finish(&(key->dmodqminus1));
ret6:
	big_finish(&(key->dmodpminus1));
ret5:
	big_finish(&(key->e));
ret4:
	big_finish(&(key->d));
ret3:
	big_finish(&(key->n));
ret2:
	big_finish(&(key->q));
ret1:
	big_finish(&(key->p));

/* EXPORT DELETE END */

	return (err);
}


void
RSA_key_finish(RSAkey *key)
{

/* EXPORT DELETE START */

	big_finish(&(key->n_rr));
	big_finish(&(key->q_rr));
	big_finish(&(key->p_rr));
	big_finish(&(key->pinvmodq));
	big_finish(&(key->dmodqminus1));
	big_finish(&(key->dmodpminus1));
	big_finish(&(key->e));
	big_finish(&(key->d));
	big_finish(&(key->n));
	big_finish(&(key->q));
	big_finish(&(key->p));

/* EXPORT DELETE END */

}


/*
 * To create a block type "02" encryption block for RSA PKCS encryption
 * process.
 *
 * The RSA PKCS Padding before encryption is in the following format:
 * +------+--------------------+----+-----------------------------+
 * |0x0002| 8 bytes or more RN |0x00|       DATA                  |
 * +------+--------------------+----+-----------------------------+
 *
 */
CK_RV
soft_encrypt_rsa_pkcs_encode(uint8_t *databuf,
    size_t datalen, uint8_t *padbuf, size_t padbuflen)
{

/* EXPORT DELETE START */

	size_t	padlen;
	CK_RV	rv;

	padlen = padbuflen - datalen;
	if (padlen < MIN_PKCS1_PADLEN) {
		return (CKR_DATA_LEN_RANGE);
	}

	/* Pad with 0x0002+non-zero pseudorandom numbers+0x00. */
	padbuf[0] = 0x00;
	padbuf[1] = 0x02;
#ifdef _KERNEL
	rv = knzero_random_generator(padbuf + 2, padbuflen - 3);
#else
	rv = soft_nzero_random_generator(padbuf + 2, padbuflen - 3);
#endif
	if (rv != CKR_OK) {
		return (rv);
	}
	padbuf[padlen - 1] = 0x00;

	bcopy(databuf, padbuf + padlen, datalen);

/* EXPORT DELETE END */

	return (CKR_OK);
}


/*
 * The RSA PKCS Padding after decryption is in the following format:
 * +------+--------------------+----+-----------------------------+
 * |0x0002| 8 bytes or more RN |0x00|       DATA                  |
 * +------+--------------------+----+-----------------------------+
 *
 * 'padbuf' points to the recovered message which is the modulus
 * length. As a result, 'plen' is changed to hold the actual data length.
 */
CK_RV
soft_decrypt_rsa_pkcs_decode(uint8_t *padbuf, int *plen)
{

/* EXPORT DELETE START */

	int	i;

	/* Check to see if the recovered data is padded is 0x0002. */
	if (padbuf[0] != 0x00 || padbuf[1] != 0x02) {
		return (CKR_ENCRYPTED_DATA_INVALID);
	}

	/* Remove all the random bits up to 0x00 (= NULL char) */
	for (i = 2; (*plen - i) > 0; i++) {
		if (padbuf[i] == 0x00) {
			i++;
			if (i < MIN_PKCS1_PADLEN) {
				return (CKR_ENCRYPTED_DATA_INVALID);
			}
			*plen -= i;

			return (CKR_OK);
		}
	}

/* EXPORT DELETE END */

	return (CKR_ENCRYPTED_DATA_INVALID);
}

/*
 * To create a block type "01" block for RSA PKCS signature process.
 *
 * The RSA PKCS Padding before Signing is in the following format:
 * +------+--------------+----+-----------------------------+
 * |0x0001| 0xFFFF.......|0x00|          DATA               |
 * +------+--------------+----+-----------------------------+
 */
CK_RV
soft_sign_rsa_pkcs_encode(uint8_t *pData, size_t dataLen, uint8_t *data,
    size_t mbit_l)
{

/* EXPORT DELETE START */

	size_t	padlen;

	padlen = mbit_l - dataLen;
	if (padlen < MIN_PKCS1_PADLEN) {
		return (CKR_DATA_LEN_RANGE);
	}

	padlen -= 3;
	data[0] = 0x00;
	data[1] = 0x01;
#ifdef _KERNEL
	kmemset(data + 2, 0xFF, padlen);
#else
	(void) memset(data + 2, 0xFF, padlen);
#endif
	data[padlen + 2] = 0x00;
	bcopy(pData, data + padlen + 3, dataLen);

/* EXPORT DELETE END */

	return (CKR_OK);
}


CK_RV
soft_verify_rsa_pkcs_decode(uint8_t *data, int *mbit_l)
{

/* EXPORT DELETE START */

	int i;

	/* Check to see if the padding of recovered data starts with 0x0001. */
	if ((data[0] != 0x00) || (data[1] != 0x01)) {
		return (CKR_SIGNATURE_INVALID);
	}
	/* Check to see if the recovered data is padded with 0xFFF...00. */
	for (i = 2; i < *mbit_l; i++) {
		if (data[i] == 0x00) {
			i++;
			if (i < MIN_PKCS1_PADLEN) {
				return (CKR_SIGNATURE_INVALID);
			}
			*mbit_l -= i;

			return (CKR_OK);
		} else if (data[i] != 0xFF) {
			return (CKR_SIGNATURE_INVALID);
		}
	}

/* EXPORT DELETE END */

	return (CKR_SIGNATURE_INVALID);
}
