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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * This file contains padding helper routines common to
 * the PKCS11 soft token code and the kernel crypto code.
 */

#include <sys/types.h>
#include "padding.h"

#ifdef _KERNEL
#include <sys/param.h>
#else
#include <strings.h>
#include <cryptoutil.h>
#endif

/*
 * To create a block type "02" encryption block for RSA PKCS encryption
 * process.
 *
 * This is EME-PKCS1-v1_5 encoding as described in RSA PKCS#1.
 *
 * The RSA PKCS Padding before encryption is in the following format:
 * +----+----+--------------------+----+-----------------------------+
 * |0x00|0x02| 8 bytes or more RN |0x00|       DATA                  |
 * +----+----+--------------------+----+-----------------------------+
 *
 *
 * To create a block type "01" block for RSA PKCS signature process.
 *
 * This EMSA-PKCS1-1_5 encoding as decribed in RSA PKCS#1.
 *
 * The RSA PKCS Padding before Signing is in the following format:
 * +----+----+----------------------+----+-----------------------------+
 * |0x00|0x01| 8 bytes of more 0xFF |0x00|          DATA               |
 * +----+----+----------------------+----+-----------------------------+
 *
 */
int
pkcs1_encode(int method, uint8_t *databuf, size_t datalen, uint8_t *padbuf,
    size_t padbuflen)
{
	size_t	padlen;
	int	rv;

	padlen = padbuflen - datalen;
	if (padlen < MIN_PKCS1_PADLEN) {
		return (CKR_DATA_LEN_RANGE);
	}

	rv = 0;

	padbuf[0] = 0x00;
	padbuf[1] = (method == PKCS1_ENCRYPT) ? 0x02 : 0x01;

	if (method == PKCS1_ENCRYPT) {
#ifdef _KERNEL
		rv = knzero_random_generator(padbuf + 2, padlen - 3);
#else
		rv = (pkcs11_get_nzero_urandom(padbuf + 2, padlen - 3) < 0) ?
		    CKR_DEVICE_ERROR : 0;
#endif
	} else if (method == PKCS1_SIGN) {
#ifdef _KERNEL
		kmemset(padbuf + 2, 0xFF, padlen - 3);
#else
		(void) memset(padbuf + 2, 0xFF, padlen - 3);
#endif
	}

	if (rv != 0) {
		return (rv);
	}

	padbuf[padlen - 1] = 0x00;

	bcopy(databuf, padbuf + padlen, datalen);

	return (0);
}

/*
 * The RSA PKCS Padding in the following format:
 * +----+----+-------------------------+----+------------------------+
 * |0x00| BT | 8 bytes or more padding |0x00|       DATA             |
 * +----+----+-+++++-------------------+----+------------------------+
 * where BT is block type: 0x02 for encrypt/decrypt, 0x01 for sign/verify
 *
 * 'padbuf' points to the recovered message.  Strip off the padding and
 * validate it as much as possible.  'plen' is changed to hold the actual
 * data length.
 */
int
pkcs1_decode(int method, uint8_t *padbuf, size_t *plen)
{
	int	rv = ((method == PKCS1_DECRYPT) ? CKR_ENCRYPTED_DATA_INVALID :
	    CKR_SIGNATURE_INVALID);
	int	i;

	/* Check to see if the recovered data is padded is 0x0002 or 0x0001. */
	if (padbuf[0] != 0x00 || padbuf[1] != (method == PKCS1_DECRYPT ?
	    0x02 : 0x01)) {
		return (rv);
	}

	/* Remove all the random bits up to 0x00 (= NULL char) */
	for (i = 2; (*plen - i) > 0; i++) {
		if (padbuf[i] == 0x00) {
			i++;
			if (i < MIN_PKCS1_PADLEN) {
				return (rv);
			}
			*plen -= i;

			return (0);
		} else if (method == PKCS1_VERIFY && padbuf[i] != 0xFF) {
			return (rv);
		}
	}

	return (rv);
}
