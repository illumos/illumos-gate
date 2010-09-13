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
 * This is padding as decribed in Section 10.3 of RSA PKCS#7.
 *
 * The RSA PKCS Padding is in the following format:
 * +-----------------------------+----+-------------+
 * |       DATA                  |0x0k|0x0k|...|0x0k|
 * +-----------------------------+----+----+---+----+
 * where 0x0k is if data_len mod multiple = multiple - k
 * and multiple < 256 and 1 <= k <= multiple
 *
 * If databuf is non NULL, padbuf must be large enough
 * to contain both databuf and the padding.  databuf and
 * padbuf may be the same buffer.
 * databuf:
 * +-----------------------------+
 * |       DATA                  |
 * +-----------------------------+
 *                           datalen
 * padbuf:
 * +-----------------------------+----+-------------+
 * |       DATA                  |0x0k|0x0k|...|0x0k|
 * +-----------------------------+----+----+---+----+
 *                           datalen          padbuflen
 *
 * If databuf is NULL, padbuf only needs to be large
 * enough for the padding, and datalen must still be
 * provided to compute the padding value:
 *				 padbuf:
 *                               +----+-------------+
 *                               |0x0k|0x0k|...|0x0k|
 *                               +----+----+---+----+
 *                           datalen           padbuflen
 */
int
pkcs7_encode(uint8_t *databuf, size_t datalen, uint8_t *padbuf,
    size_t padbuflen, uint8_t multiple)
{
	size_t	padlen;

	padlen = multiple - (datalen % multiple);
	if (databuf == NULL)
		datalen = 0;

	if (padlen > padbuflen - datalen) {
		return (CKR_DATA_LEN_RANGE);
	}

	bcopy(databuf, padbuf, datalen);
	(void) memset(padbuf + datalen, padlen & 0xff, padlen);

	return (0);
}

/*
 * 'padbuf' points to the recovered message.  Strip off the padding and
 * validate it as much as possible.  'plen' is changed to hold the actual
 * data length.  'padbuf' is unchanged.
 */
int
pkcs7_decode(uint8_t *padbuf, size_t *plen)
{
	int	i;
	size_t	padlen;

	/* Recover the padding value, even if padbuf has trailing nulls */
	while (*plen > 0 && (padlen = padbuf[*plen - 1]) == 0)
		(*plen)--;

	/* Must have non-zero padding */
	if (padlen == 0)
		return (CKR_ENCRYPTED_DATA_INVALID);

	/* Count back from all padding bytes; lint tag is for *plen-1-i >= 0 */
	/* LINTED E_SUSPICIOUS_COMPARISON */
	for (i = 0; i < padlen && (*plen - 1 - i) >= 0; i++) {
		if (padbuf[*plen - 1 - i] != (padlen & 0xff))
			return (CKR_ENCRYPTED_DATA_INVALID);
	}
	*plen -= i;
	return (0);
}
