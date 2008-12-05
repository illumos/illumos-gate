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

#include <sys/types.h>

/*
 * Fast CRC32 calculation algorithm suggested by Ferenc Rakoczi
 * (ferenc.rakoczi@sun.com).  The basic idea is to look at it
 * four bytes (one word) at a time, using four tables.  The
 * standard algorithm in RFC 3309 uses one table.
 */

/*
 * SCTP uses reflected/reverse polynomial CRC32 with generating
 * polynomial 0x1EDC6F41L
 */
#define	SCTP_POLY 0x1EDC6F41L

/* The four CRC tables. */
static uint32_t crctab[4][256];

static uint32_t
reflect_32(uint32_t b)
{
	int i;
	uint32_t rw = 0;

	for (i = 0; i < 32; i++) {
		if (b & 1) {
			rw |= 1 << (31 - i);
		}
		b >>= 1;
	}
	return (rw);
}

#ifdef _BIG_ENDIAN

/*
 * This function is only used for big endian processor.
 */
static uint32_t
flip32(uint32_t w)
{
	return (((w >> 24) | ((w >> 8) & 0xff00) | ((w << 8) & 0xff0000) |
	    (w << 24)));
}

#endif

void
sctp_crc32_init(void)
{
	uint32_t i, j, k, crc;

	for (i = 0; i < 256; i++) {
		crc = reflect_32(i);
		for (k = 0; k < 4; k++) {
			for (j = 0; j < 8; j++) {
				crc = (crc & 0x80000000) ?
				    (crc << 1) ^ SCTP_POLY : crc << 1;
			}
#ifdef _BIG_ENDIAN
			crctab[3 - k][i] = flip32(reflect_32(crc));
#else
			crctab[k][i] = reflect_32(crc);
#endif
		}
	}
}

static void
sctp_crc_byte(uint32_t *crcptr, const uint8_t *buf, int len)
{
	uint32_t crc;
	int i;

	crc = *crcptr;
	for (i = 0; i < len; i++) {
#ifdef _BIG_ENDIAN
		crc = (crc << 8) ^ crctab[3][buf[i] ^ (crc >> 24)];
#else
		crc = (crc >> 8) ^ crctab[0][buf[i] ^ (crc & 0xff)];
#endif
	}
	*crcptr = crc;
}

static void
sctp_crc_word(uint32_t *crcptr, const uint32_t *buf, int len)
{
	uint32_t w, crc;
	int i;

	crc = *crcptr;
	for (i = 0; i < len; i++) {
		w = crc ^ buf[i];
		crc = crctab[0][w >> 24] ^ crctab[1][(w >> 16) & 0xff] ^
		    crctab[2][(w >> 8) & 0xff] ^ crctab[3][w & 0xff];
	}
	*crcptr = crc;
}

uint32_t
sctp_crc32(uint32_t crc32, const uint8_t *buf, int len)
{
	int rem;

	rem = 4 - ((uintptr_t)buf) & 3;
	if (rem != 0) {
		if (len < rem) {
			rem = len;
		}
		sctp_crc_byte(&crc32, buf, rem);
		buf = buf + rem;
		len = len - rem;
	}

	if (len > 3) {
		sctp_crc_word(&crc32, (const uint32_t *)buf, len / 4);
	}

	rem = len & 3;
	if (rem != 0) {
		sctp_crc_byte(&crc32, buf + len - rem, rem);
	}
	return (crc32);
}
