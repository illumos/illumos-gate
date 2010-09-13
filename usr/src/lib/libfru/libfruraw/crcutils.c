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

#include <string.h>
#include <limits.h>

#include "crcmodel.h"

#if defined(_LITTLE_ENDIAN)

/* Little-endian architectures need byte-swapping. */

#define	sws(x) (((x >> 8) & 0x00ff) | ((x << 8) & 0xff00))
#define	swl(x) (sws(x >> 16) | (sws(x) << 16))

#define	swap_short(x) (x = sws(x))
#define	swap_long(x) (x = swl(x))

#else   /* if !_LITTLE_ENDIAN */

/* Big-endian anchictectures don't need byte-swapping. */

#define	sws(x) (x)
#define	swl(x) (x)

#define	swap_short(x) (x = sws(x))
#define	swap_long(x) (x = swl(x))

#endif  /* _LITTLE_ENDIAN */

unsigned char
compute_crc8(unsigned char *bytes, int length)
{
	cm_t crc_mdl;
	p_cm_t p_crc;
	int i;
	unsigned char aCRC;

	p_crc = &crc_mdl;

	p_crc->cm_width = 8;
	p_crc->cm_poly = 0x107; /* = X^8 + x^2 + x + 1 */
	p_crc->cm_init = 0;
	p_crc->cm_refin = TRUE;
	p_crc->cm_refot = TRUE;
	p_crc->cm_xorot = 0;

	cm_ini(p_crc);

	for (i = 0; i < length; i++) {
		cm_nxt(p_crc, bytes[i]);
	}

	aCRC = (unsigned char)cm_crc(p_crc);

	return (aCRC);
}

uint32_t
compute_crc32(unsigned char *bytes, int length)
{
	cm_t crc_mdl;
	p_cm_t p_crc;
	int i;
	uint32_t aCRC;

	p_crc = &crc_mdl;

	p_crc->cm_width = 32;
	p_crc->cm_poly = 0x04c11db7;
	p_crc->cm_init = 0xffffffff;
	p_crc->cm_refin = TRUE;
	p_crc->cm_refot = TRUE;
	p_crc->cm_xorot = 0xffffffff;

	cm_ini(p_crc);

	for (i = 0; i < length; i++) {
		cm_nxt(p_crc, bytes[i]);
	}

	aCRC = (uint32_t)cm_crc(p_crc);

	return (aCRC);
}

/*
 * This is the max value an uint32_t value can hold...
 * Define this for Windows compilers which don't have "limits.h" or equivalant
 */
#define	UINT32_T_MAX 0xFFFFFFFF

uint32_t
compute_checksum32(unsigned char *bytes, int length)
{
	uint32_t regval = 0;
	int i, j, k;
	uint32_t next4bytes;
	unsigned char tailbytes[4] = { 0x00, 0x00, 0x00, 0x00 };

	/* Grab bytes in 4-byte chunks */
	for (i = 0; i < length-4; i += 4) {
		/* Grab chunk as an int */
		(void) memcpy(&next4bytes, &(bytes[i]), 4);
		swap_long(next4bytes);

		if (next4bytes > UINT32_T_MAX - regval) {
			next4bytes -= UINT32_T_MAX - regval;
			regval = 0;
		}

		/* Add intval to regval */
		regval += next4bytes;
	}

	/* Grab any remaining bytes at the end */
	for (j = length-1, k = 3; j >= i; j--, k--) {
		tailbytes[k] = bytes[j];
	}

/*
 * Treat any remaining bytes put into tailbytes as if they were
 * a left-zero-padded unsigned int (uint32_t == 4 bytes!)
 */
	(void) memcpy(&next4bytes, tailbytes, 4);
	swap_long(next4bytes);
	if (next4bytes > UINT32_T_MAX - regval) {
		next4bytes -= UINT32_T_MAX - regval;
		regval = 0;
	}
	regval += next4bytes;

	return ((uint32_t)regval);
}
