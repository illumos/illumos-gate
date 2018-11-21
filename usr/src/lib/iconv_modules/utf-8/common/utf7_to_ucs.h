/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 1998-1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	UTF7_TO_UCS_H
#define	UTF7_TO_UCS_H


#include "common_defs.h"


/* Modified Base64 alphabet to Value mapping table -- see RFC 2045. */
static const signed char rmb64[0x100] = {
/*00*/  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
/*10*/  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
/*20*/  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
/*30*/  52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
/*40*/  -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
/*50*/  15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
/*60*/  -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
/*70*/  41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
/*80*/  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
/*90*/  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
/*a0*/  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
/*b0*/  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
/*c0*/  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
/*d0*/  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
/*e0*/  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
/*f0*/  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};

/*
 * Any UCS-2 character sequences will yield:
 *
 * +-16 bits (UCS-2)-+  +-16 bits (UCS-2)-+  +-16 bits (UCS-2)-+
 * |                 |  |                 |  |                 |
 * xxxx xxxx xxxx xxxx  xxxx xxxx xxxx xxxx  xxxx xxxx xxxx xxxx
 * |     ||     | |      ||     | |     ||      | |     ||     |
 * +--0--++--1--+ +---2--++--3--+ +--4--++---5--+ +--6--++--7--+ MBase64 chars
 *                ^                      ^
 * initially,     |                      |
 *                four remnant bits,     |
 *                                       two remnant bits,
 *
 * and, then no remnant bit for three sequential UCS-2 characters,
 * respectively, and repeat these three UCS-2 character sequences. For the
 * first UCS-2 character in this sequence, there will be two MBase64
 * characters, and for the second and the third UCS-2 characters, there will be
 * three MBase64 characters.
 *
 * Following action numbers, 0, 2, 5, and, 7, are assigned to each of
 * corresponding MBase64 characters that can either yield a UCS-2 character or
 * indicate a character that is the starting/initial one.
 */
#define	ICV_U7_ACTION_START			0
#define	ICV_U7_ACTION_HARVEST1			2
#define	ICV_U7_ACTION_HARVEST2			5
#define	ICV_U7_ACTION_HARVEST3			7

#define	ICV_U7_UCS4_OUTOFUTF16			0xfffefeff

#define OUTBUF_SIZE_CHECK(sz) \
	if ((obtail - ob) < (sz)) { \
		errno = E2BIG; \
		ret_val = (size_t)-1; \
		break; \
	}

/*
 * For better performance and readability, we perfer to write macros like
 * below instead of putting them in functions and then calling them.
 */
#define CHECK_OUTBUF_SZ_AND_WRITE_U2 \
	obsz = (cd->bom_written) ? ICV_FETCH_UCS_SIZE : ICV_FETCH_UCS_SIZE_TWO;\
	if ((obtail - ob) < obsz) { \
		errno = E2BIG; \
		ret_val = (size_t)-1; \
		break; \
	} \
	if (cd->little_endian) { \
		if (! cd->bom_written) { \
			*ob++ = (uchar_t)0xff; \
			*ob++ = (uchar_t)0xfe; \
			cd->bom_written = true; \
		} \
		*ob++ = (uchar_t)(u4 & 0xff); \
		*ob++ = (uchar_t)((u4 >> 8) & 0xff); \
	} else { \
		if (! cd->bom_written) { \
			*ob++ = (uchar_t)0xfe; \
			*ob++ = (uchar_t)0xff; \
			cd->bom_written = true; \
		} \
		*ob++ = (uchar_t)((u4 >> 8) & 0xff); \
		*ob++ = (uchar_t)(u4 & 0xff); \
	}

#define CHECK_OUTBUF_SZ_AND_WRITE_U4 \
	obsz = (cd->bom_written) ? ICV_FETCH_UCS_SIZE : ICV_FETCH_UCS_SIZE_TWO;\
	if ((obtail - ob) < obsz) { \
		errno = E2BIG; \
		ret_val = (size_t)-1; \
		break; \
	} \
	if (cd->little_endian) { \
		if (! cd->bom_written) { \
			*ob++ = (uchar_t)0xff; \
			*ob++ = (uchar_t)0xfe; \
			*(ushort_t *)ob = (ushort_t)0; \
			ob += 2; \
			cd->bom_written = true; \
		} \
		*ob++ = (uchar_t)(u4 & 0xff); \
		*ob++ = (uchar_t)((u4 >> 8) & 0xff); \
		*ob++ = (uchar_t)((u4 >> 16) & 0xff); \
		*ob++ = (uchar_t)((u4 >> 24) & 0xff); \
	} else { \
		if (! cd->bom_written) { \
			*(ushort_t *)ob = (ushort_t)0; \
			ob += 2; \
			*ob++ = (uchar_t)0xfe; \
			*ob++ = (uchar_t)0xff; \
			cd->bom_written = true; \
		} \
		*ob++ = (uchar_t)((u4 >> 24) & 0xff); \
		*ob++ = (uchar_t)((u4 >> 16) & 0xff); \
		*ob++ = (uchar_t)((u4 >> 8) & 0xff); \
		*ob++ = (uchar_t)(u4 & 0xff); \
	}

/*
 * UTF-7's code range is basically that of UTF-16, i.e.,
 * U+0000 0000 ~ U+0010 FFFF, it cannot go beyond the U+0010 FFFF.
 */
#define	CHECK_OUTBUF_SZ_AND_WRITE_U8_OR_EILSEQ \
	if (u4 <= 0x7f) { \
		OUTBUF_SIZE_CHECK(1); \
		*ob++ = (uchar_t)u4; \
	} else if (u4 <= 0x7ff) { \
		OUTBUF_SIZE_CHECK(2); \
		*ob++ = (uchar_t)(0xc0 | ((u4 & 0x07c0) >> 6)); \
		*ob++ = (uchar_t)(0x80 |  (u4 & 0x003f)); \
	} else if (u4 <= 0x00ffff) { \
		OUTBUF_SIZE_CHECK(3); \
		*ob++ = (uchar_t)(0xe0 | ((u4 & 0x0f000) >> 12)); \
		*ob++ = (uchar_t)(0x80 | ((u4 & 0x00fc0) >> 6)); \
		*ob++ = (uchar_t)(0x80 |  (u4 & 0x0003f)); \
	} else if (u4 <= 0x10ffff) { \
		OUTBUF_SIZE_CHECK(4); \
		*ob++ = (uchar_t)(0xf0 | ((u4 & 0x01c0000) >> 18)); \
		*ob++ = (uchar_t)(0x80 | ((u4 & 0x003f000) >> 12)); \
		*ob++ = (uchar_t)(0x80 | ((u4 & 0x0000fc0) >> 6)); \
		*ob++ = (uchar_t)(0x80 |  (u4 & 0x000003f)); \
	} else { \
		errno = EILSEQ; \
		ret_val = (size_t)-1; \
		break; \
	}


#endif	/* UTF7_TO_UCS_H */
