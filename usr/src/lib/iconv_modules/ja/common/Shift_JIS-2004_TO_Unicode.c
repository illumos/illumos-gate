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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <stdlib.h>
#include <errno.h>
#include <euc.h>
#include "japanese.h"
#include "jfp_iconv_unicode.h"

#define	JFP_J2U_ICONV_X0213
#include "jfp_jis_to_ucs2.h"

typedef struct {
	unsigned char	odd_row;
	unsigned char	even_row;
} sj1torow_t;

static const sj1torow_t sj1torow_x0213_p1b1[] = {
               /* 40-9e  9f-fc */
     /* 0x81 */ {     1,     2 },
     /* 0x82 */ {     3,     4 },
     /* 0x83 */ {     5,     6 },
     /* 0x84 */ {     7,     8 },
     /* 0x85 */ {     9,    10 },
     /* 0x86 */ {    11,    12 },
     /* 0x87 */ {    13,    14 },
     /* 0x88 */ {    15,    16 },
     /* 0x89 */ {    17,    18 },
     /* 0x8a */ {    19,    20 },
     /* 0x8b */ {    21,    22 },
     /* 0x8c */ {    23,    24 },
     /* 0x8d */ {    25,    26 },
     /* 0x8e */ {    27,    28 },
     /* 0x8f */ {    29,    30 },
     /* 0x90 */ {    31,    32 },
     /* 0x91 */ {    33,    34 },
     /* 0x92 */ {    35,    36 },
     /* 0x93 */ {    37,    38 },
     /* 0x94 */ {    39,    40 },
     /* 0x95 */ {    41,    42 },
     /* 0x96 */ {    43,    44 },
     /* 0x97 */ {    45,    46 },
     /* 0x98 */ {    47,    48 },
     /* 0x99 */ {    49,    50 },
     /* 0x9a */ {    51,    52 },
     /* 0x9b */ {    53,    54 },
     /* 0x9c */ {    55,    56 },
     /* 0x9d */ {    57,    58 },
     /* 0x9e */ {    59,    60 },
     /* 0x9f */ {    61,    62 },
};

static const sj1torow_t sj1torow_x0213_p1b2[] = {
               /* 40-9e  9f-fc */
     /* 0xe0 */ {    63,    64 },
     /* 0xe1 */ {    65,    66 },
     /* 0xe2 */ {    67,    68 },
     /* 0xe3 */ {    69,    70 },
     /* 0xe4 */ {    71,    72 },
     /* 0xe5 */ {    73,    74 },
     /* 0xe6 */ {    75,    76 },
     /* 0xe7 */ {    77,    78 },
     /* 0xe8 */ {    79,    80 },
     /* 0xe9 */ {    81,    82 },
     /* 0xea */ {    83,    84 },
     /* 0xeb */ {    85,    86 },
     /* 0xec */ {    87,    88 },
     /* 0xed */ {    89,    90 },
     /* 0xee */ {    91,    92 },
     /* 0xef */ {    93,    94 },
};

static const sj1torow_t sj1torow_x0213_p2[] = {
               /* 40-9e  9f-fc */
     /* 0xf0 */ {     1,     8 },
     /* 0xf1 */ {     3,     4 },
     /* 0xf2 */ {     5,    12 },
     /* 0xf3 */ {    13,    14 },
     /* 0xf4 */ {    15,    78 },
     /* 0xf5 */ {    79,    80 },
     /* 0xf6 */ {    81,    82 },
     /* 0xf7 */ {    83,    84 },
     /* 0xf8 */ {    85,    86 },
     /* 0xf9 */ {    87,    88 },
     /* 0xfa */ {    89,    90 },
     /* 0xfb */ {    91,    92 },
     /* 0xfc */ {    93,    94 },
};

static unsigned short sjtoe16_x0213(unsigned char c1, unsigned char c2)
{
	const sj1torow_t	*p;
	unsigned short		e16;

	/* range check (if valid or not) for c1 and c2 has been done
	   by the caller side */

	if ((c1 >= 0x81) && (c1 <= 0x9f)) {
		p = &(sj1torow_x0213_p1b1[c1 - 0x81]);
	} else if ((c1 >= 0xe0) && (c1 <= 0xef)) {
		p = &(sj1torow_x0213_p1b2[c1 - 0xe0]);
	} else {
		p = &(sj1torow_x0213_p2[c1 - 0xf0]);
	}

	if (c2 >= 0x9f) {
		e16 = (p->even_row + 0xa0) << 8;
		e16 |= (c2 - 0x9f + 0x21);
		e16 |= (c1 <= 0xef) ? 0x0080 : 0x0000;
	} else {
		e16 = (p->odd_row + 0xa0) << 8;
		e16 |= (c2 - 0x40 + 0x21);
		if (c2 >= 0x80) {
			e16--;
		}
		e16 |= (c1 <= 0xef) ? 0x0080 : 0x0000;
	}

	return (e16);
}

void *
_icv_open(void)
{
	return (_icv_open_unicode((size_t)0));
}

void
_icv_close(void *cd)
{
	_icv_close_unicode(cd);
	return;
}

size_t
_icv_iconv(void *cd, char **inbuf, size_t *inbytesleft,
				char **outbuf, size_t *outbytesleft)
{
	unsigned int	u32;		/* UTF-32 */
	unsigned short	e16;		/* 16-bit EUC */
	unsigned char	ic1, ic2;	/* 1st and 2nd bytes of a char */
	size_t		rv = (size_t)0;	/* return value of this function */

	unsigned char	*ip;
	size_t		ileft;
	char		*op;
	size_t		oleft;

	/*
	 * If inbuf and/or *inbuf are NULL, reset conversion descriptor
	 * and put escape sequence if needed.
	 */
	if ((inbuf == NULL) || (*inbuf == NULL)) {
		_icv_reset_unicode(cd);
		return ((size_t)0);
	}

	ip = (unsigned char *)*inbuf;
	ileft = *inbytesleft;
	op = *outbuf;
	oleft = *outbytesleft;

	while (ileft != 0) {
		NGET(ic1, "never fail here"); /* get 1st byte */

		if (ISASC((int)ic1)) {	/* ASCII; 1 byte */
			u32 = _jfp_tbl_jisx0201roman_to_ucs2[ic1];
			PUTU(u32, "ASCII");
		} else if (ISSJKANA(ic1)) { /* JIS X 0201 Kana; 1 byte */
			u32 = _jfp_tbl_jisx0201kana_to_ucs2[ic1 - 0xa1];
			PUTU(u32, "KANA");
		} else if (((ic1 >= 0x81) && (ic1 <= 0x9f)) ||
				((ic1 >= 0xe0) && (ic1 <= 0xef))) {
			/* JIS X 0213 plane 1 */
			NGET(ic2, "PLANE1-2");
			if (ISSJKANJI2(ic2)) {
				e16 = sjtoe16_x0213(ic1, ic2);
				u32 = (unsigned int)_jfp_tbl_jisx0208_to_ucs2[
					((e16 >> 8) - 0xa1) * 94
					+ ((e16 & 0xff) - 0xa1)];
				if (IFHISUR(u32)) {
					u32 = _jfp_lookup_x0213_nonbmp(
						e16, u32);
					PUTU(u32, "PLANE1->NONBMP");
				} else if (u32 == 0xffff) {
					/* need to compose */
					unsigned int	u32_2;
					u32 = _jfp_lookup_x0213_compose(
						e16, &u32_2);
					PUTU(u32, "PLANE1->CP1");
					PUTU(u32_2, "PLANE1->CP2");
				} else {
					PUTU(u32, "PLANE1->BMP");
				}
			} else { /* 2nd byte check failed */
				RETERROR(EILSEQ, "PLANE1-2")
				/* NOTREACHED */
			}
		} else if ((ic1 >= 0xf0) && (ic1 <= 0xfc)) {
			/* JIS X 0213 plane 2 */
			NGET(ic2, "PLANE2-2");
			if (ISSJKANJI2(ic2)) {
				e16 = sjtoe16_x0213(ic1, ic2);
				u32 = (unsigned int)_jfp_tbl_jisx0213p2_to_ucs2[
					((e16 >> 8) - 0xa1) * 94
					+ ((e16 & 0xff) - 0x21)];
				if (IFHISUR(u32)) {
					u32 = _jfp_lookup_x0213_nonbmp(
					e16, u32);
					PUTU(u32, "PLANE2->NONBMP");
				} else {
					PUTU(u32, "PLANE2->BMP");
				}
			} else {
				RETERROR(EILSEQ, "PLANE2-2")
				/* NOTREACHED */
			}
		} else { /* 1st byte check failed */
			RETERROR(EILSEQ, "EILSEQ at 1st")
		}

		/*
		 * One character successfully converted so update
		 * values outside of this function's stack.
		 */
		*inbuf = (char *)ip;
		*inbytesleft = ileft;
		*outbuf = op;
		*outbytesleft = oleft;
	}

ret:
	DEBUGPRINTERROR

	/*
	 * Return value for successful return is not defined by XPG
	 * so return same as *inbytesleft as existing codes do.
	 */
	return ((rv == (size_t)-1) ? rv : *inbytesleft);
}
