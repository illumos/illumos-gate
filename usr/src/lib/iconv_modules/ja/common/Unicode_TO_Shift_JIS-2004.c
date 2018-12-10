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

#define	JFP_U2E_ICONV_X0213
#include "jfp_ucs2_to_euc16.h"

#define	DEF_SINGLE	'?'

#define	INVL	0xff

static const unsigned char rowtosj1_x0213_p1[] = {
     /*          1     2     3     4     5     6     7 */
	INVL, 0x81, 0x81, 0x82, 0x82, 0x83, 0x83, 0x84,
     /*    8     9    10    11    12    13    14    15 */
	0x84, 0x85, 0x85, 0x86, 0x86, 0x87, 0x87, 0x88,
     /*   16    17    18    19    20    21    22    23 */
	0x88, 0x89, 0x89, 0x8a, 0x8a, 0x8b, 0x8b, 0x8c,
     /*   24    25    26    27    28    29    30    31 */
	0x8c, 0x8d, 0x8d, 0x8e, 0x8e, 0x8f, 0x8f, 0x90,
     /*   32    33    34    35    36    37    38    39 */
	0x90, 0x91, 0x91, 0x92, 0x92, 0x93, 0x93, 0x94,
     /*   40    41    42    43    44    45    46    47 */
	0x94, 0x95, 0x95, 0x96, 0x96, 0x97, 0x97, 0x98,
     /*   48    49    50    51    52    53    54    55 */
	0x98, 0x99, 0x99, 0x9a, 0x9a, 0x9b, 0x9b, 0x9c,
     /*   56    57    58    59    60    61    62    63 */
	0x9c, 0x9d, 0x9d, 0x9e, 0x9e, 0x9f, 0x9f, 0xe0,
     /*   64    65    66    67    68    69    70    71 */
	0xe0, 0xe1, 0xe1, 0xe2, 0xe2, 0xe3, 0xe3, 0xe4,
     /*   72    73    74    75    76    77    78    79 */
	0xe4, 0xe5, 0xe5, 0xe6, 0xe6, 0xe7, 0xe7, 0xe8,
     /*   80    81    82    83    84    85    86    87 */
	0xe8, 0xe9, 0xe9, 0xea, 0xea, 0xeb, 0xeb, 0xec,
     /*   88    89    90    91    92    93    94       */
	0xec, 0xed, 0xed, 0xee, 0xee, 0xef, 0xef
};

static const unsigned char rowtosj1_x0213_p2[] = {
     /*          1     2     3     4     5     6     7 */
	INVL, 0xf0, INVL, 0xf1, 0xf1, 0xf2, INVL, INVL,
     /*    8     9    10    11    12    13    14    15 */
	0xf0, INVL, INVL, INVL, 0xf2, 0xf3, 0xf3, 0xf4,
     /*   16    17    18    19    20    21    22    23 */
	INVL, INVL, INVL, INVL, INVL, INVL, INVL, INVL,
     /*   24    25    26    27    28    29    30    31 */
	INVL, INVL, INVL, INVL, INVL, INVL, INVL, INVL,
     /*   32    33    34    35    36    37    38    39 */
	INVL, INVL, INVL, INVL, INVL, INVL, INVL, INVL,
     /*   40    41    42    43    44    45    46    47 */
	INVL, INVL, INVL, INVL, INVL, INVL, INVL, INVL,
     /*   48    49    50    51    52    53    54    55 */
	INVL, INVL, INVL, INVL, INVL, INVL, INVL, INVL,
     /*   56    57    58    59    60    61    62    63 */
	INVL, INVL, INVL, INVL, INVL, INVL, INVL, INVL,
     /*   64    65    66    67    68    69    70    71 */
	INVL, INVL, INVL, INVL, INVL, INVL, INVL, INVL,
     /*   72    73    74    75    76    77    78    79 */
	INVL, INVL, INVL, INVL, INVL, INVL, 0xf4, 0xf5,
     /*   80    81    82    83    84    85    86    87 */
	0xf5, 0xf6, 0xf6, 0xf7, 0xf7, 0xf8, 0xf8, 0xf9,
     /*   88    89    90    91    92    93    94       */
	0xf9, 0xfa, 0xfa, 0xfb, 0xfb, 0xfc, 0xfc
};

static unsigned char e16tosj_x0213(
	unsigned short	e16,
	unsigned char	*pc2)
{
	unsigned char	c1;
	unsigned char	r, c;

	/* range check (if valid for plane 1 or 2) for e16
	   has been done by the caller side */

	r = (e16 >> 8) - 0xa0;

	if ((e16 & 0x8080) == 0x8080) { /* Plane 1 */
		c1 = rowtosj1_x0213_p1[r];
	} else { /* Plane 2 */
		c1 = rowtosj1_x0213_p2[r];
	}

	c = (e16 & 0x7f) - 0x20;

	if ((r % 2) == 1) { /* odd row */
		*pc2 = (c - 1) + 0x40;
		if (*pc2 >= 0x7f) {
			(*pc2)++;
		}
	} else { /* even row */
		*pc2 = (c - 1) + 0x9f;
	}

	return (c1);
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
	unsigned char	ic1, ic2;
	size_t		rv = (size_t)0;

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
		GETU(&u32)

		e16 = _jfp_u32_to_euc16(u32);

		switch (e16 & 0x8080) {
		case 0x0000:	/* ASCII */
			ic1 = (unsigned char)e16;
			NPUT(ic1, "ASCII");
			break;
		case 0x8080:	/* PLANE1 */
			ic1 = e16tosj_x0213(e16, &ic2);
			NPUT(ic1, "PLANE1-1");
			NPUT(ic2, "PLANE1-2");
			break;
		case 0x0080:	/* KANA */
			ic1 = (unsigned char)e16;
			NPUT(ic1, "KANA");
			break;
		case 0x8000:	/* CS3 */
			ic1 = e16tosj_x0213(e16, &ic2);
			NPUT(ic1, "PLANE2-1");
			NPUT(ic2, "PLANE2-2");
			break;
		}

next:
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
