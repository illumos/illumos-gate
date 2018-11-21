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
 * COPYRIGHT AND PERMISSION NOTICE
 *
 * Copyright (c) 1991-2005 Unicode, Inc. All rights reserved. Distributed
 * under the Terms of Use in http://www.unicode.org/copyright.html.
 *
 * This file has been modified by Sun Microsystems, Inc.
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

#ifdef JAVA_CONV_COMPAT
#define	JFP_J2U_ICONV_JAVA
#elif	JFP_ICONV_MS932
#define	JFP_J2U_ICONV_MS932
#else
#define	JFP_J2U_ICONV
#endif
#include "jfp_jis_to_ucs2.h"

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
	unsigned int	uni;		/* UTF-32 */
	unsigned int	index;		/* index for table lookup */
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
			uni = _jfp_tbl_jisx0201roman_to_ucs2[ic1];
			PUTU(uni, "ASCII");
		} else if (ISSJKANA(ic1)) { /* JIS X 0201 Kana; 1 byte */
			uni = _jfp_tbl_jisx0201kana_to_ucs2[(ic1 - 0xa1)];
			PUTU(uni, "KANA");
		} else if (ISSJKANJI1(ic1)) { /* JIS X 0208 or UDC; 2 bytes */
			NGET(ic2, "CS1-2 not available");
			if (ISSJKANJI2(ic2)) {
				ic1 = sjtojis1[(ic1 - 0x80)];
				if (ic2 >= 0x9f) {
					ic1++;
				}
				index = ((ic1 - 0x21) * 94)
					+ (sjtojis2[ic2] - 0x21);
				uni = _jfp_tbl_jisx0208_to_ucs2[index];
				PUTU(uni, "KANJI");
			} else { /* 2nd byte check failed */
				RETERROR(EILSEQ, "EILSEQ at CS1-2")
				/* NOTREACHED */
			}
		} else if (ISSJSUPKANJI1(ic1)) { /* VDC, 2 bytes */
			NGET(ic2, "SUP-2 not available");
			if (ISSJKANJI2(ic2)) {
				ic1 = sjtojis1[(ic1 - 0x80)];
				if (ic2 >= 0x9f) {
					ic1++;
				}
				index = ((ic1 - 0x21) * 94)
						+ (sjtojis2[ic2] - 0x21);
				uni = _jfp_tbl_jisx0212_to_ucs2[index];
				PUTU(uni, "SUPKANJI");
			} else { /* 2nd byte check failed */
				RETERROR(EILSEQ, "EILSEQ at CS1-2")
			}
		} else if (ISSJIBM(ic1) || /* Extended IBM char. area */
			ISSJNECIBM(ic1)) { /* NEC/IBM char. area */
			/*
			 * We need a special treatment for each codes.
			 * By adding some offset number for them, we
			 * can process them as the same way of that of
			 * extended IBM chars.
			 */
			NGET(ic2, "IBM-2 not available");
			if (ISSJKANJI2(ic2)) {
				unsigned short dest, upper, lower;
				dest = (ic1 << 8) + ic2;
				if ((0xed40 <= dest) && (dest <= 0xeffc)) {
					REMAP_NEC(dest);
					if (dest == 0xffff) {
						RETERROR(EILSEQ, "invalid NEC")
					}
				}
				/*
				 * XXX: 0xfa54 and 0xfa5b must be mapped
				 *	to JIS0208 area. Therefore we
				 *	have to do special treatment.
				 */
				if ((dest == 0xfa54) || (dest == 0xfa5b)) {
					if (dest == 0xfa54) {
			/* map to JIS X 0208 row 2 cell 44 "NOT SIGN" */
				index = (2 - 1) * 94 + (44 - 1);
					} else {
			/* map to JIS X 0208 row 2 cell 72 "BECAUSE" */
				index = (2 - 1) * 94 + (72 - 1);
					}
					uni = _jfp_tbl_jisx0208_to_ucs2[index];
					PUTU(uni, "IBM");
				} else {
					dest = dest - 0xfa40 -
						(((dest>>8) - 0xfa) * 0x40);
					dest = sjtoibmext[dest];
					if (dest == 0xffff) {
						RETERROR(EILSEQ, "invalid IBM")
					}
					upper = ((dest >> 8) & 0x7f) - 0x21;
					lower = (dest & 0x7f) - 0x21;
					index = (unsigned int)(upper * 94 +
						lower);
					uni = _jfp_tbl_jisx0212_to_ucs2[index];
					PUTU(uni, "IBM");
				}
			} else { /* 2nd byte check failed */
				RETERROR(EILSEQ, "EILSEQ at IBM-2")
			}
		} else if ((0xeb <= ic1) && (ic1 <= 0xec)) {
		/*
		 * Based on the draft convention of OSF-JVC CDEWG,
		 * characters in this area will be mapped to
		 * "CHIKAN-MOJI." (convertible character)
		 * We use U+FFFD in this case.
		 */
			NGET(ic2, "GAP-2 not available");
			if (ISSJKANJI2(ic2)) {
				uni = 0xfffd;
				PUTU(uni, "GAP");
			} else { /* 2nd byte check failed */
				RETERROR(EILSEQ, "EILSEQ at GAP-2")
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
