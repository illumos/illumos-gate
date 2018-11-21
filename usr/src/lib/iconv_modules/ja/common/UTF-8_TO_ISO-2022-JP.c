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
 * Copyright 1997-2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <euc.h>
#include "japanese.h"
#include "jfp_iconv_unicode.h"

#ifdef RFC1468_MODE
#define	JFP_U2E_ICONV_RFC1468
#else
#define	JFP_U2E_ICONV
#endif
#include "jfp_ucs2_to_euc16.h"

#define	DEF_SINGLE	'?'

/*
 * struct _cv_state; to keep status
 */
struct _icv_state {
	int	_st_cset;
};

void *
_icv_open(void)
{
	struct _icv_state *st;

	if ((st = (struct _icv_state *)
		malloc(sizeof (struct _icv_state))) == NULL)
		return ((void *)-1);

	st->_st_cset = CS_0;

	return (st);
}

void
_icv_close(void *cd)
{
	if (cd == NULL) {
		errno = EBADF;
	} else {
		free(cd);
	}
	return;
}

size_t
_icv_iconv(void *cd, char **inbuf, size_t *inbytesleft,
				char **outbuf, size_t *outbytesleft)
{
	unsigned char	ic;
	size_t		rv = (size_t)0;
	unsigned int	ucs4;
	unsigned short	euc16;

	struct _icv_state	*st = (struct _icv_state *)cd;
	int			cset;

	unsigned char	*ip;
        size_t		ileft;
	char		*op;
        size_t		oleft;

	/*
	 * If inbuf and/or *inbuf are NULL, reset conversion descriptor
	 * and put escape sequence if needed.
	 */
	if ((inbuf == NULL) || (*inbuf == NULL)) {
		if (st->_st_cset != CS_0) {
			if ((outbuf != NULL) && (*outbuf != NULL)
					&& (outbytesleft != NULL)) {
				op = (char *)*outbuf;
				oleft = *outbytesleft;
				NPUT(ESC, "RESET-SEQ-ESC");
				NPUT(SBTOG0_1, "RESET-SEQ-1");
				NPUT(F_X0201_RM, "RESET-SEQ-2");
				*outbuf = (char *)op;
				*outbytesleft = oleft;
			}
			st->_st_cset = CS_0;
		}
		return ((size_t)0);
	}

	cset = st->_st_cset;

	ip = (unsigned char *)*inbuf;
	ileft = *inbytesleft;
	op = *outbuf;
	oleft = *outbytesleft;

	while (ileft != 0) {
		if (utf8_ucs(&ucs4, &ip, &ileft) == (size_t)-1) {
			/* errno has been set in utf8_ucs() */
			rv = (size_t)-1;
			goto ret;
		}

		if (ucs4 > 0xffff) {
			/* non-BMP */
			if (cset != CS_0) {
				NPUT(ESC, "CS0-SEQ-ESC");
				NPUT(SBTOG0_1, "CS0-SEQ-1");
				NPUT(F_X0201_RM, "CS0-SEQ-2");
				cset = CS_0;
			}
			ic = (unsigned char)DEF_SINGLE;
			NPUT(ic, "DEF for non-BMP(replaced)");
		} else {
			euc16 = _jfp_ucs2_to_euc16((unsigned short)ucs4);

			switch (euc16 & 0x8080) {
			case 0x0000:	/* CS0 */
				if (cset != CS_0) {
					NPUT(ESC, "CS0-SEQ-ESC");
					NPUT(SBTOG0_1, "CS0-SEQ-1");
					NPUT(F_X0201_RM, "CS0-SEQ-2");
					cset = CS_0;
				}
				ic = (unsigned char)euc16;
				NPUT(ic, "CS0-1");
				break;
			case 0x8080:	/* CS1 */
				if (cset != CS_1) {
					NPUT(ESC, "CS1-SEQ-ESC");
					NPUT(MBTOG0_1, "CS1-SEQ-1");
					NPUT(F_X0208_83_90, "CS1-SEQ-2");
					cset = CS_1;
				}
				ic = (unsigned char)((euc16 >> 8) & CMASK);
				NPUT(ic, "CS1-1");
				ic = (unsigned char)(euc16 & CMASK);
				NPUT(ic, "CS1-2");
				break;
			case 0x0080:	/* CS2 */
#ifdef  RFC1468_MODE	/* Substitute JIS X 0208 for JIS X 0201 Katakana */
				if (cset != CS_1) {
					NPUT(ESC, "CS2-SEQ-ESC(fullsized)");
					NPUT(MBTOG0_1, "CS2-SEQ-1(fullsized)");
					NPUT(F_X0208_83_90,
						"CS2-SEQ-2(fullsized)");
					cset = CS_1;
				}
				euc16 = halfkana2zenkakuj[euc16 - 0xa1];
				ic = (unsigned char)((euc16 >> 8) & CMASK);
				NPUT(ic, "CS2-1(fullsized)");
				ic = (unsigned char)(euc16 & CMASK);
				NPUT(ic, "CS2-2(fullsized)");
#else   /* ISO-2022-JP.UIOSF */
				if (cset != CS_2) {
					NPUT(ESC, "CS2-SEQ-ESC");
					NPUT(SBTOG0_1, "CS2-SEQ-1");
					NPUT(F_X0201_KN, "CS2-SEQ-2");
					cset = CS_2;
				}
				ic = (unsigned char)euc16;
				NPUT(ic & CMASK, "CS2-1");
#endif  /* RFC1468_MODE */
				break;
			case 0x8000:	/* CS3 */
				if (cset != CS_3) {
					NPUT(ESC, "CS3-SEQ-ESC");
					NPUT(MBTOG0_1, "CS3-SEQ-1");
					NPUT(MBTOG0_2, "CS3-SEQ-2");
					NPUT(F_X0212_90, "CS3-SEQ-3");
					cset = CS_3;
				}
				ic = (unsigned char)((euc16 >> 8) & CMASK);
				NPUT(ic, "CS3-1");
				ic = (unsigned char)(euc16 & CMASK);
				NPUT(ic, "CS3-2");
				break;
			}
		}

		/*
		 * One character successfully converted so update
		 * values outside of this function's stack.
		 */
		*inbuf = (char *)ip;
		*inbytesleft = ileft;
		*outbuf = op;
		*outbytesleft = oleft;

		st->_st_cset = cset;
	}

ret:

#if	defined(DEBUG)
	if (rv == (size_t)-1) {
		fprintf(stderr, "DEBUG: errno=%d: %s\n", errno, debugmsg);
	}
#endif	/* DEBUG */

	/*
	 * Return value for successful return is not defined by XPG
	 * so return same as *inbytesleft as existing codes do.
	 */
	return ((rv == (size_t)-1) ? rv : *inbytesleft);
}
