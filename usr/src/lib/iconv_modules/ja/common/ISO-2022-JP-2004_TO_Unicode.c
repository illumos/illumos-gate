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

struct _icv_state {
	int	_st_cset;
};

void *
_icv_open(void)
{
	void			*cd;
	struct _icv_state	*st;

	cd = _icv_open_unicode(sizeof (struct _icv_state));

	if (cd != NULL) {
		st = (struct _icv_state *)(_icv_get_ext(cd));
		st->_st_cset = CS_0;
	}

	return (cd);
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
	unsigned char	ic1, ic2;	/* bytes in a char or an esc seq */
	unsigned char	ic3, ic4;	/* bytes in an esc seq */
	size_t		rv = (size_t)0;	/* return value of this function */
	struct _icv_state	*st;

	unsigned char	*ip;
        size_t		ileft;
	char		*op;
        size_t		oleft;

	st = (struct _icv_state *)(_icv_get_ext(cd));

	/*
	 * If inbuf and/or *inbuf are NULL, reset conversion descriptor
	 * and put escape sequence if needed.
	 */
	if ((inbuf == NULL) || (*inbuf == NULL)) {
		st->_st_cset = CS_0;
		_icv_reset_unicode(cd);
		return ((size_t)0);
	}

	ip = (unsigned char *)*inbuf;
	ileft = *inbytesleft;
	op = *outbuf;
	oleft = *outbytesleft;

	while (ileft != 0) {
		NGET(ic1, "never fail here"); /* get 1st byte */

		if (ic1 == ESC) { /* Escape */
			NGET(ic2, "ESC-2");
			switch (ic2) {
			case 0x24: /* $ */
				NGET(ic3, "ESC$-3");
				switch (ic3) {
				case 0x28: /* $( */
					NGET(ic4, "ESC$(-4");
					switch (ic4) {
					case 0x4f: /* 24-28-4F ESC$(O */
						st->_st_cset = CS_1;
						break;
					case 0x50: /* 24-28-50 ESC$(P */
						st->_st_cset = CS_3;
						break;
					case 0x51: /* 24-28-51 ESC$(Q */
						st->_st_cset = CS_1;
						break;
					default:
						RETERROR(EILSEQ,
							"Unknown ESC$(?");
					}
					break;
				case 0x42: /* 24-42 ESC$B */
					st->_st_cset = CS_1;
					break;
				default:
					RETERROR(EILSEQ, "Unknown ESC$?");
				}
				break;
			case 0x28: /* ( */
				NGET(ic3, "ESC(-3");
				switch (ic3) {
				case 0x42: /* 28-42 ESC(B */
					st->_st_cset = CS_0;
					break;
				default:
					RETERROR(EILSEQ, "Unknown ESC(?");
				}
				break;
			default:
				RETERROR(EILSEQ, "Unknown ESC?");
			}
		} else if (st->_st_cset == CS_0) { /* IRV */
			if ((ic1 == 0x0e) || (ic1 == 0x0f) || (ic1 > 0x7f)) {
				RETERROR(EILSEQ, "IRV-1")
			}
			u32 = (unsigned int)_jfp_tbl_jisx0201roman_to_ucs2[ic1];
			PUTU(u32, "IRV");
		} else if (st->_st_cset == CS_1) { /* Plane 1 */
			if ((ic1 < 0x21) || (ic1 > 0x7e)) {
				RETERROR(EILSEQ, "PLANE1-1")
			}
			NGET(ic2, "PLANE1-2");
			if ((ic2 < 0x21) || (ic2 > 0x7e)) {
				RETERROR(EILSEQ, "PLANE1-2")
			}
			e16 = ((ic1 << 8) | ic2) | 0x8080;
			u32 = (unsigned int)_jfp_tbl_jisx0208_to_ucs2[
				(ic1 - 0x21) * 94 + (ic2 - 0x21)];
			if (IFHISUR(u32)) {
				u32 = _jfp_lookup_x0213_nonbmp(e16, u32);
				PUTU(u32, "PLANE1->NONBMP");
			} else if (u32 == 0xffff) {
				/* need to compose */
				unsigned int	u32_2;
				u32 = _jfp_lookup_x0213_compose(e16, &u32_2);
				PUTU(u32, "PLANE1->CP1");
				PUTU(u32_2, "PLANE1->CP2");
			} else {
				PUTU(u32, "PLANE1->BMP");
			}
		} else if (st->_st_cset == CS_3) { /* Plane 2 */
			if ((ic1 < 0x21) || (ic1 > 0x7e)) {
				RETERROR(EILSEQ, "PLANE2-1")
			}
			NGET(ic2, "PLANE2-2");
			if ((ic2 < 0x21) || (ic2 > 0x7e)) {
				RETERROR(EILSEQ, "PLANE2-2")
			}
			e16 = ((ic1 << 8) | ic2) | 0x8000;
			u32 = (unsigned int)_jfp_tbl_jisx0213p2_to_ucs2[
				(ic1 - 0x21) * 94 + (ic2 - 0x21)];
			if (IFHISUR(u32)) {
				u32 = _jfp_lookup_x0213_nonbmp(e16, u32);
				PUTU(u32, "PLANE2->NONBMP");
			} else {
				PUTU(u32, "PLANE2->BMP");
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
	}

ret:
	DEBUGPRINTERROR

	/*
	 * Return value for successful return is not defined by XPG
	 * so return same as *inbytesleft as existing codes do.
	 */
	return ((rv == (size_t)-1) ? rv : *inbytesleft);
}
