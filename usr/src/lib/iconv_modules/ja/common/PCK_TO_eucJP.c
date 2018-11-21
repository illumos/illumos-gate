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
 * Copyright 1994-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <euc.h>
#define	JFP_ICONV_STATELESS
#include "japanese.h"


void *
_icv_open(void)
{
	return (_icv_open_stateless());
}

void
_icv_close(void *cd)
{
	_icv_close_stateless(cd);
	return;
}

size_t
_icv_iconv(void *cd, char **inbuf, size_t *inbytesleft,
				char **outbuf, size_t *outbytesleft)
{
	int				stat;
	unsigned char	*ip, ic, *op;
	size_t			ileft, oleft;
	size_t			retval;

	/*
	 * If inbuf and/or *inbuf are NULL, reset conversion descriptor
	 * and put escape sequence if needed.
	 */
	if ((inbuf == NULL) || (*inbuf == NULL)) {
		/* nothing to do here for this module */
		return ((size_t)0);
	}

	stat = ST_INIT;

	ip = (unsigned char *)*inbuf;
	op = (unsigned char *)*outbuf;
	ileft = *inbytesleft;
	oleft = *outbytesleft;

	/*
	 * Main loop; basically 1 loop per 1 input byte
	 */

	while ((int)ileft > 0) {
		GET(ic);
		if ((stat == ST_INCS1) || (stat == ST_INCS3)) {
			ic = sjtojis2[ic];
			PUT(ic | CMSB);
			stat = ST_INIT;
			continue;
		} else if (ISASC((int)ic)) {		/* ASCII */
			CHECK2BIG(EUCW0,1);
			PUT(ic);
			continue;
		} else if (ISSJKANA(ic)) {		/* kana start */
			CHECK2BIG((SS2W + EUCW2),1);
			PUT(SS2);
			PUT(ic);
			continue;
		} else if (ISSJKANJI1(ic)) {	/* CS_1 kanji starts */
			if ((int)ileft > 0) {
				if (ISSJKANJI2(*ip)) {
					CHECK2BIG(EUCW1,1);
					stat = ST_INCS1;
					ic = sjtojis1[(ic - 0x80)];
					if (*ip >= 0x9f) {
						ic++;
					}
					PUT(ic | CMSB);
					continue;
				} else {	/* 2nd byte is illegal */
					UNGET();
					errno = EILSEQ;
					retval = (size_t)ERR_RETURN;
					goto ret;
				}
			} else {		/* input fragment of Kanji */
				UNGET();
				errno = EINVAL;
				retval = (size_t)ERR_RETURN;
				goto ret;
			}
		} else if (ISSJSUPKANJI1(ic)) {	/* CS_3 kanji starts */
			if ((int)ileft > 0) {
				if (ISSJKANJI2(*ip)) {
					CHECK2BIG((SS3W + EUCW3),1);
					stat = ST_INCS3;
					ic = sjtojis1[(ic - 0x80)];
					if (*ip >= 0x9f) {
						ic++;
					}
					PUT(SS3);
					PUT(ic | CMSB);
					continue;
				} else {	/* 2nd byte is illegal */
					UNGET();
					errno = EILSEQ;
					retval = (size_t)ERR_RETURN;
					goto ret;
				}
			} else {		/* input fragment of Kanji */
				UNGET();
				errno = EINVAL;
				retval = (size_t)ERR_RETURN;
				goto ret;
			}
		} else if (ISSJIBM(ic) || /* Extended IBM char. area */
			ISSJNECIBM(ic)) { /* NEC/IBM char. area */
			/*
			 * We need a special treatment for each codes.
			 * By adding some offset number for them, we
			 * can process them as the same way of that of
			 * extended IBM chars.
			 */
			if ((int)ileft > 0) {
				if (ISSJKANJI2(*ip)) {
					unsigned short dest;
					dest = (ic << 8);
					GET(ic);
					dest += ic;
					if ((0xed40 <= dest) &&
						(dest <= 0xeffc)) {
						REMAP_NEC(dest);
						if (dest == 0xffff) {
							goto ill_ibm;
						}
					}
					if ((dest == 0xfa54) ||
						(dest == 0xfa5b)) {
						CHECK2BIG(EUCW1,2);
						if (dest == 0xfa54) {
							PUT(0xa2);
							PUT(0xcc);
						} else {
							PUT(0xa2);
							PUT(0xe8);
						}
						continue;
					}
					CHECK2BIG((SS3W + EUCW3),2);
					dest = dest - 0xfa40 -
						(((dest>>8) - 0xfa) * 0x40);
					dest = sjtoibmext[dest];
					if (dest == 0xffff) {
						/*
						 * Illegal code points
						 * in IBM-EXT area.
						 */
ill_ibm:
						UNGET();
						UNGET();
						errno = EILSEQ;
						retval = (size_t)ERR_RETURN;
						goto ret;
					}
					PUT(SS3);
					PUT((dest>>8) & 0xff);
					PUT(dest & 0xff);
					continue;
				} else {	/* 2nd byte is illegal */
					UNGET();
					errno = EILSEQ;
					retval = (size_t)ERR_RETURN;
					goto ret;
				}
			} else {		/* input fragment of Kanji */
				UNGET();
				errno = EINVAL;
				retval = (size_t)ERR_RETURN;
				goto ret;
			}
		} else if ((0xeb <= ic) && (ic <= 0xec)) {
		/*
		 * Based on the draft convention of OSF-JVC CDEWG,
		 * characters in this area will be mapped to
		 * "CHIKAN-MOJI." (convertible character)
		 * So far, we'll use (0x222e) for it.
		 */
			if ((int)ileft > 0) {
				if (ISSJKANJI2(*ip)) {
					CHECK2BIG(EUCW1,1);
					GET(ic); /* Dummy */
					PUT((EGETA>>8) & 0xff);
					PUT(EGETA & 0xff);
					continue;
				} else {	/* 2nd byte is illegal */
					UNGET();
					errno = EILSEQ;
					retval = (size_t)ERR_RETURN;
					goto ret;
				}
			} else {		/* input fragment of Kanji */
				UNGET();
				errno = EINVAL;
				retval = (size_t)ERR_RETURN;
				goto ret;
			}
		} else {			/* 1st byte is illegal */
			UNGET();
			errno = EILSEQ;
			retval = (size_t)ERR_RETURN;
			goto ret;
		}
	}
	retval = ileft;
ret:
	*inbuf = (char *)ip;
	*inbytesleft = ileft;
	*outbuf = (char *)op;
	*outbytesleft = oleft;

	return (retval);
}
