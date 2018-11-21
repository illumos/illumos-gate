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

static unsigned short lookuptbl(unsigned short);

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

	stat = ST_INIT;

	/*
	 * If inbuf and/or *inbuf are NULL, reset conversion descriptor
	 * and put escape sequence if needed.
	 */
	if ((inbuf == NULL) || (*inbuf == NULL)) {
		/* nothing to do here for this module */
		return ((size_t)0);
	}

	ip = (unsigned char *)*inbuf;
	op = (unsigned char *)*outbuf;
	ileft = *inbytesleft;
	oleft = *outbytesleft;

	/*
	 * Main loop; basically 1 loop per 1 input byte
	 */

	while ((int)ileft > 0) {
		GET(ic);
		if (stat == ST_INCS2) {
			PUT(ic);
			stat = ST_INIT;
			continue;
		}
		if (ISASC((int)ic)) {		/* ASCII */
			if (oleft < SJISW0) {
				UNGET();
				errno = E2BIG;
				retval = (size_t)ERR_RETURN;
				goto ret;
			}
			PUT(ic);
			continue;
		}
		if (ISCS1(ic)) {			/* Kanji starts */
			if ((int)ileft > 0) {
				if (ISCS1(*ip)) {
					int even_ku;
					if (oleft < SJISW1) {
						UNGET();
						errno = E2BIG;
						retval = (size_t)ERR_RETURN;
						goto ret;
					}
					ic &= 0x7f;
					PUT(jis208tosj1[ic]);
					if ((ic % 2) == 0)
						even_ku = TRUE;
					else
						even_ku = FALSE;
					GET(ic);
					ic &= 0x7f;
					if (even_ku)
						ic += 0x80;
					PUT(jistosj2[ic]);
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
		} else if (ic == SS2) {	/* Kana starts */
			if ((int)ileft > 0) {
				if (ISCS2(*ip)) {
					if (oleft < SJISW2) {
						UNGET();
						errno = E2BIG;
						retval = (size_t)ERR_RETURN;
						goto ret;
					}
					stat = ST_INCS2;
					continue;
				} else {	/* 2nd byte is illegal */
					UNGET();
					errno = EILSEQ;
					retval = (size_t)ERR_RETURN;
					goto ret;
				}
			} else {		/* input fragment of Kana */
				UNGET();
				errno = EINVAL;
				retval = (size_t)ERR_RETURN;
				goto ret;
			}
		} else if (ic == SS3) { /* CS_3 Kanji starts */
			unsigned short dest;
			if (ileft >= EUCW3) {
				if (ISCS3(*ip) && ISCS3(*(ip + 1))) {
					if (oleft < SJISW1) {
						UNGET();
						errno = E2BIG;
						retval = (size_t)ERR_RETURN;
						goto ret;
					}
					if (*ip < 0xf5) { /* check IBM area */
						GET(ic);
						dest = (ic << 8);
						GET(ic);
						dest += ic;
						dest = lookuptbl(dest);
						if (dest == 0xffff) {
							/*
							 * Illegal code points
							 * in G3 plane.
							 */
							UNGET();
							UNGET();
							errno = E2BIG;
							retval =
							(size_t)ERR_RETURN;
							goto ret;
						} else {
							PUT((dest >> 8) &
							0xff);
							PUT(dest & 0xff);
						}
						continue;
					} else {
						unsigned char c1, c2;

						GET(c1);
						GET(c2);
						c1 &= 0x7f;
						c2 &= 0x7f;
						if ((c1 % 2) == 0)
							c2 += 0x80;
						c1 = jis212tosj1[c1];
						c2 = jistosj2[c2];
						if ((c1 != 0xff) &&
							(c2 != 0xff)) {
							PUT(c1);
							PUT(c2);
							continue;
						}
						PUT((PGETA >> 8) & 0xff);
						PUT(PGETA & 0xff);
						continue;
					}
				} else {
					errno = EILSEQ;
					retval = (size_t)ERR_RETURN;
					goto ret;
				}
			} else {	/* input fragment of JISX0212 */
				UNGET();
				errno = EINVAL;
				retval = (size_t)ERR_RETURN;
				goto ret;
			}
		} else {
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

/*
 * lookuptbl()
 * Return the index number if its index-ed number
 * is the same as dest value.
 */
static unsigned short
lookuptbl(unsigned short dest)
{
	unsigned short tmp;
	int i;
	int sz = (sizeof (sjtoibmext) / sizeof (sjtoibmext[0]));

	for (i = 0; i < sz; i++) {
		tmp = sjtoibmext[i];
		if (tmp == dest)
			return ((i + 0xfa40 + ((i / 0xc0) * 0x40)));
	}
	return (PGETA);
}
