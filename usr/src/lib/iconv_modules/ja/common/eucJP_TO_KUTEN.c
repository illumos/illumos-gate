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
	int stat;
	unsigned char *ip, ic;
	char *op;
	size_t ileft, oleft;
	size_t retval;

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
	op = *outbuf;
	ileft = *inbytesleft;
	oleft = *outbytesleft;

	/*
	 * Main loop; basically 1 loop per 1 input byte
	 */

	while ((int)ileft > 0) {
		GET(ic);
		if (stat == ST_INCS1) {
			PUT(((ic & CMASK) - 0x20));
			stat = ST_INIT;
			continue;
		} else if (stat == ST_INCS3) {
			PUT(((ic & CMASK) - 0x20));
			GET(ic);
			PUT(((ic & CMASK) - 0x20));
			stat = ST_INIT;
			continue;
		}
		if (ISASC((int)ic)) { /* ASCII */
			errno = EILSEQ;
			retval = (size_t)ERR_RETURN;
			goto ret;
		} else if (ISCS1(ic)) { /* CS_1 starts */
			if ((int)ileft > 0) {
				if (ISCS1(ic) && ISCS1(*ip)) {
					if (oleft < JISW1) {
						UNGET();
						errno = E2BIG;
						retval = (size_t)ERR_RETURN;
						goto ret;
					}
					stat = ST_INCS1;
					PUT(((ic & CMASK) - 0x20));
					continue;
				} else {
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
			errno = EILSEQ;
			retval = (size_t)ERR_RETURN;
			goto ret;
		} else if (ic == SS3) {	/* JISX0212 starts */
			if (ileft >= EUCW3) {
				if (ISCS3(*ip) && ISCS3(*(ip + 1))) {
					if (oleft < JISW3) {
						UNGET();
						errno = E2BIG;
						retval = (size_t)ERR_RETURN;
						goto ret;
					}
					stat = ST_INCS3;
					continue;
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
ret2:
	*outbuf = op;
	*outbytesleft = oleft;

	return (retval);
}
