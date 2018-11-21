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
#include "japanese.h"


/*
 * struct _icv_state; to keep stat
 */
struct _icv_state {
	int	_st_cset;
};

void *
_icv_open()
{
	struct _icv_state *st;

	if ((st = (struct _icv_state *)malloc(sizeof (struct _icv_state)))
									== NULL)
		return ((void *)ERR_RETURN);

	st->_st_cset = CS_0;
	return (st);
}

void
_icv_close(struct _icv_state *st)
{
	free(st);
}

size_t
_icv_iconv(struct _icv_state *st, char **inbuf, size_t *inbytesleft,
				char **outbuf, size_t *outbytesleft)
{
	int cset;
	unsigned char *ip, ic;
	char *op;
	size_t ileft, oleft;
	size_t retval;

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
				if (oleft < SEQ_SBTOG0) {
					errno = E2BIG;
					return ((size_t)-1);
				}
				PUT(ESC);
				PUT(SBTOG0_1);
				PUT(F_X0201_RM);
				*outbuf = (char *)op;
				*outbytesleft = oleft;
			}
			st->_st_cset = CS_0;
		}
		return ((size_t)0);
	}

	cset = st->_st_cset;

	ip = (unsigned char *)*inbuf;
	op = *outbuf;
	ileft = *inbytesleft;
	oleft = *outbytesleft;

	/*
	 * Main loop; basically 1 loop per 1 output char
	 */
	while ((int)ileft > 0) {
		GET(ic);
		if (ISASC((int)ic)) { /* ASCII */
			if (cset != CS_0) {
				if (oleft < SEQ_SBTOG0) {
					UNGET();
					errno = E2BIG;
					retval = (size_t)ERR_RETURN;
					goto ret;
				}
				PUT(ESC);	/* Kanji Out */
				PUT(SBTOG0_1);
				PUT(F_X0201_RM);
			}
			cset = CS_0;
			if (oleft < JISW0) {
				UNGET();
				errno = E2BIG;
				retval = (size_t)ERR_RETURN;
				goto ret;
			}
			/* Put ASCII character */
			PUT(ic);
			continue;
		} else if (ISCS1((int)ic)) { /* CS_1 starts */
			if ((int)ileft > 0) {
				if (ISCS1(ic) && ISCS1(*ip)) {
					if (cset != CS_1) {
						if (oleft < SEQ_MBTOG0_O) {
							UNGET();
							errno = E2BIG;
							retval =
							(size_t)ERR_RETURN;
							goto ret;
						}
						cset = CS_1;
						PUT(ESC);
						PUT(MBTOG0_1);
						PUT(F_X0208_83_90);
					}
					if (oleft < JISW1) {
						UNGET();
						errno = E2BIG;
						retval = (size_t)ERR_RETURN;
						goto ret;
					}
#ifdef  RFC1468_MODE /* Convert VDC and UDC to GETA */
					if ((ic == 0xad) || (0xf5 <= ic )){
						PUT((JGETA >> 8) & CMASK);
						GET(ic); /* Get dummy */
						PUT(JGETA & CMASK);
						continue;
					}
#endif  /* RFC1468_MODE */
					/* Put JIS X 0208 character */
					PUT(ic & CMASK);
					GET(ic);
					PUT(ic & CMASK);
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
			if ((int)ileft > 0) {
				if (ISCS2(*ip)) {

#ifdef  RFC1468_MODE	/* Substitute JIS X 0208 for JIS X 0201 Katakana */
				unsigned short  zenkaku;
					if (cset != CS_1) {
						if (oleft < SEQ_MBTOG0_O) {
							UNGET();
							errno = E2BIG;
							retval =
							(size_t)ERR_RETURN;
							goto ret;
						}
						PUT(ESC);
						PUT(MBTOG0_1);
						PUT(F_X0208_83_90);
						cset = CS_1;
					}
					if (oleft < JISW1) {
						UNGET();
						errno = E2BIG;
						retval = (size_t)ERR_RETURN;
						goto ret;
					}
					GET(ic);
					zenkaku = halfkana2zenkakuj[ic - 0xA1];
					ic = (unsigned char)((zenkaku >> 8) &
					CMASK);
					PUT(ic);
					ic = (unsigned char)(zenkaku & CMASK);
					PUT(ic);
#else   /* ISO-2022-JP.UIOSF */
					if (cset != CS_2) {
						if (oleft < SEQ_SBTOG0) {
							UNGET();
							errno = E2BIG;
							retval =
							(size_t)ERR_RETURN;
							goto ret;
						}
						PUT(ESC);
						PUT(SBTOG0_1);
						PUT(F_X0201_KN);
						cset = CS_2;
					}
					if (oleft < JISW2) {
						UNGET();
						errno = E2BIG;
						retval = (size_t)ERR_RETURN;
						goto ret;
					}
					/* Put Kana character */
					GET(ic);
					PUT(ic & CMASK);
#endif  /* RFC1468_MODE */
					continue;
				} else {	/* 2nd byte is illegal */
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
		} else if (ic == SS3) {	/* JISX0212 starts */
			if (ileft >= EUCW3) {
				if (ISCS3(*ip) && ISCS3(*(ip + 1))) {

/* ISO-2022-JP.RFC1468 or ISO-2022-JP.UIOSF */
#ifdef  RFC1468_MODE	/* Substitute JIS X 0208 "Geta" for JIS X 0212 */
					if (cset != CS_1) {
						if (oleft < SEQ_MBTOG0_O) {
							UNGET();
							errno = E2BIG;
							retval =
							(size_t)ERR_RETURN;
							goto ret;
						}
						cset = CS_1;
						PUT(ESC);
						PUT(MBTOG0_1);
						PUT(F_X0208_83_90);
					}
					if (oleft < JISW1) {
						UNGET();
						errno = E2BIG;
						retval = (size_t)ERR_RETURN;
						goto ret;
					}
					/* Put GETA (0x222e) */
					ic = (unsigned char)((JGETA >> 8) &
					CMASK);
					PUT(ic);
					ic = (unsigned char)(JGETA & CMASK);
					PUT(ic);
					GET(ic); /* dummy GET */
					GET(ic); /* dummy GET */
#else   /* ISO-2022-JP.UIOSF */
					if (cset != CS_3) {
						if (oleft < SEQ_MBTOG0) {
							UNGET();
							errno = E2BIG;
							retval =
							(size_t)ERR_RETURN;
							goto ret;
						}
						cset = CS_3;
						PUT(ESC);
						PUT(MBTOG0_1);
						PUT(MBTOG0_2);
						PUT(F_X0212_90);
					}
					if (oleft < JISW3) {
						UNGET();
						errno = E2BIG;
						retval = (size_t)ERR_RETURN;
						goto ret;
					}
					/* Put JIS X 0212 character */
					GET(ic);
					PUT(ic & CMASK);
					GET(ic);
					PUT(ic & CMASK);
#endif  /* RFC1468_MODE */
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
	*outbuf = op;
	*outbytesleft = oleft;
	st->_st_cset = cset;

	return (retval);
}
