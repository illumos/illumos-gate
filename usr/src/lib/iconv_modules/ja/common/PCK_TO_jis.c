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



/*
 * Actual conversion; called from iconv()
 */
size_t
_icv_iconv(struct _icv_state *st, char **inbuf, size_t *inbytesleft,
				char **outbuf, size_t *outbytesleft)
{
	int		cset;
	int		stat = ST_INIT;
	unsigned char	*ip, ic;
	char			*op;
	size_t			ileft, oleft;
	size_t			retval;

	/*
	 * If inbuf and/or *inbuf are NULL, reset conversion descriptor
	 * and put escape sequence if needed.
	 */
	if ((inbuf == NULL) || (*inbuf == NULL)) {
		if ((st->_st_cset == CS_1) || (st->_st_cset == CS_3)) {
			if ((outbuf != NULL) && (*outbuf != NULL)
					&& (outbytesleft != NULL)) {
				op = *outbuf;
				oleft = *outbytesleft;
				if (oleft < SEQ_SBTOG0) {
					errno = E2BIG;
					return ((size_t)-1);
				}
				PUT(ESC);
				PUT(SBTOG0_1);
				PUT(F_X0201_RM);
				*outbuf = op;
				*outbytesleft = oleft;
			}
			st->_st_cset = CS_0;
		} else if (st->_st_cset == CS_2) {
			if ((outbuf != NULL) && (*outbuf != NULL)
					&& (outbytesleft != NULL)) {
				op = *outbuf;
				oleft = *outbytesleft;
				if (oleft < SEQ_SOSI) {
					errno = E2BIG;
					return ((size_t)-1);
				}
				PUT(SI);
				*outbuf = op;
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
	 * Main loop; basically 1 loop per 1 input byte
	 */

	while ((int)ileft > 0) {
		GET(ic);
		if ((stat == ST_INCS1) || (stat == ST_INCS3)) {
			ic = sjtojis2[ic];
			PUT(ic);
			stat = ST_INIT;
			continue;
		} else if (ISASC((int)ic)) {		/* ASCII */
			if ((cset == CS_1) || (cset == CS_3)) {
				CHECK2BIG(SEQ_SBTOG0,1);
				PUT(ESC);	/* to JIS X 0201 Roman */
				PUT(SBTOG0_1);
				PUT(F_X0201_RM);
			} else if (cset == CS_2) {
				CHECK2BIG(SEQ_SOSI,1);
				PUT(SI);	/* Shift In */
			}
			cset = CS_0;
			CHECK2BIG(JISW0,1);
			PUT(ic);
			continue;
		} else if (ISSJKANA(ic)) {		/* Kana starts */
			if ((cset == CS_1) || (cset == CS_3)) {
				CHECK2BIG(SEQ_SBTOG0,1);
				cset = CS_0;
				PUT(ESC);
				PUT(SBTOG0_1);
				PUT(F_X0201_RM);
			}
			if (cset != CS_2) {
				CHECK2BIG(SEQ_SOSI,1);
				cset = CS_2;
				PUT(SO);
			}
			CHECK2BIG(JISW2,1);
			stat = ST_INIT;
			PUT(ic & CMASK);
			continue;
		} else if (ISSJKANJI1(ic)) {	/* CS_1 Kanji starts */
			if ((int)ileft > 0) {
				if (ISSJKANJI2(*ip)) {
					if (cset == CS_2) {
						cset = CS_0;
						PUT(SI);
					}
					if (cset != CS_1) {
						CHECK2BIG(SEQ_MBTOG0_O,1);
						cset = CS_1;
						PUT(ESC);
						PUT(MBTOG0_1);
						PUT(F_X0208_83_90);
					}
					CHECK2BIG(JISW1,1);
					stat = ST_INCS1;
					ic = sjtojis1[(ic - 0x80)];
					if (*ip >= 0x9f) {
						ic++;
					}
					PUT(ic);
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
		} else if (ISSJSUPKANJI1(ic)) { /* CS_3 Kanji starts */
			if ((int)ileft > 0) {
				if (ISSJKANJI2(*ip)) {
					if (cset == CS_2) {
						cset = CS_0;
						PUT(SI);
					}
					if (cset != CS_3) {
						CHECK2BIG(SEQ_MBTOG0,1);
						cset = CS_3;
						PUT(ESC);
						PUT(MBTOG0_1);
						PUT(MBTOG0_2);
						PUT(F_X0212_90);
					}
					CHECK2BIG(JISW3,1);
					stat = ST_INCS3;
					ic = sjtojis1[(ic - 0x80)];
					if (*ip >= 0x9f) {
						ic++;
					}
					PUT(ic);
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
					if (cset == CS_2) {
						cset = CS_0;
						PUT(SI);
					}
					if ((0xed40 <= dest) &&
						(dest <= 0xeffc)) {
						REMAP_NEC(dest);
						if (dest == 0xffff) {
							goto ill_ibm;
						}
					}
					/*
					 * XXX: 0xfa54 and 0xfa5b must be mapped
					 *	to JIS0208 area. Therefore we
					 *	have to do special treatment.
					 */
					if ((cset != CS_1) &&
						((dest == 0xfa54) ||
						(dest == 0xfa5b))) {
						CHECK2BIG(SEQ_MBTOG0_O,2);
						cset = CS_1;
						PUT(ESC);
						PUT(MBTOG0_1);
						PUT(F_X0208_83_90);
						CHECK2BIG(JISW1,2);
						if (dest == 0xfa54) {
							PUT(0x22);
							PUT(0x4c);
						} else {
							PUT(0x22);
							PUT(0x68);
						}
						continue;
					}
					if (cset != CS_3) {
						CHECK2BIG(SEQ_MBTOG0,2);
						cset = CS_3;
						PUT(ESC);
						PUT(MBTOG0_1);
						PUT(MBTOG0_2);
						PUT(F_X0212_90);
					}
					CHECK2BIG(JISW3,2);
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
					PUT(((dest>>8) & 0x7f));
					PUT(dest & 0x7f);
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
					if (cset == CS_2) {
						cset = CS_0;
						PUT(SI);
					}
					if (cset != CS_1) {
						CHECK2BIG(SEQ_MBTOG0_O,1);
						cset = CS_1;
						PUT(ESC);
						PUT(MBTOG0_1);
						PUT(F_X0208_83_90);
					}
					CHECK2BIG(JISW1,1);
					GET(ic); /* Dummy */
					PUT((JGETA>>8) & CMASK);
					PUT(JGETA & CMASK);
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
	*outbuf = op;
	*outbytesleft = oleft;
	st->_st_cset = cset;

	return (retval);
}
