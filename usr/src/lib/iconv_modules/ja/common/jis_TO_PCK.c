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
 * Copyright 1991-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <euc.h>
#include "japanese.h"

/*
 * struct _cv_state; to keep status
 */
struct _icv_state {
	int	_st_cset;
	int	_st_cset_sav;
};

static unsigned short lookuptbl(unsigned short);

void *
_icv_open()
{
	struct _icv_state *st;

	if ((st = (struct _icv_state *)malloc(sizeof (struct _icv_state)))
									== NULL)
		return ((void *)ERR_RETURN);

	st->_st_cset = st->_st_cset_sav = CS_0;

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
	int		cset;
	int		stat = ST_INIT;
	unsigned char	*op, ic;
	char			*ip;
	size_t			ileft, oleft;
	size_t			retval;

	/*
	 * If inbuf and/or *inbuf are NULL, reset conversion descriptor
	 * and put escape sequence if needed.
	 */
	if ((inbuf == NULL) || (*inbuf == NULL)) {
		st->_st_cset_sav = st->_st_cset = CS_0;
		return ((size_t)0);
	}

	cset = st->_st_cset;

	ip = *inbuf;
	op = (unsigned char *)*outbuf;
	ileft = *inbytesleft;
	oleft = *outbytesleft;

	/*
	 * Main loop; basically 1 loop per 1 input byte
	 */

	while ((int)ileft > 0) {
		GET(ic);
		if (stat == ST_INIT) {
			goto text;
		}
		if (stat == ST_ESC) {
			if (ic == MBTOG0_1) {
				if ((int)ileft > 0) {
					stat = ST_MBTOG0_1;
					continue;
				} else {
					UNGET();
					UNGET();
					errno = EINVAL;
					retval = (size_t)ERR_RETURN;
					goto ret;
				}
			} else if (ic == SBTOG0_1) {
				if ((int)ileft > 0) {
					stat = ST_SBTOG0;
					continue;
				} else {
					UNGET();
					UNGET();
					errno = EINVAL;
					retval = (size_t)ERR_RETURN;
					goto ret;
				}
			} else if (ic == X208REV_1) {
				if ((int)ileft > 0) {
					stat = ST_208REV_1;
					continue;
				} else {
					UNGET();
					UNGET();
					errno = EINVAL;
					retval = (size_t)ERR_RETURN;
					goto ret;
				}
			} else {
				UNGET();
				UNGET();
				errno = EILSEQ;
				retval = (size_t)ERR_RETURN;
				goto ret;
			}
		} else if (stat == ST_MBTOG0_1) {
			if ((ic == F_X0208_83_90) || (ic == F_X0208_78)) {
				stat = ST_INIT;
				st->_st_cset_sav = cset = CS_1;
				continue;
			} else if (ic == MBTOG0_2) {
				if ((int)ileft > 0) {
					stat = ST_MBTOG0_2;
					continue;
				} else {
					UNGET();
					UNGET();
					UNGET();
					errno = EINVAL;
					retval = (size_t)ERR_RETURN;
					goto ret;
				}
			} else if (ic == F_X0212_90) {
				stat = ST_INIT;
				st->_st_cset_sav = cset = CS_3;
				continue;
			} else {
				UNGET();
				UNGET();
				UNGET();
				errno = EILSEQ;
				retval = (size_t)ERR_RETURN;
				goto ret;
			}
		} else if (stat == ST_MBTOG0_2) {
			if ((ic == F_X0208_83_90) || (ic == F_X0208_78)) {
				stat = ST_INIT;
				st->_st_cset_sav = cset = CS_1;
				continue;
			} else if (ic == F_X0212_90) {
				stat = ST_INIT;
				st->_st_cset_sav = cset = CS_3;
				continue;
			} else {
				UNGET();
				UNGET();
				UNGET();
				UNGET();
				errno = EILSEQ;
				retval = (size_t)ERR_RETURN;
				goto ret;
			}
		} else if (stat == ST_SBTOG0) {
			if ((ic == F_ASCII) ||
				(ic == F_X0201_RM) ||
				(ic == F_ISO646)) {
				stat = ST_INIT;
				st->_st_cset_sav = cset = CS_0;
				continue;
			} else if (ic == F_X0201_KN) {
				cset = CS_2;
				stat = ST_INIT;
				continue;
			} else {
				UNGET();
				UNGET();
				UNGET();
				errno = EILSEQ;
				retval = (size_t)ERR_RETURN;
				goto ret;
			}
		} else if (stat == ST_208REV_1) {
			if (ic == X208REV_2) {
				if ((int)ileft > 0) {
					stat = ST_208REV_2;
					continue;
				} else {
					UNGET();
					UNGET();
					UNGET();
					errno = EINVAL;
					retval = (size_t)ERR_RETURN;
					goto ret;
				}
			} else {
				UNGET();
				UNGET();
				UNGET();
				errno = EILSEQ;
				retval = (size_t)ERR_RETURN;
				goto ret;
			}
		} else if (stat == ST_208REV_2) {
			if (ic == ESC) {
				if ((int)ileft > 0) {
					stat = ST_REV_AFT_ESC;
					continue;
				} else {
					UNGET();
					UNGET();
					UNGET();
					UNGET();
					errno = EINVAL;
					retval = (size_t)ERR_RETURN;
					goto ret;
				}
			} else {
				UNGET();
				UNGET();
				UNGET();
				UNGET();
				errno = EILSEQ;
				retval = (size_t)ERR_RETURN;
				goto ret;
			}
		} else if (stat == ST_REV_AFT_ESC) {
			if (ic == MBTOG0_1) {
				if ((int)ileft > 0) {
					stat = ST_REV_AFT_MBTOG0_1;
					continue;
				} else {
					UNGET();
					UNGET();
					UNGET();
					UNGET();
					UNGET();
					errno = EINVAL;
					retval = (size_t)ERR_RETURN;
					goto ret;
				}
			} else {
				UNGET();
				UNGET();
				UNGET();
				UNGET();
				UNGET();
				errno = EILSEQ;
				retval = (size_t)ERR_RETURN;
				goto ret;
			}
		} else if (stat == ST_REV_AFT_MBTOG0_1) {
			if (ic == F_X0208_83_90) {
				stat = ST_INIT;
				st->_st_cset_sav = cset = CS_1;
				continue;
			} else if (ic == MBTOG0_2) {
				if ((int)ileft > 0) {
					stat = ST_REV_AFT_MBTOG0_2;
					continue;
				} else {
					UNGET();
					UNGET();
					UNGET();
					UNGET();
					UNGET();
					UNGET();
					errno = EINVAL;
					retval = (size_t)ERR_RETURN;
					goto ret;
				}
			} else {
				UNGET();
				UNGET();
				UNGET();
				UNGET();
				UNGET();
				UNGET();
				errno = EILSEQ;
				retval = (size_t)ERR_RETURN;
				goto ret;
			}
		} else if (stat == ST_REV_AFT_MBTOG0_2) {
			if (ic == F_X0208_83_90) {
				stat = ST_INIT;
				st->_st_cset_sav = cset = CS_1;
				continue;
			} else {
				UNGET();
				UNGET();
				UNGET();
				UNGET();
				UNGET();
				UNGET();
				UNGET();
				errno = EILSEQ;
				retval = (size_t)ERR_RETURN;
				goto ret;
			}
		}
text:
		/*
		 * Break through chars or ESC sequence
		 */
		if (ic == ESC) {
			if ((int)ileft > 0) {
				stat = ST_ESC;
				continue;
			} else {
				UNGET();
				errno = EINVAL;
				retval = (size_t)ERR_RETURN;
				goto ret;
			}
		} else if (ic == SO) {
			cset = CS_2;
			stat = ST_INIT;
			continue;
		} else if (ic == SI) {
			cset = st->_st_cset_sav;
			stat = ST_INIT;
			continue;
		}
		if (!(ic & CMSB)) {
			if (cset == CS_0) {
				/* ASCII or JIS roman : may be 8bit chars */
				if (oleft < SJISW0) {
					UNGET();
					errno = E2BIG;
					retval = (size_t)ERR_RETURN;
					goto ret;
				}
				PUT(ic);
				continue;
			} else if (cset == CS_1) { /* CS_1 Kanji starts */
				if ((int)ileft > 0) {
					int even_ku;
					if (oleft < SJISW1) {
						UNGET();
						errno = E2BIG;
						retval = (size_t)ERR_RETURN;
						goto ret;
					}
					if ((ic < 0x21) || (ic == 0x7f)) {
						UNGET();
						errno = EILSEQ;
						retval = (size_t)ERR_RETURN;
						goto ret;
					}
					if ((*ip < 0x21) || (*ip == 0x7f)) {
						UNGET();
						errno = EILSEQ;
						retval = (size_t)ERR_RETURN;
						goto ret;
					}
					PUT(jis208tosj1[ic]);
					if ((ic % 2) == 0)
						even_ku = TRUE;
					else
						even_ku = FALSE;
					GET(ic);
					if (even_ku)
						ic += 0x80;
					PUT(jistosj2[ic]);
					continue;
				} else {	/* input fragment of Kanji */
					UNGET();
					errno = EINVAL;
					retval = (size_t)ERR_RETURN;
					goto ret;
				}
			} else if (cset == CS_2) { /* Hankaku Katakana */
				if (oleft < SJISW2) {
					UNGET();
					errno = E2BIG;
					retval = (size_t)ERR_RETURN;
					goto ret;
				}
				PUT(ic | CMSB);
				continue;
			} else if (cset == CS_3) { /* CS_3 Kanji starts */
				unsigned short dest;
				if ((int)ileft > 0) {
					if (oleft < SJISW1) {
						UNGET();
						errno = E2BIG;
						retval = (size_t)ERR_RETURN;
						goto ret;
					}
					if ((ic < 0x21) || (ic == 0x7f)) {
						UNGET();
						errno = EILSEQ;
						retval = (size_t)ERR_RETURN;
						goto ret;
					}
					if ((*ip < 0x21) || (*ip == 0x7f)) {
						UNGET();
						errno = EILSEQ;
						retval = (size_t)ERR_RETURN;
						goto ret;
					}
					if (ic < 0x75) { /* check IBM area */
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
							errno = EILSEQ;
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
						int even_ku;

						if ((ic % 2) == 0)
							even_ku = TRUE;
						else
							even_ku = FALSE;
						PUT(jis212tosj1[ic]);
						GET(ic);
						if (even_ku)
							ic += 0x80;
						PUT(jistosj2[ic]);
						continue;
					}
				} else {	/* input fragment of Kanji */
					UNGET();
					errno = EINVAL;
					retval = (size_t)ERR_RETURN;
					goto ret;
				}
			}
		} else {
			if (oleft < UNKNOWNW) {
				UNGET();
				errno = E2BIG;
				retval = (size_t)ERR_RETURN;
				goto ret;
			}
			PUT(ic);
			continue;
		}
	}
	retval = ileft;
ret:
	*inbuf = ip;
	*inbytesleft = ileft;
	*outbuf = (char *)op;
	*outbytesleft = oleft;
	st->_st_cset = cset;

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
		tmp = (sjtoibmext[i] & 0x7f7f);
		if (tmp == dest)
			return ((i + 0xfa40 + ((i / 0xc0) * 0x40)));
	}
	return (PGETA);
}
