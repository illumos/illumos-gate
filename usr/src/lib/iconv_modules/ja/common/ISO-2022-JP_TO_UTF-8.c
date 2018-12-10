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
 * Copyright 1997-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <euc.h>
#include "japanese.h"
#include "jfp_iconv_unicode.h"

/* Note: JFP_J2U_ICONV_RFC1468 macro pass through hankaku katakata. */
#ifdef  RFC1468_MODE
#define	JFP_J2U_ICONV_RFC1468
#else
#define	JFP_J2U_ICONV
#endif
#include "jfp_jis_to_ucs2.h"

/*
 * struct _cv_state; to keep status
 */
struct _icv_state {
	int	_st_cset;
	int	_st_cset_sav;
};

void *
_icv_open()
{
	struct _icv_state *st;

	if ((st = (struct _icv_state *)malloc(sizeof (struct _icv_state)))
									== NULL)
		return ((void *)ERR_RETURN);

	st->_st_cset_sav = st->_st_cset = CS_0;

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
	int cset, stat, ret_val;
	char *ip, ic;
	size_t ileft;
	size_t retval;
	char		*op;
	size_t		oleft;
	unsigned int index = 0;

	/*
	 * If inbuf and/or *inbuf are NULL, reset conversion descriptor
	 * and put escape sequence if needed.
	 */
	if ((inbuf == NULL) || (*inbuf == NULL)) {
		st->_st_cset_sav = st->_st_cset = CS_0;
		return ((size_t)0);
	}

	cset = st->_st_cset;
	stat = ST_INIT;

	ip = *inbuf;
	op = *outbuf;
	ileft = *inbytesleft;
	oleft = *outbytesleft;

	/*
	 * Main loop; 1 loop per 1 input byte
	 */

	while ((int)ileft > 0) {
		GET(ic);
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
				stat = ST_INIT;
				st->_st_cset_sav = cset = CS_2;
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
		/*
		 * Break through chars or ESC sequence
		 * if (stat == ST_INIT)
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
		/*
		 * XXX- Because V3 mailtool uses SI/SO to switch
		 *	G0 and G1 sets while it puts "iso2022-7"
		 *	as its "X-Sun-Charset" tag. Though it
		 *	breaks ISO-2022-JP definition based on
		 *	UI-OSF, dtmail have handle them correctly.
		 *	Therefore, we have to following a few codes, UGH.
		 */
		} else if (ic == SO) {
			cset = CS_2;
			stat = ST_INIT;
			continue;
		} else if (ic == SI) {
			cset = st->_st_cset_sav;
			stat = ST_INIT;
			continue;
		} else if (!(ic & CMSB)) {
			if ((cset == CS_0) || (cset == CS_2)){
				if (cset == CS_0) {
					index = (int)_jfp_tbl_jisx0201roman_to_ucs2[(int)ic];
				} else if (cset == CS_2) {
					index =
					(int)_jfp_tbl_jisx0201kana_to_ucs2[(ic - 0x21)];
				}
				if ((ret_val = write_unicode(
					(unsigned int)index, &op, &oleft,
					B_FALSE, "writing CS_0/2"))
					< 0) {
					/* errno is set in write_unicode */
					UNGET();
					retval = (size_t)ERR_RETURN;
					goto ret;
				}
				stat = ST_INIT;
				continue;
			} else if ((cset == CS_1) || (cset == CS_3)) {
				if ((int)ileft > 0) {
					if ((ic < 0x21) || (ic == 0x7f)) {
						UNGET();
						errno = EILSEQ;
						retval = (size_t)ERR_RETURN;
						goto ret;
					} else if ((*ip < 0x21) || (*ip ==
					0x7f)) {
						UNGET();
						errno = EILSEQ;
						retval = (size_t)ERR_RETURN;
						goto ret;
					}
					index = ((ic - 0x21) * 94)
							+ (*ip - 0x21);
					if (cset == CS_1) {
#ifdef  RFC1468_MODE /* Convert VDC and UDC to GETA(DEFC_U in jis%UTF-8.h) */
						if ((ic == 0x2d) ||
						(0x75 <= ic))
							index = 0x3013;
						else
							index = (int)
							_jfp_tbl_jisx0208_to_ucs2[index];
#else   /* ISO-2022-JP.UIOSF */
						index = (int)
							_jfp_tbl_jisx0208_to_ucs2[index];
#endif  /* RFC1468_MODE */
					} else if (cset == CS_3) {
#ifdef  RFC1468_MODE /* Convert JIS X 0212 to GETA(DEFC_U in jis%UTF-8.h) */
						index = 0x3013;
#else   /* ISO-2022-JP.UIOSF */
						index =
						(int)_jfp_tbl_jisx0212_to_ucs2[index];
#endif  /* RFC1468_MODE */
					}
					if ((ret_val = write_unicode(
						(unsigned int)index,
						&op, &oleft,
						B_FALSE, "writing CS_1/3"))
						< 0) {
						/* errno is set
						in write_unicode */
						UNGET();
						retval =
						(size_t)ERR_RETURN;
		                                goto ret;
					}
					/* dummy GET for 2nd byte */
					GET(ic);
					stat = ST_INIT;
					continue;
				} else {
					UNGET();
					errno = EINVAL;
					retval = (size_t)ERR_RETURN;
					goto ret;
				}
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
	*inbuf = ip;
	*inbytesleft = ileft;
	*outbuf = (char *)op;
	*outbytesleft = oleft;
	st->_st_cset = cset;

	return (retval);
}
