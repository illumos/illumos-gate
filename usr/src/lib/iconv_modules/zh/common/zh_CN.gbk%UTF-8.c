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
 * Copyright(c) 2001 Sun Microsystems, Inc.
 * All rights reserved.
 */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/isa_defs.h>
#include <gb18030_unicode.h>	/* GBK to Unicode mapping table */
#include "common_defs.h"

#define	MSB	0x80	/* most significant bit */
#define ONEBYTE	0xff	/* right most byte */
#define GBK_LEN_MAX  4

#define INVALID_BYTE(v)   ( (v) == 0x80 || (v) == 0xff )
#define gbk4_2nd_byte(v)  ( (v) >= 0x30 && (v) <= 0x39 )
#define gbk4_3rd_byte(v)   ( (v) >= 0x81 && (v) <= 0xfe )
#define gbk4_4th_byte(v)  gbk4_2nd_byte(v)

#define UTF8_NON_ID_CHAR1 0xEF 	/* non-identified character */
#define UTF8_NON_ID_CHAR2 0xBF
#define UTF8_NON_ID_CHAR3 0xBD

#if defined UCS_2LE
    #define output_char unichr_to_ucs_2le
#elif defined UCS_2BE
    #define output_char unichr_to_ucs_2be
#elif defined UCS_4LE
    #define output_char unichr_to_ucs_4le
#elif defined UCS_4BE
    #define output_char unichr_to_ucs_4be
#else
    #define output_char unichr_to_utf8
#endif

typedef struct _icv_state {
	char	keepc[GBK_LEN_MAX];	/* maximum # byte of GBK2K code */
	short	cstate;		/* state machine id */
	int	_errno;		/* internal errno */
        boolean bom_written;
} _iconv_st;

enum _CSTATE	{ C0, C1, C2, C3 };

static unsigned long gbk_to_unicode (_iconv_st *);

static int binsearch(unsigned long x, table_t v[], int n);
static int gbk_2nd_byte(char inbuf);

#include "uni_common.c"

/*
 * Open; called from iconv_open()
 */
void *
_icv_open()
{
	_iconv_st *st;

	if ((st = (_iconv_st *)malloc(sizeof(_iconv_st))) == NULL) {
		errno = ENOMEM;
		return ((void *) -1);
	}

	st->cstate = C0;
	st->_errno = 0;
#if defined(UCS_2LE) || defined(UCS_2BE) || defined(UCS_4LE) || defined(UCS_4BE)
	st->bom_written = true;
#else
        st->bom_written = false;
#endif
	return ((void *) st);
}


/*
 * Close; called from iconv_close()
 */
void
_icv_close(_iconv_st *st)
{
	if (!st)
		errno = EBADF;
	else
		free(st);
}


/*
 * Actual conversion; called from iconv()
 */
/*=======================================================
 *
 *   State Machine for interpreting GBK code
 *
 *=======================================================
 *
 * 		                    3rd C
 *                              C2--------> C3
 *		                ^            |
 *                        2nd C |      4th C |
 *                     1st C    |            |
 *    +--------> C0 ----------> C1           |
 *    |    ascii |        2nd C |            |
 *    ^          v              v	     V
 *    +----<-----+-----<--------+-----<------+
 *
 *=======================================================*/
/*
 * GBK2 encoding range (2 byte area):
 *	High byte: 0x81 - 0xFE			(  126 encoding space)
 *	Low byte:  0x40 - 0x7E, 0x80 - 0xFE	(  190 encoding space)
 *	Total:	   126 * 190 = 23,940		(23940 encoding space)
 *
 * GBK4 encoding range (4 byte area):
 *	The First byte:  0x81 - 0xFE
 *	The Second byte: 0x30 - 0x39
 *	The Third byte:  0x81 - 0xFE
 *	The fourth byte: 0x30 - 0x39
 */

size_t
_icv_iconv(_iconv_st *st, char **inbuf, size_t *inbytesleft,
				char **outbuf, size_t *outbytesleft)
{
	int	n;
        int	uconv_num = 0;

	if (st == NULL) {
		errno = EBADF;
		return ((size_t) -1);
	}

	if (inbuf == NULL || *inbuf == NULL) { /* Reset request. */
		st->cstate = C0;
		st->_errno = 0;
		return ((size_t) 0);
	}

	st->_errno = 0;         /* reset internal errno */
	errno = 0;		/* reset external errno */

	/* a state machine for interpreting GBK code */
	while (*inbytesleft > 0 && *outbytesleft > 0) {
		switch (st->cstate) {
		case C0:		/* assuming ASCII in the beginning */
			if (**inbuf & MSB) {
				if ( INVALID_BYTE((unsigned char)**inbuf) ) {
					st->_errno = errno = EILSEQ;
				} else {
					st->keepc[0] = (**inbuf);
					st->cstate = C1;
				}
			} else {	/* real ASCII */
                                int uconv_num_internal = 0;
                                n = output_char (st, **inbuf, *outbuf,
                                                 *outbytesleft, &uconv_num_internal);
				if (n > 0) {
					(*outbuf) += n;
					(*outbytesleft) -= n;
                                }
			}
			break;
		case C1:		/* GBK2 characters: 2nd byte */
			if (gbk_2nd_byte(**inbuf) == 0) {
			        int uconv_num_internal = 0;

				st->keepc[1] = (**inbuf);
				st->keepc[2] = st->keepc[3] = 0;

				n = output_char (st, gbk_to_unicode (st), *outbuf,
						 *outbytesleft, &uconv_num_internal);
				if (n > 0) {
					(*outbuf) += n;
					(*outbytesleft) -= n;

					uconv_num += uconv_num_internal;

					st->cstate = C0;
				} else {	/* don't reset state */
					st->_errno = errno = E2BIG;
				}

			} else  if ( gbk4_2nd_byte((unsigned char)**inbuf) ) {
				st->keepc[1] = **inbuf;
				st->cstate = C2;
			} else {	/* input char doesn't belong
					 * to the input code set
					 */
				st->_errno = errno = EILSEQ;
			}
			break;
		case C2:
			if ( gbk4_3rd_byte((unsigned char)**inbuf) ) {
				st->keepc[2] = **inbuf;
				st->cstate = C3;
			} else {
				st->_errno = errno = EILSEQ;
			}
			break;
		case C3:
			if ( gbk4_4th_byte((unsigned char)**inbuf) ) {
			        int uconv_num_internal = 0;

				st->keepc[3] = **inbuf;

				n = output_char (st, gbk_to_unicode (st), *outbuf,
                                                 *outbytesleft, &uconv_num_internal);

				if ( n > 0 ) {
					(*outbuf) += n;
					(*outbytesleft) -= n;

				        uconv_num += uconv_num_internal;

					st->cstate = C0;
				} else {
					st->_errno = errno = E2BIG;
				}
			} else {
				st->_errno = errno = EILSEQ;
			}
			break;
		default:			/* should never come here */
			st->_errno = errno = EILSEQ;
			st->cstate = C0;	/* reset state */
			break;
		}

		if (st->_errno) {
			break;
		}

		(*inbuf)++;
		(*inbytesleft)--;
	}

        if (*inbytesleft == 0 && st->cstate != C0)
                errno = EINVAL;

	if (*inbytesleft > 0 && *outbytesleft == 0)
		errno = E2BIG;

        if (errno) {
                /*
		 * if error, *inbuf points to the byte following the last byte
		 * successfully used in the conversion.
		 */
		*inbuf -= (st->cstate - C0);
		*inbytesleft += (st->cstate - C0);
	        st->cstate = C0;
		return ((size_t) -1);
	}

	return uconv_num;
}


/*
 * Test whether inbuf is a valid character for 2nd byte GBK code
 * Return: = 0 - valid GBK2 2nd byte
 *         = 1 - invalid GBK2 2nd byte
 */
static int gbk_2nd_byte(char inbuf)
{
	unsigned int	buf = (unsigned int) (inbuf & ONEBYTE);

	if ((buf >= 0x40) && (buf <= 0x7E))
		return (0);
	if ((buf >= 0x80) && (buf <= 0xFE))
		return (0);
	return(1);
}

static unsigned long gbk_to_unicode (st)
_iconv_st *st;
{
	unsigned long	gbk_val;	        /* GBK value */
	int		unidx;		        /* Unicode index */
	unsigned long	uni_val = 0xffffffff;	/* Unicode */
	int		isgbk4 = 1;
	char            *keepc = st->keepc;

	if ( keepc[2] == 0 && keepc[3] == 0 )
		isgbk4 = 0;

	if ( ! isgbk4 ) {
		gbk_val = ((keepc[0]&ONEBYTE) << 8) + (keepc[1]&ONEBYTE);
        } else {
		int  i;

		gbk_val = keepc[0] & ONEBYTE;
		for ( i = 1; i < GBK_LEN_MAX; ++i )
			gbk_val = (gbk_val << 8) + (keepc[i] & ONEBYTE);
	}

	if  ( isgbk4 ) {
		unidx = binsearch(gbk_val, gbk4_unicode_tab, GBK4MAX);
		if ( unidx >= 0 ) uni_val = gbk4_unicode_tab[unidx].value;
	} else {
		unidx = binsearch(gbk_val, gbk_unicode_tab, GBKMAX);
		if ( unidx >= 0 ) uni_val = gbk_unicode_tab[unidx].value;
	}

        return uni_val;
}

/* binsearch: find x in v[0] <= v[1] <= ... <= v[n-1] */
static int binsearch(unsigned long x, table_t v[], int n)
{
	int low, high, mid;

	low = 0;
	high = n - 1;
	while (low <= high) {
		mid = (high - low) / 2 + low;
		if (x < v[mid].key)
			high = mid - 1;
		else if (x > v[mid].key)
			low = mid + 1;
		else	/* found match */
			return mid;
	}
	return (-1);	/* no match */
}

/*
vi:ts=8:ai:expandtab
*/
