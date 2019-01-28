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
 * Copyright (c) 2000, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/isa_defs.h>
#include "unicode_big5hk.h"	/* UTF8 to HKSCS mapping table */
#include "common_defs.h"

#define	MSB	0x80	/* most significant bit */
#define ONEBYTE	0xff	/* right most byte */

#define NON_ID_CHAR   '?' /* non-identified character */

typedef struct _icv_state {
	char	keepc[6];	/* maximum # byte of UTF8 code */
	short	ustate;
	int	_errno;		/* internal errno */
        boolean little_endian;
        boolean bom_written;
} _iconv_st;

enum _USTATE	{ U0, U1, U2, U3, U4, U5, U6, U7 };

static int get_hkscs_by_utf(uint_t, int *, unsigned long *);
static int utf8_to_hkscs(int, unsigned long, char *, size_t, int *);
static int binsearch(unsigned long, utf_hkscs[], int);

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

	st->ustate = U0;
	st->_errno = 0;
        st->little_endian = false;
        st->bom_written = false;
#if defined(UCS_2LE)
        st->little_endian = true;
        st->bom_written = true;
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
/*=========================================================
 *
 *       State Machine for interpreting UTF8 code
 *
 *=========================================================
 *                          2nd byte 3rd byte 4th byte
 *          +----->------->------->U5---->U6------>U7
 *          |                                      |
 *          |     3 byte unicode                   |
 *          +----->------->-------+                |
 *          |                     |                |
 *          ^                     v                |
 *          |  2 byte             U2 ---> U3       |
 *          |  unicode                    v        v
 * +------> U0 -------> U1                +-------->U4---+
 * ^  ascii |           |                           ^    |
 * |        |           +-------->--------->--------+    |
 * |        v                                            v
 * +----<---+-----<------------<------------<------------+
 *
 *=========================================================*/
size_t
_icv_iconv(_iconv_st *st, char **inbuf, size_t *inbytesleft,
				char **outbuf, size_t *outbytesleft)
{
        int             utf8_len = 0;
	int		n, unidx;
	unsigned long	hkscscode;
	int		uconv_num = 0;
	uint_t          ucs;

#ifdef DEBUG
    fprintf(stderr, "==========     iconv(): UTF2 --> HKSCS     ==========\n");
#endif
	if (st == NULL) {
		errno = EBADF;
		return ((size_t) -1);
	}

	if (inbuf == NULL || *inbuf == NULL) { /* Reset request. */
		st->ustate = U0;
		st->_errno = 0;
		return ((size_t) 0);
	}

	st->_errno = 0;		/* reset internal errno */
	errno = 0;		/* reset external errno */

	/* a state machine for interpreting UTF8 code */
	while (*inbytesleft > 0 && *outbytesleft > 0) {

	        uchar_t  first_byte;
		int	 uconv_num_internal = 0;

		switch (st->ustate) {
		case U0:		/* assuming ASCII in the beginning */
                       /*
                        * Code converion for UCS-2LE to support Samba
                        */
                        if (st->little_endian) {
                          st->ustate = U1;
                          st->keepc[0] = **inbuf;
                        }
			else if ((**inbuf & MSB) == 0) {	/* ASCII */
				**outbuf = **inbuf;
				(*outbuf)++;
				(*outbytesleft)--;
			} else {	/* Chinese character */
				if ((**inbuf & 0xe0) == 0xc0) {	/* 2 byte unicode 0xc2..0xdf */

				        /* invalid sequence if the first byte is either 0xc0 or 0xc1 */
				   if ( number_of_bytes_in_utf8_char[((uchar_t)**inbuf)] == ICV_TYPE_ILLEGAL_CHAR )
				        st->_errno = errno = EILSEQ;
				   else {
					st->ustate = U1;
					st->keepc[0] = **inbuf;
				   }
				} else if ((**inbuf & 0xf0) == 0xe0) {	/* 3 byte 0xe0..0xef */
					st->ustate = U2;
					st->keepc[0] = **inbuf;
				} else {
				        /* four bytes of UTF-8 sequences */
				        if ( number_of_bytes_in_utf8_char[((uchar_t)**inbuf)] == ICV_TYPE_ILLEGAL_CHAR )
					    st->_errno = errno = EILSEQ;
				        else
				         {
					    st->ustate = U5;
					    st->keepc[0] = **inbuf;
					 }
				}
			}
			break;
		case U1:		/* 2 byte unicode */
			if ((**inbuf & 0xc0) == MSB || st->little_endian) {
				st->keepc[1] = **inbuf;
			        utf8_len = 2;

				/*
				 * Code conversion for UCS-2LE to support Samba
				 */
				if  (st->little_endian) {
				  /*
				   * It's ASCII
                                   */
                                  if (st->keepc[1] == 0 && (st->keepc[0] & 0x80) == 0) {
                                    *(*outbuf)++ = st->keepc[0];
				    (*outbytesleft)--;
                                    st->ustate = U0;
                                    break;
                                  }

				  ucs = ((st->keepc[1] & 0xff) << 8) | ( st->keepc[0] & 0xff);

                                } else
                                  convert_utf8_to_ucs4((uchar_t*)(&st->keepc[0]), utf8_len, &ucs);

				st->ustate = U4;
#ifdef DEBUG
    fprintf(stderr, "UTF8: %02x%02x   --> ",
	st->keepc[0]&ONEBYTE, st->keepc[1]&ONEBYTE);
#endif
				continue;	/* should not advance *inbuf */
			} else {
				st->_errno = errno = EILSEQ;
			}
			break;
		case U2:		/* 3 byte unicode - 2nd byte */

		        first_byte = st->keepc[0];

		        /* if the first byte is 0xed, it is illegal sequence if the second
			 * one is between 0xa0 and 0xbf because surrogate section is ill-formed
			 */
		        if (((uchar_t)**inbuf) < valid_min_2nd_byte[first_byte] ||
			    ((uchar_t)**inbuf) > valid_max_2nd_byte[first_byte] )
				st->_errno = errno = EILSEQ;
			else {
				st->ustate = U3;
				st->keepc[1] = **inbuf;
			}
			break;
		case U3:		/* 3 byte unicode - 3rd byte */
			if ((**inbuf & 0xc0) == MSB) {
				st->ustate = U4;
				st->keepc[2] = **inbuf;
			        utf8_len = 3;

                                convert_utf8_to_ucs4((uchar_t*)(&st->keepc[0]), utf8_len, &ucs);
#ifdef DEBUG
    fprintf(stderr, "UTF8: %02x%02x%02x --> ", st->keepc[0]&ONEBYTE,
		st->keepc[1]&ONEBYTE, **inbuf&ONEBYTE);
#endif
				continue;	/* should not advance *inbuf */
			} else {
				st->_errno = errno = EILSEQ;
			}
			break;
		case U4:
			n = get_hkscs_by_utf(ucs, &unidx, &hkscscode);
		        if ( n == -1 ) { /* unicode is either 0xfffe or 0xffff */
			        st->_errno = errno = EILSEQ;
			        break;
			}

/* comment the following lines out to ignore the non-Big5 characters
g			if (n != 0) {
				st->_errno = errno = EILSEQ;
				break;
			}
*/

			n = utf8_to_hkscs(unidx, hkscscode,
					*outbuf, *outbytesleft, &uconv_num_internal);
			if (n > 0) {
				(*outbuf) += n;
				(*outbytesleft) -= n;

				uconv_num += uconv_num_internal;

				st->ustate = U0;
			} else {
				st->_errno = errno;
			}
			break;
		case U5:

		        first_byte = st->keepc[0];

		        /* if the first byte is 0xf0, it is illegal sequence if
			 * the second one is between 0x80 and 0x8f
			 * for Four-Byte UTF: U+10000..U+10FFFF
			 */
		        if (((uchar_t)**inbuf) < valid_min_2nd_byte[first_byte] ||
			    ((uchar_t)**inbuf) > valid_max_2nd_byte[first_byte] )
				st->_errno = errno = EILSEQ;
		        else
		          {
			     st->ustate = U6;
			     st->keepc[1] = **inbuf;
		          }
		        break;
		case U6:
		        if ((**inbuf & 0xc0) == MSB) /* 0x80..0xbf */
		          {
			     st->ustate = U7;
			     st->keepc[2] = **inbuf;
			  }
		        else
		             st->_errno = errno = EILSEQ;
                        break;
		case U7:
		        if ((**inbuf & 0xc0) == MSB) /* 0x80..0xbf */
		          {
			     utf8_len = 4;
			     st->keepc[3] = **inbuf;

                             convert_utf8_to_ucs4((uchar_t*)(&st->keepc[0]), utf8_len, &ucs);

			     st->ustate = U4;
			     continue;	/* should not advance *inbuf */
			  }
		        else
		             st->_errno = errno = EILSEQ;
		        break;
		default:			/* should never come here */
			st->_errno = errno = EILSEQ;
			st->ustate = U0;	/* reset state */
			break;
		}

		if (st->_errno) {
#ifdef DEBUG
    fprintf(stderr, "!!!!!\tst->_errno = %d\tst->ustate = %d\n",
		st->_errno, st->ustate);
#endif
			break;
		}

		(*inbuf)++;
		(*inbytesleft)--;
	}

        if (errno) return ((size_t) -1);

        if (*inbytesleft == 0 && st->ustate != U0)
                errno = EINVAL;

	if (*inbytesleft > 0 && *outbytesleft == 0)
		errno = E2BIG;

	if (errno) {
		int num_reversed_bytes = 0;

		switch (st->ustate)
	        {
		 case U1:
		   num_reversed_bytes = 1;
		   break;
		 case U2:
		   num_reversed_bytes = 1;
		   break;
		 case U3:
		   num_reversed_bytes = 2;
		   break;
		 case U4:
		   num_reversed_bytes = utf8_len - 1;
		   break;
		 case U5:
		   num_reversed_bytes = 1;
		   break;
		 case U6:
		   num_reversed_bytes = 2;
		   break;
		 case U7:
		   num_reversed_bytes = 3;
		   break;
	        }

		/*
		 * if error, *inbuf points to the byte following the last byte
		 * successfully used in the conversion.
		 */
		*inbuf -= num_reversed_bytes;
		*inbytesleft += num_reversed_bytes;
		st->ustate = U0;
		return ((size_t) -1);
	}

	return uconv_num;
}

/*
 * Match HKSCS code by UTF8 code;
 * Return: = 0 - match from Unicode to HKSCS found
 *         = 1 - match from Unicode to HKSCS NOT found
 *         =-1 - illegal sequence
 *
 * Since binary search of the UTF8 to HKSCS table is necessary, might as well
 * return index and HKSCS code matching to the unicode.
 */
static int get_hkscs_by_utf(uint_t unicode, int *unidx, unsigned long *hkscscode)
{
        /* the 0xFFFE and 0xFFFF should not be allowed */
        if (unicode == 0xFFFE || unicode == 0xFFFF ) return -1;

	*unidx = binsearch(unicode, utf_hkscs_tab, MAX_HKSCS_NUM);
	if ((*unidx) >= 0)
		*hkscscode = utf_hkscs_tab[*unidx].hkscscode;
	else
		return(1);	/* match from UTF8 to HKSCS not found */
#ifdef DEBUG
    fprintf(stderr, "Unicode=%04x, idx=%5d, HKSCS=%x ", unicode, *unidx, *hkscscode);
#endif

	return(0);
}


/*
 * ISO/IEC 10646 (Unicode) --> HKSCS
 * Unicode --> UTF8 (FSS-UTF)
 *             (File System Safe Universal Character Set Transformation Format)
 * Return: > 0 - converted with enough space in output buffer
 *         = 0 - no space in outbuf
 */
static int utf8_to_hkscs(int unidx, unsigned long hkscscode, char *buf, size_t buflen, int *uconv_num)
{
	unsigned long	val;		/* HKSCS value */
	char		c1, c2, hkscs_str[3];

	if (buflen < 2) {
		errno = E2BIG;
		return(0);
	}

	if (unidx < 0) {	/* no match from UTF8 to HKSCS */
		*buf = *(buf+1) = NON_ID_CHAR;

		/* non-identical conversion */
		*uconv_num = 1;
	} else {
		val = hkscscode & 0xffff;
		c1 = (char) ((val & 0xff00) >> 8);
		c2 = (char) (val & 0xff);

	*buf = hkscs_str[0] = c1;
	*(buf+1) = hkscs_str[1] = c2;
	hkscs_str[2] = '\0';
	}

#ifdef DEBUG
    fprintf(stderr, "\t->%x %x<-\n", *buf, *(buf+1));
#endif

	return(2);
}


/* binsearch: find x in v[0] <= v[1] <= ... <= v[n-1] */
static int binsearch(unsigned long x, utf_hkscs v[], int n)
{
	int low, high, mid;

	low = 0;
	high = n - 1;
	while (low <= high) {
		mid = (low + high) / 2;
		if (x < v[mid].unicode)
			high = mid - 1;
		else if (x > v[mid].unicode)
			low = mid + 1;
		else	/* found match */
			return mid;
	}
	return (-1);	/* no match */
}
