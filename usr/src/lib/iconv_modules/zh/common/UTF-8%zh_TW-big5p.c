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
 * Copyright (c) 1995, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <errno.h>
#include "unicode_big5p.h"	/* UTF8 to Big-5 Plus mapping table */
#include "common_defs.h"

#define	MSB	0x80	/* most significant bit */
#define ONEBYTE	0xff	/* right most byte */

#define NON_ID_CHAR   '?' /* non-identified character */

typedef struct _icv_state {
	char	keepc[6];	/* maximum # byte of UTF8 code */
	short	ustate;
	int	_errno;		/* internal errno */
} _iconv_st;

enum _USTATE	{ U0, U1, U2, U3, U4, U5, U6, U7 };

static int get_big5p_by_utf(char, char, int *, unsigned long *);
static int utf8_to_big5p(int, unsigned long, char *, size_t);
static int binsearch(unsigned long, utf_big5p[], int);


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
 *
 *                         2nd byte  3rd byte  4th byte
 *          +----->------->------->U5------>U6--------->U7
 *          |                                            |
 *          |     3 byte unicode                         |
 *          +----->------->-------+                      |
 *          |                     |                      |
 *          ^                     v                      |
 *          |  2 byte             U2 ---> U3             |
 *          |  unicode                    v              |
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
	char		c1 = '\0', c2 = '\0';
	int		n, unidx;
	unsigned long	big5pcode;

#ifdef DEBUG
    fprintf(stderr, "==========     iconv(): UTF2 --> Big-5 Plus     ==========\n");
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

		switch (st->ustate) {
		case U0:		/* assuming ASCII in the beginning */
			if ((**inbuf & MSB) == 0) {	/* ASCII */
				**outbuf = **inbuf;
				(*outbuf)++;
				(*outbytesleft)--;
			} else {	/* Chinese character */
				if ((**inbuf & 0xe0) == 0xc0) {	/* 2 byte unicode 0xc2..0xdf */

				        /* invalid sequence if the first char is either 0xc0 or 0xc1 */
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
				        /* currently the 16 planes are supported */
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
			if ((**inbuf & 0xc0) == MSB) {
				st->ustate = U4;
				st->keepc[1] = **inbuf;
				c1 = (st->keepc[0]&0x1c)>>2;
				c2 = ((st->keepc[0]&0x03)<<6) | ((**inbuf)&0x3f);
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
			 * one is between 0xa0 and 0xbf because the surrogate section is ill-formed
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
				c1 = ((st->keepc[0]&0x0f)<<4) |
					((st->keepc[1]&0x3c)>>2);
				c2 = ((st->keepc[1]&0x03)<<6) | ((**inbuf)&0x3f);
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
			n = get_big5p_by_utf(c1, c2, &unidx, &big5pcode);
			if ( n == -1 ) { /* unicode is either 0xfffe or 0xffff */
			   st->_errno = errno = EILSEQ;
			   break;
			}

/* comment the following lines to ignore no Big5 plus characters
			if (n != 0) {
				st->_errno = errno = EILSEQ;
				break;
			}
*/

			n = utf8_to_big5p(unidx, big5pcode,
					*outbuf, *outbytesleft);
			if (n > 0) {
				(*outbuf) += n;
				(*outbytesleft) -= n;

				st->ustate = U0;
			} else {
				st->_errno = errno = E2BIG;
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
			  { /* skip it */
			     st->ustate = U0;
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

        if (*inbytesleft == 0 && st->ustate != U0) {
                errno = EINVAL;
                return ((size_t) -1);
        }

	if (*inbytesleft > 0 && *outbytesleft == 0) {
		errno = E2BIG;
		return((size_t) -1);
	}
	return (*inbytesleft);
}


/*
 * Match Big-5 Plus code by UTF8 code;
 * Return: = 0 - match from Unicode to Big-5 Plus found
 *         = 1 - match from Unicode to Big-5 Plus NOT found
 *         =-1 - illegal sequence
 *
 * Since binary search of the UTF8 to Big-5 Plus table is necessary, might as well
 * return index and Big-5 Plus code matching to the unicode.
 */
static int get_big5p_by_utf(char c1, char c2, int *unidx, unsigned long *big5pcode)
{
	unsigned long	unicode;

	unicode = (unsigned long) ((c1 & ONEBYTE) << 8) + (c2 & ONEBYTE);
        /* 0xfffe and 0xffff should not be allowed */
        if ( unicode == 0xFFFE || unicode == 0xFFFF ) return -1;

	*unidx = binsearch(unicode, utf_big5p_tab, MAX_BIG5P_NUM);
	if ((*unidx) >= 0)
		*big5pcode = utf_big5p_tab[*unidx].big5pcode;
	else
		return(1);	/* match from UTF8 to Big-5 Plus not found */
#ifdef DEBUG
    fprintf(stderr, "Unicode=%04x, idx=%5d, Big-5 Plus=%x ", unicode, *unidx, *big5pcode);
#endif

	return(0);
}


/*
 * ISO/IEC 10646 (Unicode) --> Big-5 Plus
 * Unicode --> UTF8 (FSS-UTF)
 *             (File System Safe Universal Character Set Transformation Format)
 * Return: > 0 - converted with enough space in output buffer
 *         = 0 - no space in outbuf
 */
static int utf8_to_big5p(int unidx, unsigned long big5pcode, char *buf, size_t buflen)
{
	unsigned long	val;		/* Big-5 Plus value */
	char		c1, c2, big5p_str[3];

	if (buflen < 2) {
		errno = E2BIG;
		return(0);
	}

	if (unidx < 0) {	/* no match from UTF8 to Big-5 Plus */
		*buf = *(buf+1) = NON_ID_CHAR;
	} else {
		val = big5pcode & 0xffff;
		c1 = (char) ((val & 0xff00) >> 8);
		c2 = (char) (val & 0xff);

	*buf = big5p_str[0] = c1;
	*(buf+1) = big5p_str[1] = c2;
	big5p_str[2] = '\0';
	}

#ifdef DEBUG
    fprintf(stderr, "\t->%x %x<-\n", *buf, *(buf+1));
#endif

	return(2);
}


/* binsearch: find x in v[0] <= v[1] <= ... <= v[n-1] */
static int binsearch(unsigned long x, utf_big5p v[], int n)
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
