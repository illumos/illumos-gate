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
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unicode_gb18030.h>	/* Unicode to GBK mapping table */
#include "common_defs.h"
#include "ucs4.h"

#define	MSB	0x80	/* most significant bit */
#define ONEBYTE	0xff	/* right most byte */

#define NON_ID_CHAR '?'	/* non-identified character */

#define IS_GBK4BYTES(v)  ( (v) & 0xffff0000 )
#define GBK_LEN_MAX	4


typedef struct _icv_state {
	char	keepc[6];	/* maximum # byte of UTF8 code */
	short	ustate;
	int	_errno;		/* internal errno */
} _iconv_st;

enum _USTATE	{ U0, U1, U2, U3, U4, U5, U6, U7 };

int get_gbk_by_unicode(unsigned long, int*, unsigned long*);
static int binsearch(unsigned long x, table_t v[], int n);
int unicode_to_gbk(int unidx, unsigned long gbkcode, char* buf, size_t buflen, int *uconv_num);

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

#if defined(UCS_2LE) || defined (UCS_2BE) || defined (UCS_4LE) || defined (UCS_4BE)
size_t
_icv_iconv(_iconv_st *st, char **inbuf, size_t *inbytesleft,
				char **outbuf, size_t *outbytesleft)
{
	unsigned char   c1, c2;
#if defined(UCS_4LE) || defined (UCS_4BE)
	unsigned char	c3, c4;
#endif
	int		n, unidx;
        unsigned long   unichr;
	unsigned long	gbkcode;
        int		uconv_num = 0;

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

	while (*inbytesleft > ICV_FETCH_UCS_SIZE-1 && *outbytesleft > 0) {

                int     size = 0;
		int	uconv_num_internal = 0;

                c1 = *(*inbuf + size++);
                c2 = *(*inbuf + size++);
#if defined(UCS_4LE) || defined (UCS_4BE)
                c3 = *(*inbuf + size++);
                c4 = *(*inbuf + size++);
#endif

#if defined(UCS_2LE)
                unichr = (unsigned long) (c1 | (c2<<8));
#elif defined(UCS_2BE)
                unichr = (unsigned long) ((c1<<8) | c2);
#elif defined(UCS_4LE)
                unichr = (unsigned long) (c1 | (c2<<8) | (c3)<<16 | (c4<<24));
#else
                unichr = (unsigned long) ((c1<<24) | (c2<<16) | (c3<<8) | c4);
#endif

                if (unichr < MSB) { /* ASCII */
                        **outbuf = (char) unichr;
		        (*outbuf)++;
			(*outbytesleft)--;
                } else {
			n = get_gbk_by_unicode(unichr, &unidx, &gbkcode);
			if ( n == -1 ) { /* invalid unicode codepoint */
			        st->_errno = errno = EILSEQ;
			        return ((size_t)-1);
			}

			n = unicode_to_gbk(unidx, gbkcode, *outbuf, *outbytesleft, &uconv_num_internal);
			if (n > 0) {
				(*outbuf) += n;
				(*outbytesleft) -= n;

				uconv_num += uconv_num_internal;
                        } else {
                                return ((size_t)-1);
                        }
                }

                (*inbuf) += size;
                (*inbytesleft) -= size;
        }

        if ( *inbytesleft >0 ) {
                errno =  *outbytesleft? EINVAL: E2BIG;
                return ((size_t)-1);
        }

        return uconv_num;
}
#else
/*
 * Actual conversion; called from iconv()
 */
/*=========================================================
 *
 *       State Machine for interpreting UTF8 code
 *
 *=========================================================
 *               4 byte unicode
 *          +----->------->------------> U5 -----> U6-------> U7---+
 *          |                                                      |
 *          |    3 byte unicode                                    |
 *          +----->------->-------+                                |
 *          |                     |                                |
 *          ^                     v                                |
 *          |  2 byte             U2 ---> U3                       |
 *          |  unicode                    v                        |
 * +------> U0 -------> U1                +-------->U4---+         |
 * ^  ascii |           |                           ^    |         |
 * |        |           +-------->--------->--------+    |         |
 * |        v                                            v         V
 * +----<---+-----<------------<------------<------------+---------+
 *
 *=========================================================*/
size_t
_icv_iconv(_iconv_st *st, char **inbuf, size_t *inbytesleft,
				char **outbuf, size_t *outbytesleft)
{
	char		c1 = 0, c2 = 0;
	int		n, unidx;
        unsigned long   unichr;
	unsigned long	gbkcode;
        int		uconv_num = 0;
	int		utf8_len = 0;

#ifdef DEBUG
    fprintf(stderr, "==========     iconv(): UTF2 --> GBK2K     ==========\n");
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
			if ((**inbuf & MSB) == 0) {	/* ASCII */
				**outbuf = **inbuf;
				(*outbuf)++;
				(*outbytesleft)--;
			} else {
				if ((**inbuf & 0xe0) == 0xc0) {	/* 2 byte unicode 0xc0..0xdf */
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
				     /* four bytes of UTF-8 sequences */
				     if ( number_of_bytes_in_utf8_char[((uchar_t)**inbuf)] == ICV_TYPE_ILLEGAL_CHAR )
					st->_errno = errno = EILSEQ;
				     else {
					st->ustate = U5;
					st->keepc[0] = **inbuf;
				     }
				}
			}
			break;
		case U1:		/* 2 byte unicode */
			if ((**inbuf & 0xc0) == MSB) {
				utf8_len = 2;
				st->keepc[1] = **inbuf;

				c1 = (st->keepc[0]&0x1c)>>2;
				c2 = ((st->keepc[0]&0x03)<<6) | ((st->keepc[1])&0x3f);

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
		        first_byte = (uchar_t)st->keepc[0];

		        /* if the first byte is 0xed, it is illegal sequence if the second
			 * one is between 0xa0 and 0xbf because surrogate section is ill-formed
			 */
			if (((uchar_t)**inbuf) < valid_min_2nd_byte[first_byte] ||
			     ((uchar_t)**inbuf) > valid_max_2nd_byte[first_byte] )
		                st->_errno = errno = EILSEQ;
		        else
		           {
				st->ustate = U3;
				st->keepc[1] = **inbuf;
			   }
			break;
		case U3:		/* 3 byte unicode - 3rd byte */
			if ((**inbuf & 0xc0) == MSB) {
				st->ustate = U4;
				utf8_len = 3;
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
	                unichr = (unsigned long) ((c1 & ONEBYTE) << 8) + (c2 & ONEBYTE);
			n = get_gbk_by_unicode(unichr, &unidx, &gbkcode);
		        if ( n == -1 ) { /* unicode is either 0xFFFE or 0xFFFF */
			     st->_errno = errno = EILSEQ;
			     break;
			}
/* comment the following lines so that converter can ignore the non-GBK characters
			if (n != 0) {	* legal unicode;illegal GBK *
				st->_errno = errno = EILSEQ;
				break;
			}
*/
			n = unicode_to_gbk(unidx, gbkcode, *outbuf, *outbytesleft, &uconv_num_internal);
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
		       else {
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
			  /* replace with double NON_ID_CHARs */
			  if ( *outbytesleft < 2 ) st->_errno = errno = E2BIG;
			  else
			    {
			       **outbuf = NON_ID_CHAR;
			       *(*outbuf+1) = NON_ID_CHAR;
			       (*outbytesleft) -= 2;

			       uconv_num++;

			       st->ustate = U0;
			    }
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
		 * successfully used in conversion.
		 */
		*inbuf -= num_reversed_bytes;
		*inbytesleft += num_reversed_bytes;
	        st->ustate = U0;

		return ((size_t) -1);
	}

	return uconv_num;
}
#endif /* UCS_2LE || UCS_2BE || UCS_4LE || UCS_4BE */


/*
 * Match GBK code by UTF8 code;
 * Return: = 0 - match from Unicode to GBK found
 *         = 1 - match from Unicode to GBK NOT found
 *         = -1- illegal sequence
 *
 * Since binary search of the UTF8 to GBK table is necessary, might as well
 * return index and GBK code matching to the unicode.
 */
int get_gbk_by_unicode(unsigned long unicode, int* unidx, unsigned long* gbkcode)
{
        if ( unicode > UCS4_MAXVAL || ext_ucs4_lsw(unicode) > UCS4_PPRC_MAXVAL ) return -1;

	*unidx = binsearch(unicode, unicode_gbk_tab, UNICODEMAX);
	if ((*unidx) >= 0)
		*gbkcode = unicode_gbk_tab[*unidx].value;
	else
		return(1);	/* match from unicode to GBK not found */
#ifdef DEBUG
    fprintf(stderr, "Unicode=%04x, idx=%5d, Big-5=%x ", unicode, *unidx, *gbkcode);
#endif

	return(0);
}


/*
 * ISO/IEC 10646-2000 (Unicode) --> GBK2K
 * Unicode --> UTF8 (FSS-UTF)
 *             (File System Safe Universal Character Set Transformation Format)
 * Return: > 0 - converted with enough space in output buffer
 *         = 0 - no space in outbuf
 */
int unicode_to_gbk(int unidx, unsigned long gbkcode, char* buf, size_t buflen, int *uconv_num)
{
	unsigned long	val;		/* GBK value */
	char		c[GBK_LEN_MAX];
	int		i, length;

	if (unidx < 0) {	/* no match from Unicode to GBK */
		c[0] = c[1] = NON_ID_CHAR;

	        *uconv_num = 1;

		length = 2;
	} else {
		if (  ! IS_GBK4BYTES( gbkcode ) ) { /* character within two bytes area */
			val = gbkcode & 0xffff;
			c[0] = (char) ((val & 0xff00) >> 8);
			c[1] = (char) (val & 0xff);
			length = 2;
		} else { /* character within four bytes area */
			val = gbkcode & 0xffffffff;
			c[0] = (char) ( val >> 24 );
			c[1] = (char) ( val >> 16 );
			c[2] = (char) ( val >> 8 );
			c[3] = (char) val;
			length = 4;
		}
	}

#ifdef DEBUG
    fprintf(stderr, "\t->%x %x<-\n", *buf, *(buf+1));
#endif

	if (buflen < length) {
		errno = E2BIG;
		return(0);
	}

	for ( i = 0; i < length; ++i )
		*buf++ = c[i];

	return length;
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
