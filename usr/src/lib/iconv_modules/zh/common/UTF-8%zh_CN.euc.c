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
 * Copyright(c) 1998 Sun Microsystems, Inc.
 * All rights reserved.
 */
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/isa_defs.h>
#include <unicode_gb2312.h>
#include "common_defs.h"

#define MSB		0x80
#define	NON_ID_CHAR	'?'

typedef struct _icv_state {
	short	_ustate;
	char	_cbuf[3];
        boolean little_endian;
        boolean bom_written;
} _iconv_st;

enum	_USTATE	{ U0, U1, U2, U3, U4, U5, U6 };

int unicode_to_gb(char, char, char *, int, int *);

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

	st->_ustate = U0;
	st->little_endian = false;
	st->bom_written = false;
#if defined(UCS_2LE)
	st->little_endian = true;
	st->bom_written = true;
#endif
	return ((void *)st);
}


/*
 * Close; called from iconv_close()
 */
void
_icv_close(_iconv_st *st)
{
	if (st == NULL)
		errno = EBADF;
	else
		free(st);
}


/*
 * Actual conversion; called from iconv()
 */
size_t
_icv_iconv(_iconv_st *st, char **inbuf, size_t*inbytesleft,
			char **outbuf, size_t*outbytesleft)
{
	char	c1, c2;
	int	n;
	int     uconv_num = 0;

	if (st == NULL) {
		errno = EBADF;
		return ((size_t)-1);
	}

	if (inbuf == NULL || *inbuf == NULL) { /* Reset request. */
		st->_ustate = U0;
		return ((size_t)0);
	}

	errno = 0;

	while (*inbytesleft > 0 && *outbytesleft > 0) {

	    uchar_t first_byte;

	    switch (st->_ustate) {
	    case U0:
	        /*
		 * Code converion for UCS-2LE to support Samba
		 */
	        if (st->little_endian) {
		    st->_ustate = U1;
		    st->_cbuf[0] = **inbuf;
		}
		else if ((**inbuf & MSB) == 0) {	/* ASCII */
		    **outbuf = **inbuf;
		    (*outbuf)++; (*outbytesleft)--;
	        } else if ((**inbuf & 0xe0) == 0xc0) { /* 0xc2..0xdf */

		    /* invalid sequence if the first byte is either 0xc0 or 0xc1 */
		    if ( number_of_bytes_in_utf8_char[((uchar_t)**inbuf)] == ICV_TYPE_ILLEGAL_CHAR )
			errno = EILSEQ;
		    else {
		        st->_ustate = U1;
		        st->_cbuf[0] = **inbuf;
		    }
		} else if ((**inbuf & 0xf0) == 0xe0) { /* 0xe0..0xef */
		    st->_ustate = U2;
		    st->_cbuf[0] = **inbuf;
		} else {
		    /* four bytes of UTF-8 sequence */
		    if ( number_of_bytes_in_utf8_char[((uchar_t)**inbuf)] == ICV_TYPE_ILLEGAL_CHAR )
		        errno = EILSEQ;
		    else
		     {
			st->_ustate = U4;
			st->_cbuf[0] = **inbuf;
		     }
		}
		break;
	    case U1:
		if ((**inbuf & 0xc0) == MSB || st->little_endian) {	/* Two-byte UTF */
		    int uconv_num_internal = 0;

		    /*
		     * Code conversion for UCS-2LE to support Samba
		     */
		    if (st->little_endian) {
		        c1 = **inbuf;
			c2 = st->_cbuf[0];

			/*
			 * It's ASCII
			 */
			if (c1 == 0 && (c2 & MSB) == 0) {
			  *(*outbuf)++ = c2;
			  (*outbytesleft) --;
			  st->_ustate = U0;
			  break;
			}
		    } else {
		        c1 = (st->_cbuf[0]&0x1c)>>2;
		        c2 = ((st->_cbuf[0]&0x03)<<6) | ((**inbuf)&0x3f);
		    }
		    n = unicode_to_gb(c1, c2, *outbuf, *outbytesleft, &uconv_num_internal);
		    if (n > 0) {
			(*outbuf) += n, (*outbytesleft) -= n;

		        uconv_num += uconv_num_internal;

		        st->_ustate = U0;
		    } else if (n == 0) {
			errno = E2BIG;
		    } else { /* n == -1 if unicode is either FFFE or 0xFFFF */
		        errno = EILSEQ;
		    }
		} else {
		    errno = EILSEQ;
		}
		break;
	    case U2:

	        first_byte = st->_cbuf[0];

	        /* if the first byte is 0xed, it is illegal sequence if the second
		 * one is between 0xa0 and 0xbf because surrogate section is ill-formed
		 */
		if (((uchar_t)**inbuf) < valid_min_2nd_byte[first_byte] ||
		     ((uchar_t)**inbuf) > valid_max_2nd_byte[first_byte] )
		    errno = EILSEQ;
		else
		  {
		    st->_ustate = U3;
		    st->_cbuf[1] = **inbuf;
		  }
		break;
	    case U3:
		if ((**inbuf & 0xc0) == MSB) {	/* Three-byte UTF */
		    int uconv_num_internal = 0;

		    c1 = ((st->_cbuf[0]&0x0f)<<4) | ((st->_cbuf[1]&0x3c)>>2);
		    c2 = ((st->_cbuf[1]&0x03)<<6) | ((**inbuf)&0x3f);
		    n = unicode_to_gb(c1, c2, *outbuf, *outbytesleft, &uconv_num_internal);
		    if (n > 0) {
			(*outbuf) += n, (*outbytesleft) -= n;

		        uconv_num += uconv_num_internal;

			st->_ustate = U0;
		    } else if ( n == 0 ) {
			errno = E2BIG;
		    } else { /* n == -1 if unicode is either 0xFFFE or 0xFFFF */
		        errno = EILSEQ;
		    }
		} else {
		    errno = EILSEQ;
		}
		break;
	     case U4:

	        first_byte = st->_cbuf[0];

		/* if the first byte is 0xf0, it is illegal sequence if
		 * the second one is between 0x80 and 0x8f
		 * for Four-Byte UTF: U+10000..U+10FFFF
		 */
		if (((uchar_t)**inbuf) < valid_min_2nd_byte[first_byte] ||
		     ((uchar_t)**inbuf) > valid_max_2nd_byte[first_byte] )
		    errno = EILSEQ;
		else
	            {
		      st->_ustate = U5;
		      st->_cbuf[1] = **inbuf;
		    }
		break;
	     case U5:
	        if ((**inbuf & 0xc0) == MSB) /* 0x80..0xbf */
		  {
		     st->_ustate = U6;
		     st->_cbuf[2] = **inbuf;
		  }
		else
		  errno = EILSEQ;
		break;
	     case U6:
	        if ((**inbuf & 0xc0) == MSB) /* 0x80..0xbf */
		  {
		    /* all gb2312 characters are in Unicode Plane 0
		     * so replace these other 16 planes with 0x3f3f
		     */
		    if ( *outbytesleft < 2 )
		       errno = E2BIG;
		    else
		       {
			  **outbuf = NON_ID_CHAR;
			  *(*outbuf+1) = NON_ID_CHAR;
			  (*outbytesleft) -= 2;

			  uconv_num++;

			  st->_ustate = U0;
		       }
		  }
		else
		  errno = EILSEQ;
		break;
	    }

	    if (errno) break;

	    (*inbuf)++; (*inbytesleft)--;
	}

	if (*inbytesleft == 0 && st->_ustate != U0)
		errno = EINVAL;

	if (*inbytesleft > 0 && *outbytesleft == 0)
		errno = E2BIG;

        if (errno) {
	   int num_reversed_bytes = 0;

	   switch (st->_ustate)
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
		num_reversed_bytes = 1;
		break;
	      case U5:
		num_reversed_bytes = 2;
		break;
	      case U6:
		num_reversed_bytes = 3;
		break;
	     }

	   /*
	    * if error, *inbuf points to the byte following the last byte
	    * successfully used in conversion.
	    */
	   *inbuf -= num_reversed_bytes;
	   *inbytesleft += num_reversed_bytes;
	   st->_ustate = U0;

	   return ((size_t)-1);
	}

	return uconv_num;
}

/* return values: 0 - no enough space to hold the GB2312 code
 *               -1 - illegal sequence
 *               >0 - buffer length
 */
int unicode_to_gb(char in_byte1, char in_byte2, char *buf, int buflen, int *uconv_num)
{
	int	gb, unicode;
	int	i, l, h;

	if (buflen < 2)
		return 0;
	unicode = ((in_byte1 & 0xff) << 8) + (in_byte2 & 0xff);
	/* 0xfffe and 0xffff should not be allowed */
        if ( unicode == 0xFFFE || unicode == 0xFFFF ) return -1;

	for (l = 0, h = UNICODEMAX; l < h; ) {
		if (unicode_gb_tab[l].key == unicode) {
			i = l;
			break;
		}
		if (unicode_gb_tab[h].key == unicode) {
			i = h;
			break;
		}
		i = (l + h) / 2;
		if (unicode_gb_tab[i].key == unicode)
			break;
		if (unicode_gb_tab[i].key < unicode)
			l = i + 1;
		else	h = i - 1;
	}
	if (unicode == unicode_gb_tab[i].key) {
		gb = unicode_gb_tab[i].value;
		*buf = ((gb & 0xff00) >> 8) | MSB;
		*(buf+1) = (gb & 0xff) | MSB;
	} else {
		*buf = NON_ID_CHAR;
		*(buf+1) = NON_ID_CHAR;

	        /* non-identical conversion */
		*uconv_num = 1;
	}

	return 2;
}
