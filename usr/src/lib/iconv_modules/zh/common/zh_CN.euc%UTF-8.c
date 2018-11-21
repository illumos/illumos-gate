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
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/isa_defs.h>
#include <gb2312_unicode.h>
#include "common_defs.h"
#define MSB	0x80

#define UTF8_NON_ID_CHAR1 0xEF
#define UTF8_NON_ID_CHAR2 0xBF
#define UTF8_NON_ID_CHAR3 0xBD

#define EUC_BYTE1_LOWER   0xA1
#define EUC_BYTE1_UPPER   0xFE
#define EUC_BYTE2_LOWER   EUC_BYTE1_LOWER
#define EUC_BYTE2_UPPER   EUC_BYTE1_UPPER

#define UCHAR unsigned char

typedef struct _icv_state {
	char	_lastc;
	short	_gstate;
        boolean little_endian;
        boolean bom_written;
} _iconv_st;

enum	_GSTATE { G0, G1 };

static  int  is_valid_gb2312(UCHAR, UCHAR);
int
gb_to_unicode(_iconv_st *st, char in_byte2, char *buf, int buflen, int *uconv_num);

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

	st->_gstate = G0;
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
	int	n;
        int	uconv_num = 0;

	if (st == NULL) {
		errno = EBADF;
		return (size_t)-1;
	}
	if (inbuf == NULL || *inbuf == NULL) { /* Reset request. */
		st->_gstate = G0;
		return (size_t)0;
	}

	errno = 0;

	while (*inbytesleft > 0 && *outbytesleft > 0) {
	    switch (st->_gstate) {
	    case G0:
		if ( **inbuf & MSB ) {
		    st->_lastc = **inbuf;
		    st->_gstate = G1;
		} else {		/* ASCII */
		  /*
		   * code conversion for UCS-2LE to support Samba
		   */
		  if (st->little_endian) {
		      if (!st->bom_written) {
		         if (*outbytesleft < 4)
			    errno = E2BIG;
		         else {
			    *(*outbuf)++ = (uchar_t)0xff;
			    *(*outbuf)++ = (uchar_t)0xfe;

			    st->bom_written = true;
			    *outbytesleft -= 2;
			 }
		      }

		      if (*outbytesleft < 2)
			errno = E2BIG;
		      else {
			*(*outbuf)++ = **inbuf;
			*(*outbuf)++ = (uchar_t)0x0;
			*outbytesleft -= 2;
		      }
		  } else {
		    **outbuf = **inbuf;
		    (*outbuf)++, (*outbytesleft)--;
		  }
		}
		break;
	    case G1:
		if (**inbuf & MSB ) {
		    int uconv_num_internal = 0;

		    /* bugfix - 4669831 iconv from zh_CN.euc to UTF-8 dumps core on Intel. */
		    if ( !is_valid_gb2312((UCHAR)st->_lastc, (UCHAR)**inbuf))
		     {
			errno = EILSEQ;
			break;
		     }

		    n = gb_to_unicode(st, **inbuf, *outbuf,
				      *outbytesleft, &uconv_num_internal);
		    if (n > 0) {
			(*outbuf) += n, (*outbytesleft) -= n;

		        uconv_num += uconv_num_internal;

			st->_gstate = G0;
		    } else {
			errno = E2BIG;
		    }
	        } else {
		    errno = EILSEQ;
		}
		break;
	    }

	    if (errno) break;

	    (*inbuf)++, (*inbytesleft)--;
	}

        if (*inbytesleft == 0 && st->_gstate != G0)
                errno = EINVAL;

	if (*inbytesleft > 0 && *outbytesleft == 0)
	    errno = E2BIG;

        if (errno) {
	     /*
	      * if error, *inbuf points to the byte following the last byte
	      * successfully used in the conversion.
	      */
	     *inbuf -= (st->_gstate - G0);
	     *inbytesleft += (st->_gstate - G0);
	     st->_gstate = G0;
	     return ((size_t) -1);
	}

	return uconv_num;
}

static int
is_valid_gb2312(UCHAR byte1, UCHAR byte2)
{
   if ( (byte1 < EUC_BYTE1_LOWER || byte1 > EUC_BYTE1_UPPER) ||
	(byte2 < EUC_BYTE2_LOWER || byte2 > EUC_BYTE2_UPPER) ) {
        return 0;
    }

   return 1;
}


/*
 * return: > 0 - converted with enough space
 *	   = 0 - no space in outbuf
 */
int
gb_to_unicode(st, in_byte2, buf, buflen, uconv_num)
_iconv_st *st;
char	in_byte2;
char	*buf;
int	buflen;
int	*uconv_num;
{
	int	idx;
	int	unicode;
	char    in_byte1 = st->_lastc;

	idx = (((in_byte1 & 0xff) - 0xa1) * 94)  + (in_byte2 & 0xff) - 0xa1;
	/*
	 * code conversion for UCS-2LE to support samba in Solaris
	 */
	if (st->little_endian) {
	   int size = 0;

	   if (idx < 0 || idx >= GBMAX) {
	      unicode = ICV_CHAR_UCS2_REPLACEMENT;
	      *uconv_num = 1;
	   } else
	      unicode = Unicode[idx];

	   if (!st->bom_written) {
	      if (buflen < 4)
		return 0;

	      *(buf + size++) = (uchar_t)0xff;
	      *(buf + size++) = (uchar_t)0xfe;
	      st->bom_written = true;
	   }

	   if (buflen < 2)
	     return 0;

	   *(buf + size++) = (uchar_t)(unicode & 0xff);
	   *(buf + size++) = (uchar_t)((unicode >> 8) & 0xff);

	   return size;
	}

        /* bugfix - 4669831 iconv from zh_CN.euc to UTF-8 dumps core on Intel. */
	if (idx >= 0 && idx < GBMAX ) {
		unicode = Unicode[idx];
		if (unicode >= 0x0080 && unicode <= 0x07ff) {
		    if ( buflen < 2 )
			return 0;
		    *buf = ((unicode >> 6) & 0x1f) | 0xc0;
		    *(buf+1) = (unicode & 0x3f) | MSB;
		    return 2;
		}
		if (unicode >= 0x0800 && unicode <= 0xffff) {
		    if ( buflen < 3 )
			return 0;
		    *buf = ((unicode >> 12) & 0x0f) | 0xe0;
		    *(buf+1) = ((unicode >> 6) & 0x3f) | MSB;
		    *(buf+2) = (unicode & 0x3f) | MSB;
		    return 3;
		}
	}
	if ( buflen < 3 )
	    return 0;

	*buf     = UTF8_NON_ID_CHAR1;
	*(buf+1) = UTF8_NON_ID_CHAR2;
	*(buf+2) = UTF8_NON_ID_CHAR3;

        /* non-identical conversion */
        *uconv_num = 1;

	return 3;
}
