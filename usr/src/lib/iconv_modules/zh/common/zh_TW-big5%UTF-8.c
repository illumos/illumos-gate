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
#include <sys/isa_defs.h>
#include <errno.h>
#include "common_defs.h"
#include "big5_unicode.h"	/* Big-5 to Unicode mapping table */

#define	MSB	0x80	/* most significant bit */
#define	MBYTE	0x8e	/* multi-byte (4 byte character) */
#define	PMASK	0xa0	/* plane number mask */
#define ONEBYTE	0xff	/* right most byte */

/* non-identified character */
#define UTF8_NON_ID_CHAR1 0xEF
#define UTF8_NON_ID_CHAR2 0xBF
#define UTF8_NON_ID_CHAR3 0xBD


typedef struct  _icv_state {
	char	keepc[2];	/* maximum # byte of Big-5 code */
	short	cstate;		/* state machine id */
	int	_errno;		/* internal errno */
        boolean little_endian;
        boolean bom_written;
}_iconv_st;

enum _CSTATE	{ C0, C1 };

static int big5_2nd_byte(char);
static int big5_to_utf8(_iconv_st *, char*, size_t, int *);
static int binsearch(unsigned long, big5_utf[], int);


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
/*=======================================================
 *
 *   State Machine for interpreting Big-5 code
 *
 *=======================================================
 *
 *                     1st C
 *    +--------> C0 ----------> C1
 *    |    ascii |        2nd C |
 *    ^          v              v
 *    +----<-----+-----<--------+
 *
 *=======================================================*/
/*
 * Big-5 encoding range:
 *	High byte: 0xA1 - 0xFE			(   94 encoding space)
 *	Low byte:  0x40 - 0x7E, 0xA1 - 0xFE	(  157 encoding space)
 *	Plane #1:  0xA140 - 0xC8FE		( 6280 encoding space)
 *	Plane #2:  0xC940 - 0xFEFE		( 8478 encoding space)
 *	Total:	   94 * 157 = 14,758		(14758 encoding space)
 */
size_t
_icv_iconv(_iconv_st *st, char **inbuf, size_t *inbytesleft,
				char **outbuf, size_t *outbytesleft)
{
	int		n;
	int		uconv_num = 0;

#ifdef DEBUG
    fprintf(stderr, "==========     iconv(): Big-5 --> UTF2     ==========\n");
#endif
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

	/* a state machine for interpreting CNS 11643 code */
	while (*inbytesleft > 0 && *outbytesleft > 0) {
		switch (st->cstate) {
		case C0:		/* assuming ASCII in the beginning */
			if (**inbuf & MSB) {
				st->keepc[0] = (**inbuf);
				st->cstate = C1;
			} else {	/* real ASCII */
			  if (st->little_endian) {
			    if (!st->bom_written) {
			      if (*outbytesleft < 4)
				errno = E2BIG;
			      else {
				*(*outbuf)++ = (uchar_t)0xff;
				*(*outbuf)++ = (uchar_t)0xfe;
				*outbytesleft -= 2;

				st->bom_written = true;
			      }
			    }

			    if (*outbytesleft < 2)
			      return E2BIG;
			    else {
			      *(*outbuf)++ = **inbuf;
			      *(*outbuf)++ = (uchar_t)0x0;
			      *outbytesleft -= 2;
			    }
			  } else {
				**outbuf = **inbuf;
				(*outbuf)++;
				(*outbytesleft)--;
			  }
			}
			break;
		case C1:		/* Chinese characters: 2nd byte */
			if (big5_2nd_byte(**inbuf) == 0) {
				int uconv_num_internal = 0;

				st->keepc[1] = (**inbuf);
				n = big5_to_utf8(st, *outbuf,
						*outbytesleft, &uconv_num_internal);
				if (n > 0) {
					(*outbuf) += n;
					(*outbytesleft) -= n;

					uconv_num += uconv_num_internal;

					st->cstate = C0;
				} else {	/* don't reset state */
					st->_errno = errno = E2BIG;
				}
			} else {	/* input char doesn't belong
					 * to the input code set
					 */
				st->_errno = errno = EILSEQ;
			}
			break;
		default:			/* should never come here */
			st->_errno = errno = EILSEQ;
			st->cstate = C0;	/* reset state */
			break;
		}

		if (st->_errno) {
#ifdef DEBUG
    fprintf(stderr, "!!!!!\tst->_errno = %d\tst->cstate = %d\n",
		st->_errno, st->cstate);
#endif
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
 * Test whether inbuf is a valid character for 2nd byte Big-5 code
 * Return: = 0 - valid Big-5 2nd byte
 *         = 1 - invalid Big-5 2nd byte
 */
static int big5_2nd_byte(char inbuf)
{
	unsigned int	buf = (unsigned int) (inbuf & ONEBYTE);

	if ((buf >= 0x40) && (buf <= 0x7E))
		return (0);
	if ((buf >= 0xA1) && (buf <= 0xFE))
		return (0);
	return(1);
}

#ifdef UDC_SUPPORT
typedef struct _udc_sect {
        unsigned int start, end, count;
} UDC;

UDC udc[] = {
  { 0xFA40, 0xFEFE, 0x311 }
};

#define UDC_START_UNICODE 0xF0000

static int
ifUDC(UDC *udc, unsigned int code)
{
   int i;

   for (i=0; i < 1; ++i)
      if (code >= udc[i].start && code <= udc[i].end)
	{
	  unsigned char c1, c2, leading_c1;

	  c1 = (unsigned char)(code >> 8);
	  c2 = (unsigned char)code;
	  leading_c1 = (unsigned char) (udc[i].start >> 8);

	  return UDC_START_UNICODE + (i ? udc[i-1].count : 0) + \
                 (c1 - leading_c1) * 157 + ((c2 <= 0x7E) ? (c2 - 0x40) : ((c2 - 0x40) - (0xA1 - 0x7F)));
	}

   return 0;
}
#endif

/*
 * Big-5 code --> ISO/IEC 10646 (Unicode)
 * Unicode --> UTF8 (FSS-UTF)
 *             (File System Safe Universal Character Set Transformation Format)
 * Return: > 0 - converted with enough space in output buffer
 *         = 0 - no space in outbuf
 */
static int big5_to_utf8(_iconv_st *st, char *buf, size_t buflen, int *uconv_num)
{
	unsigned long	big5_val;	/* Big-5 value */
	int		unidx = 0;		/* Unicode index */
	unsigned long	uni_val = 0;	/* Unicode */
	char            *keepc = st->keepc;

	big5_val = ((keepc[0]&ONEBYTE) << 8) + (keepc[1]&ONEBYTE);
#ifdef DEBUG
    fprintf(stderr, "%x\t", big5_val);
#endif

#ifdef UDC_SUPPORT
      if ((uni_val = ifUDC(udc, big5_val)) == 0) {
#endif
	unidx = binsearch(big5_val, big5_utf_tab, MAX_BIG5_NUM);
	if (unidx >= 0)

	   uni_val = big5_utf_tab[unidx].unicode;
#ifdef UDC_SUPPORT
      }
#endif
#ifdef DEBUG
    fprintf(stderr, "unidx = %d, unicode = %x\t", unidx, uni_val);
#endif

        /*
	 * Code conversion for UCS-2LE to support Samba
	 */
        if (st->little_endian) {
	  int size = 0;

	  if (unidx < 0 || uni_val > 0x00ffff ) {
	    uni_val = ICV_CHAR_UCS2_REPLACEMENT;
	    *uconv_num = 1;
	  }

	  if (!st->bom_written) {
	    if (buflen < 4)
	      return 0;

	    *(buf + size++) = (uchar_t)0xff;
	    *(buf + size++) = (uchar_t)0xfe;
	    st->bom_written = true;
	  }

	  if (buflen < 2)
	    return 0;

	  *(buf + size++) = (uchar_t)(uni_val & 0xff);
	  *(buf + size++) = (uchar_t)((uni_val >> 8) & 0xff);

	  return size;
	}

	if (unidx >= 0) {	/* do Unicode to UTF8 conversion */
		if (uni_val >= 0x0080 && uni_val <= 0x07ff) {
			if (buflen < 2) {
#ifdef DEBUG
    fprintf(stderr, "outbuf overflow in big5_to_utf8()!!\n");
#endif
				errno = E2BIG;
				return(0);
			}
			*buf = (char)((uni_val >> 6) & 0x1f) | 0xc0;
			*(buf+1) = (char)(uni_val & 0x3f) | 0x80;
#ifdef DEBUG
    fprintf(stderr, "%x %x\n", *buf&ONEBYTE, *(buf+1)&ONEBYTE);
#endif
			return(2);
		}
		if (uni_val >= 0x0800 && uni_val <= 0xffff) {
			if (buflen < 3) {
#ifdef DEBUG
    fprintf(stderr, "outbuf overflow in big5_to_utf8()!!\n");
#endif
				errno = E2BIG;
				return(0);
			}
			*buf = (char)((uni_val >> 12) & 0xf) | 0xe0;
			*(buf+1) = (char)((uni_val >>6) & 0x3f) | 0x80;
			*(buf+2) = (char)(uni_val & 0x3f) | 0x80;
#ifdef DEBUG
    fprintf(stderr, "%x %x %x\n", *buf&ONEBYTE, *(buf+1)&ONEBYTE, *(buf+2)&ONEBYTE);
#endif
			return(3);
		}
		if (uni_val >= 0x10000 && uni_val <= 0x10ffff) {
		        if (buflen < 4) {
			   errno = E2BIG;
			   return 0;
			}

			*buf = (char) ((uni_val >> 18 ) & 0x7) | 0xf0;
			*(buf+1) = (char) ((uni_val >> 12) & 0x3f) | 0x80;
			*(buf+2) = (char) ((uni_val >> 6) & 0x3f) | 0x80;
			*(buf+3) = (char) (uni_val & 0x3f) | 0x80;

			return 4;
		}
	}

	/* can't find a match in Big-5 --> UTF8 table or illegal UTF8 code */
	if (buflen < 3) {
#ifdef DEBUG
    fprintf(stderr, "outbuf overflow in big5_to_utf8()!!\n");
#endif
		errno = E2BIG;
		return(0);
	}

        *(unsigned char*) buf     = UTF8_NON_ID_CHAR1;
        *(unsigned char*)(buf+1) = UTF8_NON_ID_CHAR2;
        *(unsigned char*)(buf+2) = UTF8_NON_ID_CHAR3;

	/* non-identical conversion */
	*uconv_num = 1;

#ifdef DEBUG
    fprintf(stderr, "%c %c %c\n", *buf, *(buf+1), *(buf+2));
#endif
	return(3);
}


/* binsearch: find x in v[0] <= v[1] <= ... <= v[n-1] */
static int binsearch(unsigned long x, big5_utf v[], int n)
{
	int low, high, mid;

	low = 0;
	high = n - 1;
	while (low <= high) {
		mid = (low + high) / 2;
		if (x < v[mid].big5code)
			high = mid - 1;
		else if (x > v[mid].big5code)
			low = mid + 1;
		else	/* found match */
			return mid;
	}
	return (-1);	/* no match */
}
