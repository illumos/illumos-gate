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
#include "unicode_cns11643_TW.h"
#include "common_defs.h"

#define	MSB	0x80	/* most significant bit */
#define	MBYTE	0x8e	/* multi-byte (4 byte character) */
#define	PMASK	0xa0	/* plane number mask */
#define ONEBYTE	0xff	/* right most byte */

#define NON_ID_CHAR '?'	/* non-identified character */

#define Low_UDA_In_Unicode 0xF0000
#define High_UDA_In_Unicode 0xF8A10

typedef struct _icv_state {
	char	keepc[6];	/* maximum # byte of UTF8 code */
	short	ustate;
	int	_errno;		/* internal errno */
        boolean little_endian;
        boolean bom_written;
} _iconv_st;

enum _USTATE	{ U0, U1, U2, U3, U4, U5, U6, U7 };

static int get_plane_no_by_utf(uint_t, int *, unsigned long *);
static int utf8_to_cns(int, int, unsigned long, char *, size_t, int *);
static int binsearch(unsigned long, utf_cns[], int);

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
 *                          2nd byte  3rd byte 4th byte
 *          +----->------->------->U5----->U6----------->U7
 *          |                                            |
 *          |    3 byte unicode                          |
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
	int		plane_no, n, unidx;
	unsigned long	cnscode;
        uint_t		ucs;
	int		uconv_num = 0;
	int		utf8_len = 0;

#ifdef DEBUG
    fprintf(stderr, "==========     iconv(): UTF2 --> CNS11643     ==========\n");
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
			} else {	/* Chinese character 0xc2..0xdf */
				if ((**inbuf & 0xe0) == 0xc0) {	/* 2 byte unicode */

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
			if ((**inbuf & 0xc0) == 0x80 || st->little_endian) {
				utf8_len = 2;
				st->keepc[1] = **inbuf;

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

				  ucs = ((st->keepc[1] & 0xff)<< 8) | (st->keepc[0] & 0xff);

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
			if ((**inbuf & 0xc0) == 0x80) {
				st->ustate = U4;
				utf8_len = 3;
				st->keepc[2] = **inbuf;

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

		       /* 0xfffe and 0xffff should not be allowed */
		       if ( ucs == 0xFFFE || ucs == 0xFFFF ) {
			       st->_errno = errno = EILSEQ;
			       break;
			}

			plane_no = get_plane_no_by_utf(ucs, &unidx, &cnscode);

/* comment these lines to ignore the invalid CNS
			if (plane_no < 0) {
				st->_errno = errno = EILSEQ;
				break;
			}
*/

			n = utf8_to_cns(plane_no, unidx, cnscode,
					*outbuf, *outbytesleft, &uconv_num_internal);
			if (n > 0) {
				(*outbuf) += n;
				(*outbytesleft) -= n;

				uconv_num += uconv_num_internal;

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
		        else {
			    st->ustate = U6;
			    st->keepc[1] = **inbuf;
			}
		        break;
		 case U6:
		        if ((**inbuf & 0xc0) == 0x80) /* 0x80..0xbf */
		          {
			     st->ustate = U7;
			     st->keepc[2] = **inbuf;
			  }
		        else
		          st->_errno = errno = EILSEQ;
		        break;
		 case U7:
		        if ((**inbuf & 0xc0) == 0x80) /* 0x80..0xbf */
		          {
			     st->keepc[3] = **inbuf;
			     utf8_len = 4;

			     convert_utf8_to_ucs4((uchar_t*)(&st->keepc[0]), utf8_len, &ucs);
			     st->ustate = U4;

			     continue;
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

		switch (st->ustate) {
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
 * Get plane number by UTF8 code; i.e. plane #1 returns 1, #2 returns 2, etc.
 * Returns -1 on error conditions
 *
 * Since binary search of the UTF8 to CNS table is necessary, might as well
 * return index and CNS code matching to the unicode.
 */
static int get_plane_no_by_utf(uint_t unicode,
			int *unidx, unsigned long *cnscode)
{
	int		ret;

        /* test whether it belongs to private Unicode plane 15 */
        if (unicode >= Low_UDA_In_Unicode && unicode <= High_UDA_In_Unicode)
           {
	       uint_t  internIdx = (uint_t)(unicode - Low_UDA_In_Unicode);
	       uchar_t byte1, byte2;

	       byte1 = 0xa1 + (internIdx % 8836) / 94;
	       byte2 = 0xa1 + internIdx % 94;
	       *cnscode = ((byte1 << 8) & 0xff00) | (byte2 & 0xff);

	       *unidx = 1; /* deceit the utf8_to_cns() */

	       ret = 12 + internIdx / 8836;
	       /* actually it belongs to CNS plane 16, so change it */
	       if ( ret == 15 ) ++ret;

	       return ret;
           }


	*unidx = binsearch(unicode, utf_cns_tab, MAX_UTF_NUM);
	if ((*unidx) >= 0)
		*cnscode = utf_cns_tab[*unidx].cnscode;
	else
		return(0);	/* match from UTF8 to CNS not found */
#ifdef DEBUG
    fprintf(stderr, "Unicode=%04x, idx=%5d, CNS=%x ", unicode, *unidx, *cnscode);
#endif

	ret = (int) (*cnscode >> 16);
	switch (ret) {
	case 0x21:	/* 0x8EA1 - G */
	case 0x22:	/* 0x8EA2 - H */
	case 0x23:	/* 0x8EA3 - I */
	case 0x24:	/* 0x8EA4 - J */
	case 0x25:	/* 0x8EA5 - K */
	case 0x26:	/* 0x8EA6 - L */
	case 0x27:	/* 0x8EA7 - M */
	case 0x28:	/* 0x8EA8 - N */
	case 0x29:	/* 0x8EA9 - O */
	case 0x2a:	/* 0x8EAA - P */
	case 0x2b:	/* 0x8EAB - Q */
	case 0x2c:	/* 0x8EAC - R */
	case 0x2d:	/* 0x8EAD - S */
	case 0x2e:	/* 0x8EAE - T */
	case 0x2f:	/* 0x8EAF - U */
	case 0x30:	/* 0x8EB0 - V */
		return (ret - 0x20);	/* so that we can use GET_PLANEC() */
	default:
		return (-1);
	}
}


/*
 * ISO/IEC 10646 (Unicode) --> ISO 2022-7
 * Unicode --> UTF8 (FSS-UTF)
 *             (File System Safe Universal Character Set Transformation Format)
 * Return: > 0 - converted with enough space in output buffer
 *         = 0 - no space in outbuf
 */
static int utf8_to_cns(int plane_no, int unidx, unsigned long cnscode,
						    char *buf, size_t buflen, int *uconv_num)
{
	unsigned long	val;		/* CNS 11643 value */
	unsigned char	c1 = 0, c2 = 0, cns_str[5];
	int		ret_size;

	if (unidx < 0) {	/* no match from UTF8 to CNS 11643 */
		if ( buflen < 2 ) goto err;
		*buf = *(buf+1) = NON_ID_CHAR;

		/* non-identical conversion */
		*uconv_num = 1;

		ret_size = 2;
	} else {
		val = cnscode & 0xffff;
		c1 = ((val & 0xff00) >> 8) | MSB;
		c2 = (val & 0xff) | MSB;
	}

	switch (plane_no) {
	case 1:
		if ( buflen < 2) goto err;
		*buf = cns_str[0] = c1;
		*(buf+1) = cns_str[1] = c2;
		cns_str[2] = cns_str[3] = cns_str[4] = '\0';
		ret_size = 2;
		break;
	case 2:
	case 3:
	case 4:
	case 5:
	case 6:
	case 7:
	case 8:
	case 9:
	case 10:
	case 11:
	case 12:
	case 13:
	case 14:
	case 15:
	case 16:
		if ( buflen < 4) goto err;
		*(unsigned char*) buf = cns_str[0] = MBYTE;
		*(buf+1) = cns_str[1] = PMASK + plane_no;
		*(buf+2) = cns_str[2] = c1;
		*(buf+3) = cns_str[3] = c2;
		cns_str[4] = '\0';
		ret_size = 4;
		break;
	}

#ifdef DEBUG
    fprintf(stderr, "\t#%d ->%s<-\n", plane_no, cns_str);
#endif

	return(ret_size);

err:
	errno = E2BIG;
	return 0;
}


/* binsearch: find x in v[0] <= v[1] <= ... <= v[n-1] */
static int binsearch(unsigned long x, utf_cns v[], int n)
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
