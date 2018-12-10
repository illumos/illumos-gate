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
#include "cns11643_unicode_TW.h"	/* CNS 11643 to UTF8 mapping table */

#define	MSB	0x80	/* most significant bit */
#define	MBYTE	0x8e	/* multi-byte (4 byte character) */
#define	PMASK	0xa0	/* plane number mask */
#define ONEBYTE	0xff	/* right most byte */
#define MSB_OFF	0x7f	/* mask off MBS */
#define VALID_EUC_BYTE(v) (((uchar_t)v) >= 0xA1 && ((uchar_t)v) <= 0xFE)

/* non-identified character */
#define UTF8_NON_ID_CHAR1 0xEF
#define UTF8_NON_ID_CHAR2 0xBF
#define UTF8_NON_ID_CHAR3 0xBD


typedef struct _icv_state {
	char	keepc[4];	/* maximum # byte of CNS11643 code */
	short	cstate;		/* state machine id */
	int	_errno;		/* internal errno */
        boolean little_endian;
        boolean bom_written;
} _iconv_st;

enum _CSTATE	{ C0, C1, C2, C3 };

static int get_plane_no_by_char(const char);
static int cns_to_utf8(int, _iconv_st *, char*, size_t, int *);
static int binsearch(unsigned long, cns_utf[], int);
static uint_t getUnicodeFromUDA(int, uchar_t, uchar_t);


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
 *   State Machine for interpreting CNS 11643 code
 *
 *=======================================================
 *
 *                          plane 2 - 16
 *                1st C         2nd C       3rd C
 *    +------> C0 -----> C1 -----------> C2 -----> C3
 *    |  ascii |  plane 1 |                   4th C |
 *    ^        v  2nd C   v                         v
 *    +----<---+-----<----+-------<---------<-------+
 *
 *=======================================================*/
size_t
_icv_iconv(_iconv_st *st, char **inbuf, size_t *inbytesleft,
				char **outbuf, size_t *outbytesleft)
{
	int		plane_no = 0, n;
	int		uconv_num = 0;

#ifdef DEBUG
    fprintf(stderr, "==========     iconv(): CNS11643 --> UTF2     ==========\n");
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
			   if (((uchar_t)**inbuf) == MBYTE || VALID_EUC_BYTE(**inbuf)) {
				st->keepc[0] = (**inbuf);
				st->cstate = C1;
			   } else
			        st->_errno = errno = EILSEQ;
			} else {	/* real ASCII */
			  /*
			   * Code conversion for UCS-2LE to support Samba
			   */
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
			      errno = E2BIG;
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
			if (((uchar_t)st->keepc[0]) == MBYTE) {
				plane_no = get_plane_no_by_char(**inbuf);
				if (plane_no == -1) {	/* illegal plane */
					st->_errno = errno = EILSEQ;
				} else {
					st->keepc[1] = (**inbuf);
					st->cstate = C2;
				}
			} else {
				if (VALID_EUC_BYTE(**inbuf)) {	/* plane #1 */
					int uconv_num_internal = 0;

					st->keepc[1] = (**inbuf);
					st->keepc[2] = st->keepc[3] = NULL;
					n = cns_to_utf8(1, st, *outbuf,
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
			}
			break;
		case C2:	/* plane #2 - #16 (4 bytes): get 3nd byte */
			if (VALID_EUC_BYTE(**inbuf)) {	/* 3rd byte */
				st->keepc[2] = (**inbuf);
				st->cstate = C3;
			} else {
				st->_errno = errno = EILSEQ;
			}
			break;
		case C3:	/* plane #2 - #16 (4 bytes): get 4th byte */
			if (VALID_EUC_BYTE(**inbuf)) {	/* 4th byte */
				int uconv_num_internal = 0;

				st->keepc[3] = (**inbuf);
				n = cns_to_utf8(plane_no, st, *outbuf,
						*outbytesleft, &uconv_num_internal);
				if (n > 0) {
					(*outbuf) += n;
					(*outbytesleft) -= n;

					uconv_num += uconv_num_internal;

					st->cstate = C0;	/* reset state */
				} else {	/* don't reset state */
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

	return  uconv_num;
}


/*
 * Get plane number by char; i.e. 0xa2 returns 2, 0xae returns 14, etc.
 * Returns -1 on error conditions
 */
static int get_plane_no_by_char(const char inbuf)
{
	int ret;
	unsigned char uc = (unsigned char) inbuf;

	ret = uc - PMASK;
	switch (ret) {
	case 1:		/* 0x8EA1 */
	case 2:		/* 0x8EA2 */
	case 3:		/* 0x8EA3 */
	case 4:		/* 0x8EA4 */
	case 5:		/* 0x8EA5 */
	case 6:		/* 0x8EA6 */
	case 7:		/* 0x8EA7 */
	case 12:	/* 0x8EAC */
        case 13:	/* 0x8EAD */
	case 14:	/* 0x8EAE */
	case 15:	/* 0x8EAF */
	case 16:	/* 0x8EB0 */
		return (ret);
	default:
		return (-1);
	}
}


/*
 * CNS 11643 code --> ISO/IEC 10646 (Unicode)
 * Unicode --> UTF8 (FSS-UTF)
 *             (File System Safe Universal Character Set Transformation Format)
 * Return: > 0 - converted with enough space in output buffer
 *         = 0 - no space in outbuf
 */
static int cns_to_utf8(int plane_no, _iconv_st *st, char *buf, size_t buflen, int *uconv_num)
{
	char		cns_str[3];
	unsigned long	cns_val;	/* MSB mask off CNS 11643 value */
	int		unidx;		/* Unicode index */
	unsigned long	uni_val = 0;	/* Unicode */
	char            *keepc = st->keepc;

#ifdef DEBUG
    fprintf(stderr, "%s %d ", keepc, plane_no);
#endif
	if (plane_no == 1) {
		cns_str[0] = keepc[0] & MSB_OFF;
		cns_str[1] = keepc[1] & MSB_OFF;
	} else {
		cns_str[0] = keepc[2] & MSB_OFF;
		cns_str[1] = keepc[3] & MSB_OFF;
	}
	cns_val = (cns_str[0] << 8) + cns_str[1];
#ifdef DEBUG
    fprintf(stderr, "%x\t", cns_val);
#endif

	switch (plane_no) {
	case 1:
		unidx = binsearch(cns_val, cns1_utf_tab, MAX_CNS1_NUM);
		if (unidx >= 0)
			uni_val = cns1_utf_tab[unidx].unicode;
		break;
	case 2:
		unidx = binsearch(cns_val, cns2_utf_tab, MAX_CNS2_NUM);
		if (unidx >= 0)
			uni_val = cns2_utf_tab[unidx].unicode;
		break;
	case 3:
		unidx = binsearch(cns_val, cns3_utf_tab, MAX_CNS3_NUM);
		if (unidx >= 0)
			uni_val = cns3_utf_tab[unidx].unicode;
		break;
	case 4:
		unidx = binsearch(cns_val, cns4_utf_tab, MAX_CNS4_NUM);
		if (unidx >= 0)
			uni_val = cns4_utf_tab[unidx].unicode;
		break;
	case 5:
		unidx = binsearch(cns_val, cns5_utf_tab, MAX_CNS5_NUM);
		if (unidx >= 0)
			uni_val = cns5_utf_tab[unidx].unicode;
		break;
	case 6:
		unidx = binsearch(cns_val, cns6_utf_tab, MAX_CNS6_NUM);
		if (unidx >= 0)
			uni_val = cns6_utf_tab[unidx].unicode;
		break;
	case 7:
		unidx = binsearch(cns_val, cns7_utf_tab, MAX_CNS7_NUM);
		if (unidx >= 0)
			uni_val = cns7_utf_tab[unidx].unicode;
		break;
	case 12:
	case 13:
	case 14:
	case 16:
	        uni_val = getUnicodeFromUDA(plane_no, (uchar_t)keepc[2], (uchar_t)keepc[3]);
	        unidx = 1; /* deceit the following if statement */
		break;
	case 15:
		unidx = binsearch(cns_val, cns15_utf_tab, MAX_CNS15_NUM);
		if (unidx >= 0)
			uni_val = cns15_utf_tab[unidx].unicode;
		break;
	default:
		unidx = -1;	/* no mapping from CNS to UTF8 */
		break;
	}

#ifdef DEBUG
    fprintf(stderr, "unidx = %d, unicode = %x\t", unidx, uni_val);
#endif

        /*
	 * Code version for UCS-2LE to support Samba
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
    fprintf(stderr, "outbuf overflow in cns_to_utf8()!!\n");
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
    fprintf(stderr, "outbuf overflow in cns_to_utf8()!!\n");
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
			     return(0);
			}

		        *buf = (char)((uni_val >> 18) & 0x7) | 0xf0;
		        *(buf+1) = (char)((uni_val >> 12) & 0x3f) | 0x80;
		        *(buf+2) = (char)((uni_val >>6) & 0x3f) | 0x80;
		        *(buf+3) = (char)(uni_val & 0x3f) | 0x80;
		        return(4);
		}
	}

	/* can't find a match in CNS --> UTF8 table or illegal UTF8 code */
	if (buflen < 3) {
#ifdef DEBUG
    fprintf(stderr, "outbuf overflow in cns_to_utf8()!!\n");
#endif
		errno = E2BIG;
		return(0);
	}

        *(unsigned char*) buf     = UTF8_NON_ID_CHAR1;
        *(unsigned char*) (buf+1) = UTF8_NON_ID_CHAR2;
        *(unsigned char*) (buf+2) = UTF8_NON_ID_CHAR3;

	/* non-identical conversion */
	*uconv_num = 1;

#ifdef DEBUG
    fprintf(stderr, "%c %c %c\n", *buf, *(buf+1), *(buf+2));
#endif
	return(3);
}

static uint_t
getUnicodeFromUDA(int plane_no, uchar_t byte1, uchar_t byte2)
{
        uint_t ucs4, disp;

        /* compact into consecutive Unicode value for CNS plane 16 */
        if ( plane_no == 16 ) --plane_no;

        disp = (plane_no - 12) * 8836 + (byte1 - 0xA1) * 94 + ( byte2 - 0xA1);
        return (ucs4 = (0xf << 16) | (disp & 0xffff));
}

/* binsearch: find x in v[0] <= v[1] <= ... <= v[n-1] */
static int binsearch(unsigned long x, cns_utf v[], int n)
{
	int low, high, mid;

	low = 0;
	high = n - 1;
	while (low <= high) {
		mid = (low + high) / 2;
		if (x < v[mid].cnscode)
			high = mid - 1;
		else if (x > v[mid].cnscode)
			low = mid + 1;
		else	/* found match */
			return mid;
	}
	return (-1);	/* no match */
}
