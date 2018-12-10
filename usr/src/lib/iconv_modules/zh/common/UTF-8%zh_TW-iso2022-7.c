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
#include "unicode_cns11643_TW.h"	/* UTF8 to CNS 11643 mapping table */
#include "common_defs.h"

#define	MSB	0x80	/* most significant bit */
#define	MBYTE	0x8e	/* multi-byte (4 byte character) */
#define	PMASK	0xa0	/* plane number mask */
#define ONEBYTE	0xff	/* right most byte */

#define SI	0x0f	/* shift in */
#define SO	0x0e	/* shift out */
#define ESC	0x1b	/* escape */

/* static const char plane_char[] = "0GH23456789:;<=>?"; */
static const char plane_char[] = "0GHIJKLMNOPQRSTUV";

#define	GET_PLANEC(i)	(plane_char[i])

#define NON_ID_CHAR '?'	/* non-identified character */

typedef struct _icv_state {
	char	keepc[6];	/* maximum # byte of UTF8 code */
	short	cstate;
	short	istate;
	short	ustate;
	int	_errno;		/* internal errno */
} _iconv_st;

enum _CSTATE	{ C0, C1 };
enum _ISTATE	{ IN, OUT };
enum _USTATE	{ U0, U1, U2, U3, U4, U5, U6, U7 };


static int get_plane_no_by_utf(const char, const char, int *, unsigned long *);
static int utf8_to_iso(int, int, unsigned long, char *, size_t);
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

	st->cstate = C0;
	st->istate = IN;
	st->ustate = U0;
	st->_errno = 0;

#ifdef DEBUG
    fprintf(stderr, "==========     iconv(): UTF2 --> ISO2022-7     ==========\n");
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
 *                         2nd byte   3rd byte 4th byte
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
	char c1 = '\0', c2 = '\0';
	int		plane_no, n, unidx;
	/* pre_plane_no: need to be static when re-entry occurs on errno set */
	static int	pre_plane_no = -1;	/* previous plane number */
	unsigned long	cnscode;

	if (st == NULL) {
		errno = EBADF;
		return ((size_t) -1);
	}

	if (inbuf == NULL || *inbuf == NULL) { /* Reset request. */
		st->cstate = C0;
		st->istate = IN;
		st->ustate = U0;
		st->_errno = 0;
		return ((size_t) 0);
	}

#ifdef DEBUG
    fprintf(stderr, "=== (Re-entry)     iconv(): UTF-8 --> ISO 2022-7 ===\n");
    fprintf(stderr, "st->cstate=%d\tst->istate=%d\tst->_errno=%d\tplane_no=%d\n",
	    st->cstate, st->istate, st->_errno, plane_no);
#endif
	st->_errno = 0;		/* reset internal errno */
	errno = 0;		/* reset external errno */

	/* a state machine for interpreting UTF8 code */
	while (*inbytesleft > 0 && *outbytesleft > 0) {

	        uchar_t  first_byte;

		switch (st->ustate) {
		case U0:		/* assuming ASCII in the beginning */
			if ((**inbuf & MSB) == 0) {	/* ASCII */
				if (st->istate == OUT) {
					st->cstate = C0;
					st->istate = IN;
					**outbuf = SI;
					(*outbuf)++;
					(*outbytesleft)--;
					if (*outbytesleft <= 0) {
						errno = E2BIG;
						return((size_t) -1);
					}
				}
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
			if ((**inbuf & 0xc0) == 0x80) {
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
			plane_no = get_plane_no_by_utf(c1, c2, &unidx, &cnscode);
		        if (plane_no == -2)
		         {  /* unicode is either 0xFFFE or 0xFFFF */
			    st->_errno = errno = EILSEQ;
			    break;
		         }

			if (plane_no > 0) {	/* legal unicode; illegal CNS */
			if ((st->istate == IN) || (pre_plane_no != plane_no)) {
				if ((st->cstate == C0) ||
					(pre_plane_no != plane_no)) {
					/* change plane # in Chinese mode */
					if (st->cstate == C1) {
						**outbuf = SI;
						(*outbuf)++;
						(*outbytesleft)--;
					}
					if (*outbytesleft < 4) {
						st->_errno = errno = E2BIG;
						return((size_t) -1);
					}
					pre_plane_no = plane_no;
					st->cstate = C1;
					**outbuf = ESC;
					*(*outbuf+1) = '$';
					*(*outbuf+2) = ')';
					*(*outbuf+3) = GET_PLANEC(plane_no);
#ifdef DEBUG
    fprintf(stderr, "\n\t\t\t\tESC $ ) %c\t", *(*outbuf+3));
#endif
					(*outbuf) += 4;
					(*outbytesleft) -= 4;
					if (*outbytesleft <= 0) {
						st->_errno = errno = E2BIG;
						return((size_t) -1);
					}
				}
				st->istate = OUT;
				**outbuf = SO;
				(*outbuf)++;
				(*outbytesleft)--;
			}
			}/* get_plane_no OK */

			n = utf8_to_iso(plane_no, unidx, cnscode,
					*outbuf, *outbytesleft);
			if (n > 0) {
				(*outbuf) += n;
				(*outbytesleft) -= n;
			} else {
				st->_errno = errno;
				return((size_t) -1);
			}
			st->ustate = U0;
			st->_errno = 0;
			break;
	        case U5:

		        first_byte = st->keepc[0];

		        /* if the first byte is 0xed, it is illegal sequence if the second
			 * one is between 0xa0 and 0xbf because surrogate section is ill-formed
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
		          {  /* skip it to simplify */
			     st->ustate = U0;
			     st->_errno = 0;
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

	if (errno)
		return((size_t) -1);

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
 * Get plane number by UTF8 code; i.e. plane #1 returns 1, #2 returns 2, etc.
 * Returns -1 on error conditions and return -2 due to illegal sequence
 *
 * Since binary search of the UTF8 to CNS table is necessary, might as well
 * return index and CNS code matching to the unicode.
 */
static int get_plane_no_by_utf(const char c1, const char c2,
			int *unidx, unsigned long *cnscode)
{
	int 		ret;
	unsigned long	unicode;

	unicode = (unsigned long) ((c1 & ONEBYTE) << 8) + (c2 & ONEBYTE);
        /* the 0xfffe and 0xffff should not be allowed */
	if ( unicode == 0xFFFE || unicode == 0xFFFF ) return -2;

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
	case 0x2f:	/* 0x8EAF - U */
	case 0x30:	/* 0x8EB0 - V */
		return (ret - 0x20);	/* so that we can use GET_PLANEC() */
	case 0x2e:	/* 0x8EAE - T */
		return (3);		/* CNS 11643-1992 */
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
static int utf8_to_iso(int plane_no, int unidx, unsigned long cnscode,
						    char *buf, size_t buflen)
{
	unsigned long	val;		/* CNS 11643 value */
#ifdef DEBUG
    char	cns_str[5];
#endif

	if (buflen < 2) {
		errno = E2BIG;
		return(0);
	}


	if (unidx < 0) {	/* no match from UTF8 to CNS 11643 */
	    *buf = *(buf+1) = NON_ID_CHAR;
	    return(2);
	} else {
		val = cnscode & 0xffff;
		*buf = (val & 0xff00) >> 8;
		*(buf+1) = val & 0xff;
	}
#ifdef DEBUG
    fprintf(stderr, "\t%02x%02x\t", *buf, *(buf+1));
#endif

#ifdef DEBUG
    switch (plane_no) {
    case 1:
	cns_str[0] = *buf | MSB;
	cns_str[1] = *(buf+1) | MSB;
	cns_str[2] = cns_str[3] = cns_str[4] = NULL;
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
	cns_str[0] = MBYTE;
	cns_str[1] = (char) PMASK + plane_no;
	cns_str[2] = (char) *buf | MSB;
	cns_str[3] = (char) *(buf+1) | MSB;
	cns_str[4] = NULL;
	break;
    }

    fprintf(stderr, "#%d ->%s<-\n", plane_no, cns_str);
#endif
	return(2);
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
