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
#include <errno.h>
#include "cns11643_big5.h"   /* CNS 11643 to Big-5 mapping table */

#define	MSB	0x80	/* most significant bit */
#define	MBYTE	0x8e	/* multi-byte (4 byte character) */
#define	PMASK	0xa0	/* plane number mask */
#define ONEBYTE	0xff	/* right most byte */
#define MSB_OFF	0x7f	/* mask off MBS */

#define SI	0x0f	/* shift in */
#define SO	0x0e	/* shift out */
#define ESC	0x1b	/* escape */

/*
 * static const char plane_char[] = "0GH23456789:;<=>?";
 * static const char plane_char[] = "0GHIJKLMNOPQRSTUV";
 * #define	GET_PLANEC(i)	(plane_char[i])
 */

#define NON_ID_CHAR '_'	/* non-identified character */

typedef struct _icv_state {
	char	keepc[4];	/* maximum # byte of CNS11643 code */
	short	cstate;		/* state machine id */
	int	plane_no;	/* plane number for Chinese character */
	int	_errno;		/* internal errno */
} _iconv_st;

enum _CSTATE	{ C0, C1, C2, C3, C4, C5, C6, C7 };


static int get_plane_no_by_iso(const char);
static int iso_to_big5(int, char[], char*, size_t);
static int binsearch(unsigned long, table_t[], int);


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
	st->plane_no = 0;
	st->_errno = 0;

#ifdef DEBUG
    fprintf(stderr, "==========    iconv(): ISO2022-7 --> Big-5    ==========\n");
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
/*=========================================================================
 *
 *             State Machine for interpreting ISO 2022-7 code
 *
 *=========================================================================
 *
 *                                                        plane 2 - 16
 *                                                    +---------->-------+
 *                                    plane           ^                  |
 *            ESC      $       )      number     SO   | plane 1          v
 *    +-> C0 ----> C1 ---> C2 ---> C3 ------> C4 --> C5 -------> C6     C7
 *    |   | ascii  | ascii | ascii |    ascii |   SI | |          |      |
 *    +----------------------------+    <-----+------+ +------<---+------+
 *    ^                                 |
 *    |              ascii              v
 *    +---------<-------------<---------+
 *
 *=========================================================================*/
size_t
_icv_iconv(_iconv_st *st, char **inbuf, size_t *inbytesleft,
				char **outbuf, size_t *outbytesleft)
{
	int		n;

	if (st == NULL) {
		errno = EBADF;
		return ((size_t) -1);
	}

	if (inbuf == NULL || *inbuf == NULL) { /* Reset request. */
		st->cstate = C0;
		st->_errno = 0;
		return ((size_t) 0);
	}

#ifdef DEBUG
    fprintf(stderr, "=== (Re-entry)   iconv(): ISO 2022-7 --> Big-5   ===\n");
#endif
	st->_errno = 0;         /* reset internal errno */
	errno = 0;		/* reset external errno */

	/* a state machine for interpreting ISO 2022-7 code */
	while (*inbytesleft > 0 && *outbytesleft > 0) {
		switch (st->cstate) {
		case C0:		/* assuming ASCII in the beginning */
			if (**inbuf == ESC) {
				st->cstate = C1;
			} else {	/* real ASCII */
				**outbuf = **inbuf;
				(*outbuf)++;
				(*outbytesleft)--;
			}
			break;
		case C1:		/* got ESC, expecting $ */
			if (**inbuf == '$') {
				st->cstate = C2;
			} else {
				**outbuf = ESC;
				(*outbuf)++;
				(*outbytesleft)--;
				st->cstate = C0;
				st->_errno = 0;
				continue;	/* don't advance inbuf */
			}
			break;
		case C2:		/* got $, expecting ) */
			if (**inbuf == ')') {
				st->cstate = C3;
			} else {
				if (*outbytesleft < 2) {
					st->_errno = errno = E2BIG;
					return((size_t)-1);
				}
				**outbuf = ESC;
				*(*outbuf+1) = '$';
				(*outbuf) += 2;
				(*outbytesleft) -= 2;
				st->cstate = C0;
				st->_errno = 0;
				continue;	/* don't advance inbuf */
			}
			break;
		case C3:		/* got ) expecting G,H,I,...,V */
			st->plane_no = get_plane_no_by_iso(**inbuf);
			if (st->plane_no > 0 ) {	/* plane #1 - #16 */
				st->cstate = C4;
			} else {
				if (*outbytesleft < 3) {
					st->_errno = errno = E2BIG;
					return((size_t)-1);
				}
				**outbuf = ESC;
				*(*outbuf+1) = '$';
				*(*outbuf+2) = ')';
				(*outbuf) += 3;
				(*outbytesleft) -= 3;
				st->cstate = C0;
				st->_errno = 0;
				continue;	/* don't advance inbuf */
			}
			break;
		case C4:		/* SI (Shift In) */
			if (**inbuf == ESC) {
				st->cstate = C1;
				break;
			}
			if (**inbuf == SO) {
#ifdef DEBUG
    fprintf(stderr, "<--------------  SO  -------------->\n");
#endif
				st->cstate = C5;
			} else {	/* ASCII */
				**outbuf = **inbuf;
				(*outbuf)++;
				(*outbytesleft)--;
				st->cstate = C0;
				st->_errno = 0;
			}
			break;
		case C5:		/* SO (Shift Out) */
			if (**inbuf == SI) {
#ifdef DEBUG
    fprintf(stderr, ">--------------  SI  --------------<\n");
#endif
				st->cstate = C4;
			} else {	/* 1st Chinese character */
				if (st->plane_no == 1) {
					st->keepc[0] = (char) (**inbuf | MSB);
					st->cstate = C6;
				} else {	/* 4-bypte code: plane #2 - #16 */
					st->keepc[0] = (char) MBYTE;
					st->keepc[1] = (char) (PMASK +
								st->plane_no);
					st->keepc[2] = (char) (**inbuf | MSB);
					st->cstate = C7;
				}
			}
			break;
		case C6:		/* plane #1: 2nd Chinese character */
			st->keepc[1] = (char) (**inbuf | MSB);
			st->keepc[2] = st->keepc[3] = NULL;
			n = iso_to_big5(1, st->keepc, *outbuf, *outbytesleft);
			if (n > 0) {
				(*outbuf) += n;
				(*outbytesleft) -= n;
			} else {
				st->_errno = errno;
				return((size_t)-1);
			}
			st->cstate = C5;
			break;
		case C7:		/* 4th Chinese character */
			st->keepc[3] = (char) (**inbuf | MSB);
			n = iso_to_big5(st->plane_no, st->keepc, *outbuf,
					*outbytesleft);
			if (n > 0) {
				(*outbuf) += n;
				(*outbytesleft) -= n;
			} else {
				st->_errno = errno;
				return((size_t)-1);
			}
			st->cstate = C5;
			break;
		default:			/* should never come here */
			st->_errno = errno = EILSEQ;
			st->cstate = C0;	/* reset state */
			break;
		}

		(*inbuf)++;
		(*inbytesleft)--;

		if (st->_errno) {
#ifdef DEBUG
    fprintf(stderr, "!!!!!\tst->_errno = %d\tst->cstate = %d\tinbuf=%x\n",
		st->_errno, st->cstate, **inbuf);
#endif
			break;
		}
		if (errno)
			return((size_t)-1);
	}

	if (*inbytesleft > 0 && *outbytesleft == 0) {
		errno = E2BIG;
		return((size_t)-1);
	}
	return (*inbytesleft);
}


/*
 * Get plane number by ISO plane char; i.e. 'G' returns 1, 'H' returns 2, etc.
 * Returns -1 on error conditions
 */
static int get_plane_no_by_iso(const char inbuf)
{
	int ret;
	unsigned char uc = (unsigned char) inbuf;

	if (uc == '0')	/* plane #0 */
		return(0);

	ret = uc - 'F';
	switch (ret) {
	case 1:		/* 0x8EA1 - G */
	case 2:		/* 0x8EA2 - H */
	case 3:		/* 0x8EA3 - I */
	case 4:		/* 0x8EA4 - J */
	case 5:		/* 0x8EA5 - K */
	case 6:		/* 0x8EA6 - L */
	case 7:		/* 0x8EA7 - M */
	case 8:		/* 0x8EA8 - N */
	case 9:		/* 0x8EA9 - O */
	case 10:	/* 0x8EAA - P */
	case 11:	/* 0x8EAB - Q */
	case 12:	/* 0x8EAC - R */
	case 13:	/* 0x8EAD - S */
	case 14:	/* 0x8EAE - T */
	case 15:	/* 0x8EAF - U */
	case 16:	/* 0x8EB0 - V */
		return (ret);
	default:
		return (-1);
	}
}


/*
 * ISO 2022-7 code --> Big-5 code
 * Return: > 0 - converted with enough space in output buffer
 *         = 0 - no space in outbuf
 */
static int iso_to_big5(int plane_no, char keepc[], char *buf, size_t buflen)
{
	char		cns_str[3];
	unsigned long	cns_val;	/* MSB mask off CNS 11643 value */
	int		unidx;		/* binary search index */
	unsigned long	big5_val, val;	/* Big-5 code */

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

        if (buflen < 2) {
                errno = E2BIG;
                return(0);
        }

	switch (plane_no) {
	case 1:
		unidx = binsearch(cns_val, cns_big5_tab1, MAX_CNS1_NUM);
		if (unidx >= 0)
			big5_val = cns_big5_tab1[unidx].value;
		break;
	case 2:
		unidx = binsearch(cns_val, cns_big5_tab2, MAX_CNS2_NUM);
		if (unidx >= 0)
			big5_val = cns_big5_tab2[unidx].value;
		break;
	default:
		unidx = -1;	/* no mapping from CNS to Big-5 out of plane 1&2 */
		break;
	}

#ifdef DEBUG
    fprintf(stderr, "unidx = %d, big5code = %x\t", unidx, big5_val);
#endif

	if (unidx < 0) {	/* no match from CNS to Big-5 */
		*buf = *(buf+1) = NON_ID_CHAR;
	} else {
		val = big5_val & 0xffff;
		*buf = (char) ((val & 0xff00) >> 8);
		*(buf+1) = (char) (val & 0xff);
	}

#ifdef DEBUG
    fprintf(stderr, "\t->%x %x<-\n", *buf, *(buf+1));
#endif

	return(2);
}


/* binsearch: find x in v[0] <= v[1] <= ... <= v[n-1] */
static int binsearch(unsigned long x, table_t v[], int n)
{
	int low, high, mid;

	low = 0;
	high = n - 1;
	while (low <= high) {
		mid = (low + high) / 2;
		if (x < v[mid].key)
			high = mid - 1;
		else if (x > v[mid].key)
			low = mid + 1;
		else	/* found match */
			return mid;
	}
	return (-1);	/* no match */
}
