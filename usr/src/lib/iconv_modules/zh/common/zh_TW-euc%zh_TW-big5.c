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
#include "cns11643_big5.h"	/* CNS 11643 to Big-5 mapping table */

#define	MSB	0x80	/* most significant bit */
#define	MBYTE	0x8e	/* multi-byte (4 byte character) */
#define	PMASK	0xa0	/* plane number mask */
#define ONEBYTE	0xff	/* right most byte */
#define MSB_OFF	0x7f	/* mask off MBS */

#define NON_ID_CHAR '_'	/* non-identified character */

typedef struct _icv_state {
	char	keepc[4];	/* maximum # byte of CNS11643 code */
	short	cstate;		/* state machine id */
	int	_errno;		/* internal errno */
} _iconv_st;

enum _CSTATE	{ C0, C1, C2, C3 };


static int get_plane_no_by_char(const char);
static int cns_to_big5(int, char[], char*, size_t);
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
	st->_errno = 0;

#ifdef DEBUG
    fprintf(stderr, "==========     iconv(): CNS11643 --> Big-5     ==========\n");
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
	int		plane_no = -1, n;

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
    fprintf(stderr, "=== (Re-entry)   iconv(): CNS 11643 --> Big-5 ===\n");
#endif
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
				**outbuf = **inbuf;
				(*outbuf)++;
				(*outbytesleft)--;
			}
			break;
		case C1:		/* Chinese characters: 2nd byte */
			if ((st->keepc[0] & ONEBYTE) == MBYTE) { /* 4-byte (0x8e) */
				plane_no = get_plane_no_by_char(**inbuf);
				if (plane_no == -1) {	/* illegal plane */
					st->_errno = errno = EILSEQ;
				} else {	/* 4-byte Chinese character */
					st->keepc[1] = (**inbuf);
					st->cstate = C2;
				}
			} else {	/* 2-byte Chinese character - plane #1 */
				if (**inbuf & MSB) {	/* plane #1 */
					st->keepc[1] = (**inbuf);
					st->keepc[2] = st->keepc[3] = '\0';
					n = cns_to_big5(1, st->keepc, *outbuf,
							*outbytesleft);
					if (n > 0) {
						(*outbuf) += n;
						(*outbytesleft) -= n;

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
			if (**inbuf & MSB) {	/* 3rd byte */
				st->keepc[2] = (**inbuf);
				st->cstate = C3;
			} else {
				st->_errno = errno = EILSEQ;
			}
			break;
		case C3:	/* plane #2 - #16 (4 bytes): get 4th byte */
			if (**inbuf & MSB) {	/* 4th byte */
				st->keepc[3] = (**inbuf);
				n = cns_to_big5(plane_no, st->keepc, *outbuf,
						*outbytesleft );
				if (n > 0) {
					(*outbuf) += n;
					(*outbytesleft) -= n;

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

        if (errno) return ((size_t) -1);

        if (*inbytesleft == 0 && st->cstate != C0) {
                errno = EINVAL;
                return ((size_t) -1);
        }

	if (*inbytesleft > 0 && *outbytesleft == 0) {
		errno = E2BIG;
		return((size_t)-1);
	}
	return (*inbytesleft);
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
	case 14:	/* 0x8EAE */
	case 15:	/* 0x8EAF */
	case 16:	/* 0x8EB0 */
		return (ret);
	default:
		return (-1);
	}
}


/*
 * CNS 11643 code --> Big-5
 * Return: > 0 - converted with enough space in output buffer
 *         = 0 - no space in outbuf
 */
static int cns_to_big5(int plane_no, char keepc[], char *buf, size_t buflen)
{
	char		cns_str[3];
	unsigned long	cns_val;	/* MSB mask off CNS 11643 value */
	int		unidx;		/* binary search index */
	unsigned long	big5_val, val;	/* Big-5 code */

#ifdef DEBUG
    fprintf(stderr, "%s %d ", keepc, plane_no);
#endif
	if (buflen < 2) {
		errno = E2BIG;
		return(0);
	}

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
		unidx = binsearch(cns_val, cns_big5_tab1, MAX_CNS1_NUM);
		if (unidx >= 0)
			big5_val = cns_big5_tab1[unidx].value;
		break;
	case 2:
		unidx = binsearch(cns_val, cns_big5_tab2, MAX_CNS2_NUM);
		if (unidx >= 0)
			big5_val = cns_big5_tab2[unidx].value;
		break;
	case 3:
		unidx = binsearch(cns_val, cns_big5_tab3, MAX_CNS3_NUM);
		if (unidx >= 0)
			big5_val = cns_big5_tab3[unidx].value;
		break;
	default:
		unidx = -1;	/* no mapping from CNS to Big-5 */
		break;
	}

#ifdef DEBUG
    fprintf(stderr, "unidx = %d, value = %x\t", unidx, big5_val);
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
