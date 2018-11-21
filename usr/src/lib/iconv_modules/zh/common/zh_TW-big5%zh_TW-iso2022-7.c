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
#include "big5_cns11643.h"	/* Big-5 to CNS 11643 mapping table */

#define	MSB	0x80	/* most significant bit */
#define	MBYTE	0x8e	/* multi-byte (4 byte character) */
#define	PMASK	0xa0	/* plane number mask */
#define ONEBYTE	0xff	/* right most byte */
#define MSB_OFF 0x7f    /* mask off MSB */

#define SI      0x0f    /* shift in */
#define SO      0x0e    /* shift out */
#define ESC     0x1b    /* escape */

/* static const char plane_char[] = "0GH23456789:;<=>?"; */
static const char plane_char[] = "0GHIJKLMNOPQRSTUV";

#define GET_PLANEC(i)   (plane_char[i])

#define NON_ID_CHAR '_'	/* non-identified character */

typedef struct _icv_state {
	char	keepc[2];	/* maximum # byte of Big-5 code */
	short	cstate;		/* state machine id (Big-5) */
	short	istate;		/* state machine id (ISO) */
	int	_errno;		/* internal errno */
} _iconv_st;

enum _CSTATE	{ C0, C1 };
enum _ISTATE    { IN, OUT };


static int big5_2nd_byte(char);
static int get_plane_no_by_big5(const char, const char, int*, unsigned long*);
static int big5_to_iso(int, int, unsigned long, char*, size_t);
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
	st->istate = IN;
	st->_errno = 0;

#ifdef DEBUG
    fprintf(stderr, "==========     iconv(): Big-5 --> ISO 2022-7     ==========\n");
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
	int		plane_no, n, unidx;
	unsigned long	cnscode;
	/* pre_plane_no: need to be static when re-entry occurs on errno set */
	static int      pre_plane_no = -1;      /* previous plane number */

	if (st == NULL) {
		errno = EBADF;
		return ((size_t) -1);
	}

	if (inbuf == NULL || *inbuf == NULL) { /* Reset request. */
		st->cstate = C0;
		st->istate = IN;
		st->_errno = 0;
		return ((size_t) 0);
	}

#ifdef DEBUG
    fprintf(stderr, "=== (Re-entry)   iconv(): Big-5 --> ISO 2022-7   ===\n");
    fprintf(stderr, "st->cstate=%d\tst->istate=%d\tst->_errno=%d\tplane_no=%d\n",
	    st->cstate, st->istate, st->_errno, plane_no);
#endif
	st->_errno = 0;         /* reset internal errno */
	errno = 0;		/* reset external errno */

	/* a state machine for interpreting Big-5 code */
	while (*inbytesleft > 0 && *outbytesleft > 0) {
		switch (st->cstate) {
		case C0:		/* assuming ASCII in the beginning */
			if (**inbuf & MSB) {
				st->keepc[0] = (**inbuf);
				st->cstate = C1;
			} else {	/* real ASCII */
				if (st->istate == OUT) {
					st->cstate = C0;
					st->istate = IN;
					**outbuf = SI;
					(*outbuf)++;
					(*outbytesleft)--;
					if (*outbytesleft <= 0) {
						errno = E2BIG;
						return((size_t)-1);
					}
				}
				**outbuf = **inbuf;
				(*outbuf)++;
				(*outbytesleft)--;
			}
			break;
		case C1:		/* Chinese characters: 2nd byte */
			if (big5_2nd_byte(**inbuf) != 0) {	/* illegal Big-5 */
				st->cstate = C0;
				st->istate = IN;
				st->_errno = errno = EILSEQ;
				break;
			}
			st->keepc[1] = (**inbuf);
			plane_no = get_plane_no_by_big5(st->keepc[0],
					st->keepc[1], &unidx, &cnscode);
			if (plane_no < 0) {     /* legal Big-5; illegal CNS */
				st->cstate = C0;
				st->istate = IN;
				st->_errno = errno = EILSEQ;
				break;
			}

			if ((st->istate == IN) || (pre_plane_no != plane_no)) {
				/* change plane # in Chinese mode */
				if (st->istate == OUT) {
					**outbuf = SI;
					(*outbuf)++;
					(*outbytesleft)--;
#ifdef DEBUG
fprintf(stderr, "(plane #=%d\tpre_plane #=%d)\t", plane_no, pre_plane_no);
#endif
				}
				if (*outbytesleft < 4) {
					st->_errno = errno = E2BIG;
					return((size_t)-1);
				}
				pre_plane_no = plane_no;
				st->istate = OUT;	/* shift out */
				**outbuf = ESC;
				*(*outbuf+1) = '$';
                                *(*outbuf+2) = ')';
				*(*outbuf+3) = GET_PLANEC(plane_no);
#ifdef DEBUG
fprintf(stderr, "ESC $ ) %c  ", *(*outbuf+3));
#endif
				(*outbuf) += 4;
				(*outbytesleft) -= 4;
				if (*outbytesleft <= 0) {
					st->_errno = errno = E2BIG;
					return((size_t)-1);
				}
				st->istate = OUT;
				**outbuf = SO;
				(*outbuf)++;
				(*outbytesleft)--;
			}
			n = big5_to_iso(plane_no, unidx, cnscode,
					*outbuf, *outbytesleft);
			if (n > 0) {
				(*outbuf) += n;
				(*outbytesleft) -= n;
			} else {
				st->_errno = errno;
				return((size_t)-1);
			}
			st->cstate = C0;
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
    fprintf(stderr, "!!!!!\tst->_errno = %d\tst->cstate = %d\n",
		st->_errno, st->cstate);
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


/*
 * Get plane number by Big-5 code; i.e. plane #1 returns 1, #2 returns 2, etc.
 * Returns -1 on error conditions
 *
 * Since binary search of the Big-5 to CNS table is necessary, might as well
 * return index and CNS code matching to the unicode.
 */
static int get_plane_no_by_big5(const char c1, const char c2,
			int *unidx, unsigned long *cnscode)
{
	int 		ret;
	unsigned long	big5code;

	big5code = (unsigned long) ((c1 & ONEBYTE) << 8) + (c2 & ONEBYTE);
	*unidx = binsearch(big5code, big5_cns_tab, MAX_BIG5_NUM);
	if ((*unidx) >= 0)
		*cnscode = big5_cns_tab[*unidx].value;
	else
		return(0);	/* match from Big-5 to CNS not found */
#ifdef DEBUG
    fprintf(stderr, "Big-5=%04x, idx=%5d, CNS=%06x ", big5code, *unidx, *cnscode);
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
 * Big-5 code --> ISO 2022-7
 * Return: > 0 - converted with enough space in output buffer
 *         = 0 - no space in outbuf
 */
static int big5_to_iso(int plane_no, int unidx, unsigned long cnscode,
						char *buf, size_t buflen)
{
	unsigned long	val;		/* CNS 11643 value */
#ifdef DEBUG
	char		cns_str[5];
#endif

        if (buflen < 2) {
                errno = E2BIG;
                return(0);
        }

	if (unidx < 0) {	/* no match from UTF8 to CNS 11643 */
		*buf = *(buf+1) = NON_ID_CHAR;
	} else {
		val = cnscode & 0xffff;
		*buf = (val & 0xff00) >> 8;
		*(buf+1) = val & 0xff;
	}

#ifdef DEBUG
    fprintf(stderr, "->%02x %02x<-\t->%c %c<-\t", *buf, *(buf+1), *buf, *(buf+1));
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
