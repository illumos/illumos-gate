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
#include <strings.h>
#include <errno.h>
#ifdef DEBUG
#include <sys/fcntl.h>
#include <sys/stat.h>
#endif
#include <cns11643_big5.h>	/* CNS 11643 to Big-5 mapping table */
#include <big5_gb2312.h>	/* Big-5 to GB mapping table */

#define MSB 	0x80	/* most significant bit */
#define MBYTE	0x8e	/* multi-byte (4 byte character) */
#define PMASK	0xa0	/* plane number mask */
#define ONEBYTE 0xff	/* right most byte */
#define MSB_OFF 0x7f	/* mask off MBS */

#define SI	0x0f		/* shift in */
#define SO	0x0e		/* shift out */
#define ESC 0x1b		/* escape */
#define SS2	0x4e		/* SS2 shift out */
#define SS3 0x4f		/* SS3 shift out */
#define NON_ID_CHAR_BYTE1	0xA1	/* non-identified character */
#define NON_ID_CHAR_BYTE2	0xF5	/* non-identified character */

typedef struct _icv_state {
	char	_buf[10];
	size_t	_bufcont;
	char	_keepc[4];	/* maximum # byte of CNS11643 code */
	short	_gstate;		/* state machine id */
	short	_istate;		/* state for shift in/out */
	int		_plane;		/* plane number for Chinese character */
	int		_last_plane;	/* last charactor's plane # */
	int 	_errno;		/* internal errno */
} _iconv_st;

int binsearch_big5_gb(unsigned int big5code);

enum _GSTATE    { G0, G1, G2, G3, G4, G5, G6, G7, G8, G9, \
				  G10,G11,G12,G13,G14,G15,G16,G17,G18,G19, \
				  G20,G21,G22,G23,G24,G25,G26,G27,G28,G29 };

enum _ISTATE	{ IN, OUT };


int iso_gb_to_gb(_iconv_st * st, char* buf, size_t buflen);
int iso_to_big5_to_gb(_iconv_st * st, char* buf, size_t buflen);
int binsearch(unsigned long x, table_t v[], int n);
int flush_buf(_iconv_st * st, char ** outbuf, size_t * outbytesleft);

int flush_buf(_iconv_st * st, char ** outbuf, size_t * outbytesleft) {
	if (!st->_bufcont)
		return 0;
	if (st->_bufcont > *outbytesleft) {
		st->_errno = E2BIG;
		return -1;
	}
	if (st->_istate != IN) {
		st->_errno = EILSEQ;
		return -1;
	}
	strncpy(st->_buf, *outbuf, st->_bufcont);
	(*outbuf)+=(st->_bufcont);
	(*outbytesleft)-=(st->_bufcont);
	st->_bufcont = 0;
	return st->_bufcont;
}

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
	st->_istate = IN;
	st->_last_plane = st->_plane = -1;
	st->_errno = 0;
	st->_bufcont = 0;

	return ((void *) st);
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
 *    +-> G0 ----> G1 ---> G2 ---> G3 ------> G4 --> G5 -------> G6     G7
 *    |   | ascii  | ascii | ascii |    ascii |   SI | |          |      |
 *    +----------------------------+    <-----+------+ +------<---+------+
 *    ^                                 |
 *    |              ascii              v
 *    +---------<-------------<---------+
 *
 *=========================================================================*/
size_t _icv_iconv(_iconv_st *st, \
					char **inbuf, size_t *inbytesleft, \
					char **outbuf, size_t *outbytesleft) {
	int		n;
	char	c;

	if (st == NULL) {
		errno = EBADF;
		return ((size_t) -1);
	}

	if (inbuf == NULL || *inbuf == NULL) { /* Reset request. */
		st->_gstate = G0;
		st->_istate = IN;
		st->_errno = 0;
		st->_plane = st->_last_plane = -1;
		return ((size_t) 0);
	}

	errno = st->_errno = 0;	/* reset internal and external errno */

	/* a state machine for interpreting ISO 2022-7 code */
	while (*inbytesleft > 0 && *outbytesleft > 0) {
		switch (st->_gstate) {
			case G0:		/* assuming ASCII in the beginning */
				if (**inbuf == ESC) {
					st->_gstate = G1;
					st->_buf[st->_bufcont++] = ESC;
				} else {	/* real ASCII */
					**outbuf = **inbuf;
					(*outbuf)++;
					(*outbytesleft)--;
				}
				break;
			case G1:		/* got ESC, expecting $ */
				if (**inbuf == '$') {
					st->_gstate = G2;
					st->_buf[st->_bufcont++] = '$';
				} else if (flush_buf(st, outbuf, outbytesleft) == -1) {
					errno = st->_errno;
					return (size_t)-1;
				} else {
					st->_gstate = G0;
					st->_errno = 0;
					st->_istate = IN;
					continue;	/* don't advance inbuf */
				}
				break;
			case G2:		/* got $, expecting ) * or + */
				if (**inbuf == ')') {
					st->_gstate = G3;
				} else if (**inbuf == '*') {
					st->_gstate = G12;
					st->_plane = 2;
				} else if (**inbuf == '+') {
					st->_gstate = G19;
				} else if (flush_buf(st, outbuf, outbytesleft) == -1) {
					errno = st->_errno;
					return (size_t)-1;
				} else {
					st->_gstate = G0;
					st->_errno = 0;
					st->_istate = IN;
					continue;	/* don't advance inbuf */
				}
				st->_buf[st->_bufcont++] = **inbuf;
				break;
			case G3:	/* got ) expecting A,G,H */
						/* H is for the bug of and zh_TW.BIG5 */
				if (**inbuf == 'A') {
					st->_plane = 0;
					st->_gstate = G4;
				} else if (**inbuf == 'G') {
					st->_plane = 1;
					st->_gstate = G8;
				} else if (**inbuf == 'H') {
					st->_plane = 2;
					st->_gstate = G8;
				} else if (flush_buf(st, outbuf, outbytesleft) == -1) {
					errno = st->_errno;
					return (size_t)-1;
				} else {
					st->_gstate = G0;
					st->_errno = 0;
					st->_istate = IN;
					continue;
				}
				st->_buf[st->_bufcont++] = **inbuf;
				break;
		case G4:	/* ESC $ ) A got, and SO is expected */
				if (**inbuf == SO) {
					st->_gstate = G5;
					st->_istate = OUT;
					st->_bufcont = 0;
					st->_last_plane = st->_plane;
				} else if (flush_buf(st, outbuf, outbytesleft) == -1) {
					errno = st->_errno;
					return (size_t)-1;
				} else {
					st->_gstate = G0;
					st->_errno = 0;
					st->_istate = IN;
					st->_plane = st->_last_plane;
					continue;
				}
				break;
		case G5:	/* SO (Shift Out) */
				if (**inbuf == SI) {
					st->_istate = IN;
				st->_gstate = G7;
					st->_last_plane = st->_plane;
				} else if (**inbuf == ESC) {
					st->_bufcont = 0;
					st->_gstate = G0;
					continue;
				} else {	/* Chinese Charactors */
					st->_keepc[0] = **inbuf;
					st->_gstate = G6;
				}
				break;
		case G6:	/* GB2312: 2nd Chinese character */
				st->_keepc[1] = **inbuf;
				n = iso_gb_to_gb(st, *outbuf, *outbytesleft);
				if (n > 0) {
					(*outbuf) += n;
					(*outbytesleft) -= n;
				} else {
					errno = st->_errno;
					return (size_t)-1;
				}
				st->_gstate = G5;
				break;
			case G7:	/* Shift in */
				if (**inbuf == SO) {
					st->_gstate = G5;
					st->_istate = OUT;
					st->_last_plane = st->_plane;
					st->_bufcont = 0;
				} else if (**inbuf == ESC) {
					st->_gstate = G0;
					continue;
				} else {
					**outbuf = **inbuf;
					(*outbuf)++;
					(*outbytesleft) --;
				}
				break;
		case G8:	/* BIG5: Chinese character */
				if (**inbuf == SO) {
					st->_istate = OUT;
					st->_gstate = G9;
					st->_bufcont = 0;
					st->_last_plane = st->_plane;
				} else if (flush_buf(st, outbuf, outbytesleft) == -1) {
					errno = st->_errno;
					return (size_t)-1;
				} else {
					st->_gstate = G0;
					st->_errno = 0;
					st->_plane = st->_last_plane;
					st->_istate = IN;
					continue;
				}
				break;
		case G9:
				if (**inbuf == SI) {
					st->_istate = IN;
					st->_gstate = G11;
					st->_last_plane = st->_plane;
				} else if (**inbuf == ESC) {
					if (flush_buf(st, outbuf, outbytesleft) == -1) {
						errno = st->_errno;
						return (size_t)-1;
					}
					st->_gstate = G0;
					continue;
				} else {	/* Chinese Charactor */
					st->_keepc[0] = **inbuf;
					st->_gstate = G10;
				}
				break;
			case G10:
				st->_keepc[1] = **inbuf;
				n = iso_to_big5_to_gb(st, *outbuf, *outbytesleft);
				if (n > 0) {
					(*outbuf) += n;
					(*outbytesleft) -= n;
				} else {
					errno = st->_errno;
					return (size_t)-1;
				}
				st->_gstate = G9;
				break;
			case G11:
				st->_bufcont = 0;
				if (**inbuf == SO) {
					st->_istate = OUT;
					st->_gstate = G9;
				} else if (**inbuf == ESC) {
					st->_gstate = G0;
					continue;
				} else {
					**outbuf = **inbuf;
					(*outbuf)++;
					(*outbytesleft)--;
				}
				break;
			case G12:
				if (**inbuf == 'H') {
					st->_buf[st->_bufcont++] = 'H';
					st->_gstate = G13;
				} else if (flush_buf(st, outbuf, outbytesleft) == -1) {
					errno = st->_errno;
					return (size_t)-1;
				} else {
					st->_istate = IN;
					st->_plane = st->_last_plane;
					st->_gstate = G0;
					continue;
				}
				break;
			case G13:
				if (**inbuf == ESC) {
					st->_buf[st->_bufcont++] = **inbuf;
					st->_gstate = G14;
				} else if (flush_buf(st, outbuf, outbytesleft) == -1) {
					errno = st->_errno;
					return (size_t)-1;
				} else {
					st->_gstate = G0;
					st->_istate = IN;
					st->_plane = st->_last_plane;
					continue;
				}
				break;
			case G14:
				if (**inbuf == SS2) {
					st->_istate = OUT;
					st->_gstate = G15;
					st->_bufcont = 0;
					st->_last_plane = st->_plane = 2;
				} else if (**inbuf == '$') {
					st->_bufcont --;
					if (flush_buf(st, outbuf, outbytesleft) == -1) {
						errno = st->_errno;
						return (size_t)-1;
					} else {
						st->_gstate = G1;
						st->_plane = st->_last_plane;
						st->_istate = IN;
						continue;
					}
				} else if (flush_buf(st, outbuf, outbytesleft) == -1) {
					errno = st->_errno;
					return (size_t)-1;
				} else {
					st->_gstate = G0;
					st->_istate = IN;
					st->_plane = st->_last_plane;
					continue;
				}
				break;
			case G15:
				if (**inbuf == SI) {
					st->_gstate = G16;
					st->_istate = IN;
					st->_last_plane = st->_plane;
				} else if (**inbuf == ESC) {
					st->_bufcont = 0;
					st->_gstate = G0;
					continue;
				} else {
					st->_keepc[0] = **inbuf;
					st->_gstate = G18;
				}
				break;
			case G16:
				if (**inbuf == ESC) {
					st->_gstate = G17;
					st->_buf[st->_bufcont++] = ESC;
				} else {
					**outbuf = **inbuf;
					(*outbuf) ++;
					(*outbytesleft) --;
					st->_bufcont = 0;
				}
				break;
			case G17:
				if (**inbuf == '$') {
					st->_gstate = G1;
					st->_buf[st->_bufcont++] = '$';
					continue;
				} else if (**inbuf == SS2) {
					st->_bufcont = 0;
					st->_gstate = G15;
					st->_istate = OUT;
				} else if (flush_buf(st, outbuf, outbytesleft) == -1) {
					errno = st->_errno;
					return (size_t)-1;
				} else {
					st->_gstate = G16;
					st->_istate = IN;
				}
				break;
			case G18:
				st->_keepc[1] = **inbuf;
				st->_gstate = G0;
				if ((n = iso_to_big5_to_gb(st, \
											*outbuf, \
											*outbytesleft)) > 0) {
					(*outbuf)+=n;
					(*outbytesleft)-=n;
				} else {
					errno = st->_errno;
					return (size_t)-1;
				}
				break;
			case G19:	/* Plane #: 3 - 16 */
				c = **inbuf;
				if				(c == 'I' || \
								c == 'J' || \
								c == 'K' || \
								c == 'L' || \
								c == 'M' || \
								c == 'N' || \
								c == 'O' || \
								c == 'P' || \
								c == 'Q' || \
								c == 'R' || \
								c == 'S' || \
								c == 'T' || \
								c == 'U' || \
								c == 'V') {
					st->_plane = c - 'I' + 3;
					st->_gstate = G20;
				} else if (flush_buf(st, outbuf, outbytesleft) == -1) {
					errno = st->_errno;
					return (size_t)-1;
				} else {
					st->_gstate = G0;
					st->_errno = 0;
					st->_istate = IN;
					st->_plane = st->_last_plane;
					continue;
				}
				st->_buf[st->_bufcont++] = c;
				break;
			case G20:
				if (**inbuf == ESC) {
					st->_buf[st->_bufcont++] = **inbuf;
					st->_gstate = G21;
				} else if (flush_buf(st, outbuf, outbytesleft) == -1) {
					errno = st->_errno;
					return (size_t)-1;
				} else {
					st->_gstate = G0;
					st->_istate = IN;
					st->_last_plane = st->_plane;
					continue;
				}
				break;
			case G21:
				if (**inbuf == SS3) {
					st->_istate = OUT;
					st->_gstate = G22;
					st->_bufcont = 0;
				} else if (**inbuf == '$') {
					st->_bufcont --;
					if (flush_buf(st, outbuf, outbytesleft) == -1) {
						errno = st->_errno;
						return (size_t)-1;
					} else {
						st->_istate = IN;
						st->_last_plane = st->_plane;
						st->_gstate = G1;
						continue;
					}
				} else if (flush_buf(st, outbuf, outbytesleft) == -1) {
					errno = st->_errno;
					return (size_t)-1;
				} else {
					st->_gstate = G0;
					st->_istate = IN;
					st->_last_plane = st->_plane;
					continue;
				}
				break;
			case G22:
				if (**inbuf == SI) {
					st->_istate = IN;
					st->_gstate = G24;
					st->_last_plane = st->_plane;
				} else {
					st->_keepc[0] = (char)MBYTE;
					st->_keepc[1] = (char)(PMASK + st->_plane);
					st->_keepc[2] = **inbuf;
					st->_gstate = G23;
				}
				break;
			case G23:
				st->_keepc[3] = **inbuf;
				if ((n = iso_to_big5_to_gb(st, \
											*outbuf, \
											*outbytesleft)) > 0) {
					(*outbuf)+=n;
					(*outbytesleft-=n);
				} else {
					st->_errno = errno;
					return (size_t)-1;
				}
				st->_gstate = G22;
				break;
			case G24:
				if (**inbuf == ESC) {
					st->_gstate = G25;
					st->_buf[st->_bufcont++] = ESC;
				} else {
					**outbuf = **inbuf;
					(*outbuf)++;
					(*outbytesleft)--;
					st->_bufcont = 0;
				}
				break;
			case G25:
				if (**inbuf == '$') {
					st->_gstate = G1;
					continue;
				} else if (**inbuf == SS3) {
					st->_gstate = G22;
					st->_bufcont = 0;
					st->_istate = OUT;
				} else if (flush_buf(st, outbuf, outbytesleft) == -1) {
					errno = st->_errno;
					return (size_t)-1;
				} else {
					st->_gstate = G24;
					st->_istate = IN;
				}
				break;
			default:			/* should never come here */
				st->_errno = errno = EILSEQ;
				st->_gstate = G0;	/* reset state */
				break;
		}	/* end of switch */

		(*inbuf)++;
		(*inbytesleft)--;

		if (st->_errno) {
			break;
		}
		if (errno)
			return(-1);
	}

	if (*inbytesleft > 0 && *outbytesleft == 0) {
		errno = E2BIG;
		return((size_t)(-1));
	}
	return ((size_t)(*inbytesleft));
}

int iso_gb_to_gb(_iconv_st * st, char* buf, size_t buflen) {
	if ( buflen < 2 ) {
		st->_errno = E2BIG;
	    return -1;
	}
	*buf = st->_keepc[0] | MSB;
	*(buf+1) = st->_keepc[1] | MSB;
	return 2;
}

/*
 * ISO 2022-7 code --> Big-5 code
 * Return: > 0 - converted with enough space in output buffer
 *         = 0 - no space in outbuf
 */
int iso_to_big5_to_gb(_iconv_st * st, char* buf, size_t buflen) {
	char		cns_str[3], c1, c2;
	unsigned long	cns_val;	/* MSB mask off CNS 11643 value */
	int		unidx;		/* binary search index */
	unsigned long	big5_val, val;	/* Big-5 code */
	int idx;

	if (st->_plane == 1) {
		cns_str[0] = st->_keepc[0] & MSB_OFF;
		cns_str[1] = st->_keepc[1] & MSB_OFF;
	} else {
		cns_str[0] = st->_keepc[0] & MSB_OFF;
		cns_str[1] = st->_keepc[1] & MSB_OFF;
	}
	cns_val = (cns_str[0] << 8) + cns_str[1];

	if (buflen < 2) {
		errno = E2BIG;
		return(0);
	}

	switch (st->_plane) {
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


	if (unidx < 0) {	/* no match from CNS to Big-5 */
		*buf     = NON_ID_CHAR_BYTE1;
		*(buf+1) = NON_ID_CHAR_BYTE2;
	} else {
		val = big5_val & 0xffff;
		*buf = c1 = (char) ((val & 0xff00) >> 8);
		*(buf+1) = c2 = (char) (val & 0xff);
	}


	if (unidx < 0) {
		return 2;
	} else {
		idx = binsearch_big5_gb((((*buf) & ONEBYTE) << 8) | ((*(buf+1)) & ONEBYTE));
		if (idx < 0) {
			*buf     = NON_ID_CHAR_BYTE1;
			*(buf+1) = NON_ID_CHAR_BYTE2;
		} else {
			*buf     = (big5_gb_tab[idx].value >> 8) & ONEBYTE;
			*(buf+1) = big5_gb_tab[idx].value & ONEBYTE;
		}
	}

	return(2);
}

/* binsearch: find x in v[0] <= v[1] <= ... <= v[n-1] */
int binsearch(unsigned long x, table_t v[], int n)
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

int binsearch_big5_gb(unsigned int big5code)
{
	int low, high, mid;

	low = 0;
	high = BIG5MAX - 1;
	while (low <= high) {
		mid = (low + high) / 2;
		if (big5code < big5_gb_tab[mid].key)
			high = mid - 1;
		else if (big5code > big5_gb_tab[mid].key)
			low = mid + 1;
		else	/* found match */
			return mid;
	}
	return (-1);	/* no match */
}

int
iso_to_gb(char in_byte1, char in_byte2, char *buf, int buflen)
{
	if ( buflen < 2 )
	    return 0;
	*buf = in_byte1 | MSB;
	*(buf+1) = in_byte2 | MSB;
	return 2;
}


/*
 * ==================================================================
 * enconv functions
 * ==================================================================
 */

typedef struct _enconv_st {
	char	_lastc;
	short	_gstate;
} _enconv_st;

/*
 * Open; called from enconv_open()
 */
void *
_cv_open()
{
	_enconv_st *st;

	if ((st = (_enconv_st *)malloc(sizeof(_enconv_st))) == NULL) {
		return ((void *) -1);
	}

	st->_gstate = G0;
	return ((void *)st);
}


/*
 * Close; called from enconv_close()
 */
void
_cv_close(_enconv_st *st)
{
	if (st != NULL)
		free(st);
}


/*
 * Actual conversion; called from enconv()
 */
/*=======================================================================
 *
 *         ESC        $       )        A        SO        1st C
 * +-> G0 -----> G1 ----> G2 ----> G3 ----> G4 -----> G5 ---------> G6
 * |   | ascii   | ascii  | ascii  |   |ascii|     SI | |     2nd C |
 * +-------------------------------+   +-<---+--------+ +-<---------+
 *=======================================================================*/
size_t
_cv_enconv(_enconv_st *st, char **inbuf, size_t*inbytesleft,
			char **outbuf, size_t*outbytesleft)
{
	int	n;

	if (st == NULL) {
		return -1;
	}
	if (inbuf == NULL || *inbuf == NULL) { /* Reset request */
		st->_gstate = G0;
		return 0;
	}

	while (*inbytesleft > 0 && *outbytesleft > 0) {
	    switch (st->_gstate) {
	    case G0:
		if ( **inbuf == ESC ) {
		    st->_gstate = G1;
		} else {		/* ASCII */
		    **outbuf = **inbuf;
		    (*outbuf)++, (*outbytesleft)--;
		}
		break;
	    case G1:
		if ( **inbuf == '$' ) {
		    st->_gstate = G2;
		} else {
		    **outbuf = ESC;
		    (*outbuf)++, (*outbytesleft)--;
		    st->_gstate = G0;
		    continue;
		}
		break;
	    case G2:
		if ( **inbuf == ')' ) {
		    st->_gstate = G3;
		} else {
		    if (*outbytesleft < 2) {
			return (*inbytesleft);
		    }
		    **outbuf = ESC;
		    *(*outbuf+1) = '$';
		    (*outbuf) += 2, (*outbytesleft) -= 2;
		    st->_gstate = G0;
		    continue;
		}
		break;
	    case G3:
		if ( **inbuf == 'A' ) {
		    st->_gstate = G4;
		} else {
		    if (*outbytesleft < 3) {
			return (*inbytesleft);
		    }
		    **outbuf = ESC;
		    *(*outbuf+1) = '$';
		    *(*outbuf+2) = ')';
		    (*outbuf) += 3, (*outbytesleft) -= 3;
		    st->_gstate = G0;
		    continue;
		}
		break;
	    case G4:
		if ( **inbuf == SO ) {
		    st->_gstate = G5;
		} else {
		    **outbuf = **inbuf;
		    (*outbuf)++, (*outbytesleft)--;
		}
		break;
	    case G5:
		if ( **inbuf == SI ) {
		    st->_gstate = G4;
		} else {
		    st->_lastc = **inbuf;
		    st->_gstate = G6;
		}
		break;
	    case G6:
		n = iso_to_gb(st->_lastc, **inbuf, *outbuf, *outbytesleft);
		if (n > 0) {
		    (*outbuf) += n, (*outbytesleft) -= n;
		} else {
		    return (*inbytesleft);
		}
		st->_gstate = G5;
		break;
	    }

	    (*inbuf)++, (*inbytesleft)--;
	}

	return (*inbytesleft);
}

#ifdef DEBUG
main(int argc, char ** argv) {
	char *inbuf, *outbuf, *in_tmp, *out_tmp;
	size_t inbytesleft, outbytesleft;
	int fd;
	int i;
	struct stat s;
	_iconv_st * st;
	if (argc < 2) {
		fprintf(stderr, "Usage: %s input\n", argv[0]);
		exit(-1);
	}
	if ((fd = open(argv[1], O_RDONLY)) == -1) {
		perror("open");
		exit(-2);
	}
	if (fstat(fd, &s) == -1) {
		perror("stat");
		exit(-3);
	}
	inbytesleft = outbytesleft = s.st_size;
	in_tmp = inbuf = (char *)malloc(inbytesleft);
	out_tmp = outbuf = (char *)malloc(outbytesleft);
	if (!inbuf || !outbuf) {
		perror("malloc");
		exit(-1);
	}
	if (read(fd, inbuf, inbytesleft) != inbytesleft) {
		perror("read");
		exit(-4);
	}
	for (i = 0; i < inbytesleft; i++)
		fprintf(stderr, "%x\t", *(inbuf+i));
	fprintf(stderr, "\n");
	st = (_iconv_st *)_icv_open();
	if (st == (_iconv_st *) -1) {
		perror("_icv_open");
		exit(-1);
	}
	if (_icv_iconv(st, \
				&inbuf, &inbytesleft, \
				&outbuf, &outbytesleft) == -1) {
		perror("icv_iconv");
		fprintf(stderr, "\ninbytesleft = %d\n", inbytesleft);
		exit(-2);
	}
	if (write(1, out_tmp, s.st_size - outbytesleft) == -1) {
		perror("write");
		exit(-1);
	}
	free(in_tmp);
	free(out_tmp);
	close(fd);
	_icv_close(st);
}
#endif
