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

#define	MSB	0x80	/* most significant bit */
#define	MBYTE	0x8e	/* multi-byte (4 byte character) */
#define	PMASK	0xa0	/* plane number mask */
#define ONEBYTE	0xff	/* right most byte */
#define MSB_OFF	0x7f	/* mask off MSB */

#define SI      0x0f    /* shift in */
#define SO      0x0e    /* shift out */
#define ESC     0x1b    /* escape */

/* static const char plane_char[] = "0GH23456789:;<=>?"; */
static const char plane_char[] = "0GHIJKLMNOPQRSTUV";

#define GET_PLANEC(i)   (plane_char[i])

#define NON_ID_CHAR '_'	/* non-identified character */

typedef struct _icv_state {
	char	keepc[4];	/* maximum # byte of CNS11643 code */
	short	cstate;		/* state machine id (CNS) */
	short	istate;		/* state machine id (ISO) */
	short	plane_no;	/* plane no */
	short	SOset;		/* So is set */
	short	SS2set;		/* SS2 is set */
	char	SS3char;	/* SS3 char. */
	int	_errno;		/* internal errno */
} _iconv_st;

enum _CSTATE	{ C0, C1, C2, C3, C4 };
enum _ISTATE    { IN, OUT };
enum _truefalse	{ False, True };


static int get_plane_no_by_char(const char);

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
	st->plane_no = -1;
	st->SOset = False;
	st->SS2set = False;
	st->SS3char = '0';

#ifdef DEBUG
    fprintf(stderr, "==========     iconv(): CNS11643 --> ISO 2022-CN     ==========\n");
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
 *               (ESC,SO)   plane 2 - 16
 *                1st C         2nd C       3rd C
 *    +------> C0 -----> C1 -----------> C2 -----> C3
 *    |  ascii |  plane 1 |                   4th C |
 *    ^        |  2nd C   v                         v
 *    |        |         C4 <------<--------<-------+
 *    |        v          | (SI)
 *    +----<---+-----<----v
 *
 *=======================================================*/
#define LEFT_CHECK(i)		if (*outbytesleft < i) {\
				    st->_errno = errno = E2BIG;\
				    return((size_t)-1);\
				} else\
				    (*outbytesleft) -= i
#define BUF_INPUT(c1, c2, c3, c4)\
				*(*outbuf)++ = c1;\
				*(*outbuf)++ = c2;\
				*(*outbuf)++ = c3;\
				*(*outbuf)++ = c4
size_t
_icv_iconv(_iconv_st *st, char **inbuf, size_t *inbytesleft,
				char **outbuf, size_t *outbytesleft)
{
	if (st == NULL) {
	    errno = EBADF;
	    return ((size_t) -1);
	}

	if (inbuf == NULL || *inbuf == NULL) { /* Reset request. */
	    if (st->istate == OUT) {
		if (outbytesleft && *outbytesleft >= 1 && outbuf && *outbuf) {
		    **outbuf = SI;
		    (*outbuf)++;
		    (*outbytesleft)--;
		} else {
		    errno = E2BIG;
		    return((size_t) -1);
		}
	    }
	    st->cstate = C0;
	    st->istate = IN;
	    st->_errno = 0;
	    st->plane_no = -1;
	    st->SOset = False;
	    st->SS2set = False;
	    st->SS3char = '0';
	    return ((size_t) 0);
	}

#ifdef DEBUG
    fprintf(stderr, "=== (Re-entry)     iconv(): CNS11643 --> ISO 2022-CN     ===\n");
    fprintf(stderr, "st->cstate=%d\tst->istate=%d\tst->_errno=%d\tplane_no=%d\n",
	st->cstate, st->istate, st->_errno, st->plane_no);
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
		    if (st->istate == OUT) {
			st->istate = IN;
			*(*outbuf)++ = SI;
			(*outbytesleft)--;
			if (*outbytesleft <= 0) {
			    errno = E2BIG;
			    return ((size_t) -1);
			}
		    }
		    *(*outbuf)++ = **inbuf;
		    (*outbytesleft)--;
		    if (**inbuf == '\n') {
			st->SOset = False;
			st->SS2set = False;
			st->SS3char = '0';
		    }
		}
		break;
	    case C1:		/* Chinese characters: 2nd byte */
		if ((st->keepc[0] & ONEBYTE) == MBYTE) { /* 4-byte (0x8e) */
		    st->plane_no = get_plane_no_by_char(**inbuf);
		    if (st->plane_no == -1) {	/* illegal plane */
			st->cstate = C0;
			st->istate = IN;
			st->_errno = errno = EILSEQ;
		    } else {	/* 4-byte Chinese character */
			st->cstate = C2;
			st->keepc[1] = (**inbuf);
		    }
		} else {	/* 2-byte Chinese character - plane #1 */
		    if (**inbuf & MSB) {	/* plane #1 */
			st->cstate = C4;
			st->keepc[1] = (**inbuf);
			st->plane_no = 1;
			continue;       /* should not advance *inbuf */
		    } else {	/* input char doesn't belong
				     * to the input code set */
			st->cstate = C0;
			st->istate = IN;
			st->_errno = errno = EINVAL;
		    }
		}
		break;
	    case C2:	/* plane #2 - #16 (4 bytes): get 3nd byte */
		if (**inbuf & MSB) {	/* 3rd byte */
		    st->keepc[2] = (**inbuf);
		    st->cstate = C3;
		} else {
		    st->_errno = errno = EINVAL;
		    st->cstate = C0;
		}
		break;
	    case C3:	/* plane #2 - #16 (4 bytes): get 4th byte */
		if (**inbuf & MSB) {	/* 4th byte */
		    st->cstate = C4;
		    st->keepc[3] = (**inbuf);
		    continue;       /* should not advance *inbuf */
		} else {
		    st->_errno = errno = EINVAL;
		    st->cstate = C0;
		}
		break;
	    case C4:	/* Convert code from CNS 11643 to ISO 2022-CN */
		if (st->plane_no == 1) {
		    if (st->istate == IN) {
			if (st->SOset == False) {
			    LEFT_CHECK(4);
			    BUF_INPUT(ESC, '$', ')', 'G');
			    st->SOset = True;
			}
			LEFT_CHECK(1);
			*(*outbuf)++ = SO;
			st->istate = OUT;
		    }
		    LEFT_CHECK(2);
		    *(*outbuf)++ = st->keepc[0] & MSB_OFF;
		    *(*outbuf)++ = st->keepc[1] & MSB_OFF;

		} else if (st->plane_no == 2) {
		    if (st->SS2set == False) {
		        LEFT_CHECK(4);
			BUF_INPUT(ESC, '$', '*', 'H');
			st->SS2set = True;
		    }
		    LEFT_CHECK(4);
		    BUF_INPUT(ESC, 0x4E, st->keepc[2] & MSB_OFF, st->keepc[3] & MSB_OFF);
		} else {
		    if (st->SS3char != GET_PLANEC(st->plane_no)) {
			LEFT_CHECK(4);
			st->SS3char = GET_PLANEC(st->plane_no);
			BUF_INPUT(ESC, '$', '+', st->SS3char);
		    }
		    LEFT_CHECK(4);
		    BUF_INPUT(ESC, 0x4F, st->keepc[2] & MSB_OFF, st->keepc[3] & MSB_OFF);
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
	    if (errno) {
		return((size_t)-1);
	    }

	}

	if (*inbytesleft > 0 && *outbytesleft == 0) {
	    errno = E2BIG;
	    return ((size_t)-1);
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
