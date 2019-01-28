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
#include <libintl.h>

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
	int	_errno;		/* internal errno */
} _iconv_st;

enum _CSTATE	{ C0, C1, C2, C3, C4 };
enum _ISTATE    { IN, OUT };


static int get_plane_no_by_char(const char);
static int cns_to_iso(int, char[], char*, size_t);

static int get_plane_no_by_str(const char *);
struct _cv_state {
	int	plane_no;
	int	get_a_mbchar;
	int	more_bytes;
	int	first_byte;
	int	plane_changed;
	char	planec;
	char	*p;
	char	keepc[4];
};

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
    fprintf(stderr, "==========     iconv(): CNS11643 --> ISO 2022-7     ==========\n");
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
size_t
_icv_iconv(_iconv_st *st, char **inbuf, size_t *inbytesleft,
				char **outbuf, size_t *outbytesleft)
{
	int plane_no = -1, n;
	/* pre_plane_no: need to be static when re-entry occurs on errno set */
	static int	pre_plane_no = -1;	/* previous plane number */

	if (st == NULL) {
		errno = EBADF;
		return ((size_t) -1);
	}

	if (inbuf == NULL || *inbuf == NULL) { /* Reset request. */
		if (st->cstate == C1) {
			if (outbytesleft && *outbytesleft >= 1
				&& outbuf && *outbuf) {
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
		return ((size_t) 0);
	}

#ifdef DEBUG
    fprintf(stderr, "=== (Re-entry)     iconv(): CNS11643 --> ISO 2022-7     ===\n");
    fprintf(stderr, "st->cstate=%d\tst->istate=%d\tst->_errno=%d\tplane_no=%d\n",
	st->cstate, st->istate, st->_errno, plane_no);
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
			if ((st->keepc[0] & ONEBYTE) == MBYTE) { /* 4-byte (0x8e) */
				plane_no = get_plane_no_by_char(**inbuf);
				if (plane_no == -1) {	/* illegal plane */
					st->cstate = C0;
					st->istate = IN;
					st->_errno = errno = EILSEQ;
				} else {	/* 4-byte Chinese character */
					st->keepc[1] = (**inbuf);
					st->cstate = C2;
				}
			} else {	/* 2-byte Chinese character - plane #1 */
				if (**inbuf & MSB) {	/* plane #1 */
					st->cstate = C4;
					st->keepc[1] = (**inbuf);
					st->keepc[2] = st->keepc[3] = '\0';
					plane_no = 1;
					continue;       /* should not advance *inbuf */
				} else {	/* input char doesn't belong
						 * to the input code set
						 */
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
		case C4:	/* Convert code from CNS 11643 to ISO 2022-7 */
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
fprintf(stderr, "ESC $ ) %c\n", *(*outbuf+3));
#endif
				(*outbuf) += 4;
				(*outbytesleft) -= 4;
				if (*outbytesleft <= 0) {
					st->_errno = errno = E2BIG;
					return((size_t)-1);
				}
				**outbuf = SO;
				(*outbuf)++;
				(*outbytesleft)--;
			}
			n = cns_to_iso(plane_no, st->keepc, *outbuf, *outbytesleft);
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
 * CNS 11643 code --> ISO 2022-7
 * Return: > 0 - converted with enough space in output buffer
 *         = 0 - no space in outbuf
 */
static int cns_to_iso(int plane_no, char keepc[], char *buf, size_t buflen)
{
	char		cns_str[3];
	unsigned long	cns_val;	/* MSB mask off CNS 11643 value */

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

	*buf = (cns_val & 0xff00) >> 8;
	*(buf+1) = cns_val & 0xff;

#ifdef DEBUG
    fprintf(stderr, "->%x %x<-\t->%c %c<-\n", *buf, *(buf+1), *buf, *(buf+1));
#endif
	return(2);
}
void *
_cv_open()
{
	struct _cv_state *st;

	if ((st = (struct _cv_state *)malloc(sizeof(struct _cv_state))) == NULL)
		return ((void *)-1);

	st->plane_no = 0;
	st->get_a_mbchar = 1;
	st->first_byte = 1;

	return (st);
}

void
_cv_close(struct _cv_state *st)
{
	free(st);
}


size_t
_cv_enconv(struct _cv_state *st, char **cvinbuf, size_t *cvinbytesleft,
				char **cvoutbuf, size_t *cvoutbytesleft)
{
	char	*inbuf;
	char	*outbuf;
	size_t insize;
	size_t outsize;

	unsigned char	uc;
	int		i;

	if (cvinbuf == NULL || *cvinbuf == NULL) { /* Reset request. */
		if (cvoutbuf && *cvoutbuf != NULL &&
		*cvoutbytesleft > 0 && st->plane_no != 0) {
			**cvoutbuf = SI;
			(*cvoutbytesleft)--;
			(*cvoutbuf)++;
		}
		st->plane_no = 0;
		st->get_a_mbchar = 1;
		st->first_byte = 1;

		return (0);
	}


	inbuf = *cvinbuf;
	outbuf = *cvoutbuf;
	insize = *cvinbytesleft;
	outsize = *cvoutbytesleft;

	while ((int) insize > 0 && (int) outsize > 0) {

		if (st->get_a_mbchar) {
			if (st->plane_no == 0) { /* short cut */
				do {
					uc = *inbuf;
					if ((uc & MSB) == 0) {
						*outbuf++ = uc;
						outsize--;
						inbuf++;
						insize--;
					} else
						goto non_plane_0;
				} while ((int) insize > 0 && (int) outsize > 0);
				goto success;
			}

non_plane_0:
			if (st->first_byte) {
				st->first_byte = 0;
				st->keepc[0] = uc = *inbuf++;
				insize--;
				if (uc & MSB) {
					if (uc == 0x8e)
						st->more_bytes = 3;
					else
						st->more_bytes = 1;
					st->p = st->keepc + 1;
				} else
					st->more_bytes = 0;
			}
			while (st->more_bytes > 0 && (int) insize > 0) {
				*st->p++ = *inbuf++;
				st->more_bytes--;
				insize--;
			}
			if (st->more_bytes == 0)
				st->get_a_mbchar = 0;

		/* up to this point, st->keepc contains a complete mb char */

			i = get_plane_no_by_str(st->keepc);
			st->plane_changed = (st->plane_no != i);
			if (st->plane_changed) { /* generate SI */
				st->planec = GET_PLANEC(i);
				if (st->plane_no != 0) {
					*outbuf++ = SI;
					outsize--;
					st->plane_no = i;
					if ((int) outsize <= 0)
						goto success;
				} else
					st->plane_no = i;
			}
		}

		/*
		 * up to this point, st->keepc contains a complete mb char and
		 * we know the plane_no
		 */

		switch (st->plane_no) {
		case 0:
			*outbuf++ = st->keepc[0];
			outsize--;
			break;
		case 1:
			if (st->plane_changed) {
				if (outsize < 7)
					goto success;
				*outbuf++ = ESC;
				*outbuf++ = '$';
				*outbuf++ = ')';
				*outbuf++ = 'G';
				*outbuf++ = SO;
				*outbuf++ = st->keepc[0] & MSB_OFF;
				*outbuf++ = st->keepc[1] & MSB_OFF;
				outsize -= 7;
			} else { /* don't need the escape sequence */
				if (outsize < 2)
					goto success;
				*outbuf++ = st->keepc[0] & MSB_OFF;
				*outbuf++ = st->keepc[1] & MSB_OFF;
				outsize -= 2;
			}
			break;
		default:
			if (st->plane_changed) {
				if (outsize < 7)
					goto success;
				*outbuf++ = ESC;
				*outbuf++ = '$';
				*outbuf++ = ')';
				*outbuf++ = st->planec;
				*outbuf++ = SO;
				*outbuf++ = st->keepc[2] & MSB_OFF;
				*outbuf++ = st->keepc[3] & MSB_OFF;
				outsize -= 7;
			} else { /* don't need the escape sequence */
				if (outsize < 2)
					goto success;
				*outbuf++ = st->keepc[2] & MSB_OFF;
				*outbuf++ = st->keepc[3] & MSB_OFF;
				outsize -= 2;
			}
			break;
		}
		/*
		 * up to this point, a complete multibyte character has been
		 * converted and written to outbuf, so need to grab the next
		 * mb char from inbuf
		 */
		st->get_a_mbchar = 1;
		st->first_byte = 1;
	}

success:
	*cvinbytesleft = insize;
	*cvoutbytesleft = outsize;
	*cvinbuf = inbuf;
	*cvoutbuf = outbuf;

	return (insize);
}

static int get_plane_no_by_str(const char *inbuf) {
	unsigned char uc = (unsigned char) *inbuf;

	if (uc & MSB) {
		if (uc != 0x8e)
			return (1);
		uc = *(++inbuf);
		return (uc - 0xa0);
	} else
		return (0);
}
