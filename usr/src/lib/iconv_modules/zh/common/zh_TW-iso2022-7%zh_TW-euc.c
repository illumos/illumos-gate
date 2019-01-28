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
static int iso_to_cns(int, char[], char*, size_t);

#define	LSG2 0x4e
#define	LSG3 0x4f


typedef struct IOBuf {
	char *	myin;
	char *	myout;
	size_t	insize;
	size_t	outsize;

	char	mybuf[8];
	int	bufc;
} IOBuf;

typedef struct Conversion {
	int	myplane;
} Conversion;

typedef struct GxCntl {

	int	gxplane[4];
	char	gxc;

	int	mygx;
	int	inHLE1xConv;
	int	inHLE1xSO;
	Conversion *convobj;

} GxCntl;


typedef struct TWNiconv {
	GxCntl		*cntl;
	Conversion	*conv;
	IOBuf		*iobuf;

} TWNiconv;

struct _cv_state {
	TWNiconv * iconvobj;
};

extern	TWNiconv * aTWNiconv();
extern	void	adeTWNiconv(TWNiconv *);
extern	size_t	aisotoeuc(TWNiconv *, char **, size_t *, char **, size_t *);
extern	void	areset(TWNiconv *);

extern	Conversion * zConversion();
extern	void	zdeConversion(Conversion *);
extern	void	zsetplane(Conversion *, int);
extern	int	zconversion(Conversion *, IOBuf *);

extern	GxCntl * yGxCntl(Conversion *);
extern	void	ydeGxCntl(GxCntl *);
extern	int	ygetplaneno(GxCntl *, char c);
extern	int	yescSeq(GxCntl *, IOBuf *);

extern	IOBuf *	xIOBuf();
extern	void	xdeIOBuf(IOBuf *);
extern	int	xgetc(IOBuf *);
extern	void	xbackup(IOBuf *, int);
extern	int	xputc(IOBuf *, int);
extern	int	xoutsize(IOBuf *);


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
    fprintf(stderr, "==========    iconv(): ISO2022-7 --> CNS 11643    ==========\n");
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
    fprintf(stderr, "=== (Re-entry)   iconv(): ISO 2022-7 --> CNS 11643   ===\n");
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
			if ((**inbuf == ')') || (**inbuf == '*')) {
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
			st->keepc[2] = st->keepc[3] = '\0';
			n = iso_to_cns(1, st->keepc, *outbuf, *outbytesleft);
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
			n = iso_to_cns(st->plane_no, st->keepc, *outbuf,
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
 * ISO 2022-7 code --> CNS 11643-1992 (Chinese EUC)
 * Return: > 0 - converted with enough space in output buffer
 *         = 0 - no space in outbuf
 */
static int iso_to_cns(int plane_no, char keepc[], char *buf, size_t buflen)
{
	int             ret_size;       /* return buffer size */

#ifdef DEBUG
    fprintf(stderr, "%s %d ", keepc, plane_no);
#endif
	if (plane_no == 1)
		ret_size = 2;
	else
		ret_size = 4;

        if (buflen < ret_size) {
                errno = E2BIG;
                return(0);
        }

	switch (plane_no) {
	case 1:
		*buf = keepc[0];
		*(buf+1) = keepc[1];
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
		*buf = keepc[0];
		*(buf+1) = keepc[1];
		*(buf+2) = keepc[2];
		*(buf+3) = keepc[3];
		break;
	}

#ifdef DEBUG
    fprintf(stderr, "\t#%d ->%s<-\n", plane_no, keepc);
#endif

	return(ret_size);
}
void *
_cv_open(void)
{
	struct _cv_state *st;

	if ((st = (struct _cv_state *) malloc(sizeof (struct _cv_state))) ==
			NULL)
		return ((void *) -1);

	if ((st->iconvobj = aTWNiconv()) == NULL) {
		free(st);
		return ((void *) -1);
	}

	return ((void *) st);
}

void
_cv_close(struct _cv_state *st)
{
	adeTWNiconv(st->iconvobj);
	free(st);
}


size_t
_cv_enconv(struct _cv_state *st, char **cvinbuf, size_t *cvinbytesleft,
				char **cvoutbuf, size_t *cvoutbytesleft)
{
	if (cvinbuf == NULL || *cvinbuf == NULL) { /* Reset request. */
		/*
		 * Note that no shift sequence is needed for
		 * the target encoding.
		 */
		areset(st->iconvobj);
		return (0);
	}

	return (aisotoeuc(st->iconvobj, cvinbuf, cvinbytesleft,
			cvoutbuf, cvoutbytesleft));
}

TWNiconv * aTWNiconv() {
	TWNiconv *ret = (TWNiconv *) malloc(sizeof (TWNiconv));
	if (ret == NULL)
		return (NULL);
	if ((ret->conv = zConversion()) == NULL) {
		free(ret);
		return (NULL);
	}
	if ((ret->cntl = yGxCntl(ret->conv)) == NULL) {
		free(ret->conv);
		free(ret);
		return (NULL);
	}
	if ((ret->iobuf = xIOBuf()) == NULL) {
		free(ret->cntl);
		free(ret->conv);
		free(ret);
		return (NULL);
	}
	return (ret);
}

size_t
aisotoeuc(TWNiconv *this, char **inbuf, size_t *inbufsize,
	char **outbuf, size_t *outbufsize) {

	this->iobuf->myin = *inbuf;
	this->iobuf->myout = *outbuf;
	this->iobuf->insize = *inbufsize;
	this->iobuf->outsize = *outbufsize;

	while (1) {
		int	ret;
		if ((ret = yescSeq(this->cntl, this->iobuf)) == -1)
			break;
		else if (ret != 0)
			continue;

		if (zconversion(this->conv, this->iobuf) == -1)
			break;
	}

	*inbuf = this->iobuf->myin;
	*outbuf = this->iobuf->myout;
	*inbufsize = this->iobuf->insize;
	*outbufsize = this->iobuf->outsize;

	return (*inbufsize);
}

void
adeTWNiconv(TWNiconv *this) {
	zdeConversion(this->conv);
	ydeGxCntl(this->cntl);
	xdeIOBuf(this->iobuf);
	free(this);
}

void
areset(TWNiconv *this) {
	zdeConversion(this->conv);
	ydeGxCntl(this->cntl);
	xdeIOBuf(this->iobuf);
	this->conv = zConversion();
	this->cntl = yGxCntl(this->conv);
	this->iobuf = xIOBuf();
}

Conversion *
zConversion() {
	Conversion *ret = (Conversion *) malloc(sizeof (Conversion));
	if (ret == NULL)
		return (NULL);
	ret->myplane = 0;
	return (ret);
}

void
zdeConversion(Conversion *this) { free(this); }

void
zsetplane(Conversion *this, int i) { this->myplane = i; }

int
zconversion(Conversion *this, IOBuf *ioobj) {
	int c1, c2, c;

	switch (this->myplane) {

	case 0:
		if (xoutsize(ioobj) < 1)
			return (-1);

		if ((c = xgetc(ioobj)) == -1)
			return (-1);
		xputc(ioobj, c);
		return (0);
	case 1:
		if (xoutsize(ioobj) < 2)
			return (-1);

		if ((c1 = xgetc(ioobj)) == -1)
			return (-1);
		if ((c2 = xgetc(ioobj)) == -1) {
			xbackup(ioobj, c1);
			return (-1);
		}
		xputc(ioobj, c1 | MSB);
		xputc(ioobj, c2 | MSB);
		return (0);
	default: /* plane 2 to 15 */
		if (xoutsize(ioobj) < 4)
			return (-1);

		if ((c1 = xgetc(ioobj)) == -1)
			return (-1);
		if ((c2 = xgetc(ioobj)) == -1) {
			xbackup(ioobj, c1);
			return (-1);
		}
		xputc(ioobj, 0x8e);
		xputc(ioobj, 0xa0 + this->myplane);
		xputc(ioobj, c1 | MSB);
		xputc(ioobj, c2 | MSB);
		return (0);
	}
}

GxCntl *
yGxCntl(Conversion *obj) {
	GxCntl *ret = (GxCntl *) malloc(sizeof (GxCntl));
	if (ret == NULL)
		return (NULL);

	ret->convobj = obj;
	ret->gxplane[0] = ret->gxplane[1] = ret->gxplane[2] =
	ret->gxplane[3] = 0;
	ret->inHLE1xConv = 0;
	return (ret);
}

void
ydeGxCntl(GxCntl *this) {
	free(this);
}

int
yescSeq(GxCntl *this, IOBuf *obj) {
	int c = xgetc(obj);

	if (c == -1)
		return (-1);

	switch (c) {
	case ESC:
		break;
	case SI:
		zsetplane(this->convobj, this->gxplane[0]);
		if (this->inHLE1xConv == 1)
			this->inHLE1xSO = 0;
		return (1);
	case SO:
		if (this->inHLE1xConv == 1) {
			if  (this->inHLE1xSO != 0) {
				xbackup(obj, SO);
				return (0);
			} else
				this->inHLE1xSO = 1;

		}
		zsetplane(this->convobj, this->gxplane[1]);
		return (1);
	default:
		xbackup(obj, c);
		return (0);
	}

	if ((c = xgetc(obj)) == -1) {
		xbackup(obj, ESC);
		return (1);
	}

	switch (c) {

		case LSG2:
			zsetplane(this->convobj, this->gxplane[2]);
			return (1);
		case LSG3:
			zsetplane(this->convobj, this->gxplane[3]);
			return (1);
		case '$':
			break;
		case '(':
			if (xgetc(obj) != -1) {
				this->gxplane[0] = 0;
				break;
			}
			/* else fall through */
		default:
			xbackup(obj, c);
			xbackup(obj, ESC);
			return (0);
	}

	if ((this->gxc = xgetc(obj)) == -1) {
			xbackup(obj, '$');
			xbackup(obj, ESC);
			return (-1);
	}

	switch (this->gxc) {

		case '(':
			this->mygx = 0;
			break;
		case ')':
			this->mygx = 1;
			break;
		case '*':
			this->mygx = 2;
			break;
		case '+':
			this->mygx = 3;
			break;
		default:
			xbackup(obj, this->gxc);
			xbackup(obj, '$');
			xbackup(obj, ESC);
			return (0);
	}

	if ((c = xgetc(obj)) == -1) {
			xbackup(obj, this->gxc);
			xbackup(obj, '$');
			xbackup(obj, ESC);
			return (-1);
	}

	if (c == '0' && this->mygx == 1) { /* HLE 1.x */
		this->inHLE1xConv = 1;
		this->inHLE1xSO = 0;
		this->gxplane[1] = 1;
	} else {
		this->inHLE1xConv = 0;
		this->gxplane[this->mygx] = ygetplaneno(this, c);
	}
	return (1);
}

int
ygetplaneno(GxCntl *dummy, char c) {
	if (c == 'G')
		return (1);
	else if (c == 'H')
		return (2);
	else
		return (c - '0' + 1);
}

IOBuf *
xIOBuf() {
	IOBuf *ret = (IOBuf *) malloc(sizeof (IOBuf));
	if (ret == NULL)
		return (NULL);
	ret->bufc = 0;
	return (ret);
}

void
xdeIOBuf(IOBuf *this) {
	free(this);
}

int
xgetc(IOBuf *this) {
	if (this->bufc > 0)
		return (this->mybuf[--this->bufc]);

	if (this->insize == 0)
		return (-1);
	else {
		this->insize--;
		return (*this->myin++);
	}
}

int
xputc(IOBuf *this, int c) {
	if (this->outsize <= 0)
		return (-1);
	*(this->myout)++ = c;
	this->outsize--;
	return (0);
}

void
xbackup(IOBuf *this, int c) { this->mybuf[this->bufc++] = c; }

int
xoutsize(IOBuf *this) { return (this->outsize); }
