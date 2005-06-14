/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#ifndef _REGEXP_H
#define	_REGEXP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <ctype.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	CBRA	2
#define	CCHR	4
#define	CDOT	8
#define	CCL	12
#define	CXCL	16
#define	CDOL	20
#define	CCEOF	22
#define	CKET	24
#define	CBACK	36
#define	NCCL	40

#define	STAR	01
#define	RNGE	03

#define	NBRA	9

#define	PLACE(c)	ep[c >> 3] |= bittab[c & 07]
#define	ISTHERE(c)	(ep[c >> 3] & bittab[c & 07])
#define	ecmp(s1, s2, n)	(strncmp(s1, s2, n) == 0)

static char	*braslist[NBRA];
static char	*braelist[NBRA];
int	sed, nbra;
char	*loc1, *loc2, *locs;
static int	nodelim;

int	circf;
static int	low;
static int	size;

static char	bittab[] = { 1, 2, 4, 8, 16, 32, 64, 128 };

char *
compile(instring, ep, endbuf, seof)
char *ep;
char *instring, *endbuf;
{
	INIT	/* Dependent declarations and initializations */
	int c;
	int eof = seof;
	char *lastep = instring;
	int cclcnt;
	char bracket[NBRA], *bracketp;
	int closed;
	int neg;
	int lc;
	int i, cflg;
	int iflag; /* used for non-ascii characters in brackets */

	lastep = 0;
	if ((c = GETC()) == eof || c == '\n') {
		if (c == '\n') {
			UNGETC(c);
			nodelim = 1;
		}
		if (*ep == 0 && !sed)
			ERROR(41);
		RETURN(ep);
	}
	bracketp = bracket;
	circf = closed = nbra = 0;
	if (c == '^')
		circf++;
	else
		UNGETC(c);
	while (1) {
		if (ep >= endbuf)
			ERROR(50);
		c = GETC();
		if (c != '*' && ((c != '\\') || (PEEKC() != '{')))
			lastep = ep;
		if (c == eof) {
			*ep++ = CCEOF;
			if (bracketp != bracket)
				ERROR(42);
			RETURN(ep);
		}
		switch (c) {

		case '.':
			*ep++ = CDOT;
			continue;

		case '\n':
			if (!sed) {
				UNGETC(c);
				*ep++ = CCEOF;
				nodelim = 1;
				if (bracketp != bracket)
					ERROR(42);
				RETURN(ep);
			} else ERROR(36);
		case '*':
			if (lastep == 0 || *lastep == CBRA || *lastep == CKET)
				goto defchar;
			*lastep |= STAR;
			continue;

		case '$':
			if (PEEKC() != eof && PEEKC() != '\n')
				goto defchar;
			*ep++ = CDOL;
			continue;

		case '[':
			if (&ep[17] >= endbuf)
				ERROR(50);

			*ep++ = CCL;
			lc = 0;
			for (i = 0; i < 16; i++)
				ep[i] = 0;

			neg = 0;
			if ((c = GETC()) == '^') {
				neg = 1;
				c = GETC();
			}
			iflag = 1;
			do {
				c &= 0377;
				if (c == '\0' || c == '\n')
					ERROR(49);
				if ((c & 0200) && iflag) {
					iflag = 0;
					if (&ep[32] >= endbuf)
						ERROR(50);
					ep[-1] = CXCL;
					for (i = 16; i < 32; i++)
						ep[i] = 0;
				}
				if (c == '-' && lc != 0) {
					if ((c = GETC()) == ']') {
						PLACE('-');
						break;
					}
					if ((c & 0200) && iflag) {
						iflag = 0;
						if (&ep[32] >= endbuf)
							ERROR(50);
						ep[-1] = CXCL;
						for (i = 16; i < 32; i++)
							ep[i] = 0;
					}
					while (lc < c) {
						PLACE(lc);
						lc++;
					}
				}
				lc = c;
				PLACE(c);
			} while ((c = GETC()) != ']');

			if (iflag)
				iflag = 16;
			else
				iflag = 32;

			if (neg) {
				if (iflag == 32) {
					for (cclcnt = 0; cclcnt < iflag;
						cclcnt++)
						ep[cclcnt] ^= 0377;
					ep[0] &= 0376;
				} else {
					ep[-1] = NCCL;
					/* make nulls match so test fails */
					ep[0] |= 01;
				}
			}

			ep += iflag;

			continue;

		case '\\':
			switch (c = GETC()) {

			case '(':
				if (nbra >= NBRA)
					ERROR(43);
				*bracketp++ = nbra;
				*ep++ = CBRA;
				*ep++ = nbra++;
				continue;

			case ')':
				if (bracketp <= bracket)
					ERROR(42);
				*ep++ = CKET;
				*ep++ = *--bracketp;
				closed++;
				continue;

			case '{':
				if (lastep == (char *) 0)
					goto defchar;
				*lastep |= RNGE;
				cflg = 0;
			nlim:
				c = GETC();
				i = 0;
				do {
					if ('0' <= c && c <= '9')
						i = 10 * i + c - '0';
					else
						ERROR(16);
				} while (((c = GETC()) != '\\') && (c != ','));
				if (i >= 255)
					ERROR(11);
				*ep++ = i;
				if (c == ',') {
					if (cflg++)
						ERROR(44);
					if ((c = GETC()) == '\\')
						*ep++ = 255;
					else {
						UNGETC(c);
						goto nlim;
						/* get 2'nd number */
					}
				}
				if (GETC() != '}')
					ERROR(45);
				if (!cflg)	/* one number */
					*ep++ = i;
				else if ((ep[-1] & 0377) < (ep[-2] & 0377))
					ERROR(46);
				continue;

			case '\n':
				ERROR(36);

			case 'n':
				c = '\n';
				goto defchar;

			default:
				if (c >= '1' && c <= '9') {
					if ((c -= '1') >= closed)
						ERROR(25);
					*ep++ = CBACK;
					*ep++ = c;
					continue;
				}
			}
	/* Drop through to default to use \ to turn off special chars */

		defchar:
		default:
			lastep = ep;
			*ep++ = CCHR;
			*ep++ = c;
		}
	}
}

int
step(p1, p2)
char *p1, *p2;
{
	int c;


	if (circf) {
		loc1 = p1;
		return (advance(p1, p2));
	}
	/* fast check for first character */
	if (*p2 == CCHR) {
		c = p2[1];
		do {
			if (*p1 != c)
				continue;
			if (advance(p1, p2)) {
				loc1 = p1;
				return (1);
			}
		} while (*p1++);
		return (0);
	}
		/* regular algorithm */
	do {
		if (advance(p1, p2)) {
			loc1 = p1;
			return (1);
		}
	} while (*p1++);
	return (0);
}

advance(lp, ep)
char *lp, *ep;
{
	char *curlp;
	int c;
	char *bbeg;
	char neg;
	int ct;

	while (1) {
		neg = 0;
		switch (*ep++) {

		case CCHR:
			if (*ep++ == *lp++)
				continue;
			return (0);

		case CDOT:
			if (*lp++)
				continue;
			return (0);

		case CDOL:
			if (*lp == 0)
				continue;
			return (0);

		case CCEOF:
			loc2 = lp;
			return (1);

		case CXCL:
			c = (unsigned char)*lp++;
			if (ISTHERE(c)) {
				ep += 32;
				continue;
			}
			return (0);

		case NCCL:
			neg = 1;

		case CCL:
			c = *lp++;
			if (((c & 0200) == 0 && ISTHERE(c)) ^ neg) {
				ep += 16;
				continue;
			}
			return (0);

		case CBRA:
			braslist[*ep++] = lp;
			continue;

		case CKET:
			braelist[*ep++] = lp;
			continue;

		case CCHR | RNGE:
			c = *ep++;
			getrnge(ep);
			while (low--)
				if (*lp++ != c)
					return (0);
			curlp = lp;
			while (size--)
				if (*lp++ != c)
					break;
			if (size < 0)
				lp++;
			ep += 2;
			goto star;

		case CDOT | RNGE:
			getrnge(ep);
			while (low--)
				if (*lp++ == '\0')
					return (0);
			curlp = lp;
			while (size--)
				if (*lp++ == '\0')
					break;
			if (size < 0)
				lp++;
			ep += 2;
			goto star;

		case CXCL | RNGE:
			getrnge(ep + 32);
			while (low--) {
				c = (unsigned char)*lp++;
				if (!ISTHERE(c))
					return (0);
			}
			curlp = lp;
			while (size--) {
				c = (unsigned char)*lp++;
				if (!ISTHERE(c))
					break;
			}
			if (size < 0)
				lp++;
			ep += 34;		/* 32 + 2 */
			goto star;

		case NCCL | RNGE:
			neg = 1;

		case CCL | RNGE:
			getrnge(ep + 16);
			while (low--) {
				c = *lp++;
				if (((c & 0200) || !ISTHERE(c)) ^ neg)
					return (0);
			}
			curlp = lp;
			while (size--) {
				c = *lp++;
				if (((c & 0200) || !ISTHERE(c)) ^ neg)
					break;
			}
			if (size < 0)
				lp++;
			ep += 18; 		/* 16 + 2 */
			goto star;

		case CBACK:
			bbeg = braslist[*ep];
			ct = braelist[*ep++] - bbeg;

			if (ecmp(bbeg, lp, ct)) {
				lp += ct;
				continue;
			}
			return (0);

		case CBACK | STAR:
			bbeg = braslist[*ep];
			ct = braelist[*ep++] - bbeg;
			curlp = lp;
			while (ecmp(bbeg, lp, ct))
				lp += ct;

			while (lp >= curlp) {
				if (advance(lp, ep))
					return (1);
				lp -= ct;
			}
			return (0);


		case CDOT | STAR:
			curlp = lp;
			while (*lp++);
			goto star;

		case CCHR | STAR:
			curlp = lp;
			while (*lp++ == *ep);
			ep++;
			goto star;

		case CXCL | STAR:
			curlp = lp;
			do {
				c = (unsigned char)*lp++;
			} while (ISTHERE(c));
			ep += 32;
			goto star;

		case NCCL | STAR:
			neg = 1;

		case CCL | STAR:
			curlp = lp;
			do {
				c = *lp++;
			} while (((c & 0200) == 0 && ISTHERE(c)) ^ neg);
			ep += 16;
			goto star;

		star:
			do {
				if (--lp == locs)
					break;
				if (advance(lp, ep))
					return (1);
			} while (lp > curlp);
			return (0);

		}
	}
}

static
getrnge(str)
char *str;
{
	low = *str++ & 0377;
	size = ((*str & 0377) == 255)? 20000: (*str &0377) - low;
}

#ifdef __cplusplus
}
#endif

#endif /* _REGEXP_H */
