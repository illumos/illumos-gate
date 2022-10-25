/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * routines to do regular expression matching
 *
 * Entry points:
 *
 *	re_comp(s)
 *		char *s;
 *	 ... returns 0 if the string s was compiled successfully,
 *		     a pointer to an error message otherwise.
 *	     If passed 0 or a null string returns without changing
 *           the currently compiled re (see note 11 below).
 *
 *	re_exec(s)
 *		char *s;
 *	 ... returns 1 if the string s matches the last compiled regular
 *		       expression,
 *		     0 if the string s failed to match the last compiled
 *		       regular expression, and
 *		    -1 if the compiled regular expression was invalid
 *		       (indicating an internal error).
 *
 * The strings passed to both re_comp and re_exec may have trailing or
 * embedded newline characters; they are terminated by nulls.
 *
 * The identity of the author of these routines is lost in antiquity;
 * this is essentially the same as the re code in the original V6 ed.
 *
 * The regular expressions recognized are described below. This description
 * is essentially the same as that for ed.
 *
 *	A regular expression specifies a set of strings of characters.
 *	A member of this set of strings is said to be matched by
 *	the regular expression.  In the following specification for
 *	regular expressions the word `character' means any character but NUL.
 *
 *	1.  Any character except a special character matches itself.
 *	    Special characters are the regular expression delimiter plus
 *	    \ [ . and sometimes ^ * $.
 *	2.  A . matches any character.
 *	3.  A \ followed by any character except a digit or ( )
 *	    matches that character.
 *	4.  A nonempty string s bracketed [s] (or [^s]) matches any
 *	    character in (or not in) s. In s, \ has no special meaning,
 *	    and ] may only appear as the first letter. A substring
 *	    a-b, with a and b in ascending ASCII order, stands for
 *	    the inclusive range of ASCII characters.
 *	5.  A regular expression of form 1-4 followed by * matches a
 *	    sequence of 0 or more matches of the regular expression.
 *	6.  A regular expression, x, of form 1-8, bracketed \(x\)
 *	    matches what x matches.
 *	7.  A \ followed by a digit n matches a copy of the string that the
 *	    bracketed regular expression beginning with the nth \( matched.
 *	8.  A regular expression of form 1-8, x, followed by a regular
 *	    expression of form 1-7, y matches a match for x followed by
 *	    a match for y, with the x match being as long as possible
 *	    while still permitting a y match.
 *	9.  A regular expression of form 1-8 preceded by ^ (or followed
 *	    by $), is constrained to matches that begin at the left
 *	    (or end at the right) end of a line.
 *	10. A regular expression of form 1-9 picks out the longest among
 *	    the leftmost matches in a line.
 *	11. An empty regular expression stands for a copy of the last
 *	    regular expression encountered.
 */

#include "lint.h"

#include <stdlib.h>
#include <re_comp.h>
#include <stddef.h>
#include <sys/types.h>

/*
 * constants for re's
 */
#define	CBRA	1
#define	CCHR	2
#define	CDOT	4
#define	CCL	6
#define	NCCL	8
#define	CDOL	10
#define	CEOF	11
#define	CKET	12
#define	CBACK	18

#define	CSTAR	01

#define	ESIZE	512
#define	NBRA	9

static struct re_globals {
	char	_expbuf[ESIZE];
	char	*_braslist[NBRA], *_braelist[NBRA];
	char	_circf;
} *re_globals;
#define	expbuf (_re->_expbuf)
#define	braslist (_re->_braslist)
#define	braelist (_re->_braelist)
#define	circf (_re->_circf)

static int advance(const char *, char *);
static int backref(int, const char *);
static int cclass(char *, char, int);

/*
 * compile the regular expression argument into a dfa
 */
char *
re_comp(const char *sp)
{
	char	c;
	struct re_globals *_re = re_globals;
	char	*ep;
	char	cclcnt, numbra = 0;
	char	*lastep = NULL;
	char	bracket[NBRA];
	char	*bracketp = &bracket[0];
	char	*retoolong = "Regular expression too long";

	if (_re == NULL) {
		_re = (struct re_globals *)calloc(1, sizeof (*_re));
		if (_re == NULL)
			return ("Out of memory");
		re_globals = _re;
	}
	ep = expbuf;

#define	comerr(msg) {expbuf[0] = 0; return (msg); }

	if (sp == NULL || *sp == '\0') {
		if (*ep == 0)
			return ("No previous regular expression");
		return (NULL);
	}
	if (*sp == '^') {
		circf = 1;
		sp++;
	}
	else
		circf = 0;
	for (;;) {
		if (ep >= &expbuf[ESIZE])
			comerr(retoolong);
		if ((c = *sp++) == '\0') {
			if (bracketp != bracket)
				comerr("unmatched \\(");
			*ep++ = CEOF;
			*ep++ = 0;
			return (NULL);
		}
		if (c != '*')
			lastep = ep;
		switch (c) {

		case '.':
			*ep++ = CDOT;
			continue;

		case '*':
			if (lastep == NULL || *lastep == CBRA ||
			    *lastep == CKET)
				goto defchar;
			*lastep |= CSTAR;
			continue;

		case '$':
			if (*sp != '\0')
				goto defchar;
			*ep++ = CDOL;
			continue;

		case '[':
			*ep++ = CCL;
			*ep++ = 0;
			cclcnt = 1;
			if ((c = *sp++) == '^') {
				c = *sp++;
				ep[-2] = NCCL;
			}
			do {
				if (c == '\0')
					comerr("missing ]");
				if (c == '-' && ep [-1] != 0) {
					if ((c = *sp++) == ']') {
						*ep++ = '-';
						cclcnt++;
						break;
					}
					while (ep[-1] < c) {
						*ep = ep[-1] + 1;
						ep++;
						cclcnt++;
						if (ep >= &expbuf[ESIZE])
							comerr(retoolong);
					}
				}
				*ep++ = c;
				cclcnt++;
				if (ep >= &expbuf[ESIZE])
					comerr(retoolong);
			} while ((c = *sp++) != ']');
			lastep[1] = cclcnt;
			continue;

		case '\\':
			if ((c = *sp++) == '(') {
				if (numbra >= NBRA)
					comerr("too many \\(\\) pairs");
				*bracketp++ = numbra;
				*ep++ = CBRA;
				*ep++ = numbra++;
				continue;
			}
			if (c == ')') {
				if (bracketp <= bracket)
					comerr("unmatched \\)");
				*ep++ = CKET;
				*ep++ = *--bracketp;
				continue;
			}
			if (c >= '1' && c < ('1' + NBRA)) {
				*ep++ = CBACK;
				*ep++ = c - '1';
				continue;
			}
			*ep++ = CCHR;
			*ep++ = c;
			continue;

		defchar:
		default:
			*ep++ = CCHR;
			*ep++ = c;
		}
	}
}

/*
 * match the argument string against the compiled re
 */
int
re_exec(const char *p1)
{
	struct re_globals *_re = re_globals;
	char	*p2;
	int	c;
	int	rv;

	if (_re == NULL)
		return (0);
	p2 = expbuf;
	for (c = 0; c < NBRA; c++) {
		braslist[c] = 0;
		braelist[c] = 0;
	}
	if (circf)
		return ((advance(p1, p2)));
	/*
	 * fast check for first character
	 */
	if (*p2 == CCHR) {
		c = p2[1];
		do {
			if (*p1 != c)
				continue;
			rv = advance(p1, p2);
			if (rv != 0)
				return (rv);
		} while (*p1++);
		return (0);
	}
	/*
	 * regular algorithm
	 */
	do {
		rv = advance(p1, p2);
		if (rv != 0)
			return (rv);
	} while (*p1++);
	return (0);
}

/*
 * try to match the next thing in the dfa
 */
static int
advance(const char *lp, char *ep)
{
	const char	*curlp;
	ptrdiff_t	ct;
	int		i;
	int		rv;
	struct re_globals *_re = re_globals;

	for (;;)
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
			if (*lp == '\0')
				continue;
			return (0);

		case CEOF:
			return (1);

		case CCL:
			if (cclass(ep, *lp++, 1)) {
				ep += *ep;
				continue;
			}
			return (0);

		case NCCL:
			if (cclass(ep, *lp++, 0)) {
				ep += *ep;
				continue;
			}
			return (0);

		case CBRA:
			braslist[*ep++] = (char *)lp;
			continue;

		case CKET:
			braelist[*ep++] = (char *)lp;
			continue;

		case CBACK:
			if (braelist[i = *ep++] == NULL)
				return (-1);
			if (backref(i, lp)) {
				lp += braelist[i] - braslist[i];
				continue;
			}
			return (0);

		case CBACK|CSTAR:
			if (braelist[i = *ep++] == NULL)
				return (-1);
			curlp = lp;
			ct = braelist[i] - braslist[i];
			while (backref(i, lp))
				lp += ct;
			while (lp >= curlp) {
				rv = advance(lp, ep);
				if (rv != 0)
					return (rv);
				lp -= ct;
			}
			continue;

		case CDOT|CSTAR:
			curlp = lp;
			while (*lp++)
				;
			goto star;

		case CCHR|CSTAR:
			curlp = lp;
			while (*lp++ == *ep)
				;
			ep++;
			goto star;

		case CCL|CSTAR:
		case NCCL|CSTAR:
			curlp = lp;
			while (cclass(ep, *lp++, ep[-1] == (CCL|CSTAR)))
				;
			ep += *ep;
			goto star;

		star:
			do {
				lp--;
				rv = advance(lp, ep);
				if (rv != 0)
					return (rv);
			} while (lp > curlp);
			return (0);

		default:
			return (-1);
		}
}

static int
backref(int i, const char *lp)
{
	char	*bp;
	struct re_globals *_re = re_globals;

	bp = braslist[i];
	while (*bp++ == *lp++)
		if (bp >= braelist[i])
			return (1);
	return (0);
}

static int
cclass(char *set, char c, int af)
{
	int	n;

	if (c == 0)
		return (0);
	n = *set++;
	while (--n)
		if (*set++ == c)
			return (af);
	return (! af);
}
