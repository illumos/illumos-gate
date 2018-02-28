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
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*LINTLIBRARY*/

#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include "utility.h"

/*
 *	this code was taken from REGCMP(3X)
 */
/*VARARGS*/
/*ARGSUSED*/

#define	SSIZE	50
#define	TGRP	48
#define	A256	01
#define	A512	02
#define	A768	03
#define	NBRA	10
#define	CIRCFL	32

#define	CBRA	60
#define	GRP	40
#define	SGRP	56
#define	PGRP	68
#define	EGRP	44
#define	RNGE	03
#define	CCHR	20
#define	CDOT	64
#define	CCL	24
#define	NCCL	8
#define	CDOL	28
#define	FCEOF	52 /* This was originally CEOF but it clashes with the header */
			/* definition so it was changed to FCEOF */
#define	CKET	12

#define	STAR	01
#define	PLUS	02
#define	MINUS	16

char	*__braslist[NBRA];
char	*__braelist[NBRA];
char	*__loc1;
intptr_t	__bravar[NBRA];
intptr_t	*__st[SSIZE + 1];
intptr_t	*__eptr_, *__lptr_;
intptr_t	__cflg;

char *
libform_regex(char *addrc, char *addrl, char *a1)
{
	intptr_t cur, in;
	intptr_t *adx;
	char *p1, *p2;

	for (in = 0; in < NBRA; in++) {
		__braslist[in] = 0;
		__bravar[in] = -1;
	}
	__cflg = 0;
	cur = __execute(addrc, addrl);
	adx = (intptr_t *)&a1;
	for (in = 0; in < NBRA; in++) {
		if (((p1 = __braslist[in]) != 0) && (__bravar[in] >= 0)) {
			p2 = (char *)adx[__bravar[in]];
			while (p1 < __braelist[in]) *p2++ = *p1++;
			*p2 = '\0';
		}
	}
	if (!__cflg)
		return ((addrl == (char *)cur) ? (char *)0 : (char *)cur);
	else
		return ((char *)cur);
}

intptr_t
__execute(char *addrc, char *addrl)
{
	char *p1, *p2, c;
	intptr_t i;

	p1 = addrl;
	p2 = addrc;
	__eptr_ = (intptr_t *)&__st[SSIZE];
	__lptr_ = (intptr_t *)&__st[0];
	if (*p2 == CIRCFL) {
		__loc1 = p1;
		return ((i = __advance(p1, ++p2)) ? i : (intptr_t)addrl);
	}
	/* fast check for first character */
	if (*p2 == CCHR) {
		c = p2[1];
		do {
			if (*p1 != c)
				continue;
			__eptr_ = (intptr_t *)&__st[SSIZE];
			__lptr_ = (intptr_t *)&__st[0];
			if (i = __advance(p1, p2))  {
				__loc1 = p1;
				return (i);
			}
		} while (*p1++);
		return ((intptr_t)addrl);
	}
	/* regular algorithm */
	do {
	__eptr_ = (intptr_t *)&__st[SSIZE];
	__lptr_ = (intptr_t *)&__st[0];
		if (i = __advance(p1, p2))  {
			__loc1 = p1;
			return (i);
		}
	} while (*p1++);
	return ((intptr_t)addrl);
}

intptr_t
__advance(char *alp, char *aep)
{
	char *lp, *ep, *curlp;
	char *sep, *dp;
	intptr_t i, lcnt, dcnt, gflg;

	lp = alp;
	ep = aep;
	gflg = 0;
	for (; ; ) {
		switch (*ep++) {

	case CCHR:
		if (*ep++ == *lp++)
			continue;
		return (0);

	case EGRP|RNGE:
		return ((intptr_t)lp);
	case EGRP:
	case GRP:
		ep++;
		continue;

	case EGRP|STAR:
		(void) __xpop(0);
		/* FALLTHROUGH */
	case EGRP|PLUS:
		(void) __xpush(0, ++ep);
		return ((intptr_t)lp);

	case CDOT:
		if (*lp++)
			continue;
		return (0);

	case CDOL:
		if (*lp == 0)
			continue;
		lp++;
		return (0);

	case FCEOF:
		__cflg = 1;
		return ((intptr_t)lp);

	case TGRP:
	case TGRP|A768:
	case TGRP|A512:
	case TGRP|A256:
		i = (((ep[-1] & 03) << 8) + (*ep) & 0377);
		ep++;
		(void) __xpush(0, ep + i + 2);
		(void) __xpush(0, ++ep);
		(void) __xpush(0, ++ep);
		gflg = 1;
		(void) __getrnge(&lcnt, &dcnt, &ep[i]);
		while (lcnt--)
			if (!(lp = (char *)__advance(lp, ep)))
				return (0);
		(void) __xpush(1, curlp = lp);
		while (dcnt--)
			if (!(dp = (char *)__advance(lp, ep))) break;
			else
				(void) __xpush(1, lp = dp);
		ep = (char *)__xpop(0);
		goto star;
	case CCHR|RNGE:
		sep = ep++;
		(void) __getrnge(&lcnt, &dcnt, ep);
		while (lcnt--)
			if (*lp++ != *sep)
				return (0);
		curlp = lp;
		while (dcnt--)
			if (*lp++ != *sep) break;
		if (dcnt < 0) lp++;
		ep += 2;
		goto star;
	case CDOT|RNGE:
		(void) __getrnge(&lcnt, &dcnt, ep);
		while (lcnt--)
			if (*lp++ == '\0')
				return (0);
		curlp = lp;
		while (dcnt--)
			if (*lp++ == '\0') break;
		if (dcnt < 0) lp++;
		ep += 2;
		goto star;
	case CCL|RNGE:
	case NCCL|RNGE:
		(void) __getrnge(&lcnt, &dcnt, (ep + (*ep & 0377)));
		while (lcnt--)
			if (!__cclass(ep, *lp++, ep[-1] == (CCL | RNGE)))
				return (0);
		curlp = lp;
		while (dcnt--)
			if (!__cclass(ep, *lp++, ep[-1] == (CCL|RNGE)))
				break;
		if (dcnt < 0) lp++;
		ep += (*ep + 2);
		goto star;
	case CCL:
		if (__cclass(ep, *lp++, 1)) {
			ep += *ep;
			continue;
		}
		return (0);

	case NCCL:
		if (__cclass(ep, *lp++, 0)) {
			ep += *ep;
			continue;
		}
		return (0);

	case CBRA:
		__braslist[*ep++] = lp;
		continue;

	case CKET:
		__braelist[*ep] = lp;
		__bravar[*ep] = ep[1];
		ep += 2;
		continue;

	case CDOT|PLUS:
		if (*lp++ == '\0')
			return (0);
		/* FALLTHROUGH */
	case CDOT|STAR:
		curlp = lp;
		while (*lp++)
			;
		goto star;

	case CCHR|PLUS:
		if (*lp++ != *ep)
			return (0);
		/* FALLTHROUGH */
	case CCHR|STAR:
		curlp = lp;
		while (*lp++ == *ep)
			;
		ep++;
		goto star;

	case PGRP:
	case PGRP|A256:
	case PGRP|A512:
	case PGRP|A768:
		if (!(lp = (char *)__advance(lp, ep+1)))
			return (0);
		/* FALLTHROUGH */
	case SGRP|A768:
	case SGRP|A512:
	case SGRP|A256:
	case SGRP:
		i = (((ep[-1]&03) << 8) + (*ep & 0377));
		ep++;
		(void) __xpush(0, ep + i);
		(void) __xpush(1, curlp = lp);
		while (i = __advance(lp, ep))
			(void) __xpush(1, lp = (char *)i);
		ep = (char *)__xpop(0);
		gflg = 1;
		goto star;

	case CCL|PLUS:
	case NCCL|PLUS:
		if (!__cclass(ep, *lp++, ep[-1] == (CCL | PLUS)))
			return (0);
		/* FALLTHROUGH */
	case CCL|STAR:
	case NCCL|STAR:
		curlp = lp;
		while (__cclass(ep, *lp++, ((ep[-1] == (CCL | STAR)) ||
		    (ep[-1] == (CCL | PLUS)))))
			;
		ep += *ep;
		goto star;

	star:
		do {
			if (!gflg) lp--;
			else if (!(lp = (char *)__xpop(1))) break;
			if (i = __advance(lp, ep))
				return (i);
		} while (lp > curlp);
		return (0);

	default:
		return (0);
	}
	}
}

intptr_t
__cclass(char *aset, char ac, intptr_t af)
{
	char *set, c;
	intptr_t n;

	set = (char *)aset;
	if ((c = ac) == 0)
		return (0);
	n = *set++;
	while (--n) {
		if (*set == MINUS) {
			if ((set[2] - set[1]) < 0)
				return (0);
			if (*++set <= c) {
				if (c <= *++set)
					return (af);
			} else
				++set;
			++set;
			n -= 2;
			continue;
		}
		if (*set++ == c)
			return (af);
	}
	return (!af);
}

intptr_t
__xpush(intptr_t i, char *p)
{
	if (__lptr_ >= __eptr_) {
		(void) write(2, "stack overflow\n", 15);
		(void) exit(1);
	}
	if (i)
		*__lptr_++ = (intptr_t)p;
	else
		*__eptr_-- = (intptr_t)p;
	return (1);
}

intptr_t
__xpop(intptr_t i)
{
	if (i)
		return ((__lptr_ < (intptr_t *)&__st[0]) ? 0 : *--__lptr_);
	else
		return ((__eptr_ > (intptr_t *)&__st[SSIZE]) ? 0 : *++__eptr_);
}

intptr_t
__getrnge(intptr_t *i, intptr_t *j, char *k)
{
	*i = (*k++&0377);
	if (*k == (char)-1)
		*j = 20000;
	else
		*j = ((*k&0377) - *i);
	return (1);
}
