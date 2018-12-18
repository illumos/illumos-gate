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

/*
 * Copyright (c) 2018, Joyent, Inc.
 */

/*LINTLIBRARY*/

#include <sys/types.h>
#include <stdlib.h>
#include "utility.h"

/* this code was taken from REGCMP(3X) */

#define	SSIZE	16
#define	TGRP	48
#define	A256	02
#define	ZERO	01
#define	NBRA	10
#define	CIRCFL	32;
#define	SLOP	5
#define	FEOF	0 /* This was originally EOF but it clashes with the header */
			/* definition so it was changed to FEOF */

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

intptr_t	*__sp_;
intptr_t	*__stmax;
int	__i_size;

/*ARGSUSED2*/
char *
libform_regcmp(char *cs1, char *cs2)
{
	char c;
	char *ep, *sp;
	int *adx;
	int i, cflg;
	char *lastep, *sep, *eptr;
	int nbra, ngrp;
	int cclcnt;
	intptr_t stack[SSIZE];

	__sp_ = stack;
	*__sp_ = -1;
	__stmax = &stack[SSIZE];

	adx = (int *)&cs1;
	i = nbra = ngrp = 0;
	while (*adx)
		i += __size((char *)(intptr_t)*adx++);
	adx = (int *)&cs1;
	sp = (char *)(intptr_t)*adx++;
	if ((sep = ep = malloc((unsigned)(2 * i + SLOP))) == NULL)
		return (NULL);
	if ((c = *sp++) == FEOF)
		goto cerror;
	if (c == '^') {
		c = *sp++;
		*ep++ = CIRCFL;
	}
	if ((c == '*') || (c == '+') || (c == '{'))
		goto cerror;
	sp--;
	for (;;) {
		if ((c = *sp++) == FEOF) {
			if (*adx) {
				sp = (char *)(intptr_t)*adx++;
				continue;
			}
			*ep++ = FCEOF;
			if (--nbra > NBRA || *__sp_ != -1)
				goto cerror;
			__i_size = (int) (ep - sep);
			return (sep);
		}
		if ((c != '*') && (c != '{') && (c != '+'))
			lastep = ep;
		switch (c) {

		case '(':
			if (!__rpush(ep)) goto cerror;
			*ep++ = CBRA;
			*ep++ = -1;
			continue;
		case ')':
			if (!(eptr = (char *)__rpop())) goto cerror;
			if ((c = *sp++) == '$') {
				if ('0' > (c = *sp++) || c > '9')
					goto cerror;
				*ep++ = CKET;
				*ep++ = *++eptr = nbra++;
				*ep++ = (c-'0');
				continue;
			}
			*ep++ = EGRP;
			*ep++ = ngrp++;
			sp--;
			switch (c) {
			case '+':
				*eptr = PGRP;
				break;
			case '*':
				*eptr = SGRP;
				break;
			case '{':
				*eptr = TGRP;
				break;
			default:
				*eptr = GRP;
				continue;
			}
			i = (int) (ep - eptr - 2);
			for (cclcnt = 0; i >= 256; cclcnt++)
				i -= 256;
			if (cclcnt > 3) goto cerror;
			*eptr |= cclcnt;
			*++eptr = (char) i;
			continue;

		case '\\':
			*ep++ = CCHR;
			if ((c = *sp++) == FEOF)
				goto cerror;
			*ep++ = c;
			continue;

		case '{':
			*lastep |= RNGE;
			cflg = 0;
		nlim:
			if ((c = *sp++) == '}') goto cerror;
			i = 0;
			do {
				if ('0' <= c && c <= '9')
					i = (i*10+(c-'0'));
				else goto cerror;
			} while (((c = *sp++) != '}') && (c != ','));
			if (i > 255) goto cerror;
			*ep++ = (char) i;
			if (c == ',') {
				if (cflg++) goto cerror;
				if ((c = *sp++) == '}') {
					*ep++ = -1;
					continue;
				} else {
					sp--;
					goto nlim;
				}
			}
			if (!cflg)
				*ep++ = (char) i;
			else if ((ep[-1]&0377) < (ep[-2]&0377))
				goto cerror;
			continue;

		case '.':
			*ep++ = CDOT;
			continue;

		case '+':
			if (*lastep == CBRA || *lastep == CKET)
				goto cerror;
			*lastep |= PLUS;
			continue;

		case '*':
			if (*lastep == CBRA || *lastep == CKET)
				goto cerror;
			*lastep |= STAR;
			continue;

		case '$':
			if ((*sp != FEOF) || (*adx))
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
				if (c == FEOF)
					goto cerror;
				if ((c == '-') && (cclcnt > 1) &&
				    (*sp != ']')) {
					*ep = ep[-1];
					ep++;
					ep[-2] = MINUS;
					cclcnt++;
					continue;
				}
				*ep++ = c;
				cclcnt++;
			} while ((c = *sp++) != ']');
			lastep[1] = (char) cclcnt;
			continue;

		defchar:
		default:
			*ep++ = CCHR;
			*ep++ = c;
		}
	}
cerror:
	free(sep);
	return (0);
}

int
__size(char *strg)
{
	int	i;

	i = 1;
	while (*strg++)
		i++;
	return (i);
}

intptr_t
__rpop(void)
{
	return ((*__sp_ == -1)?0:*__sp_--);
}

int
__rpush(char *ptr)
{
	if (__sp_ >= __stmax)
		return (0);
	*++__sp_ = (intptr_t)ptr;
	return (1);
}
