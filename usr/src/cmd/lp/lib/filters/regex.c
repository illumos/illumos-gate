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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* EMACS_MODES: !fill, lnumb, !overwrite, !nodelete, !picture */

#include "sys/types.h"
#include "regexpr.h"
#include "regex.h"
#include "string.h"

/**
 ** match() - TEST MATCH OF TEMPLATE/PATTERN WITH PARAMETER
 **/

int
#if	defined(__STDC__)
match (
	char *			re,
	char *			value
)
#else
match (re, value)
	register char *		re;
	register char *		value;
#endif
{
	int			ret;

	/*
	 * We want exact matches, just as if the regular expression
	 * was ^...$, to explicitly match the beginning and end of line.
	 * Using "advance" instead of "step" takes care of the ^ and
	 * checking where the match left off takes care of the $.
	 * We don't do something silly like add the ^ and $ ourselves,
	 * because the user may have done that already.
	 */
	ret = advance(value, re);
	if (ret && *loc2)
		ret = 0;
	return (ret);
}

/**
 ** replace() - REPLACE TEMPLATE WITH EXPANDED REGULAR EXPRESSION MATCH
 **/

size_t
#if	defined(__STDC__)
replace (
	char **			pp,
	char *			result,
	char *			value,
	int			nbra
)
#else
replace (pp, result, value)
	char **			pp;
	char *			result;
	char *			value;
	int			nbra;
#endif
{
	register char *		p;
	register char *		q;

	register size_t		ncount	= 0;


/*
 * Count and perhaps copy a single character:
 */
#define	CCPY(SRC)	if ((ncount++, pp)) \
				*p++ = SRC

/*
 * Count and perhaps copy a string:
 */
#define	SCPY(SRC)	if (pp) { \
				register char *	r; \
				for (r = (SRC); *r; ncount++) \
					*p++ = *r++; \
			} else \
				ncount += strlen(SRC)


	if (pp)   
		p = *pp;

	for (q = result; *q; q++)  switch (*q) {

	case '*':
	case '&':
		SCPY (value);
		break;

	case '\\':
		switch (*++q) {
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
		{
			register int		n = *q-'1';

			if (n < nbra) {
				register char		c = *(braelist[n]);

				*(braelist[n]) = 0;
				SCPY (braslist[n]);
				*(braelist[n]) = c;
			}
			break;
		}

		default:
			CCPY (*q);
			break;
		}
		break;

	default:
		CCPY (*q);
		break;
	}

	if (pp)
		*pp = p;

	return (ncount);
}
