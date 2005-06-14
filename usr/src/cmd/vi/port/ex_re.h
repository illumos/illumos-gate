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


/* Copyright (c) 1981 Regents of the University of California */
#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.6	*/

#include <regexpr.h>
/*
 * Regular expression definitions.
 * The regular expressions in ex are similar to those in ed,
 * with the addition of the word boundaries from Toronto ed
 * and allowing character classes to have [a-b] as in the shell.
 * The numbers for the nodes below are spaced further apart then
 * necessary because I at one time partially put in + and | (one or
 * more and alternation.)
 */
#define	EXPSIZ	(ESIZE + 2)

struct	regexp {
	unsigned char	Expbuf[EXPSIZ];
	short	Nbra;
};

/*
 * There are three regular expressions here, the previous (in re),
 * the previous substitute (in subre) and the previous scanning (in scanre).
 * It would be possible to get rid of "re" by making it a stack parameter
 * to the appropriate routines.
 */
var struct	regexp *re;		/* Last re */
var struct	regexp *scanre;		/* Last scanning re */
var struct	regexp *subre;		/* Last substitute re */

/*
 * Since the phototypesetter v7-epsilon
 * C compiler doesn't have structure assignment...
 */
void savere(struct regexp ** a);
void resre(struct regexp * a);

/*
 * Definitions for substitute
 */
var unsigned char	rhsbuf[RHSSIZE];	/* Rhs of last substitute */
