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


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.5	*/


#if	!defined(_LP_LP_SET_H)
#define	_LP_LP_SET_H

/*
 * How far should we check for "compressed" horizontal pitch?
 * Keep in mind that (1) too far and the user can't read it, and
 * (2) some Terminfo entries don't limit their parameters like
 * they should. Keep in mind the other hand, though: What is too
 * compact for you may be fine for the eagle eyes next to you!
 */
#define MAX_COMPRESSED	30	/* CPI */

#define	E_SUCCESS	0
#define	E_FAILURE	1
#define	E_BAD_ARGS	2
#define	E_MALLOC	3

#define	OKAY(P)		((P) && (*P))
#define R(F)		(int)((F) + .5)

#if	!defined(CHARSETDIR)
# define CHARSETDIR	"/usr/share/lib/charset"
#endif

#if	defined(__STDC__)

int		set_pitch ( char * , int , int );
int		set_size ( char * , int , int );
int		set_charset ( char * , int , char * );

#else

int		set_pitch(),
		set_size(),
		set_charset();

#endif

#endif
