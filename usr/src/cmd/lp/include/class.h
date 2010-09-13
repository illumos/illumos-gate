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


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.6	*/

#if	!defined(_LP_CLASS_H)
#define	_LP_CLASS_H

/**
 ** The internal flags seen by the Spooler/Scheduler and anyone who asks.
 **/

#define CS_REJECTED	0x001

/**
 ** The internal copy of a class as seen by the rest of the world:
 **/

/*
 * A (char **) list is an array of string pointers (char *) with
 * a null pointer after the last item.
 */
typedef struct CLASS {
	char   *name;		/* name of class (redundant) */
	char   **members;       /* members of class */
}			CLASS;

/**
 ** Various routines.
 **/

#if	defined(__STDC__)

CLASS		*getclass ( char * );

int		putclass ( char *, CLASS * );
int		delclass ( char * );

void		freeclass ( CLASS * );

#else

CLASS		*getclass();

int		putclass(),
		delclass();

void		freeclass();

#endif

#endif
