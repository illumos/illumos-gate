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


#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.2 */

#include	<sys/types.h>
#include	<stdio.h>
#include	<pwd.h>
#include	<userdefs.h>
#include	<users.h>

#include	<sys/param.h>

#ifndef MAXUID
#include	<limits.h>
#define	MAXUID	UID_MAX
#endif

struct passwd *getpwuid();

int
valid_uid( uid, pptr )
uid_t uid;
struct passwd **pptr;
{
	register struct passwd *t_pptr;

	if( uid <= 0 ) return( INVALID );
	if( uid <= DEFRID ) {
		if( pptr ) *pptr = getpwuid( uid );

		return( RESERVED );
	}

	if( uid > MAXUID ) return( TOOBIG );

	if( t_pptr = getpwuid( uid ) ) {
		if( pptr ) *pptr = t_pptr;
		return( NOTUNIQUE );
	}

	return( UNIQUE );
}
