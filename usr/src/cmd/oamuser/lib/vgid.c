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


#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.4 */

#include	<sys/types.h>
#include	<stdio.h>
#include	<grp.h>
#include	<users.h>
#include	<sys/param.h>
#include	<userdefs.h>

/*
	MAXUID should be in param.h; if it isn't,
	try for UID_MAX in limits.h
*/
#ifndef	MAXUID
#include	<limits.h>
#define	MAXUID	UID_MAX
#endif

struct group *getgrgid();

/*  validate a GID */
int
valid_gid( gid, gptr )
gid_t gid;
struct group **gptr;
{
	register struct group *t_gptr;

	if( gid < 0 ) return( INVALID );

	if( gid > MAXUID ) return( TOOBIG );

	if( t_gptr = getgrgid( gid ) ) {
		if( gptr ) *gptr = t_gptr;
		return( NOTUNIQUE );
	}

	if( gid <= DEFGID ) {
		if( gptr ) *gptr = getgrgid( gid );
		return( RESERVED );
	}

	return( UNIQUE );
}
