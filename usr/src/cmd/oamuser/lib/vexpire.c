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
/*	Copyright 1997 Sun Microsystems, Inc. All rights reserved. */
/*	Use is subject to license terms. */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	All Rights Reserved  	*/

#pragma	ident	"%Z%%M%	%I%	%E% SMI"

#include	<sys/types.h>
#include	<time.h>
#include	<users.h>

extern long p_getdate();

/*
	Validate an expiration date string
*/
int
valid_expire( string, expire )
char *string;
time_t *expire;
{
	time_t tmp, now;
	struct tm *tm;

	if( !(tmp = (time_t) p_getdate( string ) ) )
		return( INVALID );

	now = time( (time_t *)0 );
	
	/* Make a time_t for midnight tonight */
	tm = localtime( &now );
	now -= tm->tm_hour * 60*60 + tm->tm_min * 60 + tm->tm_sec;
	now += 24 * 60 * 60;

	if( tmp < now ) return( INVALID );

	if( expire ) *expire = now;

	return( UNIQUE );
}
