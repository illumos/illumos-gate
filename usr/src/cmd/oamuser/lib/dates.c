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
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <time.h>

extern int putenv();

static int mask_defined = 0;

static char *dmaskpath = "DATEMSK=/etc/datemsk";

/* Parse a date string and return time_t value */
time_t
p_getdate( string )
char *string;
{
	struct tm *tmptr, *getdate();
	time_t rtime;

	if ( !mask_defined ) {
		if ( putenv( dmaskpath ) != 0 )
			return( (time_t) 0 );
		mask_defined = 1;
	}
	if( !(tmptr = getdate( string )) )
		return( (time_t) 0 );
	if ( (rtime = mktime( tmptr )) < 0)
		return( (time_t) 0);
	return( rtime );
}

