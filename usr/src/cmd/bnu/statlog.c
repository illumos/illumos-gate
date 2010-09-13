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
/*
 * Copyright 1988 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "uucp.h"

int Retries;

/*
	Report and log file transfer rate statistics.
	This is ugly because we are not using floating point.
*/

void
statlog( direction, bytes, millisecs, breakmsg)
char		*direction;
unsigned long	bytes;
time_t		millisecs;
char		*breakmsg; /* "PARTIAL FILE" or "" */
{
	char		text[ 100 ];
	unsigned long	bytes1000;

	/* bytes1000 = bytes * 1000; */
	/* on fast machines, times(2) resolution may not be enough */
	/* so millisecs may be zero.  just use 1 as best guess */
	if ( millisecs == 0 )
		millisecs = 1;
		
		
	if (bytes < 1<<22)
		bytes1000 = (bytes*1000/millisecs);
	else
		bytes1000 = ((bytes/millisecs)*1000);
		
	(void) sprintf(text, "%s %lu / %lu.%.3lu secs, %lu bytes/sec %s",
		direction, bytes, millisecs/1000, millisecs%1000,
		bytes1000, breakmsg );
	if (Retries) {
		sprintf(text + strlen(text), " %d retries", Retries);
		Retries = 0;
	}
		/* bytes1000/millisecs, breakmsg ); */
	CDEBUG(4, "%s\n", text);
	usyslog(text);
	return;
}

static unsigned long	filesize;	/* size of file been 
					transferred or received */
/*
	return the size of file been transferred or received
*/
unsigned long
getfilesize()
{
	return(filesize);
}

/*
	update the size of file been transferred or received
*/
void
putfilesize(bytes)
unsigned long bytes;
{
	filesize = bytes;
	return;
}
