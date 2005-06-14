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
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * mailx -- a modified version of a University of California at Berkeley
 *	mail program
 */

/*
 *	libpath(file) - return the full path to the library file
 */

#include <stdio.h>	/* for declaration of sprintf */
#include <unistd.h>	/* for declaration of access */
#include "uparm.h"
#include <locale.h>

#define	PATHSIZE	1024

char *
libpath(char *file)
{
	static char	buf[PATHSIZE];

	snprintf(buf, sizeof (buf), "%s/%s", LIBPATH, file);
	return (buf);
}

/*
 * Return the path to a potentially locale-specific help file.
 */
char *
helppath(char *file)
{
	static char	buf[PATHSIZE];
	char *loc;

	loc = setlocale(LC_MESSAGES, NULL);
	if (loc != NULL) {
		snprintf(buf, sizeof (buf), "%s/%s/LC_MESSAGES/%s",
			LOCALEPATH, loc, file);
		if (access(buf, 0) == 0)
			return (buf);
	}
	snprintf(buf, sizeof (buf), "%s/%s", LIBPATH, file);
	return (buf);
}
