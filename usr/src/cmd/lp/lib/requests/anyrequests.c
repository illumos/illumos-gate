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
/* EMACS_MODES: !fill, lnumb, !overwrite, !nodelete, !picture */

#include "sys/types.h"

#include "lp.h"

/**
 ** anyrequests() - SEE IF ANY REQUESTS ARE ``QUEUED''
 **/

int
#if	defined(__STDC__)
anyrequests (
	void
)
#else
anyrequests ()
#endif
{
	long			lastdir		= -1;

	char *			name;


	/*
	 * This routine walks through the requests (secure)
	 * directory looking for files, descending one level
	 * into each sub-directory, if any. Finding at least
	 * one file means that a request is queued.
	 */
	while ((name = next_dir(Lp_Requests, &lastdir))) {

		long			lastfile	= -1;

		char *			subdir;


		if (!(subdir = makepath(Lp_Requests, name, (char *)0)))
			return (1);	/* err on safe side */

		if (next_file(subdir, &lastfile)) {
			Free (subdir);
			return (1);
		}

		Free (subdir);
	}
	return (0);
}
