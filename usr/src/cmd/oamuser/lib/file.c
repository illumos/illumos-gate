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


#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.3 */

#include	<sys/types.h>
#include	<sys/stat.h>

int
check_perm( statbuf, uid, gid, perm )
struct stat statbuf;
uid_t uid;
gid_t gid;
mode_t perm;
{
	int fail = -1;	/* assume no permission at onset */

	/* Make sure we're dealing with a directory */
	if( S_ISDIR( statbuf.st_mode )) {

		/*
		 * Have a directory, so make sure user has permission
		 * by the various possible methods to this directory.
		 */
		if( (statbuf.st_uid == uid) &&
		    (statbuf.st_mode & (perm << 6)) == (perm << 6) )
			fail = 0;
		else
		if( (statbuf.st_gid == gid) &&
		    (statbuf.st_mode & (perm << 3)) == (perm << 3) )
			fail = 0;
		else
		if( (statbuf.st_mode & perm) == perm )
			fail = 0;
	}

	return( fail );
}
