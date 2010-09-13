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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <stdio.h>
#include <userdefs.h>
#include <errno.h>
#include <strings.h>
#include "messages.h"

#define 	SBUFSZ	256

extern int rm_homedir();

static char cmdbuf[ SBUFSZ ];	/* buffer for system call */

/*
	Create a home directory and populate with files from skeleton
	directory.
*/
int
create_home(char *homedir, char *skeldir, uid_t uid, gid_t gid)
		/* home directory to create */
		/* skel directory to copy if indicated */
		/* uid of new user */
		/* group id of new user */
{
	if( mkdir(homedir, 0775) != 0 ) {
		errmsg(M_OOPS, "create the home directory", strerror(errno));
		return( EX_HOMEDIR );
	}

	if( chown(homedir, uid, gid) != 0 ) {
		errmsg(M_OOPS, "change ownership of home directory", 
		    strerror(errno));
		return( EX_HOMEDIR );
	}

	if(skeldir) {
		/* copy the skel_dir into the home directory */
		(void) sprintf( cmdbuf, "cd %s && find . -print | cpio -pd %s",
			skeldir, homedir);

		if( system( cmdbuf ) != 0 ) {
			errmsg(M_OOPS, "copy skeleton directory into home "
			    "directory", strerror(errno));
			(void) rm_homedir( homedir );
			return( EX_HOMEDIR );
		}

		/* make sure contents in the home dirctory have correct owner */
		(void) sprintf( cmdbuf,"cd %s && find . -exec chown %ld {} \\;",
			homedir, uid );
		if( system( cmdbuf ) != 0) {
			errmsg(M_OOPS, "change owner of files home directory",
			    strerror(errno));

			(void) rm_homedir( homedir );
			return( EX_HOMEDIR );
		}

		/* and group....... */
		(void) sprintf( cmdbuf, "cd %s && find . -exec chgrp %ld {} \\;",
			homedir, gid );
		if( system( cmdbuf ) != 0) {
			errmsg(M_OOPS, "change group of files home directory",
			    strerror(errno));
			(void) rm_homedir( homedir );
			return( EX_HOMEDIR );
		}
	}
	return( EX_SUCCESS );
}

/* Remove a home directory structure */
int
rm_homedir(char *dir)
{
	(void) sprintf( cmdbuf, "rm -rf %s", dir );
		
	return( system( cmdbuf ) );
}
