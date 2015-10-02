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


#include <sys/types.h>
#include <stdio.h>
#include <userdefs.h>
#include "messages.h"
#include <unistd.h>
#include <sys/stat.h>
#include <utime.h>

#define	SBUFSZ	256

extern int access(), rm_files();

static char cmdbuf[SBUFSZ];	/* buffer for system call */

/*
 *	Move directory contents from one place to another
 */
int
move_dir(char *from, char *to, char *login, int flags)
		/* directory to move files from */
		/* dirctory to move files to */
		/* login id of owner */
		/* miscellaneous flags */
{
	size_t len = 0;
	int rc = EX_SUCCESS;
	struct stat statbuf;
	struct utimbuf times;
	/*
	 * ***** THIS IS WHERE SUFFICIENT SPACE CHECK GOES
	 */

	if (access(from, F_OK) == 0) {	/* home dir exists */
		/* move all files */
		(void) sprintf(cmdbuf,
			"cd %s && find . -print | cpio -m -pd %s",
			from, to);

		if (system(cmdbuf) != 0) {
			errmsg(M_NOSPACE, from, to);
			return (EX_NOSPACE);
		}

		/*
		 * Check that to dir is not a subdirectory of from
		 */
		len = strlen(from);
		if (strncmp(from, to, len) == 0 &&
		    strncmp(to+len, "/", 1) == 0) {
			errmsg(M_RMFILES);
			return (EX_HOMEDIR);
		}
		/* Retain the original permission and modification time */
		if (stat(from, &statbuf) == 0) {
			chmod(to, statbuf.st_mode);
			times.actime = statbuf.st_atime;
			times.modtime = statbuf.st_mtime;
			(void) utime(to, &times);

		}

		/* Remove the files in the old place */
		rc = rm_files(from, login, flags);

	}

	return (rc);
}
