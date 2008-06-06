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

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * opendir -- C library extension routine
 *
 * We use lmalloc()/lfree() rather than malloc()/free() in
 * order to allow opendir()/readdir()/closedir() to be called
 * while holding internal libc locks.
 */

#pragma weak _opendir = opendir

#include "lint.h"
#include <dirent.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

DIR *
opendir(const char *filename)
{
	int fd;
	DIR *dirp;

	if ((fd = openat(AT_FDCWD, filename,
	    O_RDONLY | O_NDELAY | O_LARGEFILE, 0)) < 0)
		return (NULL);
	if ((dirp = fdopendir(fd)) == NULL)
		(void) close(fd);
	return (dirp);
}
