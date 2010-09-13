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
 * closedir -- C library extension routine
 *
 * We use lmalloc()/lfree() rather than malloc()/free() in
 * order to allow opendir()/readdir()/closedir() to be called
 * while holding internal libc locks.
 */

#pragma weak _closedir = closedir

#include "lint.h"
#include <dirent.h>
#include <stdlib.h>
#include <unistd.h>
#include "libc.h"

int
closedir(DIR *dirp)
{
	private_DIR *pdirp = (private_DIR *)(uintptr_t)dirp;
	int fd = dirp->dd_fd;

	(void) mutex_destroy(&pdirp->dd_lock);
	lfree(dirp->dd_buf, DIRBUF);
	lfree(pdirp, sizeof (*pdirp));
	return (close(fd));
}
