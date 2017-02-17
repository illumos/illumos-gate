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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#include "lint.h"
#include "file64.h"
#include "mtlib.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include "stdiom.h"

/*
 * Use fork/setsid/fork to go into background and permanently remove
 * controlling terminal.
 */
int
daemon(int nochdir, int noclose)
{
	int retv, fd;

	/*
	 * By the first fork+setsid, we disconnect from our current controlling
	 * terminal and become a session group leader.
	 */
	retv = fork();
	if (retv == -1)
		return (-1);
	if (retv != 0)
		_exit(EXIT_SUCCESS);
	if (setsid() == -1)
		return (-1);
	/*
	 * By forking again without calling setsid again, we make certain
	 * that we are not the session group leader and can never reacquire
	 * a controlling terminal.
	 */
	retv = fork();
	if (retv == -1)
		return (-1);
	if (retv != 0)
		_exit(EXIT_SUCCESS);

	if (nochdir == 0)
		(void) chdir("/");

	if (noclose == 0) {
		/*
		 * Missing the PRIV_FILE_READ privilege may be one of the
		 * reasons that prevent the opening of /dev/null to succeed.
		 */
		if ((fd = open("/dev/null", O_RDWR)) == -1)
			return (-1);

		/*
		 * Also, if any of the descriptor redirects fails we should
		 * return with error to signal to the caller that its request
		 * cannot be fulfilled properly. It is up to the caller to
		 * do the cleanup.
		 */
		if ((fd != STDIN_FILENO) && (dup2(fd, STDIN_FILENO) < 0)) {
			(void) close(fd);
			return (-1);
		}
		if ((fd != STDOUT_FILENO) && (dup2(fd, STDOUT_FILENO) < 0)) {
			(void) close(fd);
			return (-1);
		}
		if ((fd != STDERR_FILENO) && (dup2(fd, STDERR_FILENO) < 0)) {
			(void) close(fd);
			return (-1);
		}

		if (fd > STDERR_FILENO)
			(void) close(fd);
	}
	return (0);
}
