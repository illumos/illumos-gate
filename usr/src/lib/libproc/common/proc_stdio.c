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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Utility functions for buffering output to stdout, stderr while
 * process is grabbed.  Prevents infamous deadlocks due to pfiles `pgrep xterm`
 * and other varients.
 */

#include "libproc.h"
#include <stdio.h>

static int cached_stdout_fd = -1;
static int cached_stderr_fd = -1;
static int initialized = 0;

static char stdout_name[] = "/tmp/.stdoutXXXXXX";
static char stderr_name[] = "/tmp/.stderrXXXXXX";

int
proc_initstdio(void)
{
	int fd;

	(void) fflush(stdout);
	(void) fflush(stderr);

	if ((cached_stdout_fd = dup(1)) < 0) {
		return (-1);
	}

	if ((cached_stderr_fd = dup(2)) < 0) {
		(void) close(cached_stdout_fd);
		return (-1);
	}

	if ((fd = mkstemp(stdout_name)) < 0) {
		(void) close(cached_stdout_fd);
		(void) close(cached_stderr_fd);
		return (-1);
	}

	(void) unlink(stdout_name);

	if (dup2(fd, 1) < 0) {
		(void) close(fd);
		(void) close(cached_stdout_fd);
		(void) close(cached_stderr_fd);
		return (-1);
	}

	(void) close(fd);


	if ((fd = mkstemp(stderr_name)) < 0) {
		(void) dup2(cached_stdout_fd, 1);
		(void) close(cached_stdout_fd);
		(void) close(cached_stderr_fd);
		return (-1);
	}

	(void) unlink(stderr_name);

	if (dup2(fd, 2) < 0) {
		(void) close(fd);
		(void) dup2(cached_stdout_fd, 1);
		(void) close(cached_stdout_fd);
		(void) dup2(cached_stderr_fd, 2);
		(void) close(cached_stderr_fd);
		(void) close(fd);
		return (-1);
	}

	(void) close(fd);

	initialized = 1;

	return (0);
}

static int
copy_fd(int out, FILE *in, size_t len)
{
	char buffer[8192];
	int rlen, alen;
	int errors = 0;

	rewind(in);
	while (len > 0 && !errors) {
		rlen = (len > sizeof (buffer)) ? sizeof (buffer) : len;
		alen = read(fileno(in), buffer, rlen);
		if (alen == rlen) {
			if (write(out, buffer, alen) < alen)
				errors++;
			else
				len -= alen;
		}
		else
			errors++;
	}
	rewind(in);
	return (errors);
}

int
proc_flushstdio(void)
{
	size_t len;
	int errors = 0;

	/*
	 * flush any pending IO
	 */

	if (!initialized)
		return (-1);

	(void) fflush(stdout);
	(void) fflush(stderr);

	if ((len = ftell(stdout)) > 0)
		errors += copy_fd(cached_stdout_fd, stdout, len);


	if ((len = ftell(stderr)) > 0)
		errors += copy_fd(cached_stderr_fd, stderr, len);

	return (errors?-1:0);
}

int
proc_finistdio(void)
{
	if (!initialized)
		return (-1);

	if (proc_flushstdio() != 0)
		return (-1);

	(void) dup2(cached_stdout_fd, 1);
	(void) close(cached_stdout_fd);
	(void) dup2(cached_stderr_fd, 2);
	(void) close(cached_stderr_fd);

	return (0);
}
