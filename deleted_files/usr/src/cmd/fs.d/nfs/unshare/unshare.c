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
 * nfs unshare
 */
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/param.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include "../lib/sharetab.h"
#include "../lib/nfslogtab.h"

#define	RET_OK		0
#define	RET_ERR		32

static int do_unshare();
static void pr_err(char *, ...);
static int sharetab_del();
static int nfslogtab_deactivate();
static void usage();

int
main(argc, argv)
	int argc;
	char **argv;
{
	char dir[MAXPATHLEN];

	if (argc != 2) {
		usage();
		exit(1);
	}

	/* Don't drop core if the NFS module isn't loaded. */
	signal(SIGSYS, SIG_IGN);

	if (realpath(argv[1], dir) == NULL) {
		pr_err("%s: %s\n", argv[1], strerror(errno));
		exit(RET_ERR);
	}

	return (do_unshare(dir));
}

static int
do_unshare(path)
	char *path;
{
	int logging = 0;

	if (exportfs(path, NULL) < 0) {
		if (errno == EINVAL)
			pr_err("%s: not shared\n", path);
		else
			pr_err("%s: %s\n", path, strerror(errno));
		return (RET_ERR);
	}

	if (sharetab_del(path, &logging) < 0)
		return (RET_ERR);

	if (logging) {
		if (nfslogtab_deactivate(path) < 0)
			return (RET_ERR);
	}

	return (RET_OK);
}

/*
 * Remove an entry from the sharetab file.
 */
static int
sharetab_del(path, logging)
	char *path;
	int *logging;
{
	FILE *f;

	f = fopen(SHARETAB, "r+");
	if (f == NULL) {
		pr_err("%s: %s\n", SHARETAB, strerror(errno));
		return (-1);
	}
	if (lockf(fileno(f), F_LOCK, 0L) < 0) {
		pr_err("cannot lock %s: %s\n", SHARETAB, strerror(errno));
		(void) fclose(f);
		return (-1);
	}
	if (remshare(f, path, logging) < 0) {
		pr_err("remshare\n");
		(void) fclose(f);
		return (-1);
	}
	(void) fclose(f);
	return (0);
}

/*
 * Deactivate an entry from the nfslogtab file.
 */
static int
nfslogtab_deactivate(path)
	char *path;
{
	FILE *f;
	int error = 0;

	f = fopen(NFSLOGTAB, "r+");
	if (f == NULL) {
		error = errno;
		pr_err("%s: %s\n", NFSLOGTAB, strerror(error));
		goto out;
	}
	if (lockf(fileno(f), F_LOCK, 0L) < 0) {
		error = errno;
		pr_err("cannot lock %s: %s\n", NFSLOGTAB, strerror(error));
		goto out;
	}
	if (logtab_deactivate(f, NULL, path, NULL) == -1) {
		error = -1;
		pr_err("logtab_deactivate\n");
		goto out;
	}

out:	if (error) {
		pr_err("could not deactivate %s entry in %s\n",
		path, NFSLOGTAB);
	}

	if (f != NULL)
		(void) fclose(f);

	return (error);
}

static void
usage()
{
	(void) fprintf(stderr, "Usage: unshare { pathname | resource }\n");
}

/*VARARGS1*/
static void
pr_err(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	(void) fprintf(stderr, "nfs unshare: ");
	(void) vfprintf(stderr, fmt, ap);
	va_end(ap);
}
