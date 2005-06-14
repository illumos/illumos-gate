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
 * Copyright (c) 1994, by Sun Microsytems, Inc.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * interfaces to find an executable (from libc code)
 */

/* Copyright (c) 1988 AT&T */
/* All Rights Reserved   */


#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "prb_proc_int.h"

static const char *exec_cat(const char *s1, const char *s2, char *si);

prb_status_t
find_executable(const char *name, char *ret_path)
{
	const char	 *pathstr;
	char		fname[PATH_MAX + 2];
	const char	 *cp;
	struct stat	 stat_buf;

	if (*name == '\0') {
		return (prb_status_map(ENOENT));
	}
	if ((pathstr = getenv("PATH")) == NULL) {
		if (geteuid() == 0 || getuid() == 0)
			pathstr = "/usr/sbin:/usr/bin";
		else
			pathstr = "/usr/bin:";
	}
	cp = strchr(name, '/') ? (const char *) "" : pathstr;

	do {
		cp = exec_cat(cp, name, fname);
		if (stat(fname, &stat_buf) != -1) {
			/* successful find of the file */
			(void) strncpy(ret_path, fname, PATH_MAX + 2);
			return (PRB_STATUS_OK);
		}
	} while (cp);

	return (prb_status_map(ENOENT));
}



static const char *
exec_cat(const char *s1, const char *s2, char *si)
{
	char		   *s;
	/* number of characters in s2 */
	int			 cnt = PATH_MAX + 1;

	s = si;
	while (*s1 && *s1 != ':') {
		if (cnt > 0) {
			*s++ = *s1++;
			cnt--;
		} else
			s1++;
	}
	if (si != s && cnt > 0) {
		*s++ = '/';
		cnt--;
	}
	while (*s2 && cnt > 0) {
		*s++ = *s2++;
		cnt--;
	}
	*s = '\0';
	return (*s1 ? ++s1 : 0);
}
