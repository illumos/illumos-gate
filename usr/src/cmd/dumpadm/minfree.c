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
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/statvfs.h>
#include <sys/param.h>
#include <sys/stat.h>

#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>

#include "utils.h"

static FILE *
minfree_open(const char *dir, int oflags, const char *fmode)
{
	char path[MAXPATHLEN];
	int fd;

	(void) snprintf(path, sizeof (path), "%s/minfree", dir);

	if ((fd = open(path, oflags, S_IRUSR | S_IWUSR)) >= 0)
		return (fdopen(fd, fmode));

	return (NULL);
}

int
minfree_read(const char *dir, unsigned long long *ullp)
{
	FILE *fp = minfree_open(dir, O_RDONLY, "r");

	if (fp != NULL) {
		char buf[BUFSIZ];
		int status = -1;

		if (fgets(buf, BUFSIZ, fp) != NULL) {
			if (valid_str2ull(buf, ullp))
				status = 0;
			else
				warn(gettext("\"%s/minfree\": invalid minfree "
				    "value -- %s\n"), dir, buf);
		}

		(void) fclose(fp);
		return (status);
	}

	return (-1);
}

int
minfree_write(const char *dir, unsigned long long ull)
{
	FILE *fp = minfree_open(dir, O_WRONLY | O_CREAT | O_TRUNC, "w");

	if (fp != NULL) {
		int status = fprintf(fp, "%llu\n", ull);
		(void) fclose(fp);
		return (status);
	}

	return (-1);
}

int
minfree_compute(const char *dir, char *s, unsigned long long *ullp)
{
	size_t len = strlen(s);
	unsigned long long m = 1;

	struct statvfs64 fsb;
	int pct;

	switch (s[len - 1]) {
	case '%':
		s[len - 1] = '\0';

		if (!valid_str2int(s, &pct) || pct > 100) {
			warn(gettext("invalid minfree %% -- %s\n"), s);
			return (-1);
		}

		if (statvfs64(dir, &fsb) == -1) {
			warn(gettext("failed to statvfs %s"), dir);
			return (-1);
		}

		*ullp = fsb.f_blocks * fsb.f_frsize *
		    (u_longlong_t)pct / 100ULL / 1024ULL;

		return (0);

	case 'm':
	case 'M':
		m = 1024ULL;
		/*FALLTHRU*/

	case 'k':
	case 'K':
		s[len - 1] = '\0';

		if (valid_str2ull(s, ullp)) {
			*ullp *= m;
			return (0);
		}

		warn(gettext("invalid minfree value -- %s\n"), s);
		return (-1);

	default:
		warn(gettext("expected m, k, or %% unit after "
		    "minfree -- %s\n"), s);
		return (-1);
	}
}
