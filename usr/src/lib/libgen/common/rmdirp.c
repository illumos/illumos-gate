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
 * rmdirp() removes directories in path "d". Removal starts from the
 * right most directory in the path and goes backward as far as possible.
 * The remaining path, which is not removed for some reason, is stored in "d1".
 * If nothing remains, "d1" is empty.
 *
 * rmdirp()
 * returns 0 only if it succeeds in removing every directory in d.
 * returns -1 if removal stops because of errors other than the following.
 * returns -2 if removal stops when "." or ".." is encountered in path.
 * returns -3 if removal stops because it's the current directory.
 */

#include <sys/types.h>
#include <libgen.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>

static int dotdot(char *);

int
rmdirp(char *d, char *d1)
{
	struct stat64	st, cst;
	int		currstat;
	char		*slash;

	slash = strrchr(d, '/');
	currstat = stat64(".", &cst);

	/* Starts from right most element */

	while (d) {
		/* If it's under current directory */

		if (slash == NULL) {
			/* Stop if it's . or .. */

			if (dotdot(d)) {
				(void) strcpy(d1, d);
				return (-2);
			}
			/* Stop if can not stat it */

		} else {	/* If there's a slash before it */

			/* If extra / in the end */
			if (slash != d) {
				if (++slash == strrchr(d, '\0')) {
					*(--slash) = '\0';
					slash = strrchr(d, '/');
					continue;
				} else {
					slash--;
				}
			}

			/* Stop if it's . or .. */

			if (dotdot(++slash)) {
				(void) strcpy(d1, d);
				return (-2);
			}
			slash--;

			/* Stop if can not stat it */

			if (stat64(d, &st) < 0) {
				(void) strcpy(d1, d);
				return (-1);
			}
			if (currstat == 0) {
				/* Stop if it's current directory */
				if ((st.st_ino == cst.st_ino) &&
				    (st.st_dev == cst.st_dev)) {
					(void) strcpy(d1, d);
					return (-3);
				}
			}
		} /* End of else */


		/* Remove it */
		if (rmdir(d) != 0) {
			(void) strcpy(d1, d);
			return (-1);
		}

		/* Have reached left end, break */

		if (slash == NULL || slash == d)
			break;

		/* Go backward to next directory */
		*slash = '\0';
		slash = strrchr(d, '/');
	}
	*d1 = '\0';
	return (0);
}


static int
dotdot(char *dir)
{
	if (strcmp(dir, ".") == 0 || strcmp(dir, "..") == 0)
		return (-1);
	return (0);
}
