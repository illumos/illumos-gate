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
 * groups - show group memberships
 */
/* LINTLIBRARY PROTOLIB1 */

#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

extern struct group *getgrgid();
extern struct passwd *getpwnam();
extern int _getgroupsbymember(const char *, gid_t[], int, int);

static void showgroups();

static int ngroups_max;

int
main(int argc, char *argv[])
{
	int xval = 0;
	struct passwd *pw;

	ngroups_max = sysconf(_SC_NGROUPS_MAX);

	if (ngroups_max < 0) {
		(void) fprintf(stderr,
			"groups: could not get configuration info\n");
		exit(1);
	}

	if (ngroups_max == 0)
		exit(0);

	if (argc == 1) {

		if ((pw = getpwuid(getuid())) == NULL) {
			(void) fprintf(stderr, "groups: No passwd entry\n");
			xval = 1;
		} else
			showgroups(pw);

	} else while (*++argv) {

		if ((pw = getpwnam(*argv)) == NULL) {
			(void) fprintf(stderr,
				"groups: %s : No such user\n", *argv);
			xval = 1;
		} else {
			if (argc > 2)
				(void) printf("%s : ", *argv);
			showgroups(pw);
		}
	}

	return (xval);

}

static void
showgroups(struct passwd *pw)
{
	struct group *gr;
	static gid_t *groups = NULL;
	int ngroups;
	int i;

	if (groups == NULL) {
		if ((groups = (gid_t *)calloc((uint_t)ngroups_max,
						sizeof (gid_t))) == 0) {
			(void) fprintf(stderr,
				"allocation of %d bytes failed\n",
				ngroups_max * sizeof (gid_t));
			exit(1);
		}
	}
	groups[0] = pw->pw_gid;

	ngroups = _getgroupsbymember(pw->pw_name, groups, ngroups_max, 1);

	if (gr = getgrgid(groups[0]))
		(void) printf("%s", gr->gr_name);
	else
		(void) printf("%d", (int)pw->pw_gid);

	for (i = 1; i < ngroups; i++) {
		if ((gr = getgrgid(groups[i])))
			(void) printf(" %s", gr->gr_name);
		else
			(void) printf(" %d", (int)groups[i]);
	}

	(void) printf("\n");
}
