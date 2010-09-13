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
 * Copyright 1993 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */


#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <pkglocs.h>
#include <locale.h>
#include <libintl.h>
#include <pkglib.h>
#include "libadm.h"

extern char	*pkgname, pkgloc[];
extern int	warnflag;

#define	ERR_RMLINK	"unable to remove options file <%s>"
#define	ERR_SYMLINK	"unable to create symbloic link from <%s> to <%s>"
#define	ERR_PREDEPEND	"unable to create predepend file <%s>"

void
predepend(char *oldpkg)
{
	FILE	*fp;
	char	path[PATH_MAX];
	char	spath[PATH_MAX];
	struct stat statbuf;

	oldpkg = strtok(oldpkg, " \t\n");
	if (oldpkg == NULL)
		return;

	(void) sprintf(path, "%s/predepend", pkgloc);
	if ((fp = fopen(path, "w")) == NULL) {
		progerr(gettext(ERR_PREDEPEND), path);
		warnflag++;
		return;
	}
	(void) fprintf(fp, "%s\n", pkgname);
	(void) fclose(fp);

	do {
		(void) sprintf(spath, "%s/%s.name", get_PKGOLD(), oldpkg);
		if (lstat(spath, &statbuf) == 0) {
			/* options file already exists */
			if (statbuf.st_mode & S_IFLNK) {
				/* remove current link */
				if (unlink(spath)) {
					progerr(gettext(ERR_RMLINK), spath);
					warnflag++;
				}
			}
		}
		if (symlink(path, spath)) {
			progerr(gettext(ERR_SYMLINK), path, spath);
			warnflag++;
		}
	} while (oldpkg = strtok(NULL, " \t\n"));
}
