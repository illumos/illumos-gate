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
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <locale.h>
#include <libintl.h>
#include <pkglocs.h>
#include "pkglib.h"
#include "libinst.h"
#include "libadm.h"

extern int	warnflag;

#define	ERR_UNLINK	"unable to unlink <%s>"

void
predepend(char *oldpkg)
{
	struct stat status;
	char	spath[PATH_MAX];

	oldpkg = strtok(oldpkg, " \t\n");
	if (oldpkg == NULL)
		return;

	do {
		(void) sprintf(spath, "%s/%s.name", get_PKGOLD(), oldpkg);
		if (lstat(spath, &status) == 0) {
			if (status.st_mode & S_IFLNK) {
				if (unlink(spath)) {
					progerr(gettext(ERR_UNLINK), spath);
					warnflag++;
				}
				return;
			}
		}
	} while (oldpkg = strtok(NULL, " \t\n"));
}
