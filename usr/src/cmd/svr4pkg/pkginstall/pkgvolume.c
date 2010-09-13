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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */


#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/mount.h>
#include <pkgdev.h>
#include <locale.h>
#include <libintl.h>
#include <pkglib.h>
#include <libadm.h>
#include <libinst.h>

extern char	instdir[], pkgbin[];

void
pkgvolume(struct pkgdev *devp, char *pkg, int part, int nparts)
{
	static int	cpart = 0;
	char	path[PATH_MAX];
	int	n;

	if (devp->cdevice)
		return;
	if (cpart == part)
		return;
	cpart = part;

	if (part == 1) {
		if (ckvolseq(instdir, 1, nparts)) {
			progerr(gettext("corrupt directory structure"));
			quit(99);
		}
		cpart = 1;
		return;
	}

	if (devp->mount == NULL) {
		if (ckvolseq(instdir, part, nparts)) {
			progerr(gettext("corrupt directory structure"));
			quit(99);
		}
		return;
	}

	for (;;) {
		(void) chdir("/");
		if (n = pkgumount(devp)) {
			progerr(gettext("attempt to unmount <%s> failed (%d)"),
				devp->bdevice, n);
			quit(99);
		}
		if (n = pkgmount(devp, pkg, part, nparts, 1))
			quit(n);
		(void) sprintf(path, "%s/%s", devp->dirname, pkg);
		if (ckvolseq(path, part, nparts) == 0)
			break;
	}
}
