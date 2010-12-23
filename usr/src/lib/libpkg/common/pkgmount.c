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
 */

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */



#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pkgdev.h>
#include <pkginfo.h>
#include <sys/types.h>
#include <devmgmt.h>
#include <sys/mount.h>
#include "pkglib.h"
#include "pkglibmsgs.h"
#include "pkglocale.h"

extern void	quit(int retcode); 	/* Expected to be declared by caller! */
/* libadm.a */
extern int	getvol(char *device, char *label, int options, char *prompt);

#define	CMDSIZ	256

int
pkgmount(struct pkgdev *devp, char *pkg, int part, int nparts, int getvolflg)
{
	int	n;
	char	*pt, prompt[64], cmd[CMDSIZ];
	FILE	*pp;

	if (getuid()) {
		progerr(pkg_gt(ERR_NOTROOT));
		return (99);
	}

	if (part && nparts) {
		if (pkg) {
			(void) sprintf(prompt, pkg_gt(LABEL0), part,
			    nparts, pkg);
		} else {
			(void) sprintf(prompt, pkg_gt(LABEL1), part,
			    nparts);
		}
	} else if (pkg)
		(void) sprintf(prompt, pkg_gt(LABEL2), pkg);
	else
		(void) sprintf(prompt, pkg_gt(LABEL3));

	n = 0;
	for (;;) {
		if (!getvolflg && n)
			/*
			 * Return to caller if not prompting
			 * and error was encountered.
			 */
			return (-1);
		if (getvolflg && (n = getvol(devp->bdevice, NULL,
		    (devp->rdonly ? 0 : DM_FORMFS|DM_WLABEL), prompt))) {
			if (n == 3)
				return (3);
			if (n == 2)
				progerr(pkg_gt("unknown device <%s>"),
				    devp->bdevice);
			else
				progerr(
				    pkg_gt("unable to obtain package volume"));
			return (99);
		}

		if (devp->fstyp == NULL) {
			(void) sprintf(cmd, "%s %s", FSTYP, devp->bdevice);
			if ((pp = epopen(cmd, "r")) == NULL) {
				rpterr();
				logerr(pkg_gt(ERR_FSTYP), devp->bdevice);
				n = -1;
				continue;
			}
			cmd[0] = '\0';
			if (fgets(cmd, CMDSIZ, pp) == NULL) {
				logerr(pkg_gt(ERR_FSTYP), devp->bdevice);
				(void) pclose(pp);
				n = -1;
				continue;
			}
			if (epclose(pp)) {
				rpterr();
				logerr(pkg_gt(ERR_FSTYP), devp->bdevice);
				n = -1;
				continue;
			}
			if (pt = strpbrk(cmd, " \t\n"))
				*pt = '\0';
			if (cmd[0] == '\0') {
				logerr(pkg_gt(ERR_FSTYP), devp->bdevice);
				n = -1;
				continue;
			}
			devp->fstyp = strdup(cmd);
		}

		if (devp->rdonly) {
			n = pkgexecl(NULL, NULL, NULL, NULL, MOUNT, "-r", "-F",
			    devp->fstyp, devp->bdevice, devp->mount, NULL);
		} else {
			n = pkgexecl(NULL, NULL, NULL, NULL, MOUNT, "-F",
			    devp->fstyp, devp->bdevice, devp->mount, NULL);
		}
		if (n) {
			progerr(pkg_gt("mount of %s failed"), devp->bdevice);
			continue;
		}
		devp->mntflg++;
		break;
	}
	return (0);
}

int
pkgumount(struct pkgdev *devp)
{
	int	n = 1;
	int	retry = 10;

	if (!devp->mntflg)
		return (0);

	while (n != 0 && retry-- > 0) {
		n = pkgexecl(NULL, NULL, NULL, NULL, UMOUNT, devp->bdevice,
		    NULL);
		if (n != 0) {
			progerr(pkg_gt("retrying umount of %s"),
			    devp->bdevice);
			sleep(5);
		}
	}
	if (n == 0)
		devp->mntflg = 0;
	return (n);
}
