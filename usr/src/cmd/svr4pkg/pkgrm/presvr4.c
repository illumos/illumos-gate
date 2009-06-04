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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */


#include <stdio.h>
#include <signal.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>	/* chmod()? definition */
#include <valtools.h>
#include <locale.h>
#include <libintl.h>
#include <pkgdev.h>
#include <pkglocs.h>
#include "install.h"
#include <pkglib.h>
#include "libadm.h"
#include "libinst.h"

/*
 * pkgadd local includes
 */

#include "quit.h"

extern struct	admin adm;
extern struct	pkgdev pkgdev;
extern char	*tmpdir;
extern int	started;

static void	intf_reloc(void);

#define	PATH_FLAGS	P_EXIST|P_ABSOLUTE|P_BLK

#define	MSG_DEVICE	"Removal of a pre-SVR4 package requires the original " \
			"medium from which the package was installed."

#define	ASK_DEVICE	"Enter the alias or pathname for the device to be " \
			"used (e.g., diskette1 or /dev/diskette)"

#define	ASK_INSERT	 "Insert the first volume for package <%s> into %s"

#define	ERR_NOCOPY	 "unable to create copy of UNINSTALL script in <%s>"

#define	ERR_NOINT	"-n option cannot be used when removing pre-SVR4 " \
			"packages"

#define	ERR_BADDEV	"Unknown or bad device <%s> specified"

#define	MSG_MAIL	"An attempt to remove the <%s> pre-SVR4 package on " \
			"<%s> completed with exit status <%d>."

#define	INFO_P4RMOK	"\nPre-SVR4 package reported successful removal.\n"

int
presvr4(char *pkg, int a_nointeract)
{
	char	alias[PATH_MAX];
	char	path[PATH_MAX];
	char	*tmpcmd;
	int	n, retcode;
	void	(*tmpfunc)();

	echo(gettext("*** Removing Pre-SVR4 Package ***"));
	if (a_nointeract != 0) {
		progerr(gettext(ERR_NOINT));
		quit(1);
	}

	/* should accept device alias?? */

	echo(gettext(MSG_DEVICE));
	for (;;) {
		if (n = ckstr(alias, NULL, PATH_MAX, NULL, NULL, NULL,
		    gettext(ASK_DEVICE)))
			return (n);

		if (devtype(alias, &pkgdev))
			continue;
		if (!pkgdev.mount || !pkgdev.bdevice) {
			logerr(gettext(ERR_BADDEV), alias);
			continue;
		}
		break;
	}
	pkgdev.mount = pkgdev.dirname = "/install";
	pkgdev.rdonly = 1;

	if (n = pkgmount(&pkgdev, pkg, 1, 0, 1))
		quit(n);

	psvr4pkg(&pkg);

	/*
	 * check to see if we can guess (via Rlist) what
	 * pathnames this package is likely to remove;
	 * if we can, check these against the 'contents'
	 * file and warn the administrator that these
	 * pathnames might be modified in some manner
	 */
	psvr4cnflct();

	if (chdir(tmpdir)) {
		progerr(gettext("unable to change directory to <%s>"), tmpdir);
		quit(99);
	}

	(void) snprintf(path, sizeof (path), "%s/install/UNINSTALL",
			"/install");
	tmpcmd = tempnam(tmpdir, "UNINSTALL");
	if (!tmpcmd || copyf(path, tmpcmd, 0) || chmod(tmpcmd, 0500)) {
		progerr(gettext(ERR_NOCOPY), tmpdir);
		quit(99);
	}

	started++;

	echo(gettext("## Executing package UNINSTALL script"));

	retcode = pkgexecl(NULL, NULL, NULL, NULL, SHELL, "-c", tmpcmd, NULL);

	(void) unlink(tmpcmd);
	if (retcode) {
		echo(gettext("\nPre-SVR4 package reported failed removal.\n"));
	} else {
		echo(gettext(INFO_P4RMOK));
	}

	psvr4mail(adm.mail, gettext(MSG_MAIL), retcode, pkg);
	(void) pkgumount(&pkgdev);

	/* tell quit to call intf_reloc on exit */

	quitSetIntfReloc(&intf_reloc);

	return (retcode);
}

/*
 * *****************************************************************************
 * static internal (private) functions
 * *****************************************************************************
 */

/*
 * When quit() gains control this function will be invoked if quitSetIntfReloc()
 * is called specifying this function - see presvr4() above for details.
 */

static void
intf_reloc(void)
{
	char	path[PATH_MAX];

	(void) snprintf(path, sizeof (path), "%s/intf_reloc", PKGBIN);
	(void) pkgexecl(NULL, NULL, NULL, NULL, SHELL, "-c", path, NULL);
}
