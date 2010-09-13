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


/*
 * system includes
 */
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <pkginfo.h>
#include <pkgstrct.h>
#include <pkgdev.h>
#include <pkglocs.h>
#include <locale.h>
#include <libintl.h>

/*
 * consolidation pkg command library includes
 */
#include <pkglib.h>
#include <messages.h>

/*
 * local pkg command library includes
 */
#include <install.h>
#include <libinst.h>
#include <libadm.h>

/*
 * pkgadd local includes
 */
#include "quit.h"


extern struct admin adm;
extern struct pkgdev pkgdev;
extern char	*respfile;
extern char	*tmpdir;
extern int	warnflag;

static void	intf_reloc(void);

/*
 * *****************************************************************************
 * global external (public) functions
 * *****************************************************************************
 */

int
presvr4(char **ppkg, int a_nointeract)
{
	int	retcode;
	char	*tmpcmd, path[PATH_MAX];
	void	(*tmpfunc)();

	echo(MSG_INSTALLING_PSVR4);
	if (a_nointeract) {
		progerr(ERR_NOINT);
		quit(1);
		/* NOTREACHED */
	}

	if (respfile) {
		progerr(ERR_RESPFILE);
		quit(1);
		/* NOTREACHED */
	}

	/*
	 * if we were looking for a particular package, verify
	 * the first media has a /usr/options file on it
	 * which matches
	 */
	psvr4pkg(ppkg);

	/*
	 * check to see if we can guess (via Rlist) what
	 * pathnames this package is likely to install;
	 * if we can, check these against the 'contents'
	 * file and warn the administrator that these
	 * pathnames might be modified in some manner
	 */
	psvr4cnflct();

	if (chdir(tmpdir)) {
		progerr(ERR_CHDIR, tmpdir);
		quit(99);
		/* NOTREACHED */
	}

	(void) snprintf(path, sizeof (path), "%s/install/INSTALL",
			pkgdev.dirname);

	tmpcmd = tempnam(tmpdir, "INSTALL");
	if (!tmpcmd || copyf(path, tmpcmd, 0L) || chmod(tmpcmd, 0500)) {
		progerr(ERR_NOCOPY, tmpdir);
		quit(99);
		/* NOTREACHED */
	}

	echo(MSG_EXE_INSTALL_SCRIPT);

	retcode = pkgexecl(NULL, NULL, NULL, NULL, SHELL, "-c", tmpcmd,
	    pkgdev.bdevice, pkgdev.dirname, NULL);

	echo(retcode ? MSG_FAIL : gettext(MSG_SUCCEED));

	(void) unlink(tmpcmd);
	(void) chdir("/");
	(void) pkgumount(&pkgdev);

	psvr4mail(adm.mail, MSG_MAIL, retcode, *ppkg ? *ppkg : MSG_NODENAME);

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
