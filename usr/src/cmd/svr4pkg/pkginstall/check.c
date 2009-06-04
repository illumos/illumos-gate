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
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>	/* mkdir declaration is here? */
#include <unistd.h>
#include <errno.h>
#include <utmpx.h>
#include <dirent.h>
#include <sys/types.h>
#include <locale.h>
#include <libintl.h>
#include <pkgstrct.h>
#include <pkglocs.h>
#include "install.h"
#include <pkglib.h>
#include "libadm.h"
#include "libinst.h"
#include "pkginstall.h"

extern struct admin adm;
extern struct cfextra **extlist;
extern int	ckquit, nocnflct, nosetuid, rprcflag;
extern char	ilockfile[], rlockfile[], instdir[], savlog[],
		tmpdir[], pkgloc[], pkgloc_sav[], pkgbin[], pkgsav[],
		*pkginst, *msgtext;
extern char	saveSpoolInstallDir[];

static boolean_t	preinstallCheck = B_FALSE;
static char		*zoneName = (char *)NULL;

static char	ask_cont[100];

#define	DISPSIZ	20	/* number of items to display on one page */

#define	MSG_RUNLEVEL	"\\nThe current run-level of this machine is <%s>, " \
			"which is not a run-level suggested for installation " \
			"of this package.  Suggested run-levels (in order of " \
			"preference) include:"
#define	HLP_RUNLEVEL	"If this package is not installed in a run-level " \
			"which has been suggested, it is possible that the " \
			"package may not install or operate properly.  If " \
			"you wish to follow the run-level suggestions, " \
			"answer 'n' to stop installation of the package."
#define	MSG_STATECHG	"\\nTo change states, execute\\n\\tshutdown -y " \
			"-i%s -g0\\nafter exiting the installation process. " \
			"Please note that after changing states you " \
			"may have to mount appropriate filesystem(s) " \
			"in order to install this package."

#define	ASK_CONFLICT	"Do you want to install these conflicting files"
#define	MSG_CONFLICT	"\\nThe following files are already installed on the " \
			"system and are being used by another package:"
#define	MSG_ROGUE	"\\n* - conflict with a file which does not " \
			"belong to any package."
#define	HLP_CONFLICT	"If you choose to install conflicting files, the " \
			"files listed above will be overwritten and/or have " \
			"their access permissions changed.  If you choose " \
			"not to install these files, installation will " \
			"proceed but these specific files will not be " \
			"installed.  Note that sane operation of the " \
			"software being installed may require these files " \
			"be installed; thus choosing to not to do so may " \
			"cause inapropriate operation.  If you wish to stop " \
			"installation of this package, enter 'q' to quit."

#define	ASK_SETUID	"Do you want to install these as setuid/setgid files"
#define	MSG_SETUID	"\\nThe following files are being installed with " \
			"setuid and/or setgid permissions:"
#define	MSG_OVERWR	"\\n* - overwriting a file which is also " \
			"setuid/setgid."
#define	HLP_SETUID	"The package being installed appears to contain " \
			"processes which will have their effective user or " \
			"group ids set upon execution.  History has shown " \
			"that these types of processes can be a source of " \
			"security problems on your system.  If you choose " \
			"not to install these as setuid files, installation " \
			"will proceed but these specific files will be " \
			"installed as regular files with setuid and/or " \
			"setgid permissions reset.  Note that sane " \
			"operation of the software being installed may " \
			"require that these files be installed with setuid " \
			"or setgid permissions as delivered; thus choosing " \
			"to install them as regular files may cause " \
			"inapropriate operation.  If you wish to stop " \
			"installation of this package, enter 'q' to quit."
#define	MSG_PARTINST	"\\nThe installation of this package was previously " \
			"terminated and installation was never successfully " \
			"completed."
#define	MSG_PARTREM	"\\nThe removal of this package was terminated at " \
			"some point in time, and package removal was only " \
			"partially completed."
#define	HLP_PARTIAL	"Installation of partially installed packages is " \
			"normally allowable, but some packages providers " \
			"may suggest that a partially installed package be " \
			"completely removed before re-attempting " \
			"installation.  Check the documentation provided " \
			"with this package, and then answer 'y' if you feel " \
			"it is advisable to continue the installation process."

#define	HLP_SPACE	"It appears that there is not enough free space on " \
			"your system in which to install this package.  It " \
			"is possible that one or more filesystems are not " \
			"properly mounted.  Neither installation of the " \
			"package nor its operation can be guaranteed under " \
			"these conditions.  If you choose to disregard this " \
			"warning, enter 'y' to continue the installation " \
			"process."
#define	HLP_DEPEND	"The package being installed has indicated a " \
			"dependency on the existence (or non-existence) " \
			"of another software package.  If this dependency is " \
			"not met before continuing, the package may not " \
			"install or operate properly.  If you wish to " \
			"disregard this dependency, answer 'y' to continue " \
			"the installation process."

#define	MSG_PRIV	"\\nThis package contains scripts which will be " \
			"executed with super-user permission during the " \
			"process of installing this package."
#define	HLP_PRIV	"During the installation of this package, certain " \
			"scripts provided with the package will execute with " \
			"super-user permission.  These scripts may modify or " \
			"otherwise change your system without your " \
			"knowledge.  If you are certain of the origin and " \
			"trustworthiness of the package being installed, " \
			"answer 'y' to continue the installation process."

#define	ASK_CONT	"Do you want to continue with the installation of <%s>"
#define	HLP_CONT	"If you choose 'y', installation of this package " \
			"will continue.  If you want to stop installation " \
			"of this package, choose 'n'."

#define	MSG_MKPKGDIR	"unable to make packaging directory <%s>"

#define	MSG_CKCONFL_GZ	"## Checking for conflicts with packages already " \
			"installed."
#define	MSG_CKCONFL_LZ	"## Checking for conflicts with packages already " \
			"installed in zone <%s>."
#define	MSG_CKDEPEND_GZ	"## Verifying package dependencies."
#define	MSG_CKDEPEND_LZ	"## Verifying package dependencies in zone <%s>."
#define	MSG_CKSPACE_GZ	"## Verifying disk space requirements."
#define	MSG_CKSPACE_LZ	"## Verifying disk space requirements in zone <%s>."
#define	MSG_CKUID_GZ	"## Checking for setuid/setgid programs."
#define	MSG_CKUID_LZ	"## Checking for setuid/setgid programs in zone <%s>."

#define	MSG_SCRFND	"Package scripts were found."
#define	MSG_UIDFND	"Setuid/setgid processes detected."
#define	MSG_ATTRONLY	"!%s %s <attribute change only>"

#define	MSG_CONTDISP	"[Hit <RETURN> to continue display]"

#define	ERR_NO_RUNST	"unable to determine current run-state"
#define	ERR_DEPFAILED	"Dependency checking failed."
#define	ERR_SPCFAILED	"Space checking failed."
#define	ERR_CNFFAILED	"Conflict checking failed."
#define	ERR_BADFILE	"packaging file <%s> is corrupt"

/*
 * Return value:	int
 *			0 - success
 *			1 - end of file
 *			2 - undefined error
 *			3 - answer was not "y"/was "q"
 *			4 - quit action taken
 *			5 - interactive mode required
 * If "preinstallcheck" is set to B_TRUE:
 *			8 - partial install detected
 *			9 - partial removal detected
 */

int
ckpartial(void)
{
	char	ans[MAX_INPUT];
	int	n;

	if (ADM(partial, "nocheck")) {
		return (0);
	}

	if (access(ilockfile, F_OK) == 0) {
		if (preinstallCheck == B_TRUE) {
			return (8);	/* partial install detected */
		}

		(void) snprintf(ask_cont, sizeof (ask_cont),
			gettext(ASK_CONT), pkginst);

		msgtext = gettext(MSG_PARTINST);
		ptext(stderr, msgtext);

		if (ADM(partial, "quit")) {
			return (4);
		}

		if (echoGetFlag() == B_FALSE) {
			return (5);
		}

		msgtext = NULL;

		ckquit = 0;
		if (n = ckyorn(ans, NULL, NULL, gettext(HLP_PARTIAL),
				ask_cont)) {
			return (n);
		}

		if (strchr("yY", *ans) == NULL) {
			return (3);
		}
		ckquit = 1;
	}

	if (access(rlockfile, F_OK) == 0) {
		if (preinstallCheck == B_TRUE) {
			return (9);	/* partial removal detected */
		}

		(void) snprintf(ask_cont, sizeof (ask_cont),
			gettext(ASK_CONT), pkginst);


		msgtext = gettext(MSG_PARTREM);
		ptext(stderr, msgtext);

		if (ADM(partial, "quit")) {
			return (4);
		}

		if (echoGetFlag() == B_FALSE) {
			return (5);
		}

		msgtext = NULL;

		ckquit = 0;
		if (n = ckyorn(ans, NULL, NULL, gettext(HLP_PARTIAL),
			ask_cont)) {
			return (n);
		}

		if (strchr("yY", *ans) == NULL) {
			return (3);
		}
		ckquit = 1;
	}

	return (0);
}

/*
 * Return value:	int
 *			0 - success
 *			1 - end of file
 *			2 - undefined error
 *			3 - answer was not "y"/was "q"
 *			4 - quit action taken
 *			5 - interactive mode required
 *			99 - fatal error
 */

int
ckrunlevel(void)
{
	struct utmpx utmpx;
	struct utmpx *putmpx;
	char	ans[MAX_INPUT], *pt, *istates, *pstate;
	int	n;
	char	*uxstate;

	if (ADM(runlevel, "nocheck")) {
		return (0);
	}

	pt = getenv("ISTATES");
	if (pt == NULL) {
		return (0);
	}

	utmpx.ut_type = RUN_LVL;
	putmpx = getutxid(&utmpx);
	if (putmpx == NULL) {
		progerr(gettext(ERR_NO_RUNST));
		return (99);
	}

	(void) snprintf(ask_cont, sizeof (ask_cont),
			gettext(ASK_CONT), pkginst);

	/*
	 * this cryptic code is trying to pull the run level
	 * out of the utmpx entry...the level starts in column
	 * 11 - looks like "run-level %c"
	 */
	uxstate = strtok(&putmpx->ut_line[10], " \t\n");

	istates = qstrdup(pt);
	if ((pt = strtok(pt, " \t\n, ")) == NULL) {
		return (0); /* no list is no list */
	}

	pstate = pt;
	do {
		if (strcmp(pt, uxstate) == 0) {
			free(istates);
			return (0);
		}
	} while (pt = strtok(NULL, " \t\n, "));

	if (preinstallCheck == B_FALSE) {
		msgtext = gettext(MSG_RUNLEVEL);
		ptext(stderr, msgtext, uxstate);
	} else {
		(void) fprintf(stdout, "runlevel=%s", uxstate);
	}

	pt = strtok(istates, " \t\n, ");
	do {
		if (preinstallCheck == B_FALSE) {
			ptext(stderr, "\\t%s", pt);
		} else {
			(void) fprintf(stdout, ":%s", pt);
		}
	} while (pt = strtok(NULL, " \t\n, "));

	if (preinstallCheck == B_TRUE) {
		(void) fprintf(stdout, "\n");
	}

	free(istates);

	if (preinstallCheck == B_TRUE) {
		return (4);
	}

	if (ADM(runlevel, "quit")) {
		return (4);
	}

	if (echoGetFlag() == B_FALSE) {
		return (5);
	}

	msgtext = NULL;

	ckquit = 0;
	if (n = ckyorn(ans, NULL, NULL, gettext(HLP_RUNLEVEL),
		ask_cont)) {
		return (n);
	}

	ckquit = 1;

	if (strchr("yY", *ans) != NULL) {
		return (0);
	} else {
		if (preinstallCheck == B_FALSE) {
			ptext(stderr, gettext(MSG_STATECHG), pstate);
		}
		return (3);
	}
}

/*
 * Return value:	int
 *			0 - success
 *			1 - end of file
 *			2 - undefined error
 *			3 - answer was not "y"/was "q"
 *			4 - quit action taken
 *			5 - interactive mode required
 */

int
ckdepend(void)
{
	int	n;
	char	ans[MAX_INPUT];
	char	path[PATH_MAX];

	if (ADM(idepend, "nocheck")) {
		return (0);
	}

	(void) snprintf(path, sizeof (path), "%s/%s", instdir, DEPEND_FILE);
	if (access(path, F_OK) != 0) {
		return (0); /* no dependency file provided by package */
	}

	if (zoneName == (char *)NULL) {
		echo(gettext(MSG_CKDEPEND_GZ));
	} else {
		echo(gettext(MSG_CKDEPEND_LZ), zoneName);
	}

	if (dockdeps(path, 0, preinstallCheck)) {
		(void) snprintf(ask_cont, sizeof (ask_cont),
			gettext(ASK_CONT), pkginst);
		msgtext = gettext(ERR_DEPFAILED);

		if (preinstallCheck == B_TRUE) {
			return (4);
		}

		if (ADM(idepend, "quit")) {
			return (4);
		}

		if (echoGetFlag() == B_FALSE) {
			return (5);
		}

		msgtext = NULL;

		ckquit = 0;
		if (n = ckyorn(ans, NULL, NULL, gettext(HLP_DEPEND),
			ask_cont)) {
			return (n);
		}

		if (strchr("yY", *ans) == NULL) {
			return (3);
		}

		ckquit = 1;
	}

	return (0);
}

void
cksetZoneName(char *a_zoneName)
{
	zoneName = a_zoneName;
}

void
cksetPreinstallCheck(boolean_t a_preinstallCheck)
{
	preinstallCheck = a_preinstallCheck;
}

/*
 * Return value:	int
 *			0 - success
 *			1 - end of file
 *			2 - undefined error
 *			3 - answer was not "y"/was "q"
 *			4 - quit action taken
 *			5 - interactive mode required
 */
int
ckspace(void)
{
	int	n;
	char	ans[MAX_INPUT];
	char	path[PATH_MAX];

	if (ADM(space, "nocheck")) {
		return (0);
	}

	if (zoneName == (char *)NULL) {
		echo(gettext(MSG_CKSPACE_GZ));
	} else {
		echo(gettext(MSG_CKSPACE_LZ), zoneName);
	}

	(void) snprintf(path, sizeof (path), "%s/install/space", instdir);
	if (access(path, F_OK) == 0) {
		n = dockspace(path);
	} else {
		n = dockspace(NULL);
	}

	if (n) {
		msgtext = gettext(ERR_SPCFAILED);
		(void) snprintf(ask_cont, sizeof (ask_cont),
			gettext(ASK_CONT), pkginst);

		if (preinstallCheck == B_TRUE) {
			return (4);
		}

		if (ADM(space, "quit")) {
			return (4);
		}

		if (echoGetFlag() == B_FALSE) {
			return (5);
		}

		msgtext = NULL;

		ckquit = 0;
		n = ckyorn(ans, NULL, NULL, gettext(HLP_SPACE), ask_cont);
		if (n != 0) {
			return (n);
		}

		if (strchr("yY", *ans) == NULL) {
			return (3);
		}

		ckquit = 1;
	}
	return (0);
}

void
ckdirs(void)
{
	char	path[PATH_MAX];

	if (mkpath(get_PKGADM())) {
		if (preinstallCheck == B_TRUE) {
			(void) fprintf(stdout, "ckdirs=%s\n", get_PKGADM());
		} else {
			progerr(gettext(MSG_MKPKGDIR), get_PKGADM());
		}
		quit(99);
	}

	(void) snprintf(path, sizeof (path), "%s/admin", get_PKGADM());

	if (mkpath(path)) {
		if (preinstallCheck == B_TRUE) {
			(void) fprintf(stdout, "ckdirs=%s\n", path);
		} else {
			progerr(gettext(MSG_MKPKGDIR), path);
		}
		quit(99);
	}

	(void) snprintf(path, sizeof (path), "%s/logs", get_PKGADM());

	if (mkpath(path)) {
		if (preinstallCheck == B_TRUE) {
			(void) fprintf(stdout, "ckdirs=%s\n", path);
		} else {
			progerr(gettext(MSG_MKPKGDIR), path);
		}
		quit(99);
	}

	if (mkpath(PKGSCR)) {
		if (preinstallCheck == B_TRUE) {
			(void) fprintf(stdout, "ckdirs=%s\n", PKGSCR);
		} else {
			progerr(gettext(MSG_MKPKGDIR), PKGSCR);
		}
		quit(99);
	}

	if (mkpath(get_PKGLOC())) {
		if (preinstallCheck == B_TRUE) {
			(void) fprintf(stdout, "ckdirs=%s\n", get_PKGLOC());
		} else {
			progerr(gettext(MSG_MKPKGDIR), get_PKGLOC());
		}
		quit(99);
	}
}

/*
 * Return value:	int
 *			0 - success
 *			99 - failure
 */

int
ckpkgdirs(void)
{
	boolean_t nonExistentPkgloc = B_FALSE;

	/*
	 * If pkgloc doesn't exist make sure it gets removed after creating
	 * it if this is a preinstall check. All dryrun and preinstallation
	 * checks must not modify the file system.
	 */

	if (access(pkgloc, F_OK) != 0) {
		nonExistentPkgloc = B_TRUE;
	}

	if (mkpath(pkgloc)) {
		if (preinstallCheck == B_TRUE) {
			(void) fprintf(stdout, "ckdirs=%s\n", pkgloc);
		} else {
			progerr(gettext(MSG_MKPKGDIR), pkgloc);
		}
		return (99);
	}

	if (mkpath(pkgbin)) {
		if (preinstallCheck == B_TRUE) {
			(void) fprintf(stdout, "ckdirs=%s\n", pkgbin);
		} else {
			progerr(gettext(MSG_MKPKGDIR), pkgbin);
		}
		return (99);
	}

	if (mkpath(pkgsav)) {
		if (preinstallCheck == B_TRUE) {
			(void) fprintf(stdout, "ckdirs=%s\n", pkgsav);
		} else {
			progerr(gettext(MSG_MKPKGDIR), pkgsav);
		}
		return (99);
	}

	if (!is_spool_create() && mkpath(saveSpoolInstallDir)) {
		if (preinstallCheck == B_TRUE) {
			(void) fprintf(stdout, "ckdirs=%s\n", pkgsav);
		} else {
			progerr(gettext(MSG_MKPKGDIR), pkgsav);
		}
		return (99);
	}

	if (preinstallCheck && nonExistentPkgloc) {
		rrmdir(pkgloc);
	}

	return (0);
}

/*
 * Return value:	int
 *			0 - success
 *			1 - end of file
 *			2 - undefined error
 *			3 - answer was not "y"/was "q"
 *			4 - quit action taken
 *			5 - interactive mode required
 */

int
ckconflct(void)
{
	int	i, n, count, has_a_rogue = 0;
	char	ans[MAX_INPUT];

	if (ADM(conflict, "nochange")) {
		nocnflct++;
		return (0);
	}

	if (ADM(conflict, "nocheck")) {
		return (0);
	}

	if (zoneName == (char *)NULL) {
		echo(gettext(MSG_CKCONFL_GZ));
	} else {
		echo(gettext(MSG_CKCONFL_LZ), zoneName);
	}

	count = 0;
	for (i = 0; extlist[i]; i++) {
		struct cfent *ept;
		struct mergstat *mstat;

		if (extlist[i]->cf_ent.ftype == 'i') {
			continue;
		}

		ept = &(extlist[i]->cf_ent);
		mstat = &(extlist[i]->mstat);

		if (is_remote_fs(ept->path, &(extlist[i]->fsys_value)) &&
			!is_fs_writeable(ept->path,
				&(extlist[i]->fsys_value))) {
			continue;
		}

		/*
		 * If no other package claims it or it's from a continuation
		 * file, skip it.
		 */
		if (!mstat->shared || mstat->preloaded) {
			continue;
		}

		if (ept->ftype == 'e') {
			continue;
		}

		if (mstat->rogue) {
			has_a_rogue = 1;
		}

		if (mstat->contchg) {
			if (!count++) {
				if (preinstallCheck == B_FALSE) {
					ptext(stderr, gettext(MSG_CONFLICT));
				}
			} else if ((echoGetFlag() == B_TRUE) &&
					((count % DISPSIZ) == 0)) {
				echo(gettext(MSG_CONTDISP));
				(void) getc(stdin);
			}
			/*
			 * NOTE : The leading "!" in this string forces
			 * puttext() to print leading white space.
			 */

			if (preinstallCheck == B_FALSE) {
				ptext(stderr, "!%s %s",
					(mstat->rogue) ? "*" : " ", ept->path);
			} else {
				(void) fprintf(stdout,
					"conflict-contents=%s\n", ept->path);
			}
		} else if (mstat->attrchg) {
			if (!count++) {
				if (preinstallCheck == B_FALSE) {
					ptext(stderr, gettext(MSG_CONFLICT));
				}
			} else if ((echoGetFlag() == B_TRUE) &&
					((count % DISPSIZ) == 0)) {
				echo(gettext(MSG_CONTDISP));
				(void) getc(stdin);
			}
			if (preinstallCheck == B_FALSE) {
				ptext(stderr, gettext(MSG_ATTRONLY),
					(mstat->rogue) ? "*" : " ", ept->path);
			} else {
				(void) fprintf(stdout,
					"conflict-attributes=%s\n", ept->path);
			}
		}
	}

	if (count) {
		if (has_a_rogue) {
			if (preinstallCheck == B_FALSE) {
				ptext(stderr, gettext(MSG_ROGUE));
			}
		}

		msgtext = gettext(ERR_CNFFAILED);

		if (preinstallCheck == B_TRUE) {
			return (4);
		}

		if (ADM(conflict, "quit")) {
			return (4);
		}

		if (echoGetFlag() == B_FALSE) {
			return (5);
		}

		msgtext = NULL;

		if (n = ckyorn(ans, NULL, NULL, gettext(HLP_CONFLICT),
			gettext(ASK_CONFLICT))) {
			return (n);
		}

		if (strchr("yY", *ans) == NULL) {
			ckquit = 0;
			(void) snprintf(ask_cont, sizeof (ask_cont),
				gettext(ASK_CONT), pkginst);

			if (n = ckyorn(ans, NULL, NULL, gettext(HLP_CONT),
				ask_cont)) {
				return (n);
			}

			if (strchr("yY", *ans) == NULL) {
				return (3);
			}
			ckquit = 1;
			nocnflct++;
			rprcflag++;
		}
	}
	return (0);
}

/*
 * Return value:	int
 *			0 - success
 *			1 - end of file
 *			2 - undefined error
 *			3 - answer was not "y"/was "q"
 *			4 - quit action taken
 *			5 - interactive mode required
 */

int
cksetuid(void)
{
	int	i, n, count, overwriting = 0;
	char	ans[MAX_INPUT];

	/* See if the administrative defaults already resolve this check. */
	if (ADM(setuid, "nocheck")) {
		return (0);
	}

	if (ADM(setuid, "nochange")) {
		nosetuid++;	/* Do not install processes as setuid/gid. */
		return (0);
	}

	/* The administrative defaults require review of the package. */

	if (zoneName == (char *)NULL) {
		echo(gettext(MSG_CKUID_GZ));
	} else {
		echo(gettext(MSG_CKUID_LZ), zoneName);
	}

	count = 0;
	for (i = 0; extlist[i]; i++) {
		int overwr;
		struct mergstat *mstat = &(extlist[i]->mstat);

		/*
		 * Provide the administrator with info as to whether there is
		 * already a setuid process in place. This is only necessary
		 * to help the administrator decide whether or not to lay
		 * down the process, it doesn't have anything to do with the
		 * administrative defaults.
		 */
		if (mstat->osetuid || mstat->osetgid) {
			overwr = 1;
			overwriting = 1;
		} else
			overwr = 0;

		if (mstat->setuid || mstat->setgid) {
			if (!count++) {
				if (preinstallCheck == B_FALSE) {
					ptext(stderr, gettext(MSG_SETUID));
				}
			} else if ((echoGetFlag() == B_TRUE) &&
					((count % DISPSIZ) == 0)) {
				echo(gettext(MSG_CONTDISP));
				(void) getc(stdin);
			}
			/*
			 * NOTE : The leading "!" in these strings forces
			 * puttext() to print leading white space.
			 */

			if (mstat->setuid && mstat->setgid) {
				if (preinstallCheck == B_FALSE) {
					ptext(stderr, gettext(
						"!%s %s <setuid %s setgid %s>"),
						(overwr) ? "*" : " ",
						extlist[i]->cf_ent.path,
						extlist[i]->cf_ent.ainfo.owner,
						extlist[i]->cf_ent.ainfo.group);
				} else {
					(void) fprintf(stdout, "setuid=%s:%s\n",
						extlist[i]->cf_ent.path,
						extlist[i]->cf_ent.ainfo.owner);
					(void) fprintf(stdout, "setgid=%s:%s\n",
						extlist[i]->cf_ent.path,
						extlist[i]->cf_ent.ainfo.group);
				}
			} else if (mstat->setuid) {
				if (preinstallCheck == B_FALSE) {
					ptext(stderr, gettext(
						"!%s %s <setuid %s>"),
						(overwr) ? "*" : " ",
						extlist[i]->cf_ent.path,
						extlist[i]->cf_ent.ainfo.owner);
				} else {
					(void) fprintf(stdout, "setuid=%s:%s\n",
						extlist[i]->cf_ent.path,
						extlist[i]->cf_ent.ainfo.owner);
				}
			} else if (mstat->setgid) {
				if (preinstallCheck == B_FALSE) {
					ptext(stderr, gettext(
						"!%s%s <setgid %s>"),
						(overwr) ? "*" : " ",
						extlist[i]->cf_ent.path,
						extlist[i]->cf_ent.ainfo.group);
				} else {
					(void) fprintf(stdout, "setgid=%s:%s\n",
						extlist[i]->cf_ent.path,
						extlist[i]->cf_ent.ainfo.group);
				}
			}
		}
	}

	if (count) {
		if (overwriting) {
			if (preinstallCheck == B_FALSE) {
				ptext(stderr, gettext(MSG_OVERWR));
			} else {
				(void) fprintf(stdout,
					"setuid-overwrite=true\n");
			}
		}

		msgtext = gettext(MSG_UIDFND);

		if (preinstallCheck == B_TRUE) {
			return (4);
		}

		if (ADM(setuid, "quit")) {
			return (4);
		}
		if (echoGetFlag() == B_FALSE) {
			return (5);
		}
		msgtext = NULL;

		if (n = ckyorn(ans, NULL, NULL, gettext(HLP_SETUID),
			gettext(ASK_SETUID))) {
			return (n);
		}
		if (strchr("yY", *ans) == NULL) {
			ckquit = 0;
			(void) snprintf(ask_cont, sizeof (ask_cont),
				gettext(ASK_CONT), pkginst);
			if (n = ckyorn(ans, NULL, NULL, gettext(HLP_CONT),
				ask_cont)) {
				return (n);
			}
			if (strchr("yY", *ans) == NULL) {
				return (3);
			}
			ckquit = 1;
			nosetuid++;
			rprcflag++;
		}
	}

	return (0);
}

/*
 * Return value:	int
 *			0 - success
 *			1 - end of file
 *			2 - undefined error
 *			3 - answer was not "y"/was "q"
 *			4 - quit action taken
 *			5 - interactive mode required
 */

int
ckpriv(void)
{
	struct dirent *dp;
	DIR	*dirfp;
	int	n, found;
	char	ans[MAX_INPUT], path[PATH_MAX];

	if (ADM(action, "nocheck")) {
		return (0);
	}

	(void) snprintf(path, sizeof (path), "%s/install", instdir);
	if ((dirfp = opendir(path)) == NULL) {
		return (0);
	}

	found = 0;
	while ((dp = readdir(dirfp)) != NULL) {
		if (strcmp(dp->d_name, "preinstall") == 0 ||
			strcmp(dp->d_name, "postinstall") == 0 ||
			strncmp(dp->d_name, "i.", 2) == 0) {
			found++;
			break;
		}
	}
	(void) closedir(dirfp);

	if (found) {
		if (preinstallCheck == B_FALSE) {
			ptext(stderr, gettext(MSG_PRIV));
			msgtext = gettext(MSG_SCRFND);
		}
		(void) snprintf(ask_cont, sizeof (ask_cont),
				gettext(ASK_CONT), pkginst);

		if (preinstallCheck == B_TRUE) {
			return (4);
		}

		if (ADM(action, "quit")) {
			return (4);
		}

		if (echoGetFlag() == B_FALSE) {
			return (5);
		}

		msgtext = NULL;

		ckquit = 0;
		if (n = ckyorn(ans, NULL, NULL, gettext(HLP_PRIV),
			ask_cont)) {
			return (n);
		}

		if (strchr("yY", *ans) == NULL) {
			return (3);
		}
		ckquit = 1;
	}

	return (0);
}

/*
 * Return value:	int
 *			0 - success
 *			99 - failure
 */

int
ckpkgfiles(void)
{
	register int i;
	struct cfent	*ept;
	int	errflg;
	char	source[PATH_MAX];

	errflg = 0;
	for (i = 0; extlist[i]; i++) {
		ept = &(extlist[i]->cf_ent);
		if (ept->ftype != 'i') {
			continue;
		}

		if (ept->ainfo.local) {
			(void) snprintf(source, sizeof (source),
				"%s/%s", instdir, ept->ainfo.local);
		} else if (strcmp(ept->path, PKGINFO) == 0) {
			(void) snprintf(source, sizeof (source),
				"%s/%s", instdir, ept->path);
		} else {
			(void) snprintf(source, sizeof (source),
				"%s/install/%s", instdir, ept->path);
		}
		if (cverify(0, &ept->ftype, source, &ept->cinfo, 1)) {
			errflg++;
			if (preinstallCheck == B_FALSE) {
				progerr(gettext(ERR_BADFILE), source);
				logerr(getErrbufAddr());
			} else {
				(void) fprintf(stdout, "ckpkgfilebad=%s",
					source);
			}
		}
	}

	if (errflg) {
		return (99);
	} else {
		return (0);
	}
}
