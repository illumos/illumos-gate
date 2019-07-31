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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */


#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/utsname.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <pkgdev.h>
#include <pkglocs.h>
#include <locale.h>
#include <libintl.h>
#include <errno.h>
#include <pkglib.h>
#include "install.h"
#include "dryrun.h"
#include "libadm.h"
#include "libinst.h"
#include "pkginstall.h"
#include "messages.h"

/* main.c */
extern char		*pkgdrtarg;
extern struct cfextra	**extlist;

extern struct	admin adm;
extern struct	pkgdev pkgdev;	/* holds info about the installation device */

extern int	dparts;
extern int	dreboot;	/* != 0 if reboot required after installation */
extern int	failflag;	/* != 0 if fatal error has occurred (1) */
extern int	ireboot;	/* != 0 if immediate reboot required */
extern int	warnflag;	/* != 0 if non-fatal error has occurred (2) */

extern char	tmpdir[];
extern char	pkgloc[];
extern char	pkgloc_sav[];
extern char	*msgtext;
extern char	*pkginst;
extern char	*pkgname;

/*
 * exported functions
 */

void		quit(int retcode);
void		quitSetZoneName(char *a_zoneName);
sighdlrFunc_t	*quitGetTrapHandler(void);

/*
 * forward declarations
 */

static void		trap(int signo);
static void		mailmsg(int retcode);
static void		quitmsg(int retcode);

static boolean_t	silentExit = B_FALSE;
static boolean_t	pkgaskFlag = B_FALSE;
static boolean_t	installStarted = B_FALSE;
static boolean_t	updatingExistingPackage = B_FALSE;

static char		*dstreamTempDir = (char *)NULL;
static char		*zoneName = (char *)NULL;
static int		includeZonename = 0;
static int		trapEntered = 0;

/*
 * *****************************************************************************
 * global external (public) functions
 * *****************************************************************************
 */

/*
 * Name:	quitGetTrapHandler
 * Description:	return address of this modules "signal trap" handler
 * Arguments:	void
 * Returns:	sighdlrFunc_t
 *			The address of the trap handler that can be passed to
 *			the signal() type system calls
 */

sighdlrFunc_t *
quitGetTrapHandler(void)
{
	return (&trap);
}

/*
 * Name:	quitSetZoneName
 * Description:	set the zone name the program is running in
 * Arguments:	a_zoneName - pointer to string representing the name of the zone
 *			that the program is running in
 * Returns:	void
 */

void
quitSetZoneName(char *a_zoneName)
{
	zoneName = a_zoneName;
	if ((zoneName == (char *)NULL || *zoneName == '\0')) {
		includeZonename = 0;
	} else {
		includeZonename = 1;
	}
}

/*
 * Name:	quitSetDstreamTmpdir
 * Description:	set the name of a temporary directory that contains package
 *		streams to be removed when quit() is called
 * Arguments:	a_dstreamTempDir - pointer to string representing the path
 *			to the temporary directory to remove when quit()
 *			is called
 * Returns:	void
 */

void
quitSetDstreamTmpdir(char *a_dstreamTempDir)
{
	dstreamTempDir = a_dstreamTempDir;
}

/*
 * Name:	quitSetUpdatingExisting
 * Description:	set the "updating existing" flag - used in conjunction
 *		with the "install started" flag to determine the type
 *		of cleanup to be done when quit() is called
 * Arguments:	a_updatingExistingPackage - indicates whether or not existing
 *			packages are being updated (B_TRUE) or new packages
 *			are being installed (B_FALSE)
 * Returns:	void
 */

void
quitSetUpdatingExisting(boolean_t a_updatingExistingPackage)
{
	updatingExistingPackage = a_updatingExistingPackage;
}

/*
 * Name:	quitSetInstallStarted
 * Description:	set the "install started" flag - used in conjunction
 *		with the "updating existing" flag to determine the type
 *		of cleanup to be done when quit() is called, and the
 *		type of message to be output for the "reason" why quit()
 *		was called
 * Arguments:	a_installStarted - indicates whether or not installation
 *			has started
 * Returns:	void
 */

void
quitSetInstallStarted(boolean_t a_installStarted)
{
	installStarted = a_installStarted;
}

/*
 * Name:	quitSetPkgask
 * Description:	set the "pkgask is being run" flag - used to determine
 *		the type of message to be output for the "reason" why
 *		quit() was called
 * Arguments:	a_pkgaskflag - indicates whether or not pkgask is being run
 * Returns:	void
 */

void
quitSetPkgask(boolean_t a_pkgaskFlag)
{
	pkgaskFlag = a_pkgaskFlag;
}

/*
 * Name:	quitSetSilentExit
 * Description:	set the "silent exit" flag - if silent exit is TRUE, then
 *		no messages are output by quit() when it is called
 * Arguments:	a_silentExit - indicates whether or not silent exit is set
 * Returns:	void
 */

void
quitSetSilentExit(boolean_t a_silentExit)
{
	silentExit = a_silentExit;
}

/*
 * Name:	quit
 * Description:	cleanup and exit
 * Arguments:	a_retcode - the code to use to determine final exit status;
 *			if this is NOT "99" and if a "ckreturnFunc" is
 *			set, then that function is called with a_retcode
 *			to set the final exit status.
 *		Valid values are:
 *		0 - success
 *		1 - package operation failed (fatal error)
 *		2 - non-fatal error (warning)
 *		3 - user selected quit (operation interrupted)
 *		4 - admin settings prevented operation
 *		5 - interaction required and -n (non-interactive) specified
 *		"10" is added to indicate "immediate reboot required"
 *		"20" is be added to indicate "reboot after install required"
 *		99 - do not interpret the code - just exit "99"
 * Returns:	<<this function does not return - calls exit()>>
 */

void
quit(int retcode)
{
	/* disable interrupts */

	(void) signal(SIGINT, SIG_IGN);
	(void) signal(SIGHUP, SIG_IGN);

	/* process return code if not quit(99) */

	if (retcode != 99) {
		if ((retcode % 10) == 0) {
			if (failflag) {
				retcode += 1;
			} else if (warnflag) {
				retcode += 2;
			}
		}

		if (ireboot) {
			retcode = (retcode % 10) + 20;
		}
		if (dreboot) {
			retcode = (retcode % 10) + 10;
		}
	}

	/* if set remove dstream temporary directory */

	if (dstreamTempDir != (char *)NULL) {
		echoDebug(DBG_REMOVING_DSTREAM_TMPDIR, dstreamTempDir);
		(void) rrmdir(dstreamTempDir);
		dstreamTempDir = (char *)NULL;
	}

	/* If we're in dryrun mode, write out the dryrun file(s). */
	if (in_dryrun_mode()) {
		char exit_msg[200];
		set_dr_info(EXITCODE, retcode);
		if (failflag || warnflag) {
			set_dr_exitmsg(msgtext);
		} else {
			/* LINTED variable format specified */
			(void) snprintf(exit_msg, sizeof (exit_msg),
				qreason(1, retcode, installStarted,
					includeZonename),
					(pkginst ? pkginst : "unknown"),
					zoneName);
			set_dr_exitmsg(exit_msg);
		}

		write_dryrun_file(extlist);
		ptext(stderr, MSG_DRYRUN_DONE);
		ptext(stderr, MSG_NOCHANGE);

		if (tmpdir[0] != '\0')
			(void) rrmdir(tmpdir);

	} else {
		/* fix bug #1082589 that deletes root file */
		if (tmpdir[0] != '\0') {
			(void) rrmdir(tmpdir);
		}

		/* send mail to appropriate user list */
		mailmsg(retcode);

		/* display message about this installation */
		quitmsg(retcode);
	}

	/*
	 * In the event that this quit() was called prior to completion of
	 * the task, do an unlockinst() just in case.
	 */
	unlockinst();

	/* Unmount anything that's our responsibility. */
	(void) unmount_client();

	/*
	 * No need to umount device since calling process
	 * was responsible for original mount
	 */

	if (!updatingExistingPackage) {
		if (!installStarted && pkgloc[0]) {
			/*
			 * install not yet started; if package install
			 * location is defined, remove the package.
			 */
			echoDebug(DBG_QUIT_REMOVING_PKGDIR, pkgloc);

			(void) chdir("/");
			if (pkgloc[0]) {
				(void) rrmdir(pkgloc);
			}
		}
	} else {
		if (!installStarted) {
			/*
			 * If we haven't started, but have already done
			 * the <PKGINST>/install directory rename, then
			 * remove the new <PKGINST>/install directory
			 * and rename <PKGINST>/install.save back to
			 * <PKGINST>/install.
			 */
			if (pkgloc_sav[0] && !access(pkgloc_sav, F_OK)) {
				if (pkgloc[0] && !access(pkgloc, F_OK))
					(void) rrmdir(pkgloc);
				if (rename(pkgloc_sav, pkgloc) == -1) {
					progerr(ERR_PACKAGEBINREN,
						pkgloc_sav, pkgloc);
				}
			}
		} else {
			if (pkgloc_sav[0] && !access(pkgloc_sav, F_OK)) {
				echoDebug(DBG_QUIT_REMOVING_PKGSAV, pkgloc_sav);
				(void) rrmdir(pkgloc_sav);
			}
		}
	}

	/*
	 * pkginst can be null if an administration setting doesn't all
	 * the package to be installed. Make sure pkginst exeists before
	 * updating the DB
	 */

	if (dparts > 0)
		ds_skiptoend(pkgdev.cdevice);
	(void) ds_close(1);

	/* Free the filesystem table. */
	fs_tab_free();

	/* Free the package information lists. */
	pinfo_free();

	/* Free all stragglers. */
	bl_free(BL_ALL);
	(void) pathdup(NULL);

	/* Free regfiles. */
	regfiles_free();

	/* final exit debugging message */

	echoDebug(DBG_EXIT_WITH_CODE, retcode);

	exit(retcode);
	/*NOTREACHED*/
}

/*
 * *****************************************************************************
 * static internal (private) functions
 * *****************************************************************************
 */

static void
quitmsg(int retcode)
{
	if (silentExit == B_TRUE) {
		return;
	}

	(void) putc('\n', stderr);
	if (pkgaskFlag) {
		ptext(stderr, qreason(0, retcode, installStarted,
			includeZonename), zoneName);
	} else if (pkginst) {
		ptext(stderr, qreason(1, retcode, installStarted,
			includeZonename), pkginst, zoneName);
	}

	if (retcode && !installStarted) {
		ptext(stderr, MSG_NOCHANGE);
	}
}

static void
mailmsg(int retcode)
{
	struct utsname utsbuf;
	FILE	*pp;
	char	*cmd;
	size_t	len;

	if (silentExit == B_TRUE) {
		return;
	}

	if (!installStarted || pkgaskFlag || (adm.mail == NULL)) {
		return;
	}

	len = strlen(adm.mail) + sizeof (MAILCMD) + 2;
	cmd = calloc(len, sizeof (char));
	if (cmd == NULL) {
		logerr(WRN_NOMAIL);
		return;
	}

	(void) snprintf(cmd, len, "%s %s", MAILCMD, adm.mail);
	if ((pp = popen(cmd, "w")) == NULL) {
		logerr(WRN_NOMAIL);
		return;
	}

	if (msgtext)
		ptext(pp, msgtext);

	(void) strcpy(utsbuf.nodename, MSG_NODENAME);
	(void) uname(&utsbuf);

	ptext(pp, qreason(2, retcode, installStarted, includeZonename),
		pkgname, utsbuf.nodename, pkginst, zoneName);

	if (pclose(pp)) {
		logerr(WRN_FLMAIL);
	}
}

/*
 * Name:	trap
 * Description:	signal handler connected via quitGetTrapHandler()
 * Arguments:	signo - [RO, *RO] - (int)
 *			Integer representing the signal that caused the trap
 *			to this function to occur
 * Returns:	<< NONE >>
 * NOTE:	This function exits the program after doing mandatory cleanup.
 * NOTE:	Even though quit() should NOT return, there is a call to _exit()
 *		put after each call to quit() just in case quit() ever returned
 *		by mistake.
 */

static void
trap(int signo)
{
	/* prevent reentrance */

	if (trapEntered++ != 0) {
		return;
	}

	if ((signo == SIGINT) || (signo == SIGHUP)) {
		quit(3);
		_exit(3);
	}
	quit(1);
	_exit(1);
}
