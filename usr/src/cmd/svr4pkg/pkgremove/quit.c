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


/*
 * System includes
 */

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <locale.h>
#include <libintl.h>

/*
 * consolidation pkg command library includes
 */

#include <pkglib.h>

/*
 * local pkg command library includes
 */

#include "install.h"
#include "libadm.h"
#include "libinst.h"
#include "messages.h"

#define	MAILCMD	"/usr/bin/mail"

/* lockinst.c */
extern void	unlockinst(void);

/* mntinfo.c */
extern int	unmount_client(void);

extern char	*msgtext;
extern char	*pkginst;

extern int	started;
extern int	dreboot;	/* != 0 if reboot required after installation */
extern int	failflag;	/* != 0 if fatal error has occurred (1) */
extern int	ireboot;	/* != 0 if immediate reboot required */
extern int	warnflag;	/* != 0 if non-fatal error has occurred (2) */

extern struct admin	adm;

/*
 * exported functions
 */

void			quit(int retcode);
void			quitSetSilentExit(boolean_t a_silentExit);
void			quitSetZoneName(char *a_zoneName);
sighdlrFunc_t		*quitGetTrapHandler(void);

/*
 * forward declarations
 */

static void		mailmsg(int retcode);
static void		quitmsg(int retcode);
static void		trap(int signo);

static char		*zoneName = (char *)NULL;
static boolean_t	silentExit = B_FALSE;
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
quitGetTrapHandler()
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

	/*
	 * In the event that this quit() was called prior to completion of
	 * the task, do an unlockinst() just in case.
	 */
	unlockinst();

	/* unmount the mounts that are our responsibility. */
	(void) unmount_client();

	/* send mail to appropriate user list */
	mailmsg(retcode);

	/* display message about this installation */
	quitmsg(retcode);

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

	/* if there is no pkgname, no message to report */
	if (pkginst != (char *)NULL) {
		ptext(stderr, qreason(3, retcode, 0, includeZonename),
			pkginst, zoneName);
	}

	if (retcode && !started) {
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

	if (!started || (adm.mail == NULL))
		return;

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

	if (msgtext) {
		ptext(pp, gettext(msgtext));
	}

	(void) strcpy(utsbuf.nodename, gettext("(unknown)"));
	(void) uname(&utsbuf);
	ptext(pp, qreason(4, retcode, 0, includeZonename), pkginst,
		utsbuf.nodename, zoneName);

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
