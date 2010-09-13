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
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pkglocs.h>
#include <locale.h>
#include <libintl.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/signal.h>
#include <sys/fault.h>
#include <sys/syscall.h>
#include <pkglib.h>
#include "libadm.h"

extern int errno;

#define	ST_QUIT	1
#define	ST_OK	0

#define	LOCKFILE	".lockfile"
#define	LCKBUFSIZ	128
#define	LOCKWAIT	20	/* seconds between retries */
#define	LOCKRETRY	10	/* number of retries for a DB lock */
#define	LF_SIZE		128	/* size of governing lock file */

#define	MSG_WTING	"NOTE: Waiting for access to the package database."
#define	MSG_XWTING	"NOTE: Waiting for exclusive access to the package " \
			    "database."
#define	MSG_WTFOR	"NOTE: Waiting for %s of %s to complete."
#define	WRN_CLRLOCK	"WARNING: Stale lock installed for %s, pkg %s quit " \
			    "in %s state."
#define	WRN_CLRLOCK1	"Removing lock."
#define	ERR_MKLOCK	"unable to create governing lock file <%s>."
#define	ERR_NOLOCK	"unable to install governing lock on <%s>."
#define	ERR_NOOPEN	"unable to open <%s>."
#define	ERR_LCKTBL	"unable to lock <%s> - lock table full."
#define	ERR_LCKREM	"unable to lock <%s> - remote host unavailable."
#define	ERR_BADLCK	"unable to lock <%s> - unknown error."
#define	ERR_DEADLCK	"unable to lock <%s> - deadlock condition."

static pid_t lock_pid;
static int lock_fd, lock_is_applied;
static char lock_name[PKGSIZ];
static char lock_pkg[PKGSIZ];
static char lock_place[PKGSIZ];
static unsigned int lock_state;
static char lockbuf[LCKBUFSIZ];
static char lockpath[PATH_MAX];

#define	LOCK_NAME_OLD_PKG	"old version pkg command"
#define	LOCK_PKG_UNKNOWN	"unknown package"
#define	LOCK_PLACE_UNKNOWN	"unknown"

/*
 * This function writes the PID, effective utility name, package name,
 * current progress of the utility and the exit state to the lockfile in
 * support of post mortem operations.
 */
static int
wrlockdata(int fd, int this_pid, char *this_name,
    char *this_pkg, char *this_place, unsigned int this_state)
{
	if (this_pid < 0 || *this_name == '\000')
		return (0);

	(void) memset(lockbuf, 0, LCKBUFSIZ);

	(void) snprintf(lockbuf, sizeof (lockbuf),
			"%d %s %s %s %d\n", this_pid, this_name, this_pkg,
			this_place, this_state);

	(void) lseek(fd, 0, SEEK_SET);
	if (write(fd, lockbuf, LF_SIZE) == LF_SIZE)
		return (1);
	else
		return (0);
}

/*
 * This function reads the lockfile to obtain the PID and name of the lock
 * holder. Upon those rare circumstances that an older version of pkgadd
 * created the lock, this detects that zero-length file and provides the
 * appropriate data. Since this data is only used if an actual lock (from
 * lockf()) is detected, a manually created .lockfile will not result in a
 * message.
 */
static void
rdlockdata(int fd)
{
	(void) lseek(fd, 0, SEEK_SET);
	if (read(fd, lockbuf, LF_SIZE) != LF_SIZE) {
		lock_pid = 0;
		(void) strlcpy(lock_name, LOCK_NAME_OLD_PKG,
						sizeof (lock_name));

		(void) strlcpy(lock_pkg, LOCK_PKG_UNKNOWN,
						sizeof (lock_pkg));

		(void) strlcpy(lock_place, LOCK_PLACE_UNKNOWN,
						sizeof (lock_place));

		lock_state = ST_OK;
	} else {
		/* LINTED format argument contains unbounded string specifier */
		(void) sscanf(lockbuf, "%ld %s %s %s %u", &lock_pid,
			lock_name, lock_pkg, lock_place, &lock_state);
	}
}

static void
do_alarm(int n)
{
#ifdef lint
	int i = n;
	n = i;
#endif	/* lint */
	(void) signal(SIGALRM, do_alarm);
	(void) alarm(LOCKWAIT);
}

/*
 * This establishes a locked status file for a pkgadd, pkgrm or swmtool - any
 * of the complex package processes. Since numerous packages currently use
 * installf and removef in preinstall scripts, we can't enforce a contents
 * file write lock throughout the install process. In 2.7 we will enforce the
 * write lock and allow this lock to serve as a simple information carrier
 * which can be used by installf and removef too.
 * Arguments:
 *  util_name - the name of the utility that is claiming the lock
 *  pkg_name - the package that is being locked (or "all package")
 *  place - a string of ascii characters that defines the initial "place" where
 *    the current operation is - this is updated by lockupd() and is a string
 *    is used fr post mortem operations if the utility should quit improperly.
 * Returns (int):
 *  == 0 - failure
 *  != 0 - success
 */

int
lockinst(char *util_name, char *pkg_name, char *place)
{
	int	fd, retry_cnt;

	/* assume "initial" if no "place" during processing specified */

	if ((place == (char *)NULL) || (*place == '\0')) {
		place = "initial";
	}

	(void) snprintf(lockpath, sizeof (lockpath),
			"%s/%s", get_PKGADM(), LOCKFILE);

	/* If the exit file is not present, create it. */
	/* LINTED O_CREAT without O_EXCL specified in call to open() */
	if ((fd = open(lockpath, O_RDWR | O_CREAT, 0600)) == -1) {
		progerr(gettext(ERR_MKLOCK), lockpath);
		return (0);
	}

	lock_fd = fd;

	retry_cnt = LOCKRETRY;
	lock_is_applied = 0;

	(void) signal(SIGALRM, do_alarm);
	(void) alarm(LOCKWAIT);

	/*
	 * This tries to create the lock LOCKRETRY times waiting LOCKWAIT
	 * seconds between retries.
	 */
	do {

		if (lockf(fd, F_LOCK, 0)) {
			/*
			 * Try to read the status of the last (or current)
			 * utility.
			 */
			rdlockdata(fd);

			logerr(gettext(MSG_WTFOR), lock_name, lock_pkg);
		} else {	/* This process has the lock. */
			rdlockdata(fd);

			if (lock_state != 0) {
				logerr(gettext(WRN_CLRLOCK), lock_name,
				    lock_pkg, lock_place);
				logerr(gettext(WRN_CLRLOCK1));
			}

			lock_pid = getpid();
			(void) strlcpy(lock_name, (util_name) ?
			    util_name : gettext("unknown"), sizeof (lock_name));

			(void) strlcpy(lock_pkg, (pkg_name) ?
			    pkg_name : gettext("unknown"), sizeof (lock_pkg));

			(void) wrlockdata(fd, lock_pid, lock_name,
			    lock_pkg, place, ST_QUIT);
			lock_is_applied = 1;
			break;
		}
	} while (retry_cnt--);

	(void) signal(SIGALRM, SIG_IGN);

	if (!lock_is_applied) {
		progerr(gettext(ERR_NOLOCK), lockpath);
		return (0);
	}

	return (1);
}

/*
 * This function updates the utility progress data in the lock file. It is
 * used for post mortem operations if the utility should quit improperly.
 */
void
lockupd(char *place)
{
	(void) wrlockdata(lock_fd, lock_pid, lock_name, lock_pkg, place,
			ST_QUIT);
}

/*
 * This clears the governing lock and closes the lock file. If this was
 * called already, it just returns.
 */
void
unlockinst(void)
{
	if (lock_is_applied) {
		(void) wrlockdata(lock_fd, lock_pid, lock_name, lock_pkg,
			"finished", ST_OK);

		/*
		 * If close() fails, we can't be sure the lock has been
		 * removed, so we assume the worst in case this function is
		 * called again.
		 */
		if (close(lock_fd) != -1)
			lock_is_applied = 0;
	}
}
