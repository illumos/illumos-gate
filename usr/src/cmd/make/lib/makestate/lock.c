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
 * Copyright 2004 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <errno.h>		/* errno */

#if defined(_LP64)
/*
 * The symbols _sys_errlist and _sys_nerr are not visible in the
 * LP64 libc.  Use strerror(3C) instead.
 */
#else  /* #_LP64 */
extern	char *		sys_errlist[];
extern	int		sys_nerr;
#endif /* #_LP64 */

static	void		file_lock_error();

/*
 * This code stolen from the NSE library and changed to not depend
 * upon any NSE routines or header files.
 *
 * Simple file locking.
 * Create a symlink to a file.  The "test and set" will be
 * atomic as creating the symlink provides both functions.
 *
 * The timeout value specifies how long to wait for stale locks
 * to disappear.  If the lock is more than 'timeout' seconds old
 * then it is ok to blow it away.  This part has a small window
 * of vunerability as the operations of testing the time,
 * removing the lock and creating a new one are not atomic.
 * It would be possible for two processes to both decide to blow
 * away the lock and then have process A remove the lock and establish
 * its own, and then then have process B remove the lock which accidentily
 * removes A's lock rather than the stale one.
 *
 * A further complication is with the NFS.  If the file in question is
 * being served by an NFS server, then its time is set by that server.
 * We can not use the time on the client machine to check for a stale
 * lock.  Therefore, a temp file on the server is created to get
 * the servers current time.
 *
 * Returns an error message.  NULL return means the lock was obtained.
 *
 */
char *
file_lock(char * name, char * lockname, int timeout)
{
	int		r;
	int		fd;
	struct	stat	statb;
	struct	stat	fs_statb;
	char		tmpname[MAXPATHLEN];
	static	char	msg[MAXPATHLEN];

	if (timeout <= 0) {
		timeout = 15;
	}
	for (;;) {
		r = symlink(name, lockname);
		if (r == 0) {
			return (NULL);
		}
		if (errno != EEXIST) {
			file_lock_error(msg, name,
			    (const char *)"symlink(%s, %s)", name, lockname);
			return (msg);
		}
		for (;;) {
			(void) sleep(1);
			r = lstat(lockname, &statb);
			if (r == -1) {
				/*
				 * The lock must have just gone away - try
				 * again.
				 */
				break;
			}

			/*
			 * With the NFS the time given a file is the time on
			 * the file server.  This time may vary from the
			 * client's time.  Therefore, we create a tmpfile in
			 * the same directory to establish the time on the
			 * server and use this time to see if the lock has
			 * expired.
			 */
			(void) sprintf(tmpname, "%s.XXXXXX", lockname);
			(void) mktemp(tmpname);
			fd = creat(tmpname, 0666);
			if (fd != -1) {
				(void) close(fd);
			} else {
				file_lock_error(msg, name,
				    (const char *)"creat(%s)", tmpname);
				return (msg);
			}
			if (stat(tmpname, &fs_statb) == -1) {
				file_lock_error(msg, name,
				    (const char *)"stat(%s)", tmpname);
				return (msg);
			}
			(void) unlink(tmpname);
			if (statb.st_mtime + timeout < fs_statb.st_mtime) {
				/*
				 * The lock has expired - blow it away.
				 */
				(void) unlink(lockname);
				break;
			}
		}
	}
	/* NOTREACHED */
}

/*
 * Format a message telling why the lock could not be created.
 */
/* VARARGS4 */
static	void
file_lock_error(char * msg, char * file, const char * str, char * arg1,
	char * arg2)
{
	int	len;

	(void) sprintf(msg, "Could not lock file `%s'; ", file);
	len = strlen(msg);
	(void) sprintf(&msg[len], str, arg1, arg2);
	(void) strcat(msg, " failed - ");
#if defined(_LP64)
	/* Needs to be changed to use strerror(3C) instead. */
	len = strlen(msg);
	(void) sprintf(&msg[len], "errno %d", errno);
#else  /* #_LP64 */
	if (errno < sys_nerr) {
		(void) strcat(msg, sys_errlist[errno]);
	} else {
		len = strlen(msg);
		(void) sprintf(&msg[len], "errno %d", errno);
	}
#endif /* #_LP64 */
}
