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
#include <string.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <vroot/vroot.h>
#include <signal.h>
#include <errno.h>			/* errno */
#include <libintl.h>

extern	char		*sys_errlist[];
extern	int		sys_nerr;

static	void		file_lock_error(char *msg, char *file, char *str, int arg1, int arg2);

#define BLOCK_INTERUPTS sigfillset(&newset) ; \
	sigprocmask(SIG_SETMASK, &newset, &oldset)

#define UNBLOCK_INTERUPTS \
	sigprocmask(SIG_SETMASK, &oldset, &newset)

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
 * 12/6/91 Added the parameter "file_locked".  Before this parameter 
 * was added, the calling procedure would have to wait for file_lock() 
 * to return before it sets the flag. If the user interrupted "make"
 * between the time the lock was acquired and the time file_lock()
 * returns, make wouldn't know that the file has been locked, and therefore
 * it wouldn' remove the lock. Setting the flag right after locking the file
 * makes this window much smaller.
 */

int
file_lock(char *name, char *lockname, int *file_locked, int timeout)
{
	int		counter = 0;
	static char	msg[MAXPATHLEN+1];
	int		printed_warning = 0;
	int		r;
	struct stat	statb;
	sigset_t newset;
	sigset_t oldset;

	*file_locked = 0;	
	if (timeout <= 0) {
		timeout = 120;
	}
	for (;;) {
		BLOCK_INTERUPTS;
		r = symlink(name, lockname);
		if (r == 0) {
			*file_locked = 1;
			UNBLOCK_INTERUPTS;
			return 0; /* success */
		}
		UNBLOCK_INTERUPTS;

		if (errno != EEXIST) {
			file_lock_error(msg, name, (char *)"symlink(%s, %s)",
			    (int) name, (int) lockname);
			fprintf(stderr, "%s", msg);
			return errno;
		}

		counter = 0;
		for (;;) {
			sleep(1); 
			r = lstat(lockname, &statb);
			if (r == -1) {
				/*
				 * The lock must have just gone away - try 
				 * again.
				 */
				break;
			}

			if ((counter > 5) && (!printed_warning)) {
				/* Print waiting message after 5 secs */
				(void) getcwd(msg, MAXPATHLEN);
				fprintf(stderr,
					gettext("file_lock: file %s is already locked.\n"),
					name);
				fprintf(stderr,
					gettext("file_lock: will periodically check the lockfile %s for two minutes.\n"),
					lockname);
				fprintf(stderr,
					gettext("Current working directory %s\n"),
					msg);

				printed_warning = 1;
			}

			if (++counter > timeout ) {
				/*
				 * Waited enough - return an error..
				 */
				return EEXIST;
			}
		}
	}
	/* NOTREACHED */
}

/*
 * Format a message telling why the lock could not be created.
 */
static	void
file_lock_error(char *msg, char *file, char *str, int arg1, int arg2)
{
	int		len;

	sprintf(msg, gettext("Could not lock file `%s'; "), file);
	len = strlen(msg);
	sprintf(&msg[len], str, arg1, arg2);
	strcat(msg, gettext(" failed - "));
	if (errno < sys_nerr) {
		strcat(msg, strerror(errno));
	} else {
		len = strlen(msg);
		sprintf(&msg[len], "errno %d", errno);
	}
}

