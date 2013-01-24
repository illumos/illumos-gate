/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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

/*
 * Copyright (c) 2013, Joyent, Inc. All rights reserved.
 */

/*
 * utmpx.c - utmpx utility routines
 *
 * Since svc.startd(1M) places utmpx records for its launched instances, it must
 * also mark them as dead once completed.
 */

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <errno.h>
#include <pthread.h>
#include <sac.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <utmpx.h>
#include <fcntl.h>

#include "startd.h"

static const char rlevels[] = { 'S', '0', '1', '2', '3', '4', '5', '6', 0 };
static int n_prev[] = { 0, 0, 0, 0, 0, 0, 0, 0 };

static pthread_mutex_t utmpx_lock;
static int utmpx_truncated = 0;

#define	USEC_PER_MSEC	1000

int
utmpx_mark_init(pid_t pid, char *prefix)
{
	struct utmpx ut, *oldu;
	int tmplen;
	int ret;

	while (st->st_initial && !utmpx_truncated)
		(void) usleep(200 * USEC_PER_MSEC);

	/*
	 * Clean out any preexisting records for this PID, as they must be
	 * inaccurate.
	 */
	utmpx_mark_dead(pid, 0, B_TRUE);

	/*
	 * Construct a new record with the appropriate prefix.
	 */
	(void) memset(&ut, 0, sizeof (ut));
	(void) strncpy(ut.ut_user, ".startd", sizeof (ut.ut_user));
	ut.ut_pid = pid;

	ut.ut_id[0] = ut.ut_id[1] = ut.ut_id[2] = ut.ut_id[3] = (char)SC_WILDC;

	for (ret = 0; ret < strlen(prefix); ret++)
		ut.ut_id[ret] = prefix[ret];

	ut.ut_type = INIT_PROCESS;
	(void) time(&ut.ut_tv.tv_sec);

	for (;;) {
		MUTEX_LOCK(&utmpx_lock);
		setutxent();

		if ((oldu = getutxid(&ut)) != NULL) {
			/*
			 * Copy in the old "line" and "host" fields.
			 */
			bcopy(oldu->ut_line, ut.ut_line, sizeof (ut.ut_line));
			bcopy(oldu->ut_host, ut.ut_host, sizeof (ut.ut_host));
			ut.ut_syslen = (tmplen = strlen(ut.ut_host)) ?
			    min(tmplen + 1, sizeof (ut.ut_host)) : 0;
		}

		if (makeutx(&ut) != NULL)
			break;

		if (errno != EROFS)
			log_framework(LOG_WARNING,
			    "makeutx failed, retrying: %s\n", strerror(errno));

		MUTEX_UNLOCK(&utmpx_lock);

		(void) sleep(1);
	}

	updwtmpx(WTMPX_FILE, &ut);

	endutxent();
	MUTEX_UNLOCK(&utmpx_lock);

	return (ret);
}

void
utmpx_mark_dead(pid_t pid, int status, boolean_t blocking)
{
	struct utmpx *up;
	int logged = 0;

	for (;;) {
		int found = 0;

		MUTEX_LOCK(&utmpx_lock);
		setutxent();

		while (up = getutxent()) {
			if (up->ut_pid == pid) {
				found = 1;

				if (up->ut_type == DEAD_PROCESS) {
					/*
					 * Cleaned up elsewhere.
					 */
					endutxent();
					MUTEX_UNLOCK(&utmpx_lock);
					return;
				}

				up->ut_type = DEAD_PROCESS;
				up->ut_exit.e_termination = WTERMSIG(status);
				up->ut_exit.e_exit = WEXITSTATUS(status);
				(void) time(&up->ut_tv.tv_sec);

				if (pututxline(up) != NULL) {
					/*
					 * Now attempt to add to the end of the
					 * wtmp and wtmpx files.  Do not create
					 * if they don't already exist.
					 */
					updwtmpx(WTMPX_FILE, up);
					endutxent();
					MUTEX_UNLOCK(&utmpx_lock);

					return;
				}
			}
		}

		endutxent();
		MUTEX_UNLOCK(&utmpx_lock);

		if (!found || !blocking)
			return;

		if (!logged) {
			log_framework(LOG_INFO, "retrying utmpx_dead on PID "
			    "%ld\n", pid);
			logged++;
		}

		(void) sleep(1);
	}
}

static void
utmpx_check()
{
	struct stat sb;

	if (stat(_UTMPX_FILE, &sb) == 0 &&
	    sb.st_mode != (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH))
		(void) chmod(_UTMPX_FILE, S_IRUSR | S_IWUSR | S_IRGRP |
		    S_IROTH);

	if (stat(_WTMPX_FILE, &sb) == 0 &&
	    sb.st_mode != (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH))
		(void) chmod(_WTMPX_FILE, S_IRUSR | S_IWUSR | S_IRGRP |
		    S_IROTH);
}

/*
 * Retrieve the runlevel utmpx entry if there is one; used to recover
 * state when svc.startd is restarted.
 */
char
utmpx_get_runlevel(void)
{
	struct utmpx *up;
	char rl = '\0';

	MUTEX_LOCK(&utmpx_lock);
	setutxent();

	while (up = getutxent()) {
		if (up->ut_type == RUN_LVL &&
		    sscanf(up->ut_line, RUNLVL_MSG, &rl) == 1)
			break;
	}
	endutxent();
	MUTEX_UNLOCK(&utmpx_lock);

	return (rl);
}

void
utmpx_set_runlevel(char runlevel, char oldrl, boolean_t do_bump)
{
	struct utmpx u;
	struct utmpx *oup;
	size_t tmplen;
	int i;

	if (runlevel == 's')
		runlevel = 'S';
	if (oldrl == 's')
		oldrl = 'S';

	bzero(&u, sizeof (struct utmpx));

	u.ut_id[0] = u.ut_id[1] = u.ut_id[2] = u.ut_id[3] = '\0';
	u.ut_pid = 0;
	u.ut_type = RUN_LVL;

	(void) time(&u.ut_tv.tv_sec);

	MUTEX_LOCK(&utmpx_lock);
	setutxent();

	if ((oup = getutxid(&u)) != NULL) {
		bcopy(oup->ut_host, u.ut_host, sizeof (u.ut_host));
		bcopy(oup->ut_line, u.ut_line, sizeof (u.ut_line));
		bcopy(oup->ut_user, u.ut_user, sizeof (u.ut_user));

		tmplen = strlen(u.ut_host);
		if (tmplen)
			u.ut_syslen = min(tmplen + 1, sizeof (u.ut_host));
		else
			u.ut_syslen =  0;
	}

	if (oldrl != '\0')
		u.ut_exit.e_exit = oldrl;
	else if (oup != NULL)
		u.ut_exit.e_exit = oup->ut_exit.e_termination;
	else
		u.ut_exit.e_exit = '0';

	u.ut_exit.e_termination = runlevel;

	for (i = 0; rlevels[i] != '\0'; ++i) {
		if (rlevels[i] == runlevel)
			break;
	}

	u.ut_pid = n_prev[i];

	if (do_bump) {
		for (i = 0; rlevels[i] != '\0'; ++i) {
			if (rlevels[i] == u.ut_exit.e_exit)
				break;
		}

		++n_prev[i];
	}

	(void) sprintf(u.ut_line, RUNLVL_MSG, runlevel);

	if (pututxline(&u) == NULL) {
		endutxent();
		MUTEX_UNLOCK(&utmpx_lock);

		return;
	}

	updwtmpx(WTMPX_FILE, &u);

	endutxent();
	MUTEX_UNLOCK(&utmpx_lock);

	utmpx_check();
}

static void
utmpx_write_entry(short type, const char *msg, time_t tstamp)
{
	struct utmpx u;
	struct utmpx *oup;
	size_t tmplen;

	bzero(&u, sizeof (struct utmpx));

	u.ut_id[0] = u.ut_id[1] = u.ut_id[2] = u.ut_id[3] = '\0';
	u.ut_pid = 0;

	u.ut_exit.e_termination = WTERMSIG(0);
	u.ut_exit.e_exit = WEXITSTATUS(0);
	u.ut_type = type;
	u.ut_tv.tv_sec = tstamp;

	MUTEX_LOCK(&utmpx_lock);
	setutxent();

	if ((oup = getutxid(&u)) != NULL) {
		bcopy(oup->ut_user, u.ut_user, sizeof (u.ut_user));
		bcopy(oup->ut_line, u.ut_line, sizeof (u.ut_line));
		bcopy(oup->ut_host, u.ut_host, sizeof (u.ut_host));

		tmplen = strlen(u.ut_host);
		if (tmplen)
			u.ut_syslen = min(tmplen + 1, sizeof (u.ut_host));
		else
			u.ut_syslen =  0;
	}

	(void) sprintf(u.ut_line, "%.12s", msg);

	if (pututxline(&u) == NULL) {
		endutxent();
		MUTEX_UNLOCK(&utmpx_lock);

		return;
	}

	updwtmpx(WTMPX_FILE, &u);

	endutxent();
	MUTEX_UNLOCK(&utmpx_lock);

	utmpx_check();
}

void
utmpx_write_boottime(void)
{
	time_t tstamp;
	struct stat stbuf;

	/*
	 * The DOWN_TIME record tracks when the OS became unavailable
	 * during the previous boot.  We stat(2) WTMPX and check its
	 * attributes to determine when (and how) the OS became
	 * unavailable.  If the file is empty, skip writing a DOWN_TIME
	 * record.  Otherwise, check the access and modify times and
	 * use whichever is latest as the time that the OS became
	 * unavailable.  If st_atime is latest, the instance crashed or
	 * the machine lost power.  If st_mtime is latest, the shutdown
	 * was controlled.
	 */
	if (stat(WTMPX_FILE, &stbuf) == 0 && stbuf.st_size != 0) {
		tstamp = (stbuf.st_atime >= stbuf.st_mtime) ?
		    stbuf.st_atime : stbuf.st_mtime;
		utmpx_write_entry(DOWN_TIME, DOWN_MSG, tstamp);
	}

	/*
	 * The boot time (or start time, for a non-global zone) is retrieved in
	 * log_init().
	 */
	tstamp = st->st_start_time.tv_sec;

	utmpx_write_entry(BOOT_TIME, BOOT_MSG, tstamp);
}

/*
 * void utmpx_clear_old(void)
 *   At boot and only at boot, truncate the utmpx file.
 *
 */
void
utmpx_clear_old(void)
{
	int fd;
	mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;

	if (!st->st_initial || utmpx_truncated)
		return;

	MUTEX_LOCK(&utmpx_lock);

	if ((fd = open(_UTMPX_FILE,
	    O_WRONLY | O_CREAT | O_TRUNC, mode)) != -1) {
		(void) fchmod(fd, mode); /* force mode regardless of umask() */
		(void) fchown(fd, 0, 2); /* force owner to root/bin */
		(void) close(fd);
	} else {
		log_framework(LOG_NOTICE, "Unable to create %s: %s\n",
		    _UTMPX_FILE, strerror(errno));
	}

	utmpx_truncated = 1;

	MUTEX_UNLOCK(&utmpx_lock);
}

void
utmpx_init()
{
	(void) pthread_mutex_init(&utmpx_lock, &mutex_attrs);
}

void
utmpx_prefork()
{
	/*
	 * The libc utmpx routines are entirely MT-unsafe; we must assure
	 * that no other thread is in these routines when we fork lest we
	 * leave the child with inconsistent library state.
	 */
	MUTEX_LOCK(&utmpx_lock);
}

void
utmpx_postfork()
{
	MUTEX_UNLOCK(&utmpx_lock);
}
