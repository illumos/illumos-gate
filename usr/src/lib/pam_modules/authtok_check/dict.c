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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/stat.h>
#include <stdio.h>
#include <syslog.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include "packer.h"

static int lockfd = -1;
static struct flock flock = { 0, 0, 0, 0, 0, 0 };

char dblock[PATH_MAX];

#define	LOCK_WAIT	1000000
#define	LOCK_RETRIES	60

/*
 * lock_db()
 *
 * Create a lockfile to prevent simultaneous access to the database
 * creation routines. We set a timeout to LOCK_WAIT seconds. If we
 * haven't obtained a lock after LOCK_RETIRES attempts, we bail out.
 *
 * returns 0 on succes, -1 on (lock) failure.
 * side effect: the directory "path" will be created if it didn't exist.
 */
int
lock_db(char *path)
{
	int retval;
	struct stat st;
	int retries = 0;

	/* create directory "path" if it doesn't exist */
	if (stat(path, &st) == -1) {
		if (errno != ENOENT ||
		    (mkdir(path, 0755) == -1 || chmod(path, 0755) == -1))
			return (-1);
	}

	(void) snprintf(dblock, sizeof (dblock), "%s/authtok_check.lock", path);

	if ((lockfd = open(dblock, O_WRONLY|O_CREAT|O_EXCL, 0400)) == -1) {
		if (errno == EEXIST)
			lockfd = open(dblock, O_WRONLY);
		if (lockfd == -1) {
			int olderrno = errno;
			syslog(LOG_ERR, "pam_authtok_check::pam_sm_chauthtok: "
			    "can't open lockfile: %s", strerror(errno));
			errno = olderrno;
			return (-1);
		}
	}

	do {
		flock.l_type = F_WRLCK;
		retval = fcntl(lockfd, F_SETLK, &flock);
		if (retval == -1)
			(void) usleep(LOCK_WAIT);
	} while (retval == -1 && ++retries < LOCK_RETRIES);

	if (retval == -1) {
		int errno_saved = errno;
		syslog(LOG_ERR, "pam_authtok_check::pam_sm_chauthtok: timeout "
		    "waiting for dictionary lock.");
		errno = errno_saved;
	}

	return (retval);
}

/*
 * unlock_db()
 *
 * Release the database lock
 */
void
unlock_db(void)
{
	if (lockfd != -1) {
		flock.l_type = F_UNLCK;
		(void) fcntl(lockfd, F_SETLK, &flock);
		(void) close(lockfd);
		lockfd = -1;
	}
}

/*
 * database_present()
 *
 * returns 0 if the database files are found, and the database size is
 * greater than 0
 */
int
database_present(char *path)
{
	struct stat st;
	char dict_hwm[PATH_MAX];
	char dict_pwd[PATH_MAX];
	char dict_pwi[PATH_MAX];

	(void) snprintf(dict_hwm, sizeof (dict_hwm), "%s/%s", path,
	    DICT_DATABASE_HWM);
	(void) snprintf(dict_pwd, sizeof (dict_pwd), "%s/%s", path,
	    DICT_DATABASE_PWD);
	(void) snprintf(dict_pwi, sizeof (dict_pwi), "%s/%s", path,
	    DICT_DATABASE_PWI);

	if (stat(dict_hwm, &st) == -1 ||
	    (stat(dict_pwd, &st) == -1 || st.st_size == 0) ||
	    stat(dict_pwi, &st) == -1)
		return (NO_DICTDATABASE);

	return (0);
}

/*
 * build_dict_database(list, char *path)
 *
 * Create the Crack Dictionary Database based on the list of sources
 * dictionaries specified in "list". Store the database in "path".
 */
int
build_dict_database(char *list, char *path)
{
	return (packer(list, path) == -1 ? DICTDATABASE_BUILD_ERR : 0);
}

/*
 * Rebuild the database in "path" if the database is older than one of the
 * files listed in "list", or older than the config-file PWADMIN.
 */
int
update_dict_database(char *list, char *path)
{
	struct stat st_db;
	struct stat st_file;
	char *buf;
	char *listcopy;
	boolean_t update_needed = B_FALSE;
	char dbase_pwd[PATH_MAX];

	(void) snprintf(dbase_pwd, sizeof (dbase_pwd), "%s/%s", path,
	    DICT_DATABASE_PWD);

	if (stat(dbase_pwd, &st_db) == -1)
		return (DICTFILE_ERR);

	if ((listcopy = strdup(list)) == NULL)
		return (DICTFILE_ERR);

	buf = strtok(listcopy,  "\t ,");

	/* Compare mtime of each listed dictionary against DB mtime */
	while (update_needed == B_FALSE && buf != NULL) {
		if (stat(buf, &st_file) == -1) {
			if (errno == ENOENT) {
				syslog(LOG_ERR,
				    "pam_authtok_check:update_dict_database: "
				    "dictionary \"%s\" not present.", buf);
			} else {
				syslog(LOG_ERR,
				    "pam_authtok_check:update_dict_database: "
				    "stat(%s) failed: %s", buf,
				    strerror(errno));
			}
			free(listcopy);
			return (DICTFILE_ERR);
		}
		if (st_db.st_mtime < st_file.st_mtime)
			update_needed = B_TRUE;	/* database out of date */
		buf = strtok(NULL, "\t ,");
	}

	free(listcopy);

	/*
	 * If /etc/default/passwd is updated, generate the database.
	 * Because this is the only way we can check if files have been
	 * added/deleted from DICTIONLIST.
	 * Drawback: the database will also be generated when other
	 * tunables are changed.
	 */
	if (stat(PWADMIN, &st_file) != -1 && st_db.st_mtime < st_file.st_mtime)
		update_needed = B_TRUE;

	if (update_needed) {
		/*
		 * Since we actually rebuild the database, we need to remove
		 * the old database first.
		 */
		PWRemove(path);
		return (build_dict_database(list, path));
	}

	return (0);
}

/*
 * Build or update database, while holding the global lock.
 */
int
make_dict_database(char *list, char *path)
{
	int r = -1;

	if (lock_db(path) == 0) {
		if (database_present(path) == NO_DICTDATABASE)
			r = build_dict_database(list, path);
		else
			r = update_dict_database(list, path);
		unlock_db();
	}
	return (r);
}
