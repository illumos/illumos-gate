/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved. The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * defs that come from uucp.h
 */
#define	NAMESIZE 40
#define	FAIL -1
#define	SAME 0
#define	SLCKTIME (8*60*60)	/* device timeout (LCK.. files) in seconds */
#ifdef __STDC__
#define	ASSERT(e, f, v) if (!(e)) {\
	(void) fprintf(stderr, "AERROR - (%s) ", #e); \
	(void) fprintf(stderr, f, v); \
	finish(FAIL); \
}
#else
#define	ASSERT(e, f, v) if (!(e)) {\
	(void) fprintf(stderr, "AERROR - (%s) ", "e"); \
	(void) fprintf(stderr, f, v); \
	finish(FAIL); \
}
#endif
#define	SIZEOFPID	10		/* maximum number of digits in a pid */

#define	LOCKDIR "/var/spool/locks"
#define	LOCKPRE "LK"

/*
 * This code is taken almost directly from uucp and follows the same
 * conventions.  This is important since uucp and tip should
 * respect each others locks.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mkdev.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <utime.h>

static void	stlock(char *);
static int	onelock(char *, char *, char *);
static int	checkLock(char *);

extern void	finish(int);

/*
 *	ulockf(file, atime)
 *	char *file;
 *	time_t atime;
 *
 *	ulockf  -  this routine will create a lock file (file).
 *	If one already exists, send a signal 0 to the process--if
 *	it fails, then unlink it and make a new one.
 *
 *	input:
 *		file - name of the lock file
 *		atime - is unused, but we keep it for lint compatibility
 *			with non-ATTSVKILL
 *
 *	return codes:  0  |  FAIL
 */
/* ARGSUSED */
static int
ulockf(char *file, time_t atime)
{
	static char pid[SIZEOFPID+2] = { '\0' }; /* +2 for '\n' and NULL */
	static char tempfile[NAMESIZE];

	if (pid[0] == '\0') {
		(void) snprintf(pid, sizeof (pid), "%*d\n", SIZEOFPID,
		    (int)getpid());
		(void) snprintf(tempfile, sizeof (tempfile),
		    "%s/LTMP.%d", LOCKDIR, getpid());
	}
	if (onelock(pid, tempfile, file) == -1) {
		/* lock file exists */
		(void) unlink(tempfile);
		if (checkLock(file))
			return (FAIL);
		else {
			if (onelock(pid, tempfile, file)) {
				(void) unlink(tempfile);
				return (FAIL);
			}
		}
	}
	stlock(file);
	return (0);
}

/*
 * check to see if the lock file exists and is still active
 * - use kill(pid, 0) - (this only works on ATTSV and some hacked
 * BSD systems at this time)
 * return:
 *	0	-> success (lock file removed - no longer active)
 *	FAIL	-> lock file still active
 */
static int
checkLock(char *file)
{
	int ret;
	int lpid = -1;
	char alpid[SIZEOFPID+2];	/* +2 for '\n' and NULL */
	int fd;

	fd = open(file, 0);
	if (fd == -1) {
		if (errno == ENOENT)  /* file does not exist -- OK */
			return (0);
		goto unlk;
	}
	ret = read(fd, (char *)alpid, SIZEOFPID+1); /* +1 for '\n' */
	(void) close(fd);
	if (ret != (SIZEOFPID+1))
		goto unlk;
	lpid = atoi(alpid);
	if ((ret = kill(lpid, 0)) == 0 || errno == EPERM)
		return (FAIL);

unlk:
	if (unlink(file) != 0)
		return (FAIL);
	return (0);
}

#define	MAXLOCKS 10	/* maximum number of lock files */
char *Lockfile[MAXLOCKS];
int Nlocks = 0;

/*
 *	stlock(name)	put name in list of lock files
 *	char *name;
 *
 *	return codes:  none
 */

static void
stlock(char *name)
{
	char *p;
	int i;

	for (i = 0; i < Nlocks; i++) {
		if (Lockfile[i] == NULL)
			break;
	}
	ASSERT(i < MAXLOCKS, "TOO MANY LOCKS %d", i);
	if (i >= Nlocks)
		i = Nlocks++;
	p = calloc(strlen(name) + 1, sizeof (char));
	ASSERT(p != NULL, "CAN NOT ALLOCATE FOR %s", name);
	(void) strcpy(p, name);
	Lockfile[i] = p;
}

/*
 *	rmlock(name)	remove all lock files in list
 *	char *name;	or name
 *
 *	return codes: none
 */

static void
rmlock(char *name)
{
	int i;

	for (i = 0; i < Nlocks; i++) {
		if (Lockfile[i] == NULL)
			continue;
		if (name == NULL || strcmp(name, Lockfile[i]) == SAME) {
			(void) unlink(Lockfile[i]);
			free(Lockfile[i]);
			Lockfile[i] = NULL;
		}
	}
}

static int
onelock(char *pid, char *tempfile, char *name)
{
	int fd;
	static int first = 1;

	fd = creat(tempfile, 0444);
	if (fd < 0) {
		if (first) {
			if (errno == EACCES) {
				(void) fprintf(stderr,
			"tip: can't create files in lock file directory %s\n",
				    LOCKDIR);
			} else if (access(LOCKDIR, 0) < 0) {
				(void) fprintf(stderr,
				    "tip: lock file directory %s: ",
				    LOCKDIR);
				perror("");
			}
			first = 0;
		}
		if (errno == EMFILE || errno == ENFILE)
			(void) unlink(tempfile);
		return (-1);
	}
	/* +1 for '\n' */
	if (write(fd, pid, SIZEOFPID+1) != (SIZEOFPID+1)) {
		(void) fprintf(stderr,
		    "tip: can't write to files in lock file directory %s: %s\n",
		    LOCKDIR, strerror(errno));
		(void) unlink(tempfile);
		return (-1);
	}
	(void) fchmod(fd, 0444);
	(void) close(fd);
	if (link(tempfile, name) < 0) {
		(void) unlink(tempfile);
		return (-1);
	}
	(void) unlink(tempfile);
	return (0);
}

/*
 *	delock(sys)	remove a lock file
 *	char *sys;
 */

void
delock(char *sys)
{
	struct stat sb;
	char lname[NAMESIZE];

	if (stat(sys, &sb) < 0)
		return;
	(void) snprintf(lname, sizeof (lname), "%s/%s.%3.3lu.%3.3lu.%3.3lu",
	    LOCKDIR, LOCKPRE,
	    (unsigned long)major(sb.st_dev),
	    (unsigned long)major(sb.st_rdev),
	    (unsigned long)minor(sb.st_rdev));
	rmlock(lname);
}

/*
 *	tip_mlock(sys)	create system lock
 *	char *sys;
 *
 *	return codes:  0  |  FAIL
 */

int
tip_mlock(char *sys)
{
	struct stat sb;
	char lname[NAMESIZE];

	if (stat(sys, &sb) < 0)
		return (FAIL);
	(void) snprintf(lname, sizeof (lname), "%s/%s.%3.3lu.%3.3lu.%3.3lu",
	    LOCKDIR, LOCKPRE,
	    (unsigned long)major(sb.st_dev),
	    (unsigned long)major(sb.st_rdev),
	    (unsigned long)minor(sb.st_rdev));
	return (ulockf(lname, (time_t)SLCKTIME) < 0 ? FAIL : 0);
}
