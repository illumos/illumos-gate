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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/
/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "uucp.h"

#include <unistd.h>
/* #include <sys/types.h> */
/* #include <sys/stat.h> */

static struct stat _st_buf;
static char lockname[BUFSIZ];

static void	stlock(char *);
static int	onelock(char *, char *, char *);

/*
 * make a lock file with given 'name'
 * If one already exists, send a signal 0 to the process--if
 * it fails, then unlink it and make a new one.
 *
 * input:
 *	name - name of the lock file to make
 *
 * return:
 *	0	-> success
 *	FAIL	-> failure
 */

GLOBAL int
mklock(char *name)
{
	static	char pid[SIZEOFPID+2] = { '\0' }; /* +2 for '\n' and NULL */
	static char tempfile[MAXNAMESIZE];

#ifdef V8
	char *cp;
#endif

	if (pid[0] == '\0') {
		(void) sprintf(pid, "%*ld\n", SIZEOFPID, (long)getpid());
		(void) sprintf(tempfile, "%s/LTMP.%ld", X_LOCKDIR,
		    (long)getpid());
	}

#ifdef V8	/* this wouldn't be a problem if we used lock directories */
		/* some day the truncation of system names will bite us */
	cp = rindex(name, '/');
	if (cp++ != CNULL)
		if (strlen(cp) > MAXBASENAME)
			*(cp+MAXBASENAME) = NULLCHAR;
#endif /* V8 */
	if (onelock(pid, tempfile, name) == -1) {
		(void) unlink(tempfile);
		if (cklock(name)) {
			return (FAIL);
		} else {
			if (onelock(pid, tempfile, name)) {
				(void) unlink(tempfile);
				DEBUG(4, "ulockf failed in onelock()\n%s", "");
				return (FAIL);
			}
		}
	}

	stlock(name);
	return (0);
}

/*
 * check to see if the lock file exists and is still active
 * - use kill(pid,0)
 *
 * return:
 *	0	-> success (lock file removed - no longer active
 *	FAIL	-> lock file still active
 */
GLOBAL int
cklock(char *name)
{
	int ret;
	pid_t lpid = -1;
	char alpid[SIZEOFPID+2];	/* +2 for '\n' and NULL */
	int fd;

	fd = open(name, O_RDONLY);
	DEBUG(4, "ulockf name %s\n", name);
	if (fd == -1) {
		if (errno == ENOENT)  /* file does not exist -- OK */
			return (0);
		DEBUG(4, "Lock File--can't read (errno %d) --remove it!\n",
		    errno);
		goto unlk;
	}
	ret = read(fd, (char *)alpid, SIZEOFPID + 1); /* +1 for '\n' */
	(void) close(fd);
	if (ret != (SIZEOFPID+1)) {

		DEBUG(4, "Lock File--bad format--remove it!\n%s", "");
		goto unlk;
	}
	lpid = (pid_t)strtol(alpid, NULL, 10);
	if ((ret = kill(lpid, 0)) == 0 || errno == EPERM) {
		DEBUG(4, "Lock File--process still active--not removed\n%s",
		    "");
		return (FAIL);
	} else { /* process no longer active */
		DEBUG(4, "kill pid (%ld), ", (long)lpid);
		DEBUG(4, "returned %d", ret);
		DEBUG(4, "--ok to remove lock file (%s)\n", name);
	}
unlk:

	if (unlink(name) != 0) {
		DEBUG(4, "ulockf failed in unlink()\n%s", "");
		return (FAIL);
	}
	return (0);
}

#define	MAXLOCKS 10	/* maximum number of lock files */
static char *Lockfile[MAXLOCKS];
GLOBAL int Nlocks = 0;

/*
 * put name in list of lock files
 * return:
 *	none
 */
static void
stlock(char *name)
{
	int i;
	char *p;

	for (i = 0; i < Nlocks; i++) {
		if (Lockfile[i] == NULL)
			break;
	}
	ASSERT(i < MAXLOCKS, "TOO MANY LOCKS", "", i);
	if (i >= Nlocks)
		i = Nlocks++;
	p = calloc((unsigned)strlen(name) + 1, sizeof (char));
	ASSERT(p != NULL, "CAN NOT ALLOCATE FOR", name, 0);
	(void) strcpy(p, name);
	Lockfile[i] = p;
}

/*
 * remove the named lock. If named lock is NULL,
 *	then remove all locks currently in list.
 * return:
 *	none
 */
GLOBAL void
rmlock(char *name)
{
	int i;
#ifdef V8
	char *cp;

	cp = rindex(name, '/');
	if (cp++ != CNULL)
		if (strlen(cp) > MAXBASENAME)
			*(cp+MAXBASENAME) = NULLCHAR;
#endif /* V8 */


	for (i = 0; i < Nlocks; i++) {
		if (Lockfile[i] == NULL)
			continue;
		if (name == NULL || EQUALS(name, Lockfile[i])) {
			(void) unlink(Lockfile[i]);
			free(Lockfile[i]);
			Lockfile[i] = NULL;
		}
	}
}



/*
 * remove a lock file
 *
 * Parameters:
 *	pre -	Path and first part of file name of the lock file to be
 *		removed.
 *	s -	The suffix part of the lock file.  The name of the lock file
 *		will be derrived by concatenating pre, a period, and s.
 *
 * return:
 *	none
 */
GLOBAL void
delock(char *pre, char *s)
{
	char ln[MAXNAMESIZE];

	(void) sprintf(ln, "%s.%s", pre, s);
	BASENAME(ln, '/')[MAXBASENAME] = '\0';
	rmlock(ln);
}


/*
 * create lock file
 *
 * Parameters:
 *	pre -	Path and first part of file name of the lock file to be
 *		created.
 *	name -	The suffix part of the lock file.  The name of the lock file
 *		will be derrived by concatenating pre, a period, and name.
 *
 * return:
 *	0	-> success
 *	FAIL	-> failure
 */
GLOBAL int
mlock(char *pre, char *name)
{
	char lname[MAXNAMESIZE];

	/*
	 * if name has a '/' in it, then it's a device name and it's
	 * not in /dev (i.e., it's a remotely-mounted device or it's
	 * in a subdirectory of /dev).  in either case, creating our normal
	 * lockfile (/var/spool/locks/LCK..<dev>) is going to bomb if
	 * <dev> is "/remote/dev/term/14" or "/dev/net/foo/clone", so never
	 * mind.  since we're using advisory filelocks on the devices
	 * themselves, it'll be safe.
	 *
	 * of course, programs and people who are used to looking at the
	 * lockfiles to find out what's going on are going to be a trifle
	 * misled.  we really need to re-consider the lockfile naming structure
	 * to accomodate devices in directories other than /dev ... maybe in
	 * the next release.
	 */
	if (strchr(name, '/') != NULL)
		return (0);
	(void) sprintf(lname, "%s.%s", pre, BASENAME(name, '/'));
	BASENAME(lname, '/')[MAXBASENAME] = '\0';
	return (mklock(lname));
}

/*
 * makes a lock on behalf of pid.
 * input:
 *	pid - process id
 *	tempfile - name of a temporary in the same file system
 *	name - lock file name (full path name)
 * return:
 *	-1 - failed
 *	0  - lock made successfully
 */
static int
onelock(char *pid, char *tempfile, char *name)
{
	int fd;
	char	cb[100];

	fd = creat(tempfile, (mode_t)0444);
	if (fd < 0) {
		(void) sprintf(cb, "%s %s %d", tempfile, name, errno);
		logent("ULOCKC", cb);
		if ((errno == EMFILE) || (errno == ENFILE))
			(void) unlink(tempfile);
		return (-1);
	}
	/* +1 for '\n' */
	if (write(fd, pid, SIZEOFPID + 1) != (SIZEOFPID + 1)) {
		(void) sprintf(cb, "%s %s %d", tempfile, name, errno);
		logent("ULOCKW", cb);
		(void) unlink(tempfile);
		return (-1);
	}
	(void) chmod(tempfile, (mode_t)0444);
	(void) chown(tempfile, UUCPUID, UUCPGID);
	(void) close(fd);
	if (link(tempfile, name) < 0) {
		DEBUG(4, "%s: ", strerror(errno));
		DEBUG(4, "link(%s, ", tempfile);
		DEBUG(4, "%s)\n", name);
		if (unlink(tempfile) < 0) {
			(void) sprintf(cb, "ULK err %s %d", tempfile,  errno);
			logent("ULOCKLNK", cb);
		}
		return (-1);
	}
	if (unlink(tempfile) < 0) {
		(void) sprintf(cb, "%s %d", tempfile, errno);
		logent("ULOCKF", cb);
	}
	return (0);
}

/*
 * fd_mklock(fd) - lock the device indicated by fd is possible
 *
 * return -
 *	SUCCESS - this process now has the fd locked
 *	FAIL - this process was not able to lock the fd
 */

GLOBAL int
fd_mklock(int fd)
{
	int tries = 0;

	if (fstat(fd, &_st_buf) != 0)
		return (FAIL);

	(void) sprintf(lockname, "%s.%3.3lu.%3.3lu.%3.3lu", L_LOCK,
	    (unsigned long) major(_st_buf.st_dev),
	    (unsigned long) major(_st_buf.st_rdev),
	    (unsigned long) minor(_st_buf.st_rdev));

	if (mklock(lockname) == FAIL)
		return (FAIL);

	while (lockf(fd, F_TLOCK, 0L) != 0) {
		DEBUG(7, "fd_mklock: lockf returns %d\n", errno);
		if ((++tries >= MAX_LOCKTRY) || (errno != EAGAIN)) {
			rmlock(lockname);
			logent("fd_mklock", "lockf failed");
			return (FAIL);
		}
		(void) sleep(2);
	}
	DEBUG(7, "fd_mklock: ok\n%s", "");
	return (SUCCESS);
}

/*
 * fn_cklock(name) - determine if the device indicated by name is locked
 *
 * return -
 *	SUCCESS - the name is not locked
 *	FAIL - the name is locked by another process
 */

GLOBAL int
fn_cklock(char *name)
{
	/* we temporarily use lockname to hold full path name */
	(void) sprintf(lockname, "%s%s", (*name == '/' ? "" : "/dev/"), name);

	if (stat(lockname, &_st_buf) != 0)
		return (FAIL);

	(void) sprintf(lockname, "%s.%3.3lu.%3.3lu.%3.3lu", L_LOCK,
	    (unsigned long) major(_st_buf.st_dev),
	    (unsigned long) major(_st_buf.st_rdev),
	    (unsigned long) minor(_st_buf.st_rdev));

	return (cklock(lockname));
}

/*
 * fd_cklock(fd) - determine if the device indicated by fd is locked
 *
 * return -
 *	SUCCESS - the fd is not locked
 *	FAIL - the fd is locked by another process
 */

GLOBAL int
fd_cklock(int fd)
{
	if (fstat(fd, &_st_buf) != 0)
		return (FAIL);

	(void) sprintf(lockname, "%s.%3.3lu.%3.3lu.%3.3lu", L_LOCK,
	    (unsigned long) major(_st_buf.st_dev),
	    (unsigned long) major(_st_buf.st_rdev),
	    (unsigned long) minor(_st_buf.st_rdev));

	if (cklock(lockname) == FAIL)
		return (FAIL);
	else
		return (lockf(fd, F_TEST, 0L));
}

/*
 * remove the locks associated with the device file descriptor
 *
 * return -
 *	SUCCESS - both BNU lock file and advisory locks removed
 *	FAIL -
 */

GLOBAL void
fd_rmlock(int fd)
{
	if (fstat(fd, &_st_buf) == 0) {
		(void) sprintf(lockname, "%s.%3.3lu.%3.3lu.%3.3lu", L_LOCK,
		    (unsigned long) major(_st_buf.st_dev),
		    (unsigned long) major(_st_buf.st_rdev),
		    (unsigned long) minor(_st_buf.st_rdev));
		rmlock(lockname);
	}
	(void) lockf(fd, F_ULOCK, 0L);
}
