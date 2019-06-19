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

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */


/*
 * Routines to read and write the /etc/utmpx file. Also contains
 * binary compatibility routines to support the old utmp interfaces
 * on systems with MAXPID <= SHRT_MAX.
 */

#include "lint.h"
#include <sys/types.h>
#include <stdio.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <utmpx.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <ctype.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <pthread.h>
#include <limits.h>
#include <signal.h>
#include <spawn.h>

#define	IDLEN		4	/* length of id field in utmp */
#define	SC_WILDC	0xff	/* wild char for utmp ids */
#define	MAXFILE		79	/* Maximum pathname length for "utmpx" file */

#define	MAXVAL		255		/* max value for an id `character' */
#define	IPIPE		"/var/run/initpipe"	/* FIFO to send pids to init */
#define	UPIPE		"/var/run/utmppipe"	/* FIFO to send pids to utmpd */

#define	VAR_UTMPX_FILE	"/var/adm/utmpx" /* for sanity check only */


/*
 * format of message sent to init
 */

typedef struct	pidrec {
	int	pd_type;	/* command type */
	pid_t	pd_pid;		/* pid */
} pidrec_t;

/*
 * pd_type's
 */
#define	ADDPID 1	/* add a pid to "godchild" list */
#define	REMPID 2	/* remove a pid to "godchild" list */

static void	utmpx_frec2api(const struct futmpx *, struct utmpx *);
static void	utmpx_api2frec(const struct utmpx *, struct futmpx *);

static void	unlockutx(void);
static void	sendpid(int, pid_t);
static void	sendupid(int, pid_t);
static int	idcmp(const char *, const char *);
static int	allocid(char *, unsigned char *);
static int	lockutx(void);

static struct utmpx *invoke_utmp_update(const struct utmpx *);
static struct futmpx *getoneutx(off_t *);
static void	putoneutx(const struct utmpx *, off_t);
static int	big_pids_in_use(void);

/*
 * prototypes for utmp compatibility routines (in getut.c)
 */
extern struct utmp *_compat_getutent(void);
extern struct utmp *_compat_getutid(const struct utmp *);
extern struct utmp *_compat_getutline(const struct utmp *);
extern struct utmp *_compat_pututline(const struct utmp *);
extern void _compat_setutent(void);
extern void _compat_endutent(void);
extern void _compat_updwtmp(const char *, struct utmp *);
extern struct utmp *_compat_makeut(struct utmp *);

static int fd = -1;	/* File descriptor for the utmpx file. */
static int ut_got_maxpid = 0;	/* Flag set when sysconf(_SC_MAXPID) called */
static pid_t ut_maxpid = 0;	/* Value of MAXPID from sysconf */
static int tempfd = -1;  /* To store fd between lockutx() and unlockutx() */

static	FILE	*fp = NULL;	/* Buffered file descriptior for utmpx file */
static int changed_name = 0;	/* Flag set when not using utmpx file */
static char utmpxfile[MAXFILE+1] = UTMPX_FILE;	/* Name of the current */
char _compat_utmpfile[MAXFILE+1];
static int compat_utmpflag = 0;	/* old compat mode flag */

static struct futmpx fubuf;	/* Copy of last entry read in. */
static struct utmpx ubuf;	/* Last entry returned to client */

static struct utmp utmpcompat;	/* Buffer for returning utmp-format data */
/*
 * In the 64-bit world, the utmpx data structure grows because of
 * the ut_time field (a struct timeval) grows in the middle of it.
 */
static void
utmpx_frec2api(const struct futmpx *src, struct utmpx *dst)
{
	if (src == NULL)
		return;

	(void) strncpy(dst->ut_user, src->ut_user, sizeof (dst->ut_user));
	(void) strncpy(dst->ut_line, src->ut_line, sizeof (dst->ut_line));
	(void) memcpy(dst->ut_id, src->ut_id, sizeof (dst->ut_id));
	dst->ut_pid = src->ut_pid;
	dst->ut_type = src->ut_type;
	dst->ut_exit.e_termination = src->ut_exit.e_termination;
	dst->ut_exit.e_exit = src->ut_exit.e_exit;
	dst->ut_tv.tv_sec = (time_t)src->ut_tv.tv_sec;
	dst->ut_tv.tv_usec = (suseconds_t)src->ut_tv.tv_usec;
	dst->ut_session = src->ut_session;
	bzero(dst->pad, sizeof (dst->pad));
	dst->ut_syslen = src->ut_syslen;
	(void) memcpy(dst->ut_host, src->ut_host, sizeof (dst->ut_host));
}

static void
utmpx_api2frec(const struct utmpx *src, struct futmpx *dst)
{
	if (src == NULL)
		return;

	(void) strncpy(dst->ut_user, src->ut_user, sizeof (dst->ut_user));
	(void) strncpy(dst->ut_line, src->ut_line, sizeof (dst->ut_line));
	(void) memcpy(dst->ut_id, src->ut_id, sizeof (dst->ut_id));
	dst->ut_pid = src->ut_pid;
	dst->ut_type = src->ut_type;
	dst->ut_exit.e_termination = src->ut_exit.e_termination;
	dst->ut_exit.e_exit = src->ut_exit.e_exit;
	dst->ut_tv.tv_sec = (time32_t)src->ut_tv.tv_sec;
	dst->ut_tv.tv_usec = (int32_t)src->ut_tv.tv_usec;
	dst->ut_session = src->ut_session;
	bzero(dst->pad, sizeof (dst->pad));
	dst->ut_syslen = src->ut_syslen;
	(void) memcpy(dst->ut_host, src->ut_host, sizeof (dst->ut_host));
}

/*
 * "getutxent_frec" gets the raw version of the next entry in the utmpx file.
 */
static struct futmpx *
getutxent_frec(void)
{
	/*
	 * If the "utmpx" file is not open, attempt to open it for
	 * reading.  If there is no file, attempt to create one.  If
	 * both attempts fail, return NULL.  If the file exists, but
	 * isn't readable and writeable, do not attempt to create.
	 */
	if (fd < 0) {

		if ((fd = open(utmpxfile, O_RDWR|O_CREAT, 0644)) < 0) {

			/*
			 * If the open failed for permissions, try opening
			 * it only for reading.  All "pututxline()" later
			 * will fail the writes.
			 */

			if ((fd = open(utmpxfile, O_RDONLY)) < 0)
				return (NULL);

			if ((fp = fopen(utmpxfile, "rF")) == NULL) {
				(void) close(fd);
				fd = -1;
				return (NULL);
			}

		} else {
			/*
			 * Get the stream pointer
			 */
			if ((fp = fopen(utmpxfile, "r+F")) == NULL) {
				(void) close(fd);
				fd = -1;
				return (NULL);
			}
		}
	}

	/*
	 * Try to read in the next entry from the utmpx file.
	 */
	if (fread(&fubuf, sizeof (fubuf), 1, fp) != 1) {
		/*
		 * Make sure fubuf is zeroed.
		 */
		bzero(&fubuf, sizeof (fubuf));
		return (NULL);
	}

	return (&fubuf);
}

/*
 * "big_pids_in_use" determines whether large pid numbers are in use
 * or not.  If MAXPID won't fit in a signed short, the utmp.ut_pid
 * field will overflow.
 *
 * Returns 0 if small pids are in use, 1 otherwise
 */
static int
big_pids_in_use(void)
{
	if (!ut_got_maxpid) {
		ut_got_maxpid++;
		ut_maxpid = sysconf(_SC_MAXPID);
	}
	return (ut_maxpid > SHRT_MAX ? 1 : 0);
}

/*
 * "getutxent" gets the next entry in the utmpx file.
 */
struct utmpx *
getutxent(void)
{
	struct futmpx *futxp;

	futxp = getutxent_frec();
	utmpx_frec2api(&fubuf, &ubuf);
	if (futxp == NULL)
		return (NULL);
	return (&ubuf);
}
/*
 * "getutent" gets the next entry in the utmp file.
 */
struct utmp *
getutent(void)
{
	struct utmpx *utmpx;

	if (compat_utmpflag)
		return (_compat_getutent());

	/* fail if we can't represent maxpid properly */
	if (big_pids_in_use()) {
		errno = EOVERFLOW;
		return (NULL);
	}

	if ((utmpx = getutxent()) == NULL)
		return (NULL);

	getutmp(utmpx, &utmpcompat);
	return (&utmpcompat);
}

/*
 * "getutxid" finds the specified entry in the utmpx file.  If
 * it can't find it, it returns NULL.
 */
struct utmpx *
getutxid(const struct utmpx *entry)
{
	short type;

	/*
	 * From XPG5: "The getutxid() or getutxline() may cache data.
	 * For this reason, to use getutxline() to search for multiple
	 * occurrences, it is necessary to zero out the static data after
	 * each success, or getutxline() could just return a pointer to
	 * the same utmpx structure over and over again."
	 */
	utmpx_api2frec(&ubuf, &fubuf);

	/*
	 * Start looking for entry. Look in our current buffer before
	 * reading in new entries.
	 */
	do {
		/*
		 * If there is no entry in "fubuf", skip to the read.
		 */
		if (fubuf.ut_type != EMPTY) {
			switch (entry->ut_type) {

			/*
			 * Do not look for an entry if the user sent
			 * us an EMPTY entry.
			 */
			case EMPTY:
				return (NULL);

			/*
			 * For RUN_LVL, BOOT_TIME, OLD_TIME, and NEW_TIME
			 * entries, only the types have to match.  If they do,
			 * return the address of internal buffer.
			 */
			case RUN_LVL:
			case BOOT_TIME:
			case DOWN_TIME:
			case OLD_TIME:
			case NEW_TIME:
				if (entry->ut_type == fubuf.ut_type) {
					utmpx_frec2api(&fubuf, &ubuf);
					return (&ubuf);
				}
				break;

			/*
			 * For INIT_PROCESS, LOGIN_PROCESS, USER_PROCESS,
			 * and DEAD_PROCESS the type of the entry in "fubuf",
			 * must be one of the above and id's must match.
			 */
			case INIT_PROCESS:
			case LOGIN_PROCESS:
			case USER_PROCESS:
			case DEAD_PROCESS:
				if (((type = fubuf.ut_type) == INIT_PROCESS ||
				    type == LOGIN_PROCESS ||
				    type == USER_PROCESS ||
				    type == DEAD_PROCESS) &&
				    (fubuf.ut_id[0] == entry->ut_id[0]) &&
				    (fubuf.ut_id[1] == entry->ut_id[1]) &&
				    (fubuf.ut_id[2] == entry->ut_id[2]) &&
				    (fubuf.ut_id[3] == entry->ut_id[3])) {
					utmpx_frec2api(&fubuf, &ubuf);
					return (&ubuf);
				}
				break;

			/*
			 * Do not search for illegal types of entry.
			 */
			default:
				return (NULL);
			}
		}
	} while (getutxent_frec() != NULL);

	/*
	 * Return NULL since the proper entry wasn't found.
	 */
	utmpx_frec2api(&fubuf, &ubuf);
	return (NULL);
}

/*
 * "getutid" finds the specified entry in the utmp file.  If
 * it can't find it, it returns NULL.
 */
struct utmp *
getutid(const struct utmp *entry)
{
	struct utmpx utmpx;
	struct utmpx *utmpx2;

	if (compat_utmpflag)
		return (_compat_getutid(entry));

	/* fail if we can't represent maxpid properly */
	if (big_pids_in_use()) {
		errno = EOVERFLOW;
		return (NULL);
	}
	getutmpx(entry, &utmpx);
	if ((utmpx2 = getutxid(&utmpx)) == NULL)
		return (NULL);
	getutmp(utmpx2, &utmpcompat);
	return (&utmpcompat);
}

/*
 * "getutxline" searches the "utmpx" file for a LOGIN_PROCESS or
 * USER_PROCESS with the same "line" as the specified "entry".
 */
struct utmpx *
getutxline(const struct utmpx *entry)
{
	/*
	 * From XPG5: "The getutxid() or getutxline() may cache data.
	 * For this reason, to use getutxline() to search for multiple
	 * occurrences, it is necessary to zero out the static data after
	 * each success, or getutxline() could just return a pointer to
	 * the same utmpx structure over and over again."
	 */
	utmpx_api2frec(&ubuf, &fubuf);

	do {
		/*
		 * If the current entry is the one we are interested in,
		 * return a pointer to it.
		 */
		if (fubuf.ut_type != EMPTY &&
		    (fubuf.ut_type == LOGIN_PROCESS ||
		    fubuf.ut_type == USER_PROCESS) &&
		    strncmp(&entry->ut_line[0], &fubuf.ut_line[0],
		    sizeof (fubuf.ut_line)) == 0) {
			utmpx_frec2api(&fubuf, &ubuf);
			return (&ubuf);
		}
	} while (getutxent_frec() != NULL);

	/*
	 * Since entry wasn't found, return NULL.
	 */
	utmpx_frec2api(&fubuf, &ubuf);
	return (NULL);
}

/*
 * "getutline" searches the "utmp" file for a LOGIN_PROCESS or
 * USER_PROCESS with the same "line" as the specified "entry".
 */
struct utmp *
getutline(const struct utmp *entry)
{
	struct utmpx utmpx;
	struct utmpx *utmpx2;

	if (compat_utmpflag)
		return (_compat_getutline(entry));

	/* fail if we can't represent maxpid properly */
	if (big_pids_in_use()) {
		errno = EOVERFLOW;
		return (NULL);
	}
	/* call getutxline */
	getutmpx(entry, &utmpx);
	if ((utmpx2 = getutxline(&utmpx)) == NULL)
		return (NULL);
	getutmp(utmpx2, &utmpcompat);
	return (&utmpcompat);
}

/*
 * invoke_utmp_update
 *
 * Invokes the utmp_update program which has the privilege to write
 * to the /etc/utmp file.
 */

#define	UTMP_UPDATE 	"/usr/lib/utmp_update"
#define	STRSZ	64	/* Size of char buffer for argument strings */

static struct utmpx *
invoke_utmp_update(const struct utmpx *entryx)
{
	extern char **_environ;

	posix_spawnattr_t attr;
	int status;
	int cancel_state;
	pid_t child;
	pid_t w;
	int i;
	char user[STRSZ], id[STRSZ], line[STRSZ], pid[STRSZ], type[STRSZ],
	    term[STRSZ], exit[STRSZ], time[STRSZ], time_usec[STRSZ],
	    session_id[STRSZ], syslen[32];
	char pad[sizeof (entryx->pad) * 2 + 1];
	char host[sizeof (entryx->ut_host) + 1];
	struct utmpx *curx = NULL;
	char bin2hex[] = "0123456789ABCDEF";
	unsigned char *cp;
	char *argvec[15];
	int error;

	/*
	 * Convert the utmp struct to strings for command line arguments.
	 */
	(void) strncpy(user, entryx->ut_user, sizeof (entryx->ut_user));
	user[sizeof (entryx->ut_user)] = '\0';
	(void) strncpy(id, entryx->ut_id, sizeof (entryx->ut_id));
	id[sizeof (entryx->ut_id)] = '\0';
	(void) strncpy(line, entryx->ut_line, sizeof (entryx->ut_line));
	line[sizeof (entryx->ut_line)] = '\0';
	(void) sprintf(pid, "%d", (int)entryx->ut_pid);
	(void) sprintf(type, "%d", entryx->ut_type);
	(void) sprintf(term, "%d", entryx->ut_exit.e_termination);
	(void) sprintf(exit, "%d", entryx->ut_exit.e_exit);
	(void) sprintf(time, "%ld", entryx->ut_tv.tv_sec);
	(void) sprintf(time_usec, "%ld", entryx->ut_tv.tv_usec);
	(void) sprintf(session_id, "%d", entryx->ut_session);

	cp = (unsigned char *)entryx->pad;
	for (i = 0; i < sizeof (entryx->pad); ++i) {
		pad[i << 1] = bin2hex[(cp[i] >> 4) & 0xF];
		pad[(i << 1) + 1] = bin2hex[cp[i] & 0xF];
	}
	pad[sizeof (pad) - 1] = '\0';

	(void) sprintf(syslen, "%d", entryx->ut_syslen);
	(void) strlcpy(host, entryx->ut_host, sizeof (host));

	argvec[0] = UTMP_UPDATE;
	argvec[1] = user;
	argvec[2] = id;
	argvec[3] = line;
	argvec[4] = pid;
	argvec[5] = type;
	argvec[6] = term;
	argvec[7] = exit;
	argvec[8] = time;
	argvec[9] = time_usec;
	argvec[10] = session_id;
	argvec[11] = pad;
	argvec[12] = syslen;
	argvec[13] = host;
	argvec[14] = NULL;

	/*
	 * No SIGCHLD, please, and let no one else reap our child.
	 */
	error = posix_spawnattr_init(&attr);
	if (error) {
		errno = error;
		goto out;
	}
	error = posix_spawnattr_setflags(&attr,
	    POSIX_SPAWN_NOSIGCHLD_NP | POSIX_SPAWN_WAITPID_NP);
	if (error) {
		(void) posix_spawnattr_destroy(&attr);
		errno = error;
		goto out;
	}
	error = posix_spawn(&child, UTMP_UPDATE, NULL, &attr, argvec, _environ);
	(void) posix_spawnattr_destroy(&attr);
	if (error) {
		errno = error;
		goto out;
	}

	(void) pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);
	do {
		w = waitpid(child, &status, 0);
	} while (w == -1 && errno == EINTR);
	(void) pthread_setcancelstate(cancel_state, NULL);

	/*
	 * We can get ECHILD if the process is ignoring SIGCLD.
	 */
	if (!(w == -1 && errno == ECHILD) &&
	    (w == -1 || !WIFEXITED(status) || WEXITSTATUS(status) != 0)) {
		/*
		 * The child encountered an error,
		 */
		goto out;
	}

	/*
	 * Normal termination.  Return a pointer to the entry we just made.
	 */
	setutxent();	/* Reset file pointer */

	while ((curx = getutxent()) != NULL) {
		if (curx->ut_type != EMPTY &&
		    (curx->ut_type == LOGIN_PROCESS ||
		    curx->ut_type == USER_PROCESS ||
		    curx->ut_type == DEAD_PROCESS) &&
		    strncmp(&entryx->ut_line[0], &curx->ut_line[0],
		    sizeof (curx->ut_line)) == 0)
			break;
	}

out:
	return (curx);
}

/*
 * "pututxline" writes the structure sent into the utmpx file.
 * If there is already an entry with the same id, then it is
 * overwritten, otherwise a new entry is made at the end of the
 * utmpx file.
 */

struct utmpx *
pututxline(const struct utmpx *entry)
{
	struct utmpx *answer;
	int lock = 0;
	struct utmpx tmpxbuf;
	struct futmpx ftmpxbuf;

	/*
	 * Copy the user supplied entry into our temporary buffer to
	 * avoid the possibility that the user is actually passing us
	 * the address of "ubuf".
	 */
	if (entry == NULL)
		return (NULL);

	(void) memcpy(&tmpxbuf, entry, sizeof (tmpxbuf));
	utmpx_api2frec(entry, &ftmpxbuf);

	if (fd < 0) {
		(void) getutxent_frec();
		if (fd < 0)
			return ((struct utmpx *)NULL);
	}

	/*
	 * If we are not the superuser than we can't write to /etc/utmp,
	 * so invoke update_utmp(8) to write the entry for us.
	 */
	if (changed_name == 0 && geteuid() != 0)
		return (invoke_utmp_update(entry));

	/*
	 * Find the proper entry in the utmpx file.  Start at the current
	 * location.  If it isn't found from here to the end of the
	 * file, then reset to the beginning of the file and try again.
	 * If it still isn't found, then write a new entry at the end of
	 * the file.  (Making sure the location is an integral number of
	 * utmp structures into the file incase the file is scribbled.)
	 */

	if (getutxid(&tmpxbuf) == NULL) {

		setutxent();

		/*
		 * Lock the the entire file from here onwards.
		 */
		if (getutxid(&tmpxbuf) == NULL) {
			lock++;
			if (lockf(fd, F_LOCK, 0) < 0)
				return (NULL);
			(void) fseek(fp, 0, SEEK_END);
		} else
			(void) fseek(fp, -(long)sizeof (struct futmpx),
			    SEEK_CUR);
	} else
		(void) fseek(fp, -(long)sizeof (struct futmpx), SEEK_CUR);

	/*
	 * Write out the user supplied structure.  If the write fails,
	 * then the user probably doesn't have permission to write the
	 * utmpx file.
	 */
	if (fwrite(&ftmpxbuf, sizeof (ftmpxbuf), 1, fp) != 1) {
		answer = (struct utmpx *)NULL;
	} else {
		/*
		 * Save the new user structure into ubuf and fubuf so that
		 * it will be up to date in the future.
		 */
		(void) fflush(fp);
		(void) memcpy(&fubuf, &ftmpxbuf, sizeof (fubuf));
		utmpx_frec2api(&fubuf, &ubuf);
		answer = &ubuf;
	}

	if (lock)
		(void) lockf(fd, F_ULOCK, 0);

	if (answer != NULL && (tmpxbuf.ut_type == USER_PROCESS ||
	    tmpxbuf.ut_type == DEAD_PROCESS))
		sendupid(tmpxbuf.ut_type == USER_PROCESS ? ADDPID : REMPID,
		    (pid_t)tmpxbuf.ut_pid);
	return (answer);
}
/*
 * "pututline" is a wrapper that calls pututxline after converting
 * the utmp record to a utmpx record.
 */
struct utmp *
pututline(const struct utmp *entry)
{
	struct utmpx utmpx;
	struct utmpx *utmpx2;

	if (compat_utmpflag)
		return (_compat_pututline(entry));

	getutmpx(entry, &utmpx);
	if ((utmpx2 = pututxline(&utmpx)) == NULL)
		return (NULL);
	getutmp(utmpx2, &utmpcompat);
	return (&utmpcompat);
}

/*
 * "setutxent" just resets the utmpx file back to the beginning.
 */
void
setutxent(void)
{
	if (fd != -1)
		(void) lseek(fd, 0L, SEEK_SET);

	if (fp != NULL)
		(void) fseek(fp, 0L, SEEK_SET);

	/*
	 * Zero the stored copy of the last entry read, since we are
	 * resetting to the beginning of the file.
	 */
	bzero(&ubuf, sizeof (ubuf));
	bzero(&fubuf, sizeof (fubuf));
}

/*
 * "setutent" is a wrapper that calls setutxent
 */
void
setutent(void)
{
	if (compat_utmpflag) {
		_compat_setutent();
		return;
	}

	setutxent();
}

/*
 * "endutxent" closes the utmpx file.
 */
void
endutxent(void)
{
	if (fd != -1)
		(void) close(fd);
	fd = -1;

	if (fp != NULL)
		(void) fclose(fp);
	fp = NULL;

	bzero(&ubuf, sizeof (ubuf));
	bzero(&fubuf, sizeof (fubuf));
}

/*
 * "endutent" is a wrapper that calls endutxent
 * and clears the utmp compatibility buffer.
 */
void
endutent(void)
{
	if (compat_utmpflag) {
		_compat_endutent();
		return;
	}

	endutxent();
	bzero(&utmpcompat, sizeof (utmpcompat));
}

/*
 * "utmpxname" allows the user to read a file other than the
 * normal "utmpx" file.
 */
int
utmpxname(const char *newfile)
{
	size_t len;

	/*
	 * Determine if the new filename will fit.  If not, return 0.
	 */
	if ((len = strlen(newfile)) > MAXFILE-1)
		return (0);

	/*
	 * The name of the utmpx file has to end with 'x'
	 */
	if (newfile[len-1] != 'x')
		return (0);

	/*
	 * Otherwise copy in the new file name.
	 */
	else
		(void) strcpy(&utmpxfile[0], newfile);
	/*
	 * Make sure everything is reset to the beginning state.
	 */
	endutxent();

	/*
	 * If the file is being changed to /etc/utmpx or /var/adm/utmpx then
	 * we clear the flag so pututxline invokes utmp_update.  Otherwise
	 * we set the flag indicating that they changed to another name.
	 */
	if (strcmp(utmpxfile, UTMPX_FILE) == 0 ||
	    strcmp(utmpxfile, VAR_UTMPX_FILE) == 0)
		changed_name = 0;
	else
		changed_name = 1;

	return (1);
}

/*
 * "utmpname" allows the user to read a file other than the
 * normal "utmp" file. If the file specified is "/var/adm/utmp"
 * or "/var/adm/wtmp", it is translated to the corresponding "utmpx"
 * format name, and all "utmp" operations become wrapped calls
 * to the equivalent "utmpx" routines, with data conversions
 * as appropriate.  In the event the application wishes to read
 * an actual "old" utmp file (named something other than /var/adm/utmp),
 * calling this function with that name enables backward compatibility
 * mode, where we actually call the old utmp routines to operate on
 * the old file.
 */
int
utmpname(const char *newfile)
{
	char name[MAXFILE+1];

	if (strlen(newfile) > MAXFILE)
		return (0);

	if (strcmp(newfile, "/var/adm/utmp") == 0 ||
	    strcmp(newfile, "/var/adm/wtmp") == 0) {
		(void) strcpy(name, newfile);
		(void) strcat(name, "x");
		compat_utmpflag = 0;	/* turn off old compat mode */
		return (utmpxname(name));
	} else {
		(void) strcpy(_compat_utmpfile, newfile);
		compat_utmpflag = 1;
		return (1);
	}
}

/*
 * Add the record to wtmpx.
 */
void
updwtmpx(const char *filex, struct utmpx *utx)
{
	struct futmpx futx;
	int wfdx;

	if ((wfdx = open(filex, O_WRONLY | O_APPEND)) < 0)
		return;

	(void) lseek(wfdx, 0, SEEK_END);

	utmpx_api2frec(utx, &futx);
	(void) write(wfdx, &futx, sizeof (futx));

done:
	(void) close(wfdx);
}

/*
 * Add record to wtmp (actually wtmpx). If not updating /var/adm/wtmp,
 * use the old utmp compatibility routine to write a utmp-format
 * record to the file specified.
 */
void
updwtmp(const char *file, struct utmp *ut)
{
	struct utmpx utmpx;
	char xfile[MAXFILE + 1];

	if (strcmp(file, "/var/adm/wtmp") == 0) {
		(void) strlcpy(xfile, file, sizeof (xfile) - 1);
		(void) strcat(xfile, "x");
		getutmpx(ut, &utmpx);
		updwtmpx((const char *)&xfile, &utmpx);
	} else
		_compat_updwtmp(file, ut);
}

/*
 * modutx - modify a utmpx entry.  Also notify init about new pids or
 *	old pids that it no longer needs to care about
 *
 *	args:	utp- point to utmpx structure to be created
 */
struct utmpx *
modutx(const struct utmpx *utp)
{
	int i;
	struct utmpx utmp;		/* holding area */
	struct utmpx *ucp = &utmp;	/* and a pointer to it */
	struct utmpx *up;		/* "current" utmpx entry */
	struct futmpx *fup;		/* being examined */

	for (i = 0; i < IDLEN; ++i) {
		if ((unsigned char)utp->ut_id[i] == SC_WILDC)
			return (NULL);
	}

	/*
	 * copy the supplied utmpx structure someplace safe
	 */
	(void) memcpy(&utmp, utp, sizeof (utmp));
	setutxent();
	while (fup = getutxent_frec()) {
		if (idcmp(ucp->ut_id, fup->ut_id))
			continue;

		/*
		 * only get here if ids are the same, i.e. found right entry
		 */
		if (ucp->ut_pid != fup->ut_pid) {
			sendpid(REMPID, (pid_t)fup->ut_pid);
			sendpid(ADDPID, (pid_t)ucp->ut_pid);
		}
		break;
	}
	up = pututxline(ucp);
	if (ucp->ut_type == DEAD_PROCESS)
		sendpid(REMPID, (pid_t)ucp->ut_pid);
	if (up)
		updwtmpx(WTMPX_FILE, up);
	endutxent();
	return (up);
}

/*
 * modut - modify a utmp entry.	 Also notify init about new pids or
 *	old pids that it no longer needs to care about
 *
 *	args:	utmp - point to utmp structure to be created
 */
struct utmp *
modut(struct utmp *utp)
{
	struct utmpx utmpx;
	struct utmpx *utmpx2;

	getutmpx(utp, &utmpx);
	if ((utmpx2 = modutx(&utmpx)) == NULL)
		return (NULL);

	getutmp(utmpx2, utp);
	return (utp);
}

/*
 * idcmp - compare two id strings, return  0 if same, non-zero if not *
 *	args:	s1 - first id string
 *		s2 - second id string
 */
static int
idcmp(const char *s1, const char *s2)
{
	int i;

	for (i = 0; i < IDLEN; ++i)
		if ((unsigned char) *s1 != SC_WILDC && (*s1++ != *s2++))
			return (-1);
	return (0);
}


/*
 * allocid - allocate an unused id for utmp, either by recycling a
 *	DEAD_PROCESS entry or creating a new one.  This routine only
 *	gets called if a wild card character was specified.
 *
 *	args:	srcid - pattern for new id
 *		saveid - last id matching pattern for a non-dead process
 */
static int
allocid(char *srcid, unsigned char *saveid)
{
	int i;		/* scratch variable */
	int changed;		/* flag to indicate that a new id has */
				/* been generated */
	char copyid[IDLEN];	/* work area */

	(void) memcpy(copyid, srcid, IDLEN);
	changed = 0;
	for (i = 0; i < IDLEN; ++i) {

		/*
		 * if this character isn't wild, it'll be part of the
		 * generated id
		 */
		if ((unsigned char) copyid[i] != SC_WILDC)
			continue;

		/*
		 * it's a wild character, retrieve the character from the
		 * saved id
		 */
		copyid[i] = saveid[i];

		/*
		 * if we haven't changed anything yet, try to find a new char
		 * to use
		 */
		if (!changed && (saveid[i] < MAXVAL)) {

		/*
		 * Note: this algorithm is taking the "last matched" id
		 * and trying to make a 1 character change to it to create
		 * a new one.  Rather than special-case the first time
		 * (when no perturbation is really necessary), just don't
		 * allocate the first valid id.
		 */

			while (++saveid[i] < MAXVAL) {
				/*
				 * make sure new char is alphanumeric
				 */
				if (isalnum(saveid[i])) {
					copyid[i] = saveid[i];
					changed = 1;
					break;
				}
			}

			if (!changed) {
				/*
				 * Then 'reset' the current count at
				 * this position to it's lowest valid
				 * value, and propagate the carry to
				 * the next wild-card slot
				 *
				 * See 1113208.
				 */
				saveid[i] = 0;
				while (!isalnum(saveid[i]))
				saveid[i]++;
				copyid[i] = ++saveid[i];
			}
		}
	}
	/*
	 * changed is true if we were successful in allocating an id
	 */
	if (changed) {
		(void) memcpy(srcid, copyid, IDLEN);
		return (0);
	} else {
		return (-1);
	}
}


/*
 * lockutx - lock utmpx file
 */
static int
lockutx(void)
{
	int lockfd;

	if ((lockfd = open(UTMPX_FILE, O_RDWR|O_CREAT, 0644)) < 0)
		return (-1);

	if (lockf(lockfd, F_LOCK, 0) < 0) {
		(void) close(lockfd);
		return (-1);
	}

	tempfd = fd;
	fd = lockfd;

	return (0);

}



/*
 * unlockutx - unlock utmpx file
 */
static void
unlockutx(void)
{
	(void) lockf(fd, F_ULOCK, 0);
	(void) close(fd);
	fd = tempfd;
}


/*
 * sendpid - send message to init to add or remove a pid from the
 *	"godchild" list
 *
 *	args:	cmd - ADDPID or REMPID
 *		pid - pid of "godchild"
 */
static void
sendpid(int cmd, pid_t pid)
{
	int pfd;		/* file desc. for init pipe */
	pidrec_t prec;		/* place for message to be built */

	/*
	 * if for some reason init didn't open initpipe, open it read/write
	 * here to avoid sending SIGPIPE to the calling process
	 */
	pfd = open(IPIPE, O_RDWR);
	if (pfd < 0)
		return;
	prec.pd_pid = pid;
	prec.pd_type = cmd;
	(void) write(pfd, &prec, sizeof (pidrec_t));
	(void) close(pfd);
}

/*
 * makeutx - create a utmpx entry, recycling an id if a wild card is
 *	specified.  Also notify init about the new pid
 *
 *	args:	utmpx - point to utmpx structure to be created
 */

struct utmpx *
makeutx(const struct utmpx *utmp)
{
	struct utmpx *utp;
	struct futmpx *ut;		/* "current" utmpx being examined */
	unsigned char saveid[IDLEN];	/* the last id we matched that was */
					/* NOT a dead proc */
	int falphanum = 0x30;		/* first alpha num char */
	off_t offset;

	/*
	 * Are any wild card char's present in the idlen string?
	 */
	if (memchr(utmp->ut_id, SC_WILDC, IDLEN) != NULL) {
		/*
		 * try to lock the utmpx file, only needed if
		 * we're doing wildcard matching
		 */
		if (lockutx())
			return (NULL);

		/*
		 * used in allocid
		 */
		(void) memset(saveid, falphanum, IDLEN);

		while (ut = getoneutx(&offset))
			if (idcmp(utmp->ut_id, ut->ut_id)) {
				continue;
			} else {
				/*
				 * Found a match. We are done if this is
				 * a free slot. Else record this id. We
				 * will need it to generate the next new id.
				 */
				if (ut->ut_type == DEAD_PROCESS)
					break;
				else
					(void) memcpy(saveid, ut->ut_id,
					    IDLEN);
			}

		if (ut) {

			/*
			 * Unused entry, reuse it. We know the offset. So
			 * just go to that offset  utmpx and write it out.
			 */
			(void) memcpy((caddr_t)utmp->ut_id, ut->ut_id, IDLEN);

			putoneutx(utmp, offset);
			updwtmpx(WTMPX_FILE, (struct utmpx *)utmp);
			unlockutx();
			sendpid(ADDPID, (pid_t)utmp->ut_pid);
			return ((struct utmpx *)utmp);
		} else {
			/*
			 * nothing available, allocate an id and
			 * write it out at the end.
			 */

			if (allocid((char *)utmp->ut_id, saveid)) {
				unlockutx();
				return (NULL);
			} else {
				/*
				 * Seek to end and write out the entry
				 * and also update the utmpx file.
				 */
				(void) lseek(fd, 0L, SEEK_END);
				offset = lseek(fd, 0L, SEEK_CUR);

				putoneutx(utmp, offset);
				updwtmpx(WTMPX_FILE, (struct utmpx *)utmp);
				unlockutx();
				sendpid(ADDPID, (pid_t)utmp->ut_pid);
				return ((struct utmpx *)utmp);
			}
		}
	} else {
		utp = pututxline(utmp);
		if (utp)
			updwtmpx(WTMPX_FILE, utp);
		endutxent();
		sendpid(ADDPID, (pid_t)utmp->ut_pid);
		return (utp);
	}
}

/*
 * makeut - create a utmp entry, recycling an id if a wild card is
 *	specified.  Also notify init about the new pid
 *
 *	args:	utmp - point to utmp structure to be created
 */
struct utmp *
makeut(struct utmp *utmp)
{
	struct utmpx utmpx;
	struct utmpx *utmpx2;

	if (compat_utmpflag)
		return (_compat_makeut(utmp));

	getutmpx(utmp, &utmpx);
	if ((utmpx2 = makeutx(&utmpx)) == NULL)
		return (NULL);

	getutmp(utmpx2, utmp);
	return (utmp);
}


#define	UTMPNBUF	200	/* Approx 8k (FS Block) size */
static struct futmpx	*utmpbuf = NULL;

/*
 * Buffered read routine to get one entry from utmpx file
 */
static struct futmpx *
getoneutx(off_t *off)
{
	static	size_t idx = 0;	/* Current index in the utmpbuf */
	static	size_t nidx = 0;	/* Max entries in this utmpbuf */
	static	int nbuf = 0;	/* number of utmpbufs read from disk */
	ssize_t	nbytes, bufsz = sizeof (struct futmpx) * UTMPNBUF;

	if (utmpbuf == NULL)
		if ((utmpbuf = malloc(bufsz)) == NULL) {
			perror("malloc");
			return (NULL);
		}

	if (idx == nidx) {
		/*
		 *	We have read all entries in the utmpbuf. Read
		 *	the buffer from the disk.
		 */
		if ((nbytes = read(fd, utmpbuf, bufsz)) < bufsz) {
			/*
			 *	Partial read only. keep count of the
			 *	number of valid entries in the buffer
			 */
			nidx = nbytes / sizeof (struct futmpx);
		} else {
			/*
			 *	We read in the full UTMPNBUF entries
			 *	Great !
			 */
			nidx = UTMPNBUF;
		}
		nbuf++;		/* Number of buf we have read in. */
		idx = 0;	/* reset index within utmpbuf */
	}

	/*
	 *	Current offset of this buffer in the file
	 */
	*off = (((nbuf - 1) * UTMPNBUF) + idx) * sizeof (struct futmpx);

	if (idx < nidx) {
		/*
		 *	We still have at least one valid buffer in
		 *	utmpbuf to be passed to the caller.
		 */
		return (&utmpbuf[idx++]);
	}

	/*
	 *	Reached EOF. Return NULL. Offset is set correctly
	 *	to append at the end of the file
	 */

	return (NULL);
}

static void
putoneutx(const struct utmpx *utpx, off_t off)
{
	struct	futmpx futx;

	utmpx_api2frec(utpx, &futx);
	(void) lseek(fd, off, SEEK_SET);	/* seek in the utmpx file */
	(void) write(fd, &futx, sizeof (futx));
}

/*
 * sendupid - send message to utmpd to add or remove a pid from the
 *	list of procs to watch
 *
 *	args:	cmd - ADDPID or REMPID
 *		pid - process ID of process to watch
 */
static void
sendupid(int cmd, pid_t pid)
{
	int pfd;		/* file desc. for utmp pipe */
	pidrec_t prec;		/* place for message to be built */

	/*
	 * if for some reason utmp didn't open utmppipe, open it read/write
	 * here to avoid sending SIGPIPE to the calling process
	 */

	pfd = open(UPIPE, O_RDWR | O_NONBLOCK | O_NDELAY);
	if (pfd < 0)
		return;
	prec.pd_pid = pid;
	prec.pd_type = cmd;
	(void) write(pfd, &prec, sizeof (pidrec_t));
	(void) close(pfd);
}

/*
 * getutmpx - convert a utmp record into a utmpx record
 */
void
getutmpx(const struct utmp *ut, struct utmpx *utx)
{
	(void) memcpy(utx->ut_user, ut->ut_user, sizeof (ut->ut_user));
	(void) bzero(&utx->ut_user[sizeof (ut->ut_user)],
	    sizeof (utx->ut_user) - sizeof (ut->ut_user));
	(void) memcpy(utx->ut_line, ut->ut_line, sizeof (ut->ut_line));
	(void) bzero(&utx->ut_line[sizeof (ut->ut_line)],
	    sizeof (utx->ut_line) - sizeof (ut->ut_line));
	(void) memcpy(utx->ut_id, ut->ut_id, sizeof (ut->ut_id));
	utx->ut_pid = ut->ut_pid;
	utx->ut_type = ut->ut_type;
	utx->ut_exit = ut->ut_exit;
	utx->ut_tv.tv_sec = ut->ut_time;
	utx->ut_tv.tv_usec = 0;
	utx->ut_session = 0;
	bzero(utx->pad, sizeof (utx->pad));
	bzero(utx->ut_host, sizeof (utx->ut_host));
	utx->ut_syslen = 0;
}

/*
 * getutmp - convert a utmpx record into a utmp record
 */
void
getutmp(const struct utmpx *utx, struct utmp *ut)
{
	(void) memcpy(ut->ut_user, utx->ut_user, sizeof (ut->ut_user));
	(void) memcpy(ut->ut_line, utx->ut_line, sizeof (ut->ut_line));
	(void) memcpy(ut->ut_id, utx->ut_id, sizeof (utx->ut_id));
	ut->ut_pid = utx->ut_pid;
	ut->ut_type = utx->ut_type;
	ut->ut_exit = utx->ut_exit;
	ut->ut_time = utx->ut_tv.tv_sec;
}
