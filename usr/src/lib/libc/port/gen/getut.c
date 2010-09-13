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
 * Compatibility routines to read and write alternate
 * utmp-like files.  These routines are only used in
 * the case where utmpname() is used to change to a file
 * other than /var/adm/utmp or /var/adm/wtmp.  In this case,
 * we assume that someone really wants to read old utmp-format
 * files.  Otherwise, the getutent, setutent, getutid, setutline,
 * and pututline functions are actually wrappers around the
 * equivalent function operating on utmpx-like files.
 */

#include "lint.h"
#include <stdio.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <utmpx.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <utime.h>
#include <sys/wait.h>

#define	IDLEN	4	/* length of id field in utmp */
#define	SC_WILDC	0xff	/* wild char for utmp ids */
#define	MAXVAL	255	/* max value for an id 'character' */

#ifdef ut_time
#undef ut_time
#endif

static void	utmp_frec2api(const struct futmp *, struct utmp *);
static void	utmp_api2frec(const struct utmp *, struct futmp *);
struct utmp 	*_compat_getutent(void);
struct utmp	*_compat_getutid(const struct utmp *);
struct utmp	*_compat_getutline(const struct utmp *);
struct utmp	*_compat_pututline(const struct utmp *);
void		_compat_setutent(void);
void		_compat_endutent(void);
void		_compat_updwtmp(const char *, struct utmp *);
struct utmp	*_compat_makeut(struct utmp *);
struct utmp	*_compat_modut(struct utmp *);

static void	unlockut(void);
static int	idcmp(const char *, const char *);
static int	allocid(char *, unsigned char *);
static int	lockut(void);


static int fd = -1;	/* File descriptor for the utmp file. */
/*
 * name of the current utmp-like file - set by utmpname (getutx.c)
 * only if running in backward compatibility mode
 * We don't modify this, but we can't declare it const or lint will freak.
 */
extern char _compat_utmpfile[];

#ifdef ERRDEBUG
static long loc_utmp;	/* Where in "utmp" the current "ubuf" was found. */
#endif

static struct futmp fubuf;	/* Copy of last entry read in. */
static struct utmp ubuf;	/* Last entry returned to client */

/*
 * In the 64-bit world, the utmp data structure grows because of
 * the ut_time field (a time_t) at the end of it.
 */
static void
utmp_frec2api(const struct futmp *src, struct utmp *dst)
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
	dst->ut_time = (time_t)src->ut_time;
}

static void
utmp_api2frec(const struct utmp *src, struct futmp *dst)
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
	dst->ut_time = (time32_t)src->ut_time;
}

/*
 * "getutent_frec" gets the raw version of the next entry in the utmp file.
 */
static struct futmp *
getutent_frec(void)
{
	/*
	 * If the "utmp" file is not open, attempt to open it for
	 * reading.  If there is no file, attempt to create one.  If
	 * both attempts fail, return NULL.  If the file exists, but
	 * isn't readable and writeable, do not attempt to create.
	 */
	if (fd < 0) {
		if ((fd = open(_compat_utmpfile, O_RDWR|O_CREAT, 0644)) < 0) {

			/*
			 * If the open failed for permissions, try opening
			 * it only for reading.  All "pututline()" later
			 * will fail the writes.
			 */
			if ((fd = open(_compat_utmpfile, O_RDONLY)) < 0)
				return (NULL);
		}
	}

	/* Try to read in the next entry from the utmp file.  */

	if (read(fd, &fubuf, sizeof (fubuf)) != sizeof (fubuf)) {
		bzero(&fubuf, sizeof (fubuf));
		return (NULL);
	}

	/* Save the location in the file where this entry was found. */

	(void) lseek(fd, 0L, 1);
	return (&fubuf);
}

/*
 * "_compat_getutent" gets the next entry in the utmp file.
 */
struct utmp *
_compat_getutent(void)
{
	struct futmp *futp;

	futp = getutent_frec();
	utmp_frec2api(&fubuf, &ubuf);
	if (futp == NULL)
		return (NULL);
	return (&ubuf);
}

/*
 * "_compat_getutid" finds the specified entry in the utmp file.  If
 * it can't find it, it returns NULL.
 */
struct utmp *
_compat_getutid(const struct utmp *entry)
{
	short type;

	utmp_api2frec(&ubuf, &fubuf);

	/*
	 * Start looking for entry.  Look in our current buffer before
	 * reading in new entries.
	 */
	do {
		/*
		 * If there is no entry in "ubuf", skip to the read.
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
			 * For RUN_LVL, BOOT_TIME, DOWN_TIME,
			 * OLD_TIME, and NEW_TIME entries, only the
			 * types have to match.  If they do, return
			 * the address of internal buffer.
			 */
			case RUN_LVL:
			case BOOT_TIME:
			case DOWN_TIME:
			case OLD_TIME:
			case NEW_TIME:
				if (entry->ut_type == fubuf.ut_type) {
					utmp_frec2api(&fubuf, &ubuf);
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
				    fubuf.ut_id[0] == entry->ut_id[0] &&
				    fubuf.ut_id[1] == entry->ut_id[1] &&
				    fubuf.ut_id[2] == entry->ut_id[2] &&
				    fubuf.ut_id[3] == entry->ut_id[3]) {
					utmp_frec2api(&fubuf, &ubuf);
					return (&ubuf);
				}
				break;

			/* Do not search for illegal types of entry. */
			default:
				return (NULL);
			}
		}
	} while (getutent_frec() != NULL);

	/* the proper entry wasn't found. */

	utmp_frec2api(&fubuf, &ubuf);
	return (NULL);
}

/*
 * "_compat_getutline" searches the "utmp" file for a LOGIN_PROCESS or
 * USER_PROCESS with the same "line" as the specified "entry".
 */
struct utmp *
_compat_getutline(const struct utmp *entry)
{
	utmp_api2frec(&ubuf, &fubuf);

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
			utmp_frec2api(&fubuf, &ubuf);
			return (&ubuf);
		}
	} while (getutent_frec() != NULL);

	utmp_frec2api(&fubuf, &ubuf);
	return (NULL);
}

/*
 * "_compat_pututline" writes the structure sent into the utmp file
 * If there is already an entry with the same id, then it is
 * overwritten, otherwise a new entry is made at the end of the
 * utmp file.
 */
struct utmp *
_compat_pututline(const struct utmp *entry)
{
	int fc;
	struct utmp *answer;
	struct utmp tmpbuf;
	struct futmp ftmpbuf;

	/*
	 * Copy the user supplied entry into our temporary buffer to
	 * avoid the possibility that the user is actually passing us
	 * the address of "ubuf".
	 */
	tmpbuf = *entry;
	utmp_api2frec(entry, &ftmpbuf);

	(void) getutent_frec();
	if (fd < 0) {
#ifdef	ERRDEBUG
		gdebug("pututline: Unable to create utmp file.\n");
#endif
		return (NULL);
	}

	/* Make sure file is writable */

	if ((fc = fcntl(fd, F_GETFL, NULL)) == -1 || (fc & O_RDWR) != O_RDWR)
		return (NULL);

	/*
	 * Find the proper entry in the utmp file.  Start at the current
	 * location.  If it isn't found from here to the end of the
	 * file, then reset to the beginning of the file and try again.
	 * If it still isn't found, then write a new entry at the end of
	 * the file.  (Making sure the location is an integral number of
	 * utmp structures into the file incase the file is scribbled.)
	 */

	if (_compat_getutid(&tmpbuf) == NULL) {
#ifdef	ERRDEBUG
		gdebug("1st getutid() failed. fd: %d", fd);
#endif
		_compat_setutent();
		if (_compat_getutid(&tmpbuf) == NULL) {
#ifdef	ERRDEBUG
			loc_utmp = lseek(fd, 0L, 1);
			gdebug("2nd getutid() failed. fd: %d loc_utmp: %ld\n",
			    fd, loc_utmp);
#endif
			(void) fcntl(fd, F_SETFL, fc | O_APPEND);
		} else
			(void) lseek(fd, -(long)sizeof (struct futmp), 1);
	} else
		(void) lseek(fd, -(long)sizeof (struct futmp), 1);

	/*
	 * Write out the user supplied structure.  If the write fails,
	 * then the user probably doesn't have permission to write the
	 * utmp file.
	 */
	if (write(fd, &ftmpbuf, sizeof (ftmpbuf)) != sizeof (ftmpbuf)) {
#ifdef	ERRDEBUG
		gdebug("pututline failed: write-%d\n", errno);
#endif
		answer = NULL;
	} else {
		/*
		 * Copy the new user structure into ubuf so that it will
		 * be up to date in the future.
		 */
		fubuf = ftmpbuf;
		utmp_frec2api(&fubuf, &ubuf);
		answer = &ubuf;

#ifdef	ERRDEBUG
		gdebug("id: %c%c loc: %ld\n", fubuf.ut_id[0],
		    fubuf.ut_id[1], fubuf.ut_id[2], fubuf.ut_id[3],
		    loc_utmp);
#endif
	}

	(void) fcntl(fd, F_SETFL, fc);

	return (answer);
}

/*
 * "_compat_setutent" just resets the utmp file back to the beginning.
 */
void
_compat_setutent(void)
{
	if (fd != -1)
		(void) lseek(fd, 0L, 0);

	/*
	 * Zero the stored copy of the last entry read, since we are
	 * resetting to the beginning of the file.
	 */
	bzero(&ubuf, sizeof (ubuf));
	bzero(&fubuf, sizeof (fubuf));
}

/*
 * "_compat_endutent" closes the utmp file.
 */
void
_compat_endutent(void)
{
	if (fd != -1)
		(void) close(fd);
	fd = -1;
	bzero(&ubuf, sizeof (ubuf));
	bzero(&fubuf, sizeof (fubuf));
}


/*
 * If one of wtmp and wtmpx files exist, create the other, and the record.
 * If they both exist add the record.
 */
void
_compat_updwtmp(const char *file, struct utmp *ut)
{
	struct futmp fut;
	int fd;


	fd = open(file, O_WRONLY | O_APPEND);

	if (fd < 0) {
		if ((fd = open(file, O_WRONLY|O_CREAT, 0644)) < 0)
			return;
	}

	(void) lseek(fd, 0, 2);

	utmp_api2frec(ut, &fut);
	(void) write(fd, &fut, sizeof (fut));

	(void) close(fd);
}



/*
 * makeut - create a utmp entry, recycling an id if a wild card is
 *	specified.
 *
 *	args:	utmp - point to utmp structure to be created
 */
struct utmp *
_compat_makeut(struct utmp *utmp)
{
	int i;
	struct utmp *utp;	/* "current" utmp entry being examined */
	int wild;		/* flag, true iff wild card char seen */

	/* the last id we matched that was NOT a dead proc */
	unsigned char saveid[IDLEN];

	wild = 0;
	for (i = 0; i < IDLEN; i++)
		if ((unsigned char)utmp->ut_id[i] == SC_WILDC) {
			wild = 1;
			break;
		}

	if (wild) {

		/*
		 * try to lock the utmp file, only needed if we're
		 * doing wildcard matching
		 */

		if (lockut())
			return (0);
		_compat_setutent();

		/* find the first alphanumeric character */
		for (i = 0; i < MAXVAL; ++i)
			if (isalnum(i))
				break;

		(void) memset(saveid, i, IDLEN);

		while ((utp = _compat_getutent()) != 0) {
			if (idcmp(utmp->ut_id, utp->ut_id))
				continue;
			if (utp->ut_type == DEAD_PROCESS)
				break;
			(void) memcpy(saveid, utp->ut_id, IDLEN);
		}

		if (utp) {
			/*
			 * found an unused entry, reuse it
			 */
			(void) memcpy(utmp->ut_id, utp->ut_id, IDLEN);
			utp = _compat_pututline(utmp);
			if (utp)
				_compat_updwtmp(WTMP_FILE, utp);
			_compat_endutent();
			unlockut();
			return (utp);

		} else {
			/*
			 * nothing available, try to allocate an id
			 */
			if (allocid(utmp->ut_id, saveid)) {
				_compat_endutent();
				unlockut();
				return (NULL);
			} else {
				utp = _compat_pututline(utmp);
				if (utp)
					_compat_updwtmp(WTMP_FILE, utp);
				_compat_endutent();
				unlockut();
				return (utp);
			}
		}
	} else {
		utp = _compat_pututline(utmp);
		if (utp)
			_compat_updwtmp(WTMP_FILE, utp);
		_compat_endutent();
		return (utp);
	}
}


/*
 * _compat_modut - modify a utmp entry.
 *
 *	args:	utmp - point to utmp structure to be created
 */
struct utmp *
_compat_modut(struct utmp *utp)
{
	int i;					/* scratch variable */
	struct utmp utmp;			/* holding area */
	struct utmp *ucp = &utmp;		/* and a pointer to it */
	struct utmp *up;	/* "current" utmp entry being examined */
	struct futmp *fup;

	for (i = 0; i < IDLEN; ++i)
		if ((unsigned char)utp->ut_id[i] == SC_WILDC)
			return (0);

	/* copy the supplied utmp structure someplace safe */
	utmp = *utp;
	_compat_setutent();
	while (fup = getutent_frec()) {
		if (idcmp(ucp->ut_id, fup->ut_id))
			continue;
		break;
	}
	up = _compat_pututline(ucp);
	if (up)
		_compat_updwtmp(WTMP_FILE, up);
	_compat_endutent();
	return (up);
}



/*
 * idcmp - compare two id strings, return 0 if same, non-zero if not *
 *	args:	s1 - first id string
 *		s2 - second id string
 */
static int
idcmp(const char *s1, const char *s2)
{
	int i;

	for (i = 0; i < IDLEN; ++i)
		if ((unsigned char)*s1 != SC_WILDC && (*s1++ != *s2++))
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
	int changed;	/* flag to indicate that a new id has been generated */
	char copyid[IDLEN];	/* work area */

	(void) memcpy(copyid, srcid, IDLEN);
	changed = 0;
	for (i = 0; i < IDLEN; ++i) {
		/*
		 * if this character isn't wild, it'll
		 * be part of the generated id
		 */
		if ((unsigned char) copyid[i] != SC_WILDC)
			continue;
		/*
		 * it's a wild character, retrieve the
		 * character from the saved id
		 */
		copyid[i] = saveid[i];
		/*
		 * if we haven't changed anything yet,
		 * try to find a new char to use
		 */
		if (!changed && (saveid[i] < MAXVAL)) {

/*
 * Note: this algorithm is taking the "last matched" id and trying to make
 * a 1 character change to it to create a new one.  Rather than special-case
 * the first time (when no perturbation is really necessary), just don't
 * allocate the first valid id.
 */

			while (++saveid[i] < MAXVAL) {
				/* make sure new char is alphanumeric */
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
	/* changed is true if we were successful in allocating an id */
	if (changed) {
		(void) memcpy(srcid, copyid, IDLEN);
		return (0);
	} else
		return (-1);
}


/*
 * lockut - lock utmp file
 */
static int
lockut(void)
{
	if ((fd = open(_compat_utmpfile, O_RDWR|O_CREAT, 0644)) < 0)
		return (-1);

	if (lockf(fd, F_LOCK, 0) < 0) {
		(void) close(fd);
		fd = -1;
		return (-1);
	}
	return (0);
}


/*
 * unlockut - unlock utmp file
 */
static void
unlockut(void)
{
	(void) lockf(fd, F_ULOCK, 0);
	(void) close(fd);
	fd = -1;
}



#ifdef  ERRDEBUG

#include <stdarg.h>
#include <stdio.h>

static void
gdebug(const char *fmt, ...)
{
	FILE *fp;
	int errnum;
	va_list ap;

	if ((fp = fopen("/etc/dbg.getut", "a+F")) == NULL)
		return;
	va_start(ap, fmt);
	(void) vfprintf(fp, fmt, ap);
	va_end(ap);
	(void) fclose(fp);
}
#endif
