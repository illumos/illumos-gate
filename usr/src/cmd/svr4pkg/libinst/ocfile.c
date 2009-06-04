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

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */


#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <string.h>
#include <strings.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/statvfs.h>
#include <signal.h>
#include <limits.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <pkglocs.h>
#include <locale.h>
#include <libintl.h>
#include <pkglib.h>
#include "libinst.h"
#include "libadm.h"

#define	LOCKFILE	".pkg.lock"
#define	LOCKWAIT	10	/* seconds between retries */
#define	LOCKRETRY	20	/* number of retries for a DB lock */

#define	ERR_TC_WRITE	"WARNING: unable to write temp contents file <%s>"
#define	ERR_NOCLOSE	"WARNING: unable to close <%s>"
#define	ERR_NOUNLINK_LATENT	"WARNING: unable to unlink latent <%s>"
#define	ERR_LINK_FAIL	"link(%s, %s) failed (errno %d)"
#define	ERR_NORENAME_CONTENTS	"unable to establish contents file <%s> "\
			"from <%s>"
#define	ERR_RENAME_FAIL	"rename(%s, %s) failed (errno %d)"
#define	ERR_RESTORE_FAIL	"attempt to restore <%s> failed"
#define	ERR_NOUNLINK	"WARNING: unable to unlink <%s>"
#define	ERR_FCLOSE_FAIL	"fclose failed (errno %d)"
#define	ERR_ERRNO	"(errno %d: %s)"
#define	ERR_NOTMPOPEN	"unable to open temporary contents file image"
#define	ERR_CFBACK	"Not enough space to backup <%s>"
#define	ERR_CREAT_CONT	"unable to create contents file <%s>: %s"
#define	ERR_ACCESS_CONT	"unable to access contents file <%s>: %s"
#define	ERR_CFBACK1	"Need=%llu blocks, Available=%llu blocks " \
			"(block size=%d)"
#define	ERR_NOCFILE	"unable to locate contents file <%s>"
#define	ERR_NOROPEN	"unable to open <%s> for reading"
#define	ERR_NOOPEN	"unable to open <%s> for writing"
#define	ERR_NOSTAT	"unable to stat contents file <%s>"
#define	ERR_NOSTATV	"statvfs(%s) failed"
#define	ERR_NOUPD	"unable to update contents file"
#define	ERR_DRCONTCP	"unable to copy contents file to <%s>"

#define	MSG_XWTING	"NOTE: Waiting for exclusive access to the package " \
				"database."
#define	MSG_NOLOCK	"NOTE: Couldn't lock the package database."

#define	ERR_NOLOCK	"Database lock failed."
#define	ERR_OPLOCK	"unable to open lock file <%s>."
#define	ERR_MKLOCK	"unable to create lock file <%s>."
#define	ERR_LCKREM	"unable to lock package database - remote host " \
				"unavailable."
#define	ERR_BADLCK	"unable to lock package database - unknown error."
#define	ERR_DEADLCK	"unable to lock package database - deadlock condition."
#define	ERR_TMOUT	"unable to lock package database - too many retries."
#define	ERR_CFDIR	"unable to locate contents file directory"

static int	active_lock;
static int	lock_fd;	/* fd of LOCKFILE. */
static char	*pkgadm_dir;

static int	pkgWlock(int verbose);
static int	pkgWunlock(void);

/*
 * This VFP is used to cache the last copy of the contents file that was
 * written out - upon subsequent open if the contents file has not changed
 * since it was last written out, use the last cached copy that is still
 * in memory to avoid re-reading the contents file again. If the contents
 * file has changed since the cached copy was written out, the previous
 * copy is discarded and the new contents file contents are read in.
 */

static VFP_T	*contentsVfp = {(VFP_T *)NULL};

/*
 * This defines the maximum number of bytes that can be added to the contents
 * file for a single package - this must be higher than the largest expected
 * pkgmap file will ever be. This controls the amount of memory allocated for
 * the contents file additions. A pkgmap file with an average line length of
 * 128/256/512 bytes could add 62500/31250/15625 entries with this size. This
 * allows the contents file to have a fixed allocation without having to check
 * size and realloc as necessary with the attendant cost of the realloc. The
 * real memory used will only be those pages that are actually touched when
 * the contents file is written.
 */

#define	CONTENTS_DELTA	(32*1024*1024)	/* 32mb */

/* forward declarations */

int relslock(void);

/*ARGSUSED*/
static void
do_alarm(int n)
{
	(void) signal(SIGALRM, SIG_IGN);
	(void) signal(SIGALRM, do_alarm);
	(void) alarm(LOCKWAIT);
}

/*
 * Point packaging to the appropriate contents file. This is primarily used
 * to establish a dryrun contents file. If the malloc() doesn't work, this
 * returns 99 (internal error), else 0.
 */
int
set_cfdir(char *cfdir)
{
	char	realcf[PATH_MAX];
	char	tmpcf[PATH_MAX];
	int	status;

	if (cfdir == NULL) {
		pkgadm_dir = get_PKGADM();
		return (0);
	}

	if ((pkgadm_dir = strdup(cfdir)) == NULL) {
		return (99);
	}

	(void) snprintf(tmpcf, sizeof (tmpcf), "%s/contents", pkgadm_dir);

	/*
	 * return if a temporary contents file already exists -
	 * assume it is from a prior package in this series.
	 */

	if (access(tmpcf, F_OK) == 0) {
		return (0);
	}

	/*
	 * no temporary contents file exists - create one.
	 */

	(void) snprintf(realcf, sizeof (realcf), "%s/contents", get_PKGADM());

	/*
	 * If there's a contents file there already, copy it
	 * over, otherwise initialize one.
	 */

	/* create new contents file if one does not already exist */

	if (access(realcf, F_OK) != 0) {
		int n;

		n = open(tmpcf, O_WRONLY|O_CREAT|O_TRUNC|O_EXCL, 0644);
		if (n < 0) {
			progerr(gettext(ERR_CREAT_CONT), tmpcf,
						strerror(errno));
			return (99);
		}
		(void) close(n);
	} else {

		/* contents file exists, save in pkgadm-dir */

		status = copyf(realcf, tmpcf, (time_t)0);
		if (status != 0) {
			progerr(gettext(ERR_DRCONTCP), tmpcf);
			return (99);
		}
	}

	return (0);
}

/*
 * This function installs the database lock, opens the contents file for
 * reading and creates and opens the temporary contents file for read/write.
 * It returns 1 if successful, 0 otherwise.
 */
int
ocfile(VFP_T **r_mapvfp, VFP_T **r_tmpvfp, fsblkcnt_t map_blks)
{
	struct	stat64	statb;
	struct	statvfs64	svfsb;
	fsblkcnt_t free_blocks;
	fsblkcnt_t need_blocks;
	VFP_T		*mapvfp = (VFP_T *)NULL;
	VFP_T		*tmpvfp = (VFP_T *)NULL;
	char		contents[PATH_MAX];
	int		n;

	/* reset return VFP/FILE pointers */

	(*r_mapvfp) = (VFP_T *)NULL;
	(*r_tmpvfp) = (VFP_T *)NULL;

	/* establish package administration contents directory location */

	if (pkgadm_dir == NULL) {
		if (set_cfdir(NULL) != 0) {
			progerr(gettext(ERR_CFDIR));
			return (0);
		}
	}

	/* Lock the file for exclusive access */

	if (!pkgWlock(1)) {
		progerr(gettext(ERR_NOLOCK));
		return (0);
	}

	/* determine path to the primary contents file */

	(void) snprintf(contents, sizeof (contents), "%s/contents", pkgadm_dir);

	/*
	 * open the contents file to read only - if a previous contents file has
	 * been cached attempt to use that cached copy for the open, otherwise
	 * just open the contents file directly
	 */

	n = vfpCheckpointOpen(&contentsVfp, &mapvfp, contents, "r", VFP_NONE);

	/* return error if contents file cannot be accessed */

	if (n != 0) {
		int	lerrno = errno;

		if (errno == ENOENT) {
			progerr(gettext(ERR_NOCFILE), contents);
		} else {
			progerr(gettext(ERR_NOROPEN), contents);
		}

		logerr(gettext(ERR_ERRNO), lerrno, strerror(lerrno));
		return (0);
	}

	/*
	 * Check and see if there is enough space for the packaging commands
	 * to back up the contents file, if there is not, then do not allow
	 * execution to continue by failing the ocfile() call.
	 */

	/* Get the contents file size */

	if (fstat64(fileno(mapvfp->_vfpFile), &statb) == -1) {
		int	lerrno = errno;

		progerr(gettext(ERR_NOSTAT), contents);
		logerr(gettext(ERR_ERRNO), lerrno, strerror(lerrno));
		(void) vfpClose(&mapvfp);
		return (0);
	}

	/* Get the filesystem space */

	if (fstatvfs64(fileno(mapvfp->_vfpFile), &svfsb) == -1) {
		int	lerrno = errno;

		progerr(gettext(ERR_NOSTATV), contents);
		logerr(gettext(ERR_ERRNO), lerrno, strerror(lerrno));
		(void) vfpClose(&mapvfp);
		return (0);
	}

	free_blocks = (((fsblkcnt_t)svfsb.f_frsize > 0) ?
			howmany(svfsb.f_frsize, DEV_BSIZE) :
			howmany(svfsb.f_bsize, DEV_BSIZE)) * svfsb.f_bfree;

	if (map_blks == 0LL) {
		map_blks = 10LL;
	}

	/*
	 * Calculate the number of blocks we need to be able to operate on
	 * the contents file.
	 */
	need_blocks = map_blks +
		nblk(statb.st_size, svfsb.f_bsize, svfsb.f_frsize);

	if ((need_blocks + 10) > free_blocks) {
		progerr(gettext(ERR_CFBACK), contents);
		progerr(gettext(ERR_CFBACK1), need_blocks, free_blocks,
			DEV_BSIZE);
		(void) vfpClose(&mapvfp);
		return (0);
	}

	/*
	 * open the temporary contents file without a path name - this causes
	 * the "vfp" to be opened on in-memory storage only, the size of which
	 * is set following a successful return - this causes the temporary
	 * contents file to be maintained in memory only - if no changes are
	 * made as the primary contents file is processed, the in memory data
	 * is discarded and not written to the disk.
	 */

	if (vfpOpen(&tmpvfp, (char *)NULL, "w", VFP_NONE) != 0) {
		int	lerrno = errno;

		progerr(gettext(ERR_NOTMPOPEN));
		logerr(gettext(ERR_ERRNO), lerrno, strerror(lerrno));
		(void) vfpClose(&mapvfp);
		return (0);
	}

	/*
	 * set size of allocation for temporary contents file - this sets the
	 * size of the in-memory buffer associated with the open vfp.
	 */

	if (vfpSetSize(tmpvfp, statb.st_size + CONTENTS_DELTA) != 0) {
		int	lerrno = errno;

		progerr(gettext(ERR_NOTMPOPEN));
		logerr(gettext(ERR_ERRNO), lerrno, strerror(lerrno));
		(void) vfpClose(&tmpvfp);
		(void) vfpClose(&mapvfp);
		return (0);
	}

	/*
	 * now that the temporary file is opened, advise the vm system to start
	 * mapping the real contents file into memory if possible
	 */

	(void) vfpSetFlags(mapvfp, VFP_NEEDNOW);

	/* set return ->s to open vfps */

	(*r_mapvfp) = mapvfp;
	(*r_tmpvfp) = tmpvfp;

	return (1);	/* All OK */
}

/*
 * This is a simple open and lock of the contents file. It doesn't create a
 * temporary contents file and it doesn't need to do any space checking.
 * Returns 1 for OK and 0 for "didn't do it".
 */
int
socfile(VFP_T **r_mapvfp)
{
	VFP_T	*mapvfp = (VFP_T *)NULL;
	char	contents[PATH_MAX];
	int	n;

	/* reset return VFP/FILE pointer */

	(*r_mapvfp) = (VFP_T *)NULL;

	if (pkgadm_dir == NULL) {
		if (set_cfdir(NULL) != 0) {
			progerr(gettext(ERR_CFDIR));
			return (0);
		}
	}

	/*
	 * Lock the database for exclusive access, but don't make a fuss if
	 * it fails (user may not be root and the .pkg.lock file may not
	 * exist yet).
	 */

	if (!pkgWlock(0)) {
		logerr(gettext(MSG_NOLOCK));
	}

	/* open the contents file to read only */

	(void) snprintf(contents, sizeof (contents), "%s/contents", pkgadm_dir);

	n = vfpCheckpointOpen(&contentsVfp, &mapvfp, contents,
							"r", VFP_NEEDNOW);
	if (n != 0) {
		int lerrno = errno;

		if (errno == ENOENT) {
			progerr(gettext(ERR_NOCFILE), contents);
		} else {
			progerr(gettext(ERR_NOROPEN), contents);
		}
		logerr(gettext(ERR_ERRNO), lerrno, strerror(lerrno));
		return (0);
	}

	*r_mapvfp = mapvfp;

	return (1);
}

/*
 * Name:	swapcfile
 * Description: This function closes both the current and temporary contents
 *		files specified, and conditionally replaces the old transitory
 *		contents file with the newly updated temporary contents file.
 *		The "ocfile()" or "socfile()" functions must be called to re-
 *		open the real contents file for processing.
 * Arguments:	a_cfVfp - (VFP_T **) - [RW, *RW]
 *			This is the VFP associated with the real contents file
 *			that is being read from and data processed.
 *		a_cfTmpVfp - (VFP_T **) - [RW, *RW]
 *			This is the VFP associated with the temporary contents
 *			file that is being written to.
 *		pkginst - (char) - [RO, *RO]
 *			This is the name of the package being operated on;
 *			this is used to write the "last modified by xxx"
 *			comment at the end of the contents file.
 *		dbchg - (int) - [RO]
 *			== 0 - the temporary contents file has NOT been changed
 *				with respect to the real contents file; do not
 *				update the real contents file with the contents
 *				of the temporary contents file.
 *			!= 0 - the temporary contetns file HAS been changed with
 *				respect to the real contents file; DO update the
 *				real contents file with the contents of the
 *				temporary contents file.
 * Returns:	int	== RESULT_OK - successful
 *			== RESULT_WRN - successful with warnings
 *			== RESULT_ERR - failed with fatal errors - deserves an
 *				alarming message and a quit()
 * NOTES: If dbchg != 0, the contents file is always updated. If dbchg == 0,
 *		the contents file is updated IF the data is modified indication
 *		is set on the contents file associated with a_cfTmpVfp.
 */

int
swapcfile(VFP_T **a_cfVfp, VFP_T **a_cfTmpVfp, char *pkginst, int dbchg)
{
	char	*pe;
	char	*pl;
	char	*ps;
	char	contentsPath[PATH_MAX] = {'\0'};
	char	line[256];
	char	sContentsPath[PATH_MAX] = {'\0'};
	char	tContentsPath[PATH_MAX] = {'\0'};
	char	timeb[BUFSIZ];
	int	retval = RESULT_OK;
	struct tm	*timep;
	time_t	clock;

	/* normalize pkginst so its never null */

	if (pkginst == (char *)NULL) {
		dbchg = 0;
		pkginst = "<unknown>";
	}

	/* cache all paths for the associated open files */

	(void) strlcpy(contentsPath, vfpGetPath(*a_cfVfp),
			sizeof (contentsPath));

	(void) snprintf(tContentsPath, sizeof (tContentsPath),
			"%s/t.contents", pkgadm_dir);

	(void) snprintf(sContentsPath, sizeof (sContentsPath),
			"%s/s.contents", pkgadm_dir);

	/* original contents file no longer needed - close */

	if (vfpClose(a_cfVfp) != 0) {
		int	lerrno = errno;

		logerr(gettext(ERR_NOCLOSE), contentsPath);
		logerr(gettext(ERR_ERRNO), lerrno, strerror(lerrno));
		retval = RESULT_WRN;
	}

	/*
	 * If no changes were made to the database, checkpoint the temporary
	 * contents file - if this fails, then just close the file which causes
	 * the contents file to be reopened and reread if it is needed again
	 */

	if ((dbchg == 0) && (vfpGetModified(*a_cfTmpVfp) == 0)) {
		if (vfpCheckpointFile(&contentsVfp, a_cfTmpVfp,
							contentsPath) != 0) {
			vfpClose(a_cfTmpVfp);
		}
		(void) pkgWunlock();	/* Free the database lock. */
		return (retval);
	}

	/*
	 * changes made to the current temporary contents file -
	 * remove any trailing comment lines in the temp contents file, then
	 * append updated modification info records to temp contents file
	 */

	pe = vfpGetCurrCharPtr(*a_cfTmpVfp);	/* last char in contents file */
	ps = vfpGetFirstCharPtr(*a_cfTmpVfp);	/* 1st char in contents file */
	pl = pe;	/* last match is last char in contents file */

	/* skip past all trailing newlines and null bytes */

	while ((pe > ps) && ((*pe == '\n') || (*pe == '\0'))) {
		pe--;
	}

	/* remove trailing comments as long as there are lines in the file */

	while (pe > ps) {
		if (*pe != '\n') {
			/* curr char is not newline: backup one byte */
			pl = pe--;
		} else if (*pl != '#') {
			/* curr char is newline next char not comment break */
			break;
		} else {
			/* curr char is newline next char is comment - remove */
			*pl = '\0';
			vfpSetLastCharPtr(*a_cfTmpVfp, pl);
			pe--;
		}
	}

	/* create two update comment lines */

	(void) time(&clock);
	timep = localtime(&clock);

	(void) strftime(timeb, sizeof (timeb), "%c\n", timep);
	(void) snprintf(line, sizeof (line),
		gettext("# Last modified by %s for %s package\n# %s"),
		get_prog_name(), pkginst, timeb);
	vfpPuts(*a_cfTmpVfp, line);

	/* commit temporary contents file bytes to storage */

	if (vfpWriteToFile(*a_cfTmpVfp, tContentsPath) != 0) {
		int	lerrno = errno;

		logerr(gettext(ERR_TC_WRITE), tContentsPath);
		logerr(gettext(ERR_ERRNO), lerrno, strerror(lerrno));
		vfpClose(a_cfTmpVfp);
		(void) remove(tContentsPath);
		(void) pkgWunlock();	/* Free the database lock. */
		return (RESULT_ERR);
	}

	/*
	 * Now we want to make a copy of the old contents file as a
	 * fail-safe. In support of that, we create a hard link to
	 * s.contents.
	 */

	if ((access(sContentsPath, F_OK) == 0) && remove(sContentsPath)) {
		int	lerrno = errno;

		logerr(gettext(ERR_NOUNLINK_LATENT), sContentsPath);
		logerr(gettext(ERR_ERRNO), lerrno, strerror(lerrno));
		(void) remove(tContentsPath);
		(void) pkgWunlock();	/* Free the database lock. */
		vfpClose(a_cfTmpVfp);
		return (RESULT_ERR);
	}

	if (link(contentsPath, sContentsPath) != 0) {
		int	lerrno = errno;

		progerr(gettext(ERR_NOUPD));
		logerr(gettext(ERR_LINK_FAIL), contentsPath, sContentsPath,
			lerrno);
		(void) remove(tContentsPath);
		(void) pkgWunlock();	/* Free the database lock. */
		vfpClose(a_cfTmpVfp);
		return (RESULT_ERR);
	}

	if (rename(tContentsPath, contentsPath) != 0) {
		int	lerrno = errno;

		progerr(gettext(ERR_NORENAME_CONTENTS), contentsPath,
			tContentsPath);
		logerr(gettext(ERR_RENAME_FAIL), tContentsPath,
			contentsPath, lerrno);
		if (rename(sContentsPath, contentsPath)) {
			lerrno = errno;
			progerr(gettext(ERR_RESTORE_FAIL), contentsPath);
			logerr(gettext(ERR_RENAME_FAIL), sContentsPath,
				contentsPath, lerrno);
		}
		(void) remove(tContentsPath);
	}

	if (remove(sContentsPath) != 0) {
		int	lerrno = errno;

		logerr(gettext(ERR_NOUNLINK), sContentsPath);
		logerr(gettext(ERR_ERRNO), lerrno, strerror(lerrno));
		retval = RESULT_WRN;
	}

	/*
	 * checkpoint the temporary contents file - if this fails, then
	 * just close the file which causes the contents file to be reopened
	 * and reread if it is needed again
	 */

	if (vfpCheckpointFile(&contentsVfp, a_cfTmpVfp, contentsPath) != 0) {
		vfpClose(a_cfTmpVfp);
	}

	return (relslock() == 0 ? RESULT_ERR : retval);
}

/* This function releases the lock on the package database. */
int
relslock(void)
{
	/*
	 * This closes the contents file and releases the lock.
	 */
	if (!pkgWunlock()) {
		int	lerrno = errno;

		progerr(gettext(ERR_NOUPD));
		logerr(gettext(ERR_FCLOSE_FAIL), lerrno);
		return (0);
	}
	return (1);
}

/*
 * This function attempts to lock the package database. It returns 1 on
 * success, 0 on failure. The positive logic verbose flag determines whether
 * or not the function displays the error message upon failure.
 */
static int
pkgWlock(int verbose) {
	int retry_cnt, retval;
	char lockpath[PATH_MAX];

	active_lock = 0;

	(void) snprintf(lockpath, sizeof (lockpath),
			"%s/%s", pkgadm_dir, LOCKFILE);

	retry_cnt = LOCKRETRY;

	/*
	 * If the lock file is not present, create it. The mode is set to
	 * allow any process to lock the database, that's because pkgchk may
	 * be run by a non-root user.
	 */
	if (access(lockpath, F_OK) == -1) {
		lock_fd = open(lockpath, O_RDWR|O_CREAT|O_TRUNC|O_EXCL, 0644);
		if (lock_fd < 0) {
			if (verbose)
				progerr(gettext(ERR_MKLOCK), lockpath);
			return (0);
		} else {
			(void) fchmod(lock_fd, 0644);	/* force perms. */
		}
	} else {
		if ((lock_fd = open(lockpath, O_RDWR)) == -1) {
			if (verbose)
				progerr(gettext(ERR_OPLOCK), lockpath);
			return (0);
		}
	}

	(void) signal(SIGALRM, do_alarm);
	(void) alarm(LOCKWAIT);

	do {
		if (lockf(lock_fd, F_LOCK, 0)) {
			if (errno == EAGAIN || errno == EINTR)
				logerr(gettext(MSG_XWTING));
			else if (errno == ECOMM) {
				logerr(gettext(ERR_LCKREM));
				retval = 0;
				break;
			} else if (errno == EBADF) {
				logerr(gettext(ERR_BADLCK));
				retval = 0;
				break;
			} else if (errno == EDEADLK) {
				logerr(gettext(ERR_DEADLCK));
				retval = 0;
				break;
			}
		} else {
			active_lock = 1;
			retval = 1;
			break;
		}
	} while (retry_cnt--);

	(void) signal(SIGALRM, SIG_IGN);

	if (retval == 0)
	{
		if (retry_cnt == -1) {
			logerr(gettext(ERR_TMOUT));
		}

		(void) pkgWunlock();	/* close the lockfile. */
	}

	return (retval);
}

/*
 * Release the lock on the package database. Returns 1 on success, 0 on
 * failure.
 */
static int
pkgWunlock(void) {
	if (active_lock) {
		active_lock = 0;
		if (close(lock_fd))
			return (0);
		else
			return (1);
	} else
		return (1);
}

/*
 * This function verifies that the contents file is in place.
 * returns 1 - if it exists
 * returns 0 - if it does not exist
 */
int
iscfile(void)
{
	char	contents[PATH_MAX];

	(void) snprintf(contents, PATH_MAX, "%s/contents", get_PKGADM());

	return (access(contents, F_OK) == 0 ? 1 : 0);
}

/*
 * This function verifies that the contents file is in place. If it is - no
 * change. If it isn't - this creates it.
 * Returns:	== 0 : failure
 *		!= 0 : success
 */

int
vcfile(void)
{
	int	lerrno;
	int	fd;
	char	contents[PATH_MAX];

	/*
	 * create full path to contents file
	 */

	(void) snprintf(contents, sizeof (contents),
			"%s/contents", get_PKGADM());

	/*
	 * Attempt to create the file - will only be successful
	 * if the file does not currently exist.
	 */

	fd = open(contents, O_WRONLY | O_CREAT | O_EXCL, 0644);
	if (fd >= 0) {
		/*
		 * Contents file wasn't there, but is now.
		 */

		echo(gettext("## Software contents file initialized"));
		(void) close(fd);
		return (1);	/* success */
	}

	/*
	 * Could not create the file - it may exist or there may be
	 * permissions issues - find out and act accordingly.
	 */

	lerrno = errno;

	/* success if error is 'file exists' */

	if (lerrno == EEXIST) {
		return (1);	/* success */
	}

	/* success if error is 'permission denied' but file exists */

	if (lerrno == EACCES) {
		/*
		 * Because O_CREAT and O_EXCL are specified in open(),
		 * if the contents file already exists, the open will
		 * fail with EACCES - determine if this is the case -
		 * if so return success.
		 */

		if (access(contents, F_OK) == 0) {
			return (1);	/* success */
		}

		/*
		 * access() failed - if because of permissions failure this
		 * means the contents file exists but it cannot be accessed
		 * or the path to the contents file cannot be accessed - in
		 * either case the contents file cannot be accessed.
		 */

		if (errno == EACCES) {
			progerr(gettext(ERR_ACCESS_CONT), contents,
					strerror(lerrno));
			logerr(gettext(ERR_ERRNO), lerrno, strerror(lerrno));
			return (0);	/* failure */
		}
	}

	/*
	 * the contents file does not exist and it cannot be created.
	 */

	progerr(gettext(ERR_CREAT_CONT), contents, strerror(lerrno));
	logerr(gettext(ERR_ERRNO), lerrno, strerror(lerrno));
	return (0);	/* failure */
}
