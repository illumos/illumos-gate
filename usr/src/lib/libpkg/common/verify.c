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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */



#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <utime.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <grp.h>
#include <pwd.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sys/mkdev.h>
#include "pkgstrct.h"
#include "pkglib.h"
#include "pkglibmsgs.h"
#include "pkglocale.h"

#define	WDMSK	0xFFFF
#define	DATEFMT	"%D %r"
#define	LONG_BOUNDARY	((sizeof (unsigned long))-1)
#define	CHUNK	1024*1024

static char	theErrBuf[PATH_MAX+512] = {'\0'};
static char	*theErrStr = NULL;

/* checksum disable switch */
static int	enable_checksum = 1;

/* attribute disable flag */
static int	disable_attributes = 0;

/* non-ABI symlinks supported */
static int	nonabi_symlinks;

/*
 * forward declarations
 */

static int	clear_target(char *path, char *ftype, int is_a_dir);

unsigned	long compute_checksum(int *r_err, char *path);

/* union used to generate checksum */
typedef union hilo {
	struct part {
		uint16_t hi;
		uint16_t lo;
	} hl;
	uint32_t	lg;
} CHECKSUM_T;

/*PRINTFLIKE1*/
static void
reperr(char *fmt, ...)
{
	char	*pt;
	ssize_t	ptln;
	va_list	ap;
	int	n;

	if (fmt == (char *)NULL) {
		theErrBuf[0] = '\0';
	} else {
		if (n = strlen(theErrBuf)) {
			pt = theErrBuf + n;
			*pt++ = '\n';
			*pt = '\0';
			ptln = sizeof (theErrBuf)-n;
		} else {
			pt = theErrBuf;
			ptln = sizeof (theErrBuf);
		}
		va_start(ap, fmt);
		(void) vsnprintf(pt, ptln, fmt, ap);
		va_end(ap);
	}
}

/*
 * Name:	cverify
 * Description:	This function verifies and (if fix > 0) fixes the contents
 *		of the file at the path provided
 * Arguments:	fix - 0 - do not fix entries, 1 - fix entries
 *		ftype - single character "type" the entry is supposed to be
 *		path - path to file
 *		cinfo - content info structure representing the contents
 *			the entry is supposed to contain
 *		allow_checksum - determine if checksumming should be disabled:
 *		 == 0 - do not perform checksum ever - override enable_checksum.
 *		 != 0 - use the default checksum flag "enable_checksum" to
 *			determine if checksumming should be done.
 * NOTE:	modification and creation times can be repaired; the contents
 *		of the file cannot be corrected if the checksum indicates that
 *		the contents are not correct - VE_CONT will be returned in this
 *		case.
 * Possible return values:
 * - 0 = successful
 * - VE_EXIST = path name does not exist
 * - VE_FTYPE = path file type is not recognized, is not supported,
 *		or is not what was expected
 * - VE_ATTR = path mode/group/user is not what was expected
 * - VE_CONT = mod time/link target/major/minor/size/file system type/current
 *		directory is not what was expected
 * - VE_FAIL = utime/target directory/link/stat/symlink/mknod/chmod/statvfs/
 *		chown failed
 */

int
cverify(int fix, char *ftype, char *path, struct cinfo *cinfo,
    int allow_checksum)
{
	struct stat	status;		/* file status buffer */
	struct utimbuf	times;
	unsigned long	mycksum;
	int		setval, retcode;
	char		tbuf1[512];
	char		tbuf2[512];
	int		cksumerr;

	setval = (*ftype == '?');
	retcode = 0;
	reperr(NULL);

	if (stat(path, &status) < 0) {
		reperr(pkg_gt(ERR_EXIST));
		return (VE_EXIST);
	}

	/* -1	requires modtimes to be the same */
	/*  0   reports modtime failure */
	/*  1   fixes modtimes */

	if (setval || (cinfo->modtime == BADCONT)) {
		cinfo->modtime = status.st_mtime;
	} else if (status.st_mtime != cinfo->modtime) {
		if (fix > 0) {
			/* reset times on the file */
			times.actime = cinfo->modtime;
			times.modtime = cinfo->modtime;
			if (utime(path, &times)) {
				reperr(pkg_gt(ERR_MODFAIL));
				retcode = VE_FAIL;
			}
		} else if (fix < 0) {
			/* modtimes must be the same */
			if (strftime(tbuf1, sizeof (tbuf1), DATEFMT,
			    localtime(&cinfo->modtime)) == 0) {
				reperr(pkg_gt(ERR_MEM));
			}
			if (strftime(tbuf2, sizeof (tbuf2), DATEFMT,
			    localtime(&status.st_mtime)) == 0) {
				reperr(pkg_gt(ERR_MEM));
			}
			reperr(pkg_gt(ERR_MTIME), tbuf1, tbuf2);
			retcode = VE_CONT;
		}
	}

	if (setval || (cinfo->size == (fsblkcnt_t)BADCONT)) {
		cinfo->size = status.st_size;
	} else if (status.st_size != cinfo->size) {
		if (!retcode) {
			retcode = VE_CONT;
		}
		reperr(pkg_gt(ERR_SIZE), cinfo->size, status.st_size);
	}

	cksumerr = 0;

	/*
	 * see if checksumming should be done: if checksumming is allowed,
	 * and checksumming is enabled, then checksum the file.
	 */

	/* return if no need to compute checksum */

	if ((allow_checksum == 0) || (enable_checksum == 0)) {
		return (retcode);
	}

	/* compute checksum */

	mycksum = compute_checksum(&cksumerr, path);

	/* set value if not set or if checksum cannot be computed */

	if (setval || (cinfo->cksum == BADCONT)) {
		cinfo->cksum = mycksum;
		return (retcode);
	}

	/* report / return error if checksums mismatch or there is an error */

	if ((mycksum != cinfo->cksum) || cksumerr) {
		if (!retcode) {
			retcode = VE_CONT;
		}
		if (!cksumerr) {
			reperr(pkg_gt(ERR_CKSUM), cinfo->cksum, mycksum);
		}
	}

	return (retcode);
}

/*
 * Name:	compute_checksum
 * Description:	generate checksum for specified file
 * Arguments:	r_cksumerr (int *) [RO, *RW]
 *			- pointer to integer that is set on return to:
 *				== 0 - no error occurred
 *				!= 0 - error occurred
 *		a_path (char *) [RO, *RO]
 *			- pointer to string representing path to file to
 *			  generate checksum of
 * Returns:	unsigned long - results:
 *			- If *r_cksumerr == 0, checksum of specified file
 *			- If *r_cksumerr != 0, undefined
 */
unsigned long
compute_checksum(int *r_cksumerr, char *a_path)
{
	CHECKSUM_T	suma;	/* to split four-bytes into 2 two-byte values */
	CHECKSUM_T	tempa;
	int		fd;
	uint32_t	lg;	/* running checksum value */
	uint32_t	buf[CHUNK/4]; /* to read CHUNK bytes */
	uint32_t	lsavhi;	/* high order two-bytes of four-byte checksum */
	uint32_t	lsavlo;	/* low order two-bytes of four-byte checksum */
	int		leap = sizeof (uint32_t);
	int		notyet = 0;
	int		nread;
	struct stat64	sbuf;

	/* reset error flag */
	*r_cksumerr = 0;

	/* open file and obtain -> where file is mapped/read */
	if ((fd = open(a_path, O_RDONLY)) < 0) {
		*r_cksumerr = 1;
		reperr(pkg_gt(ERR_NO_CKSUM));
		perror(ERR_NO_CKSUM);
		return (0);
	}

	if (fstat64(fd, &sbuf) != 0) {
		*r_cksumerr = 1;
		reperr(pkg_gt(ERR_NO_CKSUM));
		perror(ERR_NO_CKSUM);
		return (0);
	}

	/* initialize checksum value */
	lg = 0;

	/*
	 * Read CHUNK bytes off the file at a time; Read size of long bytes
	 * from memory at a time and process them.
	 * If last read, then read remnant bytes and process individually.
	 */
	errno = 0;
	while ((nread = read(fd, (void*)buf,
	    (sbuf.st_size < CHUNK) ? sbuf.st_size : CHUNK)) > 0) {
		uchar_t *s;
		uint32_t *p = buf;

		notyet = nread % leap;
		nread -= notyet;

		for (; nread > 0; nread -= leap) {
			lg += ((((*p)>>24)&0xFF) & WDMSK);
			lg += ((((*p)>>16)&0xFF) & WDMSK);
			lg += ((((*p)>>8)&0xFF) & WDMSK);
			lg += (((*p)&0xFF) & WDMSK);
			p++;
		}
		s = (uchar_t *)p;
		/* leftover bytes less than four in number */
		while (notyet--)
			lg += (((uint32_t)(*s++)) & WDMSK);
	}

	/* wind up */
	(void) close(fd);

	/* compute checksum components */
	suma.lg = lg;
	tempa.lg = (suma.hl.lo & WDMSK) + (suma.hl.hi & WDMSK);
	lsavhi = (uint32_t)tempa.hl.hi;
	lsavlo = (uint32_t)tempa.hl.lo;

	/* return final checksum value */
	return (lsavhi+lsavlo);
}

static	struct stat	status;		/* file status buffer */
static	struct statvfs	vfsstatus;	/* filesystem status buffer */

/*
 * Remove the thing that's currently in place so we can put down the package
 * object. If we're replacing a directory with a directory, leave it alone.
 * Returns 1 if all OK and 0 if failed.
 */
static int
clear_target(char *path, char *ftype, int is_a_dir)
{
	int retcode = 1;

	if (is_a_dir) {	/* if there's a directory there already ... */
		/* ... and this isn't, ... */
		if ((*ftype != 'd') && (*ftype != 'x')) {
			if (rmdir(path)) {	/* try to remove it. */
				reperr(pkg_gt(ERR_RMDIR), path);
				retcode = 0;
			}
		}
	} else {
		if (remove(path)) {
			if (errno != ENOENT) {
				retcode = 0;	/* It didn't work. */
			}
		}
	}

	return (retcode);
}

/*
 * Name:	averify
 * Description:	This function verifies and (if fix > 0) fixes the attributes
 *		of the file at the path provided.
 * Arguments:	fix - 0 - do not fix entries, 1 - fix entries
 *		ftype - single character "type" the entry is supposed to be
 *		path - path to file
 *		ainfo - attribute info structure representing the attributes
 *			the entry is supposed to be
 * NOTE:	attributes are links and permissions
 * Possible return values:
 * - 0 = successful
 * - VE_EXIST = path name does not exist
 * - VE_FTYPE = path file type is not recognized, is not supported,
 *		or is not what was expected
 * - VE_ATTR = path mode/group/user is not what was expected
 * - VE_CONT = mod time/link target/major/minor/size/file system type/current
 *		directory is not what was expected
 * - VE_FAIL = utime/target directory/link/stat/symlink/mknod/chmod/statvfs/
 *		chown failed
 */
int
averify(int fix, char *ftype, char *path, struct ainfo *ainfo)
{
	struct group	*grp;	/* group entry buffer */
	struct passwd	*pwd;
	int		n;
	int		setval;
	int		uid, gid;
	int		dochown;
	int		retcode;
	int		statError = 0;
	int		targ_is_dir = 0;	/* replacing a directory */
	char		myftype;
	char		buf[PATH_MAX];
	ino_t		my_ino;
	dev_t		my_dev;
	char		cwd[MAXPATHLEN];
	char		*cd;
	char		*c;

	setval = (*ftype == '?');
	retcode = 0;
	reperr(NULL);

	if (get_disable_attribute_check()) {
		return (0);
	}

	if (*ftype == 'l') {
		if (stat(path, &status) < 0) {
			retcode = VE_EXIST;
			reperr(pkg_gt(ERR_EXIST));
		}

		my_ino = status.st_ino;
		my_dev = status.st_dev;

		/* Get copy of the current working directory */
		if (getcwd(cwd, MAXPATHLEN) == NULL) {
			reperr(pkg_gt(ERR_GETWD));
			return (VE_FAIL);
		}

		/*
		 * Change to the directory in which the hard
		 * link is to be created.
		 */
		cd = strdup(path);
		c = strrchr(cd, '/');
		if (c) {
			/* bugid 4247895 */
			if (strcmp(cd, c) == 0)
				(void) strcpy(cd, "/");
			else
				*c = '\0';

			if (chdir(cd) != 0) {
				reperr(pkg_gt(ERR_CHDIR), cd);
				return (VE_FAIL);
			}
		}
		free(cd);

		if (retcode || (status.st_nlink < 2) ||
		    (stat(ainfo->local, &status) < 0) ||
		    (my_dev != status.st_dev) || (my_ino != status.st_ino)) {
			if (fix) {
				/*
				 * Don't want to do a hard link to a
				 * directory.
				 */
				if (!isdir(ainfo->local)) {
					(void) chdir(cwd);
					reperr(pkg_gt(ERR_LINKISDIR),
					    ainfo->local);
					return (VE_FAIL);
				}
				/* Now do the link. */
				if (!clear_target(path, ftype, targ_is_dir))
					return (VE_FAIL);

				if (link(ainfo->local, path)) {
					(void) chdir(cwd);
					reperr(pkg_gt(ERR_LINKFAIL),
					    ainfo->local);
					return (VE_FAIL);
				}
				retcode = 0;
			} else {
				/* Go back to previous working directory */
				if (chdir(cwd) != 0)
					reperr(pkg_gt(ERR_CHDIR), cwd);

				reperr(pkg_gt(ERR_LINK), ainfo->local);
				return (VE_CONT);
			}
		}

		/* Go back to previous working directory */
		if (chdir(cwd) != 0) {
			reperr(pkg_gt(ERR_CHDIR), cwd);
			return (VE_CONT);
		}

		return (retcode);
	}

	retcode = 0;

	/* If we are to process symlinks the old way then we follow the link */
	if (nonABI_symlinks()) {
		if ((*ftype == 's') ? lstat(path, &status) :
		    stat(path, &status)) {
			reperr(pkg_gt(ERR_EXIST));
			retcode = VE_EXIST;
			myftype = '?';
			statError++;
		}
	/* If not then we inspect the target of the link */
	} else {
		if ((n = lstat(path, &status)) == -1) {
			reperr(pkg_gt(ERR_EXIST));
			retcode = VE_EXIST;
			myftype = '?';
			statError++;
		}
	}
	if (!statError) {
		/* determining actual type of existing object */
		switch (status.st_mode & S_IFMT) {
		case S_IFLNK:
			myftype = 's';
			break;

		case S_IFIFO:
			myftype = 'p';
			break;

		case S_IFCHR:
			myftype = 'c';
			break;

		case S_IFDIR:
			myftype = 'd';
			targ_is_dir = 1;
			break;

		case S_IFBLK:
			myftype = 'b';
			break;

		case S_IFREG:
		case 0:
			myftype = 'f';
			break;

		case S_IFDOOR:
			myftype = 'D';
			break;

		default:
			reperr(pkg_gt(ERR_UNKNOWN));
			return (VE_FTYPE);
		}
	}

	if (setval) {
		/*
		 * Check to make sure that a package or an installf that uses
		 * wild cards '?' to assume the ftype of an object on the
		 * system is not assuming a door ftype. Doors are not supported
		 * but should be ignored.
		 */
		if (myftype == 'D') {
			reperr(pkg_gt(ERR_FTYPED), path);
			retcode = VE_FTYPE;
			return (VE_FTYPE);
		} else {
			*ftype = myftype;
		}
	} else if (!retcode && (*ftype != myftype) &&
	    ((myftype != 'f') || !strchr("ilev", *ftype)) &&
	    ((myftype != 'd') || (*ftype != 'x'))) {
		reperr(pkg_gt(ERR_FTYPE), *ftype, myftype);
		retcode = VE_FTYPE;
	}

	if (!retcode && (*ftype == 's')) {
		/* make sure that symbolic link is correct */
		n = readlink(path, buf, PATH_MAX);
		if (n < 0) {
			reperr(pkg_gt(ERR_SLINK), ainfo->local);
			retcode = VE_CONT;
		} else if (ainfo->local != NULL) {
			buf[n] = '\0';
			if (strcmp(buf, ainfo->local)) {
				reperr(pkg_gt(ERR_SLINK), ainfo->local);
				retcode = VE_CONT;
			}
		} else if (ainfo->local == NULL) {
			/*
			 * Since a sym link target exists, insert it
			 * into the ainfo structure
			 */
			buf[n] = '\0';
			ainfo->local = strdup(buf);
		}
	}

	if (retcode) {
		/* The path doesn't exist or is different than it should be. */
		if (fix) {
			/*
			 * Clear the way for the write. If it won't clear,
			 * there's nothing we can do.
			 */
			if (!clear_target(path, ftype, targ_is_dir))
				return (VE_FAIL);

			if ((*ftype == 'd') || (*ftype == 'x')) {
				char	*pt, *p;

				/* Try to make it the easy way */
				if (mkdir(path, ainfo->mode)) {
					/*
					 * Failing that, walk through the
					 * parent directories creating
					 * whatever is needed.
					 */
					p = strdup(path);
					pt = (*p == '/') ? p+1 : p;
					do {
						if (pt = strchr(pt, '/'))
							*pt = '\0';
						if (access(p, 0) &&
						    mkdir(p, ainfo->mode))
							break;
						if (pt)
							*pt++ = '/';
					} while (pt);
					free(p);
				}
				if (stat(path, &status) < 0) {
					reperr(pkg_gt(ERR_DIRFAIL));
					return (VE_FAIL);
				}
			} else if (*ftype == 's') {
				if (symlink(ainfo->local, path)) {
					reperr(pkg_gt(ERR_SLINKFAIL),
					    ainfo->local);
					return (VE_FAIL);
				}

			} else if (*ftype == 'c') {
				int wilddevno = 0;
				/*
				 * The next three if's support 2.4 and older
				 * packages that use "?" as device numbers.
				 * This should be considered for removal by
				 * release 2.7 or so.
				 */
				if (ainfo->major == BADMAJOR) {
					ainfo->major = 0;
					wilddevno = 1;
				}

				if (ainfo->minor == BADMINOR) {
					ainfo->minor = 0;
					wilddevno = 1;
				}

				if (wilddevno) {
					wilddevno = 0;
					logerr(MSG_WLDDEVNO, path,
					    ainfo->major, ainfo->minor);
				}

				if (mknod(path, ainfo->mode | S_IFCHR,
				    makedev(ainfo->major, ainfo->minor)) ||
				    (stat(path, &status) < 0)) {
					reperr(pkg_gt(ERR_CDEVFAIL));
					return (VE_FAIL);
				}
			} else if (*ftype == 'b') {
				int wilddevno = 0;
				/*
				 * The next three if's support 2.4 and older
				 * packages that use "?" as device numbers.
				 * This should be considered for removal by
				 * release 2.7 or so.
				 */
				if (ainfo->major == BADMAJOR) {
					ainfo->major = 0;
					wilddevno = 1;
				}

				if (ainfo->minor == BADMINOR) {
					ainfo->minor = 0;
					wilddevno = 1;
				}

				if (wilddevno) {
					wilddevno = 0;
					logerr(MSG_WLDDEVNO, path,
					    ainfo->major, ainfo->minor);
				}

				if (mknod(path, ainfo->mode | S_IFBLK,
				    makedev(ainfo->major, ainfo->minor)) ||
				    (stat(path, &status) < 0)) {
					reperr(pkg_gt(ERR_BDEVFAIL));
					return (VE_FAIL);
				}
			} else if (*ftype == 'p') {
				if (mknod(path, ainfo->mode | S_IFIFO, 0) ||
				    (stat(path, &status) < 0)) {
					reperr(pkg_gt(ERR_PIPEFAIL));
					return (VE_FAIL);
				}
			} else
				return (retcode);

		} else
			return (retcode);
	}

	if (*ftype == 's')
		return (0); /* don't check anything else */
	if (*ftype == 'i')
		return (0); /* don't check anything else */

	retcode = 0;
	if ((myftype == 'c') || (myftype == 'b')) {
		if (setval || (ainfo->major == BADMAJOR))
			ainfo->major = major(status.st_rdev);
		if (setval || (ainfo->minor == BADMINOR))
			ainfo->minor = minor(status.st_rdev);
		/* check major & minor */
		if (status.st_rdev != makedev(ainfo->major, ainfo->minor)) {
			reperr(pkg_gt(ERR_MAJMIN), ainfo->major, ainfo->minor,
			    major(status.st_rdev), minor(status.st_rdev));
			retcode = VE_CONT;
		}
	}

	/* compare specified mode w/ actual mode excluding sticky bit */
	if (setval || (ainfo->mode == BADMODE) || (ainfo->mode == WILDCARD))
		ainfo->mode = status.st_mode & 07777;
	else if ((ainfo->mode & 06777) != (status.st_mode & 06777)) {
		if (fix) {
			if ((ainfo->mode == BADMODE) ||
			    (chmod(path, ainfo->mode) < 0))
				retcode = VE_FAIL;
		} else {
			reperr(pkg_gt(ERR_PERM), ainfo->mode,
			    status.st_mode & 07777);
			if (!retcode)
				retcode = VE_ATTR;
		}
	}

	dochown = 0;

	/* get group entry for specified group */
	if (setval || strcmp(ainfo->group, BADGROUP) == 0) {
		grp = cgrgid(status.st_gid);
		if (grp)
			(void) strcpy(ainfo->group, grp->gr_name);
		else {
			if (!retcode)
				retcode = VE_ATTR;
			reperr(pkg_gt(ERR_BADGRPID), status.st_gid);
		}
		gid = status.st_gid;
	} else if ((grp = cgrnam(ainfo->group)) == NULL) {
		reperr(pkg_gt(ERR_BADGRPNM), ainfo->group);
		if (!retcode)
			retcode = VE_ATTR;
	} else if ((gid = grp->gr_gid) != status.st_gid) {
		if (fix) {
			/* save specified GID */
			gid = grp->gr_gid;
			dochown++;
		} else {
			if ((grp = cgrgid((int)status.st_gid)) ==
			    (struct group *)NULL) {
				reperr(pkg_gt(ERR_GROUP), ainfo->group,
				    "(null)");
			} else {
				reperr(pkg_gt(ERR_GROUP), ainfo->group,
				    grp->gr_name);
			}
			if (!retcode)
				retcode = VE_ATTR;
		}
	}

	/* get password entry for specified owner */
	if (setval || strcmp(ainfo->owner, BADOWNER) == 0) {
		pwd = cpwuid((int)status.st_uid);
		if (pwd)
			(void) strcpy(ainfo->owner, pwd->pw_name);
		else {
			if (!retcode)
				retcode = VE_ATTR;
			reperr(pkg_gt(ERR_BADUSRID), status.st_uid);
		}
		uid = status.st_uid;
	} else if ((pwd = cpwnam(ainfo->owner)) == NULL) {
		/* UID does not exist in password file */
		reperr(pkg_gt(ERR_BADUSRNM), ainfo->owner);
		if (!retcode)
			retcode = VE_ATTR;
	} else if ((uid = pwd->pw_uid) != status.st_uid) {
		/* get owner name for actual UID */
		if (fix) {
			uid = pwd->pw_uid;
			dochown++;
		} else {
			pwd = cpwuid((int)status.st_uid);
			if (pwd == NULL)
				reperr(pkg_gt(ERR_BADUSRID),
				    (int)status.st_uid);
			else
				reperr(pkg_gt(ERR_OWNER), ainfo->owner,
				    pwd->pw_name);

			if (!retcode)
				retcode = VE_ATTR;
		}
	}

	if (statvfs(path, &vfsstatus) < 0) {
		reperr(pkg_gt(ERR_EXIST));
		retcode = VE_FAIL;
	} else {
		if (dochown) {
			/* pcfs doesn't support file ownership */
			if (strcmp(vfsstatus.f_basetype, "pcfs") != 0 &&
			    chown(path, uid, gid) < 0) {
				retcode = VE_FAIL; /* chown failed */
			}
		}
	}

	if (retcode == VE_FAIL)
		reperr(pkg_gt(ERR_ATTRFAIL));
	return (retcode);
}

/*
 * This is a special fast verify which basically checks the attributes
 * and then, if all is OK, checks the size and mod time using the same
 * stat and statvfs structures.
 */
int
fverify(int fix, char *ftype, char *path, struct ainfo *ainfo,
    struct cinfo *cinfo)
{
	int retval;

	/* return success if attribute checks are disabled */

	if (get_disable_attribute_check()) {
		return (0);
	}

	if ((retval = averify(fix, ftype, path, ainfo)) == 0) {
		if (*ftype == 'f' || *ftype == 'i') {
			if (cinfo->size != status.st_size) {
				reperr(pkg_gt(WRN_QV_SIZE), path);
				retval = VE_CONT;
			}
			/* pcfs doesn't support modification times */
			if (strcmp(vfsstatus.f_basetype, "pcfs") != 0) {
				if (cinfo->modtime != status.st_mtime) {
					reperr(pkg_gt(WRN_QV_MTIME), path);
					retval = VE_CONT;
				}
			}
		}
	}

	return (retval);
}

/*
 * This function determines whether or not non-ABI symlinks are supported.
 */

int
nonABI_symlinks(void)
{
	return (nonabi_symlinks);
}

void
set_nonABI_symlinks(void)
{
	nonabi_symlinks	= 1;
}

/*
 * Disable attribute checking. Only disable attribute checking if files
 * are guaranteed to exist in the FS.
 */
void
disable_attribute_check(void)
{
	disable_attributes = 1;
}

/*
 * This function determines whether or not to do attribute checking.
 * Returns:  0 - Do attribute checking
 *          !0 - Don't do attribute checking
 */
int
get_disable_attribute_check(void)
{
	return (disable_attributes);
}

/*
 * This function returns the address of the "global" error buffer that
 * is populated by the various functions in this module.
 */

char *
getErrbufAddr(void)
{
	return (theErrBuf);
}

/*
 * This function returns the size of the buffer returned by getErrbufAddr()
 */

int
getErrbufSize(void)
{
	return (sizeof (theErrBuf));
}

/*
 * This function returns the current global "error string"
 */

char *
getErrstr(void)
{
	return (theErrStr);
}

/*
 * This function sets the global "error string"
 */

void
setErrstr(char *a_errstr)
{
	theErrStr = a_errstr;
}

/*
 * This function enables checksumming
 */

void
checksum_on(void)
{
	enable_checksum = 1;
}

/*
 * This function disables checksumming
 */

void
checksum_off(void)
{
	enable_checksum = 0;
}
