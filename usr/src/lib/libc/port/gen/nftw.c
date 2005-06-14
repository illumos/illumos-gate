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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 *	nftw - new file tree walk
 *
 *	int nftw(char *path, int (*fn)(), int depth, int flags);
 *
 *	Derived from System V ftw() by David Korn
 *
 *	nftw visits each file and directory in the tree starting at
 *	path. It uses the generic directory reading library so it works
 *	for any file system type.  The flags field is used to specify:
 *		FTW_PHYS  Physical walk, does not follow symblolic links
 *			  Otherwise, nftw will follow links but will not
 *			  walk down any path the crosses itself.
 *		FTW_MOUNT The walk will not cross a mount point.
 *		FTW_DEPTH All subdirectories will be visited before the
 *			  directory itself.
 *		FTW_CHDIR The walk will change to each directory before
 *			  reading it.  This is faster but core dumps
 *			  may not get generated.
 *
 *	The following flags are private, and are used by the find
 *	utility:
 *		FTW_ANYERR Call the callback function and return
 *			   FTW_NS on any stat failure, not just
 *			   lack of permission.
 *		FTW_HOPTION Use stat the first time the walk
 *			    function is called, regardless of
 *			    whether or not FTW_PHYS is specified.
 *
 *	fn is called with four arguments at each file and directory.
 *	The first argument is the pathname of the object, the second
 *	is a pointer to the stat buffer and the third is an integer
 *	giving additional information as follows:
 *
 *		FTW_F	The object is a file.
 *		FTW_D	The object is a directory.
 *		FTW_DP	The object is a directory and subdirectories
 *			have been visited.
 *		FTW_SL	The object is a symbolic link.
 *		FTW_SLN The object is a symbolic link pointing at a
 *		        non-existing file.
 *		FTW_DNR	The object is a directory that cannot be read.
 *			fn will not be called for any of its descendants.
 *		FTW_NS	Stat failed on the object because of lack of
 *			appropriate permission. The stat buffer passed to fn
 *			is undefined.  Stat failure for any reason is
 *			considered an error and nftw will return -1.
 *	The fourth argument is a struct FTW* which contains the depth
 *	and the offset into pathname to the base name.
 *	If fn returns nonzero, nftw returns this value to its caller.
 *
 *	depth limits the number of open directories that ftw uses
 *	before it starts recycling file descriptors.  In general,
 *	a file descriptor is used for each level.
 *
 */

#include <sys/feature_tests.h>

#if !defined(_LP64) && _FILE_OFFSET_BITS == 64
#pragma weak nftw64 = _nftw64
#define	_nftw		_nftw64
#define	fstat64		_fstat64
#define	lstat64		_lstat64
#define	readdir64	_readdir64
#define	stat64		_stat64
#else
#pragma weak nftw = _nftw
#define	fstat		_fstat
#define	lstat		_lstat
#define	readdir		_readdir
#define	stat		_stat
#endif /* !_LP64 && _FILE_OFFSET_BITS == 64 */

#define	chdir		_chdir
#define	closedir	_closedir
#define	fchdir		_fchdir
#define	fprintf		_fprintf
#define	getcwd		_getcwd
#define	opendir		_opendir
#define	seekdir		_seekdir
#define	telldir		_telldir

#include "lint.h"
#include <mtlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <ftw.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <thread.h>
#include <synch.h>
#include <stdio.h>

#ifndef PATH_MAX
#define	PATH_MAX	1023
#endif

/*
 * Local variables (used to be static local).
 * Putting them into a structure that is passed
 * around makes nftw() MT-safe with no locking required.
 */
struct Var {
	char	*fullpath;
	char	*tmppath;
	int	curflags;
	dev_t	cur_mount;
	struct FTW state;
	int	walklevel;
	int	(*statf)(const char *, struct stat *);
	int	(*savedstatf)(const char *, struct stat *);
};

struct Save {
	struct Save *last;
	DIR	*fd;
	char	*comp;
	long	here;
	dev_t	dev;
	ino_t	inode;
};

static int oldclose(struct Save *);

/*
 * This is the recursive walker.
 */
static int
walk(char *component,
    int (*fn)(const char *, const struct stat *, int, struct FTW *),
    int depth, struct Save *last, struct Var *vp)
{
	struct stat statb;
	char *p;
	int type;
	char *comp;
	struct dirent *dir;
	char *q;
	int rc = 0;
	int val = -1;
	int cdval = -1;
	int oldbase;
	int skip;
	struct Save this;

	this.last = last;
	this.fd = 0;
	if ((vp->curflags & FTW_CHDIR) && last)
		comp = last->comp;
	else
		comp = vp->tmppath;

	if (vp->savedstatf == NULL)
		vp->savedstatf = vp->statf;

	if ((vp->walklevel++ == 0) && (vp->curflags & FTW_HOPTION))
		vp->statf = stat;
	else
		vp->statf = vp->savedstatf;

	/*
	 * Determine the type of the component.
	 */
	if ((*vp->statf)(comp, &statb) >= 0) {
		if ((statb.st_mode & S_IFMT) == S_IFDIR) {
			type = FTW_D;
			if (depth <= 1)
				(void) oldclose(last);
			if ((this.fd = opendir(comp)) == 0) {
				if (errno == EMFILE && oldclose(last) &&
				    (this.fd = opendir(comp)) != 0) {
					depth = 1;
				} else {
					type = FTW_DNR;
					goto fail;
				}
			}
			if (statb.st_fstype[0] == 'a' &&
			    strcmp(statb.st_fstype, "autofs") == 0) {
				/*
				 * this dir is on autofs
				 */
				if (fstat(this.fd->dd_fd, &statb) < 0) {
					(void) closedir(this.fd);
					type = FTW_NS;
					goto fail;
				}
			}
		} else if ((statb.st_mode & S_IFMT) == S_IFLNK) {
			type = FTW_SL;
		} else {
			type = FTW_F;
		}
	} else if ((vp->curflags & FTW_ANYERR) && errno != ENOENT) {
		/*
		 * If FTW_ANYERR is specified, then a stat error
		 * other than ENOENT automatically results in
		 * failure.  This allows the callback function
		 * to properly handle ENAMETOOLONG and ELOOP and
		 * things of that nature, that would be masked
		 * by calling lstat before failing.
		 */
		type = FTW_NS;
		goto fail;
	} else {
		/*
		 * Statf has failed. If stat was used instead of lstat,
		 * try using lstat. If lstat doesn't fail, "comp"
		 * must be a symbolic link pointing to a non-existent
		 * file. Such a symbolic link should be ignored.
		 * Also check the file type, if possible, for symbolic
		 * link.
		 */
		if ((vp->statf == stat) && (lstat(comp, &statb) >= 0) &&
		    ((statb.st_mode & S_IFMT) == S_IFLNK)) {

			/*
			 * Ignore bad symbolic link, let "fn"
			 * report it.
			 */

			errno = ENOENT;
			type = FTW_SLN;
		} else {
			type = FTW_NS;
	fail:
			/*
			 * if FTW_ANYERR is set in flags, we call
			 * the user function with FTW_NS set, regardless
			 * of the reason stat failed.
			 */
			if (!(vp->curflags & FTW_ANYERR))
				if (errno != EACCES)
					return (-1);
		}
	}

	/*
	 * If the walk is not supposed to cross a mount point,
	 * and it did, get ready to return.
	 */
	if ((vp->curflags & FTW_MOUNT) && type != FTW_NS &&
	    statb.st_dev != vp->cur_mount)
		goto quit;
	vp->state.quit = 0;

	/*
	 * If current component is not a directory, call user
	 * specified function and get ready to return.
	 */
	if (type != FTW_D || (vp->curflags & FTW_DEPTH) == 0)
		rc = (*fn)(vp->tmppath, &statb, type, &vp->state);
	if (rc > 0)
		val = rc;
	skip = (vp->state.quit & FTW_SKD);
	if (rc != 0 || type != FTW_D || (vp->state.quit & FTW_PRUNE))
		goto quit;

	if (vp->tmppath[0] != '\0' && component[-1] != '/')
		*component++ = '/';
	if (vp->curflags & FTW_CHDIR) {
		struct stat statb2;

		*component = 0;
		/*
		 * Security check (there is a window between
		 * (*vp->statf)() and opendir() above).
		 */
		if ((vp->curflags & FTW_PHYS) &&
		    (fstat(this.fd->dd_fd, &statb2) < 0 ||
		    statb2.st_ino != statb.st_ino ||
		    statb2.st_dev != statb.st_dev)) {
			errno = EAGAIN;
			rc = -1;
			goto quit;
		}

		if ((cdval = fchdir(this.fd->dd_fd)) >= 0) {
			this.comp = component;
		} else {
			type = FTW_DNR;
			rc = (*fn)(vp->tmppath, &statb, type, &vp->state);
			goto quit;
		}
	}

	/*
	 * If the walk has followed a symbolic link, traverse
	 * the walk back to make sure there is not a loop.
	 *
	 * XXX - may need to look at this
	 * There's code to check for cycles, but only for FTW_PHYS
	 * (find -L flag).  However, all directories should be
	 * checked, even if not following links because of hardlinks
	 * to directories (not recommended, but can exist).
	 *
	 * We might have added AVL tree routines here to store and search
	 * the inodes and devices, as is done for du/ls/chgrp/chown,
	 * but libcmdutils is for for internal use only, so we can't
	 * add it to a public libc function (nftw()).
	 */
	if ((vp->curflags & FTW_PHYS) == 0) {
		struct Save *sp = last;
		while (sp) {
			/*
			 * If the same node has already been visited, there
			 * is a loop. Get ready to return.
			 */
			if (sp->dev == statb.st_dev &&
			    sp->inode == statb.st_ino)
				goto quit;
			sp = sp->last;
		}
	}
	this.dev = statb.st_dev;
	this.inode = statb.st_ino;
	oldbase = vp->state.base;
	vp->state.base = (int)(component - vp->tmppath);
	while (dir = readdir(this.fd)) {
		if (dir->d_ino == 0)
			continue;
		q = dir->d_name;
		if (*q == '.') {
			if (q[1] == 0)
				continue;
			else if (q[1] == '.' && q[2] == 0)
				continue;
		}
		p = component;
		while (p < &vp->tmppath[PATH_MAX] && *q != '\0')
			*p++ = *q++;
		*p = '\0';
		vp->state.level++;

		/* Call walk() recursively.  */
		rc = walk(p, fn, depth-1, &this, vp);
		vp->state.level--;
		if (this.fd == 0) {
			*component = 0;
			if (vp->curflags & FTW_CHDIR) {
				this.fd = opendir(".");
			} else {
				this.fd = opendir(comp);
			}
			if (this.fd == 0) {
				rc = -1;
				goto quit;
			}
			seekdir(this.fd, this.here);
		}
		if (rc != 0) {
			if (errno == ENOENT) {
				(void) fprintf(stderr, "cannot open %s: %s\n",
				    vp->tmppath, strerror(errno));
				val = rc;
				continue;
			}
			goto quit;	/* this seems extreme */
		}
	}
	vp->state.base = oldbase;
	*--component = 0;
	type = FTW_DP;
	if ((vp->tmppath[0] != '\0') && (vp->curflags & FTW_DEPTH) && !skip)
		rc = (*fn)(vp->tmppath, &statb, type, &vp->state);
quit:
	if (cdval >= 0 && last) {
		/* try to change back to previous directory */
		if (last->fd != NULL) {
			if (fchdir(last->fd->dd_fd) < 0) {
				rc = -1;
			}
		} else {
			if ((cdval = chdir("..")) >= 0) {
				if ((*vp->statf)(".", &statb) < 0 ||
				    statb.st_ino != last->inode ||
				    statb.st_dev != last->dev)
					cdval = -1;
			}
			*comp = 0;
			if (cdval < 0) {
				if (chdir(vp->fullpath) < 0) {
					rc = -1;
				} else {
					/* Security check */
					if ((vp->curflags & FTW_PHYS) &&
					    ((*vp->statf)(".", &statb) < 0 ||
					    statb.st_ino != last->inode ||
					    statb.st_dev != last->dev)) {
						errno = EAGAIN;
						rc = -1;
					}
				}
			}
		}
	}
	if (this.fd)
		(void) closedir(this.fd);
	if (val > rc)
		return (val);
	else
		return (rc);
}

int
_nftw(const char *path,
    int (*fn)(const char *, const struct stat *, int, struct FTW *),
    int depth, int flags)
{
	struct Var var;
	struct stat statb;
	char home[2*(PATH_MAX+1)];
	int rc = -1;
	char *dp;
	char *base;
	char *endhome;
	const char *savepath = path;
	int save_errno;

	home[0] = 0;

	/*
	 * If the walk is going to change directory before
	 * reading it, save current woring directory.
	 */
	if (flags & FTW_CHDIR) {
		if (getcwd(home, PATH_MAX+1) == 0)
			return (-1);
	}
	endhome = dp = home + strlen(home);
	if (*path == '/')
		var.fullpath = dp;
	else {
		*dp++ = '/';
		var.fullpath = home;
	}
	var.tmppath =  dp;
	base = dp-1;
	while (*path && dp < &var.tmppath[PATH_MAX]) {
		*dp = *path;
		if (*dp == '/')
			base = dp;
		dp++, path++;
	}
	*dp = 0;
	var.state.base = (int)(base + 1 - var.tmppath);
	if (*path) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	var.curflags = flags;

	/*
	 * If doing a physical walk (not following symbolic link), set
	 * var.statf to lstat(). Otherwise, set var.statf to stat().
	 */
	if ((flags & FTW_PHYS) == 0)
		var.statf = stat;
	else
		var.statf = lstat;

	/*
	 * If walk is not going to cross a mount point,
	 * save the current mount point.
	 */
	if (flags & FTW_MOUNT) {
		if ((*var.statf)(savepath, &statb) >= 0)
			var.cur_mount = statb.st_dev;
		else
			goto done;
	}
	var.state.level = 0;

	/*
	 * Call walk() which does most of the work.
	 * walk() uses errno in a rather obtuse way
	 * so we shield any incoming errno.
	 */
	save_errno = errno;
	errno = 0;
	var.savedstatf = NULL;
	var.walklevel = 0;
	rc = walk(dp, fn, depth, (struct Save *)0, &var);
	if (errno == 0)
		errno = save_errno;
done:
	*endhome = 0;
	if (flags & FTW_CHDIR)
		(void) chdir(home);
	return (rc);
}

/*
 * close the oldest directory.  It saves the seek offset.
 * return value is 0 unless it was unable to close any descriptor
 */

static int
oldclose(struct Save *sp)
{
	struct Save *spnext;
	while (sp) {
		spnext = sp->last;
		if (spnext == 0 || spnext->fd == 0)
			break;
		sp = spnext;
	}
	if (sp == 0 || sp->fd == 0)
		return (0);
	sp->here = telldir(sp->fd);
	(void) closedir(sp->fd);
	sp->fd = 0;
	return (1);
}
