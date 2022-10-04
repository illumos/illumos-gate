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
/*	  All Rights Reserved	*/

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
 *		FTW_PHYS  Physical walk, does not follow symbolic links
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
 *		FTW_NOLOOP Allow find utility to detect infinite loops created
 *			   by both symbolic and hard linked directories.
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
 *	The following value is private, and is used by the find utility:
 *		FTW_DL	An infinite loop has been detected.
 *	The fourth argument is a struct FTW* which contains the depth
 *	and the offset into pathname to the base name.
 *	If fn returns nonzero, nftw returns this value to its caller.
 *
 *	depth limits the number of open directories that ftw uses
 *	before it starts recycling file descriptors.  In general,
 *	a file descriptor is used for each level.  When FTW_CHDIR isn't set,
 *	in order to descend to arbitrary depths, nftw requires 2 file
 *	descriptors to be open during the call to openat(), therefore if
 *	the depth argument is less than 2 nftw will not use openat(), and
 *	it will fail with ENAMETOOLONG if it descends to a directory that
 *	exceeds PATH_MAX.
 *
 */

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
#include <strings.h>
#include <fcntl.h>

#if !defined(_LP64) && _FILE_OFFSET_BITS == 64
#define	nftw	nftw64
#define	stat	stat64
#define	fstat	fstat64
#define	fstatat	fstatat64
#pragma weak _nftw64 = nftw64
#else
#pragma weak _nftw = nftw
#endif /* !_LP64 && _FILE_OFFSET_BITS == 64 */

#ifndef PATH_MAX
#define	PATH_MAX	1023
#endif

/*
 * Local variables (used to be static local).
 * Putting them into a structure that is passed
 * around makes nftw() MT-safe with no locking required.
 */
struct Save {
	struct Save *last;
	DIR	*fd;
	char	*comp;
	long	here;
	dev_t	dev;
	ino_t	inode;
};

struct Var {
	char	*home;
	size_t	len;
	char	*fullpath;
	char	*tmppath;
	int	curflags;
	dev_t	cur_mount;
	struct FTW state;
	int	walklevel;
	int	(*statf)(const char *, struct stat *, struct Save *, int flags);
	int	(*savedstatf)(const char *, struct stat *, struct Save *,
	    int flags);
	DIR	*(*opendirf)(const char *);
};

static int oldclose(struct Save *);
static int cdlstat(const char *, struct stat *, struct Save *, int flags);
static int cdstat(const char *, struct stat *, struct Save *, int flags);
static int nocdlstat(const char *, struct stat *, struct Save *, int flags);
static int nocdstat(const char *, struct stat *, struct Save *, int flags);
static DIR *cdopendir(const char *);
static DIR *nocdopendir(const char *);
static const char *get_unrooted(const char *);

/*
 * This is the recursive walker.
 */
static int
walk(char *component,
    int (*fn)(const char *, const struct stat *, int, struct FTW *),
    int depth, struct Save *last, struct Var *vp)
{
	struct stat statb;
	char *p, *tmp;
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
	size_t base_comp, base_component, base_this_comp, base_last_comp;
	size_t base_fullpath, base_tmppath;

	this.last = last;
	this.fd = 0;
	if ((vp->curflags & FTW_CHDIR) && last)
		comp = last->comp;
	else
		comp = vp->tmppath;

	if (vp->savedstatf == NULL)
		vp->savedstatf = vp->statf;

	if ((vp->walklevel++ == 0) && (vp->curflags & FTW_HOPTION)) {
		if (((vp->curflags & FTW_CHDIR) == 0) && (depth >= 2)) {
			vp->statf = nocdstat;
		} else {
			vp->statf = cdstat;
		}
	} else {
		vp->statf = vp->savedstatf;
	}

	/*
	 * Determine the type of the component.
	 *
	 * Note that if the component is a trigger mount, this
	 * will cause it to load.
	 */
	if ((*vp->statf)(comp, &statb, last, _AT_TRIGGER) >= 0) {
		if ((statb.st_mode & S_IFMT) == S_IFDIR) {
			type = FTW_D;
			if (depth <= 1)
				(void) oldclose(last);
			if ((this.fd = (*vp->opendirf)(comp)) == 0) {
				if (errno == EMFILE && oldclose(last) &&
				    (this.fd = (*vp->opendirf)(comp)) != 0) {
					/*
					 * If opendirf fails because there
					 * are OPEN_MAX fd in the calling
					 * process, and we close the oldest
					 * fd, and another opendirf doesn't
					 * fail, depth is set to 1.
					 */
					depth = 1;
				} else {
					type = FTW_DNR;
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
		if (((vp->statf == cdstat) &&
		    (cdlstat(comp, &statb, last, 0) >= 0) &&
		    ((statb.st_mode & S_IFMT) == S_IFLNK)) ||
		    ((vp->statf == nocdstat) &&
		    (nocdlstat(comp, &statb, last, 0) >= 0) &&
		    ((statb.st_mode & S_IFMT) == S_IFLNK))) {

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
	*component = 0;
	if (vp->curflags & FTW_CHDIR) {
		struct stat statb2;

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
	 * If the walk has followed a symbolic link (FTW_PHYS is not set),
	 * traverse the walk back to make sure there is not a loop.
	 * The find utility (FTW_NOLOOP is set) detects infinite loops
	 * in both symbolic and hard linked directories.
	 */
	if ((vp->curflags & FTW_NOLOOP) ||
	    ((vp->curflags & FTW_PHYS) == 0)) {
		struct Save *sp = last;
		while (sp) {
			/*
			 * If the same node has already been visited, there
			 * is a loop. Get ready to return.
			 */
			if (sp->dev == statb.st_dev &&
			    sp->inode == statb.st_ino) {
				if (vp->curflags & FTW_NOLOOP) {
					/* private interface for find util */
					type = FTW_DL;
					goto fail;
				}
				goto quit;
			}
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
		if (last != NULL && last->comp != NULL) {
			base_last_comp = last->comp - vp->home;
		}
		base_comp = comp - vp->home;
		base_component = component - vp->home;
		if ((strlen(q) + strlen(vp->home) + 1) > vp->len) {
			/*
			 * When the space needed for vp->home has
			 * exceeded the amount of space that has
			 * been allocated, realloc() more space
			 * and adjust pointers to point to the
			 * (possibly moved) new block for vp->home
			 */
			base_this_comp = this.comp - vp->home;
			base_fullpath = vp->fullpath - vp->home;
			base_tmppath = vp->tmppath - vp->home;
			vp->len *= 2;
			tmp = (char *)realloc(vp->home, vp->len);
			if (tmp == NULL) {
				rc = -1;
				goto quit;
			}
			vp->home = tmp;
			comp = vp->home + base_comp;
			component = vp->home + base_component;
			this.comp = vp->home + base_this_comp;
			vp->fullpath = vp->home + base_fullpath;
			vp->tmppath = vp->home + base_tmppath;
			if (last != NULL && last->comp != NULL) {
				last->comp = vp->home + base_last_comp;
			}
		}
		p = component;
		while (*q != '\0')
			*p++ = *q++;
		*p = '\0';
		vp->state.level++;

		/* Call walk() recursively.  */
		rc = walk(p, fn, depth-1, &this, vp);
		if (last != NULL && last->comp != NULL) {
			last->comp = vp->home + base_last_comp;
		}
		comp = vp->home + base_comp;
		component = vp->home + base_component;
		vp->state.level--;
		if (this.fd == 0) {
			*component = 0;
			if (vp->curflags & FTW_CHDIR) {
				this.fd = opendir(".");
			} else {
				this.fd = (*vp->opendirf)(comp);
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
				if ((*vp->statf)(".", &statb, last, 0) < 0 ||
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
					    ((*vp->statf)(".", &statb,
					    last, 0) < 0 ||
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
nftw(const char *path,
    int (*fn)(const char *, const struct stat *, int, struct FTW *),
    int depth, int flags)
{
	struct Var var;
	struct stat statb;
	int rc = -1;
	char *dp;
	char *base;
	char *endhome;
	const char *savepath = path;
	int save_errno;

	var.walklevel = 0;
	var.len = 2*(PATH_MAX+1);
	var.home = (char *)malloc(var.len);
	if (var.home == NULL)
		return (-1);

	var.home[0] = 0;

	/*
	 * If the walk is going to change directory before
	 * reading it, save current working directory.
	 */
	if (flags & FTW_CHDIR) {
		if (getcwd(var.home, PATH_MAX+1) == 0) {
			free(var.home);
			return (-1);
		}
	}
	endhome = dp = var.home + strlen(var.home);
	if (*path == '/')
		var.fullpath = dp;
	else {
		*dp++ = '/';
		var.fullpath = var.home;
	}
	var.tmppath =  dp;
	base = dp-1;
	while (*path) {
		*dp = *path;
		if (*dp == '/')
			base = dp;
		dp++, path++;
	}
	*dp = 0;
	var.state.base = (int)(base + 1 - var.tmppath);
	if (*path) {
		free(var.home);
		errno = ENAMETOOLONG;
		return (-1);
	}
	var.curflags = flags;

	/*
	 * If doing chdir()'s, set var.opendirf to cdopendir.
	 * If not doing chdir()'s and if nftw()'s depth arg >= 2,
	 * set var.opendirf to nocdopendir.  In order to
	 * descend to arbitrary depths without doing chdir()'s, nftw()
	 * requires a depth arg >= 2 so that nocdopendir() can use openat()
	 * to traverse the directories.  So when not doing
	 * chdir()'s if nftw()'s depth arg <= 1, set var.opendirf to
	 * cdopendir.
	 * If doing a physical walk (not following symbolic link), set
	 * var.statf to cdlstat() or nocdlstat(). Otherwise, set var.statf
	 * to cdstat() or nocdstat().
	 */
	if (((flags & FTW_CHDIR) == 0) && (depth >= 2)) {
		var.opendirf = nocdopendir;
		if (flags & FTW_PHYS)
			var.statf = nocdlstat;
		else
			var.statf = nocdstat;
	} else {
		var.opendirf = cdopendir;
		if (flags & FTW_PHYS)
			var.statf = cdlstat;
		else
			var.statf = cdstat;
	}

	/*
	 * If walk is not going to cross a mount point,
	 * save the current mount point.
	 */
	if (flags & FTW_MOUNT) {
		if ((*var.statf)(savepath, &statb, NULL, 0) >= 0)
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
	rc = walk(dp, fn, depth, (struct Save *)0, &var);
	if (errno == 0)
		errno = save_errno;
done:
	*endhome = 0;
	if (flags & FTW_CHDIR)
		(void) chdir(var.home);
	free(var.home);
	return (rc);
}

/*
 * Get stat info on path when FTW_CHDIR is set.
 */
static int
cdstat(const char *path, struct stat *statp, struct Save *lp __unused,
    int flags)
{
	return (fstatat(AT_FDCWD, path, statp, flags));
}

/*
 * Get lstat info on path when FTW_CHDIR is set.
 */
static int
cdlstat(const char *path, struct stat *statp, struct Save *lp __unused,
    int flags)
{
	return (fstatat(AT_FDCWD, path, statp,
	    flags | AT_SYMLINK_NOFOLLOW));
}

/*
 * Get stat info on path when FTW_CHDIR is not set.
 */
static int
nocdstat(const char *path, struct stat *statp, struct Save *lp, int flags)
{
	int		fd;
	const char	*basepath;

	if (lp && lp->fd) {
		/* get basename of path */
		basepath = get_unrooted(path);

		fd = lp->fd->dd_fd;
	} else {
		basepath = path;

		fd = AT_FDCWD;
	}

	return (fstatat(fd, basepath, statp, flags));
}

/*
 * Get lstat info on path when FTW_CHDIR is not set.
 */
static int
nocdlstat(const char *path, struct stat *statp, struct Save *lp, int flags)
{
	int		fd;
	const char	*basepath;

	if (lp && lp->fd) {
		/* get basename of path */
		basepath = get_unrooted(path);

		fd = lp->fd->dd_fd;
	} else {
		basepath = path;

		fd = AT_FDCWD;
	}

	return (fstatat(fd, basepath, statp, flags | AT_SYMLINK_NOFOLLOW));
}

/*
 * Open path directory when FTW_CHDIR is set.
 *
 */
static DIR *
cdopendir(const char *path)
{
	return (opendir(path));
}

/*
 * Open path directory when FTW_CHDIR is not set.
 */
static DIR *
nocdopendir(const char *path)
{
	int fd, cfd;
	DIR *fdd;
	char *dirp, *token, *ptr;

	if (((fdd = opendir(path)) == NULL) && (errno == ENAMETOOLONG)) {
		if ((dirp = strdup(path)) == NULL) {
			errno = ENAMETOOLONG;
			return (NULL);
		}
		if ((token = strtok_r(dirp, "/", &ptr)) != NULL) {
			if ((fd = openat(AT_FDCWD, dirp, O_RDONLY)) < 0) {
				(void) free(dirp);
				errno = ENAMETOOLONG;
				return (NULL);
			}
			while ((token = strtok_r(NULL, "/", &ptr)) != NULL) {
				if ((cfd = openat(fd, token, O_RDONLY)) < 0) {
					(void) close(fd);
					(void) free(dirp);
					errno = ENAMETOOLONG;
					return (NULL);
				}
				(void) close(fd);
				fd = cfd;
			}
			(void) free(dirp);
			return (fdopendir(fd));
		}
		(void) free(dirp);
		errno = ENAMETOOLONG;
	}
	return (fdd);
}

/*
 * return pointer basename of path, which may contain trailing slashes
 *
 * We do this when we do not chdir() on the input.
 */
static const char *
get_unrooted(const char *path)
{
	const char *ptr;

	if (!path || !*path)
		return (NULL);

	ptr = path + strlen(path);
	/* find last char in path before any trailing slashes */
	while (ptr != path && *--ptr == '/')
		;

	if (ptr == path)	/* all slashes */
		return (ptr);

	while (ptr != path)
		if (*--ptr == '/')
			return (++ptr);

	return (ptr);
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
