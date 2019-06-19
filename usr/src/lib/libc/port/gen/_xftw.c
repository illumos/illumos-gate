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
 *	_xftw - file tree walk the uses expanded stat structure
 *
 *	int _xftw(path, fn, depth)  char *path; int (*fn)(); int depth;
 *
 *	Given a path name, _xftw starts from the file given by that path
 *	name and visits each file and directory in the tree beneath
 *	that file.  If a single file has multiple links within the
 *	structure, it will be visited once for each such link.
 *	For each object visited, fn is called with three arguments.
 *		(*fn) (pathname, statp, ftwflag)
 *	The first contains the path name of the object, the second
 *	contains a pointer to a stat buffer which will usually hold
 *	appropriate information for the object and the third will
 *	contain an integer value giving additional information about
 *
 *		FTW_F	The object is a file for which stat was
 *			successful.  It does not guarantee that the
 *			file can actually be read.
 *
 *		FTW_D	The object is a directory for which stat and
 *			open for read were both successful.
 *
 *		FTW_DNR	The object is a directory for which stat
 *			succeeded, but which cannot be read.  Because
 *			the directory cannot be read, fn will not be
 *			called for any descendants of this directory.
 *
 *		FTW_NS	Stat failed on the object because of lack of
 *			appropriate permission.  This indication will
 *			be given for example for each file in a
 *			directory with read but no execute permission.
 *			Because stat failed, it is not possible to
 *			determine whether this object is a file or a
 *			directory.  The stat buffer passed to fn will
 *			contain garbage.  Stat failure for any reason
 *			other than lack of permission will be
 *			considered an error and will cause _xftw to stop
 *			and return -1 to its caller.
 *
 *	If fn returns nonzero, _xftw stops and returns the same value
 *	to its caller.  If _xftw gets into other trouble along the way,
 *	it returns -1 and leaves an indication of the cause in errno.
 *
 *	The third argument to _xftw does not limit the depth to which
 *	_xftw will go.  Rather, it limits the depth to which _xftw will
 *	go before it starts recycling file descriptors.  In general,
 *	it is necessary to use a file descriptor for each level of the
 *	tree, but they can be recycled for deep trees by saving the
 *	position, closing, re-opening, and seeking.  In order to descend
 *	to arbitrary depths, _xftw requires 2 file descriptors to be open
 *	during the call to openat(), therefore if the depth argument
 *	is less than 2 _xftw will not use openat(), and it will fail with
 *	ENAMETOOLONG if it descends to a directory that exceeds PATH_MAX.
 */

/*
 * this interface uses the expanded stat structure and therefore
 * must have EFT enabled.
 */
#ifdef _STYPES
#undef _STYPES
#endif

#include "lint.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/param.h>
#include <dirent.h>
#include <errno.h>
#include <ftw.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

struct Var {
	int level;
	int odepth;
};

static DIR *nocdopendir(const char *, struct Var *);
static int nocdstat(const char *, struct stat *, struct Var *, int);
static const char *get_unrooted(const char *);
static int fwalk(const char *, int (*)(const char *, const struct stat *, int),
	int, struct Var *);

/*ARGSUSED*/
int
_xftw(int ver, const char *path,
	int (*fn)(const char *, const struct stat *, int), int depth)
{
	struct Var var;
	int rc;

	var.level = 0;
	var.odepth = depth;
	rc = fwalk(path, fn, depth, &var);
	return (rc);
}

/*
 * This is the recursive walker.
 */
static int
fwalk(const char *path, int (*fn)(const char *, const struct stat *, int),
	int depth, struct Var *vp)
{
	size_t	n;
	int rc;
	int save_errno;
	DIR *dirp;
	char *subpath;
	struct stat sb;
	struct dirent *direntp;

	vp->level++;

	/*
	 * Try to get file status.
	 * If unsuccessful, errno will say why.
	 * It's ok to have a symbolic link that points to
	 * non-existing file. In this case, pass FTW_NS
	 * to a function instead of aborting fwalk() right away.
	 */
	if (nocdstat(path, &sb, vp, 0) < 0) {
#ifdef S_IFLNK
		save_errno = errno;
		if ((nocdstat(path, &sb, vp, AT_SYMLINK_NOFOLLOW) != -1) &&
		    ((sb.st_mode & S_IFMT) == S_IFLNK)) {
			errno = save_errno;
			return (*fn)(path, &sb, FTW_NS);
		} else  {
			errno = save_errno;
		}
#endif
		return (errno == EACCES? (*fn)(path, &sb, FTW_NS): -1);
	}

	/*
	 *	The stat succeeded, so we know the object exists.
	 *	If not a directory, call the user function and return.
	 */
	if ((sb.st_mode & S_IFMT) != S_IFDIR)
		return ((*fn)(path, &sb, FTW_F));

	/*
	 *	The object was a directory.
	 *
	 *	Open a file to read the directory
	 */
	dirp = nocdopendir(path, vp);

	/*
	 *	Call the user function, telling it whether
	 *	the directory can be read.  If it can't be read
	 *	call the user function or indicate an error,
	 *	depending on the reason it couldn't be read.
	 */
	if (dirp == NULL)
		return (errno == EACCES? (*fn)(path, &sb, FTW_DNR): -1);

	/* We could read the directory.  Call user function. */
	rc = (*fn)(path, &sb, FTW_D);
	if (rc != 0) {
		(void) closedir(dirp);
		return (rc);
	}

	/*
	 *	Read the directory one component at a time.
	 *	We must ignore "." and "..", but other than that,
	 *	just create a path name and call self to check it out.
	 */
	while (direntp = readdir(dirp)) {
		long here;

		if (strcmp(direntp->d_name, ".") == 0 ||
		    strcmp(direntp->d_name, "..") == 0)
			continue;

		/* Create a prefix to which we will append component names */
		n = strlen(path);
		subpath = malloc(n + strlen(direntp->d_name) + 2);
		if (subpath == 0) {
			(void) closedir(dirp);
			errno = ENOMEM;
			return (-1);
		}
		(void) strcpy(subpath, path);
		if (subpath[0] != '\0' && subpath[n-1] != '/')
			subpath[n++] = '/';

		/* Append component name to the working path */
		(void) strlcpy(&subpath[n], direntp->d_name, MAXNAMELEN);

		/*
		 *	If we are about to exceed our depth,
		 *	remember where we are and close a file.
		 */
		if (depth <= 1) {
			here = telldir(dirp);
			if (closedir(dirp) < 0) {
				free(subpath);
				return (-1);
			}
		}

		/*
		 *	Do a recursive call to process the file.
		 *	(watch this, sports fans)
		 */
		rc = fwalk(subpath, fn, depth-1, vp);
		if (rc != 0) {
			free(subpath);
			if (depth > 1)
				(void) closedir(dirp);
			return (rc);
		}

		/*
		 *	If we closed the file, try to reopen it.
		 */
		if (depth <= 1) {
			dirp = nocdopendir(path, vp);
			if (dirp == NULL) {
				free(subpath);
				return (-1);
			}
			seekdir(dirp, here);
		}
		free(subpath);
	}
	(void) closedir(dirp);
	return (0);
}

/*
 * Open a directory with an arbitrarily long path name.  If the original
 * depth arg >= 2, use openat() to make sure that it doesn't fail with
 * ENAMETOOLONG.
 */
static DIR *
nocdopendir(const char *path, struct Var *vp)
{
	int fd, cfd;
	DIR *fdd;
	char *dirp, *token, *ptr;

	fdd = opendir(path);
	if ((vp->odepth > 1) && (fdd == NULL) && (errno == ENAMETOOLONG)) {
		/*
		 * Traverse the path using openat() to get the fd for
		 * fdopendir().
		 */
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
 * Stat a file with an arbitrarily long path name. If we aren't doing a
 * stat on the arg passed to _xftw() and if the original depth arg >= 2,
 * use openat() to make sure that it doesn't fail with ENAMETOOLONG.
 */
static int
nocdstat(const char *path, struct stat *statp, struct Var *vp, int sym)
{
	int fd, cfd;
	char *dirp, *token, *ptr;
	int rc;
	const char *unrootp;
	int save_err;

	rc = fstatat(AT_FDCWD, path, statp, sym);
	if ((vp->level > 1) && (vp->odepth >= 2) && (rc < 0) &&
	    (errno == ENAMETOOLONG)) {
		/* Traverse path using openat() to get fd for fstatat(). */
		if ((dirp = strdup(path)) == NULL) {
			errno = ENAMETOOLONG;
			return (-1);
		}
		if ((token = strtok_r(dirp, "/", &ptr)) != NULL) {
		    if ((fd = openat(AT_FDCWD, dirp, O_RDONLY)) < 0) {
			(void) free(dirp);
			errno = ENAMETOOLONG;
			return (-1);
		    }
		    unrootp = get_unrooted(path);
		    while (((token = strtok_r(NULL, "/", &ptr)) != NULL) &&
			(strcmp(token, unrootp) != 0)) {
			    if ((cfd = openat(fd, token, O_RDONLY)) < 0) {
				(void) close(fd);
				(void) free(dirp);
				errno = ENAMETOOLONG;
				return (0);
			    }
			    (void) close(fd);
			    fd = cfd;
		    }
		    (void) free(dirp);
		    rc = fstatat(fd, unrootp, statp, sym);
		    save_err = errno;
		    (void) close(fd);
		    errno = save_err;
		    return (rc);
		}
		(void) free(dirp);
		errno = ENAMETOOLONG;
	}
	return (rc);
}

/*
 * Return pointer basename of path.  This routine doesn't remove
 * trailing slashes, but there won't be any.
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
