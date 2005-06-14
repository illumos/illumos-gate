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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
 *	position, closing, re-opening, and seeking.  It is possible
 *	to start recycling file descriptors by sensing when we have
 *	run out, but in general this will not be terribly useful if
 *	fn expects to be able to open files.  We could also figure out
 *	how many file descriptors are available and guarantee a certain
 *	number to fn, but we would not know how many to guarantee,
 *	and we do not want to impose the extra overhead on a caller who
 *	knows how many are available without having to figure it out.
 *
 *	It is possible for _xftw to die with a memory fault in the event
 *	of a file system so deeply nested that the stack overflows.
 */

/*
 * this interface uses the expanded stat structure and therefore
 * must have EFT enabled.
 */
#ifdef _STYPES
#undef _STYPES
#endif

#include <sys/feature_tests.h>

#if !defined(_LP64) && _FILE_OFFSET_BITS == 64
#define	lstat64		_lstat64
#define	readdir64	_readdir64
#define	stat64		_stat64
#else
#define	lstat		_lstat
#define	readdir		_readdir
#define	stat		_stat
#endif /* !_LP64 && _FILE_OFFSET_BITS == 64 */

#define	closedir	_closedir
#define	opendir		_opendir
#define	seekdir		_seekdir
#define	telldir		_telldir

#include "lint.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <dirent.h>
#include <errno.h>
#include <ftw.h>
#include <string.h>
#include <stdlib.h>
#include <alloca.h>

int
_xftw(int ver, const char *path,
	int (*fn)(const char *, const struct stat *, int), int depth)
{
	size_t	n;
	int rc;
	int save_errno;
	DIR *dirp;
	char *subpath;
	struct stat sb;
	struct dirent *direntp;


	/*
	 * Try to get file status.
	 * If unsuccessful, errno will say why.
	 * It's ok to have a symbolic link that points to
	 * non-existing file. In this case, pass FTW_NS
	 * to a function instead of aborting _xftw() right away.
	 */
	if (stat(path, &sb) < 0) {
#ifdef S_IFLNK
		save_errno = errno;
		if ((lstat(path, &sb) != -1) &&
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
	dirp = opendir(path);

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

	/* Create a prefix to which we will append component names */
	n = strlen(path);
	subpath = alloca(n + MAXNAMELEN + 2);
	(void) strcpy(subpath, path);
	if (subpath[0] != '\0' && subpath[n-1] != '/')
		subpath[n++] = '/';

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

		/* Append component name to the working path */
		(void) strlcpy(&subpath[n], direntp->d_name, MAXNAMELEN);

		/*
		 *	If we are about to exceed our depth,
		 *	remember where we are and close a file.
		 */
		if (depth <= 1) {
			here = telldir(dirp);
			if (closedir(dirp) < 0)
				return (-1);
		}

		/*
		 *	Do a recursive call to process the file.
		 *	(watch this, sports fans)
		 */
		rc = _xftw(ver, subpath, fn, depth-1);
		if (rc != 0) {
			if (depth > 1)
				(void) closedir(dirp);
			return (rc);
		}

		/*
		 *	If we closed the file, try to reopen it.
		 */
		if (depth <= 1) {
			dirp = opendir(path);
			if (dirp == NULL)
				return (-1);
			seekdir(dirp, here);
		}
	}
	(void) closedir(dirp);
	return (0);
}
