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
 * Copyright 1989 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*      Copyright (c) 1984 AT&T */
/*        All Rights Reserved   */

#pragma ident	"%Z%%M%	%I%	%E% SMI"  /* from S5R2 1.2 */

/*LINTLIBRARY*/
/***************************************************************
 *	ftw - file tree walk
 *
 *	int ftw (path, fn, depth)  char *path; int (*fn)(); int depth;
 *
 *	Given a path name, ftw starts from the file given by that path
 *	name and visits each file and directory in the tree beneath
 *	that file.  If a single file has multiple links within the
 *	structure, it will be visited once for each such link.
 *	For each object visited, fn is called with three arguments.
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
 *			appropriate permission, or because the object is a 
 *			symbolic link that points to a non-existent file.
 *			This indication will be given, for example, for each 
 *			file in a directory with read but no execute 
 *			permission.   Because stat failed, it is not 
 *			possible to determine whether this object is a file 
 *			or a directory.  The stat buffer passed to fn will
 *			contain garbage.  Stat failure for any reason
 *			other than lack of permission will be
 *			considered an error and will cause ftw to stop 
 *			and return -1 to its caller.
 *
 *	If fn returns nonzero, ftw stops and returns the same value
 *	to its caller.  If ftw gets into other trouble along the way,
 *	it returns -1 and leaves an indication of the cause in errno.
 *
 *	The third argument to ftw does not limit the depth to which
 *	ftw will go.  Rather, it limits the depth to which ftw will
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
 *	It is possible for ftw to die with a memory fault in the event
 *	of a file system so deeply nested that the stack overflows.
 **************************************************************/

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/dir.h>
#include <errno.h>
#include <ftw.h>

#define NULL 0

extern char *malloc(), *strcpy();
extern void free();
extern int errno;

int
ftw(path, fn, depth)
char *path;
int (*fn)();
int depth;
{
	int rc, n;
	DIR *dirp;
	char *subpath, *component;
	struct stat sb;
	struct direct *dp;

	/* Try to get file status.
				If unsuccessful, errno will say why. */
	if(stat(path, &sb) < 0) {
		if (errno == EACCES) {
			return((*fn)(path, &sb, FTW_NS));
		} else if (errno == ENOENT) {
			/* Check if symbolic link points to non-existent file */
			if (lstat(path, &sb) < 0) {
				return(-1);
			}
			else if ((sb.st_mode & S_IFMT) == S_IFLNK) {
				errno = ENOENT;
				return((*fn)(path, &sb, FTW_NS));
			}
			else {
				return(-1);
			}
		} else {
			return(-1);
		}
	}

	/*
	 *	The stat succeeded, so we know the object exists.
	 *	If not a directory, call the user function and return.
	 */
	if((sb.st_mode & S_IFMT) != S_IFDIR)
		return((*fn)(path, &sb, FTW_F));

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
	if(dirp == NULL)
		return(errno == EACCES? (*fn)(path, &sb, FTW_DNR): -1);

	/* We could read the directory.  Call user function. */
	rc = (*fn)(path, &sb, FTW_D);
	if(rc != 0)
		return(rc);

	/* Allocate a buffer to hold generated pathnames. */
	n = strlen(path);
	subpath = malloc((unsigned)(n+MAXNAMLEN+2));
	if(subpath == NULL) {
		closedir(dirp);
		errno = ENOMEM;
		return(-1);
	}
	
	/* Create a prefix to which we will append component names */
	(void)strcpy(subpath, path);
	if(subpath[0] != '\0' && subpath[n-1] != '/')
		subpath[n++] = '/';
	component = &subpath[n];

	/*
	 *	Read the directory one component at a time.
	 *	We must ignore "." and "..", but other than that,
	 *	just create a path name and call self to check it out.
	 */
	while((dp = readdir(dirp)) != NULL) {
		if(strcmp(dp->d_name, ".") != 0 &&
			strcmp(dp->d_name, "..") != 0) {
				long here;

			/* Append component name to the working path */
			(void)strcpy(component, dp->d_name);

			/*
			 *	If we are about to exceed our depth,
			 *	remember where we are and close a file.
			 */
			if(depth <= 1) {
				here = telldir(dirp);
				closedir(dirp);
			}

			/*
			 *	Do a recursive call to process the file.
			 *	(watch this, sports fans)
			 */
			rc = ftw(subpath, fn, depth-1);
			if(rc != 0) {
				free(subpath);
				if(depth > 1)
					closedir(dirp);
				return(rc);
			}

			/*
			 *	If we closed the file, try to reopen it.
			 */
			if(depth <= 1) {
				dirp = opendir(path);
				if(dirp == NULL) {
					free(subpath);
					return(-1);
				}
				seekdir(dirp, here);
			}
		}
	}

	/*
	 *	We got out of the subdirectory loop.  The return from
	 *	the final readdir is in dp.  Clean up.
	 */
	free(subpath);
	closedir(dirp);
	return(0);
}
