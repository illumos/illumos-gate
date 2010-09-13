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
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/

/*
 * Scan the directory dirname calling select to make a list of selected
 * directory entries then sort using qsort and compare routine dcomp.
 * Returns the number of entries and a pointer to a list of pointers to
 * struct direct (through namelist). Returns -1 if there were any errors.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/dir.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

/*
 * The macro DIRSIZ(dp) gives an amount of space required to represent
 * a directory entry.  For any directory entry dp->d_reclen >= DIRSIZ(dp).
 * Specific filesystem types may use this use this macro to construct the value
 * for d_reclen.
 */
#undef DIRSIZ
#define	DIRSIZ(dp)  \
	((sizeof (struct direct) - sizeof ((dp)->d_name) + \
	(strlen((dp)->d_name)+1) + 3) & ~3)

#if !defined(_LP64)
int
scandir64(char *dirname, struct direct64 *(*namelist[]),
    int (*select)(struct direct64 *),
    int (*dcomp)(struct direct64 **, struct direct64 **))
{
	struct direct64 *d, *p, **names;
	int nitems;
	char *cp1, *cp2;
	struct stat64 stb;
	long arraysz;
	DIR *dirp;

	if ((dirp = opendir(dirname)) == NULL)
		return (-1);
	if (fstat64(dirp->dd_fd, &stb) < 0)
		return (-1);

	/*
	 * estimate the array size by taking the size of the directory file
	 * and dividing it by a multiple of the minimum size entry.
	 */
	arraysz = (stb.st_size / 24);
	names = (struct direct64 **)malloc(arraysz *
		sizeof (struct direct64 *));
	if (names == NULL)
		return (-1);

	nitems = 0;
	while ((d = readdir64(dirp)) != NULL) {
		if (select != NULL && !(*select)(d))
			continue;	/* just selected names */
		/*
		 * Make a minimum size copy of the data
		 */
		p = (struct direct64 *)malloc(DIRSIZ64(d));
		if (p == NULL)
			return (-1);
		p->d_ino = d->d_ino;
		p->d_reclen = d->d_reclen;
		p->d_namlen = d->d_namlen;
		for (cp1 = p->d_name, cp2 = d->d_name; *cp1++ = *cp2++; )
			;
		/*
		 * Check to make sure the array has space left and
		 * realloc the maximum size.
		 */
		if (++nitems >= arraysz) {
			if (fstat64(dirp->dd_fd, &stb) < 0)
				return (-1);	/* just might have grown */
			arraysz = stb.st_size / 12;
			names = (struct direct64 **)realloc((char *)names,
				arraysz * sizeof (struct direct64 *));
			if (names == NULL)
				return (-1);
		}
		names[nitems-1] = p;
	}
	(void) closedir(dirp);
	if (nitems && dcomp != NULL)
		qsort(names, nitems, sizeof (struct direct64 *),
			(int(*)(const void *, const void *)) dcomp);
	*namelist = names;
	return (nitems);
}
#endif


int
scandir(char *dirname, struct direct *(*namelist[]),
    int (*select)(struct direct *),
    int (*dcomp)(struct direct **, struct direct **))
{
	struct direct *d, *p, **names;
	int nitems;
	char *cp1, *cp2;
	struct stat64 stb;
	long arraysz;
	DIR *dirp;

	if ((dirp = opendir(dirname)) == NULL)
		return (-1);
	if (fstat64(dirp->dd_fd, &stb) < 0)
		return (-1);
	/*
	 * estimate the array size by taking the size of the directory file
	 * and dividing it by a multiple of the minimum size entry.
	 */
	if (stb.st_size > SSIZE_MAX) {
		errno = EOVERFLOW;
		return (-1);
	}
	arraysz = (stb.st_size / 24);

	names = (struct direct **)malloc(arraysz * sizeof (struct direct *));
	if (names == NULL)
		return (-1);

	nitems = 0;
	while ((d = readdir(dirp)) != NULL) {
		if (select != NULL && !(*select)(d))
			continue;	/* just selected names */
		/*
		 * Make a minimum size copy of the data
		 */
		p = (struct direct *)malloc(DIRSIZ(d));
		if (p == NULL)
			return (-1);
		p->d_ino = d->d_ino;
		p->d_reclen = d->d_reclen;
		p->d_namlen = d->d_namlen;
		for (cp1 = p->d_name, cp2 = d->d_name; *cp1++ = *cp2++; )
			;
		/*
		 * Check to make sure the array has space left and
		 * realloc the maximum size.
		 */
		if (++nitems >= arraysz) {
			if (fstat64(dirp->dd_fd, &stb) < 0)
				return (-1);	/* just might have grown */
			arraysz = stb.st_size / 12;
			names = (struct direct **)realloc((char *)names,
				arraysz * sizeof (struct direct *));
			if (names == NULL)
				return (-1);
		}
		names[nitems-1] = p;
	}
	(void) closedir(dirp);
	if (nitems && dcomp != NULL)
		qsort(names, nitems, sizeof (struct direct *),
			(int(*)(const void *, const void *)) dcomp);
	*namelist = names;
	return (nitems);
}

/*
 * Alphabetic order comparison routine for those who want it.
 */
int
alphasort(struct direct **d1, struct direct **d2)
{
	return (strcmp((*d1)->d_name, (*d2)->d_name));
}

#if !defined(_LP64)
int
alphasort64(struct direct64 **d1, struct direct64 **d2)
{
	return (strcmp((*d1)->d_name, (*d2)->d_name));
}
#endif
