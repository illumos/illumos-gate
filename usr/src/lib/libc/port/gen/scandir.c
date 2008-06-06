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

/*
 * Based on usr/src/ucblib/libucb/port/gen/scandir.c
 */

/*
 * Scan the directory dirname calling select to make a list of selected
 * directory entries then sort using qsort and compare routine dcomp.
 * Returns the number of entries and a pointer to a list of pointers to
 * struct direct (through namelist). Returns -1 if there were any errors.
 */

#include <sys/feature_tests.h>

#pragma weak _scandir = scandir
#pragma weak _alphasort = alphasort
#if !defined(_LP64)
#pragma weak _scandir64 = scandir64
#pragma weak _alphasort64 = alphasort64
#endif

#include "lint.h"
#include <dirent.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>


#if !defined(_LP64)
int
scandir64(const char *dirname, struct dirent64 *(*namelist[]),
    int (*select)(const struct dirent64 *),
    int (*dcomp)(const struct dirent64 **, const struct dirent64 **))
{
	struct dirent64	*d, *p, **names = NULL;
	size_t	nitems = 0;
	size_t	arraysz, entlen;
	struct stat64	stb;
	DIR	*dirp;
	u_longlong_t	tmp_arraysz;

	if ((dirp = opendir(dirname)) == NULL)
		return (-1);
	if (fstat64(dirp->dd_fd, &stb) < 0)
		goto fail;

	/*
	 * estimate the array size by taking the size of the directory file
	 * and dividing it by a multiple of the minimum size entry.
	 */
	tmp_arraysz = stb.st_size / 24;	/* 24 bytes on a 64-bit system */
	if (tmp_arraysz > INT_MAX)
		arraysz = INT_MAX;
	else
		arraysz = (size_t)tmp_arraysz;
	names = malloc(arraysz * sizeof (struct dirent64 *));
	if (names == NULL)
		goto fail;

	while ((d = readdir64(dirp)) != NULL) {
		if (select != NULL && !(*select)(d))
			continue;	/* just selected names */

		entlen = d->d_reclen;
		/*
		 * Make a minimum size copy of the data
		 */
		p = malloc(entlen);
		if (p == NULL)
			goto fail;
		(void) memcpy(p, d, entlen);
		/*
		 * Check to make sure the array has space left and
		 * realloc the maximum size.
		 */
		if (nitems >= arraysz) {
			struct dirent64	**tmp;
			if (nitems == INT_MAX) {
				/* overflow */
				free(p);
				errno = EOVERFLOW;
				goto fail;
			}
			arraysz += 512;		/* no science here */
			tmp = realloc(names,
			    arraysz * sizeof (struct dirent64 *));
			if (tmp == NULL) {
				free(p);
				goto fail;
			}
			names = tmp;
		}
		names[nitems++] = p;
	}
	(void) closedir(dirp);
	if (nitems && dcomp != NULL)
		qsort(names, nitems, sizeof (struct dirent64 *),
		    (int(*)(const void *, const void *))dcomp);
	*namelist = names;

	return ((int)nitems);

fail:
	while (nitems != 0) {
		free(names[--nitems]);
	}
	if (names)
		free(names);
	(void) closedir(dirp);
	return (-1);
}
#endif


int
scandir(const char *dirname, struct dirent *(*namelist[]),
    int (*select)(const struct dirent *),
    int (*dcomp)(const struct dirent **, const struct dirent **))
{
	struct dirent	*d, *p, **names = NULL;
	size_t	nitems = 0;
	size_t	arraysz, entlen;
	struct stat64	stb;
	DIR	*dirp;
	u_longlong_t	tmp_arraysz;

	if ((dirp = opendir(dirname)) == NULL)
		return (-1);
	if (fstat64(dirp->dd_fd, &stb) < 0)
		goto fail;

	/*
	 * estimate the array size by taking the size of the directory file
	 * and dividing it by a multiple of the minimum size entry.
	 */
	tmp_arraysz = stb.st_size / 24;	/* 24 bytes on a 64-bit system */
	if (tmp_arraysz > INT_MAX)
		arraysz = INT_MAX;
	else
		arraysz = (size_t)tmp_arraysz;
	names = malloc(arraysz * sizeof (struct dirent *));
	if (names == NULL)
		goto fail;

	while ((d = readdir(dirp)) != NULL) {
		if (select != NULL && !(*select)(d))
			continue;	/* just selected names */

		entlen = d->d_reclen;
		/*
		 * Make a minimum size copy of the data
		 */
		p = malloc(entlen);
		if (p == NULL)
			goto fail;
		(void) memcpy(p, d, entlen);
		/*
		 * Check to make sure the array has space left and
		 * realloc the maximum size.
		 */
		if (nitems >= arraysz) {
			struct dirent **tmp;
			if (nitems == INT_MAX) {
				/* overflow */
				free(p);
				errno = EOVERFLOW;
				goto fail;
			}
			arraysz += 512;		/* no science here */
			tmp = realloc(names,
			    arraysz * sizeof (struct dirent *));
			if (tmp == NULL) {
				free(p);
				goto fail;
			}
			names = tmp;
		}
		names[nitems++] = p;
	}
	(void) closedir(dirp);
	if (nitems && dcomp != NULL)
		qsort(names, nitems, sizeof (struct dirent *),
		    (int(*)(const void *, const void *))dcomp);
	*namelist = names;

	return ((int)nitems);

fail:
	while (nitems != 0) {
		free(names[--nitems]);
	}
	if (names)
		free(names);
	(void) closedir(dirp);
	return (-1);
}

/*
 * Alphabetic order comparison routine for those who want it.
 */
int
alphasort(const struct dirent **d1, const struct dirent **d2)
{
	return (strcoll((*d1)->d_name,
	    (*d2)->d_name));
}

#if !defined(_LP64)
int
alphasort64(const struct dirent64 **d1, const struct dirent64 **d2)
{
	return (strcoll((*d1)->d_name,
	    (*d2)->d_name));
}
#endif
