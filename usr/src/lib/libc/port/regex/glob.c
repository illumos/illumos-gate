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

/*
 * This code is MKS code ported to Solaris originally with minimum
 * modifications so that upgrades from MKS would readily integrate.
 * The MKS basis for this modification was:
 *
 *	$Id: glob.c 1.31 1994/04/07 22:50:43 mark
 *
 * Additional modifications have been made to this code to make it
 * 64-bit clean.
 */

/*
 * glob, globfree -- POSIX.2 compatible file name expansion routines.
 *
 * Copyright 1985, 1991 by Mortice Kern Systems Inc.  All rights reserved.
 *
 * Written by Eric Gisin.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#pragma	weak _glob = glob
#pragma	weak _globfree = globfree

#include "lint.h"
#include <stdio.h>
#include <unistd.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <glob.h>
#include <errno.h>
#include <fnmatch.h>

#define	GLOB__CHECK	0x80	/* stat generated paths */

#define	INITIAL	8		/* initial pathv allocation */
#define	NULLCPP	((char **)0)	/* Null char ** */
#define	NAME_MAX	1024	/* something large */

static int	globit(size_t, const char *, glob_t *, int,
	int (*)(const char *, int), char **);
static int	pstrcmp(const void *, const void *);
static int	append(glob_t *, const char *);

/*
 * Free all space consumed by glob.
 */
void
globfree(glob_t *gp)
{
	size_t i;

	if (gp->gl_pathv == 0)
		return;

	for (i = gp->gl_offs; i < gp->gl_offs + gp->gl_pathc; ++i)
		free(gp->gl_pathv[i]);
	free((void *)gp->gl_pathv);

	gp->gl_pathc = 0;
	gp->gl_pathv = NULLCPP;
}

/*
 * Do filename expansion.
 */
int
glob(const char *pattern, int flags,
	int (*errfn)(const char *, int), glob_t *gp)
{
	int rv;
	size_t i;
	size_t ipathc;
	char	*path;

	if ((flags & GLOB_DOOFFS) == 0)
		gp->gl_offs = 0;

	if (!(flags & GLOB_APPEND)) {
		gp->gl_pathc = 0;
		gp->gl_pathn = gp->gl_offs + INITIAL;
		gp->gl_pathv = (char **)malloc(sizeof (char *) * gp->gl_pathn);

		if (gp->gl_pathv == NULLCPP)
			return (GLOB_NOSPACE);
		gp->gl_pathp = gp->gl_pathv + gp->gl_offs;

		for (i = 0; i < gp->gl_offs; ++i)
			gp->gl_pathv[i] = NULL;
	}

	if ((path = malloc(strlen(pattern)+1)) == NULL)
		return (GLOB_NOSPACE);

	ipathc = gp->gl_pathc;
	rv = globit(0, pattern, gp, flags, errfn, &path);

	if (rv == GLOB_ABORTED) {
		/*
		 * User's error function returned non-zero, or GLOB_ERR was
		 * set, and we encountered a directory we couldn't search.
		 */
		free(path);
		return (GLOB_ABORTED);
	}

	i = gp->gl_pathc - ipathc;
	if (i >= 1 && !(flags & GLOB_NOSORT)) {
		qsort((char *)(gp->gl_pathp+ipathc), i, sizeof (char *),
		    pstrcmp);
	}
	if (i == 0) {
		if (flags & GLOB_NOCHECK)
			(void) append(gp, pattern);
		else
			rv = GLOB_NOMATCH;
	}
	gp->gl_pathp[gp->gl_pathc] = NULL;
	free(path);

	return (rv);
}


/*
 * Recursive routine to match glob pattern, and walk directories.
 */
int
globit(size_t dend, const char *sp, glob_t *gp, int flags,
	int (*errfn)(const char *, int), char **path)
{
	size_t n;
	size_t m;
	ssize_t end = 0;	/* end of expanded directory */
	char *pat = (char *)sp;	/* pattern component */
	char *dp = (*path) + dend;
	int expand = 0;		/* path has pattern */
	char *cp;
	struct stat64 sb;
	DIR *dirp;
	struct dirent64 *d;
	int err;

	for (;;)
		switch (*dp++ = *(unsigned char *)sp++) {
		case '\0':	/* end of source path */
			if (expand)
				goto Expand;
			else {
				if (!(flags & GLOB_NOCHECK) ||
				    flags & (GLOB__CHECK|GLOB_MARK))
					if (stat64(*path, &sb) < 0) {
						return (0);
					}
				if (flags & GLOB_MARK && S_ISDIR(sb.st_mode)) {
					*dp = '\0';
					*--dp = '/';
				}
				if (append(gp, *path) < 0) {
					return (GLOB_NOSPACE);
				}
				return (0);
			}
			/*NOTREACHED*/

		case '*':
		case '?':
		case '[':
		case '\\':
			++expand;
			break;

		case '/':
			if (expand)
				goto Expand;
			end = dp - *path;
			pat = (char *)sp;
			break;

		Expand:
			/* determine directory and open it */
			(*path)[end] = '\0';
			dirp = opendir(**path == '\0' ? "." : *path);
			if (dirp == NULL) {
				if (errfn != 0 && errfn(*path, errno) != 0 ||
				    flags&GLOB_ERR) {
					return (GLOB_ABORTED);
				}
				return (0);
			}

			/* extract pattern component */
			n = sp - pat;
			if ((cp = malloc(n)) == NULL) {
				(void) closedir(dirp);
				return (GLOB_NOSPACE);
			}
			pat = memcpy(cp, pat, n);
			pat[n-1] = '\0';
			if (*--sp != '\0')
				flags |= GLOB__CHECK;

			/* expand path to max. expansion */
			n = dp - *path;
			*path = realloc(*path,
			    strlen(*path) + NAME_MAX + strlen(sp) + 1);
			if (*path == NULL) {
				(void) closedir(dirp);
				free(pat);
				return (GLOB_NOSPACE);
			}
			dp = (*path) + n;

			/* read directory and match entries */
			err = 0;
			while ((d = readdir64(dirp)) != NULL) {
				cp = d->d_name;
				if ((flags&GLOB_NOESCAPE)
				    ? fnmatch(pat, cp, FNM_PERIOD|FNM_NOESCAPE)
				    : fnmatch(pat, cp, FNM_PERIOD))
					continue;

				n = strlen(cp);
				(void) memcpy((*path) + end, cp, n);
				m = dp - *path;
				err = globit(end+n, sp, gp, flags, errfn, path);
				dp = (*path) + m;   /* globit can move path */
				if (err != 0)
					break;
			}

			(void) closedir(dirp);
			free(pat);
			return (err);
		}
		/* NOTREACHED */
}

/*
 * Comparison routine for two name arguments, called by qsort.
 */
int
pstrcmp(const void *npp1, const void *npp2)
{
	return (strcoll(*(char **)npp1, *(char **)npp2));
}

/*
 * Add a new matched filename to the glob_t structure, increasing the
 * size of that array, as required.
 */
int
append(glob_t *gp, const char *str)
{
	char *cp;

	if ((cp = malloc(strlen(str)+1)) == NULL)
		return (GLOB_NOSPACE);
	gp->gl_pathp[gp->gl_pathc++] = strcpy(cp, str);

	if ((gp->gl_pathc + gp->gl_offs) >= gp->gl_pathn) {
		gp->gl_pathn *= 2;
		gp->gl_pathv = (char **)realloc((void *)gp->gl_pathv,
		    gp->gl_pathn * sizeof (char *));
		if (gp->gl_pathv == NULLCPP)
			return (GLOB_NOSPACE);
		gp->gl_pathp = gp->gl_pathv + gp->gl_offs;
	}
	return (0);
}
