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
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Finds all unreferenced files in a source tree that do not match a list of
 * permitted pathnames.
 */

#include <ctype.h>
#include <errno.h>
#include <fnmatch.h>
#include <ftw.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>

/*
 * Pathname set: a simple datatype for storing pathname pattern globs and
 * for checking whether a given pathname is matched by a pattern glob in
 * the set.
 */
typedef struct {
	char		**paths;
	unsigned int	npath;
	unsigned int	maxpaths;
} pnset_t;

static int	pnset_add(pnset_t *, const char *);
static int	pnset_check(const pnset_t *, const char *);
static void	pnset_empty(pnset_t *);
static int	checkpath(const char *, const struct stat *, int, struct FTW *);
static pnset_t	*make_exset(const char *);
static void	warn(const char *, ...);
static void	die(const char *, ...);

static time_t		tstamp;		/* timestamp to compare files to */
static pnset_t		*exsetp;	/* pathname globs to ignore */
static const char	*progname;
static boolean_t	allfiles = B_FALSE;

int
main(int argc, char *argv[])
{
	int c;
	char path[MAXPATHLEN];
	char subtree[MAXPATHLEN] = "./";
	char *tstampfile = ".build.tstamp";
	struct stat tsstat;

	progname = strrchr(argv[0], '/');
	if (progname == NULL)
		progname = argv[0];
	else
		progname++;

	while ((c = getopt(argc, argv, "as:t:")) != EOF) {
		switch (c) {
		case 'a':
			allfiles = B_TRUE;
			break;

		case 's':
			(void) strlcat(subtree, optarg, MAXPATHLEN);
			break;

		case 't':
			tstampfile = optarg;
			break;

		default:
		case '?':
			goto usage;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 2) {
usage:		(void) fprintf(stderr, "usage: %s [-a] [-s subtree] "
		    "[-t tstampfile] srcroot exceptfile\n", progname);
		return (EXIT_FAILURE);
	}

	/*
	 * Interpret a relative timestamp path as relative to srcroot.
	 */
	if (tstampfile[0] == '/')
		(void) strlcpy(path, tstampfile, MAXPATHLEN);
	else
		(void) snprintf(path, MAXPATHLEN, "%s/%s", argv[0], tstampfile);

	if (stat(path, &tsstat) == -1)
		die("cannot stat timestamp file \"%s\"", path);
	tstamp = tsstat.st_mtime;

	/*
	 * Create the exception pathname set.
	 */
	exsetp = make_exset(argv[1]);
	if (exsetp == NULL)
		die("cannot make exception pathname set\n");

	/*
	 * Walk the specified subtree of the tree rooted at argv[0].
	 */
	(void) chdir(argv[0]);
	if (nftw(subtree, checkpath, 100, FTW_PHYS) != 0)
		die("cannot walk tree rooted at \"%s\"\n", argv[0]);

	pnset_empty(exsetp);
	return (EXIT_SUCCESS);
}

/*
 * Using `exceptfile' and a built-in list of exceptions, build and return a
 * pnset_t consisting of all of the pathnames globs which are allowed to be
 * unreferenced in the source tree.
 */
static pnset_t *
make_exset(const char *exceptfile)
{
	FILE		*fp;
	char		line[MAXPATHLEN];
	char		*newline;
	pnset_t		*pnsetp;
	unsigned int	i;

	pnsetp = calloc(sizeof (pnset_t), 1);
	if (pnsetp == NULL)
		return (NULL);

	/*
	 * Add any exceptions from the file.
	 */
	fp = fopen(exceptfile, "r");
	if (fp == NULL) {
		warn("cannot open exception file \"%s\"", exceptfile);
		goto fail;
	}

	while (fgets(line, sizeof (line), fp) != NULL) {
		newline = strrchr(line, '\n');
		if (newline != NULL)
			*newline = '\0';

		for (i = 0; isspace(line[i]); i++)
			;

		if (line[i] == '#' || line[i] == '\0')
			continue;

		if (pnset_add(pnsetp, line) == 0) {
			(void) fclose(fp);
			goto fail;
		}
	}

	(void) fclose(fp);
	return (pnsetp);
fail:
	pnset_empty(pnsetp);
	free(pnsetp);
	return (NULL);
}

/*
 * FTW callback: print `path' if it's older than `tstamp' and not in `exsetp'.
 */
static int
checkpath(const char *path, const struct stat *statp, int type,
    struct FTW *ftwp)
{
	char sccspath[MAXPATHLEN];

	switch (type) {
	case FTW_F:
		/*
		 * Skip if the file is referenced or in the exception list.
		 */
		if (statp->st_atime >= tstamp || pnset_check(exsetp, path))
			return (0);

		/*
		 * If not explicitly checking all files, restrict ourselves
		 * to unreferenced files under SCCS control.
		 */
		if (!allfiles) {
			(void) snprintf(sccspath, MAXPATHLEN, "%.*s/SCCS/s.%s",
			    ftwp->base, path, path + ftwp->base);

			if (access(sccspath, F_OK) == -1)
				return (0);
		}

		(void) puts(path);
		return (0);

	case FTW_D:
		/*
		 * Prune any directories in the exception list.
		 */
		if (pnset_check(exsetp, path))
			ftwp->quit = FTW_PRUNE;
		return (0);

	case FTW_DNR:
		warn("cannot read \"%s\"", path);
		return (0);

	case FTW_NS:
		warn("cannot stat \"%s\"", path);
		return (0);

	default:
		break;
	}

	return (0);
}

/*
 * Add `path' to the pnset_t pointed to by `pnsetp'.
 */
static int
pnset_add(pnset_t *pnsetp, const char *path)
{
	char **newpaths;

	if (pnsetp->npath == pnsetp->maxpaths) {
		newpaths = realloc(pnsetp->paths, sizeof (const char *) *
		    (pnsetp->maxpaths + 15));
		if (newpaths == NULL)
			return (0);
		pnsetp->paths = newpaths;
		pnsetp->maxpaths += 15;
	}

	pnsetp->paths[pnsetp->npath] = strdup(path);
	if (pnsetp->paths[pnsetp->npath] == NULL)
		return (0);

	pnsetp->npath++;
	return (1);
}

/*
 * Check `path' against the pnset_t pointed to by `pnsetp'.
 */
static int
pnset_check(const pnset_t *pnsetp, const char *path)
{
	unsigned int i;

	for (i = 0; i < pnsetp->npath; i++) {
		if (fnmatch(pnsetp->paths[i], path, 0) == 0)
			return (1);
	}
	return (0);
}

/*
 * Empty the pnset_t pointed to by `pnsetp'.
 */
static void
pnset_empty(pnset_t *pnsetp)
{
	while (pnsetp->npath-- != 0)
		free(pnsetp->paths[pnsetp->npath]);

	free(pnsetp->paths);
	pnsetp->maxpaths = 0;
}

/* PRINTFLIKE1 */
static void
warn(const char *format, ...)
{
	va_list alist;
	char *errstr = strerror(errno);

	if (errstr == NULL)
		errstr = "<unknown error>";

	(void) fprintf(stderr, "%s: ", progname);

	va_start(alist, format);
	(void) vfprintf(stderr, format, alist);
	va_end(alist);

	if (strrchr(format, '\n') == NULL)
		(void) fprintf(stderr, ": %s\n", errstr);
}

/* PRINTFLIKE1 */
static void
die(const char *format, ...)
{
	va_list alist;
	char *errstr = strerror(errno);

	if (errstr == NULL)
		errstr = "<unknown error>";

	(void) fprintf(stderr, "%s: fatal: ", progname);

	va_start(alist, format);
	(void) vfprintf(stderr, format, alist);
	va_end(alist);

	if (strrchr(format, '\n') == NULL)
		(void) fprintf(stderr, ": %s\n", errstr);

	exit(EXIT_FAILURE);
}
