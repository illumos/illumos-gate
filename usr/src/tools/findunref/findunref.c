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
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

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

/*
 * Data associated with the current SCM manifest.
 */
typedef struct scmdata {
	pnset_t		*manifest;
	char		metapath[MAXPATHLEN];
	char		root[MAXPATHLEN];
	unsigned int	rootlen;
	boolean_t	rootwarn;
} scmdata_t;

/*
 * Hooks used to check if a given unreferenced file is known to an SCM
 * (currently Git, Mercurial and TeamWare).
 */
typedef int checkscm_func_t(const char *, const struct FTW *);
typedef void chdirscm_func_t(const char *);

typedef struct {
	const char	*name;
	checkscm_func_t	*checkfunc;
	chdirscm_func_t	*chdirfunc;
} scm_t;

static checkscm_func_t check_tw, check_scmdata;
static chdirscm_func_t chdir_hg, chdir_git;
static int	pnset_add(pnset_t *, const char *);
static int	pnset_check(const pnset_t *, const char *);
static void	pnset_empty(pnset_t *);
static void	pnset_free(pnset_t *);
static int	checkpath(const char *, const struct stat *, int, struct FTW *);
static pnset_t	*make_exset(const char *);
static void	warn(const char *, ...);
static void	die(const char *, ...);

static const scm_t scms[] = {
	{ "tw",		check_tw,	NULL		},
	{ "teamware",	check_tw,	NULL		},
	{ "hg",		check_scmdata,	chdir_hg 	},
	{ "mercurial",	check_scmdata,	chdir_hg	},
	{ "git",	check_scmdata,	chdir_git	},
	{ NULL,		NULL, 		NULL		}
};

static const scm_t	*scm;
static scmdata_t	scmdata;
static time_t		tstamp;		/* timestamp to compare files to */
static pnset_t		*exsetp;	/* pathname globs to ignore */
static const char	*progname;

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

	while ((c = getopt(argc, argv, "as:t:S:")) != EOF) {
		switch (c) {
		case 'a':
			/* for compatibility; now the default */
			break;

		case 's':
			(void) strlcat(subtree, optarg, MAXPATHLEN);
			break;

		case 't':
			tstampfile = optarg;
			break;

		case 'S':
			for (scm = scms; scm->name != NULL; scm++) {
				if (strcmp(scm->name, optarg) == 0)
					break;
			}
			if (scm->name == NULL)
				die("unsupported SCM `%s'\n", optarg);
			break;

		default:
		case '?':
			goto usage;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 2) {
usage:		(void) fprintf(stderr, "usage: %s [-s <subtree>] "
		    "[-t <tstampfile>] [-S hg|tw|git] <srcroot> <exceptfile>\n",
		    progname);
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
	if (chdir(argv[0]) == -1)
		die("cannot change directory to \"%s\"", argv[0]);

	if (nftw(subtree, checkpath, 100, FTW_PHYS) != 0)
		die("cannot walk tree rooted at \"%s\"\n", argv[0]);

	pnset_empty(exsetp);
	return (EXIT_SUCCESS);
}

/*
 * Load and return a pnset for the manifest for the Mercurial repo at `hgroot'.
 */
static pnset_t *
hg_manifest(const char *hgroot)
{
	FILE	*fp = NULL;
	char	*hgcmd = NULL;
	char	*newline;
	pnset_t	*pnsetp;
	char	path[MAXPATHLEN];

	pnsetp = calloc(sizeof (pnset_t), 1);
	if (pnsetp == NULL ||
	    asprintf(&hgcmd, "hg manifest -R %s", hgroot) == -1)
		goto fail;

	fp = popen(hgcmd, "r");
	if (fp == NULL)
		goto fail;

	while (fgets(path, sizeof (path), fp) != NULL) {
		newline = strrchr(path, '\n');
		if (newline != NULL)
			*newline = '\0';

		if (pnset_add(pnsetp, path) == 0)
			goto fail;
	}

	(void) pclose(fp);
	free(hgcmd);
	return (pnsetp);
fail:
	warn("cannot load hg manifest at %s", hgroot);
	if (fp != NULL)
		(void) pclose(fp);
	free(hgcmd);
	pnset_free(pnsetp);
	return (NULL);
}

/*
 * Load and return a pnset for the manifest for the Git repo at `gitroot'.
 */
static pnset_t *
git_manifest(const char *gitroot)
{
	FILE	*fp = NULL;
	char	*gitcmd = NULL;
	char	*newline;
	pnset_t	*pnsetp;
	char	path[MAXPATHLEN];

	pnsetp = calloc(sizeof (pnset_t), 1);
	if (pnsetp == NULL ||
	    asprintf(&gitcmd, "git --git-dir=%s/.git ls-files", gitroot) == -1)
		goto fail;

	fp = popen(gitcmd, "r");
	if (fp == NULL)
		goto fail;

	while (fgets(path, sizeof (path), fp) != NULL) {
		newline = strrchr(path, '\n');
		if (newline != NULL)
			*newline = '\0';

		if (pnset_add(pnsetp, path) == 0)
			goto fail;
	}

	(void) pclose(fp);
	free(gitcmd);
	return (pnsetp);
fail:
	warn("cannot load git manifest at %s", gitroot);
	if (fp != NULL)
		(void) pclose(fp);
	free(gitcmd);
	pnset_free(pnsetp);
	return (NULL);
}

/*
 * If necessary, change our active manifest to be appropriate for `path'.
 */
static void
chdir_scmdata(const char *path, const char *meta,
    pnset_t *(*manifest_func)(const char *path))
{
	char scmpath[MAXPATHLEN];
	char basepath[MAXPATHLEN];
	char *slash;

	(void) snprintf(scmpath, MAXPATHLEN, "%s/%s", path, meta);

	/*
	 * Change our active manifest if any one of the following is true:
	 *
	 *   1. No manifest is loaded.  Find the nearest SCM root to load from.
	 *
	 *   2. A manifest is loaded, but we've moved into a directory with
	 *	its own metadata directory (e.g., usr/closed).  Load from its
	 *	root.
	 *
	 *   3. A manifest is loaded, but no longer applies (e.g., the manifest
	 *	under usr/closed is loaded, but we've moved to usr/src).
	 */
	if (scmdata.manifest == NULL ||
	    (strcmp(scmpath, scmdata.metapath) != 0 &&
	    access(scmpath, X_OK) == 0) ||
	    strncmp(path, scmdata.root, scmdata.rootlen - 1) != 0) {
		pnset_free(scmdata.manifest);
		scmdata.manifest = NULL;

		(void) strlcpy(basepath, path, MAXPATHLEN);

		/*
		 * Walk up the directory tree looking for metadata
		 * subdirectories.
		 */
		while (access(scmpath, X_OK) == -1) {
			slash = strrchr(basepath, '/');
			if (slash == NULL) {
				if (!scmdata.rootwarn) {
					warn("no metadata directory "
					    "for \"%s\"\n", path);
					scmdata.rootwarn = B_TRUE;
				}
				return;
			}
			*slash = '\0';
			(void) snprintf(scmpath, MAXPATHLEN, "%s/%s", basepath,
			    meta);
		}

		/*
		 * We found a directory with an SCM metadata directory; record
		 * it and load its manifest.
		 */
		(void) strlcpy(scmdata.metapath, scmpath, MAXPATHLEN);
		(void) strlcpy(scmdata.root, basepath, MAXPATHLEN);
		scmdata.manifest = manifest_func(scmdata.root);

		/*
		 * The logic in check_scmdata() depends on scmdata.root having
		 * a single trailing slash, so only add it if it's missing.
		 */
		if (scmdata.root[strlen(scmdata.root) - 1] != '/')
			(void) strlcat(scmdata.root, "/", MAXPATHLEN);
		scmdata.rootlen = strlen(scmdata.root);
	}
}

/*
 * If necessary, change our active manifest to be appropriate for `path'.
 */
static void
chdir_git(const char *path)
{
	chdir_scmdata(path, ".git", git_manifest);
}

static void
chdir_hg(const char *path)
{
	chdir_scmdata(path, ".hg", hg_manifest);
}

/* ARGSUSED */
static int
check_scmdata(const char *path, const struct FTW *ftwp)
{
	/*
	 * The manifest paths are relative to the manifest root; skip past it.
	 */
	path += scmdata.rootlen;

	return (scmdata.manifest != NULL && pnset_check(scmdata.manifest,
	    path));
}

/*
 * Check if a file is under TeamWare control by checking for its corresponding
 * SCCS "s-dot" file.
 */
static int
check_tw(const char *path, const struct FTW *ftwp)
{
	char sccspath[MAXPATHLEN];

	(void) snprintf(sccspath, MAXPATHLEN, "%.*s/SCCS/s.%s", ftwp->base,
	    path, path + ftwp->base);

	return (access(sccspath, F_OK) == 0);
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
	pnset_free(pnsetp);
	return (NULL);
}

/*
 * FTW callback: print `path' if it's older than `tstamp' and not in `exsetp'.
 */
static int
checkpath(const char *path, const struct stat *statp, int type,
    struct FTW *ftwp)
{
	switch (type) {
	case FTW_F:
		/*
		 * Skip if the file is referenced or in the exception list.
		 */
		if (statp->st_atime >= tstamp || pnset_check(exsetp, path))
			return (0);

		/*
		 * If requested, restrict ourselves to unreferenced files
		 * under SCM control.
		 */
		if (scm == NULL || scm->checkfunc(path, ftwp))
			(void) puts(path);
		return (0);

	case FTW_D:
		/*
		 * Prune any directories in the exception list.
		 */
		if (pnset_check(exsetp, path)) {
			ftwp->quit = FTW_PRUNE;
			return (0);
		}

		/*
		 * If necessary, advise the SCM logic of our new directory.
		 */
		if (scm != NULL && scm->chdirfunc != NULL)
			scm->chdirfunc(path);

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
	unsigned int maxpaths;

	if (pnsetp->npath == pnsetp->maxpaths) {
		maxpaths = (pnsetp->maxpaths == 0) ? 512 : pnsetp->maxpaths * 2;
		newpaths = realloc(pnsetp->paths, sizeof (char *) * maxpaths);
		if (newpaths == NULL)
			return (0);
		pnsetp->paths = newpaths;
		pnsetp->maxpaths = maxpaths;
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

/*
 * Free the pnset_t pointed to by `pnsetp'.
 */
static void
pnset_free(pnset_t *pnsetp)
{
	if (pnsetp != NULL) {
		pnset_empty(pnsetp);
		free(pnsetp);
	}
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
