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

/*
 *
 *			cfsadmin.c
 *
 * Cache FS admin utility.
 */

#include <assert.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <dirent.h>
#include <ftw.h>
#include <fcntl.h>
#include <ctype.h>
#include <stdarg.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/mman.h>
#include <sys/mnttab.h>
#include <sys/fs/cachefs_fs.h>
#include <sys/fs/cachefs_dir.h>
#include <sys/utsname.h>
#include <rpc/rpc.h>
#include <priv.h>
#include "../common/subr.h"
#include "../common/cachefsd.h"

char *cfsadmin_opts[] = {
#define		COPT_MAXBLOCKS		0
		"maxblocks",
#define		COPT_MINBLOCKS		1
		"minblocks",
#define		COPT_THRESHBLOCKS	2
		"threshblocks",

#define		COPT_MAXFILES 		3
		"maxfiles",
#define		COPT_MINFILES		4
		"minfiles",
#define		COPT_THRESHFILES	5
		"threshfiles",

#define		COPT_MAXFILESIZE	6
		"maxfilesize",

#define		COPT_HIBLOCKS		7
		"hiblocks",
#define		COPT_LOWBLOCKS		8
		"lowblocks",
#define		COPT_HIFILES		9
		"hifiles",
#define		COPT_LOWFILES		10
		"lowfiles",
		NULL
};

#define	bad(val)	((val) == NULL || !isdigit(*(val)))

/* numbers must be valid percentages ranging from 0 to 100 */
#define	badpercent(val) \
	((val) == NULL || !isdigit(*(val)) || \
	    atoi((val)) < 0 || atoi((val)) > 100)

/* forward references */
void usage(char *msg);
void pr_err(char *fmt, ...);
int cfs_get_opts(char *oarg, struct cachefs_user_values *uvp);
int update_cachelabel(char *dirp, char *optionp);
void user_values_defaults(struct cachefs_user_values *uvp);
int check_user_values_for_sanity(const struct cachefs_user_values *uvp);
int cache_stats(char *dirp);
int resource_file_grow(char *dirp, int oldcnt, int newcnt);
int resource_file_dirty(char *dirp);
void simulate_disconnection(char *namep, int disconnect);

/*
 *
 *			main
 *
 * Description:
 *	Main routine for the cfsadmin program.
 * Arguments:
 *	argc	number of command line arguments
 *	argv	command line arguments
 * Returns:
 *	Returns 0 for failure, > 0 for an error.
 * Preconditions:
 */

int
main(int argc, char **argv)
{
	int c;
	int xx;
	int lockid;

	char *cacheid;
	char *cachedir;

	int cflag;
	int uflag;
	int dflag;
	int sflag;
	int allflag;
	int lflag;
	char *optionp;
	int Cflag;
	int Dflag;

	priv_set_t *priv_needed, *priv_effective;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	/* set defaults for command line options */
	cflag = 0;
	uflag = 0;
	dflag = 0;
	sflag = 0;
	allflag = 0;
	lflag = 0;
	optionp = NULL;
	Cflag = 0;
	Dflag = 0;

	/* parse the command line arguments */
	while ((c = getopt(argc, argv, "cCDuo:d:sl")) != EOF) {
		switch (c) {

		case 'c':		/* create */
			cflag = 1;
			break;

			/*
			 * -C and -D are undocumented calls used
			 * to simulate disconnection on a file system.
			 */
		case 'C':		/* connect file system */
			Cflag = 1;
			break;
		case 'D':		/* disconnect file system */
			Dflag = 1;
			break;

		case 'u':		/* update */
			uflag = 1;
			break;

		case 'd':		/* delete */
			dflag = 1;
			if (strcmp(optarg, "all") == 0)
				allflag = 1;
			else
				cacheid = optarg;
			break;

		case 's':		/* consistency on demand */
			sflag = 1;
			break;

		case 'l':		/* list cache ids */
			lflag = 1;
			break;

		case 'o':		/* options for update and create */
			optionp = optarg;
			break;

		default:
			usage(gettext("illegal option"));
			return (1);
		}
	}

	if ((cflag + dflag + lflag + sflag + uflag + Cflag + Dflag) == 0) {
		usage(gettext("no options specified"));
		return (1);
	}

	if (cflag || uflag || dflag || Cflag || Dflag)
		priv_needed = priv_str_to_set("all", ",", NULL);
	if ((cflag || uflag) && getuid() != 0) {
		/* These options create files. We want them to be root owned */
		pr_err(gettext("must be run by root"));
		return (1);
	}

	else if (lflag)
		priv_needed = priv_str_to_set("file_dac_search,file_dac_read",
		    ",", NULL);

	else if (sflag)
		priv_needed = priv_str_to_set("sys_config", ",", NULL);

	priv_effective = priv_allocset();
	(void) getppriv(PRIV_EFFECTIVE, priv_effective);
	if (priv_issubset(priv_needed, priv_effective) == 0) {
		pr_err(gettext("Not privileged."));
		return (1);
	}
	priv_freeset(priv_effective);
	priv_freeset(priv_needed);

	if ((sflag + Cflag + Dflag) == 0) {
		/* make sure cachedir is specified */
		if (argc - 1 != optind) {
			usage(gettext("cache directory not specified"));
			return (1);
		}
		cachedir = argv[argc-1];
	} else {
		/* make sure at least one mount point is specified */
		if (argc - 1 < optind) {
			usage(gettext("mount points not specified"));
			return (1);
		}
	}

	/* make sure a reasonable set of flags were specified */
	if ((cflag + uflag + dflag + sflag + lflag + Cflag + Dflag) != 1) {
		/* flags are mutually exclusive, at least one must be set */
		usage(gettext(
		    "exactly one of -c, -u, -d, -s, -l must be specified"));
		return (1);
	}

	/* make sure -o specified with -c or -u */
	if (optionp && !(cflag|uflag)) {
		usage(gettext("-o can only be used with -c or -u"));
		return (1);
	}

	/* if creating a cache */
	if (cflag) {
		struct cachefs_user_values uv;
		struct cache_label clabel;

		/* get default cache paramaters */
		user_values_defaults(&uv);

		/* parse the options if specified */
		if (optionp) {
			xx = cfs_get_opts(optionp, &uv);
			if (xx)
				return (1);
		}

		/* verify options are reasonable */
		xx = check_user_values_for_sanity(&uv);
		if (xx)
			return (1);

		/* lock the cache directory non-shared */
		lockid = cachefs_dir_lock(cachedir, 0);
		if (lockid == -1) {
			/* quit if could not get the lock */
			return (1);
		}

		/* create the cache */
		xx = cachefs_create_cache(cachedir, &uv, &clabel);
		if (xx != 0) {
			if (xx == -2) {
				/* remove a partially created cache dir */
				(void) cachefs_delete_all_cache(cachedir);
			}
			cachefs_dir_unlock(lockid);
			return (1);
		}
		cachefs_dir_unlock(lockid);
	}

	/* else if updating resource parameters */
	else if (uflag) {
		/* lock the cache directory non-shared */
		lockid = cachefs_dir_lock(cachedir, 0);
		if (lockid == -1) {
			/* quit if could not get the lock */
			return (1);
		}

		xx = update_cachelabel(cachedir, optionp);
		cachefs_dir_unlock(lockid);
		if (xx != 0) {
			return (1);
		}
	}

	/* else if deleting a specific cacheID (or all caches) */
	else if (dflag) {
		/* lock the cache directory non-shared */
		lockid = cachefs_dir_lock(cachedir, 0);
		if (lockid == -1) {
			/* quit if could not get the lock */
			return (1);
		}

		/* if the cache is in use */
		if (cachefs_inuse(cachedir)) {
			pr_err(gettext("Cache %s is in use and "
			    "cannot be modified."), cachedir);
			cachefs_dir_unlock(lockid);
			return (1);
		}

		if (allflag)
			xx = cachefs_delete_all_cache(cachedir);
		else {
			/* mark resource file as dirty */
			xx = resource_file_dirty(cachedir);
			if (xx == 0)
				xx = cachefs_delete_cache(cachedir, cacheid);
		}
		cachefs_dir_unlock(lockid);
		if (xx != 0) {
			return (1);
		}
	}

	/* else if listing cache statistics */
	else if (lflag) {
		xx = cache_stats(cachedir);
		if (xx != 0)
			return (1);
	}

	/* else if issuing a check event to cached file systems */
	else if (sflag) {
		for (xx = optind; xx < argc; xx++) {
			issue_cod(argv[xx]);
		}
	}

	/* else if simulating a disconnection */
	else if (Dflag) {
		for (xx = optind; xx < argc; xx++) {
			simulate_disconnection(argv[xx], 1);
		}
	}

	/* else if connection after a simulated disconnection */
	else if (Cflag) {
		for (xx = optind; xx < argc; xx++) {
			simulate_disconnection(argv[xx], 0);
		}
	}

	/* return success */
	return (0);
}


/*
 *
 *			usage
 *
 * Description:
 *	Prints a usage message for this utility.
 * Arguments:
 *	msgp	message to include with the usage message
 * Returns:
 * Preconditions:
 *	precond(msgp)
 */

void
usage(char *msgp)
{
	fprintf(stderr, gettext("cfsadmin: %s\n"), msgp);
	fprintf(stderr, gettext(
	    "usage: cfsadmin -[cu] [-o parameter-list] cachedir\n"));
	fprintf(stderr, gettext("       cfsadmin -d [CacheID|all] cachedir\n"));
	fprintf(stderr, gettext("       cfsadmin -l cachedir\n"));
	fprintf(stderr, gettext("       cfsadmin -s [mntpnt1 ... | all]\n"));
}

/*
 *
 *			pr_err
 *
 * Description:
 *	Prints an error message to stderr.
 * Arguments:
 *	fmt	printf style format
 *	...	arguments for fmt
 * Returns:
 * Preconditions:
 *	precond(fmt)
 */

void
pr_err(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	(void) fprintf(stderr, gettext("cfsadmin: "));
	(void) vfprintf(stderr, fmt, ap);
	(void) fprintf(stderr, "\n");
	va_end(ap);
}

/*
 *
 *			cfs_get_opts
 *
 * Description:
 *	Decodes cfs options specified with -o.
 *	Only the fields referenced by the options are modified.
 * Arguments:
 *	oarg	options from -o option
 *	uvp	place to put options
 * Returns:
 *	Returns 0 for success, -1 for an error.
 * Preconditions:
 *	precond(oarg)
 *	precond(uvp)
 */

int
cfs_get_opts(char *oarg, struct cachefs_user_values *uvp)
{
	char *optstr, *opts, *val;
	char *saveopts;
	int badopt;

	/* make a copy of the options because getsubopt modifies it */
	optstr = opts = strdup(oarg);
	if (opts == NULL) {
		pr_err(gettext("no memory"));
		return (-1);
	}

	/* process the options */
	badopt = 0;
	while (*opts && !badopt) {
		saveopts = opts;
		switch (getsubopt(&opts, cfsadmin_opts, &val)) {
		case COPT_MAXBLOCKS:
			if (badpercent(val))
				badopt = 1;
			else
				uvp->uv_maxblocks = atoi(val);
			break;
		case COPT_MINBLOCKS:
			if (badpercent(val))
				badopt = 1;
			else
				uvp->uv_minblocks = atoi(val);
			break;
		case COPT_THRESHBLOCKS:
			if (badpercent(val))
				badopt = 1;
			else
				uvp->uv_threshblocks = atoi(val);
			break;

		case COPT_MAXFILES:
			if (badpercent(val))
				badopt = 1;
			else
				uvp->uv_maxfiles = atoi(val);
			break;
		case COPT_MINFILES:
			if (badpercent(val))
				badopt = 1;
			else
				uvp->uv_minfiles = atoi(val);
			break;
		case COPT_THRESHFILES:
			if (badpercent(val))
				badopt = 1;
			else
				uvp->uv_threshfiles = atoi(val);
			break;

		case COPT_MAXFILESIZE:
			if (bad(val))
				badopt = 1;
			else
				uvp->uv_maxfilesize = atoi(val);
			break;

		case COPT_HIBLOCKS:
			if (badpercent(val))
				badopt = 1;
			else
				uvp->uv_hiblocks = atoi(val);
			break;
		case COPT_LOWBLOCKS:
			if (badpercent(val))
				badopt = 1;
			else
				uvp->uv_lowblocks = atoi(val);
			break;
		case COPT_HIFILES:
			if (badpercent(val))
				badopt = 1;
			else
				uvp->uv_hifiles = atoi(val);
			break;
		case COPT_LOWFILES:
			if (badpercent(val))
				badopt = 1;
			else
				uvp->uv_lowfiles = atoi(val);
			break;
		default:
			/* if a bad option argument */
			pr_err(gettext("Invalid option %s"), saveopts);
			return (-1);
		}
	}

	/* if a bad value for an option, display an error message */
	if (badopt) {
		pr_err(gettext("invalid argument to option: \"%s\""),
		    saveopts);
	}

	/* free the duplicated option string */
	free(optstr);

	/* return the result */
	return (badopt ? -1 : 0);
}

/*
 *
 *			update_cachelabel
 *
 * Description:
 *	Changes the parameters of the cache_label.
 *	If optionp is NULL then the cache_label is set to
 *	default values.
 * Arguments:
 *	dirp		the name of the cache directory
 *	optionp		comma delimited options
 * Returns:
 *	Returns 0 for success and -1 for an error.
 * Preconditions:
 *	precond(dirp)
 */

int
update_cachelabel(char *dirp, char *optionp)
{
	char path[CACHEFS_XMAXPATH];
	struct cache_label clabel_new;
	struct cache_label clabel_orig;
	struct cachefs_user_values uv_orig, uv_new;
	int xx;

	/* if the cache is in use */
	if (cachefs_inuse(dirp)) {
		pr_err(gettext("Cache %s is in use and cannot be modified."),
		    dirp);
		return (-1);
	}

	/* make sure we don't overwrite path */
	if (strlen(dirp) > (size_t)PATH_MAX) {
		pr_err(gettext("name of label file %s is too long."),
		    dirp);
		return (-1);
	}

	/* construct the pathname to the cach_label file */
	sprintf(path, "%s/%s", dirp, CACHELABEL_NAME);

	/* read the current set of parameters */
	xx = cachefs_label_file_get(path, &clabel_orig);
	if (xx == -1) {
		pr_err(gettext("reading %s failed"), path);
		return (-1);
	}
	xx = cachefs_label_file_vcheck(path, &clabel_orig);
	if (xx != 0) {
		pr_err(gettext("version mismatch on %s"), path);
		return (-1);
	}

	/* convert the cache_label to user values */
	xx = cachefs_convert_cl2uv(&clabel_orig, &uv_orig, dirp);
	if (xx) {
		return (-1);
	}

	/* if options were specified */
	if (optionp) {
		/* start with the original values */
		uv_new = uv_orig;

		/* parse the options */
		xx = cfs_get_opts(optionp, &uv_new);
		if (xx) {
			return (-1);
		}

		/* verify options are reasonable */
		xx = check_user_values_for_sanity(&uv_new);
		if (xx) {
			return (-1);
		}
	}

	/* else if options where not specified, get defaults */
	else {
		user_values_defaults(&uv_new);
	}

	/* convert user values to a cache_label */
	xx = cachefs_convert_uv2cl(&uv_new, &clabel_new, dirp);
	if (xx) {
		return (-1);
	}

	/* do not allow the cache size to shrink */
	if (uv_orig.uv_maxblocks > uv_new.uv_maxblocks) {
		pr_err(gettext("Cache size cannot be reduced,"
			" maxblocks current %d%%, requested %d%%"),
			uv_orig.uv_maxblocks, uv_new.uv_maxblocks);
		return (-1);
	}
	if (clabel_orig.cl_maxinodes > clabel_new.cl_maxinodes) {
		pr_err(gettext("Cache size cannot be reduced,"
			" maxfiles current %d%% requested %d%%"),
			uv_orig.uv_maxfiles, uv_new.uv_maxfiles);
		return (-1);
	}

	/* write back the new values */
	xx = cachefs_label_file_put(path, &clabel_new);
	if (xx == -1) {
		pr_err(gettext("writing %s failed"), path);
		return (-1);
	}

	/* put the new values in the duplicate cache label file also */
	sprintf(path, "%s/%s.dup", dirp, CACHELABEL_NAME);
	xx = cachefs_label_file_put(path, &clabel_new);
	if (xx == -1) {
		pr_err(gettext("writing %s failed"), path);
		return (-1);
	}

	/* grow resouces file if necessary */
	xx = 0;
	if (clabel_orig.cl_maxinodes != clabel_new.cl_maxinodes) {
		xx = resource_file_grow(dirp, clabel_orig.cl_maxinodes,
			clabel_new.cl_maxinodes);
	}

	/* return status */
	return (xx);
}

/*
 *
 *			user_values_defaults
 *
 * Description:
 *	Sets default values in the cachefs_user_values object.
 * Arguments:
 *	uvp	cachefs_user_values object to set values for
 * Returns:
 * Preconditions:
 *	precond(uvp)
 */

void
user_values_defaults(struct cachefs_user_values *uvp)
{
	uvp->uv_maxblocks = 90;
	uvp->uv_minblocks = 0;
	uvp->uv_threshblocks = 85;
	uvp->uv_maxfiles = 90;
	uvp->uv_minfiles = 0;
	uvp->uv_threshfiles = 85;
	uvp->uv_maxfilesize = 3;
	uvp->uv_hiblocks = 85;
	uvp->uv_lowblocks = 75;
	uvp->uv_hifiles = 85;
	uvp->uv_lowfiles = 75;
}

/*
 *
 *			check_user_values_for_sanity
 *
 * Description:
 *	Check the cachefs_user_values for sanity.
 * Arguments:
 *	uvp	cachefs_user_values object to check
 * Returns:
 *	Returns 0 if okay, -1 if not.
 * Preconditions:
 *	precond(uvp)
 */

int
check_user_values_for_sanity(const struct cachefs_user_values *uvp)
{
	int ret;

	ret = 0;

	if (uvp->uv_lowblocks >= uvp->uv_hiblocks) {
		pr_err(gettext("lowblocks can't be >= hiblocks."));
		ret = -1;
	}
	if (uvp->uv_lowfiles >= uvp->uv_hifiles) {
		pr_err(gettext("lowfiles can't be >= hifiles."));
		ret = -1;
	}

	/* XXX more conditions to check here? */

	/* XXX make sure thresh values are between min and max values */

	/* return status */
	return (ret);
}

/*
 *
 *			cache_stats
 *
 * Description:
 *	Show each cache in the directory, cache resource statistics,
 *	and, for each fs in the cache, the name of the fs, and the
 *	cache resource parameters.
 * Arguments:
 *	dirp	name of the cache directory
 * Returns:
 *	Returns 0 for success, -1 for an error.
 * Errors:
 * Preconditions:
 */

int
cache_stats(char *dirp)
{
	DIR *dp;
	struct dirent64 *dep;
	char path[CACHEFS_XMAXPATH];
	struct stat64 statinfo;
	int ret;
	int xx;
	struct cache_label clabel;
	struct cachefs_user_values uv;

	/* make sure cache dir name is not too long */
	if (strlen(dirp) > (size_t)PATH_MAX) {
		pr_err(gettext("path name %s is too long."), dirp);
		return (-1);
	}

	/* read the cache label file */
	sprintf(path, "%s/%s", dirp, CACHELABEL_NAME);
	xx = cachefs_label_file_get(path, &clabel);
	if (xx == -1) {
		pr_err(gettext("Reading %s failed."), path);
		return (-1);
	}
	xx = cachefs_label_file_vcheck(path, &clabel);
	if (xx != 0) {
		pr_err(gettext("Version mismatch on %s."), path);
		return (-1);
	}

	/* convert the cache_label to user values */
	xx = cachefs_convert_cl2uv(&clabel, &uv, dirp);
	if (xx)
		return (-1);

	/* display the parameters */
	printf(gettext("cfsadmin: list cache FS information\n"));
#if 0
	printf(gettext("   Version      %3d\n"), clabel.cl_cfsversion);
#endif
	printf(gettext("   maxblocks    %3d%%\n"), uv.uv_maxblocks);
	printf(gettext("   minblocks    %3d%%\n"), uv.uv_minblocks);
	printf(gettext("   threshblocks %3d%%\n"), uv.uv_threshblocks);
	printf(gettext("   maxfiles     %3d%%\n"), uv.uv_maxfiles);
	printf(gettext("   minfiles     %3d%%\n"), uv.uv_minfiles);
	printf(gettext("   threshfiles  %3d%%\n"), uv.uv_threshfiles);
	printf(gettext("   maxfilesize  %3dMB\n"), uv.uv_maxfilesize);

	/* open the directory */
	if ((dp = opendir(dirp)) == NULL) {
		pr_err(gettext("opendir %s failed: %s"), dirp,
		    strerror(errno));
		return (-1);
	}

	/* loop reading the contents of the directory */
	ret = 0;
	while ((dep = readdir64(dp)) != NULL) {
		/* ignore . and .. */
		if ((strcmp(dep->d_name, ".") == 0) ||
		    (strcmp(dep->d_name, "..") == 0))
			continue;

		/* stat the file */
		sprintf(path, "%s/%s", dirp, dep->d_name);
		xx = lstat64(path, &statinfo);
		if (xx == -1) {
			pr_err(gettext("lstat %s failed: %s"),
			    path, strerror(errno));
			closedir(dp);
			return (-1);
		}

		/* ignore anything that is not a link */
		if (!S_ISLNK(statinfo.st_mode))
			continue;

		/* print the file system cache directory name */
		printf(gettext("  %s\n"), dep->d_name);

		/* XXX anything else */
	}

	/* XXX what about stats */

	/* return status */
	return (ret);
}

/*
 *
 *			resource_file_grow
 *
 * Description:
 *	Grows the resource file in the specified directory
 *	to its new size.
 * Arguments:
 *	dirp	cache directory resource file is in
 *	oldcnt	previous number of files in resource file
 *	newcnt	new number of files in resource file
 * Returns:
 *	Returns 0 for success, -1 for an error.
 * Preconditions:
 *	precond(dirp)
 *	precond(oldcnt <= newcnt)
 *	precond(cache is locked exclusively)
 *	precond(cache is not in use)
 */

int
resource_file_grow(char *dirp, int oldcnt, int newcnt)
{
	int fd;
	char path[CACHEFS_XMAXPATH];
	int xx;
	struct stat64 st;
	static struct cachefs_rinfo rold, rnew;
	struct cache_usage cusage, *cusagep;
	char buf[MAXBSIZE];
	int cnt;
	caddr_t addrp;
	int dirty;

	/* get info about the resouce file for the various sizes */
	cachefs_resource_size(oldcnt, &rold);
	cachefs_resource_size(newcnt, &rnew);

	/* open the resource file for writing */
	/* this file is < 2GB */
	sprintf(path, "%s/%s", dirp, RESOURCE_NAME);
	fd = open(path, O_RDWR);
	if (fd == -1) {
		pr_err(gettext("Could not open %s: %s, run fsck"), path,
		    strerror(errno));
		return (-1);
	}

	/* get info on the file */
	xx = fstat64(fd, &st);
	if (xx == -1) {
		pr_err(gettext("Could not stat %s: %s"), path,
		    strerror(errno));
		close(fd);
		return (-1);
	}

	/* make sure the size is the correct */
	if ((off_t)st.st_size != rold.r_fsize) {
		pr_err(gettext("Resource file has wrong size %d %d, run fsck"),
			(off_t)st.st_size, rold.r_fsize);
		close(fd);
		return (-1);
	}

	/* read the cache usage structure */
	xx = read(fd, &cusage, sizeof (cusage));
	if (xx != sizeof (cusage)) {
		pr_err(gettext("Could not read cache_usage, %d, run fsck"),
			xx);
		close(fd);
		return (-1);
	}

	/* rewind */
	xx = lseek(fd, 0, SEEK_SET);
	if (xx == -1) {
		pr_err(gettext("Could not lseek %s: %s"), path,
			strerror(errno));
		close(fd);
		return (-1);
	}

	/* indicate cache is dirty if necessary */
	dirty = 1;
	if ((cusage.cu_flags & CUSAGE_ACTIVE) == 0) {
		dirty = 0;
		cusage.cu_flags |= CUSAGE_ACTIVE;
		xx = write(fd, &cusage, sizeof (cusage));
		if (xx != sizeof (cusage)) {
			pr_err(gettext(
				"Could not write cache_usage, %d, run fsck"),
				xx);
			close(fd);
			return (-1);
		}
	}

	/* go to the end of the file */
	xx = lseek(fd, 0, SEEK_END);
	if (xx == -1) {
		pr_err(gettext("Could not lseek %s: %s"), path,
			strerror(errno));
		close(fd);
		return (-1);
	}

	/* grow the file to the new size */
	memset(buf, 0, sizeof (buf));
	cnt = rnew.r_fsize - rold.r_fsize;
	assert((cnt % MAXBSIZE) == 0);
	cnt /= MAXBSIZE;
	while (cnt-- > 0) {
		xx = write(fd, buf, sizeof (buf));
		if (xx != sizeof (buf)) {
			pr_err(gettext("Could not write file, %d, run fsck"),
				xx);
			close(fd);
			return (-1);
		}
	}

	/* mmap the file into our address space */
	addrp = mmap(NULL, rnew.r_fsize, PROT_READ | PROT_WRITE, MAP_SHARED,
		fd, 0);
	if (addrp == (void *)-1) {
		pr_err(gettext("Could not mmap file %s: %s"), path,
			strerror(errno));
		close(fd);
		return (-1);
	}

	/* close the file descriptor, we do not need it anymore */
	close(fd);

	/* move the idents region to its new location */
	memmove(addrp + rnew.r_identoffset, addrp + rold.r_identoffset,
		rold.r_identsize);

	/* zero out the old idents region that is now in the pointers region */
	memset(addrp + rold.r_identoffset, 0,
		rnew.r_identoffset - rold.r_identoffset);

	/* sync the data to the file */
	xx = msync(addrp, rnew.r_fsize, MS_SYNC);
	if (xx == -1) {
		pr_err(gettext("Could not sync file %s: %s"), path,
			strerror(errno));
		munmap(addrp, rnew.r_fsize);
		return (-1);
	}

	/* mark the file as clean if it was not dirty originally */
	if (!dirty) {
		cusagep = (struct cache_usage *)addrp;
		cusagep->cu_flags &= ~CUSAGE_ACTIVE;

		/* sync the data to the file */
		xx = msync(addrp, rnew.r_fsize, MS_SYNC);
		if (xx == -1) {
			pr_err(gettext("Could not sync file %s: %s"), path,
				strerror(errno));
			munmap(addrp, rnew.r_fsize);
			return (-1);
		}
	}

	/* unmap the file */
	munmap(addrp, rnew.r_fsize);

	/* return success */
	return (0);
}

/*
 *
 *			resource_file_dirty
 *
 * Description:
 *	Marks the resource file as dirty.
 *	This will cause fsck to fix it up the next time it
 *	is run.
 * Arguments:
 *	dirp	cache directory resource file is in
 * Returns:
 *	Returns 0 for success, -1 for an error.
 * Preconditions:
 *	precond(dirp)
 *	precond(cache is locked exclusively)
 *	precond(cache is not in use)
 */

int
resource_file_dirty(char *dirp)
{
	int fd;
	char path[CACHEFS_XMAXPATH];
	int xx;
	struct cache_usage cusage;

	/* open the resource file for writing */
	/* this file is < 2GB */
	sprintf(path, "%s/%s", dirp, RESOURCE_NAME);
	fd = open(path, O_RDWR);
	if (fd == -1) {
		pr_err(gettext("Could not open %s: %s, run fsck"), path,
		    strerror(errno));
		return (-1);
	}

	/* read the cache usage structure */
	xx = read(fd, &cusage, sizeof (cusage));
	if (xx != sizeof (cusage)) {
		pr_err(gettext("Could not read cache_usage, %d, run fsck"),
			xx);
		close(fd);
		return (-1);
	}

	/* rewind */
	xx = lseek(fd, 0, SEEK_SET);
	if (xx == -1) {
		pr_err(gettext("Could not lseek %s: %s"), path,
			strerror(errno));
		close(fd);
		return (-1);
	}

	/* indicate cache is dirty if necessary */
	if ((cusage.cu_flags & CUSAGE_ACTIVE) == 0) {
		cusage.cu_flags |= CUSAGE_ACTIVE;
		xx = write(fd, &cusage, sizeof (cusage));
		if (xx != sizeof (cusage)) {
			pr_err(gettext(
				"Could not write cache_usage, %d, run fsck"),
				xx);
			close(fd);
			return (-1);
		}
	}

	xx = close(fd);
	if (xx == -1) {
		pr_err(gettext("Could not successfully close %s: %s"), path,
			strerror(errno));
	}
	return (xx);
}

/*
 *
 *			issue_cod
 *
 * Description:
 *	Executes the _FIOCOD ioctl on the specified file.
 * Arguments:
 *	name	filename to issue ioctl on (or "all")
 * Returns:
 *	Returns 0 for success, -1 for an error.
 * Preconditions:
 *	precond(dirp)
 */

int
issue_cod(char *name)
{
	int fd;
	int xx;
	int arg;
	char *dirp;
	FILE *mfp;
	struct mnttab mt, mtpref;

#ifndef MNTTYPE_CACHEFS
#define	MNTTYPE_CACHEFS	"cachefs"
#endif

	arg = 0;
	if (strcmp(name, "all") == 0) {
		/*
		 * if "all" was specified rather than a mount point,
		 * we locate a cachefs mount in /etc/mnttab (any cachefs
		 * mount will do).  We issue the ioctl on this mount point,
		 * and specify a non-zero argument to the ioctl.  The non-zero
		 * arg tells the kernel to do demandconst on all relevant
		 * cachefs mounts
		 */
		if ((mfp = fopen(MNTTAB, "r")) == NULL) {
			pr_err(gettext("Could not open %s."), MNTTAB);
			return (-1);
		}
		mtpref.mnt_special = NULL;
		mtpref.mnt_mountp = NULL;
		mtpref.mnt_mntopts = NULL;
		mtpref.mnt_time = NULL;
		mtpref.mnt_fstype = MNTTYPE_CACHEFS;
		if (getmntany(mfp, &mt, &mtpref) != 0) {
			(void) fclose(mfp);
			return (-1);
		}
		(void) fclose(mfp);
		dirp = mt.mnt_mountp;
		arg = 1;
	} else {
		dirp = name;
	}

	/* open the file */
	fd = open(dirp, O_RDONLY);
	if (fd == -1) {
		pr_err(gettext("Could not open %s, %s."),
			dirp, strerror(errno));
		return (-1);
	}

	/* issue the ioctl */
	xx = ioctl(fd, _FIOCOD, arg);
	if (xx) {
		if (errno == ENOTTY) {
			pr_err(gettext("%s is not a CacheFS file system"),
				dirp);
		} else if (errno == EBUSY) {
			if (arg == 0)
				/* we're quiet if "all" was specified */
				pr_err(gettext("CacheFS file system %s is not"
					" mounted demandconst."), dirp);
		} else {
			pr_err(gettext("Could not issue consistency request"
				" on %s\n    %s."), dirp, strerror(errno));
		}
	}
	close(fd);
	return (xx);
}

/*
 *
 *			simulate_disconnection
 *
 * Description:
 *	Sends the rpc message to the cachefsd to turn simulated
 *	disconnection on or off
 * Arguments:
 *	namep		name of file system or "all"
 *	disconnect	1 means disconnect, 0 means connect
 * Returns:
 * Preconditions:
 *	precond(name)
 */

void
simulate_disconnection(char *namep, int disconnect)
{
	CLIENT *clnt;
	enum clnt_stat retval;
	int ret;
	int xx;
	int result;
	char *hostp;
	struct utsname info;
	struct cachefsd_disconnection_args args;
	char *msgp;
	struct timeval tval;

	/* get the host name */
	xx = uname(&info);
	if (xx == -1) {
		pr_err(gettext("cannot get host name, errno %d"), errno);
		return;
	}
	hostp = info.nodename;

	/* creat the connection to the daemon */
	clnt = clnt_create(hostp, CACHEFSDPROG, CACHEFSDVERS, "local");
	if (clnt == NULL) {
		pr_err(gettext("cachefsd is not running"));
		return;
	}

	/* give it a chance to complete */
	tval.tv_sec = 60 * 60 * 24;
	tval.tv_usec = 0;
	clnt_control(clnt, CLSET_TIMEOUT, (char *)&tval);

	/* perform the operation */
	args.cda_mntpt = namep;
	args.cda_disconnect = disconnect;
	retval = cachefsd_disconnection_1(&args, &ret, clnt);
	if (retval != RPC_SUCCESS) {
		clnt_perror(clnt, gettext("cachefsd is not responding"));
		clnt_destroy(clnt);
		return;
	}

	/* check for error from daemon */
	if (ret != 0) {
		if (disconnect) {
			switch (ret) {
			default:
				msgp = "unknown error";
				break;
			case 1:
				msgp = "not mounted disconnectable";
				break;
			case 2:
				msgp = "already disconnected";
				break;
			case 3:
				msgp = "not a cached file system";
				break;
			}
			pr_err(gettext("Could not disconnect %s: %s"),
			    namep, msgp);
		} else {
			switch (ret) {
			default:
				msgp = "unknown error";
				break;
			case 1:
				msgp = "already connected";
				break;
			case 2:
				msgp = "not simulated disconnection";
				break;
			case 3:
				msgp = "not a cached file system";
				break;
			}
			pr_err(gettext("Could not reconnect %s: %s"),
			    namep, msgp);
		}
	}

	ret = 0;

	clnt_destroy(clnt);
}
