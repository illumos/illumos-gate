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

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/*	    All Rights Reserved */

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *
 *			fsck.c
 *
 * Cachefs fsck program.
 */

#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdarg.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <wait.h>
#include <ctype.h>
#include <fcntl.h>
#include <ftw.h>
#include <dirent.h>
#include <search.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/mount.h>
#include <sys/mntent.h>
#include <sys/mnttab.h>
#include <sys/mman.h>
#include <sys/fs/cachefs_fs.h>
#include <syslog.h>
#include "../common/subr.h"
#include "res.h"

char *cfs_opts[] = {
#define		CFSOPT_PREEN		0
		"preen",
#define		CFSOPT_NOCLEAN		1
		"noclean",
#define		CFSOPT_VERBOSE		2
		"verbose",
#define		CFSOPT_NONOCLEAN	3
		"nonoclean",

		NULL
};

extern int dlog_ck(char *dir_path, ino64_t *maxlocalfilenop);

/* forward references */
void usage(char *msgp);
void pr_err(char *fmt, ...);
int cfs_check(char *cachedirp, int noclean, int mflag, int verbose,
    int nonoclean);
int cache_label_file(char *cachedirp, struct cache_label *clabelp);
int cache_permissions(char *cachedirp);
int cache_check_dir(char *cachedirp, char *namep);
int process_fsdir(char *cachedirp, char *namep, res *resp, int verbose);
int process_fsinfo(char *namep, ino64_t maxlocalfileno,
    cachefs_fsinfo_t *fsinfop, int verbose);
int process_fsgroup(char *dirp, char *namep, res *resp, ino64_t base,
    int fgsize, ino64_t fsid, int local, int verbose);
int tree_remove(const char *namep, const struct stat64 *statp, int type,
    struct FTW *ftwp);
int cache_upgrade(char *cachedirp, int lockid);
int file_remove(const char *namep, const struct stat64 *statp, int verbose);
void cache_backmnt_cleanup(char *cachedirp, char *backmnt_namep);

#define	FLAGS_FTW (FTW_PHYS | FTW_MOUNT | FTW_DEPTH)

static int S_verbose = 0;
static char S_lostfound[MAXPATHLEN];
static int S_move_lostfound = 0;

/*
 *
 *			main
 *
 * Description:
 *	Main routine for the cachefs fsck program.
 * Arguments:
 *	argc	number of command line arguments
 *	argv	list of command line arguments
 * Returns:
 *	Returns:
 *		 0	file system is okay and does not need checking
 *		 1	problem unrelated to the file system
 *		32	file system is unmounted and needs checking  (fsck
 *			-m only)
 *		33	file system is already mounted
 *		34	cannot stat device
 *		36	uncorrectable errors detected - terminate normally
 *		37	a signal was caught during processing
 *		39	uncorrectable errors detected - terminate  immediately
 *		40	for root mounted fs, same as 0
 * Preconditions:
 */

int
main(int argc, char **argv)
{
	int xx;
	int c;
	char *optionp;
	char *valuep;
	int mflag;
	int noclean;
	char *cachedirp;
	int lockid;
	int verbose;
	int nonoclean;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	/* verify root running command */
	if (getuid() != 0) {
		fprintf(stderr, gettext(
			"fsck -F cachefs: must be run by root\n"));
		return (1);
	}

	/* process command line options */
	optionp = NULL;
	mflag = 0;
	noclean = 0;
	verbose = 0;
	nonoclean = 0;
	while ((c = getopt(argc, argv, "mnNo:yY")) != EOF) {
		switch (c) {
		case 'm':	/* check but do not repair */
			mflag = 1;
			break;

		case 'n':	/* answer no to questions */
		case 'N':
			/* ignored */
			break;

		case 'o':
			optionp = optarg;
			while (*optionp) {
				xx = getsubopt(&optionp, cfs_opts, &valuep);
				switch (xx) {
				case CFSOPT_PREEN:
					/* preen is the default mode */
					break;
				case CFSOPT_NOCLEAN:
					noclean = 1;
					break;
				case CFSOPT_VERBOSE:
					verbose++;
					S_verbose++;
					break;
				case CFSOPT_NONOCLEAN:
					nonoclean = 1;
					break;
				default:
				case -1:
					pr_err(gettext("unknown option %s"),
					    valuep);
					return (1);
				}
			}
			break;

		case 'y':	/* answer yes to questions */
		case 'Y':
			/* ignored, this is the default */
			break;

		default:
			usage("invalid option");
			return (1);
		}
	}

	/* verify fsck device is specified */
	if (argc - optind < 1) {
		usage(gettext("must specify cache directory"));
		return (1);
	}

	/* save cache directory */
	cachedirp = argv[argc - 1];

	/* ensure cache directory exists */
	if (access(cachedirp, F_OK) != 0) {
		pr_err(gettext("Cache directory %s does not exist."),
		    cachedirp);
		return (39);
	}

	/* lock the cache directory non-shared */
	lockid = cachefs_dir_lock(cachedirp, 0);
	if (lockid == -1) {
		/* exit if could not get the lock */
		return (1);
	}

	/* is the cache directory in use */
	if (cachefs_inuse(cachedirp)) {
		if (noclean) {
			pr_err(gettext("Cache directory %s is in use."),
			    cachedirp);
			xx = 33;
		} else {
			/* assume if in use that it is clean */
			xx = 0;
		}
		cachefs_dir_unlock(lockid);
		return (xx);
	}

	xx = cache_upgrade(cachedirp, lockid);
	if (xx != 0) {
		/* check the file system */
		xx = cfs_check(cachedirp, noclean, mflag, verbose, nonoclean);
	}

	/* unlock the cache directory */
	cachefs_dir_unlock(lockid);

	/* inform if files moved to lost+found */
	if (S_move_lostfound) {
		pr_err(gettext("Files recovered to %s"), S_lostfound);
	}

	/* return the status of the file system checking */
	return (xx);
}

/*
 *
 *			usage
 *
 * Description:
 *	Prints a short usage message.
 * Arguments:
 *	msgp	message to include with the usage message
 * Returns:
 * Preconditions:
 */

void
usage(char *msgp)
{
	if (msgp) {
		pr_err("%s", msgp);
	}

	(void) fprintf(stderr,
	    gettext("Usage: fsck -F cachefs [ -o specific_options ] [ -m ] "
	    "cachedir\n"));
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
	(void) fprintf(stderr, gettext("fsck -F cachefs: "));
	(void) vfprintf(stderr, fmt, ap);
	(void) fprintf(stderr, "\n");
	va_end(ap);
}

/*
 *
 *			cache_upgrade
 *
 * Description:
 *
 *	See if the current cache is out of date.  If it is, do
 *	whatever magic is necessary to upgrade it.  All such magic
 *	should be encapsulated here!
 *
 * Arguments:
 *
 *	cachedirp	name of the cache directory to check
 *
 * Returns:
 *	Returns:
 *		 0	cache was upgraded and shouldn't be checked
 *		 1	problem unrelated to the file system
 *		36	uncorrectable errors detected - terminate normally
 *		39	uncorrectable errors detected - terminate  immediately
 *		50	cache was already up-to-date (maybe we should fsck it)
 *		51	cache was upgraded (but you should do fsck)
 * Preconditions:
 *	precond(cachedirp)
 */

int
cache_upgrade(char *cachedirp, int lockid)
{
#ifdef CFSRLDEBUG
	static int canupgrade[] = {1, 2, 3, 103, 104, 105, 106, 107,
	    4, 5, 108, 6, 7, 8, 0};
#else /* CFSRLDEBUG */
	static int canupgrade[] = {1, 2, 3, 103, 104, 105, 106, 107,
	    4, 108, 5, 109, 110, 6, 111, 0};
#endif /* CFSRLDEBUG */
	char labelpath[MAXPATHLEN];
	struct cache_label clabel;
	int i;

	if (((int)strlen(cachedirp) + (int)strlen(CACHELABEL_NAME) + 2)
	    >= MAXPATHLEN)
		return (1);

	(void) sprintf(labelpath, "%s/%s", cachedirp, CACHELABEL_NAME);

	if (cachefs_label_file_get(labelpath, &clabel) != 0)
		return (1);

	/* nothing to do if we're current */
	if (clabel.cl_cfsversion == CFSVERSION)
		return (50);

	/* see if it's an old version that we know how to upgrade */
	for (i = 0; canupgrade[i] != 0; i++)
		if (clabel.cl_cfsversion == canupgrade[i])
			break;
	if (canupgrade[i] == 0)
		return (36);

	syslog(LOG_USER | LOG_INFO,
	    gettext("fsck -F cachefs: Recreating cache %s"), cachedirp);

	/* currently, to `upgrade' we delete the old cache */
	if (cachefs_delete_all_cache(cachedirp) != 0)
		return (36);

	/* do any magic necessary to convert the old label to the new one */
	clabel.cl_cfsversion = CFSVERSION;

	/* create the new cache! */
	if (cachefs_create_cache(cachedirp, NULL, &clabel) != 0)
		return (36);

	return (0);
}

/*
 *
 *			cfs_check
 *
 * Description:
 *	This routine performs the actual checking of the cache
 *	file system.
 *	The file system must be inactive when this routine is called.
 * Arguments:
 *	cachedirp	name of the cache directory to check
 *	noclean		1 means ignore clean flag
 *	mflag		1 means no fixes, only check if mountable
 *	verbose		indicate level of verbosity for diagnostics
 *	nonoclean	1 means honor clean flag; don't by default
 * Returns:
 *	Returns:
 *		 0	file system is okay and does not need checking
 *		 1	problem unrelated to the file system
 *		32	file system is unmounted and needs checking
 *		33	file system is already mounted
 *		34	cannot stat device
 *		36	uncorrectable errors detected - terminate normally
 *		37	a signal was caught during processing
 *		39	uncorrectable errors detected - terminate  immediately
 *		40	for root mounted fs, same as 0, XXX
 * Preconditions:
 *	precond(cachedirp)
 */

int
cfs_check(char *cachedirp, int noclean, int mflag, int verbose, int nonoclean)
{
	DIR *dp;
	struct dirent64 *dep;
	char buf[MAXPATHLEN];
	struct stat64 statinfo;
	int xx;
	char *namep;
	res *resp;
	struct cache_label clabel;

	/* if checking the clean flag is sufficient */
	if ((noclean == 0) && (nonoclean || mflag)) {
		/* if the clean flag is set */
		if (cachefs_clean_flag_test(cachedirp)) {
			if (verbose) {
				pr_err(gettext("Cache %s is clean"), cachedirp);
			}
			return (0);
		}
	}

	/* if mflag specified then go no farther */
	if (mflag)
		return (32);

	/* check the cache label file for correctness */
	xx = cache_label_file(cachedirp, &clabel);
	if (xx)
		return (xx);

	/* make sure the kernel lock file exists */
	sprintf(buf, "%s/%s", cachedirp, CACHEFS_LOCK_FILE);
	xx = open(buf, O_RDWR | O_CREAT, 0700);
	if (xx == -1) {
		pr_err(gettext("Cannot create lock file %s"), buf);
		return (39);
	}
	close(xx);

	/* fix permissions on the cache directory */
	xx = cache_permissions(cachedirp);
	if (xx)
		return (xx);

	/* make the back file system mount directory if necessary */
	xx = cache_check_dir(cachedirp, BACKMNT_NAME);
	if (xx)
		return (xx);

	/* clean out junk in the back file system mount directory */
	cache_backmnt_cleanup(cachedirp, BACKMNT_NAME);

	/* make the lost+found directory if necessary */
	xx = cache_check_dir(cachedirp, CACHEFS_LOSTFOUND_NAME);
	if (xx)
		return (xx);

	/* construct the path to the lost and found directory for file_remove */
	sprintf(S_lostfound, "%s/%s", cachedirp, CACHEFS_LOSTFOUND_NAME);

	/* construct the path name of the resource file */
	namep = RESOURCE_NAME;
	xx = strlen(cachedirp) + strlen(namep) + 3;
	if (xx >= MAXPATHLEN) {
		pr_err(gettext("Path name too long %s/%s"),
		    cachedirp, namep);
		return (39);
	}
	sprintf(buf, "%s/%s", cachedirp, namep);

	/* make a res object to operate on the resource file */
	resp = res_create(buf, clabel.cl_maxinodes, verbose);
	if (resp == NULL) {
		pr_err(gettext("Could not process resource file %s: %s"),
		    buf, strerror(errno));
		return (39);
	}

	/* open the cache directory */
	if ((dp = opendir(cachedirp)) == NULL) {
		pr_err(gettext("Cannot open directory %s: %s"), cachedirp,
		    strerror(errno));
		res_destroy(resp);
		return (39);
	}

	/* mark all directories */
	while ((dep = readdir64(dp)) != NULL) {
		/* ignore . and .. */
		if ((strcmp(dep->d_name, ".") == 0) ||
				(strcmp(dep->d_name, "..") == 0))
			continue;

		/* check path length */
		xx = strlen(cachedirp) + strlen(dep->d_name) + 3;
		if (xx >= MAXPATHLEN) {
			pr_err(gettext("Path name too long %s/%s"),
			    cachedirp, dep->d_name);
			closedir(dp);
			res_destroy(resp);
			return (39);
		}

		/* stat the file */
		sprintf(buf, "%s/%s", cachedirp, dep->d_name);
		xx = lstat64(buf, &statinfo);
		if (xx == -1) {
			if (errno != ENOENT) {
				pr_err(gettext("Cannot stat %s: %s"), cachedirp,
				    strerror(errno));
				closedir(dp);
				res_destroy(resp);
				return (39);
			}
			continue;
		}

		/* if a directory */
		if (S_ISDIR(statinfo.st_mode)) {
			xx = chmod(buf, 0700);
			if (xx == -1) {
				pr_err(gettext("Cannot chmod %s: %s"), buf,
				    strerror(errno));
				closedir(dp);
				res_destroy(resp);
				return (39);
			}
		}
	}

	/* process files in the cache directory */
	rewinddir(dp);
	while ((dep = readdir64(dp)) != NULL) {
		/* ignore . and .. */
		if ((strcmp(dep->d_name, ".") == 0) ||
				(strcmp(dep->d_name, "..") == 0))
			continue;

		/* stat the file */
		sprintf(buf, "%s/%s", cachedirp, dep->d_name);
		xx = lstat64(buf, &statinfo);
		if (xx == -1) {
			if (errno != ENOENT) {
				pr_err(gettext("Cannot stat %s: %s"), cachedirp,
				    strerror(errno));
				closedir(dp);
				res_destroy(resp);
				return (39);
			}
			continue;
		}

		/* ignore directories */
		if (S_ISDIR(statinfo.st_mode))
			continue;

		/* if not a link */
		if (!S_ISLNK(statinfo.st_mode)) {
			/*
			 * XXX make sure a valid file
			 * Update file and block counts for this file.
			 * This file will be <2GB.
			 */
			res_addfile(resp, (long)statinfo.st_size);
			continue;
		}

		/* process the file system cache directory */
		xx = process_fsdir(cachedirp, dep->d_name, resp, verbose);
		if (xx) {
			closedir(dp);
			res_destroy(resp);
			return (xx);
		}
	}

	/* look for directories that do not belong */
	rewinddir(dp);
	while ((dep = readdir64(dp)) != NULL) {
		/* ignore . and .. */
		if ((strcmp(dep->d_name, ".") == 0) ||
				(strcmp(dep->d_name, "..") == 0))
			continue;

		/* stat the file */
		sprintf(buf, "%s/%s", cachedirp, dep->d_name);
		xx = lstat64(buf, &statinfo);
		if (xx == -1) {
			if (errno != ENOENT) {
				pr_err(gettext("Cannot stat %s: %s"), cachedirp,
				    strerror(errno));
				closedir(dp);
				res_destroy(resp);
				return (39);
			}
			continue;
		}

		/* XXX should we unlink extraneous regular files? */

		/* ignore all but directories */
		if (!S_ISDIR(statinfo.st_mode))
			continue;

		/* ignore directories we have checked */
		if ((statinfo.st_mode & S_IAMB) != 0700)
			continue;

		/* ignore the mount directory */
		if (strcmp(dep->d_name, BACKMNT_NAME) == 0)
			continue;

		/* ignore the lost+found directory */
		if (strcmp(dep->d_name, CACHEFS_LOSTFOUND_NAME) == 0)
			continue;

		/* remove the directory */
		xx = nftw64(buf, tree_remove, 3, FLAGS_FTW);
		if (xx != 0) {
			pr_err(gettext("Error walking tree %s."), namep);
			closedir(dp);
			res_destroy(resp);
			return (39);
		}

		if (verbose)
			pr_err(gettext("Directory removed: %s"), buf);
	}

	/* close the directory */
	closedir(dp);

	/* add one file and one block for the cache directory itself */
	res_addfile(resp, 1);

	/* finish off the resource file processing */
	xx = res_done(resp);
	if (xx == -1) {
		pr_err(gettext("Could not finish resource file %s: %s"),
		    buf, strerror(errno));
		return (39);
	}
	res_destroy(resp);

	/* return success */
	return (0);
}

/*
 *
 *			cache_label_file
 *
 * Description:
 *	This routine performs the checking and fixing up of the
 *	cache label file.
 * Arguments:
 *	cachedirp	name of the cache directory to check
 *	clabelp		cache label contents put here if not NULL
 * Returns:
 *		 0	file system is okay and does not need checking
 *		 1	problem unrelated to the file system
 *		32	file system is unmounted and needs checking
 *		33	file system is already mounted
 *		34	cannot stat device
 *		36	uncorrectable errors detected - terminate normally
 *		37	a signal was caught during processing
 *		39	uncorrectable errors detected - terminate  immediately
 * Preconditions:
 *	precond(cachedirp)
 */

int
cache_label_file(char *cachedirp, struct cache_label *clabelp)
{
	int xx;
	char buf1[MAXPATHLEN];
	char buf2[MAXPATHLEN];
	char *namep;
	struct cache_label clabel1, clabel2;

	namep = CACHELABEL_NAME;

	/* see if path name is too long */
	xx = strlen(cachedirp) + strlen(namep) + 10;
	if (xx >= MAXPATHLEN) {
		pr_err(gettext("Cache directory name %s is too long"),
		    cachedirp);
		return (39);
	}

	/* make a path to the cache label file and its backup copy */
	sprintf(buf1, "%s/%s", cachedirp, namep);
	sprintf(buf2, "%s/%s.dup", cachedirp, namep);

	/* get the contents of the cache label file */
	xx = cachefs_label_file_get(buf1, &clabel1);
	if (xx == -1) {
		/* get the backup cache label file contents */
		xx = cachefs_label_file_get(buf2, &clabel2);
		if (xx == -1) {
			pr_err(gettext("Run `cfsadmin -d all %s'\n"
			    "and then run\n"
			    "`cfsadmin -c %s'\n"), cachedirp, cachedirp);
			return (39);
		}

		/* write the cache label file */
		xx = cachefs_label_file_put(buf1, &clabel2);
		if (xx == -1) {
			pr_err(gettext("Run `cfsadmin -d all %s'\n"
			    "and then run\n"
			    "`cfsadmin -c %s'\n"), cachedirp, cachedirp);
			return (39);
		}
		pr_err(gettext("Cache label file %s repaired."), buf1);

		/* copy out the contents to the caller */
		if (clabelp)
			*clabelp = clabel2;

		/* return success */
		return (0);
	}

	/* get the contents of the backup cache label file */
	xx = cachefs_label_file_get(buf2, &clabel2);
	if (xx == -1) {
		/* write the backup cache label file */
		xx = cachefs_label_file_put(buf2, &clabel1);
		if (xx == -1) {
			return (39);
		}
		pr_err(gettext("Cache label file %s repaired."), buf2);
	}

	/* copy out the contents to the caller */
	if (clabelp)
		*clabelp = clabel1;

	/* return success */
	return (0);
}

/*
 *
 *			cache_permissions
 *
 * Description:
 *	Checks the permissions on the cache directory and fixes
 *	them if necessary.
 * Arguments:
 *	cachedirp	name of the cache directory to check
 * Returns:
 *		 0	file system is okay and does not need checking
 *		 1	problem unrelated to the file system
 *		32	file system is unmounted and needs checking
 *		33	file system is already mounted
 *		34	cannot stat device
 *		36	uncorrectable errors detected - terminate normally
 *		37	a signal was caught during processing
 *		39	uncorrectable errors detected - terminate  immediately
 * Preconditions:
 *	precond(cachedirp)
 */

int
cache_permissions(char *cachedirp)
{
	int xx;
	struct stat64 statinfo;

	/* get info about the cache directory */
	xx = lstat64(cachedirp, &statinfo);
	if (xx == -1) {
		pr_err(gettext("Could not stat %s: %s"), cachedirp,
		    strerror(errno));
		return (34);
	}

	/* check the mode bits */
	if ((statinfo.st_mode & S_IAMB) != 0) {

		/* fix the mode bits */
		xx = chmod(cachedirp, 0);
		if (xx == -1) {
			pr_err(gettext("Could not set modes bits on "
			    "cache directory %s: %s"),
			    cachedirp, strerror(errno));
			return (36);
		}
		pr_err(gettext("Mode bits reset on cache directory %s"),
		    cachedirp);
	}

	/* return success */
	return (0);
}

/*
 *
 *			cache_check_dir
 *
 * Description:
 *	Checks for the existance of the directory
 *	and creates it if necessary.
 * Arguments:
 *	cachedirp	name of the cache directory containing the dir
 *	namep		name of dir
 * Returns:
 *		 0	file system is okay and does not need checking
 *		 1	problem unrelated to the file system
 *		32	file system is unmounted and needs checking
 *		33	file system is already mounted
 *		34	cannot stat device
 *		36	uncorrectable errors detected - terminate normally
 *		37	a signal was caught during processing
 *		39	uncorrectable errors detected - terminate  immediately
 * Preconditions:
 *	precond(cachedirp)
 *	precond(dirp)
 */

int
cache_check_dir(char *cachedirp, char *namep)
{
	int xx;
	char buf[MAXPATHLEN];
	struct stat64 statinfo;

	/* see if path name is too long */
	xx = strlen(cachedirp) + strlen(namep) + 3;
	if (xx >= MAXPATHLEN) {
		pr_err(gettext("Cache directory name %s is too long"),
		    cachedirp);
		return (39);
	}

	/* make the pathname of the directory */
	sprintf(buf, "%s/%s", cachedirp, namep);

	/* get info on the directory */
	xx = lstat64(buf, &statinfo);
	if (xx == -1) {
		/* if an error other than it does not exist */
		if (errno != ENOENT) {
			pr_err(gettext("Error on lstat(2) of %s: %s"),
			    buf, strerror(errno));
			return (39);
		}

		/* make the directory */
		xx = mkdir(buf, 0);
		if (xx == -1) {
			pr_err(gettext("Could not create directory %s"),
			    buf);
			return (39);
		}
		pr_err(gettext("Created directory %s"), buf);
	}

	/* else see if really a directory */
	else if (!S_ISDIR(statinfo.st_mode)) {
		/* get rid of the file */
		xx = unlink(buf);
		if (xx == -1) {
			pr_err(gettext("Cannot remove %s: %s"), buf,
			    strerror(errno));
			return (39);
		}

		/* make the directory */
		xx = mkdir(buf, 0);
		if (xx == -1) {
			pr_err(gettext("Could not create directory %s"),
			    buf);
			return (39);
		}
		pr_err(gettext("Created directory %s"), buf);
	}

	/* return success */
	return (0);
}

/*
 *
 *			process_fsdir
 *
 * Description:
 *	Performs the necessary checking and repair on the
 *	specified file system cache directory.
 *	Calls res_addfile and res_addident as appropriate.
 * Arguments:
 *	cachedirp	name of cache directory
 *	namep		name of link file for the file system cache
 *	resp		res object for res_addfile and res_addident calls
 *	verbose		indicate level of verbosity for diagnostics
 * Returns:
 *		 0	file system is okay and does not need checking
 *		 1	problem unrelated to the file system
 *		32	file system is unmounted and needs checking
 *		33	file system is already mounted
 *		34	cannot stat device
 *		36	uncorrectable errors detected - terminate normally
 *		37	a signal was caught during processing
 *		39	uncorrectable errors detected - terminate  immediately
 * Preconditions:
 *	precond(cachedirp)
 *	precond(namep && is a sym link)
 *	precond(resp)
 */

int
process_fsdir(char *cachedirp, char *namep, res *resp, int verbose)
{
	DIR *dp;
	struct dirent64 *dep;
	char linkpath[MAXPATHLEN];
	char dirpath[MAXPATHLEN];
	char attrpath[MAXPATHLEN];
	char buf[MAXPATHLEN];
	int xx;
	struct stat64 statinfo;
	char *atp = ATTRCACHE_NAME;
	int fd;
	ino64_t base;
	int local;
	char *strp;
	ino64_t fsid;
	int error = 0;
	int hashsize = 0;
	ENTRY hitem;
	ino64_t maxlocalfileno;
	cachefs_fsinfo_t fsinfo;
	time32_t btime;

	/* construct the path to the sym link */
	xx = strlen(cachedirp) + strlen(namep) + 3;
	if (xx >= MAXPATHLEN) {
		pr_err(gettext("Pathname too long %s/%s"), cachedirp, namep);
		error = 39;
		goto out;
	}
	sprintf(linkpath, "%s/%s", cachedirp, namep);

	/* read the contents of the link */
	xx = readlink(linkpath, buf, sizeof (buf));
	if (xx == -1) {
		pr_err(gettext("Unable to read link %s: %s"), linkpath,
		    strerror(errno));
		error = 39;
		goto out;
	}
	buf[xx] = '\0';

	/* do a one time check on lengths of files */
	xx = strlen(cachedirp) + strlen(buf) + 20 + 20;
	if (xx >= MAXPATHLEN) {
		pr_err(gettext("Pathname too long %s/%s"), cachedirp, buf);
		error = 39;
		goto out;
	}

	/* construct the path to the directory */
	sprintf(dirpath, "%s/%s", cachedirp, buf);

	/* stat the directory */
	xx = lstat64(dirpath, &statinfo);
	if ((xx == -1) || (strtoull(buf, NULL, 16) != statinfo.st_ino)) {
		if ((xx == -1) && (errno != ENOENT)) {
			pr_err(gettext("Could not stat %s: %s"), dirpath,
			    strerror(errno));
			error = 39;
		} else
			error = -1;
		goto out;
	}
	fsid = statinfo.st_ino;

	/*
	 * Check for a disconnect log(dlog) file and verify it.
	 */
	xx = dlog_ck(dirpath, &maxlocalfileno);
	if (xx) {
		error = -1;
		goto out;
	}

	/* process the fsinfo file */
	sprintf(buf, "%s/%s", dirpath, CACHEFS_FSINFO);
	xx = process_fsinfo(buf, maxlocalfileno, &fsinfo, verbose);
	if (xx) {
		error = -1;
		pr_err(gettext("Cannot update fsinfo file %s"), buf);
		goto out;
	}

	/* create the unmount file in the cachedir */
	sprintf(buf, "%s/%s", dirpath, CACHEFS_UNMNT_FILE);
	/* this file will be < 2GB */
	fd = open(buf, O_CREAT | O_RDWR, 0666);
	if (fd == -1) {
		pr_err(gettext("Cannot create unmnt file %s: %s"), buf,
		    strerror(errno));
		error = -1;
		goto out;
	}
	btime = get_boottime();
	if (write(fd, &btime, sizeof (btime)) == -1) {
		pr_err(gettext("Cannot write cachedir unmnt file %s: %s"), buf,
		    strerror(errno));
		error = -1;
		goto out;
	}
	close(fd);

	/* create the unmount file */
	sprintf(buf, "%s/%s", dirpath, CACHEFS_UNMNT_FILE);
	/* this file will be < 2GB */
	fd = open(buf, O_CREAT | O_RDWR, 0666);
	if (fd == -1) {
		pr_err(gettext("Cannot create unmnt file %s: %s"), buf,
		    strerror(errno));
		error = -1;
		goto out;
	}
	close(fd);

	/* construct the name to the attrcache directory */
	sprintf(attrpath, "%s/%s", dirpath, atp);

	/* open the attrcache directory */
	if ((dp = opendir(attrpath)) == NULL) {
		pr_err(gettext("Cannot open directory %s: %s"), attrpath,
		    strerror(errno));
		error = -1;
		goto out;
	}

	/* make one pass, counting how big to make the hash table */
	while (readdir64(dp) != NULL)
		++hashsize;
	if (hcreate(hashsize + 1000) == 0) {
		pr_err(gettext("Cannot allocate heap space."));
		(void) closedir(dp);
		hashsize = 0;
		error = 39;
		goto out;
	}
	rewinddir(dp);

	/* loop reading the contents of the directory */
	while ((dep = readdir64(dp)) != NULL) {
		/* ignore . and .. */
		if ((strcmp(dep->d_name, ".") == 0) ||
		    (strcmp(dep->d_name, "..") == 0))
			continue;

		/* check for a reasonable name */
		xx = strlen(dep->d_name);
		if ((xx != 16) && (xx != 17)) {
			/* bad file */
			pr_err(gettext("Unknown file %s/%s"),
				attrpath, dep->d_name);
			closedir(dp);
			error = 39;
			goto out;
		}

		/* derive the base number from the file name */
		if (*(dep->d_name) == 'L') {
			local = 1;
			base = strtoull(dep->d_name + 1, &strp, 16);
		} else {
			local = 0;
			base = strtoull(dep->d_name, &strp, 16);
		}
		if (*strp != '\0') {
			/* bad file */
			pr_err(gettext("Unknown file %s/%s"),
				attrpath, dep->d_name);
			closedir(dp);
			error = 39;
			goto out;
		}

		/* process the file group */
		error = process_fsgroup(dirpath, dep->d_name, resp,
			base, fsinfo.fi_fgsize, fsid, local, verbose);
		if (error) {
			closedir(dp);
			goto out;
		}
	}
	closedir(dp);

	/* open the fscache directory */
	if ((dp = opendir(dirpath)) == NULL) {
		pr_err(gettext("Cannot open directory %s: %s"), dirpath,
		    strerror(errno));
		error = 39;
		goto out;
	}

	/* loop reading the contents of the directory */
	while ((dep = readdir64(dp)) != NULL) {
		/* ignore . and .. */
		if ((strcmp(dep->d_name, ".") == 0) ||
		    (strcmp(dep->d_name, "..") == 0))
			continue;

		/* ignore cachefs special files */
		xx = strncmp(dep->d_name, CACHEFS_PREFIX, CACHEFS_PREFIX_LEN);
		if (xx == 0)
			continue;

		hitem.key = dep->d_name;
		hitem.data = NULL;
		if (hsearch(hitem, FIND) == NULL) {
			sprintf(buf, "%s/%s", dirpath, dep->d_name);
			if (verbose) {
				printf("Unreferenced dir %s\n", buf);
			}
			xx = nftw64(buf, tree_remove, 3, FLAGS_FTW);
			if (xx != 0) {
				pr_err(gettext("Could not remove %s"), buf);
				error = 39;
				closedir(dp);
				goto out;
			}
		}
	}
	closedir(dp);

	/* add the info file to the resource */
	res_addfile(resp, 1);

	/* add the directory to the resources */
	res_addfile(resp, 1);

	/* add the sym link to the resources */
	res_addfile(resp, 1);

	/* change the mode on the directory to indicate we visited it */
	xx = chmod(dirpath, 0777);
	if (xx == -1) {
		pr_err(gettext("Cannot chmod %s: %s"), dirpath,
		    strerror(errno));
		error = 39;
		goto out;
	}

out:
	/* free up the heap allocated by the hash functions */
	if (hashsize != 0)
		hdestroy();

	if (error == -1) {
		/* remove the sym link */
		xx = unlink(linkpath);
		if (xx == -1) {
			pr_err(gettext("Unable to remove %s: %s"), linkpath,
			    strerror(errno));
			error = 39;
		} else {
			error = 0;
		}
	}

	return (error);
}

/*
 * Processes and fixes up the fsinfo file.
 */
int
process_fsinfo(char *namep, ino64_t maxlocalfileno, cachefs_fsinfo_t *fsinfop,
    int verbose)
{
	int fd;
	int error;
	cachefs_fsinfo_t fsinfo;
	int xx;

	/* open the info file; this file will be <2GB */
	fd = open(namep, O_RDWR);
	if (fd == -1) {
		error = errno;
		if (verbose)
			pr_err(gettext("Could not open %s: %s"),
			    namep, strerror(errno));
		if (error != ENOENT)
			return (-1);

		/* try to create the info file */
		fd = open(namep, O_RDWR | O_CREAT, 0666);
		if (fd == -1) {
			if (verbose)
				pr_err(gettext("Could not create %s: %s"),
				    namep, strerror(errno));
			return (-1);
		}

	}

	/* read the contents of the info file */
	xx = read(fd, &fsinfo, sizeof (fsinfo));
	if (xx != sizeof (fsinfo)) {
		memset(&fsinfo, 0, sizeof (fsinfo));
	}

	/* fix up the fields as necessary */
	if (fsinfo.fi_popsize < DEF_POP_SIZE)
		fsinfo.fi_popsize = DEF_POP_SIZE;
	if (fsinfo.fi_fgsize < DEF_FILEGRP_SIZE)
		fsinfo.fi_fgsize = DEF_FILEGRP_SIZE;
	if (fsinfo.fi_localfileno < maxlocalfileno)
		fsinfo.fi_localfileno = maxlocalfileno;

	/* write back the info to the file */
	if (lseek(fd, 0, SEEK_SET) == -1) {
		if (verbose)
			pr_err(gettext("Could not lseek %s: %s"),
			    namep, strerror(errno));
		close(fd);
		return (-1);
	}
	xx = write(fd, &fsinfo, sizeof (fsinfo));
	if (xx != sizeof (fsinfo)) {
		if (verbose)
			pr_err(gettext("Could not write %s: %s"),
			    namep, strerror(errno));
		close(fd);
		return (-1);
	}

	if (fsync(fd) == -1) {
		pr_err(gettext("Could not sync %s: %s"),
		    namep, strerror(errno));
		(void) close(fd);
		return (-1);
	}
	(void) close(fd);
	*fsinfop = fsinfo;
	return (0);
}

/*
 *
 *			process_fsgroup
 *
 * Description:
 *	Performs the necessary checking and repair on the
 *	specified file group directory.
 *	Calls res_addfile and res_addident as appropriate.
 * Arguments:
 *	dirpath	pathname to fscache directory
 *	namep	name of fsgroup
 *	resp	res object for res_addfile and res_addident calls
 *	base	base offset for file numbers in this directory
 *	fgsize	size of the file groups
 *	fsid	file system id
 *	local	1 if fsgroup dir is a local dir
 *	verbose		indicate level of verbosity for diagnostics
 * Returns:
 *		 0	file system is okay and does not need checking
 *		 1	problem unrelated to the file system
 *		32	file system is unmounted and needs checking
 *		33	file system is already mounted
 *		34	cannot stat device
 *		36	uncorrectable errors detected - terminate normally
 *		37	a signal was caught during processing
 *		39	uncorrectable errors detected - terminate  immediately
 * Preconditions:
 *	precond(dirp)
 *	precond(namep)
 *	precond(resp)
 *	precond(fgsize > 0)
 */

int
process_fsgroup(char *dirp, char *namep, res *resp, ino64_t base, int fgsize,
    ino64_t fsid, int local, int verbose)
{
	DIR *dp;
	struct dirent64 *dep;
	char buf[MAXPATHLEN];
	char attrfile[MAXPATHLEN];
	char attrdir[MAXPATHLEN];
	int xx;
	struct stat64 statinfo;
	char *atp = ATTRCACHE_NAME;
	void *addrp = MAP_FAILED;
	struct attrcache_header *ahp;
	struct attrcache_index *startp = NULL;
	struct attrcache_index *aip;
	uchar_t *bitp;
	int offlen;
	int bitlen;
	int fd;
	int offentry;
	int size;
	struct cachefs_metadata *metap;
	int index;
	char *strp;
	uint_t offset;
	int error = 0;
	ENTRY hitem;
	int nffs;
	int rlno;
	rl_entry_t ent;
	enum cachefs_rl_type which;

	/* construct the name to the attribute file and front file dir */
	sprintf(attrfile, "%s/%s/%s", dirp, atp, namep);
	sprintf(attrdir, "%s/%s", dirp, namep);

	/* get the size of the attribute file */
	xx = lstat64(attrfile, &statinfo);
	if (xx == -1) {
		pr_err(gettext("Could not stat %s: %s"), attrfile,
		    strerror(errno));
		error = 39;
		goto out;
	}

	offlen = sizeof (struct attrcache_index) * fgsize;
	bitlen = (sizeof (uchar_t) * fgsize + 7) / 8;
	/* attrfile will be <2GB */
	size = (int)statinfo.st_size;
	offentry = sizeof (struct attrcache_header) + offlen + bitlen;

	/* if the attribute file is the wrong size */
	if (size < offentry) {
		error = -1;
		goto out;
	}

	/* open the attribute file */
	fd = open(attrfile, O_RDWR);
	if (fd == -1) {
		pr_err(gettext("Could not open %s: %s"),
			attrfile, strerror(errno));
		error = 39;
		goto out;
	}

	/* mmap the file into our address space */
	addrp = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (addrp == MAP_FAILED) {
		pr_err(gettext("Could not map %s: %s"),
			attrfile, strerror(errno));
		close(fd);
		error = 39;
		goto out;
	}
	close(fd);

	/* set up pointers into mapped file */
	ahp = (struct attrcache_header *)addrp;
	startp = (struct attrcache_index *)(ahp + 1);
	bitp = (uchar_t *)((char *)startp + offlen);

	/* clear the bitmap */
	memset(bitp, 0, bitlen);

	/* fix number of allocated blocks value if necessary */
	xx = (size + MAXBSIZE - 1) / MAXBSIZE;
	if (xx != ahp->ach_nblks) {
		if (verbose) {
			pr_err(gettext("File %s size wrong, old %d new %d:"
				"corrected."),
				attrfile, ahp->ach_nblks, xx);
		}
		ahp->ach_nblks = xx;
	}
	ahp->ach_nffs = 0;
	nffs = 0;

	/* verify sanity of attribute file */
	ahp->ach_count = 0;
	for (index = 0; index < fgsize; index++) {

		/* get next entry to work on */
		aip = startp + index;

		/* save offset to data */
		offset = aip->ach_offset;
		aip->ach_offset = 0;

		/* if entry not in use */
		if (aip->ach_written == 0)
			continue;
		aip->ach_written = 0;

		/* if offset is out of range or invalid */
		if ((offset < offentry) ||
		    ((size - sizeof (struct cachefs_metadata)) < offset) ||
		    (offset & 3)) {
			if (verbose)
				pr_err(gettext("Offset %d invalid - index %d"),
				    offset, index);
			continue;
		}

		/* get pointer to meta data */
		metap = (struct cachefs_metadata *)((char *)addrp + offset);

		/* sanity check the meta data */
		if ((metap->md_vattr.va_nodeid != (base + (ino64_t)index)) ||
		    ((metap->md_flags & (MD_FILE | MD_POPULATED)) ==
		    MD_POPULATED) ||
		    ((metap->md_flags & MD_FILE) && (metap->md_rlno == 0)) ||
		    (metap->md_rltype < CACHEFS_RL_START) ||
		    (metap->md_rltype > CACHEFS_RL_END)) {
			if (verbose) {
				pr_err(gettext("Metadata corrupted %d"), index);
			}
			continue;
		}

		/* if there is a front file */
		if (metap->md_flags & MD_FILE) {
			/* make sure front file is still there */
			if (local)
				sprintf(buf, "%s/L%016llx", attrdir,
				    base + (ino64_t)index);
			else
				sprintf(buf, "%s/%016llx", attrdir,
				    base + (ino64_t)index);
			if (access(buf, F_OK)) {
				if (verbose) {
					pr_err(gettext("File error %s %s"),
					    buf, strerror(errno));
				}
				continue;
			}
			nffs++;

			/* make sure default ACL directory holder is there */
			if (metap->md_flags & MD_ACLDIR) {
				sprintf(buf, (local) ?
				    "%s/L%016llx.d" : "%s/%016llx.d",
				    attrdir, base + (ino64_t)index);
				if (access(buf, F_OK)) {
					if (verbose) {
						pr_err(gettext(
						    "File error %s %s"),
						    buf, strerror(errno));
					}
					continue;
				}
			}
		}

		/* if using a rl slot */
		if (metap->md_rlno) {
			/* make sure not on an unusable list */
			if ((metap->md_rltype == CACHEFS_RL_NONE) ||
			    (metap->md_rltype == CACHEFS_RL_FREE)) {
				if (verbose) {
					pr_err(gettext("Bad list %d, %d"),
					    metap->md_rltype, index);
				}
				continue;
			}

			/* move from the active to the gc list */
			if (metap->md_rltype == CACHEFS_RL_ACTIVE)
				metap->md_rltype = CACHEFS_RL_GC;

			/* move from the mf to the modified list */
			if (metap->md_rltype == CACHEFS_RL_MF)
				metap->md_rltype = CACHEFS_RL_MODIFIED;

			/* add to the resource file */
			ent.rl_attrc = 0;
			ent.rl_local = local;
			ent.rl_fsid = fsid;
			ent.rl_fileno = base + (ino64_t)index;
			ent.rl_current = metap->md_rltype;
			xx = res_addident(resp, metap->md_rlno, &ent,
			    metap->md_frontblks * MAXBSIZE,
			    (metap->md_flags & MD_FILE) ? 1 : 0);
			if (xx == -1) {
				if (verbose) {
					pr_err(gettext(
					    "File %s, bad rlno"), attrfile);
				}
				continue;
			}
			ahp->ach_nffs++;
		}

		/* mark entry as valid */
		aip->ach_written = 1;
		aip->ach_offset = offset;

		/* set bitmap for this entry */
		xx = (offset - offentry) / sizeof (struct cachefs_metadata);
		bitp[xx/8] |= 1 << (xx % 8);

		/* bump number of active entries */
		ahp->ach_count += 1;
	}

	/* loop reading the contents of the front file directory */
	dp = opendir(attrdir);
	while (dp && ((dep = readdir64(dp)) != NULL)) {
		int acldir;

		/* ignore . and .. */
		if ((strcmp(dep->d_name, ".") == 0) ||
		    (strcmp(dep->d_name, "..") == 0))
			continue;

		acldir = 0;
		xx = strlen(dep->d_name);
		/* check for valid ACL directory */
		if ((xx > 2) && (strcmp(dep->d_name + xx - 2, ".d") == 0)) {
			acldir = 1;
		} else if ((xx != 16) && (xx != 17)) {
			/*
			 * Bad file.
			 * Front file dir name is based on 64 bit inode number.
			 */
			pr_err(gettext("Unknown file %s/%s"),
				attrdir, dep->d_name);
			closedir(dp);
			error = 39;
			goto out;
		}

		sprintf(buf, "%s/%s", attrdir, dep->d_name);

		/* determine index into file group */
		if (*(dep->d_name) == 'L') {
			index = (int)(strtoull(dep->d_name + 1, &strp,
			    16) - base);
		} else {
			index = (int)(strtoull(dep->d_name, &strp, 16) - base);
		}

		/* verify a valid file */
		if (((! acldir) && (*strp != '\0')) ||
		    ((acldir) && (strcmp(strp, ".d") != 0)) ||
		    (index < 0) || (fgsize <= index) ||
		    (startp[index].ach_written == 0)) {
			/* remove the file */
			xx = file_remove(buf, NULL, verbose);
			if (xx == -1) {
				error = 39;
				goto out;
			}
			continue;
		}

		/* verify file should be there */
		aip = startp + index;
		offset = aip->ach_offset;
		metap = (struct cachefs_metadata *)((char *)addrp + offset);
		if (((metap->md_flags & MD_FILE) == 0) ||
		    ((acldir) && ((metap->md_flags & MD_ACLDIR) == 0))) {
			/* remove the file */
			if (acldir)
				xx = rmdir(buf);
			else
				xx = file_remove(buf, NULL, verbose);
			if (xx == -1) {
				error = 39;
				goto out;
			}
			continue;
		}
		if (! acldir)
			nffs--;
	}

	/* close the directory */
	if (dp)
		closedir(dp);

	/* if we did not find the correct number of front files in the dir */
	rlno = ahp->ach_rlno;
	if (nffs != 0) {
		if (verbose) {
			pr_err(gettext("Front file mismatch %d in %s"),
			    nffs, attrdir);
		}
		error = -1;
		goto out;
	}

	/* add the attrcache file to the resouce file */
	which = (ahp->ach_nffs == 0) ? CACHEFS_RL_GC : CACHEFS_RL_ATTRFILE;
	ahp->ach_rl_current = which;
	ent.rl_attrc = 1;
	ent.rl_local = local;
	ent.rl_fsid = fsid;
	ent.rl_fileno = base;
	ent.rl_current = which;
	error = res_addident(resp, rlno, &ent, size, 1);
	if (error == -1) {
		if (verbose) {
			pr_err(gettext("%s bad rlno %d\n"), attrfile, rlno);
		}
		goto out;
	} else if (ahp->ach_nffs > 0) {
		/* add the directory to the resources */
		res_addfile(resp, 1);

		/* indicate that the file group directory is okay */
		hitem.key = strdup(namep);
		hitem.data = NULL;
		if (hsearch(hitem, ENTER) == NULL) {
			pr_err(gettext("Hash table full"));
			error = 39;
			goto out;
		}
	}

out:
	if (error == -1) {
		if (startp) {
			/* clear idents we created for this attrcache file */
			for (index = 0; index < fgsize; index++) {
				aip = startp + index;
				if (aip->ach_written == 0)
					continue;
				metap = (struct cachefs_metadata *)((char *)
				    addrp + aip->ach_offset);
				if (metap->md_rlno != 0) {
					/* clear the resource file idents */
					res_clearident(resp, metap->md_rlno,
					    (metap->md_frontblks * MAXBSIZE),
					    (metap->md_flags & MD_FILE) ? 1:0);
					if (verbose) {
						pr_err(gettext("Removed %d"),
							metap->md_rlno);
					}
				}
			}
		}

		/* nuke the attrcache file */
		xx = unlink(attrfile);
		if (xx == -1) {
			pr_err(gettext("Unable to remove %s"), attrfile);
			error = 39;
		} else {
			error = 0;
			if (verbose) {
				pr_err(gettext("Removed attrcache %s"),
					attrfile);
			}
		}
	}

	if (msync(addrp, size, MS_SYNC) == -1) {
		pr_err(gettext("Unable to sync %s"), attrfile);
		error = 39;
	}

	/* unmap the attribute file */
	if (addrp != MAP_FAILED)
		munmap(addrp, size);

	return (error);
}

/*
 *
 *			tree_remove
 *
 * Description:
 *	Called via the nftw64(3c) routine, this routine removes
 *	the specified file.
 * Arguments:
 *	namep	pathname to the file
 *	statp	stat info on the file
 *	type	ftw type information
 *	ftwp	pointer to additional ftw information
 * Returns:
 *	Returns 0 for success or -1 if an error occurs.
 * Preconditions:
 *	precond(namep)
 *	precond(statp)
 *	precond(ftwp)
 */

int
tree_remove(const char *namep, const struct stat64 *statp, int type,
    struct FTW *ftwp)
{
	int xx;

	switch (type) {
	case FTW_D:
	case FTW_DP:
	case FTW_DNR:
		xx = rmdir(namep);
		if (xx != 0) {
			pr_err(gettext("Could not remove directory %s: %s"),
			    namep, strerror(errno));
			return (-1);
		}
#if 0
		pr_err(gettext("Directory %s removed."), namep);
#endif
		break;

	default:
		xx = file_remove(namep, statp, S_verbose);
#if 0
		pr_err(gettext("File %s removed."), namep);
#endif
		break;
	}

	/* return success */
	return (0);
}

/*
 *
 *			file_remove
 *
 * Description:
 *	Removes the specified file.
 *	If the file is a local file or has been modified locally
 *	then it is moved to lost+found.
 *	Should only be called for non-directory files.
 * Arguments:
 *	namep	pathname to the file
 *	statp	stat info on the file or NULL
 *	verbose	1 means be verbose about what is being removed
 * Returns:
 *	Returns 0 for success or -1 if an error occurs.
 * Preconditions:
 *	precond(namep)
 */

int
file_remove(const char *namep, const struct stat64 *statp, int verbose)
{
	int xx;
	int ii;
	struct stat64 statinfo;
	int dolf = 0;
	char newname[MAXPATHLEN * 2];
	char *strp;

	/* get stat info on the file if we were not passed it */
	if (statp == NULL) {
		xx = stat64(namep, &statinfo);
		if (xx) {
			if (verbose) {
				pr_err(gettext("stat failed %s %d"),
				    namep, errno);
			}
			return (-1);
		}
		statp = &statinfo;
	}

	/* ignore directories */
	if (S_ISDIR(statp->st_mode)) {
		errno = EINVAL;
		return (-1);
	}

	/* if a local file then move to lost+found */
	strp = strrchr(namep, '/');
	if (strp == NULL) {
		errno = EINVAL;
		return (-1);
	}
	strp++;
	if (*strp == 'L')
		dolf = 1;

	/* if a modified file then move to lost+found */
	if ((statp->st_mode & S_IAMB) == 0766)
		dolf = 1;

	/* if moving to lost+found */
	if (dolf) {
		sprintf(newname, "%s/%s", S_lostfound, strp);
		xx = stat64(newname, &statinfo);
		for (ii = 1; ((ii < 1000) && (xx == 0)); ii++) {
			sprintf(newname, "%s/%s_%d", S_lostfound, strp, ii);
			xx = stat64(newname, &statinfo);
		}
		xx = rename(namep, newname);
		if (xx) {
			pr_err(gettext("Could not move file %s to %s: %s"),
			    namep, newname, strerror(errno));
			exit(-1);
		}
		S_move_lostfound = 1;
		return (0);
	}

	/* remove the file */
	xx = unlink(namep);
	if (xx == -1) {
		pr_err(gettext("Could not remove file %s: %s"),
		    namep, strerror(errno));
	} else if (verbose) {
		pr_err(gettext("Removed %s"), namep);
	}

	return (0);
}

void
cache_backmnt_cleanup(char *cachedirp, char *backmnt_namep)
{
	DIR *dirp;
	struct dirent *entp;
	char dirname[MAXPATHLEN * 2];

	/* open the directory */
	sprintf(dirname, "%s/%s", cachedirp, backmnt_namep);
	dirp = opendir(dirname);
	if (dirp == NULL)
		return;

	/*
	 * Try to remove everything in the directory with rmdir.
	 * Should only be empty directories in here at this point.
	 * If not, do not worry about it.
	 */
	for (;;) {
		/* get the next dir entry */
		entp = readdir(dirp);
		if (entp == NULL)
			break;

		/*
		 * Try and remove the directory.
		 * This will fail if there is anything in the dir,
		 * like a mounted file system.
		 */
		rmdir(entp->d_name);
	}
	closedir(dirp);
}
