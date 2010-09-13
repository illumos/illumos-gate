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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Common subroutines used by the programs in these subdirectories.
 */

#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <wait.h>
#include <ctype.h>
#include <fcntl.h>
#include <ftw.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/time.h>
#include <utmpx.h>
#include <sys/uio.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/mount.h>
#include <sys/mntent.h>
#include <sys/mnttab.h>
#include <sys/mman.h>
#include <sys/fs/cachefs_fs.h>
#include "subr.h"

/*
 *
 *			cachefs_dir_lock
 *
 * Description:
 *	Gets a lock on the cache directory.
 *	To release the lock, call cachefs_dir_unlock
 *	with the returned value.
 * Arguments:
 *	cachedirp	name of the cache directory
 *	shared		1 if shared, 0 if not
 * Returns:
 *	Returns -1 if the lock cannot be obtained immediatly.
 *	If the lock is obtained, returns a value >= 0.
 * Preconditions:
 *	precond(cachedirp)
 */

int
cachefs_dir_lock(const char *cachedirp, int shared)
{
	int fd;
	int xx;
	int len;
	char buf[MAXPATHLEN];
	struct flock fl;
	char *strp;
	struct stat statb;

	/* make a path prefix to the cache directory lock file */
	strp = CACHEFS_ROOTRUN;
	xx = stat(strp, &statb);
	if ((xx < 0) || ((statb.st_mode & S_IFMT) != S_IFDIR))
		strp = "/tmp";

	/* won't overflow */
	len = snprintf(buf, sizeof (buf), "%s/%s", strp, CACHEFS_LOCKDIR_PRE);

	if (strlcat(buf, cachedirp, sizeof (buf)) >= sizeof (buf)) {
		pr_err(gettext("Cache directory name %s is too long"),
			cachedirp);
		return (-1);
	}

	strp = &buf[len];

	while (strp = strchr(strp, '/')) { 	/* convert path to a file */
		*strp = '_';
	}

	/*
	 * Create and open the cache directory lock file.
	 * This file will be <2G.
	 */
	fd = open(buf, O_RDWR | O_CREAT, 0700);
	if (fd == -1) {
		pr_err(gettext("Cannot open lock file %s"), buf);
		return (-1);
	}

	/* try to set the lock */
	fl.l_type = (shared == 1) ? F_RDLCK : F_WRLCK;
	fl.l_whence = 0;
	fl.l_start = 1024;
	fl.l_len = 1024;
	fl.l_sysid = 0;
	fl.l_pid = 0;
	/* CACHEFS_LOCK_FILE will be <2GB */
	xx = fcntl(fd, F_SETLKW, &fl);
	if (xx == -1) {
		if (errno == EAGAIN) {
			pr_err(gettext("Cannot gain access to the "
			    "cache directory %s."), cachedirp);
		} else {
			pr_err(gettext("Unexpected failure on lock file %s %s"),
			    buf, strerror(errno));
		}
		close(fd);
		return (-1);
	}

	/* return the file descriptor which can be used to release the lock */
	return (fd);
}

/*
 *
 *			cachefs_dir_unlock
 *
 * Description:
 *	Releases an advisory lock on the cache directory.
 * Arguments:
 *	fd	cookie returned by cachefs_dir_lock
 * Returns:
 *	Returns -1 if the lock cannot be released or 0 for success.
 * Preconditions:
 */

int
cachefs_dir_unlock(int fd)
{
	struct flock fl;
	int error = 0;
	int xx;

	/* release the lock */
	fl.l_type = F_UNLCK;
	fl.l_whence = 0;
	fl.l_start = 1024;
	fl.l_len = 1024;
	fl.l_sysid = 0;
	fl.l_pid = 0;
	/* fd will be <2GB */
	xx = fcntl(fd, F_SETLK, &fl);
	if (xx == -1) {
		pr_err(gettext("Unexpected failure releasing lock file %s"),
			strerror(errno));
		error = -1;
	}

	/* close the lock file */
	close(fd);

	return (error);
}

/*
 *
 *			cachefs_label_file_get
 *
 * Description:
 *	Gets the contents of a cache label file.
 *	Performs error checking on the file.
 * Arguments:
 *	filep	name of the cache label file
 *	clabelp	where to put the file contents
 * Returns:
 *	Returns 0 for success or -1 if an error occurs.
 * Preconditions:
 *	precond(filep)
 *	precond(clabelp)
 */

int
cachefs_label_file_get(const char *filep, struct cache_label *clabelp)
{
	int xx;
	int fd;
	struct stat64 statinfo;

	/* get info on the file */
	xx = lstat64(filep, &statinfo);
	if (xx == -1) {
		if (errno != ENOENT) {
			pr_err(gettext("Cannot stat file %s: %s"),
			    filep, strerror(errno));
		} else {
			pr_err(gettext("File %s does not exist."), filep);
		}

		return (-1);
	}

	/* if the file is the wrong type */
	if (!S_ISREG(statinfo.st_mode)) {
		pr_err(gettext("Cache label file %s corrupted"), filep);
		return (-1);
	}

	/* if the file is the wrong size; it will be <2GB */
	if (statinfo.st_size != (offset_t)sizeof (struct cache_label)) {
		pr_err(gettext("Cache label file %s wrong size"), filep);
		return (-1);
	}

	/* open the cache label file */
	fd = open(filep, O_RDONLY);
	if (fd == -1) {
		pr_err(gettext("Error opening %s: %s"), filep,
		    strerror(errno));
		return (-1);
	}

	/* read the current set of parameters */
	xx = read(fd, clabelp, sizeof (struct cache_label));
	if (xx != sizeof (struct cache_label)) {
		pr_err(gettext("Reading %s failed: %s\n"), filep,
		    strerror(errno));
		close(fd);
		return (-1);
	}
	close(fd);

	/* return success */
	return (0);
}

/*
 *
 *			cachefs_label_file_put
 *
 * Description:
 *	Outputs the contents of a cache label object to a file.
 * Arguments:
 *	filep	name of the cache label file
 *	clabelp	where to get the file contents
 * Returns:
 *	Returns 0 for success or -1 if an error occurs.
 * Preconditions:
 *	precond(filep)
 *	precond(clabelp)
 */

int
cachefs_label_file_put(const char *filep, struct cache_label *clabelp)
{
	int xx;
	int fd;

	/* get rid of the file if it already exists */
	xx = unlink(filep);
	if ((xx == -1) && (errno != ENOENT)) {
		pr_err(gettext("Could not remove %s: %s"), filep,
		    strerror(errno));
		return (-1);
	}

	/* open the cache label file; this file will be <2GB */
	fd = open(filep, O_CREAT | O_RDWR, 0600);
	if (fd == -1) {
		pr_err(gettext("Error creating %s: %s"), filep,
		    strerror(errno));
		return (-1);
	}

	/* write out the cache label object */
	xx = write(fd, clabelp, sizeof (struct cache_label));
	if (xx != sizeof (struct cache_label)) {
		pr_err(gettext("Writing %s failed: %s"), filep,
		    strerror(errno));
		close(fd);
		return (-1);
	}

	/* make sure the contents get to disk */
	if (fsync(fd) != 0) {
		pr_err(gettext("Writing %s failed on sync: %s"), filep,
		    strerror(errno));
		close(fd);
		return (-1);
	}

	close(fd);

	/* return success */
	return (0);
}

int
cachefs_label_file_vcheck(char *filep, struct cache_label *clabelp)
{
	/* check for an invalid version number */
	if (clabelp->cl_cfsversion != CFSVERSION) {
		pr_err(gettext("Cache label file %s corrupted"), filep);
		return (-1);
	}

	return (0);
}

/*
 *
 *			cachefs_inuse
 *
 * Description:
 *	Tests whether or not the cache directory is in use by
 *	the cache file system.
 * Arguments:
 *	cachedirp	name of the file system cache directory
 * Returns:
 *	Returns 1 if the cache is in use or an error, 0 if not.
 * Preconditions:
 *	precond(cachedirp)
 */

int
cachefs_inuse(const char *cachedirp)
{
	int fd;
	int xx;
	char buf[MAXPATHLEN];
	char *lockp = CACHEFS_LOCK_FILE;
	struct flock fl;

	/* see if path name is too long */
	xx = strlen(cachedirp) + strlen(lockp) + 3;
	if (xx >= MAXPATHLEN) {
		pr_err(gettext("Cache directory name %s is too long"),
		    cachedirp);
		return (1);
	}

	/* make a path to the cache directory lock file */
	snprintf(buf, sizeof (buf), "%s/%s", cachedirp, lockp);

	/* Open the kernel in use lock file.  This file will be <2GB. */
	fd = open(buf, O_RDWR, 0700);
	if (fd == -1) {
		pr_err(gettext("Cannot open lock file %s"), buf);
		return (1);
	}

	/* test the lock status */
	fl.l_type = F_WRLCK;
	fl.l_whence = 0;
	fl.l_start = 0;
	fl.l_len = 1024;
	fl.l_sysid = 0;
	fl.l_pid = 0;
	xx = fcntl(fd, F_GETLK, &fl);
	if (xx == -1) {
		pr_err(gettext("Unexpected failure on lock file %s %s"),
		    buf, strerror(errno));
		close(fd);
		return (1);
	}
	close(fd);

	if (fl.l_type == F_UNLCK)
		xx = 0;
	else
		xx = 1;

	/* return whether or not the cache is in use */
	return (xx);
}

/*
 *
 *			cachefs_resouce_size
 *
 * Description:
 *	Returns information about a resource file.
 * Arguments:
 *	maxinodes	number of inodes to be managed by the resource file
 *	rinfop		set to info about the resource file
 * Returns:
 * Preconditions:
 *	precond(rinfop)
 */

void
cachefs_resource_size(int maxinodes, struct cachefs_rinfo *rinfop)
{
	int fsize;

	fsize = MAXBSIZE;

	rinfop->r_ptroffset = fsize;

	fsize += MAXBSIZE * (maxinodes / CACHEFS_RLPMBS);
	if ((maxinodes % CACHEFS_RLPMBS) != 0)
		fsize += MAXBSIZE;

	rinfop->r_fsize = fsize;
}

/*
 *
 *			cachefs_create_cache
 *
 * Description:
 *	Creates the specified cache directory and populates it as
 *	needed by CFS.
 * Arguments:
 *	dirp		the name of the cache directory
 *	uv		user values (may be NULL)
 *	clabel		label file contents, or placeholder for this
 * Returns:
 *	Returns 0 for success or:
 *		-1 for an error
 *		-2 for an error and cache directory partially created
 * Preconditions:
 *	precond(dirp)
 */

int
cachefs_create_cache(char *dirp, struct cachefs_user_values *uv,
    struct cache_label *clabel)
{
	int xx;
	char path[CACHEFS_XMAXPATH];
	int fd;
	void *bufp;
	int cnt;
	struct cache_usage cu;
	FILE *fp;
	char *parent;
	struct statvfs64 svfs;

	cu.cu_blksused = 0;
	cu.cu_filesused = 0;
	cu.cu_flags = 0;

	/* make sure cache dir name is not too long */
	if (strlen(dirp) > (size_t)PATH_MAX) {
		pr_err(gettext("path name %s is too long."), dirp);
		return (-1);
	}

	/* ensure the path isn't in cachefs */
	parent = cachefs_file_to_dir(dirp);
	if (parent == NULL) {
		pr_err(gettext("Out of memory"));
		return (-1);
	}
	if (statvfs64(parent, &svfs) != 0) {
		pr_err(gettext("%s: %s"), parent, strerror(errno));
		free(parent);
		return (-1);
	}
	if (strcmp(svfs.f_basetype, CACHEFS_BASETYPE) == 0) {
		pr_err(gettext("Cannot create cache in cachefs filesystem"));
		free(parent);
		return (-1);
	}
	free(parent);

	/* make the directory */
	if (mkdir(dirp, 0) == -1) {
		switch (errno) {
		case EEXIST:
			pr_err(gettext("%s already exists."), dirp);
			break;

		default:
			pr_err(gettext("mkdir %s failed: %s"),
			    dirp, strerror(errno));
		}
		return (-1);
	}
	cu.cu_filesused += 1;
	cu.cu_blksused += 1;

	/* convert user values to a cache_label */
	if (uv != NULL) {
		xx = cachefs_convert_uv2cl(uv, clabel, dirp);
		if (xx)
			return (-2);
	}

	/*
	 * Create the cache directory lock file.
	 * Used by the kernel module to indicate the cache is in use.
	 * This file will be <2G.
	 */
	snprintf(path, sizeof (path), "%s/%s", dirp, CACHEFS_LOCK_FILE);
	fd = open(path, O_RDWR | O_CREAT, 0700);
	if (fd == -1) {
		pr_err(gettext("Cannot create lock file %s"), path);
		return (-1);
	}
	close(fd);

	/* make the directory for the back file system mount points */
	/* note: we do not count this directory in the resources */
	snprintf(path, sizeof (path), "%s/%s", dirp, BACKMNT_NAME);
	if (mkdir(path, 0700) == -1) {
		pr_err(gettext("mkdir %s failed: %s"), path,
		    strerror(errno));
		return (-2);
	}

	/* make the directory for lost+found */
	/* note: we do not count this directory in the resources */
	snprintf(path, sizeof (path), "%s/%s", dirp, CACHEFS_LOSTFOUND_NAME);
	if (mkdir(path, 0700) == -1) {
		pr_err(gettext("mkdir %s failed: %s"), path,
		    strerror(errno));
		return (-2);
	}

	/* make the networker "don't back up" file; this file is <2GB */
	xx = 0;
	snprintf(path, sizeof (path), "%s/%s", dirp, NOBACKUP_NAME);
	if ((fp = fopen(path, "w")) != NULL) {
		if (realpath(dirp, path) != NULL) {
			fprintf(fp, "<< ./ >>\n");
			fprintf(fp, "+skip: .?* *\n");
			if (fclose(fp) == 0)
				xx = 1;
		}
	}
	if (xx == 0) {
		snprintf(path, sizeof (path), "%s/%s", dirp, NOBACKUP_NAME);
		pr_err(gettext("can't create %s"), path);
		(void) unlink(path);
	} else {
		cu.cu_filesused += 1;
		cu.cu_blksused += 1;
	}

	/* create the unmount file */
	xx = 0;
	snprintf(path, sizeof (path), "%s/%s", dirp, CACHEFS_UNMNT_FILE);
	if ((fp = fopen(path, "w")) != NULL) {
		time32_t btime;

		btime = get_boottime();
		fwrite((void *)&btime, sizeof (btime), 1, fp);
		if (fclose(fp) == 0)
			xx = 1;
	}
	if (xx == 0)
		pr_err(gettext("can't create .cfs_unmnt file"));

	/* create the cache label file */
	snprintf(path, sizeof (path), "%s/%s", dirp, CACHELABEL_NAME);
	xx = cachefs_label_file_put(path, clabel);
	if (xx == -1) {
		pr_err(gettext("creating %s failed."), path);
		return (-2);
	}
	cu.cu_filesused += 1;
	cu.cu_blksused += 1;

	/* create the cache label duplicate file */
	snprintf(path, sizeof (path), "%s/%s.dup", dirp, CACHELABEL_NAME);
	xx = cachefs_label_file_put(path, clabel);
	if (xx == -1) {
		pr_err(gettext("creating %s failed."), path);
		return (-2);
	}
	cu.cu_filesused += 1;
	cu.cu_blksused += 1;

	/* create the resouce file; this file will be <2GB */
	snprintf(path, sizeof (path), "%s/%s", dirp, RESOURCE_NAME);
	fd = open(path, O_CREAT | O_RDWR, 0600);
	if (fd == -1) {
		pr_err(gettext("create %s failed: %s"), path,
		    strerror(errno));
		return (-2);
	}
	cu.cu_filesused += 1;

	/* allocate a zeroed buffer for filling the resouce file */
	bufp = calloc(1, MAXBSIZE);
	if (bufp == NULL) {
		pr_err(gettext("out of space %d."), MAXBSIZE);
		close(fd);
		return (-2);
	}

	/* determine number of MAXBSIZE chunks to make the file */
	cnt = 1;	/* for the header */
	cnt += clabel->cl_maxinodes / CACHEFS_RLPMBS;
	if ((clabel->cl_maxinodes % CACHEFS_RLPMBS) != 0)
		++cnt;

	/* fill up the file with zeros */
	for (xx = 0; xx < cnt; xx++) {
		if (write(fd, bufp, MAXBSIZE) != MAXBSIZE) {
			pr_err(gettext("write %s failed: %s"), path,
			    strerror(errno));
			close(fd);
			free(bufp);
			return (-2);
		}
	}
	free(bufp);
	cu.cu_blksused += cnt;

	/* position to the begining of the file */
	if (lseek(fd, 0, SEEK_SET) == -1) {
		pr_err(gettext("lseek %s failed: %s"), path,
		    strerror(errno));
		close(fd);
		return (-2);
	}

	/* write the cache usage structure */
	xx = sizeof (struct cache_usage);
	if (write(fd, &cu, xx) != xx) {
		pr_err(gettext("cu write %s failed: %s"), path,
		    strerror(errno));
		close(fd);
		return (-2);
	}

	/* make sure the contents get to disk */
	if (fsync(fd) != 0) {
		pr_err(gettext("fsync %s failed: %s"), path,
		    strerror(errno));
		close(fd);
		return (-2);
	}
	close(fd);

	/* return success */
	return (0);
}

/*
 *
 *			cachefs_delete_all_cache
 *
 * Description:
 *	Delete all caches in cache directory.
 * Arguments:
 *	dirp	the pathname of of the cache directory to delete
 * Returns:
 *	Returns 0 for success or -1 for an error.
 * Preconditions:
 *	precond(dirp)
 */

int
cachefs_delete_all_cache(char *dirp)
{
	DIR *dp;
	struct dirent64 *dep;
	int xx;
	char path[CACHEFS_XMAXPATH];
	struct stat64 statinfo;

	/* make sure cache dir name is not too long */
	if (strlen(dirp) > (size_t)PATH_MAX) {
		pr_err(gettext("path name %s is too long."),
		    dirp);
		return (-1);
	}

	/* check that dirp is probably a cachefs directory */
	snprintf(path, sizeof (path), "%s/%s", dirp, BACKMNT_NAME);
	xx = access(path, R_OK | W_OK | X_OK);

	snprintf(path, sizeof (path), "%s/%s", dirp, CACHELABEL_NAME);
	xx |= access(path, R_OK | W_OK);

	if (xx) {
		pr_err(gettext("%s does not appear to be a "
		    "cachefs cache directory."), dirp);
		return (-1);
	}

	/* remove the lost+found directory if it exists and is empty */
	snprintf(path, sizeof (path), "%s/%s", dirp, CACHEFS_LOSTFOUND_NAME);
	xx = rmdir(path);
	if (xx == -1) {
		if (errno == EEXIST) {
			pr_err(gettext("Cannot delete cache '%s'.  "
			    "First move files in '%s' to a safe location."),
			    dirp, path);
			return (-1);
		} else if (errno != ENOENT) {
			pr_err(gettext("rmdir %s failed: %s"), path,
			    strerror(errno));
			return (-1);
		}
	}

	/* delete the back FS mount point directory if it exists */
	snprintf(path, sizeof (path), "%s/%s", dirp, BACKMNT_NAME);
	xx = lstat64(path, &statinfo);
	if (xx == -1) {
		if (errno != ENOENT) {
			pr_err(gettext("lstat %s failed: %s"), path,
			    strerror(errno));
			return (-1);
		}
	} else {
		xx = nftw64(path, cachefs_delete_file, 16,
		    FTW_PHYS | FTW_DEPTH | FTW_MOUNT);
		if (xx == -1) {
			pr_err(gettext("unable to delete %s"), path);
			return (-1);
		}
	}

	/* open the cache directory specified */
	if ((dp = opendir(dirp)) == NULL) {
		pr_err(gettext("cannot open cache directory %s: %s"),
		    dirp, strerror(errno));
		return (-1);
	}

	/* read the file names in the cache directory */
	while ((dep = readdir64(dp)) != NULL) {
		/* ignore . and .. */
		if (strcmp(dep->d_name, ".") == 0 ||
				strcmp(dep->d_name, "..") == 0)
			continue;

		/* stat the file */
		snprintf(path, sizeof (path), "%s/%s", dirp, dep->d_name);
		xx = lstat64(path, &statinfo);
		if (xx == -1) {
			if (errno == ENOENT) {
				/* delete_cache may have nuked a directory */
				continue;
			}

			pr_err(gettext("lstat %s failed: %s"),
			    path, strerror(errno));
			closedir(dp);
			return (-1);
		}

		/* ignore anything that is not a link */
		if (!S_ISLNK(statinfo.st_mode))
			continue;

		/* delete the file system cache directory */
		xx = cachefs_delete_cache(dirp, dep->d_name);
		if (xx) {
			closedir(dp);
			return (-1);
		}
	}
	closedir(dp);

	/* remove the cache dir unmount file */
	snprintf(path, sizeof (path), "%s/%s", dirp, CACHEFS_UNMNT_FILE);
	xx = unlink(path);
	if ((xx == -1) && (errno != ENOENT)) {
		pr_err(gettext("unlink %s failed: %s"), path,
		    strerror(errno));
		return (-1);
	}

	/* remove the cache label file */
	snprintf(path, sizeof (path), "%s/%s", dirp, CACHELABEL_NAME);
	xx = unlink(path);
	if ((xx == -1) && (errno != ENOENT)) {
		pr_err(gettext("unlink %s failed: %s"), path,
		    strerror(errno));
		return (-1);
	}

	/* remove the cache label duplicate file */
	snprintf(path, sizeof (path), "%s/%s.dup", dirp, CACHELABEL_NAME);
	xx = unlink(path);
	if ((xx == -1) && (errno != ENOENT)) {
		pr_err(gettext("unlink %s failed: %s"), path,
		    strerror(errno));
		return (-1);
	}

	/* remove the resource file */
	snprintf(path, sizeof (path), "%s/%s", dirp, RESOURCE_NAME);
	xx = unlink(path);
	if ((xx == -1) && (errno != ENOENT)) {
		pr_err(gettext("unlink %s failed: %s"), path,
		    strerror(errno));
		return (-1);
	}

	/* remove the cachefslog file if it exists */
	snprintf(path, sizeof (path), "%s/%s", dirp, LOG_STATUS_NAME);
	(void) unlink(path);

	/* remove the networker "don't back up" file if it exists */
	snprintf(path, sizeof (path), "%s/%s", dirp, NOBACKUP_NAME);
	(void) unlink(path);

	/* remove the lock file */
	snprintf(path, sizeof (path), "%s/%s", dirp, CACHEFS_LOCK_FILE);
	xx = unlink(path);
	if ((xx == -1) && (errno != ENOENT)) {
		pr_err(gettext("unlink %s failed: %s"), path,
		    strerror(errno));
		return (-1);
	}

	/* remove the directory */
	xx = rmdir(dirp);
	if (xx == -1) {
		pr_err(gettext("rmdir %s failed: %s"), dirp,
		    strerror(errno));
		return (-1);
	}

	/* return success */
	return (0);
}

/*
 *
 *			cachefs_delete_cache
 *
 * Description:
 *	Deletes the specified file system cache.
 * Arguments:
 *	dirp	cache directory name
 *	namep	file system cache directory to delete
 * Returns:
 *	Returns 0 for success, -1 for failure.
 * Preconditions:
 *	precond(dirp)
 *	precond(namep)
 */

int
cachefs_delete_cache(char *dirp, char *namep)
{
	char path[CACHEFS_XMAXPATH];
	char buf[CACHEFS_XMAXPATH];
	int xx;
	struct stat64 statinfo;

	/* make sure cache dir name is not too long */
	if (strlen(dirp) > (size_t)PATH_MAX) {
		pr_err(gettext("path name %s is too long."),
		    dirp);
		return (-1);
	}

	/* construct the path name of the file system cache directory */
	snprintf(path, sizeof (path), "%s/%s", dirp, namep);

	/* stat the specified file */
	xx = lstat64(path, &statinfo);
	if (xx == -1) {
		pr_err(gettext("lstat %s failed: %s"), path,
		    strerror(errno));
		return (-1);
	}

	/* make sure name is a symbolic link */
	if (!S_ISLNK(statinfo.st_mode)) {
		pr_err(gettext("\"%s\" is not a valid cache id."), namep);
		return (-1);
	}

	/* read the contents of the symbolic link */
	xx = readlink(path, buf, sizeof (buf));
	if (xx == -1) {
		pr_err(gettext("Readlink of %s failed: %s"), path,
		    strerror(errno));
		return (-1);
	}
	buf[xx] = '\0';

	/* remove the directory */
	snprintf(path, sizeof (path), "%s/%s", dirp, buf);
	xx = nftw64(path, cachefs_delete_file, 16,
	    FTW_PHYS | FTW_DEPTH | FTW_MOUNT);
	if (xx == -1) {
		pr_err(gettext("directory walk of %s failed."), dirp);
		return (-1);
	}

	/* delete the link */
	snprintf(path, sizeof (path), "%s/%s", dirp, namep);
	if (unlink(path) == -1) {
		pr_err(gettext("unlink %s failed: %s"), path,
		    strerror(errno));
		return (-1);
	}

	/* return success */
	return (0);
}

/*
 *
 *			cachefs_delete_file
 *
 * Description:
 *	Remove a file or directory; called by nftw64().
 * Arguments:
 *	namep	pathname of the file
 *	statp	stat info about the file
 *	flg	info about file
 *	ftwp	depth information
 * Returns:
 *	Returns 0 for success, -1 for failure.
 * Preconditions:
 *	precond(namep)
 */

int
cachefs_delete_file(const char *namep, const struct stat64 *statp, int flg,
    struct FTW *ftwp)
{
	/* ignore . and .. */
	if (strcmp(namep, ".") == 0 || strcmp(namep, "..") == 0)
		return (0);

	switch (flg) {
	case FTW_F:	/* files */
	case FTW_SL:
		if (unlink(namep) == -1) {
			pr_err(gettext("unlink %s failed: %s"),
			    namep, strerror(errno));
			return (-1);
		}
		break;

	case FTW_DP:	/* directories that have their children processed */
		if (rmdir(namep) == -1) {
			pr_err(gettext("rmdir %s failed: %s"),
			    namep, strerror(errno));
			return (-1);
		}
		break;

	case FTW_D:	/* ignore directories if children not processed */
		break;

	default:
		pr_err(gettext("failure on file %s, flg %d."),
		    namep, flg);
		return (-1);
	}

	/* return success */
	return (0);
}

/*
 *
 *			cachefs_convert_uv2cl
 *
 * Description:
 *	Copies the contents of a cachefs_user_values object into a
 *	cache_label object, performing the necessary conversions.
 * Arguments:
 *	uvp	cachefs_user_values to copy from
 *	clp	cache_label to copy into
 *	dirp	cache directory
 * Returns:
 *	Returns 0 for success, -1 for an error.
 * Preconditions:
 *	precond(uvp)
 *	precond(clp)
 *	precond(dirp)
 */

int
cachefs_convert_uv2cl(const struct cachefs_user_values *uvp,
    struct cache_label *clp, const char *dirp)
{
	struct statvfs64 fs;
	int xx;
	double ftmp;
	double temp;

	/* get file system information */
	xx = statvfs64(dirp, &fs);
	if (xx == -1) {
		pr_err(gettext("statvfs %s failed: %s"), dirp,
		    strerror(errno));
		return (-1);
	}

	ftmp = (double)fs.f_frsize / (double)MAXBSIZE;

	/* front fs is less than 1 terabyte */
	temp = (double)uvp->uv_maxblocks / 100.0 *
	    (double)fs.f_blocks * ftmp + .5;
	clp->cl_maxblks = temp < (double)INT_MAX ? (int)temp : INT_MAX;

	temp = (double)uvp->uv_minblocks / 100.0 *
	    (double)fs.f_blocks * ftmp + .5;
	clp->cl_blockmin = temp < (double)INT_MAX ? (int)temp : INT_MAX;

	temp = (double)uvp->uv_threshblocks / 100.0 *
	    (double)fs.f_blocks * ftmp + .5;
	clp->cl_blocktresh = temp < (double)INT_MAX ? (int)temp : INT_MAX;

	temp = (double)uvp->uv_maxfiles / 100.0 * (double)fs.f_files + .5;
	clp->cl_maxinodes = temp < (double)INT_MAX ? (int)temp : INT_MAX;

	temp = (double)uvp->uv_minfiles / 100.0 * (double)fs.f_files + .5;
	clp->cl_filemin = temp < (double)INT_MAX ? (int)temp : INT_MAX;

	temp = (double)uvp->uv_threshfiles / 100.0 * (double)fs.f_files +.5;
	clp->cl_filetresh = temp < (double)INT_MAX ? (int)temp : INT_MAX;

	ftmp = (double)(1024 * 1024) / (double)MAXBSIZE;
	clp->cl_maxfiles = uvp->uv_maxfilesize * ftmp + .5;

	clp->cl_blkhiwat = uvp->uv_hiblocks / 100.0 * clp->cl_maxblks + .5;
	clp->cl_blklowat = uvp->uv_lowblocks / 100.0 * clp->cl_maxblks + .5;

	clp->cl_filehiwat = uvp->uv_hifiles / 100.0 * clp->cl_maxinodes + .5;
	clp->cl_filelowat = uvp->uv_lowfiles / 100.0 * clp->cl_maxinodes + .5;

	clp->cl_cfsversion = CFSVERSION;

	/* return success */
	return (0);
}

/*
 *
 *			cachefs_convert_cl2uv
 *
 * Description:
 *	Copies the contents of a cache_label object into a
 *	cachefs_user_values object, performing the necessary conversions.
 * Arguments:
 *	clp	cache_label to copy from
 *	uvp	cachefs_user_values to copy into
 *	dirp	cache directory
 * Returns:
 *	Returns 0 for success, -1 for an error.
 * Preconditions:
 *	precond(clp)
 *	precond(uvp)
 *	precond(dirp)
 */

int
cachefs_convert_cl2uv(const struct cache_label *clp,
    struct cachefs_user_values *uvp, const char *dirp)
{
	struct statvfs64 fs;
	int xx;
	double temp;
	double ftmp;
	long long ltmp;

	/* get file system information */
	xx = statvfs64(dirp, &fs);
	if (xx == -1) {
		pr_err(gettext("statvfs %s failed: %s"), dirp,
		    strerror(errno));
		return (-1);
	}

#define	BOUND(yy) \
	yy = (yy < 0) ? 0 : yy; \
	yy = (yy > 100) ? 100 : yy;

	ftmp = (double)MAXBSIZE / (double)fs.f_frsize;

	temp = (double)clp->cl_maxblks * ftmp /
	    (double)fs.f_blocks * 100. + .5;
	BOUND(temp);
	uvp->uv_maxblocks = (int)temp;

	temp = (double)clp->cl_blockmin * ftmp /
	    (double)fs.f_blocks * 100. + .5;
	BOUND(temp);
	uvp->uv_minblocks = (int)temp;

	temp = (double)clp->cl_blocktresh * ftmp /
	    (double)fs.f_blocks * 100. + .5;
	BOUND(temp);
	uvp->uv_threshblocks = (int)temp;

	temp = ((double)clp->cl_maxinodes / fs.f_files) * 100. + .5;
	BOUND(temp);
	uvp->uv_maxfiles = (int)temp;

	temp = ((double)clp->cl_filemin / fs.f_files) * 100. + .5;
	BOUND(temp);
	uvp->uv_minfiles = (int)temp;

	temp = ((double)clp->cl_filetresh / fs.f_files) * 100. + .5;
	BOUND(temp);
	uvp->uv_threshfiles = (int)temp;

	ltmp = ((long long)clp->cl_maxfiles * MAXBSIZE);
	uvp->uv_maxfilesize = (ltmp + (MAXBSIZE / 2)) / (1024 * 1024);

	xx = ((double)clp->cl_blkhiwat / clp->cl_maxblks) * 100. + .5;
	BOUND(xx);
	uvp->uv_hiblocks = xx;

	xx = ((double)clp->cl_blklowat / clp->cl_maxblks) * 100. + .5;
	BOUND(xx);
	uvp->uv_lowblocks = xx;

	xx = ((double)clp->cl_filehiwat / clp->cl_maxinodes) * 100. + .5;
	BOUND(xx);
	uvp->uv_hifiles = xx;

	xx = ((double)clp->cl_filelowat / clp->cl_maxinodes) * 100. + .5;
	BOUND(xx);
	uvp->uv_lowfiles = xx;

	/* return success */
	return (0);
}

/*
 * cachefs_file_to_dir
 *
 * takes in a path, and returns the parent directory of that path.
 *
 * it's the caller's responsibility to free the pointer returned by
 * this function.
 */

char *
cachefs_file_to_dir(const char *path)
{
	char *rc, *cp;

	if (path == NULL)
		return (NULL);

	rc = strdup(path);
	if (rc == NULL)
		return (NULL);

	if ((cp = strrchr(rc, '/')) == NULL) {

		/*
		 * if no slashes at all, return "." (current directory).
		 */

		(void) free(rc);
		rc = strdup(".");

	} else if (cp == rc) {

		/*
		 * else, if the last '/' is the first character, chop
		 * off from there (i.e. return "/").
		 */

		rc[1] = '\0';

	} else {

		/*
		 * else, we have a path like /foo/bar or foo/bar.
		 * chop off from the last '/'.
		 */

		*cp = '\0';

	}

	return (rc);
}

/*
 *			cachefs_clean_flag_test
 *
 * Description:
 *	Tests whether or not the clean flag on the file system
 *	is set.
 * Arguments:
 *	cachedirp	name of the the file system cache directory
 * Returns:
 *	Returns 1 if the cache was shut down cleanly, 0 if not.
 * Preconditions:
 *	precond(cachedirp)
 */

int
cachefs_clean_flag_test(const char *cachedirp)
{
	char *namep;
	int xx;
	char buf[MAXPATHLEN];
	int fd;
	struct cache_usage cu;

	/* construct the path name of the resource file */
	namep = RESOURCE_NAME;
	xx = strlen(cachedirp) + strlen(namep) + 3;
	if (xx >= MAXPATHLEN) {
		pr_err(gettext("Path name too long %s/%s"),
		    cachedirp, namep);
		return (39);
	}
	snprintf(buf, sizeof (buf), "%s/%s", cachedirp, namep);

	/* open the file; it will be <2GB */
	fd = open(buf, O_RDONLY);
	if (fd == -1) {
		pr_err(gettext("Cannot open %s: %s"), buf, strerror(errno));
		return (0);
	}

	/* read the cache_usage structure */
	xx = read(fd, &cu, sizeof (cu));
	if (xx != sizeof (cu)) {
		pr_err(gettext("Error reading %s: %d %s"), buf,
		    xx, strerror(errno));
		close(fd);
		return (0);
	}
	close(fd);

	/* return state of the cache */
	return ((cu.cu_flags & CUSAGE_ACTIVE) == 0);
}

time32_t
get_boottime()
{
	struct utmpx id, *putmp;

	id.ut_type = BOOT_TIME;
	setutxent();
	if ((putmp = getutxid(&id)) != NULL)
		return ((time32_t)putmp->ut_tv.tv_sec);
	return (-1);
}
