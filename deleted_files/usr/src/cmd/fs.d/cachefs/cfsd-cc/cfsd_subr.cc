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
// ------------------------------------------------------------
//
//			cfsd_subr.cc
//
// Various support routines.
//

#pragma ident	"%Z%%M%	%I%	%E% SMI"
// Copyright (c) 1994 by Sun Microsystems, Inc.

#include <libintl.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <dirent.h>
#include <wait.h>
#include <varargs.h>
#include <limits.h>
#include <rpc/rpc.h>
#include <rpc/pmap_clnt.h> /* for pmap_unset */
#include <string.h> /* strcmp */
#include <signal.h>
#include <sysent.h> /* getdtablesize, open */
#include <unistd.h> /* setsid */
#include <sys/utsname.h>
#include <sys/param.h>
#include <sys/mnttab.h>
#include <sys/vfstab.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <memory.h>
#include <stropts.h>
#include <netconfig.h>
#include <sys/resource.h> /* rlimit */
#include <thread.h>
#include <synch.h>
#include <rw/cstring.h>
#include <rw/regexp.h>
#include <rw/rstream.h>
#include <rw/tpdlist.h>
#include <mdbug-cc/mdbug.h>
#include <sys/fs/cachefs_fs.h>
#include <sys/fs/cachefs_dlog.h>
#include <sys/fs/cachefs_ioctl.h>
#include "cfsd_kmod.h"
#include "cfsd_maptbl.h"
#include "cfsd_logfile.h"
#include "cfsd_fscache.h"
#include "cfsd_cache.h"
#include "cfsd_all.h"
#include <common/cachefsd.h>
#include <common/subr.h>

// forward references
void *subr_mount_thread(void *datap);
int subr_fsck_cache(const char *cachedirp);
void subr_doexec(const char *fstype, char *newargv[], const char *progp);

//
//			subr_add_mount
//
// Description:
//	Adds the specified file system to the data structures.
// Arguments:
//	allp	ptr to set of data structures
//	dirp	ptr to name of cache directory
//	idp	ptr to id of file system cache in dirp
// Returns:
// Preconditions:
//	precond(allp)
//	precond(dirp)
//	precond(idp)

void
subr_add_mount(cfsd_all *allp, const char *dirp, const char *idp)
{
	dbug_enter("subr_add_mount");

	dbug_precond(allp);
	dbug_precond(dirp);
	dbug_precond(idp);

	dbug_print("info", ("cachedir %s, cacheid %s", dirp, idp));

	int xx;

	// find or create the cache object
	allp->all_lock();
	cfsd_cache *cachep = allp->all_cachelist_find(dirp);
	if (cachep == NULL) {
		// make the cache object
		cachep = new cfsd_cache;
		xx = allp->all_nextcacheid();
		xx = cachep->cache_setup(dirp, xx);
		if (xx == 0) {
			dbug_print("error", ("invalid cache %s", dirp));
			delete cachep;
			allp->all_unlock();
			return;
		}
		allp->all_cachelist_add(cachep);
		allp->all_cachefstab_update();
	}
	cachep->cache_lock();
	cachep->cache_refinc();
	cachep->cache_unlock();
	allp->all_unlock();

	// find or create the fscache object
	cachep->cache_lock();
	cfsd_fscache *fscachep = cachep->cache_fscachelist_find(idp);
	if (fscachep == NULL) {
		// make the fscache object and add it to the list
		xx = cachep->cache_nextfscacheid();
		fscachep = new cfsd_fscache(idp, dirp, xx);
		cachep->cache_fscachelist_add(fscachep);
	} else {
		/* don't do any more if already mounted */
		fscachep->fscache_lock();
		if (fscachep->fscache_mounted()) {
			cachep->cache_refdec();
			fscachep->fscache_unlock();
			cachep->cache_unlock();
			dbug_print("info", ("fscache already mounted"));
			return;
		}
		fscachep->fscache_unlock();
	}
	fscachep->fscache_lock();
	fscachep->fscache_refinc();
	fscachep->fscache_unlock();
	cachep->cache_unlock();

	// init the fscache object with mount information
	fscachep->fscache_lock();
	fscachep->fscache_setup();

	// start the disconnect thread if necessary
	if (fscachep->fscache_disconnectable() &&
	    fscachep->fscache_mounted() &&
	    (fscachep->fscache_threaded() == 0) &&
	    (strcmp(fscachep->fscache_name(), "rootcache") != 0)) {
		thread_t new_thread;
		fscachep->fscache_refinc();
		fscachep->fscache_threaded(1);
		xx = thr_create(NULL, 0, subr_mount_thread, fscachep,
				THR_DETACHED | THR_NEW_LWP, &new_thread);
		if (xx) {
			// XXX cachefs kmod cannot allow transition
			dbug_print("error", ("mount thr_create failed %d", xx));
			fscachep->fscache_refdec();
			fscachep->fscache_threaded(0);
		}
		fscachep->fscache_threadid(new_thread);
	}
	fscachep->fscache_refdec();
	fscachep->fscache_unlock();

	cachep->cache_lock();
	cachep->cache_refdec();
	cachep->cache_unlock();
}

// -----------------------------------------------------------------
//
//			subr_mount_thread
//
// Description:
//	Called when a thread is created via thr_create to process
//	an fscache.
// Arguments:
//	datap	ptr to cfsd_fscache to process
// Returns:
//	Returns NULL.
// Preconditions:
//	precond(datap)

void *
subr_mount_thread(void *datap)
{
	dbug_enter("subr_mount_thread");
	dbug_precond(datap);

	cfsd_fscache *fscachep = (cfsd_fscache *)datap;

	fscachep->fscache_process();

	fscachep->fscache_lock();
	fscachep->fscache_threaded(0);
	fscachep->fscache_refdec();
	fscachep->fscache_unlock();

	return (NULL);
}

// -----------------------------------------------------------------
//
//			subr_cache_setup
//
// Description:
//	Called once when the daemon starts up to get the current state
//	of caches reflected in the daemon.
// Arguments:
//	allp
// Returns:
// Preconditions:
//	precond(allp)

void
subr_cache_setup(cfsd_all *allp)
{
	dbug_enter("subr_cache_setup");
	dbug_precond(allp);

	cfsd_cache *cachep;
	int fixcachefstab = 0;

	allp->all_lock();

	// find all the caches indicated in the CACHEFSTAB file
	int xx;
	FILE *fin = fopen(CACHEFSTAB, "r");
	if (fin == NULL) {
		dbug_print("info", ("%s does not exist", CACHEFSTAB));
	} else {
		char buf[MAXPATHLEN];
		while ((xx = fscanf(fin, "%s\n", buf)) != EOF) {
			if (xx != 1)
				continue;
			dbug_print("info", ("cachefstab cache \"%s\"", buf));
			cachep = allp->all_cachelist_find(buf);
			if (cachep == NULL) {
				// make the cache object
				cachep = new cfsd_cache;
				xx = allp->all_nextcacheid();
				xx = cachep->cache_setup(buf, xx);
				if (xx == 0) {
					delete cachep;
					fixcachefstab++;
				} else {
					allp->all_cachelist_add(cachep);
				}
			} else {
				fixcachefstab++;
			}
		}
		fclose(fin);
	}

	// read the mnttab file looking for caches we may have missed
	fin = fopen(MNTTAB, "r");
	if (fin == NULL) {
		dbug_print("info", ("%s does not exist", MNTTAB));
	} else {
		struct mnttab minfo;
		struct mnttab mpref;
		mpref.mnt_special = NULL;
		mpref.mnt_mountp = NULL;
		mpref.mnt_fstype = "cachefs";
		mpref.mnt_mntopts = NULL;
		mpref.mnt_time = NULL;
		while ((xx = getmntany(fin, &minfo, &mpref)) != -1) {
			if (xx != 0)
				continue;
			char *cp = hasmntopt(&minfo, "cachedir=");
			if (cp == NULL)
				cp = "/cache"; // XXX define in mount.c
			else {
				cp += 9;
				char *xcp = strchr(cp, ',');
				if (xcp)
					*xcp = '\0';
			}
			dbug_print("info", ("mnttab cache \"%s\"", cp));
			cachep = allp->all_cachelist_find(cp);
			if (cachep == NULL) {
				// make the cache object
				cachep = new cfsd_cache;
				xx = allp->all_nextcacheid();
				xx = cachep->cache_setup(cp, xx);
				if (xx == 0) {
					delete cachep;
				} else {
					allp->all_cachelist_add(cachep);
					fixcachefstab++;
				}
			}
		}
		fclose(fin);
	}

	// read the vfstab file looking for caches we may have missed
	fin = fopen(VFSTAB, "r");
	if (fin == NULL) {
		dbug_print("info", ("%s does not exist", VFSTAB));
	} else {
		struct vfstab vinfo;
		struct vfstab vpref;
		vpref.vfs_special = NULL;
		vpref.vfs_fsckdev = NULL;
		vpref.vfs_mountp = NULL;
		vpref.vfs_fstype = "cachefs";
		vpref.vfs_fsckpass = NULL;
		vpref.vfs_automnt = NULL;
		vpref.vfs_mntopts = NULL;
		while ((xx = getvfsany(fin, &vinfo, &vpref)) != -1) {
			if (xx != 0)
				continue;
			char *cp = strstr(vinfo.vfs_mntopts, "cachedir=");
			if (cp == NULL)
				cp = "/cache"; // XXX define in mount.c
			else {
				cp += 9;
				char *xcp = strchr(cp, ',');
				if (xcp)
					*xcp = '\0';
			}
			dbug_print("info", ("vfstab cache \"%s\"", cp));
			cachep = allp->all_cachelist_find(cp);
			if (cachep == NULL) {
				// make the cache object
				cachep = new cfsd_cache;
				xx = allp->all_nextcacheid();
				xx = cachep->cache_setup(cp, xx);
				if (xx == 0) {
					delete cachep;
				} else {
					allp->all_cachelist_add(cachep);
					fixcachefstab++;
				}
			}
		}
		fclose(fin);
	}

	// fix up the CACHEFSTAB file if it is out of date
	if (fixcachefstab)
		allp->all_cachefstab_update();

	// now for each cache we found, find all the file systems in the cache
	size_t index;
	for (index = 0; index < allp->all_cachelist_entries(); index++) {
		cachep = allp->all_cachelist_at(index);
		dbug_assert(cachep);
		cachep->cache_lock();
		cachep->cache_refinc();
		cachep->cache_unlock();
		allp->all_unlock();

		// fix up the cache if necessary
		xx = subr_fsck_cache(cachep->cache_cachedir());
		if (xx != 0) {
			dbug_print("error", ("could not fix up cache %d",
				cachep->cache_cachedir()));
			allp->all_lock();
			continue;
		}

		// lock out activity on the cache
		int lockfd = cachefs_dir_lock(cachep->cache_cachedir(), 0);
		if (lockfd < 0) {
			dbug_print("error", ("cannot aquire cache lock on %s",
				cachep->cache_cachedir()));
			allp->all_lock();
			continue;
		}

		// open the cache directory
		DIR *dirp = opendir(cachep->cache_cachedir());
		if (dirp == NULL) {
			dbug_print("error", ("cannot open dir %s",
				cachep->cache_cachedir()));
			cachefs_dir_unlock(lockfd);
			allp->all_lock();
			continue;
		}

		char pathname[MAXPATHLEN + MAXNAMELEN];
		strcpy(pathname, cachep->cache_cachedir());
		strcat(pathname, "/");
		int len = strlen(pathname);

		// read the directory entries
		dirent *entp;
		while ((entp = readdir(dirp)) != NULL) {
			// skip . and ..
			if ((strcmp(entp->d_name, ".") == 0) ||
			    (strcmp(entp->d_name, "..") == 0))
				continue;

			strcpy(&pathname[len], entp->d_name);

			// get info on the file
			struct stat sinfo;
			xx = lstat(pathname, &sinfo);
			if (xx != 0) {
				dbug_print("error", ("cannot stat %s %d",
				    pathname, errno));
				continue;
			}

			// skip unless a symbolic link
			if (!S_ISLNK(sinfo.st_mode))
				continue;

			// add this file system to the list
			subr_add_mount(allp, cachep->cache_cachedir(),
			    entp->d_name);
		}
		closedir(dirp);
		cachefs_dir_unlock(lockfd);
		allp->all_lock();
		cachep->cache_lock();
		cachep->cache_refdec();
		cachep->cache_unlock();
	}

	allp->all_unlock();
}

// -----------------------------------------------------------------
//
//			subr_fsck_cache
//
// Description:
//	Fixes the cache if necessary.
// Arguments:
//	cachedirp
// Returns:
//	Returns 0 for success !0 if the cache is not fixed.
// Preconditions:
//	precond(cachedirp)

int
subr_fsck_cache(const char *cachedirp)
{
	dbug_enter("subr_fsck_cache");

	dbug_precond(cachedirp);

	char *fsck_argv[4];
	int status = 0;
	pid_t pid;

	fsck_argv[1] = "fsck";
	fsck_argv[2] = (char *)cachedirp;
	fsck_argv[3] = NULL;

	dbug_print("info", ("about to fsck %s", cachedirp));

	/* fork */
	if ((pid = fork()) == -1) {
		dbug_print("error", ("could not fork fsck %d", errno));
		return (1);
	}

	if (pid == 0) {
		/* do the fsck */
		subr_doexec("cachefs", fsck_argv, "fsck");
	} else {
		/* wait for the child to exit */
		if (wait(&status) == -1) {
			dbug_print("error", ("fsck wait failed %d", errno));
			return (1);
		}

		if (!WIFEXITED(status)) {
			dbug_print("error", ("fsck did not exit"));
			return (1);
		}

		if (WEXITSTATUS(status) != 0) {
			dbug_print("error", ("fsck failed"));
			return (1);
		}
	}
	return (0);
}

// -----------------------------------------------------------------
//
//			subr_doexec
//
// Description:
//	Execs the specified program with the specified command line arguments.
//	This function never returns.
// Arguments:
//	fstype	type of file system
//	newargv	command line arguments
//	progp	name of program to exec
// Returns:
// Preconditions:
//	precond(fstype)
//	precond(newargv)
//	precond(progp)

void
subr_doexec(const char *fstype, char *newargv[], const char *progp)
{
	dbug_enter("subr_doexec");

	dbug_precond(fstype);
	dbug_precond(newargv);
	dbug_precond(progp);

#define	VFS_PATH	"/usr/lib/fs"
#define	ALT_PATH	"/etc/fs"

	char	full_path[PATH_MAX];
	char	alter_path[PATH_MAX];
	char	*vfs_path = VFS_PATH;
	char	*alt_path = ALT_PATH;

	/* build the full pathname of the fstype dependent command. */
	sprintf(full_path, "%s/%s/%s", vfs_path, fstype, progp);
	sprintf(alter_path, "%s/%s/%s", alt_path, fstype, progp);

	/* if the program exists */
	if (access(full_path, 0) == 0) {
		/* invoke the program */
		execv(full_path, &newargv[1]);

		/* if wrong permissions */
		if (errno == EACCES) {
			dbug_print("error", ("cannot execute %s %s",
				full_path, strerror(errno)));
		}

		/* if it did not work and the shell might make it */
		if (errno == ENOEXEC) {
			newargv[0] = "sh";
			newargv[1] = full_path;
			execv("/sbin/sh", &newargv[0]);
		}
	}

	/* try the alternate path */
	execv(alter_path, &newargv[1]);

	/* if wrong permissions */
	if (errno == EACCES) {
		dbug_print("error", ("cannot execute %s %s",
		    alter_path, strerror(errno)));
	}

	/* if it did not work and the shell might make it */
	if (errno == ENOEXEC) {
		newargv[0] = "sh";
		newargv[1] = alter_path;
		execv("/sbin/sh", &newargv[0]);
	}

	dbug_print("error", ("operation not applicable to FSType %s", fstype));
	_exit(1);
}

// -----------------------------------------------------------------
//
//			pr_err
//
// Description:
// Arguments:
//	fmt
// Returns:
// Preconditions:
//	precond(fmt)

void
pr_err(char *fmt, ...)
{
	va_list ap;

	va_start(ap);
	(void) fprintf(stderr, gettext("mount -F cachefs: "));
	(void) vfprintf(stderr, fmt, ap);
	(void) fprintf(stderr, "\n");
	va_end(ap);
}


//
//			subr_strdup
//
// Description:
//	Returns the string dupped.  Returns NULL if passed NULL.
//	Calls new to allocate memory.
// Arguments:
//	strp
// Returns:
// Preconditions:

char *
subr_strdup(const char *strp)
{
	char *retp = NULL;
	int len;

	if (strp) {
		len = strlen(strp) + 1;
		retp = new char[len];
		if (retp)
			strcpy(retp, strp);
	}
	return (retp);
}
