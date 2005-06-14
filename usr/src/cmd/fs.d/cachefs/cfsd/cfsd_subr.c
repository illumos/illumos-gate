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
 * Various support routines.
 */

#include <libintl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <wait.h>
#include <stdarg.h>
#include <limits.h>
#include <rpc/rpc.h>
#include <rpc/pmap_clnt.h> /* for pmap_unset */
#include <string.h> /* strcmp */
#include <signal.h>
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
#include <mdbug/mdbug.h>
#include <sys/fs/cachefs_fs.h>
#include <sys/fs/cachefs_dlog.h>
#include <sys/fs/cachefs_ioctl.h>
#include "cfsd.h"
#include "cfsd_kmod.h"
#include "cfsd_maptbl.h"
#include "cfsd_logfile.h"
#include "cfsd_fscache.h"
#include "cfsd_cache.h"
#include "cfsd_all.h"
#include <common/cachefsd.h>
#include <common/subr.h>

/* forward references */
void *subr_mount_thread(void *datap);
int subr_fsck_cache(const char *cachedirp);
void subr_doexec(const char *fstype, char *newargv[], const char *progp);

/*
 *			subr_add_mount
 *
 * Description:
 *	Adds the specified file system to the data structures.
 * Arguments:
 *	allp	ptr to set of data structures
 *	dirp	ptr to name of cache directory
 *	idp	ptr to id of file system cache in dirp
 * Returns:
 * Preconditions:
 *	precond(allp)
 *	precond(dirp)
 *	precond(idp)
 */
void
subr_add_mount(cfsd_all_object_t *all_object_p,
	const char *dirp,
	const char *idp)
{
	int xx;
	thread_t new_thread;
	cfsd_cache_object_t *cache_object_p;
	cfsd_fscache_object_t *fscache_object_p;

	dbug_enter("subr_add_mount");

	dbug_precond(all_object_p);
	dbug_precond(dirp);
	dbug_precond(idp);

	dbug_print(("info", "cachedir %s, cacheid %s", dirp, idp));

	/* find or create the cache object */
	all_lock(all_object_p);
	cache_object_p = all_cachelist_find(all_object_p, dirp);
	if (cache_object_p == NULL) {
		/* make the cache object */
		cache_object_p = cfsd_cache_create();
		xx = all_object_p->i_nextcacheid;
		xx = cache_setup(cache_object_p, dirp, xx);
		if (xx == 0) {
			dbug_print(("error", "invalid cache %s", dirp));
			cfsd_cache_destroy(cache_object_p);
			all_unlock(all_object_p);
			dbug_leave("subr_add_mount");
			return;
		}
		all_cachelist_add(all_object_p, cache_object_p);
		all_cachefstab_update(all_object_p);
	}
	cache_lock(cache_object_p);
	cache_object_p->i_refcnt++;
	cache_unlock(cache_object_p);
	all_unlock(all_object_p);

	/* find or create the fscache object */
	cache_lock(cache_object_p);
	fscache_object_p = cache_fscachelist_find(cache_object_p, idp);
	if (fscache_object_p == NULL) {
		/* make the fscache object and add it to the list */
		xx = cache_object_p->i_nextfscacheid;
		fscache_object_p = cfsd_fscache_create(idp, dirp, xx);
		cache_fscachelist_add(cache_object_p, fscache_object_p);
	} else {
		/* don't do any more if already mounted */
		fscache_lock(fscache_object_p);
		if (fscache_object_p->i_mounted) {
			cache_object_p->i_refcnt--;
			fscache_unlock(fscache_object_p);
			cache_unlock(cache_object_p);
			dbug_print(("info", "fscache already mounted"));
			dbug_leave("subr_add_mount");
			return;
		}
		fscache_unlock(fscache_object_p);
	}

	fscache_lock(fscache_object_p);
	fscache_object_p->i_refcnt++;
	fscache_unlock(fscache_object_p);
	cache_unlock(cache_object_p);

	/* init the fscache object with mount information */
	fscache_lock(fscache_object_p);
	fscache_setup(fscache_object_p);

	/* start the disconnect thread if necessary */
	if (fscache_object_p->i_disconnectable &&
	    fscache_object_p->i_mounted &&
	    (fscache_object_p->i_threaded == 0) &&
	    (strcmp(fscache_object_p->i_name, "rootcache") != 0)) {
		fscache_object_p->i_refcnt++;
		fscache_object_p->i_threaded = 1;
		xx = thr_create(NULL, 0, subr_mount_thread, fscache_object_p,
		    THR_DETACHED | THR_NEW_LWP, &new_thread);
		if (xx) {
			/* XXX cachefs kmod cannot allow transition */
			dbug_print(("error", "mount thr_create failed %d", xx));
			fscache_object_p->i_refcnt--;
			fscache_object_p->i_threaded = 0;
		}
		fscache_object_p->i_threadid = new_thread;
	}
	fscache_object_p->i_refcnt--;
	fscache_unlock(fscache_object_p);

	cache_lock(cache_object_p);
	cache_object_p->i_refcnt--;
	cache_unlock(cache_object_p);
	dbug_leave("subr_add_mount");
}

/*
 * ------------------------------------------------------------
 *			subr_mount_thread
 *
 * Description:
 *	Called when a thread is created via thr_create to process
 *	an fscache.
 * Arguments:
 *	datap	ptr to cfsd_fscache to process
 * Returns:
 *	Returns NULL.
 * Preconditions:
 *	precond(datap)
 */
void *
subr_mount_thread(void *datap)
{
	cfsd_fscache_object_t *fscache_object_p;

	dbug_enter("subr_mount_thread");
	dbug_precond(datap);

	fscache_object_p = (cfsd_fscache_object_t *)datap;

	fscache_process(fscache_object_p);

	fscache_lock(fscache_object_p);

	/* close down the message file descriptor */
	if (fscache_object_p->i_ofd >= 0) {
		if (close(fscache_object_p->i_ofd))
			dbug_print(("error", "cannot close fscache fd error %d",
			    errno));
		fscache_object_p->i_ofd = -1;
	}

	fscache_object_p->i_threaded = 0;
	fscache_object_p->i_refcnt--;
	fscache_unlock(fscache_object_p);

	dbug_leave("subr_mount_thread");
	return (NULL);
}

/*
 * ------------------------------------------------------------
 *			subr_cache_setup
 *
 * Description:
 *	Called once when the daemon starts up to get the current state
 *	of caches reflected in the daemon.
 * Arguments:
 *	allp
 * Returns:
 * Preconditions:
 *	precond(allp)
 */
void
subr_cache_setup(cfsd_all_object_t *all_object_p)
{
	cfsd_cache_object_t *cache_object_p;
	int fixcachefstab = 0;
	int xx;
	FILE *fin;
	char buf[MAXPATHLEN];
	struct mnttab minfo;
	struct mnttab mpref;
	char *cp;
	char *xcp;
	struct vfstab vinfo;
	struct vfstab vpref;
	size_t index;
	int lockfd;
	DIR *dirp;
	char pathname[MAXPATHLEN];
	int len;
	struct dirent64 *entp;
	struct stat64 sinfo;

	dbug_enter("subr_cache_setup");
	dbug_precond(all_object_p);

	all_lock(all_object_p);

	/* find all the caches indicated in the CACHEFSTAB file */
	fin = fopen(CACHEFSTAB, "r");
	if (fin == NULL) {
		dbug_print(("info", "%s does not exist", CACHEFSTAB));
	} else {
		while (fgets(buf, sizeof (buf), fin) != NULL) {
			if (strlen(buf) == 1)
				continue;
			/*
			 * if the line did not fit in the buffer
			 * it is invalid (i.e. no newline char)
			 */
			dbug_precond(buf[(strlen(buf) - 1)] == '\n');
			if (buf[(strlen(buf) - 1)] != '\n') {
#if 0
				/*
				 * if the line is invalid read until
				 * you get to the next line.
				 * we only need to do this if we are
				 * going to continue
				 */
				do {
					cp = fgets(buf, sizeof (buf), fin);
				} while ((cp != NULL) &&
				    (buf[(strlen(buf) - 1)] != '\n'));
#endif
				break;
			}
			buf[strlen(buf) - 1] = '\0';
			dbug_print(("info", "cachefstab cache \"%s\"", buf));
			cache_object_p = all_cachelist_find(all_object_p, buf);
			if (cache_object_p == NULL) {
				/* make the cache object */
				cache_object_p = cfsd_cache_create();
				xx = all_object_p->i_nextcacheid;
				xx = cache_setup(cache_object_p, buf, xx);
				if (xx == 0) {
					cfsd_cache_destroy(cache_object_p);
					fixcachefstab++;
				} else {
					all_cachelist_add(all_object_p,
					    cache_object_p);
				}
			} else {
				fixcachefstab++;
			}
		}
		if (fclose(fin))
			dbug_print(("err", "cannot close %s, %d",
			    CACHEFSTAB, errno));
	}

	/* read the mnttab file looking for caches we may have missed */
	fin = fopen(MNTTAB, "r");
	if (fin == NULL) {
		dbug_print(("info", "%s does not exist", MNTTAB));
	} else {
		mpref.mnt_special = NULL;
		mpref.mnt_mountp = NULL;
		mpref.mnt_fstype = "cachefs";
		mpref.mnt_mntopts = NULL;
		mpref.mnt_time = NULL;
		while ((xx = getmntany(fin, &minfo, &mpref)) != -1) {
			if (xx != 0)
				continue;
			cp = hasmntopt(&minfo, "cachedir=");
			if (cp == NULL)
				cp = "/cache"; /* XXX define in mount.c */
			else {
				cp += 9;
				xcp = strchr(cp, ',');
				if (xcp)
					*xcp = '\0';
			}
			dbug_print(("info", "mnttab cache \"%s\"", cp));
			cache_object_p = all_cachelist_find(all_object_p, cp);
			if (cache_object_p == NULL) {
				/* make the cache object */
				cache_object_p = cfsd_cache_create();
				xx = all_object_p->i_nextcacheid;
				xx = cache_setup(cache_object_p, cp, xx);
				if (xx == 0) {
					cfsd_cache_destroy(cache_object_p);
					fixcachefstab++;
				} else {
					all_cachelist_add(all_object_p,
					    cache_object_p);
				}
			} else {
				fixcachefstab++;
			}
		}
		if (fclose(fin))
			dbug_print(("err", "cannot close %s, %d",
			    MNTTAB, errno));
	}

	/* read the vfstab file looking for caches we may have missed */
	fin = fopen(VFSTAB, "r");
	if (fin == NULL) {
		dbug_print(("info", "%s does not exist", VFSTAB));
	} else {
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
			cp = strstr(vinfo.vfs_mntopts, "cachedir=");
			if (cp == NULL)
				cp = "/cache"; /* XXX define in mount.c */
			else {
				cp += 9;
				xcp = strchr(cp, ',');
				if (xcp)
					*xcp = '\0';
			}
			dbug_print(("info", "vfstab cache \"%s\"", cp));
			cache_object_p = all_cachelist_find(all_object_p, cp);
			if (cache_object_p == NULL) {
				/* make the cache object */
				cache_object_p = cfsd_cache_create();
				xx = all_object_p->i_nextcacheid;
				xx = cache_setup(cache_object_p, cp, xx);
				if (xx == 0) {
					cfsd_cache_destroy(cache_object_p);
				} else {
					all_cachelist_add(all_object_p,
					    cache_object_p);
					fixcachefstab++;
				}
			}
		}
		if (fclose(fin))
			dbug_print(("err", "cannot close %s, %d",
			    VFSTAB, errno));
	}

	/* fix up the CACHEFSTAB file if it is out of date */
	if (fixcachefstab)
		all_cachefstab_update(all_object_p);

	/*
	 * now for each cache we found,
	 * find all the file systems in the cache
	 */
	for (index = 0; index < all_object_p->i_cachecount; index++) {
		cache_object_p = all_cachelist_at(all_object_p, index);
		dbug_assert(cache_object_p);
		cache_lock(cache_object_p);
		cache_object_p->i_refcnt++;
		cache_unlock(cache_object_p);
		all_unlock(all_object_p);

		/* fix up the cache if necessary */
		xx = subr_fsck_cache(cache_object_p->i_cachedir);
		if (xx != 0) {
			dbug_print(("error", "could not fix up cache %d",
			    cache_object_p->i_cachedir));
			all_lock(all_object_p);
			cache_lock(cache_object_p);
			cache_object_p->i_refcnt--;
			cache_unlock(cache_object_p);
			continue;
		}

		/* lock out activity on the cache */
		lockfd = cachefs_dir_lock(cache_object_p->i_cachedir, 0);
		if (lockfd < 0) {
			dbug_print(("error", "cannot aquire cache lock on %s",
			    cache_object_p->i_cachedir));
			all_lock(all_object_p);
			cache_lock(cache_object_p);
			cache_object_p->i_refcnt--;
			cache_unlock(cache_object_p);
			continue;
		}

		/* open the cache directory */
		dirp = opendir(cache_object_p->i_cachedir);
		if (dirp == NULL) {
			dbug_print(("error", "cannot open dir %s",
			    cache_object_p->i_cachedir));
			cachefs_dir_unlock(lockfd);
			all_lock(all_object_p);
			cache_lock(cache_object_p);
			cache_object_p->i_refcnt--;
			cache_unlock(cache_object_p);
			continue;
		}

		strlcpy(pathname, cache_object_p->i_cachedir,
		    sizeof (pathname));
		strlcat(pathname, "/", sizeof (pathname));
		len = strlen(pathname);

		/* read the directory entries */
		while ((entp = readdir64(dirp)) != NULL) {
			/* skip . and .. */
			if ((strcmp(entp->d_name, ".") == 0) ||
			    (strcmp(entp->d_name, "..") == 0))
				continue;

			pathname[len] = '\0';
			strlcat(pathname, entp->d_name, sizeof (pathname));

			/* get info on the file */
			xx = lstat64(pathname, &sinfo);
			if (xx != 0) {
				dbug_print(("error",
				    "cannot stat %s %d", pathname, errno));
				continue;
			}

			/* skip unless a symbolic link */
			if (!S_ISLNK(sinfo.st_mode))
				continue;

			/* add this file system to the list */
			subr_add_mount(all_object_p, cache_object_p->i_cachedir,
			    entp->d_name);
		}
		if (closedir(dirp))
			dbug_print(("err", "cannot close dir, %d", errno));
		cachefs_dir_unlock(lockfd);
		all_lock(all_object_p);
		cache_lock(cache_object_p);
		cache_object_p->i_refcnt--;
		cache_unlock(cache_object_p);
	}

	all_unlock(all_object_p);
	dbug_leave("subr_cache_setup");
}

/*
 * ------------------------------------------------------------
 *			subr_fsck_cache
 *
 * Description:
 *	Fixes the cache if necessary.
 * Arguments:
 *	cachedirp
 * Returns:
 *	Returns 0 for success !0 if the cache is not fixed.
 * Preconditions:
 *	precond(cachedirp)
 */
int
subr_fsck_cache(const char *cachedirp)
{
	char *fsck_argv[4];
	int status = 0;
	pid_t pid;

	dbug_enter("subr_fsck_cache");

	dbug_precond(cachedirp);

	fsck_argv[1] = "fsck";
	fsck_argv[2] = (char *)cachedirp;
	fsck_argv[3] = NULL;

	dbug_print(("info", "about to fsck %s", cachedirp));

	/* fork */
	if ((pid = fork()) == -1) {
		dbug_print(("error", "could not fork fsck %d", errno));
		dbug_leave("subr_fsck_cache");
		return (1);
	}

	if (pid == 0) {
		/* do the fsck */
		subr_doexec("cachefs", fsck_argv, "fsck");
	} else {
		/* wait for the child to exit */
		if (waitpid(pid, &status, 0) == -1) {
			dbug_print(("error", "fsck wait failed %d", errno));
			dbug_leave("subr_fsck_cache");
			return (1);
		}

		if (!WIFEXITED(status)) {
			dbug_print(("error", "fsck did not exit"));
			dbug_leave("subr_fsck_cache");
			return (1);
		}

		if (WEXITSTATUS(status) != 0) {
			dbug_print(("error", "fsck failed"));
			dbug_leave("subr_fsck_cache");
			return (1);
		}
	}
	dbug_leave("subr_fsck_cache");
	return (0);
}

/*
 * ------------------------------------------------------------
 *			subr_doexec
 *
 * Description:
 *	Execs the specified program with the specified command line arguments.
 *	This function never returns.
 * Arguments:
 *	fstype	type of file system
 *	newargv	command line arguments
 *	progp	name of program to exec
 * Returns:
 * Preconditions:
 *	precond(fstype)
 *	precond(newargv)
 *	precond(progp)
 */
void
subr_doexec(const char *fstype, char *newargv[], const char *progp)
{
#define	VFS_PATH	"/usr/lib/fs"
#define	ALT_PATH	"/etc/fs"

	char	full_path[MAXPATHLEN];
	char	alter_path[MAXPATHLEN];
	char	*vfs_path = VFS_PATH;
	char	*alt_path = ALT_PATH;

	dbug_enter("subr_doexec");

	dbug_precond(fstype);
	dbug_precond(newargv);
	dbug_precond(progp);

	/* build the full pathname of the fstype dependent command. */
	snprintf(full_path, sizeof (full_path), "%s/%s/%s", vfs_path,
	    fstype, progp);
	snprintf(alter_path, sizeof (alter_path), "%s/%s/%s", alt_path,
	    fstype, progp);

	/* if the program exists */
	if (access(full_path, X_OK) == 0) {
		/* invoke the program */
		execv(full_path, &newargv[1]);

		/* if wrong permissions */
		if (errno == EACCES) {
			dbug_print(("error", "cannot execute %s %s",
			    full_path, strerror(errno)));
		}

#ifdef OBSOLETE
		/* if it did not work and the shell might make it */
		if (errno == ENOEXEC) {
			newargv[0] = "sh";
			newargv[1] = full_path;
			execv("/sbin/sh", &newargv[0]);
		}
#endif
	}

#ifdef OBSOLETE
	/* try the alternate path */
	execv(alter_path, &newargv[1]);

	/* if wrong permissions */
	if (errno == EACCES) {
		dbug_print(("error", "cannot execute %s %s",
		    alter_path, strerror(errno)));
	}

	/* if it did not work and the shell might make it */
	if (errno == ENOEXEC) {
		newargv[0] = "sh";
		newargv[1] = alter_path;
		execv("/sbin/sh", &newargv[0]);
	}

	dbug_print(("error", "operation not applicable to FSType %s", fstype));
#endif
	dbug_leave("subr_doexec");
	_exit(1);
}

/*
 * ------------------------------------------------------------
 *			pr_err
 *
 * Description:
 * Arguments:
 *	fmt
 * Returns:
 * Preconditions:
 *	precond(fmt)
 */
void
pr_err(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	(void) fprintf(stderr, "cachefsd -F cachefs: ");
	(void) vfprintf(stderr, fmt, ap);
	(void) fprintf(stderr, "\n");
	va_end(ap);
}


/*
 *			subr_strdup
 *
 * Description:
 *	Returns the string dupped.  Returns NULL if passed NULL.
 *	Calls new to allocate memory.
 * Arguments:
 *	strp
 * Returns:
 * Preconditions:
 */
char *
subr_strdup(const char *strp)
{
	char *retp = NULL;
	int len;

	if (strp) {
		len = strlen(strp) + 1;
		retp = cfsd_calloc(len);
		if (retp)
			strlcpy(retp, strp, len);
	}
	return (retp);
}
/*
 * -----------------------------------------------------------------
 *			cfsd_calloc
 *
 * Description:
 *	allocates memory of a given size, will retry if error
 * Arguments:
 *	size
 * Returns:
 *	pointer to memory
 * Preconditions:
 *	precond(size)
 */

void *
cfsd_calloc(int size)
{
	void *alloc_ptr;

	dbug_enter("cfsd_calloc");
	dbug_precond(size);

	/* allocate memory, if calloc fails sleep and retry */
	while ((alloc_ptr = calloc(size, 1)) == NULL) {
		cfsd_sleep(5);
	}

	dbug_leave("cfsd_calloc");
	return (alloc_ptr);
}
/*
 * -----------------------------------------------------------------
 *			cfsd_free
 *
 * Description:
 *	frees memory allocated from cfsd_calloc
 * Arguments:
 *	pointer to memeory
 * Returns:
 *	none
 * Preconditions:
 *	precond(size)
 */

void
cfsd_free(void *free_ptr)
{
	dbug_enter("cfsd_free");
	dbug_precond(free_ptr);

	/* free memory */
	if (free_ptr)
		free(free_ptr);

	dbug_leave("cfsd_free");
}
/*
 * -----------------------------------------------------------------
 *			cfsd_sleep
 *
 * Description:
 *	A reimplemenation of the sleep(3c) function call using
 *	cond_timedwait.
 *	Problem withe sleep(3c) hanging. May return early.
 * Arguments:
 *	sec	number of seconds to sleep for
 * Returns:
 * Preconditions:
 */

void
cfsd_sleep(int sec)
{
	cond_t cv;
	mutex_t mt;
	timestruc_t reltime;

	dbug_enter("cfsd_sleep");

	if (sec > 0) {
		mutex_init(&mt, USYNC_THREAD, NULL);
		cond_init(&cv, USYNC_THREAD, 0);

		reltime.tv_sec = sec;
		reltime.tv_nsec = 0;

		mutex_lock(&mt);
		cond_reltimedwait(&cv, &mt, &reltime);
		mutex_unlock(&mt);

		cond_destroy(&cv);
		mutex_destroy(&mt);
	}
	dbug_leave("cfsd_sleep");
}
