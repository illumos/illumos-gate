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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <userdefs.h>
#include <errno.h>
#include <strings.h>
#include <stdlib.h>
#include <sys/mntent.h>
#include <sys/mnttab.h>
#include <libzfs.h>
#include <libgen.h>
#include <limits.h>
#include <deflt.h>

#include "funcs.h"
#include "messages.h"

#define	SBUFSZ	256

#define	DEFAULT_USERADD	"/etc/default/useradd"

static int rm_homedir();
static char *get_mnt_special();

static char cmdbuf[ SBUFSZ ];	/* buffer for system call */
static char dhome[ PATH_MAX + 1 ]; /* buffer for dirname */
static char bhome[ PATH_MAX + 1 ]; /* buffer for basename */
static char pdir[ PATH_MAX + 1 ]; /* parent directory */
static libzfs_handle_t *g_zfs = NULL;

/*
 * Create a home directory and populate with files from skeleton
 * directory.
 */
int
create_home(char *homedir, char *skeldir, uid_t uid, gid_t gid, int flags)
		/* home directory to create */
		/* skel directory to copy if indicated */
		/* uid of new user */
		/* group id of new user */
		/* miscellaneous flags */
{
	struct stat stbuf;
	char *dataset;
	char *dname, *bname, *rp;
	int created_fs = 0;

	rp = realpath(homedir, NULL);
	if (rp && (strcmp(rp, "/") == 0)) {
		return (EX_HOMEDIR);
	}

	(void) strcpy(dhome, homedir);
	(void) strcpy(bhome, homedir);
	dname = dirname(dhome);
	bname = basename(bhome);
	(void) strcpy(pdir, dname);

	if ((stat(pdir, &stbuf) != 0) || !S_ISDIR(stbuf.st_mode)) {
		errmsg(M_OOPS, "access the parent directory", strerror(errno));
		return (EX_HOMEDIR);
	}

	if ((strcmp(stbuf.st_fstype, MNTTYPE_ZFS) == 0) &&
	    (flags & MANAGE_ZFS)) {
		if (g_zfs == NULL)
			g_zfs = libzfs_init();
		if (g_zfs == NULL) {
			errmsg(M_OOPS, "libzfs_init failure", strerror(errno));
			return (EX_HOMEDIR);
		}
		if ((dataset = get_mnt_special(pdir, stbuf.st_fstype))
		    != NULL) {
			char nm[ZFS_MAX_DATASET_NAME_LEN];
			zfs_handle_t *zhp;

			(void) snprintf(nm, sizeof (nm), "%s/%s",
			    dataset, bname);

			if ((zfs_create(g_zfs, nm, ZFS_TYPE_FILESYSTEM, NULL)
				!= 0) ||
			    ((zhp = zfs_open(g_zfs, nm, ZFS_TYPE_FILESYSTEM)) ==
			    NULL)) {
				errmsg(M_OOPS, "create the home directory",
				    libzfs_error_description(g_zfs));
				libzfs_fini(g_zfs);
				g_zfs = NULL;
				return (EX_HOMEDIR);
			}

			if (zfs_mount(zhp, NULL, 0) != 0) {
				errmsg(M_OOPS, "mount the home directory",
				    libzfs_error_description(g_zfs));
				(void) zfs_destroy(zhp, B_FALSE);
				zfs_close(zhp);
				libzfs_fini(g_zfs);
				g_zfs = NULL;
				return (EX_HOMEDIR);
			}

			zfs_close(zhp);

			if (chmod(homedir,
				S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH) != 0) {
				errmsg(M_OOPS,
				    "change permissions of home directory",
				    strerror(errno));
				libzfs_fini(g_zfs);
				g_zfs = NULL;
				return (EX_HOMEDIR);
			}

			created_fs = 1;
		} else {
			errmsg(M_NO_ZFS_MOUNTPOINT, pdir);
		}
	}

	if (!created_fs) {
		if (mkdir(homedir, S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH)
			!= 0) {
			errmsg(M_OOPS, "create the home directory",
			    strerror(errno));
			if (g_zfs != NULL) {
				libzfs_fini(g_zfs);
				g_zfs = NULL;
			}
			return (EX_HOMEDIR);
		}
	}

	if (chown(homedir, uid, gid) != 0) {
		errmsg(M_OOPS, "change ownership of home directory",
		    strerror(errno));
		if (g_zfs != NULL) {
			libzfs_fini(g_zfs);
			g_zfs = NULL;
		}
		return (EX_HOMEDIR);
	}

	if (skeldir != NULL) {
		/* copy the skel_dir into the home directory */
		(void) sprintf(cmdbuf, "cd %s && find . -print | cpio -pd %s",
			skeldir, homedir);

		if (system(cmdbuf) != 0) {
			errmsg(M_OOPS, "copy skeleton directory into home "
			    "directory", strerror(errno));
			(void) rm_homedir(homedir, flags);
			if (g_zfs != NULL) {
				libzfs_fini(g_zfs);
				g_zfs = NULL;
			}
			return (EX_HOMEDIR);
		}

		/* make sure contents in the home dirctory have correct owner */
		(void) sprintf(cmdbuf,
		    "cd %s && find . -exec chown %ld:%ld {} \\;",
		    homedir, uid, gid);
		if (system(cmdbuf) != 0) {
			errmsg(M_OOPS,
			    "change owner and group of files home directory",
			    strerror(errno));
			(void) rm_homedir(homedir, flags);
			if (g_zfs != NULL) {
				libzfs_fini(g_zfs);
				g_zfs = NULL;
			}
			return (EX_HOMEDIR);
		}

	}
	if (g_zfs != NULL) {
		libzfs_fini(g_zfs);
		g_zfs = NULL;
	}
	return (EX_SUCCESS);
}

/* Remove a home directory structure */
int
rm_homedir(char *dir, int flags)
{
	struct stat stbuf;
	char *nm, *rp;

	rp = realpath(dir, NULL);
	if (rp && (strcmp(rp, "/") == 0)) {
		return (0);
	}

	if ((stat(dir, &stbuf) != 0) || !S_ISDIR(stbuf.st_mode))
		return (0);

	if ((strcmp(stbuf.st_fstype, MNTTYPE_ZFS) == 0) &&
	    (flags & MANAGE_ZFS)) {
		if (g_zfs == NULL)
			g_zfs = libzfs_init();

		if (g_zfs == NULL) {
			errmsg(M_OOPS, "libzfs_init failure", strerror(errno));
			return (EX_HOMEDIR);
		}

		if ((nm = get_mnt_special(dir, stbuf.st_fstype)) != NULL) {
			zfs_handle_t *zhp;

			if ((zhp = zfs_open(g_zfs, nm, ZFS_TYPE_FILESYSTEM))
			    != NULL) {
				if ((zfs_unmount(zhp, NULL, 0) == 0) &&
				    (zfs_destroy(zhp, B_FALSE) == 0)) {
					zfs_close(zhp);
					libzfs_fini(g_zfs);
					g_zfs = NULL;
					return (0);
				}

				errmsg(M_OOPS, "destroy the home directory",
				    libzfs_error_description(g_zfs));

				(void) zfs_mount(zhp, NULL, 0);
				zfs_close(zhp);

				libzfs_fini(g_zfs);
				g_zfs = NULL;
				return (EX_HOMEDIR);
			}
		}
	}

	(void) sprintf(cmdbuf, "rm -rf %s", dir);

	if (g_zfs != NULL) {
		libzfs_fini(g_zfs);
		g_zfs = NULL;
	}

	return (system(cmdbuf));
}

int
rm_files(char *homedir, char *user, int flags)
{
	if (rm_homedir(homedir, flags) != 0) {
		errmsg(M_RMFILES);
		return (EX_HOMEDIR);
	}

	return (EX_SUCCESS);
}

int
get_default_zfs_flags()
{
	int flags = 0;

	if (defopen(DEFAULT_USERADD) == 0) {
		char *defptr;

		if ((defptr = defread(MANAGE_ZFS_OPT)) != NULL) {
			char let = tolower(*defptr);

			switch (let) {
				case 'y':	/* yes */
					flags |= MANAGE_ZFS;
				case 'n':	/* no */
					break;
			}
		}
		(void) defopen((char *)NULL);
	}
	return (flags);
}

/* Get the name of a mounted filesytem */
char *
get_mnt_special(char *mountp, char *fstype)
{
	struct mnttab entry, search;
	char *special = NULL;
	FILE *fp;

	search.mnt_special = search.mnt_mntopts = search.mnt_time = NULL;
	search.mnt_mountp = mountp;
	search.mnt_fstype = fstype;

	if ((fp = fopen(MNTTAB, "r")) != NULL) {
		if (getmntany(fp, &entry, &search) == 0)
			special = entry.mnt_special;

		(void) fclose(fp);
	}

	return (special);
}
