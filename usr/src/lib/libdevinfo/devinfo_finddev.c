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

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <thread.h>
#include <synch.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <dirent.h>
#include <regex.h>
#include <errno.h>
#include <stdarg.h>
#include <libdevinfo.h>
#include <zone.h>
#include <sys/modctl.h>
#include <syslog.h>
#include <sys/stat.h>
#include <assert.h>


struct finddevhdl {
	int	npaths;
	int	curpath;
	char	**paths;
};


#define	GLOBAL_DEV_PATH(devpath)			\
	((getzoneid() == GLOBAL_ZONEID) &&		\
	    ((strcmp(devpath, "/dev") == 0) ||		\
	    (strncmp(devpath, "/dev/", strlen("/dev/")) == 0)))

/*
 * Return true if a device exists
 * If the path refers into the /dev filesystem, use a
 * private interface to query if the device exists but
 * without triggering an implicit reconfig if it does not.
 * Note: can only function properly with absolute pathnames
 * and only functions for persisted global /dev names, ie
 * those managed by devfsadm.  For paths other than
 * /dev, stat(2) is sufficient.
 */
int
device_exists(const char *devname)
{
	int	rv;
	struct stat st;

	if (GLOBAL_DEV_PATH(devname)) {
		rv = modctl(MODDEVEXISTS, devname, strlen(devname));
		return ((rv == 0) ? 1 : 0);
	}
	if (stat(devname, &st) == 0)
		return (1);
	return (0);
}


/*
 * Use the standard library readdir to read the contents of
 * directories on alternate root mounted filesystems.
 * Return results as per dev_readdir_devfs().
 *
 * The directory is traversed twice.  First, to calculate
 * the size of the buffer required; second, to copy the
 * directory contents into the buffer.  If the directory
 * contents grow in between passes, which should almost
 * never happen, start over again.
 */
static int
finddev_readdir_alt(const char *path, finddevhdl_t *handlep)
{
	struct finddevhdl *handle;
	DIR *dir;
	struct dirent *dp;
	size_t n;

	*handlep = NULL;
	if ((dir = opendir(path)) == NULL)
		return (ENOENT);

restart:
	handle = calloc(1, sizeof (struct finddevhdl));
	if (handle == NULL) {
		(void) closedir(dir);
		return (ENOMEM);
	}

	handle->npaths = 0;
	handle->curpath = 0;
	handle->paths = NULL;

	n = 0;
	rewinddir(dir);
	while ((dp = readdir(dir)) != NULL) {
		if ((strcmp(dp->d_name, ".") == 0) ||
		    (strcmp(dp->d_name, "..") == 0))
			continue;
		n++;
	}

	handle->npaths = n;
	handle->paths = calloc(n, sizeof (char *));
	if (handle->paths == NULL) {
		free(handle);
		(void) closedir(dir);
		return (ENOMEM);
	}

	n = 0;
	rewinddir(dir);
	while ((dp = readdir(dir)) != NULL) {
		if ((strcmp(dp->d_name, ".") == 0) ||
		    (strcmp(dp->d_name, "..") == 0))
			continue;
		if (n == handle->npaths) {
			/*
			 * restart if directory contents have out-grown
			 * buffer allocated in the first pass.
			 */
			finddev_close((finddevhdl_t)handle);
			goto restart;
		}
		handle->paths[n] = strdup(dp->d_name);
		if (handle->paths[n] == NULL) {
			(void) closedir(dir);
			finddev_close((finddevhdl_t)handle);
			return (ENOMEM);
		}
		n++;
	}
	(void) closedir(dir);
	*handlep = (finddevhdl_t)handle;
	return (0);
}

/*
 * Use of the dev filesystem's private readdir does not trigger
 * the implicit device reconfiguration.
 *
 * Note: only useable with paths mounted on an instance of the
 * dev filesystem.
 *
 * Does not return the . and .. entries.
 * Empty directories are returned as an zero-length list.
 * ENOENT is returned as a NULL list pointer.
 */
static int
finddev_readdir_devfs(const char *path, finddevhdl_t *handlep)
{
	struct finddevhdl	*handle;
	int			n;
	int			rv;
	int64_t			bufsiz;
	char			*pathlist;
	char			*p;
	int			len;

	*handlep = NULL;
	handle = calloc(1, sizeof (struct finddevhdl));
	if (handle == NULL)
		return (ENOMEM);

	handle->npaths = 0;
	handle->curpath = 0;
	handle->paths = NULL;

	rv = modctl(MODDEVREADDIR, path, strlen(path), NULL, &bufsiz);
	if (rv != 0) {
		free(handle);
		return (rv);
	}

	for (;;) {
		assert(bufsiz != 0);
		if ((pathlist = malloc(bufsiz)) == NULL) {
			free(handle);
			return (ENOMEM);
		}

		rv = modctl(MODDEVREADDIR, path, strlen(path),
		    pathlist, &bufsiz);
		if (rv == 0) {
			for (n = 0, p = pathlist;
			    (len = strlen(p)) > 0; p += len+1) {
				n++;
			}
			handle->npaths = n;
			handle->paths = calloc(n, sizeof (char *));
			if (handle->paths == NULL) {
				free(handle);
				free(pathlist);
				return (ENOMEM);
			}
			for (n = 0, p = pathlist;
			    (len = strlen(p)) > 0; p += len+1, n++) {
				handle->paths[n] = strdup(p);
				if (handle->paths[n] == NULL) {
					finddev_close((finddevhdl_t)handle);
					free(pathlist);
					return (ENOMEM);
				}
			}
			*handlep = (finddevhdl_t)handle;
			free(pathlist);
			return (0);
		}
		free(pathlist);
		switch (errno) {
		case EAGAIN:
			break;
		case ENOENT:
		default:
			free(handle);
			return (errno);
		}
	}
	/*NOTREACHED*/
}

int
finddev_readdir(const char *path, finddevhdl_t *handlep)
{
	if (GLOBAL_DEV_PATH(path)) {
		return (finddev_readdir_devfs(path, handlep));
	}
	return (finddev_readdir_alt(path, handlep));
}

/*
 * Return true if a directory is empty
 * Use the standard library readdir to determine if a directory is
 * empty.
 */
static int
finddev_emptydir_alt(const char *path)
{
	DIR		*dir;
	struct dirent	*dp;

	if ((dir = opendir(path)) == NULL)
		return (ENOENT);

	while ((dp = readdir(dir)) != NULL) {
		if ((strcmp(dp->d_name, ".") == 0) ||
		    (strcmp(dp->d_name, "..") == 0))
			continue;
		(void) closedir(dir);
		return (0);		/* not empty */
	}
	(void) closedir(dir);
	return (1);			/* empty */
}

/*
 * Use of the dev filesystem's private readdir does (not trigger
 * the implicit device reconfiguration) to determine if a directory
 * is empty.
 *
 * Note: only useable with paths mounted on an instance of the
 * dev filesystem.
 *
 * Does not return the . and .. entries.
 * Empty directories are returned as an zero-length list.
 * ENOENT is returned as a NULL list pointer.
 */
static int
finddev_emptydir_devfs(const char *path)
{
	int	rv;
	int	empty;

	rv = modctl(MODDEVEMPTYDIR, path, strlen(path), &empty);
	if (rv == 0) {
		return (empty);
	}
	return (0);
}

int
finddev_emptydir(const char *path)
{
	if (GLOBAL_DEV_PATH(path)) {
		return (finddev_emptydir_devfs(path));
	}
	return (finddev_emptydir_alt(path));
}

void
finddev_close(finddevhdl_t arg)
{
	struct finddevhdl *handle = (struct finddevhdl *)arg;
	int i;

	for (i = 0; i < handle->npaths; i++) {
		if (handle->paths[i])
			free(handle->paths[i]);
	}
	free(handle->paths);
	free(handle);
}

const char *
finddev_next(finddevhdl_t arg)
{
	struct finddevhdl *handle = (struct finddevhdl *)arg;
	const char *path = NULL;

	if (handle->curpath < handle->npaths) {
		path = handle->paths[handle->curpath];
		handle->curpath++;
	}
	return (path);
}
