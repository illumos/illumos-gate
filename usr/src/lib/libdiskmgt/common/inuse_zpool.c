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
 * Attempt to dynamically link in the ZFS libzfs.so.1 so that we can
 * see if there are any ZFS zpools on any of the slices.
 */

#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <thread.h>
#include <synch.h>
#include <dlfcn.h>
#include <link.h>
#include <ctype.h>

#include "libdiskmgt.h"
#include "disks_private.h"

/*
 * Pointers to libzfs.so functions that we dynamically resolve.
 */
static	int	(*zfsdl_zpool_in_use)(int fd, char **desc, char **name);

static mutex_t			init_lock = DEFAULTMUTEX;
static rwlock_t			zpool_lock = DEFAULTRWLOCK;
static	int			initialized = 0;

static void	*init_zpool();

int
inuse_zpool(char *slice, nvlist_t *attrs, int *errp)
{
	int		found = 0;
	char		*desc, *name;
	int		fd;

	*errp = 0;
	if (slice == NULL) {
	    return (found);
	}

	(void) mutex_lock(&init_lock);

	/*
	 * Dynamically load libzfs
	 */
	if (!initialized) {
		if (!init_zpool()) {
			(void) mutex_unlock(&init_lock);
			return (found);
		}
		initialized = 1;
	}
	(void) mutex_unlock(&init_lock);
	(void) rw_rdlock(&zpool_lock);
	if ((fd = open(slice, O_RDONLY)) > 0) {
		if (zfsdl_zpool_in_use(fd, &desc, &name)) {
			libdiskmgt_add_str(attrs, DM_USED_BY,
				DM_USE_ZPOOL, errp);
			libdiskmgt_add_str(attrs, DM_USED_NAME,
				name, errp);
			found = 1;
		}
	}
	(void) rw_unlock(&zpool_lock);

	return (found);
}

/*
 * Try to dynamically link the zfs functions we need.
 */
static void*
init_zpool()
{
	void	*lh = NULL;

	if ((lh = dlopen("libzfs.so", RTLD_NOW)) == NULL) {
		return (lh);
	}
	/*
	 * Instantiate the functions needed to get zpool configuration
	 * data
	 */
	if ((zfsdl_zpool_in_use = (int (*)(int, char **, char **))dlsym(lh,
	    "zpool_in_use")) == NULL) {
		(void) dlclose(lh);
		return (NULL);
	}

	return (lh);
}
