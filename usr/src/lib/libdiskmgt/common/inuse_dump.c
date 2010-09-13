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
 * Checks for a match with the the dump slice.
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <synch.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/dumpadm.h>

#include "libdiskmgt.h"
#include "disks_private.h"

/* Cached file descriptor for /dev/dump. */
static int		dump_fd = -1;

static mutex_t		dump_lock = DEFAULTMUTEX;

/*
 * Check the dump device against the input slice.
 */
int
inuse_dump(char *slice, nvlist_t *attrs, int *errp)
{
	int		found = 0;
	int		fd;
	char		device[MAXPATHLEN];

	*errp = 0;
	if (slice == NULL) {
	    return (found);
	}

	/*
	 * We only want to open /dev/dump once instead of for every
	 * slice so we cache the open file descriptor.  The ioctl
	 * is cheap so we can do that for every slice.
	 */
	(void) mutex_lock(&dump_lock);

	if (dump_fd == -1) {
		if ((dump_fd = open("/dev/dump", O_RDONLY)) >= 0)
			(void) fcntl(dump_fd, F_SETFD, FD_CLOEXEC);
	}

	fd = dump_fd;

	(void) mutex_unlock(&dump_lock);

	if (fd != -1) {
		if (ioctl(fd, DIOCGETDEV, device) != -1) {
			if (strcmp(slice, device) == 0) {
				libdiskmgt_add_str(attrs, DM_USED_BY,
				    DM_USE_DUMP, errp);
				libdiskmgt_add_str(attrs, DM_USED_NAME,
				    DM_USE_DUMP, errp);
				found = 1;
			}
		}
	}

	return (found);
}
