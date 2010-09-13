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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Interfaces for getting device configuration data from kernel
 * through the devinfo driver.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdarg.h>
#include <unistd.h>
#include <libgen.h>
#include "libdevinfo.h"

/* Function Prototypes */
static int di_dli_open(char *, int, short, int);

#define	DLI_NAME	0x1

/*
 * Private hotplug interfaces to be used between cfgadm pci plugin and
 * devfsadm link generator.
 */


/*
 * returns a devlink info file name derived from <path>
 * callers need to free the returned string
 */
char *
di_dli_name(char *path)
{
#define	dliroot		"/etc/devices/dli/info."
#define	dliroot_len	(sizeof (dliroot) - 1)

	char *dlipath;
	int dlipathsz;
	char *basep;

	basep = basename(path);
	dlipathsz = strlen(basep) + dliroot_len + 1;
	dlipath = malloc(sizeof (char) * dlipathsz);

	(void) snprintf(dlipath, dlipathsz, "%s%s", dliroot, basep);
	dlipath[dlipathsz - 1] = '\0';
	return (dlipath);

#undef	dlipre
#undef	dlipre_len
#undef	dliroot
#undef	dliroot_len
}


static int
di_dli_open(char *path, int oflag, short l_type, int flags)
{
	int fd;
	char *dlipath, *dlipath_dir, *dlipath_dup;
	struct stat statbuf;
	int mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	flock_t lock;

	dlipath = (flags & DLI_NAME) ? di_dli_name(path) : (char *)path;
	dlipath_dup = strdup(dlipath);
	dlipath_dir = dirname(dlipath_dup);

	if (stat(dlipath_dir, &statbuf) < 0) {
		if (mkdirp(dlipath_dir,
		    S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) < 0) {
			fd = -1;
			goto OUT;
		}
	}

	fd = open(dlipath, oflag, mode);
	if (fd < 0)
		goto OUT;

	if (fchmod(fd, mode) < 0) {
		(void) close(fd);
		fd = -1;
		goto OUT;
	}

	bzero(&lock, sizeof (lock));
	lock.l_type = l_type;
	if (fcntl(fd, F_SETLKW, &lock) < 0) {
		(void) close(fd);
		fd = -1;
	}
OUT:
	free(dlipath_dup);
	if (flags & DLI_NAME)
		free(dlipath);
	return (fd);
}


int
di_dli_openr(char *path)
{
	return (di_dli_open(path, O_RDONLY, F_RDLCK, DLI_NAME));
}


int
di_dli_openw(char *path)
{
	return (di_dli_open(path, O_RDWR | O_SYNC | O_TRUNC | O_CREAT,
	    F_WRLCK, DLI_NAME));
}


void
di_dli_close(int fd)
{
	flock_t lock;
	if (fd < 0)
		return;

	bzero(&lock, sizeof (lock));
	lock.l_type = F_UNLCK;
	(void) fcntl(fd, F_SETLK, &lock);
	(void) close(fd);
}
