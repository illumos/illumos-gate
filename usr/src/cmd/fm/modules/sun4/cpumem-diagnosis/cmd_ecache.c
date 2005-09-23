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
 * E-cache flushing
 *
 * Prior to clearing the UE cache, the CPU state code needs to ensure that the
 * CPU's E-cache has been flushed.  The flushing is handled by the routines in
 * in this file, which use the memory controller (mc) driver to perform the
 * flush.
 *
 * Matters are complicated by the fact that there isn't a well-known device name
 * for driver access - we have to hunt around for one.  Furthermore, the minor
 * nodes that are created correspond to individual memory controllers, and as
 * such can change during a DR.  We'll search for a memory controller device
 * during initialization just to make sure that we can do E$ flushing on this
 * platform, but we're also able to rescan if the device we found suddenly
 * disappears.
 */

#include <cmd_ecache.h>
#include <cmd.h>

#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <fm/fmd_api.h>
#include <sys/mc.h>
#include <sys/param.h>

static int
ecache_scan_dir(const char *dir, const char *pref, char *buf, size_t bufsz)
{
	struct dirent *dp;
	char path[MAXPATHLEN];
	DIR *mcdir;

	if ((mcdir = opendir(dir)) == NULL)
		return (-1); /* errno is set for us */

	while ((dp = readdir(mcdir)) != NULL) {
		struct mc_ctrlconf mcc;
		int fd;

		if (strncmp(dp->d_name, pref, strlen(pref)) != 0)
			continue;

		(void) snprintf(path, sizeof (path), "%s/%s", dir, dp->d_name);

		if ((fd = open(path, O_RDONLY)) < 0)
			continue;

		mcc.nmcs = 0;
		if (ioctl(fd, MCIOC_CTRLCONF, &mcc) >= 0 || errno != EINVAL ||
		    mcc.nmcs == 0) {
			(void) close(fd);
			continue;
		}

		(void) close(fd);
		(void) closedir(mcdir);

		if (strlen(path) >= bufsz)
			return (cmd_set_errno(ENOSPC));
		(void) strcpy(buf, path);
		return (0);
	}

	(void) closedir(mcdir);
	return (cmd_set_errno(ENOENT));
}

static int
ecache_find_device(char *buf, size_t bufsz)
{
	if (ecache_scan_dir("/dev/mc", "mc", buf, bufsz) != 0) {
		/*
		 * Yet more platform-specific hackery.  It's possible that the
		 * /dev/mc links could be out of date, and thus we may not be
		 * able to use any of them.  As a fallback, therefore, we're
		 * going to search a couple of well-known locations in /devices.
		 */
		const char *dir = "/devices/ssm@0,0";

		if (access(dir, R_OK) != 0)
			dir = "/devices";

		return (ecache_scan_dir(dir, "memory-controller", buf, bufsz));
	}

	return (0);
}

int
cmd_ecache_init(void)
{
	return (ecache_find_device(cmd.cmd_ecache_dev,
	    sizeof (cmd.cmd_ecache_dev)));
}

int
cmd_ecache_flush(int cpuid)
{
	int fd;

	if ((fd = open(cmd.cmd_ecache_dev, O_RDONLY)) < 0) {
		if (errno != ENOENT)
			return (-1); /* errno is set for us */

		/*
		 * A DR may have occurred, thus rendering our path invalid.
		 * Try once to find another one.
		 */
		if (cmd_ecache_init() < 0 ||
		    (fd = open(cmd.cmd_ecache_dev, O_RDONLY)) < 0)
			return (-1); /* errno is set for us */
	}

	if (ioctl(fd, MCIOC_ECFLUSH, cpuid) < 0) {
		int oserr = errno;
		(void) close(fd);
		return (cmd_set_errno(oserr));
	}

	(void) close(fd);
	return (0);
}
