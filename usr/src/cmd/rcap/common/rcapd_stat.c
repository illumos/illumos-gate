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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include "rcapd_stat.h"

/*
 * Return the pid of the writer of the statistics file.
 */
pid_t
stat_get_rcapd_pid(char *file)
{
	int fd;
	rcapd_stat_hdr_t hdr;
	char procfile[20];
	struct stat st;

	if ((fd = open(file, O_RDONLY)) < 0)
		return (-1);

	if (read(fd, &hdr, sizeof (hdr)) != sizeof (hdr)) {
		(void) close(fd);
		return (-1);
	}
	(void) close(fd);

	(void) snprintf(procfile, 20, "/proc/%d/psinfo", (int)hdr.rs_pid);
	if (stat(procfile, &st) == 0)
		return (hdr.rs_pid);
	else
		return (-1);
}
