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

#include <mem.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <fm/fmd_fmri.h>

void
mem_strarray_free(char **arr, size_t dim)
{
	int i;

	for (i = 0; i < dim; i++) {
		if (arr[i] != NULL)
			fmd_fmri_strfree(arr[i]);
	}
	fmd_fmri_free(arr, sizeof (char *) * dim);
}

int
mem_page_cmd(int cmd, uint64_t addr)
{
	int fd, rc, err;

	if ((fd = open("/dev/mem", O_RDONLY)) < 0)
		return (-1); /* errno is set for us */

	if ((rc = ioctl(fd, cmd, &addr)) < 0)
		err = errno;

	(void) close(fd);

	if (rc < 0) {
		errno = err;
		return (-1);
	}

	return (0);
}
