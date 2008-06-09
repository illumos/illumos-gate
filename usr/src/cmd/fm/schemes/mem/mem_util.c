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

#include <mem.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mem.h>
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
mem_page_cmd(int cmd, nvlist_t *nvl)
{
	mem_page_t mpage;
	char *fmribuf;
	size_t fmrisz;
	int fd, rc, err;

	if ((fd = open("/dev/mem", O_RDONLY)) < 0)
		return (-1); /* errno is set for us */

	if ((errno = nvlist_size(nvl, &fmrisz, NV_ENCODE_NATIVE)) != 0 ||
	    fmrisz > MEM_FMRI_MAX_BUFSIZE ||
	    (fmribuf = fmd_fmri_alloc(fmrisz)) == NULL) {
		(void) close(fd);
		return (-1); /* errno is set for us */
	}

	if ((errno = nvlist_pack(nvl, &fmribuf, &fmrisz,
	    NV_ENCODE_NATIVE, 0)) != 0) {
		fmd_fmri_free(fmribuf, fmrisz);
		(void) close(fd);
		return (-1); /* errno is set for us */
	}

	mpage.m_fmri = fmribuf;
	mpage.m_fmrisz = fmrisz;

	if ((rc = ioctl(fd, cmd, &mpage)) < 0)
		err = errno;

	fmd_fmri_free(fmribuf, fmrisz);

	(void) close(fd);

	if (rc < 0) {
		errno = err;
		return (-1);
	}

	return (0);
}
