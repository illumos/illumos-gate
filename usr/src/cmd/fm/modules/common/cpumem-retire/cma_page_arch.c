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

/*
 * Page retirement can be an extended process due to the fact that a retirement
 * may not be possible when the original request is made.  The kernel will
 * repeatedly attempt to retire a given page, but will not let us know when the
 * page has been retired.  We therefore have to poll to see if the retirement
 * has been completed.  This poll is implemented with a bounded exponential
 * backoff to reduce the burden which we impose upon the system.
 *
 * To reduce the burden on fmd in the face of retirement storms, we schedule
 * all retries as a group.  In the simplest case, we attempt to retire a single
 * page.  When forced to retry, we initially schedule a retry at a configurable
 * interval t.  If the retry fails, we schedule another at 2 * t, and so on,
 * until t reaches the maximum interval (also configurable).  Future retries
 * for that page will occur with t equal to the maximum interval value.  We
 * will never give up on a retirement.
 *
 * With multiple retirements, the situation gets slightly more complicated.  As
 * indicated above, we schedule retries as a group.  We don't want to deny new
 * pages their short retry intervals, so we'll (re)set the retry interval to the
 * value appropriate for the newest page.
 */

#include <cma.h>

#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <strings.h>
#include <fm/fmd_api.h>
#include <fm/libtopo.h>
#include <sys/fm/protocol.h>
#include <sys/mem.h>

int
cma_page_cmd(fmd_hdl_t *hdl, int cmd, nvlist_t *nvl)
{
	mem_page_t mpage;
	char *fmribuf;
	size_t fmrisz;
	int fd, rc, err;

	if ((fd = open("/dev/mem", O_RDONLY)) < 0)
		return (-1); /* errno is set for us */

	if ((errno = nvlist_size(nvl, &fmrisz, NV_ENCODE_NATIVE)) != 0 ||
	    fmrisz > MEM_FMRI_MAX_BUFSIZE ||
	    (fmribuf = fmd_hdl_alloc(hdl, fmrisz, FMD_SLEEP)) == NULL) {
		(void) close(fd);
		return (-1); /* errno is set for us */
	}

	if ((errno = nvlist_pack(nvl, &fmribuf, &fmrisz,
	    NV_ENCODE_NATIVE, 0)) != 0) {
		fmd_hdl_free(hdl, fmribuf, fmrisz);
		(void) close(fd);
		return (-1); /* errno is set for us */
	}

	mpage.m_fmri = fmribuf;
	mpage.m_fmrisz = fmrisz;

	if ((rc = ioctl(fd, cmd, &mpage)) < 0)
		err = errno;

	fmd_hdl_free(hdl, fmribuf, fmrisz);

	(void) close(fd);

	if (rc < 0) {
		errno = err;
		return (-1);
	}

	return (0);
}
