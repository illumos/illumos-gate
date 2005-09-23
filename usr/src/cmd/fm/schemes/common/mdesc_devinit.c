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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <strings.h>
#include <sys/mdesc.h>
#include <fm/fmd_fmri.h>
#include <sys/param.h>

/*
 * Initialize sun4v machine descriptor file for subsequent use.
 * If the open fails (most likely because file doesn't exit), or if
 * initialization fails, deallocate any storage and return NULL.
 *
 * If the open succeeds and initialization also succeeds, the returned value is
 * a pointer to an md_impl_t, whose 1st element points to the buffer where
 * the full mdesc has been read in.  The size of this buffer is returned
 * as 'bufsiz'.  Caller is responsible for deallocating BOTH of these objects.
 */

#define	MDESC_PATH	"%s/devices/pseudo/mdesc@0:mdesc"

md_t *
mdesc_devinit(size_t *bufsiz)
{
	int fh;
	size_t size;
	uint8_t *bufp;
	char mdescpath[MAXPATHLEN];

	(void) snprintf(mdescpath, sizeof (mdescpath), MDESC_PATH,
	    fmd_fmri_get_rootdir());

	fh = open(mdescpath, O_RDONLY, 0);
	if (fh < 0)
		return (NULL);

	if (ioctl(fh, MDESCIOCGSZ, &size) < 0) {
		fmd_fmri_warn("cannot determine mdesc size\n");
		(void) close(fh);
		return (NULL);
	}

	bufp = fmd_fmri_alloc(size);

	if (read(fh, bufp, size) < 0) {
		fmd_fmri_warn("failed reading machine description\n");
		fmd_fmri_free(bufp, size);
		(void) close(fh);
		return (NULL);
	}

	*bufsiz = size;
	(void) close(fh);
	return (md_init_intern((uint64_t *)bufp,
	    fmd_fmri_alloc, fmd_fmri_free));
}
