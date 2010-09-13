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
 * miscellaneous utilities
 */

#include <meta.h>
#include <zone.h>

static	int	meta_fd = -1;
static	major_t	meta_major;

/*
 * open administrative device
 */
int
open_admin(
	md_error_t	*ep
)
{
	struct stat	buf;

	/* if not already open */
	if (meta_fd < 0) {
		ulong_t	dversion = 0;

		/* try read/write fall back to readonly */
		if ((meta_fd = open(ADMSPECIAL, O_RDWR, 0)) < 0) {
			if (errno == ENOENT && getzoneid() != GLOBAL_ZONEID)
				return (mderror(ep, MDE_ZONE_ADMIN, NULL));
			if (errno != EACCES)
				return (mdsyserror(ep, errno, ADMSPECIAL));
			if ((meta_fd = open(ADMSPECIAL, O_RDONLY, 0)) < 0)
				return (mdsyserror(ep, errno, ADMSPECIAL));
		}

		/* get major */
		if (fstat(meta_fd, &buf) != 0)
			return (mdsyserror(ep, errno, ADMSPECIAL));
		meta_major = major(buf.st_rdev);

		/* check driver version */
		if (metaioctl(MD_IOCGVERSION, &dversion, ep, NULL) != 0)
			return (-1);
		if (dversion != MD_DVERSION)
			return (mderror(ep, MDE_DVERSION, NULL));
	}

	/* return fd */
	return (meta_fd);
}

int
close_admin(
	md_error_t	*ep
)
{
	if (meta_fd >= 0) {
		if (close(meta_fd) == -1)
			return (mdsyserror(ep, errno, ADMSPECIAL));
		meta_fd = -1;
	}

	return (0);
}

/*
 * Returns True if the md_dev64_t passed in is a metadevice.
 * Else it returns False.
 */
int
meta_dev_ismeta(
	md_dev64_t	dev
)
{
	int		fd;
	md_error_t	status = mdnullerror;

	fd = open_admin(&status);
	assert(fd >= 0);
	return (meta_getmajor(dev) == meta_major);
}


int
meta_get_nunits(md_error_t *ep)
{

	static set_t		max_nunits = 0;

	if (max_nunits == 0)
		if (metaioctl(MD_IOCGETNUNITS, &max_nunits, ep, NULL) != 0)
			return (-1);

	return (max_nunits);
}

md_dev64_t
metamakedev(minor_t mnum)
{
	int		fd;
	md_error_t	status = mdnullerror;

	fd = open_admin(&status);

	assert(fd >= 0);

	return (((md_dev64_t)meta_major << NBITSMINOR64) | mnum);
}
