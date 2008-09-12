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

/*
 * get timestamp from device
 */

#include <meta.h>

/*
 * get timestamp
 */
int
getdevstamp(
	mddrivename_t	*dnp,
	time_t		*stamp,		/* return timestamp here */
	md_error_t	*ep
)
{
	int		fd;
	int		partno;
	struct extvtoc	vtocbuf;
	mdname_t	*np;

	if ((np = metaslicename(dnp, MD_SLICE0, ep)) == NULL)
		return (-1);

	/* open given device */
	if ((fd = open(np->rname, O_RDONLY | O_NDELAY, 0)) < 0)
		return (mdsyserror(ep, errno, np->cname));

	/* re-read vtoc */
	if (meta_getvtoc(fd, np->cname, &vtocbuf, &partno, ep) == -1) {
		(void) close(fd);
		return (-1);
	}

	/* close device */
	(void) close(fd);	/* sd/ssd bug */

	/* return timestamp, success */
	*stamp = vtocbuf.timestamp[partno];
	return (0);
}

/*
 * returns
 *	0 on success,
 * 	ENOTSUP if it's not a device with a vtoc
 *	-1 on failure
 */
int
setdevstamp(
	mddrivename_t	*dnp,
	time_t		*stamp,		/* returned timestamp */
	md_error_t	*ep
)
{
	int		fd;
	int		partno;
	struct extvtoc	vtocbuf;
	time_t		now = time(NULL);
	mdname_t	*np;

	if ((np = metaslicename(dnp, MD_SLICE0, ep)) == NULL)
		return (-1);

	/* open for vtoc */
	if ((fd = open(np->rname, O_RDWR | O_NDELAY, 0)) < 0)
		return (mdsyserror(ep, errno, np->cname));

	if (meta_getvtoc(fd, np->cname, &vtocbuf, &partno, ep) == -1) {
		(void) close(fd);
		if (partno == VT_ENOTSUP)
			return (ENOTSUP);
		else
			return (-1);
	}

	*stamp = vtocbuf.timestamp[partno] = now;

	if (meta_setvtoc(fd, np->cname, &vtocbuf, ep) == -1) {
		(void) close(fd);
		return (-1);
	}

	/* Clear the timestamp */
	vtocbuf.timestamp[partno] = 0;

	if (meta_getvtoc(fd, np->cname, &vtocbuf, &partno, ep) == -1) {
		(void) close(fd);
		return (-1);
	}

	(void) close(fd);	/* sd/ssd bug */

	if (*stamp != vtocbuf.timestamp[partno])
		return (mddeverror(ep, MDE_CANTVERIFY_VTOC, NODEV64,
		    np->cname));

	return (0);
}
