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
 * mirror operations
 */

#include <meta.h>
#include <sdssc.h>

/*
 * resync named device
 */
int
meta_resync_byname(
	mdsetname_t	*sp,
	mdname_t	*np,
	daddr_t		size,
	md_error_t	*ep,
	md_resync_cmd_t	cmd	/* action to perform */
)
{
	char		*miscname;

	/* should have a set */
	assert(sp != NULL);
	assert(sp->setno == MD_MIN2SET(meta_getminor(np->dev)));

	/* get type */
	if (metachkmeta(np, ep) != 0)
		return (-1);
	if ((miscname = metagetmiscname(np, ep)) == NULL)
		return (-1);

	/* dispatch */
	if (strcmp(miscname, MD_RAID) == 0) {
		return (meta_raid_resync(sp, np, size, ep));
	} else if (strcmp(miscname, MD_MIRROR) == 0) {
		return (meta_mirror_resync(sp, np, size, ep, cmd));
	} else {
		return (mdmderror(ep, MDE_UNKNOWN_TYPE, meta_getminor(np->dev),
		    np->cname));
	}
}

/*
 * resync all devices
 */
int
meta_resync_all(
	mdsetname_t	*sp,
	daddr_t		size,
	md_error_t	*ep
)
{
	int		rval = 0;
	md_set_desc	*sd;

	/* see if we have any databases */
	if (meta_setup_db_locations(ep) != 0) {
		if (mdismddberror(ep, MDE_DB_NODB)) {
			mdclrerror(ep);
			return (0);
		}
		rval = -1;
	}

	if (!(metaislocalset(sp))) {
		if ((sd = metaget_setdesc(sp, ep)) == NULL)
			return (-1);

		/* MN disksets don't use DCS clustering services. */
		if (!(MD_MNSET_DESC(sd)))
			sdssc_notify_service(NULL, Shutdown_Services);
	}

	/* resync units */
	if (meta_mirror_resync_all(sp, size, ep) != 0)
		rval = -1;
	if (meta_raid_resync_all(sp, size, ep) != 0)
		rval = -1;
	return (rval);
}
