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
 * Copyright 1994-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * raid operations
 */

#include <meta.h>
#include <sys/lvm/md_mirror.h>

/*
 * resync raid
 */
int
meta_raid_resync(
	mdsetname_t		*sp,
	mdname_t		*raidnp,
	daddr_t			size,
	md_error_t		*ep
)
{
	char			*miscname;
	md_resync_ioctl_t	ri;

	/* should have a set */
	assert(sp != NULL);
	assert(sp->setno == MD_MIN2SET(meta_getminor(raidnp->dev)));

	/* make sure we have a raid */
	if ((miscname = metagetmiscname(raidnp, ep)) == NULL)
		return (-1);
	if (strcmp(miscname, MD_RAID) != 0) {
		return (mdmderror(ep, MDE_NOT_RAID, meta_getminor(raidnp->dev),
		    raidnp->cname));
	}

	/* start resync */
	(void) memset(&ri, 0, sizeof (ri));
	MD_SETDRIVERNAME(&ri, MD_RAID, sp->setno);
	ri.ri_mnum = meta_getminor(raidnp->dev);
	ri.ri_copysize = size;
	if (metaioctl(MD_IOCSETSYNC, &ri, &ri.mde, raidnp->cname) != 0)
		return (mdstealerror(ep, &ri.mde));

	/* return success */
	return (0);
}

/*
 * NAME:	meta_raid_resync_all
 * DESCRIPTION: loop through the RAID devices synch'ing all
 * PARAMETERS:	char		*sp	- the set to synch
 *		daddr_t		size	- resync size
 *		md_error_t	*ep	- return error info
 *
 */
int
meta_raid_resync_all(
	mdsetname_t	*sp,
	daddr_t		size,
	md_error_t	*ep
)
{
	mdnamelist_t	*nlp = NULL;
	mdnamelist_t	*p;
	int		rval = 0, fval;

	/* should have a set */
	assert(sp != NULL);

	/* get raids */
	if (meta_get_raid_names(sp, &nlp, 0, ep) < 0)
		return (-1);

	/* fork a process */
	if ((fval = md_daemonize(sp, ep)) != 0) {
		/*
		 * md_daemonize forks off a process to do the work.  This
		 * is the parent or errror.
		 */
		if (fval > 0) {
			if (nlp != NULL)
				metafreenamelist(nlp);
			return (0);
		}
		mdclrerror(ep);
	}

	assert((fval == 0) || (fval == -1));

	/* resync each raid */
	for (p = nlp; (p != NULL); p = p->next) {
		mdname_t	*raidnp = p->namep;

		if (meta_raid_resync(sp, raidnp, size, ep) != 0)
			rval = -1;
	}

	/* cleanup, return success */
	if (nlp != NULL)
		metafreenamelist(nlp);
	if (fval == 0)
		exit(0);
	return (rval);
}
