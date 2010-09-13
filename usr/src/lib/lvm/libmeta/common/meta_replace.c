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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * replace components in metadevices
 */

#include <meta.h>
#include <sys/lvm/md_stripe.h>

/*
 * replace named device
 */
int
meta_replace_byname(
	mdsetname_t	*sp,
	mdname_t	*np,
	mdname_t	*oldnp,
	mdname_t	*newnp,
	mdcmdopts_t	options,
	md_error_t	*ep
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
		return (meta_raid_replace(sp, np, oldnp, newnp, options, ep));
	} else if (strcmp(miscname, MD_MIRROR) == 0) {
		return (meta_mirror_replace(sp, np, oldnp, newnp, options, ep));
	} else {
		return (mdmderror(ep, MDE_UNKNOWN_TYPE, meta_getminor(np->dev),
		    np->cname));
	}
}

/*
 * enable named device
 */
int
meta_enable_byname(
	mdsetname_t	*sp,
	mdname_t	*np,
	mdname_t	*compnp,
	mdcmdopts_t	options,
	md_error_t	*ep
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
		return (meta_raid_enable(sp, np, compnp, options, ep));
	} else if (strcmp(miscname, MD_MIRROR) == 0) {
		return (meta_mirror_enable(sp, np, compnp, options, ep));
	} else {
		return (mdmderror(ep, MDE_UNKNOWN_TYPE, meta_getminor(np->dev),
		    np->cname));
	}
}
