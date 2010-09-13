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
 * Copyright 1993-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * get/set user flags for the metadevices (FOR GUI USE ONLY)
 */

#include <meta.h>

/*
 * get user flags stored in the common unit structure.
 */
int
meta_getuserflags(
	mdsetname_t	*sp,
	mdname_t	*np,
	uint_t		*userflags,
	md_error_t	*ep
)
{
	md_common_t	*mdp;

	/* should have a set */
	assert(sp != NULL);
	assert(sp->setno == MD_MIN2SET(meta_getminor(np->dev)));

	if ((mdp = meta_get_unit(sp, np, ep)) == NULL)
		return (-1);

	*userflags = mdp->user_flags;
	return (0);
}


/*
 * set user flags, stored in the common unit structure.
 */
int
meta_setuserflags(
	mdsetname_t	*sp,
	mdname_t	*np,
	uint_t		userflags,
	md_error_t	*ep
)
{
	md_set_userflags_t	msu;
	char			*miscname;

	/* should have a set */
	assert(sp != NULL);
	assert(sp->setno == MD_MIN2SET(meta_getminor(np->dev)));

	/* check name */
	if (metachkmeta(np, ep) != 0)
		return (-1);

	/* get misc name */
	if ((miscname = metagetmiscname(np, ep)) == NULL)
		return (-1);

	/* set parameters */
	(void) memset(&msu, 0, sizeof (msu));
	MD_SETDRIVERNAME(&msu, miscname, sp->setno);
	msu.mnum = meta_getminor(np->dev);
	msu.userflags = userflags;
	if (metaioctl(MD_IOCSET_FLAGS, &msu, &msu.mde, np->cname) != 0)
		return (mdstealerror(ep, &msu.mde));

	/* clear cache */
	meta_invalidate_name(np);

	return (0);
}
