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
 * attach operations
 */

#include <meta.h>

/*
 * grow generic device
 */
int
meta_concat_generic(
	mdsetname_t		*sp,
	mdname_t		*namep,
	u_longlong_t		big_or_little,
	md_error_t		*ep
)
{
	md_grow_params_t	mgp;
	char			*miscname;

	/* should have a set */
	assert(sp != NULL);
	assert(sp->setno == MD_MIN2SET(meta_getminor(namep->dev)));

	/* get type */
	if ((miscname = metagetmiscname(namep, ep)) == NULL)
		return (-1);

	/* grow device */
	(void) memset(&mgp, 0, sizeof (mgp));
	if (big_or_little & MD_64BIT_META_DEV)
		mgp.options = MD_CRO_64BIT;
	else
		mgp.options = MD_CRO_32BIT;

	mgp.mnum = meta_getminor(namep->dev);
	MD_SETDRIVERNAME(&mgp, miscname, sp->setno);
	if (metaioctl(MD_IOCGROW, &mgp, &mgp.mde, namep->cname) != 0)
		return (mdstealerror(ep, &mgp.mde));

	/* clear cache */
	meta_invalidate_name(namep);

	/* return success */
	return (0);
}

/*
 * grow the parent of a device
 */
int
meta_concat_parent(
	mdsetname_t	*sp,
	mdname_t	*childnp,
	md_error_t	*ep
)
{
	md_common_t	*mdp;
	mdname_t	*parentnp;
	md_unit_t	*mup;

	/* should have a set */
	assert(sp != NULL);
	assert(sp->setno == MD_MIN2SET(meta_getminor(childnp->dev)));

	/* get parent */
	if ((mdp = meta_get_unit(sp, childnp, ep)) == NULL)
		return (-1);
	if (! MD_HAS_PARENT(mdp->parent))
		return (0);
	if (mdp->parent == MD_MULTI_PARENT)
		return (0);

	/* single parent */
	if ((parentnp = metamnumname(&sp, mdp->parent, 0, ep)) == NULL)
		return (-1);
	/* don't grow non-metadevices or soft partitions */
	if (! metaismeta(parentnp) || meta_sp_issp(sp, parentnp, ep) == 0)
		return (0);

	if ((mup = meta_get_mdunit(sp, childnp, ep)) == NULL)
		return (-1);

	/* grow parent */
	if (meta_concat_generic(sp, parentnp, mup->c.un_revision, ep) != 0)
		return (-1);

	/* recursively check for parents of parents */
	return (meta_concat_parent(sp, parentnp, ep));
}
