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
 * clear metadevices
 */

#include <meta.h>

/*
 * clear a metadevice.
 */
int
meta_reset(
	mdsetname_t	*sp,
	mdname_t	*np,
	mdcmdopts_t	options,
	md_error_t	*ep
)
{
	char		*miscname;
	md_i_reset_t	mir;

	/* should have a set */
	assert(sp != NULL);
	assert(sp->setno == MD_MIN2SET(meta_getminor(np->dev)));
	/* clear device */
	if ((miscname = metagetmiscname(np, ep)) == NULL)
		return (-1);
	if (meta_isopen(sp, np, ep, options) != 0) {
		return (mdmderror(ep, MDE_IS_OPEN, meta_getminor(np->dev),
			np->cname));
	}
	(void) memset(&mir, '\0', sizeof (mir));
	MD_SETDRIVERNAME(&mir, miscname, sp->setno);
	mir.mnum = meta_getminor(np->dev);
	mir.force = (options & MDCMD_FORCE) ? 1 : 0;
	if (metaioctl(MD_IOCRESET, &mir, &mir.mde, np->cname) != 0)
		return (mdstealerror(ep, &mir.mde));

	/*
	 * Wait for the /dev to be cleaned up. Ignore the return
	 * value since there's not much we can do.
	 */
	(void) meta_update_devtree(meta_getminor(np->dev));

	/* return success */
	return (0);
}

/*
 * reset all the metadevice and hotspares
 */
int
meta_reset_all(
	mdsetname_t	*sp,
	mdcmdopts_t	options,
	md_error_t	*ep
)
{
	options |= MDCMD_RECURSE;

	/*
	 * since soft partitions can appear at the top and bottom
	 * of the stack, we call meta_sp_reset twice to handle all
	 * cases.
	 */
	if (meta_trans_reset(sp, NULL, options, ep) != 0)
		return (-1);
	if (meta_sp_reset(sp, NULL, options, ep) != 0)
		return (-1);
	if (meta_raid_reset(sp, NULL, options, ep) != 0)
		return (-1);
	if (meta_mirror_reset(sp, NULL, options, ep) != 0)
		return (-1);
	if (meta_stripe_reset(sp, NULL, options, ep) != 0)
		return (-1);
	if (meta_hsp_reset(sp, NULL, options, ep) != 0)
		return (-1);
	if (meta_sp_reset(sp, NULL, options, ep) != 0)
		return (-1);

	return (0);
}

/*
 * reset named device
 */
int
meta_reset_by_name(
	mdsetname_t	*sp,
	mdname_t	*np,
	mdcmdopts_t	options,
	md_error_t	*ep
)
{
	char		*miscname;
	int		rval = 0;

	/* should have a set */
	assert(sp != NULL);
	assert(sp->setno == MD_MIN2SET(meta_getminor(np->dev)));

	/* get type */
	if (metachkmeta(np, ep) != 0)
		return (-1);
	if ((miscname = metagetmiscname(np, ep)) == NULL)
		return (-1);
	/* dispatch */
	if (strcmp(miscname, MD_STRIPE) == 0) {
		rval = meta_stripe_reset(sp, np, options, ep);
	} else if (strcmp(miscname, MD_MIRROR) == 0) {
		rval = meta_mirror_reset(sp, np, options, ep);
	} else if (strcmp(miscname, MD_TRANS) == 0) {
		rval = meta_trans_reset(sp, np, options, ep);
	} else if (strcmp(miscname, MD_RAID) == 0) {
		rval = meta_raid_reset(sp, np, options, ep);
	} else if (strcmp(miscname, MD_SP) == 0) {
		rval = meta_sp_reset(sp, np, options, ep);
	} else {
		rval = mdmderror(ep, MDE_UNKNOWN_TYPE, meta_getminor(np->dev),
		    np->cname);
	}

	/* cleanup */
	return (rval);
}
