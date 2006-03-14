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
 * get root device
 */

#include <meta.h>
#include "meta_lib_prv.h"

#include <sys/mnttab.h>

/*
 * Return the current root filesystem block device name
 */
void *
meta_get_current_root(
	md_error_t	*ep
)
{
	FILE		*fp;
	struct mnttab	mp;

	if ((fp = open_mnttab()) == NULL) {
		(void) mdsyserror(ep, errno, MNTTAB);
		return (NULL);
	}

	while (getmntent(fp, &mp) == 0) {
	if (strcmp(mp.mnt_mountp, "/") == 0)
		return (mp.mnt_special);
	}
	(void) mderror(ep, MDE_NOROOT, NULL);
	return (NULL);
}

/*
 * Return the current root filesystem block device name. This is only valid
 * when root is either a slice, a stripe or a mirror.
 */
mdname_t *
meta_get_current_root_dev(
	mdsetname_t	*sp,
	md_error_t	*ep
)
{
	md_stripe_t	*stripep;
	md_mirror_t	*mirrorp;
	md_row_t	*rp;
	md_comp_t	*cp;
	mdname_t	*rootnp;
	void		*curroot;
	char		*miscname;
	int		smi;

	if ((curroot = meta_get_current_root(ep)) == NULL)
		return (NULL);
	if ((rootnp = metaname(&sp, curroot, UNKNOWN, ep)) == NULL)
		return (NULL);
	if (metaismeta(rootnp)) {
		if ((miscname = metagetmiscname(rootnp, ep)) == NULL)
			return (NULL);
		if ((strcmp(miscname, MD_MIRROR) == 0) &&
		    ((mirrorp = meta_get_mirror(sp, rootnp, ep)) != NULL)) {
			for (smi = 0; smi < NMIRROR; smi++) {
				md_submirror_t *mdsp =
				    &mirrorp->submirrors[smi];
				rootnp = mdsp->submirnamep;
				/* skip unused submirrors */
				if (rootnp == NULL) {
					assert(mdsp->state == SMS_UNUSED);
					continue;
				}
				if ((miscname = metagetmiscname(rootnp, ep))
				    == NULL) {
					(void) mdmderror(ep, MDE_UNKNOWN_TYPE,
					    meta_getminor(rootnp->dev),
					    rootnp->cname);
					return (NULL);
				}
				break;
			}
		}
		if ((strcmp(miscname, MD_STRIPE) == 0) &&
		    ((stripep = meta_get_stripe(sp, rootnp, ep)) != NULL)) {
			rp = &stripep->rows.rows_val[0];
			cp = &rp->comps.comps_val[0];
			if (metachkcomp(cp->compnamep, ep) == 0)
				return (cp->compnamep);
		}
		/* Root is not a single stripe metadevice */
		(void) mddeverror(ep, MDE_INV_ROOT, rootnp->dev, rootnp->cname);
		return (NULL);
	} else return (rootnp);
}
