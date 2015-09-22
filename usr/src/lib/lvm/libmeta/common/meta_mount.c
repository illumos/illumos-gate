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
 * Copyright 2015 Nexenta Systems, Inc. All rights reserved.
 */


/*
 * return mount association with meta device
 */

#include <meta.h>

#include <sys/mnttab.h>

#include "meta_lib_prv.h"

/*
 * return associated mount point with this mdname_t
 */
char *
meta_get_mountp(
	mdsetname_t	*sp,
	mdname_t	*np,
	md_error_t	*ep
)
{
	FILE		*mfp;
	struct mnttab	 m;
	char		*mountp	= NULL;
	char		mnt_mountp[MNT_LINE_MAX];
	char		mnt_special[MNT_LINE_MAX];

	/* should have a set */
	assert(sp != NULL);

	/* look in mnttab */
	if ((mfp = open_mnttab()) == NULL) {
		(void) mdsyserror(ep, errno, MNTTAB);
		return (NULL);
	}

	while ((!mountp) && (getmntent(mfp, &m) == 0)) {
		mdname_t	*mnp;

		if ((m.mnt_special == NULL) || (m.mnt_mountp == NULL))
			continue;

		if (m.mnt_mountp[0] != '/')
			continue;

		if ((strcmp(m.mnt_fstype, "nfs") == 0) ||
		    (strcmp(m.mnt_fstype, "autofs") == 0) ||
		    (strcmp(m.mnt_fstype, "proc") == 0) ||
		    (strcmp(m.mnt_fstype, "tmpfs") == 0) ||
		    (strcmp(m.mnt_fstype, "lofs") == 0) ||
		    (strcmp(m.mnt_fstype, "rfs") == 0) ||
		    (strcmp(m.mnt_fstype, "fd") == 0))
			continue;

		(void) strcpy(mnt_mountp, m.mnt_mountp);
		(void) strcpy(mnt_special, m.mnt_special);
		if ((mnp = metaname(&sp, mnt_special, UNKNOWN, ep)) == NULL) {
			mdclrerror(ep);
			continue;
		}

		if (np->dev == mnp->dev) {
			mountp = mnt_mountp;
		}
	}

	/* return success, if found */
	return (mountp? Strdup(mountp): NULL);
}
