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

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/zone.h>
#include <sys/errno.h>
#include <sys/cred.h>
#include <sys/policy.h>

#include <sys/fs/autofs.h>

int
autofssys(enum autofssys_op opcode, uintptr_t arg)
{
	int error = 0;

	switch (opcode) {
	case AUTOFS_UNMOUNTALL: { /* attempt to remove all autofs mounts */
		zone_t *zone;
		zoneid_t zoneid;
		struct autofs_globals *fngp;

		zoneid = (zoneid_t)arg;
		if (secpolicy_fs_unmount(CRED(), NULL) != 0 ||
		    crgetzoneid(CRED()) != GLOBAL_ZONEID)
			return (set_errno(EPERM));
		if ((zone = zone_find_by_id(zoneid)) == NULL)
			return (set_errno(EINVAL));
		fngp = zone_getspecific(autofs_key, zone);
		if (fngp == NULL) {
			zone_rele(zone);
			/*
			 * There were no mounts, so no work to do. Success.
			 */
			return (0);
		}
		unmount_tree(fngp, 1);
		zone_rele(zone);
		break;
	}
	default:
		error = EINVAL;
		break;
	}
	return (error ? set_errno(error) : 0);
}
