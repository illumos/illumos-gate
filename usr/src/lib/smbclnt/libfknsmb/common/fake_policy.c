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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2016 Joyent, Inc.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/types.h>
#include <sys/cred.h>
#include <sys/errno.h>
#include <sys/policy.h>

/* ARGSUSED */
int
secpolicy_fs_allowed_mount(const char *fsname)
{
	return (0);
}

int
secpolicy_vnode_access2(const cred_t *cr, vnode_t *vp, uid_t owner,
    mode_t curmode, mode_t wantmode)
{
	mode_t mode;

	mode = ~curmode & wantmode;

	if (mode == 0)
		return (0);
	return (EACCES);
}

int
secpolicy_vnode_owner(const cred_t *cr, uid_t owner)
{
	/* cr->cr_uid */
	if (owner == crgetruid(cr))
		return (0);

	return (EPERM);
}

int
secpolicy_vnode_setattr(cred_t *cr, struct vnode *vp, struct vattr *vap,
    const struct vattr *ovap, int flags,
    int unlocked_access(void *, int, cred_t *),
    void *node)
{
	int mask = vap->va_mask;

	if (mask & AT_SIZE) {
		if (vp->v_type == VDIR)
			return (EISDIR);
	}
	if (mask & AT_MODE)
		return (EACCES);
	if (mask & (AT_UID|AT_GID))
		return (EACCES);

	return (0);
}

int
secpolicy_vnode_setdac(const cred_t *cred, uid_t owner)
{
	if (owner == crgetuid(cred))
		return (0);

	return (EPERM);
}
