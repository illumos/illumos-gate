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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/systm.h>
#include <sys/vnode.h>
#include <sys/uio.h>
#include <sys/errno.h>
#include <sys/fs/ufs_inode.h>

#include <sys/fs/ufs_filio.h>
#include <sys/fs/ufs_log.h>
#include <sys/sunddi.h>
#include <sys/file.h>

/* ARGSUSED */
int
ufs_fiologenable(vnode_t *vp, fiolog_t *ufl, cred_t *cr, int flags)
{
	int		error = 0;
	fiolog_t	fl;

	/*
	 * Enable logging
	 */
	if (ddi_copyin(ufl, &fl, sizeof (fl), flags))
		return (EFAULT);
	error = lufs_enable(vp, &fl, cr);
	if (ddi_copyout(&fl, ufl, sizeof (*ufl), flags))
		return (EFAULT);

	return (error);
}

/* ARGSUSED */
int
ufs_fiologdisable(vnode_t *vp, fiolog_t *ufl, cred_t *cr, int flags)
{
	int		error = 0;
	struct fiolog	fl;

	/*
	 * Disable logging
	 */
	if (ddi_copyin(ufl, &fl, sizeof (fl), flags))
		return (EFAULT);
	error = lufs_disable(vp, &fl);
	if (ddi_copyout(&fl, ufl, sizeof (*ufl), flags))
		return (EFAULT);

	return (error);
}

/*
 * ufs_fioislog
 *	Return true if log is present and active; otherwise false
 */
/* ARGSUSED */
int
ufs_fioislog(vnode_t *vp, uint32_t *islog, cred_t *cr, int flags)
{
	ufsvfs_t	*ufsvfsp	= VTOI(vp)->i_ufsvfs;
	int		active;

	active = (ufsvfsp && ufsvfsp->vfs_log);
	if (flags & FKIOCTL)
		*islog = active;
	else if (suword32(islog, active))
		return (EFAULT);
	return (0);
}
