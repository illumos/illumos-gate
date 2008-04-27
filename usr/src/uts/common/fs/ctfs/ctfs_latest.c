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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/cred.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/gfs.h>
#include <sys/vnode.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/sysmacros.h>
#include <fs/fs_subr.h>
#include <sys/contract.h>
#include <sys/contract_impl.h>
#include <sys/ctfs.h>
#include <sys/ctfs_impl.h>
#include <sys/file.h>

/*
 * CTFS routines for the /system/contract/<type>/latest vnode.
 */

/*
 * ctfs_create_latenode
 */
vnode_t *
ctfs_create_latenode(vnode_t *pvp)
{
	return (gfs_file_create(sizeof (ctfs_latenode_t), pvp,
	    ctfs_ops_latest));
}

/*
 * ctfs_latest_nested_open
 *
 * The latest node is just a doorway to the status file; this function
 * is used by ctfs_latest_access, ctfs_latest_open, and
 * ctfs_latest_getattr to obtain that file.
 */
static vnode_t *
ctfs_latest_nested_open(vnode_t *vp, cred_t *cr)
{
	contract_t *ct = ttolwp(curthread)->lwp_ct_latest[
	    gfs_file_index(gfs_file_parent(vp))];

	if (ct) {
		vnode_t *cvp, *svp;

		cvp = ctfs_create_cdirnode(gfs_file_parent(vp), ct);

		gfs_file_set_index(cvp, -1);

		VERIFY(gfs_dir_lookup(cvp, "status", &svp,
		    cr, 0, NULL, NULL) == 0);

		VN_RELE(cvp);

		return (svp);
	}

	return (NULL);
}

/*
 * ctfs_latest_access - VOP_ACCESS entry point
 *
 * Fails if there isn't a latest contract.
 */
/* ARGSUSED */
static int
ctfs_latest_access(
	vnode_t *vp,
	int mode,
	int flags,
	cred_t *cr,
	caller_context_t *ct)
{
	vnode_t *nvp;

	if (mode & (VEXEC | VWRITE))
		return (EACCES);

	if (nvp = ctfs_latest_nested_open(vp, cr)) {
		VN_RELE(nvp);
		return (0);
	}

	return (ESRCH);
}

/*
 * ctfs_latest_open - VOP_OPEN entry point
 *
 * After checking the mode bits, opens and returns the status file for
 * the LWP's latest contract.
 */
static int
ctfs_latest_open(vnode_t **vpp, int flag, cred_t *cr, caller_context_t *ct)
{
	vnode_t *nvp;

	if (flag != (FREAD | FOFFMAX))
		return (EINVAL);

	if (nvp = ctfs_latest_nested_open(*vpp, cr)) {
		VN_RELE(*vpp);
		*vpp = nvp;
		return (VOP_OPEN(vpp, flag, cr, ct));
	}

	return (ESRCH);
}

/*
 * ctfs_latest_getattr - the VOP_GETATTR entry point
 *
 * Fetches and calls VOP_GETATTR on the status file for the LWP's
 * latest contract.  Otherwise it fakes up something bland.
 */
static int
ctfs_latest_getattr(
	vnode_t *vp,
	vattr_t *vap,
	int flags,
	cred_t *cr,
	caller_context_t *ct)
{
	vnode_t *nvp;

	if (nvp = ctfs_latest_nested_open(vp, cr)) {
		int res = VOP_GETATTR(nvp, vap, flags, cr, ct);
		VN_RELE(nvp);
		return (res);
	}

	vap->va_type = VREG;
	vap->va_mode = 0444;
	vap->va_nlink = 1;
	vap->va_size = 0;
	vap->va_ctime.tv_sec = vp->v_vfsp->vfs_mtime;
	vap->va_ctime.tv_nsec = 0;
	vap->va_atime = vap->va_mtime = vap->va_ctime;
	ctfs_common_getattr(vp, vap);

	return (0);
}

const fs_operation_def_t ctfs_tops_latest[] = {
	{ VOPNAME_OPEN,		{ .vop_open = ctfs_latest_open } },
	{ VOPNAME_CLOSE,	{ .error = fs_inval } },
	{ VOPNAME_IOCTL,	{ .error = fs_inval } },
	{ VOPNAME_GETATTR,	{ .vop_getattr = ctfs_latest_getattr } },
	{ VOPNAME_ACCESS,	{ .vop_access = ctfs_latest_access } },
	{ VOPNAME_READDIR,	{ .error = fs_notdir } },
	{ VOPNAME_LOOKUP,	{ .error = fs_notdir } },
	{ VOPNAME_INACTIVE,	{ .vop_inactive = gfs_vop_inactive } },
	{ NULL, NULL }
};
