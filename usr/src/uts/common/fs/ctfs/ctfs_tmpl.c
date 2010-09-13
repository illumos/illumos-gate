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
#include <sys/model.h>

/*
 * CTFS routines for the /system/contract/<type>/template vnode.
 */

/*
 * ctfs_create_tmplnode
 *
 * Creates a new template and tdirnode, and returns the tdirnode.
 */
vnode_t *
ctfs_create_tmplnode(vnode_t *pvp)
{
	vnode_t *vp;
	ctfs_tmplnode_t *tmplnode;

	ASSERT(gfs_file_index(pvp) < ct_ntypes);

	vp = gfs_file_create(sizeof (ctfs_tmplnode_t), pvp, ctfs_ops_tmpl);
	tmplnode = vp->v_data;
	tmplnode->ctfs_tmn_tmpl =
	    ct_types[gfs_file_index(pvp)]->ct_type_default();

	return (vp);
}

/*
 * ctfs_tmpl_open - VOP_OPEN entry point
 *
 * Just ensures the right mode bits are set.
 */
/* ARGSUSED */
static int
ctfs_tmpl_open(vnode_t **vpp, int flag, cred_t *cr, caller_context_t *ct)
{
	if (flag != (FREAD | FWRITE | FOFFMAX))
		return (EINVAL);

	return (0);
}

/*
 * ctfs_tmpl_getattr - VOP_GETATTR entry point
 */
/* ARGSUSED */
static int
ctfs_tmpl_getattr(
	vnode_t *vp,
	vattr_t *vap,
	int flags,
	cred_t *cr,
	caller_context_t *ct)
{
	vap->va_type = VREG;
	vap->va_mode = 0666;
	vap->va_nlink = 1;
	vap->va_size = 0;
	vap->va_ctime.tv_sec = vp->v_vfsp->vfs_mtime;
	vap->va_ctime.tv_nsec = 0;
	vap->va_atime = vap->va_mtime = vap->va_ctime;
	ctfs_common_getattr(vp, vap);

	return (0);
}

/*
 * ctfs_tmpl_ioctl - VOP_IOCTL entry point
 *
 * All the ct_tmpl_*(3contract) interfaces point here.
 */
/* ARGSUSED */
static int
ctfs_tmpl_ioctl(
	vnode_t *vp,
	int cmd,
	intptr_t arg,
	int flag,
	cred_t *cr,
	int *rvalp,
	caller_context_t *ct)
{
	ctfs_tmplnode_t	*tmplnode = vp->v_data;
	ct_kparam_t kparam;
	ct_param_t *param = &kparam.param;
	ctid_t ctid;
	int error;

	switch (cmd) {
	case CT_TACTIVATE:
		ASSERT(tmplnode->ctfs_tmn_tmpl != NULL);
		ctmpl_activate(tmplnode->ctfs_tmn_tmpl);
		break;
	case CT_TCLEAR:
		ASSERT(tmplnode->ctfs_tmn_tmpl != NULL);
		ctmpl_clear(tmplnode->ctfs_tmn_tmpl);
		break;
	case CT_TCREATE:
		ASSERT(tmplnode->ctfs_tmn_tmpl != NULL);
		error = ctmpl_create(tmplnode->ctfs_tmn_tmpl, &ctid);
		if (error)
			return (error);
		*rvalp = ctid;
		break;
	case CT_TSET:
		error = ctparam_copyin((void *)arg, &kparam, flag, cmd);
		if (error != 0)
			return (error);
		error = ctmpl_set(tmplnode->ctfs_tmn_tmpl, &kparam, cr);
		kmem_free(kparam.ctpm_kbuf, param->ctpm_size);

		return (error);
	case CT_TGET:
		error = ctparam_copyin((void *)arg, &kparam, flag, cmd);
		if (error != 0)
			return (error);
		error = ctmpl_get(tmplnode->ctfs_tmn_tmpl, &kparam);
		if (error != 0) {
			kmem_free(kparam.ctpm_kbuf, param->ctpm_size);
		} else {
			error = ctparam_copyout(&kparam, (void *)arg, flag);
		}

		return (error);
	default:
		return (EINVAL);
	}

	return (0);
}

/*
 * ctfs_tmpl_inactive - VOP_INACTIVE entry point
 */
/* ARGSUSED */
static void
ctfs_tmpl_inactive(vnode_t *vp, cred_t *cr, caller_context_t *ct)
{
	ctfs_tmplnode_t *tmplnode;

	if ((tmplnode = gfs_file_inactive(vp)) != NULL) {
		ctmpl_free(tmplnode->ctfs_tmn_tmpl);
		kmem_free(tmplnode, sizeof (ctfs_tmplnode_t));
	}
}

const fs_operation_def_t ctfs_tops_tmpl[] = {
	{ VOPNAME_OPEN,		{ .vop_open = ctfs_tmpl_open } },
	{ VOPNAME_CLOSE,	{ .vop_close = ctfs_close } },
	{ VOPNAME_IOCTL,	{ .vop_ioctl = ctfs_tmpl_ioctl } },
	{ VOPNAME_GETATTR,	{ .vop_getattr = ctfs_tmpl_getattr } },
	{ VOPNAME_ACCESS,	{ .vop_access = ctfs_access_readwrite } },
	{ VOPNAME_READDIR,	{ .error = fs_notdir } },
	{ VOPNAME_LOOKUP,	{ .error = fs_notdir } },
	{ VOPNAME_INACTIVE,	{ .vop_inactive = ctfs_tmpl_inactive } },
	{ NULL, NULL }
};
