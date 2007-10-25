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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
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
 * CTFS routines for the /system/contract/<type>/<ctid>/ctl vnode.
 * CTFS routines for the /system/contract/<type>/<ctid>/status vnode.
 */

/*
 * ctfs_create_ctlnode
 *
 * If necessary, creates a ctlnode for a ctl file and inserts it into
 * the specified cdirnode's gfs_dir_t.  Returns either the existing
 * vnode or the new one.
 */
vnode_t *
ctfs_create_ctlnode(vnode_t *pvp)
{
	ctfs_ctlnode_t *ctlnode;
	ctfs_cdirnode_t *cdirnode = pvp->v_data;
	vnode_t *vp;

	vp = gfs_file_create(sizeof (ctfs_ctlnode_t), pvp, ctfs_ops_ctl);
	ctlnode = vp->v_data;
	/*
	 * We transitively have a hold on the contract through our
	 * parent directory.
	 */
	ctlnode->ctfs_ctl_contract = cdirnode->ctfs_cn_contract;

	return (vp);
}

/*
 * ctfs_ctl_access - VOP_ACCESS entry point
 *
 * You only get to access ctl files for contracts you own or were
 * abandoned and inherited by your containing process contract.
 */
/* ARGSUSED */
static int
ctfs_ctl_access(
	vnode_t *vp,
	int mode,
	int flags,
	cred_t *cr,
	caller_context_t *cct)
{
	ctfs_ctlnode_t *ctlnode = vp->v_data;
	contract_t *ct = ctlnode->ctfs_ctl_contract;

	if (mode & (VEXEC | VREAD))
		return (EACCES);

	mutex_enter(&ct->ct_lock);
	if ((curproc == ct->ct_owner) ||
	    (ct->ct_owner == NULL && ct->ct_regent != NULL &&
	    ct->ct_regent->ct_data == curproc->p_ct_process)) {
		mutex_exit(&ct->ct_lock);
		return (0);
	}

	mutex_exit(&ct->ct_lock);
	return (EACCES);
}

/*
 * ctfs_ctl_open - VOP_OPEN entry point
 *
 * Just checks to make sure the mode bits are set, and that the
 * constraints imposed by ctfs_ctl_access are met.
 */
static int
ctfs_ctl_open(vnode_t **vpp, int flag, cred_t *cr, caller_context_t *ct)
{
	if (flag != (FWRITE | FOFFMAX))
		return (EINVAL);

	return (ctfs_ctl_access(*vpp, VWRITE, 0, cr, ct));
}

/*
 * ctfs_ctl_common_getattr
 * Implements functionality common to ctl and status ctfs VOP_GETATTR
 * entry points. It assumes vp->v_data is set
 */
static int
ctfs_ctl_common_getattr(vnode_t *vp, vattr_t *vap)
{
	ctfs_ctlnode_t *ctlnode = vp->v_data;

	vap->va_type = VREG;
	vap->va_nlink = 1;
	vap->va_size = 0;
	vap->va_ctime = ctlnode->ctfs_ctl_contract->ct_ctime;
	mutex_enter(&ctlnode->ctfs_ctl_contract->ct_events.ctq_lock);
	vap->va_atime = vap->va_mtime =
	    ctlnode->ctfs_ctl_contract->ct_events.ctq_atime;
	mutex_exit(&ctlnode->ctfs_ctl_contract->ct_events.ctq_lock);
	ctfs_common_getattr(vp, vap);

	return (0);
}

/*
 * ctfs_ctl_getattr - VOP_GETATTR entry point
 */
/* ARGSUSED */
static int
ctfs_ctl_getattr(vnode_t *vp, vattr_t *vap, int flags,
    cred_t *cr, caller_context_t *ct)
{
	vap->va_mode = 0222;

	return (ctfs_ctl_common_getattr(vp, vap));
}

/*
 * ctfs_stat_getattr - VOP_GETATTR entry point
 */
/* ARGSUSED */
static int
ctfs_stat_getattr(vnode_t *vp, vattr_t *vap, int flags, cred_t *cr,
    caller_context_t *ct)
{
	vap->va_mode = 0444;

	return (ctfs_ctl_common_getattr(vp, vap));
}

/*
 * ctfs_ctl_ioctl - VOP_IOCTL entry point
 *
 * All the ct_ctl_*(3contract) interfaces point here.
 */
/* ARGSUSED */
static int
ctfs_ctl_ioctl(
	vnode_t *vp,
	int cmd,
	intptr_t arg,
	int flag,
	cred_t *cr,
	int *rvalp,
	caller_context_t *cct)
{
	ctfs_ctlnode_t	*ctlnode = vp->v_data;
	contract_t	*ct = ctlnode->ctfs_ctl_contract;
	int		error = 0;
	uint64_t	event;
	int		ack;

	switch (cmd) {
	case CT_CABANDON:
		error = contract_abandon(ct, curproc, 1);
		break;

	case CT_CACK:
	case CT_CNACK:
		if (copyin((void *)arg, &event, sizeof (uint64_t)))
			return (EFAULT);
		ack = (cmd == CT_CACK) ? CT_ACK : CT_NACK;
		error = contract_ack(ct, event, ack);
		break;

	case CT_CNEWCT:
		error = contract_newct(ct);
		break;

	case CT_CQREQ:
		if (copyin((void *)arg, &event, sizeof (uint64_t)))
			return (EFAULT);
		error = contract_qack(ct, event);
		break;

	case CT_CADOPT:
		error = contract_adopt(ct, curproc);
		break;

	default:
		return (EINVAL);
	}

	return (error);
}

const fs_operation_def_t ctfs_tops_ctl[] = {
	{ VOPNAME_OPEN,		{ .vop_open = ctfs_ctl_open } },
	{ VOPNAME_CLOSE,	{ .vop_close = ctfs_close } },
	{ VOPNAME_IOCTL,	{ .vop_ioctl = ctfs_ctl_ioctl } },
	{ VOPNAME_GETATTR,	{ .vop_getattr = ctfs_ctl_getattr } },
	{ VOPNAME_ACCESS,	{ .vop_access = ctfs_ctl_access } },
	{ VOPNAME_READDIR,	{ .error = fs_notdir } },
	{ VOPNAME_LOOKUP,	{ .error = fs_notdir } },
	{ VOPNAME_INACTIVE,	{ .vop_inactive = gfs_vop_inactive } },
	{ NULL, NULL }
};

/*
 * ctfs_create_statnode
 *
 * If necessary, creates a ctlnode for a status file and inserts it
 * into the specified cdirnode's gfs_dir_t.  Returns either the
 * existing vnode or the new one.
 */
vnode_t *
ctfs_create_statnode(vnode_t *pvp)
{
	vnode_t *vp;
	ctfs_cdirnode_t *cdirnode = pvp->v_data;
	ctfs_ctlnode_t *ctlnode;

	vp = gfs_file_create(sizeof (ctfs_ctlnode_t), pvp, ctfs_ops_stat);
	ctlnode = vp->v_data;
	/*
	 * We transitively have a hold on the contract through our
	 * parent directory.
	 */
	ctlnode->ctfs_ctl_contract = cdirnode->ctfs_cn_contract;

	return (vp);
}

/*
 * ctfs_stat_ioctl - VOP_IOCTL entry point
 *
 * The kernel half of ct_status_read(3contract).
 */
/* ARGSUSED */
static int
ctfs_stat_ioctl(
	vnode_t *vp,
	int cmd,
	intptr_t arg,
	int flag,
	cred_t *cr,
	int *rvalp,
	caller_context_t *cct)
{
	ctfs_ctlnode_t	*statnode = vp->v_data;
	contract_t	*ct = statnode->ctfs_ctl_contract;
	ct_type_t	*type = ct->ct_type;
	STRUCT_DECL(ct_status, st);
	nvlist_t	*foo;
	char		*bufp = NULL;
	size_t		len;
	model_t		mdl = get_udatamodel();
	uint_t		detail;

	STRUCT_INIT(st, mdl);

	if (cmd != CT_SSTATUS)
		return (EINVAL);

	if (copyin((void *)arg, STRUCT_BUF(st), STRUCT_SIZE(st)))
		return (EFAULT);
	detail = STRUCT_FGET(st, ctst_detail);
	if (detail == CTD_COMMON) {
		mutex_enter(&ct->ct_lock);
		contract_status_common(ct, VTOZONE(vp), STRUCT_BUF(st), mdl);
		mutex_exit(&ct->ct_lock);
	} else if (detail <= CTD_ALL) {
		VERIFY(nvlist_alloc(&foo, NV_UNIQUE_NAME, KM_SLEEP) == 0);
		type->ct_type_ops->contop_status(ct, VTOZONE(vp), detail, foo,
		    STRUCT_BUF(st), mdl);
		VERIFY(nvlist_pack(foo, &bufp, &len, NV_ENCODE_NATIVE,
		    KM_SLEEP) == 0);
		nvlist_free(foo);

		if ((len <= STRUCT_FGET(st, ctst_nbytes)) &&
		    (copyout(bufp, STRUCT_FGETP(st, ctst_buffer), len) == -1)) {
			kmem_free(bufp, len);
			return (EFAULT);
		}
		kmem_free(bufp, len);
		STRUCT_FSET(st, ctst_nbytes, len);
	} else {
		return (EINVAL);
	}
	if (copyout(STRUCT_BUF(st), (void *)arg, STRUCT_SIZE(st)))
		return (EFAULT);

	return (0);
}

const fs_operation_def_t ctfs_tops_stat[] = {
	{ VOPNAME_OPEN,		{ .vop_open = ctfs_open } },
	{ VOPNAME_CLOSE,	{ .vop_close = ctfs_close } },
	{ VOPNAME_IOCTL,	{ .vop_ioctl = ctfs_stat_ioctl } },
	{ VOPNAME_GETATTR,	{ .vop_getattr = ctfs_stat_getattr } },
	{ VOPNAME_ACCESS,	{ .vop_access = ctfs_access_readonly } },
	{ VOPNAME_READDIR,	{ .error = fs_notdir } },
	{ VOPNAME_LOOKUP,	{ .error = fs_notdir } },
	{ VOPNAME_INACTIVE,	{ .vop_inactive = gfs_vop_inactive } },
	{ NULL, NULL }
};
