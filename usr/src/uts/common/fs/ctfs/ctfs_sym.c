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
#include <sys/cmn_err.h>

/*
 * CTFS routines for the /system/contract/all/<ctid> vnode.
 */

/*
 * ctfs_create_symnode
 *
 * Creates and returns a symnode for the specified contract.
 */
vnode_t *
ctfs_create_symnode(vnode_t *pvp, contract_t *ct)
{
	ctfs_symnode_t *symnode;
	vnode_t *vp;
	size_t len;

	vp = gfs_file_create(sizeof (ctfs_symnode_t), pvp, ctfs_ops_sym);
	vp->v_type = VLNK;
	symnode = vp->v_data;

	symnode->ctfs_sn_contract = ct;
	symnode->ctfs_sn_size = len = snprintf(NULL, 0, "../%s/%ld",
	    ct->ct_type->ct_type_name, (long)ct->ct_id) + 1;
	symnode->ctfs_sn_string = kmem_alloc(len, KM_SLEEP);
	VERIFY(snprintf(symnode->ctfs_sn_string, len, "../%s/%ld",
	    ct->ct_type->ct_type_name, (long)ct->ct_id) < len);

	contract_hold(ct);

	return (vp);
}

/*
 * ctfs_sym_getattr - VOP_GETATTR entry point
 */
/* ARGSUSED */
static int
ctfs_sym_getattr(
	vnode_t *vp,
	vattr_t *vap,
	int flags,
	cred_t *cr,
	caller_context_t *ct)
{
	ctfs_symnode_t *symnode = vp->v_data;

	vap->va_type = VLNK;
	vap->va_mode = 0444;
	vap->va_nlink = 1;
	vap->va_size = symnode->ctfs_sn_size - 1;
	vap->va_mtime = vap->va_atime = vap->va_ctime =
	    symnode->ctfs_sn_contract->ct_ctime;
	ctfs_common_getattr(vp, vap);

	return (0);
}

/*
 * ctfs_sym_readlink - VOP_READLINK entry point
 *
 * Since we built the symlink string in ctfs_create_symnode, this is
 * just a uiomove.
 */
/* ARGSUSED */
int
ctfs_sym_readlink(vnode_t *vp, uio_t *uiop, cred_t *cr, caller_context_t *ct)
{
	ctfs_symnode_t *symnode = vp->v_data;

	return (uiomove(symnode->ctfs_sn_string, symnode->ctfs_sn_size - 1,
	    UIO_READ, uiop));
}

/*
 * ctfs_sym_inactive - VOP_INACTIVE entry point
 */
/* ARGSUSED */
static void
ctfs_sym_inactive(vnode_t *vp, cred_t *cr, caller_context_t *ct)
{
	ctfs_symnode_t *symnode;

	if ((symnode = gfs_file_inactive(vp)) != NULL) {
		contract_rele(symnode->ctfs_sn_contract);
		kmem_free(symnode->ctfs_sn_string, symnode->ctfs_sn_size);
		kmem_free(symnode, sizeof (ctfs_symnode_t));
	}
}

const fs_operation_def_t ctfs_tops_sym[] = {
	{ VOPNAME_OPEN,		{ .vop_open = ctfs_open } },
	{ VOPNAME_CLOSE,	{ .vop_close = ctfs_close } },
	{ VOPNAME_IOCTL,	{ .error = fs_inval } },
	{ VOPNAME_GETATTR,	{ .vop_getattr = ctfs_sym_getattr } },
	{ VOPNAME_READLINK,	{ .vop_readlink = ctfs_sym_readlink } },
	{ VOPNAME_ACCESS,	{ .vop_access = ctfs_access_readonly } },
	{ VOPNAME_READDIR,	{ .error = fs_notdir } },
	{ VOPNAME_LOOKUP,	{ .error = fs_notdir } },
	{ VOPNAME_INACTIVE,	{ .vop_inactive = ctfs_sym_inactive } },
	{ NULL, NULL }
};
