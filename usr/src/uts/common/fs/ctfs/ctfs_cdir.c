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
#include <sys/pathname.h>

/*
 * Entries in a /system/contract/<type>/<ctid> directory.
 */
static gfs_dirent_t ctfs_ctls[] = {
	{ "ctl", ctfs_create_ctlnode, GFS_CACHE_VNODE, },
	{ "status", ctfs_create_statnode, GFS_CACHE_VNODE },
	{ "events", ctfs_create_evnode },
	{ NULL }
};
#define	CTFS_NCTLS	((sizeof ctfs_ctls / sizeof (gfs_dirent_t)) - 1)

static ino64_t ctfs_cdir_do_inode(vnode_t *, int);

/*
 * ctfs_create_cdirnode
 *
 * If necessary, creates a cdirnode for the specified contract and
 * inserts it into the contract's list of vnodes.  Returns either the
 * existing vnode or the new one.
 */
vnode_t *
ctfs_create_cdirnode(vnode_t *pvp, contract_t *ct)
{
	vnode_t *vp;
	ctfs_cdirnode_t *cdir;

	if ((vp = contract_vnode_get(ct, pvp->v_vfsp)) != NULL)
		return (vp);

	vp = gfs_dir_create(sizeof (ctfs_cdirnode_t), pvp, ctfs_ops_cdir,
	    ctfs_ctls, ctfs_cdir_do_inode, CTFS_NAME_MAX, NULL, NULL);
	cdir = vp->v_data;

	/*
	 * We must set the inode because this is called explicitly rather than
	 * through GFS callbacks.
	 */
	gfs_file_set_inode(vp, CTFS_INO_CT_DIR(ct->ct_id));

	cdir->ctfs_cn_contract	= ct;
	contract_hold(ct);
	contract_vnode_set(ct, &cdir->ctfs_cn_linkage, vp);

	return (vp);
}

/*
 * ctfs_cdir_getattr - VOP_GETATTR entry point
 */
/* ARGSUSED */
static int
ctfs_cdir_getattr(
	vnode_t *vp,
	vattr_t *vap,
	int flags,
	cred_t *cr,
	caller_context_t *ct)
{
	ctfs_cdirnode_t *cdirnode = vp->v_data;

	vap->va_type = VDIR;
	vap->va_mode = 0555;
	vap->va_nlink = 2 + CTFS_NCTLS;
	vap->va_size = vap->va_nlink;
	vap->va_ctime = cdirnode->ctfs_cn_contract->ct_ctime;
	mutex_enter(&cdirnode->ctfs_cn_contract->ct_events.ctq_lock);
	vap->va_atime = vap->va_mtime =
	    cdirnode->ctfs_cn_contract->ct_events.ctq_atime;
	mutex_exit(&cdirnode->ctfs_cn_contract->ct_events.ctq_lock);
	ctfs_common_getattr(vp, vap);

	return (0);
}

/*
 * ctfs_cdir_do_inode - return inode number based on static index
 */
static ino64_t
ctfs_cdir_do_inode(vnode_t *vp, int index)
{
	ctfs_cdirnode_t *cdirnode = vp->v_data;

	return (CTFS_INO_CT_FILE(cdirnode->ctfs_cn_contract->ct_id, index));
}

/*
 * ctfs_cdir_inactive - VOP_INACTIVE entry point
 */
/* ARGSUSED */
static void
ctfs_cdir_inactive(vnode_t *vp, cred_t *cr, caller_context_t *cct)
{
	ctfs_cdirnode_t *cdirnode = vp->v_data;
	contract_t *ct = cdirnode->ctfs_cn_contract;

	mutex_enter(&ct->ct_lock);
	if (gfs_dir_inactive(vp) == NULL) {
		mutex_exit(&ct->ct_lock);
		return;
	}

	list_remove(&ct->ct_vnodes, &cdirnode->ctfs_cn_linkage);
	mutex_exit(&ct->ct_lock);

	contract_rele(ct);
	kmem_free(cdirnode, sizeof (ctfs_cdirnode_t));
}


const fs_operation_def_t ctfs_tops_cdir[] = {
	{ VOPNAME_OPEN,		{ .vop_open = ctfs_open } },
	{ VOPNAME_CLOSE,	{ .vop_close = ctfs_close } },
	{ VOPNAME_IOCTL,	{ .error = fs_inval } },
	{ VOPNAME_GETATTR,	{ .vop_getattr = ctfs_cdir_getattr } },
	{ VOPNAME_ACCESS,	{ .vop_access = ctfs_access_dir } },
	{ VOPNAME_READDIR,	{ .vop_readdir = gfs_vop_readdir } },
	{ VOPNAME_LOOKUP,	{ .vop_lookup = gfs_vop_lookup } },
	{ VOPNAME_SEEK,		{ .vop_seek = fs_seek } },
	{ VOPNAME_INACTIVE,	{ .vop_inactive = ctfs_cdir_inactive } },
	{ NULL, NULL }
};
