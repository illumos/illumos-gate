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
#include <sys/pathname.h>

/*
 * CTFS routines for the /system/contract/all vnode.
 */

static int ctfs_adir_do_readdir(vnode_t *, void *, int *, offset_t *,
    offset_t *, void *, int);
static int ctfs_adir_do_lookup(vnode_t *, const char *, vnode_t **, ino64_t *,
    cred_t *, int, int *, pathname_t *);

/*
 * ctfs_create_adirnode
 */
/* ARGSUSED */
vnode_t *
ctfs_create_adirnode(vnode_t *pvp)
{
	vnode_t *vp = gfs_dir_create(sizeof (ctfs_adirnode_t), pvp,
	    ctfs_ops_adir, NULL, NULL, CTFS_NAME_MAX, ctfs_adir_do_readdir,
	    ctfs_adir_do_lookup);

	return (vp);
}

/*
 * ctfs_adir_getattr - VOP_GETATTR entry point
 */
/* ARGSUSED */
static int
ctfs_adir_getattr(
	vnode_t *vp,
	vattr_t *vap,
	int flags,
	cred_t *cr,
	caller_context_t *ct)
{
	int i, total;

	vap->va_type = VDIR;
	vap->va_mode = 0555;
	for (i = 0, total = 0; i < ct_ntypes; i++)
		total += contract_type_count(ct_types[i]);
	vap->va_nlink = 2;
	vap->va_size = 2 + total;
	vap->va_ctime.tv_sec = vp->v_vfsp->vfs_mtime;
	vap->va_ctime.tv_nsec = 0;
	vap->va_mtime = vap->va_atime = vap->va_ctime;
	ctfs_common_getattr(vp, vap);

	return (0);
}

/* ARGSUSED */
static int
ctfs_adir_do_lookup(vnode_t *vp, const char *nm, vnode_t **vpp, ino64_t *inop,
    cred_t *cr, int flags, int *deflags, pathname_t *rpnp)
{
	int i;
	contract_t *ct;

	i = stoi((char **)&nm);
	if (*nm != '\0')
		return (ENOENT);

	ct = contract_ptr(i, VTOZONE(vp)->zone_uniqid);
	if (ct == NULL)
		return (ENOENT);

	*vpp = ctfs_create_symnode(vp, ct);
	*inop = CTFS_INO_CT_LINK(ct->ct_id);
	contract_rele(ct);

	return (0);
}

/* ARGSUSED */
static int
ctfs_adir_do_readdir(vnode_t *vp, void *dp, int *eofp,
    offset_t *offp, offset_t *nextp, void *unused, int flags)
{
	uint64_t zuniqid;
	ctid_t next;
	struct dirent64 *odp = dp;

	ASSERT(!(flags & V_RDDIR_ENTFLAGS));

	zuniqid = VTOZONE(vp)->zone_uniqid;
	next = contract_lookup(zuniqid, *offp);

	if (next == -1) {
		*eofp = 1;
		return (0);
	}

	odp->d_ino = CTFS_INO_CT_LINK(next);
	numtos(next, odp->d_name);
	*offp = next;
	*nextp = next + 1;

	return (0);
}

const fs_operation_def_t ctfs_tops_adir[] = {
	{ VOPNAME_OPEN,		{ .vop_open = ctfs_open } },
	{ VOPNAME_CLOSE,	{ .vop_close = ctfs_close } },
	{ VOPNAME_IOCTL,	{ .error = fs_inval } },
	{ VOPNAME_GETATTR,	{ .vop_getattr = ctfs_adir_getattr } },
	{ VOPNAME_ACCESS,	{ .vop_access = ctfs_access_dir } },
	{ VOPNAME_READDIR,	{ .vop_readdir = gfs_vop_readdir } },
	{ VOPNAME_LOOKUP,	{ .vop_lookup = gfs_vop_lookup } },
	{ VOPNAME_SEEK,		{ .vop_seek = fs_seek } },
	{ VOPNAME_INACTIVE,	{ .vop_inactive = gfs_vop_inactive } },
	{ NULL, NULL }
};
