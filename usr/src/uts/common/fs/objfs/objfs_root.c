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


#include <fs/fs_subr.h>

#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/modctl.h>
#include <sys/objfs.h>
#include <sys/objfs_impl.h>
#include <sys/vfs_opreg.h>
#include <sys/systm.h>

extern int last_module_id;

static int objfs_root_do_lookup(vnode_t *, const char *, vnode_t **, ino64_t *,
    cred_t *, int, int *, pathname_t *);
static int objfs_root_do_readdir(vnode_t *, void *, int *,
    offset_t *, offset_t *, void *, int);

vnode_t *
objfs_create_root(vfs_t *vfsp)
{
	vnode_t *vp = gfs_root_create(sizeof (objfs_rootnode_t), vfsp,
	    objfs_ops_root, OBJFS_INO_ROOT, NULL, NULL, OBJFS_NAME_MAX,
	    objfs_root_do_readdir, objfs_root_do_lookup);

	return (vp);
}

/* ARGSUSED */
static int
objfs_root_getattr(vnode_t *vp, vattr_t *vap, int flags, cred_t *cr,
	caller_context_t *ct)
{
	vap->va_type = VDIR;
	vap->va_mode = 0555;
	vap->va_nodeid = gfs_file_inode(vp);
	vap->va_nlink = objfs_nobjs() + 2;
	vap->va_size = vap->va_nlink;
	vap->va_atime.tv_sec = vp->v_vfsp->vfs_mtime;
	vap->va_atime.tv_nsec = 0;
	vap->va_mtime = vap->va_ctime = vap->va_atime;
	return (objfs_common_getattr(vp, vap));
}

/* ARGSUSED */
static int
objfs_root_do_lookup(vnode_t *vp, const char *nm, vnode_t **vpp, ino64_t *inop,
    cred_t *cr, int flags, int *deflags, pathname_t *rpnp)
{
	int result = ENOENT;
	struct modctl *mp;

	/*
	 * Run through all the loaded modules on the system looking for
	 * a matching module name.
	 */
	mutex_enter(&mod_lock);
	mp = &modules;
	do {
		if (mp->mod_loaded &&
		    strcmp(nm, mp->mod_modname) == 0) {
			/*
			 * We drop mod_lock in order to do allocations,
			 * as modctls are persistent.
			 */
			mutex_exit(&mod_lock);
			*vpp = objfs_create_odirnode(vp, mp);
			*inop = OBJFS_INO_ODIR(mp->mod_id);
			mutex_enter(&mod_lock);
			result = 0;
			break;
		}
	} while ((mp = mp->mod_next) != &modules);
	mutex_exit(&mod_lock);

	return (result);
}

/* ARGSUSED */
int
objfs_root_do_readdir(vnode_t *vp, void *dp, int *eofp,
    offset_t *offp, offset_t *nextp, void *data, int flags)
{
	struct modctl **mpp = data;
	struct modctl *mp = *mpp;
	struct dirent64 *odp = dp;

	ASSERT(!(flags & V_RDDIR_ENTFLAGS));

	mutex_enter(&mod_lock);

	/* Check for EOF */
	if (*offp >= last_module_id) {
		*eofp = 1;
		mutex_exit(&mod_lock);
		return (0);
	}

	/*
	 * Find the appropriate modctl
	 */
	while (mp->mod_id < *offp) {
		mp = mp->mod_next;
		ASSERT(mp != &modules);
	}

	while (!mp->mod_loaded && mp != &modules)
		mp = mp->mod_next;

	if (mp == &modules && *offp != 0) {
		*eofp = 1;
		mutex_exit(&mod_lock);
		return (0);
	}

	/*
	 * The modctl will not change, as they are persistent.
	 */
	mutex_exit(&mod_lock);

	(void) strncpy(odp->d_name, mp->mod_modname, OBJFS_NAME_MAX);
	odp->d_ino = OBJFS_INO_ODIR(mp->mod_id);
	*offp = mp->mod_id;
	*nextp = mp->mod_id + 1;

	return (0);
}

/* ARGSUSED */
static int
objfs_root_readdir(vnode_t *vp, uio_t *uiop, cred_t *cr, int *eofp,
	caller_context_t *ct, int flags)
{
	struct modctl *mp = &modules;

	return (gfs_dir_readdir(vp, uiop, eofp, &mp, cr, ct, flags));
}

const fs_operation_def_t objfs_tops_root[] = {
	{ VOPNAME_OPEN,		{ .vop_open = objfs_dir_open } },
	{ VOPNAME_CLOSE,	{ .vop_close = objfs_common_close } },
	{ VOPNAME_IOCTL,	{ .error = fs_inval } },
	{ VOPNAME_GETATTR,	{ .vop_getattr = objfs_root_getattr } },
	{ VOPNAME_ACCESS,	{ .vop_access = objfs_dir_access } },
	{ VOPNAME_READDIR,	{ .vop_readdir = objfs_root_readdir } },
	{ VOPNAME_LOOKUP,	{ .vop_lookup = gfs_vop_lookup } },
	{ VOPNAME_SEEK,		{ .vop_seek = fs_seek } },
	{ VOPNAME_INACTIVE,	{ .vop_inactive = gfs_vop_inactive } },
	{ NULL }
};
