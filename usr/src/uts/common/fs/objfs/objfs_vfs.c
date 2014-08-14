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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/atomic.h>
#include <sys/cmn_err.h>
#include <sys/errno.h>
#include <sys/mount.h>
#include <sys/objfs.h>
#include <sys/objfs_impl.h>
#include <sys/vfs_opreg.h>
#include <sys/policy.h>
#include <sys/sunddi.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>

/*
 * Kernel object filesystem.
 *
 * This is a pseudo filesystem which exports information about currently loaded
 * kernel objects.  The root directory contains one directory for each loaded
 * object, indexed by module name.  Within each object directory is an ELF file,
 * 'object', that contains information about the currently loaded module.
 *
 * This file contains functions that interact with the VFS layer.  Each
 * filesystem element is represented by a a different node.
 *
 * 	/		objfs_rootnode_t	objfs_root.c
 *	/<obj>		objfs_odirnode_t	objfs_odir.c
 *	/<obj>/object	objfs_datanode_t	objfs_data.c
 *
 * In addition, some common routines are found in the 'objfs_common.c' file.
 */

vnodeops_t *objfs_ops_root;
vnodeops_t *objfs_ops_odir;
vnodeops_t *objfs_ops_data;

static const fs_operation_def_t objfs_vfstops[];
static gfs_opsvec_t objfs_opsvec[];

static int objfs_init(int, char *);

/*
 * Module linkage
 */
static mntopts_t objfs_mntopts = {
	0,
	NULL
};

static vfsdef_t vfw = {
	VFSDEF_VERSION,
	"objfs",
	objfs_init,
	VSW_HASPROTO | VSW_ZMOUNT,
	&objfs_mntopts,
};

extern struct mod_ops mod_fsops;

static struct modlfs modlfs = {
	&mod_fsops, "kernel object filesystem", &vfw
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlfs, NULL
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	/*
	 * The object filesystem cannot be unloaded.
	 */
	return (EBUSY);
}

/*
 * Filesystem initialization.
 */

static int objfs_fstype;
static major_t objfs_major;
static minor_t objfs_minor;

static gfs_opsvec_t objfs_opsvec[] = {
	{ "objfs root directory", objfs_tops_root, &objfs_ops_root },
	{ "objfs object directory", objfs_tops_odir, &objfs_ops_odir },
	{ "objfs data file", objfs_tops_data, &objfs_ops_data },
	{ NULL }
};

/* ARGSUSED */
static int
objfs_init(int fstype, char *name)
{
	vfsops_t *vfsops;
	int error;

	objfs_fstype = fstype;
	if (error = vfs_setfsops(fstype, objfs_vfstops, &vfsops)) {
		cmn_err(CE_WARN, "objfs_init: bad vfs ops template");
		return (error);
	}

	if (error = gfs_make_opsvec(objfs_opsvec)) {
		(void) vfs_freevfsops(vfsops);
		return (error);
	}

	if ((objfs_major = getudev()) == (major_t)-1) {
		cmn_err(CE_WARN, "objfs_init: can't get unique device number");
		objfs_major = 0;
	}

	objfs_data_init();

	return (0);
}

/*
 * VFS entry points
 */
static int
objfs_mount(vfs_t *vfsp, vnode_t *mvp, struct mounta *uap, cred_t *cr)
{
	objfs_vfs_t *data;
	dev_t dev;

	if (secpolicy_fs_mount(cr, mvp, vfsp) != 0)
		return (EPERM);

	if (mvp->v_type != VDIR)
		return (ENOTDIR);

	if ((uap->flags & MS_OVERLAY) == 0 &&
	    (mvp->v_count > 1 || (mvp->v_flag & VROOT)))
		return (EBUSY);

	data = kmem_alloc(sizeof (objfs_vfs_t), KM_SLEEP);

	/*
	 * Initialize vfs fields
	 */
	vfsp->vfs_bsize = DEV_BSIZE;
	vfsp->vfs_fstype = objfs_fstype;
	do {
		dev = makedevice(objfs_major,
		    atomic_inc_32_nv(&objfs_minor) & L_MAXMIN32);
	} while (vfs_devismounted(dev));
	vfs_make_fsid(&vfsp->vfs_fsid, dev, objfs_fstype);
	vfsp->vfs_data = data;
	vfsp->vfs_dev = dev;

	/*
	 * Create root
	 */
	data->objfs_vfs_root = objfs_create_root(vfsp);

	return (0);
}

static int
objfs_unmount(vfs_t *vfsp, int flag, struct cred *cr)
{
	objfs_vfs_t *data;

	if (secpolicy_fs_unmount(cr, vfsp) != 0)
		return (EPERM);

	/*
	 * We do not currently support forced unmounts
	 */
	if (flag & MS_FORCE)
		return (ENOTSUP);

	/*
	 * We should never have a reference count of less than 2: one for the
	 * caller, one for the root vnode.
	 */
	ASSERT(vfsp->vfs_count >= 2);

	/*
	 * Any active vnodes will result in a hold on the root vnode
	 */
	data = vfsp->vfs_data;
	if (data->objfs_vfs_root->v_count > 1)
		return (EBUSY);

	/*
	 * Release the last hold on the root vnode
	 */
	VN_RELE(data->objfs_vfs_root);

	kmem_free(data, sizeof (objfs_vfs_t));

	return (0);
}

static int
objfs_root(vfs_t *vfsp, vnode_t **vpp)
{
	objfs_vfs_t *data = vfsp->vfs_data;

	*vpp = data->objfs_vfs_root;
	VN_HOLD(*vpp);

	return (0);
}

static int
objfs_statvfs(vfs_t *vfsp, statvfs64_t *sp)
{
	dev32_t d32;
	int total = objfs_nobjs();

	bzero(sp, sizeof (*sp));
	sp->f_bsize = DEV_BSIZE;
	sp->f_frsize = DEV_BSIZE;
	sp->f_files = total;
	sp->f_ffree = sp->f_favail = INT_MAX - total;
	(void) cmpldev(&d32, vfsp->vfs_dev);
	sp->f_fsid = d32;
	(void) strlcpy(sp->f_basetype, vfssw[vfsp->vfs_fstype].vsw_name,
	    sizeof (sp->f_basetype));
	sp->f_flag = vf_to_stf(vfsp->vfs_flag);
	sp->f_namemax = OBJFS_NAME_MAX;
	(void) strlcpy(sp->f_fstr, "object", sizeof (sp->f_fstr));

	return (0);
}

static const fs_operation_def_t objfs_vfstops[] = {
	{ VFSNAME_MOUNT,	{ .vfs_mount = objfs_mount } },
	{ VFSNAME_UNMOUNT,	{ .vfs_unmount = objfs_unmount } },
	{ VFSNAME_ROOT,		{ .vfs_root = objfs_root } },
	{ VFSNAME_STATVFS,	{ .vfs_statvfs = objfs_statvfs } },
	{ NULL }
};
