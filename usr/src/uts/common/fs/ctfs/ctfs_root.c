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

#include <sys/modctl.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/cred.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/gfs.h>
#include <sys/vnode.h>
#include <sys/systm.h>
#include <sys/cmn_err.h>
#include <sys/errno.h>
#include <sys/sysmacros.h>
#include <sys/policy.h>
#include <sys/mount.h>
#include <sys/pathname.h>
#include <sys/dirent.h>
#include <fs/fs_subr.h>
#include <sys/contract.h>
#include <sys/contract_impl.h>
#include <sys/ctfs.h>
#include <sys/ctfs_impl.h>
#include <sys/uio.h>
#include <sys/file.h>
#include <sys/atomic.h>
#include <sys/sunddi.h>

/*
 * ctfs, the contract filesystem.
 *
 * Exposes the construct subsystem to userland.  The structure of the
 * filesytem is a public interface, but the behavior of the files is
 * private and unstable.  Contract consumers are expected to use
 * libcontract(3lib) to operate on ctfs file descriptors.
 *
 * We're trying something a little different here.  Rather than make
 * each vnode op itself call into a vector of file type operations, we
 * actually use different vnode types (gasp!), the implementations of
 * which may call into routines providing common functionality.  This
 * design should hopefully make it easier to factor and maintain the
 * code.  For the most part, there is a separate file for each vnode
 * type's implementation.  The exceptions to this are the ctl/stat
 * nodes, which are very similar, and the three event endpoint types.
 *
 * This file contains common routines used by some or all of the vnode
 * types, the filesystem's module linkage and VFS operations, and the
 * implementation of the root vnode.
 */

/*
 * Ops vectors for all the vnode types; they have to be defined
 * somewhere.  See gfs_make_opsvec for thoughts on how this could be
 * done differently.
 */
vnodeops_t *ctfs_ops_root;
vnodeops_t *ctfs_ops_adir;
vnodeops_t *ctfs_ops_sym;
vnodeops_t *ctfs_ops_tdir;
vnodeops_t *ctfs_ops_tmpl;
vnodeops_t *ctfs_ops_cdir;
vnodeops_t *ctfs_ops_ctl;
vnodeops_t *ctfs_ops_stat;
vnodeops_t *ctfs_ops_event;
vnodeops_t *ctfs_ops_bundle;
vnodeops_t *ctfs_ops_latest;

static const fs_operation_def_t ctfs_vfstops[];
static gfs_opsvec_t ctfs_opsvec[];

static int ctfs_init(int, char *);

static ino64_t ctfs_root_do_inode(vnode_t *, int);


/*
 * File system module linkage
 */
static mntopts_t ctfs_mntopts = {
	0,
	NULL
};

static vfsdef_t vfw = {
	VFSDEF_VERSION,
	"ctfs",
	ctfs_init,
	VSW_HASPROTO|VSW_ZMOUNT,
	&ctfs_mntopts,
};

extern struct mod_ops mod_fsops;

static struct modlfs modlfs = {
	&mod_fsops, "contract filesystem", &vfw
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
	 * As unloading filesystem modules isn't completely safe, we
	 * don't allow it.
	 */
	return (EBUSY);
}

static int ctfs_fstype;
static major_t ctfs_major;
static minor_t ctfs_minor = 0;

/*
 * The ops vector vector.
 */
static const fs_operation_def_t ctfs_tops_root[];
extern const fs_operation_def_t ctfs_tops_tmpl[];
extern const fs_operation_def_t ctfs_tops_ctl[];
extern const fs_operation_def_t ctfs_tops_adir[];
extern const fs_operation_def_t ctfs_tops_cdir[];
extern const fs_operation_def_t ctfs_tops_tdir[];
extern const fs_operation_def_t ctfs_tops_latest[];
extern const fs_operation_def_t ctfs_tops_stat[];
extern const fs_operation_def_t ctfs_tops_sym[];
extern const fs_operation_def_t ctfs_tops_event[];
extern const fs_operation_def_t ctfs_tops_bundle[];
static gfs_opsvec_t ctfs_opsvec[] = {
	{ "ctfs root directory", ctfs_tops_root, &ctfs_ops_root },
	{ "ctfs all directory", ctfs_tops_adir, &ctfs_ops_adir },
	{ "ctfs all symlink", ctfs_tops_sym, &ctfs_ops_sym },
	{ "ctfs template directory", ctfs_tops_tdir, &ctfs_ops_tdir },
	{ "ctfs template file", ctfs_tops_tmpl, &ctfs_ops_tmpl },
	{ "ctfs contract directory", ctfs_tops_cdir, &ctfs_ops_cdir },
	{ "ctfs ctl file", ctfs_tops_ctl, &ctfs_ops_ctl },
	{ "ctfs status file", ctfs_tops_stat, &ctfs_ops_stat },
	{ "ctfs events file", ctfs_tops_event, &ctfs_ops_event },
	{ "ctfs bundle file", ctfs_tops_bundle, &ctfs_ops_bundle },
	{ "ctfs latest file", ctfs_tops_latest, &ctfs_ops_latest },
	{ NULL }
};


/*
 * ctfs_init - the vfsdef_t init entry point
 *
 * Sets the VFS ops, builds all the vnode ops, and allocates a device
 * number.
 */
/* ARGSUSED */
static int
ctfs_init(int fstype, char *name)
{
	vfsops_t *vfsops;
	int error;

	ctfs_fstype = fstype;
	if (error = vfs_setfsops(fstype, ctfs_vfstops, &vfsops)) {
		cmn_err(CE_WARN, "ctfs_init: bad vfs ops template");
		return (error);
	}

	if (error = gfs_make_opsvec(ctfs_opsvec)) {
		(void) vfs_freevfsops(vfsops);
		return (error);
	}

	if ((ctfs_major = getudev()) == (major_t)-1) {
		cmn_err(CE_WARN, "ctfs_init: can't get unique device number");
		ctfs_major = 0;
	}

	return (0);
}

/*
 * ctfs_mount - the VFS_MOUNT entry point
 */
static int
ctfs_mount(vfs_t *vfsp, vnode_t *mvp, struct mounta *uap, cred_t *cr)
{
	ctfs_vfs_t *data;
	dev_t dev;
	gfs_dirent_t *dirent;
	int i;

	if (secpolicy_fs_mount(cr, mvp, vfsp) != 0)
		return (EPERM);

	if (mvp->v_type != VDIR)
		return (ENOTDIR);

	if ((uap->flags & MS_OVERLAY) == 0 &&
	    (mvp->v_count > 1 || (mvp->v_flag & VROOT)))
		return (EBUSY);

	data = kmem_alloc(sizeof (ctfs_vfs_t), KM_SLEEP);

	/*
	 * Initialize vfs fields not initialized by VFS_INIT/domount
	 */
	vfsp->vfs_bsize = DEV_BSIZE;
	vfsp->vfs_fstype = ctfs_fstype;
	do {
		dev = makedevice(ctfs_major,
		    atomic_inc_32_nv(&ctfs_minor) & L_MAXMIN32);
	} while (vfs_devismounted(dev));
	vfs_make_fsid(&vfsp->vfs_fsid, dev, ctfs_fstype);
	vfsp->vfs_data = data;
	vfsp->vfs_dev = dev;

	/*
	 * Dynamically create gfs_dirent_t array for the root directory.
	 */
	dirent = kmem_zalloc((ct_ntypes + 2) * sizeof (gfs_dirent_t), KM_SLEEP);
	for (i = 0; i < ct_ntypes; i++) {
		dirent[i].gfse_name = (char *)ct_types[i]->ct_type_name;
		dirent[i].gfse_ctor = ctfs_create_tdirnode;
		dirent[i].gfse_flags = GFS_CACHE_VNODE;
	}
	dirent[i].gfse_name = "all";
	dirent[i].gfse_ctor = ctfs_create_adirnode;
	dirent[i].gfse_flags = GFS_CACHE_VNODE;
	dirent[i+1].gfse_name = NULL;

	/*
	 * Create root vnode
	 */
	data->ctvfs_root = gfs_root_create(sizeof (ctfs_rootnode_t),
	    vfsp, ctfs_ops_root, CTFS_INO_ROOT, dirent, ctfs_root_do_inode,
	    CTFS_NAME_MAX, NULL, NULL);

	kmem_free(dirent, (ct_ntypes + 2) * sizeof (gfs_dirent_t));

	return (0);
}

/*
 * ctfs_unmount - the VFS_UNMOUNT entry point
 */
static int
ctfs_unmount(vfs_t *vfsp, int flag, struct cred *cr)
{
	ctfs_vfs_t *data;

	if (secpolicy_fs_unmount(cr, vfsp) != 0)
		return (EPERM);

	/*
	 * Supporting forced unmounts would be nice to do at some
	 * point.
	 */
	if (flag & MS_FORCE)
		return (ENOTSUP);

	/*
	 * We should never have a reference count less than 2: one for
	 * the caller, one for the root vnode.
	 */
	ASSERT(vfsp->vfs_count >= 2);

	/*
	 * If we have any active vnodes, they will (transitively) have
	 * holds on the root vnode.
	 */
	data = vfsp->vfs_data;
	if (data->ctvfs_root->v_count > 1)
		return (EBUSY);

	/*
	 * Release the last hold on the root vnode.  It will, in turn,
	 * release its hold on us.
	 */
	VN_RELE(data->ctvfs_root);

	/*
	 * Disappear.
	 */
	kmem_free(data, sizeof (ctfs_vfs_t));

	return (0);
}

/*
 * ctfs_root - the VFS_ROOT entry point
 */
static int
ctfs_root(vfs_t *vfsp, vnode_t **vpp)
{
	vnode_t *vp;

	vp = ((ctfs_vfs_t *)vfsp->vfs_data)->ctvfs_root;
	VN_HOLD(vp);
	*vpp = vp;

	return (0);
}

/*
 * ctfs_statvfs - the VFS_STATVFS entry point
 */
static int
ctfs_statvfs(vfs_t *vfsp, statvfs64_t *sp)
{
	dev32_t	d32;
	int	total, i;

	bzero(sp, sizeof (*sp));
	sp->f_bsize = DEV_BSIZE;
	sp->f_frsize = DEV_BSIZE;
	for (i = 0, total = 0; i < ct_ntypes; i++)
		total += contract_type_count(ct_types[i]);
	sp->f_files = total;
	sp->f_favail = sp->f_ffree = INT_MAX - total;
	(void) cmpldev(&d32, vfsp->vfs_dev);
	sp->f_fsid = d32;
	(void) strlcpy(sp->f_basetype, vfssw[vfsp->vfs_fstype].vsw_name,
	    sizeof (sp->f_basetype));
	sp->f_flag = vf_to_stf(vfsp->vfs_flag);
	sp->f_namemax = CTFS_NAME_MAX;
	(void) strlcpy(sp->f_fstr, "contract", sizeof (sp->f_fstr));

	return (0);
}

static const fs_operation_def_t ctfs_vfstops[] = {
	{ VFSNAME_MOUNT,	{ .vfs_mount = ctfs_mount } },
	{ VFSNAME_UNMOUNT,	{ .vfs_unmount = ctfs_unmount } },
	{ VFSNAME_ROOT,		{ .vfs_root = ctfs_root } },
	{ VFSNAME_STATVFS,	{ .vfs_statvfs = ctfs_statvfs } },
	{ NULL, NULL }
};

/*
 * ctfs_common_getattr
 *
 * Implements functionality common to all ctfs VOP_GETATTR entry
 * points.  It assumes vap->va_size is set.
 */
void
ctfs_common_getattr(vnode_t *vp, vattr_t *vap)
{
	vap->va_uid = 0;
	vap->va_gid = 0;
	vap->va_rdev = 0;
	vap->va_blksize = DEV_BSIZE;
	vap->va_nblocks = howmany(vap->va_size, vap->va_blksize);
	vap->va_seq = 0;
	vap->va_fsid = vp->v_vfsp->vfs_dev;
	vap->va_nodeid = gfs_file_inode(vp);
}

/*
 * ctfs_open - common VOP_OPEN entry point
 *
 * Used by all ctfs directories; just verifies we are using large-file
 * aware interfaces and we aren't trying to open the directories
 * writable.
 */
/* ARGSUSED */
int
ctfs_open(vnode_t **vpp, int flag, cred_t *cr, caller_context_t *ct)
{
	if ((flag & (FOFFMAX | FWRITE)) != FOFFMAX)
		return (EINVAL);

	return (0);
}

/*
 * ctfs_close - common VOP_CLOSE entry point
 *
 * For all ctfs vnode types which have no close-time clean-up to do.
 */
/* ARGSUSED */
int
ctfs_close(
	vnode_t *vp,
	int flag,
	int count,
	offset_t offset,
	cred_t *cr,
	caller_context_t *ct)
{
	return (0);
}

/*
 * ctfs_access_dir - common VOP_ACCESS entry point for directories
 */
/* ARGSUSED */
int
ctfs_access_dir(
	vnode_t *vp,
	int mode,
	int flags,
	cred_t *cr,
	caller_context_t *ct)
{
	if (mode & VWRITE)
		return (EACCES);

	return (0);
}

/*
 * ctfs_access_dir - common VOP_ACCESS entry point for read-only files
 */
/* ARGSUSED */
int
ctfs_access_readonly(
	vnode_t *vp,
	int mode,
	int flags,
	cred_t *cr,
	caller_context_t *ct)
{
	if (mode & (VWRITE | VEXEC))
		return (EACCES);

	return (0);
}

/*
 * ctfs_access_dir - common VOP_ACCESS entry point for read-write files
 */
/* ARGSUSED */
int
ctfs_access_readwrite(
	vnode_t *vp,
	int mode,
	int flags,
	cred_t *cr,
	caller_context_t *ct)
{
	if (mode & VEXEC)
		return (EACCES);

	return (0);
}

/*
 * ctfs_root_getattr - VOP_GETATTR entry point
 */
/* ARGSUSED */
static int
ctfs_root_getattr(
	vnode_t *vp,
	vattr_t *vap,
	int flags,
	cred_t *cr,
	caller_context_t *ct)
{
	vap->va_type = VDIR;
	vap->va_mode = 0555;
	vap->va_nlink = 2 + ct_ntypes + 1;
	vap->va_size = vap->va_nlink;
	vap->va_atime.tv_sec = vp->v_vfsp->vfs_mtime;
	vap->va_atime.tv_nsec = 0;
	vap->va_mtime = vap->va_ctime = vap->va_atime;
	ctfs_common_getattr(vp, vap);

	return (0);
}

/* ARGSUSED */
static ino64_t
ctfs_root_do_inode(vnode_t *vp, int index)
{
	return (CTFS_INO_TYPE_DIR(index));
}

static const fs_operation_def_t ctfs_tops_root[] = {
	{ VOPNAME_OPEN,		{ .vop_open = ctfs_open } },
	{ VOPNAME_CLOSE,	{ .vop_close = ctfs_close } },
	{ VOPNAME_IOCTL,	{ .error = fs_inval } },
	{ VOPNAME_GETATTR,	{ .vop_getattr = ctfs_root_getattr } },
	{ VOPNAME_ACCESS,	{ .vop_access = ctfs_access_dir } },
	{ VOPNAME_READDIR,	{ .vop_readdir = gfs_vop_readdir } },
	{ VOPNAME_LOOKUP,	{ .vop_lookup = gfs_vop_lookup } },
	{ VOPNAME_SEEK,		{ .vop_seek = fs_seek } },
	{ VOPNAME_INACTIVE,	{ .vop_inactive = gfs_vop_inactive } },
	{ NULL, NULL }
};
