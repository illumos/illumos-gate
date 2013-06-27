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
 * Copyright (c) 1990, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2011 Bayard G. Bell. All rights reserved.
 * Copyright 2013 Joyent, Inc. All rights reserved.
 */

/*
 * VFS operations for High Sierra filesystem
 */

#include <sys/types.h>
#include <sys/isa_defs.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/kmem.h>
#include <sys/signal.h>
#include <sys/user.h>
#include <sys/proc.h>
#include <sys/disp.h>
#include <sys/buf.h>
#include <sys/pathname.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/uio.h>
#include <sys/conf.h>
#include <sys/policy.h>

#include <vm/page.h>

#include <sys/fs/snode.h>
#include <sys/fs/hsfs_spec.h>
#include <sys/fs/hsfs_isospec.h>
#include <sys/fs/hsfs_node.h>
#include <sys/fs/hsfs_impl.h>
#include <sys/fs/hsfs_susp.h>
#include <sys/fs/hsfs_rrip.h>

#include <sys/statvfs.h>
#include <sys/mount.h>
#include <sys/mntent.h>
#include <sys/swap.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include "fs/fs_subr.h"
#include <sys/cmn_err.h>
#include <sys/bootconf.h>

#include <sys/sdt.h>

/*
 * These are needed for the CDROMREADOFFSET Code
 */
#include <sys/cdio.h>
#include <sys/sunddi.h>

#define	HSFS_CLKSET

#include <sys/modctl.h>

/*
 * Options for mount.
 */
#define	HOPT_GLOBAL	MNTOPT_GLOBAL
#define	HOPT_NOGLOBAL	MNTOPT_NOGLOBAL
#define	HOPT_MAPLCASE	"maplcase"
#define	HOPT_NOMAPLCASE	"nomaplcase"
#define	HOPT_NOTRAILDOT	"notraildot"
#define	HOPT_TRAILDOT	"traildot"
#define	HOPT_NRR	"nrr"
#define	HOPT_RR		"rr"
#define	HOPT_JOLIET	"joliet"
#define	HOPT_NOJOLIET	"nojoliet"
#define	HOPT_JOLIETLONG	"jolietlong"
#define	HOPT_VERS2	"vers2"
#define	HOPT_NOVERS2	"novers2"
#define	HOPT_RO		MNTOPT_RO

static char *global_cancel[] = { HOPT_NOGLOBAL, NULL };
static char *noglobal_cancel[] = { HOPT_GLOBAL, NULL };
static char *mapl_cancel[] = { HOPT_NOMAPLCASE, NULL };
static char *nomapl_cancel[] = { HOPT_MAPLCASE, NULL };
static char *ro_cancel[] = { MNTOPT_RW, NULL };
static char *rr_cancel[] = { HOPT_NRR, NULL };
static char *nrr_cancel[] = { HOPT_RR, NULL };
static char *joliet_cancel[] = { HOPT_NOJOLIET, NULL };
static char *nojoliet_cancel[] = { HOPT_JOLIET, NULL };
static char *vers2_cancel[] = { HOPT_NOVERS2, NULL };
static char *novers2_cancel[] = { HOPT_VERS2, NULL };
static char *trail_cancel[] = { HOPT_NOTRAILDOT, NULL };
static char *notrail_cancel[] = { HOPT_TRAILDOT, NULL };

static mntopt_t hsfs_options[] = {
	{ HOPT_GLOBAL, global_cancel, NULL, 0, NULL },
	{ HOPT_NOGLOBAL, noglobal_cancel, NULL, MO_DEFAULT, NULL },
	{ HOPT_MAPLCASE, mapl_cancel, NULL, MO_DEFAULT, NULL },
	{ HOPT_NOMAPLCASE, nomapl_cancel, NULL, 0, NULL },
	{ HOPT_RO, ro_cancel, NULL, MO_DEFAULT, NULL },
	{ HOPT_RR, rr_cancel, NULL, MO_DEFAULT, NULL },
	{ HOPT_NRR, nrr_cancel, NULL, 0, NULL },
	{ HOPT_JOLIET, joliet_cancel, NULL, 0, NULL },
	{ HOPT_NOJOLIET, nojoliet_cancel, NULL, 0, NULL },
	{ HOPT_JOLIETLONG, NULL, NULL, 0, NULL },
	{ HOPT_VERS2, vers2_cancel, NULL, 0, NULL },
	{ HOPT_NOVERS2, novers2_cancel, NULL, 0, NULL },
	{ HOPT_TRAILDOT, trail_cancel, NULL, MO_DEFAULT, NULL },
	{ HOPT_NOTRAILDOT, notrail_cancel, NULL, 0, NULL },
	{ "sector", NULL, "0", MO_HASVALUE, NULL},
};

static mntopts_t hsfs_proto_opttbl = {
	sizeof (hsfs_options) / sizeof (mntopt_t),
	hsfs_options
};

/*
 * Indicates whether to enable the I/O scheduling and readahead logic
 * 1 - Enable, 0 - Do not Enable.
 * Debugging purposes.
 */
int do_schedio = 1;
static int hsfsfstype;
static int hsfsinit(int, char *);

static vfsdef_t vfw = {
	VFSDEF_VERSION,
	"hsfs",
	hsfsinit,
	/* We don't suppport remounting */
	VSW_HASPROTO|VSW_STATS|VSW_CANLOFI,
	&hsfs_proto_opttbl
};

static struct modlfs modlfs = {
	&mod_fsops, "filesystem for HSFS", &vfw
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlfs, NULL
};

extern void hsched_init_caches(void);
extern void hsched_fini_caches(void);


int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	int	error;

	error = mod_remove(&modlinkage);

	DTRACE_PROBE1(mod_remove, int, error);

	if (error)
		return (error);

	mutex_destroy(&hs_mounttab_lock);

	/*
	 * Tear down the operations vectors
	 */
	(void) vfs_freevfsops_by_type(hsfsfstype);
	vn_freevnodeops(hsfs_vnodeops);

	hs_fini_hsnode_cache();
	hsched_fini_caches();
	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

#define	BDEVFLAG(dev)	((devopsp[getmajor(dev)])->devo_cb_ops->cb_flag)

kmutex_t hs_mounttab_lock;
struct hsfs *hs_mounttab = NULL;

/* default mode, uid, gid */
mode_t hsfs_default_mode = 0555;
uid_t hsfs_default_uid = 0;
gid_t hsfs_default_gid = 3;

extern void hsched_init(struct hsfs *fsp, int fsid,
					struct modlinkage *modlinkage);
extern void hsched_fini(struct hsfs_queue *hqueue);
extern void hsfs_init_kstats(struct hsfs *fsp, int fsid);
extern void hsfs_fini_kstats(struct hsfs *fsp);

static int hsfs_mount(struct vfs *vfsp, struct vnode *mvp,
	struct mounta *uap, struct cred *cr);
static int hsfs_unmount(struct vfs *vfsp, int, struct cred *cr);
static int hsfs_root(struct vfs *vfsp, struct vnode **vpp);
static int hsfs_statvfs(struct vfs *vfsp, struct statvfs64 *sbp);
static int hsfs_vget(struct vfs *vfsp, struct vnode **vpp, struct fid *fidp);
static int hsfs_mountroot(struct vfs *, enum whymountroot);

static int hs_mountfs(struct vfs *vfsp, dev_t dev, char *path,
	mode_t mode, int flags, struct cred *cr, int isroot);
static int hs_getrootvp(struct vfs *vfsp, struct hsfs *fsp, size_t pathsize);
static int hs_findhsvol(struct hsfs *fsp, struct vnode *vp,
	struct hs_volume *hvp);
static int hs_parsehsvol(struct hsfs *fsp, uchar_t *volp,
	struct hs_volume *hvp);
static int hs_findisovol(struct hsfs *fsp, struct vnode *vp,
	struct hs_volume *hvp,
	struct hs_volume *svp,
	struct hs_volume *jvp);
static int hs_joliet_level(uchar_t *volp);
static int hs_parseisovol(struct hsfs *fsp, uchar_t *volp,
	struct hs_volume *hvp);
static void hs_copylabel(struct hs_volume *, unsigned char *, int);
static int hs_getmdev(struct vfs *, char *fspec, int flags, dev_t *pdev,
	mode_t *mode, cred_t *cr);
static int hs_findvoldesc(dev_t rdev, int desc_sec);

static int
hsfsinit(int fstype, char *name)
{
	static const fs_operation_def_t hsfs_vfsops_template[] = {
		VFSNAME_MOUNT,		{ .vfs_mount = hsfs_mount },
		VFSNAME_UNMOUNT,	{ .vfs_unmount = hsfs_unmount },
		VFSNAME_ROOT,		{ .vfs_root = hsfs_root },
		VFSNAME_STATVFS,	{ .vfs_statvfs = hsfs_statvfs },
		VFSNAME_VGET,		{ .vfs_vget = hsfs_vget },
		VFSNAME_MOUNTROOT,	{ .vfs_mountroot = hsfs_mountroot },
		NULL,			NULL
	};
	int error;

	error = vfs_setfsops(fstype, hsfs_vfsops_template, NULL);
	if (error != 0) {
		cmn_err(CE_WARN, "hsfsinit: bad vfs ops template");
		return (error);
	}

	error = vn_make_ops(name, hsfs_vnodeops_template, &hsfs_vnodeops);
	if (error != 0) {
		(void) vfs_freevfsops_by_type(fstype);
		cmn_err(CE_WARN, "hsfsinit: bad vnode ops template");
		return (error);
	}

	hsfsfstype = fstype;
	mutex_init(&hs_mounttab_lock, NULL, MUTEX_DEFAULT, NULL);
	hs_init_hsnode_cache();
	hsched_init_caches();
	return (0);
}

/*ARGSUSED*/
static int
hsfs_mount(struct vfs *vfsp, struct vnode *mvp,
    struct mounta *uap, struct cred *cr)
{
	int		vnode_busy;
	dev_t		dev;
	struct pathname dpn;
	int		error;
	mode_t		mode;
	int		flags;	/* this will hold the mount specific data */

	if ((error = secpolicy_fs_mount(cr, mvp, vfsp)) != 0)
		return (error);

	if (mvp->v_type != VDIR)
		return (ENOTDIR);

	/* mount option must be read only, else mount will be rejected */
	if (!(uap->flags & MS_RDONLY))
		return (EROFS);

	/*
	 * We already told the framework that we don't support remounting.
	 */
	ASSERT(!(uap->flags & MS_REMOUNT));

	mutex_enter(&mvp->v_lock);
	vnode_busy = (mvp->v_count != 1) || (mvp->v_flag & VROOT);
	mutex_exit(&mvp->v_lock);

	if ((uap->flags & MS_OVERLAY) == 0 && vnode_busy) {
		return (EBUSY);
	}

	/*
	 * Check for the options that actually affect things
	 * at our level.
	 */
	flags = 0;
	if (vfs_optionisset(vfsp, HOPT_NOMAPLCASE, NULL))
		flags |= HSFSMNT_NOMAPLCASE;
	if (vfs_optionisset(vfsp, HOPT_NOTRAILDOT, NULL))
		flags |= HSFSMNT_NOTRAILDOT;
	if (vfs_optionisset(vfsp, HOPT_NRR, NULL))
		flags |= HSFSMNT_NORRIP;
	if (vfs_optionisset(vfsp, HOPT_NOJOLIET, NULL))
		flags |= HSFSMNT_NOJOLIET;
	if (vfs_optionisset(vfsp, HOPT_JOLIETLONG, NULL))
		flags |= HSFSMNT_JOLIETLONG;
	if (vfs_optionisset(vfsp, HOPT_NOVERS2, NULL))
		flags |= HSFSMNT_NOVERS2;

	error = pn_get(uap->dir, (uap->flags & MS_SYSSPACE) ?
	    UIO_SYSSPACE : UIO_USERSPACE, &dpn);
	if (error)
		return (error);

	error = hs_getmdev(vfsp, uap->spec, uap->flags, &dev, &mode, cr);
	if (error != 0) {
		pn_free(&dpn);
		return (error);
	}

	/*
	 * If the device is a tape, return error
	 */
	if ((BDEVFLAG(dev) & D_TAPE) == D_TAPE)  {
		pn_free(&dpn);
		return (ENOTBLK);
	}

	/*
	 * Mount the filesystem.
	 */
	error = hs_mountfs(vfsp, dev, dpn.pn_path, mode, flags, cr, 0);
	pn_free(&dpn);
	return (error);
}

/*ARGSUSED*/
static int
hsfs_unmount(
	struct vfs *vfsp,
	int flag,
	struct cred *cr)
{
	struct hsfs **tspp;
	struct hsfs *fsp;

	if (secpolicy_fs_unmount(cr, vfsp) != 0)
		return (EPERM);

	/*
	 * forced unmount is not supported by this file system
	 * and thus, ENOTSUP is being returned.
	 */
	if (flag & MS_FORCE)
		return (ENOTSUP);

	fsp = VFS_TO_HSFS(vfsp);

	if (fsp->hsfs_rootvp->v_count != 1)
		return (EBUSY);

	/* destroy all old pages and hsnodes for this vfs */
	if (hs_synchash(vfsp))
		return (EBUSY);

	mutex_enter(&hs_mounttab_lock);
	for (tspp = &hs_mounttab; *tspp != NULL; tspp = &(*tspp)->hsfs_next) {
		if (*tspp == fsp)
			break;
	}
	if (*tspp == NULL) {
		mutex_exit(&hs_mounttab_lock);
		panic("hsfs_unmount: vfs not mounted?");
		/*NOTREACHED*/
	}

	*tspp = fsp->hsfs_next;

	mutex_exit(&hs_mounttab_lock);

	hsfs_fini_kstats(fsp);
	(void) VOP_CLOSE(fsp->hsfs_devvp, FREAD, 1, (offset_t)0, cr, NULL);
	VN_RELE(fsp->hsfs_devvp);
	/* free path table space */
	if (fsp->hsfs_ptbl != NULL)
		kmem_free(fsp->hsfs_ptbl, (size_t)fsp->hsfs_vol.ptbl_len);
	/* free path table index table */
	if (fsp->hsfs_ptbl_idx != NULL)
		kmem_free(fsp->hsfs_ptbl_idx, (size_t)
		    (fsp->hsfs_ptbl_idx_size * sizeof (struct ptable_idx)));

	/* free "mounted on" pathame */
	if (fsp->hsfs_fsmnt != NULL)
		kmem_free(fsp->hsfs_fsmnt, strlen(fsp->hsfs_fsmnt) + 1);

	hsched_fini(fsp->hqueue);
	kmem_free(fsp->hqueue, sizeof (struct hsfs_queue));

	mutex_destroy(&fsp->hsfs_free_lock);
	rw_destroy(&fsp->hsfs_hash_lock);

	kmem_free(fsp, sizeof (*fsp));
	return (0);
}

/*ARGSUSED*/
static int
hsfs_root(struct vfs *vfsp, struct vnode **vpp)
{
	*vpp = (VFS_TO_HSFS(vfsp))->hsfs_rootvp;
	VN_HOLD(*vpp);
	return (0);
}

/*ARGSUSED*/
static int
hsfs_statvfs(struct vfs *vfsp, struct statvfs64 *sbp)
{
	struct hsfs *fsp;
	dev32_t d32;

	fsp = VFS_TO_HSFS(vfsp);
	if (fsp->hsfs_magic != HSFS_MAGIC)
		return (EINVAL);
	bzero(sbp, sizeof (*sbp));
	sbp->f_bsize = vfsp->vfs_bsize;
	sbp->f_frsize = sbp->f_bsize; /* no fragment, same as block size */
	sbp->f_blocks = (fsblkcnt64_t)fsp->hsfs_vol.vol_size;

	sbp->f_bfree = (fsblkcnt64_t)0;
	sbp->f_bavail = (fsblkcnt64_t)0;
	sbp->f_files = (fsfilcnt64_t)-1;
	sbp->f_ffree = (fsfilcnt64_t)0;
	sbp->f_favail = (fsfilcnt64_t)0;
	(void) cmpldev(&d32, vfsp->vfs_dev);
	sbp->f_fsid = d32;
	(void) strcpy(sbp->f_basetype, vfssw[vfsp->vfs_fstype].vsw_name);
	sbp->f_flag = vf_to_stf(vfsp->vfs_flag);
	sbp->f_namemax = fsp->hsfs_namemax;
	(void) strcpy(sbp->f_fstr, fsp->hsfs_vol.vol_id);

	return (0);
}

/*
 * Previously nodeid was declared as uint32_t. This has been changed
 * to conform better with the ISO9660 standard. The standard states that
 * a LBN can be a 32 bit number, as the MAKE_NODEID macro shifts this
 * LBN 11 places left (LBN_TO_BYTE) and then shifts the result 5 right
 * (divide by 32) we are left with the potential of an overflow if
 * confined to a 32 bit value.
 */

static int
hsfs_vget(struct vfs *vfsp, struct vnode **vpp, struct fid *fidp)
{
	struct hsfid *fid;
	struct hsfs *fsp;
	ino64_t nodeid;
	int error;

	fsp = (struct hsfs *)VFS_TO_HSFS(vfsp);
	fid = (struct hsfid *)fidp;

	/*
	 * Look for vnode on hashlist.
	 * If found, it's now active and the refcnt was incremented.
	 */

	rw_enter(&fsp->hsfs_hash_lock, RW_READER);

	nodeid = fid->hf_ino;

	if ((*vpp = hs_findhash(nodeid, fid->hf_dir_lbn,
	    (uint_t)fid->hf_dir_off, vfsp)) == NULL) {
		/*
		 * Not in cache, so we need to remake it.
		 * hs_remakenode() will read the directory entry
		 * and then check again to see if anyone else has
		 * put it in the cache.
		 */
		rw_exit(&fsp->hsfs_hash_lock);
		error = hs_remakenode(fid->hf_dir_lbn, (uint_t)fid->hf_dir_off,
		    vfsp, vpp);
		return (error);
	}
	rw_exit(&fsp->hsfs_hash_lock);
	return (0);
}


#define	CHECKSUM_SIZE				(64 * 1024)

/*
 * Compute a CD-ROM fsid by checksumming the first 64K of data on the CD
 * We use the 'fsp' argument to determine the location of the root
 * directory entry, and we start reading from there.
 */
static int
compute_cdrom_id(struct hsfs *fsp, vnode_t *devvp)
{
	uint_t		secno;
	struct hs_volume *hsvp = &fsp->hsfs_vol;
	struct buf	*bp;
	int		error;
	int		fsid;

	secno = hsvp->root_dir.ext_lbn >> hsvp->lbn_secshift;
	bp = bread(devvp->v_rdev, secno * 4, CHECKSUM_SIZE);
	error = geterror(bp);

	/*
	 * An error on read or a partial read means we asked
	 * for a nonexistant/corrupted piece of the device
	 * (including past-the-end of the media). Don't
	 * try to use the checksumming method then.
	 */
	if (!error && bp->b_bcount == CHECKSUM_SIZE) {
		int *ibuf = (int *)bp->b_un.b_addr;
		int i;

		fsid = 0;

		for (i = 0; i < CHECKSUM_SIZE / sizeof (int); i++)
			fsid ^= ibuf[ i ];
	} else {
		/*
		 * Fallback - use creation date
		 */
		fsid = hsvp->cre_date.tv_sec;
	}

	brelse(bp);

	return (fsid);
}


/*ARGSUSED*/
static int
hs_mountfs(
	struct vfs	*vfsp,
	dev_t		dev,
	char		*path,
	mode_t		mode,
	int		mount_flags,
	struct cred	*cr,
	int		isroot)
{
	struct vnode	*devvp;
	struct hsfs	*tsp;
	struct hsfs	*fsp = NULL;
	struct vattr	vap;
	struct hsnode	*hp;
	int		error;
	struct timeval	tv;
	int		fsid;
	int		use_rrip;
	int		use_vers2;
	int		use_joliet;
	int		has_rrip = 0;
	int		has_vers2 = 0;
	int		has_joliet = 0;
	int		force_rrip_off;
	int		force_vers2_off;
	int		force_joliet_off;
	size_t		pathbufsz = strlen(path) + 1;
	int		redo_rootvp;

	struct hs_volume *svp = NULL;	/* Supplemental VD for ISO-9660:1999 */
	struct hs_volume *jvp = NULL;	/* Joliet VD */

	/*
	 * The rules for which extension will be used are:
	 * 1. No specific mount options given:
	 *	- use rrip if available
	 *	- use ISO9660:1999 if available
	 *	- use joliet if available.
	 * 2. rrip/ISO9660:1999/joliet explicitly disabled via mount option:
	 *	- use next "lower" extension
	 * 3. joliet/ISO9660:1999/rrip explicitly requested via mount option:
	 *	- disable rrip support even if available
	 *	- disable IOS9660:1999 support even if available
	 *
	 * We need to adjust these flags as we discover the extensions
	 * present. See below. These are just the starting values.
	 */
	use_rrip = (mount_flags & HSFSMNT_NORRIP) == 0;
	use_vers2 = (mount_flags & HSFSMNT_NOVERS2) == 0;
	use_joliet = (mount_flags & HSFSMNT_NOJOLIET) == 0;

	/*
	 * Open the device
	 */
	devvp = makespecvp(dev, VBLK);
	ASSERT(devvp != 0);

	/*
	 * Open the target device (file) for read only.
	 */
	if (error = VOP_OPEN(&devvp, FREAD, cr, NULL)) {
		VN_RELE(devvp);
		return (error);
	}

	/*
	 * Refuse to go any further if this
	 * device is being used for swapping
	 */
	if (IS_SWAPVP(common_specvp(devvp))) {
		error = EBUSY;
		goto cleanup;
	}

	vap.va_mask = AT_SIZE;
	if ((error = VOP_GETATTR(devvp, &vap, ATTR_COMM, cr, NULL)) != 0) {
		cmn_err(CE_NOTE, "Cannot get attributes of the CD-ROM driver");
		goto cleanup;
	}

	/*
	 * Make sure we have a nonzero size partition.
	 * The current version of the SD driver will *not* fail the open
	 * of such a partition so we have to check for it here.
	 */
	if (vap.va_size == 0) {
		error = ENXIO;
		goto cleanup;
	}

	/*
	 * Init a new hsfs structure.
	 */
	fsp = kmem_zalloc(sizeof (*fsp), KM_SLEEP);
	svp = kmem_zalloc(sizeof (*svp), KM_SLEEP);
	jvp = kmem_zalloc(sizeof (*jvp), KM_SLEEP);

	/* hardwire perms, uid, gid */
	fsp->hsfs_vol.vol_uid = hsfs_default_uid;
	fsp->hsfs_vol.vol_gid =  hsfs_default_gid;
	fsp->hsfs_vol.vol_prot = hsfs_default_mode;
	svp->vol_uid = hsfs_default_uid;
	svp->vol_gid =  hsfs_default_gid;
	svp->vol_prot = hsfs_default_mode;
	jvp->vol_uid = hsfs_default_uid;
	jvp->vol_gid =  hsfs_default_gid;
	jvp->vol_prot = hsfs_default_mode;

	/*
	 * Look for a Standard File Structure Volume Descriptor,
	 * of which there must be at least one.
	 * If found, check for volume size consistency.
	 *
	 * If svp->lbn_size is != 0, we did find a ISO-9660:1999 SVD
	 * If jvp->lbn_size is != 0, we did find a Joliet SVD.
	 */
	fsp->hsfs_namemax = ISO_FILE_NAMELEN;
	fsp->hsfs_namelen = ISO_FILE_NAMELEN;
	error = hs_findisovol(fsp, devvp, &fsp->hsfs_vol, svp, jvp);
	if (error == EINVAL) /* no iso 9660 - try high sierra ... */
		error = hs_findhsvol(fsp, devvp, &fsp->hsfs_vol);

	if (error)
		goto cleanup;

	DTRACE_PROBE4(findvol,
	    struct hsfs *, fsp,
	    struct hs_volume *, &fsp->hsfs_vol,
	    struct hs_volume *, svp,
	    struct hs_volume *, jvp);

	/*
	 * Generate a file system ID from the CD-ROM,
	 * and check it for uniqueness.
	 *
	 * What we are aiming for is some chance of integrity
	 * across disk change.  That is, if a client has an fhandle,
	 * it will be valid as long as the same disk is mounted.
	 */
	fsid = compute_cdrom_id(fsp, devvp);

	mutex_enter(&hs_mounttab_lock);

	if (fsid == 0 || fsid == -1) {
		uniqtime(&tv);
		fsid = tv.tv_sec;
	} else	/* make sure that the fsid is unique */
		for (tsp = hs_mounttab; tsp != NULL; tsp = tsp->hsfs_next) {
			if (fsid == tsp->hsfs_vfs->vfs_fsid.val[0]) {
				uniqtime(&tv);
				fsid = tv.tv_sec;
				break;
			}
		}

	fsp->hsfs_next = hs_mounttab;
	hs_mounttab = fsp;

	fsp->hsfs_devvp = devvp;
	fsp->hsfs_vfs = vfsp;
	fsp->hsfs_fsmnt = kmem_alloc(pathbufsz, KM_SLEEP);
	(void) strlcpy(fsp->hsfs_fsmnt, path, pathbufsz);

	mutex_init(&fsp->hsfs_free_lock, NULL, MUTEX_DEFAULT, NULL);
	rw_init(&fsp->hsfs_hash_lock, NULL, RW_DEFAULT, NULL);

	vfsp->vfs_data = (caddr_t)fsp;
	vfsp->vfs_dev = dev;
	vfsp->vfs_fstype = hsfsfstype;
	vfsp->vfs_bsize = fsp->hsfs_vol.lbn_size; /* %% */
	vfsp->vfs_fsid.val[0] = fsid;
	vfsp->vfs_fsid.val[1] =  hsfsfstype;

	if (!hs_getrootvp(vfsp, fsp, pathbufsz)) {
		DTRACE_PROBE1(rootvp__failed, struct hsfs *, fsp);
		error = EINVAL;
		goto cleanup;
	}
	DTRACE_PROBE1(rootvp, struct hsfs *, fsp);

	/*
	 * Attempt to discover a RR extension.
	 */
	if (use_rrip) {
		hp = VTOH(fsp->hsfs_rootvp);
		hs_check_root_dirent(fsp->hsfs_rootvp, &(hp->hs_dirent));
	}

	has_rrip = IS_RRIP_IMPLEMENTED(fsp);
	has_vers2 = (svp->lbn_size != 0);
	has_joliet = (jvp->lbn_size != 0);

	DTRACE_PROBE4(voltype__suggested, struct hsfs *, fsp,
	    int, use_rrip, int, use_vers2, int, use_joliet);

	DTRACE_PROBE4(voltype__actual, struct hsfs *, fsp,
	    int, has_rrip, int, has_vers2, int, has_joliet);

	DTRACE_PROBE4(findvol,
	    struct hsfs *, fsp,
	    struct hs_volume *, &fsp->hsfs_vol,
	    struct hs_volume *, svp,
	    struct hs_volume *, jvp);

	force_rrip_off = !use_rrip ||
	    (vfs_optionisset(vfsp, HOPT_JOLIET, NULL) && has_joliet) ||
	    (vfs_optionisset(vfsp, HOPT_VERS2, NULL) && has_vers2);

	force_vers2_off = !use_vers2 ||
	    (vfs_optionisset(vfsp, HOPT_JOLIET, NULL) && has_joliet);

	force_joliet_off = !use_joliet;

	DTRACE_PROBE4(voltype__force_off, struct hsfs *, fsp,
	    int, force_rrip_off, int, force_vers2_off, int, force_joliet_off);

	/*
	 * At the moment, we have references of all three possible
	 * extensions (RR, ISO9660:1999/v2 and Joliet) if present.
	 *
	 * The "active" volume descriptor is RRIP (or ISO9660:1988).
	 * We now switch to the user-requested one.
	 */
	redo_rootvp = 0;

	if (force_rrip_off || !has_rrip) {
		if (has_vers2 && !force_vers2_off) {
			VN_RELE(fsp->hsfs_rootvp);
			bcopy(svp, &fsp->hsfs_vol, sizeof (struct hs_volume));
			fsp->hsfs_vol_type = HS_VOL_TYPE_ISO_V2;
			vfsp->vfs_bsize = fsp->hsfs_vol.lbn_size;
			redo_rootvp = 1;
			has_joliet = 0;
		} else if (has_joliet && !force_joliet_off) {
			VN_RELE(fsp->hsfs_rootvp);
			bcopy(jvp, &fsp->hsfs_vol, sizeof (struct hs_volume));
			fsp->hsfs_vol_type = HS_VOL_TYPE_JOLIET;
			vfsp->vfs_bsize = fsp->hsfs_vol.lbn_size;
			redo_rootvp = 1;
			has_vers2 = 0;
		}
	}

	if (redo_rootvp) {
		/*
		 * Make sure not to use Rock Ridge.
		 */
		UNSET_IMPL_BIT(fsp, RRIP_BIT);
		UNSET_SUSP_BIT(fsp);
		has_rrip = 0;

		if (!hs_getrootvp(vfsp, fsp, pathbufsz)) {
			DTRACE_PROBE1(rootvp__failed, struct hsfs *, fsp);
			error = EINVAL;
			goto cleanup;
		}
		DTRACE_PROBE1(rootvp, struct hsfs *, fsp);
	}
	if (IS_RRIP_IMPLEMENTED(fsp)) {
		has_vers2 = 0;
		has_joliet = 0;
	}
	if (force_vers2_off)
		has_vers2 = 0;
	if (force_joliet_off)
		has_joliet = 0;
	DTRACE_PROBE4(voltype__taken, struct hsfs *, fsp,
	    int, has_rrip, int, has_vers2, int, has_joliet);

	/*
	 * mark root node as VROOT
	 */
	fsp->hsfs_rootvp->v_flag |= VROOT;

	/* Here we take care of some special case stuff for mountroot */
	if (isroot) {
		fsp->hsfs_rootvp->v_rdev = devvp->v_rdev;
		rootvp = fsp->hsfs_rootvp;
	}

	if (IS_RRIP_IMPLEMENTED(fsp)) {
		/*
		 * if RRIP, don't copy NOMAPLCASE or NOTRAILDOT to hsfs_flags
		 */
		mount_flags &= ~(HSFSMNT_NOMAPLCASE | HSFSMNT_NOTRAILDOT);

		fsp->hsfs_namemax = RRIP_FILE_NAMELEN;
		fsp->hsfs_namelen = RRIP_FILE_NAMELEN;

		ASSERT(vfs_optionisset(vfsp, HOPT_RR, NULL));
		vfs_clearmntopt(vfsp, HOPT_VERS2);
		vfs_clearmntopt(vfsp, HOPT_JOLIET);

	} else switch (fsp->hsfs_vol_type) {

	case HS_VOL_TYPE_HS:
	case HS_VOL_TYPE_ISO:
	default:
		/*
		 * if iso v1, don't allow trailing spaces in iso file names
		 */
		mount_flags |= HSFSMNT_NOTRAILSPACE;
		fsp->hsfs_namemax = ISO_NAMELEN_V2_MAX;
		fsp->hsfs_namelen = ISO_FILE_NAMELEN;
		vfs_clearmntopt(vfsp, HOPT_RR);
		vfs_clearmntopt(vfsp, HOPT_VERS2);
		vfs_clearmntopt(vfsp, HOPT_JOLIET);
		break;

	case HS_VOL_TYPE_ISO_V2:
		/*
		 * if iso v2, don't copy NOTRAILDOT to hsfs_flags
		 */
		mount_flags &= ~HSFSMNT_NOTRAILDOT;
		mount_flags |= HSFSMNT_NOMAPLCASE | HSFSMNT_NOVERSION;
		fsp->hsfs_namemax = ISO_NAMELEN_V2_MAX;
		fsp->hsfs_namelen = ISO_NAMELEN_V2;
		vfs_setmntopt(vfsp, HOPT_VERS2, NULL, 0);
		vfs_clearmntopt(vfsp, HOPT_RR);
		vfs_clearmntopt(vfsp, HOPT_JOLIET);
		break;

	case HS_VOL_TYPE_JOLIET:
		/*
		 * if Joliet, don't copy NOMAPLCASE or NOTRAILDOT to hsfs_flags
		 */
		mount_flags &= ~(HSFSMNT_NOMAPLCASE | HSFSMNT_NOTRAILDOT);
		mount_flags |= HSFSMNT_NOMAPLCASE;
		if (mount_flags & HSFSMNT_JOLIETLONG)
			fsp->hsfs_namemax = JOLIET_NAMELEN_MAX*3; /* UTF-8 */
		else
			fsp->hsfs_namemax = MAXNAMELEN-1;
		fsp->hsfs_namelen = JOLIET_NAMELEN*2;
		vfs_setmntopt(vfsp, HOPT_JOLIET, NULL, 0);
		vfs_clearmntopt(vfsp, HOPT_RR);
		vfs_clearmntopt(vfsp, HOPT_VERS2);
		break;
	}

	/*
	 * Add the HSFSMNT_INODE pseudo mount flag to the current mount flags.
	 */
	fsp->hsfs_flags = mount_flags | (fsp->hsfs_flags & HSFSMNT_INODE);

	/*
	 * Setup I/O Scheduling structures
	 */
	if (do_schedio) {
		fsp->hqueue = kmem_alloc(sizeof (struct hsfs_queue), KM_SLEEP);
		hsched_init(fsp, fsid, &modlinkage);
	}

	/*
	 * Setup kstats
	 */
	hsfs_init_kstats(fsp, fsid);

	DTRACE_PROBE1(mount__done, struct hsfs *, fsp);

	/*
	 * set the magic word
	 */
	fsp->hsfs_magic = HSFS_MAGIC;
	mutex_exit(&hs_mounttab_lock);

	kmem_free(svp, sizeof (*svp));
	kmem_free(jvp, sizeof (*jvp));

	return (0);

cleanup:
	(void) VOP_CLOSE(devvp, FREAD, 1, (offset_t)0, cr, NULL);
	VN_RELE(devvp);
	if (fsp)
		kmem_free(fsp, sizeof (*fsp));
	if (svp)
		kmem_free(svp, sizeof (*svp));
	if (jvp)
		kmem_free(jvp, sizeof (*jvp));
	return (error);
}

/*
 * Get the rootvp associated with fsp->hsfs_vol
 */
static int
hs_getrootvp(
	struct vfs	*vfsp,
	struct hsfs	*fsp,
	size_t		pathsize)
{
	struct hsnode	*hp;

	ASSERT(pathsize == strlen(fsp->hsfs_fsmnt) + 1);

	/*
	 * If the root directory does not appear to be
	 * valid, use what it points to as "." instead.
	 * Some Defense Mapping Agency disks are non-conformant
	 * in this way.
	 */
	if (!hsfs_valid_dir(&fsp->hsfs_vol.root_dir)) {
		hs_log_bogus_disk_warning(fsp, HSFS_ERR_BAD_ROOT_DIR, 0);
		if (hs_remakenode(fsp->hsfs_vol.root_dir.ext_lbn,
		    (uint_t)0, vfsp, &fsp->hsfs_rootvp)) {
			hs_mounttab = hs_mounttab->hsfs_next;
			mutex_destroy(&fsp->hsfs_free_lock);
			rw_destroy(&fsp->hsfs_hash_lock);
			kmem_free(fsp->hsfs_fsmnt, pathsize);
			mutex_exit(&hs_mounttab_lock);
			return (0);
		}
	} else {
		fsp->hsfs_rootvp = hs_makenode(&fsp->hsfs_vol.root_dir,
		    fsp->hsfs_vol.root_dir.ext_lbn, 0, vfsp);
	}

	/* XXX - ignore the path table for now */
	fsp->hsfs_ptbl = NULL;
	hp = VTOH(fsp->hsfs_rootvp);
	hp->hs_ptbl_idx = NULL;

	return (1);
}

/*
 * hs_findhsvol()
 *
 * Locate the Standard File Structure Volume Descriptor and
 * parse it into an hs_volume structure.
 *
 * XXX - May someday want to look for Coded Character Set FSVD, too.
 */
static int
hs_findhsvol(struct hsfs *fsp, struct vnode *vp, struct hs_volume *hvp)
{
	struct buf *secbp;
	int i;
	int n;
	uchar_t *volp;
	int error;
	uint_t secno;

	secno = hs_findvoldesc(vp->v_rdev, HS_VOLDESC_SEC);
	secbp = bread(vp->v_rdev, secno * 4, HS_SECTOR_SIZE);
	error = geterror(secbp);

	if (error != 0) {
		cmn_err(CE_NOTE, "hs_findhsvol: bread: error=(%d)", error);
		brelse(secbp);
		return (error);
	}

	volp = (uchar_t *)secbp->b_un.b_addr;

	/*
	 * To avoid that we read the whole medium in case that someone prepares
	 * a malicious "fs image", we read at most 32 blocks.
	 */
	for (n = 0; n < 32 &&
	    HSV_DESC_TYPE(volp) != VD_EOV; n++) {
		for (i = 0; i < HSV_ID_STRLEN; i++)
			if (HSV_STD_ID(volp)[i] != HSV_ID_STRING[i])
				goto cantfind;
		if (HSV_STD_VER(volp) != HSV_ID_VER)
			goto cantfind;
		switch (HSV_DESC_TYPE(volp)) {
		case VD_SFS:
			/* Standard File Structure */
			fsp->hsfs_vol_type = HS_VOL_TYPE_HS;
			error = hs_parsehsvol(fsp, volp, hvp);
			brelse(secbp);
			return (error);

		case VD_CCFS:
			/* Coded Character File Structure */
		case VD_BOOT:
		case VD_UNSPEC:
		case VD_EOV:
			break;
		}
		brelse(secbp);
		++secno;
		secbp = bread(vp->v_rdev, secno * 4, HS_SECTOR_SIZE);

		error = geterror(secbp);

		if (error != 0) {
			cmn_err(CE_NOTE, "hs_findhsvol: bread: error=(%d)",
			    error);
			brelse(secbp);
			return (error);
		}

		volp = (uchar_t *)secbp->b_un.b_addr;
	}
cantfind:
	brelse(secbp);
	return (EINVAL);
}

/*
 * hs_parsehsvol
 *
 * Parse the Standard File Structure Volume Descriptor into
 * an hs_volume structure.  We can't just bcopy it into the
 * structure because of byte-ordering problems.
 *
 */
static int
hs_parsehsvol(struct hsfs *fsp, uchar_t *volp, struct hs_volume *hvp)
{
	hvp->vol_size = HSV_VOL_SIZE(volp);
	hvp->lbn_size = HSV_BLK_SIZE(volp);
	if (hvp->lbn_size == 0) {
		cmn_err(CE_NOTE, "hs_parsehsvol: logical block size in the "
		    "SFSVD is zero");
		return (EINVAL);
	}
	hvp->lbn_shift = ffs((long)hvp->lbn_size) - 1;
	hvp->lbn_secshift =
	    ffs((long)howmany(HS_SECTOR_SIZE, (int)hvp->lbn_size)) - 1;
	hvp->lbn_maxoffset = hvp->lbn_size - 1;
	hs_parse_longdate(HSV_cre_date(volp), &hvp->cre_date);
	hs_parse_longdate(HSV_mod_date(volp), &hvp->mod_date);
	hvp->file_struct_ver = HSV_FILE_STRUCT_VER(volp);
	hvp->ptbl_len = HSV_PTBL_SIZE(volp);
	hvp->vol_set_size = (ushort_t)HSV_SET_SIZE(volp);
	hvp->vol_set_seq = (ushort_t)HSV_SET_SEQ(volp);
#if defined(_LITTLE_ENDIAN)
	hvp->ptbl_lbn = HSV_PTBL_MAN_LS(volp);
#else
	hvp->ptbl_lbn = HSV_PTBL_MAN_MS(volp);
#endif
	hs_copylabel(hvp, HSV_VOL_ID(volp), 0);

	/*
	 * Make sure that lbn_size is a power of two and otherwise valid.
	 */
	if (hvp->lbn_size & ~(1 << hvp->lbn_shift)) {
		cmn_err(CE_NOTE,
		    "hsfs: %d-byte logical block size not supported",
		    hvp->lbn_size);
		return (EINVAL);
	}
	return (hs_parsedir(fsp, HSV_ROOT_DIR(volp), &hvp->root_dir,
	    (char *)NULL, (int *)NULL, HDE_ROOT_DIR_REC_SIZE));
}

/*
 * hs_findisovol()
 *
 * Locate the Primary Volume Descriptor
 * parse it into an hs_volume structure.
 *
 * XXX - Partition not yet done
 *
 * Except for fsp->hsfs_vol_type, no fsp member may be modified.
 * fsp->hsfs_vol is modified indirectly via the *hvp argument.
 */
static int
hs_findisovol(struct hsfs *fsp, struct vnode *vp,
    struct hs_volume *hvp,
    struct hs_volume *svp,
    struct hs_volume *jvp)
{
	struct buf *secbp;
	int i;
	int n;
	uchar_t *volp;
	int error;
	uint_t secno;
	int foundpvd = 0;
	int foundsvd = 0;
	int foundjvd = 0;
	int pvd_sum = 0;

	secno = hs_findvoldesc(vp->v_rdev, ISO_VOLDESC_SEC);
	secbp = bread(vp->v_rdev, secno * 4, ISO_SECTOR_SIZE);
	error = geterror(secbp);

	if (error != 0) {
		cmn_err(CE_NOTE, "hs_findisovol: bread: error=(%d)", error);
		brelse(secbp);
		return (error);
	}

	volp = (uchar_t *)secbp->b_un.b_addr;

	/*
	 * To avoid that we read the whole medium in case that someone prepares
	 * a malicious "fs image", we read at most 32 blocks.
	 */
	for (n = 0; n < 32 && ISO_DESC_TYPE(volp) != ISO_VD_EOV; n++) {
		for (i = 0; i < ISO_ID_STRLEN; i++)
			if (ISO_STD_ID(volp)[i] != ISO_ID_STRING[i])
				goto cantfind;
		switch (ISO_DESC_TYPE(volp)) {
		case ISO_VD_PVD:
			/* Standard File Structure */
			if (ISO_STD_VER(volp) != ISO_ID_VER)
				goto cantfind;
			if (foundpvd != 1) {
				fsp->hsfs_vol_type = HS_VOL_TYPE_ISO;
				if (error = hs_parseisovol(fsp, volp, hvp)) {
					brelse(secbp);
					return (error);
				}
				foundpvd = 1;
				for (i = 0; i < ISO_SECTOR_SIZE; i++)
					pvd_sum += volp[i];
			}
			break;
		case ISO_VD_SVD:
			/* Supplementary Volume Descriptor */
			if (ISO_STD_VER(volp) == ISO_ID_VER2 &&
			    foundsvd != 1) {
				fsp->hsfs_vol_type = HS_VOL_TYPE_ISO;
				if (error = hs_parseisovol(fsp, volp, svp)) {
					brelse(secbp);
					return (error);
				}
				foundsvd = 1;
			}
			if (hs_joliet_level(volp) >= 1 && foundjvd != 1) {
				fsp->hsfs_vol_type = HS_VOL_TYPE_ISO;
				if (error = hs_parseisovol(fsp, volp, jvp)) {
					brelse(secbp);
					return (error);
				}
				foundjvd = 1;
			}
			break;
		case ISO_VD_BOOT:
			break;
		case ISO_VD_VPD:
			/* currently cannot handle partition */
			break;
		case VD_EOV:
			break;
		}
		brelse(secbp);
		++secno;
		secbp = bread(vp->v_rdev, secno * 4, HS_SECTOR_SIZE);
		error = geterror(secbp);

		if (error != 0) {
			cmn_err(CE_NOTE, "hs_findisovol: bread: error=(%d)",
			    error);
			brelse(secbp);
			return (error);
		}

		volp = (uchar_t *)secbp->b_un.b_addr;
	}
	for (n = 0; n < 16; n++) {
		brelse(secbp);
		++secno;
		secbp = bread(vp->v_rdev, secno * 4, HS_SECTOR_SIZE);
		error = geterror(secbp);

		if (error != 0) {
			cmn_err(CE_NOTE, "hs_findisovol: bread: error=(%d)",
			    error);
			brelse(secbp);
			return (error);
		}

		/*
		 * Check for the signature from mkisofs that grants that
		 * the current filesystem allows to use the extent lbn as
		 * inode number even in pure ISO9660 mode.
		 */
		volp = (uchar_t *)secbp->b_un.b_addr;
		if (strncmp((char *)volp, "MKI ", 4) == 0) {
			int	sum;

			sum  = volp[2045];
			sum *= 256;
			sum += volp[2046];
			sum *= 256;
			sum += volp[2047];
			if (sum == pvd_sum)
				fsp->hsfs_flags |= HSFSMNT_INODE;
			break;
		}
	}
	if (foundpvd) {
		brelse(secbp);
		return (0);
	}
cantfind:
	brelse(secbp);
	return (EINVAL);
}

/*
 * Return 0 if no Joliet is found
 * else return Joliet Level 1..3
 */
static int
hs_joliet_level(uchar_t *volp)
{
	if (ISO_std_ver(volp)[0] == ISO_ID_VER &&
	    ISO_svd_esc(volp)[0] == '%' &&
	    ISO_svd_esc(volp)[1] == '/') {

		switch (ISO_svd_esc(volp)[2]) {

		case '@':
			return (1);
		case 'C':
			return (2);
		case 'E':
			return (3);
		}
	}
	return (0);
}

/*
 * hs_parseisovol
 *
 * Parse the Primary Volume Descriptor into an hs_volume structure.
 *
 */
static int
hs_parseisovol(struct hsfs *fsp, uchar_t *volp, struct hs_volume *hvp)
{
	hvp->vol_size = ISO_VOL_SIZE(volp);
	hvp->lbn_size = ISO_BLK_SIZE(volp);
	if (hvp->lbn_size == 0) {
		cmn_err(CE_NOTE, "hs_parseisovol: logical block size in the "
		    "PVD is zero");
		return (EINVAL);
	}
	hvp->lbn_shift = ffs((long)hvp->lbn_size) - 1;
	hvp->lbn_secshift =
	    ffs((long)howmany(ISO_SECTOR_SIZE, (int)hvp->lbn_size)) - 1;
	hvp->lbn_maxoffset = hvp->lbn_size - 1;
	hs_parse_longdate(ISO_cre_date(volp), &hvp->cre_date);
	hs_parse_longdate(ISO_mod_date(volp), &hvp->mod_date);
	hvp->file_struct_ver = ISO_FILE_STRUCT_VER(volp);
	hvp->ptbl_len = ISO_PTBL_SIZE(volp);
	hvp->vol_set_size = (ushort_t)ISO_SET_SIZE(volp);
	hvp->vol_set_seq = (ushort_t)ISO_SET_SEQ(volp);
#if defined(_LITTLE_ENDIAN)
	hvp->ptbl_lbn = ISO_PTBL_MAN_LS(volp);
#else
	hvp->ptbl_lbn = ISO_PTBL_MAN_MS(volp);
#endif
	hs_copylabel(hvp, ISO_VOL_ID(volp), hs_joliet_level(volp) >= 1);

	/*
	 * Make sure that lbn_size is a power of two and otherwise valid.
	 */
	if (hvp->lbn_size & ~(1 << hvp->lbn_shift)) {
		cmn_err(CE_NOTE,
		    "hsfs: %d-byte logical block size not supported",
		    hvp->lbn_size);
		return (EINVAL);
	}
	return (hs_parsedir(fsp, ISO_ROOT_DIR(volp), &hvp->root_dir,
	    (char *)NULL, (int *)NULL, IDE_ROOT_DIR_REC_SIZE));
}

/*
 * Common code for mount and umount.
 * Check that the user's argument is a reasonable
 * thing on which to mount, and return the device number if so.
 */
static int
hs_getmdev(struct vfs *vfsp, char *fspec, int flags, dev_t *pdev, mode_t *mode,
    cred_t *cr)
{
	int error;
	struct vnode *svp = NULL;
	struct vnode *lvp = NULL;
	struct vnode *bvp;
	struct vattr vap;
	dev_t dev;
	enum uio_seg fromspace = (flags & MS_SYSSPACE) ?
	    UIO_SYSSPACE : UIO_USERSPACE;

	/*
	 * Look up the device/file to be mounted.
	 */
	error = lookupname(fspec, fromspace, FOLLOW, NULLVPP, &svp);
	if (error) {
		if (error == ENOENT)
			error = ENODEV;
		goto out;
	}

	error = vfs_get_lofi(vfsp, &lvp);

	if (error > 0) {
		if (error == ENOENT)
			error = ENODEV;
		goto out;
	} else if (error == 0) {
		bvp = lvp;
	} else {
		bvp = svp;

		if (bvp->v_type != VBLK) {
			error = ENOTBLK;
			goto out;
		}

		if ((error = secpolicy_spec_open(cr, bvp, FREAD)) != 0)
			goto out;
	}

	/*
	 * Can we read from the device/file ?
	 */
	if ((error = VOP_ACCESS(svp, VREAD, 0, cr, NULL)) != 0)
		goto out;

	vap.va_mask = AT_MODE;		/* get protection mode */
	(void) VOP_GETATTR(bvp, &vap, 0, CRED(), NULL);
	*mode = vap.va_mode;

	dev = *pdev = bvp->v_rdev;

	error = EBUSY;

	/*
	 * Ensure that this device isn't already mounted,
	 * unless this is a REMOUNT request or we are told to suppress
	 * mount checks.
	 */
	if ((flags & MS_NOCHECK) == 0) {
		if (vfs_devmounting(dev, vfsp))
			goto out;
		if (vfs_devismounted(dev) && !(flags & MS_REMOUNT))
			goto out;
	}

	if (getmajor(*pdev) >= devcnt) {
		error = ENXIO;
		goto out;
	}

	error = 0;
out:
	if (svp != NULL)
		VN_RELE(svp);
	if (lvp != NULL)
		VN_RELE(lvp);
	return (error);
}

static void
hs_copylabel(struct hs_volume *hvp, unsigned char *label, int isjoliet)
{
	char	lbuf[64];	/* hs_joliet_cp() creates 48 bytes at most */

	if (isjoliet) {
		/*
		 * hs_joliet_cp() will output 16..48 bytes.
		 * We need to clear 'lbuf' to avoid junk chars past byte 15.
		 */
		bzero(lbuf, sizeof (lbuf));
		(void) hs_joliet_cp((char *)label, lbuf, 32);
		label = (unsigned char *)lbuf;
	}
	/* cdrom volid is at most 32 bytes */
	bcopy(label, hvp->vol_id, 32);
	hvp->vol_id[31] = NULL;
}

/*
 * Mount root file system.
 * "why" is ROOT_INIT on initial call, ROOT_REMOUNT if called to
 * remount the root file system, and ROOT_UNMOUNT if called to
 * unmount the root (e.g., as part of a system shutdown).
 *
 * XXX - this may be partially machine-dependent; it, along with the VFS_SWAPVP
 * operation, goes along with auto-configuration.  A mechanism should be
 * provided by which machine-INdependent code in the kernel can say "get me the
 * right root file system" and "get me the right initial swap area", and have
 * that done in what may well be a machine-dependent fashion.
 * Unfortunately, it is also file-system-type dependent (NFS gets it via
 * bootparams calls, UFS gets it from various and sundry machine-dependent
 * mechanisms, as SPECFS does for swap).
 */
static int
hsfs_mountroot(struct vfs *vfsp, enum whymountroot why)
{
	int error;
	struct hsfs *fsp;
	struct hs_volume *fvolp;
	static int hsfsrootdone = 0;
	dev_t rootdev;
	mode_t mode = 0;

	if (why == ROOT_INIT) {
		if (hsfsrootdone++)
			return (EBUSY);
		rootdev = getrootdev();
		if (rootdev == (dev_t)NODEV)
			return (ENODEV);
		vfsp->vfs_dev = rootdev;
		vfsp->vfs_flag |= VFS_RDONLY;
	} else if (why == ROOT_REMOUNT) {
		cmn_err(CE_NOTE, "hsfs_mountroot: ROOT_REMOUNT");
		return (0);
	} else if (why == ROOT_UNMOUNT) {
		return (0);
	}
	error = vfs_lock(vfsp);
	if (error) {
		cmn_err(CE_NOTE, "hsfs_mountroot: couldn't get vfs_lock");
		return (error);
	}

	error = hs_mountfs(vfsp, rootdev, "/", mode, 1, CRED(), 1);
	/*
	 * XXX - assumes root device is not indirect, because we don't set
	 * rootvp.  Is rootvp used for anything?  If so, make another arg
	 * to mountfs.
	 */
	if (error) {
		vfs_unlock(vfsp);
		if (rootvp) {
			VN_RELE(rootvp);
			rootvp = (struct vnode *)0;
		}
		return (error);
	}
	if (why == ROOT_INIT)
		vfs_add((struct vnode *)0, vfsp,
		    (vfsp->vfs_flag & VFS_RDONLY) ? MS_RDONLY : 0);
	vfs_unlock(vfsp);
	fsp = VFS_TO_HSFS(vfsp);
	fvolp = &fsp->hsfs_vol;
#ifdef HSFS_CLKSET
	if (fvolp->cre_date.tv_sec == 0) {
		cmn_err(CE_NOTE, "hsfs_mountroot: cre_date.tv_sec == 0");
		if (fvolp->mod_date.tv_sec == 0) {
			cmn_err(CE_NOTE,
			    "hsfs_mountroot: mod_date.tv_sec == 0");
			cmn_err(CE_NOTE, "hsfs_mountroot: clkset(-1L)");
			clkset(-1L);
		} else {
			clkset(fvolp->mod_date.tv_sec);
		}
	} else {
		clkset(fvolp->mod_date.tv_sec);
	}
#else	/* HSFS_CLKSET */
	clkset(-1L);
#endif	/* HSFS_CLKSET */
	return (0);
}

/*
 * hs_findvoldesc()
 *
 * Return the sector where the volume descriptor lives.  This is
 * a fixed value for "normal" cd-rom's, but can change for
 * multisession cd's.
 *
 * desc_sec is the same for high-sierra and iso 9660 formats, why
 * there are two different #defines used in the code for this is
 * beyond me.  These are standards, cast in concrete, right?
 * To be general, however, this function supports passing in different
 * values.
 */
static int
hs_findvoldesc(dev_t rdev, int desc_sec)
{
	int secno;
	int error;
	int rval;	/* ignored */

#ifdef CDROMREADOFFSET
	/*
	 * Issue the Read Offset ioctl directly to the
	 * device. Ignore any errors and set starting
	 * secno to the default, otherwise add the
	 * VOLDESC sector number to the offset.
	 */
	error = cdev_ioctl(rdev, CDROMREADOFFSET, (intptr_t)&secno,
	    FNATIVE|FKIOCTL|FREAD, CRED(), &rval);
	if (error) {
		secno = desc_sec;
	} else {
		secno += desc_sec;
	}
#else
	secno = desc_sec;
#endif

	return (secno);
}
