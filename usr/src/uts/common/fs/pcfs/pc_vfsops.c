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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kmem.h>
#include <sys/user.h>
#include <sys/proc.h>
#include <sys/cred.h>
#include <sys/disp.h>
#include <sys/buf.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/fdio.h>
#include <sys/file.h>
#include <sys/uio.h>
#include <sys/conf.h>
#undef NFSCLIENT
#include <sys/statvfs.h>
#include <sys/mount.h>
#include <sys/pathname.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <sys/conf.h>
#include <sys/mkdev.h>
#include <sys/swap.h>
#include <sys/sunddi.h>
#include <sys/sunldi.h>
#include <sys/dktp/fdisk.h>
#include <sys/fs/pc_label.h>
#include <sys/fs/pc_fs.h>
#include <sys/fs/pc_dir.h>
#include <sys/fs/pc_node.h>
#include <fs/fs_subr.h>
#include <sys/modctl.h>
#include <sys/dkio.h>
#include <sys/open.h>
#include <sys/mntent.h>
#include <sys/policy.h>
#include <sys/atomic.h>

/*
 * The majority of PC media use a 512 sector size, but
 * occasionally you will run across a 1k sector size.
 * For media with a 1k sector size, fd_strategy() requires
 * the I/O size to be a 1k multiple; so when the sector size
 * is not yet known, always read 1k.
 */
#define	PC_SAFESECSIZE	(PC_SECSIZE * 2)

static int pcfs_pseudo_floppy(dev_t);

static int pcfsinit(int, char *);
static int pcfs_mount(struct vfs *, struct vnode *, struct mounta *,
	struct cred *);
static int pcfs_unmount(struct vfs *, int, struct cred *);
static int pcfs_root(struct vfs *, struct vnode **);
static int pcfs_statvfs(struct vfs *, struct statvfs64 *);
static int pc_syncfsnodes(struct pcfs *);
static int pcfs_sync(struct vfs *, short, struct cred *);
static int pcfs_vget(struct vfs *vfsp, struct vnode **vpp, struct fid *fidp);
static void pcfs_freevfs(vfs_t *vfsp);

static int pc_getfattype(struct vnode *, int, daddr_t *, int *);
static int pc_readfat(struct pcfs *fsp, uchar_t *fatp, daddr_t start,
    size_t fatsize);
static int pc_writefat(struct pcfs *fsp, daddr_t start);

/*
 * pcfs mount options table
 */

static char *nohidden_cancel[] = { MNTOPT_PCFS_HIDDEN, NULL };
static char *hidden_cancel[] = { MNTOPT_PCFS_NOHIDDEN, NULL };
static char *nofoldcase_cancel[] = { MNTOPT_PCFS_FOLDCASE, NULL };
static char *foldcase_cancel[] = { MNTOPT_PCFS_NOFOLDCASE, NULL };
static char *clamptime_cancel[] = { MNTOPT_PCFS_NOCLAMPTIME, NULL };
static char *noclamptime_cancel[] = { MNTOPT_PCFS_CLAMPTIME, NULL };

static mntopt_t mntopts[] = {
/*
 *	option name	cancel option	default arg	flags	opt data
 */
	{ MNTOPT_PCFS_NOHIDDEN, nohidden_cancel, NULL, 0, NULL },
	{ MNTOPT_PCFS_HIDDEN, hidden_cancel, NULL, MO_DEFAULT, NULL },
	{ MNTOPT_PCFS_NOFOLDCASE, nofoldcase_cancel, NULL, MO_DEFAULT, NULL },
	{ MNTOPT_PCFS_FOLDCASE, foldcase_cancel, NULL, 0, NULL },
	{ MNTOPT_PCFS_CLAMPTIME, clamptime_cancel, NULL, MO_DEFAULT, NULL },
	{ MNTOPT_PCFS_NOCLAMPTIME, noclamptime_cancel, NULL, NULL, NULL }
};

static mntopts_t pcfs_mntopts = {
	sizeof (mntopts) / sizeof (mntopt_t),
	mntopts
};

int pcfsdebuglevel = 0;

/*
 * pcfslock:	protects the list of mounted pc filesystems "pc_mounttab.
 * pcfs_lock:	(inside per filesystem structure "pcfs")
 *		per filesystem lock. Most of the vfsops and vnodeops are
 *		protected by this lock.
 * pcnodes_lock: protects the pcnode hash table "pcdhead", "pcfhead".
 *
 * Lock hierarchy: pcfslock > pcfs_lock > pcnodes_lock
 *
 * pcfs_mountcount:	used to prevent module unloads while there is still
 *			pcfs state from a former mount hanging around. With
 *			forced umount support, the filesystem module must not
 *			be allowed to go away before the last VFS_FREEVFS()
 *			call has been made.
 *			Since this is just an atomic counter, there's no need
 *			for locking.
 */
kmutex_t	pcfslock;
krwlock_t	pcnodes_lock;
uint32_t	pcfs_mountcount;

static int pcfstype;

static vfsdef_t vfw = {
	VFSDEF_VERSION,
	"pcfs",
	pcfsinit,
	VSW_HASPROTO|VSW_CANREMOUNT|VSW_STATS,
	&pcfs_mntopts
};

extern struct mod_ops mod_fsops;

static struct modlfs modlfs = {
	&mod_fsops,
	"PC filesystem v1.100",
	&vfw
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modlfs,
	NULL
};

int
_init(void)
{
	int	error;

#if !defined(lint)
	/* make sure the on-disk structures are sane */
	ASSERT(sizeof (struct pcdir) == 32);
	ASSERT(sizeof (struct pcdir_lfn) == 32);
#endif
	mutex_init(&pcfslock, NULL, MUTEX_DEFAULT, NULL);
	rw_init(&pcnodes_lock, NULL, RW_DEFAULT, NULL);
	error = mod_install(&modlinkage);
	if (error) {
		mutex_destroy(&pcfslock);
		rw_destroy(&pcnodes_lock);
	}
	return (error);
}

int
_fini(void)
{
	int	error;

	/*
	 * If a forcedly unmounted instance is still hanging around,
	 * we cannot allow the module to be unloaded because that would
	 * cause panics once the VFS framework decides it's time to call
	 * into VFS_FREEVFS().
	 */
	if (pcfs_mountcount)
		return (EBUSY);

	error = mod_remove(&modlinkage);
	if (error)
		return (error);
	mutex_destroy(&pcfslock);
	rw_destroy(&pcnodes_lock);
	/*
	 * Tear down the operations vectors
	 */
	(void) vfs_freevfsops_by_type(pcfstype);
	vn_freevnodeops(pcfs_fvnodeops);
	vn_freevnodeops(pcfs_dvnodeops);
	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/* ARGSUSED1 */
static int
pcfsinit(int fstype, char *name)
{
	static const fs_operation_def_t pcfs_vfsops_template[] = {
		VFSNAME_MOUNT, pcfs_mount,
		VFSNAME_UNMOUNT, pcfs_unmount,
		VFSNAME_ROOT, pcfs_root,
		VFSNAME_STATVFS, pcfs_statvfs,
		VFSNAME_SYNC, (fs_generic_func_p) pcfs_sync,
		VFSNAME_VGET, pcfs_vget,
		VFSNAME_FREEVFS, (fs_generic_func_p) pcfs_freevfs,
		NULL, NULL
	};
	int error;

	error = vfs_setfsops(fstype, pcfs_vfsops_template, NULL);
	if (error != 0) {
		cmn_err(CE_WARN, "pcfsinit: bad vfs ops template");
		return (error);
	}

	error = vn_make_ops("pcfs", pcfs_fvnodeops_template, &pcfs_fvnodeops);
	if (error != 0) {
		(void) vfs_freevfsops_by_type(fstype);
		cmn_err(CE_WARN, "pcfsinit: bad file vnode ops template");
		return (error);
	}

	error = vn_make_ops("pcfsd", pcfs_dvnodeops_template, &pcfs_dvnodeops);
	if (error != 0) {
		(void) vfs_freevfsops_by_type(fstype);
		vn_freevnodeops(pcfs_fvnodeops);
		cmn_err(CE_WARN, "pcfsinit: bad dir vnode ops template");
		return (error);
	}

	pcfstype = fstype;
	(void) pc_init();
	pcfs_mountcount = 0;
	return (0);
}

static struct pcfs *pc_mounttab = NULL;

extern struct pcfs_args pc_tz;

/*
 *  Define some special logical drives we use internal to this file.
 */
#define	BOOT_PARTITION_DRIVE	99
#define	PRIMARY_DOS_DRIVE	1

/*
 * pc_mount system call
 */
static int
pcfs_mount(
	struct vfs *vfsp,
	struct vnode *mvp,
	struct mounta *uap,
	struct cred *cr)
{
	struct pcfs *fsp;
	struct vnode *bvp;
	struct vnode *devvp;
	struct pathname special;
	daddr_t dosstart;
	dev_t pseudodev;
	dev_t xdev;
	char *c;
	char *data = uap->dataptr;
	int datalen = uap->datalen;
	int dos_ldrive = 0;
	int error;
	int fattype;
	minor_t	minor;
	int oflag, aflag;

	if ((error = secpolicy_fs_mount(cr, mvp, vfsp)) != 0)
		return (error);

	PC_DPRINTF0(4, "pcfs_mount\n");
	if (mvp->v_type != VDIR) {
		return (ENOTDIR);
	}
	mutex_enter(&mvp->v_lock);
	if ((uap->flags & MS_REMOUNT) == 0 &&
	    (uap->flags & MS_OVERLAY) == 0 &&
	    (mvp->v_count != 1 || (mvp->v_flag & VROOT))) {
		mutex_exit(&mvp->v_lock);
		return (EBUSY);
	}
	mutex_exit(&mvp->v_lock);

	/*
	 * The caller is responsible for making sure to always
	 * pass in sizeof(struct pcfs_args) (or the old one).
	 * Doing this is the only way to know an EINVAL return
	 * from mount(2) is due to the "not a DOS filesystem"
	 * EINVAL that pc_verify/pc_getfattype could return.
	 */
	if ((datalen != sizeof (struct pcfs_args)) &&
	    (datalen != sizeof (struct old_pcfs_args))) {
		return (EINVAL);
	} else {
		struct pcfs_args tmp_tz;
		int hidden = 0;
		int foldcase = 0;
		int noclamptime = 0;

		tmp_tz.flags = 0;
		if (copyin(data, &tmp_tz, datalen)) {
			return (EFAULT);
		}
		if (datalen == sizeof (struct pcfs_args)) {
			hidden = tmp_tz.flags & PCFS_MNT_HIDDEN;
			foldcase = tmp_tz.flags & PCFS_MNT_FOLDCASE;
			noclamptime = tmp_tz.flags & PCFS_MNT_NOCLAMPTIME;
		}

		if (hidden)
			vfs_setmntopt(vfsp, MNTOPT_PCFS_HIDDEN,	NULL, 0);
		if (foldcase)
			vfs_setmntopt(vfsp, MNTOPT_PCFS_FOLDCASE, NULL, 0);
		if (noclamptime)
			vfs_setmntopt(vfsp, MNTOPT_PCFS_NOCLAMPTIME, NULL, 0);
		/*
		 * more than one pc filesystem can be mounted on x86
		 * so the pc_tz structure is now a critical region
		 */
		mutex_enter(&pcfslock);
		if (pc_mounttab == NULL)
			bcopy(&tmp_tz, &pc_tz, sizeof (struct pcfs_args));
		mutex_exit(&pcfslock);
	}
	/*
	 * Resolve path name of special file being mounted.
	 */
	if (error = pn_get(uap->spec, UIO_USERSPACE, &special)) {
		return (error);
	}
	if (error =
	    lookupname(special.pn_path, UIO_SYSSPACE, FOLLOW, NULLVPP, &bvp)) {
		/*
		 * Split the pathname string at the last ':' separator.
		 * If there's no ':' in the device name, or the ':' is the
		 * last character in the string, the name is invalid and
		 * the error from the previous lookup will be returned.
		 */
		c = strrchr(special.pn_path, ':');
		if (c == NULL || strlen(c) == 0)
			goto devlookup_done;

		*c++ = '\0';

		/*
		 * PCFS partition name suffixes can be:
		 *	- "boot" to indicate the X86BOOT partition
		 *	- a drive letter [c-z] for the "DOS logical drive"
		 *	- a drive number 1..24 for the "DOS logical drive"
		 */
		if (strcasecmp(c, "boot") == 0) {
			/*
			 * The Solaris boot partition is requested.
			 */
			dos_ldrive = BOOT_PARTITION_DRIVE;
		} else if (strspn(c, "0123456789") == strlen(c)) {
			/*
			 * All digits - parse the partition number.
			 */
			long drvnum = 0;

			if ((error = ddi_strtol(c, NULL, 10, &drvnum)) == 0) {
				/*
				 * A number alright - in the allowed range ?
				 */
				if (drvnum > 24 || drvnum == 0)
					error = EINVAL;
			}
			if (error)
				goto devlookup_done;
			dos_ldrive = (int)drvnum;
		} else if (strlen(c) == 1) {
			/*
			 * A single trailing character - is it [c-zC-Z] ?
			 */
			*c = tolower(*c);
			if (*c < 'c' || *c > 'z') {
				error = EINVAL;
				goto devlookup_done;
			}
			dos_ldrive = 1 + *c - 'c';
		} else {
			/*
			 * Can't parse this - pass through previous error.
			 */
			goto devlookup_done;
		}

		ASSERT(dos_ldrive > 0);

		error = lookupname(special.pn_path, UIO_SYSSPACE, FOLLOW,
		    NULLVPP, &bvp);
	}
devlookup_done:
	pn_free(&special);
	if (error)
		return (error);

	if (bvp->v_type != VBLK) {
		VN_RELE(bvp);
		return (ENOTBLK);
	}
	xdev = bvp->v_rdev;
	/*
	 * Verify caller's permission to open the device special file.
	 */
	if ((vfsp->vfs_flag & VFS_RDONLY) != 0 ||
	    ((uap->flags & MS_RDONLY) != 0)) {
		oflag = FREAD;
		aflag = VREAD;
	} else {
		oflag = FREAD | FWRITE;
		aflag = VREAD | VWRITE;
	}
	if ((error = VOP_ACCESS(bvp, aflag, 0, cr)) != 0 ||
	    (error = secpolicy_spec_open(cr, bvp, oflag)) != 0) {
		VN_RELE(bvp);
		return (error);
	}

	VN_RELE(bvp);
	if (getmajor(xdev) >= devcnt) {
		return (ENXIO);
	}
	/*
	 * Ensure that this logical drive isn't already mounted, unless
	 * this is a REMOUNT request.
	 * Note: The framework will perform this check if the "...:c"
	 * PCFS-style "logical drive" syntax has not been used and an
	 * actually existing physical device is backing this filesystem.
	 */
	if (dos_ldrive) {
		mutex_enter(&pcfslock);
		for (fsp = pc_mounttab; fsp; fsp = fsp->pcfs_nxt)
			if (fsp->pcfs_xdev == xdev &&
			    fsp->pcfs_ldrv == dos_ldrive) {
				mutex_exit(&pcfslock);
				if (uap->flags & MS_REMOUNT) {
					return (0);
				} else {
					return (EBUSY);
				}
			}
		/*
		 * Assign a unique device number for the vfs
		 * The old way (getudev() + a constantly incrementing
		 * major number) was wrong because it changes vfs_dev
		 * across mounts and reboots, which breaks nfs file handles.
		 * UFS just uses the real dev_t. We can't do that because
		 * of the way pcfs opens fdisk partitons (the :c and :d
		 * partitions are on the same dev_t). Though that _might_
		 * actually be ok, since the file handle contains an
		 * absolute block number, it's probably better to make them
		 * different. So I think we should retain the original
		 * dev_t, but come up with a different minor number based
		 * on the logical drive that will _always_ come up the same.
		 * For now, we steal the upper 6 bits.
		 */
#ifdef notdef
		/* what should we do here? */
		if (((getminor(xdev) >> 12) & 0x3F) != 0)
			printf("whoops - upper bits used!\n");
#endif
		minor = ((dos_ldrive << 12) | getminor(xdev)) & MAXMIN32;
		pseudodev = makedevice(getmajor(xdev), minor);
		if (vfs_devmounting(pseudodev, vfsp)) {
			mutex_exit(&pcfslock);
			return (EBUSY);
		}
		if (vfs_devismounted(pseudodev)) {
			mutex_exit(&pcfslock);
			if (uap->flags & MS_REMOUNT) {
				return (0);
			} else {
				return (EBUSY);
			}
		}
		mutex_exit(&pcfslock);
	} else {
		if (vfs_devmounting(xdev, vfsp)) {
			return (EBUSY);
		}
		if (vfs_devismounted(xdev))
			if (uap->flags & MS_REMOUNT) {
				return (0);
			} else {
				return (EBUSY);
			}
		pseudodev = xdev;
	}

	if (uap->flags & MS_RDONLY) {
		vfsp->vfs_flag |= VFS_RDONLY;
		vfs_setmntopt(vfsp, MNTOPT_RO, NULL, 0);
	}

	/*
	 * Mount the filesystem
	 */
	devvp = makespecvp(xdev, VBLK);
	if (IS_SWAPVP(devvp)) {
		VN_RELE(devvp);
		return (EBUSY);
	}

	/*
	 * special handling for PCMCIA memory card
	 * with pseudo floppies organization
	 */
	if (dos_ldrive == 0 && pcfs_pseudo_floppy(xdev)) {
		dosstart = (daddr_t)0;
		fattype = PCFS_PCMCIA_NO_CIS;
	} else {
		if (error = pc_getfattype(devvp, dos_ldrive, &dosstart,
		    &fattype)) {
			VN_RELE(devvp);
			return (error);
		}
	}

	(void) VOP_PUTPAGE(devvp, (offset_t)0, (uint_t)0, B_INVAL, cr);
	fsp = kmem_zalloc((uint_t)sizeof (struct pcfs), KM_SLEEP);
	fsp->pcfs_vfs = vfsp;
	fsp->pcfs_flags = fattype;
	fsp->pcfs_devvp = devvp;
	fsp->pcfs_xdev = xdev;
	fsp->pcfs_ldrv = dos_ldrive;
	fsp->pcfs_dosstart = dosstart;
	mutex_init(&fsp->pcfs_lock, NULL, MUTEX_DEFAULT, NULL);

	if (vfs_optionisset(vfsp, MNTOPT_PCFS_HIDDEN, NULL))
		fsp->pcfs_flags |= PCFS_HIDDEN;
	if (vfs_optionisset(vfsp, MNTOPT_PCFS_FOLDCASE, NULL))
		fsp->pcfs_flags |= PCFS_FOLDCASE;
	if (vfs_optionisset(vfsp, MNTOPT_PCFS_NOCLAMPTIME, NULL))
		fsp->pcfs_flags |= PCFS_NOCLAMPTIME;
	vfsp->vfs_dev = pseudodev;
	vfsp->vfs_fstype = pcfstype;
	vfs_make_fsid(&vfsp->vfs_fsid, pseudodev, pcfstype);
	vfsp->vfs_data = (caddr_t)fsp;
	vfsp->vfs_bcount = 0;

	error = pc_verify(fsp);
	if (error) {
		VN_RELE(devvp);
		mutex_destroy(&fsp->pcfs_lock);
		kmem_free(fsp, (uint_t)sizeof (struct pcfs));
		return (error);
	}
	vfsp->vfs_bsize = fsp->pcfs_clsize;

	mutex_enter(&pcfslock);
	fsp->pcfs_nxt = pc_mounttab;
	pc_mounttab = fsp;
	mutex_exit(&pcfslock);
	atomic_inc_32(&pcfs_mountcount);
	return (0);
}

/*
 * vfs operations
 */

/* ARGSUSED */
static int
pcfs_unmount(
	struct vfs *vfsp,
	int flag,
	struct cred *cr)
{
	struct pcfs *fsp, *fsp1;

	if (secpolicy_fs_unmount(cr, vfsp) != 0)
		return (EPERM);

	PC_DPRINTF0(4, "pcfs_unmount\n");
	fsp = VFSTOPCFS(vfsp);

	/*
	 * We don't have to lock fsp because the VVFSLOCK in vfs layer will
	 * prevent lookuppn from crossing the mount point.
	 * If this is not a forced umount request and there's ongoing I/O,
	 * don't allow the mount to proceed.
	 */
	if (flag & MS_FORCE)
		vfsp->vfs_flag |= VFS_UNMOUNTED;
	else if (fsp->pcfs_nrefs)
		return (EBUSY);

	mutex_enter(&pcfslock);

	/*
	 * If this is a forced umount request or if the fs instance has
	 * been marked as beyond recovery, allow the umount to proceed
	 * regardless of state. pc_diskchanged() forcibly releases all
	 * inactive vnodes/pcnodes.
	 */
	if (flag & MS_FORCE || fsp->pcfs_flags & PCFS_IRRECOV) {
		rw_enter(&pcnodes_lock, RW_WRITER);
		pc_diskchanged(fsp);
		rw_exit(&pcnodes_lock);
	}

	/* now there should be no pcp node on pcfhead or pcdhead. */

	if (fsp == pc_mounttab) {
		pc_mounttab = fsp->pcfs_nxt;
	} else {
		for (fsp1 = pc_mounttab; fsp1 != NULL; fsp1 = fsp1->pcfs_nxt)
			if (fsp1->pcfs_nxt == fsp)
				fsp1->pcfs_nxt = fsp->pcfs_nxt;
	}

	mutex_exit(&pcfslock);

	/*
	 * Since we support VFS_FREEVFS(), there's no need to
	 * free the fsp right now. The framework will tell us
	 * when the right time to do so has arrived by calling
	 * into pcfs_freevfs.
	 */
	return (0);
}

/*
 * find root of pcfs
 */
static int
pcfs_root(
	struct vfs *vfsp,
	struct vnode **vpp)
{
	struct pcfs *fsp;
	struct pcnode *pcp;
	int error;

	fsp = VFSTOPCFS(vfsp);
	if (error = pc_lockfs(fsp, 0, 0))
		return (error);

	pcp = pc_getnode(fsp, (daddr_t)0, 0, (struct pcdir *)0);
	PC_DPRINTF2(9, "pcfs_root(0x%p) pcp= 0x%p\n",
	    (void *)vfsp, (void *)pcp);
	pc_unlockfs(fsp);
	*vpp = PCTOV(pcp);
	pcp->pc_flags |= PC_EXTERNAL;
	return (0);
}

/*
 * Get file system statistics.
 */
static int
pcfs_statvfs(
	struct vfs *vfsp,
	struct statvfs64 *sp)
{
	struct pcfs *fsp;
	int error;
	dev32_t d32;

	fsp = VFSTOPCFS(vfsp);
	error = pc_getfat(fsp);
	if (error)
		return (error);
	bzero(sp, sizeof (*sp));
	sp->f_bsize = sp->f_frsize = fsp->pcfs_clsize;
	sp->f_blocks = (fsblkcnt64_t)fsp->pcfs_ncluster;
	sp->f_bavail = sp->f_bfree = (fsblkcnt64_t)pc_freeclusters(fsp);
	sp->f_files = (fsfilcnt64_t)-1;
	sp->f_ffree = (fsfilcnt64_t)-1;
	sp->f_favail = (fsfilcnt64_t)-1;
#ifdef notdef
	(void) cmpldev(&d32, fsp->pcfs_devvp->v_rdev);
#endif /* notdef */
	(void) cmpldev(&d32, vfsp->vfs_dev);
	sp->f_fsid = d32;
	(void) strcpy(sp->f_basetype, vfssw[vfsp->vfs_fstype].vsw_name);
	sp->f_flag = vf_to_stf(vfsp->vfs_flag);
	sp->f_namemax = PCFNAMESIZE;
	return (0);
}

static int
pc_syncfsnodes(struct pcfs *fsp)
{
	struct pchead *hp;
	struct pcnode *pcp;
	int error;

	PC_DPRINTF0(7, "pcfs_syncfsnodes\n");
	if (error = pc_lockfs(fsp, 0, 0))
		return (error);

	if (!(error = pc_syncfat(fsp))) {
		hp = pcfhead;
		while (hp < & pcfhead [ NPCHASH ]) {
			rw_enter(&pcnodes_lock, RW_READER);
			pcp = hp->pch_forw;
			while (pcp != (struct pcnode *)hp) {
				if (VFSTOPCFS(PCTOV(pcp) -> v_vfsp) == fsp)
					if (error = pc_nodesync(pcp))
						break;
				pcp = pcp -> pc_forw;
			}
			rw_exit(&pcnodes_lock);
			if (error)
				break;
			hp++;
		}
	}
	pc_unlockfs(fsp);
	return (error);
}

/*
 * Flush any pending I/O.
 */
/*ARGSUSED*/
static int
pcfs_sync(
	struct vfs *vfsp,
	short flag,
	struct cred *cr)
{
	struct pcfs *fsp;
	int error = 0;

	/* this prevents the filesystem from being umounted. */
	mutex_enter(&pcfslock);
	if (vfsp != NULL) {
		fsp = VFSTOPCFS(vfsp);
		if (!(fsp->pcfs_flags & PCFS_IRRECOV)) {
			error = pc_syncfsnodes(fsp);
		} else {
			rw_enter(&pcnodes_lock, RW_WRITER);
			pc_diskchanged(fsp);
			rw_exit(&pcnodes_lock);
			error = EIO;
		}
	} else {
		fsp = pc_mounttab;
		while (fsp != NULL) {
			if (fsp->pcfs_flags & PCFS_IRRECOV) {
				rw_enter(&pcnodes_lock, RW_WRITER);
				pc_diskchanged(fsp);
				rw_exit(&pcnodes_lock);
				error = EIO;
				break;
			}
			error = pc_syncfsnodes(fsp);
			if (error) break;
			fsp = fsp->pcfs_nxt;
		}
	}
	mutex_exit(&pcfslock);
	return (error);
}

int
pc_lockfs(struct pcfs *fsp, int diskchanged, int releasing)
{
	int err;

	if ((fsp->pcfs_flags & PCFS_IRRECOV) && !releasing)
		return (EIO);

	if ((fsp->pcfs_flags & PCFS_LOCKED) && (fsp->pcfs_owner == curthread)) {
		fsp->pcfs_count++;
	} else {
		mutex_enter(&fsp->pcfs_lock);
		if (fsp->pcfs_flags & PCFS_LOCKED)
			panic("pc_lockfs");
		/*
		 * We check the IRRECOV bit again just in case somebody
		 * snuck past the initial check but then got held up before
		 * they could grab the lock.  (And in the meantime someone
		 * had grabbed the lock and set the bit)
		 */
		if (!diskchanged && !(fsp->pcfs_flags & PCFS_IRRECOV)) {
			if ((err = pc_getfat(fsp))) {
				mutex_exit(&fsp->pcfs_lock);
				return (err);
			}
		}
		fsp->pcfs_flags |= PCFS_LOCKED;
		fsp->pcfs_owner = curthread;
		fsp->pcfs_count++;
	}
	return (0);
}

void
pc_unlockfs(struct pcfs *fsp)
{

	if ((fsp->pcfs_flags & PCFS_LOCKED) == 0)
		panic("pc_unlockfs");
	if (--fsp->pcfs_count < 0)
		panic("pc_unlockfs: count");
	if (fsp->pcfs_count == 0) {
		fsp->pcfs_flags &= ~PCFS_LOCKED;
		fsp->pcfs_owner = 0;
		mutex_exit(&fsp->pcfs_lock);
	}
}

/*
 * isDosDrive()
 *	Boolean function.  Give it the systid field for an fdisk partition
 *	and it decides if that's a systid that describes a DOS drive.  We
 *	use systid values defined in sys/dktp/fdisk.h.
 */
static int
isDosDrive(uchar_t checkMe)
{
	return ((checkMe == DOSOS12) || (checkMe == DOSOS16) ||
	    (checkMe == DOSHUGE) || (checkMe == FDISK_WINDOWS) ||
	    (checkMe == FDISK_EXT_WIN) || (checkMe == FDISK_FAT95) ||
	    (checkMe == DIAGPART));
}

/*
 * isDosExtended()
 *	Boolean function.  Give it the systid field for an fdisk partition
 *	and it decides if that's a systid that describes an extended DOS
 *	partition.
 */
static int
isDosExtended(uchar_t checkMe)
{
	return ((checkMe == EXTDOS) || (checkMe == FDISK_EXTLBA));
}

/*
 * isBootPart()
 *	Boolean function.  Give it the systid field for an fdisk partition
 *	and it decides if that's a systid that describes a Solaris boot
 *	partition.
 */
static int
isBootPart(uchar_t checkMe)
{
	return (checkMe == X86BOOT);
}

/*
 * noLogicalDrive()
 *	Display error message about not being able to find a logical
 *	drive.
 */
static void
noLogicalDrive(int requested)
{
	if (requested == BOOT_PARTITION_DRIVE) {
		cmn_err(CE_NOTE, "!pcfs: no boot partition");
	} else {
		cmn_err(CE_NOTE, "!pcfs: no such logical drive");
	}
}

/*
 * findTheDrive()
 *	Discover offset of the requested logical drive, and return
 *	that offset (startSector), the systid of that drive (sysid),
 *	and a buffer pointer (bp), with the buffer contents being
 *	the first sector of the logical drive (i.e., the sector that
 *	contains the BPB for that drive).
 */
static int
findTheDrive(dev_t dev, int ldrive, buf_t **bp,
    daddr_t *startSector, uchar_t *sysid)
{
	struct ipart dosp[FD_NUMPART];	/* incore fdisk partition structure */
	struct mboot *dosp_ptr;		/* boot structure pointer */
	daddr_t lastseek = 0;		/* Disk block we sought previously */
	daddr_t diskblk = 0;		/* Disk block to get */
	daddr_t xstartsect;		/* base of Extended DOS partition */
	int logicalDriveCount = 0;	/* Count of logical drives seen */
	int extendedPart = -1;		/* index of extended dos partition */
	int primaryPart = -1;		/* index of primary dos partition */
	int bootPart = -1;		/* index of a Solaris boot partition */
	int xnumsect = -1;		/* length of extended DOS partition */
	int driveIndex;			/* computed FDISK table index */
	int i;
	/*
	 * Count of drives in the current extended partition's
	 * FDISK table, and indexes of the drives themselves.
	 */
	int extndDrives[FD_NUMPART];
	int numDrives = 0;

	/*
	 * Count of drives (beyond primary) in master boot record's
	 * FDISK table, and indexes of the drives themselves.
	 */
	int extraDrives[FD_NUMPART];
	int numExtraDrives = 0;

	/*
	 * "ldrive == 0" should never happen, as this is a request to
	 * mount the physical device (and ignore partitioning). The code
	 * in pcfs_mount() should have made sure that a logical drive number
	 * is at least 1, meaning we're looking for drive "C:". It is not
	 * safe (and a bug in the callers of this function) to request logical
	 * drive number 0; we could ASSERT() but a graceful EIO is a more
	 * polite way.
	 */
	if (ldrive == 0) {
		cmn_err(CE_NOTE, "!pcfs: request for logical partition zero");
		noLogicalDrive(ldrive);
		return (EIO);
	}

	/*
	 *  Copy from disk block into memory aligned structure for fdisk usage.
	 */
	dosp_ptr = (struct mboot *)(*bp)->b_un.b_addr;
	bcopy(dosp_ptr->parts, dosp, sizeof (struct ipart) * FD_NUMPART);

	if (ltohs(dosp_ptr->signature) != MBB_MAGIC) {
		cmn_err(CE_NOTE, "!pcfs: MBR partition table signature err");
		return (EINVAL);
	}

	/*
	 * Get a summary of what is in the Master FDISK table.
	 * Normally we expect to find one partition marked as a DOS drive.
	 * This partition is the one Windows calls the primary dos partition.
	 * If the machine has any logical drives then we also expect
	 * to find a partition marked as an extended DOS partition.
	 *
	 * Sometimes we'll find multiple partitions marked as DOS drives.
	 * The Solaris fdisk program allows these partitions
	 * to be created, but Windows fdisk no longer does.  We still need
	 * to support these, though, since Windows does.  We also need to fix
	 * our fdisk to behave like the Windows version.
	 *
	 * It turns out that some off-the-shelf media have *only* an
	 * Extended partition, so we need to deal with that case as well.
	 *
	 * Only a single (the first) Extended or Boot Partition will
	 * be recognized.  Any others will be ignored.
	 */
	for (i = 0; i < FD_NUMPART; i++) {
		PC_DPRINTF1(2, "findTheDrive: found partition type %02x",
			dosp[i].systid);

		if (isDosDrive(dosp[i].systid)) {
			if (primaryPart < 0) {
				logicalDriveCount++;
				primaryPart = i;
			} else {
				extraDrives[numExtraDrives++] = i;
			}
			continue;
		}
		if ((extendedPart < 0) && isDosExtended(dosp[i].systid)) {
			extendedPart = i;
			continue;
		}
		if ((bootPart < 0) && isBootPart(dosp[i].systid)) {
			bootPart = i;
			continue;
		}
	}

	if (ldrive == BOOT_PARTITION_DRIVE) {
		if (bootPart < 0) {
			noLogicalDrive(ldrive);
			return (EINVAL);
		}
		*sysid = dosp[bootPart].systid;
		*startSector = ltohi(dosp[bootPart].relsect);
		return (0);
	}

	if (ldrive == PRIMARY_DOS_DRIVE && primaryPart >= 0) {
		*sysid = dosp[primaryPart].systid;
		*startSector = ltohi(dosp[primaryPart].relsect);
		return (0);
	}

	/*
	 * We are not looking for the C: drive (or the primary drive
	 * was not found), so we had better have an extended partition
	 * or extra drives in the Master FDISK table.
	 */
	if ((extendedPart < 0) && (numExtraDrives == 0)) {
		cmn_err(CE_NOTE, "!pcfs: no extended dos partition");
		noLogicalDrive(ldrive);
		return (EINVAL);
	}

	if (extendedPart >= 0) {
		diskblk = xstartsect = ltohi(dosp[extendedPart].relsect);
		xnumsect = ltohi(dosp[extendedPart].numsect);
		do {
			/*
			 *  If the seek would not cause us to change
			 *  position on the drive, then we're out of
			 *  extended partitions to examine.
			 */
			if (diskblk == lastseek)
				break;
			logicalDriveCount += numDrives;
			/*
			 *  Seek the next extended partition, and find
			 *  logical drives within it.
			 */
			brelse(*bp);
			*bp = bread(dev, diskblk, PC_SAFESECSIZE);
			if ((*bp)->b_flags & B_ERROR) {
				PC_DPRINTF0(1, "pc_getfattype: read error\n");
				return (EIO);
			}
			lastseek = diskblk;
			dosp_ptr = (struct mboot *)(*bp)->b_un.b_addr;
			if (ltohs(dosp_ptr->signature) != MBB_MAGIC) {
				cmn_err(CE_NOTE, "!pcfs: "
				    "extended partition signature err");
				return (EINVAL);
			}
			bcopy(dosp_ptr->parts, dosp,
			    sizeof (struct ipart) * FD_NUMPART);
			/*
			 *  Count up drives, and track where the next
			 *  extended partition is in case we need it.  We
			 *  are expecting only one extended partition.  If
			 *  there is more than one we'll only go to the
			 *  first one we see, but warn about ignoring.
			 */
			numDrives = 0;
			for (i = 0; i < FD_NUMPART; i++) {
				if (isDosDrive(dosp[i].systid)) {
					extndDrives[numDrives++] = i;
				} else if (isDosExtended(dosp[i].systid)) {
					if (diskblk != lastseek) {
						/*
						 * Already found an extended
						 * partition in this table.
						 */
						cmn_err(CE_NOTE,
						    "!pcfs: ignoring unexpected"
						    " additional extended"
						    " partition");
					} else {
						diskblk = xstartsect +
						    ltohi(dosp[i].relsect);
					}
				}
			}
		} while (ldrive > logicalDriveCount + numDrives);

		if (ldrive <= logicalDriveCount + numDrives) {
			/*
			 * The number of logical drives we've found thus
			 * far is enough to get us to the one we were
			 * searching for.
			 */
			driveIndex = logicalDriveCount + numDrives - ldrive;
			*sysid = dosp[extndDrives[driveIndex]].systid;
			*startSector =
			    ltohi(dosp[extndDrives[driveIndex]].relsect) +
			    lastseek;
			if (*startSector > (xstartsect + xnumsect)) {
				cmn_err(CE_NOTE, "!pcfs: extended partition "
				    "values bad");
				return (EINVAL);
			}
			return (0);
		} else {
			/*
			 * We ran out of extended dos partition
			 * drives.  The only hope now is to go
			 * back to extra drives defined in the master
			 * fdisk table.  But we overwrote that table
			 * already, so we must load it in again.
			 */
			logicalDriveCount += numDrives;
			brelse(*bp);
			*bp = bread(dev, (daddr_t)0, PC_SAFESECSIZE);
			if ((*bp)->b_flags & B_ERROR) {
				PC_DPRINTF0(1, "pc_getfattype: read error\n");
				return (EIO);
			}
			dosp_ptr = (struct mboot *)(*bp)->b_un.b_addr;
			bcopy(dosp_ptr->parts, dosp,
			    sizeof (struct ipart) * FD_NUMPART);
		}
	}
	/*
	 *  Still haven't found the drive, is it an extra
	 *  drive defined in the main FDISK table?
	 */
	if (ldrive <= logicalDriveCount + numExtraDrives) {
		driveIndex = logicalDriveCount + numExtraDrives - ldrive;
		ASSERT(driveIndex < MIN(numExtraDrives, FD_NUMPART));
		*sysid = dosp[extraDrives[driveIndex]].systid;
		*startSector = ltohi(dosp[extraDrives[driveIndex]].relsect);
		return (0);
	}
	/*
	 *  Still haven't found the drive, and there is
	 *  nowhere else to look.
	 */
	noLogicalDrive(ldrive);
	return (EINVAL);
}

/*
 * FAT12/FAT16 specific consistency checks.
 */
static int
check_bpb_fat16(struct bootsec *bpb)
{
	if (pcfsdebuglevel >= 5) {
		PC_DPRINTF1(5, "check_bpb_fat: RootEntCount = %d",
			ltohs(bpb->rdirents[0]));
		PC_DPRINTF1(5, "check_bpb_fat16: TotSec16 = %d",
			ltohs(bpb->numsect[0]));
		PC_DPRINTF1(5, "check_bpb_fat16: FATSz16 = %d",
			ltohs(bpb->fatsec));
		PC_DPRINTF1(5, "check_bpb_fat16: TotSec32 = %d",
			ltohi(bpb->totalsec));
	}
	return (ltohs(bpb->rdirents[0]) > 0 &&	 /* RootEntCnt > 0 */
		((ltohs(bpb->numsect[0]) == 0 && /* TotSec16 == 0 */
		ltohi(bpb->totalsec) > 0) ||	 /* TotSec32 > 0 */
		ltohs(bpb->numsect[0]) > 0) && /* TotSec16 > 0 */
		ltohs(bpb->fatsec) > 0);	 /* FatSz16 > 0 */
}

/*
 * FAT32 specific consistency checks.
 */
static int
check_bpb_fat32(struct fat32_bootsec *bpb)
{
	if (pcfsdebuglevel >= 5) {
		PC_DPRINTF1(5, "check_bpb_fat32: RootEntCount = %d",
			ltohs(bpb->f_bs.rdirents[0]));
		PC_DPRINTF1(5, "check_bpb_fat32: TotSec16 = %d",
			ltohs(bpb->f_bs.numsect[0]));
		PC_DPRINTF1(5, "check_bpb_fat32: FATSz16 = %d",
			ltohs(bpb->f_bs.fatsec));
		PC_DPRINTF1(5, "check_bpb_fat32: TotSec32 = %d",
			ltohi(bpb->f_bs.totalsec));
		PC_DPRINTF1(5, "check_bpb_fat32: FATSz32 = %d",
			ltohi(bpb->f_fatlength));
	}
	return (ltohs(bpb->f_bs.rdirents[0]) == 0 &&
		ltohs(bpb->f_bs.numsect[0]) == 0 &&
		ltohs(bpb->f_bs.fatsec) == 0 &&
		ltohi(bpb->f_bs.totalsec) > 0 &&
		ltohi(bpb->f_fatlength) > 0);
}

/*
 * Calculate the number of clusters in order to determine
 * the type of FAT we are looking at.  This is the only
 * recommended way of determining FAT type, though there
 * are other hints in the data, this is the best way.
 */
static ulong_t
bpb_to_numclusters(uchar_t *cp)
{
	struct fat32_bootsec *bpb;

	ulong_t rootdirsectors;
	ulong_t FATsz;
	ulong_t TotSec;
	ulong_t DataSec;
	ulong_t CountOfClusters;
	char FileSysType[9];

	/*
	 * Cast it to FAT32 bpb. If it turns out to be FAT12/16, its
	 * OK, we won't try accessing the data beyond the FAT16 header
	 * boundary.
	 */
	bpb = (struct fat32_bootsec *)cp;

	if (pcfsdebuglevel >= 5) {
		if (ltohs(bpb->f_bs.rdirents[0]) != 0) {
			(void) memcpy(FileSysType, &cp[54], 8);
			FileSysType[8] = 0;
			PC_DPRINTF1(5, "debug_bpb: FAT12/FAT16 FileSysType = "
				"%s", FileSysType);
		}
	}

	rootdirsectors = ((ltohs(bpb->f_bs.rdirents[0]) * 32) +
		(ltohs(bpb->f_bs.bps[0]) - 1)) / ltohs(bpb->f_bs.bps[0]);

	if (ltohs(bpb->f_bs.fatsec) != 0)
		FATsz = ltohs(bpb->f_bs.fatsec);
	else
		FATsz = ltohi(bpb->f_fatlength);

	if (ltohs(bpb->f_bs.numsect[0]) != 0)
		TotSec = ltohs(bpb->f_bs.numsect[0]);
	else
		TotSec = ltohi(bpb->f_bs.totalsec);

	DataSec = TotSec - (ltohs(bpb->f_bs.res_sec[0]) +
			(bpb->f_bs.nfat * FATsz) + rootdirsectors);

	CountOfClusters = DataSec / bpb->f_bs.spcl;

	PC_DPRINTF1(5, "debug_bpb: CountOfClusters = %ld", CountOfClusters);

	return (CountOfClusters);

}

static int
fattype(ulong_t CountOfClusters)
{
	/*
	 * From Microsoft:
	 * In the following example, when it says <, it does not mean <=.
	 * Note also that the numbers are correct.  The first number for
	 * FAT12 is 4085; the second number for FAT16 is 65525. These numbers
	 * and the '<' signs are not wrong.
	 */

	/* Watch for edge cases */
	if ((CountOfClusters >= 4085 && CountOfClusters <= 4095) ||
	    (CountOfClusters >= 65525 && CountOfClusters <= 65535)) {
		PC_DPRINTF1(5, "debug_bpb: Cannot determine FAT yet - %ld",
			CountOfClusters);
		return (-1); /* Cannot be determined yet */
	} else if (CountOfClusters < 4085) {
		/* Volume is FAT12 */
		PC_DPRINTF0(5, "debug_bpb: This must be FAT12");
		return (0);
	} else if (CountOfClusters < 65525) {
		/* Volume is FAT16 */
		PC_DPRINTF0(5, "debug_bpb: This must be FAT16");
		return (PCFS_FAT16);
	} else {
		/* Volume is FAT32 */
		PC_DPRINTF0(5, "debug_bpb: This must be FAT32");
		return (PCFS_FAT32);
	}
}

#define	VALID_SECSIZE(s) (s == 512 || s == 1024 || s == 2048 || s == 4096)

#define	VALID_SPCL(s) (s == 1 || s == 2 || s == 4 || s == 8 || s == 16 ||\
	s == 32 || s == 64 || s == 128)

static int
secondaryBPBChecks(uchar_t *cp)
{
	struct bootsec *bpb = (struct bootsec *)cp;
	struct fat32_bootsec *f32bpb = (struct fat32_bootsec *)cp;

	/*
	 * Perform secondary checks to try and determine what sort
	 * of FAT partition we have based on other, less reliable,
	 * data in the BPB header.
	 */
	if (ltohs(bpb->fatsec) != 0) {
		/*
		 * Must be FAT12 or FAT16, check the
		 * FilSysType string (not 100% reliable).
		 */
		if (!memcmp((cp + PCFS_TYPESTRING_OFFSET16), "FAT12", 5)) {
			PC_DPRINTF0(5, "secondaryBPBCheck says: FAT12");
			return (0); /* FAT12 */
		} else if (!memcmp((cp + PCFS_TYPESTRING_OFFSET16), "FAT16",
			5)) {
			PC_DPRINTF0(5, "secondaryBPBCheck says: FAT16");
			return (PCFS_FAT16);
		} else {
			/*
			 * Try to use the BPB_Media byte
			 *
			 *  If the media byte indicates a floppy we'll
			 *  assume FAT12, otherwise we'll assume FAT16.
			 */
			switch (bpb->mediadesriptor) {
				case SS8SPT:
				case DS8SPT:
				case SS9SPT:
				case DS9SPT:
				case DS18SPT:
				case DS9_15SPT:
					PC_DPRINTF0(5,
					"secondaryBPBCheck says: FAT12");
					return (0); /* FAT12 */
				case MD_FIXED:
					PC_DPRINTF0(5,
					"secondaryBPBCheck says: FAT16");
					return (PCFS_FAT16);
				default:
					cmn_err(CE_NOTE,
						"!pcfs: unknown FAT type");
					return (-1);
			}
		}
	} else if (ltohi(f32bpb->f_fatlength) > 0) {
		PC_DPRINTF0(5, "secondaryBPBCheck says: FAT32");
		return (PCFS_FAT32);
	} else {
		/* We don't know */
		PC_DPRINTF0(5, "secondaryBPBCheck says: unknown!!");
		return (-1);
	}
}

/*
 * Check to see if the BPB we found is correct.
 *
 * First, look for obvious, tell-tale signs of trouble:
 * The NumFATs value should always be 2.  Sometimes it can be a '1'
 * on FLASH memory cards and other non-disk-based media, so we
 * will allow that as well.
 *
 * We also look at the Media byte, the valid range is 0xF0, or
 * 0xF8 thru 0xFF, anything else means this is probably not a good
 * BPB.
 *
 * Finally, check the BPB Magic number at the end of the 512 byte
 * block, it must be 0xAA55.
 *
 * If that all is good, calculate the number of clusters and
 * do some final verification steps.
 *
 * If all is well, return success (1) and set the fattypep value to the
 * correct FAT value if the caller provided a pointer to store it in.
 */
static int
isBPB(uchar_t *cp, int *fattypep)
{
	struct bootsec *bpb = (struct bootsec *)cp;
	int type;

	uint_t numclusters;		/* number of clusters in file area */
	ushort_t secsize = (int)ltohs(bpb->bps[0]);

	if (pcfsdebuglevel >= 3) {
		if (!VALID_SECSIZE(secsize))
			PC_DPRINTF1(3, "check_bpb: invalid bps value %d",
				secsize);

		if (!VALID_SPCL(bpb->spcl))
			PC_DPRINTF1(3, "check_bpb: invalid spcl value %d",
				bpb->spcl);

		if ((secsize * bpb->spcl) >= (32 * 1024))
			PC_DPRINTF3(3, "check_bpb: BPC > 32K  %d x %d = %d",
				secsize,
				bpb->spcl,
				secsize * bpb->spcl);

		if (bpb->nfat == 0)
			PC_DPRINTF1(3, "check_bpb: bad NumFATs value %d",
				bpb->nfat);

		if (ltohs(bpb->res_sec[0]) == 0)
			PC_DPRINTF1(3, "check_bpb: bad RsvdSecCnt value %d",
				ltohs(bpb->res_sec[0]));

		PC_DPRINTF1(5, "check_bpb: Media byte = %02x",
			bpb->mediadesriptor);

	}
	if ((bpb->nfat == 0) ||
		(bpb->mediadesriptor != 0xF0 && bpb->mediadesriptor < 0xF8) ||
		(ltohs(cp[510]) != MBB_MAGIC) ||
		!VALID_SECSIZE(secsize) ||
		!VALID_SPCL(bpb->spcl) ||
		(secsize * bpb->spcl > (64 * 1024)) ||
		!(ltohs(bpb->res_sec[0])))
		return (0);

	/*
	 * Basic sanity checks passed so far, now try to determine which
	 * FAT format to use.
	 */
	numclusters = bpb_to_numclusters(cp);

	type = fattype(numclusters);

	/* Do some final sanity checks for each specific type of FAT */
	switch (type) {
		case 0: /* FAT12 */
		case PCFS_FAT16:
			if (!check_bpb_fat16((struct bootsec *)cp))
				return (0);
			break;
		case PCFS_FAT32:
			if (!check_bpb_fat32((struct fat32_bootsec *)cp))
				return (0);
			break;
		default: /* not sure yet */
			type = secondaryBPBChecks(cp);
			if (type == -1) {
				/* Still nothing, give it up. */
				return (0);
			}
			break;
	}

	if (fattypep)
		*fattypep = type;

	PC_DPRINTF0(5, "isBPB: BPB passes verification tests");
	return (1);
}


/*
 * Get the FAT type for the DOS medium.
 *
 * -------------------------
 * According to Microsoft:
 *   The FAT type one of FAT12, FAT16, or FAT32 is determined by the
 * count of clusters on the volume and nothing else.
 * -------------------------
 *
 */
static int
pc_getfattype(
	struct vnode *devvp,
	int ldrive,
	daddr_t *strtsectp,
	int *fattypep)
{
	buf_t *bp = NULL;		/* Disk buffer pointer */
	int err = 0;
	uchar_t sysid = 0;		/* System ID character */
	dev_t	dev = devvp->v_rdev;


	/*
	 * Open the device so we can check out the BPB or FDISK table,
	 * then read in the sector.
	 */
	PC_DPRINTF2(5, "pc_getfattype: dev=%x  ldrive=%x  ", (int)dev, ldrive);
	if (err = VOP_OPEN(&devvp, FREAD, CRED())) {
		PC_DPRINTF1(1, "pc_getfattype: open error=%d\n", err);
		return (err);
	}

	/*
	 * Unpartitioned media (floppies and some removeable devices)
	 * don't have a partition table, the FAT BPB is at disk block 0.
	 * Start out by reading block 0.
	 */
	*strtsectp = (daddr_t)0;
	bp = bread(dev, *strtsectp, PC_SAFESECSIZE);

	if (bp->b_flags & B_ERROR) {
		PC_DPRINTF2(1, "pc_getfattype: read error on "
		    "device %d, disk LBA %d\n", (int)dev, (int)*strtsectp);
		err = EIO;
		goto out;
	}

	/*
	 * If a logical drive number is requested, parse the partition table
	 * and attempt to locate it. Otherwise, proceed immediately to the
	 * BPB check. findTheDrive(), if successful, returns the disk block
	 * number where the requested partition starts in "strtsecp".
	 */
	if (ldrive != 0) {
		PC_DPRINTF0(5, "pc_getfattype: using FDISK table to find BPB");

		if (err = findTheDrive(dev, ldrive, &bp, strtsectp, &sysid))
			goto out;

		brelse(bp);
		bp = bread(dev, *strtsectp, PC_SAFESECSIZE);
		if (bp->b_flags & B_ERROR) {
			PC_DPRINTF2(1, "pc_getfattype: read error on "
			    "device %d, disk LBA %d\n",
			    (int)dev, (int)*strtsectp);
			err = EIO;
			goto out;
		}
	}

	if (!isBPB((uchar_t *)bp->b_un.b_addr, fattypep)) {
		PC_DPRINTF2(1, "pc_getfattype: No FAT BPB on device %d, "
		    "disk LBA %d\n", (int)dev, (int)*strtsectp);
		err = EIO;
		goto out;
	}

out:
	/*
	 * Release the buffer used
	 */
	if (bp != NULL)
		brelse(bp);
	(void) VOP_CLOSE(devvp, FREAD, 1, (offset_t)0, CRED());
	return (err);
}


/*
 * Get the boot parameter block and file allocation table.
 * If there is an old FAT, invalidate it.
 */
int
pc_getfat(struct pcfs *fsp)
{
	struct vfs *vfsp = PCFSTOVFS(fsp);
	struct buf *tp = 0;
	struct buf *bp = 0;
	uchar_t *fatp = NULL;
	uchar_t *fat_changemap = NULL;
	struct bootsec *bootp;
	struct fat32_bootsec *f32b;
	struct vnode *devvp;
	int error;
	int fatsize;
	int fat_changemapsize;
	int flags = 0;
	int nfat;
	int secsize;
	int fatsec;

	PC_DPRINTF0(5, "pc_getfat\n");
	devvp = fsp->pcfs_devvp;
	if (fsp->pcfs_fatp) {
		/*
		 * There is a FAT in core.
		 * If there are open file pcnodes or we have modified it or
		 * it hasn't timed out yet use the in core FAT.
		 * Otherwise invalidate it and get a new one
		 */
#ifdef notdef
		if (fsp->pcfs_frefs ||
		    (fsp->pcfs_flags & PCFS_FATMOD) ||
		    (gethrestime_sec() < fsp->pcfs_fattime)) {
			return (0);
		} else {
			mutex_enter(&pcfslock);
			pc_invalfat(fsp);
			mutex_exit(&pcfslock);
		}
#endif /* notdef */
		return (0);
	}
	/*
	 * Open block device mounted on.
	 */
	error = VOP_OPEN(&devvp,
	    (vfsp->vfs_flag & VFS_RDONLY) ? FREAD : FREAD|FWRITE,
	    CRED());
	if (error) {
		PC_DPRINTF1(1, "pc_getfat: open error=%d\n", error);
		return (error);
	}
	/*
	 * Get boot parameter block and check it for validity
	 */
	tp = bread(fsp->pcfs_xdev, fsp->pcfs_dosstart, PC_SAFESECSIZE);
	if ((tp->b_flags & (B_ERROR | B_STALE)) ||
	    !isBPB((uchar_t *)tp->b_un.b_addr, NULL)) {
		PC_DPRINTF2(1, "pc_getfat: boot block error on device %d, "
		    "disk LBA %d\n",
		    (int)fsp->pcfs_xdev, (int)fsp->pcfs_dosstart);
		flags = tp->b_flags & B_ERROR;
		error = EIO;
		goto out;
	}
	tp->b_flags |= B_STALE | B_AGE;
	bootp = (struct bootsec *)tp->b_un.b_addr;


	/* get the sector size - may be more than 512 bytes */
	secsize = (int)ltohs(bootp->bps[0]);
	/* check for bogus sector size - fat should be at least 1 sector */
	if (IS_FAT32(fsp)) {
		f32b = (struct fat32_bootsec *)bootp;
		fatsec = ltohi(f32b->f_fatlength);
	} else {
		fatsec = ltohs(bootp->fatsec);
	}
	if (secsize < 512 || fatsec < 1 || bootp->nfat < 1) {
		cmn_err(CE_NOTE, "!pcfs: FAT size error");
		error = EINVAL;
		goto out;
	}

	switch (bootp->mediadesriptor) {
	default:
		cmn_err(CE_NOTE, "!pcfs: media-descriptor error, 0x%x",
		    bootp->mediadesriptor);
		error = EINVAL;
		goto out;

	case MD_FIXED:
		/*
		 * PCMCIA pseudo floppy is type MD_FIXED,
		 * but is accessed like a floppy
		 */
		if (!(fsp->pcfs_flags & PCFS_PCMCIA_NO_CIS)) {
			fsp->pcfs_flags |= PCFS_NOCHK;
		}
		/* FALLTHRU */
	case SS8SPT:
	case DS8SPT:
	case SS9SPT:
	case DS9SPT:
	case DS18SPT:
	case DS9_15SPT:
		fsp->pcfs_secsize = secsize;
		fsp->pcfs_sdshift = secsize / DEV_BSIZE - 1;
		fsp->pcfs_entps = secsize / sizeof (struct pcdir);
		fsp->pcfs_spcl = (int)bootp->spcl;
		fsp->pcfs_fatsec = fatsec;
		fsp->pcfs_spt = (int)ltohs(bootp->spt);
		fsp->pcfs_rdirsec = ((int)ltohs(bootp->rdirents[0])
		    * sizeof (struct pcdir) + (secsize - 1)) / secsize;
		fsp->pcfs_clsize = fsp->pcfs_spcl * secsize;
		fsp->pcfs_fatstart = fsp->pcfs_dosstart +
		    (daddr_t)ltohs(bootp->res_sec[0]);
		fsp->pcfs_rdirstart = fsp->pcfs_fatstart +
		    (bootp->nfat * fsp->pcfs_fatsec);
		fsp->pcfs_datastart = fsp->pcfs_rdirstart + fsp->pcfs_rdirsec;
		if (IS_FAT32(fsp))
			fsp->pcfs_rdirstart = ltohi(f32b->f_rootcluster);
		fsp->pcfs_ncluster = (((int)(ltohs(bootp->numsect[0]) ?
		    ltohs(bootp->numsect[0]) : ltohi(bootp->totalsec))) -
		    fsp->pcfs_datastart + fsp->pcfs_dosstart) / fsp->pcfs_spcl;
		fsp->pcfs_numfat = (int)bootp->nfat;
		fsp->pcfs_nxfrecls = PCF_FIRSTCLUSTER;
		break;
	}

	/*
	 * Get FAT and check it for validity
	 */
	fatsize = fsp->pcfs_fatsec * fsp->pcfs_secsize;
	fatp = kmem_alloc(fatsize, KM_SLEEP);
	error = pc_readfat(fsp, fatp, fsp->pcfs_fatstart, fatsize);
	if (error) {
		flags = B_ERROR;
		goto out;
	}
	fat_changemapsize = (fatsize / fsp->pcfs_clsize) + 1;
	fat_changemap = kmem_zalloc(fat_changemapsize, KM_SLEEP);

	/*
	 * The only definite signature check is that the
	 * media descriptor byte should match the first byte
	 * of the FAT block.
	 */
	if (fatp[0] != bootp->mediadesriptor) {
		cmn_err(CE_NOTE, "!pcfs: FAT signature error");
		error = EINVAL;
		goto out;
	}
	/*
	 * Checking for fatsec and number of supported clusters, should
	 * actually determine a FAT12/FAT media.
	 */
	if (fsp->pcfs_flags & PCFS_FAT16) {
		if ((fsp->pcfs_fatsec <= 12) &&
		    ((fatsize * 2 / 3) >= fsp->pcfs_ncluster)) {
			/*
			 * We have a 12-bit FAT, rather than a 16-bit FAT.
			 * Ignore what the fdisk table says.
			 */
			PC_DPRINTF0(2, "pc_getfattype: forcing 12-bit FAT\n");
			fsp->pcfs_flags &= ~PCFS_FAT16;
		}
	}
	/*
	 * Sanity check our FAT is large enough for the
	 * clusters we think we have.
	 */
	if ((fsp->pcfs_flags & PCFS_FAT16) &&
	    ((fatsize / 2) < fsp->pcfs_ncluster)) {
		cmn_err(CE_NOTE, "!pcfs: FAT too small for number of clusters");
		error = EINVAL;
		goto out;
	}

	/*
	 * Get alternate FATs and check for consistency
	 * This is an inlined version of pc_readfat().
	 * Since we're only comparing FAT and alternate FAT,
	 * there's no reason to let pc_readfat() copy data out
	 * of the buf. Instead, compare in-situ, one cluster
	 * at a time.
	 */
	for (nfat = 1; nfat < fsp->pcfs_numfat; nfat++) {
		size_t startsec;
		size_t off;

		startsec = fsp->pcfs_fatstart + nfat * fsp->pcfs_fatsec;

		for (off = 0; off < fatsize; off += fsp->pcfs_clsize) {
			bp = bread(fsp->pcfs_xdev, pc_dbdaddr(fsp,
				startsec +
				pc_cltodb(fsp, pc_lblkno(fsp, off))),
				MIN(fsp->pcfs_clsize, fatsize - off));
			if (bp->b_flags & (B_ERROR | B_STALE)) {
				cmn_err(CE_NOTE,
					"!pcfs: alternate FAT #%d read error"
					" at byte %ld", nfat, off);
				flags = B_ERROR;
				error = EIO;
				goto out;
			}
			bp->b_flags |= B_STALE | B_AGE;
			if (bcmp(bp->b_un.b_addr,
			    fatp + off,
			    MIN(fsp->pcfs_clsize, fatsize - off))) {
				cmn_err(CE_NOTE,
					"!pcfs: alternate FAT #%d corrupted"
					" at byte %ld", nfat, off);
				flags = B_ERROR;
			}
			brelse(bp);
			bp = NULL;	/* prevent double release */
		}
	}

	fsp->pcfs_fatsize = fatsize;
	fsp->pcfs_fatp = fatp;
	fsp->pcfs_fat_changemapsize = fat_changemapsize;
	fsp->pcfs_fat_changemap = fat_changemap;
	fsp->pcfs_fattime = gethrestime_sec() + PCFS_DISKTIMEOUT;
	fsp->pcfs_fatjustread = 1;

	brelse(tp);
	tp = NULL;
	if (IS_FAT32(fsp)) {
		/* get fsinfo */
		struct fat32_boot_fsinfo fsinfo_disk;

		fsp->f32fsinfo_sector = ltohs(f32b->f_infosector);
		tp = bread(fsp->pcfs_xdev,
		    fsp->pcfs_dosstart + pc_dbdaddr(fsp, fsp->f32fsinfo_sector),
		    PC_SAFESECSIZE);
		if (tp->b_flags & (B_ERROR | B_STALE)) {
			cmn_err(CE_NOTE, "!pcfs: error reading fat32 fsinfo");
			flags = tp->b_flags & B_ERROR;
			brelse(tp);
			tp = NULL;
			error = EIO;
			goto out;
		}
		tp->b_flags |= B_STALE | B_AGE;
		bcopy((void *)(tp->b_un.b_addr + FAT32_BOOT_FSINFO_OFF),
		    &fsinfo_disk, sizeof (struct fat32_boot_fsinfo));
		brelse(tp);
		tp = NULL;

		/* translated fields */
		fsp->fsinfo_native.fs_signature =
		    ltohi(fsinfo_disk.fs_signature);
		fsp->fsinfo_native.fs_free_clusters =
		    ltohi(fsinfo_disk.fs_free_clusters);
		if (fsp->fsinfo_native.fs_signature != FAT32_FS_SIGN) {
			cmn_err(CE_NOTE,
			    "!pcfs: fat32 fsinfo signature mismatch.");
			error = EINVAL;
			goto out;
		}
	}

	return (0);

out:
	cmn_err(CE_NOTE, "!pcfs: illegal disk format");
	if (tp)
		brelse(tp);
	if (bp)
		brelse(bp);
	if (fatp)
		kmem_free(fatp, fatsize);
	if (fat_changemap)
		kmem_free(fat_changemap, fat_changemapsize);

	if (flags) {
		pc_mark_irrecov(fsp);
	}
	(void) VOP_CLOSE(devvp, (vfsp->vfs_flag & VFS_RDONLY) ?
	    FREAD : FREAD|FWRITE, 1, (offset_t)0, CRED());
	return (error);
}

int
pc_syncfat(struct pcfs *fsp)
{
	struct buf *bp;
	int nfat;
	int	error;
	struct fat32_boot_fsinfo fsinfo_disk;

	PC_DPRINTF0(7, "pcfs_syncfat\n");
	if ((fsp->pcfs_fatp == (uchar_t *)0) ||
	    !(fsp->pcfs_flags & PCFS_FATMOD))
		return (0);
	/*
	 * write out all copies of FATs
	 */
	fsp->pcfs_flags &= ~PCFS_FATMOD;
	fsp->pcfs_fattime = gethrestime_sec() + PCFS_DISKTIMEOUT;
	for (nfat = 0; nfat < fsp->pcfs_numfat; nfat++) {
		error = pc_writefat(fsp,
		    fsp->pcfs_fatstart + nfat*fsp->pcfs_fatsec);
		if (error) {
			pc_mark_irrecov(fsp);
			return (EIO);
		}
	}
	pc_clear_fatchanges(fsp);
	PC_DPRINTF0(6, "pcfs_syncfat: wrote out FAT\n");
	/* write out fsinfo */
	if (IS_FAT32(fsp)) {
		bp = bread(fsp->pcfs_xdev,
		    fsp->pcfs_dosstart + pc_dbdaddr(fsp, fsp->f32fsinfo_sector),
		    PC_SAFESECSIZE);
		if (bp->b_flags & (B_ERROR | B_STALE)) {
			brelse(bp);
			return (EIO);
		}
		bcopy((void *)(bp->b_un.b_addr + FAT32_BOOT_FSINFO_OFF),
		    &fsinfo_disk, sizeof (struct fat32_boot_fsinfo));
		/* translate fields */
		fsinfo_disk.fs_free_clusters =
		    htoli(fsp->fsinfo_native.fs_free_clusters);
		fsinfo_disk.fs_next_cluster = (uint32_t)FSINFO_UNKNOWN;
		bcopy(&fsinfo_disk,
		    (void *)(bp->b_un.b_addr + FAT32_BOOT_FSINFO_OFF),
		    sizeof (struct fat32_boot_fsinfo));
		bwrite2(bp);
		error = geterror(bp);
		brelse(bp);
		if (error) {
			pc_mark_irrecov(fsp);
			return (EIO);
		}
	}
	return (0);
}

void
pc_invalfat(struct pcfs *fsp)
{
	struct pcfs *xfsp;
	int mount_cnt = 0;

	PC_DPRINTF0(7, "pc_invalfat\n");
	if (fsp->pcfs_fatp == (uchar_t *)0)
		panic("pc_invalfat");
	/*
	 * Release FAT
	 */
	kmem_free(fsp->pcfs_fatp, fsp->pcfs_fatsize);
	fsp->pcfs_fatp = NULL;
	kmem_free(fsp->pcfs_fat_changemap, fsp->pcfs_fat_changemapsize);
	fsp->pcfs_fat_changemap = NULL;
	/*
	 * Invalidate all the blocks associated with the device.
	 * Not needed if stateless.
	 */
	for (xfsp = pc_mounttab; xfsp; xfsp = xfsp->pcfs_nxt)
		if (xfsp != fsp && xfsp->pcfs_xdev == fsp->pcfs_xdev)
			mount_cnt++;

	if (!mount_cnt)
		binval(fsp->pcfs_xdev);
	/*
	 * close mounted device
	 */
	(void) VOP_CLOSE(fsp->pcfs_devvp,
	    (PCFSTOVFS(fsp)->vfs_flag & VFS_RDONLY) ? FREAD : FREAD|FWRITE,
	    1, (offset_t)0, CRED());
}

void
pc_badfs(struct pcfs *fsp)
{
	cmn_err(CE_WARN, "corrupted PC file system on dev %x.%x\n",
	    getmajor(fsp->pcfs_devvp->v_rdev),
	    getminor(fsp->pcfs_devvp->v_rdev));
}

/*
 * The problem with supporting NFS on the PCFS filesystem is that there
 * is no good place to keep the generation number. The only possible
 * place is inside a directory entry. There are a few words that we
 * don't use - they store NT & OS/2 attributes, and the creation/last access
 * time of the file - but it seems wrong to use them. In addition, directory
 * entries come and go. If a directory is removed completely, its directory
 * blocks are freed and the generation numbers are lost. Whereas in ufs,
 * inode blocks are dedicated for inodes, so the generation numbers are
 * permanently kept on the disk.
 */
static int
pcfs_vget(struct vfs *vfsp, struct vnode **vpp, struct fid *fidp)
{
	struct pcnode *pcp;
	struct pc_fid *pcfid;
	struct pcfs *fsp;
	struct pcdir *ep;
	daddr_t eblkno;
	int eoffset;
	struct buf *bp;
	int error;
	pc_cluster32_t	cn;

	pcfid = (struct pc_fid *)fidp;
	fsp = VFSTOPCFS(vfsp);

	error = pc_lockfs(fsp, 0, 0);
	if (error) {
		*vpp = NULL;
		return (error);
	}

	if (pcfid->pcfid_block == 0) {
		pcp = pc_getnode(fsp, (daddr_t)0, 0, (struct pcdir *)0);
		pcp->pc_flags |= PC_EXTERNAL;
		*vpp = PCTOV(pcp);
		pc_unlockfs(fsp);
		return (0);
	}
	eblkno = pcfid->pcfid_block;
	eoffset = pcfid->pcfid_offset;
	if ((pc_dbtocl(fsp,
	    eblkno - fsp->pcfs_dosstart) >= fsp->pcfs_ncluster) ||
	    (eoffset > fsp->pcfs_clsize)) {
		pc_unlockfs(fsp);
		*vpp = NULL;
		return (EINVAL);
	}

	if (eblkno >= fsp->pcfs_datastart || (eblkno-fsp->pcfs_rdirstart)
	    < (fsp->pcfs_rdirsec & ~(fsp->pcfs_spcl - 1))) {
		bp = bread(fsp->pcfs_xdev, eblkno, fsp->pcfs_clsize);
	} else {
		bp = bread(fsp->pcfs_xdev, eblkno,
		    (int)(fsp->pcfs_datastart - eblkno) * fsp->pcfs_secsize);
	}
	if (bp->b_flags & (B_ERROR | B_STALE)) {
		error = geterror(bp);
		brelse(bp);
		if (error)
			pc_mark_irrecov(fsp);
		*vpp = NULL;
		pc_unlockfs(fsp);
		return (error);
	}
	ep = (struct pcdir *)(bp->b_un.b_addr + eoffset);
	/*
	 * Ok, if this is a valid file handle that we gave out,
	 * then simply ensuring that the creation time matches,
	 * the entry has not been deleted, and it has a valid first
	 * character should be enough.
	 *
	 * Unfortunately, verifying that the <blkno, offset> _still_
	 * refers to a directory entry is not easy, since we'd have
	 * to search _all_ directories starting from root to find it.
	 * That's a high price to pay just in case somebody is forging
	 * file handles. So instead we verify that as much of the
	 * entry is valid as we can:
	 *
	 * 1. The starting cluster is 0 (unallocated) or valid
	 * 2. It is not an LFN entry
	 * 3. It is not hidden (unless mounted as such)
	 * 4. It is not the label
	 */
	cn = pc_getstartcluster(fsp, ep);
	/*
	 * if the starting cluster is valid, but not valid according
	 * to pc_validcl(), force it to be to simplify the following if.
	 */
	if (cn == 0)
		cn = PCF_FIRSTCLUSTER;
	if (IS_FAT32(fsp)) {
		if (cn >= PCF_LASTCLUSTER32)
			cn = PCF_FIRSTCLUSTER;
	} else {
		if (cn >= PCF_LASTCLUSTER)
			cn = PCF_FIRSTCLUSTER;
	}
	if ((!pc_validcl(fsp, cn)) ||
	    (PCDL_IS_LFN(ep)) ||
	    (PCA_IS_HIDDEN(fsp, ep->pcd_attr)) ||
	    ((ep->pcd_attr & PCA_LABEL) == PCA_LABEL)) {
		bp->b_flags |= B_STALE | B_AGE;
		brelse(bp);
		pc_unlockfs(fsp);
		return (EINVAL);
	}
	if ((ep->pcd_crtime.pct_time == pcfid->pcfid_ctime) &&
	    (ep->pcd_filename[0] != PCD_ERASED) &&
	    (pc_validchar(ep->pcd_filename[0]) ||
		(ep->pcd_filename[0] == '.' && ep->pcd_filename[1] == '.'))) {
		pcp = pc_getnode(fsp, eblkno, eoffset, ep);
		pcp->pc_flags |= PC_EXTERNAL;
		*vpp = PCTOV(pcp);
	} else {
		*vpp = NULL;
	}
	bp->b_flags |= B_STALE | B_AGE;
	brelse(bp);
	pc_unlockfs(fsp);
	return (0);
}

/*
 * if device is a PCMCIA pseudo floppy, return 1
 * otherwise, return 0
 */
static int
pcfs_pseudo_floppy(dev_t rdev)
{
	int			error, err;
	struct dk_cinfo		info;
	ldi_handle_t		lh;
	ldi_ident_t		li;

	err = ldi_ident_from_mod(&modlinkage, &li);
	if (err) {
		PC_DPRINTF1(1,
		    "pcfs_pseudo_floppy: ldi_ident_from_mod err=%d\n", err);
		return (0);
	}

	err = ldi_open_by_dev(&rdev, OTYP_CHR, FREAD, CRED(), &lh, li);
	ldi_ident_release(li);
	if (err) {
		PC_DPRINTF1(1,
		    "pcfs_pseudo_floppy: ldi_open err=%d\n", err);
		return (0);
	}

	/* return value stored in err is purposfully ignored */
	error = ldi_ioctl(lh, DKIOCINFO, (intptr_t)&info, FKIOCTL,
	    CRED(), &err);

	err = ldi_close(lh, FREAD, CRED());
	if (err != 0) {
		PC_DPRINTF1(1,
		    "pcfs_pseudo_floppy: ldi_close err=%d\n", err);
		return (0);
	}

	if ((error == 0) && (info.dki_ctype == DKC_PCMCIA_MEM) &&
		(info.dki_flags & DKI_PCMCIA_PFD))
		return (1);
	else
		return (0);
}

/*
 * Unfortunately, FAT32 fat's can be pretty big (On a 1 gig jaz drive, about
 * a meg), so we can't bread() it all in at once. This routine reads a
 * fat a chunk at a time.
 */
static int
pc_readfat(struct pcfs *fsp, uchar_t *fatp, daddr_t start, size_t fatsize)
{
	struct buf *bp;
	size_t off;
	size_t readsize;

	readsize = fsp->pcfs_clsize;
	for (off = 0; off < fatsize; off += readsize, fatp += readsize) {
		if (readsize > (fatsize - off))
			readsize = fatsize - off;
		bp = bread(fsp->pcfs_xdev,
		    pc_dbdaddr(fsp, start +
			pc_cltodb(fsp, pc_lblkno(fsp, off))),
		    readsize);
		if (bp->b_flags & (B_ERROR | B_STALE)) {
			brelse(bp);
			return (EIO);
		}
		bp->b_flags |= B_STALE | B_AGE;
		bcopy(bp->b_un.b_addr, fatp, readsize);
		brelse(bp);
	}
	return (0);
}

/*
 * We write the FAT out a _lot_, in order to make sure that it
 * is up-to-date. But on a FAT32 system (large drive, small clusters)
 * the FAT might be a couple of megabytes, and writing it all out just
 * because we created or deleted a small file is painful (especially
 * since we do it for each alternate FAT too). So instead, for FAT16 and
 * FAT32 we only write out the bit that has changed. We don't clear
 * the 'updated' fields here because the caller might be writing out
 * several FATs, so the caller must use pc_clear_fatchanges() after
 * all FATs have been updated.
 */
static int
pc_writefat(struct pcfs *fsp, daddr_t start)
{
	struct buf *bp;
	size_t off;
	size_t writesize;
	int	error;
	uchar_t *fatp = fsp->pcfs_fatp;
	size_t fatsize = fsp->pcfs_fatsize;

	writesize = fsp->pcfs_clsize;
	for (off = 0; off < fatsize; off += writesize, fatp += writesize) {
		if (writesize > (fatsize - off))
			writesize = fatsize - off;
		if (!pc_fat_is_changed(fsp, pc_lblkno(fsp, off))) {
			continue;
		}
		bp = ngeteblk(writesize);
		bp->b_edev = fsp->pcfs_xdev;
		bp->b_dev = cmpdev(bp->b_edev);
		bp->b_blkno = pc_dbdaddr(fsp, start +
		    pc_cltodb(fsp, pc_lblkno(fsp, off)));
		bcopy(fatp, bp->b_un.b_addr, writesize);
		bwrite2(bp);
		error = geterror(bp);
		brelse(bp);
		if (error) {
			return (error);
		}
	}
	return (0);
}

/*
 * Mark the FAT cluster that 'cn' is stored in as modified.
 */
void
pc_mark_fat_updated(struct pcfs *fsp, pc_cluster32_t cn)
{
	pc_cluster32_t	bn;
	size_t		size;

	/* which fat block is the cluster number stored in? */
	if (IS_FAT32(fsp)) {
		size = sizeof (pc_cluster32_t);
		bn = pc_lblkno(fsp, cn * size);
		fsp->pcfs_fat_changemap[bn] = 1;
	} else if (IS_FAT16(fsp)) {
		size = sizeof (pc_cluster16_t);
		bn = pc_lblkno(fsp, cn * size);
		fsp->pcfs_fat_changemap[bn] = 1;
	} else {
		offset_t off;
		pc_cluster32_t nbn;

		ASSERT(IS_FAT12(fsp));
		off = cn + (cn >> 1);
		bn = pc_lblkno(fsp, off);
		fsp->pcfs_fat_changemap[bn] = 1;
		/* does this field wrap into the next fat cluster? */
		nbn = pc_lblkno(fsp, off + 1);
		if (nbn != bn) {
			fsp->pcfs_fat_changemap[nbn] = 1;
		}
	}
}

/*
 * return whether the FAT cluster 'bn' is updated and needs to
 * be written out.
 */
int
pc_fat_is_changed(struct pcfs *fsp, pc_cluster32_t bn)
{
	return (fsp->pcfs_fat_changemap[bn] == 1);
}

/*
 * Implementation of VFS_FREEVFS() to support forced umounts.
 * This is called by the vfs framework after umount, to trigger
 * the release of any resources still associated with the given
 * vfs_t once the need to keep them has gone away.
 */
void
pcfs_freevfs(vfs_t *vfsp)
{
	struct pcfs *fsp = VFSTOPCFS(vfsp);

	mutex_enter(&pcfslock);
	if (fsp->pcfs_fatp != (uchar_t *)0)
		pc_invalfat(fsp);
	mutex_exit(&pcfslock);

	VN_RELE(fsp->pcfs_devvp);
	mutex_destroy(&fsp->pcfs_lock);
	kmem_free(fsp, (uint_t)sizeof (struct pcfs));

	/*
	 * Allow _fini() to succeed now, if so desired.
	 */
	atomic_dec_32(&pcfs_mountcount);
}
