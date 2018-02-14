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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2017 by Delphix. All rights reserved.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kmem.h>
#include <sys/user.h>
#include <sys/proc.h>
#include <sys/cred.h>
#include <sys/disp.h>
#include <sys/buf.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/vnode.h>
#include <sys/fdio.h>
#include <sys/file.h>
#include <sys/uio.h>
#include <sys/conf.h>
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
#include <sys/sdt.h>

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

static int pc_readfat(struct pcfs *fsp, uchar_t *fatp);
static int pc_writefat(struct pcfs *fsp, daddr_t start);

static int pc_getfattype(struct pcfs *fsp);
static void pcfs_parse_mntopts(struct pcfs *fsp);


/*
 * pcfs mount options table
 */

static char *nohidden_cancel[] = { MNTOPT_PCFS_HIDDEN, NULL };
static char *hidden_cancel[] = { MNTOPT_PCFS_NOHIDDEN, NULL };
static char *nofoldcase_cancel[] = { MNTOPT_PCFS_FOLDCASE, NULL };
static char *foldcase_cancel[] = { MNTOPT_PCFS_NOFOLDCASE, NULL };
static char *clamptime_cancel[] = { MNTOPT_PCFS_NOCLAMPTIME, NULL };
static char *noclamptime_cancel[] = { MNTOPT_PCFS_CLAMPTIME, NULL };
static char *atime_cancel[] = { MNTOPT_NOATIME, NULL };
static char *noatime_cancel[] = { MNTOPT_ATIME, NULL };

static mntopt_t mntopts[] = {
/*
 *	option name	cancel option	default arg	flags	opt data
 */
	{ MNTOPT_PCFS_NOHIDDEN, nohidden_cancel, NULL, 0, NULL },
	{ MNTOPT_PCFS_HIDDEN, hidden_cancel, NULL, MO_DEFAULT, NULL },
	{ MNTOPT_PCFS_NOFOLDCASE, nofoldcase_cancel, NULL, MO_DEFAULT, NULL },
	{ MNTOPT_PCFS_FOLDCASE, foldcase_cancel, NULL, 0, NULL },
	{ MNTOPT_PCFS_CLAMPTIME, clamptime_cancel, NULL, MO_DEFAULT, NULL },
	{ MNTOPT_PCFS_NOCLAMPTIME, noclamptime_cancel, NULL, NULL, NULL },
	{ MNTOPT_NOATIME, noatime_cancel, NULL, NULL, NULL },
	{ MNTOPT_ATIME, atime_cancel, NULL, NULL, NULL },
	{ MNTOPT_PCFS_TIMEZONE, NULL, "+0", MO_DEFAULT | MO_HASVALUE, NULL },
	{ MNTOPT_PCFS_SECSIZE, NULL, NULL, MO_HASVALUE, NULL }
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
	VSW_HASPROTO|VSW_CANREMOUNT|VSW_STATS|VSW_CANLOFI|VSW_MOUNTDEV,
	&pcfs_mntopts
};

extern struct mod_ops mod_fsops;

static struct modlfs modlfs = {
	&mod_fsops,
	"PC filesystem",
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
		VFSNAME_MOUNT,		{ .vfs_mount = pcfs_mount },
		VFSNAME_UNMOUNT,	{ .vfs_unmount = pcfs_unmount },
		VFSNAME_ROOT,		{ .vfs_root = pcfs_root },
		VFSNAME_STATVFS,	{ .vfs_statvfs = pcfs_statvfs },
		VFSNAME_SYNC,		{ .vfs_sync = pcfs_sync },
		VFSNAME_VGET,		{ .vfs_vget = pcfs_vget },
		VFSNAME_FREEVFS,	{ .vfs_freevfs = pcfs_freevfs },
		NULL,			NULL
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
#define	UNPARTITIONED_DRIVE	0

static int
pcfs_device_identify(
	struct vfs *vfsp,
	struct mounta *uap,
	struct cred *cr,
	int *dos_ldrive,
	dev_t *xdev)
{
	struct pathname special;
	char *c;
	struct vnode *svp = NULL;
	struct vnode *lvp = NULL;
	int oflag, aflag;
	int error;

	/*
	 * Resolve path name of special file being mounted.
	 */
	if (error = pn_get(uap->spec, UIO_USERSPACE, &special)) {
		return (error);
	}

	*dos_ldrive = -1;

	if (error =
	    lookupname(special.pn_path, UIO_SYSSPACE, FOLLOW, NULLVPP, &svp)) {
		/*
		 * If there's no device node, the name specified most likely
		 * maps to a PCFS-style "partition specifier" to select a
		 * harddisk primary/logical partition. Disable floppy-specific
		 * checks in such cases unless an explicit :A or :B is
		 * requested.
		 */

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
		 *	- a "floppy name letter", 'a' or 'b' (just strip this)
		 */
		if (strcasecmp(c, "boot") == 0) {
			/*
			 * The Solaris boot partition is requested.
			 */
			*dos_ldrive = BOOT_PARTITION_DRIVE;
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
					error = ENXIO;
			}
			if (error)
				goto devlookup_done;
			*dos_ldrive = (int)drvnum;
		} else if (strlen(c) == 1) {
			/*
			 * A single trailing character was specified.
			 *	- [c-zC-Z] means a harddisk partition, and
			 *	  we retrieve the partition number.
			 *	- [abAB] means a floppy drive, so we swallow
			 *	  the "drive specifier" and test later
			 *	  whether the physical device is a floppy.
			 */
			*c = tolower(*c);
			if (*c == 'a' || *c == 'b') {
				*dos_ldrive = UNPARTITIONED_DRIVE;
			} else if (*c < 'c' || *c > 'z') {
				error = ENXIO;
				goto devlookup_done;
			} else {
				*dos_ldrive = 1 + *c - 'c';
			}
		} else {
			/*
			 * Can't parse this - pass through previous error.
			 */
			goto devlookup_done;
		}


		error = lookupname(special.pn_path, UIO_SYSSPACE, FOLLOW,
		    NULLVPP, &svp);
	} else {
		*dos_ldrive = UNPARTITIONED_DRIVE;
	}
devlookup_done:
	pn_free(&special);
	if (error)
		return (error);

	ASSERT(*dos_ldrive >= UNPARTITIONED_DRIVE);

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

	error = vfs_get_lofi(vfsp, &lvp);

	if (error > 0) {
		if (error == ENOENT)
			error = ENODEV;
		goto out;
	} else if (error == 0) {
		*xdev = lvp->v_rdev;
	} else {
		*xdev = svp->v_rdev;

		if (svp->v_type != VBLK) {
			error = ENOTBLK;
			goto out;
		}

		if ((error = secpolicy_spec_open(cr, svp, oflag)) != 0)
			goto out;
	}

	if (getmajor(*xdev) >= devcnt) {
		error = ENXIO;
		goto out;
	}

	if ((error = VOP_ACCESS(svp, aflag, 0, cr, NULL)) != 0)
		goto out;

out:
	if (svp != NULL)
		VN_RELE(svp);
	if (lvp != NULL)
		VN_RELE(lvp);
	return (error);
}

static int
pcfs_device_ismounted(
	struct vfs *vfsp,
	int dos_ldrive,
	dev_t xdev,
	int *remounting,
	dev_t *pseudodev)
{
	struct pcfs *fsp;
	int remount = *remounting;

	/*
	 * Ensure that this logical drive isn't already mounted, unless
	 * this is a REMOUNT request.
	 * Note: The framework will perform this check if the "...:c"
	 * PCFS-style "logical drive" syntax has not been used and an
	 * actually existing physical device is backing this filesystem.
	 * Once all block device drivers support PC-style partitioning,
	 * this codeblock can be dropped.
	 */
	*pseudodev = xdev;

	if (dos_ldrive) {
		mutex_enter(&pcfslock);
		for (fsp = pc_mounttab; fsp; fsp = fsp->pcfs_nxt)
			if (fsp->pcfs_xdev == xdev &&
			    fsp->pcfs_ldrive == dos_ldrive) {
				mutex_exit(&pcfslock);
				if (remount) {
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
		*pseudodev = makedevice(getmajor(xdev),
		    ((dos_ldrive << 12) | getminor(xdev)) & MAXMIN32);
		if (vfs_devmounting(*pseudodev, vfsp)) {
			mutex_exit(&pcfslock);
			return (EBUSY);
		}
		if (vfs_devismounted(*pseudodev)) {
			mutex_exit(&pcfslock);
			if (remount) {
				return (0);
			} else {
				return (EBUSY);
			}
		}
		mutex_exit(&pcfslock);
	} else {
		*pseudodev = xdev;
		if (vfs_devmounting(*pseudodev, vfsp)) {
			return (EBUSY);
		}
		if (vfs_devismounted(*pseudodev))
			if (remount) {
				return (0);
			} else {
				return (EBUSY);
			}
	}

	/*
	 * This is not a remount. Even if MS_REMOUNT was requested,
	 * the caller needs to proceed as it would on an ordinary
	 * mount.
	 */
	*remounting = 0;

	ASSERT(*pseudodev);
	return (0);
}

/*
 * Get the PCFS-specific mount options from the VFS framework.
 * For "timezone" and "secsize", we need to parse the number
 * ourselves and ensure its validity.
 * Note: "secsize" is deliberately undocumented at this time,
 * it's a workaround for devices (particularly: lofi image files)
 * that don't support the DKIOCGMEDIAINFO ioctl for autodetection.
 */
static void
pcfs_parse_mntopts(struct pcfs *fsp)
{
	char *c;
	char *endptr;
	long l;
	struct vfs *vfsp = fsp->pcfs_vfs;

	ASSERT(fsp->pcfs_secondswest == 0);
	ASSERT(fsp->pcfs_secsize == 0);

	if (vfs_optionisset(vfsp, MNTOPT_PCFS_HIDDEN, NULL))
		fsp->pcfs_flags |= PCFS_HIDDEN;
	if (vfs_optionisset(vfsp, MNTOPT_PCFS_FOLDCASE, NULL))
		fsp->pcfs_flags |= PCFS_FOLDCASE;
	if (vfs_optionisset(vfsp, MNTOPT_PCFS_NOCLAMPTIME, NULL))
		fsp->pcfs_flags |= PCFS_NOCLAMPTIME;
	if (vfs_optionisset(vfsp, MNTOPT_NOATIME, NULL))
		fsp->pcfs_flags |= PCFS_NOATIME;

	if (vfs_optionisset(vfsp, MNTOPT_PCFS_TIMEZONE, &c)) {
		if (ddi_strtol(c, &endptr, 10, &l) == 0 &&
		    endptr == c + strlen(c)) {
			/*
			 * A number alright - in the allowed range ?
			 */
			if (l <= -12*3600 || l >= 12*3600) {
				cmn_err(CE_WARN, "!pcfs: invalid use of "
				    "'timezone' mount option - %ld "
				    "is out of range. Assuming 0.", l);
				l = 0;
			}
		} else {
			cmn_err(CE_WARN, "!pcfs: invalid use of "
			    "'timezone' mount option - argument %s "
			    "is not a valid number. Assuming 0.", c);
			l = 0;
		}
		fsp->pcfs_secondswest = l;
	}

	/*
	 * The "secsize=..." mount option is a workaround for the lack of
	 * lofi(7d) support for DKIOCGMEDIAINFO. If PCFS wants to parse the
	 * partition table of a disk image and it has been partitioned with
	 * sector sizes other than 512 bytes, we'd fail on loopback'ed disk
	 * images.
	 * That should really be fixed in lofi ... this is a workaround.
	 */
	if (vfs_optionisset(vfsp, MNTOPT_PCFS_SECSIZE, &c)) {
		if (ddi_strtol(c, &endptr, 10, &l) == 0 &&
		    endptr == c + strlen(c)) {
			/*
			 * A number alright - a valid sector size as well ?
			 */
			if (!VALID_SECSIZE(l)) {
				cmn_err(CE_WARN, "!pcfs: invalid use of "
				    "'secsize' mount option - %ld is "
				    "unsupported. Autodetecting.", l);
				l = 0;
			}
		} else {
			cmn_err(CE_WARN, "!pcfs: invalid use of "
			    "'secsize' mount option - argument %s "
			    "is not a valid number. Autodetecting.", c);
			l = 0;
		}
		fsp->pcfs_secsize = l;
		fsp->pcfs_sdshift = ddi_ffs(l / DEV_BSIZE) - 1;
	}
}

/*
 * vfs operations
 */

/*
 * pcfs_mount - backend for VFS_MOUNT() on PCFS.
 */
static int
pcfs_mount(
	struct vfs *vfsp,
	struct vnode *mvp,
	struct mounta *uap,
	struct cred *cr)
{
	struct pcfs *fsp;
	struct vnode *devvp;
	dev_t pseudodev;
	dev_t xdev;
	int dos_ldrive = 0;
	int error;
	int remounting;

	if ((error = secpolicy_fs_mount(cr, mvp, vfsp)) != 0)
		return (error);

	if (mvp->v_type != VDIR)
		return (ENOTDIR);

	mutex_enter(&mvp->v_lock);
	if ((uap->flags & MS_REMOUNT) == 0 &&
	    (uap->flags & MS_OVERLAY) == 0 &&
	    (mvp->v_count != 1 || (mvp->v_flag & VROOT))) {
		mutex_exit(&mvp->v_lock);
		return (EBUSY);
	}
	mutex_exit(&mvp->v_lock);

	/*
	 * PCFS doesn't do mount arguments anymore - everything's a mount
	 * option these days. In order not to break existing callers, we
	 * don't reject it yet, just warn that the data (if any) is ignored.
	 */
	if (uap->datalen != 0)
		cmn_err(CE_WARN, "!pcfs: deprecated use of mount(2) with "
		    "mount argument structures instead of mount options. "
		    "Ignoring mount(2) 'dataptr' argument.");

	/*
	 * This is needed early, to make sure the access / open calls
	 * are done using the correct mode. Processing this mount option
	 * only when calling pcfs_parse_mntopts() would lead us to attempt
	 * a read/write access to a possibly writeprotected device, and
	 * a readonly mount attempt might fail because of that.
	 */
	if (uap->flags & MS_RDONLY) {
		vfsp->vfs_flag |= VFS_RDONLY;
		vfs_setmntopt(vfsp, MNTOPT_RO, NULL, 0);
	}

	/*
	 * For most filesystems, this is just a lookupname() on the
	 * mount pathname string. PCFS historically has to do its own
	 * partition table parsing because not all Solaris architectures
	 * support all styles of partitioning that PC media can have, and
	 * hence PCFS understands "device names" that don't map to actual
	 * physical device nodes. Parsing the "PCFS syntax" for device
	 * names is done in pcfs_device_identify() - see there.
	 *
	 * Once all block device drivers that can host FAT filesystems have
	 * been enhanced to create device nodes for all PC-style partitions,
	 * this code can go away.
	 */
	if (error = pcfs_device_identify(vfsp, uap, cr, &dos_ldrive, &xdev))
		return (error);

	/*
	 * As with looking up the actual device to mount, PCFS cannot rely
	 * on just the checks done by vfs_ismounted() whether a given device
	 * is mounted already. The additional check against the "PCFS syntax"
	 * is done in  pcfs_device_ismounted().
	 */
	remounting = (uap->flags & MS_REMOUNT);

	if (error = pcfs_device_ismounted(vfsp, dos_ldrive, xdev, &remounting,
	    &pseudodev))
		return (error);

	if (remounting)
		return (0);

	/*
	 * Mount the filesystem.
	 * An instance structure is required before the attempt to locate
	 * and parse the FAT BPB. This is because mount options may change
	 * the behaviour of the filesystem type matching code. Precreate
	 * it and fill it in to a degree that allows parsing the mount
	 * options.
	 */
	devvp = makespecvp(xdev, VBLK);
	if (IS_SWAPVP(devvp)) {
		VN_RELE(devvp);
		return (EBUSY);
	}
	error = VOP_OPEN(&devvp,
	    (vfsp->vfs_flag & VFS_RDONLY) ? FREAD : FREAD | FWRITE, cr, NULL);
	if (error) {
		VN_RELE(devvp);
		return (error);
	}

	fsp = kmem_zalloc(sizeof (*fsp), KM_SLEEP);
	fsp->pcfs_vfs = vfsp;
	fsp->pcfs_xdev = xdev;
	fsp->pcfs_devvp = devvp;
	fsp->pcfs_ldrive = dos_ldrive;
	mutex_init(&fsp->pcfs_lock, NULL, MUTEX_DEFAULT, NULL);

	pcfs_parse_mntopts(fsp);

	/*
	 * This is the actual "mount" - the PCFS superblock check.
	 *
	 * Find the requested logical drive and the FAT BPB therein.
	 * Check device type and flag the instance if media is removeable.
	 *
	 * Initializes most members of the filesystem instance structure.
	 * Returns EINVAL if no valid BPB can be found. Other errors may
	 * occur after I/O failures, or when invalid / unparseable partition
	 * tables are encountered.
	 */
	if (error = pc_getfattype(fsp))
		goto errout;

	/*
	 * Now that the BPB has been parsed, this structural information
	 * is available and known to be valid. Initialize the VFS.
	 */
	vfsp->vfs_data = fsp;
	vfsp->vfs_dev = pseudodev;
	vfsp->vfs_fstype = pcfstype;
	vfs_make_fsid(&vfsp->vfs_fsid, pseudodev, pcfstype);
	vfsp->vfs_bcount = 0;
	vfsp->vfs_bsize = fsp->pcfs_clsize;

	/*
	 * Validate that we can access the FAT and that it is, to the
	 * degree we can verify here, self-consistent.
	 */
	if (error = pc_verify(fsp))
		goto errout;

	/*
	 * Record the time of the mount, to return as an "approximate"
	 * timestamp for the FAT root directory. Since FAT roots don't
	 * have timestamps, this is less confusing to the user than
	 * claiming "zero" / Jan/01/1970.
	 */
	gethrestime(&fsp->pcfs_mounttime);

	/*
	 * Fix up the mount options. Because "noatime" is made default on
	 * removeable media only, a fixed disk will have neither "atime"
	 * nor "noatime" set. We set the options explicitly depending on
	 * the PCFS_NOATIME flag, to inform the user of what applies.
	 * Mount option cancellation will take care that the mutually
	 * exclusive 'other' is cleared.
	 */
	vfs_setmntopt(vfsp,
	    fsp->pcfs_flags & PCFS_NOATIME ? MNTOPT_NOATIME : MNTOPT_ATIME,
	    NULL, 0);

	/*
	 * All clear - insert the FS instance into PCFS' list.
	 */
	mutex_enter(&pcfslock);
	fsp->pcfs_nxt = pc_mounttab;
	pc_mounttab = fsp;
	mutex_exit(&pcfslock);
	atomic_inc_32(&pcfs_mountcount);
	return (0);

errout:
	(void) VOP_CLOSE(devvp,
	    vfsp->vfs_flag & VFS_RDONLY ? FREAD : FREAD | FWRITE,
	    1, (offset_t)0, cr, NULL);
	VN_RELE(devvp);
	mutex_destroy(&fsp->pcfs_lock);
	kmem_free(fsp, sizeof (*fsp));
	return (error);

}

static int
pcfs_unmount(
	struct vfs *vfsp,
	int flag,
	struct cred *cr)
{
	struct pcfs *fsp, *fsp1;

	if (secpolicy_fs_unmount(cr, vfsp) != 0)
		return (EPERM);

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
	sp->f_namemax = PCMAXNAMLEN;
	return (0);
}

static int
pc_syncfsnodes(struct pcfs *fsp)
{
	struct pchead *hp;
	struct pcnode *pcp;
	int error;

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

int
pc_syncfat(struct pcfs *fsp)
{
	struct buf *bp;
	int nfat;
	int	error = 0;
	struct fat_od_fsi *fsinfo_disk;

	if ((fsp->pcfs_fatp == (uchar_t *)0) ||
	    !(fsp->pcfs_flags & PCFS_FATMOD))
		return (0);
	/*
	 * write out all copies of FATs
	 */
	fsp->pcfs_flags &= ~PCFS_FATMOD;
	fsp->pcfs_fattime = gethrestime_sec() + PCFS_DISKTIMEOUT;
	for (nfat = 0; nfat < fsp->pcfs_numfat; nfat++) {
		error = pc_writefat(fsp, pc_dbdaddr(fsp,
		    fsp->pcfs_fatstart + nfat * fsp->pcfs_fatsec));
		if (error) {
			pc_mark_irrecov(fsp);
			return (EIO);
		}
	}
	pc_clear_fatchanges(fsp);

	/*
	 * Write out fsinfo sector.
	 */
	if (IS_FAT32(fsp)) {
		bp = bread(fsp->pcfs_xdev,
		    pc_dbdaddr(fsp, fsp->pcfs_fsistart), fsp->pcfs_secsize);
		if (bp->b_flags & (B_ERROR | B_STALE)) {
			error = geterror(bp);
		}
		fsinfo_disk = (fat_od_fsi_t *)(bp->b_un.b_addr);
		if (!error && FSISIG_OK(fsinfo_disk)) {
			fsinfo_disk->fsi_incore.fs_free_clusters =
			    LE_32(fsp->pcfs_fsinfo.fs_free_clusters);
			fsinfo_disk->fsi_incore.fs_next_free =
			    LE_32(FSINFO_UNKNOWN);
			bwrite2(bp);
			error = geterror(bp);
		}
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

	if (fsp->pcfs_fatp == (uchar_t *)0)
		panic("pc_invalfat");
	/*
	 * Release FAT
	 */
	kmem_free(fsp->pcfs_fatp, fsp->pcfs_fatsec * fsp->pcfs_secsize);
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
	    1, (offset_t)0, CRED(), NULL);
}

void
pc_badfs(struct pcfs *fsp)
{
	cmn_err(CE_WARN, "corrupted PC file system on dev (%x.%x):%d\n",
	    getmajor(fsp->pcfs_devvp->v_rdev),
	    getminor(fsp->pcfs_devvp->v_rdev), fsp->pcfs_ldrive);
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

	if (eblkno >= fsp->pcfs_datastart || (eblkno - fsp->pcfs_rdirstart)
	    < (fsp->pcfs_rdirsec & ~(fsp->pcfs_spcl - 1))) {
		bp = bread(fsp->pcfs_xdev, pc_dbdaddr(fsp, eblkno),
		    fsp->pcfs_clsize);
	} else {
		/*
		 * This is an access "backwards" into the FAT12/FAT16
		 * root directory. A better code structure would
		 * significantly improve maintainability here ...
		 */
		bp = bread(fsp->pcfs_xdev, pc_dbdaddr(fsp, eblkno),
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
 * Unfortunately, FAT32 fat's can be pretty big (On a 1 gig jaz drive, about
 * a meg), so we can't bread() it all in at once. This routine reads a
 * fat a chunk at a time.
 */
static int
pc_readfat(struct pcfs *fsp, uchar_t *fatp)
{
	struct buf *bp;
	size_t off;
	size_t readsize;
	daddr_t diskblk;
	size_t fatsize = fsp->pcfs_fatsec * fsp->pcfs_secsize;
	daddr_t start = fsp->pcfs_fatstart;

	readsize = fsp->pcfs_clsize;
	for (off = 0; off < fatsize; off += readsize, fatp += readsize) {
		if (readsize > (fatsize - off))
			readsize = fatsize - off;
		diskblk = pc_dbdaddr(fsp, start +
		    pc_cltodb(fsp, pc_lblkno(fsp, off)));
		bp = bread(fsp->pcfs_xdev, diskblk, readsize);
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
 * This function doesn't take "start" from fsp->pcfs_dosstart because
 * callers can use it to write either the primary or any of the alternate
 * FAT tables.
 */
static int
pc_writefat(struct pcfs *fsp, daddr_t start)
{
	struct buf *bp;
	size_t off;
	size_t writesize;
	int	error;
	uchar_t *fatp = fsp->pcfs_fatp;
	size_t fatsize = fsp->pcfs_fatsec * fsp->pcfs_secsize;

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
	/*
	 * Purging the FAT closes the device - can't do any more
	 * I/O after this.
	 */
	if (fsp->pcfs_fatp != (uchar_t *)0)
		pc_invalfat(fsp);
	mutex_exit(&pcfslock);

	VN_RELE(fsp->pcfs_devvp);
	mutex_destroy(&fsp->pcfs_lock);
	kmem_free(fsp, sizeof (*fsp));

	/*
	 * Allow _fini() to succeed now, if so desired.
	 */
	atomic_dec_32(&pcfs_mountcount);
}


/*
 * PC-style partition parsing and FAT BPB identification/validation code.
 * The partition parsers here assume:
 *	- a FAT filesystem will be in a partition that has one of a set of
 *	  recognized partition IDs
 *	- the user wants the 'numbering' (C:, D:, ...) that one would get
 *	  on MSDOS 6.x.
 *	  That means any non-FAT partition type (NTFS, HPFS, or any Linux fs)
 *	  will not factor in the enumeration.
 * These days, such assumptions should be revisited. FAT is no longer the
 * only game in 'PC town'.
 */
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
noLogicalDrive(int ldrive)
{
	if (ldrive == BOOT_PARTITION_DRIVE) {
		cmn_err(CE_NOTE, "!pcfs: no boot partition");
	} else {
		cmn_err(CE_NOTE, "!pcfs: %d: no such logical drive", ldrive);
	}
}


/*
 * findTheDrive()
 *	Discover offset of the requested logical drive, and return
 *	that offset (startSector), the systid of that drive (sysid),
 *	and a buffer pointer (bp), with the buffer contents being
 *	the first sector of the logical drive (i.e., the sector that
 *	contains the BPB for that drive).
 *
 * Note: this code is not capable of addressing >2TB disks, as it uses
 *       daddr_t not diskaddr_t, some of the calculations would overflow
 */
#define	COPY_PTBL(mbr, ptblp)					\
	bcopy(&(((struct mboot *)(mbr))->parts), (ptblp),	\
	    FD_NUMPART * sizeof (struct ipart))

static int
findTheDrive(struct pcfs *fsp, buf_t **bp)
{
	int ldrive = fsp->pcfs_ldrive;
	dev_t dev = fsp->pcfs_devvp->v_rdev;

	struct ipart dosp[FD_NUMPART];	/* incore fdisk partition structure */
	daddr_t lastseek = 0;		/* Disk block we sought previously */
	daddr_t diskblk = 0;		/* Disk block to get */
	daddr_t xstartsect;		/* base of Extended DOS partition */
	int logicalDriveCount = 0;	/* Count of logical drives seen */
	int extendedPart = -1;		/* index of extended dos partition */
	int primaryPart = -1;		/* index of primary dos partition */
	int bootPart = -1;		/* index of a Solaris boot partition */
	uint32_t xnumsect = 0;		/* length of extended DOS partition */
	int driveIndex;			/* computed FDISK table index */
	daddr_t startsec;
	len_t mediasize;
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
	COPY_PTBL((*bp)->b_un.b_addr, dosp);

	/*
	 * This check is ok because a FAT BPB and a master boot record (MBB)
	 * have the same signature, in the same position within the block.
	 */
	if (bpb_get_BPBSig((*bp)->b_un.b_addr) != MBB_MAGIC) {
		cmn_err(CE_NOTE, "!pcfs: MBR partition table signature err, "
		    "device (%x.%x):%d\n",
		    getmajor(dev), getminor(dev), ldrive);
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
		DTRACE_PROBE4(primarypart, struct pcfs *, fsp,
		    uint_t, (uint_t)dosp[i].systid,
		    uint_t, LE_32(dosp[i].relsect),
		    uint_t, LE_32(dosp[i].numsect));

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
		startsec = LE_32(dosp[bootPart].relsect);
		mediasize = LE_32(dosp[bootPart].numsect);
		goto found;
	}

	if (ldrive == PRIMARY_DOS_DRIVE && primaryPart >= 0) {
		startsec = LE_32(dosp[primaryPart].relsect);
		mediasize = LE_32(dosp[primaryPart].numsect);
		goto found;
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
		diskblk = xstartsect = LE_32(dosp[extendedPart].relsect);
		xnumsect = LE_32(dosp[extendedPart].numsect);
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
			/*
			 * bread() block numbers are multiples of DEV_BSIZE
			 * but the device sector size (the unit of partitioning)
			 * might be larger than that; pcfs_get_device_info()
			 * has calculated the multiplicator for us.
			 */
			*bp = bread(dev,
			    pc_dbdaddr(fsp, diskblk), fsp->pcfs_secsize);
			if ((*bp)->b_flags & B_ERROR) {
				return (EIO);
			}

			lastseek = diskblk;
			COPY_PTBL((*bp)->b_un.b_addr, dosp);
			if (bpb_get_BPBSig((*bp)->b_un.b_addr) != MBB_MAGIC) {
				cmn_err(CE_NOTE, "!pcfs: "
				    "extended partition table signature err, "
				    "device (%x.%x):%d, LBA %u",
				    getmajor(dev), getminor(dev), ldrive,
				    (uint_t)pc_dbdaddr(fsp, diskblk));
				return (EINVAL);
			}
			/*
			 *  Count up drives, and track where the next
			 *  extended partition is in case we need it.  We
			 *  are expecting only one extended partition.  If
			 *  there is more than one we'll only go to the
			 *  first one we see, but warn about ignoring.
			 */
			numDrives = 0;
			for (i = 0; i < FD_NUMPART; i++) {
				DTRACE_PROBE4(extendedpart,
				    struct pcfs *, fsp,
				    uint_t, (uint_t)dosp[i].systid,
				    uint_t, LE_32(dosp[i].relsect),
				    uint_t, LE_32(dosp[i].numsect));
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
						    LE_32(dosp[i].relsect);
					}
				}
			}
		} while (ldrive > logicalDriveCount + numDrives);

		ASSERT(numDrives <= FD_NUMPART);

		if (ldrive <= logicalDriveCount + numDrives) {
			/*
			 * The number of logical drives we've found thus
			 * far is enough to get us to the one we were
			 * searching for.
			 */
			driveIndex = logicalDriveCount + numDrives - ldrive;
			mediasize =
			    LE_32(dosp[extndDrives[driveIndex]].numsect);
			startsec =
			    LE_32(dosp[extndDrives[driveIndex]].relsect) +
			    lastseek;
			if (startsec > (xstartsect + xnumsect)) {
				cmn_err(CE_NOTE, "!pcfs: extended partition "
				    "values bad");
				return (EINVAL);
			}
			goto found;
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
			ASSERT(fsp->pcfs_dosstart == 0);
			*bp = bread(dev, pc_dbdaddr(fsp, fsp->pcfs_dosstart),
			    fsp->pcfs_secsize);
			if ((*bp)->b_flags & B_ERROR) {
				return (EIO);
			}
			COPY_PTBL((*bp)->b_un.b_addr, dosp);
		}
	}
	/*
	 *  Still haven't found the drive, is it an extra
	 *  drive defined in the main FDISK table?
	 */
	if (ldrive <= logicalDriveCount + numExtraDrives) {
		driveIndex = logicalDriveCount + numExtraDrives - ldrive;
		ASSERT(driveIndex < MIN(numExtraDrives, FD_NUMPART));
		mediasize = LE_32(dosp[extraDrives[driveIndex]].numsect);
		startsec = LE_32(dosp[extraDrives[driveIndex]].relsect);
		goto found;
	}
	/*
	 *  Still haven't found the drive, and there is
	 *  nowhere else to look.
	 */
	noLogicalDrive(ldrive);
	return (EINVAL);

found:
	/*
	 * We need this value in units of sectorsize, because PCFS' internal
	 * offset calculations go haywire for > 512Byte sectors unless all
	 * pcfs_.*start values are in units of sectors.
	 * So, assign before the capacity check (that's done in DEV_BSIZE)
	 */
	fsp->pcfs_dosstart = startsec;

	/*
	 * convert from device sectors to proper units:
	 *	- starting sector: DEV_BSIZE (as argument to bread())
	 *	- media size: Bytes
	 */
	startsec = pc_dbdaddr(fsp, startsec);
	mediasize *= fsp->pcfs_secsize;

	/*
	 * some additional validation / warnings in case the partition table
	 * and the actual media capacity are not in accordance ...
	 */
	if (fsp->pcfs_mediasize != 0) {
		diskaddr_t startoff =
		    (diskaddr_t)startsec * (diskaddr_t)DEV_BSIZE;

		if (startoff >= fsp->pcfs_mediasize ||
		    startoff + mediasize > fsp->pcfs_mediasize) {
			cmn_err(CE_WARN,
			    "!pcfs: partition size (LBA start %u, %lld bytes, "
			    "device (%x.%x):%d) smaller than "
			    "mediasize (%lld bytes).\n"
			    "filesystem may be truncated, access errors "
			    "may result.\n",
			    (uint_t)startsec, (long long)mediasize,
			    getmajor(fsp->pcfs_xdev), getminor(fsp->pcfs_xdev),
			    fsp->pcfs_ldrive, (long long)fsp->pcfs_mediasize);
		}
	} else {
		fsp->pcfs_mediasize = mediasize;
	}

	return (0);
}


static fattype_t
secondaryBPBChecks(struct pcfs *fsp, uchar_t *bpb, size_t secsize)
{
	uint32_t ncl = fsp->pcfs_ncluster;

	if (ncl <= 4096) {
		if (bpb_get_FatSz16(bpb) == 0)
			return (FAT_UNKNOWN);

		if (bpb_get_FatSz16(bpb) * secsize < ncl * 2 &&
		    bpb_get_FatSz16(bpb) * secsize >= (3 * ncl / 2))
			return (FAT12);
		if (bcmp(bpb_FilSysType16(bpb), "FAT12", 5) == 0)
			return (FAT12);
		if (bcmp(bpb_FilSysType16(bpb), "FAT16", 5) == 0)
			return (FAT16);

		switch (bpb_get_Media(bpb)) {
			case SS8SPT:
			case DS8SPT:
			case SS9SPT:
			case DS9SPT:
			case DS18SPT:
			case DS9_15SPT:
				/*
				 * Is this reliable - all floppies are FAT12 ?
				 */
				return (FAT12);
			case MD_FIXED:
				/*
				 * Is this reliable - disks are always FAT16 ?
				 */
				return (FAT16);
			default:
				break;
		}
	} else if (ncl <= 65536) {
		if (bpb_get_FatSz16(bpb) == 0 && bpb_get_FatSz32(bpb) > 0)
			return (FAT32);
		if (VALID_BOOTSIG(bpb_get_BootSig32(bpb)))
			return (FAT32);
		if (VALID_FSTYPSTR32(bpb_FilSysType32(bpb)))
			return (FAT32);

		if (VALID_BOOTSIG(bpb_get_BootSig16(bpb)))
			return (FAT16);
		if (bpb_get_FatSz16(bpb) * secsize < ncl * 4)
			return (FAT16);
	}

	/*
	 * We don't know
	 */
	return (FAT_UNKNOWN);
}

/*
 * Check to see if the BPB we found is correct.
 *
 * This looks far more complicated that it needs to be for pure structural
 * validation. The reason for this is that parseBPB() is also used for
 * debugging purposes (mdb dcmd) and we therefore want a bitmap of which
 * BPB fields (do not) have 'known good' values, even if we (do not) reject
 * the BPB when attempting to mount the filesystem.
 *
 * Real-world usage of FAT shows there are a lot of corner-case situations
 * and, following the specification strictly, invalid filesystems out there.
 * Known are situations such as:
 *	- FAT12/FAT16 filesystems with garbage in either totsec16/32
 *	  instead of the zero in one of the fields mandated by the spec
 *	- filesystems that claim to be larger than the partition they're in
 *	- filesystems without valid media descriptor
 *	- FAT32 filesystems with RootEntCnt != 0
 *	- FAT32 filesystems with less than 65526 clusters
 *	- FAT32 filesystems without valid FSI sector
 *	- FAT32 filesystems with FAT size in fatsec16 instead of fatsec32
 *
 * Such filesystems are accessible by PCFS - if it'd know to start with that
 * the filesystem should be treated as a specific FAT type. Before S10, it
 * relied on the PC/fdisk partition type for the purpose and almost completely
 * ignored the BPB; now it ignores the partition type for anything else but
 * logical drive enumeration, which can result in rejection of (invalid)
 * FAT32 - if the partition ID says FAT32, but the filesystem, for example
 * has less than 65526 clusters.
 *
 * Without a "force this fs as FAT{12,16,32}" tunable or mount option, it's
 * not possible to allow all such mostly-compliant filesystems in unless one
 * accepts false positives (definitely invalid filesystems that cause problems
 * later). This at least allows to pinpoint why the mount failed.
 *
 * Due to the use of FAT on removeable media, all relaxations of the rules
 * here need to be carefully evaluated wrt. to potential effects on PCFS
 * resilience. A faulty/"mis-crafted" filesystem must not cause a panic, so
 * beware.
 */
static int
parseBPB(struct pcfs *fsp, uchar_t *bpb, int *valid)
{
	fattype_t type;

	uint32_t	ncl;	/* number of clusters in file area */
	uint32_t	rec;
	uint32_t	reserved;
	uint32_t	fsisec, bkbootsec;
	blkcnt_t	totsec, totsec16, totsec32, datasec;
	size_t		fatsec, fatsec16, fatsec32, rdirsec;
	size_t		secsize;
	len_t		mediasize;
	uint64_t	validflags = 0;

	if (VALID_BPBSIG(bpb_get_BPBSig(bpb)))
		validflags |= BPB_BPBSIG_OK;

	rec = bpb_get_RootEntCnt(bpb);
	reserved = bpb_get_RsvdSecCnt(bpb);
	fsisec = bpb_get_FSInfo32(bpb);
	bkbootsec = bpb_get_BkBootSec32(bpb);
	totsec16 = (blkcnt_t)bpb_get_TotSec16(bpb);
	totsec32 = (blkcnt_t)bpb_get_TotSec32(bpb);
	fatsec16 = bpb_get_FatSz16(bpb);
	fatsec32 = bpb_get_FatSz32(bpb);

	totsec = totsec16 ? totsec16 : totsec32;
	fatsec = fatsec16 ? fatsec16 : fatsec32;

	secsize = bpb_get_BytesPerSec(bpb);
	if (!VALID_SECSIZE(secsize))
		secsize = fsp->pcfs_secsize;
	if (secsize != fsp->pcfs_secsize) {
		PC_DPRINTF3(3, "!pcfs: parseBPB, device (%x.%x):%d:\n",
		    getmajor(fsp->pcfs_xdev),
		    getminor(fsp->pcfs_xdev), fsp->pcfs_ldrive);
		PC_DPRINTF2(3, "!BPB secsize %d != "
		    "autodetected media block size %d\n",
		    (int)secsize, (int)fsp->pcfs_secsize);
		if (fsp->pcfs_ldrive) {
			/*
			 * We've already attempted to parse the partition
			 * table. If the block size used for that don't match
			 * the PCFS sector size, we're hosed one way or the
			 * other. Just try what happens.
			 */
			secsize = fsp->pcfs_secsize;
			PC_DPRINTF1(3,
			    "!pcfs: Using autodetected secsize %d\n",
			    (int)secsize);
		} else {
			/*
			 * This allows mounting lofi images of PCFS partitions
			 * with sectorsize != DEV_BSIZE. We can't parse the
			 * partition table on whole-disk images unless the
			 * (undocumented) "secsize=..." mount option is used,
			 * but at least this allows us to mount if we have
			 * an image of a partition.
			 */
			PC_DPRINTF1(3,
			    "!pcfs: Using BPB secsize %d\n", (int)secsize);
		}
	}

	if (fsp->pcfs_mediasize == 0) {
		mediasize = (len_t)totsec * (len_t)secsize;
		/*
		 * This is not an error because not all devices support the
		 * dkio(7i) mediasize queries, and/or not all devices are
		 * partitioned. If we have not been able to figure out the
		 * size of the underlaying medium, we have to trust the BPB.
		 */
		PC_DPRINTF4(3, "!pcfs: parseBPB: mediasize autodetect failed "
		    "on device (%x.%x):%d, trusting BPB totsec (%lld Bytes)\n",
		    getmajor(fsp->pcfs_xdev), getminor(fsp->pcfs_xdev),
		    fsp->pcfs_ldrive, (long long)fsp->pcfs_mediasize);
	} else if ((len_t)totsec * (len_t)secsize > fsp->pcfs_mediasize) {
		cmn_err(CE_WARN,
		    "!pcfs: autodetected mediasize (%lld Bytes) smaller than "
		    "FAT BPB mediasize (%lld Bytes).\n"
		    "truncated filesystem on device (%x.%x):%d, access errors "
		    "possible.\n",
		    (long long)fsp->pcfs_mediasize,
		    (long long)(totsec * (blkcnt_t)secsize),
		    getmajor(fsp->pcfs_xdev), getminor(fsp->pcfs_xdev),
		    fsp->pcfs_ldrive);
		mediasize = fsp->pcfs_mediasize;
	} else {
		/*
		 * This is actually ok. A FAT needs not occupy the maximum
		 * space available in its partition, it can be shorter.
		 */
		mediasize = (len_t)totsec * (len_t)secsize;
	}

	/*
	 * Since we let just about anything pass through this function,
	 * fence against divide-by-zero here.
	 */
	if (secsize)
		rdirsec = roundup(rec * 32, secsize) / secsize;
	else
		rdirsec = 0;

	/*
	 * This assignment is necessary before pc_dbdaddr() can first be
	 * used. Must initialize the value here.
	 */
	fsp->pcfs_secsize = secsize;
	fsp->pcfs_sdshift = ddi_ffs(secsize / DEV_BSIZE) - 1;

	fsp->pcfs_mediasize = mediasize;

	fsp->pcfs_spcl = bpb_get_SecPerClus(bpb);
	fsp->pcfs_numfat = bpb_get_NumFATs(bpb);
	fsp->pcfs_mediadesc = bpb_get_Media(bpb);
	fsp->pcfs_clsize = secsize * fsp->pcfs_spcl;
	fsp->pcfs_rdirsec = rdirsec;

	/*
	 * Remember: All PCFS offset calculations in sectors. Before I/O
	 * is done, convert to DEV_BSIZE units via pc_dbdaddr(). This is
	 * necessary so that media with > 512Byte sector sizes work correctly.
	 */
	fsp->pcfs_fatstart = fsp->pcfs_dosstart + reserved;
	fsp->pcfs_rdirstart = fsp->pcfs_fatstart + fsp->pcfs_numfat * fatsec;
	fsp->pcfs_datastart = fsp->pcfs_rdirstart + rdirsec;
	datasec = totsec -
	    (blkcnt_t)fatsec * fsp->pcfs_numfat -
	    (blkcnt_t)rdirsec -
	    (blkcnt_t)reserved;

	DTRACE_PROBE4(fatgeometry,
	    blkcnt_t, totsec, size_t, fatsec,
	    size_t, rdirsec, blkcnt_t, datasec);

	/*
	 * 'totsec' is taken directly from the BPB and guaranteed to fit
	 * into a 32bit unsigned integer. The calculation of 'datasec',
	 * on the other hand, could underflow for incorrect values in
	 * rdirsec/reserved/fatsec. Check for that.
	 * We also check that the BPB conforms to the FAT specification's
	 * requirement that either of the 16/32bit total sector counts
	 * must be zero.
	 */
	if (totsec != 0 &&
	    (totsec16 == totsec32 || totsec16 == 0 || totsec32 == 0) &&
	    datasec < totsec && datasec <= UINT32_MAX)
		validflags |= BPB_TOTSEC_OK;

	if ((len_t)totsec * (len_t)secsize <= mediasize)
		validflags |= BPB_MEDIASZ_OK;

	if (VALID_SECSIZE(secsize))
		validflags |= BPB_SECSIZE_OK;
	if (VALID_SPCL(fsp->pcfs_spcl))
		validflags |= BPB_SECPERCLUS_OK;
	if (VALID_CLSIZE(fsp->pcfs_clsize))
		validflags |= BPB_CLSIZE_OK;
	if (VALID_NUMFATS(fsp->pcfs_numfat))
		validflags |= BPB_NUMFAT_OK;
	if (VALID_RSVDSEC(reserved) && reserved < totsec)
		validflags |= BPB_RSVDSECCNT_OK;
	if (VALID_MEDIA(fsp->pcfs_mediadesc))
		validflags |= BPB_MEDIADESC_OK;
	if (VALID_BOOTSIG(bpb_get_BootSig16(bpb)))
		validflags |= BPB_BOOTSIG16_OK;
	if (VALID_BOOTSIG(bpb_get_BootSig32(bpb)))
		validflags |= BPB_BOOTSIG32_OK;
	if (VALID_FSTYPSTR16(bpb_FilSysType16(bpb)))
		validflags |= BPB_FSTYPSTR16_OK;
	if (VALID_FSTYPSTR32(bpb_FilSysType32(bpb)))
		validflags |= BPB_FSTYPSTR32_OK;
	if (VALID_OEMNAME(bpb_OEMName(bpb)))
		validflags |= BPB_OEMNAME_OK;
	if (bkbootsec > 0 && bkbootsec <= reserved && fsisec != bkbootsec)
		validflags |= BPB_BKBOOTSEC_OK;
	if (fsisec > 0 && fsisec <= reserved)
		validflags |= BPB_FSISEC_OK;
	if (VALID_JMPBOOT(bpb_jmpBoot(bpb)))
		validflags |= BPB_JMPBOOT_OK;
	if (VALID_FSVER32(bpb_get_FSVer32(bpb)))
		validflags |= BPB_FSVER_OK;
	if (VALID_VOLLAB(bpb_VolLab16(bpb)))
		validflags |= BPB_VOLLAB16_OK;
	if (VALID_VOLLAB(bpb_VolLab32(bpb)))
		validflags |= BPB_VOLLAB32_OK;
	if (VALID_EXTFLAGS(bpb_get_ExtFlags32(bpb)))
		validflags |= BPB_EXTFLAGS_OK;

	/*
	 * Try to determine which FAT format to use.
	 *
	 * Calculate the number of clusters in order to determine
	 * the type of FAT we are looking at.  This is the only
	 * recommended way of determining FAT type, though there
	 * are other hints in the data, this is the best way.
	 *
	 * Since we let just about "anything" pass through this function
	 * without early exits, fence against divide-by-zero here.
	 *
	 * datasec was already validated against UINT32_MAX so we know
	 * the result will not overflow the 32bit calculation.
	 */
	if (fsp->pcfs_spcl)
		ncl = (uint32_t)datasec / fsp->pcfs_spcl;
	else
		ncl = 0;

	fsp->pcfs_ncluster = ncl;

	/*
	 * From the Microsoft FAT specification:
	 * In the following example, when it says <, it does not mean <=.
	 * Note also that the numbers are correct.  The first number for
	 * FAT12 is 4085; the second number for FAT16 is 65525. These numbers
	 * and the '<' signs are not wrong.
	 *
	 * We "specialdetect" the corner cases, and use at least one "extra"
	 * criterion to decide whether it's FAT16 or FAT32 if the cluster
	 * count is dangerously close to the boundaries.
	 */

	if (ncl <= PCF_FIRSTCLUSTER) {
		type = FAT_UNKNOWN;
	} else if (ncl < 4085) {
		type = FAT12;
	} else if (ncl <= 4096) {
		type = FAT_QUESTIONABLE;
	} else if (ncl < 65525) {
		type = FAT16;
	} else if (ncl <= 65536) {
		type = FAT_QUESTIONABLE;
	} else if (ncl < PCF_LASTCLUSTER32) {
		type = FAT32;
	} else {
		type = FAT_UNKNOWN;
	}

	DTRACE_PROBE4(parseBPB__initial,
	    struct pcfs *, fsp, unsigned char *, bpb,
	    int, validflags, fattype_t, type);

recheck:
	fsp->pcfs_fatsec = fatsec;

	/* Do some final sanity checks for each specific type of FAT */
	switch (type) {
		case FAT12:
			if (rec != 0)
				validflags |= BPB_ROOTENTCNT_OK;
			if ((blkcnt_t)bpb_get_TotSec16(bpb) == totsec ||
			    bpb_get_TotSec16(bpb) == 0)
				validflags |= BPB_TOTSEC16_OK;
			if ((blkcnt_t)bpb_get_TotSec32(bpb) == totsec ||
			    bpb_get_TotSec32(bpb) == 0)
				validflags |= BPB_TOTSEC32_OK;
			if (bpb_get_FatSz16(bpb) == fatsec)
				validflags |= BPB_FATSZ16_OK;
			if (fatsec * secsize >= (ncl + PCF_FIRSTCLUSTER)
			    * 3 / 2)
				validflags |= BPB_FATSZ_OK;
			if (ncl < 4085)
				validflags |= BPB_NCLUSTERS_OK;

			fsp->pcfs_lastclmark = (PCF_LASTCLUSTER & 0xfff);
			fsp->pcfs_rootblksize =
			    fsp->pcfs_rdirsec * secsize;
			fsp->pcfs_fsistart = 0;

			if ((validflags & FAT12_VALIDMSK) != FAT12_VALIDMSK)
				type = FAT_UNKNOWN;
			break;
		case FAT16:
			if (rec != 0)
				validflags |= BPB_ROOTENTCNT_OK;
			if ((blkcnt_t)bpb_get_TotSec16(bpb) == totsec ||
			    bpb_get_TotSec16(bpb) == 0)
				validflags |= BPB_TOTSEC16_OK;
			if ((blkcnt_t)bpb_get_TotSec32(bpb) == totsec ||
			    bpb_get_TotSec32(bpb) == 0)
				validflags |= BPB_TOTSEC32_OK;
			if (bpb_get_FatSz16(bpb) == fatsec)
				validflags |= BPB_FATSZ16_OK;
			if (fatsec * secsize >= (ncl + PCF_FIRSTCLUSTER) * 2)
				validflags |= BPB_FATSZ_OK;
			if (ncl >= 4085 && ncl < 65525)
				validflags |= BPB_NCLUSTERS_OK;

			fsp->pcfs_lastclmark = PCF_LASTCLUSTER;
			fsp->pcfs_rootblksize =
			    fsp->pcfs_rdirsec * secsize;
			fsp->pcfs_fsistart = 0;

			if ((validflags & FAT16_VALIDMSK) != FAT16_VALIDMSK)
				type = FAT_UNKNOWN;
			break;
		case FAT32:
			if (rec == 0)
				validflags |= BPB_ROOTENTCNT_OK;
			if (bpb_get_TotSec16(bpb) == 0)
				validflags |= BPB_TOTSEC16_OK;
			if ((blkcnt_t)bpb_get_TotSec32(bpb) == totsec)
				validflags |= BPB_TOTSEC32_OK;
			if (bpb_get_FatSz16(bpb) == 0)
				validflags |= BPB_FATSZ16_OK;
			if (bpb_get_FatSz32(bpb) == fatsec)
				validflags |= BPB_FATSZ32_OK;
			if (fatsec * secsize >= (ncl + PCF_FIRSTCLUSTER) * 4)
				validflags |= BPB_FATSZ_OK;
			if (ncl >= 65525 && ncl < PCF_LASTCLUSTER32)
				validflags |= BPB_NCLUSTERS_OK;

			fsp->pcfs_lastclmark = PCF_LASTCLUSTER32;
			fsp->pcfs_rootblksize = fsp->pcfs_clsize;
			fsp->pcfs_fsistart = fsp->pcfs_dosstart + fsisec;
			if (validflags & BPB_FSISEC_OK)
				fsp->pcfs_flags |= PCFS_FSINFO_OK;
			fsp->pcfs_rootclnum = bpb_get_RootClus32(bpb);
			if (pc_validcl(fsp, fsp->pcfs_rootclnum))
				validflags |= BPB_ROOTCLUSTER_OK;

			/*
			 * Current PCFS code only works if 'pcfs_rdirstart'
			 * contains the root cluster number on FAT32.
			 * That's a mis-use and would better be changed.
			 */
			fsp->pcfs_rdirstart = (daddr_t)fsp->pcfs_rootclnum;

			if ((validflags & FAT32_VALIDMSK) != FAT32_VALIDMSK)
				type = FAT_UNKNOWN;
			break;
		case FAT_QUESTIONABLE:
			type = secondaryBPBChecks(fsp, bpb, secsize);
			goto recheck;
		default:
			ASSERT(type == FAT_UNKNOWN);
			break;
	}

	ASSERT(type != FAT_QUESTIONABLE);

	fsp->pcfs_fattype = type;

	if (valid)
		*valid = validflags;

	DTRACE_PROBE4(parseBPB__final,
	    struct pcfs *, fsp, unsigned char *, bpb,
	    int, validflags, fattype_t, type);

	if (type != FAT_UNKNOWN) {
		ASSERT((secsize & (DEV_BSIZE - 1)) == 0);
		ASSERT(ISP2(secsize / DEV_BSIZE));
		return (1);
	}

	return (0);
}


/*
 * Detect the device's native block size (sector size).
 *
 * Test whether the device is:
 *	- a floppy device from a known controller type via DKIOCINFO
 *	- a real floppy using the fd(7d) driver and capable of fdio(7I) ioctls
 *	- a USB floppy drive (identified by drive geometry)
 *
 * Detecting a floppy will make PCFS metadata updates on such media synchronous,
 * to minimize risks due to slow I/O and user hotplugging / device ejection.
 *
 * This might be a bit wasteful on kernel stack space; if anyone's
 * bothered by this, kmem_alloc/kmem_free the ioctl arguments...
 */
static void
pcfs_device_getinfo(struct pcfs *fsp)
{
	dev_t			rdev = fsp->pcfs_xdev;
	int			error;
	union {
		struct dk_minfo		mi;
		struct dk_cinfo		ci;
		struct dk_geom		gi;
		struct fd_char		fc;
	} arg;				/* save stackspace ... */
	intptr_t argp = (intptr_t)&arg;
	ldi_handle_t		lh;
	ldi_ident_t		li;
	int isfloppy, isremoveable, ishotpluggable;
	cred_t			*cr = CRED();

	if (ldi_ident_from_dev(rdev, &li))
		goto out;

	error = ldi_open_by_dev(&rdev, OTYP_CHR, FREAD, cr, &lh, li);
	ldi_ident_release(li);
	if (error)
		goto out;

	/*
	 * Not sure if this could possibly happen. It'd be a bit like
	 * VOP_OPEN() changing the passed-in vnode ptr. We're just not
	 * expecting it, needs some thought if triggered ...
	 */
	ASSERT(fsp->pcfs_xdev == rdev);

	/*
	 * Check for removeable/hotpluggable media.
	 */
	if (ldi_ioctl(lh, DKIOCREMOVABLE,
	    (intptr_t)&isremoveable, FKIOCTL, cr, NULL)) {
		isremoveable = 0;
	}
	if (ldi_ioctl(lh, DKIOCHOTPLUGGABLE,
	    (intptr_t)&ishotpluggable, FKIOCTL, cr, NULL)) {
		ishotpluggable = 0;
	}

	/*
	 * Make sure we don't use "half-initialized" values if the ioctls fail.
	 */
	if (ldi_ioctl(lh, DKIOCGMEDIAINFO, argp, FKIOCTL, cr, NULL)) {
		bzero(&arg, sizeof (arg));
		fsp->pcfs_mediasize = 0;
	} else {
		fsp->pcfs_mediasize =
		    (len_t)arg.mi.dki_lbsize *
		    (len_t)arg.mi.dki_capacity;
	}

	if (VALID_SECSIZE(arg.mi.dki_lbsize)) {
		if (fsp->pcfs_secsize == 0) {
			fsp->pcfs_secsize = arg.mi.dki_lbsize;
			fsp->pcfs_sdshift =
			    ddi_ffs(arg.mi.dki_lbsize / DEV_BSIZE) - 1;
		} else {
			PC_DPRINTF4(1, "!pcfs: autodetected media block size "
			    "%d, device (%x.%x), different from user-provided "
			    "%d. User override - ignoring autodetect result.\n",
			    arg.mi.dki_lbsize,
			    getmajor(fsp->pcfs_xdev), getminor(fsp->pcfs_xdev),
			    fsp->pcfs_secsize);
		}
	} else if (arg.mi.dki_lbsize) {
		PC_DPRINTF3(1, "!pcfs: autodetected media block size "
		    "%d, device (%x.%x), invalid (not 512, 1024, 2048, 4096). "
		    "Ignoring autodetect result.\n",
		    arg.mi.dki_lbsize,
		    getmajor(fsp->pcfs_xdev), getminor(fsp->pcfs_xdev));
	}

	/*
	 * We treat the following media types as a floppy by default.
	 */
	isfloppy =
	    (arg.mi.dki_media_type == DK_FLOPPY ||
	    arg.mi.dki_media_type == DK_ZIP ||
	    arg.mi.dki_media_type == DK_JAZ);

	/*
	 * if this device understands fdio(7I) requests it's
	 * obviously a floppy drive.
	 */
	if (!isfloppy &&
	    !ldi_ioctl(lh, FDIOGCHAR, argp, FKIOCTL, cr, NULL))
		isfloppy = 1;

	/*
	 * some devices we like to treat as floppies, but they don't
	 * understand fdio(7I) requests.
	 */
	if (!isfloppy &&
	    !ldi_ioctl(lh, DKIOCINFO, argp, FKIOCTL, cr, NULL) &&
	    (arg.ci.dki_ctype == DKC_WDC2880 ||
	    arg.ci.dki_ctype == DKC_NCRFLOPPY ||
	    arg.ci.dki_ctype == DKC_SMSFLOPPY ||
	    arg.ci.dki_ctype == DKC_INTEL82077))
		isfloppy = 1;

	/*
	 * This is the "final fallback" test - media with
	 * 2 heads and 80 cylinders are assumed to be floppies.
	 * This is normally true for USB floppy drives ...
	 */
	if (!isfloppy &&
	    !ldi_ioctl(lh, DKIOCGGEOM, argp, FKIOCTL, cr, NULL) &&
	    (arg.gi.dkg_ncyl == 80 && arg.gi.dkg_nhead == 2))
		isfloppy = 1;

	/*
	 * This is similar to the "old" PCFS code that sets this flag
	 * just based on the media descriptor being 0xf8 (MD_FIXED).
	 * Should be re-worked. We really need some specialcasing for
	 * removeable media.
	 */
	if (!isfloppy) {
		fsp->pcfs_flags |= PCFS_NOCHK;
	}

	/*
	 * We automatically disable access time updates if the medium is
	 * removeable and/or hotpluggable, and the admin did not explicitly
	 * request access time updates (via the "atime" mount option).
	 * The majority of flash-based media should fit this category.
	 * Minimizing write access extends the lifetime of your memory stick !
	 */
	if (!vfs_optionisset(fsp->pcfs_vfs, MNTOPT_ATIME, NULL) &&
	    (isremoveable || ishotpluggable | isfloppy)) {
		fsp->pcfs_flags |= PCFS_NOATIME;
	}

	(void) ldi_close(lh, FREAD, cr);
out:
	if (fsp->pcfs_secsize == 0) {
		PC_DPRINTF3(1, "!pcfs: media block size autodetection "
		    "device (%x.%x) failed, no user-provided fallback. "
		    "Using %d bytes.\n",
		    getmajor(fsp->pcfs_xdev), getminor(fsp->pcfs_xdev),
		    DEV_BSIZE);
		fsp->pcfs_secsize = DEV_BSIZE;
		fsp->pcfs_sdshift = 0;
	}
	ASSERT(fsp->pcfs_secsize % DEV_BSIZE == 0);
	ASSERT(VALID_SECSIZE(fsp->pcfs_secsize));
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
pc_getfattype(struct pcfs *fsp)
{
	int error = 0;
	buf_t *bp = NULL;
	struct vnode *devvp = fsp->pcfs_devvp;
	dev_t	dev = devvp->v_rdev;

	/*
	 * Detect the native block size of the medium, and attempt to
	 * detect whether the medium is removeable.
	 * We do treat removable media (floppies, USB and FireWire disks)
	 * differently wrt. to the frequency and synchronicity of FAT updates.
	 * We need to know the media block size in order to be able to
	 * parse the partition table.
	 */
	pcfs_device_getinfo(fsp);

	/*
	 * Unpartitioned media (floppies and some removeable devices)
	 * don't have a partition table, the FAT BPB is at disk block 0.
	 * Start out by reading block 0.
	 */
	fsp->pcfs_dosstart = 0;
	bp = bread(dev, pc_dbdaddr(fsp, fsp->pcfs_dosstart), fsp->pcfs_secsize);

	if (error = geterror(bp))
		goto out;

	/*
	 * If a logical drive number is requested, parse the partition table
	 * and attempt to locate it. Otherwise, proceed immediately to the
	 * BPB check. findTheDrive(), if successful, returns the disk block
	 * number where the requested partition starts in "startsec".
	 */
	if (fsp->pcfs_ldrive != 0) {
		PC_DPRINTF3(5, "!pcfs: pc_getfattype: using FDISK table on "
		    "device (%x,%x):%d to find BPB\n",
		    getmajor(dev), getminor(dev), fsp->pcfs_ldrive);

		if (error = findTheDrive(fsp, &bp))
			goto out;

		ASSERT(fsp->pcfs_dosstart != 0);

		brelse(bp);
		bp = bread(dev, pc_dbdaddr(fsp, fsp->pcfs_dosstart),
		    fsp->pcfs_secsize);
		if (error = geterror(bp))
			goto out;
	}

	/*
	 * Validate the BPB and fill in the instance structure.
	 */
	if (!parseBPB(fsp, (uchar_t *)bp->b_un.b_addr, NULL)) {
		PC_DPRINTF4(1, "!pcfs: pc_getfattype: No FAT BPB on "
		    "device (%x.%x):%d, disk LBA %u\n",
		    getmajor(dev), getminor(dev), fsp->pcfs_ldrive,
		    (uint_t)pc_dbdaddr(fsp, fsp->pcfs_dosstart));
		error = EINVAL;
		goto out;
	}

	ASSERT(fsp->pcfs_fattype != FAT_UNKNOWN);

out:
	/*
	 * Release the buffer used
	 */
	if (bp != NULL)
		brelse(bp);
	return (error);
}


/*
 * Get the file allocation table.
 * If there is an old FAT, invalidate it.
 */
int
pc_getfat(struct pcfs *fsp)
{
	struct buf *bp = NULL;
	uchar_t *fatp = NULL;
	uchar_t *fat_changemap = NULL;
	int error;
	int fat_changemapsize;
	int flags = 0;
	int nfat;
	int altfat_mustmatch = 0;
	int fatsize = fsp->pcfs_fatsec * fsp->pcfs_secsize;

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
	 * Get FAT and check it for validity
	 */
	fatp = kmem_alloc(fatsize, KM_SLEEP);
	error = pc_readfat(fsp, fatp);
	if (error) {
		flags = B_ERROR;
		goto out;
	}
	fat_changemapsize = (fatsize / fsp->pcfs_clsize) + 1;
	fat_changemap = kmem_zalloc(fat_changemapsize, KM_SLEEP);
	fsp->pcfs_fatp = fatp;
	fsp->pcfs_fat_changemapsize = fat_changemapsize;
	fsp->pcfs_fat_changemap = fat_changemap;

	/*
	 * The only definite signature check is that the
	 * media descriptor byte should match the first byte
	 * of the FAT block.
	 */
	if (fatp[0] != fsp->pcfs_mediadesc) {
		cmn_err(CE_NOTE, "!pcfs: FAT signature mismatch, "
		    "media descriptor %x, FAT[0] lowbyte %x\n",
		    (uint32_t)fsp->pcfs_mediadesc, (uint32_t)fatp[0]);
		cmn_err(CE_NOTE, "!pcfs: Enforcing alternate FAT validation\n");
		altfat_mustmatch = 1;
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

		startsec = pc_dbdaddr(fsp,
		    fsp->pcfs_fatstart + nfat * fsp->pcfs_fatsec);

		for (off = 0; off < fatsize; off += fsp->pcfs_clsize) {
			daddr_t fatblk = startsec + pc_dbdaddr(fsp,
			    pc_cltodb(fsp, pc_lblkno(fsp, off)));

			bp = bread(fsp->pcfs_xdev, fatblk,
			    MIN(fsp->pcfs_clsize, fatsize - off));
			if (bp->b_flags & (B_ERROR | B_STALE)) {
				cmn_err(CE_NOTE,
				    "!pcfs: alternate FAT #%d (start LBA %p)"
				    " read error at offset %ld on device"
				    " (%x.%x):%d",
				    nfat, (void *)(uintptr_t)startsec, off,
				    getmajor(fsp->pcfs_xdev),
				    getminor(fsp->pcfs_xdev),
				    fsp->pcfs_ldrive);
				flags = B_ERROR;
				error = EIO;
				goto out;
			}
			bp->b_flags |= B_STALE | B_AGE;
			if (bcmp(bp->b_un.b_addr, fatp + off,
			    MIN(fsp->pcfs_clsize, fatsize - off))) {
				cmn_err(CE_NOTE,
				    "!pcfs: alternate FAT #%d (start LBA %p)"
				    " corrupted at offset %ld on device"
				    " (%x.%x):%d",
				    nfat, (void *)(uintptr_t)startsec, off,
				    getmajor(fsp->pcfs_xdev),
				    getminor(fsp->pcfs_xdev),
				    fsp->pcfs_ldrive);
				if (altfat_mustmatch) {
					flags = B_ERROR;
					error = EIO;
					goto out;
				}
			}
			brelse(bp);
			bp = NULL;	/* prevent double release */
		}
	}

	fsp->pcfs_fattime = gethrestime_sec() + PCFS_DISKTIMEOUT;
	fsp->pcfs_fatjustread = 1;

	/*
	 * Retrieve FAT32 fsinfo sector.
	 * A failure to read this is not fatal to accessing the volume.
	 * It simply means operations that count or search free blocks
	 * will have to do a full FAT walk, vs. a possibly quicker lookup
	 * of the summary information.
	 * Hence, we log a message but return success overall after this point.
	 */
	if (IS_FAT32(fsp) && (fsp->pcfs_flags & PCFS_FSINFO_OK)) {
		struct fat_od_fsi *fsinfo_disk;

		bp = bread(fsp->pcfs_xdev,
		    pc_dbdaddr(fsp, fsp->pcfs_fsistart), fsp->pcfs_secsize);
		fsinfo_disk = (struct fat_od_fsi *)bp->b_un.b_addr;
		if (bp->b_flags & (B_ERROR | B_STALE) ||
		    !FSISIG_OK(fsinfo_disk)) {
			cmn_err(CE_NOTE,
			    "!pcfs: error reading fat32 fsinfo from "
			    "device (%x.%x):%d, block %lld",
			    getmajor(fsp->pcfs_xdev), getminor(fsp->pcfs_xdev),
			    fsp->pcfs_ldrive,
			    (long long)pc_dbdaddr(fsp, fsp->pcfs_fsistart));
			fsp->pcfs_flags &= ~PCFS_FSINFO_OK;
			fsp->pcfs_fsinfo.fs_free_clusters = FSINFO_UNKNOWN;
			fsp->pcfs_fsinfo.fs_next_free = FSINFO_UNKNOWN;
		} else {
			bp->b_flags |= B_STALE | B_AGE;
			fsinfo_disk = (fat_od_fsi_t *)(bp->b_un.b_addr);
			fsp->pcfs_fsinfo.fs_free_clusters =
			    LE_32(fsinfo_disk->fsi_incore.fs_free_clusters);
			fsp->pcfs_fsinfo.fs_next_free =
			    LE_32(fsinfo_disk->fsi_incore.fs_next_free);
		}
		brelse(bp);
		bp = NULL;
	}

	if (pc_validcl(fsp, (pc_cluster32_t)fsp->pcfs_fsinfo.fs_next_free))
		fsp->pcfs_nxfrecls = fsp->pcfs_fsinfo.fs_next_free;
	else
		fsp->pcfs_nxfrecls = PCF_FIRSTCLUSTER;

	return (0);

out:
	cmn_err(CE_NOTE, "!pcfs: illegal disk format");
	if (bp)
		brelse(bp);
	if (fatp)
		kmem_free(fatp, fatsize);
	if (fat_changemap)
		kmem_free(fat_changemap, fat_changemapsize);

	if (flags) {
		pc_mark_irrecov(fsp);
	}
	return (error);
}
