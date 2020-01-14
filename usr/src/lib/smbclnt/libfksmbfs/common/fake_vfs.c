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
 * Copyright (c) 1988, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2016 Joyent, Inc.
 * Copyright 2016 Toomas Soome <tsoome@me.com>
 * Copyright (c) 2016 by Delphix. All rights reserved.
 * Copyright 2017 RackTop Systems.
 * Copyright 2018 Nexenta Systems, Inc.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

/*
 * This file contains those functions from fs/vfs.c that can be
 * used with relatively little change.  Functions that differ
 * significantly from that are in other files.
 */

#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/user.h>
#include <sys/fstyp.h>
#include <sys/kmem.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/mount.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/fem.h>
#include <sys/mntent.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/statfs.h>
#include <sys/cred.h>
#include <sys/vnode.h>
#include <sys/rwstlock.h>
#include <sys/dnlc.h>
#include <sys/file.h>
#include <sys/time.h>
#include <sys/atomic.h>
#include <sys/cmn_err.h>
#include <sys/buf.h>
#include <sys/debug.h>
#include <sys/vnode.h>
#include <sys/ddi.h>
#include <sys/pathname.h>
#include <sys/poll.h>
#include <sys/sunddi.h>
#include <sys/sysmacros.h>
#include <sys/zone.h>
#include <sys/policy.h>
#include <sys/attr.h>
#include <fs/fs_subr.h>

#include <libfksmbfs.h>

static void vfs_clearmntopt_nolock(mntopts_t *, const char *, int);
static void vfs_setmntopt_nolock(mntopts_t *, const char *,
    const char *, int, int);
static int  vfs_optionisset_nolock(const mntopts_t *, const char *, char **);
// static void vfs_freemnttab(struct vfs *);
static void vfs_freeopt(mntopt_t *);
static void vfs_swapopttbl_nolock(mntopts_t *, mntopts_t *);
static void vfs_swapopttbl(mntopts_t *, mntopts_t *);
static void vfs_copyopttbl_extend(const mntopts_t *, mntopts_t *, int);
// static void vfs_createopttbl_extend(mntopts_t *, const char *,
//    const mntopts_t *);
// static char **vfs_copycancelopt_extend(char **const, int);
static void vfs_freecancelopt(char **);

/*
 * VFS global data.
 */
vnode_t *rootdir;		/* pointer to root inode vnode. */
struct vfs *rootvfs = NULL;	/* pointer to root vfs; head of VFS list. */
static krwlock_t vfslist;
struct vfs	*zone_vfslist;	/* list of FS's mounted in zone */

/* from os/vfs_conf.c */
const int nfstype = 5;
struct vfssw vfssw[10] = {
	{ "BADVFS" },				/* 0:invalid */
	{ "" },					/* reserved for loadable fs */
	{ "" },
	{ "" },
	{ "" },
};

/*
 * Table for generic options recognized in the VFS layer and acted
 * on at this level before parsing file system specific options.
 * The nosuid option is stronger than any of the devices and setuid
 * options, so those are canceled when nosuid is seen.
 *
 * All options which are added here need to be added to the
 * list of standard options in usr/src/cmd/fs.d/fslib.c as well.
 */
/*
 * VFS Mount options table
 */
static char *ro_cancel[] = { MNTOPT_RW, NULL };
static char *rw_cancel[] = { MNTOPT_RO, NULL };
static char *suid_cancel[] = { MNTOPT_NOSUID, NULL };
static char *nosuid_cancel[] = { MNTOPT_SUID, MNTOPT_DEVICES, MNTOPT_NODEVICES,
    MNTOPT_NOSETUID, MNTOPT_SETUID, NULL };
static char *devices_cancel[] = { MNTOPT_NODEVICES, NULL };
static char *nodevices_cancel[] = { MNTOPT_DEVICES, NULL };
static char *setuid_cancel[] = { MNTOPT_NOSETUID, NULL };
static char *nosetuid_cancel[] = { MNTOPT_SETUID, NULL };
static char *nbmand_cancel[] = { MNTOPT_NONBMAND, NULL };
static char *nonbmand_cancel[] = { MNTOPT_NBMAND, NULL };
static char *exec_cancel[] = { MNTOPT_NOEXEC, NULL };
static char *noexec_cancel[] = { MNTOPT_EXEC, NULL };

static const mntopt_t mntopts[] = {
/*
 *	option name		cancel options		default arg	flags
 */
	{ MNTOPT_REMOUNT,	NULL,			NULL,
		MO_NODISPLAY, (void *)0 },
	{ MNTOPT_RO,		ro_cancel,		NULL,		0,
		(void *)0 },
	{ MNTOPT_RW,		rw_cancel,		NULL,		0,
		(void *)0 },
	{ MNTOPT_SUID,		suid_cancel,		NULL,		0,
		(void *)0 },
	{ MNTOPT_NOSUID,	nosuid_cancel,		NULL,		0,
		(void *)0 },
	{ MNTOPT_DEVICES,	devices_cancel,		NULL,		0,
		(void *)0 },
	{ MNTOPT_NODEVICES,	nodevices_cancel,	NULL,		0,
		(void *)0 },
	{ MNTOPT_SETUID,	setuid_cancel,		NULL,		0,
		(void *)0 },
	{ MNTOPT_NOSETUID,	nosetuid_cancel,	NULL,		0,
		(void *)0 },
	{ MNTOPT_NBMAND,	nbmand_cancel,		NULL,		0,
		(void *)0 },
	{ MNTOPT_NONBMAND,	nonbmand_cancel,	NULL,		0,
		(void *)0 },
	{ MNTOPT_EXEC,		exec_cancel,		NULL,		0,
		(void *)0 },
	{ MNTOPT_NOEXEC,	noexec_cancel,		NULL,		0,
		(void *)0 },
};

const mntopts_t vfs_mntopts = {
	sizeof (mntopts) / sizeof (mntopt_t),
	(mntopt_t *)&mntopts[0]
};

/*
 * File system operation dispatch functions.
 */

int
fsop_mount(vfs_t *vfsp, vnode_t *mvp, struct mounta *uap, cred_t *cr)
{
	return (*(vfsp)->vfs_op->vfs_mount)(vfsp, mvp, uap, cr);
}

int
fsop_unmount(vfs_t *vfsp, int flag, cred_t *cr)
{
	return (*(vfsp)->vfs_op->vfs_unmount)(vfsp, flag, cr);
}

int
fsop_root(vfs_t *vfsp, vnode_t **vpp)
{
	return ((*(vfsp)->vfs_op->vfs_root)(vfsp, vpp));
}

int
fsop_statfs(vfs_t *vfsp, statvfs64_t *sp)
{
	return (*(vfsp)->vfs_op->vfs_statvfs)(vfsp, sp);
}

int
fsop_sync(vfs_t *vfsp, short flag, cred_t *cr)
{
	return (*(vfsp)->vfs_op->vfs_sync)(vfsp, flag, cr);
}

int
fsop_vget(vfs_t *vfsp, vnode_t **vpp, fid_t *fidp)
{
	return (*(vfsp)->vfs_op->vfs_vget)(vfsp, vpp, fidp);
}

int
fsop_mountroot(vfs_t *vfsp, enum whymountroot reason)
{
	return (*(vfsp)->vfs_op->vfs_mountroot)(vfsp, reason);
}

void
fsop_freefs(vfs_t *vfsp)
{
	(*(vfsp)->vfs_op->vfs_freevfs)(vfsp);
}

int
fsop_vnstate(vfs_t *vfsp, vnode_t *vp, vntrans_t nstate)
{
	return ((*(vfsp)->vfs_op->vfs_vnstate)(vfsp, vp, nstate));
}

int
fsop_sync_by_kind(int fstype, short flag, cred_t *cr)
{
	ASSERT((fstype >= 0) && (fstype < nfstype));

	if (ALLOCATED_VFSSW(&vfssw[fstype]) && VFS_INSTALLED(&vfssw[fstype]))
		return (*vfssw[fstype].vsw_vfsops.vfs_sync) (NULL, flag, cr);
	else
		return (ENOTSUP);
}

/*
 * File system initialization.  vfs_setfsops() must be called from a file
 * system's init routine.
 */

static int
fs_copyfsops(const fs_operation_def_t *template, vfsops_t *actual,
    int *unused_ops)
{
	static const fs_operation_trans_def_t vfs_ops_table[] = {
		VFSNAME_MOUNT, offsetof(vfsops_t, vfs_mount),
			fs_nosys, fs_nosys,

		VFSNAME_UNMOUNT, offsetof(vfsops_t, vfs_unmount),
			fs_nosys, fs_nosys,

		VFSNAME_ROOT, offsetof(vfsops_t, vfs_root),
			fs_nosys, fs_nosys,

		VFSNAME_STATVFS, offsetof(vfsops_t, vfs_statvfs),
			fs_nosys, fs_nosys,

		VFSNAME_SYNC, offsetof(vfsops_t, vfs_sync),
			(fs_generic_func_p) fs_sync,
			(fs_generic_func_p) fs_sync,	/* No errors allowed */

		VFSNAME_VGET, offsetof(vfsops_t, vfs_vget),
			fs_nosys, fs_nosys,

		VFSNAME_MOUNTROOT, offsetof(vfsops_t, vfs_mountroot),
			fs_nosys, fs_nosys,

		VFSNAME_FREEVFS, offsetof(vfsops_t, vfs_freevfs),
			(fs_generic_func_p)(uintptr_t)fs_freevfs,
			(fs_generic_func_p)(uintptr_t)
			fs_freevfs,	/* Shouldn't fail */

		VFSNAME_VNSTATE, offsetof(vfsops_t, vfs_vnstate),
			(fs_generic_func_p)fs_nosys,
			(fs_generic_func_p)fs_nosys,

		NULL, 0, NULL, NULL
	};

	return (fs_build_vector(actual, unused_ops, vfs_ops_table, template));
}

/* zfs_boot_init() */

int
vfs_setfsops(int fstype, const fs_operation_def_t *template, vfsops_t **actual)
{
	int error;
	int unused_ops;

	/*
	 * Verify that fstype refers to a valid fs.  Note that
	 * 0 is valid since it's used to set "stray" ops.
	 */
	if ((fstype < 0) || (fstype >= nfstype))
		return (EINVAL);

	if (!ALLOCATED_VFSSW(&vfssw[fstype]))
		return (EINVAL);

	/* Set up the operations vector. */

	error = fs_copyfsops(template, &vfssw[fstype].vsw_vfsops, &unused_ops);

	if (error != 0)
		return (error);

	vfssw[fstype].vsw_flag |= VSW_INSTALLED;

	if (actual != NULL)
		*actual = &vfssw[fstype].vsw_vfsops;

#if DEBUG
	if (unused_ops != 0)
		cmn_err(CE_WARN, "vfs_setfsops: %s: %d operations supplied "
		    "but not used", vfssw[fstype].vsw_name, unused_ops);
#endif

	return (0);
}

int
vfs_makefsops(const fs_operation_def_t *template, vfsops_t **actual)
{
	int error;
	int unused_ops;

	*actual = (vfsops_t *)kmem_alloc(sizeof (vfsops_t), KM_SLEEP);

	error = fs_copyfsops(template, *actual, &unused_ops);
	if (error != 0) {
		kmem_free(*actual, sizeof (vfsops_t));
		*actual = NULL;
		return (error);
	}

	return (0);
}

/*
 * Free a vfsops structure created as a result of vfs_makefsops().
 * NOTE: For a vfsops structure initialized by vfs_setfsops(), use
 * vfs_freevfsops_by_type().
 */
void
vfs_freevfsops(vfsops_t *vfsops)
{
	kmem_free(vfsops, sizeof (vfsops_t));
}

/*
 * Since the vfsops structure is part of the vfssw table and wasn't
 * really allocated, we're not really freeing anything.  We keep
 * the name for consistency with vfs_freevfsops().  We do, however,
 * need to take care of a little bookkeeping.
 * NOTE: For a vfsops structure created by vfs_setfsops(), use
 * vfs_freevfsops_by_type().
 */
int
vfs_freevfsops_by_type(int fstype)
{

	/* Verify that fstype refers to a loaded fs (and not fsid 0). */
	if ((fstype <= 0) || (fstype >= nfstype))
		return (EINVAL);

	WLOCK_VFSSW();
	if ((vfssw[fstype].vsw_flag & VSW_INSTALLED) == 0) {
		WUNLOCK_VFSSW();
		return (EINVAL);
	}

	vfssw[fstype].vsw_flag &= ~VSW_INSTALLED;
	WUNLOCK_VFSSW();

	return (0);
}

/* Support routines used to reference vfs_op */

/* Set the operations vector for a vfs */
void
vfs_setops(vfs_t *vfsp, vfsops_t *vfsops)
{

	ASSERT(vfsp != NULL);
	ASSERT(vfsops != NULL);

	vfsp->vfs_op = vfsops;
}

/* Retrieve the operations vector for a vfs */
vfsops_t *
vfs_getops(vfs_t *vfsp)
{

	ASSERT(vfsp != NULL);

	return (vfsp->vfs_op);
}

/*
 * Returns non-zero (1) if the vfsops matches that of the vfs.
 * Returns zero (0) if not.
 */
int
vfs_matchops(vfs_t *vfsp, vfsops_t *vfsops)
{
	return (vfs_getops(vfsp) == vfsops);
}

/*
 * Returns non-zero (1) if the file system has installed a non-default,
 * non-error vfs_sync routine.  Returns zero (0) otherwise.
 */
int
vfs_can_sync(vfs_t *vfsp)
{
	/* vfs_sync() routine is not the default/error function */
	return (vfs_getops(vfsp)->vfs_sync != fs_sync);
}

/*
 * Initialize a vfs structure.
 */
void
vfs_init(vfs_t *vfsp, vfsops_t *op, void *data)
{
	/* Always do full init, like vfs_alloc() */
	bzero(vfsp, sizeof (vfs_t));
	vfsp->vfs_count = 0;
	vfsp->vfs_next = vfsp;
	vfsp->vfs_prev = vfsp;
	vfsp->vfs_zone_next = vfsp;
	vfsp->vfs_zone_prev = vfsp;
	vfsp->vfs_lofi_id = 0;
	sema_init(&vfsp->vfs_reflock, 1, NULL, SEMA_DEFAULT, NULL);
	vfsimpl_setup(vfsp);
	vfsp->vfs_data = (data);
	vfs_setops((vfsp), (op));
}

/*
 * Allocate and initialize the vfs implementation private data
 * structure, vfs_impl_t.
 */
void
vfsimpl_setup(vfs_t *vfsp)
{
	int i;

	if (vfsp->vfs_implp != NULL) {
		return;
	}

	vfsp->vfs_implp = kmem_alloc(sizeof (vfs_impl_t), KM_SLEEP);
	/* Note that these are #define'd in vfs.h */
	vfsp->vfs_vskap = NULL;
	vfsp->vfs_fstypevsp = NULL;

	/* Set size of counted array, then zero the array */
	vfsp->vfs_featureset[0] = VFS_FEATURE_MAXSZ - 1;
	for (i = 1; i <  VFS_FEATURE_MAXSZ; i++) {
		vfsp->vfs_featureset[i] = 0;
	}
}

/*
 * Release the vfs_impl_t structure, if it exists. Some unbundled
 * filesystems may not use the newer version of vfs and thus
 * would not contain this implementation private data structure.
 */
void
vfsimpl_teardown(vfs_t *vfsp)
{
	vfs_impl_t	*vip = vfsp->vfs_implp;

	if (vip == NULL)
		return;

	kmem_free(vfsp->vfs_implp, sizeof (vfs_impl_t));
	vfsp->vfs_implp = NULL;
}

/*
 * VFS system calls: mount, umount, syssync, statfs, fstatfs, statvfs,
 * fstatvfs, and sysfs moved to common/syscall.
 */

// vfs_sync, sync

/*
 * External routines.
 */

krwlock_t vfssw_lock;	/* lock accesses to vfssw */

/*
 * Lock for accessing the vfs linked list.  Initialized in vfs_mountroot(),
 * but otherwise should be accessed only via vfs_list_lock() and
 * vfs_list_unlock().  Also used to protect the timestamp for mods to the list.
 */
static krwlock_t vfslist;

// vfs_mountdevices(void)
// vfs_mountdev1(void)
// vfs_mountfs()
// vfs_mountroot()
// lofi_add, lofi_remove


/*
 * Mount the FS for the test jig.  Based on domount()
 */
int
fake_domount(char *fsname, struct mounta *uap, struct vfs **vfspp)
{
	vnode_t		*vp;
	struct cred	*credp;
	struct vfssw	*vswp;
	vfsops_t	*vfsops;
	struct vfs	*vfsp = NULL;
	mntopts_t	mnt_mntopts;
	int		error = 0;
	int		copyout_error = 0;
	char		*opts = uap->optptr;
	char		*inargs = opts;
	int		optlen = uap->optlen;

	credp = CRED();

	/*
	 * Test jig specific: mount on rootdir
	 */
	if (rootvfs != NULL)
		return (EBUSY);
	vp = rootdir;

	/*
	 * The v_flag value for the mount point vp is permanently set
	 * to VVFSLOCK so that no one bypasses the vn_vfs*locks routine
	 * for mount point locking.
	 */
	mutex_enter(&vp->v_lock);
	vp->v_flag |= VVFSLOCK;
	mutex_exit(&vp->v_lock);

	mnt_mntopts.mo_count = 0;

	/*
	 * Find the ops vector to use to invoke the file system-specific mount
	 * method.  If the fsname argument is non-NULL, use it directly.
	 */
	if ((vswp = vfs_getvfssw(fsname)) == NULL) {
		return (EINVAL);
	}
	if (!VFS_INSTALLED(vswp))
		return (EINVAL);

	// secpolicy_fs_allowed_mount(fsname)

	vfsops = &vswp->vsw_vfsops;

	vfs_copyopttbl(&vswp->vsw_optproto, &mnt_mntopts);

	/*
	 * Fetch mount options and parse them for generic vfs options
	 */
	if (uap->flags & MS_OPTIONSTR) {
		/*
		 * Limit the buffer size
		 */
		if (optlen < 0 || optlen > MAX_MNTOPT_STR) {
			error = EINVAL;
			goto errout;
		}
		if ((uap->flags & MS_SYSSPACE) == 0) {
			inargs = kmem_alloc(MAX_MNTOPT_STR, KM_SLEEP);
			inargs[0] = '\0';
			if (optlen) {
				error = copyinstr(opts, inargs, (size_t)optlen,
				    NULL);
				if (error) {
					goto errout;
				}
			}
		}
		vfs_parsemntopts(&mnt_mntopts, inargs, 0);
	}
	/*
	 * Flag bits override the options string.
	 */
	if (uap->flags & MS_REMOUNT)
		vfs_setmntopt_nolock(&mnt_mntopts, MNTOPT_REMOUNT, NULL, 0, 0);
	if (uap->flags & MS_RDONLY)
		vfs_setmntopt_nolock(&mnt_mntopts, MNTOPT_RO, NULL, 0, 0);
	if (uap->flags & MS_NOSUID)
		vfs_setmntopt_nolock(&mnt_mntopts, MNTOPT_NOSUID, NULL, 0, 0);

	/*
	 * Check if this is a remount; must be set in the option string and
	 * the file system must support a remount option.
	 */
	if (vfs_optionisset_nolock(&mnt_mntopts,
	    MNTOPT_REMOUNT, NULL)) {
		/* disallow here */
		error = ENOTSUP;
		goto errout;
	}

	/*
	 * uap->flags and vfs_optionisset() should agree.
	 */
	if (vfs_optionisset_nolock(&mnt_mntopts, MNTOPT_RO, NULL)) {
		uap->flags |= MS_RDONLY;
	}
	if (vfs_optionisset_nolock(&mnt_mntopts, MNTOPT_NOSUID, NULL)) {
		uap->flags |= MS_NOSUID;
	}
	// nbmand ...

	/*
	 * If we are splicing the fs into the namespace,
	 * perform mount point checks...
	 * (always splice=0 here)
	 */

	if ((uap->flags & (MS_DATA | MS_OPTIONSTR)) == 0) {
		uap->dataptr = NULL;
		uap->datalen = 0;
	}

	/*
	 * If this is a remount, ... (never here)
	 */
	vfsp = vfs_alloc(KM_SLEEP);
	VFS_INIT(vfsp, vfsops, NULL);

	VFS_HOLD(vfsp);

	// lofi_add(fsname, vfsp, &mnt_mntopts, uap)

	/*
	 * PRIV_SYS_MOUNT doesn't mean you can become root.
	 */
	uap->flags |= MS_NOSUID;
	vfs_setmntopt_nolock(&mnt_mntopts, MNTOPT_NOSUID, NULL, 0, 0);

	/*
	 * The vfs_reflock...
	 */

	/*
	 * Lock the vfs...
	 */
	if ((error = vfs_lock(vfsp)) != 0) {
		vfs_free(vfsp);
		vfsp = NULL;
		goto errout;
	}

	/*
	 * Add device to mount in progress table...
	 */
	/*
	 * Invalidate cached entry for the mount point.
	 */

	/*
	 * If have an option string but the filesystem doesn't supply a
	 * prototype options table, create a table...
	 */

	/*
	 * Serialize with zone state transitions...
	 */

	// mount_in_progress(zone);

	/*
	 * Instantiate (or reinstantiate) the file system...
	 */
	vfs_swapopttbl(&mnt_mntopts, &vfsp->vfs_mntopts);

	vfs_setresource(vfsp, uap->spec, 0);
	vfs_setmntpoint(vfsp, uap->dir, 0);

	/*
	 * going to mount on this vnode, so notify.
	 */
	// vnevent_mountedover(vp, NULL);
	error = VFS_MOUNT(vfsp, vp, uap, credp);

	if (uap->flags & MS_RDONLY)
		vfs_setmntopt(vfsp, MNTOPT_RO, NULL, 0);
	if (uap->flags & MS_NOSUID)
		vfs_setmntopt(vfsp, MNTOPT_NOSUID, NULL, 0);
	if (uap->flags & MS_GLOBAL)
		vfs_setmntopt(vfsp, MNTOPT_GLOBAL, NULL, 0);

	if (error) {
		// lofi_remove(vfsp);

		// (remount == 0)
		vfs_unlock(vfsp);
		// vfs_freemnttab(vfsp);
		vfs_free(vfsp);
		vfsp = NULL;
	} else {
		/*
		 * Set the mount time to now
		 */
		// vfsp->vfs_mtime = ddi_get_time();
		// if (remount) ...
		// else if (splice) vfs_add(vp, vfsp, flags)
		// else VFS_HOLD(vfsp);

		/*
		 * Test jig specific:
		 * Do sort of like vfs_add for vp=rootdir
		 * Already have hold on vp.
		 */
		vfsp->vfs_vnodecovered = vp;
		vfsp->vfs_flag |= (VFS_NOSETUID|VFS_NODEVICES);
		VFS_HOLD(vfsp);
		rootvfs = vfsp;

		/*
		 * Set flags for global options encountered
		 */
		if (vfs_optionisset(vfsp, MNTOPT_RO, NULL))
			vfsp->vfs_flag |= VFS_RDONLY;
		else
			vfsp->vfs_flag &= ~VFS_RDONLY;
		if (vfs_optionisset(vfsp, MNTOPT_NOSUID, NULL)) {
			vfsp->vfs_flag |= (VFS_NOSETUID|VFS_NODEVICES);
		} else {
			if (vfs_optionisset(vfsp, MNTOPT_NODEVICES, NULL))
				vfsp->vfs_flag |= VFS_NODEVICES;
			else
				vfsp->vfs_flag &= ~VFS_NODEVICES;
			if (vfs_optionisset(vfsp, MNTOPT_NOSETUID, NULL))
				vfsp->vfs_flag |= VFS_NOSETUID;
			else
				vfsp->vfs_flag &= ~VFS_NOSETUID;
		}
		if (vfs_optionisset(vfsp, MNTOPT_NBMAND, NULL))
			vfsp->vfs_flag |= VFS_NBMAND;
		else
			vfsp->vfs_flag &= ~VFS_NBMAND;

		if (vfs_optionisset(vfsp, MNTOPT_XATTR, NULL))
			vfsp->vfs_flag |= VFS_XATTR;
		else
			vfsp->vfs_flag &= ~VFS_XATTR;

		if (vfs_optionisset(vfsp, MNTOPT_NOEXEC, NULL))
			vfsp->vfs_flag |= VFS_NOEXEC;
		else
			vfsp->vfs_flag &= ~VFS_NOEXEC;

		/*
		 * Now construct the output option string of options
		 * we recognized.
		 */
		if (uap->flags & MS_OPTIONSTR) {
			vfs_list_read_lock();
			copyout_error = vfs_buildoptionstr(
			    &vfsp->vfs_mntopts, inargs, optlen);
			vfs_list_unlock();
			if (copyout_error == 0 &&
			    (uap->flags & MS_SYSSPACE) == 0) {
				copyout_error = copyout(inargs, opts, optlen);
			}
		}

		/*
		 * If this isn't a remount, set up the vopstats...
		 */
		if (vswp->vsw_flag & VSW_XID)
			vfsp->vfs_flag |= VFS_XID;

		vfs_unlock(vfsp);

		/*
		 * Test jig specicific:
		 * Replace rootdir with the mounted root.
		 */
		error = VFS_ROOT(vfsp, &rootdir);
		if (error != 0) {
			panic("fake_domount, get root %d\n", error);
		}
	}
	// mount_completed(zone);
	// zone_rele(zone);

	// if (splice)
	//	vn_vfsunlock(vp);

	if ((error == 0) && (copyout_error == 0)) {
		/* get_vskstat_anchor() */
		/* Return vfsp to caller. */
		*vfspp = vfsp;
	}
errout:
	vfs_freeopttbl(&mnt_mntopts);
	/* resource, mountpt not allocated */
	/* no addmip, delmip */
	ASSERT(vswp != NULL);
	vfs_unrefvfssw(vswp);
	if (inargs != opts)
		kmem_free(inargs, MAX_MNTOPT_STR);
	if (copyout_error) {
		if (vfsp != NULL) {
			// lofi_remove(vfsp);
			VFS_RELE(vfsp);
		}
		error = copyout_error;
	}
	return (error);
}


static void
vfs_setpath(
    struct vfs *vfsp,		/* vfs being updated */
    refstr_t **refp,		/* Ref-count string to contain the new path */
    const char *newpath,	/* Path to add to refp (above) */
    uint32_t flag)		/* flag */
{
	// size_t len;
	refstr_t *ref;
	// char *sp;
	int have_list_lock = 0;

	ASSERT(!VFS_ON_LIST(vfsp) || vfs_lock_held(vfsp));

	/*
	 * New path must be less than MAXPATHLEN because mntfs
	 * will only display up to MAXPATHLEN bytes. This is currently
	 * safe, because domount() uses pn_get(), and other callers
	 * similarly cap the size to fewer than MAXPATHLEN bytes.
	 */

	ASSERT(strlen(newpath) < MAXPATHLEN);

	/* mntfs requires consistency while vfs list lock is held */

	if (VFS_ON_LIST(vfsp)) {
		have_list_lock = 1;
		vfs_list_lock();
	}

	if (*refp != NULL)
		refstr_rele(*refp);

	/*
	 * If we are in a non-global zone... (do something else)
	 */
	ref = refstr_alloc(newpath);
	*refp = ref;

	if (have_list_lock) {
		vfs_mnttab_modtimeupd();
		vfs_list_unlock();
	}
}

/*
 * Record a mounted resource name in a vfs structure.
 * If vfsp is already mounted, caller must hold the vfs lock.
 */
void
vfs_setresource(struct vfs *vfsp, const char *resource, uint32_t flag)
{
	if (resource == NULL || resource[0] == '\0')
		resource = VFS_NORESOURCE;
	vfs_setpath(vfsp, &vfsp->vfs_resource, resource, flag);
}

/*
 * Record a mount point name in a vfs structure.
 * If vfsp is already mounted, caller must hold the vfs lock.
 */
void
vfs_setmntpoint(struct vfs *vfsp, const char *mntpt, uint32_t flag)
{
	if (mntpt == NULL || mntpt[0] == '\0')
		mntpt = VFS_NOMNTPT;
	vfs_setpath(vfsp, &vfsp->vfs_mntpt, mntpt, flag);
}

/* Returns the vfs_resource. Caller must call refstr_rele() when finished. */

refstr_t *
vfs_getresource(const struct vfs *vfsp)
{
	refstr_t *resource;

	vfs_list_read_lock();
	resource = vfsp->vfs_resource;
	refstr_hold(resource);
	vfs_list_unlock();

	return (resource);
}

/* Returns the vfs_mntpt. Caller must call refstr_rele() when finished. */

refstr_t *
vfs_getmntpoint(const struct vfs *vfsp)
{
	refstr_t *mntpt;

	vfs_list_read_lock();
	mntpt = vfsp->vfs_mntpt;
	refstr_hold(mntpt);
	vfs_list_unlock();

	return (mntpt);
}

// vfs_createopttbl_extend
// vfs_createopttbl

/*
 * Swap two mount options tables
 */
static void
vfs_swapopttbl_nolock(mntopts_t *optbl1, mntopts_t *optbl2)
{
	uint_t tmpcnt;
	mntopt_t *tmplist;

	tmpcnt = optbl2->mo_count;
	tmplist = optbl2->mo_list;
	optbl2->mo_count = optbl1->mo_count;
	optbl2->mo_list = optbl1->mo_list;
	optbl1->mo_count = tmpcnt;
	optbl1->mo_list = tmplist;
}

static void
vfs_swapopttbl(mntopts_t *optbl1, mntopts_t *optbl2)
{
	vfs_list_lock();
	vfs_swapopttbl_nolock(optbl1, optbl2);
	vfs_mnttab_modtimeupd();
	vfs_list_unlock();
}

static char **
vfs_copycancelopt_extend(char **const moc, int extend)
{
	int i = 0;
	int j;
	char **result;

	if (moc != NULL) {
		for (; moc[i] != NULL; i++)
			/* count number of options to cancel */;
	}

	if (i + extend == 0)
		return (NULL);

	result = kmem_alloc((i + extend + 1) * sizeof (char *), KM_SLEEP);

	for (j = 0; j < i; j++) {
		result[j] = kmem_alloc(strlen(moc[j]) + 1, KM_SLEEP);
		(void) strcpy(result[j], moc[j]);
	}
	for (; j <= i + extend; j++)
		result[j] = NULL;

	return (result);
}

static void
vfs_copyopt(const mntopt_t *s, mntopt_t *d)
{
	char *sp, *dp;

	d->mo_flags = s->mo_flags;
	d->mo_data = s->mo_data;
	sp = s->mo_name;
	if (sp != NULL) {
		dp = kmem_alloc(strlen(sp) + 1, KM_SLEEP);
		(void) strcpy(dp, sp);
		d->mo_name = dp;
	} else {
		d->mo_name = NULL; /* should never happen */
	}

	d->mo_cancel = vfs_copycancelopt_extend(s->mo_cancel, 0);

	sp = s->mo_arg;
	if (sp != NULL) {
		dp = kmem_alloc(strlen(sp) + 1, KM_SLEEP);
		(void) strcpy(dp, sp);
		d->mo_arg = dp;
	} else {
		d->mo_arg = NULL;
	}
}

// vfs_copyopttbl_extend
// vfs_copyopttbl

/*
 * Copy a mount options table, possibly allocating some spare
 * slots at the end.  It is permissible to copy_extend the NULL table.
 */
static void
vfs_copyopttbl_extend(const mntopts_t *smo, mntopts_t *dmo, int extra)
{
	uint_t i, count;
	mntopt_t *motbl;

	/*
	 * Clear out any existing stuff in the options table being initialized
	 */
	vfs_freeopttbl(dmo);
	count = (smo == NULL) ? 0 : smo->mo_count;
	if ((count + extra) == 0)	/* nothing to do */
		return;
	dmo->mo_count = count + extra;
	motbl = kmem_zalloc((count + extra) * sizeof (mntopt_t), KM_SLEEP);
	dmo->mo_list = motbl;
	for (i = 0; i < count; i++) {
		vfs_copyopt(&smo->mo_list[i], &motbl[i]);
	}
	for (i = count; i < count + extra; i++) {
		motbl[i].mo_flags = MO_EMPTY;
	}
}

/*
 * Copy a mount options table.
 *
 * This function is *not* for general use by filesystems.
 *
 * Note: caller is responsible for locking the vfs list, if needed,
 *       to protect smo and dmo.
 */
void
vfs_copyopttbl(const mntopts_t *smo, mntopts_t *dmo)
{
	vfs_copyopttbl_extend(smo, dmo, 0);
}

static char **
vfs_mergecancelopts(const mntopt_t *mop1, const mntopt_t *mop2)
{
	int c1 = 0;
	int c2 = 0;
	char **result;
	char **sp1, **sp2, **dp;

	/*
	 * First we count both lists of cancel options.
	 * If either is NULL or has no elements, we return a copy of
	 * the other.
	 */
	if (mop1->mo_cancel != NULL) {
		for (; mop1->mo_cancel[c1] != NULL; c1++)
			/* count cancel options in mop1 */;
	}

	if (c1 == 0)
		return (vfs_copycancelopt_extend(mop2->mo_cancel, 0));

	if (mop2->mo_cancel != NULL) {
		for (; mop2->mo_cancel[c2] != NULL; c2++)
			/* count cancel options in mop2 */;
	}

	result = vfs_copycancelopt_extend(mop1->mo_cancel, c2);

	if (c2 == 0)
		return (result);

	/*
	 * When we get here, we've got two sets of cancel options;
	 * we need to merge the two sets.  We know that the result
	 * array has "c1+c2+1" entries and in the end we might shrink
	 * it.
	 * Result now has a copy of the c1 entries from mop1; we'll
	 * now lookup all the entries of mop2 in mop1 and copy it if
	 * it is unique.
	 * This operation is O(n^2) but it's only called once per
	 * filesystem per duplicate option.  This is a situation
	 * which doesn't arise with the filesystems in ON and
	 * n is generally 1.
	 */

	dp = &result[c1];
	for (sp2 = mop2->mo_cancel; *sp2 != NULL; sp2++) {
		for (sp1 = mop1->mo_cancel; *sp1 != NULL; sp1++) {
			if (strcmp(*sp1, *sp2) == 0)
				break;
		}
		if (*sp1 == NULL) {
			/*
			 * Option *sp2 not found in mop1, so copy it.
			 * The calls to vfs_copycancelopt_extend()
			 * guarantee that there's enough room.
			 */
			*dp = kmem_alloc(strlen(*sp2) + 1, KM_SLEEP);
			(void) strcpy(*dp++, *sp2);
		}
	}
	if (dp != &result[c1+c2]) {
		size_t bytes = (dp - result + 1) * sizeof (char *);
		char **nres = kmem_alloc(bytes, KM_SLEEP);

		bcopy(result, nres, bytes);
		kmem_free(result, (c1 + c2 + 1) * sizeof (char *));
		result = nres;
	}
	return (result);
}

/*
 * Merge two mount option tables (outer and inner) into one.  This is very
 * similar to "merging" global variables and automatic variables in C.
 *
 * This isn't (and doesn't have to be) fast.
 *
 * This function is *not* for general use by filesystems.
 *
 * Note: caller is responsible for locking the vfs list, if needed,
 *       to protect omo, imo & dmo.
 */
void
vfs_mergeopttbl(const mntopts_t *omo, const mntopts_t *imo, mntopts_t *dmo)
{
	uint_t i, count;
	mntopt_t *mop, *motbl;
	uint_t freeidx;

	/*
	 * First determine how much space we need to allocate.
	 */
	count = omo->mo_count;
	for (i = 0; i < imo->mo_count; i++) {
		if (imo->mo_list[i].mo_flags & MO_EMPTY)
			continue;
		if (vfs_hasopt(omo, imo->mo_list[i].mo_name) == NULL)
			count++;
	}
	ASSERT(count >= omo->mo_count &&
	    count <= omo->mo_count + imo->mo_count);
	motbl = kmem_alloc(count * sizeof (mntopt_t), KM_SLEEP);
	for (i = 0; i < omo->mo_count; i++)
		vfs_copyopt(&omo->mo_list[i], &motbl[i]);
	freeidx = omo->mo_count;
	for (i = 0; i < imo->mo_count; i++) {
		if (imo->mo_list[i].mo_flags & MO_EMPTY)
			continue;
		if ((mop = vfs_hasopt(omo, imo->mo_list[i].mo_name)) != NULL) {
			char **newcanp;
			uint_t index = mop - omo->mo_list;

			newcanp = vfs_mergecancelopts(mop, &motbl[index]);

			vfs_freeopt(&motbl[index]);
			vfs_copyopt(&imo->mo_list[i], &motbl[index]);

			vfs_freecancelopt(motbl[index].mo_cancel);
			motbl[index].mo_cancel = newcanp;
		} else {
			/*
			 * If it's a new option, just copy it over to the first
			 * free location.
			 */
			vfs_copyopt(&imo->mo_list[i], &motbl[freeidx++]);
		}
	}
	dmo->mo_count = count;
	dmo->mo_list = motbl;
}

/*
 * Functions to set and clear mount options in a mount options table.
 */

/*
 * Clear a mount option, if it exists.
 *
 * The update_mnttab arg indicates whether mops is part of a vfs that is on
 * the vfs list.
 */
static void
vfs_clearmntopt_nolock(mntopts_t *mops, const char *opt, int update_mnttab)
{
	struct mntopt *mop;
	uint_t i, count;

	ASSERT(!update_mnttab || RW_WRITE_HELD(&vfslist));

	count = mops->mo_count;
	for (i = 0; i < count; i++) {
		mop = &mops->mo_list[i];

		if (mop->mo_flags & MO_EMPTY)
			continue;
		if (strcmp(opt, mop->mo_name))
			continue;
		mop->mo_flags &= ~MO_SET;
		if (mop->mo_arg != NULL) {
			kmem_free(mop->mo_arg, strlen(mop->mo_arg) + 1);
		}
		mop->mo_arg = NULL;
		if (update_mnttab)
			vfs_mnttab_modtimeupd();
		break;
	}
}

void
vfs_clearmntopt(struct vfs *vfsp, const char *opt)
{
	int gotlock = 0;

	if (VFS_ON_LIST(vfsp)) {
		gotlock = 1;
		vfs_list_lock();
	}
	vfs_clearmntopt_nolock(&vfsp->vfs_mntopts, opt, gotlock);
	if (gotlock)
		vfs_list_unlock();
}


/*
 * Set a mount option on...
 */
static void
vfs_setmntopt_nolock(mntopts_t *mops, const char *opt,
    const char *arg, int flags, int update_mnttab)
{
	mntopt_t *mop;
	uint_t i, count;
	char *sp;

	ASSERT(!update_mnttab || RW_WRITE_HELD(&vfslist));

	if (flags & VFS_CREATEOPT) {
		if (vfs_hasopt(mops, opt) != NULL) {
			flags &= ~VFS_CREATEOPT;
		}
	}
	count = mops->mo_count;
	for (i = 0; i < count; i++) {
		mop = &mops->mo_list[i];

		if (mop->mo_flags & MO_EMPTY) {
			if ((flags & VFS_CREATEOPT) == 0)
				continue;
			sp = kmem_alloc(strlen(opt) + 1, KM_SLEEP);
			(void) strcpy(sp, opt);
			mop->mo_name = sp;
			if (arg != NULL)
				mop->mo_flags = MO_HASVALUE;
			else
				mop->mo_flags = 0;
		} else if (strcmp(opt, mop->mo_name)) {
			continue;
		}
		if ((mop->mo_flags & MO_IGNORE) && (flags & VFS_NOFORCEOPT))
			break;
		if (arg != NULL && (mop->mo_flags & MO_HASVALUE) != 0) {
			sp = kmem_alloc(strlen(arg) + 1, KM_SLEEP);
			(void) strcpy(sp, arg);
		} else {
			sp = NULL;
		}
		if (mop->mo_arg != NULL)
			kmem_free(mop->mo_arg, strlen(mop->mo_arg) + 1);
		mop->mo_arg = sp;
		if (flags & VFS_DISPLAY)
			mop->mo_flags &= ~MO_NODISPLAY;
		if (flags & VFS_NODISPLAY)
			mop->mo_flags |= MO_NODISPLAY;
		mop->mo_flags |= MO_SET;
		if (mop->mo_cancel != NULL) {
			char **cp;

			for (cp = mop->mo_cancel; *cp != NULL; cp++)
				vfs_clearmntopt_nolock(mops, *cp, 0);
		}
		if (update_mnttab)
			vfs_mnttab_modtimeupd();
		break;
	}
}

void
vfs_setmntopt(struct vfs *vfsp, const char *opt, const char *arg, int flags)
{
	int gotlock = 0;

	if (VFS_ON_LIST(vfsp)) {
		gotlock = 1;
		vfs_list_lock();
	}
	vfs_setmntopt_nolock(&vfsp->vfs_mntopts, opt, arg, flags, gotlock);
	if (gotlock)
		vfs_list_unlock();
}

// vfs_addtag
// vfs_settag
// vfs_clrtag

/*
 * Function to parse an option string and fill in a mount options table.
 * Unknown options are silently ignored.  The input option string is modified
 * by replacing separators with nulls.  If the create flag is set, options
 * not found in the table are just added on the fly.  The table must have
 * an option slot marked MO_EMPTY to add an option on the fly.
 *
 * This function is *not* for general use by filesystems.
 *
 * Note: caller is responsible for locking the vfs list, if needed,
 *       to protect mops..
 */
void
vfs_parsemntopts(mntopts_t *mops, char *osp, int create)
{
	char *s = osp, *p, *nextop, *valp, *cp, *ep = NULL;
	int setflg = VFS_NOFORCEOPT;

	if (osp == NULL)
		return;
	while (*s != '\0') {
		p = strchr(s, ',');	/* find next option */
		if (p == NULL) {
			cp = NULL;
			p = s + strlen(s);
		} else {
			cp = p;		/* save location of comma */
			*p++ = '\0';	/* mark end and point to next option */
		}
		nextop = p;
		p = strchr(s, '=');	/* look for value */
		if (p == NULL) {
			valp = NULL;	/* no value supplied */
			ep = NULL;
		} else {
			ep = p;		/* save location of equals */
			*p++ = '\0';	/* end option and point to value */
			valp = p;
		}
		/*
		 * set option into options table
		 */
		if (create)
			setflg |= VFS_CREATEOPT;
		vfs_setmntopt_nolock(mops, s, valp, setflg, 0);
		if (cp != NULL)
			*cp = ',';	/* restore the comma */
		if (valp != NULL)
			*ep = '=';	/* restore the equals */
		s = nextop;
	}
}

/*
 * Function to inquire if an option exists in a mount options table.
 * Returns a pointer to the option if it exists, else NULL.
 */
struct mntopt *
vfs_hasopt(const mntopts_t *mops, const char *opt)
{
	struct mntopt *mop;
	uint_t i, count;

	count = mops->mo_count;
	for (i = 0; i < count; i++) {
		mop = &mops->mo_list[i];

		if (mop->mo_flags & MO_EMPTY)
			continue;
		if (strcmp(opt, mop->mo_name) == 0)
			return (mop);
	}
	return (NULL);
}

/*
 * Function to inquire if an option is set in a mount options table.
 * Returns non-zero if set and fills in the arg pointer with a pointer to
 * the argument string or NULL if there is no argument string.
 */
static int
vfs_optionisset_nolock(const mntopts_t *mops, const char *opt, char **argp)
{
	struct mntopt *mop;
	uint_t i, count;

	count = mops->mo_count;
	for (i = 0; i < count; i++) {
		mop = &mops->mo_list[i];

		if (mop->mo_flags & MO_EMPTY)
			continue;
		if (strcmp(opt, mop->mo_name))
			continue;
		if ((mop->mo_flags & MO_SET) == 0)
			return (0);
		if (argp != NULL && (mop->mo_flags & MO_HASVALUE) != 0)
			*argp = mop->mo_arg;
		return (1);
	}
	return (0);
}


int
vfs_optionisset(const struct vfs *vfsp, const char *opt, char **argp)
{
	int ret;

	vfs_list_read_lock();
	ret = vfs_optionisset_nolock(&vfsp->vfs_mntopts, opt, argp);
	vfs_list_unlock();
	return (ret);
}


/*
 * Construct a comma separated string of the options set in the given
 * mount table, return the string in the given buffer.  Return non-zero if
 * the buffer would overflow.
 *
 * This function is *not* for general use by filesystems.
 *
 * Note: caller is responsible for locking the vfs list, if needed,
 *       to protect mp.
 */
int
vfs_buildoptionstr(const mntopts_t *mp, char *buf, int len)
{
	char *cp;
	uint_t i;

	buf[0] = '\0';
	cp = buf;
	for (i = 0; i < mp->mo_count; i++) {
		struct mntopt *mop;

		mop = &mp->mo_list[i];
		if (mop->mo_flags & MO_SET) {
			int optlen, comma = 0;

			if (buf[0] != '\0')
				comma = 1;
			optlen = strlen(mop->mo_name);
			if (strlen(buf) + comma + optlen + 1 > len)
				goto err;
			if (comma)
				*cp++ = ',';
			(void) strcpy(cp, mop->mo_name);
			cp += optlen;
			/*
			 * Append option value if there is one
			 */
			if (mop->mo_arg != NULL) {
				int arglen;

				arglen = strlen(mop->mo_arg);
				if (strlen(buf) + arglen + 2 > len)
					goto err;
				*cp++ = '=';
				(void) strcpy(cp, mop->mo_arg);
				cp += arglen;
			}
		}
	}
	return (0);
err:
	return (EOVERFLOW);
}

static void
vfs_freecancelopt(char **moc)
{
	if (moc != NULL) {
		int ccnt = 0;
		char **cp;

		for (cp = moc; *cp != NULL; cp++) {
			kmem_free(*cp, strlen(*cp) + 1);
			ccnt++;
		}
		kmem_free(moc, (ccnt + 1) * sizeof (char *));
	}
}

static void
vfs_freeopt(mntopt_t *mop)
{
	if (mop->mo_name != NULL)
		kmem_free(mop->mo_name, strlen(mop->mo_name) + 1);

	vfs_freecancelopt(mop->mo_cancel);

	if (mop->mo_arg != NULL)
		kmem_free(mop->mo_arg, strlen(mop->mo_arg) + 1);
}

/*
 * Free a mount options table
 *
 * This function is *not* for general use by filesystems.
 *
 * Note: caller is responsible for locking the vfs list, if needed,
 *       to protect mp.
 */
void
vfs_freeopttbl(mntopts_t *mp)
{
	uint_t i, count;

	count = mp->mo_count;
	for (i = 0; i < count; i++) {
		vfs_freeopt(&mp->mo_list[i]);
	}
	if (count) {
		kmem_free(mp->mo_list, sizeof (mntopt_t) * count);
		mp->mo_count = 0;
		mp->mo_list = NULL;
	}
}

// vfs_mntdummyread
// vfs_mntdummywrite
// vfs_mntdummygetattr
// vfs_mnttabvp_setup
// vfs_mnttab_rwop
// vfs_mnttab_writeop
// vfs_mnttab_readop
// vfs_freemnttab
// vfs_mnttab_modtime
// vfs_mnttab_poll
// vfs_mono_time

/*
 * Update the mnttab modification time...
 */
void
vfs_mnttab_modtimeupd()
{
}

/*
 * Unlike the real dounmount, we don't have
 * vn_vfswlock_held(coveredvp)
 */
int
fake_dounmount(struct vfs *vfsp, int flag)
{
	cred_t *cr = CRED();
	vnode_t *coveredvp;
	int error;

	/*
	 * Get covered vnode. This will be NULL if the vfs is not linked
	 * into the file system name space (i.e., domount() with MNT_NOSPICE).
	 */
	coveredvp = vfsp->vfs_vnodecovered;

	/* For forcible umount, skip VFS_SYNC() since it may hang */
	if ((flag & MS_FORCE) == 0)
		(void) VFS_SYNC(vfsp, 0, cr);

	/*
	 * Test-jig specific:
	 * Need to release rootdir before unmount or VFS_UNMOUNT
	 * may fail due to that node being active.
	 */
	if (rootdir != NULL) {
		ASSERT(rootdir != coveredvp);
		VN_RELE(rootdir);
		rootdir = NULL;
	}

	/*
	 * Lock the vfs to maintain fs status quo during unmount.  This
	 * has to be done after the sync because ufs_update tries to acquire
	 * the vfs_reflock.
	 */
	vfs_lock_wait(vfsp);

	if ((error = VFS_UNMOUNT(vfsp, flag, cr)) != 0) {
		int err2;
		vfs_unlock(vfsp);
		/* Get rootdir back */
		err2 = VFS_ROOT(vfsp, &rootdir);
		if (err2 != 0) {
			panic("fake_dounmount, get root %d\n", err2);
		}
	} else {
		/*
		 * Real dounmount does vfs_remove.
		 *
		 * Test-jig specific:
		 * Restore the covered rootdir,
		 * release the rootvfs hold and clear.
		 */
		if (coveredvp != NULL) {
			// vfs_list_remove(vfsp);
			vfsp->vfs_vnodecovered = NULL;
			rootdir = coveredvp;
		}
		if (rootvfs == vfsp) {
			VFS_RELE(vfsp);
			rootvfs = NULL;
		}

		/*
		 * Release the (final) reference to vfs
		 */
		vfs_unlock(vfsp);
		VFS_RELE(vfsp);
	}
	return (error);
}

// vfs_unmountall(void)
// vfs_addmip
// vfs_delmip
// vfs_add
// vfs_remove

static krwlock_t vpvfsentry_ve_lock;

/*
 * Lock a filesystem to prevent access to it while mounting,
 * unmounting and syncing.  Return EBUSY immediately if lock
 * can't be acquired.
 */
int
vfs_lock(vfs_t *vfsp)
{

	if (rw_tryenter(&vpvfsentry_ve_lock, RW_WRITER))
		return (0);

	return (EBUSY);
}

int
vfs_rlock(vfs_t *vfsp)
{

	if (rw_tryenter(&vpvfsentry_ve_lock, RW_READER))
		return (0);

	return (EBUSY);
}

void
vfs_lock_wait(vfs_t *vfsp)
{

	rw_enter(&vpvfsentry_ve_lock, RW_WRITER);
}

void
vfs_rlock_wait(vfs_t *vfsp)
{
	rw_enter(&vpvfsentry_ve_lock, RW_READER);
}

/*
 * Unlock a locked filesystem.
 */
void
vfs_unlock(vfs_t *vfsp)
{

	rw_exit(&vpvfsentry_ve_lock);
}

/*
 * Utility routine that allows a filesystem to construct its
 * fsid in "the usual way" - by munging some underlying dev_t and
 * the filesystem type number into the 64-bit fsid. ...
 */
void
vfs_make_fsid(fsid_t *fsi, dev_t dev, int val)
{
	if (!cmpldev((dev32_t *)&fsi->val[0], dev))
		panic("device number too big for fsid!");
	fsi->val[1] = val;
}

int
vfs_lock_held(vfs_t *vfsp)
{
	int held;

	held = rw_write_held(&vpvfsentry_ve_lock);

	return (held);
}

// vfs_lock_owner

/*
 * vfs list locking.
 */

void
vfs_list_lock()
{
	rw_enter(&vfslist, RW_WRITER);
}

void
vfs_list_read_lock()
{
	rw_enter(&vfslist, RW_READER);
}

void
vfs_list_unlock()
{
	rw_exit(&vfslist);
}

/*
 * Low level worker routines for adding entries to and removing entries from
 * the vfs list.
 */

// vfs_hash_add
// vfs_hash_remove
// vfs_list_add
// vfs_list_remove
// getvfs
// vfs_devmounting

/*
 * Search the vfs list for a specified device.  Returns 1, if entry is found
 * or 0 if no suitable entry is found.
 */

int
vfs_devismounted(dev_t dev)
{
	return (0);
}

// vfs_dev2vfsp
// vfs_mntpoint2vfsp

/*
 * Search the vfs list for a specified vfsops.
 * if vfs entry is found then return 1, else 0.
 */
int
vfs_opsinuse(vfsops_t *ops)
{
	return (0);
}

/*
 * Allocate an entry in vfssw for a file system type
 */
struct vfssw *
allocate_vfssw(const char *type)
{
	struct vfssw *vswp;

	if (type[0] == '\0' || strlen(type) + 1 > _ST_FSTYPSZ) {
		/*
		 * The vfssw table uses the empty string to identify an
		 * available entry; we cannot add any type which has
		 * a leading NUL. The string length is limited to
		 * the size of the st_fstype array in struct stat.
		 */
		return (NULL);
	}

	ASSERT(VFSSW_WRITE_LOCKED());
	for (vswp = &vfssw[1]; vswp < &vfssw[nfstype]; vswp++)
		if (!ALLOCATED_VFSSW(vswp)) {
			vswp->vsw_name = kmem_alloc(strlen(type) + 1, KM_SLEEP);
			(void) strcpy(vswp->vsw_name, type);
			ASSERT(vswp->vsw_count == 0);
			vswp->vsw_count = 1;
			mutex_init(&vswp->vsw_lock, NULL, MUTEX_DEFAULT, NULL);
			return (vswp);
		}
	return (NULL);
}

// vfs_to_modname
// vfs_getvfssw

/*
 * Find a vfssw entry given a file system type name.
 */
struct vfssw *
vfs_getvfssw(const char *type)
{
	struct vfssw *vswp;

	if (type == NULL || *type == '\0')
		return (NULL);

	for (vswp = &vfssw[1]; vswp < &vfssw[nfstype]; vswp++) {
		if (strcmp(type, vswp->vsw_name) == 0) {
			return (vswp);
		}
	}

	return (NULL);

}

/*
 * Find a vfssw entry given a file system type name.
 */
struct vfssw *
vfs_getvfsswbyname(const char *type)
{
	struct vfssw *vswp;

	ASSERT(VFSSW_LOCKED());
	if (type == NULL || *type == '\0')
		return (NULL);

	for (vswp = &vfssw[1]; vswp < &vfssw[nfstype]; vswp++) {
		if (strcmp(type, vswp->vsw_name) == 0) {
			vfs_refvfssw(vswp);
			return (vswp);
		}
	}

	return (NULL);
}

// vfs_getvfsswbyvfsops

/*
 * Reference a vfssw entry.
 */
void
vfs_refvfssw(struct vfssw *vswp)
{

	mutex_enter(&vswp->vsw_lock);
	vswp->vsw_count++;
	mutex_exit(&vswp->vsw_lock);
}

/*
 * Unreference a vfssw entry.
 */
void
vfs_unrefvfssw(struct vfssw *vswp)
{

	mutex_enter(&vswp->vsw_lock);
	vswp->vsw_count--;
	mutex_exit(&vswp->vsw_lock);
}

// vfs_syncall

/*
 * Map VFS flags to statvfs flags.  These shouldn't really be separate
 * flags at all.
 */
uint_t
vf_to_stf(uint_t vf)
{
	uint_t stf = 0;

	if (vf & VFS_RDONLY)
		stf |= ST_RDONLY;
	if (vf & VFS_NOSETUID)
		stf |= ST_NOSUID;
	if (vf & VFS_NOTRUNC)
		stf |= ST_NOTRUNC;

	return (stf);
}

// vfsstray_sync
// vfsstray
// vfs_EIO
// vfs_EIO_sync
// EIO_vfs
// EIO_vfsops

#pragma init(vfsinit)

/*
 * Called from startup() to initialize all loaded vfs's
 */
void
vfsinit(void)
{
	vn_create_cache();

	/* Temporary, until we mount root */
	rootdir = vn_alloc(KM_SLEEP);
	rootdir->v_type = VDIR;
}

vfs_t *
vfs_alloc(int kmflag)
{
	vfs_t *vfsp;

	vfsp = kmem_alloc(sizeof (struct vfs), kmflag);

	/*
	 * Do the simplest initialization here.
	 * Everything else gets done in vfs_init()
	 */
	bzero(vfsp, sizeof (vfs_t));
	return (vfsp);
}

void
vfs_free(vfs_t *vfsp)
{
	/*
	 * One would be tempted to assert that "vfsp->vfs_count == 0".
	 * Don't.  See fs/vfs.c
	 */

	/* If FEM was in use, make sure everything gets cleaned up */

	if (vfsp->vfs_implp)
		vfsimpl_teardown(vfsp);
	sema_destroy(&vfsp->vfs_reflock);
	kmem_free(vfsp, sizeof (struct vfs));
}

/*
 * Increments the vfs reference count by one atomically.
 */
void
vfs_hold(vfs_t *vfsp)
{
	atomic_inc_32(&vfsp->vfs_count);
	ASSERT(vfsp->vfs_count != 0);
}

/*
 * Decrements the vfs reference count by one atomically. When
 * vfs reference count becomes zero, it calls the file system
 * specific vfs_freevfs() to free up the resources.
 */
void
vfs_rele(vfs_t *vfsp)
{
	ASSERT(vfsp->vfs_count != 0);
	if (atomic_dec_32_nv(&vfsp->vfs_count) == 0) {
		VFS_FREEVFS(vfsp);
		// lofi_remove(vfsp);
		// zone_rele_ref...
		// vfs_freemnttab(vfsp);
		vfs_free(vfsp);
	}
}

/*
 * Generic operations vector support.
 */

int
fs_build_vector(void *vector, int *unused_ops,
    const fs_operation_trans_def_t *translation,
    const fs_operation_def_t *operations)
{
	int i, num_trans, num_ops, used;

	/*
	 * Count the number of translations and the number of supplied
	 * operations.
	 */

	{
		const fs_operation_trans_def_t *p;

		for (num_trans = 0, p = translation;
		    p->name != NULL;
		    num_trans++, p++)
			;
	}

	{
		const fs_operation_def_t *p;

		for (num_ops = 0, p = operations;
		    p->name != NULL;
		    num_ops++, p++)
			;
	}

	/* Walk through each operation known to our caller.  There will be */
	/* one entry in the supplied "translation table" for each. */

	used = 0;

	for (i = 0; i < num_trans; i++) {
		int j, found;
		char *curname;
		fs_generic_func_p result;
		fs_generic_func_p *location;

		curname = translation[i].name;

		/* Look for a matching operation in the list supplied by the */
		/* file system. */

		found = 0;

		for (j = 0; j < num_ops; j++) {
			if (strcmp(operations[j].name, curname) == 0) {
				used++;
				found = 1;
				break;
			}
		}

		/*
		 * If the file system is using a "placeholder" for default
		 * or error functions, grab the appropriate function out of
		 * the translation table.  If the file system didn't supply
		 * this operation at all, use the default function.
		 */

		if (found) {
			result = operations[j].func.fs_generic;
			if (result == fs_default) {
				result = translation[i].defaultFunc;
			} else if (result == fs_error) {
				result = translation[i].errorFunc;
			} else if (result == NULL) {
				/* Null values are PROHIBITED */
				return (EINVAL);
			}
		} else {
			result = translation[i].defaultFunc;
		}

		/* Now store the function into the operations vector. */

		/* LINTED E_BAD_PTR_CAST_ALIGN */
		location = (fs_generic_func_p *)
		    (((char *)vector) + translation[i].offset);

		*location = result;
	}

	*unused_ops = num_ops - used;

	return (0);
}

/* Placeholder functions, should never be called. */

int
fs_error(void)
{
	cmn_err(CE_PANIC, "fs_error called");
	return (0);
}

int
fs_default(void)
{
	cmn_err(CE_PANIC, "fs_default called");
	return (0);
}

// rootconf
// getfsname
// getrootfs

/*
 * VFS feature routines
 */

#define	VFTINDEX(feature)	(((feature) >> 32) & 0xFFFFFFFF)
#define	VFTBITS(feature)	((feature) & 0xFFFFFFFFLL)

/* Register a feature in the vfs */
void
vfs_set_feature(vfs_t *vfsp, vfs_feature_t feature)
{
	/* Note that vfs_featureset[] is found in *vfsp->vfs_implp */
	if (vfsp->vfs_implp == NULL)
		return;

	vfsp->vfs_featureset[VFTINDEX(feature)] |= VFTBITS(feature);
}

void
vfs_clear_feature(vfs_t *vfsp, vfs_feature_t feature)
{
	/* Note that vfs_featureset[] is found in *vfsp->vfs_implp */
	if (vfsp->vfs_implp == NULL)
		return;
	vfsp->vfs_featureset[VFTINDEX(feature)] &= VFTBITS(~feature);
}

/*
 * Query a vfs for a feature.
 * Returns 1 if feature is present, 0 if not
 */
int
vfs_has_feature(vfs_t *vfsp, vfs_feature_t feature)
{
	int	ret = 0;

	/* Note that vfs_featureset[] is found in *vfsp->vfs_implp */
	if (vfsp->vfs_implp == NULL)
		return (ret);

	if (vfsp->vfs_featureset[VFTINDEX(feature)] & VFTBITS(feature))
		ret = 1;

	return (ret);
}

// vfs_propagate_features
// vfs_get_lofi
