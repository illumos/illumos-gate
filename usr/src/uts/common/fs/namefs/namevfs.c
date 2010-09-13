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
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * This file supports the vfs operations for the NAMEFS file system.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/debug.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/inline.h>
#include <sys/file.h>
#include <sys/proc.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/mount.h>
#include <sys/sysmacros.h>
#include <sys/var.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/vnode.h>
#include <sys/mode.h>
#include <sys/pcb.h>
#include <sys/signal.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <sys/cred.h>
#include <sys/fs/namenode.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/cmn_err.h>
#include <sys/modctl.h>
#include <fs/fs_subr.h>
#include <sys/policy.h>
#include <sys/vmem.h>
#include <sys/fs/sdev_impl.h>

#define	NM_INOQUANT		(64 * 1024)

/*
 * Define global data structures.
 */
dev_t	namedev;
int	namefstype;
struct	namenode *nm_filevp_hash[NM_FILEVP_HASH_SIZE];
struct	vfs namevfs;
kmutex_t ntable_lock;

static vmem_t	*nm_inoarena;	/* vmem arena to allocate inode no's from */
static kmutex_t	nm_inolock;

vfsops_t *namefs_vfsops;
/*
 * Functions to allocate node id's starting from 1. Based on vmem routines.
 * The vmem arena is extended in NM_INOQUANT chunks.
 */
uint64_t
namenodeno_alloc(void)
{
	uint64_t nno;

	mutex_enter(&nm_inolock);
	nno = (uint64_t)(uintptr_t)
	    vmem_alloc(nm_inoarena, 1, VM_NOSLEEP + VM_FIRSTFIT);
	if (nno == 0) {
		(void) vmem_add(nm_inoarena, (void *)(vmem_size(nm_inoarena,
		    VMEM_ALLOC | VMEM_FREE) + 1), NM_INOQUANT, VM_SLEEP);
		nno = (uint64_t)(uintptr_t)
		    vmem_alloc(nm_inoarena, 1, VM_SLEEP + VM_FIRSTFIT);
		ASSERT(nno != 0);
	}
	mutex_exit(&nm_inolock);
	ASSERT32(nno <= ULONG_MAX);
	return (nno);
}

static void
namenodeno_init(void)
{
	nm_inoarena = vmem_create("namefs_inodes", (void *)1, NM_INOQUANT, 1,
	    NULL, NULL, NULL, 1, VM_SLEEP);
	mutex_init(&nm_inolock, NULL, MUTEX_DEFAULT, NULL);
}

void
namenodeno_free(uint64_t nn)
{
	void *vaddr = (void *)(uintptr_t)nn;

	ASSERT32((uint64_t)(uintptr_t)vaddr == nn);

	mutex_enter(&nm_inolock);
	vmem_free(nm_inoarena, vaddr, 1);
	mutex_exit(&nm_inolock);
}

/*
 * Insert a namenode into the nm_filevp_hash table.
 *
 * Each link has a unique namenode with a unique nm_mountvp field.
 * The nm_filevp field of the namenode need not be unique, since a
 * file descriptor may be mounted to multiple nodes at the same time.
 * We hash on nm_filevp since that's what discriminates the searches
 * in namefind() and nm_unmountall().
 */
void
nameinsert(struct namenode *nodep)
{
	struct namenode **bucket;

	ASSERT(MUTEX_HELD(&ntable_lock));

	bucket = NM_FILEVP_HASH(nodep->nm_filevp);
	nodep->nm_nextp = *bucket;
	*bucket = nodep;
}

/*
 * Remove a namenode from the hash table, if present.
 */
void
nameremove(struct namenode *nodep)
{
	struct namenode *np, **npp;

	ASSERT(MUTEX_HELD(&ntable_lock));

	for (npp = NM_FILEVP_HASH(nodep->nm_filevp); (np = *npp) != NULL;
	    npp = &np->nm_nextp) {
		if (np == nodep) {
			*npp = np->nm_nextp;
			return;
		}
	}
}

/*
 * Search for a namenode that has a nm_filevp == vp and nm_mountpt == mnt.
 * If mnt is NULL, return the first link with nm_filevp of vp.
 * Returns namenode pointer on success, NULL on failure.
 */
struct namenode *
namefind(vnode_t *vp, vnode_t *mnt)
{
	struct namenode *np;

	ASSERT(MUTEX_HELD(&ntable_lock));
	for (np = *NM_FILEVP_HASH(vp); np != NULL; np = np->nm_nextp)
		if (np->nm_filevp == vp &&
		    (mnt == NULL || np->nm_mountpt == mnt))
			break;
	return (np);
}

/*
 * Force the unmouting of a file descriptor from ALL of the nodes
 * that it was mounted to.
 * At the present time, the only usage for this routine is in the
 * event one end of a pipe was mounted. At the time the unmounted
 * end gets closed down, the mounted end is forced to be unmounted.
 *
 * This routine searches the namenode hash list for all namenodes
 * that have a nm_filevp field equal to vp. Each time one is found,
 * the dounmount() routine is called. This causes the nm_unmount()
 * routine to be called and thus, the file descriptor is unmounted
 * from the node.
 *
 * At the start of this routine, the reference count for vp is
 * incremented to protect the vnode from being released in the
 * event the mount was the only thing keeping the vnode active.
 * If that is the case, the VOP_CLOSE operation is applied to
 * the vnode, prior to it being released.
 */
static int
nm_umountall(vnode_t *vp, cred_t *crp)
{
	vfs_t *vfsp;
	struct namenode *nodep;
	int error = 0;
	int realerr = 0;

	/*
	 * For each namenode that is associated with the file:
	 * If the v_vfsp field is not namevfs, dounmount it.  Otherwise,
	 * it was created in nm_open() and will be released in time.
	 * The following loop replicates some code from nm_find.  That
	 * routine can't be used as is since the list isn't strictly
	 * consumed as it is traversed.
	 */
	mutex_enter(&ntable_lock);
	nodep = *NM_FILEVP_HASH(vp);
	while (nodep) {
		if (nodep->nm_filevp == vp &&
		    (vfsp = NMTOV(nodep)->v_vfsp) != NULL &&
		    vfsp != &namevfs && (NMTOV(nodep)->v_flag & VROOT)) {

			/*
			 * If the vn_vfswlock fails, skip the vfs since
			 * somebody else may be unmounting it.
			 */
			if (vn_vfswlock(vfsp->vfs_vnodecovered)) {
				realerr = EBUSY;
				nodep = nodep->nm_nextp;
				continue;
			}

			/*
			 * Can't hold ntable_lock across call to do_unmount
			 * because nm_unmount tries to acquire it.  This means
			 * there is a window where another mount of vp can
			 * happen so it is possible that after nm_unmountall
			 * there are still some mounts.  This situation existed
			 * without MT locking because dounmount can sleep
			 * so another mount could happen during that time.
			 * This situation is unlikely and doesn't really cause
			 * any problems.
			 */
			mutex_exit(&ntable_lock);
			if ((error = dounmount(vfsp, 0, crp)) != 0)
				realerr = error;
			mutex_enter(&ntable_lock);
			/*
			 * Since we dropped the ntable_lock, we
			 * have to start over from the beginning.
			 * If for some reasons dounmount() fails,
			 * start from beginning means that we will keep on
			 * trying unless another thread unmounts it for us.
			 */
			nodep = *NM_FILEVP_HASH(vp);
		} else
			nodep = nodep->nm_nextp;
	}
	mutex_exit(&ntable_lock);
	return (realerr);
}

/*
 * Force the unmouting of a file descriptor from ALL of the nodes
 * that it was mounted to.  XXX: fifo_close() calls this routine.
 *
 * nm_umountall() may return EBUSY.
 * nm_unmountall() will keep on trying until it succeeds.
 */
int
nm_unmountall(vnode_t *vp, cred_t *crp)
{
	int error;

	/*
	 * Nm_umuontall() returns only if it succeeds or
	 * return with error EBUSY.  If EBUSY, that means
	 * it cannot acquire the lock on the covered vnode,
	 * and we will keep on trying.
	 */
	for (;;) {
		error = nm_umountall(vp, crp);
		if (error != EBUSY)
			break;
		delay(1);	/* yield cpu briefly, then try again */
	}
	return (error);
}

/*
 * Mount a file descriptor onto the node in the file system.
 * Create a new vnode, update the attributes with info from the
 * file descriptor and the mount point.  The mask, mode, uid, gid,
 * atime, mtime and ctime are taken from the mountpt.  Link count is
 * set to one, the file system id is namedev and nodeid is unique
 * for each mounted object.  Other attributes are taken from mount point.
 * Make sure user is owner (or root) with write permissions on mount point.
 * Hash the new vnode and return 0.
 * Upon entry to this routine, the file descriptor is in the
 * fd field of a struct namefd.  Copy that structure from user
 * space and retrieve the file descriptor.
 */
static int
nm_mount(vfs_t *vfsp, vnode_t *mvp, struct mounta *uap, cred_t *crp)
{
	struct namefd namefdp;
	struct vnode *filevp;		/* file descriptor vnode */
	struct file *fp;
	struct vnode *newvp;		/* vnode representing this mount */
	struct vnode *rvp;		/* realvp (if any) for the mountpt */
	struct namenode *nodep;		/* namenode for this mount */
	struct vattr filevattr;		/* attributes of file dec.  */
	struct vattr *vattrp;		/* attributes of this mount */
	char *resource_name;
	char *resource_nodetype;
	statvfs64_t *svfsp;
	int error = 0;

	/*
	 * Get the file descriptor from user space.
	 * Make sure the file descriptor is valid and has an
	 * associated file pointer.
	 * If so, extract the vnode from the file pointer.
	 */
	if (uap->datalen != sizeof (struct namefd))
		return (EINVAL);

	if (copyin(uap->dataptr, &namefdp, uap->datalen))
		return (EFAULT);

	if ((fp = getf(namefdp.fd)) == NULL)
		return (EBADF);

	/*
	 * If the mount point already has something mounted
	 * on it, disallow this mount.  (This restriction may
	 * be removed in a later release).
	 * Or unmount has completed but the namefs ROOT vnode
	 * count has not decremented to zero, disallow this mount.
	 */

	mutex_enter(&mvp->v_lock);
	if ((mvp->v_flag & VROOT) ||
	    vfs_matchops(mvp->v_vfsp, namefs_vfsops)) {
		mutex_exit(&mvp->v_lock);
		releasef(namefdp.fd);
		return (EBUSY);
	}
	mutex_exit(&mvp->v_lock);

	/*
	 * Cannot allow users to fattach() in /dev/pts.
	 * First, there is no need for doing so and secondly
	 * we cannot allow arbitrary users to park on a node in
	 * /dev/pts or /dev/vt.
	 */
	rvp = NULLVP;
	if (vn_matchops(mvp, spec_getvnodeops()) &&
	    VOP_REALVP(mvp, &rvp, NULL) == 0 && rvp &&
	    (vn_matchops(rvp, devpts_getvnodeops()) ||
	    vn_matchops(rvp, devvt_getvnodeops()))) {
		releasef(namefdp.fd);
		return (ENOTSUP);
	}

	filevp = fp->f_vnode;
	if (filevp->v_type == VDIR || filevp->v_type == VPORT) {
		releasef(namefdp.fd);
		return (EINVAL);
	}

	/*
	 * If the fd being mounted refers to neither a door nor a stream,
	 * make sure the caller is privileged.
	 */
	if (filevp->v_type != VDOOR && filevp->v_stream == NULL) {
		if (secpolicy_fs_mount(crp, filevp, vfsp) != 0) {
			/* fd is neither a stream nor a door */
			releasef(namefdp.fd);
			return (EINVAL);
		}
	}

	/*
	 * Make sure the file descriptor is not the root of some
	 * file system.
	 * If it's not, create a reference and allocate a namenode
	 * to represent this mount request.
	 */
	if (filevp->v_flag & VROOT) {
		releasef(namefdp.fd);
		return (EBUSY);
	}

	nodep = kmem_zalloc(sizeof (struct namenode), KM_SLEEP);

	mutex_init(&nodep->nm_lock, NULL, MUTEX_DEFAULT, NULL);
	vattrp = &nodep->nm_vattr;
	vattrp->va_mask = AT_ALL;
	if (error = VOP_GETATTR(mvp, vattrp, 0, crp, NULL))
		goto out;

	filevattr.va_mask = AT_ALL;
	if (error = VOP_GETATTR(filevp, &filevattr, 0, crp, NULL))
		goto out;
	/*
	 * Make sure the user is the owner of the mount point
	 * or has sufficient privileges.
	 */
	if (error = secpolicy_vnode_owner(crp, vattrp->va_uid))
		goto out;

	/*
	 * Make sure the user has write permissions on the
	 * mount point (or has sufficient privileges).
	 */
	if (secpolicy_vnode_access2(crp, mvp, vattrp->va_uid, vattrp->va_mode,
	    VWRITE) != 0) {
		error = EACCES;
		goto out;
	}

	/*
	 * If the file descriptor has file/record locking, don't
	 * allow the mount to succeed.
	 */
	if (vn_has_flocks(filevp)) {
		error = EACCES;
		goto out;
	}

	/*
	 * Initialize the namenode.
	 */
	if (filevp->v_stream) {
		struct stdata *stp = filevp->v_stream;
		mutex_enter(&stp->sd_lock);
		stp->sd_flag |= STRMOUNT;
		mutex_exit(&stp->sd_lock);
	}
	nodep->nm_filevp = filevp;
	mutex_enter(&fp->f_tlock);
	fp->f_count++;
	mutex_exit(&fp->f_tlock);

	releasef(namefdp.fd);
	nodep->nm_filep = fp;
	nodep->nm_mountpt = mvp;

	/*
	 * The attributes for the mounted file descriptor were initialized
	 * above by applying VOP_GETATTR to the mount point.  Some of
	 * the fields of the attributes structure will be overwritten
	 * by the attributes from the file descriptor.
	 */
	vattrp->va_type    = filevattr.va_type;
	vattrp->va_fsid    = namedev;
	vattrp->va_nodeid  = namenodeno_alloc();
	vattrp->va_nlink   = 1;
	vattrp->va_size    = filevattr.va_size;
	vattrp->va_rdev    = filevattr.va_rdev;
	vattrp->va_blksize = filevattr.va_blksize;
	vattrp->va_nblocks = filevattr.va_nblocks;
	vattrp->va_seq	   = 0;

	/*
	 * Initialize new vnode structure for the mounted file descriptor.
	 */
	nodep->nm_vnode = vn_alloc(KM_SLEEP);
	newvp = NMTOV(nodep);

	newvp->v_flag = filevp->v_flag | VROOT | VNOMAP | VNOSWAP;
	vn_setops(newvp, nm_vnodeops);
	newvp->v_vfsp = vfsp;
	newvp->v_stream = filevp->v_stream;
	newvp->v_type = filevp->v_type;
	newvp->v_rdev = filevp->v_rdev;
	newvp->v_data = (caddr_t)nodep;
	VFS_HOLD(vfsp);
	vn_exists(newvp);

	/*
	 * Initialize the vfs structure.
	 */
	vfsp->vfs_vnodecovered = NULL;
	vfsp->vfs_flag |= VFS_UNLINKABLE;
	vfsp->vfs_bsize = 1024;
	vfsp->vfs_fstype = namefstype;
	vfs_make_fsid(&vfsp->vfs_fsid, namedev, namefstype);
	vfsp->vfs_data = (caddr_t)nodep;
	vfsp->vfs_dev = namedev;
	vfsp->vfs_bcount = 0;

	/*
	 * Set the name we mounted from.
	 */
	switch (filevp->v_type) {
	case VPROC:	/* VOP_GETATTR() translates this to VREG */
	case VREG:	resource_nodetype = "file"; break;
	case VDIR:	resource_nodetype = "directory"; break;
	case VBLK:	resource_nodetype = "device"; break;
	case VCHR:	resource_nodetype = "device"; break;
	case VLNK:	resource_nodetype = "link"; break;
	case VFIFO:	resource_nodetype = "fifo"; break;
	case VDOOR:	resource_nodetype = "door"; break;
	case VSOCK:	resource_nodetype = "socket"; break;
	default:	resource_nodetype = "resource"; break;
	}

#define	RESOURCE_NAME_SZ 128 /* Maximum length of the resource name */
	resource_name = kmem_alloc(RESOURCE_NAME_SZ, KM_SLEEP);
	svfsp = kmem_alloc(sizeof (statvfs64_t), KM_SLEEP);

	error = VFS_STATVFS(filevp->v_vfsp, svfsp);
	if (error == 0) {
		(void) snprintf(resource_name, RESOURCE_NAME_SZ,
		    "unspecified_%s_%s", svfsp->f_basetype, resource_nodetype);
	} else {
		(void) snprintf(resource_name, RESOURCE_NAME_SZ,
		    "unspecified_%s", resource_nodetype);
	}

	vfs_setresource(vfsp, resource_name, 0);

	kmem_free(svfsp, sizeof (statvfs64_t));
	kmem_free(resource_name, RESOURCE_NAME_SZ);
#undef RESOURCE_NAME_SZ

	/*
	 * Insert the namenode.
	 */
	mutex_enter(&ntable_lock);
	nameinsert(nodep);
	mutex_exit(&ntable_lock);
	return (0);
out:
	releasef(namefdp.fd);
	kmem_free(nodep, sizeof (struct namenode));
	return (error);
}

/*
 * Unmount a file descriptor from a node in the file system.
 * If the user is not the owner of the file and is not privileged,
 * the request is denied.
 * Otherwise, remove the namenode from the hash list.
 * If the mounted file descriptor was that of a stream and this
 * was the last mount of the stream, turn off the STRMOUNT flag.
 * If the rootvp is referenced other than through the mount,
 * nm_inactive will clean up.
 */
static int
nm_unmount(vfs_t *vfsp, int flag, cred_t *crp)
{
	struct namenode *nodep = (struct namenode *)vfsp->vfs_data;
	vnode_t *vp, *thisvp;
	struct file *fp = NULL;

	ASSERT((nodep->nm_flag & NMNMNT) == 0);

	/*
	 * forced unmount is not supported by this file system
	 * and thus, ENOTSUP, is being returned.
	 */
	if (flag & MS_FORCE) {
		return (ENOTSUP);
	}

	vp = nodep->nm_filevp;
	mutex_enter(&nodep->nm_lock);
	if (secpolicy_vnode_owner(crp, nodep->nm_vattr.va_uid) != 0) {
		mutex_exit(&nodep->nm_lock);
		return (EPERM);
	}

	mutex_exit(&nodep->nm_lock);

	mutex_enter(&ntable_lock);
	nameremove(nodep);
	thisvp = NMTOV(nodep);
	mutex_enter(&thisvp->v_lock);
	if (thisvp->v_count-- == 1) {
		fp = nodep->nm_filep;
		mutex_exit(&thisvp->v_lock);
		vn_invalid(thisvp);
		vn_free(thisvp);
		VFS_RELE(vfsp);
		namenodeno_free(nodep->nm_vattr.va_nodeid);
		kmem_free(nodep, sizeof (struct namenode));
	} else {
		thisvp->v_flag &= ~VROOT;
		mutex_exit(&thisvp->v_lock);
	}
	if (namefind(vp, NULLVP) == NULL && vp->v_stream) {
		struct stdata *stp = vp->v_stream;
		mutex_enter(&stp->sd_lock);
		stp->sd_flag &= ~STRMOUNT;
		mutex_exit(&stp->sd_lock);
	}
	mutex_exit(&ntable_lock);
	if (fp != NULL)
		(void) closef(fp);
	return (0);
}

/*
 * Create a reference to the root of a mounted file descriptor.
 * This routine is called from lookupname() in the event a path
 * is being searched that has a mounted file descriptor in it.
 */
static int
nm_root(vfs_t *vfsp, vnode_t **vpp)
{
	struct namenode *nodep = (struct namenode *)vfsp->vfs_data;
	struct vnode *vp = NMTOV(nodep);

	VN_HOLD(vp);
	*vpp = vp;
	return (0);
}

/*
 * Return in sp the status of this file system.
 */
static int
nm_statvfs(vfs_t *vfsp, struct statvfs64 *sp)
{
	dev32_t d32;

	bzero(sp, sizeof (*sp));
	sp->f_bsize	= 1024;
	sp->f_frsize	= 1024;
	(void) cmpldev(&d32, vfsp->vfs_dev);
	sp->f_fsid = d32;
	(void) strcpy(sp->f_basetype, vfssw[vfsp->vfs_fstype].vsw_name);
	sp->f_flag	= vf_to_stf(vfsp->vfs_flag);
	return (0);
}

/*
 * Since this file system has no disk blocks of its own, apply
 * the VOP_FSYNC operation on the mounted file descriptor.
 */
static int
nm_sync(vfs_t *vfsp, short flag, cred_t *crp)
{
	struct namenode *nodep;

	if (vfsp == NULL)
		return (0);

	nodep = (struct namenode *)vfsp->vfs_data;
	if (flag & SYNC_CLOSE)
		return (nm_umountall(nodep->nm_filevp, crp));

	return (VOP_FSYNC(nodep->nm_filevp, FSYNC, crp, NULL));
}

/*
 * File system initialization routine. Save the file system type,
 * establish a file system device number and initialize nm_filevp_hash[].
 */
int
nameinit(int fstype, char *name)
{
	static const fs_operation_def_t nm_vfsops_template[] = {
		VFSNAME_MOUNT,		{ .vfs_mount = nm_mount },
		VFSNAME_UNMOUNT,	{ .vfs_unmount = nm_unmount },
		VFSNAME_ROOT,		{ .vfs_root = nm_root },
		VFSNAME_STATVFS,	{ .vfs_statvfs = nm_statvfs },
		VFSNAME_SYNC,		{ .vfs_sync = nm_sync },
		NULL,			NULL
	};
	static const fs_operation_def_t nm_dummy_vfsops_template[] = {
		VFSNAME_STATVFS,	{ .vfs_statvfs = nm_statvfs },
		VFSNAME_SYNC,		{ .vfs_sync = nm_sync },
		NULL,			NULL
	};
	int error;
	int dev;
	vfsops_t *dummy_vfsops;

	error = vfs_setfsops(fstype, nm_vfsops_template, &namefs_vfsops);
	if (error != 0) {
		cmn_err(CE_WARN, "nameinit: bad vfs ops template");
		return (error);
	}

	error = vfs_makefsops(nm_dummy_vfsops_template, &dummy_vfsops);
	if (error != 0) {
		(void) vfs_freevfsops_by_type(fstype);
		cmn_err(CE_WARN, "nameinit: bad dummy vfs ops template");
		return (error);
	}

	error = vn_make_ops(name, nm_vnodeops_template, &nm_vnodeops);
	if (error != 0) {
		(void) vfs_freevfsops_by_type(fstype);
		vfs_freevfsops(dummy_vfsops);
		cmn_err(CE_WARN, "nameinit: bad vnode ops template");
		return (error);
	}

	namefstype = fstype;

	if ((dev = getudev()) == (major_t)-1) {
		cmn_err(CE_WARN, "nameinit: can't get unique device");
		dev = 0;
	}
	mutex_init(&ntable_lock, NULL, MUTEX_DEFAULT, NULL);
	namedev = makedevice(dev, 0);
	bzero(nm_filevp_hash, sizeof (nm_filevp_hash));
	vfs_setops(&namevfs, dummy_vfsops);
	namevfs.vfs_vnodecovered = NULL;
	namevfs.vfs_bsize = 1024;
	namevfs.vfs_fstype = namefstype;
	vfs_make_fsid(&namevfs.vfs_fsid, namedev, namefstype);
	namevfs.vfs_dev = namedev;
	return (0);
}

static mntopts_t nm_mntopts = {
	NULL,
	0
};

static vfsdef_t vfw = {
	VFSDEF_VERSION,
	"namefs",
	nameinit,
	VSW_HASPROTO | VSW_ZMOUNT,
	&nm_mntopts
};

/*
 * Module linkage information for the kernel.
 */
static struct modlfs modlfs = {
	&mod_fsops, "filesystem for namefs", &vfw
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlfs, NULL
};

int
_init(void)
{
	namenodeno_init();
	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	return (EBUSY);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
