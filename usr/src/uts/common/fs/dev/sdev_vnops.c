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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright (c) 2013, Joyent, Inc.  All rights reserved.
 */

/*
 * vnode ops for the /dev filesystem
 *
 * - VDIR, VCHR, CBLK, and VLNK are considered must supported files
 * - VREG and VDOOR are used for some internal implementations in
 *    the global zone, e.g. devname and devfsadm communication
 * - other file types are unusual in this namespace and
 *    not supported for now
 */

/*
 * sdev has a few basic goals:
 *   o Provide /dev for the global zone as well as various non-global zones.
 *   o Provide the basic functionality that devfsadm might need (mknod,
 *     symlinks, etc.)
 *   o Allow persistent permissions on files in /dev.
 *   o Allow for dynamic directories and nodes for use by various services (pts,
 *     zvol, net, etc.)
 *
 * The sdev file system is primarily made up of sdev_node_t's which is sdev's
 * counterpart to the vnode_t. There are two different classes of sdev_node_t's
 * that we generally care about, dynamic and otherwise.
 *
 * Persisting Information
 * ----------------------
 *
 * When sdev is mounted, it keeps track of the underlying file system it is
 * mounted over. In certain situations, sdev will go and create entries in that
 * underlying file system. These underlying 'back end' nodes are used as proxies
 * for various changes in permissions. While specific sets of nodes, such as
 * dynamic ones, are exempt, this process stores permission changes against
 * these back end nodes. The point of all of this is to allow for these settings
 * to persist across host and zone reboots. As an example, consider the entry
 * /dev/dsk/c0t0d0 which is a character device and that / is in UFS. Upon
 * changing the permissions on c0t0d0 you'd have the following logical
 * relationships:
 *
 *    +------------------+   sdev_vnode     +--------------+
 *    | sdev_node_t      |<---------------->| vnode_t      |
 *    | /dev/dsk/c0t0d0  |<---------------->| for sdev     |
 *    +------------------+                  +--------------+
 *           |
 *           | sdev_attrvp
 *           |
 *           |    +---------------------+
 *           +--->| vnode_t for UFS|ZFS |
 *                | /dev/dsk/c0t0d0     |
 *                +---------------------+
 *
 * sdev is generally in memory. Therefore when a lookup happens and there is no
 * entry already inside of a directory cache, it will next check the backing
 * store. If the backing store exists, we will reconstitute the sdev_node based
 * on the information that we persisted. When we create the backing store node,
 * we use the struct vattr information that we already have in sdev_node_t.
 * Because of this, we already know if the entry was previously a symlink,
 * directory, or some other kind of type. Note that not all types of nodes are
 * supported. Currently only VDIR, VCHR, VBLK, VREG, VDOOR, and VLNK are
 * eligible to be persisted.
 *
 * When the sdev_node is created and the lookup is done, we grab a hold on the
 * underlying vnode as part of the call to VOP_LOOKUP. That reference is held
 * until the sdev_node becomes inactive. Once its reference count reaches one
 * and the VOP_INACTIVE callback fires leading to the destruction of the node,
 * the reference on the underlying vnode will be released.
 *
 * The backing store node will be deleted only when the node itself is deleted
 * through the means of a VOP_REMOVE, VOP_RMDIR, or similar call.
 *
 * Not everything can be persisted, see The Rules section for more details.
 *
 * Dynamic Nodes
 * -------------
 *
 * Dynamic nodes allow for specific interactions with various kernel subsystems
 * when looking up directory entries. This allows the lookup and readdir
 * functions to check against the kernel subsystem's for validity. eg. does a
 * zvol or nic still exist.
 *
 * More specifically, when we create various directories we check if the
 * directory name matches that of one of the names in the vtab[] (sdev_subr.c).
 * If it does, we swap out the vnode operations into a new set which combine the
 * normal sdev vnode operations with the dynamic set here.
 *
 * In addition, various dynamic nodes implement a verification entry point. This
 * verification entry is used as a part of lookup and readdir. The goal for
 * these dynamic nodes is to allow them to check with the underlying subsystems
 * to ensure that these devices are still present, or if they have gone away, to
 * remove them from the results. This is indicated by using the SDEV_VTOR flag
 * in vtab[].
 *
 * Dynamic nodes have additional restrictions placed upon them. They may only
 * appear at the top level directory of the file system. In addition, users
 * cannot create dirents below any leve of a dynamic node aside from its special
 * vnops.
 *
 * Profiles
 * --------
 *
 * Profiles exist for the purpose of non-global zones. They work with the zone
 * brands and zoneadmd to set up a filter of allowed devices that can appear in
 * a non-global zone's /dev. These are sent to sdev by means of libdevinfo and a
 * modctl system call. Specifically it allows one to add patterns of device
 * paths to include and exclude. It allows for a collection of symlinks to be
 * added and it allows for remapping names.
 *
 * When operating in a non-global zone, several of the sdev vnops are redirected
 * to the profile versions. These impose additional restrictions such as
 * enforcing that a non-global zone's /dev is read only.
 *
 * sdev_node_t States
 * ------------------
 *
 * A given sdev_node_t has a field called the sdev_state which describes where
 * in the sdev life cycle it is. There are three primary states: SDEV_INIT,
 * SDEV_READY, and SDEV_ZOMBIE.
 *
 *	SDEV_INIT: When a new /dev file is first looked up, a sdev_node
 *		   is allocated, initialized and added to the directory's
 *		   sdev_node cache. A node at this state will also
 *		   have the SDEV_LOOKUP flag set.
 *
 *		   Other threads that are trying to look up a node at
 *		   this state will be blocked until the SDEV_LOOKUP flag
 *		   is cleared.
 *
 *		   When the SDEV_LOOKUP flag is cleared, the node may
 *		   transition into the SDEV_READY state for a successful
 *		   lookup or the node is removed from the directory cache
 *		   and destroyed if the named node can not be found.
 *		   An ENOENT error is returned for the second case.
 *
 *	SDEV_READY: A /dev file has been successfully looked up and
 *		    associated with a vnode. The /dev file is available
 *		    for the supported /dev file system operations.
 *
 *	SDEV_ZOMBIE: Deletion of a /dev file has been explicitly issued
 *		    to an SDEV_READY node. The node is transitioned into
 *		    the SDEV_ZOMBIE state if the vnode reference count
 *		    is still held. A SDEV_ZOMBIE node does not support
 *		    any of the /dev file system operations. A SDEV_ZOMBIE
 *		    node is immediately removed from the directory cache
 *		    and destroyed once the reference count reaches zero.
 *
 * Historically nodes that were marked SDEV_ZOMBIE were not removed from the
 * underlying directory caches. This has been the source of numerous bugs and
 * thus to better mimic what happens on a real file system, it is no longer the
 * case.
 *
 * The following state machine describes the life cycle of a given node and its
 * associated states:
 *
 * node is . . . . .
 * allocated via   .     +-------------+         . . . . . . . vnode_t refcount
 * sdev_nodeinit() .     | Unallocated |         .             reaches zero and
 *        +--------*-----|   Memory    |<--------*---+         sdev_inactive is
 *        |              +-------------+             |         called.
 *        |       +------------^                     |         called.
 *        v       |                                  |
 *  +-----------+ * . . sdev_nodeready()      +-------------+
 *  | SDEV_INIT | |     or related setup      | SDEV_ZOMBIE |
 *  +-----------+ |     failure               +-------------+
 *        |       |                                  ^
 *        |       |      +------------+              |
 *        +-*----------->| SDEV_READY |--------*-----+
 *          .            +------------+        .          The node is no longer
 *          . . node successfully              . . . . .  valid or we've been
 *              inserted into the                         asked to remove it.
 *              directory cache                           This happens via
 *              and sdev_nodready()                       sdev_dirdelete().
 *              call successful.
 *
 * Adding and Removing Dirents, Zombie Nodes
 * -----------------------------------------
 *
 * As part of doing a lookup, readdir, or an explicit creation operation like
 * mkdir or create, nodes may be created. Every directory has an avl tree which
 * contains its children, the sdev_entries tree. This is only used if the type
 * is VDIR. Access to this is controlled by the sdev_node_t's contents_lock and
 * it is managed through sdev_cache_update().
 *
 * Every sdev_node_t has a field sdev_state, which describes the current state
 * of the node. A node is generally speaking in the SDEV_READY state. When it is
 * there, it can be looked up, accessed, and operations performed on it. When a
 * node is going to be removed from the directory cache it is marked as a
 * zombie. Once a node becomes a zombie, no other file system operations will
 * succeed and it will continue to exist as a node until the vnode count on the
 * node reaches zero. At that point, the node will be freed.  However, once a
 * node has been marked as a zombie, it will be removed immediately from the
 * directory cache such that no one else may find it again.  This means that
 * someone else can insert a new entry into that directory with the same name
 * and without a problem.
 *
 * To remove a node, see the section on that in The Rules.
 *
 * The Rules
 * ---------
 * These are the rules to live by when working in sdev. These are not
 * exhaustive.
 *
 * - Set 1: Working with Backing Nodes
 *   o If there is a SDEV_READY sdev_node_t, it knows about its backing node.
 *   o If we find a backing node when looking up an sdev_node_t for the first
 *     time, we use its attributes to build our sdev_node_t.
 *   o If there is a found backing node, or we create a backing node, that's
 *     when we grab the hold on its vnode.
 *   o If we mark an sdev_node_t a ZOMBIE, we must remove its backing node from
 *     the underlying file system. It must not be searchable or findable.
 *   o We release our hold on the backing node vnode when we destroy the
 *     sdev_node_t.
 *
 * - Set 2: Locking rules for sdev (not exhaustive)
 *   o The majority of nodes contain an sdev_contents rw lock. You must hold it
 *     for read or write if manipulating its contents appropriately.
 *   o You must lock your parent before yourself.
 *   o If you need your vnode's v_lock and the sdev_contents rw lock, you must
 *     grab the v_lock before the sdev_contents rw_lock.
 *   o If you release a lock on the node as a part of upgrading it, you must
 *     verify that the node has not become a zombie as a part of this process.
 *
 * - Set 3: Zombie Status and What it Means
 *   o If you encounter a node that is a ZOMBIE, that means that it has been
 *     unlinked from the backing store.
 *   o If you release your contents lock and acquire it again (say as part of
 *     trying to grab a write lock) you must check that the node has not become
 *     a zombie.
 *   o You should VERIFY that a looked up node is not a zombie. This follows
 *     from the following logic. To mark something as a zombie means that it is
 *     removed from the parents directory cache. To do that, you must have a
 *     write lock on the parent's sdev_contents. To lookup through that
 *     directory you must have a read lock. This then becomes a simple ordering
 *     problem. If you've been granted the lock then the other operation cannot
 *     be in progress or must have already succeeded.
 *
 * - Set 4: Removing Directory Entries (aka making nodes Zombies)
 *   o Write lock must be held on the directory
 *   o Write lock must be held on the node
 *   o Remove the sdev_node_t from its parent cache
 *   o Remove the corresponding backing store node, if it exists, eg. use
 *     VOP_REMOVE or VOP_RMDIR.
 *   o You must NOT make any change in the vnode reference count! Nodes should
 *     only be cleaned up through VOP_INACTIVE callbacks.
 *   o VOP_INACTIVE is the only one responsible for doing the final vn_rele of
 *     the backing store vnode that was grabbed during lookup.
 *
 * - Set 5: What Nodes may be Persisted
 *   o The root, /dev is always persisted
 *   o Any node in vtab which is marked SDEV_DYNAMIC, may not be persisted
 *     unless it is also marked SDEV_PERSIST
 *   o Anything whose parent directory is marked SDEV_PERSIST will pass that
 *     along to the child as long as it does not contradict the above rules
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/t_lock.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/user.h>
#include <sys/time.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/vfs_opreg.h>
#include <sys/file.h>
#include <sys/fcntl.h>
#include <sys/flock.h>
#include <sys/kmem.h>
#include <sys/uio.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/cred.h>
#include <sys/dirent.h>
#include <sys/pathname.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/policy.h>
#include <vm/hat.h>
#include <vm/seg_vn.h>
#include <vm/seg_map.h>
#include <vm/seg.h>
#include <vm/as.h>
#include <vm/page.h>
#include <sys/proc.h>
#include <sys/mode.h>
#include <sys/sunndi.h>
#include <sys/ptms.h>
#include <fs/fs_subr.h>
#include <sys/fs/dv_node.h>
#include <sys/fs/sdev_impl.h>

/*ARGSUSED*/
static int
sdev_open(struct vnode **vpp, int flag, struct cred *cred, caller_context_t *ct)
{
	struct sdev_node *dv = VTOSDEV(*vpp);
	struct sdev_node *ddv = dv->sdev_dotdot;
	int error = 0;

	if ((*vpp)->v_type == VDIR)
		return (0);

	if (!SDEV_IS_GLOBAL(dv))
		return (ENOTSUP);

	if ((*vpp)->v_type == VLNK)
		return (ENOENT);
	ASSERT((*vpp)->v_type == VREG);
	if ((*vpp)->v_type != VREG)
		return (ENOTSUP);

	ASSERT(ddv);
	rw_enter(&ddv->sdev_contents, RW_READER);
	if (dv->sdev_attrvp == NULL) {
		rw_exit(&ddv->sdev_contents);
		return (ENOENT);
	}
	error = VOP_OPEN(&(dv->sdev_attrvp), flag, cred, ct);
	rw_exit(&ddv->sdev_contents);
	return (error);
}

/*ARGSUSED1*/
static int
sdev_close(struct vnode *vp, int flag, int count,
    offset_t offset, struct cred *cred, caller_context_t *ct)
{
	struct sdev_node *dv = VTOSDEV(vp);

	if (vp->v_type == VDIR) {
		cleanlocks(vp, ttoproc(curthread)->p_pid, 0);
		cleanshares(vp, ttoproc(curthread)->p_pid);
		return (0);
	}

	if (!SDEV_IS_GLOBAL(dv))
		return (ENOTSUP);

	ASSERT(vp->v_type == VREG);
	if (vp->v_type != VREG)
		return (ENOTSUP);

	ASSERT(dv->sdev_attrvp);
	return (VOP_CLOSE(dv->sdev_attrvp, flag, count, offset, cred, ct));
}

/*ARGSUSED*/
static int
sdev_read(struct vnode *vp, struct uio *uio, int ioflag, struct cred *cred,
	struct caller_context *ct)
{
	struct sdev_node *dv = (struct sdev_node *)VTOSDEV(vp);
	int	error;

	if (!SDEV_IS_GLOBAL(dv))
		return (EINVAL);

	if (vp->v_type == VDIR)
		return (EISDIR);

	/* only supporting regular files in /dev */
	ASSERT(vp->v_type == VREG);
	if (vp->v_type != VREG)
		return (EINVAL);

	ASSERT(RW_READ_HELD(&VTOSDEV(vp)->sdev_contents));
	ASSERT(dv->sdev_attrvp);
	(void) VOP_RWLOCK(dv->sdev_attrvp, 0, ct);
	error = VOP_READ(dv->sdev_attrvp, uio, ioflag, cred, ct);
	VOP_RWUNLOCK(dv->sdev_attrvp, 0, ct);
	return (error);
}

/*ARGSUSED*/
static int
sdev_write(struct vnode *vp, struct uio *uio, int ioflag, struct cred *cred,
	struct caller_context *ct)
{
	struct sdev_node *dv = VTOSDEV(vp);
	int	error = 0;

	if (!SDEV_IS_GLOBAL(dv))
		return (EINVAL);

	if (vp->v_type == VDIR)
		return (EISDIR);

	/* only supporting regular files in /dev */
	ASSERT(vp->v_type == VREG);
	if (vp->v_type != VREG)
		return (EINVAL);

	ASSERT(dv->sdev_attrvp);

	(void) VOP_RWLOCK(dv->sdev_attrvp, 1, ct);
	error = VOP_WRITE(dv->sdev_attrvp, uio, ioflag, cred, ct);
	VOP_RWUNLOCK(dv->sdev_attrvp, 1, ct);
	if (error == 0) {
		sdev_update_timestamps(dv->sdev_attrvp, kcred,
		    AT_MTIME);
	}
	return (error);
}

/*ARGSUSED*/
static int
sdev_ioctl(struct vnode *vp, int cmd, intptr_t arg, int flag,
    struct cred *cred, int *rvalp,  caller_context_t *ct)
{
	struct sdev_node *dv = VTOSDEV(vp);

	if (!SDEV_IS_GLOBAL(dv) || (vp->v_type == VDIR))
		return (ENOTTY);

	ASSERT(vp->v_type == VREG);
	if (vp->v_type != VREG)
		return (EINVAL);

	ASSERT(dv->sdev_attrvp);
	return (VOP_IOCTL(dv->sdev_attrvp, cmd, arg, flag, cred, rvalp, ct));
}

static int
sdev_getattr(struct vnode *vp, struct vattr *vap, int flags,
    struct cred *cr, caller_context_t *ct)
{
	int			error = 0;
	struct sdev_node	*dv = VTOSDEV(vp);
	struct sdev_node	*parent = dv->sdev_dotdot;

	ASSERT(parent);

	rw_enter(&parent->sdev_contents, RW_READER);
	ASSERT(dv->sdev_attr || dv->sdev_attrvp);

	/*
	 * search order:
	 * 	- for persistent nodes (SDEV_PERSIST): backstore
	 *	- for non-persistent nodes: module ops if global, then memory
	 */
	if (dv->sdev_attrvp) {
		rw_exit(&parent->sdev_contents);
		error = VOP_GETATTR(dv->sdev_attrvp, vap, flags, cr, ct);
		sdev_vattr_merge(dv, vap);
	} else {
		ASSERT(dv->sdev_attr);
		*vap = *dv->sdev_attr;
		sdev_vattr_merge(dv, vap);
		rw_exit(&parent->sdev_contents);
	}

	return (error);
}

/*ARGSUSED4*/
static int
sdev_setattr(struct vnode *vp, struct vattr *vap, int flags,
    struct cred *cred, caller_context_t *ctp)
{
	return (devname_setattr_func(vp, vap, flags, cred, NULL, 0));
}

static int
sdev_getsecattr(struct vnode *vp, struct vsecattr *vsap, int flags,
    struct cred *cr, caller_context_t *ct)
{
	int	error;
	struct sdev_node *dv = VTOSDEV(vp);
	struct vnode *avp = dv->sdev_attrvp;

	if (avp == NULL) {
		/* return fs_fab_acl() if flavor matches, else do nothing */
		if ((SDEV_ACL_FLAVOR(vp) == _ACL_ACLENT_ENABLED &&
		    (vsap->vsa_mask & (VSA_ACLCNT | VSA_DFACLCNT))) ||
		    (SDEV_ACL_FLAVOR(vp) == _ACL_ACE_ENABLED &&
		    (vsap->vsa_mask & (VSA_ACECNT | VSA_ACE))))
			return (fs_fab_acl(vp, vsap, flags, cr, ct));

		return (ENOSYS);
	}

	(void) VOP_RWLOCK(avp, 1, ct);
	error = VOP_GETSECATTR(avp, vsap, flags, cr, ct);
	VOP_RWUNLOCK(avp, 1, ct);
	return (error);
}

static int
sdev_setsecattr(struct vnode *vp, struct vsecattr *vsap, int flags,
    struct cred *cr, caller_context_t *ct)
{
	int	error;
	struct sdev_node *dv = VTOSDEV(vp);
	struct vnode *avp = dv->sdev_attrvp;

	if (dv->sdev_state == SDEV_ZOMBIE)
		return (0);

	if (avp == NULL) {
		if (SDEV_IS_GLOBAL(dv) && !SDEV_IS_PERSIST(dv))
			return (fs_nosys());
		ASSERT(dv->sdev_attr);
		/*
		 * if coming in directly, the acl system call will
		 * have held the read-write lock via VOP_RWLOCK()
		 * If coming in via specfs, specfs will have
		 * held the rw lock on the realvp i.e. us.
		 */
		ASSERT(RW_WRITE_HELD(&dv->sdev_contents));
		sdev_vattr_merge(dv, dv->sdev_attr);
		error = sdev_shadow_node(dv, cr);
		if (error) {
			return (fs_nosys());
		}

		ASSERT(dv->sdev_attrvp);
		/* clean out the memory copy if any */
		if (dv->sdev_attr) {
			kmem_free(dv->sdev_attr, sizeof (struct vattr));
			dv->sdev_attr = NULL;
		}
		avp = dv->sdev_attrvp;
	}
	ASSERT(avp);

	(void) VOP_RWLOCK(avp, V_WRITELOCK_TRUE, ct);
	error = VOP_SETSECATTR(avp, vsap, flags, cr, ct);
	VOP_RWUNLOCK(avp, V_WRITELOCK_TRUE, ct);
	return (error);
}

int
sdev_unlocked_access(void *vdv, int mode, struct cred *cr)
{
	struct sdev_node	*dv = vdv;
	int			shift = 0;
	uid_t			owner = dv->sdev_attr->va_uid;

	if (crgetuid(cr) != owner) {
		shift += 3;
		if (groupmember(dv->sdev_attr->va_gid, cr) == 0)
			shift += 3;
	}

	return (secpolicy_vnode_access2(cr, SDEVTOV(dv), owner,
	    dv->sdev_attr->va_mode << shift, mode));
}

static int
sdev_access(struct vnode *vp, int mode, int flags, struct cred *cr,
    caller_context_t *ct)
{
	struct sdev_node	*dv = VTOSDEV(vp);
	int ret = 0;

	ASSERT(dv->sdev_attr || dv->sdev_attrvp);

	if (dv->sdev_attrvp) {
		ret = VOP_ACCESS(dv->sdev_attrvp, mode, flags, cr, ct);
	} else if (dv->sdev_attr) {
		rw_enter(&dv->sdev_contents, RW_READER);
		ret = sdev_unlocked_access(dv, mode, cr);
		if (ret)
			ret = EACCES;
		rw_exit(&dv->sdev_contents);
	}

	return (ret);
}

/*
 * Lookup
 */
/*ARGSUSED3*/
static int
sdev_lookup(struct vnode *dvp, char *nm, struct vnode **vpp,
    struct pathname *pnp, int flags, struct vnode *rdir, struct cred *cred,
    caller_context_t *ct, int *direntflags, pathname_t *realpnp)
{
	struct sdev_node *parent;
	int error;

	parent = VTOSDEV(dvp);
	ASSERT(parent);

	/* execute access is required to search the directory */
	if ((error = VOP_ACCESS(dvp, VEXEC, 0, cred, ct)) != 0)
		return (error);

	if (!SDEV_IS_GLOBAL(parent))
		return (prof_lookup(dvp, nm, vpp, cred));
	return (devname_lookup_func(parent, nm, vpp, cred, NULL, 0));
}

/*ARGSUSED2*/
static int
sdev_create(struct vnode *dvp, char *nm, struct vattr *vap, vcexcl_t excl,
    int mode, struct vnode **vpp, struct cred *cred, int flag,
    caller_context_t *ct, vsecattr_t *vsecp)
{
	struct vnode		*vp = NULL;
	struct vnode		*avp;
	struct sdev_node	*parent;
	struct sdev_node	*self = NULL;
	int			error = 0;
	vtype_t			type = vap->va_type;

	ASSERT(type != VNON && type != VBAD);

	if ((type == VFIFO) || (type == VSOCK) ||
	    (type == VPROC) || (type == VPORT))
		return (ENOTSUP);

	parent = VTOSDEV(dvp);
	ASSERT(parent);

	rw_enter(&parent->sdev_dotdot->sdev_contents, RW_READER);
	if (parent->sdev_state == SDEV_ZOMBIE) {
		rw_exit(&parent->sdev_dotdot->sdev_contents);
		return (ENOENT);
	}

	/* non-global do not allow pure node creation */
	if (!SDEV_IS_GLOBAL(parent)) {
		rw_exit(&parent->sdev_dotdot->sdev_contents);
		return (prof_lookup(dvp, nm, vpp, cred));
	}
	rw_exit(&parent->sdev_dotdot->sdev_contents);

	/* execute access is required to search the directory */
	if ((error = VOP_ACCESS(dvp, VEXEC, 0, cred, ct)) != 0)
		return (error);

	/* check existing name */
/* XXXci - We may need to translate the C-I flags on VOP_LOOKUP */
	error = VOP_LOOKUP(dvp, nm, &vp, NULL, 0, NULL, cred, ct, NULL, NULL);

	/* name found */
	if (error == 0) {
		ASSERT(vp);
		if (excl == EXCL) {
			error = EEXIST;
		} else if ((vp->v_type == VDIR) && (mode & VWRITE)) {
			/* allowing create/read-only an existing directory */
			error = EISDIR;
		} else {
			error = VOP_ACCESS(vp, mode, 0, cred, ct);
		}

		if (error) {
			VN_RELE(vp);
			return (error);
		}

		/* truncation first */
		if ((vp->v_type == VREG) && (vap->va_mask & AT_SIZE) &&
		    (vap->va_size == 0)) {
			ASSERT(parent->sdev_attrvp);
			error = VOP_CREATE(parent->sdev_attrvp,
			    nm, vap, excl, mode, &avp, cred, flag, ct, vsecp);

			if (error) {
				VN_RELE(vp);
				return (error);
			}
		}

		sdev_update_timestamps(vp, kcred,
		    AT_CTIME|AT_MTIME|AT_ATIME);
		*vpp = vp;
		return (0);
	}

	/* bail out early */
	if (error != ENOENT)
		return (error);

	/* verify write access - compliance specifies ENXIO */
	if ((error = VOP_ACCESS(dvp, VEXEC|VWRITE, 0, cred, ct)) != 0) {
		if (error == EACCES)
			error = ENXIO;
		return (error);
	}

	/*
	 * For memory-based (ROFS) directory:
	 * 	- either disallow node creation;
	 *	- or implement VOP_CREATE of its own
	 */
	rw_enter(&parent->sdev_contents, RW_WRITER);
	if (!SDEV_IS_PERSIST(parent)) {
		rw_exit(&parent->sdev_contents);
		return (ENOTSUP);
	}
	ASSERT(parent->sdev_attrvp);
	error = sdev_mknode(parent, nm, &self, vap, NULL, NULL,
	    cred, SDEV_READY);
	if (error) {
		rw_exit(&parent->sdev_contents);
		if (self)
			SDEV_RELE(self);
		return (error);
	}
	rw_exit(&parent->sdev_contents);

	ASSERT(self);
	/* take care the timestamps for the node and its parent */
	sdev_update_timestamps(SDEVTOV(self), kcred,
	    AT_CTIME|AT_MTIME|AT_ATIME);
	sdev_update_timestamps(dvp, kcred, AT_MTIME|AT_ATIME);
	if (SDEV_IS_GLOBAL(parent))
		atomic_inc_ulong(&parent->sdev_gdir_gen);

	/* wake up other threads blocked on looking up this node */
	mutex_enter(&self->sdev_lookup_lock);
	SDEV_UNBLOCK_OTHERS(self, SDEV_LOOKUP);
	mutex_exit(&self->sdev_lookup_lock);
	error = sdev_to_vp(self, vpp);
	return (error);
}

static int
sdev_remove(struct vnode *dvp, char *nm, struct cred *cred,
    caller_context_t *ct, int flags)
{
	int	error;
	struct sdev_node *parent = (struct sdev_node *)VTOSDEV(dvp);
	struct vnode *vp = NULL;
	struct sdev_node *dv = NULL;
	int len;
	int bkstore;

	/* bail out early */
	len = strlen(nm);
	if (nm[0] == '.') {
		if (len == 1) {
			return (EINVAL);
		} else if (len == 2 && nm[1] == '.') {
			return (EEXIST);
		}
	}

	ASSERT(parent);
	rw_enter(&parent->sdev_contents, RW_READER);
	if (!SDEV_IS_GLOBAL(parent)) {
		rw_exit(&parent->sdev_contents);
		return (ENOTSUP);
	}

	/* execute access is required to search the directory */
	if ((error = VOP_ACCESS(dvp, VEXEC, 0, cred, ct)) != 0) {
		rw_exit(&parent->sdev_contents);
		return (error);
	}

	/* check existence first */
	dv = sdev_cache_lookup(parent, nm);
	if (dv == NULL) {
		rw_exit(&parent->sdev_contents);
		return (ENOENT);
	}

	vp = SDEVTOV(dv);
	if ((dv->sdev_state == SDEV_INIT) ||
	    (dv->sdev_state == SDEV_ZOMBIE)) {
		rw_exit(&parent->sdev_contents);
		VN_RELE(vp);
		return (ENOENT);
	}

	/* write access is required to remove an entry */
	if ((error = VOP_ACCESS(dvp, VWRITE, 0, cred, ct)) != 0) {
		rw_exit(&parent->sdev_contents);
		VN_RELE(vp);
		return (error);
	}

	bkstore = SDEV_IS_PERSIST(dv) ? 1 : 0;
	if (!rw_tryupgrade(&parent->sdev_contents)) {
		rw_exit(&parent->sdev_contents);
		rw_enter(&parent->sdev_contents, RW_WRITER);
		/* Make sure we didn't become a zombie */
		if (parent->sdev_state == SDEV_ZOMBIE) {
			rw_exit(&parent->sdev_contents);
			VN_RELE(vp);
			return (ENOENT);
		}
	}

	/* we do not support unlinking a non-empty directory */
	if (vp->v_type == VDIR && dv->sdev_nlink > 2) {
		rw_exit(&parent->sdev_contents);
		VN_RELE(vp);
		return (EBUSY);
	}

	/*
	 * sdev_dirdelete does the real job of:
	 *  - make sure no open ref count
	 *  - destroying the sdev_node
	 *  - releasing the hold on attrvp
	 */
	sdev_cache_update(parent, &dv, nm, SDEV_CACHE_DELETE);
	VN_RELE(vp);
	rw_exit(&parent->sdev_contents);

	/*
	 * best efforts clean up the backing store
	 */
	if (bkstore) {
		ASSERT(parent->sdev_attrvp);
		error = VOP_REMOVE(parent->sdev_attrvp, nm, cred,
		    ct, flags);
		/*
		 * do not report BUSY error
		 * because the backing store ref count is released
		 * when the last ref count on the sdev_node is
		 * released.
		 */
		if (error == EBUSY) {
			sdcmn_err2(("sdev_remove: device %s is still on"
			    "disk %s\n", nm, parent->sdev_path));
			error = 0;
		}
	}

	return (error);
}

/*
 * Some restrictions for this file system:
 *  - both oldnm and newnm are in the scope of /dev file system,
 *    to simply the namespace management model.
 */
/*ARGSUSED6*/
static int
sdev_rename(struct vnode *odvp, char *onm, struct vnode *ndvp, char *nnm,
    struct cred *cred, caller_context_t *ct, int flags)
{
	struct sdev_node	*fromparent = NULL;
	struct vattr		vattr;
	struct sdev_node	*toparent;
	struct sdev_node	*fromdv = NULL;	/* source node */
	struct vnode 		*ovp = NULL;	/* source vnode */
	struct sdev_node	*todv = NULL;	/* destination node */
	struct vnode 		*nvp = NULL;	/* destination vnode */
	int			samedir = 0;	/* set if odvp == ndvp */
	struct vnode		*realvp;
	int error = 0;
	dev_t fsid;
	int bkstore = 0;
	vtype_t type;

	/* prevent modifying "." and ".." */
	if ((onm[0] == '.' &&
	    (onm[1] == '\0' || (onm[1] == '.' && onm[2] == '\0'))) ||
	    (nnm[0] == '.' &&
	    (nnm[1] == '\0' || (nnm[1] == '.' && nnm[2] == '\0')))) {
		return (EINVAL);
	}

	fromparent = VTOSDEV(odvp);
	toparent = VTOSDEV(ndvp);

	/* ZOMBIE parent doesn't allow new node creation */
	rw_enter(&fromparent->sdev_dotdot->sdev_contents, RW_READER);
	if (fromparent->sdev_state == SDEV_ZOMBIE) {
		rw_exit(&fromparent->sdev_dotdot->sdev_contents);
		return (ENOENT);
	}

	/* renaming only supported for global device nodes */
	if (!SDEV_IS_GLOBAL(fromparent)) {
		rw_exit(&fromparent->sdev_dotdot->sdev_contents);
		return (ENOTSUP);
	}
	rw_exit(&fromparent->sdev_dotdot->sdev_contents);

	rw_enter(&toparent->sdev_dotdot->sdev_contents, RW_READER);
	if (toparent->sdev_state == SDEV_ZOMBIE) {
		rw_exit(&toparent->sdev_dotdot->sdev_contents);
		return (ENOENT);
	}
	rw_exit(&toparent->sdev_dotdot->sdev_contents);

	/*
	 * acquire the global lock to prevent
	 * mount/unmount/other rename activities.
	 */
	mutex_enter(&sdev_lock);

	/* check existence of the source node */
/* XXXci - We may need to translate the C-I flags on VOP_LOOKUP */
	error = VOP_LOOKUP(odvp, onm, &ovp, NULL, 0, NULL, cred, ct,
	    NULL, NULL);
	if (error) {
		sdcmn_err2(("sdev_rename: the source node %s exists\n",
		    onm));
		mutex_exit(&sdev_lock);
		return (error);
	}

	if (VOP_REALVP(ovp, &realvp, ct) == 0) {
		VN_HOLD(realvp);
		VN_RELE(ovp);
		ovp = realvp;
	}

	/* check existence of destination */
/* XXXci - We may need to translate the C-I flags on VOP_LOOKUP */
	error = VOP_LOOKUP(ndvp, nnm, &nvp, NULL, 0, NULL, cred, ct,
	    NULL, NULL);
	if (error && (error != ENOENT)) {
		mutex_exit(&sdev_lock);
		VN_RELE(ovp);
		return (error);
	}

	if (nvp && (VOP_REALVP(nvp, &realvp, ct) == 0)) {
		VN_HOLD(realvp);
		VN_RELE(nvp);
		nvp = realvp;
	}

	/*
	 * make sure the source and the destination are
	 * in the same dev filesystem
	 */
	if (odvp != ndvp) {
		vattr.va_mask = AT_FSID;
		if (error = VOP_GETATTR(odvp, &vattr, 0, cred, ct)) {
			mutex_exit(&sdev_lock);
			VN_RELE(ovp);
			if (nvp != NULL)
				VN_RELE(nvp);
			return (error);
		}
		fsid = vattr.va_fsid;
		vattr.va_mask = AT_FSID;
		if (error = VOP_GETATTR(ndvp, &vattr, 0, cred, ct)) {
			mutex_exit(&sdev_lock);
			VN_RELE(ovp);
			if (nvp != NULL)
				VN_RELE(nvp);
			return (error);
		}
		if (fsid != vattr.va_fsid) {
			mutex_exit(&sdev_lock);
			VN_RELE(ovp);
			if (nvp != NULL)
				VN_RELE(nvp);
			return (EXDEV);
		}
	}

	/* make sure the old entry can be deleted */
	error = VOP_ACCESS(odvp, VWRITE, 0, cred, ct);
	if (error) {
		mutex_exit(&sdev_lock);
		VN_RELE(ovp);
		if (nvp != NULL)
			VN_RELE(nvp);
		return (error);
	}

	/* make sure the destination allows creation */
	samedir = (fromparent == toparent);
	if (!samedir) {
		error = VOP_ACCESS(ndvp, VEXEC|VWRITE, 0, cred, ct);
		if (error) {
			mutex_exit(&sdev_lock);
			VN_RELE(ovp);
			if (nvp != NULL)
				VN_RELE(nvp);
			return (error);
		}
	}

	fromdv = VTOSDEV(ovp);
	ASSERT(fromdv);

	/* destination file exists */
	if (nvp != NULL) {
		todv = VTOSDEV(nvp);
		ASSERT(todv);
	}

	if ((fromdv->sdev_flags & SDEV_DYNAMIC) != 0 ||
	    (todv != NULL && (todv->sdev_flags & SDEV_DYNAMIC) != 0)) {
		mutex_exit(&sdev_lock);
		if (nvp != NULL)
			VN_RELE(nvp);
		VN_RELE(ovp);
		return (EACCES);
	}

	/*
	 * link source to new target in the memory. Regardless of failure, we
	 * must rele our hold on nvp.
	 */
	error = sdev_rnmnode(fromparent, fromdv, toparent, &todv, nnm, cred);
	if (nvp != NULL)
		VN_RELE(nvp);
	if (error) {
		sdcmn_err2(("sdev_rename: renaming %s to %s failed "
		    " with error %d\n", onm, nnm, error));
		mutex_exit(&sdev_lock);
		VN_RELE(ovp);
		return (error);
	}

	/*
	 * unlink from source
	 */
	rw_enter(&fromparent->sdev_contents, RW_READER);
	fromdv = sdev_cache_lookup(fromparent, onm);
	if (fromdv == NULL) {
		rw_exit(&fromparent->sdev_contents);
		mutex_exit(&sdev_lock);
		VN_RELE(ovp);
		sdcmn_err2(("sdev_rename: the source is deleted already\n"));
		return (0);
	}

	if (fromdv->sdev_state == SDEV_ZOMBIE) {
		rw_exit(&fromparent->sdev_contents);
		mutex_exit(&sdev_lock);
		VN_RELE(SDEVTOV(fromdv));
		VN_RELE(ovp);
		sdcmn_err2(("sdev_rename: the source is being deleted\n"));
		return (0);
	}
	rw_exit(&fromparent->sdev_contents);
	ASSERT(SDEVTOV(fromdv) == ovp);
	VN_RELE(ovp);

	/* clean out the directory contents before it can be removed */
	type = SDEVTOV(fromdv)->v_type;
	if (type == VDIR) {
		error = sdev_cleandir(fromdv, NULL, 0);
		sdcmn_err2(("sdev_rename: cleandir finished with %d\n",
		    error));
		if (error == EBUSY)
			error = 0;
	}

	rw_enter(&fromparent->sdev_contents, RW_WRITER);
	bkstore = SDEV_IS_PERSIST(fromdv) ? 1 : 0;
	sdev_cache_update(fromparent, &fromdv, onm,
	    SDEV_CACHE_DELETE);
	VN_RELE(SDEVTOV(fromdv));

	/* best effforts clean up the backing store */
	if (bkstore) {
		ASSERT(fromparent->sdev_attrvp);
		if (type != VDIR) {
/* XXXci - We may need to translate the C-I flags on VOP_REMOVE */
			error = VOP_REMOVE(fromparent->sdev_attrvp,
			    onm, kcred, ct, 0);
		} else {
/* XXXci - We may need to translate the C-I flags on VOP_RMDIR */
			error = VOP_RMDIR(fromparent->sdev_attrvp,
			    onm, fromparent->sdev_attrvp, kcred, ct, 0);
		}

		if (error) {
			sdcmn_err2(("sdev_rename: device %s is "
			    "still on disk %s\n", onm,
			    fromparent->sdev_path));
			error = 0;
		}
	}
	rw_exit(&fromparent->sdev_contents);
	mutex_exit(&sdev_lock);

	/* once reached to this point, the rename is regarded successful */
	return (0);
}

/*
 * dev-fs version of "ln -s path dev-name"
 *	tnm - path, e.g. /devices/... or /dev/...
 *	lnm - dev_name
 */
/*ARGSUSED6*/
static int
sdev_symlink(struct vnode *dvp, char *lnm, struct vattr *tva,
    char *tnm, struct cred *cred, caller_context_t *ct, int flags)
{
	int error;
	struct vnode *vp = NULL;
	struct sdev_node *parent = (struct sdev_node *)VTOSDEV(dvp);
	struct sdev_node *self = (struct sdev_node *)NULL;

	ASSERT(parent);
	rw_enter(&parent->sdev_dotdot->sdev_contents, RW_READER);
	if (parent->sdev_state == SDEV_ZOMBIE) {
		rw_exit(&parent->sdev_dotdot->sdev_contents);
		sdcmn_err2(("sdev_symlink: parent %s is ZOMBIED \n",
		    parent->sdev_name));
		return (ENOENT);
	}

	if (!SDEV_IS_GLOBAL(parent)) {
		rw_exit(&parent->sdev_dotdot->sdev_contents);
		return (ENOTSUP);
	}
	rw_exit(&parent->sdev_dotdot->sdev_contents);

	/* execute access is required to search a directory */
	if ((error = VOP_ACCESS(dvp, VEXEC, 0, cred, ct)) != 0)
		return (error);

	/* find existing name */
/* XXXci - We may need to translate the C-I flags here */
	error = VOP_LOOKUP(dvp, lnm, &vp, NULL, 0, NULL, cred, ct, NULL, NULL);
	if (error == 0) {
		ASSERT(vp);
		VN_RELE(vp);
		sdcmn_err2(("sdev_symlink: node %s already exists\n", lnm));
		return (EEXIST);
	}
	if (error != ENOENT)
		return (error);

	/* write access is required to create a symlink */
	if ((error = VOP_ACCESS(dvp, VWRITE, 0, cred, ct)) != 0)
		return (error);

	/* put it into memory cache */
	rw_enter(&parent->sdev_contents, RW_WRITER);
	error = sdev_mknode(parent, lnm, &self, tva, NULL, (void *)tnm,
	    cred, SDEV_READY);
	if (error) {
		rw_exit(&parent->sdev_contents);
		sdcmn_err2(("sdev_symlink: node %s creation failed\n", lnm));
		if (self)
			SDEV_RELE(self);

		return (error);
	}
	ASSERT(self && (self->sdev_state == SDEV_READY));
	rw_exit(&parent->sdev_contents);

	/* take care the timestamps for the node and its parent */
	sdev_update_timestamps(SDEVTOV(self), kcred,
	    AT_CTIME|AT_MTIME|AT_ATIME);
	sdev_update_timestamps(dvp, kcred, AT_MTIME|AT_ATIME);
	if (SDEV_IS_GLOBAL(parent))
		atomic_inc_ulong(&parent->sdev_gdir_gen);

	/* wake up other threads blocked on looking up this node */
	mutex_enter(&self->sdev_lookup_lock);
	SDEV_UNBLOCK_OTHERS(self, SDEV_LOOKUP);
	mutex_exit(&self->sdev_lookup_lock);
	SDEV_RELE(self);	/* don't return with vnode held */
	return (0);
}

/*ARGSUSED6*/
static int
sdev_mkdir(struct vnode *dvp, char *nm, struct vattr *va, struct vnode **vpp,
    struct cred *cred, caller_context_t *ct, int flags, vsecattr_t *vsecp)
{
	int error;
	struct sdev_node *parent = (struct sdev_node *)VTOSDEV(dvp);
	struct sdev_node *self = NULL;
	struct vnode	*vp = NULL;

	ASSERT(parent && parent->sdev_dotdot);
	rw_enter(&parent->sdev_dotdot->sdev_contents, RW_READER);
	if (parent->sdev_state == SDEV_ZOMBIE) {
		rw_exit(&parent->sdev_dotdot->sdev_contents);
		return (ENOENT);
	}

	/* non-global do not allow pure directory creation */
	if (!SDEV_IS_GLOBAL(parent)) {
		rw_exit(&parent->sdev_dotdot->sdev_contents);
		return (prof_lookup(dvp, nm, vpp, cred));
	}
	rw_exit(&parent->sdev_dotdot->sdev_contents);

	/* execute access is required to search the directory */
	if ((error = VOP_ACCESS(dvp, VEXEC, 0, cred, ct)) != 0) {
		return (error);
	}

	/* find existing name */
/* XXXci - We may need to translate the C-I flags on VOP_LOOKUP */
	error = VOP_LOOKUP(dvp, nm, &vp, NULL, 0, NULL, cred, ct, NULL, NULL);
	if (error == 0) {
		VN_RELE(vp);
		return (EEXIST);
	}
	if (error != ENOENT)
		return (error);

	/* require write access to create a directory */
	if ((error = VOP_ACCESS(dvp, VWRITE, 0, cred, ct)) != 0) {
		return (error);
	}

	/* put it into memory */
	rw_enter(&parent->sdev_contents, RW_WRITER);
	error = sdev_mknode(parent, nm, &self,
	    va, NULL, NULL, cred, SDEV_READY);
	if (error) {
		rw_exit(&parent->sdev_contents);
		if (self)
			SDEV_RELE(self);
		return (error);
	}
	ASSERT(self && (self->sdev_state == SDEV_READY));
	rw_exit(&parent->sdev_contents);

	/* take care the timestamps for the node and its parent */
	sdev_update_timestamps(SDEVTOV(self), kcred,
	    AT_CTIME|AT_MTIME|AT_ATIME);
	sdev_update_timestamps(dvp, kcred, AT_MTIME|AT_ATIME);
	if (SDEV_IS_GLOBAL(parent))
		atomic_inc_ulong(&parent->sdev_gdir_gen);

	/* wake up other threads blocked on looking up this node */
	mutex_enter(&self->sdev_lookup_lock);
	SDEV_UNBLOCK_OTHERS(self, SDEV_LOOKUP);
	mutex_exit(&self->sdev_lookup_lock);
	*vpp = SDEVTOV(self);
	return (0);
}

/*
 * allowing removing an empty directory under /dev
 */
/*ARGSUSED*/
static int
sdev_rmdir(struct vnode *dvp, char *nm, struct vnode *cdir, struct cred *cred,
    caller_context_t *ct, int flags)
{
	int error = 0;
	struct sdev_node *parent = (struct sdev_node *)VTOSDEV(dvp);
	struct sdev_node *self = NULL;
	struct vnode *vp = NULL;

	/* bail out early */
	if (strcmp(nm, ".") == 0)
		return (EINVAL);
	if (strcmp(nm, "..") == 0)
		return (EEXIST); /* should be ENOTEMPTY */

	/* no destruction of non-global node */
	ASSERT(parent && parent->sdev_dotdot);
	rw_enter(&parent->sdev_dotdot->sdev_contents, RW_READER);
	if (!SDEV_IS_GLOBAL(parent)) {
		rw_exit(&parent->sdev_dotdot->sdev_contents);
		return (ENOTSUP);
	}
	rw_exit(&parent->sdev_dotdot->sdev_contents);

	/* execute access is required to search the directory */
	if ((error = VOP_ACCESS(dvp, VEXEC|VWRITE, 0, cred, ct)) != 0)
		return (error);

	/* check existing name */
	rw_enter(&parent->sdev_contents, RW_WRITER);
	self = sdev_cache_lookup(parent, nm);
	if (self == NULL) {
		rw_exit(&parent->sdev_contents);
		return (ENOENT);
	}

	vp = SDEVTOV(self);
	if ((self->sdev_state == SDEV_INIT) ||
	    (self->sdev_state == SDEV_ZOMBIE)) {
		rw_exit(&parent->sdev_contents);
		VN_RELE(vp);
		return (ENOENT);
	}

	/* some sanity checks */
	if (vp == dvp || vp == cdir) {
		rw_exit(&parent->sdev_contents);
		VN_RELE(vp);
		return (EINVAL);
	}

	if (vp->v_type != VDIR) {
		rw_exit(&parent->sdev_contents);
		VN_RELE(vp);
		return (ENOTDIR);
	}

	if (vn_vfswlock(vp)) {
		rw_exit(&parent->sdev_contents);
		VN_RELE(vp);
		return (EBUSY);
	}

	if (vn_mountedvfs(vp) != NULL) {
		rw_exit(&parent->sdev_contents);
		vn_vfsunlock(vp);
		VN_RELE(vp);
		return (EBUSY);
	}

	self = VTOSDEV(vp);
	/* bail out on a non-empty directory */
	rw_enter(&self->sdev_contents, RW_READER);
	if (self->sdev_nlink > 2) {
		rw_exit(&self->sdev_contents);
		rw_exit(&parent->sdev_contents);
		vn_vfsunlock(vp);
		VN_RELE(vp);
		return (ENOTEMPTY);
	}
	rw_exit(&self->sdev_contents);

	/* unlink it from the directory cache */
	sdev_cache_update(parent, &self, nm, SDEV_CACHE_DELETE);
	rw_exit(&parent->sdev_contents);
	vn_vfsunlock(vp);
	VN_RELE(vp);

	/* best effort to clean up the backing store */
	if (SDEV_IS_PERSIST(parent)) {
		ASSERT(parent->sdev_attrvp);
		error = VOP_RMDIR(parent->sdev_attrvp, nm,
		    parent->sdev_attrvp, kcred, ct, flags);

		if (error)
			sdcmn_err2(("sdev_rmdir: cleaning device %s is on"
			    " disk error %d\n", parent->sdev_path, error));
		if (error == EBUSY)
			error = 0;

	}

	return (error);
}

/*
 * read the contents of a symbolic link
 */
static int
sdev_readlink(struct vnode *vp, struct uio *uiop, struct cred *cred,
    caller_context_t *ct)
{
	struct sdev_node *dv;
	int	error = 0;

	ASSERT(vp->v_type == VLNK);

	dv = VTOSDEV(vp);

	if (dv->sdev_attrvp) {
		/* non-NULL attrvp implys a persisted node at READY state */
		return (VOP_READLINK(dv->sdev_attrvp, uiop, cred, ct));
	} else if (dv->sdev_symlink != NULL) {
		/* memory nodes, e.g. local nodes */
		rw_enter(&dv->sdev_contents, RW_READER);
		sdcmn_err2(("sdev_readlink link is %s\n", dv->sdev_symlink));
		error = uiomove(dv->sdev_symlink, strlen(dv->sdev_symlink),
		    UIO_READ, uiop);
		rw_exit(&dv->sdev_contents);
		return (error);
	}

	return (ENOENT);
}

/*ARGSUSED4*/
static int
sdev_readdir(struct vnode *dvp, struct uio *uiop, struct cred *cred, int *eofp,
    caller_context_t *ct, int flags)
{
	struct sdev_node *parent = VTOSDEV(dvp);
	int error;

	/*
	 * We must check that we have execute access to search the directory --
	 * but because our sdev_contents lock is already held as a reader (the
	 * caller must have done a VOP_RWLOCK()), we call directly into the
	 * underlying access routine if sdev_attr is non-NULL.
	 */
	if (parent->sdev_attr != NULL) {
		VERIFY(RW_READ_HELD(&parent->sdev_contents));

		if (sdev_unlocked_access(parent, VEXEC, cred) != 0)
			return (EACCES);
	} else {
		if ((error = VOP_ACCESS(dvp, VEXEC, 0, cred, ct)) != 0)
			return (error);
	}

	ASSERT(parent);
	if (!SDEV_IS_GLOBAL(parent))
		prof_filldir(parent);
	return (devname_readdir_func(dvp, uiop, cred, eofp, SDEV_BROWSE));
}

/*ARGSUSED1*/
static void
sdev_inactive(struct vnode *vp, struct cred *cred, caller_context_t *ct)
{
	devname_inactive_func(vp, cred, NULL);
}

/*ARGSUSED2*/
static int
sdev_fid(struct vnode *vp, struct fid *fidp, caller_context_t *ct)
{
	struct sdev_node	*dv = VTOSDEV(vp);
	struct sdev_fid	*sdev_fid;

	if (fidp->fid_len < (sizeof (struct sdev_fid) - sizeof (ushort_t))) {
		fidp->fid_len = sizeof (struct sdev_fid) - sizeof (ushort_t);
		return (ENOSPC);
	}

	sdev_fid = (struct sdev_fid *)fidp;
	bzero(sdev_fid, sizeof (struct sdev_fid));
	sdev_fid->sdevfid_len =
	    (int)sizeof (struct sdev_fid) - sizeof (ushort_t);
	sdev_fid->sdevfid_ino = dv->sdev_ino;

	return (0);
}

/*
 * This pair of routines bracket all VOP_READ, VOP_WRITE
 * and VOP_READDIR requests.  The contents lock stops things
 * moving around while we're looking at them.
 */
/*ARGSUSED2*/
static int
sdev_rwlock(struct vnode *vp, int write_flag, caller_context_t *ctp)
{
	rw_enter(&VTOSDEV(vp)->sdev_contents,
	    write_flag ? RW_WRITER : RW_READER);
	return (write_flag ? V_WRITELOCK_TRUE : V_WRITELOCK_FALSE);
}

/*ARGSUSED1*/
static void
sdev_rwunlock(struct vnode *vp, int write_flag, caller_context_t *ctp)
{
	rw_exit(&VTOSDEV(vp)->sdev_contents);
}

/*ARGSUSED1*/
static int
sdev_seek(struct vnode *vp, offset_t ooff, offset_t *noffp,
    caller_context_t *ct)
{
	struct vnode *attrvp = VTOSDEV(vp)->sdev_attrvp;

	ASSERT(vp->v_type != VCHR &&
	    vp->v_type != VBLK && vp->v_type != VLNK);

	if (vp->v_type == VDIR)
		return (fs_seek(vp, ooff, noffp, ct));

	ASSERT(attrvp);
	return (VOP_SEEK(attrvp, ooff, noffp, ct));
}

/*ARGSUSED1*/
static int
sdev_frlock(struct vnode *vp, int cmd, struct flock64 *bfp, int flag,
    offset_t offset, struct flk_callback *flk_cbp, struct cred *cr,
    caller_context_t *ct)
{
	int error;
	struct sdev_node *dv = VTOSDEV(vp);

	ASSERT(dv);
	ASSERT(dv->sdev_attrvp);
	error = VOP_FRLOCK(dv->sdev_attrvp, cmd, bfp, flag, offset,
	    flk_cbp, cr, ct);

	return (error);
}

static int
sdev_pathconf(vnode_t *vp, int cmd, ulong_t *valp, cred_t *cr,
    caller_context_t *ct)
{
	switch (cmd) {
	case _PC_ACL_ENABLED:
		*valp = SDEV_ACL_FLAVOR(vp);
		return (0);
	}

	return (fs_pathconf(vp, cmd, valp, cr, ct));
}

vnodeops_t *sdev_vnodeops;

const fs_operation_def_t sdev_vnodeops_tbl[] = {
	VOPNAME_OPEN,		{ .vop_open = sdev_open },
	VOPNAME_CLOSE,		{ .vop_close = sdev_close },
	VOPNAME_READ,		{ .vop_read = sdev_read },
	VOPNAME_WRITE,		{ .vop_write = sdev_write },
	VOPNAME_IOCTL,		{ .vop_ioctl = sdev_ioctl },
	VOPNAME_GETATTR,	{ .vop_getattr = sdev_getattr },
	VOPNAME_SETATTR,	{ .vop_setattr = sdev_setattr },
	VOPNAME_ACCESS,		{ .vop_access = sdev_access },
	VOPNAME_LOOKUP,		{ .vop_lookup = sdev_lookup },
	VOPNAME_CREATE,		{ .vop_create = sdev_create },
	VOPNAME_RENAME,		{ .vop_rename = sdev_rename },
	VOPNAME_REMOVE,		{ .vop_remove = sdev_remove },
	VOPNAME_MKDIR,		{ .vop_mkdir = sdev_mkdir },
	VOPNAME_RMDIR,		{ .vop_rmdir = sdev_rmdir },
	VOPNAME_READDIR,	{ .vop_readdir = sdev_readdir },
	VOPNAME_SYMLINK,	{ .vop_symlink = sdev_symlink },
	VOPNAME_READLINK,	{ .vop_readlink = sdev_readlink },
	VOPNAME_INACTIVE,	{ .vop_inactive = sdev_inactive },
	VOPNAME_FID,		{ .vop_fid = sdev_fid },
	VOPNAME_RWLOCK,		{ .vop_rwlock = sdev_rwlock },
	VOPNAME_RWUNLOCK,	{ .vop_rwunlock = sdev_rwunlock },
	VOPNAME_SEEK,		{ .vop_seek = sdev_seek },
	VOPNAME_FRLOCK,		{ .vop_frlock = sdev_frlock },
	VOPNAME_PATHCONF,	{ .vop_pathconf = sdev_pathconf },
	VOPNAME_SETSECATTR,	{ .vop_setsecattr = sdev_setsecattr },
	VOPNAME_GETSECATTR,	{ .vop_getsecattr = sdev_getsecattr },
	NULL,			NULL
};

int sdev_vnodeops_tbl_size = sizeof (sdev_vnodeops_tbl);
