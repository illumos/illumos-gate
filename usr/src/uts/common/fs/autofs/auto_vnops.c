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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2017 by Delphix. All rights reserved.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/uio.h>
#include <sys/cred.h>
#include <sys/pathname.h>
#include <sys/dirent.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <sys/tiuser.h>
#include <sys/cmn_err.h>
#include <sys/stat.h>
#include <sys/mode.h>
#include <sys/policy.h>
#include <rpc/types.h>
#include <rpc/auth.h>
#include <rpc/clnt.h>
#include <sys/fs/autofs.h>
#include <rpcsvc/autofs_prot.h>
#include <fs/fs_subr.h>

/*
 *  Vnode ops for autofs
 */
static int auto_open(vnode_t **, int, cred_t *, caller_context_t *);
static int auto_close(vnode_t *, int, int, offset_t, cred_t *,
	caller_context_t *);
static int auto_getattr(vnode_t *, vattr_t *, int, cred_t *,
	caller_context_t *);
static int auto_setattr(vnode_t *, vattr_t *, int, cred_t *,
	caller_context_t *);
static int auto_access(vnode_t *, int, int, cred_t *, caller_context_t *);
static int auto_lookup(vnode_t *, char *, vnode_t **,
	pathname_t *, int, vnode_t *, cred_t *, caller_context_t *, int *,
	pathname_t *);
static int auto_create(vnode_t *, char *, vattr_t *, vcexcl_t,
	int, vnode_t **, cred_t *, int, caller_context_t *,  vsecattr_t *);
static int auto_remove(vnode_t *, char *, cred_t *, caller_context_t *, int);
static int auto_link(vnode_t *, vnode_t *, char *, cred_t *,
	caller_context_t *, int);
static int auto_rename(vnode_t *, char *, vnode_t *, char *, cred_t *,
	caller_context_t *, int);
static int auto_mkdir(vnode_t *, char *, vattr_t *, vnode_t **, cred_t *,
	caller_context_t *, int, vsecattr_t *);
static int auto_rmdir(vnode_t *, char *, vnode_t *, cred_t *,
	caller_context_t *, int);
static int auto_readdir(vnode_t *, uio_t *, cred_t *, int *,
	caller_context_t *, int);
static int auto_symlink(vnode_t *, char *, vattr_t *, char *, cred_t *,
	caller_context_t *, int);
static int auto_readlink(vnode_t *, struct uio *, cred_t *,
	caller_context_t *);
static int auto_fsync(vnode_t *, int, cred_t *, caller_context_t *);
static void auto_inactive(vnode_t *, cred_t *, caller_context_t *);
static int auto_rwlock(vnode_t *, int, caller_context_t *);
static void auto_rwunlock(vnode_t *vp, int, caller_context_t *);
static int auto_seek(vnode_t *vp, offset_t, offset_t *, caller_context_t *);

static int auto_trigger_mount(vnode_t *, cred_t *, vnode_t **);

vnodeops_t *auto_vnodeops;

const fs_operation_def_t auto_vnodeops_template[] = {
	VOPNAME_OPEN,		{ .vop_open = auto_open },
	VOPNAME_CLOSE,		{ .vop_close = auto_close },
	VOPNAME_GETATTR,	{ .vop_getattr = auto_getattr },
	VOPNAME_SETATTR,	{ .vop_setattr = auto_setattr },
	VOPNAME_ACCESS,		{ .vop_access = auto_access },
	VOPNAME_LOOKUP,		{ .vop_lookup = auto_lookup },
	VOPNAME_CREATE,		{ .vop_create = auto_create },
	VOPNAME_REMOVE,		{ .vop_remove = auto_remove },
	VOPNAME_LINK,		{ .vop_link = auto_link },
	VOPNAME_RENAME,		{ .vop_rename = auto_rename },
	VOPNAME_MKDIR,		{ .vop_mkdir = auto_mkdir },
	VOPNAME_RMDIR,		{ .vop_rmdir = auto_rmdir },
	VOPNAME_READDIR,	{ .vop_readdir = auto_readdir },
	VOPNAME_SYMLINK,	{ .vop_symlink = auto_symlink },
	VOPNAME_READLINK,	{ .vop_readlink = auto_readlink },
	VOPNAME_FSYNC,		{ .vop_fsync = auto_fsync },
	VOPNAME_INACTIVE,	{ .vop_inactive = auto_inactive },
	VOPNAME_RWLOCK,		{ .vop_rwlock = auto_rwlock },
	VOPNAME_RWUNLOCK,	{ .vop_rwunlock = auto_rwunlock },
	VOPNAME_SEEK,		{ .vop_seek = auto_seek },
	VOPNAME_FRLOCK,		{ .error = fs_error },
	VOPNAME_DISPOSE,	{ .error = fs_error },
	VOPNAME_SHRLOCK,	{ .error = fs_error },
	VOPNAME_VNEVENT,	{ .vop_vnevent = fs_vnevent_support },
	NULL,			NULL
};



/* ARGSUSED */
static int
auto_open(vnode_t **vpp, int flag, cred_t *cred, caller_context_t *ct)
{
	vnode_t *newvp;
	int error;

	AUTOFS_DPRINT((4, "auto_open: *vpp=%p\n", (void *)*vpp));

	error = auto_trigger_mount(*vpp, cred, &newvp);
	if (error)
		goto done;

	if (newvp != NULL) {
		/*
		 * Node is now mounted on.
		 */
		VN_RELE(*vpp);
		*vpp = newvp;
		error = VOP_ACCESS(*vpp, VREAD, 0, cred, ct);
		if (!error)
			error = VOP_OPEN(vpp, flag, cred, ct);
	}

done:
	AUTOFS_DPRINT((5, "auto_open: *vpp=%p error=%d\n", (void *)*vpp,
	    error));
	return (error);
}

/* ARGSUSED */
static int
auto_close(
	vnode_t *vp,
	int flag,
	int count,
	offset_t offset,
	cred_t *cred,
	caller_context_t *ct)
{
	return (0);
}

static int
auto_getattr(
	vnode_t *vp,
	vattr_t *vap,
	int flags,
	cred_t *cred,
	caller_context_t *ct)
{
	fnnode_t *fnp = vntofn(vp);
	vnode_t *newvp;
	vfs_t *vfsp;
	int error;

	AUTOFS_DPRINT((4, "auto_getattr vp %p\n", (void *)vp));

	if (flags & ATTR_TRIGGER) {
		/*
		 * Pre-trigger the mount
		 */
		error = auto_trigger_mount(vp, cred, &newvp);
		if (error)
			return (error);

		if (newvp == NULL)
			goto defattr;

		if (error = vn_vfsrlock_wait(vp)) {
			VN_RELE(newvp);
			return (error);
		}

		vfsp = newvp->v_vfsp;
		VN_RELE(newvp);
	} else {
		/*
		 * Recursive auto_getattr/mount; go to the vfsp == NULL
		 * case.
		 */
		if (vn_vfswlock_held(vp))
			goto defattr;

		if (error = vn_vfsrlock_wait(vp))
			return (error);

		vfsp = vn_mountedvfs(vp);
	}

	if (vfsp != NULL) {
		/*
		 * Node is mounted on.
		 */
		error = VFS_ROOT(vfsp, &newvp);
		vn_vfsunlock(vp);
		if (error)
			return (error);
		mutex_enter(&fnp->fn_lock);
		if (fnp->fn_seen == newvp && fnp->fn_thread == curthread) {
			/*
			 * Recursive auto_getattr(); just release newvp and drop
			 * into the vfsp == NULL case.
			 */
			mutex_exit(&fnp->fn_lock);
			VN_RELE(newvp);
		} else {
			while (fnp->fn_thread && fnp->fn_thread != curthread) {
				fnp->fn_flags |= MF_ATTR_WAIT;
				cv_wait(&fnp->fn_cv_mount, &fnp->fn_lock);
			}
			fnp->fn_thread = curthread;
			fnp->fn_seen = newvp;
			mutex_exit(&fnp->fn_lock);
			error = VOP_GETATTR(newvp, vap, flags, cred, ct);
			VN_RELE(newvp);
			mutex_enter(&fnp->fn_lock);
			fnp->fn_seen = 0;
			fnp->fn_thread = 0;
			if (fnp->fn_flags & MF_ATTR_WAIT) {
				fnp->fn_flags &= ~MF_ATTR_WAIT;
				cv_broadcast(&fnp->fn_cv_mount);
			}
			mutex_exit(&fnp->fn_lock);
			return (error);
		}
	} else {
		vn_vfsunlock(vp);
	}

defattr:
	ASSERT(vp->v_type == VDIR || vp->v_type == VLNK);
	vap->va_uid	= 0;
	vap->va_gid	= 0;
	vap->va_nlink	= fnp->fn_linkcnt;
	vap->va_nodeid	= (u_longlong_t)fnp->fn_nodeid;
	vap->va_size	= fnp->fn_size;
	vap->va_atime	= fnp->fn_atime;
	vap->va_mtime	= fnp->fn_mtime;
	vap->va_ctime	= fnp->fn_ctime;
	vap->va_type	= vp->v_type;
	vap->va_mode	= fnp->fn_mode;
	vap->va_fsid	= vp->v_vfsp->vfs_dev;
	vap->va_rdev	= 0;
	vap->va_blksize	= MAXBSIZE;
	vap->va_nblocks	= (fsblkcnt64_t)btod(vap->va_size);
	vap->va_seq	= 0;

	return (0);
}

/*ARGSUSED4*/
static int
auto_setattr(
	vnode_t *vp,
	struct vattr *vap,
	int flags,
	cred_t *cred,
	caller_context_t *ct)
{
	vnode_t *newvp;
	int error;

	AUTOFS_DPRINT((4, "auto_setattr vp %p\n", (void *)vp));

	if (error = auto_trigger_mount(vp, cred, &newvp))
		goto done;

	if (newvp != NULL) {
		/*
		 * Node is mounted on.
		 */
		if (vn_is_readonly(newvp))
			error = EROFS;
		else
			error = VOP_SETATTR(newvp, vap, flags, cred, ct);
		VN_RELE(newvp);
	} else
		error = ENOSYS;

done:
	AUTOFS_DPRINT((5, "auto_setattr: error=%d\n", error));
	return (error);
}

/* ARGSUSED */
static int
auto_access(
	vnode_t *vp,
	int mode,
	int flags,
	cred_t *cred,
	caller_context_t *ct)
{
	fnnode_t *fnp = vntofn(vp);
	vnode_t *newvp;
	int error;

	AUTOFS_DPRINT((4, "auto_access: vp=%p\n", (void *)vp));

	if (error = auto_trigger_mount(vp, cred, &newvp))
		goto done;

	if (newvp != NULL) {
		/*
		 * Node is mounted on.
		 */
		error = VOP_ACCESS(newvp, mode, 0, cred, ct);
		VN_RELE(newvp);
	} else {
		int shift = 0;

		/*
		 * really interested in the autofs node, check the
		 * access on it
		 */
		ASSERT(error == 0);
		if (crgetuid(cred) != fnp->fn_uid) {
			shift += 3;
			if (groupmember(fnp->fn_gid, cred) == 0)
				shift += 3;
		}
		error = secpolicy_vnode_access2(cred, vp, fnp->fn_uid,
		    fnp->fn_mode << shift, mode);
	}

done:
	AUTOFS_DPRINT((5, "auto_access: error=%d\n", error));
	return (error);
}

static int
auto_lookup(
	vnode_t *dvp,
	char *nm,
	vnode_t **vpp,
	pathname_t *pnp,
	int flags,
	vnode_t *rdir,
	cred_t *cred,
	caller_context_t *ct,
	int *direntflags,
	pathname_t *realpnp)
{
	int error = 0;
	vnode_t *newvp = NULL;
	vfs_t *vfsp;
	fninfo_t *dfnip;
	fnnode_t *dfnp = NULL;
	fnnode_t *fnp = NULL;
	char *searchnm;
	int operation;		/* either AUTOFS_LOOKUP or AUTOFS_MOUNT */

	dfnip = vfstofni(dvp->v_vfsp);
	AUTOFS_DPRINT((3, "auto_lookup: dvp=%p (%s) name=%s\n",
	    (void *)dvp, dfnip->fi_map, nm));

	if (nm[0] == 0) {
		VN_HOLD(dvp);
		*vpp = dvp;
		return (0);
	}

	if (error = VOP_ACCESS(dvp, VEXEC, 0, cred, ct))
		return (error);

	if (nm[0] == '.' && nm[1] == 0) {
		VN_HOLD(dvp);
		*vpp = dvp;
		return (0);
	}

	if (nm[0] == '.' && nm[1] == '.' && nm[2] == 0) {
		fnnode_t *pdfnp;

		pdfnp = (vntofn(dvp))->fn_parent;
		ASSERT(pdfnp != NULL);

		/*
		 * Since it is legitimate to have the VROOT flag set for the
		 * subdirectories of the indirect map in autofs filesystem,
		 * rootfnnodep is checked against fnnode of dvp instead of
		 * just checking whether VROOT flag is set in dvp
		 */

		if (pdfnp == pdfnp->fn_globals->fng_rootfnnodep) {
			vnode_t *vp;

			vfs_rlock_wait(dvp->v_vfsp);
			if (dvp->v_vfsp->vfs_flag & VFS_UNMOUNTED) {
				vfs_unlock(dvp->v_vfsp);
				return (EIO);
			}
			vp = dvp->v_vfsp->vfs_vnodecovered;
			VN_HOLD(vp);
			vfs_unlock(dvp->v_vfsp);
			error = VOP_LOOKUP(vp, nm, vpp, pnp, flags, rdir, cred,
			    ct, direntflags, realpnp);
			VN_RELE(vp);
			return (error);
		} else {
			*vpp = fntovn(pdfnp);
			VN_HOLD(*vpp);
			return (0);
		}
	}

top:
	dfnp = vntofn(dvp);
	searchnm = nm;
	operation = 0;

	ASSERT(vn_matchops(dvp, auto_vnodeops));

	AUTOFS_DPRINT((3, "auto_lookup: dvp=%p dfnp=%p\n", (void *)dvp,
	    (void *)dfnp));

	/*
	 * If a lookup or mount of this node is in progress, wait for it
	 * to finish, and return whatever result it got.
	 */
	mutex_enter(&dfnp->fn_lock);
	if (dfnp->fn_flags & (MF_LOOKUP | MF_INPROG)) {
		mutex_exit(&dfnp->fn_lock);
		error = auto_wait4mount(dfnp);
		if (error == AUTOFS_SHUTDOWN)
			error = ENOENT;
		if (error == EAGAIN)
			goto top;
		if (error)
			return (error);
	} else
		mutex_exit(&dfnp->fn_lock);


	error = vn_vfsrlock_wait(dvp);
	if (error)
		return (error);
	vfsp = vn_mountedvfs(dvp);
	if (vfsp != NULL) {
		error = VFS_ROOT(vfsp, &newvp);
		vn_vfsunlock(dvp);
		if (!error) {
			error = VOP_LOOKUP(newvp, nm, vpp, pnp,
			    flags, rdir, cred, ct, direntflags, realpnp);
			VN_RELE(newvp);
		}
		return (error);
	}
	vn_vfsunlock(dvp);

	rw_enter(&dfnp->fn_rwlock, RW_READER);
	error = auto_search(dfnp, nm, &fnp, cred);
	if (error) {
		if (dfnip->fi_flags & MF_DIRECT) {
			/*
			 * direct map.
			 */
			if (dfnp->fn_dirents) {
				/*
				 * Mount previously triggered.
				 * 'nm' not found
				 */
				error = ENOENT;
			} else {
				/*
				 * I need to contact the daemon to trigger
				 * the mount. 'dfnp' will be the mountpoint.
				 */
				operation = AUTOFS_MOUNT;
				VN_HOLD(fntovn(dfnp));
				fnp = dfnp;
				error = 0;
			}
		} else if (dvp == dfnip->fi_rootvp) {
			/*
			 * 'dfnp' is the root of the indirect AUTOFS.
			 */
			if (rw_tryupgrade(&dfnp->fn_rwlock) == 0) {
				/*
				 * Could not acquire writer lock, release
				 * reader, and wait until available. We
				 * need to search for 'nm' again, since we
				 * had to release the lock before reacquiring
				 * it.
				 */
				rw_exit(&dfnp->fn_rwlock);
				rw_enter(&dfnp->fn_rwlock, RW_WRITER);
				error = auto_search(dfnp, nm, &fnp, cred);
			}

			ASSERT(RW_WRITE_HELD(&dfnp->fn_rwlock));
			if (error) {
				/*
				 * create node being looked-up and request
				 * mount on it.
				 */
				error = auto_enter(dfnp, nm, &fnp, kcred);
				if (!error)
					operation = AUTOFS_LOOKUP;
			}
		} else if ((dfnp->fn_dirents == NULL) &&
		    ((dvp->v_flag & VROOT) == 0) &&
		    ((fntovn(dfnp->fn_parent))->v_flag & VROOT)) {
			/*
			 * dfnp is the actual 'mountpoint' of indirect map,
			 * it is the equivalent of a direct mount,
			 * ie, /home/'user1'
			 */
			operation = AUTOFS_MOUNT;
			VN_HOLD(fntovn(dfnp));
			fnp = dfnp;
			error = 0;
			searchnm = dfnp->fn_name;
		}
	}

	if (error == EAGAIN) {
		rw_exit(&dfnp->fn_rwlock);
		goto top;
	}
	if (error) {
		rw_exit(&dfnp->fn_rwlock);
		return (error);
	}

	/*
	 * We now have the actual fnnode we're interested in.
	 * The 'MF_LOOKUP' indicates another thread is currently
	 * performing a daemon lookup of this node, therefore we
	 * wait for its completion.
	 * The 'MF_INPROG' indicates another thread is currently
	 * performing a daemon mount of this node, we wait for it
	 * to be done if we are performing a MOUNT. We don't
	 * wait for it if we are performing a LOOKUP.
	 * We can release the reader/writer lock as soon as we acquire
	 * the mutex, since the state of the lock can only change by
	 * first acquiring the mutex.
	 */
	mutex_enter(&fnp->fn_lock);
	rw_exit(&dfnp->fn_rwlock);
	if ((fnp->fn_flags & MF_LOOKUP) ||
	    ((operation == AUTOFS_MOUNT) && (fnp->fn_flags & MF_INPROG))) {
		mutex_exit(&fnp->fn_lock);
		error = auto_wait4mount(fnp);
		VN_RELE(fntovn(fnp));
		if (error == AUTOFS_SHUTDOWN)
			error = ENOENT;
		if (error && error != EAGAIN)
			return (error);
		goto top;
	}

	if (operation == 0) {
		/*
		 * got the fnnode, check for any errors
		 * on the previous operation on that node.
		 */
		error = fnp->fn_error;
		if ((error == EINTR) || (error == EAGAIN)) {
			/*
			 * previous operation on this node was
			 * not completed, do a lookup now.
			 */
			operation = AUTOFS_LOOKUP;
		} else {
			/*
			 * previous operation completed. Return
			 * a pointer to the node only if there was
			 * no error.
			 */
			mutex_exit(&fnp->fn_lock);
			if (!error)
				*vpp = fntovn(fnp);
			else
				VN_RELE(fntovn(fnp));
			return (error);
		}
	}

	/*
	 * Since I got to this point, it means I'm the one
	 * responsible for triggering the mount/look-up of this node.
	 */
	switch (operation) {
	case AUTOFS_LOOKUP:
		AUTOFS_BLOCK_OTHERS(fnp, MF_LOOKUP);
		fnp->fn_error = 0;
		mutex_exit(&fnp->fn_lock);
		error = auto_lookup_aux(fnp, searchnm, cred);
		if (!error) {
			/*
			 * Return this vnode
			 */
			*vpp = fntovn(fnp);
		} else {
			/*
			 * release our reference to this vnode
			 * and return error
			 */
			VN_RELE(fntovn(fnp));
		}
		break;
	case AUTOFS_MOUNT:
		AUTOFS_BLOCK_OTHERS(fnp, MF_INPROG);
		fnp->fn_error = 0;
		mutex_exit(&fnp->fn_lock);
		/*
		 * auto_new_mount_thread fires up a new thread which
		 * calls automountd finishing up the work
		 */
		auto_new_mount_thread(fnp, searchnm, cred);

		/*
		 * At this point, we are simply another thread
		 * waiting for the mount to complete
		 */
		error = auto_wait4mount(fnp);
		if (error == AUTOFS_SHUTDOWN)
			error = ENOENT;

		/*
		 * now release our reference to this vnode
		 */
		VN_RELE(fntovn(fnp));
		if (!error)
			goto top;
		break;
	default:
		auto_log(dfnp->fn_globals->fng_verbose,
		    dfnp->fn_globals->fng_zoneid, CE_WARN,
		    "auto_lookup: unknown operation %d",
		    operation);
	}

	AUTOFS_DPRINT((5, "auto_lookup: name=%s *vpp=%p return=%d\n",
	    nm, (void *)*vpp, error));

	return (error);
}

static int
auto_create(
	vnode_t *dvp,
	char *nm,
	vattr_t *va,
	vcexcl_t excl,
	int mode,
	vnode_t **vpp,
	cred_t *cred,
	int flag,
	caller_context_t *ct,
	vsecattr_t *vsecp)
{
	vnode_t *newvp;
	int error;

	AUTOFS_DPRINT((4, "auto_create dvp %p nm %s\n", (void *)dvp, nm));

	if (error = auto_trigger_mount(dvp, cred, &newvp))
		goto done;

	if (newvp != NULL) {
		/*
		 * Node is now mounted on.
		 */
		if (vn_is_readonly(newvp))
			error = EROFS;
		else
			error = VOP_CREATE(newvp, nm, va, excl,
			    mode, vpp, cred, flag, ct, vsecp);
		VN_RELE(newvp);
	} else
		error = ENOSYS;

done:
	AUTOFS_DPRINT((5, "auto_create: error=%d\n", error));
	return (error);
}

static int
auto_remove(
	vnode_t *dvp,
	char *nm,
	cred_t *cred,
	caller_context_t *ct,
	int flags)
{
	vnode_t *newvp;
	int error;

	AUTOFS_DPRINT((4, "auto_remove dvp %p nm %s\n", (void *)dvp, nm));

	if (error = auto_trigger_mount(dvp, cred, &newvp))
		goto done;

	if (newvp != NULL) {
		/*
		 * Node is now mounted on.
		 */
		if (vn_is_readonly(newvp))
			error = EROFS;
		else
			error = VOP_REMOVE(newvp, nm, cred, ct, flags);
		VN_RELE(newvp);
	} else
		error = ENOSYS;

done:
	AUTOFS_DPRINT((5, "auto_remove: error=%d\n", error));
	return (error);
}

static int
auto_link(
	vnode_t *tdvp,
	vnode_t *svp,
	char *nm,
	cred_t *cred,
	caller_context_t *ct,
	int flags)
{
	vnode_t *newvp;
	int error;

	AUTOFS_DPRINT((4, "auto_link tdvp %p svp %p nm %s\n", (void *)tdvp,
	    (void *)svp, nm));

	if (error = auto_trigger_mount(tdvp, cred, &newvp))
		goto done;

	if (newvp == NULL) {
		/*
		 * an autonode can not be a link to another node
		 */
		error = ENOSYS;
		goto done;
	}

	if (vn_is_readonly(newvp)) {
		error = EROFS;
		VN_RELE(newvp);
		goto done;
	}

	if (vn_matchops(svp, auto_vnodeops)) {
		/*
		 * source vp can't be an autonode
		 */
		error = ENOSYS;
		VN_RELE(newvp);
		goto done;
	}

	error = VOP_LINK(newvp, svp, nm, cred, ct, flags);
	VN_RELE(newvp);

done:
	AUTOFS_DPRINT((5, "auto_link error=%d\n", error));
	return (error);
}

static int
auto_rename(
	vnode_t *odvp,
	char *onm,
	vnode_t *ndvp,
	char *nnm,
	cred_t *cr,
	caller_context_t *ct,
	int flags)
{
	vnode_t *o_newvp, *n_newvp;
	int error;

	AUTOFS_DPRINT((4, "auto_rename odvp %p onm %s to ndvp %p nnm %s\n",
	    (void *)odvp, onm, (void *)ndvp, nnm));

	/*
	 * we know odvp is an autonode, otherwise this function
	 * could not have ever been called.
	 */
	ASSERT(vn_matchops(odvp, auto_vnodeops));

	if (error = auto_trigger_mount(odvp, cr, &o_newvp))
		goto done;

	if (o_newvp == NULL) {
		/*
		 * can't rename an autonode
		 */
		error = ENOSYS;
		goto done;
	}

	if (vn_matchops(ndvp, auto_vnodeops)) {
		/*
		 * directory is AUTOFS, need to trigger the
		 * mount of the real filesystem.
		 */
		if (error = auto_trigger_mount(ndvp, cr, &n_newvp)) {
			VN_RELE(o_newvp);
			goto done;
		}

		if (n_newvp == NULL) {
			/*
			 * target can't be an autonode
			 */
			error = ENOSYS;
			VN_RELE(o_newvp);
			goto done;
		}
	} else {
		/*
		 * destination directory mount had been
		 * triggered prior to the call to this function.
		 */
		n_newvp = ndvp;
	}

	ASSERT(!vn_matchops(n_newvp, auto_vnodeops));

	if (vn_is_readonly(n_newvp)) {
		error = EROFS;
		VN_RELE(o_newvp);
		if (n_newvp != ndvp)
			VN_RELE(n_newvp);
		goto done;
	}

	error = VOP_RENAME(o_newvp, onm, n_newvp, nnm, cr, ct, flags);
	VN_RELE(o_newvp);
	if (n_newvp != ndvp)
		VN_RELE(n_newvp);

done:
	AUTOFS_DPRINT((5, "auto_rename error=%d\n", error));
	return (error);
}

static int
auto_mkdir(
	vnode_t *dvp,
	char *nm,
	vattr_t *va,
	vnode_t **vpp,
	cred_t *cred,
	caller_context_t *ct,
	int flags,
	vsecattr_t *vsecp)
{
	vnode_t *newvp;
	int error;

	AUTOFS_DPRINT((4, "auto_mkdir dvp %p nm %s\n", (void *)dvp, nm));

	if (error = auto_trigger_mount(dvp, cred, &newvp))
		goto done;

	if (newvp != NULL) {
		/*
		 * Node is now mounted on.
		 */
		if (vn_is_readonly(newvp))
			error = EROFS;
		else
			error = VOP_MKDIR(newvp, nm, va, vpp, cred, ct,
			    flags, vsecp);
		VN_RELE(newvp);
	} else
		error = ENOSYS;

done:
	AUTOFS_DPRINT((5, "auto_mkdir: error=%d\n", error));
	return (error);
}

static int
auto_rmdir(
	vnode_t *dvp,
	char *nm,
	vnode_t *cdir,
	cred_t *cred,
	caller_context_t *ct,
	int flags)
{
	vnode_t *newvp;
	int error;

	AUTOFS_DPRINT((4, "auto_rmdir: vp=%p nm=%s\n", (void *)dvp, nm));

	if (error = auto_trigger_mount(dvp, cred, &newvp))
		goto done;

	if (newvp != NULL) {
		/*
		 * Node is now mounted on.
		 */
		if (vn_is_readonly(newvp))
			error = EROFS;
		else
			error = VOP_RMDIR(newvp, nm, cdir, cred, ct, flags);
		VN_RELE(newvp);
	} else
		error = ENOSYS;

done:
	AUTOFS_DPRINT((5, "auto_rmdir: error=%d\n", error));
	return (error);
}

static int autofs_nobrowse = 0;

#ifdef nextdp
#undef nextdp
#endif
#define	nextdp(dp)	((struct dirent64 *)((char *)(dp) + (dp)->d_reclen))

/* ARGSUSED */
static int
auto_readdir(
	vnode_t *vp,
	uio_t *uiop,
	cred_t *cred,
	int *eofp,
	caller_context_t *ct,
	int flags)
{
	struct autofs_rddirargs	rda;
	autofs_rddirres rd;
	fnnode_t *fnp = vntofn(vp);
	fnnode_t *cfnp, *nfnp;
	dirent64_t *dp;
	ulong_t offset;
	ulong_t outcount = 0, count = 0;
	size_t namelen;
	ulong_t alloc_count;
	void *outbuf = NULL;
	fninfo_t *fnip = vfstofni(vp->v_vfsp);
	struct iovec *iovp;
	int error = 0;
	int reached_max = 0;
	int myeof = 0;
	int this_reclen;
	struct autofs_globals *fngp = vntofn(fnip->fi_rootvp)->fn_globals;

	AUTOFS_DPRINT((4, "auto_readdir vp=%p offset=%lld\n",
	    (void *)vp, uiop->uio_loffset));

	if (eofp != NULL)
		*eofp = 0;

	if (uiop->uio_iovcnt != 1)
		return (EINVAL);

	iovp = uiop->uio_iov;
	alloc_count = iovp->iov_len;

	gethrestime(&fnp->fn_atime);
	fnp->fn_ref_time = fnp->fn_atime.tv_sec;

	dp = outbuf = kmem_zalloc(alloc_count, KM_SLEEP);

	/*
	 * Held when getdents calls VOP_RWLOCK....
	 */
	ASSERT(RW_READ_HELD(&fnp->fn_rwlock));
	if (uiop->uio_offset >= AUTOFS_DAEMONCOOKIE) {
again:
		/*
		 * Do readdir of daemon contents only
		 * Drop readers lock and reacquire after reply.
		 */
		rw_exit(&fnp->fn_rwlock);
		bzero(&rd, sizeof (struct autofs_rddirres));
		count = 0;
		rda.rda_map = fnip->fi_map;
		rda.rda_offset = (uint_t)uiop->uio_offset;
		rd.rd_rddir.rddir_entries = dp;
		rda.rda_count = rd.rd_rddir.rddir_size = (uint_t)alloc_count;
		rda.uid = crgetuid(cred);

		error = auto_calldaemon(fngp->fng_zoneid,
		    AUTOFS_READDIR,
		    xdr_autofs_rddirargs,
		    &rda,
		    xdr_autofs_rddirres,
		    (void *)&rd,
		    sizeof (autofs_rddirres),
		    TRUE);

		/*
		 * reacquire previously dropped lock
		 */
		rw_enter(&fnp->fn_rwlock, RW_READER);

		if (!error) {
			error = rd.rd_status;
			dp = rd.rd_rddir.rddir_entries;
		}

		if (error) {
			if (error == AUTOFS_SHUTDOWN) {
				/*
				 * treat as empty directory
				 */
				error = 0;
				myeof = 1;
				if (eofp)
					*eofp = 1;
			}
			goto done;
		}
		if (rd.rd_rddir.rddir_size) {
			dirent64_t *odp = dp;   /* next in output buffer */
			dirent64_t *cdp = dp;   /* current examined entry */

			/*
			 * Check for duplicates here
			 */
			do {
				this_reclen = cdp->d_reclen;
				if (auto_search(fnp, cdp->d_name,
				    NULL, cred)) {
					/*
					 * entry not found in kernel list,
					 * include it in readdir output.
					 *
					 * If we are skipping entries. then
					 * we need to copy this entry to the
					 * correct position in the buffer
					 * to be copied out.
					 */
					if (cdp != odp)
						bcopy(cdp, odp,
						    (size_t)this_reclen);
					odp = nextdp(odp);
					outcount += this_reclen;
				} else {
					/*
					 * Entry was found in the kernel
					 * list. If it is the first entry
					 * in this buffer, then just skip it
					 */
					if (odp == dp) {
						dp = nextdp(dp);
						odp = dp;
					}
				}
				count += this_reclen;
				cdp = (struct dirent64 *)
				    ((char *)cdp + this_reclen);
			} while (count < rd.rd_rddir.rddir_size);

			if (outcount)
				error = uiomove(dp, outcount, UIO_READ, uiop);
			uiop->uio_offset = rd.rd_rddir.rddir_offset;
		} else {
			if (rd.rd_rddir.rddir_eof == 0) {
				/*
				 * alloc_count not large enough for one
				 * directory entry
				 */
				error = EINVAL;
			}
		}
		if (rd.rd_rddir.rddir_eof && !error) {
			myeof = 1;
			if (eofp)
				*eofp = 1;
		}
		if (!error && !myeof && outcount == 0) {
			/*
			 * call daemon with new cookie, all previous
			 * elements happened to be duplicates
			 */
			dp = outbuf;
			goto again;
		}
		goto done;
	}

	if (uiop->uio_offset == 0) {
		/*
		 * first time: so fudge the . and ..
		 */
		this_reclen = DIRENT64_RECLEN(1);
		if (alloc_count < this_reclen) {
			error = EINVAL;
			goto done;
		}
		dp->d_ino = (ino64_t)fnp->fn_nodeid;
		dp->d_off = (off64_t)1;
		dp->d_reclen = (ushort_t)this_reclen;

		/* use strncpy(9f) to zero out uninitialized bytes */

		(void) strncpy(dp->d_name, ".",
		    DIRENT64_NAMELEN(this_reclen));
		outcount += dp->d_reclen;
		dp = nextdp(dp);

		this_reclen = DIRENT64_RECLEN(2);
		if (alloc_count < outcount + this_reclen) {
			error = EINVAL;
			goto done;
		}
		dp->d_reclen = (ushort_t)this_reclen;
		dp->d_ino = (ino64_t)fnp->fn_parent->fn_nodeid;
		dp->d_off = (off64_t)2;

		/* use strncpy(9f) to zero out uninitialized bytes */

		(void) strncpy(dp->d_name, "..",
		    DIRENT64_NAMELEN(this_reclen));
		outcount += dp->d_reclen;
		dp = nextdp(dp);
	}

	offset = 2;
	cfnp = fnp->fn_dirents;
	while (cfnp != NULL) {
		nfnp = cfnp->fn_next;
		offset = cfnp->fn_offset;
		if ((offset >= uiop->uio_offset) &&
		    (!(cfnp->fn_flags & MF_LOOKUP))) {
			int reclen;

			/*
			 * include node only if its offset is greater or
			 * equal to the one required and it is not in
			 * transient state (not being looked-up)
			 */
			namelen = strlen(cfnp->fn_name);
			reclen = (int)DIRENT64_RECLEN(namelen);
			if (outcount + reclen > alloc_count) {
				reached_max = 1;
				break;
			}
			dp->d_reclen = (ushort_t)reclen;
			dp->d_ino = (ino64_t)cfnp->fn_nodeid;
			if (nfnp != NULL) {
				/*
				 * get the offset of the next element
				 */
				dp->d_off = (off64_t)nfnp->fn_offset;
			} else {
				/*
				 * This is the last element, make
				 * offset one plus the current
				 */
				dp->d_off = (off64_t)cfnp->fn_offset + 1;
			}

			/* use strncpy(9f) to zero out uninitialized bytes */

			(void) strncpy(dp->d_name, cfnp->fn_name,
			    DIRENT64_NAMELEN(reclen));
			outcount += dp->d_reclen;
			dp = nextdp(dp);
		}
		cfnp = nfnp;
	}

	if (outcount)
		error = uiomove(outbuf, outcount, UIO_READ, uiop);

	if (!error) {
		if (reached_max) {
			/*
			 * This entry did not get added to the buffer on this,
			 * call. We need to add it on the next call therefore
			 * set uio_offset to this entry's offset.  If there
			 * wasn't enough space for one dirent, return EINVAL.
			 */
			uiop->uio_offset = offset;
			if (outcount == 0)
				error = EINVAL;
		} else if (autofs_nobrowse ||
		    auto_nobrowse_option(fnip->fi_opts) ||
		    (fnip->fi_flags & MF_DIRECT) ||
		    (fnp->fn_trigger != NULL) ||
		    (((vp->v_flag & VROOT) == 0) &&
		    ((fntovn(fnp->fn_parent))->v_flag & VROOT) &&
		    (fnp->fn_dirents == NULL))) {
			/*
			 * done reading directory entries
			 */
			uiop->uio_offset = offset + 1;
			if (eofp)
				*eofp = 1;
		} else {
			/*
			 * Need to get the rest of the entries from the daemon.
			 */
			uiop->uio_offset = AUTOFS_DAEMONCOOKIE;
		}
	}

done:
	kmem_free(outbuf, alloc_count);
	AUTOFS_DPRINT((5, "auto_readdir vp=%p offset=%lld eof=%d\n",
	    (void *)vp, uiop->uio_loffset, myeof));
	return (error);
}

static int
auto_symlink(
	vnode_t *dvp,
	char *lnknm,		/* new entry */
	vattr_t *tva,
	char *tnm,		/* existing entry */
	cred_t *cred,
	caller_context_t *ct,
	int flags)
{
	vnode_t *newvp;
	int error;

	AUTOFS_DPRINT((4, "auto_symlink: dvp=%p lnknm=%s tnm=%s\n",
	    (void *)dvp, lnknm, tnm));

	if (error = auto_trigger_mount(dvp, cred, &newvp))
		goto done;

	if (newvp != NULL) {
		/*
		 * Node is mounted on.
		 */
		if (vn_is_readonly(newvp))
			error = EROFS;
		else
			error = VOP_SYMLINK(newvp, lnknm, tva, tnm, cred,
			    ct, flags);
		VN_RELE(newvp);
	} else
		error = ENOSYS;

done:
	AUTOFS_DPRINT((5, "auto_symlink: error=%d\n", error));
	return (error);
}

/* ARGSUSED */
static int
auto_readlink(vnode_t *vp, struct uio *uiop, cred_t *cr, caller_context_t *ct)
{
	fnnode_t *fnp = vntofn(vp);
	int error;
	timestruc_t now;

	AUTOFS_DPRINT((4, "auto_readlink: vp=%p\n", (void *)vp));

	gethrestime(&now);
	fnp->fn_ref_time = now.tv_sec;

	if (vp->v_type != VLNK)
		error = EINVAL;
	else {
		ASSERT(!(fnp->fn_flags & (MF_INPROG | MF_LOOKUP)));
		fnp->fn_atime = now;
		error = uiomove(fnp->fn_symlink, MIN(fnp->fn_symlinklen,
		    uiop->uio_resid), UIO_READ, uiop);
	}

	AUTOFS_DPRINT((5, "auto_readlink: error=%d\n", error));
	return (error);
}

/* ARGSUSED */
static int
auto_fsync(vnode_t *cp, int syncflag, cred_t *cred, caller_context_t *ct)
{
	return (0);
}

/* ARGSUSED */
static void
auto_inactive(vnode_t *vp, cred_t *cred, caller_context_t *ct)
{
	fnnode_t *fnp = vntofn(vp);
	fnnode_t *dfnp = fnp->fn_parent;
	int count;

	AUTOFS_DPRINT((4, "auto_inactive: vp=%p v_count=%u fn_link=%d\n",
	    (void *)vp, vp->v_count, fnp->fn_linkcnt));

	/*
	 * The rwlock should not be already held by this thread.
	 * The assert relies on the fact that the owner field is cleared
	 * when the lock is released.
	 */
	ASSERT(dfnp != NULL);
	ASSERT(rw_owner(&dfnp->fn_rwlock) != curthread);
	rw_enter(&dfnp->fn_rwlock, RW_WRITER);
	mutex_enter(&vp->v_lock);
	ASSERT(vp->v_count > 0);
	VN_RELE_LOCKED(vp);
	count = vp->v_count;
	mutex_exit(&vp->v_lock);
	if (count == 0) {
		/*
		 * Free only if node has no subdirectories.
		 */
		if (fnp->fn_linkcnt == 1) {
			auto_disconnect(dfnp, fnp);
			rw_exit(&dfnp->fn_rwlock);
			auto_freefnnode(fnp);
			AUTOFS_DPRINT((5, "auto_inactive: (exit) vp=%p freed\n",
			    (void *)vp));
			return;
		}
	}
	rw_exit(&dfnp->fn_rwlock);

	AUTOFS_DPRINT((5, "auto_inactive: (exit) vp=%p v_count=%u fn_link=%d\n",
	    (void *)vp, vp->v_count, fnp->fn_linkcnt));
}

/* ARGSUSED2 */
static int
auto_rwlock(vnode_t *vp, int write_lock, caller_context_t *ct)
{
	fnnode_t *fnp = vntofn(vp);
	if (write_lock)
		rw_enter(&fnp->fn_rwlock, RW_WRITER);
	else
		rw_enter(&fnp->fn_rwlock, RW_READER);
	return (write_lock);
}

/* ARGSUSED */
static void
auto_rwunlock(vnode_t *vp, int write_lock, caller_context_t *ct)
{
	fnnode_t *fnp = vntofn(vp);
	rw_exit(&fnp->fn_rwlock);
}


/* ARGSUSED */
static int
auto_seek(
	struct vnode *vp,
	offset_t ooff,
	offset_t *noffp,
	caller_context_t *ct)
{
	/*
	 * Return 0 unconditionally, since we expect
	 * a VDIR all the time
	 */
	return (0);
}

/*
 * Triggers the mount if needed. If the mount has been triggered by
 * another thread, it will wait for its return status, and return it.
 * Whether the mount is triggered by this thread, another thread, or
 * if the vnode was already covered, '*newvp' is a
 * VN_HELD vnode pointing to the root of the filesystem covering 'vp'.
 * If the node is not mounted on, and should not be mounted on, '*newvp'
 * will be NULL.
 * The calling routine may use '*newvp' to do the filesystem jump.
 */
static int
auto_trigger_mount(vnode_t *vp, cred_t *cred, vnode_t **newvp)
{
	fnnode_t *fnp = vntofn(vp);
	fninfo_t *fnip = vfstofni(vp->v_vfsp);
	vnode_t *dvp;
	vfs_t *vfsp;
	int delayed_ind;
	char name[AUTOFS_MAXPATHLEN];
	int error;

	AUTOFS_DPRINT((4, "auto_trigger_mount: vp=%p\n", (void *)vp));

	*newvp = NULL;

	/*
	 * Cross-zone mount triggering is disallowed.
	 */
	if (fnip->fi_zoneid != getzoneid())
		return (EPERM);	/* Not owner of mount */

retry:
	error = 0;
	delayed_ind = 0;
	mutex_enter(&fnp->fn_lock);
	while (fnp->fn_flags & (MF_LOOKUP | MF_INPROG)) {
		/*
		 * Mount or lookup in progress,
		 * wait for it before proceeding.
		 */
		mutex_exit(&fnp->fn_lock);
		error = auto_wait4mount(fnp);
		if (error == AUTOFS_SHUTDOWN) {
			error = 0;
			goto done;
		}
		if (error && error != EAGAIN)
			goto done;
		error = 0;
		mutex_enter(&fnp->fn_lock);
	}

	/*
	 * If the vfslock can't be acquired for the first time.
	 * drop the fn_lock and retry next time in blocking mode.
	 */
	if (vn_vfswlock(vp)) {
		/*
		 * Lock held by another thread.
		 * Perform blocking by dropping the
		 * fn_lock.
		 */
		mutex_exit(&fnp->fn_lock);
		error = vn_vfswlock_wait(vp);
		if (error)
			goto done;
		/*
		 * Because fn_lock wasn't held, the state
		 * of the trigger node might have changed.
		 * Need to run through the checks on trigger
		 * node again.
		 */
		vn_vfsunlock(vp);
		goto retry;
	}

	vfsp = vn_mountedvfs(vp);
	if (vfsp != NULL) {
		mutex_exit(&fnp->fn_lock);
		error = VFS_ROOT(vfsp, newvp);
		vn_vfsunlock(vp);
		goto done;
	} else {
		vn_vfsunlock(vp);
		if ((fnp->fn_flags & MF_MOUNTPOINT) &&
		    fnp->fn_trigger != NULL) {
			ASSERT(fnp->fn_dirents == NULL);
			mutex_exit(&fnp->fn_lock);
			/*
			 * The filesystem that used to sit here has been
			 * forcibly unmounted. Do our best to recover.
			 * Try to unmount autofs subtree below this node
			 * and retry the action.
			 */
			if (unmount_subtree(fnp, B_TRUE) != 0) {
				error = EIO;
				goto done;
			}
			goto retry;
		}
	}

	ASSERT(vp->v_type == VDIR);
	dvp = fntovn(fnp->fn_parent);

	if ((fnp->fn_dirents == NULL) &&
	    ((fnip->fi_flags & MF_DIRECT) == 0) &&
	    ((vp->v_flag & VROOT) == 0) &&
	    (dvp->v_flag & VROOT)) {
		/*
		 * If the parent of this node is the root of an indirect
		 * AUTOFS filesystem, this node is remountable.
		 */
		delayed_ind = 1;
	}

	if (delayed_ind ||
	    ((fnip->fi_flags & MF_DIRECT) && (fnp->fn_dirents == NULL))) {
		/*
		 * Trigger mount since:
		 * direct mountpoint with no subdirs or
		 * delayed indirect.
		 */
		AUTOFS_BLOCK_OTHERS(fnp, MF_INPROG);
		fnp->fn_error = 0;
		mutex_exit(&fnp->fn_lock);
		if (delayed_ind)
			(void) strcpy(name, fnp->fn_name);
		else
			(void) strcpy(name, ".");
		fnp->fn_ref_time = gethrestime_sec();
		auto_new_mount_thread(fnp, name, cred);
		/*
		 * At this point we're simply another thread waiting
		 * for the mount to finish.
		 */
		error = auto_wait4mount(fnp);
		if (error == EAGAIN)
			goto retry;
		if (error == AUTOFS_SHUTDOWN) {
			error = 0;
			goto done;
		}
		if (error == 0) {
			if (error = vn_vfsrlock_wait(vp))
				goto done;
			/* Reacquire after dropping locks */
			vfsp = vn_mountedvfs(vp);
			if (vfsp != NULL) {
				error = VFS_ROOT(vfsp, newvp);
				vn_vfsunlock(vp);
			} else {
				vn_vfsunlock(vp);
				goto retry;
			}
		}
	} else
		mutex_exit(&fnp->fn_lock);

done:
	AUTOFS_DPRINT((5, "auto_trigger_mount: error=%d\n", error));
	return (error);
}
