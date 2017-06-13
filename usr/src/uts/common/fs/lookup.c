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
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 1988, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2015, Joyent, Inc.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/cpuvar.h>
#include <sys/errno.h>
#include <sys/cred.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/pathname.h>
#include <sys/proc.h>
#include <sys/vtrace.h>
#include <sys/sysmacros.h>
#include <sys/debug.h>
#include <sys/dirent.h>
#include <c2/audit.h>
#include <sys/zone.h>
#include <sys/dnlc.h>
#include <sys/fs/snode.h>

/* Controls whether paths are stored with vnodes. */
int vfs_vnode_path = 1;

int
lookupname(
	char *fnamep,
	enum uio_seg seg,
	int followlink,
	vnode_t **dirvpp,
	vnode_t **compvpp)
{
	return (lookupnameatcred(fnamep, seg, followlink, dirvpp, compvpp, NULL,
	    CRED()));
}

/*
 * Lookup the user file name,
 * Handle allocation and freeing of pathname buffer, return error.
 */
int
lookupnameatcred(
	char *fnamep,			/* user pathname */
	enum uio_seg seg,		/* addr space that name is in */
	int followlink,			/* follow sym links */
	vnode_t **dirvpp,		/* ret for ptr to parent dir vnode */
	vnode_t **compvpp,		/* ret for ptr to component vnode */
	vnode_t *startvp,		/* start path search from vp */
	cred_t *cr)			/* credential */
{
	char namebuf[TYPICALMAXPATHLEN];
	struct pathname lookpn;
	int error;

	error = pn_get_buf(fnamep, seg, &lookpn, namebuf, sizeof (namebuf));
	if (error == 0) {
		error = lookuppnatcred(&lookpn, NULL, followlink,
		    dirvpp, compvpp, startvp, cr);
	}
	if (error == ENAMETOOLONG) {
		/*
		 * This thread used a pathname > TYPICALMAXPATHLEN bytes long.
		 */
		if (error = pn_get(fnamep, seg, &lookpn))
			return (error);
		error = lookuppnatcred(&lookpn, NULL, followlink,
		    dirvpp, compvpp, startvp, cr);
		pn_free(&lookpn);
	}

	return (error);
}

int
lookupnameat(char *fnamep, enum uio_seg seg, int followlink,
    vnode_t **dirvpp, vnode_t **compvpp, vnode_t *startvp)
{
	return (lookupnameatcred(fnamep, seg, followlink, dirvpp, compvpp,
	    startvp, CRED()));
}

int
lookuppn(
	struct pathname *pnp,
	struct pathname *rpnp,
	int followlink,
	vnode_t **dirvpp,
	vnode_t **compvpp)
{
	return (lookuppnatcred(pnp, rpnp, followlink, dirvpp, compvpp, NULL,
	    CRED()));
}

/*
 * Lookup the user file name from a given vp, using a specific credential.
 */
int
lookuppnatcred(
	struct pathname *pnp,		/* pathname to lookup */
	struct pathname *rpnp,		/* if non-NULL, return resolved path */
	int followlink,			/* (don't) follow sym links */
	vnode_t **dirvpp,		/* ptr for parent vnode */
	vnode_t **compvpp,		/* ptr for entry vnode */
	vnode_t *startvp,		/* start search from this vp */
	cred_t *cr)			/* user credential */
{
	vnode_t *vp;	/* current directory vp */
	vnode_t *rootvp;
	proc_t *p = curproc;

	if (pnp->pn_pathlen == 0)
		return (ENOENT);

	mutex_enter(&p->p_lock);	/* for u_rdir and u_cdir */
	if ((rootvp = PTOU(p)->u_rdir) == NULL)
		rootvp = rootdir;
	else if (rootvp != rootdir)	/* no need to VN_HOLD rootdir */
		VN_HOLD(rootvp);

	if (pnp->pn_path[0] == '/') {
		vp = rootvp;
	} else {
		vp = (startvp == NULL) ? PTOU(p)->u_cdir : startvp;
	}
	VN_HOLD(vp);
	mutex_exit(&p->p_lock);

	/*
	 * Skip over leading slashes
	 */
	if (pnp->pn_path[0] == '/') {
		do {
			pnp->pn_path++;
			pnp->pn_pathlen--;
		} while (pnp->pn_path[0] == '/');
	}

	return (lookuppnvp(pnp, rpnp, followlink, dirvpp,
	    compvpp, rootvp, vp, cr));
}

int
lookuppnat(struct pathname *pnp, struct pathname *rpnp,
    int followlink, vnode_t **dirvpp, vnode_t **compvpp,
    vnode_t *startvp)
{
	return (lookuppnatcred(pnp, rpnp, followlink, dirvpp, compvpp, startvp,
	    CRED()));
}

/* Private flag to do our getcwd() dirty work */
#define	LOOKUP_CHECKREAD	0x10
#define	LOOKUP_MASK		(~LOOKUP_CHECKREAD)

/*
 * Starting at current directory, translate pathname pnp to end.
 * Leave pathname of final component in pnp, return the vnode
 * for the final component in *compvpp, and return the vnode
 * for the parent of the final component in dirvpp.
 *
 * This is the central routine in pathname translation and handles
 * multiple components in pathnames, separating them at /'s.  It also
 * implements mounted file systems and processes symbolic links.
 *
 * vp is the vnode where the directory search should start.
 *
 * Reference counts: vp must be held prior to calling this function.  rootvp
 * should only be held if rootvp != rootdir.
 */
int
lookuppnvp(
	struct pathname *pnp,		/* pathname to lookup */
	struct pathname *rpnp,		/* if non-NULL, return resolved path */
	int flags,			/* follow symlinks */
	vnode_t **dirvpp,		/* ptr for parent vnode */
	vnode_t **compvpp,		/* ptr for entry vnode */
	vnode_t *rootvp,		/* rootvp */
	vnode_t *vp,			/* directory to start search at */
	cred_t *cr)			/* user's credential */
{
	vnode_t *cvp;	/* current component vp */
	char component[MAXNAMELEN];	/* buffer for component (incl null) */
	int error;
	int nlink;
	int lookup_flags;
	struct pathname presrvd; /* case preserved name */
	struct pathname *pp = NULL;
	vnode_t *startvp;
	vnode_t *zonevp = curproc->p_zone->zone_rootvp;		/* zone root */
	int must_be_directory = 0;
	boolean_t retry_with_kcred;
	uint32_t auditing = AU_AUDITING();

	CPU_STATS_ADDQ(CPU, sys, namei, 1);
	nlink = 0;
	cvp = NULL;
	if (rpnp)
		rpnp->pn_pathlen = 0;

	lookup_flags = dirvpp ? LOOKUP_DIR : 0;
	if (flags & FIGNORECASE) {
		lookup_flags |= FIGNORECASE;
		pn_alloc(&presrvd);
		pp = &presrvd;
	}

	if (auditing)
		audit_anchorpath(pnp, vp == rootvp);

	/*
	 * Eliminate any trailing slashes in the pathname.
	 * If there are any, we must follow all symlinks.
	 * Also, we must guarantee that the last component is a directory.
	 */
	if (pn_fixslash(pnp)) {
		flags |= FOLLOW;
		must_be_directory = 1;
	}

	startvp = vp;
next:
	retry_with_kcred = B_FALSE;

	/*
	 * Make sure we have a directory.
	 */
	if (vp->v_type != VDIR) {
		error = ENOTDIR;
		goto bad;
	}

	if (rpnp && VN_CMP(vp, rootvp))
		(void) pn_set(rpnp, "/");

	/*
	 * Process the next component of the pathname.
	 */
	if (error = pn_getcomponent(pnp, component)) {
		goto bad;
	}

	/*
	 * Handle "..": two special cases.
	 * 1. If we're at the root directory (e.g. after chroot or
	 *    zone_enter) then change ".." to "." so we can't get
	 *    out of this subtree.
	 * 2. If this vnode is the root of a mounted file system,
	 *    then replace it with the vnode that was mounted on
	 *    so that we take the ".." in the other file system.
	 */
	if (component[0] == '.' && component[1] == '.' && component[2] == 0) {
checkforroot:
		if (VN_CMP(vp, rootvp) || VN_CMP(vp, zonevp)) {
			component[1] = '\0';
		} else if (vp->v_flag & VROOT) {
			vfs_t *vfsp;
			cvp = vp;

			/*
			 * While we deal with the vfs pointer from the vnode
			 * the filesystem could have been forcefully unmounted
			 * and the vnode's v_vfsp could have been invalidated
			 * by VFS_UNMOUNT. Hence, we cache v_vfsp and use it
			 * with vfs_rlock_wait/vfs_unlock.
			 * It is safe to use the v_vfsp even it is freed by
			 * VFS_UNMOUNT because vfs_rlock_wait/vfs_unlock
			 * do not dereference v_vfsp. It is just used as a
			 * magic cookie.
			 * One more corner case here is the memory getting
			 * reused for another vfs structure. In this case
			 * lookuppnvp's vfs_rlock_wait will succeed, domount's
			 * vfs_lock will fail and domount will bail out with an
			 * error (EBUSY).
			 */
			vfsp = cvp->v_vfsp;

			/*
			 * This lock is used to synchronize
			 * mounts/unmounts and lookups.
			 * Threads doing mounts/unmounts hold the
			 * writers version vfs_lock_wait().
			 */

			vfs_rlock_wait(vfsp);

			/*
			 * If this vnode is on a file system that
			 * has been forcibly unmounted,
			 * we can't proceed. Cancel this operation
			 * and return EIO.
			 *
			 * vfs_vnodecovered is NULL if unmounted.
			 * Currently, nfs uses VFS_UNMOUNTED to
			 * check if it's a forced-umount. Keep the
			 * same checking here as well even though it
			 * may not be needed.
			 */
			if (((vp = cvp->v_vfsp->vfs_vnodecovered) == NULL) ||
			    (cvp->v_vfsp->vfs_flag & VFS_UNMOUNTED)) {
				vfs_unlock(vfsp);
				VN_RELE(cvp);
				if (pp)
					pn_free(pp);
				return (EIO);
			}
			VN_HOLD(vp);
			vfs_unlock(vfsp);
			VN_RELE(cvp);
			cvp = NULL;
			/*
			 * Crossing mount points. For eg: We are doing
			 * a lookup of ".." for file systems root vnode
			 * mounted here, and VOP_LOOKUP() (with covered vnode)
			 * will be on underlying file systems mount point
			 * vnode. Set retry_with_kcred flag as we might end
			 * up doing VOP_LOOKUP() with kcred if required.
			 */
			retry_with_kcred = B_TRUE;
			goto checkforroot;
		}
	}

	/*
	 * LOOKUP_CHECKREAD is a private flag used by vnodetopath() to indicate
	 * that we need to have read permission on every directory in the entire
	 * path.  This is used to ensure that a forward-lookup of a cached value
	 * has the same effect as a reverse-lookup when the cached value cannot
	 * be found.
	 */
	if ((flags & LOOKUP_CHECKREAD) &&
	    (error = VOP_ACCESS(vp, VREAD, 0, cr, NULL)) != 0)
		goto bad;

	/*
	 * Perform a lookup in the current directory.
	 */
	error = VOP_LOOKUP(vp, component, &cvp, pnp, lookup_flags,
	    rootvp, cr, NULL, NULL, pp);

	/*
	 * Retry with kcred - If crossing mount points & error is EACCES.
	 *
	 * If we are crossing mount points here and doing ".." lookup,
	 * VOP_LOOKUP() might fail if the underlying file systems
	 * mount point has no execute permission. In cases like these,
	 * we retry VOP_LOOKUP() by giving as much privilage as possible
	 * by passing kcred credentials.
	 *
	 * In case of hierarchical file systems, passing kcred still may
	 * or may not work.
	 * For eg: UFS FS --> Mount NFS FS --> Again mount UFS on some
	 *			directory inside NFS FS.
	 */
	if ((error == EACCES) && retry_with_kcred)
		error = VOP_LOOKUP(vp, component, &cvp, pnp, lookup_flags,
		    rootvp, zone_kcred(), NULL, NULL, pp);

	if (error) {
		cvp = NULL;
		/*
		 * On error, return hard error if
		 * (a) we're not at the end of the pathname yet, or
		 * (b) the caller didn't want the parent directory, or
		 * (c) we failed for some reason other than a missing entry.
		 */
		if (pn_pathleft(pnp) || dirvpp == NULL || error != ENOENT)
			goto bad;
		if (auditing) {	/* directory access */
			if (error = audit_savepath(pnp, vp, vp, error, cr))
				goto bad_noaudit;
		}

		pn_setlast(pnp);
		/*
		 * We inform the caller that the desired entry must be
		 * a directory by adding a '/' to the component name.
		 */
		if (must_be_directory && (error = pn_addslash(pnp)) != 0)
			goto bad;
		*dirvpp = vp;
		if (compvpp != NULL)
			*compvpp = NULL;
		if (rootvp != rootdir)
			VN_RELE(rootvp);
		if (pp)
			pn_free(pp);
		return (0);
	}

	/*
	 * Traverse mount points.
	 * XXX why don't we need to hold a read lock here (call vn_vfsrlock)?
	 * What prevents a concurrent update to v_vfsmountedhere?
	 * 	Possible answer: if mounting, we might not see the mount
	 *	if it is concurrently coming into existence, but that's
	 *	really not much different from the thread running a bit slower.
	 *	If unmounting, we may get into traverse() when we shouldn't,
	 *	but traverse() will catch this case for us.
	 *	(For this to work, fetching v_vfsmountedhere had better
	 *	be atomic!)
	 */
	if (vn_mountedvfs(cvp) != NULL) {
		if ((error = traverse(&cvp)) != 0)
			goto bad;
	}

	/*
	 * If we hit a symbolic link and there is more path to be
	 * translated or this operation does not wish to apply
	 * to a link, then place the contents of the link at the
	 * front of the remaining pathname.
	 */
	if (cvp->v_type == VLNK && ((flags & FOLLOW) || pn_pathleft(pnp))) {
		struct pathname linkpath;

		if (++nlink > MAXSYMLINKS) {
			error = ELOOP;
			goto bad;
		}
		pn_alloc(&linkpath);
		if (error = pn_getsymlink(cvp, &linkpath, cr)) {
			pn_free(&linkpath);
			goto bad;
		}

		if (auditing)
			audit_symlink(pnp, &linkpath);

		if (pn_pathleft(&linkpath) == 0)
			(void) pn_set(&linkpath, ".");
		error = pn_insert(pnp, &linkpath, strlen(component));
		pn_free(&linkpath);
		if (error)
			goto bad;
		VN_RELE(cvp);
		cvp = NULL;
		if (pnp->pn_pathlen == 0) {
			error = ENOENT;
			goto bad;
		}
		if (pnp->pn_path[0] == '/') {
			do {
				pnp->pn_path++;
				pnp->pn_pathlen--;
			} while (pnp->pn_path[0] == '/');
			VN_RELE(vp);
			vp = rootvp;
			VN_HOLD(vp);
		}
		if (auditing)
			audit_anchorpath(pnp, vp == rootvp);
		if (pn_fixslash(pnp)) {
			flags |= FOLLOW;
			must_be_directory = 1;
		}
		goto next;
	}

	/*
	 * If rpnp is non-NULL, remember the resolved path name therein.
	 * Do not include "." components.  Collapse occurrences of
	 * "previous/..", so long as "previous" is not itself "..".
	 * Exhausting rpnp results in error ENAMETOOLONG.
	 */
	if (rpnp && strcmp(component, ".") != 0) {
		size_t len;

		if (strcmp(component, "..") == 0 &&
		    rpnp->pn_pathlen != 0 &&
		    !((rpnp->pn_pathlen > 2 &&
		    strncmp(rpnp->pn_path+rpnp->pn_pathlen-3, "/..", 3) == 0) ||
		    (rpnp->pn_pathlen == 2 &&
		    strncmp(rpnp->pn_path, "..", 2) == 0))) {
			while (rpnp->pn_pathlen &&
			    rpnp->pn_path[rpnp->pn_pathlen-1] != '/')
				rpnp->pn_pathlen--;
			if (rpnp->pn_pathlen > 1)
				rpnp->pn_pathlen--;
			rpnp->pn_path[rpnp->pn_pathlen] = '\0';
		} else {
			if (rpnp->pn_pathlen != 0 &&
			    rpnp->pn_path[rpnp->pn_pathlen-1] != '/')
				rpnp->pn_path[rpnp->pn_pathlen++] = '/';
			if (flags & FIGNORECASE) {
				/*
				 * Return the case-preserved name
				 * within the resolved path.
				 */
				error = copystr(pp->pn_buf,
				    rpnp->pn_path + rpnp->pn_pathlen,
				    rpnp->pn_bufsize - rpnp->pn_pathlen, &len);
			} else {
				error = copystr(component,
				    rpnp->pn_path + rpnp->pn_pathlen,
				    rpnp->pn_bufsize - rpnp->pn_pathlen, &len);
			}
			if (error)	/* copystr() returns ENAMETOOLONG */
				goto bad;
			rpnp->pn_pathlen += (len - 1);
			ASSERT(rpnp->pn_bufsize > rpnp->pn_pathlen);
		}
	}

	/*
	 * If no more components, return last directory (if wanted) and
	 * last component (if wanted).
	 */
	if (pn_pathleft(pnp) == 0) {
		/*
		 * If there was a trailing slash in the pathname,
		 * make sure the last component is a directory.
		 */
		if (must_be_directory && cvp->v_type != VDIR) {
			error = ENOTDIR;
			goto bad;
		}
		if (dirvpp != NULL) {
			/*
			 * Check that we have the real parent and not
			 * an alias of the last component.
			 */
			if (vn_compare(vp, cvp)) {
				if (auditing)
					(void) audit_savepath(pnp, cvp, vp,
					    EINVAL, cr);
				pn_setlast(pnp);
				VN_RELE(vp);
				VN_RELE(cvp);
				if (rootvp != rootdir)
					VN_RELE(rootvp);
				if (pp)
					pn_free(pp);
				return (EINVAL);
			}
			*dirvpp = vp;
		} else
			VN_RELE(vp);
		if (auditing)
			(void) audit_savepath(pnp, cvp, vp, 0, cr);
		if (pnp->pn_path == pnp->pn_buf)
			(void) pn_set(pnp, ".");
		else
			pn_setlast(pnp);
		if (rpnp) {
			if (VN_CMP(cvp, rootvp))
				(void) pn_set(rpnp, "/");
			else if (rpnp->pn_pathlen == 0)
				(void) pn_set(rpnp, ".");
		}

		if (compvpp != NULL)
			*compvpp = cvp;
		else
			VN_RELE(cvp);
		if (rootvp != rootdir)
			VN_RELE(rootvp);
		if (pp)
			pn_free(pp);
		return (0);
	}

	/*
	 * Skip over slashes from end of last component.
	 */
	while (pnp->pn_path[0] == '/') {
		pnp->pn_path++;
		pnp->pn_pathlen--;
	}

	/*
	 * Searched through another level of directory:
	 * release previous directory handle and save new (result
	 * of lookup) as current directory.
	 */
	VN_RELE(vp);
	vp = cvp;
	cvp = NULL;
	goto next;

bad:
	if (auditing)	/* reached end of path */
		(void) audit_savepath(pnp, cvp, vp, error, cr);
bad_noaudit:
	/*
	 * Error.  Release vnodes and return.
	 */
	if (cvp)
		VN_RELE(cvp);
	/*
	 * If the error was ESTALE and the current directory to look in
	 * was the root for this lookup, the root for a mounted file
	 * system, or the starting directory for lookups, then
	 * return ENOENT instead of ESTALE.  In this case, no recovery
	 * is possible by the higher level.  If ESTALE was returned for
	 * some intermediate directory along the path, then recovery
	 * is potentially possible and retrying from the higher level
	 * will either correct the situation by purging stale cache
	 * entries or eventually get back to the point where no recovery
	 * is possible.
	 */
	if (error == ESTALE &&
	    (VN_CMP(vp, rootvp) || (vp->v_flag & VROOT) || vp == startvp))
		error = ENOENT;
	VN_RELE(vp);
	if (rootvp != rootdir)
		VN_RELE(rootvp);
	if (pp)
		pn_free(pp);
	return (error);
}

/*
 * Traverse a mount point.  Routine accepts a vnode pointer as a reference
 * parameter and performs the indirection, releasing the original vnode.
 */
int
traverse(vnode_t **cvpp)
{
	int error = 0;
	vnode_t *cvp;
	vnode_t *tvp;
	vfs_t *vfsp;

	cvp = *cvpp;

	/*
	 * If this vnode is mounted on, then we transparently indirect
	 * to the vnode which is the root of the mounted file system.
	 * Before we do this we must check that an unmount is not in
	 * progress on this vnode.
	 */

	for (;;) {
		/*
		 * Try to read lock the vnode.  If this fails because
		 * the vnode is already write locked, then check to
		 * see whether it is the current thread which locked
		 * the vnode.  If it is not, then read lock the vnode
		 * by waiting to acquire the lock.
		 *
		 * The code path in domount() is an example of support
		 * which needs to look up two pathnames and locks one
		 * of them in between the two lookups.
		 */
		error = vn_vfsrlock(cvp);
		if (error) {
			if (!vn_vfswlock_held(cvp))
				error = vn_vfsrlock_wait(cvp);
			if (error != 0) {
				/*
				 * lookuppn() expects a held vnode to be
				 * returned because it promptly calls
				 * VN_RELE after the error return
				 */
				*cvpp = cvp;
				return (error);
			}
		}

		/*
		 * Reached the end of the mount chain?
		 */
		vfsp = vn_mountedvfs(cvp);
		if (vfsp == NULL) {
			vn_vfsunlock(cvp);
			break;
		}

		/*
		 * The read lock must be held across the call to VFS_ROOT() to
		 * prevent a concurrent unmount from destroying the vfs.
		 */
		error = VFS_ROOT(vfsp, &tvp);
		vn_vfsunlock(cvp);

		if (error)
			break;

		VN_RELE(cvp);

		cvp = tvp;
	}

	*cvpp = cvp;
	return (error);
}

/*
 * Return the lowermost vnode if this is a mountpoint.
 */
static vnode_t *
vn_under(vnode_t *vp)
{
	vnode_t *uvp;
	vfs_t *vfsp;

	while (vp->v_flag & VROOT) {

		vfsp = vp->v_vfsp;
		vfs_rlock_wait(vfsp);
		if ((uvp = vfsp->vfs_vnodecovered) == NULL ||
		    (vfsp->vfs_flag & VFS_UNMOUNTED)) {
			vfs_unlock(vfsp);
			break;
		}
		VN_HOLD(uvp);
		vfs_unlock(vfsp);
		VN_RELE(vp);
		vp = uvp;
	}

	return (vp);
}

static int
vnode_match(vnode_t *v1, vnode_t *v2, cred_t *cr)
{
	vattr_t	v1attr, v2attr;

	/*
	 * If we have a device file, check to see if is a cloned open of the
	 * same device.  For self-cloning devices, the major numbers will match.
	 * For devices cloned through the 'clone' driver, the minor number of
	 * the source device will be the same as the major number of the cloned
	 * device.
	 */
	if ((v1->v_type == VCHR || v1->v_type == VBLK) &&
	    v1->v_type == v2->v_type) {
		if ((spec_is_selfclone(v1) || spec_is_selfclone(v2)) &&
		    getmajor(v1->v_rdev) == getmajor(v2->v_rdev))
			return (1);

		if (spec_is_clone(v1) &&
		    getmajor(v1->v_rdev) == getminor(v2->v_rdev))
			return (1);

		if (spec_is_clone(v2) &&
		    getmajor(v2->v_rdev) == getminor(v1->v_rdev))
			return (1);
	}

	v1attr.va_mask = v2attr.va_mask = AT_TYPE;

	/*
	 * This check for symbolic links handles the pseudo-symlinks in procfs.
	 * These particular links have v_type of VDIR, but the attributes have a
	 * type of VLNK.  We need to avoid these links because otherwise if we
	 * are currently in '/proc/self/fd', then '/proc/self/cwd' will compare
	 * as the same vnode.
	 */
	if (VOP_GETATTR(v1, &v1attr, 0, cr, NULL) != 0 ||
	    VOP_GETATTR(v2, &v2attr, 0, cr, NULL) != 0 ||
	    v1attr.va_type == VLNK || v2attr.va_type == VLNK)
		return (0);

	v1attr.va_mask = v2attr.va_mask = AT_TYPE | AT_FSID | AT_NODEID;

	if (VOP_GETATTR(v1, &v1attr, ATTR_REAL, cr, NULL) != 0 ||
	    VOP_GETATTR(v2, &v2attr, ATTR_REAL, cr, NULL) != 0)
		return (0);

	return (v1attr.va_fsid == v2attr.va_fsid &&
	    v1attr.va_nodeid == v2attr.va_nodeid);
}


/*
 * Find the entry in the directory corresponding to the target vnode.
 */
int
dirfindvp(vnode_t *vrootp, vnode_t *dvp, vnode_t *tvp, cred_t *cr, char *dbuf,
    size_t dlen, dirent64_t **rdp)
{
	size_t dbuflen;
	struct iovec iov;
	struct uio uio;
	int error;
	int eof;
	vnode_t *cmpvp;
	struct dirent64 *dp;
	pathname_t pnp;

	ASSERT(dvp->v_type == VDIR);

	/*
	 * This is necessary because of the strange semantics of VOP_LOOKUP().
	 */
	bzero(&pnp, sizeof (pnp));

	eof = 0;

	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_fmode = 0;
	uio.uio_extflg = UIO_COPY_CACHED;
	uio.uio_loffset = 0;

	if ((error = VOP_ACCESS(dvp, VREAD, 0, cr, NULL)) != 0)
		return (error);

	while (!eof) {
		uio.uio_resid = dlen;
		iov.iov_base = dbuf;
		iov.iov_len = dlen;

		(void) VOP_RWLOCK(dvp, V_WRITELOCK_FALSE, NULL);
		error = VOP_READDIR(dvp, &uio, cr, &eof, NULL, 0);
		VOP_RWUNLOCK(dvp, V_WRITELOCK_FALSE, NULL);

		dbuflen = dlen - uio.uio_resid;

		if (error || dbuflen == 0)
			break;

		dp = (dirent64_t *)dbuf;
		while ((intptr_t)dp < (intptr_t)dbuf + dbuflen) {
			/*
			 * Ignore '.' and '..' entries
			 */
			if (strcmp(dp->d_name, ".") == 0 ||
			    strcmp(dp->d_name, "..") == 0) {
				dp = (dirent64_t *)((intptr_t)dp +
				    dp->d_reclen);
				continue;
			}

			error = VOP_LOOKUP(dvp, dp->d_name, &cmpvp, &pnp, 0,
			    vrootp, cr, NULL, NULL, NULL);

			/*
			 * We only want to bail out if there was an error other
			 * than ENOENT.  Otherwise, it could be that someone
			 * just removed an entry since the readdir() call, and
			 * the entry we want is further on in the directory.
			 */
			if (error == 0) {
				if (vnode_match(tvp, cmpvp, cr)) {
					VN_RELE(cmpvp);
					*rdp = dp;
					return (0);
				}

				VN_RELE(cmpvp);
			} else if (error != ENOENT) {
				return (error);
			}

			dp = (dirent64_t *)((intptr_t)dp + dp->d_reclen);
		}
	}

	/*
	 * Something strange has happened, this directory does not contain the
	 * specified vnode.  This should never happen in the normal case, since
	 * we ensured that dvp is the parent of vp.  This is possible in some
	 * rare conditions (races and the special .zfs directory).
	 */
	if (error == 0) {
		error = VOP_LOOKUP(dvp, ".zfs", &cmpvp, &pnp, 0, vrootp, cr,
		    NULL, NULL, NULL);
		if (error == 0) {
			if (vnode_match(tvp, cmpvp, cr)) {
				(void) strcpy(dp->d_name, ".zfs");
				dp->d_reclen = strlen(".zfs");
				dp->d_off = 2;
				dp->d_ino = 1;
				*rdp = dp;
			} else {
				error = ENOENT;
			}
			VN_RELE(cmpvp);
		}
	}

	return (error);
}

/*
 * Given a global path (from rootdir), and a vnode that is the current root,
 * return the portion of the path that is beneath the current root or NULL on
 * failure.  The path MUST be a resolved path (no '..' entries or symlinks),
 * otherwise this function will fail.
 */
static char *
localpath(char *path, struct vnode *vrootp, cred_t *cr)
{
	vnode_t *vp;
	vnode_t *cvp;
	char component[MAXNAMELEN];
	char *ret = NULL;
	pathname_t pn;

	/*
	 * We use vn_compare() instead of VN_CMP() in order to detect lofs
	 * mounts and stacked vnodes.
	 */
	if (vn_compare(vrootp, rootdir))
		return (path);

	if (pn_get(path, UIO_SYSSPACE, &pn) != 0)
		return (NULL);

	vp = rootdir;
	VN_HOLD(vp);

	if (vn_ismntpt(vp) && traverse(&vp) != 0) {
		VN_RELE(vp);
		pn_free(&pn);
		return (NULL);
	}

	while (pn_pathleft(&pn)) {
		pn_skipslash(&pn);

		if (pn_getcomponent(&pn, component) != 0)
			break;

		if (VOP_LOOKUP(vp, component, &cvp, &pn, 0, rootdir, cr,
		    NULL, NULL, NULL) != 0)
			break;
		VN_RELE(vp);
		vp = cvp;

		if (vn_ismntpt(vp) && traverse(&vp) != 0)
			break;

		if (vn_compare(vp, vrootp)) {
			ret = path + (pn.pn_path - pn.pn_buf);
			break;
		}
	}

	VN_RELE(vp);
	pn_free(&pn);

	return (ret);
}

/*
 * Given a directory, return the full, resolved path.  This looks up "..",
 * searches for the given vnode in the parent, appends the component, etc.  It
 * is used to implement vnodetopath() and getcwd() when the cached path fails.
 */
static int
dirtopath(vnode_t *vrootp, vnode_t *vp, char *buf, size_t buflen, int flags,
    cred_t *cr)
{
	pathname_t pn, rpn, emptypn;
	vnode_t *cmpvp, *pvp = NULL;
	vnode_t *startvp = vp;
	int err = 0, vprivs;
	size_t complen;
	char *dbuf;
	dirent64_t *dp;
	char		*bufloc;
	size_t		dlen = DIRENT64_RECLEN(MAXPATHLEN);
	refstr_t	*mntpt;

	/* Operation only allowed on directories */
	ASSERT(vp->v_type == VDIR);

	/* We must have at least enough space for "/" */
	if (buflen < 2)
		return (ENAMETOOLONG);

	/* Start at end of string with terminating null */
	bufloc = &buf[buflen - 1];
	*bufloc = '\0';

	pn_alloc(&pn);
	pn_alloc(&rpn);
	dbuf = kmem_alloc(dlen, KM_SLEEP);
	bzero(&emptypn, sizeof (emptypn));

	/*
	 * Begin with an additional reference on vp.  This will be decremented
	 * during the loop.
	 */
	VN_HOLD(vp);

	for (;;) {
		/*
		 * Return if we've reached the root.  If the buffer is empty,
		 * return '/'.  We explicitly don't use vn_compare(), since it
		 * compares the real vnodes.  A lofs mount of '/' would produce
		 * incorrect results otherwise.
		 */
		if (VN_CMP(vrootp, vp)) {
			if (*bufloc == '\0')
				*--bufloc = '/';
			break;
		}

		/*
		 * If we've reached the VFS root, something has gone wrong.  We
		 * should have reached the root in the above check.  The only
		 * explantation is that 'vp' is not contained withing the given
		 * root, in which case we return EPERM.
		 */
		if (VN_CMP(rootdir, vp)) {
			err = EPERM;
			goto out;
		}

		/*
		 * Shortcut: see if this vnode is a mountpoint.  If so,
		 * grab the path information from the vfs_t.
		 */
		if (vp->v_flag & VROOT) {

			mntpt = vfs_getmntpoint(vp->v_vfsp);
			if ((err = pn_set(&pn, (char *)refstr_value(mntpt)))
			    == 0) {
				refstr_rele(mntpt);
				rpn.pn_path = rpn.pn_buf;

				/*
				 * Ensure the mountpoint still exists.
				 */
				VN_HOLD(vrootp);
				if (vrootp != rootdir)
					VN_HOLD(vrootp);
				if (lookuppnvp(&pn, &rpn, flags, NULL,
				    &cmpvp, vrootp, vrootp, cr) == 0) {

					if (VN_CMP(vp, cmpvp)) {
						VN_RELE(cmpvp);

						complen = strlen(rpn.pn_path);
						bufloc -= complen;
						if (bufloc < buf) {
							err = ERANGE;
							goto out;
						}
						bcopy(rpn.pn_path, bufloc,
						    complen);
						break;
					} else {
						VN_RELE(cmpvp);
					}
				}
			} else {
				refstr_rele(mntpt);
			}
		}

		/*
		 * Shortcut: see if this vnode has correct v_path. If so,
		 * we have the work done.
		 */
		mutex_enter(&vp->v_lock);
		if (vp->v_path != NULL) {

			if ((err = pn_set(&pn, vp->v_path)) == 0) {
				mutex_exit(&vp->v_lock);
				rpn.pn_path = rpn.pn_buf;

				/*
				 * Ensure the v_path pointing to correct vnode
				 */
				VN_HOLD(vrootp);
				if (vrootp != rootdir)
					VN_HOLD(vrootp);
				if (lookuppnvp(&pn, &rpn, flags, NULL,
				    &cmpvp, vrootp, vrootp, cr) == 0) {

					if (VN_CMP(vp, cmpvp)) {
						VN_RELE(cmpvp);

						complen = strlen(rpn.pn_path);
						bufloc -= complen;
						if (bufloc < buf) {
							err = ERANGE;
							goto out;
						}
						bcopy(rpn.pn_path, bufloc,
						    complen);
						break;
					} else {
						VN_RELE(cmpvp);
					}
				}
			} else {
				mutex_exit(&vp->v_lock);
			}
		} else {
			mutex_exit(&vp->v_lock);
		}

		/*
		 * Shortcuts failed, search for this vnode in its parent.  If
		 * this is a mountpoint, then get the vnode underneath.
		 */
		if (vp->v_flag & VROOT)
			vp = vn_under(vp);
		if ((err = VOP_LOOKUP(vp, "..", &pvp, &emptypn, 0, vrootp, cr,
		    NULL, NULL, NULL)) != 0)
			goto out;

		/*
		 * With extended attributes, it's possible for a directory to
		 * have a parent that is a regular file.  Check for that here.
		 */
		if (pvp->v_type != VDIR) {
			err = ENOTDIR;
			goto out;
		}

		/*
		 * If this is true, something strange has happened.  This is
		 * only true if we are the root of a filesystem, which should
		 * have been caught by the check above.
		 */
		if (VN_CMP(pvp, vp)) {
			err = ENOENT;
			goto out;
		}

		/*
		 * Check if we have read and search privilege so, that
		 * we can lookup the path in the directory
		 */
		vprivs = (flags & LOOKUP_CHECKREAD) ? VREAD | VEXEC : VEXEC;
		if ((err = VOP_ACCESS(pvp, vprivs, 0, cr, NULL)) != 0) {
			goto out;
		}

		/*
		 * Search the parent directory for the entry corresponding to
		 * this vnode.
		 */
		if ((err = dirfindvp(vrootp, pvp, vp, cr, dbuf, dlen, &dp))
		    != 0)
			goto out;
		complen = strlen(dp->d_name);
		bufloc -= complen;
		if (bufloc <= buf) {
			err = ENAMETOOLONG;
			goto out;
		}
		bcopy(dp->d_name, bufloc, complen);

		/* Prepend a slash to the current path.  */
		*--bufloc = '/';

		/* And continue with the next component */
		VN_RELE(vp);
		vp = pvp;
		pvp = NULL;
	}

	/*
	 * Place the path at the beginning of the buffer.
	 */
	if (bufloc != buf)
		ovbcopy(bufloc, buf, buflen - (bufloc - buf));

out:
	/*
	 * If the error was ESTALE and the current directory to look in
	 * was the root for this lookup, the root for a mounted file
	 * system, or the starting directory for lookups, then
	 * return ENOENT instead of ESTALE.  In this case, no recovery
	 * is possible by the higher level.  If ESTALE was returned for
	 * some intermediate directory along the path, then recovery
	 * is potentially possible and retrying from the higher level
	 * will either correct the situation by purging stale cache
	 * entries or eventually get back to the point where no recovery
	 * is possible.
	 */
	if (err == ESTALE &&
	    (VN_CMP(vp, vrootp) || (vp->v_flag & VROOT) || vp == startvp))
		err = ENOENT;

	kmem_free(dbuf, dlen);
	VN_RELE(vp);
	if (pvp)
		VN_RELE(pvp);
	pn_free(&pn);
	pn_free(&rpn);

	return (err);
}

/*
 * The additional flag, LOOKUP_CHECKREAD, is used to enforce artificial
 * constraints in order to be standards compliant.  For example, if we have
 * the cached path of '/foo/bar', and '/foo' has permissions 100 (execute
 * only), then we can legitimately look up the path to the current working
 * directory without needing read permission.  Existing standards tests,
 * however, assume that we are determining the path by repeatedly looking up
 * "..".  We need to keep this behavior in order to maintain backwards
 * compatibility.
 */
static int
vnodetopath_common(vnode_t *vrootp, vnode_t *vp, char *buf, size_t buflen,
    cred_t *cr, int flags)
{
	pathname_t pn, rpn;
	int ret;
	vnode_t *compvp, *realvp;
	proc_t *p = curproc;
	int doclose = 0;

	/*
	 * If vrootp is NULL, get the root for curproc.  Callers with any other
	 * requirements should pass in a different vrootp.
	 */
	if (vrootp == NULL) {
		mutex_enter(&p->p_lock);
		if ((vrootp = PTOU(p)->u_rdir) == NULL)
			vrootp = rootdir;
		VN_HOLD(vrootp);
		mutex_exit(&p->p_lock);
	} else {
		VN_HOLD(vrootp);
	}

	/*
	 * This is to get around an annoying artifact of the /proc filesystem,
	 * which is the behavior of {cwd/root}.  Trying to resolve this path
	 * will result in /proc/pid/cwd instead of whatever the real working
	 * directory is.  We can't rely on VOP_REALVP(), since that will break
	 * lofs.  The only difference between procfs and lofs is that opening
	 * the file will return the underling vnode in the case of procfs.
	 */
	if (vp->v_type == VDIR && VOP_REALVP(vp, &realvp, NULL) == 0 &&
	    realvp != vp) {
		VN_HOLD(vp);
		if (VOP_OPEN(&vp, FREAD, cr, NULL) == 0)
			doclose = 1;
		else
			VN_RELE(vp);
	}

	pn_alloc(&pn);

	/*
	 * Check to see if we have a cached path in the vnode.
	 */
	mutex_enter(&vp->v_lock);
	if (vp->v_path != NULL) {
		(void) pn_set(&pn, vp->v_path);
		mutex_exit(&vp->v_lock);

		pn_alloc(&rpn);

		/* We should only cache absolute paths */
		ASSERT(pn.pn_buf[0] == '/');

		/*
		 * If we are in a zone or a chroot environment, then we have to
		 * take additional steps, since the path to the root might not
		 * be readable with the current credentials, even though the
		 * process can legitmately access the file.  In this case, we
		 * do the following:
		 *
		 * lookuppnvp() with all privileges to get the resolved path.
		 * call localpath() to get the local portion of the path, and
		 * continue as normal.
		 *
		 * If the the conversion to a local path fails, then we continue
		 * as normal.  This is a heuristic to make process object file
		 * paths available from within a zone.  Because lofs doesn't
		 * support page operations, the vnode stored in the seg_t is
		 * actually the underlying real vnode, not the lofs node itself.
		 * Most of the time, the lofs path is the same as the underlying
		 * vnode (for example, /usr/lib/libc.so.1).
		 */
		if (vrootp != rootdir) {
			char *local = NULL;
			VN_HOLD(rootdir);
			if (lookuppnvp(&pn, &rpn, FOLLOW,
			    NULL, &compvp, rootdir, rootdir, kcred) == 0) {
				local = localpath(rpn.pn_path, vrootp,
				    kcred);
				VN_RELE(compvp);
			}

			/*
			 * The original pn was changed through lookuppnvp().
			 * Set it to local for next validation attempt.
			 */
			if (local) {
				(void) pn_set(&pn, local);
			} else {
				goto notcached;
			}
		}

		/*
		 * We should have a local path at this point, so start the
		 * search from the root of the current process.
		 */
		VN_HOLD(vrootp);
		if (vrootp != rootdir)
			VN_HOLD(vrootp);
		ret = lookuppnvp(&pn, &rpn, FOLLOW | flags, NULL,
		    &compvp, vrootp, vrootp, cr);
		if (ret == 0) {
			/*
			 * Check to see if the returned vnode is the same as
			 * the one we expect.  If not, give up.
			 */
			if (!vn_compare(vp, compvp) &&
			    !vnode_match(vp, compvp, cr)) {
				VN_RELE(compvp);
				goto notcached;
			}

			VN_RELE(compvp);

			/*
			 * Return the result.
			 */
			if (buflen <= rpn.pn_pathlen)
				goto notcached;

			bcopy(rpn.pn_path, buf, rpn.pn_pathlen + 1);
			pn_free(&pn);
			pn_free(&rpn);
			VN_RELE(vrootp);
			if (doclose) {
				(void) VOP_CLOSE(vp, FREAD, 1, 0, cr, NULL);
				VN_RELE(vp);
			}
			return (0);
		}

notcached:
		pn_free(&rpn);
	} else {
		mutex_exit(&vp->v_lock);
	}

	pn_free(&pn);

	if (vp->v_type != VDIR) {
		ret = ENOENT;
	} else {
		ret = dirtopath(vrootp, vp, buf, buflen, flags, cr);
	}

	VN_RELE(vrootp);
	if (doclose) {
		(void) VOP_CLOSE(vp, FREAD, 1, 0, cr, NULL);
		VN_RELE(vp);
	}

	return (ret);
}

int
vnodetopath(vnode_t *vrootp, vnode_t *vp, char *buf, size_t buflen, cred_t *cr)
{
	return (vnodetopath_common(vrootp, vp, buf, buflen, cr, 0));
}

int
dogetcwd(char *buf, size_t buflen)
{
	int ret;
	vnode_t *vp;
	vnode_t *compvp;
	refstr_t *cwd, *oldcwd;
	const char *value;
	pathname_t rpnp, pnp;
	proc_t *p = curproc;

	/*
	 * Check to see if there is a cached version of the cwd.  If so, lookup
	 * the cached value and make sure it is the same vnode.
	 */
	mutex_enter(&p->p_lock);
	if ((cwd = PTOU(p)->u_cwd) != NULL)
		refstr_hold(cwd);
	vp = PTOU(p)->u_cdir;
	VN_HOLD(vp);
	mutex_exit(&p->p_lock);

	/*
	 * Make sure we have permission to access the current directory.
	 */
	if ((ret = VOP_ACCESS(vp, VEXEC, 0, CRED(), NULL)) != 0) {
		if (cwd != NULL)
			refstr_rele(cwd);
		VN_RELE(vp);
		return (ret);
	}

	if (cwd) {
		value = refstr_value(cwd);
		if ((ret = pn_get((char *)value, UIO_SYSSPACE, &pnp)) != 0) {
			refstr_rele(cwd);
			VN_RELE(vp);
			return (ret);
		}

		pn_alloc(&rpnp);

		if (lookuppn(&pnp, &rpnp, NO_FOLLOW, NULL, &compvp) == 0) {

			if (VN_CMP(vp, compvp) &&
			    strcmp(value, rpnp.pn_path) == 0) {
				VN_RELE(compvp);
				VN_RELE(vp);
				pn_free(&pnp);
				pn_free(&rpnp);
				if (strlen(value) + 1 > buflen) {
					refstr_rele(cwd);
					return (ENAMETOOLONG);
				}
				bcopy(value, buf, strlen(value) + 1);
				refstr_rele(cwd);
				return (0);
			}

			VN_RELE(compvp);
		}

		pn_free(&rpnp);
		pn_free(&pnp);

		refstr_rele(cwd);
	}

	ret = vnodetopath_common(NULL, vp, buf, buflen, CRED(),
	    LOOKUP_CHECKREAD);

	VN_RELE(vp);

	/*
	 * Store the new cwd and replace the existing cached copy.
	 */
	if (ret == 0)
		cwd = refstr_alloc(buf);
	else
		cwd = NULL;

	mutex_enter(&p->p_lock);
	oldcwd = PTOU(p)->u_cwd;
	PTOU(p)->u_cwd = cwd;
	mutex_exit(&p->p_lock);

	if (oldcwd)
		refstr_rele(oldcwd);

	return (ret);
}
