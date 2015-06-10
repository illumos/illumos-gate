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
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
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
#include <sys/file.h>
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
#include <sys/zone.h>
#include <sys/dnlc.h>
#include <sys/fs/snode.h>

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
	vnode_t *tvp;	/* addressable temp ptr */
	char component[MAXNAMELEN];	/* buffer for component (incl null) */
	int error;
	int nlink;
	int lookup_flags;
	struct pathname presrvd; /* case preserved name */
	struct pathname *pp = NULL;
	vnode_t *startvp;
	int must_be_directory = 0;
	boolean_t retry_with_kcred;

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
		if (VN_CMP(vp, rootvp)) {
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
	 * Perform a lookup in the current directory.
	 */
	error = VOP_LOOKUP(vp, component, &tvp, pnp, lookup_flags,
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
		error = VOP_LOOKUP(vp, component, &tvp, pnp, lookup_flags,
		    rootvp, zone_kcred(), NULL, NULL, pp);

	cvp = tvp;
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
	 */
	if (vn_mountedvfs(cvp) != NULL) {
		tvp = cvp;
		if ((error = traverse(&tvp)) != 0) {
			/*
			 * It is required to assign cvp here, because
			 * traverse() will return a held vnode which
			 * may different than the vnode that was passed
			 * in (even in the error case).  If traverse()
			 * changes the vnode it releases the original,
			 * and holds the new one.
			 */
			cvp = tvp;
			goto bad;
		}
		cvp = tvp;
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
		 * Used to try to read lock the vnode here.
		 */

		/*
		 * Reached the end of the mount chain?
		 */
		vfsp = vn_mountedvfs(cvp);
		if (vfsp == NULL) {
			break;
		}

		/*
		 * The read lock must be held across the call to VFS_ROOT() to
		 * prevent a concurrent unmount from destroying the vfs.
		 */
		error = VFS_ROOT(vfsp, &tvp);
		if (error)
			break;

		VN_RELE(cvp);

		cvp = tvp;
	}

	*cvpp = cvp;
	return (error);
}

/*
 * Get the vnode path, relative to the passed rootvp.
 * Our vncache always fills in v_path, so this is easy.
 */
/* ARGSUSED */
int
vnodetopath(vnode_t *vrootp, vnode_t *vp, char *buf, size_t buflen, cred_t *cr)
{
	int len, rvp_len = 0;
	const char *p = vp->v_path;

	if (vrootp)
		rvp_len = strlen(vrootp->v_path);
	len = strlen(p);
	if (rvp_len < len)
		p += rvp_len;
	else
		p = "/";

	(void) strlcpy(buf, p, buflen);
	return (0);
}
