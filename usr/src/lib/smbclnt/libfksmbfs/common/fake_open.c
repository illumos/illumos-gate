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
 * Copyright 2017, Joyent, Inc.
 * Copyright (c) 2011, 2017 by Delphix. All rights reserved.
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
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
 * Portions of code from both of:
 *	syscall/open.c
 *	fs/vnode.c
 * heavily modified for this use.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/t_lock.h>
#include <sys/errno.h>
#include <sys/cred.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <sys/file.h>
#include <sys/pathname.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/vnode.h>
#include <sys/rwstlock.h>
#include <sys/fem.h>
#include <sys/stat.h>
#include <sys/mode.h>
#include <sys/conf.h>
#include <sys/sysmacros.h>
#include <sys/cmn_err.h>
#include <sys/systm.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/acl.h>
#include <sys/nbmlock.h>
#include <sys/fcntl.h>
#include <fs/fs_subr.h>
#include <sys/taskq.h>
#include <fs/fs_reparse.h>
#include <sys/time.h>

#include <libfksmbfs.h>

/* close and release */
int
vn_close_rele(vnode_t *vp, int flag)
{
	int error;

	error = VOP_CLOSE(vp, flag, 0, 0, CRED(), NULL);
	vn_rele(vp);

	return (error);
}

/*
 * Open/create a vnode.
 * This may be callable by the kernel, the only known use
 * of user context being that the current user credentials
 * are used for permissions.  crwhy is defined iff filemode & FCREAT.
 */
int
vn_open(
	char *pnamep,
	enum uio_seg seg,
	int filemode,
	int createmode,
	struct vnode **vpp,
	enum create crwhy,
	mode_t umask)
{
	struct vnode *vp;
	int mode;
	int accessflags;
	int error;
	int open_done = 0;
	struct vattr vattr;
	int estale_retry = 0;

	mode = 0;
	accessflags = 0;
	if (filemode & FREAD)
		mode |= VREAD;
	if (filemode & (FWRITE|FTRUNC))
		mode |= VWRITE;
	if (filemode & (FSEARCH|FEXEC|FXATTRDIROPEN))
		mode |= VEXEC;

	if (filemode & FAPPEND)
		accessflags |= V_APPEND;

top:
	if (filemode & FCREAT) {
		enum vcexcl excl;

		/*
		 * Wish to create a file.
		 */
		vattr.va_type = VREG;
		vattr.va_mode = createmode;
		vattr.va_mask = AT_TYPE|AT_MODE;
		if (filemode & FTRUNC) {
			vattr.va_size = 0;
			vattr.va_mask |= AT_SIZE;
		}
		if (filemode & FEXCL)
			excl = EXCL;
		else
			excl = NONEXCL;

		if ((error =
		    vn_create(pnamep, seg, &vattr, excl, mode, &vp, crwhy,
		    (filemode & ~(FTRUNC|FEXCL)), umask)) != 0)
			return (error);
	} else {
		/*
		 * Wish to open a file.  Just look it up.
		 * Was lookupnameat()
		 */
		if ((error = fake_lookup(NULL, pnamep, &vp)) != 0) {
			if ((error == ESTALE) &&
			    fs_need_estale_retry(estale_retry++))
				goto top;
			return (error);
		}

		/*
		 * Want the XATTRDIR under it?
		 */
		if (filemode & FXATTRDIROPEN) {
			vnode_t *xvp = NULL;
			error = VOP_LOOKUP(vp, NULL, &xvp, NULL,
			    LOOKUP_XATTR, rootdir, CRED(), NULL,
			    NULL, NULL);
			VN_RELE(vp);
			vp = xvp;
			/* continue with vp */
		}

		/*
		 * Can't write directories, active texts, or
		 * read-only filesystems.  Can't truncate files
		 * on which mandatory locking is in effect.
		 */
		if (filemode & (FWRITE|FTRUNC)) {
			if (vp->v_type == VDIR) {
				error = EISDIR;
				goto out;
			}
		}
		/*
		 * Check permissions.
		 */
		if (error = VOP_ACCESS(vp, mode, accessflags, CRED(), NULL))
			goto out;
		/*
		 * Require FSEARCH to return a directory.
		 * Require FEXEC to return a regular file.
		 */
		if ((filemode & FSEARCH) && vp->v_type != VDIR) {
			error = ENOTDIR;
			goto out;
		}
		if ((filemode & FEXEC) && vp->v_type != VREG) {
			error = ENOEXEC;
			goto out;
		}
	}

	/*
	 * Do remaining checks for FNOFOLLOW and FNOLINKS.
	 */
	if ((filemode & FNOFOLLOW) && vp->v_type == VLNK) {
		error = ELOOP;
		goto out;
	}
	if (filemode & FNOLINKS) {
		vattr.va_mask = AT_NLINK;
		if ((error = VOP_GETATTR(vp, &vattr, 0, CRED(), NULL))) {
			goto out;
		}
		if (vattr.va_nlink != 1) {
			error = EMLINK;
			goto out;
		}
	}

	/*
	 * Opening a socket corresponding to the AF_UNIX pathname
	 * in the filesystem name space is not supported...
	 */
	if (vp->v_type == VSOCK) {
		error = EOPNOTSUPP;
		goto out;
	}

	/*
	 * Do opening protocol.
	 */
	error = VOP_OPEN(&vp, filemode, CRED(), NULL);
	if (error)
		goto out;
	open_done = 1;

	/*
	 * Truncate if required.
	 */
	if ((filemode & FTRUNC) && !(filemode & FCREAT)) {
		vattr.va_size = 0;
		vattr.va_mask = AT_SIZE;
		if ((error = VOP_SETATTR(vp, &vattr, 0, CRED(), NULL)) != 0)
			goto out;
	}
out:
	ASSERT(vp->v_count > 0);

	if (error) {
		if (open_done) {
			(void) VOP_CLOSE(vp, filemode, 1, (offset_t)0, CRED(),
			    NULL);
			open_done = 0;
		}
		VN_RELE(vp);
	} else
		*vpp = vp;
	return (error);
}


/*
 * Create a vnode (makenode).
 */
int
vn_create(
	char *pnamep,
	enum uio_seg seg,
	struct vattr *vap,
	enum vcexcl excl,
	int mode,
	struct vnode **vpp,
	enum create why,
	int flag,
	mode_t umask)
{
	struct vnode *dvp = NULL;	/* ptr to parent dir vnode */
	char *lastcomp = NULL;
	int error;

	ASSERT((vap->va_mask & (AT_TYPE|AT_MODE)) == (AT_TYPE|AT_MODE));

	flag &= ~(FNOFOLLOW|FNOLINKS);

	*vpp = NULL;

	/*
	 * Lookup directory and last component
	 */
	error = fake_lookup_dir(pnamep, &dvp, &lastcomp);
	if (error != 0) {
		/* dir not found */
		return (error);
	}

	/*
	 * If default ACLs are defined for the directory don't apply the
	 * umask if umask is passed.
	 */

	if (umask) {
		/*
		 * Apply the umask if no default ACLs...
		 */
		vap->va_mode &= ~umask;
	}

	if (dvp->v_vfsp->vfs_flag & VFS_RDONLY) {
		error = EROFS;
		goto out;
	}

	/*
	 * Call mkdir() if specified, otherwise create().
	 */
	if (why == CRMKDIR) {
		/*
		 * N.B., if vn_createat() ever requests
		 * case-insensitive behavior then it will need
		 * to be passed to VOP_MKDIR().  VOP_CREATE()
		 * will already get it via "flag"
		 */
		error = VOP_MKDIR(dvp, lastcomp, vap, vpp, CRED(),
		    NULL, 0, NULL);
	} else {
		error = VOP_CREATE(dvp, lastcomp, vap,
		    excl, mode, vpp, CRED(), flag, NULL, NULL);
	}

out:
	if (dvp != NULL)
		VN_RELE(dvp);

	return (error);
}
