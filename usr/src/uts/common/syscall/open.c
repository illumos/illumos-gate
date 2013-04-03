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
 * Copyright (c) 1994, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright (c) 2013, OmniTI Computer Consulting, Inc. All rights reserved.
 */
/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#include <sys/param.h>
#include <sys/isa_defs.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/user.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/file.h>
#include <sys/mode.h>
#include <sys/uio.h>
#include <sys/debug.h>
#include <c2/audit.h>

/*
 * Common code for openat().  Check permissions, allocate an open
 * file structure, and call the device open routine (if any).
 */

static int
copen(int startfd, char *fname, int filemode, int createmode)
{
	struct pathname pn;
	vnode_t *vp, *sdvp;
	file_t *fp, *startfp;
	enum vtype type;
	int error;
	int fd, dupfd;
	vnode_t *startvp;
	proc_t *p = curproc;
	uio_seg_t seg = UIO_USERSPACE;
	char *open_filename = fname;
	uint32_t auditing = AU_AUDITING();
	char startchar;

	if (filemode & (FSEARCH|FEXEC)) {
		/*
		 * Must be one or the other and neither FREAD nor FWRITE
		 * Must not be any of FAPPEND FCREAT FTRUNC FXATTR FXATTRDIROPEN
		 * XXX: Should these just be silently ignored?
		 */
		if ((filemode & (FREAD|FWRITE)) ||
		    (filemode & (FSEARCH|FEXEC)) == (FSEARCH|FEXEC) ||
		    (filemode & (FAPPEND|FCREAT|FTRUNC|FXATTR|FXATTRDIROPEN)))
			return (set_errno(EINVAL));
	}

	if (startfd == AT_FDCWD) {
		/*
		 * Regular open()
		 */
		startvp = NULL;
	} else {
		/*
		 * We're here via openat()
		 */
		if (copyin(fname, &startchar, sizeof (char)))
			return (set_errno(EFAULT));

		/*
		 * if startchar is / then startfd is ignored
		 */
		if (startchar == '/')
			startvp = NULL;
		else {
			if ((startfp = getf(startfd)) == NULL)
				return (set_errno(EBADF));
			startvp = startfp->f_vnode;
			VN_HOLD(startvp);
			releasef(startfd);
		}
	}

	/*
	 * Handle __openattrdirat() requests
	 */
	if (filemode & FXATTRDIROPEN) {
		if (auditing && startvp != NULL)
			audit_setfsat_path(1);
		if (error = lookupnameat(fname, seg, FOLLOW,
		    NULLVPP, &vp, startvp))
			return (set_errno(error));
		if (startvp != NULL)
			VN_RELE(startvp);

		startvp = vp;
	}

	/*
	 * Do we need to go into extended attribute space?
	 */
	if (filemode & FXATTR) {
		if (startfd == AT_FDCWD) {
			if (copyin(fname, &startchar, sizeof (char)))
				return (set_errno(EFAULT));

			/*
			 * If startchar == '/' then no extended attributes
			 * are looked up.
			 */
			if (startchar == '/') {
				startvp = NULL;
			} else {
				mutex_enter(&p->p_lock);
				startvp = PTOU(p)->u_cdir;
				VN_HOLD(startvp);
				mutex_exit(&p->p_lock);
			}
		}

		/*
		 * Make sure we have a valid extended attribute request.
		 * We must either have a real fd or AT_FDCWD and a relative
		 * pathname.
		 */
		if (startvp == NULL) {
			goto noxattr;
		}
	}

	if (filemode & (FXATTR|FXATTRDIROPEN)) {
		vattr_t vattr;

		if (error = pn_get(fname, UIO_USERSPACE, &pn)) {
			goto out;
		}

		/*
		 * In order to access hidden attribute directory the
		 * user must be able to stat() the file
		 */
		vattr.va_mask = AT_ALL;
		if (error = VOP_GETATTR(startvp, &vattr, 0, CRED(), NULL)) {
			pn_free(&pn);
			goto out;
		}

		if ((startvp->v_vfsp->vfs_flag & VFS_XATTR) != 0 ||
		    vfs_has_feature(startvp->v_vfsp, VFSFT_SYSATTR_VIEWS)) {
			error = VOP_LOOKUP(startvp, "", &sdvp, &pn,
			    (filemode & FXATTRDIROPEN) ? LOOKUP_XATTR :
			    LOOKUP_XATTR|CREATE_XATTR_DIR, rootvp, CRED(),
			    NULL, NULL, NULL);
		} else {
			error = EINVAL;
		}

		/*
		 * For __openattrdirat() use "." as filename to open
		 * as part of vn_openat()
		 */
		if (error == 0 && (filemode & FXATTRDIROPEN)) {
			open_filename = ".";
			seg = UIO_SYSSPACE;
		}

		pn_free(&pn);
		if (error != 0)
			goto out;

		VN_RELE(startvp);
		startvp = sdvp;
	}

noxattr:
	if ((filemode & (FREAD|FWRITE|FSEARCH|FEXEC|FXATTRDIROPEN)) != 0) {
		if ((filemode & (FNONBLOCK|FNDELAY)) == (FNONBLOCK|FNDELAY))
			filemode &= ~FNDELAY;
		error = falloc((vnode_t *)NULL, filemode, &fp, &fd);
		if (error == 0) {
			if (auditing && startvp != NULL)
				audit_setfsat_path(1);
			/*
			 * Last arg is a don't-care term if
			 * !(filemode & FCREAT).
			 */
			error = vn_openat(open_filename, seg, filemode,
			    (int)(createmode & MODEMASK),
			    &vp, CRCREAT, PTOU(curproc)->u_cmask,
			    startvp, fd);

			if (startvp != NULL)
				VN_RELE(startvp);
			if (error == 0) {
				if ((vp->v_flag & VDUP) == 0) {
					fp->f_vnode = vp;
					mutex_exit(&fp->f_tlock);
					/*
					 * We must now fill in the slot
					 * falloc reserved.
					 */
					setf(fd, fp);
					if ((filemode & FCLOEXEC) != 0) {
						f_setfd(fd, FD_CLOEXEC);
					}
					return (fd);
				} else {
					/*
					 * Special handling for /dev/fd.
					 * Give up the file pointer
					 * and dup the indicated file descriptor
					 * (in v_rdev). This is ugly, but I've
					 * seen worse.
					 */
					unfalloc(fp);
					dupfd = getminor(vp->v_rdev);
					type = vp->v_type;
					mutex_enter(&vp->v_lock);
					vp->v_flag &= ~VDUP;
					mutex_exit(&vp->v_lock);
					VN_RELE(vp);
					if (type != VCHR)
						return (set_errno(EINVAL));
					if ((fp = getf(dupfd)) == NULL) {
						setf(fd, NULL);
						return (set_errno(EBADF));
					}
					mutex_enter(&fp->f_tlock);
					fp->f_count++;
					mutex_exit(&fp->f_tlock);
					setf(fd, fp);
					if ((filemode & FCLOEXEC) != 0) {
						f_setfd(fd, FD_CLOEXEC);
					}
					releasef(dupfd);
				}
				return (fd);
			} else {
				setf(fd, NULL);
				unfalloc(fp);
				return (set_errno(error));
			}
		}
	} else {
		error = EINVAL;
	}
out:
	if (startvp != NULL)
		VN_RELE(startvp);
	return (set_errno(error));
}

#define	OPENMODE32(fmode)	(((fmode) & (FSEARCH | FEXEC))? \
				    (fmode) : (fmode) - FOPEN)
#define	OPENMODE64(fmode)	(OPENMODE32(fmode) | FOFFMAX)
#ifdef _LP64
#define	OPENMODE(fmode)		OPENMODE64(fmode)
#else
#define	OPENMODE(fmode)		OPENMODE32(fmode)
#endif

/*
 * Open a file.
 */
int
openat(int fd, char *path, int fmode, int cmode)
{
	return (copen(fd, path, OPENMODE(fmode), cmode));
}

int
open(char *path, int fmode, int cmode)
{
	return (openat(AT_FDCWD, path, fmode, cmode));
}

#if defined(_ILP32) || defined(_SYSCALL32_IMPL)
/*
 * Open for large files in 32-bit environment. Sets the FOFFMAX flag.
 */
int
openat64(int fd, char *path, int fmode, int cmode)
{
	return (copen(fd, path, OPENMODE64(fmode), cmode));
}

int
open64(char *path, int fmode, int cmode)
{
	return (openat64(AT_FDCWD, path, fmode, cmode));
}

#endif	/* _ILP32 || _SYSCALL32_IMPL */

#ifdef _SYSCALL32_IMPL
/*
 * Open for 32-bit compatibility on 64-bit kernel
 */
int
openat32(int fd, char *path, int fmode, int cmode)
{
	return (copen(fd, path, OPENMODE32(fmode), cmode));
}

int
open32(char *path, int fmode, int cmode)
{
	return (openat32(AT_FDCWD, path, fmode, cmode));
}

#endif	/* _SYSCALL32_IMPL */
