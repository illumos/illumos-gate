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
 * Copyright (c) 2013, OmniTI Computer Consulting, Inc. All rights reserved.
 * Copyright 2018, Joyent, Inc.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */


#include <sys/param.h>
#include <sys/isa_defs.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/fcntl.h>
#include <sys/flock.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/mode.h>
#include <sys/proc.h>
#include <sys/filio.h>
#include <sys/share.h>
#include <sys/debug.h>
#include <sys/rctl.h>
#include <sys/nbmlock.h>

#include <sys/cmn_err.h>

static int flock_check(vnode_t *, flock64_t *, offset_t, offset_t);
static int flock_get_start(vnode_t *, flock64_t *, offset_t, u_offset_t *);
static void fd_too_big(proc_t *);

/*
 * File control.
 */
int
fcntl(int fdes, int cmd, intptr_t arg)
{
	int iarg;
	int error = 0;
	int retval;
	proc_t *p;
	file_t *fp;
	vnode_t *vp;
	u_offset_t offset;
	u_offset_t start;
	struct vattr vattr;
	int in_crit;
	int flag;
	struct flock sbf;
	struct flock64 bf;
	struct o_flock obf;
	struct flock64_32 bf64_32;
	struct fshare fsh;
	struct shrlock shr;
	struct shr_locowner shr_own;
	offset_t maxoffset;
	model_t datamodel;
	int fdres;

#if defined(_ILP32) && !defined(lint) && defined(_SYSCALL32)
	ASSERT(sizeof (struct flock) == sizeof (struct flock32));
	ASSERT(sizeof (struct flock64) == sizeof (struct flock64_32));
#endif
#if defined(_LP64) && !defined(lint) && defined(_SYSCALL32)
	ASSERT(sizeof (struct flock) == sizeof (struct flock64_64));
	ASSERT(sizeof (struct flock64) == sizeof (struct flock64_64));
#endif

	/*
	 * First, for speed, deal with the subset of cases
	 * that do not require getf() / releasef().
	 */
	switch (cmd) {
	case F_GETFD:
		if ((error = f_getfd_error(fdes, &flag)) == 0)
			retval = flag;
		goto out;

	case F_SETFD:
		error = f_setfd_error(fdes, (int)arg);
		retval = 0;
		goto out;

	case F_GETFL:
		if ((error = f_getfl(fdes, &flag)) == 0) {
			retval = (flag & (FMASK | FASYNC));
			if ((flag & (FSEARCH | FEXEC)) == 0)
				retval += FOPEN;
			else
				retval |= (flag & (FSEARCH | FEXEC));
		}
		goto out;

	case F_GETXFL:
		if ((error = f_getfl(fdes, &flag)) == 0) {
			retval = flag;
			if ((flag & (FSEARCH | FEXEC)) == 0)
				retval += FOPEN;
		}
		goto out;

	case F_BADFD:
		if ((error = f_badfd(fdes, &fdres, (int)arg)) == 0)
			retval = fdres;
		goto out;
	}

	/*
	 * Second, for speed, deal with the subset of cases that
	 * require getf() / releasef() but do not require copyin.
	 */
	if ((fp = getf(fdes)) == NULL) {
		error = EBADF;
		goto out;
	}
	iarg = (int)arg;

	switch (cmd) {
	case F_DUPFD:
	case F_DUPFD_CLOEXEC:
		p = curproc;
		if ((uint_t)iarg >= p->p_fno_ctl) {
			if (iarg >= 0)
				fd_too_big(p);
			error = EINVAL;
			goto done;
		}
		/*
		 * We need to increment the f_count reference counter
		 * before allocating a new file descriptor.
		 * Doing it other way round opens a window for race condition
		 * with closeandsetf() on the target file descriptor which can
		 * close the file still referenced by the original
		 * file descriptor.
		 */
		mutex_enter(&fp->f_tlock);
		fp->f_count++;
		mutex_exit(&fp->f_tlock);
		if ((retval = ufalloc_file(iarg, fp)) == -1) {
			/*
			 * New file descriptor can't be allocated.
			 * Revert the reference count.
			 */
			mutex_enter(&fp->f_tlock);
			fp->f_count--;
			mutex_exit(&fp->f_tlock);
			error = EMFILE;
		} else {
			if (cmd == F_DUPFD_CLOEXEC) {
				f_setfd(retval, FD_CLOEXEC);
			}
		}
		goto done;

	case F_DUP2FD_CLOEXEC:
		if (fdes == iarg) {
			error = EINVAL;
			goto done;
		}

		/*FALLTHROUGH*/

	case F_DUP2FD:
		p = curproc;
		if (fdes == iarg) {
			retval = iarg;
		} else if ((uint_t)iarg >= p->p_fno_ctl) {
			if (iarg >= 0)
				fd_too_big(p);
			error = EBADF;
		} else {
			/*
			 * We can't hold our getf(fdes) across the call to
			 * closeandsetf() because it creates a window for
			 * deadlock: if one thread is doing dup2(a, b) while
			 * another is doing dup2(b, a), each one will block
			 * waiting for the other to call releasef().  The
			 * solution is to increment the file reference count
			 * (which we have to do anyway), then releasef(fdes),
			 * then closeandsetf().  Incrementing f_count ensures
			 * that fp won't disappear after we call releasef().
			 * When closeandsetf() fails, we try avoid calling
			 * closef() because of all the side effects.
			 */
			mutex_enter(&fp->f_tlock);
			fp->f_count++;
			mutex_exit(&fp->f_tlock);
			releasef(fdes);
			if ((error = closeandsetf(iarg, fp)) == 0) {
				if (cmd == F_DUP2FD_CLOEXEC) {
					f_setfd(iarg, FD_CLOEXEC);
				}
				retval = iarg;
			} else {
				mutex_enter(&fp->f_tlock);
				if (fp->f_count > 1) {
					fp->f_count--;
					mutex_exit(&fp->f_tlock);
				} else {
					mutex_exit(&fp->f_tlock);
					(void) closef(fp);
				}
			}
			goto out;
		}
		goto done;

	case F_SETFL:
		vp = fp->f_vnode;
		flag = fp->f_flag;
		if ((iarg & (FNONBLOCK|FNDELAY)) == (FNONBLOCK|FNDELAY))
			iarg &= ~FNDELAY;
		if ((error = VOP_SETFL(vp, flag, iarg, fp->f_cred, NULL)) ==
		    0) {
			iarg &= FMASK;
			mutex_enter(&fp->f_tlock);
			fp->f_flag &= ~FMASK | (FREAD|FWRITE);
			fp->f_flag |= (iarg - FOPEN) & ~(FREAD|FWRITE);
			mutex_exit(&fp->f_tlock);
		}
		retval = 0;
		goto done;
	}

	/*
	 * Finally, deal with the expensive cases.
	 */
	retval = 0;
	in_crit = 0;
	maxoffset = MAXOFF_T;
	datamodel = DATAMODEL_NATIVE;
#if defined(_SYSCALL32_IMPL)
	if ((datamodel = get_udatamodel()) == DATAMODEL_ILP32)
		maxoffset = MAXOFF32_T;
#endif

	vp = fp->f_vnode;
	flag = fp->f_flag;
	offset = fp->f_offset;

	switch (cmd) {
	/*
	 * The file system and vnode layers understand and implement
	 * locking with flock64 structures. So here once we pass through
	 * the test for compatibility as defined by LFS API, (for F_SETLK,
	 * F_SETLKW, F_GETLK, F_GETLKW, F_OFD_GETLK, F_OFD_SETLK, F_OFD_SETLKW,
	 * F_FREESP) we transform the flock structure to a flock64 structure
	 * and send it to the lower layers. Similarly in case of GETLK and
	 * OFD_GETLK the returned flock64 structure is transformed to a flock
	 * structure if everything fits in nicely, otherwise we return
	 * EOVERFLOW.
	 */

	case F_GETLK:
	case F_O_GETLK:
	case F_SETLK:
	case F_SETLKW:
	case F_SETLK_NBMAND:
	case F_OFD_GETLK:
	case F_OFD_SETLK:
	case F_OFD_SETLKW:
	case F_FLOCK:
	case F_FLOCKW:

		/*
		 * Copy in input fields only.
		 */

		if (cmd == F_O_GETLK) {
			if (datamodel != DATAMODEL_ILP32) {
				error = EINVAL;
				break;
			}

			if (copyin((void *)arg, &obf, sizeof (obf))) {
				error = EFAULT;
				break;
			}
			bf.l_type = obf.l_type;
			bf.l_whence = obf.l_whence;
			bf.l_start = (off64_t)obf.l_start;
			bf.l_len = (off64_t)obf.l_len;
			bf.l_sysid = (int)obf.l_sysid;
			bf.l_pid = obf.l_pid;
		} else if (datamodel == DATAMODEL_NATIVE) {
			if (copyin((void *)arg, &sbf, sizeof (sbf))) {
				error = EFAULT;
				break;
			}
			/*
			 * XXX	In an LP64 kernel with an LP64 application
			 *	there's no need to do a structure copy here
			 *	struct flock == struct flock64. However,
			 *	we did it this way to avoid more conditional
			 *	compilation.
			 */
			bf.l_type = sbf.l_type;
			bf.l_whence = sbf.l_whence;
			bf.l_start = (off64_t)sbf.l_start;
			bf.l_len = (off64_t)sbf.l_len;
			bf.l_sysid = sbf.l_sysid;
			bf.l_pid = sbf.l_pid;
		}
#if defined(_SYSCALL32_IMPL)
		else {
			struct flock32 sbf32;
			if (copyin((void *)arg, &sbf32, sizeof (sbf32))) {
				error = EFAULT;
				break;
			}
			bf.l_type = sbf32.l_type;
			bf.l_whence = sbf32.l_whence;
			bf.l_start = (off64_t)sbf32.l_start;
			bf.l_len = (off64_t)sbf32.l_len;
			bf.l_sysid = sbf32.l_sysid;
			bf.l_pid = sbf32.l_pid;
		}
#endif /* _SYSCALL32_IMPL */

		/*
		 * 64-bit support: check for overflow for 32-bit lock ops
		 */
		if ((error = flock_check(vp, &bf, offset, maxoffset)) != 0)
			break;

		if (cmd == F_FLOCK || cmd == F_FLOCKW) {
			/* FLOCK* locking is always over the entire file. */
			if (bf.l_whence != 0 || bf.l_start != 0 ||
			    bf.l_len != 0) {
				error = EINVAL;
				break;
			}
			if (bf.l_type < F_RDLCK || bf.l_type > F_UNLCK) {
				error = EINVAL;
				break;
			}
		}

		if (cmd == F_OFD_GETLK || cmd == F_OFD_SETLK ||
		    cmd == F_OFD_SETLKW) {
			/*
			 * TBD OFD-style locking is currently limited to
			 * covering the entire file.
			 */
			if (bf.l_whence != 0 || bf.l_start != 0 ||
			    bf.l_len != 0) {
				error = EINVAL;
				break;
			}
		}

		/*
		 * Not all of the filesystems understand F_O_GETLK, and
		 * there's no need for them to know.  Map it to F_GETLK.
		 *
		 * The *_frlock functions in the various file systems basically
		 * do some validation and then funnel everything through the
		 * fs_frlock function. For OFD-style locks fs_frlock will do
		 * nothing so that once control returns here we can call the
		 * ofdlock function with the correct fp. For OFD-style locks
		 * the unsupported remote file systems, such as NFS, detect and
		 * reject the OFD-style cmd argument.
		 */
		if ((error = VOP_FRLOCK(vp, (cmd == F_O_GETLK) ? F_GETLK : cmd,
		    &bf, flag, offset, NULL, fp->f_cred, NULL)) != 0)
			break;

		if (cmd == F_FLOCK || cmd == F_FLOCKW || cmd == F_OFD_GETLK ||
		    cmd == F_OFD_SETLK || cmd == F_OFD_SETLKW) {
			/*
			 * This is an OFD-style lock so we need to handle it
			 * here. Because OFD-style locks are associated with
			 * the file_t we didn't have enough info down the
			 * VOP_FRLOCK path immediately above.
			 */
			if ((error = ofdlock(fp, cmd, &bf, flag, offset)) != 0)
				break;
		}

		/*
		 * If command is GETLK and no lock is found, only
		 * the type field is changed.
		 */
		if ((cmd == F_O_GETLK || cmd == F_GETLK ||
		    cmd == F_OFD_GETLK) && bf.l_type == F_UNLCK) {
			/* l_type always first entry, always a short */
			if (copyout(&bf.l_type, &((struct flock *)arg)->l_type,
			    sizeof (bf.l_type)))
				error = EFAULT;
			break;
		}

		if (cmd == F_O_GETLK) {
			/*
			 * Return an SVR3 flock structure to the user.
			 */
			obf.l_type = (int16_t)bf.l_type;
			obf.l_whence = (int16_t)bf.l_whence;
			obf.l_start = (int32_t)bf.l_start;
			obf.l_len = (int32_t)bf.l_len;
			if (bf.l_sysid > SHRT_MAX || bf.l_pid > SHRT_MAX) {
				/*
				 * One or both values for the above fields
				 * is too large to store in an SVR3 flock
				 * structure.
				 */
				error = EOVERFLOW;
				break;
			}
			obf.l_sysid = (int16_t)bf.l_sysid;
			obf.l_pid = (int16_t)bf.l_pid;
			if (copyout(&obf, (void *)arg, sizeof (obf)))
				error = EFAULT;
		} else if (cmd == F_GETLK || cmd == F_OFD_GETLK) {
			/*
			 * Copy out SVR4 flock.
			 */
			int i;

			if (bf.l_start > maxoffset || bf.l_len > maxoffset) {
				error = EOVERFLOW;
				break;
			}

			if (datamodel == DATAMODEL_NATIVE) {
				for (i = 0; i < 4; i++)
					sbf.l_pad[i] = 0;
				/*
				 * XXX	In an LP64 kernel with an LP64
				 *	application there's no need to do a
				 *	structure copy here as currently
				 *	struct flock == struct flock64.
				 *	We did it this way to avoid more
				 *	conditional compilation.
				 */
				sbf.l_type = bf.l_type;
				sbf.l_whence = bf.l_whence;
				sbf.l_start = (off_t)bf.l_start;
				sbf.l_len = (off_t)bf.l_len;
				sbf.l_sysid = bf.l_sysid;
				sbf.l_pid = bf.l_pid;
				if (copyout(&sbf, (void *)arg, sizeof (sbf)))
					error = EFAULT;
			}
#if defined(_SYSCALL32_IMPL)
			else {
				struct flock32 sbf32;
				if (bf.l_start > MAXOFF32_T ||
				    bf.l_len > MAXOFF32_T) {
					error = EOVERFLOW;
					break;
				}
				for (i = 0; i < 4; i++)
					sbf32.l_pad[i] = 0;
				sbf32.l_type = (int16_t)bf.l_type;
				sbf32.l_whence = (int16_t)bf.l_whence;
				sbf32.l_start = (off32_t)bf.l_start;
				sbf32.l_len = (off32_t)bf.l_len;
				sbf32.l_sysid = (int32_t)bf.l_sysid;
				sbf32.l_pid = (pid32_t)bf.l_pid;
				if (copyout(&sbf32,
				    (void *)arg, sizeof (sbf32)))
					error = EFAULT;
			}
#endif
		}
		break;

	case F_CHKFL:
		/*
		 * This is for internal use only, to allow the vnode layer
		 * to validate a flags setting before applying it.  User
		 * programs can't issue it.
		 */
		error = EINVAL;
		break;

	case F_ALLOCSP:
	case F_FREESP:
	case F_ALLOCSP64:
	case F_FREESP64:
		/*
		 * Test for not-a-regular-file (and returning EINVAL)
		 * before testing for open-for-writing (and returning EBADF).
		 * This is relied upon by posix_fallocate() in libc.
		 */
		if (vp->v_type != VREG) {
			error = EINVAL;
			break;
		}

		if ((flag & FWRITE) == 0) {
			error = EBADF;
			break;
		}

		if (datamodel != DATAMODEL_ILP32 &&
		    (cmd == F_ALLOCSP64 || cmd == F_FREESP64)) {
			error = EINVAL;
			break;
		}

#if defined(_ILP32) || defined(_SYSCALL32_IMPL)
		if (datamodel == DATAMODEL_ILP32 &&
		    (cmd == F_ALLOCSP || cmd == F_FREESP)) {
			struct flock32 sbf32;
			/*
			 * For compatibility we overlay an SVR3 flock on an SVR4
			 * flock.  This works because the input field offsets
			 * in "struct flock" were preserved.
			 */
			if (copyin((void *)arg, &sbf32, sizeof (sbf32))) {
				error = EFAULT;
				break;
			} else {
				bf.l_type = sbf32.l_type;
				bf.l_whence = sbf32.l_whence;
				bf.l_start = (off64_t)sbf32.l_start;
				bf.l_len = (off64_t)sbf32.l_len;
				bf.l_sysid = sbf32.l_sysid;
				bf.l_pid = sbf32.l_pid;
			}
		}
#endif /* _ILP32 || _SYSCALL32_IMPL */

#if defined(_LP64)
		if (datamodel == DATAMODEL_LP64 &&
		    (cmd == F_ALLOCSP || cmd == F_FREESP)) {
			if (copyin((void *)arg, &bf, sizeof (bf))) {
				error = EFAULT;
				break;
			}
		}
#endif /* defined(_LP64) */

#if !defined(_LP64) || defined(_SYSCALL32_IMPL)
		if (datamodel == DATAMODEL_ILP32 &&
		    (cmd == F_ALLOCSP64 || cmd == F_FREESP64)) {
			if (copyin((void *)arg, &bf64_32, sizeof (bf64_32))) {
				error = EFAULT;
				break;
			} else {
				/*
				 * Note that the size of flock64 is different in
				 * the ILP32 and LP64 models, due to the l_pad
				 * field. We do not want to assume that the
				 * flock64 structure is laid out the same in
				 * ILP32 and LP64 environments, so we will
				 * copy in the ILP32 version of flock64
				 * explicitly and copy it to the native
				 * flock64 structure.
				 */
				bf.l_type = (short)bf64_32.l_type;
				bf.l_whence = (short)bf64_32.l_whence;
				bf.l_start = bf64_32.l_start;
				bf.l_len = bf64_32.l_len;
				bf.l_sysid = (int)bf64_32.l_sysid;
				bf.l_pid = (pid_t)bf64_32.l_pid;
			}
		}
#endif /* !defined(_LP64) || defined(_SYSCALL32_IMPL) */

		if (cmd == F_ALLOCSP || cmd == F_FREESP)
			error = flock_check(vp, &bf, offset, maxoffset);
		else if (cmd == F_ALLOCSP64 || cmd == F_FREESP64)
			error = flock_check(vp, &bf, offset, MAXOFFSET_T);
		if (error)
			break;

		if (vp->v_type == VREG && bf.l_len == 0 &&
		    bf.l_start > OFFSET_MAX(fp)) {
			error = EFBIG;
			break;
		}

		/*
		 * Make sure that there are no conflicting non-blocking
		 * mandatory locks in the region being manipulated. If
		 * there are such locks then return EACCES.
		 */
		if ((error = flock_get_start(vp, &bf, offset, &start)) != 0)
			break;

		if (nbl_need_check(vp)) {
			u_offset_t	begin;
			ssize_t		length;

			nbl_start_crit(vp, RW_READER);
			in_crit = 1;
			vattr.va_mask = AT_SIZE;
			if ((error = VOP_GETATTR(vp, &vattr, 0, CRED(), NULL))
			    != 0)
				break;
			begin = start > vattr.va_size ? vattr.va_size : start;
			length = vattr.va_size > start ? vattr.va_size - start :
			    start - vattr.va_size;
			if (nbl_conflict(vp, NBL_WRITE, begin, length, 0,
			    NULL)) {
				error = EACCES;
				break;
			}
		}

		if (cmd == F_ALLOCSP64)
			cmd = F_ALLOCSP;
		else if (cmd == F_FREESP64)
			cmd = F_FREESP;

		error = VOP_SPACE(vp, cmd, &bf, flag, offset, fp->f_cred, NULL);

		break;

#if !defined(_LP64) || defined(_SYSCALL32_IMPL)
	case F_GETLK64:
	case F_SETLK64:
	case F_SETLKW64:
	case F_SETLK64_NBMAND:
	case F_OFD_GETLK64:
	case F_OFD_SETLK64:
	case F_OFD_SETLKW64:
	case F_FLOCK64:
	case F_FLOCKW64:
		/*
		 * Large Files: Here we set cmd as *LK and send it to
		 * lower layers. *LK64 is only for the user land.
		 * Most of the comments described above for F_SETLK
		 * applies here too.
		 * Large File support is only needed for ILP32 apps!
		 */
		if (datamodel != DATAMODEL_ILP32) {
			error = EINVAL;
			break;
		}

		if (cmd == F_GETLK64)
			cmd = F_GETLK;
		else if (cmd == F_SETLK64)
			cmd = F_SETLK;
		else if (cmd == F_SETLKW64)
			cmd = F_SETLKW;
		else if (cmd == F_SETLK64_NBMAND)
			cmd = F_SETLK_NBMAND;
		else if (cmd == F_OFD_GETLK64)
			cmd = F_OFD_GETLK;
		else if (cmd == F_OFD_SETLK64)
			cmd = F_OFD_SETLK;
		else if (cmd == F_OFD_SETLKW64)
			cmd = F_OFD_SETLKW;
		else if (cmd == F_FLOCK64)
			cmd = F_FLOCK;
		else if (cmd == F_FLOCKW64)
			cmd = F_FLOCKW;

		/*
		 * Note that the size of flock64 is different in the ILP32
		 * and LP64 models, due to the sucking l_pad field.
		 * We do not want to assume that the flock64 structure is
		 * laid out in the same in ILP32 and LP64 environments, so
		 * we will copy in the ILP32 version of flock64 explicitly
		 * and copy it to the native flock64 structure.
		 */

		if (copyin((void *)arg, &bf64_32, sizeof (bf64_32))) {
			error = EFAULT;
			break;
		}

		bf.l_type = (short)bf64_32.l_type;
		bf.l_whence = (short)bf64_32.l_whence;
		bf.l_start = bf64_32.l_start;
		bf.l_len = bf64_32.l_len;
		bf.l_sysid = (int)bf64_32.l_sysid;
		bf.l_pid = (pid_t)bf64_32.l_pid;

		if ((error = flock_check(vp, &bf, offset, MAXOFFSET_T)) != 0)
			break;

		if (cmd == F_FLOCK || cmd == F_FLOCKW) {
			/* FLOCK* locking is always over the entire file. */
			if (bf.l_whence != 0 || bf.l_start != 0 ||
			    bf.l_len != 0) {
				error = EINVAL;
				break;
			}
			if (bf.l_type < F_RDLCK || bf.l_type > F_UNLCK) {
				error = EINVAL;
				break;
			}
		}

		if (cmd == F_OFD_GETLK || cmd == F_OFD_SETLK ||
		    cmd == F_OFD_SETLKW) {
			/*
			 * TBD OFD-style locking is currently limited to
			 * covering the entire file.
			 */
			if (bf.l_whence != 0 || bf.l_start != 0 ||
			    bf.l_len != 0) {
				error = EINVAL;
				break;
			}
		}

		/*
		 * The *_frlock functions in the various file systems basically
		 * do some validation and then funnel everything through the
		 * fs_frlock function. For OFD-style locks fs_frlock will do
		 * nothing so that once control returns here we can call the
		 * ofdlock function with the correct fp. For OFD-style locks
		 * the unsupported remote file systems, such as NFS, detect and
		 * reject the OFD-style cmd argument.
		 */
		if ((error = VOP_FRLOCK(vp, cmd, &bf, flag, offset,
		    NULL, fp->f_cred, NULL)) != 0)
			break;

		if (cmd == F_FLOCK || cmd == F_FLOCKW || cmd == F_OFD_GETLK ||
		    cmd == F_OFD_SETLK || cmd == F_OFD_SETLKW) {
			/*
			 * This is an OFD-style lock so we need to handle it
			 * here. Because OFD-style locks are associated with
			 * the file_t we didn't have enough info down the
			 * VOP_FRLOCK path immediately above.
			 */
			if ((error = ofdlock(fp, cmd, &bf, flag, offset)) != 0)
				break;
		}

		if ((cmd == F_GETLK || cmd == F_OFD_GETLK) &&
		    bf.l_type == F_UNLCK) {
			if (copyout(&bf.l_type, &((struct flock *)arg)->l_type,
			    sizeof (bf.l_type)))
				error = EFAULT;
			break;
		}

		if (cmd == F_GETLK || cmd == F_OFD_GETLK) {
			int i;

			/*
			 * We do not want to assume that the flock64 structure
			 * is laid out in the same in ILP32 and LP64
			 * environments, so we will copy out the ILP32 version
			 * of flock64 explicitly after copying the native
			 * flock64 structure to it.
			 */
			for (i = 0; i < 4; i++)
				bf64_32.l_pad[i] = 0;
			bf64_32.l_type = (int16_t)bf.l_type;
			bf64_32.l_whence = (int16_t)bf.l_whence;
			bf64_32.l_start = bf.l_start;
			bf64_32.l_len = bf.l_len;
			bf64_32.l_sysid = (int32_t)bf.l_sysid;
			bf64_32.l_pid = (pid32_t)bf.l_pid;
			if (copyout(&bf64_32, (void *)arg, sizeof (bf64_32)))
				error = EFAULT;
		}
		break;
#endif /* !defined(_LP64) || defined(_SYSCALL32_IMPL) */

	case F_SHARE:
	case F_SHARE_NBMAND:
	case F_UNSHARE:

		/*
		 * Copy in input fields only.
		 */
		if (copyin((void *)arg, &fsh, sizeof (fsh))) {
			error = EFAULT;
			break;
		}

		/*
		 * Local share reservations always have this simple form
		 */
		shr.s_access = fsh.f_access;
		shr.s_deny = fsh.f_deny;
		shr.s_sysid = 0;
		shr.s_pid = ttoproc(curthread)->p_pid;
		shr_own.sl_pid = shr.s_pid;
		shr_own.sl_id = fsh.f_id;
		shr.s_own_len = sizeof (shr_own);
		shr.s_owner = (caddr_t)&shr_own;
		error = VOP_SHRLOCK(vp, cmd, &shr, flag, fp->f_cred, NULL);
		break;

	default:
		error = EINVAL;
		break;
	}

	if (in_crit)
		nbl_end_crit(vp);

done:
	releasef(fdes);
out:
	if (error)
		return (set_errno(error));
	return (retval);
}

int
flock_check(vnode_t *vp, flock64_t *flp, offset_t offset, offset_t max)
{
	struct vattr	vattr;
	int	error;
	u_offset_t start, end;

	/*
	 * Determine the starting point of the request
	 */
	switch (flp->l_whence) {
	case 0:		/* SEEK_SET */
		start = (u_offset_t)flp->l_start;
		if (start > max)
			return (EINVAL);
		break;
	case 1:		/* SEEK_CUR */
		if (flp->l_start > (max - offset))
			return (EOVERFLOW);
		start = (u_offset_t)(flp->l_start + offset);
		if (start > max)
			return (EINVAL);
		break;
	case 2:		/* SEEK_END */
		vattr.va_mask = AT_SIZE;
		if (error = VOP_GETATTR(vp, &vattr, 0, CRED(), NULL))
			return (error);
		if (flp->l_start > (max - (offset_t)vattr.va_size))
			return (EOVERFLOW);
		start = (u_offset_t)(flp->l_start + (offset_t)vattr.va_size);
		if (start > max)
			return (EINVAL);
		break;
	default:
		return (EINVAL);
	}

	/*
	 * Determine the range covered by the request.
	 */
	if (flp->l_len == 0)
		end = MAXEND;
	else if ((offset_t)flp->l_len > 0) {
		if (flp->l_len > (max - start + 1))
			return (EOVERFLOW);
		end = (u_offset_t)(start + (flp->l_len - 1));
		ASSERT(end <= max);
	} else {
		/*
		 * Negative length; why do we even allow this ?
		 * Because this allows easy specification of
		 * the last n bytes of the file.
		 */
		end = start;
		start += (u_offset_t)flp->l_len;
		(start)++;
		if (start > max)
			return (EINVAL);
		ASSERT(end <= max);
	}
	ASSERT(start <= max);
	if (flp->l_type == F_UNLCK && flp->l_len > 0 &&
	    end == (offset_t)max) {
		flp->l_len = 0;
	}
	if (start  > end)
		return (EINVAL);
	return (0);
}

static int
flock_get_start(vnode_t *vp, flock64_t *flp, offset_t offset, u_offset_t *start)
{
	struct vattr	vattr;
	int	error;

	/*
	 * Determine the starting point of the request. Assume that it is
	 * a valid starting point.
	 */
	switch (flp->l_whence) {
	case 0:		/* SEEK_SET */
		*start = (u_offset_t)flp->l_start;
		break;
	case 1:		/* SEEK_CUR */
		*start = (u_offset_t)(flp->l_start + offset);
		break;
	case 2:		/* SEEK_END */
		vattr.va_mask = AT_SIZE;
		if (error = VOP_GETATTR(vp, &vattr, 0, CRED(), NULL))
			return (error);
		*start = (u_offset_t)(flp->l_start + (offset_t)vattr.va_size);
		break;
	default:
		return (EINVAL);
	}

	return (0);
}

/*
 * Take rctl action when the requested file descriptor is too big.
 */
static void
fd_too_big(proc_t *p)
{
	mutex_enter(&p->p_lock);
	(void) rctl_action(rctlproc_legacy[RLIMIT_NOFILE],
	    p->p_rctls, p, RCA_SAFE);
	mutex_exit(&p->p_lock);
}
