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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2015, Joyent, Inc.  All rights reserved.
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
#include <sys/inttypes.h>
#include <sys/sysmacros.h>
#include <sys/cred.h>
#include <sys/user.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/proc.h>
#include <sys/cpuvar.h>
#include <sys/uio.h>
#include <sys/debug.h>
#include <sys/rctl.h>
#include <sys/nbmlock.h>

#define	COPYOUT_MAX_CACHE	(1<<17)		/* 128K */

size_t copyout_max_cached = COPYOUT_MAX_CACHE;	/* global so it's patchable */

/*
 * read, write, pread, pwrite, readv, and writev syscalls.
 *
 * 64-bit open:	all open's are large file opens.
 * Large Files: the behaviour of read depends on whether the fd
 *		corresponds to large open or not.
 * 32-bit open:	FOFFMAX flag not set.
 *		read until MAXOFF32_T - 1 and read at MAXOFF32_T returns
 *		EOVERFLOW if count is non-zero and if size of file
 *		is > MAXOFF32_T. If size of file is <= MAXOFF32_T read
 *		at >= MAXOFF32_T returns EOF.
 */

/*
 * Native system call
 */
ssize_t
read(int fdes, void *cbuf, size_t count)
{
	struct uio auio;
	struct iovec aiov;
	file_t *fp;
	register vnode_t *vp;
	struct cpu *cp;
	int fflag, ioflag, rwflag;
	ssize_t cnt, bcount;
	int error = 0;
	u_offset_t fileoff;
	int in_crit = 0;

	if ((cnt = (ssize_t)count) < 0)
		return (set_errno(EINVAL));
	if ((fp = getf(fdes)) == NULL)
		return (set_errno(EBADF));
	if (((fflag = fp->f_flag) & FREAD) == 0) {
		error = EBADF;
		goto out;
	}
	vp = fp->f_vnode;

	if (vp->v_type == VREG && cnt == 0) {
		goto out;
	}

	rwflag = 0;
	aiov.iov_base = cbuf;
	aiov.iov_len = cnt;

	/*
	 * We have to enter the critical region before calling VOP_RWLOCK
	 * to avoid a deadlock with write() calls.
	 */
	if (nbl_need_check(vp)) {
		int svmand;

		nbl_start_crit(vp, RW_READER);
		in_crit = 1;
		error = nbl_svmand(vp, fp->f_cred, &svmand);
		if (error != 0)
			goto out;
		if (nbl_conflict(vp, NBL_READ, fp->f_offset, cnt, svmand,
		    NULL)) {
			error = EACCES;
			goto out;
		}
	}

	(void) VOP_RWLOCK(vp, rwflag, NULL);

	/*
	 * We do the following checks inside VOP_RWLOCK so as to
	 * prevent file size from changing while these checks are
	 * being done. Also, we load fp's offset to the local
	 * variable fileoff because we can have a parallel lseek
	 * going on (f_offset is not protected by any lock) which
	 * could change f_offset. We need to see the value only
	 * once here and take a decision. Seeing it more than once
	 * can lead to incorrect functionality.
	 */

	fileoff = (u_offset_t)fp->f_offset;
	if (fileoff >= OFFSET_MAX(fp) && (vp->v_type == VREG)) {
		struct vattr va;
		va.va_mask = AT_SIZE;
		if ((error = VOP_GETATTR(vp, &va, 0, fp->f_cred, NULL)))  {
			VOP_RWUNLOCK(vp, rwflag, NULL);
			goto out;
		}
		if (fileoff >= va.va_size) {
			cnt = 0;
			VOP_RWUNLOCK(vp, rwflag, NULL);
			goto out;
		} else {
			error = EOVERFLOW;
			VOP_RWUNLOCK(vp, rwflag, NULL);
			goto out;
		}
	}
	if ((vp->v_type == VREG) &&
	    (fileoff + cnt > OFFSET_MAX(fp))) {
		cnt = (ssize_t)(OFFSET_MAX(fp) - fileoff);
	}
	auio.uio_loffset = fileoff;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_resid = bcount = cnt;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_llimit = MAXOFFSET_T;
	auio.uio_fmode = fflag;
	/*
	 * Only use bypass caches when the count is large enough
	 */
	if (bcount <= copyout_max_cached)
		auio.uio_extflg = UIO_COPY_CACHED;
	else
		auio.uio_extflg = UIO_COPY_DEFAULT;

	ioflag = auio.uio_fmode & (FAPPEND|FSYNC|FDSYNC|FRSYNC);

	/* If read sync is not asked for, filter sync flags */
	if ((ioflag & FRSYNC) == 0)
		ioflag &= ~(FSYNC|FDSYNC);
	error = VOP_READ(vp, &auio, ioflag, fp->f_cred, NULL);
	cnt -= auio.uio_resid;
	CPU_STATS_ENTER_K();
	cp = CPU;
	CPU_STATS_ADDQ(cp, sys, sysread, 1);
	CPU_STATS_ADDQ(cp, sys, readch, (ulong_t)cnt);
	CPU_STATS_EXIT_K();
	ttolwp(curthread)->lwp_ru.ioch += (ulong_t)cnt;

	if (vp->v_type == VFIFO)	/* Backward compatibility */
		fp->f_offset = cnt;
	else if (((fp->f_flag & FAPPEND) == 0) ||
	    (vp->v_type != VREG) || (bcount != 0))	/* POSIX */
		fp->f_offset = auio.uio_loffset;
	VOP_RWUNLOCK(vp, rwflag, NULL);

	if (error == EINTR && cnt != 0)
		error = 0;
out:
	if (in_crit)
		nbl_end_crit(vp);
	releasef(fdes);
	if (error)
		return (set_errno(error));
	return (cnt);
}

/*
 * Native system call
 */
ssize_t
write(int fdes, void *cbuf, size_t count)
{
	struct uio auio;
	struct iovec aiov;
	file_t *fp;
	register vnode_t *vp;
	struct cpu *cp;
	int fflag, ioflag, rwflag;
	ssize_t cnt, bcount;
	int error = 0;
	u_offset_t fileoff;
	int in_crit = 0;

	if ((cnt = (ssize_t)count) < 0)
		return (set_errno(EINVAL));
	if ((fp = getf(fdes)) == NULL)
		return (set_errno(EBADF));
	if (((fflag = fp->f_flag) & FWRITE) == 0) {
		error = EBADF;
		goto out;
	}
	vp = fp->f_vnode;

	if (vp->v_type == VREG && cnt == 0) {
		goto out;
	}

	rwflag = 1;
	aiov.iov_base = cbuf;
	aiov.iov_len = cnt;

	/*
	 * We have to enter the critical region before calling VOP_RWLOCK
	 * to avoid a deadlock with ufs.
	 */
	if (nbl_need_check(vp)) {
		int svmand;

		nbl_start_crit(vp, RW_READER);
		in_crit = 1;
		error = nbl_svmand(vp, fp->f_cred, &svmand);
		if (error != 0)
			goto out;
		if (nbl_conflict(vp, NBL_WRITE, fp->f_offset, cnt, svmand,
		    NULL)) {
			error = EACCES;
			goto out;
		}
	}

	(void) VOP_RWLOCK(vp, rwflag, NULL);

	fileoff = fp->f_offset;
	if (vp->v_type == VREG) {

		/*
		 * We raise psignal if write for >0 bytes causes
		 * it to exceed the ulimit.
		 */
		if (fileoff >= curproc->p_fsz_ctl) {
			VOP_RWUNLOCK(vp, rwflag, NULL);

			mutex_enter(&curproc->p_lock);
			(void) rctl_action(rctlproc_legacy[RLIMIT_FSIZE],
			    curproc->p_rctls, curproc, RCA_UNSAFE_SIGINFO);
			mutex_exit(&curproc->p_lock);

			error = EFBIG;
			goto out;
		}
		/*
		 * We return EFBIG if write is done at an offset
		 * greater than the offset maximum for this file structure.
		 */

		if (fileoff >= OFFSET_MAX(fp)) {
			VOP_RWUNLOCK(vp, rwflag, NULL);
			error = EFBIG;
			goto out;
		}
		/*
		 * Limit the bytes to be written  upto offset maximum for
		 * this open file structure.
		 */
		if (fileoff + cnt > OFFSET_MAX(fp))
			cnt = (ssize_t)(OFFSET_MAX(fp) - fileoff);
	}
	auio.uio_loffset = fileoff;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_resid = bcount = cnt;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_llimit = curproc->p_fsz_ctl;
	auio.uio_fmode = fflag;
	auio.uio_extflg = UIO_COPY_DEFAULT;

	ioflag = auio.uio_fmode & (FAPPEND|FSYNC|FDSYNC|FRSYNC);

	error = VOP_WRITE(vp, &auio, ioflag, fp->f_cred, NULL);
	cnt -= auio.uio_resid;
	CPU_STATS_ENTER_K();
	cp = CPU;
	CPU_STATS_ADDQ(cp, sys, syswrite, 1);
	CPU_STATS_ADDQ(cp, sys, writech, (ulong_t)cnt);
	CPU_STATS_EXIT_K();
	ttolwp(curthread)->lwp_ru.ioch += (ulong_t)cnt;

	if (vp->v_type == VFIFO)	/* Backward compatibility */
		fp->f_offset = cnt;
	else if (((fp->f_flag & FAPPEND) == 0) ||
	    (vp->v_type != VREG) || (bcount != 0))	/* POSIX */
		fp->f_offset = auio.uio_loffset;
	VOP_RWUNLOCK(vp, rwflag, NULL);

	if (error == EINTR && cnt != 0)
		error = 0;
out:
	if (in_crit)
		nbl_end_crit(vp);
	releasef(fdes);
	if (error)
		return (set_errno(error));
	return (cnt);
}

ssize_t
pread(int fdes, void *cbuf, size_t count, off_t offset)
{
	struct uio auio;
	struct iovec aiov;
	file_t *fp;
	register vnode_t *vp;
	struct cpu *cp;
	int fflag, ioflag, rwflag;
	ssize_t bcount;
	int error = 0;
	u_offset_t fileoff = (u_offset_t)(ulong_t)offset;
#ifdef _SYSCALL32_IMPL
	u_offset_t maxoff = get_udatamodel() == DATAMODEL_ILP32 ?
	    MAXOFF32_T : MAXOFFSET_T;
#else
	const u_offset_t maxoff = MAXOFF32_T;
#endif
	int in_crit = 0;

	if ((bcount = (ssize_t)count) < 0)
		return (set_errno(EINVAL));

	if ((fp = getf(fdes)) == NULL)
		return (set_errno(EBADF));
	if (((fflag = fp->f_flag) & (FREAD)) == 0) {
		error = EBADF;
		goto out;
	}

	rwflag = 0;
	vp = fp->f_vnode;

	if (vp->v_type == VREG) {

		if (bcount == 0)
			goto out;

		/*
		 * Return EINVAL if an invalid offset comes to pread.
		 * Negative offset from user will cause this error.
		 */

		if (fileoff > maxoff) {
			error = EINVAL;
			goto out;
		}
		/*
		 * Limit offset such that we don't read or write
		 * a file beyond the maximum offset representable in
		 * an off_t structure.
		 */
		if (fileoff + bcount > maxoff)
			bcount = (ssize_t)((offset_t)maxoff - fileoff);
	} else if (vp->v_type == VFIFO) {
		error = ESPIPE;
		goto out;
	}

	/*
	 * We have to enter the critical region before calling VOP_RWLOCK
	 * to avoid a deadlock with ufs.
	 */
	if (nbl_need_check(vp)) {
		int svmand;

		nbl_start_crit(vp, RW_READER);
		in_crit = 1;
		error = nbl_svmand(vp, fp->f_cred, &svmand);
		if (error != 0)
			goto out;
		if (nbl_conflict(vp, NBL_READ, fileoff, bcount, svmand,
		    NULL)) {
			error = EACCES;
			goto out;
		}
	}

	aiov.iov_base = cbuf;
	aiov.iov_len = bcount;
	(void) VOP_RWLOCK(vp, rwflag, NULL);
	if (vp->v_type == VREG && fileoff == (u_offset_t)maxoff) {
		struct vattr va;
		va.va_mask = AT_SIZE;
		if ((error = VOP_GETATTR(vp, &va, 0, fp->f_cred, NULL))) {
			VOP_RWUNLOCK(vp, rwflag, NULL);
			goto out;
		}
		VOP_RWUNLOCK(vp, rwflag, NULL);

		/*
		 * We have to return EOF if fileoff is >= file size.
		 */
		if (fileoff >= va.va_size) {
			bcount = 0;
			goto out;
		}

		/*
		 * File is greater than or equal to maxoff and therefore
		 * we return EOVERFLOW.
		 */
		error = EOVERFLOW;
		goto out;
	}
	auio.uio_loffset = fileoff;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_resid = bcount;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_llimit = MAXOFFSET_T;
	auio.uio_fmode = fflag;
	auio.uio_extflg = UIO_COPY_CACHED;

	ioflag = auio.uio_fmode & (FAPPEND|FSYNC|FDSYNC|FRSYNC);

	/* If read sync is not asked for, filter sync flags */
	if ((ioflag & FRSYNC) == 0)
		ioflag &= ~(FSYNC|FDSYNC);
	error = VOP_READ(vp, &auio, ioflag, fp->f_cred, NULL);
	bcount -= auio.uio_resid;
	CPU_STATS_ENTER_K();
	cp = CPU;
	CPU_STATS_ADDQ(cp, sys, sysread, 1);
	CPU_STATS_ADDQ(cp, sys, readch, (ulong_t)bcount);
	CPU_STATS_EXIT_K();
	ttolwp(curthread)->lwp_ru.ioch += (ulong_t)bcount;
	VOP_RWUNLOCK(vp, rwflag, NULL);

	if (error == EINTR && bcount != 0)
		error = 0;
out:
	if (in_crit)
		nbl_end_crit(vp);
	releasef(fdes);
	if (error)
		return (set_errno(error));
	return (bcount);
}

ssize_t
pwrite(int fdes, void *cbuf, size_t count, off_t offset)
{
	struct uio auio;
	struct iovec aiov;
	file_t *fp;
	register vnode_t *vp;
	struct cpu *cp;
	int fflag, ioflag, rwflag;
	ssize_t bcount;
	int error = 0;
	u_offset_t fileoff = (u_offset_t)(ulong_t)offset;
#ifdef _SYSCALL32_IMPL
	u_offset_t maxoff = get_udatamodel() == DATAMODEL_ILP32 ?
	    MAXOFF32_T : MAXOFFSET_T;
#else
	const u_offset_t maxoff = MAXOFF32_T;
#endif
	int in_crit = 0;

	if ((bcount = (ssize_t)count) < 0)
		return (set_errno(EINVAL));
	if ((fp = getf(fdes)) == NULL)
		return (set_errno(EBADF));
	if (((fflag = fp->f_flag) & (FWRITE)) == 0) {
		error = EBADF;
		goto out;
	}

	rwflag = 1;
	vp = fp->f_vnode;

	if (vp->v_type == VREG) {

		if (bcount == 0)
			goto out;

		/*
		 * return EINVAL for offsets that cannot be
		 * represented in an off_t.
		 */
		if (fileoff > maxoff) {
			error = EINVAL;
			goto out;
		}
		/*
		 * Take appropriate action if we are trying to write above the
		 * resource limit.
		 */
		if (fileoff >= curproc->p_fsz_ctl) {
			mutex_enter(&curproc->p_lock);
			(void) rctl_action(rctlproc_legacy[RLIMIT_FSIZE],
			    curproc->p_rctls, curproc, RCA_UNSAFE_SIGINFO);
			mutex_exit(&curproc->p_lock);

			error = EFBIG;
			goto out;
		}
		/*
		 * Don't allow pwrite to cause file sizes to exceed
		 * maxoff.
		 */
		if (fileoff == maxoff) {
			error = EFBIG;
			goto out;
		}
		if (fileoff + count > maxoff)
			bcount = (ssize_t)((u_offset_t)maxoff - fileoff);
	} else if (vp->v_type == VFIFO) {
		error = ESPIPE;
		goto out;
	}

	/*
	 * We have to enter the critical region before calling VOP_RWLOCK
	 * to avoid a deadlock with ufs.
	 */
	if (nbl_need_check(vp)) {
		int svmand;

		nbl_start_crit(vp, RW_READER);
		in_crit = 1;
		error = nbl_svmand(vp, fp->f_cred, &svmand);
		if (error != 0)
			goto out;
		if (nbl_conflict(vp, NBL_WRITE, fileoff, bcount, svmand,
		    NULL)) {
			error = EACCES;
			goto out;
		}
	}

	aiov.iov_base = cbuf;
	aiov.iov_len = bcount;
	(void) VOP_RWLOCK(vp, rwflag, NULL);
	auio.uio_loffset = fileoff;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_resid = bcount;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_llimit = curproc->p_fsz_ctl;
	auio.uio_fmode = fflag;
	auio.uio_extflg = UIO_COPY_CACHED;

	/*
	 * The SUSv4 POSIX specification states:
	 *	The pwrite() function shall be equivalent to write(), except
	 *	that it writes into a given position and does not change
	 *	the file offset (regardless of whether O_APPEND is set).
	 * To make this be true, we omit the FAPPEND flag from ioflag.
	 */
	ioflag = auio.uio_fmode & (FSYNC|FDSYNC|FRSYNC);

	error = VOP_WRITE(vp, &auio, ioflag, fp->f_cred, NULL);
	bcount -= auio.uio_resid;
	CPU_STATS_ENTER_K();
	cp = CPU;
	CPU_STATS_ADDQ(cp, sys, syswrite, 1);
	CPU_STATS_ADDQ(cp, sys, writech, (ulong_t)bcount);
	CPU_STATS_EXIT_K();
	ttolwp(curthread)->lwp_ru.ioch += (ulong_t)bcount;
	VOP_RWUNLOCK(vp, rwflag, NULL);

	if (error == EINTR && bcount != 0)
		error = 0;
out:
	if (in_crit)
		nbl_end_crit(vp);
	releasef(fdes);
	if (error)
		return (set_errno(error));
	return (bcount);
}

/*
 * XXX -- The SVID refers to IOV_MAX, but doesn't define it.  Grrrr....
 * XXX -- However, SVVS expects readv() and writev() to fail if
 * XXX -- iovcnt > 16 (yes, it's hard-coded in the SVVS source),
 * XXX -- so I guess that's the "interface".
 */
#define	DEF_IOV_MAX	16

ssize_t
readv(int fdes, struct iovec *iovp, int iovcnt)
{
	struct uio auio;
	struct iovec aiov[DEF_IOV_MAX];
	file_t *fp;
	register vnode_t *vp;
	struct cpu *cp;
	int fflag, ioflag, rwflag;
	ssize_t count, bcount;
	int error = 0;
	int i;
	u_offset_t fileoff;
	int in_crit = 0;

	if (iovcnt <= 0 || iovcnt > DEF_IOV_MAX)
		return (set_errno(EINVAL));

#ifdef _SYSCALL32_IMPL
	/*
	 * 32-bit callers need to have their iovec expanded,
	 * while ensuring that they can't move more than 2Gbytes
	 * of data in a single call.
	 */
	if (get_udatamodel() == DATAMODEL_ILP32) {
		struct iovec32 aiov32[DEF_IOV_MAX];
		ssize32_t count32;

		if (copyin(iovp, aiov32, iovcnt * sizeof (struct iovec32)))
			return (set_errno(EFAULT));

		count32 = 0;
		for (i = 0; i < iovcnt; i++) {
			ssize32_t iovlen32 = aiov32[i].iov_len;
			count32 += iovlen32;
			if (iovlen32 < 0 || count32 < 0)
				return (set_errno(EINVAL));
			aiov[i].iov_len = iovlen32;
			aiov[i].iov_base =
			    (caddr_t)(uintptr_t)aiov32[i].iov_base;
		}
	} else
#endif
	if (copyin(iovp, aiov, iovcnt * sizeof (struct iovec)))
		return (set_errno(EFAULT));

	count = 0;
	for (i = 0; i < iovcnt; i++) {
		ssize_t iovlen = aiov[i].iov_len;
		count += iovlen;
		if (iovlen < 0 || count < 0)
			return (set_errno(EINVAL));
	}
	if ((fp = getf(fdes)) == NULL)
		return (set_errno(EBADF));
	if (((fflag = fp->f_flag) & FREAD) == 0) {
		error = EBADF;
		goto out;
	}
	vp = fp->f_vnode;
	if (vp->v_type == VREG && count == 0) {
		goto out;
	}

	rwflag = 0;

	/*
	 * We have to enter the critical region before calling VOP_RWLOCK
	 * to avoid a deadlock with ufs.
	 */
	if (nbl_need_check(vp)) {
		int svmand;

		nbl_start_crit(vp, RW_READER);
		in_crit = 1;
		error = nbl_svmand(vp, fp->f_cred, &svmand);
		if (error != 0)
			goto out;
		if (nbl_conflict(vp, NBL_READ, fp->f_offset, count, svmand,
		    NULL)) {
			error = EACCES;
			goto out;
		}
	}

	(void) VOP_RWLOCK(vp, rwflag, NULL);
	fileoff = fp->f_offset;

	/*
	 * Behaviour is same as read. Please see comments in read.
	 */

	if ((vp->v_type == VREG) && (fileoff >= OFFSET_MAX(fp))) {
		struct vattr va;
		va.va_mask = AT_SIZE;
		if ((error = VOP_GETATTR(vp, &va, 0, fp->f_cred, NULL)))  {
			VOP_RWUNLOCK(vp, rwflag, NULL);
			goto out;
		}
		if (fileoff >= va.va_size) {
			VOP_RWUNLOCK(vp, rwflag, NULL);
			count = 0;
			goto out;
		} else {
			VOP_RWUNLOCK(vp, rwflag, NULL);
			error = EOVERFLOW;
			goto out;
		}
	}
	if ((vp->v_type == VREG) && (fileoff + count > OFFSET_MAX(fp))) {
		count = (ssize_t)(OFFSET_MAX(fp) - fileoff);
	}
	auio.uio_loffset = fileoff;
	auio.uio_iov = aiov;
	auio.uio_iovcnt = iovcnt;
	auio.uio_resid = bcount = count;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_llimit = MAXOFFSET_T;
	auio.uio_fmode = fflag;
	if (bcount <= copyout_max_cached)
		auio.uio_extflg = UIO_COPY_CACHED;
	else
		auio.uio_extflg = UIO_COPY_DEFAULT;


	ioflag = auio.uio_fmode & (FAPPEND|FSYNC|FDSYNC|FRSYNC);

	/* If read sync is not asked for, filter sync flags */
	if ((ioflag & FRSYNC) == 0)
		ioflag &= ~(FSYNC|FDSYNC);
	error = VOP_READ(vp, &auio, ioflag, fp->f_cred, NULL);
	count -= auio.uio_resid;
	CPU_STATS_ENTER_K();
	cp = CPU;
	CPU_STATS_ADDQ(cp, sys, sysread, 1);
	CPU_STATS_ADDQ(cp, sys, readch, (ulong_t)count);
	CPU_STATS_EXIT_K();
	ttolwp(curthread)->lwp_ru.ioch += (ulong_t)count;

	if (vp->v_type == VFIFO)	/* Backward compatibility */
		fp->f_offset = count;
	else if (((fp->f_flag & FAPPEND) == 0) ||
	    (vp->v_type != VREG) || (bcount != 0))	/* POSIX */
		fp->f_offset = auio.uio_loffset;

	VOP_RWUNLOCK(vp, rwflag, NULL);

	if (error == EINTR && count != 0)
		error = 0;
out:
	if (in_crit)
		nbl_end_crit(vp);
	releasef(fdes);
	if (error)
		return (set_errno(error));
	return (count);
}

ssize_t
writev(int fdes, struct iovec *iovp, int iovcnt)
{
	struct uio auio;
	struct iovec aiov[DEF_IOV_MAX];
	file_t *fp;
	register vnode_t *vp;
	struct cpu *cp;
	int fflag, ioflag, rwflag;
	ssize_t count, bcount;
	int error = 0;
	int i;
	u_offset_t fileoff;
	int in_crit = 0;

	if (iovcnt <= 0 || iovcnt > DEF_IOV_MAX)
		return (set_errno(EINVAL));

#ifdef _SYSCALL32_IMPL
	/*
	 * 32-bit callers need to have their iovec expanded,
	 * while ensuring that they can't move more than 2Gbytes
	 * of data in a single call.
	 */
	if (get_udatamodel() == DATAMODEL_ILP32) {
		struct iovec32 aiov32[DEF_IOV_MAX];
		ssize32_t count32;

		if (copyin(iovp, aiov32, iovcnt * sizeof (struct iovec32)))
			return (set_errno(EFAULT));

		count32 = 0;
		for (i = 0; i < iovcnt; i++) {
			ssize32_t iovlen = aiov32[i].iov_len;
			count32 += iovlen;
			if (iovlen < 0 || count32 < 0)
				return (set_errno(EINVAL));
			aiov[i].iov_len = iovlen;
			aiov[i].iov_base =
			    (caddr_t)(uintptr_t)aiov32[i].iov_base;
		}
	} else
#endif
	if (copyin(iovp, aiov, iovcnt * sizeof (struct iovec)))
		return (set_errno(EFAULT));

	count = 0;
	for (i = 0; i < iovcnt; i++) {
		ssize_t iovlen = aiov[i].iov_len;
		count += iovlen;
		if (iovlen < 0 || count < 0)
			return (set_errno(EINVAL));
	}
	if ((fp = getf(fdes)) == NULL)
		return (set_errno(EBADF));
	if (((fflag = fp->f_flag) & FWRITE) == 0) {
		error = EBADF;
		goto out;
	}
	vp = fp->f_vnode;
	if (vp->v_type == VREG && count == 0) {
		goto out;
	}

	rwflag = 1;

	/*
	 * We have to enter the critical region before calling VOP_RWLOCK
	 * to avoid a deadlock with ufs.
	 */
	if (nbl_need_check(vp)) {
		int svmand;

		nbl_start_crit(vp, RW_READER);
		in_crit = 1;
		error = nbl_svmand(vp, fp->f_cred, &svmand);
		if (error != 0)
			goto out;
		if (nbl_conflict(vp, NBL_WRITE, fp->f_offset, count, svmand,
		    NULL)) {
			error = EACCES;
			goto out;
		}
	}

	(void) VOP_RWLOCK(vp, rwflag, NULL);

	fileoff = fp->f_offset;

	/*
	 * Behaviour is same as write. Please see comments for write.
	 */

	if (vp->v_type == VREG) {
		if (fileoff >= curproc->p_fsz_ctl) {
			VOP_RWUNLOCK(vp, rwflag, NULL);
			mutex_enter(&curproc->p_lock);
			(void) rctl_action(rctlproc_legacy[RLIMIT_FSIZE],
			    curproc->p_rctls, curproc, RCA_UNSAFE_SIGINFO);
			mutex_exit(&curproc->p_lock);
			error = EFBIG;
			goto out;
		}
		if (fileoff >= OFFSET_MAX(fp)) {
			VOP_RWUNLOCK(vp, rwflag, NULL);
			error = EFBIG;
			goto out;
		}
		if (fileoff + count > OFFSET_MAX(fp))
			count = (ssize_t)(OFFSET_MAX(fp) - fileoff);
	}
	auio.uio_loffset = fileoff;
	auio.uio_iov = aiov;
	auio.uio_iovcnt = iovcnt;
	auio.uio_resid = bcount = count;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_llimit = curproc->p_fsz_ctl;
	auio.uio_fmode = fflag;
	auio.uio_extflg = UIO_COPY_DEFAULT;

	ioflag = auio.uio_fmode & (FAPPEND|FSYNC|FDSYNC|FRSYNC);

	error = VOP_WRITE(vp, &auio, ioflag, fp->f_cred, NULL);
	count -= auio.uio_resid;
	CPU_STATS_ENTER_K();
	cp = CPU;
	CPU_STATS_ADDQ(cp, sys, syswrite, 1);
	CPU_STATS_ADDQ(cp, sys, writech, (ulong_t)count);
	CPU_STATS_EXIT_K();
	ttolwp(curthread)->lwp_ru.ioch += (ulong_t)count;

	if (vp->v_type == VFIFO)	/* Backward compatibility */
		fp->f_offset = count;
	else if (((fp->f_flag & FAPPEND) == 0) ||
	    (vp->v_type != VREG) || (bcount != 0))	/* POSIX */
		fp->f_offset = auio.uio_loffset;
	VOP_RWUNLOCK(vp, rwflag, NULL);

	if (error == EINTR && count != 0)
		error = 0;
out:
	if (in_crit)
		nbl_end_crit(vp);
	releasef(fdes);
	if (error)
		return (set_errno(error));
	return (count);
}

ssize_t
preadv(int fdes, struct iovec *iovp, int iovcnt, off_t offset,
    off_t extended_offset)
{
	struct uio auio;
	struct iovec aiov[DEF_IOV_MAX];
	file_t *fp;
	register vnode_t *vp;
	struct cpu *cp;
	int fflag, ioflag, rwflag;
	ssize_t count, bcount;
	int error = 0;
	int i;

#if defined(_SYSCALL32_IMPL) || defined(_ILP32)
	u_offset_t fileoff = ((u_offset_t)extended_offset << 32) |
	    (u_offset_t)offset;
#else /* _SYSCALL32_IMPL || _ILP32 */
	u_offset_t fileoff = (u_offset_t)(ulong_t)offset;
#endif /* _SYSCALL32_IMPR || _ILP32 */
#ifdef _SYSCALL32_IMPL
	const u_offset_t maxoff = get_udatamodel() == DATAMODEL_ILP32 &&
	    extended_offset == 0?
	    MAXOFF32_T : MAXOFFSET_T;
#else /* _SYSCALL32_IMPL */
	const u_offset_t maxoff = MAXOFF32_T;
#endif /* _SYSCALL32_IMPL */

	int in_crit = 0;

	if (iovcnt <= 0 || iovcnt > DEF_IOV_MAX)
		return (set_errno(EINVAL));

#ifdef _SYSCALL32_IMPL
	/*
	 * 32-bit callers need to have their iovec expanded,
	 * while ensuring that they can't move more than 2Gbytes
	 * of data in a single call.
	 */
	if (get_udatamodel() == DATAMODEL_ILP32) {
		struct iovec32 aiov32[DEF_IOV_MAX];
		ssize32_t count32;

		if (copyin(iovp, aiov32, iovcnt * sizeof (struct iovec32)))
			return (set_errno(EFAULT));

		count32 = 0;
		for (i = 0; i < iovcnt; i++) {
			ssize32_t iovlen32 = aiov32[i].iov_len;
			count32 += iovlen32;
			if (iovlen32 < 0 || count32 < 0)
				return (set_errno(EINVAL));
			aiov[i].iov_len = iovlen32;
			aiov[i].iov_base =
			    (caddr_t)(uintptr_t)aiov32[i].iov_base;
		}
	} else
#endif /* _SYSCALL32_IMPL */
		if (copyin(iovp, aiov, iovcnt * sizeof (struct iovec)))
			return (set_errno(EFAULT));

	count = 0;
	for (i = 0; i < iovcnt; i++) {
		ssize_t iovlen = aiov[i].iov_len;
		count += iovlen;
		if (iovlen < 0 || count < 0)
			return (set_errno(EINVAL));
	}

	if ((bcount = (ssize_t)count) < 0)
		return (set_errno(EINVAL));
	if ((fp = getf(fdes)) == NULL)
		return (set_errno(EBADF));
	if (((fflag = fp->f_flag) & FREAD) == 0) {
		error = EBADF;
		goto out;
	}
	vp = fp->f_vnode;
	rwflag = 0;
	if (vp->v_type == VREG) {

		if (bcount == 0)
			goto out;

		/*
		 * return EINVAL for offsets that cannot be
		 * represented in an off_t.
		 */
		if (fileoff > maxoff) {
			error = EINVAL;
			goto out;
		}

		if (fileoff + bcount > maxoff)
			bcount = (ssize_t)((u_offset_t)maxoff - fileoff);
	} else if (vp->v_type == VFIFO) {
		error = ESPIPE;
		goto out;
	}
	/*
	 * We have to enter the critical region before calling VOP_RWLOCK
	 * to avoid a deadlock with ufs.
	 */
	if (nbl_need_check(vp)) {
		int svmand;

		nbl_start_crit(vp, RW_READER);
		in_crit = 1;
		error = nbl_svmand(vp, fp->f_cred, &svmand);
		if (error != 0)
			goto out;
		if (nbl_conflict(vp, NBL_WRITE, fileoff, count, svmand,
		    NULL)) {
			error = EACCES;
			goto out;
		}
	}

	(void) VOP_RWLOCK(vp, rwflag, NULL);

	/*
	 * Behaviour is same as read(2). Please see comments in
	 * read(2).
	 */

	if ((vp->v_type == VREG) && (fileoff >= OFFSET_MAX(fp))) {
		struct vattr va;
		va.va_mask = AT_SIZE;
		if ((error =
		    VOP_GETATTR(vp, &va, 0, fp->f_cred, NULL)))  {
			VOP_RWUNLOCK(vp, rwflag, NULL);
			goto out;
		}
		if (fileoff >= va.va_size) {
			VOP_RWUNLOCK(vp, rwflag, NULL);
			count = 0;
			goto out;
		} else {
			VOP_RWUNLOCK(vp, rwflag, NULL);
			error = EOVERFLOW;
			goto out;
		}
	}
	if ((vp->v_type == VREG) &&
	    (fileoff + count > OFFSET_MAX(fp))) {
		count = (ssize_t)(OFFSET_MAX(fp) - fileoff);
	}
	auio.uio_loffset = fileoff;
	auio.uio_iov = aiov;
	auio.uio_iovcnt = iovcnt;
	auio.uio_resid = bcount = count;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_llimit = MAXOFFSET_T;
	auio.uio_fmode = fflag;
	if (bcount <= copyout_max_cached)
		auio.uio_extflg = UIO_COPY_CACHED;
	else
		auio.uio_extflg = UIO_COPY_DEFAULT;

	ioflag = auio.uio_fmode & (FAPPEND|FSYNC|FDSYNC|FRSYNC);
	error = VOP_READ(vp, &auio, ioflag, fp->f_cred, NULL);
	count -= auio.uio_resid;
	CPU_STATS_ENTER_K();
	cp = CPU;
	CPU_STATS_ADDQ(cp, sys, sysread, 1);
	CPU_STATS_ADDQ(cp, sys, readch, (ulong_t)count);
	CPU_STATS_EXIT_K();
	ttolwp(curthread)->lwp_ru.ioch += (ulong_t)count;

	VOP_RWUNLOCK(vp, rwflag, NULL);

	if (error == EINTR && count != 0)
		error = 0;
out:
	if (in_crit)
		nbl_end_crit(vp);
	releasef(fdes);
	if (error)
		return (set_errno(error));
	return (count);
}

ssize_t
pwritev(int fdes, struct iovec *iovp, int iovcnt, off_t offset,
    off_t extended_offset)
{
	struct uio auio;
	struct iovec aiov[DEF_IOV_MAX];
	file_t *fp;
	register vnode_t *vp;
	struct cpu *cp;
	int fflag, ioflag, rwflag;
	ssize_t count, bcount;
	int error = 0;
	int i;

#if defined(_SYSCALL32_IMPL) || defined(_ILP32)
	u_offset_t fileoff = ((u_offset_t)extended_offset << 32) |
	    (u_offset_t)offset;
#else /* _SYSCALL32_IMPL || _ILP32 */
	u_offset_t fileoff = (u_offset_t)(ulong_t)offset;
#endif /* _SYSCALL32_IMPR || _ILP32 */
#ifdef _SYSCALL32_IMPL
	const u_offset_t maxoff = get_udatamodel() == DATAMODEL_ILP32 &&
	    extended_offset == 0?
	    MAXOFF32_T : MAXOFFSET_T;
#else /* _SYSCALL32_IMPL */
	const u_offset_t maxoff = MAXOFF32_T;
#endif /* _SYSCALL32_IMPL */

	int in_crit = 0;

	if (iovcnt <= 0 || iovcnt > DEF_IOV_MAX)
		return (set_errno(EINVAL));

#ifdef _SYSCALL32_IMPL
	/*
	 * 32-bit callers need to have their iovec expanded,
	 * while ensuring that they can't move more than 2Gbytes
	 * of data in a single call.
	 */
	if (get_udatamodel() == DATAMODEL_ILP32) {
		struct iovec32 aiov32[DEF_IOV_MAX];
		ssize32_t count32;

		if (copyin(iovp, aiov32, iovcnt * sizeof (struct iovec32)))
			return (set_errno(EFAULT));

		count32 = 0;
		for (i = 0; i < iovcnt; i++) {
			ssize32_t iovlen32 = aiov32[i].iov_len;
			count32 += iovlen32;
			if (iovlen32 < 0 || count32 < 0)
				return (set_errno(EINVAL));
			aiov[i].iov_len = iovlen32;
			aiov[i].iov_base =
			    (caddr_t)(uintptr_t)aiov32[i].iov_base;
		}
	} else
#endif /* _SYSCALL32_IMPL */
		if (copyin(iovp, aiov, iovcnt * sizeof (struct iovec)))
			return (set_errno(EFAULT));

	count = 0;
	for (i = 0; i < iovcnt; i++) {
		ssize_t iovlen = aiov[i].iov_len;
		count += iovlen;
		if (iovlen < 0 || count < 0)
			return (set_errno(EINVAL));
	}

	if ((bcount = (ssize_t)count) < 0)
		return (set_errno(EINVAL));
	if ((fp = getf(fdes)) == NULL)
		return (set_errno(EBADF));
	if (((fflag = fp->f_flag) & FWRITE) == 0) {
		error = EBADF;
		goto out;
	}
	vp = fp->f_vnode;
	rwflag = 1;
	if (vp->v_type == VREG) {

		if (bcount == 0)
			goto out;

		/*
		 * return EINVAL for offsets that cannot be
		 * represented in an off_t.
		 */
		if (fileoff > maxoff) {
			error = EINVAL;
			goto out;
		}
		/*
		 * Take appropriate action if we are trying
		 * to write above the resource limit.
		 */
		if (fileoff >= curproc->p_fsz_ctl) {
			mutex_enter(&curproc->p_lock);
			/*
			 * Return value ignored because it lists
			 * actions taken, but we are in an error case.
			 * We don't have any actions that depend on
			 * what could happen in this call, so we ignore
			 * the return value.
			 */
			(void) rctl_action(
			    rctlproc_legacy[RLIMIT_FSIZE],
			    curproc->p_rctls, curproc,
			    RCA_UNSAFE_SIGINFO);
			mutex_exit(&curproc->p_lock);

			error = EFBIG;
			goto out;
		}
		/*
		 * Don't allow pwritev to cause file sizes to exceed
		 * maxoff.
		 */
		if (fileoff == maxoff) {
			error = EFBIG;
			goto out;
		}

		if (fileoff + bcount > maxoff)
			bcount = (ssize_t)((u_offset_t)maxoff - fileoff);
	} else if (vp->v_type == VFIFO) {
		error = ESPIPE;
		goto out;
	}
	/*
	 * We have to enter the critical region before calling VOP_RWLOCK
	 * to avoid a deadlock with ufs.
	 */
	if (nbl_need_check(vp)) {
		int svmand;

		nbl_start_crit(vp, RW_READER);
		in_crit = 1;
		error = nbl_svmand(vp, fp->f_cred, &svmand);
		if (error != 0)
			goto out;
		if (nbl_conflict(vp, NBL_WRITE, fileoff, count, svmand,
		    NULL)) {
			error = EACCES;
			goto out;
		}
	}

	(void) VOP_RWLOCK(vp, rwflag, NULL);


	/*
	 * Behaviour is same as write(2). Please see comments for
	 * write(2).
	 */

	if (vp->v_type == VREG) {
		if (fileoff >= curproc->p_fsz_ctl) {
			VOP_RWUNLOCK(vp, rwflag, NULL);
			mutex_enter(&curproc->p_lock);
			/* see above rctl_action comment */
			(void) rctl_action(
			    rctlproc_legacy[RLIMIT_FSIZE],
			    curproc->p_rctls,
			    curproc, RCA_UNSAFE_SIGINFO);
			mutex_exit(&curproc->p_lock);
			error = EFBIG;
			goto out;
		}
		if (fileoff >= OFFSET_MAX(fp)) {
			VOP_RWUNLOCK(vp, rwflag, NULL);
			error = EFBIG;
			goto out;
		}
		if (fileoff + count > OFFSET_MAX(fp))
			count = (ssize_t)(OFFSET_MAX(fp) - fileoff);
	}

	auio.uio_loffset = fileoff;
	auio.uio_iov = aiov;
	auio.uio_iovcnt = iovcnt;
	auio.uio_resid = bcount = count;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_llimit = curproc->p_fsz_ctl;
	auio.uio_fmode = fflag;
	auio.uio_extflg = UIO_COPY_CACHED;
	ioflag = auio.uio_fmode & (FSYNC|FDSYNC|FRSYNC);
	error = VOP_WRITE(vp, &auio, ioflag, fp->f_cred, NULL);
	count -= auio.uio_resid;
	CPU_STATS_ENTER_K();
	cp = CPU;
	CPU_STATS_ADDQ(cp, sys, syswrite, 1);
	CPU_STATS_ADDQ(cp, sys, writech, (ulong_t)count);
	CPU_STATS_EXIT_K();
	ttolwp(curthread)->lwp_ru.ioch += (ulong_t)count;

	VOP_RWUNLOCK(vp, rwflag, NULL);

	if (error == EINTR && count != 0)
		error = 0;
out:
	if (in_crit)
		nbl_end_crit(vp);
	releasef(fdes);
	if (error)
		return (set_errno(error));
	return (count);
}

#if defined(_SYSCALL32_IMPL) || defined(_ILP32)

/*
 * This syscall supplies 64-bit file offsets to 32-bit applications only.
 */
ssize32_t
pread64(int fdes, void *cbuf, size32_t count, uint32_t offset_1,
    uint32_t offset_2)
{
	struct uio auio;
	struct iovec aiov;
	file_t *fp;
	register vnode_t *vp;
	struct cpu *cp;
	int fflag, ioflag, rwflag;
	ssize_t bcount;
	int error = 0;
	u_offset_t fileoff;
	int in_crit = 0;

#if defined(_LITTLE_ENDIAN)
	fileoff = ((u_offset_t)offset_2 << 32) | (u_offset_t)offset_1;
#else
	fileoff = ((u_offset_t)offset_1 << 32) | (u_offset_t)offset_2;
#endif

	if ((bcount = (ssize_t)count) < 0 || bcount > INT32_MAX)
		return (set_errno(EINVAL));

	if ((fp = getf(fdes)) == NULL)
		return (set_errno(EBADF));
	if (((fflag = fp->f_flag) & (FREAD)) == 0) {
		error = EBADF;
		goto out;
	}

	rwflag = 0;
	vp = fp->f_vnode;

	if (vp->v_type == VREG) {

		if (bcount == 0)
			goto out;

		/*
		 * Same as pread. See comments in pread.
		 */

		if (fileoff > MAXOFFSET_T) {
			error = EINVAL;
			goto out;
		}
		if (fileoff + bcount > MAXOFFSET_T)
			bcount = (ssize_t)(MAXOFFSET_T - fileoff);
	} else if (vp->v_type == VFIFO) {
		error = ESPIPE;
		goto out;
	}

	/*
	 * We have to enter the critical region before calling VOP_RWLOCK
	 * to avoid a deadlock with ufs.
	 */
	if (nbl_need_check(vp)) {
		int svmand;

		nbl_start_crit(vp, RW_READER);
		in_crit = 1;
		error = nbl_svmand(vp, fp->f_cred, &svmand);
		if (error != 0)
			goto out;
		if (nbl_conflict(vp, NBL_READ, fileoff, bcount, svmand,
		    NULL)) {
			error = EACCES;
			goto out;
		}
	}

	aiov.iov_base = cbuf;
	aiov.iov_len = bcount;
	(void) VOP_RWLOCK(vp, rwflag, NULL);
	auio.uio_loffset = fileoff;

	/*
	 * Note: File size can never be greater than MAXOFFSET_T.
	 * If ever we start supporting 128 bit files the code
	 * similar to the one in pread at this place should be here.
	 * Here we avoid the unnecessary VOP_GETATTR() when we
	 * know that fileoff == MAXOFFSET_T implies that it is always
	 * greater than or equal to file size.
	 */
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_resid = bcount;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_llimit = MAXOFFSET_T;
	auio.uio_fmode = fflag;
	auio.uio_extflg = UIO_COPY_CACHED;

	ioflag = auio.uio_fmode & (FAPPEND|FSYNC|FDSYNC|FRSYNC);

	/* If read sync is not asked for, filter sync flags */
	if ((ioflag & FRSYNC) == 0)
		ioflag &= ~(FSYNC|FDSYNC);
	error = VOP_READ(vp, &auio, ioflag, fp->f_cred, NULL);
	bcount -= auio.uio_resid;
	CPU_STATS_ENTER_K();
	cp = CPU;
	CPU_STATS_ADDQ(cp, sys, sysread, 1);
	CPU_STATS_ADDQ(cp, sys, readch, (ulong_t)bcount);
	CPU_STATS_EXIT_K();
	ttolwp(curthread)->lwp_ru.ioch += (ulong_t)bcount;
	VOP_RWUNLOCK(vp, rwflag, NULL);

	if (error == EINTR && bcount != 0)
		error = 0;
out:
	if (in_crit)
		nbl_end_crit(vp);
	releasef(fdes);
	if (error)
		return (set_errno(error));
	return (bcount);
}

/*
 * This syscall supplies 64-bit file offsets to 32-bit applications only.
 */
ssize32_t
pwrite64(int fdes, void *cbuf, size32_t count, uint32_t offset_1,
    uint32_t offset_2)
{
	struct uio auio;
	struct iovec aiov;
	file_t *fp;
	register vnode_t *vp;
	struct cpu *cp;
	int fflag, ioflag, rwflag;
	ssize_t bcount;
	int error = 0;
	u_offset_t fileoff;
	int in_crit = 0;

#if defined(_LITTLE_ENDIAN)
	fileoff = ((u_offset_t)offset_2 << 32) | (u_offset_t)offset_1;
#else
	fileoff = ((u_offset_t)offset_1 << 32) | (u_offset_t)offset_2;
#endif

	if ((bcount = (ssize_t)count) < 0 || bcount > INT32_MAX)
		return (set_errno(EINVAL));
	if ((fp = getf(fdes)) == NULL)
		return (set_errno(EBADF));
	if (((fflag = fp->f_flag) & (FWRITE)) == 0) {
		error = EBADF;
		goto out;
	}

	rwflag = 1;
	vp = fp->f_vnode;

	if (vp->v_type == VREG) {

		if (bcount == 0)
			goto out;

		/*
		 * See comments in pwrite.
		 */
		if (fileoff > MAXOFFSET_T) {
			error = EINVAL;
			goto out;
		}
		if (fileoff >= curproc->p_fsz_ctl) {
			mutex_enter(&curproc->p_lock);
			(void) rctl_action(rctlproc_legacy[RLIMIT_FSIZE],
			    curproc->p_rctls, curproc, RCA_SAFE);
			mutex_exit(&curproc->p_lock);
			error = EFBIG;
			goto out;
		}
		if (fileoff == MAXOFFSET_T) {
			error = EFBIG;
			goto out;
		}
		if (fileoff + bcount > MAXOFFSET_T)
			bcount = (ssize_t)((u_offset_t)MAXOFFSET_T - fileoff);
	} else if (vp->v_type == VFIFO) {
		error = ESPIPE;
		goto out;
	}

	/*
	 * We have to enter the critical region before calling VOP_RWLOCK
	 * to avoid a deadlock with ufs.
	 */
	if (nbl_need_check(vp)) {
		int svmand;

		nbl_start_crit(vp, RW_READER);
		in_crit = 1;
		error = nbl_svmand(vp, fp->f_cred, &svmand);
		if (error != 0)
			goto out;
		if (nbl_conflict(vp, NBL_WRITE, fileoff, bcount, svmand,
		    NULL)) {
			error = EACCES;
			goto out;
		}
	}

	aiov.iov_base = cbuf;
	aiov.iov_len = bcount;
	(void) VOP_RWLOCK(vp, rwflag, NULL);
	auio.uio_loffset = fileoff;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_resid = bcount;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_llimit = curproc->p_fsz_ctl;
	auio.uio_fmode = fflag;
	auio.uio_extflg = UIO_COPY_CACHED;

	/*
	 * The SUSv4 POSIX specification states:
	 *	The pwrite() function shall be equivalent to write(), except
	 *	that it writes into a given position and does not change
	 *	the file offset (regardless of whether O_APPEND is set).
	 * To make this be true, we omit the FAPPEND flag from ioflag.
	 */
	ioflag = auio.uio_fmode & (FSYNC|FDSYNC|FRSYNC);

	error = VOP_WRITE(vp, &auio, ioflag, fp->f_cred, NULL);
	bcount -= auio.uio_resid;
	CPU_STATS_ENTER_K();
	cp = CPU;
	CPU_STATS_ADDQ(cp, sys, syswrite, 1);
	CPU_STATS_ADDQ(cp, sys, writech, (ulong_t)bcount);
	CPU_STATS_EXIT_K();
	ttolwp(curthread)->lwp_ru.ioch += (ulong_t)bcount;
	VOP_RWUNLOCK(vp, rwflag, NULL);

	if (error == EINTR && bcount != 0)
		error = 0;
out:
	if (in_crit)
		nbl_end_crit(vp);
	releasef(fdes);
	if (error)
		return (set_errno(error));
	return (bcount);
}

#endif	/* _SYSCALL32_IMPL || _ILP32 */

#ifdef _SYSCALL32_IMPL
/*
 * Tail-call elimination of xxx32() down to xxx()
 *
 * A number of xxx32 system calls take a len (or count) argument and
 * return a number in the range [0,len] or -1 on error.
 * Given an ssize32_t input len, the downcall xxx() will return
 * a 64-bit value that is -1 or in the range [0,len] which actually
 * is a proper return value for the xxx32 call. So even if the xxx32
 * calls can be considered as returning a ssize32_t, they are currently
 * declared as returning a ssize_t as this enables tail-call elimination.
 *
 * The cast of len (or count) to ssize32_t is needed to ensure we pass
 * down negative input values as such and let the downcall handle error
 * reporting. Functions covered by this comments are:
 *
 * rw.c:           read32, write32, pread32, pwrite32, readv32, writev32.
 * socksyscall.c:  recv32, recvfrom32, send32, sendto32.
 * readlink.c:     readlink32.
 */

ssize_t
read32(int32_t fdes, caddr32_t cbuf, size32_t count)
{
	return (read(fdes,
	    (void *)(uintptr_t)cbuf, (ssize32_t)count));
}

ssize_t
write32(int32_t fdes, caddr32_t cbuf, size32_t count)
{
	return (write(fdes,
	    (void *)(uintptr_t)cbuf, (ssize32_t)count));
}

ssize_t
pread32(int32_t fdes, caddr32_t cbuf, size32_t count, off32_t offset)
{
	return (pread(fdes,
	    (void *)(uintptr_t)cbuf, (ssize32_t)count,
	    (off_t)(uint32_t)offset));
}

ssize_t
pwrite32(int32_t fdes, caddr32_t cbuf, size32_t count, off32_t offset)
{
	return (pwrite(fdes,
	    (void *)(uintptr_t)cbuf, (ssize32_t)count,
	    (off_t)(uint32_t)offset));
}

ssize_t
readv32(int32_t fdes, caddr32_t iovp, int32_t iovcnt)
{
	return (readv(fdes, (void *)(uintptr_t)iovp, iovcnt));
}

ssize_t
writev32(int32_t fdes, caddr32_t iovp, int32_t iovcnt)
{
	return (writev(fdes, (void *)(uintptr_t)iovp, iovcnt));
}
#endif	/* _SYSCALL32_IMPL */
