/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2015 Joyent, Inc.
 */

#include <sys/errno.h>
#include <sys/systm.h>
#include <sys/file.h>
#include <sys/vnode.h>
#include <sys/brand.h>
#include <sys/lx_brand.h>
#include <sys/nbmlock.h>
#include <sys/limits.h>

/* uts/common/syscall/rw.c */
extern size_t copyout_max_cached;


/* Common routines */

static int
lx_iovec_copyin(void *uiovp, int iovcnt, iovec_t *kiovp, ssize_t *count)
{
#ifdef _SYSCALL32_IMPL
	/*
	 * 32-bit callers need to have their iovec expanded, while ensuring
	 * that they can't move more than 2Gbytes of data in a single call.
	 */
	if (get_udatamodel() == DATAMODEL_ILP32) {
		struct iovec32 buf32[IOV_MAX_STACK], *aiov32 = buf32;
		int aiov32len = 0;
		ssize32_t total32 = 0;
		int i;

		if (iovcnt > IOV_MAX_STACK) {
			aiov32len = iovcnt * sizeof (iovec32_t);
			aiov32 = kmem_alloc(aiov32len, KM_SLEEP);
		}

		if (copyin(uiovp, aiov32, iovcnt * sizeof (iovec32_t))) {
			if (aiov32len != 0) {
				kmem_free(aiov32, aiov32len);
			}
			return (EFAULT);
		}

		for (i = 0; i < iovcnt; i++) {
			ssize32_t iovlen32 = aiov32[i].iov_len;
			total32 += iovlen32;
			if (iovlen32 < 0 || total32 < 0) {
				if (aiov32len != 0) {
					kmem_free(aiov32, aiov32len);
				}
				return (EINVAL);
			}
			kiovp[i].iov_len = iovlen32;
			kiovp[i].iov_base =
			    (caddr_t)(uintptr_t)aiov32[i].iov_base;
		}
		*count = total32;

		if (aiov32len != 0)
			kmem_free(aiov32, aiov32len);
	} else
#endif
	{
		ssize_t total = 0;
		int i;

		if (copyin(uiovp, kiovp, iovcnt * sizeof (iovec_t)))
			return (EFAULT);
		for (i = 0; i < iovcnt; i++) {
			ssize_t iovlen = kiovp[i].iov_len;
			total += iovlen;
			if (iovlen < 0 || total < 0) {
				return (EINVAL);
			}
		}
		*count = total;
	}
	return (0);
}

static int
lx_read_common(file_t *fp, uio_t *uiop, size_t *nread, boolean_t positioned)
{
	vnode_t *vp = fp->f_vnode;
	int error = 0, rwflag = 0, ioflag;
	ssize_t count = uiop->uio_resid;
	size_t rcount = 0;
	struct cpu *cp;
	boolean_t in_crit = B_FALSE;

	/*
	 * We have to enter the critical region before calling VOP_RWLOCK
	 * to avoid a deadlock with ufs.
	 */
	if (nbl_need_check(vp)) {
		int svmand;

		nbl_start_crit(vp, RW_READER);
		in_crit = B_TRUE;
		error = nbl_svmand(vp, fp->f_cred, &svmand);
		if (error != 0)
			goto out;
		if (nbl_conflict(vp, NBL_READ, uiop->uio_offset, count, svmand,
		    NULL) != 0) {
			error = EACCES;
			goto out;
		}
	}

	(void) VOP_RWLOCK(vp, rwflag, NULL);
	/*
	 * For non-positioned reads, recheck offset/count validity inside
	 * VOP_WRLOCK to prevent filesize from changing during validation.
	 */
	if (!positioned) {
		u_offset_t uoffset = (u_offset_t)(ulong_t)fp->f_offset;

		if ((vp->v_type == VREG) && (uoffset >= OFFSET_MAX(fp))) {
			struct vattr va;

			va.va_mask = AT_SIZE;
			error = VOP_GETATTR(vp, &va, 0, fp->f_cred, NULL);
			VOP_RWUNLOCK(vp, rwflag, NULL);
			if (error != 0)
				goto out;
			/* We have to return EOF if fileoff is >= file size. */
			if (uoffset >= va.va_size)
				goto out;
			/*
			 * File is greater than or equal to maxoff and
			 * therefore we return EOVERFLOW.
			 */
			error = EOVERFLOW;
			goto out;
		}
		if ((vp->v_type == VREG) &&
		    (uoffset + count > OFFSET_MAX(fp))) {
			count = (ssize_t)(OFFSET_MAX(fp) - uoffset);
			uiop->uio_resid = count;
		}
		uiop->uio_offset = uoffset;
	}
	ioflag = uiop->uio_fmode & (FAPPEND|FSYNC|FDSYNC|FRSYNC);
	/* If read sync is not asked for, filter sync flags */
	if ((ioflag & FRSYNC) == 0)
		ioflag &= ~(FSYNC|FDSYNC);
	error = VOP_READ(vp, uiop, ioflag, fp->f_cred, NULL);
	rcount = count - uiop->uio_resid;
	CPU_STATS_ENTER_K();
	cp = CPU;
	CPU_STATS_ADDQ(cp, sys, sysread, 1);
	CPU_STATS_ADDQ(cp, sys, readch, (ulong_t)rcount);
	CPU_STATS_EXIT_K();
	ttolwp(curthread)->lwp_ru.ioch += (ulong_t)rcount;
	/* Store offset for non-positioned reads */
	if (!positioned) {
		if (vp->v_type == VFIFO) {
			/* Backward compatibility */
			fp->f_offset = rcount;
		} else if (((fp->f_flag & FAPPEND) == 0) ||
		    (vp->v_type != VREG) || (count != 0)) {
			/* POSIX */
			fp->f_offset = uiop->uio_loffset;
		}
	}
	VOP_RWUNLOCK(vp, rwflag, NULL);

out:
	if (in_crit)
		nbl_end_crit(vp);
	*nread = rcount;
	return (error);
}

static int
lx_write_common(file_t *fp, uio_t *uiop, size_t *nwrite, boolean_t positioned)
{
	vnode_t *vp = fp->f_vnode;
	int error = 0, rwflag = 1, ioflag;
	ssize_t count = uiop->uio_resid;
	size_t wcount = 0;
	struct cpu *cp;
	boolean_t in_crit = B_FALSE;

	/*
	 * We have to enter the critical region before calling VOP_RWLOCK
	 * to avoid a deadlock with ufs.
	 */
	if (nbl_need_check(vp)) {
		int svmand;

		nbl_start_crit(vp, RW_READER);
		in_crit = B_TRUE;
		error = nbl_svmand(vp, fp->f_cred, &svmand);
		if (error != 0)
			goto out;
		if (nbl_conflict(vp, NBL_WRITE, uiop->uio_loffset, count,
		    svmand, NULL) != 0) {
			error = EACCES;
			goto out;
		}
	}

	(void) VOP_RWLOCK(vp, rwflag, NULL);

	if (!positioned) {
		/*
		 * For non-positioned writes, the value of fp->f_offset is
		 * re-queried while inside VOP_RWLOCK.  This ensures that other
		 * writes which alter the filesize will be taken into account.
		 */
		uiop->uio_loffset = fp->f_offset;
		ioflag = uiop->uio_fmode & (FAPPEND|FSYNC|FDSYNC|FRSYNC);
	} else {
		/*
		 * The SUSv4 POSIX specification states:
		 * The pwrite() function shall be equivalent to write(), except
		 * that it writes into a given position and does not change
		 * the file offset (regardless of whether O_APPEND is set).
		 *
		 * To make this be true, we omit the FAPPEND flag from ioflag.
		 */
		ioflag = uiop->uio_fmode & (FSYNC|FDSYNC|FRSYNC);
	}
	if (vp->v_type == VREG) {
		u_offset_t fileoff = (u_offset_t)(ulong_t)uiop->uio_loffset;

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
		if (fileoff + count > OFFSET_MAX(fp)) {
			count = (ssize_t)(OFFSET_MAX(fp) - fileoff);
			uiop->uio_resid = count;
		}
	}

	error = VOP_WRITE(vp, uiop, ioflag, fp->f_cred, NULL);
	wcount = count - uiop->uio_resid;
	CPU_STATS_ENTER_K();
	cp = CPU;
	CPU_STATS_ADDQ(cp, sys, syswrite, 1);
	CPU_STATS_ADDQ(cp, sys, writech, (ulong_t)wcount);
	CPU_STATS_EXIT_K();
	ttolwp(curthread)->lwp_ru.ioch += (ulong_t)wcount;

	/* Store offset for non-positioned writes */
	if (!positioned) {
		if (vp->v_type == VFIFO) {
			/* Backward compatibility */
			fp->f_offset = wcount;
		} else if (((fp->f_flag & FAPPEND) == 0) ||
		    (vp->v_type != VREG) || (count != 0)) {
			/* POSIX */
			fp->f_offset = uiop->uio_loffset;
		}
	}
	VOP_RWUNLOCK(vp, rwflag, NULL);

out:
	if (in_crit)
		nbl_end_crit(vp);
	*nwrite = wcount;
	return (error);
}


ssize_t
lx_read(int fdes, void *cbuf, size_t ccount)
{
	struct uio auio;
	struct iovec aiov;
	file_t *fp;
	ssize_t count = (ssize_t)ccount;
	size_t nread = 0;
	int fflag, error = 0;

	if (count < 0)
		return (set_errno(EINVAL));
	if ((fp = getf(fdes)) == NULL)
		return (set_errno(EBADF));
	if (((fflag = fp->f_flag) & FREAD) == 0) {
		error = EBADF;
		goto out;
	}
	if (fp->f_vnode->v_type == VREG && count == 0) {
		goto out;
	}
	if (fp->f_vnode->v_type == VDIR) {
		error = EISDIR;
		goto out;
	}

	aiov.iov_base = cbuf;
	aiov.iov_len = count;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_loffset = fp->f_offset;
	auio.uio_resid = count;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_llimit = MAXOFFSET_T;
	auio.uio_fmode = fflag;
	if (count <= copyout_max_cached)
		auio.uio_extflg = UIO_COPY_CACHED;
	else
		auio.uio_extflg = UIO_COPY_DEFAULT;

	error = lx_read_common(fp, &auio, &nread, B_FALSE);

	if (error == EINTR) {
		if (nread != 0) {
			error = 0;
		} else {
			/*
			 * If read(2) returns EINTR, we want to signal that
			 * restarting the system call is acceptable:
			 */
			ttolxlwp(curthread)->br_syscall_restart = B_TRUE;
		}
	}
out:
	releasef(fdes);
	if (error != 0)
		return (set_errno(error));
	return ((ssize_t)nread);
}

ssize_t
lx_write(int fdes, void *cbuf, size_t ccount)
{
	struct uio auio;
	struct iovec aiov;
	file_t *fp;
	ssize_t count = (ssize_t)ccount;
	size_t nwrite = 0;
	int fflag, error = 0;

	if (count < 0)
		return (set_errno(EINVAL));
	if ((fp = getf(fdes)) == NULL)
		return (set_errno(EBADF));
	if (((fflag = fp->f_flag) & FWRITE) == 0) {
		error = EBADF;
		goto out;
	}
	if (fp->f_vnode->v_type == VREG && count == 0) {
		goto out;
	}

	aiov.iov_base = cbuf;
	aiov.iov_len = count;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_loffset = fp->f_offset;
	auio.uio_resid = count;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_llimit = curproc->p_fsz_ctl;
	auio.uio_fmode = fflag;
	auio.uio_extflg = UIO_COPY_DEFAULT;

	error = lx_write_common(fp, &auio, &nwrite, B_FALSE);

	if (error == EINTR) {
		if (nwrite != 0) {
			error = 0;
		} else {
			/*
			 * If write(2) returns EINTR, we want to signal that
			 * restarting the system call is acceptable:
			 */
			ttolxlwp(curthread)->br_syscall_restart = B_TRUE;
		}
	}
out:
	releasef(fdes);
	if (error != 0)
		return (set_errno(error));
	return (nwrite);
}

/*
 * Implementation of Linux readv() and writev() system calls.
 *
 * These differ from the SunOS implementation in a few key areas:
 *
 * - Passing 0 as a vector count is an error on SunOS, but on Linux results in
 *   a return value of 0.
 *
 * - If the Nth vector results in an error, SunOS will return an error code for
 *   the entire operation.  Linux only returns an error if no data has
 *   successfully been transfered yet.
 */

ssize_t
lx_readv(int fdes, struct iovec *iovp, int iovcnt)
{
	struct uio auio;
	struct iovec buf[IOV_MAX_STACK], *aiov = buf;
	int aiovlen = 0;
	file_t *fp;
	ssize_t count;
	size_t nread = 0;
	int fflag, error = 0;

	if (iovcnt < 0 || iovcnt > IOV_MAX)
		return (set_errno(EINVAL));
	else if (iovcnt == 0)
		return (0);

	if (iovcnt > IOV_MAX_STACK) {
		aiovlen = iovcnt * sizeof (iovec_t);
		aiov = kmem_alloc(aiovlen, KM_SLEEP);
	}
	if ((error = lx_iovec_copyin(iovp, iovcnt, aiov, &count)) != 0) {
		if (aiovlen != 0)
			kmem_free(aiov, aiovlen);
		return (set_errno(error));
	}

	if ((fp = getf(fdes)) == NULL) {
		if (aiovlen != 0)
			kmem_free(aiov, aiovlen);
		return (set_errno(EBADF));
	}
	if (((fflag = fp->f_flag) & FREAD) == 0) {
		error = EBADF;
		goto out;
	}
	if (fp->f_vnode->v_type == VREG && count == 0) {
		goto out;
	}
	if (fp->f_vnode->v_type == VDIR) {
		error = EISDIR;
		goto out;
	}

	auio.uio_iov = aiov;
	auio.uio_iovcnt = iovcnt;
	auio.uio_loffset = fp->f_offset;
	auio.uio_resid = count;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_llimit = MAXOFFSET_T;
	auio.uio_fmode = fflag;
	if (count <= copyout_max_cached)
		auio.uio_extflg = UIO_COPY_CACHED;
	else
		auio.uio_extflg = UIO_COPY_DEFAULT;

	error = lx_read_common(fp, &auio, &nread, B_FALSE);

	if (error == EINTR) {
		/*
		 * If readv(2) returns EINTR, we want to signal that restarting
		 * the system call is acceptable:
		 */
		ttolxlwp(curthread)->br_syscall_restart = B_TRUE;
	}
out:
	releasef(fdes);
	if (aiovlen != 0)
		kmem_free(aiov, aiovlen);
	/* Linux does not report an error if any bytes were read */
	if (error != 0 && nread == 0)
		return (set_errno(error));
	return (nread);
}

ssize_t
lx_writev(int fdes, struct iovec *iovp, int iovcnt)
{
	struct uio auio;
	struct iovec buf[IOV_MAX_STACK], *aiov = buf;
	int aiovlen = 0;
	file_t *fp;
	ssize_t count;
	size_t nwrite = 0;
	int fflag, error = 0;

	if (iovcnt < 0 || iovcnt > IOV_MAX)
		return (set_errno(EINVAL));
	else if (iovcnt == 0)
		return (0);

	if (iovcnt > IOV_MAX_STACK) {
		aiovlen = iovcnt * sizeof (iovec_t);
		aiov = kmem_alloc(aiovlen, KM_SLEEP);
	}
	if ((error = lx_iovec_copyin(iovp, iovcnt, aiov, &count)) != 0) {
		if (aiovlen != 0)
			kmem_free(aiov, aiovlen);
		return (set_errno(error));
	}

	if ((fp = getf(fdes)) == NULL) {
		if (aiovlen != 0)
			kmem_free(aiov, aiovlen);
		return (set_errno(EBADF));
	}
	if (((fflag = fp->f_flag) & FWRITE) == 0) {
		error = EBADF;
		goto out;
	}
	if (fp->f_vnode->v_type == VREG && count == 0) {
		goto out;
	}

	auio.uio_iov = aiov;
	auio.uio_iovcnt = iovcnt;
	auio.uio_loffset = fp->f_offset;
	auio.uio_resid = count;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_llimit = curproc->p_fsz_ctl;
	auio.uio_fmode = fflag;
	auio.uio_extflg = UIO_COPY_DEFAULT;

	error = lx_write_common(fp, &auio, &nwrite, B_FALSE);

	if (error == EINTR) {
		/*
		 * If writev(2) returns EINTR, we want to signal that
		 * restarting the system call is acceptable:
		 */
		ttolxlwp(curthread)->br_syscall_restart = B_TRUE;
	}
out:
	releasef(fdes);
	if (aiovlen != 0)
		kmem_free(aiov, aiovlen);
	/* Linux does not report an error if any bytes were written */
	if (error != 0 && nwrite == 0)
		return (set_errno(error));
	return (nwrite);
}
