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
 * Copyright 2016 Joyent, Inc.
 */

#include <sys/errno.h>
#include <sys/systm.h>
#include <sys/file.h>
#include <sys/vnode.h>
#include <sys/brand.h>
#include <sys/lx_brand.h>
#include <sys/lx_types.h>
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
			/* Linux does a basic sanity test on the address */
			if ((uintptr_t)kiovp[i].iov_base >= USERLIMIT32) {
				if (aiov32len != 0) {
					kmem_free(aiov32, aiov32len);
				}
				return (EFAULT);
			}
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
			/* Linux does a basic sanity test on the address */
			if ((uintptr_t)kiovp[i].iov_base >= USERLIMIT) {
				return (EFAULT);
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
		 * In a senseless departure from POSIX, positioned write calls
		 * on Linux do _not_ ignore the O_APPEND flag.
		 */
		ioflag = uiop->uio_fmode & (FAPPEND|FSYNC|FDSYNC|FRSYNC);
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

/*
 * The Linux routines for reading and writing data from file descriptors behave
 * differently from their SunOS counterparts in a few key ways:
 *
 * - Passing an iovcnt of 0 to the vectored functions results in an error on
 *   SunOS, but on Linux it yields return value of 0.
 *
 * - If any data is successfully read or written, Linux will return a success.
 *   This is unlike SunOS which would return an error code for the entire
 *   operation in cases where vectors had gone unprocessed.
 *
 * - Breaking from POSIX, Linux positioned writes (pwrite/pwritev) on Linux
 *   will obey the O_APPEND flag if it is set on the descriptor.
 */

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
			ttolxlwp(curthread)->br_syscall_restart = B_TRUE;
		}
	}
out:
	releasef(fdes);
	if (error != 0)
		return (set_errno(error));
	return (nwrite);
}

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

	if (iovcnt < 0 || iovcnt > IOV_MAX) {
		return (set_errno(EINVAL));
	} else if (iovcnt == 0) {
		return (0);
	}

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

	if (error != 0) {
		if (nread != 0) {
			error = 0;
		} else if (error == EINTR) {
			ttolxlwp(curthread)->br_syscall_restart = B_TRUE;
		}
	}
out:
	releasef(fdes);
	if (aiovlen != 0)
		kmem_free(aiov, aiovlen);
	if (error != 0) {
		return (set_errno(error));
	}
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

	if (iovcnt < 0 || iovcnt > IOV_MAX) {
		return (set_errno(EINVAL));
	} else if (iovcnt == 0) {
		return (0);
	}

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

	if (error != 0) {
		if (nwrite != 0) {
			error = 0;
		} else if (error == EINTR) {
			ttolxlwp(curthread)->br_syscall_restart = B_TRUE;
		}
	}
out:
	releasef(fdes);
	if (aiovlen != 0)
		kmem_free(aiov, aiovlen);
	if (error != 0) {
		return (set_errno(error));
	}
	return (nwrite);
}

ssize_t
lx_pread(int fdes, void *cbuf, size_t ccount, off64_t offset)
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
	if (fp->f_vnode->v_type == VREG) {
		u_offset_t fileoff = (u_offset_t)offset;

		if (count == 0)
			goto out;
		/*
		 * Return EINVAL if an invalid offset comes to pread.
		 * Negative offset from user will cause this error.
		 */
		if (fileoff > MAXOFFSET_T) {
			error = EINVAL;
			goto out;
		}
		/*
		 * Limit offset such that we don't read or write
		 * a file beyond the maximum offset representable in
		 * an off_t structure.
		 */
		if (fileoff + count > MAXOFFSET_T)
			count = (ssize_t)((offset_t)MAXOFFSET_T - fileoff);
	} else if (fp->f_vnode->v_type == VFIFO) {
		error = ESPIPE;
		goto out;
	} else if (fp->f_vnode->v_type == VDIR) {
		error = EISDIR;
		goto out;
	}

	aiov.iov_base = cbuf;
	aiov.iov_len = count;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_loffset = offset;
	auio.uio_resid = count;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_llimit = MAXOFFSET_T;
	auio.uio_fmode = fflag;
	auio.uio_extflg = UIO_COPY_CACHED;

	error = lx_read_common(fp, &auio, &nread, B_TRUE);

	if (error == EINTR) {
		if (nread != 0) {
			error = 0;
		} else {
			ttolxlwp(curthread)->br_syscall_restart = B_TRUE;
		}
	}
out:
	releasef(fdes);
	if (error) {
		return (set_errno(error));
	}
	return ((ssize_t)nread);

}

ssize_t
lx_pwrite(int fdes, void *cbuf, size_t ccount, off64_t offset)
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
	if (((fflag = fp->f_flag) & (FWRITE)) == 0) {
		error = EBADF;
		goto out;
	}
	if (fp->f_vnode->v_type == VREG) {
		u_offset_t fileoff = (u_offset_t)offset;

		if (count == 0)
			goto out;
		/*
		 * return EINVAL for offsets that cannot be
		 * represented in an off_t.
		 */
		if (fileoff > MAXOFFSET_T) {
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
		 * Don't allow pwrite to cause file sizes to exceed maxoffset.
		 */
		if (fileoff == MAXOFFSET_T) {
			error = EFBIG;
			goto out;
		}
		if (fileoff + count > MAXOFFSET_T)
			count = (ssize_t)((u_offset_t)MAXOFFSET_T - fileoff);
	} else if (fp->f_vnode->v_type == VFIFO) {
		error = ESPIPE;
		goto out;
	}

	aiov.iov_base = cbuf;
	aiov.iov_len = count;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_loffset = offset;
	auio.uio_resid = count;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_llimit = curproc->p_fsz_ctl;
	auio.uio_fmode = fflag;
	auio.uio_extflg = UIO_COPY_CACHED;

	error = lx_write_common(fp, &auio, &nwrite, B_TRUE);

	if (error == EINTR) {
		if (nwrite != 0) {
			error = 0;
		} else {
			ttolxlwp(curthread)->br_syscall_restart = B_TRUE;
		}
	}
out:
	releasef(fdes);
	if (error) {
		return (set_errno(error));
	}
	return (nwrite);
}

ssize_t
lx_pread32(int fdes, void *cbuf, size_t ccount, uint32_t off_lo,
    uint32_t off_hi)
{
	return (lx_pread(fdes, cbuf, ccount, LX_32TO64(off_lo, off_hi)));
}

ssize_t
lx_pwrite32(int fdes, void *cbuf, size_t ccount, uint32_t off_lo,
    uint32_t off_hi)
{
	return (lx_pwrite(fdes, cbuf, ccount, LX_32TO64(off_lo, off_hi)));
}

ssize_t
lx_preadv(int fdes, void *iovp, int iovcnt, off64_t offset)
{
	struct uio auio;
	struct iovec buf[IOV_MAX_STACK], *aiov = buf;
	int aiovlen = 0;
	file_t *fp;
	ssize_t count;
	size_t nread = 0;
	int fflag, error = 0;

	if (iovcnt < 0 || iovcnt > IOV_MAX) {
		return (set_errno(EINVAL));
	} else if (iovcnt == 0) {
		return (0);
	}

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
	if (fp->f_vnode->v_type == VREG) {
		u_offset_t fileoff = (u_offset_t)offset;

		if (count == 0)
			goto out;
		/*
		 * Return EINVAL if an invalid offset comes to pread.
		 * Negative offset from user will cause this error.
		 */
		if (fileoff > MAXOFFSET_T) {
			error = EINVAL;
			goto out;
		}
		/*
		 * Limit offset such that we don't read or write a file beyond
		 * the maximum offset representable in an off_t structure.
		 */
		if (fileoff + count > MAXOFFSET_T)
			count = (ssize_t)((offset_t)MAXOFFSET_T - fileoff);
	} else if (fp->f_vnode->v_type == VDIR) {
		error = EISDIR;
		goto out;
	} else if (fp->f_vnode->v_type == VFIFO) {
		error = ESPIPE;
		goto out;
	}

	auio.uio_iov = aiov;
	auio.uio_iovcnt = iovcnt;
	auio.uio_loffset = offset;
	auio.uio_resid = count;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_llimit = MAXOFFSET_T;
	auio.uio_fmode = fflag;
	if (count <= copyout_max_cached)
		auio.uio_extflg = UIO_COPY_CACHED;
	else
		auio.uio_extflg = UIO_COPY_DEFAULT;

	error = lx_read_common(fp, &auio, &nread, B_TRUE);

	if (error != 0) {
		if (nread != 0) {
			error = 0;
		} else if (error == EINTR) {
			ttolxlwp(curthread)->br_syscall_restart = B_TRUE;
		}
	}
out:
	releasef(fdes);
	if (aiovlen != 0)
		kmem_free(aiov, aiovlen);
	if (error != 0) {
		return (set_errno(error));
	}
	return (nread);
}

ssize_t
lx_pwritev(int fdes, void *iovp, int iovcnt, off64_t offset)
{
	struct uio auio;
	struct iovec buf[IOV_MAX_STACK], *aiov = buf;
	int aiovlen = 0;
	file_t *fp;
	ssize_t count;
	size_t nwrite = 0;
	int fflag, error = 0;

	if (iovcnt < 0 || iovcnt > IOV_MAX) {
		return (set_errno(EINVAL));
	} else if (iovcnt == 0) {
		return (0);
	}

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
	if (fp->f_vnode->v_type == VREG) {
		u_offset_t fileoff = (u_offset_t)offset;

		if (count == 0)
			goto out;
		/*
		 * Return EINVAL if an invalid offset comes to pread.
		 * Negative offset from user will cause this error.
		 */
		if (fileoff > MAXOFFSET_T) {
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
		 * Don't allow pwritev to cause file sizes to exceed maxoffset.
		 */
		if (fileoff == MAXOFFSET_T) {
			error = EFBIG;
			goto out;
		}
		/*
		 * Limit offset such that we don't read or write a file beyond
		 * the maximum offset representable in an off_t structure.
		 */
		if (fileoff + count > MAXOFFSET_T)
			count = (ssize_t)((u_offset_t)MAXOFFSET_T - fileoff);
	} else if (fp->f_vnode->v_type == VFIFO) {
		error = ESPIPE;
		goto out;
	}

	auio.uio_iov = aiov;
	auio.uio_iovcnt = iovcnt;
	auio.uio_loffset = offset;
	auio.uio_resid = count;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_llimit = curproc->p_fsz_ctl;
	auio.uio_fmode = fflag;
	auio.uio_extflg = UIO_COPY_DEFAULT;

	error = lx_write_common(fp, &auio, &nwrite, B_TRUE);

	if (error != 0) {
		if (nwrite != 0) {
			error = 0;
		} else if (error == EINTR) {
			ttolxlwp(curthread)->br_syscall_restart = B_TRUE;
		}
	}
out:
	releasef(fdes);
	if (aiovlen != 0)
		kmem_free(aiov, aiovlen);
	if (error != 0) {
		return (set_errno(error));
	}
	return (nwrite);
}

ssize_t
lx_preadv32(int fdes, void *iovp, int iovcnt, uint32_t off_lo, uint32_t off_hi)
{
	return (lx_preadv(fdes, iovp, iovcnt, LX_32TO64(off_lo, off_hi)));
}

ssize_t
lx_pwritev32(int fdes, void *iovp, int iovcnt, uint32_t off_lo,
    uint32_t off_hi)
{
	return (lx_pwritev(fdes, iovp, iovcnt, LX_32TO64(off_lo, off_hi)));
}
