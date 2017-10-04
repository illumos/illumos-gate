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
 * Copyright 2017, Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/thread.h>
#include <sys/proc.h>
#include <sys/zone.h>
#include <sys/brand.h>
#include <sys/sunddi.h>
#include <sys/fs/fifonode.h>
#include <sys/strsun.h>
#include <sys/lx_brand.h>
#include <sys/lx_types.h>
#include <sys/lx_misc.h>
#include <sys/lx_signal.h>

/* Splice flags */
#define	LX_SPLICE_F_MOVE	0x01
#define	LX_SPLICE_F_NONBLOCK	0x02
#define	LX_SPLICE_F_MORE	0x04
#define	LX_SPLICE_F_GIFT	0x08

/*
 * Use a max buffer size of 32k. This is a good compromise between doing I/O in
 * large chunks, the limit on how much data we can write into an lx pipe by
 * default (LX_DEFAULT_PIPE_SIZE), and how much kernel memory we'll allocate.
 */
#define	LX_SPL_BUF_SIZE		(32 * 1024)

/*
 * We only want to read as much from the input fd as we can write into the
 * output fd, up to our buffer size. Figure out what that quantity is.
 * Note that len will continuously decrease to 0 which triggers the typical
 * end of the splice loop.
 */
static size_t
lx_spl_wr_sz(file_t *fp_out, u_offset_t fileoff, size_t bsz, size_t len,
    boolean_t first)
{
	size_t sz;

	sz = MIN(bsz, len);
	if (fp_out->f_vnode->v_type == VFIFO) {
		/*
		 * If no readers on pipe, or if it would go over high water
		 * mark then return 0. Note that the first write into a
		 * pipe is expected to block if we're over the high water mark.
		 */
		fifonode_t *fn_dest = VTOF(fp_out->f_vnode)->fn_dest;
		fifolock_t *fn_lock = fn_dest->fn_lock;

		mutex_enter(&fn_lock->flk_lock);
		if (fn_dest->fn_rcnt == 0) {
			sz = 0;
		} else if (!first &&
		    (sz + fn_dest->fn_count) > fn_dest->fn_hiwat) {
			sz = 0;
		}
		mutex_exit(&fn_lock->flk_lock);
	} else if (fp_out->f_vnode->v_type == VREG) {
		if (fileoff >= curproc->p_fsz_ctl ||
		    fileoff >= OFFSET_MAX(fp_out)) {
			sz = 0;
		} else {
			sz = MIN(sz, (size_t)curproc->p_fsz_ctl - fileoff);
			sz = MIN(sz, (size_t)OFFSET_MAX(fp_out) - fileoff);
		}
	}

	/*
	 * if (fp_out->f_vnode->v_type == VSOCK)
	 *
	 * There is no good way to determine if a socket is "full". A write for
	 * the different protocol implementations can return EWOULDBLOCK under
	 * different conditions, none of which we can easily check for in
	 * advance.
	 */

	return (sz);
}

/*
 * The splice read function handles "reading" from a pipe and passes everything
 * else along to our normal VOP_READ code path.
 *
 * When we have a pipe as our input, we don't want to consume the data out
 * of the pipe until the write has succeeded. This aligns more closely with
 * the Linux behavior when a write error occurs. Thus, when a pipe is the input
 * and we got some data, we return with the fifo flagged as FIFORDBLOCK. This
 * ensures that the data we're writing cannot be consumed by another thread
 * until we consume it ourself.
 *
 * The pipe "read" code here is derived from the fifo I_PEEK code.
 */
static int
lx_spl_read(file_t *fp, uio_t *uiop, size_t *nread, boolean_t pipe_in,
    boolean_t rd_pos)
{
	fifonode_t *fnp;
	fifolock_t *fn_lock;
	int count;
	mblk_t *bp;

	if (!pipe_in)
		return (lx_read_common(fp, uiop, nread, rd_pos));

	ASSERT(fp->f_vnode->v_type == VFIFO);
	fnp = VTOF(fp->f_vnode);
	fn_lock = fnp->fn_lock;
	*nread = 0;

	mutex_enter(&fn_lock->flk_lock);

	/*
	 * If the pipe has been switched to socket mode then this implies an
	 * internal programmatic error. Likewise, if it was switched to
	 * socket mode because we dropped the lock to set the stayfast flag.
	 */
	if ((fnp->fn_flag & FIFOFAST) == 0 || !fifo_stayfast_enter(fnp)) {
		mutex_exit(&fn_lock->flk_lock);
		return (EBADF);
	}

	while (fnp->fn_count == 0 || (fnp->fn_flag & FIFORDBLOCK) != 0) {
		fifonode_t *fn_dest = fnp->fn_dest;

		/* No writer, EOF */
		if (fn_dest->fn_wcnt == 0 || fn_dest->fn_rcnt == 0) {
			fifo_stayfast_exit(fnp);
			mutex_exit(&fn_lock->flk_lock);
			return (0);
		}

		/* If non-blocking, return EAGAIN otherwise 0. */
		if (uiop->uio_fmode & (FNDELAY|FNONBLOCK)) {
			fifo_stayfast_exit(fnp);
			mutex_exit(&fn_lock->flk_lock);
			if (uiop->uio_fmode & FNONBLOCK)
				return (EAGAIN);
			return (0);
		}

		/* Wait for data */
		fnp->fn_flag |= FIFOWANTR;
		if (!cv_wait_sig_swap(&fnp->fn_wait_cv, &fn_lock->flk_lock)) {
			fifo_stayfast_exit(fnp);
			mutex_exit(&fn_lock->flk_lock);
			return (EINTR);
		}
	}

	VERIFY((fnp->fn_flag & FIFORDBLOCK) == 0);
	VERIFY((fnp->fn_flag & FIFOSTAYFAST) != 0);

	/* Get up to our read size or whatever is currently available. */
	count = MIN(uiop->uio_resid, fnp->fn_count);
	ASSERT(count > 0);
	*nread = count;
	bp = fnp->fn_mp;
	while (count > 0) {
		uint_t cnt = MIN(uiop->uio_resid, MBLKL(bp));

		/*
		 * We have the input pipe locked and we know there is data
		 * available to consume. We're doing a UIO_SYSSPACE move into
		 * an internal buffer that we allocated in lx_splice() so
		 * this should never fail.
		 */
		VERIFY(uiomove((char *)bp->b_rptr, cnt, UIO_READ, uiop) == 0);
		count -= cnt;
		bp = bp->b_cont;
	}

	fnp->fn_flag |= FIFORDBLOCK;

	mutex_exit(&fn_lock->flk_lock);
	return (0);
}

/*
 * We've already "read" the data out of the pipe without actually consuming it.
 * Here we update the pipe to consume the data and discard it. This is derived
 * from the fifo_read code, except that we already know the amount of data
 * in the pipe to consume and we don't have to actually move any data.
 */
static void
lx_spl_consume(file_t *fp, uint_t count)
{
	fifonode_t *fnp, *fn_dest;
	fifolock_t *fn_lock;

	ASSERT(fp->f_vnode->v_type == VFIFO);

	fnp = VTOF(fp->f_vnode);
	fn_lock = fnp->fn_lock;

	mutex_enter(&fn_lock->flk_lock);
	VERIFY(fnp->fn_count >= count);

	while (count > 0) {
		int bpsize = MBLKL(fnp->fn_mp);
		int decr_size = MIN(bpsize, count);

		fnp->fn_count -= decr_size;
		if (bpsize <= decr_size) {
			mblk_t *bp = fnp->fn_mp;
			fnp->fn_mp = fnp->fn_mp->b_cont;
			freeb(bp);
		} else {
			fnp->fn_mp->b_rptr += decr_size;
		}

		count -= decr_size;
	}

	fnp->fn_flag &= ~FIFORDBLOCK;
	fifo_stayfast_exit(fnp);

	fifo_wakereader(fnp, fn_lock);

	/*
	 * Wake up any blocked writers, processes sleeping on POLLWRNORM, or
	 * processes waiting for SIGPOLL.
	 */
	fn_dest = fnp->fn_dest;
	if (fn_dest->fn_flag & (FIFOWANTW | FIFOHIWATW) &&
	    fnp->fn_count < fn_dest->fn_hiwat) {
		fifo_wakewriter(fn_dest, fn_lock);
	}

	/* Update vnode update access time */
	fnp->fn_atime = fnp->fn_dest->fn_atime = gethrestime_sec();

	mutex_exit(&fn_lock->flk_lock);
}

/*
 * Transfer data from the input file descriptor to the output file descriptor
 * without leaving the kernel. For Linux this is limited by it's kernel
 * implementation which forces at least one of the file descriptors to be a
 * pipe. Our implementation is likely quite different from the Linux
 * one, which appears to play some VM tricks with shared pages from the pipe
 * code. Instead, our implementation uses our normal VOP_READ/VOP_WRITE
 * operations to internally move the data while using a single uio buffer. We
 * implement the additional Linux behavior around the various checks and
 * limitations.
 *
 * One key point on the read side is how we handle an input pipe. We don't
 * want to consume the data out of the pipe until the write has succeeded.
 * This aligns more closely with the Linux behavior when a write error occurs.
 * The lx_spl_read() and lx_spl_consume() functions are used to handle this
 * case.
 */
long
lx_splice(int fd_in, off_t *off_in, int fd_out, off_t *off_out, size_t len,
    uint_t flags)
{
	int error = 0;
	file_t *fp_in = NULL, *fp_out = NULL;
	boolean_t found_pipe = B_FALSE, rd_pos = B_FALSE, wr_pos = B_FALSE;
	boolean_t first = B_TRUE, pipe_in = B_FALSE;
	iovec_t iov;
	uio_t uio;
	void *buf = NULL;
	off_t r_off = 0, w_off = 0;
	ushort_t r_flag, w_flag;
	size_t bsize = 0, wr_sz, nread, nwrite, total = 0;

	/*
	 * Start by validating the inputs.
	 *
	 * Linux doesn't bother to check for valid flags, so neither do we.
	 * Also, aside from SPLICE_F_NONBLOCK, we ignore the rest of the
	 * flags since they're just hints to the Linux kernel implementation
	 * and have no effect on the proper functioning of the syscall.
	 */

	if (len == 0)
		return (0);

	if ((fp_in = getf(fd_in)) == NULL) {
		error = EBADF;
		goto done;
	}
	switch (fp_in->f_vnode->v_type) {
	case VFIFO:
		/* A fifo that is not in fast mode does not count as a pipe */
		if (((VTOF(fp_in->f_vnode))->fn_flag & FIFOFAST) != 0) {
			found_pipe = B_TRUE;
			pipe_in = B_TRUE;
		}
		/*FALLTHROUGH*/
	case VSOCK:
		if (off_in != NULL) {
			error = ESPIPE;
			goto done;
		}
		break;
	case VREG:
	case VBLK:
	case VCHR:
	case VPROC:
		if (off_in != NULL) {
			if (copyin(off_in, &r_off, sizeof (r_off)) != 0) {
				error = EFAULT;
				goto done;
			}
			rd_pos = B_TRUE;
		}
		break;
	default:
		error = EBADF;
		goto done;
	}
	r_flag = fp_in->f_flag;
	if ((r_flag & FREAD) == 0) {
		error = EBADF;
		goto done;
	}

	if ((fp_out = getf(fd_out)) == NULL) {
		error = EBADF;
		goto done;
	}
	switch (fp_out->f_vnode->v_type) {
	case VFIFO:
		found_pipe = B_TRUE;
		/* Splicing to ourself returns EINVAL on Linux */
		if (pipe_in) {
			fifonode_t *fnp = VTOF(fp_in->f_vnode);
			if (VTOF(fp_out->f_vnode) == fnp->fn_dest) {
				error = EINVAL;
				goto done;
			}
		}
		/*FALLTHROUGH*/
	case VSOCK:
		if (off_out != NULL) {
			error = ESPIPE;
			goto done;
		}
		break;
	case VREG:
	case VBLK:
	case VCHR:
	case VPROC:
		if (off_out != NULL) {
			if (copyin(off_out, &w_off, sizeof (w_off)) != 0) {
				error = EFAULT;
				goto done;
			}
			wr_pos = B_TRUE;
		}
		break;
	default:
		error = EBADF;
		goto done;
	}
	w_flag = fp_out->f_flag;
	if ((w_flag & FWRITE) == 0) {
		error = EBADF;
		goto done;
	}
	/* Appending is invalid for output fd in splice */
	if ((w_flag & FAPPEND) != 0) {
		error = EINVAL;
		goto done;
	}

	if (!found_pipe) {
		error = EINVAL;
		goto done;
	}

	/*
	 * Check for non-blocking pipe operations. If no data in the input
	 * pipe, return EAGAIN. If the output pipe is full, return EAGAIN.
	 */
	if (flags & LX_SPLICE_F_NONBLOCK) {
		fifonode_t *fn_dest;

		if (fp_in->f_vnode->v_type == VFIFO) {
			fn_dest = VTOF(fp_in->f_vnode)->fn_dest;
			if (fn_dest->fn_count == 0) {
				error = EAGAIN;
				goto done;
			}
		}
		if (fp_out->f_vnode->v_type == VFIFO) {
			fn_dest = VTOF(fp_out->f_vnode)->fn_dest;
			fifolock_t *fn_lock = fn_dest->fn_lock;
			mutex_enter(&fn_lock->flk_lock);
			if (fn_dest->fn_count >= fn_dest->fn_hiwat) {
				mutex_exit(&fn_lock->flk_lock);
				error = EAGAIN;
				goto done;
			}
			mutex_exit(&fn_lock->flk_lock);
		}
	}

	bsize = MIN(LX_SPL_BUF_SIZE, len);

	buf = kmem_alloc(bsize, KM_SLEEP);
	bzero(&uio, sizeof (uio));
	uio.uio_iovcnt = 1;
	uio.uio_iov = &iov;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_llimit = curproc->p_fsz_ctl;

	/*
	 * Loop reading data from fd_in and writing to fd_out. This is
	 * controlled by how much of the requested data we can actually write,
	 * particularly when the destination is a pipe. This matches the Linux
	 * behavior, which may terminate earlier than the full 'len' if the
	 * pipe fills up. However, we need to block when writing into a full
	 * pipe on the first iteration of the loop. We already checked above
	 * for a full output pipe when non-blocking.
	 */
	while ((wr_sz = lx_spl_wr_sz(fp_out, w_off, bsize, len, first)) > 0) {
		first = B_FALSE;

		/* (re)setup for a read */
		uio.uio_resid = iov.iov_len = wr_sz; /* only rd. max writable */
		iov.iov_base = buf;
		uio.uio_offset = r_off;
		uio.uio_extflg = UIO_COPY_CACHED;
		uio.uio_fmode = r_flag;
		error = lx_spl_read(fp_in, &uio, &nread, pipe_in, rd_pos);
		if (error != 0 || nread == 0)
			break;
		r_off = uio.uio_offset;

		/* Setup and perform a write from the same buffer */
		uio.uio_resid = iov.iov_len = nread;
		iov.iov_base = buf;
		uio.uio_offset = w_off;
		uio.uio_extflg = UIO_COPY_DEFAULT;
		uio.uio_fmode = w_flag;
		error = lx_write_common(fp_out, &uio, &nwrite, wr_pos);
		if (error != 0) {
			if (pipe_in) {
				/* Need to unblock reading from the fifo. */
				fifonode_t *fnp = VTOF(fp_in->f_vnode);

				mutex_enter(&fnp->fn_lock->flk_lock);
				fnp->fn_flag &= ~FIFORDBLOCK;
				fifo_stayfast_exit(fnp);
				fifo_wakereader(fnp, fnp->fn_lock);
				mutex_exit(&fnp->fn_lock->flk_lock);
			}
			break;
		}
		w_off  = uio.uio_offset;

		/*
		 * If input is a pipe, then we can consume the amount of data
		 * out of the pipe that we successfully wrote.
		 */
		if (pipe_in)
			lx_spl_consume(fp_in, nwrite);

		total += nwrite;
		len -= nwrite;
	}

done:
	if (buf != NULL)
		kmem_free(buf, bsize);
	if (fp_in != NULL)
		releasef(fd_in);
	if (fp_out != NULL)
		releasef(fd_out);
	if (error != 0)
		return (set_errno(error));

	return (total);
}
