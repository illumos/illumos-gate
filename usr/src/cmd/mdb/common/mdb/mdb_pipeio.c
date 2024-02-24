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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Pipe I/O Backend
 *
 * In order to implement dcmd pipelines, we provide a pipe i/o backend that
 * can be used to connect two mdb_iob structures (a read and write end).
 * This backend is selected when mdb_iob_pipe is used to construct a pair of
 * iobs.  Each iob points at the same i/o backend (the pipe i/o), and the
 * backend manages a circular fixed-size buffer which moves data between
 * the reader and writer.  The caller provides read and write-side service
 * routines that are expected to perform context switching (see mdb_context.c).
 * The pipe implementation is relatively simple: the writer calls any of the
 * mdb_iob_* routines to fill the write-side iob, and when this iob needs to
 * flush data to the underlying i/o, pio_write() below is called.  This
 * routine copies data into the pipe buffer until no more free space is
 * available, and then calls the read-side service routine (presuming that
 * when it returns, more free space will be available).  On the read-side,
 * pio_read() copies data up from the pipe buffer into the read-side iob.
 * If pio_read() is called and the pipe buffer is empty, pio_read() calls
 * the write-side service routine to force the writer to produce more data.
 */

#include <sys/sysmacros.h>
#include <stropts.h>
#include <limits.h>

#include <mdb/mdb.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb_string.h>
#include <mdb/mdb_context.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_io_impl.h>
#include <mdb/mdb_frame.h>

typedef struct pipe_data {
	mdb_iobsvc_f *pipe_rdsvc;	/* Read-side service routine */
	mdb_iob_t *pipe_rdiob;		/* Read-side i/o buffer */
	mdb_iobsvc_f *pipe_wrsvc;	/* Write-side service routine */
	mdb_iob_t *pipe_wriob;		/* Write-side i/o buffer */
	char pipe_buf[BUFSIZ];		/* Ring buffer for pipe contents */
	mdb_iob_ctx_t pipe_ctx;		/* Context data for service routines */
	uint_t pipe_rdndx;		/* Next byte index for reading */
	uint_t pipe_wrndx;		/* Next byte index for writing */
	uint_t pipe_free;		/* Free space for writing in bytes */
	uint_t pipe_used;		/* Used space for reading in bytes */
} pipe_data_t;


static ssize_t
pio_read(mdb_io_t *io, void *buf, size_t nbytes)
{
	pipe_data_t *pd = io->io_data;
	size_t n, nleft;

	if (nbytes == 0)
		return (0); /* return 0 for zero-length read */

	for (nleft = nbytes; nleft == nbytes; nleft -= n) {
		if (pd->pipe_used == 0) {
			if (pd->pipe_wriob != NULL) {
				pd->pipe_wrsvc(pd->pipe_rdiob,
				    pd->pipe_wriob, &pd->pipe_ctx);
			}
			if (pd->pipe_used == 0)
				break;
		}

		n = MIN(pd->pipe_used, nleft);

		if (BUFSIZ - pd->pipe_rdndx < n) {
			/*
			 * Case 1: The amount to read overlaps the end of the
			 * circular buffer.  'n1' will be the amount to copy
			 * from the end of the buffer, and 'n2' will be the
			 * amount to copy from the beginning.  Note that since
			 * n <= pipe_used, it is impossible to read past
			 * pipe_wrndx into undefined territory.
			 */
			size_t n1 = BUFSIZ - pd->pipe_rdndx;
			size_t n2 = n - n1;

			ASSERT(n2 <= pd->pipe_wrndx);
			bcopy(&pd->pipe_buf[pd->pipe_rdndx], buf, n1);
			buf = (char *)buf + n1;
			bcopy(&pd->pipe_buf[0], buf, n2);
			buf = (char *)buf + n2;
		} else {
			/*
			 * Case 2: The easy case.  Simply copy the data over
			 * to the buffer.
			 */
			bcopy(&pd->pipe_buf[pd->pipe_rdndx], buf, n);
			buf = (char *)buf + n;
		}

		pd->pipe_rdndx = (pd->pipe_rdndx + n) % BUFSIZ;
		pd->pipe_free += n;
		pd->pipe_used -= n;
	}

	/*
	 * If we have a writer, but pipe_wrsvc failed to produce any data,
	 * we return EAGAIN.  If there is no writer, then return 0 for EOF.
	 */
	if (nleft == nbytes) {
		if (pd->pipe_wriob != NULL)
			return (set_errno(EAGAIN));
		else
			return (0);
	}

	return (nbytes - nleft);
}

static ssize_t
pio_write(mdb_io_t *io, const void *buf, size_t nbytes)
{
	pipe_data_t *pd = io->io_data;
	size_t n, nleft;

	if (pd->pipe_rdiob == NULL)
		return (set_errno(EPIPE)); /* fail with EPIPE if no reader */

	for (nleft = nbytes; nleft != 0; nleft -= n) {
		if (pd->pipe_free == 0) {
			pd->pipe_rdsvc(pd->pipe_rdiob,
			    pd->pipe_wriob, &pd->pipe_ctx);
			if (pd->pipe_free == 0)
				break; /* if nothing consumed by reader, exit */
		}

		n = MIN(pd->pipe_free, nleft);

		if (BUFSIZ - pd->pipe_wrndx < n) {
			/*
			 * Case 1: The data will overlap the circular buffer
			 * boundary. In this case, 'n1' will be the number of
			 * bytes to put at the end of the buffer, and 'n2' will
			 * be the number of bytes to put at the beginning.
			 * Note that since n <= pipe_free, it is impossible to
			 * overlap rdndx with the initial data.
			 */
			size_t n1 = BUFSIZ - pd->pipe_wrndx;
			size_t n2 = n - n1;

			ASSERT(n2 <= pd->pipe_rdndx);

			bcopy(buf, &pd->pipe_buf[pd->pipe_wrndx], n1);
			buf = (const char *)buf + n1;
			bcopy(buf, &pd->pipe_buf[0], n2);
			buf = (const char *)buf + n2;
		} else {
			/*
			 * Case 2: The easy case.  Simply copy the data into
			 * the buffer.
			 */
			bcopy(buf, &pd->pipe_buf[pd->pipe_wrndx], n);
			buf = (const char *)buf + n;
		}

		pd->pipe_wrndx = (pd->pipe_wrndx + n) % BUFSIZ;
		pd->pipe_free -= n;
		pd->pipe_used += n;
	}

	if (nleft == nbytes && nbytes != 0)
		return (set_errno(EAGAIN));

	return (nbytes - nleft);
}

/*
 * Provide support for STREAMS-style write-side flush ioctl.  This can be
 * used by the caller to force a context switch to the read-side.
 */
static int
pio_ctl(mdb_io_t *io, int req, void *arg)
{
	pipe_data_t *pd = io->io_data;

	if (io->io_next != NULL)
		return (IOP_CTL(io->io_next, req, arg));

	if (req != I_FLUSH || (intptr_t)arg != FLUSHW)
		return (set_errno(ENOTSUP));

	if (pd->pipe_used != 0)
		pd->pipe_rdsvc(pd->pipe_rdiob, pd->pipe_wriob, &pd->pipe_ctx);

	return (0);
}

static void
pio_close(mdb_io_t *io)
{
	mdb_free(io->io_data, sizeof (pipe_data_t));
}

/*ARGSUSED*/
static const char *
pio_name(mdb_io_t *io)
{
	return ("(pipeline)");
}

static void
pio_link(mdb_io_t *io, mdb_iob_t *iob)
{
	pipe_data_t *pd = io->io_data;

	/*
	 * Here we take advantage of the IOP_LINK calls made to associate each
	 * i/o backend with its iob to determine our read and write iobs.
	 */
	if (io->io_next == NULL) {
		if (iob->iob_flags & MDB_IOB_RDONLY)
			pd->pipe_rdiob = iob;
		else
			pd->pipe_wriob = iob;
	} else
		IOP_LINK(io->io_next, iob);
}

static void
pio_unlink(mdb_io_t *io, mdb_iob_t *iob)
{
	pipe_data_t *volatile pd = io->io_data;

	/*
	 * The IOP_UNLINK call will be made when one of our associated iobs is
	 * destroyed.  If the read-side iob is being destroyed, we simply set
	 * pipe_rdiob to NULL, forcing subsequent pio_write() calls to fail
	 * with EPIPE.  Things are more complicated when the write-side is
	 * being destroyed.  If this is the last close prior to destroying the
	 * pipe, we need to arrange for any in-transit data to be consumed by
	 * the reader.  We first set pipe_wriob to NULL, which forces pio_read
	 * to return EOF when all in-transit data is consumed.  We then call
	 * the read-service routine while there is still a reader and pipe_used
	 * is non-zero, indicating there is still data in the pipe.
	 */
	if (io->io_next == NULL) {
		if (pd->pipe_wriob == iob) {
			pd->pipe_wriob = NULL;	/* remove writer */

			if (pd->pipe_used == 0 && pd->pipe_ctx.ctx_data == NULL)
				return;	/* no reader and nothing to read */

			/*
			 * Note that we need to use a do-while construct here
			 * so that we resume the reader's context at *least*
			 * once.  This forces it to read EOF and exit even if
			 * the pipeline is already completely flushed.
			 */
			do {
				if (pd->pipe_rdiob == NULL)
					break;
				if (mdb_iob_err(pd->pipe_rdiob) != 0) {
					if (pd->pipe_ctx.ctx_wptr != NULL) {
						mdb_frame_pop(
						    pd->pipe_ctx.ctx_wptr,
						    MDB_ERR_ABORT);
						pd->pipe_ctx.ctx_wptr = NULL;
					}
					break; /* don't read if error bit set */
				}
				if (pd->pipe_ctx.ctx_data == NULL ||
				    setjmp(*mdb_context_getpcb(
				    pd->pipe_ctx.ctx_data)) == 0) {
					pd->pipe_rdsvc(pd->pipe_rdiob,
					    pd->pipe_wriob, &pd->pipe_ctx);
				}

			} while (pd->pipe_used != 0);

			if (pd->pipe_ctx.ctx_data != NULL) {
				mdb_context_destroy(pd->pipe_ctx.ctx_data);
				pd->pipe_ctx.ctx_data = NULL;
			}

		} else if (pd->pipe_rdiob == iob)
			pd->pipe_rdiob = NULL; /* remove reader */
	} else
		IOP_UNLINK(io->io_next, iob);
}

static const mdb_io_ops_t pipeio_ops = {
	.io_read = pio_read,
	.io_write = pio_write,
	.io_seek = no_io_seek,
	.io_ctl = pio_ctl,
	.io_close = pio_close,
	.io_name = pio_name,
	.io_link = pio_link,
	.io_unlink = pio_unlink,
	.io_setattr = no_io_setattr,
	.io_suspend = no_io_suspend,
	.io_resume = no_io_resume,
};

mdb_io_t *
mdb_pipeio_create(mdb_iobsvc_f *rdsvc, mdb_iobsvc_f *wrsvc)
{
	mdb_io_t *io = mdb_alloc(sizeof (mdb_io_t), UM_SLEEP);
	pipe_data_t *pd = mdb_zalloc(sizeof (pipe_data_t), UM_SLEEP);

	ASSERT(rdsvc != NULL && wrsvc != NULL);
	pd->pipe_rdsvc = rdsvc;
	pd->pipe_wrsvc = wrsvc;
	pd->pipe_free = BUFSIZ;

	io->io_ops = &pipeio_ops;
	io->io_data = pd;
	io->io_next = NULL;
	io->io_refcnt = 0;

	return (io);
}

int
mdb_iob_isapipe(mdb_iob_t *iob)
{
	mdb_io_t *io;

	for (io = iob->iob_iop; io != NULL; io = io->io_next) {
		if (io->io_ops == &pipeio_ops)
			return (1);
	}

	return (0);
}
