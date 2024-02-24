/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 1997-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 * Log I/O Backend
 *
 * This backend provides the ability to form a T in an iob's output routine.
 * We use this capability to provide interactive session logging.  We create
 * a log i/o and give it a pointer to another i/o backend representing the
 * log file, and then stack this on top of the existing stdio i/o backend.
 * As each write occurs, the log i/o writes to the log file, and also passes
 * the write request along to io->io_next.
 */

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_io_impl.h>
#include <mdb/mdb.h>

static ssize_t
logio_read(mdb_io_t *io, void *buf, size_t nbytes)
{
	mdb_io_t *logio = io->io_data;
	ssize_t rbytes;

	if (io->io_next != NULL) {
		rbytes = IOP_READ(io->io_next, buf, nbytes);

		if (rbytes > 0) {
			(void) IOP_WRITE(logio, mdb.m_prompt, mdb.m_promptlen);
			(void) IOP_WRITE(logio, buf, rbytes);
		}

		return (rbytes);
	}

	return (-1);
}

static ssize_t
logio_write(mdb_io_t *io, const void *buf, size_t nbytes)
{
	mdb_io_t *logio = io->io_data;
	ssize_t wbytes;

	if (io->io_next != NULL) {
		wbytes = IOP_WRITE(io->io_next, buf, nbytes);

		if (wbytes > 0)
			(void) IOP_WRITE(logio, buf, wbytes);

		return (wbytes);
	}

	return (-1);
}

static void
logio_close(mdb_io_t *io)
{
	mdb_io_rele(io->io_data);
}

static const char *
logio_name(mdb_io_t *io)
{
	if (io->io_next != NULL)
		return (IOP_NAME(io->io_next));

	return ("(log)");
}

static const mdb_io_ops_t logio_ops = {
	.io_read = logio_read,
	.io_write = logio_write,
	.io_seek = no_io_seek,
	.io_ctl = no_io_ctl,
	.io_close = logio_close,
	.io_name = logio_name,
	.io_link = no_io_link,
	.io_unlink = no_io_unlink,
	.io_setattr = no_io_setattr,
	.io_suspend = no_io_suspend,
	.io_resume = no_io_resume
};

mdb_io_t *
mdb_logio_create(mdb_io_t *logio)
{
	mdb_io_t *io = mdb_alloc(sizeof (mdb_io_t), UM_SLEEP);

	io->io_ops = &logio_ops;
	io->io_data = mdb_io_hold(logio);
	io->io_next = NULL;
	io->io_refcnt = 0;

	return (io);
}
