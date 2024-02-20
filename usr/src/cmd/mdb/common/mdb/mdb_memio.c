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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Memory I/O backend.
 *
 * Simple backend that has main memory as its backing store.
 */

#include <mdb/mdb_io_impl.h>
#include <mdb/mdb.h>

typedef struct mem_data {
	char *md_buf;
	size_t md_size;
	offset_t md_off;
} mem_data_t;

static ssize_t
memio_read(mdb_io_t *io, void *buf, size_t nbytes)
{
	mem_data_t *mdp = io->io_data;

	if (io->io_next == NULL) {
		if (mdp->md_off + nbytes > mdp->md_size)
			nbytes = (mdp->md_size - mdp->md_off);
		bcopy(mdp->md_buf + mdp->md_off, buf, nbytes);
		mdp->md_off += nbytes;
		return (nbytes);
	}

	return (IOP_READ(io->io_next, buf, nbytes));
}

static off64_t
memio_seek(mdb_io_t *io, off64_t offset, int whence)
{
	mem_data_t *mdp = io->io_data;

	if (io->io_next == NULL) {
		switch (whence) {
		case SEEK_SET:
			mdp->md_off = offset;
			break;
		case SEEK_CUR:
			mdp->md_off += offset;
			break;
		case SEEK_END:
			mdp->md_off = mdp->md_size + offset;
			if (mdp->md_off > mdp->md_size)
				mdp->md_off = mdp->md_size;
			break;
		default:
			return (-1);
		}

		return (mdp->md_off);
	}

	return (IOP_SEEK(io->io_next, offset, whence));
}

static const mdb_io_ops_t memio_ops = {
	.io_read = memio_read,
	.io_write = no_io_write,
	.io_seek = memio_seek,
	.io_ctl = no_io_ctl,
	.io_close = no_io_close,
	.io_name = no_io_name,
	.io_link = no_io_link,
	.io_unlink = no_io_unlink,
	.io_setattr = no_io_setattr,
	.io_suspend = no_io_suspend,
	.io_resume = no_io_resume,
};

mdb_io_t *
mdb_memio_create(char *buf, size_t size)
{
	mdb_io_t *io = mdb_alloc(sizeof (mdb_io_t), UM_SLEEP);
	mem_data_t *mdp = mdb_alloc(sizeof (mem_data_t), UM_SLEEP);

	mdp->md_buf = buf;
	mdp->md_size = size;
	mdp->md_off = 0;

	io->io_ops = &memio_ops;
	io->io_data = mdp;
	io->io_next = NULL;
	io->io_refcnt = 0;

	return (io);
}
