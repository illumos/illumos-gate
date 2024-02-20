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
 */

/*
 * File Descriptor I/O Backend
 *
 * Simple backend to pass though io_ops to the corresponding system calls on
 * an underlying fd.  We provide functions to create fdio objects using file
 * descriptors, explicit file names, and path lookups.  We save the complete
 * filename so that mdb_iob_name can be used to report the complete filename
 * of an open macro file in syntax error messages.
 */

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/dkio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_io_impl.h>
#include <mdb/mdb.h>

typedef struct fd_data {
	char fd_name[MAXPATHLEN];	/* Save filename for error messages */
	int fd_fd;			/* File descriptor */
} fd_data_t;

static ssize_t
fdio_read(mdb_io_t *io, void *buf, size_t nbytes)
{
	fd_data_t *fdp = io->io_data;

	if (io->io_next == NULL)
		return (read(fdp->fd_fd, buf, nbytes));

	return (IOP_READ(io->io_next, buf, nbytes));
}

static ssize_t
fdio_write(mdb_io_t *io, const void *buf, size_t nbytes)
{
	fd_data_t *fdp = io->io_data;

	if (io->io_next == NULL)
		return (write(fdp->fd_fd, buf, nbytes));

	return (IOP_WRITE(io->io_next, buf, nbytes));
}

static off64_t
fdio_seek(mdb_io_t *io, off64_t offset, int whence)
{
	fd_data_t *fdp = io->io_data;

	if (io->io_next == NULL)
		return (lseek64(fdp->fd_fd, offset, whence));

	return (IOP_SEEK(io->io_next, offset, whence));
}

static int
fdio_ctl(mdb_io_t *io, int req, void *arg)
{
	fd_data_t *fdp = io->io_data;

	if (io->io_next != NULL)
		return (IOP_CTL(io->io_next, req, arg));

	if (req == MDB_IOC_GETFD)
		return (fdp->fd_fd);
	else
		return (ioctl(fdp->fd_fd, req, arg));
}

static void
fdio_close(mdb_io_t *io)
{
	fd_data_t *fdp = io->io_data;

	(void) close(fdp->fd_fd);
	mdb_free(fdp, sizeof (fd_data_t));
}

static const char *
fdio_name(mdb_io_t *io)
{
	fd_data_t *fdp = io->io_data;

	if (io->io_next == NULL)
		return (fdp->fd_name);

	return (IOP_NAME(io->io_next));
}

mdb_io_t *
mdb_fdio_create_path(const char *path[], const char *fname,
    int flags, mode_t mode)
{
	int fd;
	char buf[MAXPATHLEN];

	if (path != NULL && strchr(fname, '/') == NULL) {
		int i;

		for (fd = -1, i = 0; path[i] != NULL; i++) {
			(void) mdb_iob_snprintf(buf, MAXPATHLEN, "%s/%s",
			    path[i], fname);

			if (access(buf, F_OK) == 0) {
				fd = open64(buf, flags, mode);
				fname = buf;
				break;
			}
		}

		if (fd == -1)
			(void) set_errno(ENOENT);
	} else
		fd = open64(fname, flags, mode);

	if (fd >= 0)
		return (mdb_fdio_create_named(fd, fname));

	return (NULL);
}

static const mdb_io_ops_t fdio_file_ops = {
	.io_read = fdio_read,
	.io_write = fdio_write,
	.io_seek = fdio_seek,
	.io_ctl = fdio_ctl,
	.io_close = fdio_close,
	.io_name = fdio_name,
	.io_link = no_io_link,
	.io_unlink = no_io_unlink,
	.io_setattr = no_io_setattr,
	.io_suspend = no_io_suspend,
	.io_resume = no_io_resume
};

/*
 * Read media logical block size. On error, return DEV_BSIZE.
 */
static uint_t
fdio_bdev_info(int fd)
{
	struct dk_minfo disk_info;

	if ((ioctl(fd, DKIOCGMEDIAINFO, (caddr_t)&disk_info)) == -1)
		return (DEV_BSIZE);

	return (disk_info.dki_lbsize);
}

/*
 * In order to read from a block-oriented device, we pick up the seek pointer,
 * read each containing block, and then copy the desired range of bytes back
 * into the caller's buffer. At the end of the transfer we reset the seek
 * pointer to where the caller thinks it should be.
 */
static ssize_t
fdio_bdev_read(mdb_io_t *io, void *buf, size_t nbytes)
{
	fd_data_t *fdp = io->io_data;
	ssize_t resid = nbytes;
	size_t blksize;
	uchar_t *blk;
	off64_t off;

	if (io->io_next != NULL)
		return (IOP_READ(io->io_next, buf, nbytes));

	if ((off = lseek64(fdp->fd_fd, 0, SEEK_CUR)) == -1)
		return (-1); /* errno is set for us */

	blksize = fdio_bdev_info(fdp->fd_fd);
	blk = mdb_zalloc(blksize, UM_SLEEP | UM_GC);
	while (resid != 0) {
		off64_t devoff = off & ~(blksize - 1);
		size_t blkoff = off & (blksize - 1);
		size_t len = MIN(resid, blksize - blkoff);

		if (pread64(fdp->fd_fd, blk, blksize, devoff) != blksize)
			break; /* errno is set for us, unless EOF */

		bcopy(&blk[blkoff], buf, len);
		resid -= len;
		off += len;
		buf = (char *)buf + len;
	}

	if (resid == nbytes && nbytes != 0)
		return (set_errno(EMDB_EOF));

	(void) lseek64(fdp->fd_fd, off, SEEK_SET);
	return (nbytes - resid);
}

/*
 * To perform a write to a block-oriented device, we use the same basic
 * algorithm as fdio_bdev_read(), above.  In the inner loop, we read an
 * entire block, modify it using the data from the caller's buffer, and
 * then write the entire block back to the device.
 */
static ssize_t
fdio_bdev_write(mdb_io_t *io, const void *buf, size_t nbytes)
{
	fd_data_t *fdp = io->io_data;
	ssize_t resid = nbytes;
	size_t blksize;
	uchar_t *blk;
	off64_t off;

	if (io->io_next != NULL)
		return (IOP_WRITE(io->io_next, buf, nbytes));

	if ((off = lseek64(fdp->fd_fd, 0, SEEK_CUR)) == -1)
		return (-1); /* errno is set for us */

	blksize = fdio_bdev_info(fdp->fd_fd);
	blk = mdb_zalloc(blksize, UM_SLEEP | UM_GC);
	while (resid != 0) {
		off64_t devoff = off & ~(blksize - 1);
		size_t blkoff = off & (blksize - 1);
		size_t len = MIN(resid, blksize - blkoff);

		if (pread64(fdp->fd_fd, blk, blksize, devoff) != blksize)
			break; /* errno is set for us, unless EOF */

		bcopy(buf, &blk[blkoff], len);

		if (pwrite64(fdp->fd_fd, blk, blksize, devoff) != blksize)
			break; /* errno is set for us, unless EOF */

		resid -= len;
		off += len;
		buf = (char *)buf + len;
	}

	if (resid == nbytes && nbytes != 0)
		return (set_errno(EMDB_EOF));

	(void) lseek64(fdp->fd_fd, off, SEEK_SET);
	return (nbytes - resid);
}

static const mdb_io_ops_t fdio_bdev_ops = {
	.io_read = fdio_bdev_read,
	.io_write = fdio_bdev_write,
	.io_seek = fdio_seek,
	.io_ctl = fdio_ctl,
	.io_close = fdio_close,
	.io_name = fdio_name,
	.io_link = no_io_link,
	.io_unlink = no_io_unlink,
	.io_setattr = no_io_setattr,
	.io_suspend = no_io_suspend,
	.io_resume = no_io_resume,
};

mdb_io_t *
mdb_fdio_create(int fd)
{
	mdb_io_t *io = mdb_alloc(sizeof (mdb_io_t), UM_SLEEP);
	fd_data_t *fdp = mdb_alloc(sizeof (fd_data_t), UM_SLEEP);

	struct dk_cinfo info;
	struct stat64 st;

	switch (fd) {
	case STDIN_FILENO:
		(void) strcpy(fdp->fd_name, "(stdin)");
		break;
	case STDOUT_FILENO:
		(void) strcpy(fdp->fd_name, "(stdout)");
		break;
	case STDERR_FILENO:
		(void) strcpy(fdp->fd_name, "(stderr)");
		break;
	default:
		(void) mdb_iob_snprintf(fdp->fd_name, MAXPATHLEN, "fd %d", fd);
	}

	fdp->fd_fd = fd;

	/*
	 * We determine if something is a raw block-oriented disk device by
	 * testing to see if it is a character device that supports DKIOCINFO.
	 * If we are operating on a disk in raw mode, we must do our own
	 * block-oriented i/o; otherwise we can just use read() and write().
	 */
	if (fstat64(fd, &st) == 0 && S_ISCHR(st.st_mode) &&
	    ioctl(fd, DKIOCINFO, &info) == 0)
		io->io_ops = &fdio_bdev_ops;
	else
		io->io_ops = &fdio_file_ops;

	io->io_data = fdp;
	io->io_next = NULL;
	io->io_refcnt = 0;

	return (io);
}

mdb_io_t *
mdb_fdio_create_named(int fd, const char *name)
{
	mdb_io_t *io = mdb_fdio_create(fd);
	fd_data_t *fdp = io->io_data;

	(void) strncpy(fdp->fd_name, name, MAXPATHLEN);
	fdp->fd_name[MAXPATHLEN - 1] = '\0';

	return (io);
}

int
mdb_fdio_fileno(mdb_io_t *io)
{
	fd_data_t *fdp = io->io_data;
	return (fdp->fd_fd);
}
