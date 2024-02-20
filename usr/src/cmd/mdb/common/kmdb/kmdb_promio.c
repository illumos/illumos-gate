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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * PROM I/O backend
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/obpdefs.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_io_impl.h>
#include <kmdb/kmdb_promif.h>
#include <kmdb/kmdb_io.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb.h>

#define	PIO_FL_TIO_READ	0x001

typedef struct pio_data {
	char		pio_name[MAXPATHLEN];
	ihandle_t	pio_fd;
	uint_t		pio_flags;
	struct termios	pio_ti;
} pio_data_t;

static pid_t pio_pgrp;

static ssize_t
pio_read(mdb_io_t *io, void *buf, size_t nbytes)
{
	pio_data_t *pdp = io->io_data;

	if (io->io_next == NULL)
		return (kmdb_prom_read(buf, nbytes, &pdp->pio_ti));

	return (IOP_READ(io->io_next, buf, nbytes));
}

static ssize_t
pio_write(mdb_io_t *io, const void *buf, size_t nbytes)
{
	pio_data_t *pdp = io->io_data;

	if (io->io_next == NULL)
		return (kmdb_prom_write(buf, nbytes, &pdp->pio_ti));

	return (IOP_WRITE(io->io_next, buf, nbytes));
}

static off64_t
pio_seek(mdb_io_t *io, off64_t offset, int whence)
{
	if (io->io_next == NULL)
		return (set_errno(ENOTSUP));

	return (IOP_SEEK(io->io_next, offset, whence));
}

static int
pio_ctl(mdb_io_t *io, int req, void *arg)
{
	pio_data_t *pdp = io->io_data;

	if (io->io_next != NULL)
		return (IOP_CTL(io->io_next, req, arg));

	switch (req) {
	case TIOCGWINSZ:
		return (kmdb_prom_term_ctl(TIOCGWINSZ, arg));

	case TCGETS: {
		struct termios *ti = arg;

		if (!(pdp->pio_flags & PIO_FL_TIO_READ)) {
			(void) kmdb_prom_term_ctl(TCGETS, &pdp->pio_ti);
			pdp->pio_flags |= PIO_FL_TIO_READ;
		}

		bcopy(&pdp->pio_ti, ti, sizeof (struct termios));

		mdb_dprintf(MDB_DBG_CMDBUF, "pio_ctl: gets: i: 0%o o: 0%o c: "
		    "0%o l: 0%o\n", ti->c_iflag, ti->c_oflag, ti->c_cflag,
		    ti->c_lflag);
		return (0);
	}

	case TCSETSW: {
		struct termios *ti = arg;

		mdb_dprintf(MDB_DBG_CMDBUF, "pio_ctl: setsw: i: 0%o o: 0%o c: "
		    "0%o l: 0%o\n", ti->c_iflag, ti->c_oflag, ti->c_cflag,
		    ti->c_lflag);

		bcopy(ti, &pdp->pio_ti, sizeof (struct termios));

		return (0);
	}

	case TIOCSPGRP:
		pio_pgrp = *(pid_t *)arg;
		mdb_dprintf(MDB_DBG_CMDBUF, "pio_ctl: spgrp: %ld\n",
		    (long)pio_pgrp);
		return (0);

	case TIOCGPGRP:
		mdb_dprintf(MDB_DBG_CMDBUF, "pio_ctl: gpgrp: %ld\n",
		    (long)pio_pgrp);
		*(pid_t *)arg = pio_pgrp;
		return (0);

	case MDB_IOC_CTTY:
		mdb_dprintf(MDB_DBG_CMDBUF, "pio_ctl: ignoring MDB_IOC_CTTY\n");
		return (0);

	case MDB_IOC_GETFD:
		return (set_errno(ENOTSUP));

	default:
		warn("Unknown ioctl %d\n", req);
		return (set_errno(EINVAL));
	}
}

void
pio_close(mdb_io_t *io)
{
	pio_data_t *pdp = io->io_data;

	mdb_free(pdp, sizeof (pio_data_t));
}

static const char *
pio_name(mdb_io_t *io)
{
	pio_data_t *pdp = io->io_data;

	if (io->io_next == NULL)
		return (pdp->pio_name);

	return (IOP_NAME(io->io_next));
}

static const mdb_io_ops_t promio_ops = {
	.io_read = pio_read,
	.io_write = pio_write,
	.io_seek = pio_seek,
	.io_ctl = pio_ctl,
	.io_close = pio_close,
	.io_name = pio_name,
	.io_link = no_io_link,
	.io_unlink = no_io_unlink,
	.io_setattr = no_io_setattr,
	.io_suspend = no_io_suspend,
	.io_resume = no_io_resume,
};

mdb_io_t *
kmdb_promio_create(char *name)
{
	mdb_io_t *io;
	pio_data_t *pdp;
	ihandle_t hdl = kmdb_prom_get_handle(name);

	if (hdl == -1)
		return (NULL);

	io = mdb_zalloc(sizeof (mdb_io_t), UM_SLEEP);
	pdp = mdb_zalloc(sizeof (pio_data_t), UM_SLEEP);

	(void) strlcpy(pdp->pio_name, name, MAXPATHLEN);
	pdp->pio_fd = hdl;

#ifdef __sparc
	pdp->pio_ti.c_oflag |= ONLCR;
	pdp->pio_ti.c_iflag |= ICRNL;
#endif
	pdp->pio_ti.c_lflag |= ECHO;

	io->io_data = pdp;
	io->io_ops = &promio_ops;

	return (io);
}

char
kmdb_getchar(void)
{
	char c;

	while (IOP_READ(mdb.m_term, &c, 1) != 1)
		continue;
	if (isprint(c) && c != '\n')
		mdb_iob_printf(mdb.m_out, "%c", c);
	mdb_iob_printf(mdb.m_out, "\n");

	return (c);
}
