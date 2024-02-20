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
 * String I/O Backend
 *
 * Simple backend to provide the ability to perform i/o reads from an in-memory
 * string.  This allows us to mdb_eval() a string -- by creating an i/o object
 * out of it, we can then pass it to the parser as stdin.
 */

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_io_impl.h>
#include <mdb/mdb_string.h>
#include <mdb/mdb_err.h>

typedef struct str_data {
	char *str_base;		/* Pointer to private copy of string */
	char *str_ptr;		/* Current seek pointer */
	size_t str_len;		/* Length of string */
} str_data_t;

static ssize_t
strio_read(mdb_io_t *io, void *buf, size_t nbytes)
{
	str_data_t *sd = io->io_data;
	size_t left = sd->str_base + sd->str_len - sd->str_ptr;

	if (left != 0) {
		size_t obytes = nbytes < left ? nbytes : left;
		(void) strncpy(buf, sd->str_ptr, obytes);
		sd->str_ptr += obytes;
		return (obytes);
	}

	return (0); /* At end of string: return EOF */
}

static off64_t
strio_seek(mdb_io_t *io, off64_t offset, int whence)
{
	str_data_t *sd = io->io_data;
	char *nptr;

	if (io->io_next != NULL)
		return (IOP_SEEK(io->io_next, offset, whence));

	switch (whence) {
	case SEEK_SET:
		nptr = sd->str_base + offset;
		break;
	case SEEK_CUR:
		nptr = sd->str_ptr + offset;
		break;
	case SEEK_END:
		nptr = sd->str_base + sd->str_len + offset;
		break;
	default:
		return (set_errno(EINVAL));
	}

	if (nptr < sd->str_base || nptr > sd->str_ptr + sd->str_len)
		return (set_errno(EINVAL));

	sd->str_ptr = nptr;
	return ((off64_t)(nptr - sd->str_base));
}

static void
strio_close(mdb_io_t *io)
{
	str_data_t *sd = io->io_data;

	strfree(sd->str_base);
	mdb_free(sd, sizeof (str_data_t));
}

static const char *
strio_name(mdb_io_t *io)
{
	if (io->io_next != NULL)
		return (IOP_NAME(io->io_next));

	return ("(string)");
}

static const mdb_io_ops_t strio_ops = {
	.io_read = strio_read,
	.io_write = no_io_write,
	.io_seek = strio_seek,
	.io_ctl = no_io_ctl,
	.io_close = strio_close,
	.io_name = strio_name,
	.io_link = no_io_link,
	.io_unlink = no_io_unlink,
	.io_setattr = no_io_setattr,
	.io_suspend = no_io_suspend,
	.io_resume = no_io_resume,
};

mdb_io_t *
mdb_strio_create(const char *s)
{
	mdb_io_t *io = mdb_alloc(sizeof (mdb_io_t), UM_SLEEP);
	str_data_t *sd = mdb_alloc(sizeof (str_data_t), UM_SLEEP);

	/*
	 * Our parser expects each command to end with '\n' or ';'.  To
	 * simplify things for the caller, we append a trailing newline
	 * so the argvec string can be passed directly sans modifications.
	 */
	sd->str_len = strlen(s) + 1;
	sd->str_base = strndup(s, sd->str_len);
	(void) strcat(sd->str_base, "\n");
	sd->str_ptr = sd->str_base;

	io->io_ops = &strio_ops;
	io->io_data = sd;
	io->io_next = NULL;
	io->io_refcnt = 0;

	return (io);
}

int
mdb_iob_isastr(mdb_iob_t *iob)
{
	mdb_io_t *io;

	for (io = iob->iob_iop; io != NULL; io = io->io_next) {
		if (io->io_ops == &strio_ops)
			return (1);
	}

	return (0);
}
