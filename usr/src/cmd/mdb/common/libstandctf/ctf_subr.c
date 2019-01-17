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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <mdb/mdb_debug.h>
#include <mdb/mdb.h>

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/zmod.h>

#include <ctf_impl.h>
#include <stdlib.h>

/*ARGSUSED*/
void *
ctf_zopen(int *errp)
{
	/* The kernel will have decompressed the buffer for us */
	return (ctf_set_open_errno(errp, ECTF_ZMISSING));
}

/*ARGSUSED*/
const void *
ctf_sect_mmap(ctf_sect_t *sp, int fd)
{
	return (MAP_FAILED); /* we don't support this in kmdb  */
}

/*ARGSUSED*/
void
ctf_sect_munmap(const ctf_sect_t *sp)
{
	/* we don't support this in kmdb */
}

/*ARGSUSED*/
ctf_file_t *
ctf_fdopen(int fd, int *errp)
{
	return (ctf_set_open_errno(errp, ENOTSUP));
}

/*ARGSUSED*/
ctf_file_t *
ctf_fdcreate_int(int fd, int *errp, ctf_sect_t *ctfp)
{
	return (ctf_set_open_errno(errp, ENOTSUP));
}

/*ARGSUSED*/
ctf_file_t *
ctf_open(const char *filename, int *errp)
{
	return (ctf_set_open_errno(errp, ENOTSUP));
}

int
ctf_version(int version)
{
	ASSERT(version > 0 && version <= CTF_VERSION);

	if (version > 0)
		_libctf_version = MIN(CTF_VERSION, version);

	return (_libctf_version);
}

void *
ctf_data_alloc(size_t size)
{
	void *buf = mdb_alloc(size, UM_NOSLEEP);

	if (buf == NULL)
		return (MAP_FAILED);

	return (buf);
}

void
ctf_data_free(void *buf, size_t size)
{
	mdb_free(buf, size);
}

/*ARGSUSED*/
void
ctf_data_protect(void *buf, size_t size)
{
	/* Not supported in kmdb */
}

void *
ctf_alloc(size_t size)
{
	return (mdb_alloc(size, UM_NOSLEEP));
}

void
ctf_free(void *buf, size_t size)
{
	mdb_free(buf, size);
}

/*ARGSUSED*/
const char *
ctf_strerror(int err)
{
	return (NULL); /* Not supported in kmdb */
}

/*PRINTFLIKE1*/
void
ctf_dprintf(const char *format, ...)
{
	va_list alist;

	va_start(alist, format);
	mdb_dvprintf(MDB_DBG_CTF, format, alist);
	va_end(alist);
}

/*ARGSUSED*/
int
z_uncompress(void *dst, size_t *dstlen, const void *src, size_t srclen)
{
	return (Z_ERRNO);
}

/*ARGSUSED*/
const char *
z_strerror(int err)
{
	return ("zlib unsupported in kmdb");
}

int
ctf_vsnprintf(char *buf, size_t nbytes, const char *format, va_list alist)
{
	return ((int)mdb_iob_vsnprintf(buf, nbytes, format, alist));
}
