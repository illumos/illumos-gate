/*	$NetBSD: firmload.c,v 1.19 2014/03/25 16:19:13 christos Exp $	*/

/*
 * Copyright 2016 Hans Rosenfeld <rosenfeld@grumpf.hope-2000.org>
 */

/*
 * Copyright (c) 2005, 2006 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Jason R. Thorpe.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * The firmload API provides an interface for device drivers to access
 * firmware images that must be loaded onto their devices.
 */

#include <sys/param.h>
#include <sys/fcntl.h>
#include <sys/systm.h>
#include <sys/vnode.h>
#include <sys/lwp.h>
#include <sys/file.h>
#include <sys/cmn_err.h>
#include <sys/modctl.h>
#include <sys/kobj.h>
#include <sys/kobj_impl.h>

#include <sys/firmload.h>

struct firmware_handle {
	struct _buf	*fh_buf;
	off_t		 fh_size;
};

static firmware_handle_t
firmware_handle_alloc(void)
{
	return (kmem_alloc(sizeof (struct firmware_handle), KM_SLEEP));
}

static void
firmware_handle_free(firmware_handle_t fh)
{
	kmem_free(fh, sizeof (struct firmware_handle));
}

/*
 * firmware_open:
 *
 *	Open a firmware image and return its handle.
 */
int
firmware_open(const char *drvname, const char *imgname, firmware_handle_t *fhp)
{
	char *path;
	firmware_handle_t fh;
	int error;

	if (drvname == NULL || imgname == NULL || fhp == NULL)
		return (EINVAL);

	path = kmem_asprintf("firmware/%s/%s", drvname, imgname);
	fh = firmware_handle_alloc();

	fh->fh_buf = kobj_open_path(path, 1, 0);
	strfree(path);

	if (fh->fh_buf == (struct _buf *)-1) {
		firmware_handle_free(fh);
		return (ENOENT);
	}

	error = kobj_get_filesize(fh->fh_buf, (uint64_t *)&fh->fh_size);
	if (error != 0) {
		kobj_close_file(fh->fh_buf);
		firmware_handle_free(fh);
		return (error);
	}

	*fhp = fh;
	return (0);
}

/*
 * firmware_close:
 *
 *	Close a firmware image.
 */
int
firmware_close(firmware_handle_t fh)
{
	if (fh != NULL) {
		kobj_close_file(fh->fh_buf);
		firmware_handle_free(fh);
	}
	return (0);
}

/*
 * firmware_get_size:
 *
 *	Return the total size of a firmware image.
 */
off_t
firmware_get_size(firmware_handle_t fh)
{
	ASSERT(fh != NULL);
	return (fh->fh_size);
}

/*
 * firmware_read:
 *
 *	Read data from a firmware image at the specified offset into
 *	the provided buffer.
 */
int
firmware_read(firmware_handle_t fh, off_t offset, void *buf, size_t len)
{
	ASSERT(fh != NULL);
	if (kobj_read_file(fh->fh_buf, buf, len, offset) == -1)
		return (-1);

	return (0);
}
