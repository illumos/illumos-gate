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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/modctl.h>
#include <sys/zmod.h>
#include <sys/systm.h>

#include "zlib.h"

/*
 * Uncompress the buffer 'src' into the buffer 'dst'.  The caller must store
 * the expected decompressed data size externally so it can be passed in.
 * The resulting decompressed size is then returned through dstlen.  This
 * function return Z_OK on success, or another error code on failure.
 */
int
z_uncompress(void *dst, size_t *dstlen, const void *src, size_t srclen)
{
	z_stream zs;
	int err;

	bzero(&zs, sizeof (zs));
	zs.next_in = (uchar_t *)src;
	zs.avail_in = srclen;
	zs.next_out = dst;
	zs.avail_out = *dstlen;

	if ((err = inflateInit(&zs)) != Z_OK)
		return (err);

	if ((err = inflate(&zs, Z_FINISH)) != Z_STREAM_END) {
		(void) inflateEnd(&zs);
		return (err == Z_OK ? Z_BUF_ERROR : err);
	}

	*dstlen = zs.total_out;
	return (inflateEnd(&zs));
}

static const char *const z_errmsg[] = {
	"need dictionary",	/* Z_NEED_DICT		2  */
	"stream end",		/* Z_STREAM_END		1  */
	"",			/* Z_OK			0  */
	"file error",		/* Z_ERRNO		(-1) */
	"stream error",		/* Z_STREAM_ERROR	(-2) */
	"data error",		/* Z_DATA_ERROR		(-3) */
	"insufficient memory",	/* Z_MEM_ERROR		(-4) */
	"buffer error",		/* Z_BUF_ERROR		(-5) */
	"incompatible version"	/* Z_VERSION_ERROR	(-6) */
};

/*
 * Convert a zlib error code into a string error message.
 */
const char *
z_strerror(int err)
{
	int i = Z_NEED_DICT - err;

	if (i < 0 || i >= sizeof (z_errmsg) / sizeof (z_errmsg[0]))
		return ("unknown error");

	return (z_errmsg[i]);
}
