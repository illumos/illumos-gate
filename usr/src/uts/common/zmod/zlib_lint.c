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

#include <sys/types.h>
#include <sys/zmod.h>

#include "zlib.h"

/*ARGSUSED*/
int
z_uncompress(void *dst, size_t *dstlen, const void *src, size_t srclen)
{
	return (0);
}

/*ARGSUSED*/
int
z_compress(void *dst, size_t *dstlen, const void *src, size_t srclen)
{
	return (0);
}

/*ARGSUSED*/
int
z_compress_level(void *dst, size_t *dstlen, const void *src, size_t srclen,
    int level)
{
	return (0);
}

/*ARGSUSED*/
const char *
z_strerror(int err)
{
	return (NULL);
}

/*ARGSUSED*/
int
inflate(z_streamp strm, int flush)
{
	return (0);
}

/*ARGSUSED*/
int
inflateInit2_(z_streamp strm, int window, const char *version, int size)
{
	return (0);
}

/*ARGSUSED*/
int
inflateEnd(z_streamp strm)
{
	return (0);
}

/*ARGSUSED*/
int
inflateReset(z_streamp strm)
{
	return (0);
}
