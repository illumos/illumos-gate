/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
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

static struct modlmisc modlmisc = {
	&mod_miscops, "RFC 1950 decompression routines"
};

static struct modlinkage modlinkage = {
	MODREV_1, &modlmisc, NULL
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_info(struct modinfo *mip)
{
	return (mod_info(&modlinkage, mip));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}
