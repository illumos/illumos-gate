/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */


#include <sys/types.h>
#include <sys/time.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/kiconv.h>

#include <errno.h>
#include <iconv.h>


kiconv_t
kiconv_open(const char *tocode, const char *fromcode)
{
	return (iconv_open(tocode, fromcode));
}

int
kiconv_close(kiconv_t handle)
{
	if (iconv_close(handle) < 0)
		return (EBADF);

	return (0);
}

size_t
kiconv(
    kiconv_t handle,
    char **inbuf,
    size_t *inbytesleft,
    char **outbuf,
    size_t *outbytesleft,
    int *errno_out)
{
	size_t code;

	code = iconv(handle, (const char **)inbuf, inbytesleft,
	    outbuf, outbytesleft);
	*errno_out = errno;
	return (code);
}
