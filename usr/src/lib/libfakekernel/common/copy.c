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

int
copyinstr(const char *src, char *dst, size_t max_len, size_t *copied)
{
	return (copystr(src, dst, max_len, copied));
}

int
copystr(const char *src, char *dst, size_t max_len, size_t *outlen)
{
	size_t copied;

	if (max_len == 0)
		return (ENAMETOOLONG);

	copied = strlcpy(dst, src, max_len) + 1;
	if (copied >= max_len)
		return (ENAMETOOLONG);

	if (outlen != NULL)
		*outlen = copied;

	return (0);
}

void
ovbcopy(const void *src, void *dst, size_t len)
{
	(void) memmove(dst, src, len);
}
