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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 */

/* $Id: misc.c 146 2006-03-24 00:26:54Z njacobs $ */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/

#include <string.h>
#include <papi.h>

#include <config-site.h>

/*
 * The implementations of strlcpy() and strlcat() have been taken directly
 * from OpenSolaris.  The contents of this file originated from
 *     usr/src/lib/libc/port/gen/strlcpy.c
 *     usr/src/lib/libc/port/gen/strcat.c
 */

#ifndef HAVE_STRLCPY
size_t
strlcpy(char *dst, const char *src, size_t len)
{
	size_t slen = strlen(src);
	size_t copied;

	if (len == 0)
		return (slen);

	if (slen >= len)
		copied = len - 1;
	else
		copied = slen;
	(void) memcpy(dst, src, copied);
	dst[copied] = '\0';
	return (slen);
}
#endif

#ifndef HAVE_STRLCAT
size_t
strlcat(char *dst, const char *src, size_t dstsize)
{
	char *df = dst;
	size_t left = dstsize;
	size_t l1;
	size_t l2 = strlen(src);
	size_t copied;

	while (left-- != 0 && *df != '\0')
		df++;
	l1 = df - dst;
	if (dstsize == l1)
		return (l1 + l2);

	copied = l1 + l2 >= dstsize ? dstsize - l1 - 1 : l2;
	(void) memcpy(dst + l1, src, copied);
	dst[l1+copied] = '\0';
	return (l1 + l2);
}
#endif
