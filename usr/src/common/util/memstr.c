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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#if defined(_BOOT)
#include <sys/salib.h>
#else
#include <sys/systm.h>
#endif

/*
 * Implementations of functions described in memory(3C).
 * These functions match the section 3C manpages.
 */
/*
 * The SunStudio compiler may generate calls to _memmove, _memset,
 * and _memcpy; So we need to make sure that the correct symbols
 * exist for these calls. We also use _memset to work around some
 * standards namespacing challenges.
 */
#pragma weak _memmove = memmove
void *
memmove(void *s1, const void *s2, size_t n)
{
#if defined(_BOOT)
	bcopy(s2, s1, n);
#else
	ovbcopy(s2, s1, n);
#endif
	return (s1);
}

#pragma weak _memset = memset
void *
memset(void *s, int c, size_t n)
{
	unsigned char *t;

	if ((unsigned char)c == '\0')
		bzero(s, n);
	else {
		for (t = (unsigned char *)s; n > 0; n--)
			*t++ = (unsigned char)c;
	}
	return (s);
}

int
memcmp(const void *s1, const void *s2, size_t n)
{
	const uchar_t *ps1 = s1;
	const uchar_t *ps2 = s2;

	if (s1 != s2 && n != 0) {
		do {
			if (*ps1++ != *ps2++)
				return (ps1[-1] - ps2[-1]);
		} while (--n != 0);
	}

	return (0);
}

#pragma weak _memcpy = memcpy
void *
memcpy(void *s1, const void *s2, size_t n)
{
	bcopy(s2, s1, n);
	return (s1);
}

void *
memchr(const void *sptr, int c1, size_t n)
{
	if (n != 0) {
		unsigned char c = (unsigned char)c1;
		const unsigned char *sp = sptr;

		do {
			if (*sp++ == c)
				return ((void *)--sp);
		} while (--n != 0);
	}
	return (NULL);
}
