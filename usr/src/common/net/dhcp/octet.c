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
 * Copyright 1996-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* LINTLIBRARY */

#if !defined(_BOOT) && !defined(_KERNEL)
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#endif	/* _BOOT && _KERNEL */
#include <sys/types.h>
#include <sys/null.h>
#include <sys/errno.h>

#if	defined(_BOOT) || defined(_KERNEL)
#define	isdigit(c)	((c) >= '0' && c <= '9')
#define	isxdigit(c)	(isdigit(c) || (((c) >= 'a') && ((c) <= 'f')) || \
			(((c) >= 'A') && ((c) <= 'F')))
#endif	/* _BOOT || _KERNEL */

/*
 * Converts an octet string into an ASCII string. The string returned is
 * NULL-terminated, and the length recorded in blen does *not* include the
 * null terminator (in other words, octet_to_hexascii() returns the length a'la
 * strlen()).
 *
 * Returns 0 for Success, errno otherwise.
 */
int
octet_to_hexascii(const void *nump, uint_t nlen, char *bufp, uint_t *blen)
{
	int		i;
	char		*bp;
	const uchar_t	*np;
	static char	ascii_conv[] = "0123456789ABCDEF";

	if (nump == NULL || bufp == NULL || blen == NULL)
		return (EINVAL);

	if ((nlen * 2) >= *blen) {
		*blen = 0;
		return (E2BIG);
	}
	for (i = 0, bp = bufp, np = (const uchar_t *)nump; i < nlen; i++) {
		*bp++ = ascii_conv[(np[i] >> 4) & 0x0f];
		*bp++ = ascii_conv[np[i] & 0x0f];
	}
	*bp = '\0';
	*blen = i * 2;
	return (0);
}

/*
 * Converts an ASCII string into an octet string.
 *
 * Returns 0 for success, errno otherwise.
 */
int
hexascii_to_octet(const char *asp, uint_t alen, void *bufp, uint_t *blen)
{
	int		i, j, k;
	const char	*tp;
	uchar_t		*u_tp;

	if (asp == NULL || bufp == NULL || blen == NULL)
		return (EINVAL);

	if (alen > (*blen * 2))
		return (E2BIG);

	k = ((alen % 2) == 0) ? alen / 2 : (alen / 2) + 1;
	for (tp = asp, u_tp = (uchar_t *)bufp, i = 0; i < k; i++, u_tp++) {
		/* one nibble at a time */
		for (*u_tp = 0, j = 0; j < 2; j++, tp++) {
			if (isdigit(*tp))
				*u_tp |= *tp - '0';
			else if (isxdigit(*tp))
				*u_tp |= (*tp & ~0x20) + 10 - 'A';
			else
				return (EINVAL);
			if ((j % 2) == 0)
				*u_tp <<= 4;
		}
	}
	*blen = k;
	return (0);
}
