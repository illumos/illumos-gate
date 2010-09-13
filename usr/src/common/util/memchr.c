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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


#include <sys/types.h>
#if defined(_KERNEL)
#include <sys/systm.h>
#else
#include <string.h>
#include <stddef.h>
#endif

/*
 * Return the ptr in sptr at which the character c1 appears;
 * or NULL if not found in n chars; don't stop at \0.
 */
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
