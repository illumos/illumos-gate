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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#if !defined(_KMDB) && !defined(_KERNEL)

#pragma weak _memmove = memmove

#include "lint.h"
#endif /* !_KMDB && !_KERNEL */

#include <sys/types.h>

#if defined(_KERNEL)
#include <sys/systm.h>
#else
#include <string.h>
#include <memory.h>
#endif

/*
 * Copy s0 to s, always copy n bytes.
 * Return s
 * Copying between objects that overlap will take place correctly
 */
void *
memmove(void *s, const void *s0, size_t n)
{
	if (n != 0) {
		char *s1 = s;
		const char *s2 = s0;

		if (s1 <= s2) {
			do {
				*s1++ = *s2++;
			} while (--n != 0);
		} else {
			s2 += n;
			s1 += n;
			do {
				*--s1 = *--s2;
			} while (--n != 0);
		}
	}
	return (s);
}
