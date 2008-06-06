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

/*
 * The SunStudio compiler may generate calls to _memcpy and so we
 * need to make sure that the correct symbol exists for these calls,
 * whether it be libc (first case below) or the kernel (second case).
 */

#if !defined(_KMDB) && !defined(_BOOT) && !defined(_KERNEL)

#include "lint.h"

#endif /* !_KMDB && !_BOOT && !_KERNEL */

#pragma weak _memcpy = memcpy

#include <sys/types.h>

#if defined(_KERNEL)
#include <sys/systm.h>
#elif !defined(_BOOT)
#include <stddef.h>
#include <string.h>
#endif

#include "memcpy.h"

/*
 * Copy s0 to s, always copy n bytes.
 * Return s
 */
void *
memcpy(void *s, const void *s0, size_t n)
{
	if (n != 0) {
		char *s1 = s;
		const char *s2 = s0;

		do {
			*s1++ = *s2++;
		} while (--n != 0);
	}
	return (s);
}
