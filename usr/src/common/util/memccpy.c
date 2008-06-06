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

#ifndef _KMDB
#pragma weak _memccpy = memccpy

#include "lint.h"
#endif /* !_KMDB */
#include <sys/types.h>
#include <string.h>
#include <stddef.h>
#include <memory.h>

/*
 * Copy s0 to s, stopping if character c is copied. Copy no more than n bytes.
 * Return a pointer to the byte after character c in the copy,
 * or NULL if c is not found in the first n bytes.
 */
void *
memccpy(void *s, const void *s0, int c, size_t n)
{
	if (n != 0) {
		unsigned char *s1 = s;
		const unsigned char *s2 = s0;
		do {
			if ((*s1++ = *s2++) == (unsigned char)c)
				return (s1);
		} while (--n != 0);
	}
	return (NULL);
}
