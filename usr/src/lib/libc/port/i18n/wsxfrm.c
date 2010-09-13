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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* This is Sun's propriatry implementation of wsxfrm() and wscoll()	*/
/* using dynamic linking.  It is probably free from AT&T copyright.	*/

#pragma weak _wscoll = wscoll
#pragma weak _wsxfrm = wsxfrm

#include "lint.h"
#include <wchar.h>
#include "libc.h"

size_t
wsxfrm(wchar_t *s1, const wchar_t *s2, size_t n)
{
	return (wcsxfrm(s1, s2, n));
}

int
wscoll(const wchar_t *s1, const wchar_t *s2)
{
	return (wcscoll(s1, s2));
}
