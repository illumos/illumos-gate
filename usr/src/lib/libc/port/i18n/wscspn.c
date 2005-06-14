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

/*	Copyright (c) 1986 AT&T	*/
/*	  All Rights Reserved  	*/


/*	This module is created for NLS on Sep.03.86		*/

/*
 * Return the number of characters in the maximum leading segment
 * of string which consists solely of characters NOT from charset.
 */

#pragma weak wcscspn = _wcscspn
#pragma weak wscspn = _wscspn

#include "lint.h"
#include <stdlib.h>
#include <wchar.h>

size_t
_wcscspn(const wchar_t *string, const wchar_t *charset)
{
	const wchar_t *p, *q;

	for (q = string; *q != 0; ++q) {
		for (p = charset; *p != 0 && *p != *q; ++p)
			;
		if (*p != 0)
			break;
	}
	return (q - string);
}

size_t
_wscspn(const wchar_t *string, const wchar_t *charset)
{
	return (_wcscspn(string, charset));
}
