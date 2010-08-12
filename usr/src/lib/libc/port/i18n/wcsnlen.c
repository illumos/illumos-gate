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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Returns the number of non-NULL characters in str,
 * but not more than maxlen.  Does not look past str + maxlen.
 */

#include "lint.h"
#include <stdlib.h>
#include <wchar.h>

size_t
wcsnlen(const wchar_t *str, size_t maxlen)
{
	const wchar_t *ptr = str;

	if (maxlen != 0) {
		do {
			if (*ptr++ == L'\0') {
				ptr--;
				break;
			}
		} while (--maxlen != 0);
	}

	return (ptr - str);
}
