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

#include "lint.h"
#include <stddef.h>
#include <inttypes.h>
#include <wchar.h>

/*
 * In _LP64
 *	intmax_t and uintmax_t are always equivalent to
 *	int64_t and uint64_t, respectively.
 *
 * In _ILP32
 *	intmax_t and uintmax_t are equivalent to int64_t and uint64_t,
 *	respectively, when the following both conditions become
 *	true:
 *		- strict c89 mode is not used
 *		- _NO_LONGLONG is not defined
 *	Otherwise, intmax_t and uintmax_t are equivalent to
 *	int32_t and uint32_t, respectively.
 *
 * libc is compiled neither in strict-c89 mode nor is _NO_LONGLONG
 * defined.
 */

/* for int64_t instance */
intmax_t
wcstoimax(const wchar_t *nptr, wchar_t **endptr, int base)
{
	return ((intmax_t)wcstoll(nptr, endptr, base));
}

/* for uint64_t instance */
uintmax_t
wcstoumax(const wchar_t *nptr, wchar_t **endptr, int base)
{
	return ((uintmax_t)wcstoull(nptr, endptr, base));
}

#if	!defined(_LP64)
/* for int32_t instance */
int32_t
_wcstoimax_c89(const wchar_t *nptr, wchar_t **endptr, int base)
{
	return ((int32_t)wcstol(nptr, endptr, base));
}

/* for int32_t instance */
uint32_t
_wcstoumax_c89(const wchar_t *nptr, wchar_t **endptr, int base)
{
	return ((uint32_t)wcstoul(nptr, endptr, base));
}
#endif
