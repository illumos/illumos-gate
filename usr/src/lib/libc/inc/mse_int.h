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

#ifndef	_MSE_INT_H
#define	_MSE_INT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stddef.h>
#include <time.h>

#undef wcsftime
#undef wcstok

extern size_t wcsftime(wchar_t *, size_t, const char *, const struct tm *);
extern size_t __wcsftime_xpg5(wchar_t *, size_t, const wchar_t *,
	const struct tm *);

extern wchar_t *wcstok(wchar_t *, const wchar_t *);
extern wchar_t *__wcstok_xpg5(wchar_t *, const wchar_t *, wchar_t **);

#endif	/* _MSE_INT_H */
