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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _LOCALE_H
#define	_LOCALE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <iso/locale_iso.h>

#if (!defined(_STRICT_STDC) && !defined(__XOPEN_OR_POSIX)) || \
	defined(__EXTENSIONS__)
#include <libintl.h>
#endif

/*
 * Allow global visibility for symbols defined in
 * C++ "std" namespace in <iso/locale_iso.h>.
 */
#if __cplusplus >= 199711L
using std::lconv;
using std::setlocale;
using std::localeconv;
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define	_LastCategory	LC_MESSAGES	/* This must be last category */

#define	_ValidCategory(c) \
	(((int)(c) >= LC_CTYPE) && ((int)(c) <= _LastCategory) || \
	((int)c == LC_ALL))

#ifdef	__cplusplus
}
#endif

#endif	/* _LOCALE_H */
