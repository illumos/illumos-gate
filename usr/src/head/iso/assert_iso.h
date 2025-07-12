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
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Copyright 2016 Joyent, Inc.
 * Copyright 2025 Oxide Computer Company
 *
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _ISO_ASSERT_ISO_H
#define	_ISO_ASSERT_ISO_H

/*
 * This file contains all of the portions of the assert.h implementation that we
 * wish to be re-entrant safe. This is not in <assert.h> as a number of
 * third-party applications have tried to use their own wrappers that use a
 * header guard, which lead to us losing the definitions that we need to have.
 * While those applications are potentially using the implementation namespace
 * incorrectly, separating out the two logical uses is helpful nonetheless and
 * hopefully makes it clearer what is what.
 *
 * This header should not be included directly by applications!
 */

#include <sys/feature_tests.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_STDC_C99)
extern _NORETURN_KYWD void __assert_c99(const char *, const char *, int,
    const char *) __NORETURN;
#else
extern _NORETURN_KYWD void __assert(const char *, const char *, int) __NORETURN;
#endif /* _STDC_C99 */

/*
 * In C11 the static_assert macro is always defined, unlike the assert macro.
 * Starting in C23, static_assert is a keyword, so this is no longer required.
 */
#if defined(_STDC_C11) && !defined(__cplusplus) && !defined(_STDC_C23)
#define	static_assert	_Static_assert
#endif /* _STDC_C11 && !defined(__cplusplus) && !_STDC_C23 */

#ifdef __cplusplus
}
#endif

#endif /* _ISO_ASSERT_ISO_H */
