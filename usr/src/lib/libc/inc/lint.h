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

#ifndef _LIBC_LINT_H
#define	_LIBC_LINT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * We must include "lint.h" as the first #include in all libc source files
 * for the purpose of running lint over libc, else lint errors occur due to
 * lint not knowing the details of the implementation of locales and stdio.
 */
#if defined(__lint)

#include "mbstatet.h"
#include "file64.h"

#else

/*
 * Small optimization for callers of syscall() and __systemcall().
 * This could/should be defined elsewhere, but here is a particularly
 * attractive place since all source files in libc include "lint.h".
 */
#define	syscall		_syscall6
#define	__systemcall	__systemcall6

#endif

#ifdef __cplusplus
}
#endif

#endif /* _LIBC_LINT_H */
