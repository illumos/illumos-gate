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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _LIBC_LINT_H
#define	_LIBC_LINT_H

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

/*
 * Shades of the old and deprecated "synonyms.h" file.
 * Because of the awkward relationship between these functions:
 *	memcmp()
 *	memcpy()
 *	memmove()
 *	memset()
 * and the sparc auxiliary filters:
 *	/platform/.../lib/libc_psr.so.1
 * we must be careful always to call the leading-underscore
 * symbol names when calling from within libc itself.
 *
 * If an interposer interposes on these mem*() symbol names,
 * and we call one of them from within a critical region in libc,
 * we will end up in the interposer code while executing within
 * the critical region.  Chaos can ensue.
 *
 * We try to avoid this by calling only the leading-underscore names.
 * We hope that no interposer will interpose on the leading-underscore
 * versions of these functions, else all hope is lost.
 */

#pragma	redefine_extname	memcmp		_memcmp
#pragma	redefine_extname	memcpy		_memcpy
#pragma	redefine_extname	memmove		_memmove
#pragma	redefine_extname	memset		_memset

#endif

#ifdef __cplusplus
}
#endif

#endif /* _LIBC_LINT_H */
