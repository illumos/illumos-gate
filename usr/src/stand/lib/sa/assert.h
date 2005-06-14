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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SA_ASSERT_H
#define	_SA_ASSERT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Exported interfaces for standalone's subset of libc's <assert.h>.
 * All standalone code *must* use this header rather than libc's.
 */

#ifdef __cplusplus
extern "C" {
#endif

extern void __assert(const char *, const char *, int);

#ifdef __cplusplus
}
#endif

#endif /* _SA_ASSERT_H */

/*
 * Note that the ANSI C Standard requires all headers to be idempotent except
 * <assert.h> which is explicitly required not to be idempotent (section 4.1.2).
 * Therefore, it is by intent that the header guards (#ifndef _SA_ASSERT_H) do
 * not span this entire file.
 */

#undef  assert

#ifdef  NDEBUG
#define	assert(EX) ((void)0)
#else
#define	assert(EX) (void)((EX) || (__assert(#EX, __FILE__, __LINE__), 0))
#endif  /* NDEBUG */
