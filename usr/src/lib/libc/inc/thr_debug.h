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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _THR_DEBUG_H
#define	_THR_DEBUG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#if defined(THREAD_DEBUG)

extern void __assfail(const char *, const char *, int);
#pragma rarely_called(__assfail)
#define	ASSERT(EX)	(void)((EX) || (__assfail(#EX, __FILE__, __LINE__), 0))

#else

#define	ASSERT(EX)	((void)0)

#endif

#endif	/* _THR_DEBUG_H */
