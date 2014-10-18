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
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 */
/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#if defined(ELFOBJ)
#pragma weak nanl = __nanl
#endif

#include "libm.h"

#if defined(__sparc)

static const union {
	unsigned i[4];
	long double ld;
} __nanl_union = { 0x7fffffff, 0xffffffff, 0xffffffff, 0xffffffff };

#elif defined(__x86)

static const union {
	unsigned i[3];
	long double ld;
} __nanl_union = { 0xffffffff, 0xffffffff, 0x7fff };

#else
#error Unknown architecture
#endif

/* ARGSUSED0 */
long double
__nanl(const char *c) {
	return (__nanl_union.ld);
}
