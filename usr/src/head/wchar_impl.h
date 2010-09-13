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
 * Copyright (c) 1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_WCHAR_IMPL_H
#define	_WCHAR_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/isa_defs.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef	_MBSTATET_H
#define	_MBSTATET_H
typedef struct __mbstate_t {
#if defined(_LP64)
	long	__filler[4];
#else
	int	__filler[6];
#endif
} __mbstate_t;
#endif	/* _MBSTATET_H */

#ifdef	__cplusplus
}
#endif

#endif	/* _WCHAR_IMPL_H */
