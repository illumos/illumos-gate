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

#ifndef	_AMD64_BOOTSVCS64_H
#define	_AMD64_BOOTSVCS64_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * We have to do this uglyness because of <bootsvcs.h>, sigh...
 */

#ifndef	_KERNEL
#define	_KERNEL		1
#define	__XX64_KERNEL	1
#endif	/* _KERNEL */

#undef	getchar
#undef	putchar
#undef	ischar

#include <amd64/types.h>

struct boot_syscalls64 {
	fnaddr64_t	getchar;	/*  7 - getchar */
	fnaddr64_t	putchar;	/*  8 - putchar */
	fnaddr64_t	ischar;		/*  9 - ischar */
};

#ifdef	__XX64_KERNEL
#undef	_KERNEL
#undef	__XX64_KERNEL
#endif	/* __XX64_KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _AMD64_BOOTSVCS64_H */
