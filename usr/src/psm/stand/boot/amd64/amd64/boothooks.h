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

#ifndef	_AMD64_BOOTHOOKS_H
#define	_AMD64_BOOTHOOKS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/bootconf.h>
#include <sys/bootsvcs.h>

/*
 * Grrr... conflicting #defines in sys/bootsvcs.h and sys/saio.h...
 */
#undef printf
#undef getchar
#undef putchar
#undef ischar

#include <sys/saio.h>
#include <strings.h>

extern caddr_t idmap_mem(uint32_t, size_t, int);

#ifdef	__cplusplus
}
#endif

#endif	/* _AMD64_BOOTHOOKS_H */
