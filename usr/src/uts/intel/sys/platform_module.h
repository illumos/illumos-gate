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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_PLATFORM_MODULE_H
#define	_SYS_PLATFORM_MODULE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/sunddi.h>

#ifdef	__cplusplus
extern "C" {
#endif


#if defined(_KERNEL)
/*
 * The functions that are expected of the platform modules.
 */
extern void plat_build_mem_nodes(struct memlist *);
extern void plat_slice_add(pfn_t, pfn_t);
extern void plat_slice_del(pfn_t, pfn_t);

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_PLATFORM_MODULE_H */
