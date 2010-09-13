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
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _SYS_IOMMUTSB_H
#define	_SYS_IOMMUTSB_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _KERNEL

/*
 * IOMMU TSB allocation.
 */

/* These four function comprise the interface for the nexus drivers. */
#define	IOMMU_TSB_COOKIE_NONE	((uint16_t)-1)
extern uint16_t iommu_tsb_alloc(uint16_t);
extern void iommu_tsb_free(uint16_t);
extern uint64_t *iommu_tsb_cookie_to_va(uint16_t);
extern uint_t iommu_tsb_cookie_to_size(uint16_t);

/* iommu_tsb_init() is called during startup. */
extern caddr_t iommu_tsb_init(caddr_t);

#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_IOMMUTSB_H */
