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

#ifndef	_SYS_AMD_IOMMU_H
#define	_SYS_AMD_IOMMU_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/sunddi.h>
#include <sys/iommulib.h>

#ifdef _KERNEL

#define	BITPOS_START(b)	((b) >> 16)
#define	BITPOS_END(b)	((b) & 0xFFFF)

#define	START_MASK(s)	(((s) == 63) ? ~((uint64_t)0) : (1ULL << ((s)+1)) - 1)
#define	END_MASK(e)	((1ULL << (e)) - 1)

#define	BIT_MASK(s, e)	(START_MASK(s) & ~END_MASK(e))

#define	AMD_IOMMU_REG_GET(r, b) \
	(((r) & (START_MASK(BITPOS_START(b)))) >> BITPOS_END(b))

#define	AMD_IOMMU_REG_SET(r, b, v) \
	((r) = (((uint64_t)(r) & ~(BIT_MASK(BITPOS_START(b), BITPOS_END(b)))) \
	    | ((uint64_t)(v) << BITPOS_END(b))))

typedef enum {
	AMD_IOMMU_INTR_INVALID = 0,
	AMD_IOMMU_INTR_TABLE,
	AMD_IOMMU_INTR_ALLOCED,
	AMD_IOMMU_INTR_HANDLER,
	AMD_IOMMU_INTR_ENABLED
} amd_iommu_intr_state_t;

typedef struct amd_iommu_state {
	int	aioms_instance;			/* instance */
	dev_info_t *aioms_devi;			/* dip */
	struct amd_iommu *aioms_iommu_start;	/* start of list of IOMMUs */
	struct amd_iommu *aioms_iommu_end;	/* end of list of IOMMUs */
	int aioms_nunits;			/* # of IOMMUs in function */
} amd_iommu_state_t;

int amd_iommu_setup(dev_info_t *dip, amd_iommu_state_t *statep);
int amd_iommu_teardown(dev_info_t *dip, amd_iommu_state_t *statep);
int amd_iommu_lookup_src_bdf(uint16_t bdf, uint16_t *src_bdfp);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_AMD_IOMMU_H */
