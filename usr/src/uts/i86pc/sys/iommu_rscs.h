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

#ifndef	_SYS_IOMMU_H
#define	_SYS_IOMMU_H

/*
 * XXX
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/sunddi.h>

#ifdef	__cplusplus
extern "C" {
#endif


/*
 * iommu_page_alloc()
 *   allocate a 4K page and map it into KVA
 * iommu_page_free()
 *   unmap and free page from iommu_page_alloc()
 * iommu_page_map()
 *   map page into kva
 * iommu_page_unmap()
 *   unmap page out of kva
 */
paddr_t iommu_page_alloc(int kmflag);
void iommu_page_free(paddr_t paddr);
caddr_t iommu_page_map(paddr_t paddr);
void iommu_page_unmap(caddr_t kva);


typedef struct iommu_rscs_s *iommu_rscs_t;

void iommu_rscs_init(uint_t min_val, uint_t max_val, iommu_rscs_t *handle);
void iommu_rscs_fini(iommu_rscs_t *handle);
int iommu_rscs_alloc(iommu_rscs_t handle, uint_t *rs);
void iommu_rscs_free(iommu_rscs_t handle, uint_t rs);


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_IOMMU_H */
