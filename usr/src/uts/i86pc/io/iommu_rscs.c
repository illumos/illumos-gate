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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <sys/conf.h>
#include <sys/autoconf.h>
#include <sys/sysmacros.h>
#include <sys/debug.h>
#include <sys/psw.h>
#include <sys/ddidmareq.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <vm/seg.h>
#include <vm/seg_kmem.h>
#include <vm/seg_kpm.h>
#include <vm/seg_dev.h>
#include <sys/vmem.h>
#include <vm/hat.h>
#include <vm/as.h>
#include <vm/page.h>
#include <sys/avintr.h>
#include <sys/errno.h>
#include <sys/modctl.h>
#include <sys/ddi_impldefs.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/mach_intr.h>
#include <vm/hat_i86.h>
#include <sys/machsystm.h>
#include <sys/iommu_rscs.h>
#include <sys/intel_iommu.h>

ddi_dma_attr_t page_dma_attr = {
	DMA_ATTR_V0,
	0U,
	0xffffffffU,
	0xffffffffU,
	MMU_PAGESIZE, /* page aligned */
	0x1,
	0x1,
	0xffffffffU,
	0xffffffffU,
	1,
	4,
	0
};

ddi_device_acc_attr_t page_acc_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC
};

typedef struct iommu_rscs_s {
	/*
	 * Bounds of resource allocation. We will start allocating at rs_min
	 * and rollover at rs_max+1 (rs_max is included). e.g. for rs_min=0
	 * and rs_max=7, we will have 8 total resources which can be alloced.
	 */
	uint_t rs_min;
	uint_t rs_max;

	/*
	 * rs_free points to an array of 64-bit values used to track resource
	 * allocation. rs_free_size is the free buffer size in bytes.
	 */
	uint64_t *rs_free;
	uint_t rs_free_size;

	/*
	 * last tracks the last alloc'd resource. This allows us to do a round
	 * robin allocation.
	 */
	uint_t rs_last;

	kmutex_t rs_mutex;
} iommu_rscs_state_t;

static uint_t
iommu_pghdl_hash_func(paddr_t paddr)
{
	return (paddr % IOMMU_PGHDL_HASH_SIZE);
}

/*
 * iommu_page_alloc()
 *
 */
iommu_pghdl_t *
iommu_page_alloc(intel_iommu_state_t *iommu, int kmflag)
{
	size_t actual_size = 0;
	iommu_pghdl_t *pghdl;
	caddr_t vaddr;
	uint_t idx;

	ASSERT(kmflag == KM_SLEEP || kmflag == KM_NOSLEEP);

	pghdl = kmem_zalloc(sizeof (*pghdl), kmflag);
	if (pghdl == NULL) {
		return (0);
	}

	if (ddi_dma_alloc_handle(ddi_root_node(), &page_dma_attr, DDI_DMA_SLEEP,
	    NULL, &pghdl->dma_hdl) != DDI_SUCCESS) {
		kmem_free(pghdl, sizeof (*pghdl));
		return (0);
	}

	if (ddi_dma_mem_alloc(pghdl->dma_hdl, PAGESIZE, &page_acc_attr,
	    DDI_DMA_CONSISTENT | IOMEM_DATA_UNCACHED,
	    (kmflag == KM_SLEEP) ? DDI_DMA_SLEEP : DDI_DMA_DONTWAIT,
	    NULL, &vaddr, &actual_size, &pghdl->mem_hdl) != DDI_SUCCESS) {
		ddi_dma_free_handle(&pghdl->dma_hdl);
		kmem_free(pghdl, sizeof (*pghdl));
		return (0);
	}

	ASSERT(actual_size == PAGESIZE);

	if (actual_size != PAGESIZE) {
		ddi_dma_mem_free(&pghdl->mem_hdl);
		ddi_dma_free_handle(&pghdl->dma_hdl);
		kmem_free(pghdl, sizeof (*pghdl));
		return (0);

	}

	pghdl->paddr = pfn_to_pa(hat_getpfnum(kas.a_hat, vaddr));

	idx = iommu_pghdl_hash_func(pghdl->paddr);
	pghdl->next = iommu->iu_pghdl_hash[idx];
	if (pghdl->next)
		pghdl->next->prev = pghdl;
	iommu->iu_pghdl_hash[idx] = pghdl;

	return (pghdl);
}

/*
 * iommu_page_free()
 */
void
iommu_page_free(intel_iommu_state_t *iommu, paddr_t paddr)
{
	uint_t idx;
	iommu_pghdl_t *pghdl;

	idx = iommu_pghdl_hash_func(paddr);
	pghdl = iommu->iu_pghdl_hash[idx];
	while (pghdl && pghdl->paddr != paddr)
		continue;
	if (pghdl == NULL) {
		cmn_err(CE_PANIC,
		    "Freeing a free IOMMU page: paddr=0x%" PRIx64,
		    paddr);
		/*NOTREACHED*/
	}
	if (pghdl->prev == NULL)
		iommu->iu_pghdl_hash[idx] = pghdl->next;
	else
		pghdl->prev->next = pghdl->next;
	if (pghdl->next)
		pghdl->next->prev = pghdl->prev;

	ddi_dma_mem_free(&pghdl->mem_hdl);
	ddi_dma_free_handle(&pghdl->dma_hdl);
	kmem_free(pghdl, sizeof (*pghdl));
}

/*
 * iommu_get_vaddr()
 */
caddr_t
iommu_get_vaddr(intel_iommu_state_t *iommu, paddr_t paddr)
{
	uint_t idx;
	iommu_pghdl_t *pghdl;

	idx = iommu_pghdl_hash_func(paddr);
	pghdl = iommu->iu_pghdl_hash[idx];
	while (pghdl && pghdl->paddr != paddr)
		continue;
	if (pghdl == NULL) {
		return (0);
	}
	return (pghdl->vaddr);
}


/*
 * iommu_rscs_init()
 *    Initialize the resource structure. init() returns a handle to be
 *    used for the rest of the resource functions. This code is written assuming
 *    that min_val will be close to 0. Therefore, we will allocate the free
 *    buffer only taking max_val into account.
 */
void
iommu_rscs_init(uint_t min_val, uint_t max_val, iommu_rscs_t *handle)
{
	iommu_rscs_state_t *rstruct;
	uint_t array_size;
	uint_t index;


	ASSERT(handle != NULL);
	ASSERT(min_val < max_val);

	/* alloc space for resource structure */
	rstruct = kmem_alloc(sizeof (iommu_rscs_state_t), KM_SLEEP);

	/*
	 * Test to see if the max value is 64-bit aligned. If so, we don't need
	 * to allocate an extra 64-bit word. alloc space for free buffer
	 * (8 bytes per uint64_t).
	 */
	if ((max_val & 0x3F) == 0) {
		rstruct->rs_free_size = (max_val >> 6) * 8;
	} else {
		rstruct->rs_free_size = ((max_val >> 6) + 1) * 8;
	}
	rstruct->rs_free = kmem_alloc(rstruct->rs_free_size, KM_SLEEP);

	/* Initialize resource structure */
	rstruct->rs_min = min_val;
	rstruct->rs_last = min_val;
	rstruct->rs_max = max_val;
	mutex_init(&rstruct->rs_mutex, NULL, MUTEX_DRIVER, NULL);

	/* Mark all resources as free */
	array_size = rstruct->rs_free_size >> 3;
	for (index = 0; index < array_size; index++) {
		rstruct->rs_free[index] = (uint64_t)0xFFFFFFFFFFFFFFFF;
	}

	/* setup handle which is returned from this function */
	*handle = rstruct;
}


/*
 * iommu_rscs_fini()
 *    Frees up the space allocated in init().  Notice that a pointer to the
 *    handle is used for the parameter.  fini() will set the handle to NULL
 *    before returning.
 */
void
iommu_rscs_fini(iommu_rscs_t *handle)
{
	iommu_rscs_state_t *rstruct;


	ASSERT(handle != NULL);

	rstruct = (iommu_rscs_state_t *)*handle;

	mutex_destroy(&rstruct->rs_mutex);
	kmem_free(rstruct->rs_free, rstruct->rs_free_size);
	kmem_free(rstruct, sizeof (iommu_rscs_state_t));

	/* set handle to null.  This helps catch bugs. */
	*handle = NULL;
}


/*
 * iommu_rscs_alloc()
 *    alloc a resource. If alloc fails, we are out of resources.
 */
int
iommu_rscs_alloc(iommu_rscs_t handle, uint_t *resource)
{
	iommu_rscs_state_t *rstruct;
	uint_t array_idx;
	uint64_t free;
	uint_t index;
	uint_t last;
	uint_t min;
	uint_t max;


	ASSERT(handle != NULL);
	ASSERT(resource != NULL);

	rstruct = (iommu_rscs_state_t *)handle;

	mutex_enter(&rstruct->rs_mutex);
	min = rstruct->rs_min;
	max = rstruct->rs_max;

	/*
	 * Find a free resource. This will return out of the loop once it finds
	 * a free resource. There are a total of 'max'-'min'+1 resources.
	 * Performs a round robin allocation.
	 */
	for (index = min; index <= max; index++) {

		array_idx = rstruct->rs_last >> 6;
		free = rstruct->rs_free[array_idx];
		last = rstruct->rs_last & 0x3F;

		/* if the next resource to check is free */
		if ((free & ((uint64_t)1 << last)) != 0) {
			/* we are using this resource */
			*resource = rstruct->rs_last;

			/* take it out of the free list */
			rstruct->rs_free[array_idx] &= ~((uint64_t)1 << last);

			/*
			 * increment the last count so we start checking the
			 * next resource on the next alloc().  Note the rollover
			 * at 'max'+1.
			 */
			rstruct->rs_last++;
			if (rstruct->rs_last > max) {
				rstruct->rs_last = rstruct->rs_min;
			}

			/* unlock the resource structure */
			mutex_exit(&rstruct->rs_mutex);

			return (DDI_SUCCESS);
		}

		/*
		 * This resource is not free, lets go to the next one. Note the
		 * rollover at 'max'.
		 */
		rstruct->rs_last++;
		if (rstruct->rs_last > max) {
			rstruct->rs_last = rstruct->rs_min;
		}
	}

	mutex_exit(&rstruct->rs_mutex);

	return (DDI_FAILURE);
}


/*
 * iommu_rscs_free()
 *    Free the previously alloc'd resource.  Once a resource has been free'd,
 *    it can be used again when alloc is called.
 */
void
iommu_rscs_free(iommu_rscs_t handle, uint_t resource)
{
	iommu_rscs_state_t *rstruct;
	uint_t array_idx;
	uint_t offset;


	ASSERT(handle != NULL);

	rstruct = (iommu_rscs_state_t *)handle;
	ASSERT(resource >= rstruct->rs_min);
	ASSERT(resource <= rstruct->rs_max);

	mutex_enter(&rstruct->rs_mutex);

	/* Put the resource back in the free list */
	array_idx = resource >> 6;
	offset = resource & 0x3F;
	rstruct->rs_free[array_idx] |= ((uint64_t)1 << offset);

	mutex_exit(&rstruct->rs_mutex);
}
