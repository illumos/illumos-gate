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


/*
 * iommu_page_alloc()
 *
 */
paddr_t
iommu_page_alloc(int kmflag)
{
	paddr_t paddr;
	page_t *pp;

	ASSERT(kmflag == KM_SLEEP || kmflag == KM_NOSLEEP);

	pp = page_get_physical(kmflag);
	if (pp == NULL) {
		return (NULL);
	}

	paddr =  pa_to_ma((uint64_t)pp->p_pagenum << PAGESHIFT);

	return (paddr);
}


/*
 * iommu_page_free()
 */
void
iommu_page_free(paddr_t paddr)
{
	page_t *pp;

	pp = page_numtopp_nolock(ma_to_pa(paddr) >> PAGESHIFT);
	page_free_physical(pp);
}


/*
 * iommu_page_map()
 *
 */
caddr_t
iommu_page_map(paddr_t addr)
{
	paddr_t paddr;
	caddr_t kva;
	page_t *pp;

	paddr = ma_to_pa(addr);

	if (kpm_enable) {
		kva = hat_kpm_pfn2va((pfn_t)btop(paddr));
	} else {
		kva = vmem_alloc(heap_arena, PAGESIZE, VM_SLEEP);
		if (kva == NULL) {
			return (NULL);
		}
		pp = page_numtopp_nolock(paddr >> PAGESHIFT);
		hat_memload(kas.a_hat, kva, pp,
		    PROT_READ | PROT_WRITE, HAT_LOAD_LOCK);
	}

	return (kva);
}


/*
 * iommu_page_unmap()
 *
 */
void
iommu_page_unmap(caddr_t kva)
{
	if (!kpm_enable) {
		hat_unload(kas.a_hat, kva, PAGESIZE, HAT_UNLOAD_UNLOCK);
		vmem_free(heap_arena, kva, PAGESIZE);
	}
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
