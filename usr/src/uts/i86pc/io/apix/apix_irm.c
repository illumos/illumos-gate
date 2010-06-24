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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/ddi.h>
#include <sys/sunndi.h>
#include <sys/ddi_impldefs.h>
#include <sys/psm_types.h>
#include <sys/smp_impldefs.h>
#include <sys/apic.h>
#include <sys/processor.h>
#include <sys/apix_irm_impl.h>

/* global variable for static default limit for non-IRM drivers */
extern int ddi_msix_alloc_limit;

/* Extern declarations */
extern int (*psm_intr_ops)(dev_info_t *, ddi_intr_handle_impl_t *,
    psm_intr_op_t, int *);

/*
 * Global variables for IRM pool configuration:
 *
 *    (1) apix_system_max_vectors -- this would limit the maximum
 *    number of interrupt vectors that will be made avilable
 *    to the device drivers. The default value (-1) indicates
 *    that all the available vectors could be used.
 *
 *    (2) apix_irm_cpu_factor -- This would specify the number of CPUs that
 *    should be excluded from the global IRM pool of interrupt vectors.
 *    By default this would be zero, so vectors from all the CPUs
 *    present will be factored into the IRM pool.
 *
 *    (3) apix_irm_reserve_fixed_vectors -- This would specify the number
 *    of vectors that should be reserved for FIXED type interrupts and
 *    exclude them from the IRM pool. The value can be one of the
 *    following:
 *	0	- no reservation (default)
 *	<n>	- a positive number for the reserved cache
 *	-1	- reserve the maximum needed
 *
 *    (4) apix_irm_free_fixed_vectors -- This flag specifies if the
 *    vectors for FIXED type should be freed and added back
 *    to the IRM pool when ddi_intr_free() is called. The default
 *    is to add it back to the pool.
 */
int apix_system_max_vectors = -1;
int apix_irm_cpu_factor = 0;
int apix_irm_reserve_fixed_vectors = 0;
int apix_irm_free_fixed_vector = 1;

/* info from APIX module for IRM configuration */
apix_irm_info_t apix_irminfo;

kmutex_t apix_irm_lock; /* global mutex for apix_irm_* data */
ddi_irm_params_t apix_irm_params; /* IRM pool info */
int apix_irm_cache_size = 0; /* local cache for FIXED type requests */
int apix_irm_cpu_factor_available = 0;
int apix_irm_max_cpus = 0;
int apix_irm_cpus_used = 0;
int apix_irm_fixed_intr_vectors_used;

extern int ncpus;

/* local data/functions */
static int apix_irm_chk_apix();
int apix_irm_intr_ops(dev_info_t *dip, ddi_intr_handle_impl_t *handle,
	psm_intr_op_t op, int *result);
int apix_irm_disable_intr(processorid_t);
void apix_irm_enable_intr(processorid_t);
int (*psm_intr_ops_saved)(dev_info_t *dip, ddi_intr_handle_impl_t *handle,
	psm_intr_op_t op, int *result) = NULL;
int (*psm_disable_intr_saved)(processorid_t) = NULL;
void (*psm_enable_intr_saved)(processorid_t) = NULL;
int apix_irm_alloc_fixed(dev_info_t *, ddi_intr_handle_impl_t *, int *);
int apix_irm_free_fixed(dev_info_t *, ddi_intr_handle_impl_t *, int *);

/*
 * Initilaize IRM pool for APIC interrupts if the PSM module
 * is of APIX type. This should be called only after PSM module
 * is loaded and APIC interrupt system is initialized.
 */
void
apix_irm_init(void)
{
	dev_info_t		*dip;
	int			total_avail_vectors;
	int			cpus_used;
	int			cache_size;

	/* nothing to do if IRM is disabled */
	if (!irm_enable)
		return;

	/*
	 * Use root devinfo node to associate the IRM pool with it
	 * as the pool is global to the system.
	 */
	dip = ddi_root_node();

	/*
	 * Check if PSM module is initialized and it is APIX
	 * module (which supports IRM functionality).
	 */
	if ((psm_intr_ops == NULL) || !apix_irm_chk_apix()) {
		/* not an APIX module */
		APIX_IRM_DEBUG((CE_CONT,
		    "apix_irm_init: APIX module not present"));
		return;
	}

	/*
	 * Now, determine the IRM pool parameters based on the
	 * info from APIX module and global config variables.
	 */

	/*
	 * apix_ncpus shows all the CPUs present in the
	 * system but not all of them may have been enabled
	 * (i.e. mp_startup() may not have been called yet).
	 * So, use ncpus for IRM pool creation.
	 */
	if (apix_irminfo.apix_ncpus > ncpus)
		apix_irminfo.apix_ncpus = ncpus;

	/* apply the CPU factor if possible */
	if ((apix_irm_cpu_factor > 0) &&
	    (apix_irminfo.apix_ncpus > apix_irm_cpu_factor)) {
		cpus_used = apix_irminfo.apix_ncpus - apix_irm_cpu_factor;
		apix_irm_cpu_factor_available = apix_irm_cpu_factor;
	} else {
		cpus_used = apix_irminfo.apix_ncpus;
	}
	apix_irm_cpus_used = apix_irm_max_cpus = cpus_used;

	APIX_IRM_DEBUG((CE_CONT,
	    "apix_irm_init: %d CPUs used for IRM pool size", cpus_used));

	total_avail_vectors = cpus_used * apix_irminfo.apix_per_cpu_vectors -
	    apix_irminfo.apix_vectors_allocated;

	apix_irm_fixed_intr_vectors_used = apix_irminfo.apix_vectors_allocated;

	if (total_avail_vectors <= 0) {
		/* can not determine pool size */
		APIX_IRM_DEBUG((CE_NOTE,
		    "apix_irm_init: can not determine pool size"));
		return;
	}

	/* adjust the pool size as per the global config variable */
	if ((apix_system_max_vectors > 0) &&
	    (apix_system_max_vectors < total_avail_vectors))
		total_avail_vectors = apix_system_max_vectors;

	/* pre-reserve vectors (i.e. local cache) for FIXED type if needed */
	if (apix_irm_reserve_fixed_vectors != 0) {
		cache_size = apix_irm_reserve_fixed_vectors;
		if ((cache_size == -1) ||
		    (cache_size > apix_irminfo.apix_ioapic_max_vectors))
			cache_size = apix_irminfo.apix_ioapic_max_vectors;
		total_avail_vectors -= cache_size;
		apix_irm_cache_size = cache_size;
	}

	if (total_avail_vectors <= 0) {
		APIX_IRM_DEBUG((CE_NOTE,
		    "apix_irm_init: invalid config parameters!"));
		return;
	}

	/* IRM pool is used only for MSI/X interrupts */
	apix_irm_params.iparams_types = DDI_INTR_TYPE_MSI | DDI_INTR_TYPE_MSIX;
	apix_irm_params.iparams_total = total_avail_vectors;

	if (ndi_irm_create(dip, &apix_irm_params,
	    &apix_irm_pool_p) == NDI_SUCCESS) {
		/*
		 * re-direct psm_intr_ops to intercept FIXED
		 * interrupt allocation requests.
		 */
		psm_intr_ops_saved = psm_intr_ops;
		psm_intr_ops = apix_irm_intr_ops;
		/*
		 * re-direct psm_enable_intr()/psm_disable_intr() to
		 * intercept CPU offline/online requests.
		 */
		psm_disable_intr_saved = psm_disable_intr;
		psm_enable_intr_saved = psm_enable_intr;
		psm_enable_intr = apix_irm_enable_intr;
		psm_disable_intr = apix_irm_disable_intr;

		mutex_init(&apix_irm_lock, NULL, MUTEX_DRIVER, NULL);

		/*
		 * Set default alloc limit for non-IRM drivers
		 * to DDI_MIN_MSIX_ALLOC (currently defined as 8).
		 *
		 * NOTE: This is done here so that the limit of 8 vectors
		 * is applicable only with APIX module. For the old pcplusmp
		 * implementation, the current default of 2 (i.e
		 * DDI_DEFAULT_MSIX_ALLOC) is retained.
		 */
		if (ddi_msix_alloc_limit < DDI_MIN_MSIX_ALLOC)
			ddi_msix_alloc_limit = DDI_MIN_MSIX_ALLOC;
	} else {
		APIX_IRM_DEBUG((CE_NOTE,
		    "apix_irm_init: ndi_irm_create() failed"));
		apix_irm_pool_p = NULL;
	}
}

/*
 * Check if the PSM module is "APIX" type which supports IRM feature.
 * Returns 0 if it is not an APIX module.
 */
static int
apix_irm_chk_apix(void)
{
	ddi_intr_handle_impl_t	info_hdl;
	apic_get_type_t		type_info;

	if (!psm_intr_ops)
		return (0);

	bzero(&info_hdl, sizeof (ddi_intr_handle_impl_t));
	info_hdl.ih_private = &type_info;
	if (((*psm_intr_ops)(NULL, &info_hdl, PSM_INTR_OP_APIC_TYPE,
	    NULL)) != PSM_SUCCESS) {
		/* unknown type; assume not an APIX module */
		return (0);
	}
	if (strcmp(type_info.avgi_type, APIC_APIX_NAME) == 0)
		return (1);
	else
		return (0);
}

/*
 * This function intercepts PSM_INTR_OP_* requests to deal with
 * IRM pool maintainance for FIXED type interrupts. The following
 * commands are intercepted and the rest are simply passed back to
 * the original psm_intr_ops function:
 *	PSM_INTR_OP_ALLOC_VECTORS
 *	PSM_INTR_OP_FREE_VECTORS
 * Return value is either PSM_SUCCESS or PSM_FAILURE.
 */
int
apix_irm_intr_ops(dev_info_t *dip, ddi_intr_handle_impl_t *handle,
	psm_intr_op_t op, int *result)
{
	switch (op) {
	case PSM_INTR_OP_ALLOC_VECTORS:
		if (handle->ih_type == DDI_INTR_TYPE_FIXED)
			return (apix_irm_alloc_fixed(dip, handle, result));
		else
			break;
	case PSM_INTR_OP_FREE_VECTORS:
		if (handle->ih_type == DDI_INTR_TYPE_FIXED)
			return (apix_irm_free_fixed(dip, handle, result));
		else
			break;
	default:
		break;
	}

	/* pass the request to APIX */
	return ((*psm_intr_ops_saved)(dip, handle, op, result));
}

/*
 * Allocate a FIXED type interrupt. The procedure for this
 * operation is as follows:
 *
 * 1) Check if this IRQ is shared (i.e. IRQ is already mapped
 *    and a vector has been already allocated). If so, then no
 *    new vector is needed and simply pass the request to APIX
 *    and return.
 * 2) Check the local cache pool for an available vector. If
 *    the cache is not empty then take it from there and simply
 *    pass the request to APIX and return.
 * 3) Otherwise, get a vector from the IRM pool by reducing the
 *    pool size by 1. If it is successful then pass the
 *    request to APIX module. Otherwise return PSM_FAILURE.
 */
int
apix_irm_alloc_fixed(dev_info_t *dip, ddi_intr_handle_impl_t *handle,
	int *result)
{
	int	vector;
	uint_t	new_pool_size;
	int	ret;

	/*
	 * Check if this IRQ has been mapped (i.e. shared IRQ case)
	 * by doing PSM_INTR_OP_XLATE_VECTOR.
	 */
	ret = (*psm_intr_ops_saved)(dip, handle, PSM_INTR_OP_XLATE_VECTOR,
	    &vector);
	if (ret == PSM_SUCCESS) {
		APIX_IRM_DEBUG((CE_CONT,
		    "apix_irm_alloc_fixed: dip %p (%s) xlated vector 0x%x",
		    (void *)dip, ddi_driver_name(dip), vector));
		/* (1) mapping already exists; pass the request to PSM */
		return ((*psm_intr_ops_saved)(dip, handle,
		    PSM_INTR_OP_ALLOC_VECTORS, result));
	}

	/* check the local cache for an available vector */
	mutex_enter(&apix_irm_lock);
	if (apix_irm_cache_size) { /* cache is not empty */
		--apix_irm_cache_size;
		apix_irm_fixed_intr_vectors_used++;
		mutex_exit(&apix_irm_lock);
		/* (2) use the vector from the local cache */
		return ((*psm_intr_ops_saved)(dip, handle,
		    PSM_INTR_OP_ALLOC_VECTORS, result));
	}

	/* (3) get a vector from the IRM pool */

	new_pool_size = apix_irm_params.iparams_total - 1;

	APIX_IRM_DEBUG((CE_CONT, "apix_irm_alloc_fixed: dip %p (%s) resize pool"
	    " from %x to %x\n", (void *)dip, ddi_driver_name(dip),
	    apix_irm_pool_p->ipool_totsz, new_pool_size));

	if (ndi_irm_resize_pool(apix_irm_pool_p, new_pool_size) ==
	    NDI_SUCCESS) {
		/* update the pool size info */
		apix_irm_params.iparams_total = new_pool_size;
		apix_irm_fixed_intr_vectors_used++;
		mutex_exit(&apix_irm_lock);
		return ((*psm_intr_ops_saved)(dip, handle,
		    PSM_INTR_OP_ALLOC_VECTORS, result));
	}

	mutex_exit(&apix_irm_lock);

	return (PSM_FAILURE);
}

/*
 * Free up the FIXED type interrupt.
 *
 * 1) If it is a shared vector then simply pass the request to
 *    APIX and return.
 * 2) Otherwise, if apix_irm_free_fixed_vector is not set then add the
 *    vector back to the IRM pool. Otherwise, keep it in the local cache.
 */
int
apix_irm_free_fixed(dev_info_t *dip, ddi_intr_handle_impl_t *handle,
	int *result)
{
	int shared;
	int ret;
	uint_t new_pool_size;

	/* check if it is a shared vector */
	ret = (*psm_intr_ops_saved)(dip, handle,
	    PSM_INTR_OP_GET_SHARED, &shared);

	if ((ret == PSM_SUCCESS) && (shared > 0)) {
		/* (1) it is a shared vector; simply pass the request */
		APIX_IRM_DEBUG((CE_CONT, "apix_irm_free_fixed: dip %p (%s) "
		    "shared %d\n", (void *)dip, ddi_driver_name(dip), shared));
		return ((*psm_intr_ops_saved)(dip, handle,
		    PSM_INTR_OP_FREE_VECTORS, result));
	}

	ret = (*psm_intr_ops_saved)(dip, handle,
	    PSM_INTR_OP_FREE_VECTORS, result);

	if (ret == PSM_SUCCESS) {
		mutex_enter(&apix_irm_lock);
		if (apix_irm_free_fixed_vector) {
			/* (2) add the vector back to IRM pool */
			new_pool_size = apix_irm_params.iparams_total + 1;
			APIX_IRM_DEBUG((CE_CONT, "apix_irm_free_fixed: "
			    "dip %p (%s) resize pool from %x to %x\n",
			    (void *)dip, ddi_driver_name(dip),
			    apix_irm_pool_p->ipool_totsz, new_pool_size));
			if (ndi_irm_resize_pool(apix_irm_pool_p,
			    new_pool_size) == NDI_SUCCESS) {
				/* update the pool size info */
				apix_irm_params.iparams_total = new_pool_size;
			} else {
				cmn_err(CE_NOTE,
				    "apix_irm_free_fixed: failed to add"
				    " a vector to IRM pool");
			}
		} else {
			/* keep the vector in the local cache */
			apix_irm_cache_size += 1;
		}
		apix_irm_fixed_intr_vectors_used--;
		mutex_exit(&apix_irm_lock);
	}

	return (ret);
}

/*
 * Disable the CPU for interrupts. It is assumed that this is called to
 * offline/disable the CPU so that no interrupts are allocated on
 * that CPU. For IRM perspective, the interrupt vectors on this
 * CPU are to be excluded for any allocations.
 *
 * If APIX module is successful in migrating all the vectors
 * from this CPU then reduce the IRM pool size to exclude the
 * interrupt vectors for that CPU.
 */
int
apix_irm_disable_intr(processorid_t id)
{
	uint_t new_pool_size;

	/* Interrupt disabling for Suspend/Resume */
	if (apic_cpus[id].aci_status & APIC_CPU_SUSPEND)
		return ((*psm_disable_intr_saved)(id));

	mutex_enter(&apix_irm_lock);
	/*
	 * Don't remove the CPU from the IRM pool if we have CPU factor
	 * available.
	 */
	if ((apix_irm_cpu_factor > 0) && (apix_irm_cpu_factor_available > 0)) {
		apix_irm_cpu_factor_available--;
	} else {
		/* can't disable if there is only one CPU used */
		if (apix_irm_cpus_used == 1) {
			mutex_exit(&apix_irm_lock);
			return (PSM_FAILURE);
		}
		/* Calculate the new size for the IRM pool */
		new_pool_size = apix_irm_params.iparams_total -
		    apix_irminfo.apix_per_cpu_vectors;

		/* Apply the max. limit */
		if (apix_system_max_vectors > 0) {
			uint_t	max;

			max = apix_system_max_vectors -
			    apix_irm_fixed_intr_vectors_used -
			    apix_irm_cache_size;

			new_pool_size = MIN(new_pool_size, max);
		}

		if (new_pool_size == 0) {
			cmn_err(CE_WARN, "Invalid pool size 0 with "
			    "apix_system_max_vectors = %d",
			    apix_system_max_vectors);
			mutex_exit(&apix_irm_lock);
			return (PSM_FAILURE);
		}

		if (new_pool_size != apix_irm_params.iparams_total) {
			/* remove the CPU from the IRM pool */
			if (ndi_irm_resize_pool(apix_irm_pool_p,
			    new_pool_size) != NDI_SUCCESS) {
				mutex_exit(&apix_irm_lock);
				APIX_IRM_DEBUG((CE_NOTE,
				    "apix_irm_disable_intr: failed to resize"
				    " the IRM pool"));
				return (PSM_FAILURE);
			}
			/* update the pool size info */
			apix_irm_params.iparams_total = new_pool_size;
		}

		/* decrement the CPU count used by IRM pool */
		apix_irm_cpus_used--;
	}

	/*
	 * Now, disable the CPU for interrupts.
	 */
	if ((*psm_disable_intr_saved)(id) != PSM_SUCCESS) {
		APIX_IRM_DEBUG((CE_NOTE,
		    "apix_irm_disable_intr: failed to disable CPU interrupts"
		    " for CPU#%d", id));
		mutex_exit(&apix_irm_lock);
		return (PSM_FAILURE);
	}
	/* decrement the CPU count enabled for interrupts */
	apix_irm_max_cpus--;
	mutex_exit(&apix_irm_lock);
	return (PSM_SUCCESS);
}

/*
 * Enable the CPU for interrupts. It is assumed that this function is
 * called to enable/online the CPU so that interrupts could be assigned
 * to it. If successful, add available vectors for that CPU to the IRM
 * pool if apix_irm_cpu_factor is already satisfied.
 */
void
apix_irm_enable_intr(processorid_t id)
{
	uint_t new_pool_size;

	/* Interrupt enabling for Suspend/Resume */
	if (apic_cpus[id].aci_status & APIC_CPU_SUSPEND) {
		(*psm_enable_intr_saved)(id);
		return;
	}

	mutex_enter(&apix_irm_lock);

	/* enable the CPU for interrupts */
	(*psm_enable_intr_saved)(id);

	/* increment the number of CPUs enabled for interrupts */
	apix_irm_max_cpus++;

	ASSERT(apix_irminfo.apix_per_cpu_vectors > 0);

	/*
	 * Check if the apix_irm_cpu_factor is satisfied before.
	 * If satisfied, add the CPU to IRM pool.
	 */
	if ((apix_irm_cpu_factor > 0) &&
	    (apix_irm_cpu_factor_available < apix_irm_cpu_factor)) {
		/*
		 * Don't add the CPU to the IRM pool. Just update
		 * the available CPU factor.
		 */
		apix_irm_cpu_factor_available++;
		mutex_exit(&apix_irm_lock);
		return;
	}

	/*
	 * Add the CPU to the IRM pool.
	 */

	/* increment the CPU count used by IRM */
	apix_irm_cpus_used++;

	/* Calculate the new pool size */
	new_pool_size = apix_irm_params.iparams_total +
	    apix_irminfo.apix_per_cpu_vectors;

	/* Apply the max. limit */
	if (apix_system_max_vectors > 0) {
		uint_t	max;

		max = apix_system_max_vectors -
		    apix_irm_fixed_intr_vectors_used -
		    apix_irm_cache_size;

		new_pool_size = MIN(new_pool_size, max);
	}
	if (new_pool_size == apix_irm_params.iparams_total) {
		/* no change to pool size */
		mutex_exit(&apix_irm_lock);
		return;
	}
	if (new_pool_size < apix_irm_params.iparams_total) {
		cmn_err(CE_WARN, "new_pool_size %d is inconsistent "
		    "with irm_params.iparams_total %d",
		    new_pool_size, apix_irm_params.iparams_total);
		mutex_exit(&apix_irm_lock);
		return;
	}

	(void) ndi_irm_resize_pool(apix_irm_pool_p, new_pool_size);

	/* update the pool size info */
	apix_irm_params.iparams_total = new_pool_size;

	mutex_exit(&apix_irm_lock);
}
