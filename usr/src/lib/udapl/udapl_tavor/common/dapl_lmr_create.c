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
 * Copyright (c) 2002-2003, Network Appliance, Inc. All rights reserved.
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 *
 * MODULE: dapl_lmr_create.c
 *
 * PURPOSE: Memory management
 * Description: Interfaces in this file are completely described in
 *		the DAPL 1.1 API, Chapter 6, section 6
 *
 */

#include <dat/udat.h>
#include <dapl_lmr_util.h>
#include <dapl_adapter_util.h>
#include <libdevinfo.h>

/*
 * Function Prototypes
 */

static DAT_RETURN
dapl_lmr_create_virtual(IN DAPL_IA *ia,
    IN DAT_PVOID virt_addr,
    IN DAT_VLEN length,
    IN DAT_LMR_COOKIE shm_cookie,
    IN DAPL_PZ *pz,
    IN DAT_MEM_PRIV_FLAGS privileges,
    OUT DAT_LMR_HANDLE *lmr_handle,
    OUT DAT_LMR_CONTEXT *lmr_context,
    OUT DAT_RMR_CONTEXT *rmr_context,
    OUT DAT_VLEN *registered_length,
    OUT DAT_VADDR *registered_address);

static DAT_RETURN
dapl_lmr_create_lmr(IN DAPL_IA *ia,
    IN DAPL_LMR *original_lmr,
    IN DAPL_PZ *pz,
    IN DAT_MEM_PRIV_FLAGS privileges,
    OUT DAT_LMR_HANDLE *lmr_handle,
    OUT DAT_LMR_CONTEXT *lmr_context,
    OUT DAT_RMR_CONTEXT *rmr_context,
    OUT DAT_VLEN *registered_length,
    OUT DAT_VADDR *registered_address);

/*
 * Function Definitions
 */

static DAT_RETURN
dapl_lmr_create_virtual(IN DAPL_IA *ia,
    IN DAT_PVOID virt_addr,
    IN DAT_VLEN length,
    IN DAT_LMR_COOKIE shm_cookie,
    IN DAPL_PZ *pz,
    IN DAT_MEM_PRIV_FLAGS privileges,
    OUT DAT_LMR_HANDLE *lmr_handle,
    OUT DAT_LMR_CONTEXT *lmr_context,
    OUT DAT_RMR_CONTEXT *rmr_context,
    OUT DAT_VLEN *registered_length,
    OUT DAT_VADDR *registered_address)
{
	DAPL_LMR *lmr;
	DAT_REGION_DESCRIPTION reg_desc;
	DAT_RETURN dat_status;

	reg_desc.for_va = virt_addr;
	dat_status = DAT_SUCCESS;

	lmr = dapl_lmr_alloc(ia, DAT_MEM_TYPE_VIRTUAL,
	    reg_desc, length, (DAT_PZ_HANDLE) pz, privileges);

	if (NULL == lmr) {
		dat_status = DAT_ERROR(DAT_INSUFFICIENT_RESOURCES,
		    DAT_RESOURCE_MEMORY);
		goto bail;
	}

	if (shm_cookie == NULL) {
		dat_status = dapls_ib_mr_register(ia, lmr, virt_addr,
		    length, privileges);
	} else {
		dat_status = dapls_ib_mr_register_shared(ia, lmr, virt_addr,
		    length, shm_cookie, privileges);
	}

	if (DAT_SUCCESS != dat_status) {
		dapl_lmr_dealloc(lmr);
		goto bail;
	}

	/* if the LMR context is already in the hash table */
	dat_status = dapls_hash_search(ia->hca_ptr->lmr_hash_table,
	    lmr->param.lmr_context, NULL);
	if (dat_status == DAT_SUCCESS) {
		(void) dapls_ib_mr_deregister(lmr);
		dapl_lmr_dealloc(lmr);

		dat_status = DAT_ERROR(DAT_INVALID_STATE,
		    DAT_INVALID_STATE_LMR_IN_USE);
		goto bail;
	}

	dat_status = dapls_hash_insert(ia->hca_ptr->lmr_hash_table,
	    lmr->param.lmr_context, lmr);
	if (dat_status != DAT_SUCCESS) {
		(void) dapls_ib_mr_deregister(lmr);
		dapl_lmr_dealloc(lmr);
		/*
		 * The value returned by dapls_hash_insert(.) is not
		 * returned to the consumer because the spec. requires
		 * that dat_lmr_create(.) return only certain values.
		 */
		dat_status = DAT_ERROR(DAT_INSUFFICIENT_RESOURCES,
		    DAT_RESOURCE_MEMORY);
		goto bail;
	}

	dapl_os_atomic_inc(&pz->pz_ref_count);

	if (NULL != lmr_handle) {
		*lmr_handle = (DAT_LMR_HANDLE) lmr;
	}
	if (NULL != lmr_context) {
		*lmr_context = lmr->param.lmr_context;
	}
	if (NULL != rmr_context) {
		*rmr_context = lmr->param.rmr_context;
	}
	if (NULL != registered_length) {
		*registered_length = lmr->param.registered_size;
	}
	if (NULL != registered_address) {
		*registered_address = lmr->param.registered_address;
	}

bail:
	return (dat_status);
}


static DAT_RETURN
dapl_lmr_create_lmr(IN DAPL_IA *ia,
    IN DAPL_LMR *original_lmr,
    IN DAPL_PZ *pz,
    IN DAT_MEM_PRIV_FLAGS privileges,
    OUT DAT_LMR_HANDLE *lmr_handle,
    OUT DAT_LMR_CONTEXT *lmr_context,
    OUT DAT_RMR_CONTEXT *rmr_context,
    OUT DAT_VLEN *registered_length,
    OUT DAT_VADDR *registered_address)
{
	DAPL_LMR *lmr;
	DAT_REGION_DESCRIPTION reg_desc;
	DAT_RETURN dat_status;

	dapl_dbg_log(DAPL_DBG_TYPE_API,
	    "dapl_lmr_create_lmr (%p, %p, %p, %x, %p, %p, %p, %p)\n",
	    ia,
	    original_lmr,
	    pz, privileges,
	    lmr_handle,
	    lmr_context, registered_length, registered_address);

	dat_status = dapls_hash_search(ia->hca_ptr->lmr_hash_table,
	    original_lmr->param.lmr_context,
	    (DAPL_HASH_DATA *) & lmr);
	if (dat_status != DAT_SUCCESS) {
		dat_status = DAT_ERROR(DAT_INVALID_PARAMETER,
		    DAT_INVALID_ARG2);
		goto bail;
	}

	reg_desc.for_lmr_handle = (DAT_LMR_HANDLE) original_lmr;

	lmr = dapl_lmr_alloc(ia, DAT_MEM_TYPE_LMR, reg_desc, 0,
	    (DAT_PZ_HANDLE) pz, privileges);

	if (NULL == lmr) {
		dat_status = DAT_ERROR(DAT_INSUFFICIENT_RESOURCES,
		    DAT_RESOURCE_MEMORY);
		goto bail;
	}

	dat_status = dapls_ib_mr_register_lmr(ia, lmr, privileges);

	if (DAT_SUCCESS != dat_status) {
		dapl_lmr_dealloc(lmr);
		goto bail;
	}

	/* if the LMR context is already in the hash table */
	dat_status = dapls_hash_search(ia->hca_ptr->lmr_hash_table,
	    lmr->param.lmr_context, NULL);
	if (dat_status == DAT_SUCCESS) {
		(void) dapls_ib_mr_deregister(lmr);
		dapl_lmr_dealloc(lmr);

		dat_status = DAT_ERROR(DAT_INVALID_STATE,
		    DAT_INVALID_STATE_LMR_IN_USE);
		goto bail;
	}

	dat_status = dapls_hash_insert(ia->hca_ptr->lmr_hash_table,
	    lmr->param.lmr_context, lmr);
	if (dat_status != DAT_SUCCESS) {
		(void) dapls_ib_mr_deregister(lmr);
		dapl_lmr_dealloc(lmr);

		/*
		 * The value returned by dapls_hash_insert(.) is not
		 * returned to the consumer because the spec. requires
		 * that dat_lmr_create(.) return only certain values.
		 */
		dat_status = DAT_ERROR(DAT_INSUFFICIENT_RESOURCES,
		    DAT_RESOURCE_MEMORY);
		goto bail;
	}

	dapl_os_atomic_inc(&pz->pz_ref_count);

	if (NULL != lmr_handle) {
		*lmr_handle = (DAT_LMR_HANDLE)lmr;
	}
	if (NULL != lmr_context) {
		*lmr_context = lmr->param.lmr_context;
	}
	if (NULL != rmr_context) {
		*rmr_context = lmr->param.rmr_context;
	}
	if (NULL != registered_length) {
		*registered_length = original_lmr->param.registered_size;
	}
	if (NULL != registered_address) {
		*registered_address = original_lmr->param.registered_address;
	}

bail:
	return (dat_status);
}


/*
 * dapl_lmr_create
 *
 * DAPL Requirements Version xxx, 6.6.3.1
 *
 * Register a memory region with an Interface Adaptor.
 *
 * Input:
 *	ia_handle
 *	mem_type
 *	region_description
 *	length
 *	pz_handle
 *	privileges
 *
 * Output:
 *	lmr_handle
 *	lmr_context
 *	registered_length
 *	registered_address
 *
 * Returns:
 * 	DAT_SUCCESS
 * 	DAT_INSUFFICIENT_RESOURCES
 * 	DAT_INVALID_PARAMETER
 * 	DAT_INVALID_STATE
 * 	DAT_MODEL_NOT_SUPPORTED
 *
 */
DAT_RETURN
dapl_lmr_create(IN DAT_IA_HANDLE ia_handle,
    IN DAT_MEM_TYPE mem_type,
    IN DAT_REGION_DESCRIPTION region_description,
    IN DAT_VLEN length,
    IN DAT_PZ_HANDLE pz_handle,
    IN DAT_MEM_PRIV_FLAGS privileges,
    OUT DAT_LMR_HANDLE *lmr_handle,
    OUT DAT_LMR_CONTEXT *lmr_context,
    OUT DAT_RMR_CONTEXT *rmr_context,
    OUT DAT_VLEN *registered_length,
    OUT DAT_VADDR *registered_address)
{
	DAPL_IA *ia;
	DAPL_PZ *pz;

	if (DAPL_BAD_HANDLE(ia_handle, DAPL_MAGIC_IA) ||
	    DAPL_BAD_HANDLE(pz_handle, DAPL_MAGIC_PZ)) {
		return (DAT_INVALID_HANDLE);
	}

	if (length == 0) {
		return (DAT_ERROR(DAT_INVALID_PARAMETER, DAT_INVALID_ARG4));
	}

	ia = (DAPL_IA *) ia_handle;
	pz = (DAPL_PZ *) pz_handle;

	/* Always ignore this bit as it is passed in */
	privileges &= ~DAT_MEM_PRIV_RO_DISABLE_FLAG;

	/*
	 * If at open time we determined that RO should not be used,
	 * note it here.
	 */
	if (ia->dapl_flags & DAPL_DISABLE_RO)
		privileges |= DAT_MEM_PRIV_RO_DISABLE_FLAG;

	switch (mem_type) {
	case DAT_MEM_TYPE_SO_VIRTUAL:
		privileges |= DAT_MEM_PRIV_RO_DISABLE_FLAG;
		/* FALLTHROUGH */
	case DAT_MEM_TYPE_VIRTUAL:
		return (dapl_lmr_create_virtual(ia, region_description.for_va,
		    length, NULL, pz, privileges,
		    lmr_handle, lmr_context,
		    rmr_context, registered_length,
		    registered_address));
		/* NOTREACHED */
	case DAT_MEM_TYPE_LMR: {
		DAPL_LMR *lmr;

		if (DAPL_BAD_HANDLE
		    (region_description.for_lmr_handle, DAPL_MAGIC_LMR)) {
			return (DAT_INVALID_HANDLE);
		}

		lmr = (DAPL_LMR *)region_description.for_lmr_handle;

		return (dapl_lmr_create_lmr(ia, lmr, pz, privileges, lmr_handle,
		    lmr_context, rmr_context,
		    registered_length, registered_address));
		/* NOTREACHED */
	}
	case DAT_MEM_TYPE_SHARED_VIRTUAL:
		return (dapl_lmr_create_virtual(ia,
		    region_description.
		    for_shared_memory.virtual_address,
		    length,
		    region_description.
		    for_shared_memory.shared_memory_id,
		    pz, privileges, lmr_handle,
		    lmr_context, rmr_context,
		    registered_length,
		    registered_address));
		/* NOTREACHED */
	default:
		return (DAT_INVALID_PARAMETER);
	}
}
