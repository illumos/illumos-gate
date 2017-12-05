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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *
 * MODULE: dapl_rmr_create.c
 *
 * PURPOSE: Memory management
 * Description: Interfaces in this file are completely described in
 *		the DAPL 1.1 API, Chapter 6, section 6
 *
 */

#include "dapl_rmr_util.h"
#include "dapl_adapter_util.h"

/*
 * dapl_rmr_create
 *
 * DAPL Requirements Version xxx, 6.6.4.1
 *
 * Create a remote memory region for the specified protection zone
 *
 * Input:
 * 	pz_handle
 *
 * Output:
 * 	rmr_handle
 *
 * Returns:
 * 	DAT_SUCCESS
 * 	DAT_INSUFFICIENT_RESOURCES
 * 	DAT_INVALID_PARAMETER
 */
DAT_RETURN
dapl_rmr_create(IN DAT_PZ_HANDLE pz_handle,
    OUT DAT_RMR_HANDLE * rmr_handle)
{
	DAPL_PZ *pz;
	DAPL_RMR *rmr;
	DAT_RETURN dat_status;

	dat_status = DAT_SUCCESS;

	if (DAPL_BAD_HANDLE(pz_handle, DAPL_MAGIC_PZ)) {
		dat_status = DAT_ERROR(DAT_INVALID_HANDLE,
		    DAT_INVALID_HANDLE_PZ);
		goto bail;
	}

	pz = (DAPL_PZ *) pz_handle;

	rmr = dapl_rmr_alloc(pz);

	if (rmr == NULL) {
		dat_status = DAT_ERROR(DAT_INSUFFICIENT_RESOURCES,
		    DAT_RESOURCE_MEMORY);
		goto bail;
	}

	dat_status = dapls_ib_mw_alloc(rmr);

	if (dat_status != DAT_SUCCESS) {
		dapl_rmr_dealloc(rmr);
		dat_status = DAT_ERROR(DAT_INSUFFICIENT_RESOURCES,
		    DAT_RESOURCE_MEMORY_REGION);
		goto bail;
	}

	dapl_os_atomic_inc(&pz->pz_ref_count);

	*rmr_handle = rmr;

bail:
	return (dat_status);
}
