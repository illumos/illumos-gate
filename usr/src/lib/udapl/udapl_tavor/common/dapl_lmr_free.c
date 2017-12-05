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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *
 * MODULE: dapl_lmr_free.c
 *
 * PURPOSE: Memory management
 * Description: Interfaces in this file are completely described in
 *		the DAPL 1.1 API, Chapter 6, section 6
 *
 */

#include "dapl_lmr_util.h"
#include "dapl_adapter_util.h"
#include "dapl_ia_util.h"

/*
 * dapl_lmr_free
 *
 * DAPL Requirements Version xxx, 6.6.3.2
 *
 * Destroy an instance of the Local Memory Region
 *
 * Input:
 * 	lmr_handle
 *
 * Output:
 *
 * Returns:
 * 	DAT_SUCCESS
 *      DAT_INVALID_HANDLE
 * 	DAT_INVALID_PARAMETER
 * 	DAT_INVALID_STATE
 */

DAT_RETURN
dapl_lmr_free(IN DAT_LMR_HANDLE lmr_handle)
{
	DAPL_LMR *lmr;
	DAT_RETURN dat_status;

	dapl_dbg_log(DAPL_DBG_TYPE_API, "dapl_lmr_free (%p)\n", lmr_handle);

	if (DAPL_BAD_HANDLE(lmr_handle, DAPL_MAGIC_LMR)) {
		dat_status = DAT_ERROR(DAT_INVALID_HANDLE,
		    DAT_INVALID_HANDLE_LMR);
		goto bail;
	}

	lmr = (DAPL_LMR *)lmr_handle;

	switch (lmr->param.mem_type) {
	case DAT_MEM_TYPE_VIRTUAL:
	/* fall through */
	case DAT_MEM_TYPE_LMR: {
		DAPL_PZ *pz;

		if (0 != lmr->lmr_ref_count) {
			return (DAT_INVALID_STATE);
		}

		dat_status = dapls_hash_remove(
		    lmr->header.owner_ia->hca_ptr->lmr_hash_table,
		    lmr->param.lmr_context, NULL);
		if (dat_status != DAT_SUCCESS) {
			goto bail;
		}

		dat_status = dapls_ib_mr_deregister(lmr);

		if (dat_status == DAT_SUCCESS) {
			pz = (DAPL_PZ *) lmr->param.pz_handle;
			dapl_os_atomic_dec(&pz->pz_ref_count);

			dapl_lmr_dealloc(lmr);
		} else {
		/*
		 * Deregister failed; put it back in the
		 * hash table.
		 */
		(void) dapls_hash_insert(lmr->header.owner_ia->
		    hca_ptr->lmr_hash_table,
		    lmr->param.lmr_context, lmr);
		}
		break;
	}
	case DAT_MEM_TYPE_SHARED_VIRTUAL: {
		dat_status = DAT_ERROR(DAT_NOT_IMPLEMENTED, 0);
		break;
	}
	default:
		dat_status = DAT_ERROR(DAT_INVALID_PARAMETER,
		    DAT_INVALID_ARG1);
		break;
	}
bail:
	return (dat_status);
}
