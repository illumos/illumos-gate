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
 * MODULE: dapl_evd_create.c
 *
 * PURPOSE: EVENT management
 *
 * Description: Interfaces in this file are completely defined in
 * 		the uDAPL 1.1 API, Chapter 6, section 3
 *
 * $Id: dapl_evd_create.c,v 1.12 2003/08/06 14:04:27 sjs2 Exp $
 */

#include "dapl.h"
#include "dapl_evd_util.h"

/*
 * dapl_evd_create
 *
 * DAPL Requirements Version xxx, 6.3.2.1
 *
 * Create and instance of Event Dispatcher.
 *
 * Input:
 *    ia_handle
 *    cno_handle
 *    evd_min_qlen
 *    evd_flags
 *
 * Output:
 *    evd_handle
 *
 * Returns:
 *     DAT_SUCCESS
 *     DAT_INSUFFICIENT_RESOURCES
 *     DAT_INVALID_PARAMETER
 */

/*
 * ** REVISIT **
 *
 * Selecting the cqe handing domain must still be done.
 * We *probably* want one per hca, but we could have one
 * per provider or one per consumer.
 */
/*
 * Note that if there already is a cq, it is not deleted
 * even if it is not required. However, it will not be armed.
 */

DAT_RETURN dapl_evd_create(
    IN    DAT_IA_HANDLE		ia_handle,
    IN    DAT_COUNT		evd_min_qlen,
    IN    DAT_CNO_HANDLE	cno_handle,
    IN    DAT_EVD_FLAGS		evd_flags,
    OUT   DAT_EVD_HANDLE	*evd_handle)
{
	DAPL_IA			*ia_ptr;
	DAPL_EVD		*evd_ptr;
	DAPL_CNO		*cno_ptr;
	DAT_RETURN		dat_status;
	DAT_PROVIDER_ATTR	provider_attr = {0};
	int			i;
	int			j;
	DAT_EVD_FLAGS		mask[6] = {DAT_EVD_SOFTWARE_FLAG,
	    DAT_EVD_CR_FLAG, DAT_EVD_DTO_FLAG, DAT_EVD_CONNECTION_FLAG,
	    DAT_EVD_RMR_BIND_FLAG, DAT_EVD_ASYNC_FLAG};

	dapl_dbg_log(DAPL_DBG_TYPE_API,
	    "dapl_evd_create (%p, %d, %p, 0x%x, %p)\n",
	    ia_handle,
	    evd_min_qlen,
	    cno_handle,
	    evd_flags,
	    evd_handle);

	ia_ptr		= (DAPL_IA *)ia_handle;
	cno_ptr		= (DAPL_CNO *)cno_handle;
	evd_ptr		= NULL;
	*evd_handle	= NULL;
	dat_status	= DAT_SUCCESS;

	if (DAPL_BAD_HANDLE(ia_handle, DAPL_MAGIC_IA)) {
		dat_status = DAT_ERROR(DAT_INVALID_HANDLE,
		    DAT_INVALID_HANDLE_IA);
		goto bail;
	}

	if (evd_min_qlen <= 0) {
		dat_status = DAT_ERROR(DAT_INVALID_PARAMETER, DAT_INVALID_ARG2);
		goto bail;
	}
	if (evd_min_qlen > ia_ptr->hca_ptr->ia_attr.max_evd_qlen) {
		dat_status = DAT_ERROR(DAT_INSUFFICIENT_RESOURCES,
		    DAT_RESOURCE_TEVD);
		goto bail;
	}

	if ((cno_handle != DAT_HANDLE_NULL) &&
	    DAPL_BAD_HANDLE(cno_handle, DAPL_MAGIC_CNO)) {
		dat_status = DAT_ERROR(DAT_INVALID_HANDLE,
		    DAT_INVALID_HANDLE_CNO);
		goto bail;
	}

	/*
	 * Check the merging attributes to ensure the combination of
	 * flags requested is supported.
	 */
	(void) dapl_ia_query(ia_handle, NULL,
	    0, NULL,
	    DAT_PROVIDER_FIELD_ALL, &provider_attr);


	for (i = 0; i < 6; i++) {
		if (mask[i] & evd_flags) {
			for (j = i; j < 6; j++) {
				if (mask[j] & evd_flags) {
					if (provider_attr.
					    evd_stream_merging_supported[i][j]
					    == DAT_FALSE) {
						dat_status = DAT_ERROR(
						    DAT_INVALID_PARAMETER,
						    DAT_INVALID_ARG4);
						goto bail;
					}
				}
			} /* end for j */
		}
	} /* end for i */

	dat_status = dapls_evd_internal_create(ia_ptr,
	    cno_ptr,
	    evd_min_qlen,
	    evd_flags,
	    &evd_ptr);
	if (dat_status != DAT_SUCCESS) {
		goto bail;
	}

	evd_ptr->evd_state = DAPL_EVD_STATE_OPEN;

	*evd_handle = (DAT_EVD_HANDLE) evd_ptr;

bail:
	if (dat_status != DAT_SUCCESS) {
		if (evd_ptr) {
			(void) dapl_evd_free(evd_ptr);
		}
	}

	dapl_dbg_log(DAPL_DBG_TYPE_RTN,
	    "dapl_evd_create () returns 0x%x\n",
	    dat_status);

	return (dat_status);
}
