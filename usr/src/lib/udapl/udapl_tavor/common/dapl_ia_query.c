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
 * MODULE: dapl_ia_query.c
 *
 * PURPOSE: Interface Adapter management
 * Description: Interfaces in this file are completely described in
 *		the DAPL 1.1 API, Chapter 6, section 2
 *
 * $Id: dapl_ia_query.c,v 1.20 2003/08/06 14:04:27 sjs2 Exp $
 */

#include "dapl.h"
#include "dapl_adapter_util.h"
#include "dapl_vendor.h"

/*
 * dapl_ia_query
 *
 * DAPL Requirements Version xxx, 6.2.1.3
 *
 * Provide the consumer with Interface Adapter and Provider parameters.
 *
 * Input:
 *	ia_handle
 *	ia_mask
 *	provider_mask
 *
 * Output:
 *	async_evd_handle
 *	ia_parameters
 *	provider_parameters
 *
 * Returns:
 * 	DAT_SUCCESS
 * 	DAT_INVALID_PARAMETER
 */
DAT_RETURN
dapl_ia_query(
	IN	DAT_IA_HANDLE			ia_handle,
	OUT	DAT_EVD_HANDLE			*async_evd_handle,
	IN	DAT_IA_ATTR_MASK		ia_attr_mask,
	OUT	DAT_IA_ATTR			*ia_attr,
	IN	DAT_PROVIDER_ATTR_MASK		provider_attr_mask,
	OUT	DAT_PROVIDER_ATTR		*provider_attr)
{
	DAPL_IA		*ia_ptr;
	DAT_RETURN	dat_status;
	struct evd_merge_type {
		DAT_BOOLEAN		array[6][6];
	} *evd_merge;
	int		i;
	int		j;

	dapl_dbg_log(DAPL_DBG_TYPE_API,
	    "dapl_ia_query (%p, %p, 0x%x, %p, 0x%x, %p)\n",
	    ia_handle,
	    async_evd_handle,
	    ia_attr_mask,
	    ia_attr,
	    provider_attr_mask,
	    provider_attr);

	ia_ptr = (DAPL_IA *)ia_handle;
	dat_status = DAT_SUCCESS;

	if (DAPL_BAD_HANDLE(ia_ptr, DAPL_MAGIC_IA)) {
		dat_status = DAT_ERROR(DAT_INVALID_HANDLE,
		    DAT_INVALID_HANDLE_IA);
		goto bail;
	}

	if (NULL != async_evd_handle) {
		*async_evd_handle = ia_ptr->async_error_evd;
	}

	if (ia_attr_mask & DAT_IA_ALL) {
		if (NULL == ia_attr) {
			dat_status = DAT_ERROR(DAT_INVALID_PARAMETER,
			    DAT_INVALID_ARG4);
			goto bail;
		}

		/*
		 * Obtain parameters from the HCA.  Protect against multiple
		 * IAs beating on the HCA at the same time.
		 */
		dat_status = dapls_ib_query_hca(ia_ptr->hca_ptr, ia_attr, NULL,
		    NULL, NULL);
		if (dat_status != DAT_SUCCESS) {
			goto bail;
		}
	}

	if (ia_attr_mask & ~DAT_IA_ALL) {
		dat_status = DAT_ERROR(DAT_INVALID_PARAMETER, DAT_INVALID_ARG3);
		goto bail;
	}

	if (provider_attr_mask & DAT_PROVIDER_FIELD_ALL) {
		if (NULL == provider_attr) {
			dat_status = DAT_ERROR(DAT_INVALID_PARAMETER,
			    DAT_INVALID_ARG6);
			goto bail;
		}

		(void) dapl_os_strncpy(provider_attr->provider_name,
		    ia_ptr->header.provider->device_name,
		    DAT_NAME_MAX_LENGTH);
		provider_attr->provider_version_major	  = VN_PROVIDER_MAJOR;
		provider_attr->provider_version_minor	  = VN_PROVIDER_MINOR;
		provider_attr->dapl_version_major	  = DAT_VERSION_MAJOR;
		provider_attr->dapl_version_minor	  = DAT_VERSION_MINOR;
		provider_attr->lmr_mem_types_supported	  =
		    DAT_MEM_TYPE_VIRTUAL | DAT_MEM_TYPE_LMR;
#if VN_MEM_SHARED_VIRTUAL_SUPPORT > 0
		provider_attr->lmr_mem_types_supported	 |=
		    DAT_MEM_TYPE_SHARED_VIRTUAL;
#endif
		provider_attr->iov_ownership_on_return	  = DAT_IOV_CONSUMER;
		provider_attr->dat_qos_supported	  = DAT_QOS_BEST_EFFORT;
		provider_attr->completion_flags_supported =
		    DAT_COMPLETION_DEFAULT_FLAG;
		provider_attr->is_thread_safe		  = DAT_FALSE;
		provider_attr->max_private_data_size	  =
		    DAPL_CONSUMER_MAX_PRIVATE_DATA_SIZE;
		provider_attr->supports_multipath	  = DAT_TRUE;
		provider_attr->ep_creator		  =
		    DAT_PSP_CREATES_EP_NEVER;
		provider_attr->optimal_buffer_alignment   =
		    DAT_OPTIMAL_ALIGNMENT;
		provider_attr->num_provider_specific_attr = 0;
		provider_attr->srq_supported = DAT_TRUE;
		/*
		 * 0x000 no watermarks support
		 * 0x001 low watermark support
		 * 0x010 soft high watermark support
		 * 0x100 hard high watermark support
		 */
		provider_attr->srq_watermarks_supported = 0x00;
		provider_attr->srq_ep_pz_difference_supported = DAT_FALSE;
		/*
		 * 0x01 available_dto_count
		 * 0x10 outstanding_dto_count
		 */
		provider_attr->srq_info_supported = 0x10;
		/*
		 * 0x00 no ep recv info support
		 * 0x01 nbufs_allocated returned from dat_ep_recv_query
		 * 0x10 bufs_alloc_span returned from dat_ep_recv_query
		 */
		provider_attr->ep_recv_info_supported = 0;
		/*
		 * we want the application to use the lmr_sync_rdma
		 * as a programming model and thus always true from the
		 * provider perspective. dat_registry will return success
		 * to consumers on platforms with coherent memory
		 */
		provider_attr->lmr_sync_req = DAT_TRUE;
		provider_attr->dto_async_return_guaranteed = DAT_FALSE;
		provider_attr->rdma_write_for_rdma_read_req = DAT_FALSE;
		provider_attr->provider_specific_attr	  = NULL;
		/*
		 * Set up evd_stream_merging_supported options. Note there is
		 * one bit per allowable combination, using the ordinal
		 * position of the DAT_EVD_FLAGS as positions in the
		 * array. e.g.
		 * [0][0] is DAT_EVD_SOFTWARE_FLAG | DAT_EVD_SOFTWARE_FLAG,
		 * [0][1] is DAT_EVD_SOFTWARE_FLAG | DAT_EVD_CR_FLAG, and
		 * [2][4] is DAT_EVD_DTO_FLAG | DAT_EVD_RMR_BIND_FLAG
		 *
		 * Most combinations are true, so initialize the array that way.
		 * Then finish by resetting the bad combinations.
		 */

		evd_merge = (struct evd_merge_type *)&provider_attr->
		    evd_stream_merging_supported[0][0];
		for (i = 0; i < 6; i++) {
			for (j = 0; j < 6; j++) {
				if (j == 5 || i == 5) {
					/* DAT_EVD_ASYNC_FLAG is disallowed */
					evd_merge->array[i][j] = DAT_FALSE;
				} else {
					evd_merge->array[i][j] = DAT_TRUE;
				}
			}
		}
	}

bail:
	dapl_dbg_log(DAPL_DBG_TYPE_RTN,
	    "dapl_ia_query () returns 0x%x\n",
	    dat_status);

	return (dat_status);
}

/*
 * Local variables:
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 8
 * End:
 */
