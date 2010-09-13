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

#include "dapl.h"
#include "dapl_mr_util.h"
#include <dapl_tavor_ibtf_impl.h>

DAT_RETURN
dapls_ib_lmr_sync_rdma_common(
	IN	DAT_IA_HANDLE ia_handle,
	IN 	const DAT_LMR_TRIPLET *lmr_triplet,
	IN	DAT_VLEN num_segments,
	IN	uint32_t op_type)
{
	DAPL_IA		*ia_ptr;
	DAPL_LMR	*lmr;
	DAT_RETURN	dat_status;
	dapl_mr_sync_t	args;
	int		i, j;
	int		retval;

	if (DAPL_BAD_HANDLE(ia_handle, DAPL_MAGIC_IA)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_IA));
	}

	ia_ptr = (DAPL_IA *)ia_handle;
	args.mrs_flags = op_type;

	for (i = 0, j = 0; i < num_segments; i++) {
		dat_status = dapls_hash_search(
		    ia_ptr->hca_ptr->lmr_hash_table,
		    lmr_triplet[i].lmr_context, (DAPL_HASH_DATA *)&lmr);

		if (dat_status != DAT_SUCCESS) {
			return (DAT_ERROR(DAT_INVALID_PARAMETER,
			    DAT_INVALID_ARG2));
		}

		dat_status = dapl_mr_bounds_check(
		    dapl_mr_get_address(lmr->param.region_desc,
		    lmr->param.mem_type),
		    lmr->param.length,
		    lmr_triplet[i].virtual_address,
		    lmr_triplet[i].segment_length);
		if (dat_status != DAT_TRUE) {
			return (DAT_ERROR(DAT_INVALID_PARAMETER,
			    DAT_INVALID_ARG2));
		}
		args.mrs_vec[j].mrsv_hkey = lmr->mr_handle->mr_hkey;
		args.mrs_vec[j].mrsv_va = lmr_triplet[i].virtual_address;
		args.mrs_vec[j].mrsv_len = lmr_triplet[i].segment_length;
		j = j + 1;
		args.mrs_numseg = j;
		if (j == DAPL_MR_PER_SYNC) {
			j = 0;
			retval = ioctl(ia_ptr->hca_ptr->ib_hca_handle->ia_fd,
			    DAPL_MR_SYNC, &args);

			if (retval != 0) {
				dapl_dbg_log(DAPL_DBG_TYPE_ERR,
				    "dapls_ib_lmr_sync: failed %s, retval %d\n",
				    strerror(errno), retval);
				return (dapls_convert_error(errno, retval));
			}
		}
	}

	if (j != 0) {
		retval = ioctl(ia_ptr->hca_ptr->ib_hca_handle->ia_fd,
		    DAPL_MR_SYNC, &args);
		if (retval != 0) {
			dapl_dbg_log(DAPL_DBG_TYPE_ERR,
			    "dapls_ib_lmr_sync: failed %s, retval %d\n",
			    strerror(errno), retval);
			return (dapls_convert_error(errno, retval));
		}
	}
	return (DAT_SUCCESS);
}
