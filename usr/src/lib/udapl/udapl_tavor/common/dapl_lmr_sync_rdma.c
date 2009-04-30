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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *
 * MODULE: dapl_lmr_sync_rdma.c
 *
 * PURPOSE: Non-coherent Memory Support
 * Description: Interfaces in this file are completely described in
 *		the DAPL 1.2 API, Chapter 6, section 7
 *
 */

#include "dapl.h"
#include "dapl_adapter_util.h"

/*
 * dapl_lmr_sync_rdma_read
 *
 * uDAPL: User Direct Access Program Library Version 1.2, 6.7.4.1
 *
 * make memory changes visible to an incoming RDMA Read operation.
 * This operation guarantees consistency by locally flushing the non-coherent
 * cache prior to it being retrieved by remote peer RDMA read operation(s)
 *
 * Input:
 * 	ia_handle
 * 	local_segments
 * 	num_segments
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 * 	DAT_INVALID_HANDLE
 * 	DAT_INVALID_PARAMETER
 */

DAT_RETURN
dapl_lmr_sync_rdma_read(
	IN	DAT_IA_HANDLE ia_handle,
	IN 	const DAT_LMR_TRIPLET *local_segments,
	IN	DAT_VLEN num_segments)
{
	return (dapls_ib_lmr_sync_rdma_common(ia_handle, local_segments,
	    num_segments, DAPL_MR_SYNC_RDMA_RD));
}

/*
 * dapl_lmr_sync_rdma_write
 *
 * uDAPL: User Direct Access Program Library Version 1.2, 6.7.4.1
 *
 * make effects of an incoming RDMA Write operation visible to Consumer.
 * This operation guarantees consistency by locally invalidating the
 * non-coherent cache whose buffer has been populated by remote peer
 * RDMA write operation(s).
 *
 * Input:
 * 	ia_handle
 * 	local_segments
 * 	num_segments
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 * 	DAT_INVALID_HANDLE
 * 	DAT_INVALID_PARAMETER
 */

DAT_RETURN
dapl_lmr_sync_rdma_write(
	IN	DAT_IA_HANDLE ia_handle,
	IN 	const DAT_LMR_TRIPLET *local_segments,
	IN	DAT_VLEN num_segments)
{
	return (dapls_ib_lmr_sync_rdma_common(ia_handle, local_segments,
	    num_segments, DAPL_MR_SYNC_RDMA_WR));
}
