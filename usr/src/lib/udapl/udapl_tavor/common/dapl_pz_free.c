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
 * MODULE: dapl_pz_create.c
 *
 * PURPOSE: Memory management
 * Description: Interfaces in this file are completely described in
 *		the DAPL 1.1 API, Chapter 6, section 6
 *
 * $Id: dapl_pz_free.c,v 1.9 2003/07/30 18:13:40 hobie16 Exp $
 */

#include "dapl.h"
#include "dapl_pz_util.h"
#include "dapl_adapter_util.h"
#include "dapl_ia_util.h"

/*
 * dapl_pz_free
 *
 * DAPL Requirements Version xxx, 6.6.2.1
 *
 * Remove an instance of a protection zone
 *
 * Input:
 * 	pz_handle
 *
 * Output:
 * 	None.
 *
 * Returns:
 * 	DAT_SUCCESS
 * 	DAT_INVALID_PARAMETER
 * 	DAT_INVALID_STATE
 */
DAT_RETURN
dapl_pz_free(
	IN	DAT_PZ_HANDLE	pz_handle)
{
	DAPL_PZ		*pz;
	DAT_RETURN	dat_status;

	dapl_dbg_log(DAPL_DBG_TYPE_API, "dapl_pz_free(%p)\n", pz_handle);

	dat_status = DAT_SUCCESS;
	if (DAPL_BAD_HANDLE(pz_handle, DAPL_MAGIC_PZ)) {
		dat_status = DAT_ERROR(DAT_INVALID_HANDLE,
		    DAT_INVALID_HANDLE_PZ);
		goto bail;
	}

	pz = (DAPL_PZ *)pz_handle;

	if (0 != pz->pz_ref_count) {
		dat_status = DAT_ERROR(DAT_INVALID_STATE,
		    DAT_INVALID_STATE_PZ_IN_USE);
		goto bail;
	}

	dat_status = dapls_ib_pd_free(pz);

	if (dat_status == DAT_SUCCESS) {
		dapl_pz_dealloc(pz);
	}

bail:
	return (dat_status);
}
