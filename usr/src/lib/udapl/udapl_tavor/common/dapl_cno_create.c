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
 * MODULE: dapl_cno_create.c
 *
 * PURPOSE: Consumer Notification Object creation
 * Description: Interfaces in this file are completely described in
 *		the DAPL 1.1 API, Chapter 6, section 3.2.1
 *
 * $Id: dapl_cno_create.c,v 1.5 2003/06/16 17:53:32 sjs2 Exp $
 */

#include "dapl.h"
#include "dapl_cno_util.h"
#include "dapl_ia_util.h"
#include "dapl_adapter_util.h"

/*
 * dapl_cno_create
 *
 * DAPL Requirements Version xxx, 6.3.4.1
 *
 * Create a consumer notification object instance
 *
 * Input:
 *	ia_handle
 *	wait_agent
 *	cno_handle
 *
 * Output:
 *	cno_handle
 *
 * Returns:
 *	DAT_SUCCESS
 *	DAT_INSUFFICIENT_RESOURCES
 *	DAT_INVALID_HANDLE
 *	DAT_INVALID_PARAMETER
 */
DAT_RETURN dapl_cno_create(
	IN	DAT_IA_HANDLE			ia_handle,	/* ia_handle */
	IN	DAT_OS_WAIT_PROXY_AGENT		wait_agent,	/* agent */
	OUT	DAT_CNO_HANDLE			*cno_handle)	/* cno_handle */

{
	DAPL_IA		*ia_ptr;
	DAPL_CNO	*cno_ptr;
	DAT_RETURN	dat_status;

	ia_ptr = (DAPL_IA *)ia_handle;
	cno_ptr = NULL;
	dat_status = DAT_SUCCESS;

	if (DAPL_BAD_HANDLE(ia_handle, DAPL_MAGIC_IA)) {
		dat_status = DAT_ERROR(DAT_INVALID_HANDLE,
		    DAT_INVALID_HANDLE_IA);
		goto bail;
	}

	cno_ptr = dapl_cno_alloc(ia_ptr, wait_agent);

	if (!cno_ptr) {
		dat_status = DAT_ERROR(DAT_INSUFFICIENT_RESOURCES,
		    DAT_RESOURCE_MEMORY);
		goto bail;
	}

	cno_ptr->cno_state = DAPL_CNO_STATE_UNTRIGGERED;

	dat_status = dapls_ib_cno_alloc(ia_ptr, cno_ptr);
	if (dat_status != DAT_SUCCESS) {
		goto bail;
	}

	dapl_ia_link_cno(ia_ptr, cno_ptr);

	*cno_handle = cno_ptr;

bail:
	if (dat_status != DAT_SUCCESS && cno_ptr != NULL) {
		dapl_cno_dealloc(cno_ptr);
	}
	return (dat_status);
}
