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
 * MODULE: dapl_get_handle_type.c
 *
 * PURPOSE: Interface Adapter management
 * Description: Interfaces in this file are completely described in
 *		the DAPL 1.1 API, Chapter 6, section 2
 *
 */

#include "dapl.h"

/*
 * dapl_get_handle_type
 *
 * DAPL Requirements Version xxx, 6.2.2.6
 *
 * Gets the handle type for the given dat_handle
 *
 * Input:
 * 	dat_handle
 *
 * Output:
 * 	handle_type
 *
 * Returns:
 * 	DAT_SUCCESS
 * 	DAT_INVALID_PARAMETER
 */
DAT_RETURN
dapl_get_handle_type(
	IN	DAT_HANDLE		dat_handle,
	OUT	DAT_HANDLE_TYPE		*handle_type)
{
	DAT_RETURN	dat_status;
	DAPL_HEADER	*header;

	dat_status = DAT_SUCCESS;

	header = (DAPL_HEADER *)dat_handle;
	if (((header) == NULL) ||
	    ((unsigned long)(header) & 3) ||
	    (header->magic != DAPL_MAGIC_IA &&
	    header->magic != DAPL_MAGIC_EVD &&
	    header->magic != DAPL_MAGIC_EP &&
	    header->magic != DAPL_MAGIC_LMR &&
	    header->magic != DAPL_MAGIC_RMR &&
	    header->magic != DAPL_MAGIC_PZ &&
	    header->magic != DAPL_MAGIC_PSP &&
	    header->magic != DAPL_MAGIC_RSP &&
	    header->magic != DAPL_MAGIC_CR)) {
		dat_status = DAT_ERROR(DAT_INVALID_HANDLE, 0);
		goto bail;
	}
	*handle_type = header->handle_type;

bail:
	return (dat_status);
}
