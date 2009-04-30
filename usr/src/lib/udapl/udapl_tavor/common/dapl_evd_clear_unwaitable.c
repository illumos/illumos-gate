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
 * MODULE: dapl_evd_clear_unwaitable.c
 *
 * PURPOSE: EVENT management
 * Description: Interfaces in this file are completely described in
 *		the DAPL 1.1 API, Chapter 6, section 3.4.8
 *
 * $Id: dapl_evd_clear_unwaitable.c,v 1.2 2003/08/20 13:18:36 sjs2 Exp $
 */

#include "dapl.h"

/*
 * dapl_evd_clear_unwaitable
 *
 * DAPL Requirements Version 1.1, 6.3.4.8
 *
 * Transition the Event Dispatcher into a waitable state
 *
 * Input:
 * 	evd_handle
 *
 * Output:
 *	none
 *
 * Returns:
 *	DAT_SUCCESS
 *	DAT_INVALID_HANDLE
 */
DAT_RETURN
dapl_evd_clear_unwaitable(
	IN    DAT_EVD_HANDLE	evd_handle)
{
	DAPL_EVD		*evd_ptr;
	DAT_RETURN		dat_status;

	evd_ptr    = (DAPL_EVD *)evd_handle;
	dat_status = DAT_SUCCESS;

	if (DAPL_BAD_HANDLE(evd_handle, DAPL_MAGIC_EVD)) {
		dat_status = DAT_ERROR(DAT_INVALID_HANDLE, 0);
		goto bail;
	}
	dapl_os_lock(&evd_ptr->header.lock);
	evd_ptr->evd_waitable = DAT_TRUE;
	dapl_os_unlock(&evd_ptr->header.lock);

	dat_status = DAT_SUCCESS;

bail:
	return (dat_status);
}
