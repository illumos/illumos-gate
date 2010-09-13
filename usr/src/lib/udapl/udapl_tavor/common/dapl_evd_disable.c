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
 * MODULE: dapl_evd_disable.c
 *
 * PURPOSE: EVENT management
 *
 * Description: Interfaces in this file are completely defined in
 *              the uDAPL 1.1 API, Chapter 6, section 3
 *
 * $Id: dapl_evd_disable.c,v 1.6 2003/06/16 17:53:32 sjs2 Exp $
 */

#include "dapl.h"

/*
 * dapl_evd_disable
 *
 * DAPL Requirements Version xxx, 6.3.2.5
 *
 * Modify the size fo the event queue of an Event Dispatcher
 *
 * Input:
 * 	evd_handle
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 * 	DAT_INVALID_HANDLE
 */

DAT_RETURN dapl_evd_disable(
	IN	DAT_EVD_HANDLE	   evd_handle)
{
	DAPL_EVD		*evd_ptr;
	DAT_RETURN		dat_status;

	evd_ptr = (DAPL_EVD *)evd_handle;
	dat_status = DAT_SUCCESS;

	if (DAPL_BAD_HANDLE(evd_handle, DAPL_MAGIC_EVD)) {
		dat_status = DAT_ERROR(DAT_INVALID_HANDLE, 0);
		goto bail;
	}

	evd_ptr->evd_enabled = DAT_FALSE;

bail:
	return (dat_status);
}
