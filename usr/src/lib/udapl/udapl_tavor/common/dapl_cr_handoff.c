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
 * MODULE: dapl_cr_handoff.c
 *
 * PURPOSE: Connection management
 * Description: Interfaces in this file are completely described in
 *		the DAPL 1.1 API, Chapter 6, section 4
 *
 * $Id: dapl_cr_handoff.c,v 1.4 2003/06/16 17:53:32 sjs2 Exp $
 */

#include "dapl.h"
#include "dapl_cr_util.h"
#include "dapl_sp_util.h"
#include "dapl_adapter_util.h"

/*
 * dapl_cr_handoff
 *
 * DAPL Requirements Version xxx, 6.4.2.4
 *
 * Hand the connection request to another Sevice pont specified by the
 * Connectin Qualifier.
 *
 * Input:
 *	cr_handle
 *	cr_handoff
 *
 * Output:
 *	none
 *
 * Returns:
 *	DAT_SUCCESS
 *	DAT_INVALID_HANDLE
 *	DAT_INVALID_PARAMETER
 */

DAT_RETURN
dapl_cr_handoff(
	IN DAT_CR_HANDLE cr_handle,
	IN DAT_CONN_QUAL cr_handoff)		/* handoff */
{
	DAPL_CR *cr_ptr;
	DAT_RETURN dat_status;

	if (DAPL_BAD_HANDLE(cr_handle, DAPL_MAGIC_CR)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_CR));
	}

	cr_ptr = (DAPL_CR *)cr_handle;
	dat_status = dapls_ib_handoff_connection(cr_ptr, cr_handoff);

	/* Remove the CR from the queue, then free it */
	dapl_sp_remove_cr(cr_ptr->sp_ptr, cr_ptr);
	dapls_cr_free(cr_ptr);

	return (dat_status);
}
