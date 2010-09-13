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
 * MODULE: dapl_cno_modify_agent.c
 *
 * PURPOSE: Modify the wait proxy agent associted with the CNO
 * Description: Interfaces in this file are completely described in
 *		the DAPL 1.1 API, Chapter 6, section 3.2.4
 *
 * $Id: dapl_cno_modify_agent.c,v 1.5 2003/06/16 17:53:32 sjs2 Exp $
 */

#include "dapl.h"

/*
 * dapl_cno_modify_agent
 *
 * DAPL Requirements Version xxx, 6.3.2.4
 *
 * Modify the wait proxy agent associted with the CNO
 *
 * Input:
 *	cno_handle
 *	prx_agent
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
dapl_cno_modify_agent(
	IN	DAT_CNO_HANDLE		cno_handle,	/* cno_handle */
	IN	DAT_OS_WAIT_PROXY_AGENT	prx_agent)	/* agent */
{
	DAPL_CNO	 *cno_ptr;
	DAT_RETURN   dat_status;

	dat_status = DAT_SUCCESS;
	if (DAPL_BAD_HANDLE(cno_handle, DAPL_MAGIC_CNO)) {
		dat_status = DAT_ERROR(DAT_INVALID_HANDLE,
		    DAT_INVALID_HANDLE_CNO);
		goto bail;
	}

	cno_ptr = (DAPL_CNO *) cno_handle;
	dapl_os_lock(&cno_ptr->header.lock);
	cno_ptr->cno_wait_agent = prx_agent;
	dapl_os_unlock(&cno_ptr->header.lock);

bail:
	return (dat_status);
}
