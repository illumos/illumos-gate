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
 * MODULE: dapl_rsp_free.c
 *
 * PURPOSE: Connection management
 * Description: Interfaces in this file are completely described in
 *		the DAPL 1.1 API, Chapter 6, section 4
 *
 * $Id: dapl_rsp_free.c,v 1.16 2003/07/25 19:24:11 sjs2 Exp $
 */

#include "dapl.h"
#include "dapl_sp_util.h"
#include "dapl_ia_util.h"
#include "dapl_adapter_util.h"

/*
 * dapl_rsp_free
 *
 * uDAPL: User Direct Access Program Library Version 1.1, 6.4.3.5
 *
 * Destroy a specific instance of a Reserved Service Point.
 *
 * Input:
 *	rsp_handle
 *
 * Output:
 *	none
 *
 * Returns:
 *	DAT_SUCCESS
 *	DAT_INVALID_HANDLE
 */
DAT_RETURN
dapl_rsp_free(
	IN	DAT_RSP_HANDLE	   rsp_handle)
{
	DAPL_IA		*ia_ptr;
	DAPL_SP		*sp_ptr;
	DAPL_EP		*ep_ptr;
	DAT_RETURN		dat_status;

	dat_status = DAT_SUCCESS;

	sp_ptr = (DAPL_SP *)rsp_handle;
	/*
	 * Verify handle
	 */
	dapl_dbg_log(DAPL_DBG_TYPE_CM,
	    ">>> dapl_rsp_free %p\n",
	    rsp_handle);
	if (DAPL_BAD_HANDLE(sp_ptr, DAPL_MAGIC_RSP)) {
		dat_status = DAT_ERROR(DAT_INVALID_HANDLE,
		    DAT_INVALID_HANDLE_RSP);
		goto bail;
	}

	/* ia_ptr = (DAPL_IA *)sp_ptr->header.owner_ia; */
	ia_ptr = sp_ptr->header.owner_ia;

	/*
	 * Remove the connection listener if there are no connections.  If
	 * we defer removing the sp it becomes something of a zombie
	 * container until disconnection, after which it will be cleaned up.
	 */
	dapl_os_lock(&sp_ptr->header.lock);

	/*
	 * Make sure we don't leave a dangling EP. If the state is still
	 * RESERVED then the RSP still owns it.
	 */
	ep_ptr = (DAPL_EP *)sp_ptr->ep_handle;
	if (ep_ptr->param.ep_state == DAT_EP_STATE_RESERVED) {
		ep_ptr->param.ep_state = DAT_EP_STATE_UNCONNECTED;
	}
	sp_ptr->ep_handle = NULL;

	/* Release reference on EVD */
	dapl_os_atomic_dec(&((DAPL_EVD *)sp_ptr->evd_handle)->evd_ref_count);
	sp_ptr->evd_handle = NULL;

	/*
	 * Release the base resource if there are no outstanding connections;
	 * else the last disconnect on this RSP will free it up. The RSP
	 * is used to contain CR records for each connection, which
	 * contain information necessary to disconnect.
	 */
	if (sp_ptr->listening == DAT_TRUE && sp_ptr->cr_list_count == 0) {
		sp_ptr->listening	= DAT_FALSE;
		sp_ptr->state		= DAPL_SP_STATE_FREE;
		dapl_os_unlock(&sp_ptr->header.lock);
		dat_status = dapls_ib_remove_conn_listener(ia_ptr, sp_ptr);
		if (dat_status != DAT_SUCCESS) {
			sp_ptr->listening = DAT_TRUE;
			sp_ptr->state = DAPL_SP_STATE_RSP_LISTENING;
			goto bail;
		}
		dapls_ia_unlink_sp(ia_ptr, sp_ptr);
		dapls_sp_free_sp(sp_ptr);

	} else {
		/*
		 * The RSP is now in the pending state, where it will sit until
		 * the connection terminates or the app uses the same
		 * ServiceID again, which will reactivate it.
		 */
		sp_ptr->state = DAPL_SP_STATE_RSP_PENDING;
		dapl_os_unlock(&sp_ptr->header.lock);
	}

bail:
	return (dat_status);
}

/*
 * Local variables:
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  c-brace-offset: -4
 *  tab-width: 8
 * End:
 */
