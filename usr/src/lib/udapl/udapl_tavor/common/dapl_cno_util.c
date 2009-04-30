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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *
 * MODULE: dapl_cno_util.c
 *
 * PURPOSE: Manage CNO Info structure
 *
 * $Id: dapl_cno_util.c,v 1.6 2003/06/13 12:21:02 sjs2 Exp $
 */

#include "dapl_ia_util.h"
#include "dapl_cno_util.h"
#include "dapl_adapter_util.h"



/*
 * dapl_cno_alloc
 *
 * alloc and initialize an EVD struct
 *
 * Input:
 *	ia
 *
 * Returns:
 *	cno_ptr, or null on failure.
 */
DAPL_CNO *
dapl_cno_alloc(
    IN DAPL_IA				*ia_ptr,
    IN DAT_OS_WAIT_PROXY_AGENT		wait_agent)
{
	DAPL_CNO *cno_ptr;

	cno_ptr = (DAPL_CNO *) dapl_os_alloc(sizeof (DAPL_CNO));
	if (!cno_ptr) {
		return (NULL);
	}

	/* zero the structure */
	(void) dapl_os_memzero(cno_ptr, sizeof (DAPL_CNO));

	/*
	 * Initialize the header.
	 */
	cno_ptr->header.provider	= ia_ptr->header.provider;
	cno_ptr->header.magic		= DAPL_MAGIC_CNO;
	cno_ptr->header.handle_type	= DAT_HANDLE_TYPE_CNO;
	cno_ptr->header.owner_ia	= ia_ptr;
	cno_ptr->header.user_context.as_64  = 0;
	cno_ptr->header.user_context.as_ptr = NULL;
	dapl_llist_init_entry(&cno_ptr->header.ia_list_entry);
	dapl_llist_init_head(&cno_ptr->evd_list_head);
	dapl_os_lock_init(&cno_ptr->header.lock);

	/*
	 * Initialize the body
	 */
	cno_ptr->cno_waiters = 0;
	cno_ptr->cno_ref_count = 0;
	cno_ptr->cno_state = DAPL_CNO_STATE_UNTRIGGERED;
	cno_ptr->cno_evd_triggered = NULL;
	cno_ptr->cno_wait_agent = wait_agent;
	(void) dapl_os_wait_object_init(&cno_ptr->cno_wait_object);

	return (cno_ptr);
}

/*
 * dapl_cno_dealloc
 *
 * Free the passed in CNO structure.
 *
 * Input:
 * 	cno_ptr
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	none
 *
 */
void
dapl_cno_dealloc(
    IN DAPL_CNO *cno_ptr)
{
	dapl_os_assert(cno_ptr->header.magic == DAPL_MAGIC_CNO);
	dapl_os_assert(cno_ptr->cno_ref_count == 0);

	/*
	 * deinitialize the header
	 */
	/* reset magic to prevent reuse */
	cno_ptr->header.magic = DAPL_MAGIC_INVALID;

	(void) dapl_os_wait_object_destroy(&cno_ptr->cno_wait_object);
	dapl_os_free(cno_ptr, sizeof (DAPL_CNO));
}

/*
 * dapl_cno_trigger
 *
 * DAPL Internal routine to trigger the specified CNO.
 * Called by the callback of some EVD associated with the CNO.
 *
 * Input:
 *	cno_ptr
 *	evd_ptr		EVD triggering
 *
 * Output:
 *	None
 *
 * Returns:
 *	None
 */
void
dapl_cno_trigger(
	IN DAPL_CNO		*cno_ptr,
	IN DAPL_EVD		*evd_ptr) /* ARGSUSED */
{
	/*
	 * In Solaris uDAPL the CNO is triggered in the kernel
	 */
}
