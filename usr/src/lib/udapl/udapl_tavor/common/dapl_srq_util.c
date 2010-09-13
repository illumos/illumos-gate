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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *
 * MODULE: dapl_srq_util.c
 *
 * PURPOSE: Shared Receive Queue utility functions.
 *
 */

#include "dapl.h"
#include "dapl_cookie.h"
#include "dapl_srq_util.h"

/*
 * dapl_srq_alloc
 *
 * Allocate SRQ structure.
 *
 * Input:
 * 	IA, srq_attr
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	Pointer to alloted SRQ
 *
 */
DAPL_SRQ *
dapl_srq_alloc(IN DAPL_IA *ia_ptr, IN const DAT_SRQ_ATTR *srq_attr)
{
	DAPL_SRQ *srq_ptr;
	DAT_RETURN retval;

	/* Allocate SRQ */
	srq_ptr = (DAPL_SRQ *)dapl_os_alloc(sizeof (DAPL_SRQ));
	if (srq_ptr == NULL) {
		goto bail;
	}

	/* zero the structure */
	(void) dapl_os_memzero(srq_ptr, sizeof (DAPL_SRQ));

	/*
	 * initialize the header
	 */
	srq_ptr->header.provider	= ia_ptr->header.provider;
	srq_ptr->header.magic		= DAPL_MAGIC_SRQ;
	srq_ptr->header.handle_type	= DAT_HANDLE_TYPE_SRQ;
	srq_ptr->header.owner_ia	= ia_ptr;
	srq_ptr->header.user_context.as_64	= 0;
	dapl_llist_init_entry(&srq_ptr->header.ia_list_entry);
	dapl_os_lock_init(&srq_ptr->header.lock);

	/* The SRQ ptr is stored in the cookies */
	retval = dapls_cb_create(&srq_ptr->recv_buffer, srq_ptr,
	    DAPL_COOKIE_QUEUE_SRQ, srq_attr->max_recv_dtos);
	if (retval != DAT_SUCCESS) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR, "dapls_srq_alloc cb_create "
		    "failed %d\n", retval);
		dapl_srq_dealloc(srq_ptr);
		srq_ptr = NULL;
		goto bail;
	}

bail:
	return (srq_ptr);
}

/*
 * dapl_srq_dealloc
 *
 * Free the passed in SRQ structure.
 *
 * Input:
 * 	entry point pointer
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	none
 *
 */
void
dapl_srq_dealloc(IN DAPL_SRQ	*srq_ptr)
{
	dapl_os_assert(srq_ptr->header.magic == DAPL_MAGIC_SRQ);

	/* reset magic to prevent reuse */
	srq_ptr->header.magic = DAPL_MAGIC_INVALID;

	dapls_cb_free(&srq_ptr->recv_buffer);

	dapl_os_lock_destroy(&srq_ptr->header.lock);
	dapl_os_free(srq_ptr, sizeof (DAPL_SRQ));
}
