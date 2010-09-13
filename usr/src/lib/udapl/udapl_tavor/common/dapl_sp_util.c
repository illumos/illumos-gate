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
 * MODULE: dapl_sp_util.c
 *
 * PURPOSE: Manage PSP Info structure
 *
 * $Id: dapl_sp_util.c,v 1.10 2003/08/20 14:55:39 sjs2 Exp $
 */

#include "dapl.h"
#include "dapl_sp_util.h"

/*
 * Local definitions
 */


/*
 * dapl_sp_alloc
 *
 * alloc and initialize a PSP INFO struct
 *
 * Input:
 * 	IA INFO struct ptr
 *
 * Output:
 * 	sp_ptr
 *
 * Returns:
 * 	NULL
 *	pointer to sp info struct
 *
 */
DAPL_SP *
dapls_sp_alloc(
	IN DAPL_IA *ia_ptr,
	IN DAT_BOOLEAN is_psp)
{
	DAPL_SP *sp_ptr;

	/* Allocate EP */
	sp_ptr = (DAPL_SP *)dapl_os_alloc(sizeof (DAPL_SP));
	if (sp_ptr == NULL) {
		return (NULL);
	}

	/* zero the structure */
	(void) dapl_os_memzero(sp_ptr, sizeof (DAPL_SP));

	/*
	 * initialize the header
	 */
	sp_ptr->header.provider = ia_ptr->header.provider;
	if (is_psp) {
		sp_ptr->header.magic = DAPL_MAGIC_PSP;
		sp_ptr->header.handle_type = DAT_HANDLE_TYPE_PSP;
	} else {
		sp_ptr->header.magic = DAPL_MAGIC_RSP;
		sp_ptr->header.handle_type = DAT_HANDLE_TYPE_RSP;
	}
	sp_ptr->header.owner_ia = ia_ptr;
	sp_ptr->header.user_context.as_64 = 0;
	sp_ptr->header.user_context.as_ptr = NULL;
	dapl_llist_init_entry(&sp_ptr->header.ia_list_entry);
	dapl_os_lock_init(&sp_ptr->header.lock);

	/*
	 * Initialize the Body (set to NULL above)
	 */
	dapl_llist_init_head(&sp_ptr->cr_list_head);

	return (sp_ptr);
}


/*
 * dapl_sp_free
 *
 * Free the passed in PSP structure.
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
dapls_sp_free_sp(
	IN DAPL_SP *sp_ptr)
{
	dapl_os_assert(sp_ptr->header.magic == DAPL_MAGIC_PSP ||
	    sp_ptr->header.magic == DAPL_MAGIC_RSP);
	dapl_os_assert(dapl_llist_is_empty(&sp_ptr->cr_list_head));

	dapl_os_lock(&sp_ptr->header.lock);
	/* reset magic to prevent reuse */
	sp_ptr->header.magic = DAPL_MAGIC_INVALID;
	dapl_os_unlock(&sp_ptr->header.lock);
	dapl_os_free(sp_ptr, sizeof (DAPL_SP));
}


/*
 * dapl_cr_link_cr
 *
 * Add a cr to a PSP structure
 *
 * Input:
 *	sp_ptr
 *	cr_ptr
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	none
 *
 */
void
dapl_sp_link_cr(
	IN DAPL_SP *sp_ptr,
	IN DAPL_CR *cr_ptr)
{
	dapl_os_lock(&sp_ptr->header.lock);
	dapl_llist_add_tail(&sp_ptr->cr_list_head,
	    &cr_ptr->header.ia_list_entry, cr_ptr);
	sp_ptr->cr_list_count++;
	dapl_os_unlock(&sp_ptr->header.lock);
}


/*
 * dapl_sp_search_cr
 *
 * Search for a CR on the PSP cr_list with a matching cm_handle. When
 * found, remove it from the list and update fields.
 *
 * Input:
 *	sp_ptr
 *	ib_cm_handle
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	cr_ptr_fnd	Pointer to matching DAPL_CR
 *
 */
DAPL_CR *
dapl_sp_search_cr(
	IN DAPL_SP *sp_ptr,
	IN  ib_cm_handle_t ib_cm_handle)
{
	DAPL_CR	*cr_ptr;
	DAPL_CR	*cr_ptr_fnd;

	dapl_os_lock(&sp_ptr->header.lock);
	cr_ptr_fnd = NULL;
	cr_ptr = (DAPL_CR *) dapl_llist_peek_head(&sp_ptr->cr_list_head);

	do {
		if (cr_ptr->ib_cm_handle == ib_cm_handle) {
			cr_ptr_fnd = cr_ptr;
			break;
		}
		cr_ptr = cr_ptr->header.ia_list_entry.flink->data;
	} while ((void *)cr_ptr != (void *)sp_ptr->cr_list_head->data);

	dapl_os_unlock(&sp_ptr->header.lock);
	return (cr_ptr_fnd);
}



/*
 * dapl_sp_remove_cr
 *
 * Remove the CR from the PSP. Done prior to freeing the CR resource.
 *
 * Input:
 *	sp_ptr
 *	cr_ptr
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	void
 *
 */
void
dapl_sp_remove_cr(
	IN  DAPL_SP *sp_ptr,
	IN  DAPL_CR *cr_ptr)
{
	dapl_os_lock(&sp_ptr->header.lock);

	if (dapl_llist_is_empty(&sp_ptr->cr_list_head)) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "***dapl_sp_remove_cr: removing from empty queue! sp %p\n",
		    sp_ptr);
		dapl_os_unlock(&sp_ptr->header.lock);
		return;
	}

	(void) dapl_llist_remove_entry(&sp_ptr->cr_list_head,
	    &cr_ptr->header.ia_list_entry);
	sp_ptr->cr_list_count--;

	dapl_os_unlock(&sp_ptr->header.lock);
}
