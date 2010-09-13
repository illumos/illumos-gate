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
 * MODULE: dapl_hca_util.c
 *
 * PURPOSE: Manage HCA structure
 *
 */

#include "dapl.h"
#include "dapl_adapter_util.h"
#include "dapl_provider.h"
#include "dapl_hca_util.h"
#include "dapl_hash.h"


/*
 * dapl_hca_alloc
 *
 * alloc and initialize an HCA struct
 *
 * Input:
 * 	name
 *      port
 *
 * Output:
 * 	hca_ptr
 *
 * Returns:
 * 	none
 *
 */
/* ARGSUSED */
DAPL_HCA *
dapl_hca_alloc(char *name, char *port)
{
	DAPL_HCA *hca_ptr;

	hca_ptr = dapl_os_alloc(sizeof (DAPL_HCA));
	if (NULL != hca_ptr) {
		(void) dapl_os_memzero(hca_ptr, sizeof (DAPL_HCA));

		if (DAT_SUCCESS ==
		    dapls_hash_create(DAPL_HASH_TABLE_DEFAULT_CAPACITY,
		    DAT_TRUE, &hca_ptr->lmr_hash_table)) {
			dapl_os_lock_init(&hca_ptr->lock);
			dapl_llist_init_head(&hca_ptr->ia_list_head);

			hca_ptr->name = dapl_os_strdup(name);
			hca_ptr->ib_hca_handle = IB_INVALID_HANDLE;
			hca_ptr->port_num = 0;
			hca_ptr->null_ib_cq_handle = IB_INVALID_HANDLE;
		} else {
			dapl_os_free(hca_ptr, sizeof (DAPL_HCA));
			hca_ptr = NULL;
		}
	}
	return (hca_ptr);
}

/*
 * dapl_hca_free
 *
 * free an IA INFO struct
 *
 * Input:
 * 	hca_ptr
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	none
 *
 */
void
dapl_hca_free(DAPL_HCA *hca_ptr)
{
	unsigned int		len;

	(void) dapls_hash_free(hca_ptr->lmr_hash_table);
	if (NULL != hca_ptr->name) {
		len = dapl_os_strlen(hca_ptr->name);
		/* pacify lint dapl_os_free macro doesn't use len */
		len = len;
		dapl_os_free(hca_ptr->name, len + 1);
	}

	dapl_os_free(hca_ptr, sizeof (DAPL_HCA));
}

/*
 * dapl_hca_link_ia
 *
 * Add an ia to the HCA structure
 *
 * Input:
 *	hca_ptr
 *	ia_ptr
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	none
 *
 */
void
dapl_hca_link_ia(IN DAPL_HCA *hca_ptr, IN DAPL_IA *ia_ptr)
{
	dapl_os_lock(&hca_ptr->lock);
	dapl_llist_add_head(&hca_ptr->ia_list_head,
	    &ia_ptr->hca_ia_list_entry, ia_ptr);
	dapl_os_unlock(&hca_ptr->lock);
}

/*
 * dapl_hca_unlink_ia
 *
 * Remove an ia from the hca info structure
 *
 * Input:
 *	hca_ptr
 *	ia_ptr
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	none
 *
 */
void
dapl_hca_unlink_ia(IN DAPL_HCA *hca_ptr, IN DAPL_IA *ia_ptr)
{
	dapl_os_lock(&hca_ptr->lock);
	/*
	 * If an error occurred when we were opening the IA it
	 * will not be linked on the list; don't unlink an unlinked
	 * list!
	 */
	if (!dapl_llist_is_empty(&hca_ptr->ia_list_head)) {
		(void) dapl_llist_remove_entry(&hca_ptr->ia_list_head,
		    &ia_ptr->hca_ia_list_entry);
	}
	dapl_os_unlock(&hca_ptr->lock);
}
