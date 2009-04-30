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
 * MODULE: dapl_pz_util.c
 *
 * PURPOSE: Manage PZ structure
 *
 * $Id: dapl_pz_util.c,v 1.7 2003/06/13 12:21:11 sjs2 Exp $
 */

#include "dapl_pz_util.h"
#include "dapl_ia_util.h"

/*
 * dapl_pz_alloc
 *
 * alloc and initialize an PZ struct
 *
 * Input:
 * 	none
 *
 * Output:
 * 	pz_ptr
 *
 * Returns:
 * 	none
 *
 */
DAPL_PZ *
dapl_pz_alloc(
    IN DAPL_IA 		*ia)
{
	DAPL_PZ *pz;

	/* Allocate PZ */
	pz = (DAPL_PZ *) dapl_os_alloc(sizeof (DAPL_PZ));
	if (NULL == pz) {
		return (NULL);
	}

	/* zero the structure */
	(void) dapl_os_memzero(pz, sizeof (DAPL_PZ));

	/*
	 * initialize the header
	 */
	pz->header.provider	   = ia->header.provider;
	pz->header.magic	   = DAPL_MAGIC_PZ;
	pz->header.handle_type	   = DAT_HANDLE_TYPE_PZ;
	pz->header.owner_ia	   = ia;
	pz->header.user_context.as_64  = 0;
	pz->header.user_context.as_ptr = NULL;
	dapl_llist_init_entry(&pz->header.ia_list_entry);
	dapl_ia_link_pz(ia, pz);
	dapl_os_lock_init(&pz->header.lock);

	/*
	 * initialize the body
	 */
	pz->pz_ref_count = 0;

	return (pz);
}

/*
 * dapl_pz_dealloc
 *
 * free an PZ struct
 *
 * Input:
 * 	pz_ptr
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	none
 *
 */
void
dapl_pz_dealloc(
	IN DAPL_PZ *pz)
{
	/* reset magic to prevent reuse */
	pz->header.magic = DAPL_MAGIC_INVALID;
	dapl_ia_unlink_pz(pz->header.owner_ia, pz);
	dapl_os_lock_destroy(&pz->header.lock);

	dapl_os_free(pz, sizeof (DAPL_PZ));
}
