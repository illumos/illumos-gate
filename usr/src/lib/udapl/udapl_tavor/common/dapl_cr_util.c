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
 * MODULE: dapl_cr_util.c
 *
 * PURPOSE: Manage CR (Connection Request) structure
 *
 * $Id: dapl_cr_util.c,v 1.7 2003/08/08 19:20:05 sjs2 Exp $
 */

#include "dapl.h"
#include "dapl_cr_util.h"

/*
 * dapls_cr_create
 *
 * Create a CR. Part of the passive side of a connection
 *
 * Input:
 * 	ia_ptr
 *	cno_ptr
 *	qlen
 *	evd_flags
 *
 * Output:
 * 	evd_ptr_ptr
 *
 * Returns:
 * 	none
 *
 */

DAPL_CR	*
dapls_cr_alloc(
	DAPL_IA	*ia_ptr)
{
	DAPL_CR	*cr_ptr;

	/* Allocate EP */
	cr_ptr = (DAPL_CR *)dapl_os_alloc(sizeof (DAPL_CR));
	if (cr_ptr == NULL) {
		return (NULL);
	}

	/* zero the structure */
	(void) dapl_os_memzero(cr_ptr, sizeof (DAPL_CR));

	/*
	 * initialize the header
	 */
	cr_ptr->header.provider = ia_ptr->header.provider;
	cr_ptr->header.magic = DAPL_MAGIC_CR;
	cr_ptr->header.handle_type = DAT_HANDLE_TYPE_CR;
	cr_ptr->header.owner_ia = ia_ptr;
	cr_ptr->header.user_context.as_64 = 0;
	cr_ptr->header.user_context.as_ptr = NULL;
	dapl_llist_init_entry(&cr_ptr->header.ia_list_entry);
	dapl_os_lock_init(&cr_ptr->header.lock);

	return (cr_ptr);
}


/*
 * dapls_cr_free
 *
 * Free the passed in EP structure.
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
dapls_cr_free(
	IN DAPL_CR *cr_ptr)
{
	dapl_os_assert(cr_ptr->header.magic == DAPL_MAGIC_CR ||
	    cr_ptr->header.magic == DAPL_MAGIC_CR_DESTROYED);

	/* reset magic to prevent reuse */
	cr_ptr->header.magic = DAPL_MAGIC_INVALID;
	dapl_os_free(cr_ptr, sizeof (DAPL_CR));
}
