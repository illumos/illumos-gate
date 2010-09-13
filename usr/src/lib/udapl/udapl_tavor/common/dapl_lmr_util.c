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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 *
 * MODULE: dapl_lmr_util.c
 *
 * PURPOSE: Memory management support routines
 * Description: Support routines for LMR functions
 *
 */

#include <sys/ib/ibtl/ibtl_types.h>
#include "dapl_lmr_util.h"
#include "dapl_ia_util.h"

DAPL_LMR *
dapl_lmr_alloc(IN DAPL_IA *ia,
	IN DAT_MEM_TYPE mem_type,
	IN DAT_REGION_DESCRIPTION region_desc,
	IN DAT_VLEN length,
	IN DAT_PZ_HANDLE pz_handle,
	IN DAT_MEM_PRIV_FLAGS mem_priv)
{
	DAPL_LMR *lmr;

	/* Allocate LMR */
	lmr = (DAPL_LMR *)dapl_os_alloc(sizeof (DAPL_LMR));
	if (NULL == lmr) {
		return (NULL);
	}

	/* zero the structure */
	(void) dapl_os_memzero(lmr, sizeof (DAPL_LMR));

	/*
	 * initialize the header
	 */
	lmr->header.provider = ia->header.provider;
	lmr->header.magic = DAPL_MAGIC_LMR;
	lmr->header.handle_type = DAT_HANDLE_TYPE_LMR;
	lmr->header.owner_ia = ia;
	lmr->header.user_context.as_64 = 0;
	lmr->header.user_context.as_ptr = NULL;
	dapl_llist_init_entry(&lmr->header.ia_list_entry);
	dapl_ia_link_lmr(ia, lmr);
	dapl_os_lock_init(&lmr->header.lock);

	/*
	 * initialize the body
	 */
	lmr->param.ia_handle = (DAT_IA_HANDLE)ia;
	lmr->param.mem_type = mem_type;
	lmr->param.region_desc = region_desc;
	lmr->param.length = length;
	lmr->param.pz_handle = pz_handle;
	lmr->param.mem_priv = mem_priv;
	lmr->lmr_ref_count = 0;

	return (lmr);
}

void
dapl_lmr_dealloc(IN DAPL_LMR *lmr)
{
	/* reset magic to prevent reuse */
	lmr->header.magic = DAPL_MAGIC_INVALID;
	dapl_ia_unlink_lmr(lmr->header.owner_ia, lmr);
	dapl_os_lock_destroy(&lmr->header.lock);

	dapl_os_free((void *) lmr, sizeof (DAPL_LMR));
}

int32_t
dapl_lmr_convert_privileges(IN DAT_MEM_PRIV_FLAGS privileges)
{
	int32_t value = 0;

	/*
	 *    if (DAT_MEM_PRIV_LOCAL_READ_FLAG & privileges)
	 *	do nothing
	 */
	if (DAT_MEM_PRIV_LOCAL_WRITE_FLAG & privileges) {
		value |= IB_ACCESS_LOCAL_WRITE;
	}
	if (DAT_MEM_PRIV_REMOTE_READ_FLAG & privileges) {
		value |= IB_ACCESS_REMOTE_READ;
	}
	if (DAT_MEM_PRIV_REMOTE_WRITE_FLAG & privileges) {
		value |= IB_ACCESS_REMOTE_WRITE;
	}
	if (DAT_MEM_PRIV_RO_DISABLE_FLAG & privileges) {
		value |= IBT_MR_DISABLE_RO;
	}
	return (value);
}
