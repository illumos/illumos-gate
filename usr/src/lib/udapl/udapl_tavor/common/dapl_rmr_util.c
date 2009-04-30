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

#include "dapl_rmr_util.h"
#include "dapl_ia_util.h"

DAPL_RMR *
dapl_rmr_alloc(IN DAPL_PZ * pz)
{
	DAPL_RMR *rmr;

	/* Allocate LMR */
	rmr = (DAPL_RMR *)dapl_os_alloc(sizeof (DAPL_RMR));
	if (NULL == rmr) {
		return (NULL);
	}

	/* zero the structure */
	(void) dapl_os_memzero(rmr, sizeof (DAPL_RMR));

	/*
	 * initialize the header
	 */
	rmr->header.provider = pz->header.provider;
	rmr->header.magic = DAPL_MAGIC_RMR;
	rmr->header.handle_type = DAT_HANDLE_TYPE_RMR;
	rmr->header.owner_ia = pz->header.owner_ia;
	rmr->header.user_context.as_64 = 0;
	rmr->header.user_context.as_ptr = 0;
	dapl_llist_init_entry(&rmr->header.ia_list_entry);
	dapl_ia_link_rmr(rmr->header.owner_ia, rmr);
	dapl_os_lock_init(&rmr->header.lock);

	/*
	 * initialize the body
	 */
	rmr->param.ia_handle = (DAT_IA_HANDLE)pz->header.owner_ia;
	rmr->param.pz_handle = (DAT_PZ_HANDLE)pz;
	rmr->param.lmr_triplet.lmr_context = 0;
	rmr->param.lmr_triplet.pad = 0;
	rmr->param.lmr_triplet.virtual_address = 0;
	rmr->param.lmr_triplet.segment_length = 0;

	rmr->param.mem_priv = 0;
	rmr->pz = pz;
	rmr->lmr = NULL;

	return (rmr);
}

void
dapl_rmr_dealloc(IN DAPL_RMR *rmr)
{
	/* reset magic to prevent reuse */
	rmr->header.magic = DAPL_MAGIC_INVALID;

	dapl_ia_unlink_rmr(rmr->header.owner_ia, rmr);
	dapl_os_lock_destroy(&rmr->header.lock);

	dapl_os_free((void *) rmr, sizeof (DAPL_RMR));
}

DAT_BOOLEAN
dapl_rmr_validate_completion_flag(IN DAT_COMPLETION_FLAGS mask,
	IN DAT_COMPLETION_FLAGS allow,
	IN DAT_COMPLETION_FLAGS request)
{
	if ((mask & request) && !(mask & allow)) {
		return (DAT_FALSE);
	} else {
		return (DAT_TRUE);
	}
}

int32_t
dapl_rmr_convert_privileges(IN DAT_MEM_PRIV_FLAGS privileges)
{
	int32_t value = 0;

	if (DAT_MEM_PRIV_REMOTE_READ_FLAG & privileges) {
		value |= IB_BIND_ACCESS_REMOTE_READ;
	}
	if (DAT_MEM_PRIV_REMOTE_WRITE_FLAG & privileges) {
		value |= IB_BIND_ACCESS_REMOTE_WRITE;
	}
	return (value);
}
