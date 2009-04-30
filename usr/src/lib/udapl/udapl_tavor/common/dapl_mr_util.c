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

#include "dapl_mr_util.h"

/*
 *
 * MODULE: dapl_mr_util.c
 *
 * PURPOSE: Common Memory Management functions and data structures
 *
 */

/*
 *
 * Function Definitions
 *
 */

/*
 * dapl_mr_get_address
 *
 * Returns the memory address associated with the given memory descriptor
 *
 */
DAT_VADDR
dapl_mr_get_address(DAT_REGION_DESCRIPTION desc, DAT_MEM_TYPE type)
{
	switch (type) {
	case DAT_MEM_TYPE_VIRTUAL: {
		return ((DAT_VADDR)(uintptr_t)desc.for_va);
	}
	case DAT_MEM_TYPE_LMR: {
		DAPL_LMR 	*lmr;

		lmr = (DAPL_LMR *)desc.for_lmr_handle;

		/* Since this function is recoursive we cannot inline it */
		return (dapl_mr_get_address(lmr->param.region_desc,
		    lmr->param.mem_type));
	}
	case DAT_MEM_TYPE_SHARED_VIRTUAL: {
		return ((DAT_VADDR)(uintptr_t)
		    desc.for_shared_memory.virtual_address);
	}
	default:
		dapl_os_assert(0);
		return (0);
	}
}

/*
 * dapl_mr_bounds_check
 *
 * Returns true if region B is contained within region A
 * and false otherwise
 *
 */
DAT_BOOLEAN
dapl_mr_bounds_check(DAT_VADDR addr_a, DAT_VLEN length_a,
	DAT_VADDR addr_b, DAT_VLEN length_b)
{
	if ((addr_a <= addr_b) &&
	    (addr_b + length_b) <= (addr_a + length_a)) {
		return (DAT_TRUE);
	} else {
		return (DAT_FALSE);
	}
}
