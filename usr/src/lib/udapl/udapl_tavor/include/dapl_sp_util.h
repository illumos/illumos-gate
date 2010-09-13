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
 * HEADER: dapl_sp_util.h
 *
 * PURPOSE: Utility defs & routines for the PSP & RSP data structure
 *
 */

#ifndef _DAPL_PSP_UTIL_H_
#define	_DAPL_PSP_UTIL_H_

#ifdef __cplusplus
extern "C" {
#endif

DAPL_SP *
dapls_sp_alloc(
	IN DAPL_IA	*ia_ptr,
	IN DAT_BOOLEAN	is_psp);

void
dapls_sp_free_sp(
	IN DAPL_SP	*sp_ptr);

void
dapl_sp_link_cr(
	IN DAPL_SP	*sp_ptr,
	IN DAPL_CR	*cr_ptr);

DAPL_CR *dapl_sp_search_cr(
	IN DAPL_SP		*sp_ptr,
	IN  ib_cm_handle_t	ib_cm_handle);

void dapl_sp_remove_cr(
	IN  DAPL_SP		*sp_ptr,
	IN  DAPL_CR		*cr_ptr);

#ifdef __cplusplus
}
#endif

#endif /* _DAPL_PSP_UTIL_H_ */
