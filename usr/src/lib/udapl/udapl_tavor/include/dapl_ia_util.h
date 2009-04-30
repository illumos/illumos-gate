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
 * HEADER: dapl_ia_util.h
 *
 * PURPOSE: Utility defs & routines for the IA data structure
 *
 * $Id: dapl_ia_util.h,v 1.9 2003/07/25 19:24:11 sjs2 Exp $
 */

#ifndef _DAPL_IA_UTIL_H_
#define	_DAPL_IA_UTIL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "dapl.h"

DAPL_IA *
dapl_ia_alloc(
	DAT_PROVIDER	*provider,
	DAPL_HCA	*hca_ptr);

DAT_RETURN
dapl_ia_abrupt_close(
	IN DAPL_IA 	*ia_ptr);

DAT_RETURN
dapl_ia_graceful_close(
	IN DAPL_IA 	*ia_ptr);

void
dapls_ia_free(DAPL_IA *ia_ptr);

void
dapl_ia_link_ep(
	IN DAPL_IA 	*ia_ptr,
	IN DAPL_EP	*ep_info);

void
dapl_ia_unlink_ep(
	IN DAPL_IA 	*ia_ptr,
	IN DAPL_EP	*ep_info);

void
dapl_ia_link_lmr(
	IN DAPL_IA 	*ia_ptr,
	IN DAPL_LMR	*lmr_info);

void
dapl_ia_unlink_lmr(
	IN DAPL_IA 	*ia_ptr,
	IN DAPL_LMR	*lmr_info);

void
dapl_ia_link_rmr(
	IN DAPL_IA 	*ia_ptr,
	IN DAPL_RMR	*rmr_info);

void
dapl_ia_unlink_rmr(
	IN DAPL_IA 	*ia_ptr,
	IN DAPL_RMR	*rmr_info);

void
dapl_ia_link_pz(
	IN DAPL_IA 	*ia_ptr,
	IN DAPL_PZ	*pz_info);

void
dapl_ia_unlink_pz(
	IN DAPL_IA 	*ia_ptr,
	IN DAPL_PZ	*pz_info);

void
dapl_ia_link_evd(
	IN DAPL_IA 	*ia_ptr,
	IN DAPL_EVD	*evd_info);

void
dapl_ia_unlink_evd(
	IN DAPL_IA 	*ia_ptr,
	IN DAPL_EVD	*evd_info);

void
dapl_ia_link_cno(
	IN DAPL_IA 	*ia_ptr,
	IN DAPL_CNO	*cno_info);

void
dapl_ia_unlink_cno(
	IN DAPL_IA 	*ia_ptr,
	IN DAPL_CNO	*cno_info);

void
dapl_ia_link_psp(
	IN DAPL_IA 	*ia_ptr,
	IN DAPL_SP	*sp_info);

void
dapls_ia_unlink_sp(
	IN DAPL_IA 	*ia_ptr,
	IN DAPL_SP	*sp_info);

void
dapl_ia_link_rsp(
	IN DAPL_IA 	*ia_ptr,
	IN DAPL_SP	*sp_info);


DAPL_SP *
dapls_ia_sp_search(
	IN	DAPL_IA		   *ia_ptr,
	IN	DAT_CONN_QUAL	   conn_qual,
	IN	DAT_BOOLEAN	   is_psp);

void
dapl_ia_link_srq(
	IN DAPL_IA 	*ia_ptr,
	IN DAPL_SRQ	*srq_info);

void
dapl_ia_unlink_srq(
	IN DAPL_IA 	*ia_ptr,
	IN DAPL_SRQ	*srq_info);

DAT_RETURN
dapls_ia_setup_callbacks(
    IN	DAPL_IA		*ia_ptr,
    IN	DAPL_EVD	*async_evd_ptr);

DAT_RETURN
dapls_ia_teardown_callbacks(
    IN	DAPL_IA		*ia_ptr);

#ifdef __cplusplus
}
#endif

#endif /* _DAPL_IA_UTIL_H_ */
