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
 * HEADER: dapl_evd_util.h
 *
 * PURPOSE: Utility defs & routines for the EVD data structure
 *
 * $Id: dapl_evd_util.h,v 1.10 2003/06/13 12:21:09 sjs2 Exp $
 *
 */

#ifndef _DAPL_EVD_UTIL_H_
#define	_DAPL_EVD_UTIL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "dapl.h"

DAT_RETURN
dapls_evd_internal_create(
    IN DAPL_IA		*ia_ptr,
    IN DAPL_CNO		*cno_ptr,
    IN DAT_COUNT	min_qlen,
    IN DAT_EVD_FLAGS	evd_flags,
    OUT DAPL_EVD	**evd_ptr_ptr);

DAPL_EVD *
dapls_evd_alloc(
    IN DAPL_IA		*ia_ptr,
    IN DAPL_CNO		*cno_ptr,
    IN DAT_EVD_FLAGS	evd_flags,
    IN DAT_COUNT	qlen);

DAT_RETURN
dapls_evd_dealloc(
    IN DAPL_EVD 	*evd_ptr);

/*
 * Each of these functions will retrieve a free event from
 * the specified EVD, fill in the elements of that event, and
 * post the event back to the EVD.  If there is no EVD available,
 * an overflow event will be posted to the async EVD associated
 * with the EVD.
 *
 * DAT_INSUFFICIENT_RESOURCES will be returned on overflow,
 * DAT_SUCCESS otherwise.
 */

DAT_RETURN
dapls_evd_post_cr_arrival_event(
    IN DAPL_EVD				*evd_ptr,
    IN DAT_EVENT_NUMBER			event_number,
    IN DAT_SP_HANDLE			sp_handle,
    DAT_IA_ADDRESS_PTR			ia_address_ptr,
    DAT_CONN_QUAL			conn_qual,
    DAT_CR_HANDLE			cr_handle);

DAT_RETURN
dapls_evd_post_connection_event(
    IN DAPL_EVD			*evd_ptr,
    IN DAT_EVENT_NUMBER		event_number,
    IN DAT_EP_HANDLE		ep_handle,
    IN DAT_COUNT		private_data_size,
    IN DAT_PVOID		private_data);

DAT_RETURN
dapls_evd_post_async_error_event(
    IN DAPL_EVD				*evd_ptr,
    IN DAT_EVENT_NUMBER			event_number,
    IN DAT_IA_HANDLE			ia_handle);

DAT_RETURN
dapls_evd_post_software_event(
    IN DAPL_EVD				*evd_ptr,
    IN DAT_EVENT_NUMBER			event_number,
    IN DAT_PVOID			pointer);

/*
 * dapl internal callbacks functions
 */

/* connection verb callback */
extern void dapl_evd_connection_callback(
    IN	ib_cm_handle_t		ib_cm_handle,
    IN	const ib_cm_events_t	ib_cm_events,
    IN	const void 		*instant_data_p,
    IN	const void *		context);

/* dto verb callback */
extern void dapl_evd_dto_callback(
    IN  ib_hca_handle_t 	ib_hca_handle,
    IN  ib_cq_handle_t 		ib_cq_handle,
    IN  void* 			context);

/* async verb callbacks */
extern void dapl_evd_un_async_error_callback(
    IN	ib_hca_handle_t		ib_hca_handle,
    IN	ib_error_record_t	*cause_ptr,
    IN	void			*context);

extern void dapl_evd_cq_async_error_callback(
    IN	ib_hca_handle_t 	ib_hca_handle,
    IN	ib_cq_handle_t		ib_cq_handle,
    IN	ib_error_record_t	*cause_ptr,
    IN	void			*context);

extern void dapl_evd_qp_async_error_callback(
    IN	ib_hca_handle_t 	ib_hca_handle,
    IN	ib_qp_handle_t		ib_qp_handle,
    IN	ib_error_record_t	*cause_ptr,
    IN	void			*context);

extern void dapls_cr_callback(
    ib_cm_handle_t		ib_cm_handle,
    IN    const ib_cm_events_t  ib_cm_event,
    IN    const void		*instant_data_p,
    IN    const void		*context);

extern void dapls_evd_copy_cq(
    IN	 DAPL_EVD 		*evd_ptr,
    OUT  int			*nevents);

extern DAT_RETURN dapls_evd_copy_events(
    DAPL_EVD 			*evd_ptr,
    DAT_TIMEOUT			timeout);

extern void dapls_evd_post_premature_events(
    DAPL_EP			*ep_ptr);

extern DAT_RETURN dapls_evd_cq_poll_to_event(
    IN DAPL_EVD 		*evd_ptr,
    OUT DAT_EVENT		*event);

#ifdef __cplusplus
}
#endif

#endif /* _DAPL_EVD_UTIL_H_ */
