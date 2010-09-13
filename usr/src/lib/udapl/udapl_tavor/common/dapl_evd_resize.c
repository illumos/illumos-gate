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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *
 * MODULE: dapl_evd_resize.c
 *
 * PURPOSE: EVENT management
 *
 * Description: Interfaces in this file are completely defined in
 *              the uDAPL 1.1 API, Chapter 6, section 3
 *
 * $Id: dapl_evd_resize.c,v 1.4 2003/06/16 17:53:32 sjs2 Exp $
 */

#include "dapl_evd_util.h"
#include "dapl_ring_buffer_util.h"
#include "dapl_adapter_util.h"
#include "dapl.h"

#define	DAPL_MIN_RESZ_QLEN	4096

/*
 * dapl_evd_resize
 *
 * DAPL Requirements Version xxx, 6.3.2.5
 *
 * Modify the size fo the event queue of an Event Dispatcher
 *
 * Input:
 * 	evd_handle
 * 	evd_qlen
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 * 	DAT_INVALID_PARAMETER
 * 	DAT_INSUFFICIENT_RESOURCES
 * 	DAT_INVALID_STATE
 */

DAT_RETURN dapl_evd_resize(
	IN	DAT_EVD_HANDLE	   evd_handle,
	IN	DAT_COUNT	   req_evd_qlen)
{
	int			i;
	DAPL_EVD		*evd_ptr;
	DAT_EVENT		*event_ptr;
	DAT_EVENT		*eventp;
	DAT_EVENT		*event;
	DAT_EVENT		*new_event;
	DAPL_RING_BUFFER	free_event_queue;
	DAPL_RING_BUFFER	pending_event_queue;
	DAT_RETURN		dat_status;
	DAT_COUNT		max_evd_qlen;
	DAT_COUNT		evd_qlen;

	evd_ptr = (DAPL_EVD *)evd_handle;
	dat_status = DAT_SUCCESS;

	if (DAPL_BAD_HANDLE(evd_handle, DAPL_MAGIC_EVD)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, 0));
	}

	if (req_evd_qlen < evd_ptr->qlen) {
		return (DAT_ERROR(DAT_INVALID_STATE, 0));
	}

	if (req_evd_qlen == evd_ptr->qlen) {
		return (DAT_SUCCESS);
	}

	max_evd_qlen = evd_ptr->header.owner_ia->hca_ptr->ia_attr.max_evd_qlen;
	if (req_evd_qlen > max_evd_qlen) {
		return (DAT_ERROR(DAT_INVALID_STATE, 0));
	}

	evd_qlen = DAPL_MIN_RESZ_QLEN;
	while (req_evd_qlen > evd_qlen) {
		evd_qlen <<= 1;
		if (evd_qlen > max_evd_qlen)
			evd_qlen = max_evd_qlen;
	}

	/* Allocate EVENTs */
	event_ptr = (DAT_EVENT *) dapl_os_alloc(evd_qlen * sizeof (DAT_EVENT));
	if (!event_ptr) {
		return (DAT_ERROR(DAT_INSUFFICIENT_RESOURCES,
		    DAT_RESOURCE_MEMORY));
	}

	/* allocate free event queue */
	dat_status = dapls_rbuf_alloc(&free_event_queue, evd_qlen);
	if (dat_status != DAT_SUCCESS) {
		goto bail;
	}

	/* allocate pending event queue */
	dat_status = dapls_rbuf_alloc(&pending_event_queue, evd_qlen);
	if (dat_status != DAT_SUCCESS) {
		goto bail;
	}

	/* need to resize the cq only for DTO/BIND evds */
	if (0 != (evd_ptr->evd_flags & ~ (DAT_EVD_SOFTWARE_FLAG |
	    DAT_EVD_CONNECTION_FLAG | DAT_EVD_CR_FLAG))) {
		dat_status = dapls_ib_cq_resize(evd_ptr, evd_qlen);
		if (dat_status != DAT_SUCCESS)
			goto bail;
	}

	/* add events to free event queue */
	for (i = 0, eventp = event_ptr; i < evd_qlen; i++) {
		(void) dapls_rbuf_add(&free_event_queue, (void *)eventp);
		eventp++;
	}
	/*
	 * copy pending events from evd to the new pending event queue
	 */
	while (event = (DAT_EVENT *)
	    dapls_rbuf_remove(&evd_ptr->pending_event_queue)) {
		new_event = (DAT_EVENT *) dapls_rbuf_remove(&free_event_queue);
		dapl_os_assert(new_event);
		(void) dapl_os_memcpy(new_event, event, sizeof (DAT_EVENT));
		dat_status = dapls_rbuf_add(&pending_event_queue, new_event);
		dapl_os_assert(dat_status == DAT_SUCCESS);
		dat_status = dapls_rbuf_add(&evd_ptr->free_event_queue, event);
		dapl_os_assert(dat_status == DAT_SUCCESS);
	}

	dapls_rbuf_destroy(&evd_ptr->free_event_queue);
	dapls_rbuf_destroy(&evd_ptr->pending_event_queue);
	if (evd_ptr->events) {
		dapl_os_free(evd_ptr->events,
		    evd_ptr->qlen * sizeof (DAT_EVENT));
	}
	evd_ptr->events = event_ptr;
	evd_ptr->free_event_queue = free_event_queue;
	evd_ptr->pending_event_queue = pending_event_queue;
	evd_ptr->qlen = evd_qlen;

	return (DAT_SUCCESS);
bail:
	/*
	 * If we are here means event_ptr was allocd but something else
	 * failed
	 */
	dapl_os_free(event_ptr, evd_qlen * sizeof (DAT_EVENT));
	dapls_rbuf_destroy(&free_event_queue);
	dapls_rbuf_destroy(&pending_event_queue);

	return (dat_status);
}
