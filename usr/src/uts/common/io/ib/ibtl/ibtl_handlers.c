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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/ib/ibtl/impl/ibtl.h>
#include <sys/ib/ibtl/impl/ibtl_cm.h>
#include <sys/taskq.h>
#include <sys/disp.h>
#include <sys/callb.h>
#include <sys/proc.h>

/*
 * ibtl_handlers.c
 */

/*
 * What's in this file?
 *
 *   This file started as an implementation of Asynchronous Event/Error
 *   handling and Completion Queue handling.  As the implementation
 *   evolved, code has been added for other ibc_* interfaces (resume,
 *   predetach, etc.) that use the same mechanisms as used for asyncs.
 *
 * Async and CQ handling at interrupt level.
 *
 *   CQ handling is normally done at interrupt level using the CQ callback
 *   handler to call the appropriate IBT Client (owner of the CQ).  For
 *   clients that would prefer a fully flexible non-interrupt context to
 *   do their CQ handling, a CQ can be created so that its handler is
 *   called from a non-interrupt thread.  CQ handling is done frequently
 *   whereas Async handling is expected to occur very infrequently.
 *
 *   Async handling is done by marking (or'ing in of an async_code of) the
 *   pertinent IBTL data structure, and then notifying the async_thread(s)
 *   that the data structure has async work to be done.  The notification
 *   occurs by linking the data structure through its async_link onto a
 *   list of like data structures and waking up an async_thread.  This
 *   list append is not done if there is already async work pending on
 *   this data structure (IBTL_ASYNC_PENDING).
 *
 * Async Mutex and CQ Mutex
 *
 *   The global ibtl_async_mutex is "the" mutex used to control access
 *   to all the data needed by ibc_async_handler.  All the threads that
 *   use this mutex are written so that the mutex is held for very short
 *   periods of time, and never held while making calls to functions
 *   that may block.
 *
 *   The global ibtl_cq_mutex is used similarly by ibc_cq_handler and
 *   the ibtl_cq_thread(s).
 *
 * Mutex hierarchy
 *
 *   The ibtl_clnt_list_mutex is above the ibtl_async_mutex.
 *   ibtl_clnt_list_mutex protects all of the various lists.
 *   The ibtl_async_mutex is below this in the hierarchy.
 *
 *   The ibtl_cq_mutex is independent of the above mutexes.
 *
 * Threads
 *
 *   There are "ibtl_cq_threads" number of threads created for handling
 *   Completion Queues in threads.  If this feature really gets used,
 *   then we will want to do some suitable tuning.  Similarly, we may
 *   want to tune the number of "ibtl_async_thread_init".
 *
 *   The function ibtl_cq_thread is the main loop for handling a CQ in a
 *   thread.  There can be multiple threads executing this same code.
 *   The code sleeps when there is no work to be done (list is empty),
 *   otherwise it pulls the first CQ structure off the list and performs
 *   the CQ handler callback to the client.  After that returns, a check
 *   is made, and if another ibc_cq_handler call was made for this CQ,
 *   the client is called again.
 *
 *   The function ibtl_async_thread is the main loop for handling async
 *   events/errors.  There can be multiple threads executing this same code.
 *   The code sleeps when there is no work to be done (lists are empty),
 *   otherwise it pulls the first structure off one of the lists and
 *   performs the async callback(s) to the client(s).  Note that HCA
 *   async handling is done by calling each of the clients using the HCA.
 *   When the async handling completes, the data structure having the async
 *   event/error is checked for more work before it's considered "done".
 *
 * Taskq
 *
 *   The async_taskq is used here for allowing async handler callbacks to
 *   occur simultaneously to multiple clients of an HCA.  This taskq could
 *   be used for other purposes, e.g., if all the async_threads are in
 *   use, but this is deemed as overkill since asyncs should occur rarely.
 */

/* Globals */
static char ibtf_handlers[] = "ibtl_handlers";

/* priority for IBTL threads (async, cq, and taskq) */
static pri_t ibtl_pri = MAXCLSYSPRI - 1; /* maybe override in /etc/system */

/* taskq used for HCA asyncs */
#define	ibtl_async_taskq system_taskq

/* data for async handling by threads */
static kmutex_t ibtl_async_mutex;	/* protects most *_async_* data */
static kcondvar_t ibtl_async_cv;	/* async_threads wait on this */
static kcondvar_t ibtl_clnt_cv;		/* ibt_detach might wait on this */
static void ibtl_dec_clnt_async_cnt(ibtl_clnt_t *clntp);
static void ibtl_inc_clnt_async_cnt(ibtl_clnt_t *clntp);

static kt_did_t *ibtl_async_did;	/* for thread_join() */
int ibtl_async_thread_init = 4;	/* total # of async_threads to create */
static int ibtl_async_thread_exit = 0;	/* set if/when thread(s) should exit */

/* async lists for various structures */
static ibtl_hca_devinfo_t *ibtl_async_hca_list_start, *ibtl_async_hca_list_end;
static ibtl_eec_t *ibtl_async_eec_list_start, *ibtl_async_eec_list_end;
static ibtl_qp_t *ibtl_async_qp_list_start, *ibtl_async_qp_list_end;
static ibtl_cq_t *ibtl_async_cq_list_start, *ibtl_async_cq_list_end;
static ibtl_srq_t *ibtl_async_srq_list_start, *ibtl_async_srq_list_end;

/* data for CQ completion handling by threads */
static kmutex_t ibtl_cq_mutex;	/* protects the cv and the list below */
static kcondvar_t ibtl_cq_cv;
static ibtl_cq_t *ibtl_cq_list_start, *ibtl_cq_list_end;

static int ibtl_cq_threads = 0;		/* total # of cq threads */
static int ibtl_cqs_using_threads = 0;	/* total # of cqs using threads */
static int ibtl_cq_thread_exit = 0;	/* set if/when thread(s) should exit */

/* value used to tell IBTL threads to exit */
#define	IBTL_THREAD_EXIT 0x1b7fdead	/* IBTF DEAD */
/* Cisco Topspin Vendor ID for Rereg hack */
#define	IBT_VENDOR_CISCO 0x05ad

int ibtl_eec_not_supported = 1;

char *ibtl_last_client_name;	/* may help debugging */
typedef ibt_status_t (*ibtl_node_info_cb_t)(ib_guid_t, uint8_t, ib_lid_t,
    ibt_node_info_t *);

ibtl_node_info_cb_t ibtl_node_info_cb;

_NOTE(LOCK_ORDER(ibtl_clnt_list_mutex ibtl_async_mutex))

void
ibtl_cm_set_node_info_cb(ibt_status_t (*node_info_cb)(ib_guid_t, uint8_t,
    ib_lid_t, ibt_node_info_t *))
{
	mutex_enter(&ibtl_clnt_list_mutex);
	ibtl_node_info_cb = node_info_cb;
	mutex_exit(&ibtl_clnt_list_mutex);
}

/*
 * ibc_async_handler()
 *
 * Asynchronous Event/Error Handler.
 *
 *	This is the function called HCA drivers to post various async
 *	event and errors mention in the IB architecture spec.  See
 *	ibtl_types.h for additional details of this.
 *
 *	This function marks the pertinent IBTF object with the async_code,
 *	and queues the object for handling by an ibtl_async_thread.  If
 *	the object is NOT already marked for async processing, it is added
 *	to the associated list for that type of object, and an
 *	ibtl_async_thread is signaled to finish the async work.
 */
void
ibc_async_handler(ibc_clnt_hdl_t hca_devp, ibt_async_code_t code,
    ibc_async_event_t *event_p)
{
	ibtl_qp_t	*ibtl_qp;
	ibtl_cq_t	*ibtl_cq;
	ibtl_srq_t	*ibtl_srq;
	ibtl_eec_t	*ibtl_eec;
	uint8_t		port_minus1;

	ibtl_async_port_event_t	*portp;

	IBTF_DPRINTF_L2(ibtf_handlers, "ibc_async_handler(%p, 0x%x, %p)",
	    hca_devp, code, event_p);

	mutex_enter(&ibtl_async_mutex);

	switch (code) {
	case IBT_EVENT_PATH_MIGRATED_QP:
	case IBT_EVENT_SQD:
	case IBT_ERROR_CATASTROPHIC_QP:
	case IBT_ERROR_PATH_MIGRATE_REQ_QP:
	case IBT_EVENT_COM_EST_QP:
	case IBT_ERROR_INVALID_REQUEST_QP:
	case IBT_ERROR_ACCESS_VIOLATION_QP:
	case IBT_EVENT_EMPTY_QP:
	case IBT_FEXCH_ERROR:
		ibtl_qp = event_p->ev_qp_hdl;
		if (ibtl_qp == NULL) {
			IBTF_DPRINTF_L2(ibtf_handlers, "ibc_async_handler: "
			    "bad qp handle");
			break;
		}
		switch (code) {
		case IBT_ERROR_CATASTROPHIC_QP:
			ibtl_qp->qp_cat_fma_ena = event_p->ev_fma_ena; break;
		case IBT_ERROR_PATH_MIGRATE_REQ_QP:
			ibtl_qp->qp_pth_fma_ena = event_p->ev_fma_ena; break;
		case IBT_ERROR_INVALID_REQUEST_QP:
			ibtl_qp->qp_inv_fma_ena = event_p->ev_fma_ena; break;
		case IBT_ERROR_ACCESS_VIOLATION_QP:
			ibtl_qp->qp_acc_fma_ena = event_p->ev_fma_ena; break;
		}

		ibtl_qp->qp_async_codes |= code;
		if ((ibtl_qp->qp_async_flags & IBTL_ASYNC_PENDING) == 0) {
			ibtl_qp->qp_async_flags |= IBTL_ASYNC_PENDING;
			ibtl_qp->qp_async_link = NULL;
			if (ibtl_async_qp_list_end == NULL)
				ibtl_async_qp_list_start = ibtl_qp;
			else
				ibtl_async_qp_list_end->qp_async_link = ibtl_qp;
			ibtl_async_qp_list_end = ibtl_qp;
			cv_signal(&ibtl_async_cv);
		}
		break;

	case IBT_ERROR_CQ:
		ibtl_cq = event_p->ev_cq_hdl;
		if (ibtl_cq == NULL) {
			IBTF_DPRINTF_L2(ibtf_handlers, "ibc_async_handler: "
			    "bad cq handle");
			break;
		}
		ibtl_cq->cq_async_codes |= code;
		ibtl_cq->cq_fma_ena = event_p->ev_fma_ena;
		if ((ibtl_cq->cq_async_flags & IBTL_ASYNC_PENDING) == 0) {
			ibtl_cq->cq_async_flags |= IBTL_ASYNC_PENDING;
			ibtl_cq->cq_async_link = NULL;
			if (ibtl_async_cq_list_end == NULL)
				ibtl_async_cq_list_start = ibtl_cq;
			else
				ibtl_async_cq_list_end->cq_async_link = ibtl_cq;
			ibtl_async_cq_list_end = ibtl_cq;
			cv_signal(&ibtl_async_cv);
		}
		break;

	case IBT_ERROR_CATASTROPHIC_SRQ:
	case IBT_EVENT_LIMIT_REACHED_SRQ:
		ibtl_srq = event_p->ev_srq_hdl;
		if (ibtl_srq == NULL) {
			IBTF_DPRINTF_L2(ibtf_handlers, "ibc_async_handler: "
			    "bad srq handle");
			break;
		}
		ibtl_srq->srq_async_codes |= code;
		ibtl_srq->srq_fma_ena = event_p->ev_fma_ena;
		if ((ibtl_srq->srq_async_flags & IBTL_ASYNC_PENDING) == 0) {
			ibtl_srq->srq_async_flags |= IBTL_ASYNC_PENDING;
			ibtl_srq->srq_async_link = NULL;
			if (ibtl_async_srq_list_end == NULL)
				ibtl_async_srq_list_start = ibtl_srq;
			else
				ibtl_async_srq_list_end->srq_async_link =
				    ibtl_srq;
			ibtl_async_srq_list_end = ibtl_srq;
			cv_signal(&ibtl_async_cv);
		}
		break;

	case IBT_EVENT_PATH_MIGRATED_EEC:
	case IBT_ERROR_PATH_MIGRATE_REQ_EEC:
	case IBT_ERROR_CATASTROPHIC_EEC:
	case IBT_EVENT_COM_EST_EEC:
		if (ibtl_eec_not_supported) {
			IBTF_DPRINTF_L2(ibtf_handlers, "ibc_async_handler: "
			    "EEC events are disabled.");
			break;
		}
		ibtl_eec = event_p->ev_eec_hdl;
		if (ibtl_eec == NULL) {
			IBTF_DPRINTF_L2(ibtf_handlers, "ibc_async_handler: "
			    "bad eec handle");
			break;
		}
		switch (code) {
		case IBT_ERROR_PATH_MIGRATE_REQ_EEC:
			ibtl_eec->eec_pth_fma_ena = event_p->ev_fma_ena; break;
		case IBT_ERROR_CATASTROPHIC_EEC:
			ibtl_eec->eec_cat_fma_ena = event_p->ev_fma_ena; break;
		}
		ibtl_eec->eec_async_codes |= code;
		if ((ibtl_eec->eec_async_flags & IBTL_ASYNC_PENDING) == 0) {
			ibtl_eec->eec_async_flags |= IBTL_ASYNC_PENDING;
			ibtl_eec->eec_async_link = NULL;
			if (ibtl_async_eec_list_end == NULL)
				ibtl_async_eec_list_start = ibtl_eec;
			else
				ibtl_async_eec_list_end->eec_async_link =
				    ibtl_eec;
			ibtl_async_eec_list_end = ibtl_eec;
			cv_signal(&ibtl_async_cv);
		}
		break;

	case IBT_ERROR_LOCAL_CATASTROPHIC:
		hca_devp->hd_async_codes |= code;
		hca_devp->hd_fma_ena = event_p->ev_fma_ena;
		/* FALLTHROUGH */

	case IBT_EVENT_PORT_UP:
	case IBT_PORT_CHANGE_EVENT:
	case IBT_CLNT_REREG_EVENT:
	case IBT_ERROR_PORT_DOWN:
		if ((code & IBT_PORT_EVENTS) != 0) {
			if ((port_minus1 = event_p->ev_port - 1) >=
			    hca_devp->hd_hca_attr->hca_nports) {
				IBTF_DPRINTF_L2(ibtf_handlers,
				    "ibc_async_handler: bad port #: %d",
				    event_p->ev_port);
				break;
			}
			portp = &hca_devp->hd_async_port[port_minus1];
			if (code == IBT_EVENT_PORT_UP) {
				/*
				 * The port is just coming UP we can't have any
				 * valid older events.
				 */
				portp->status = IBTL_HCA_PORT_UP;
			} else if (code == IBT_ERROR_PORT_DOWN) {
				/*
				 * The port is going DOWN older events don't
				 * count.
				 */
				portp->status = IBTL_HCA_PORT_DOWN;
			} else if (code == IBT_PORT_CHANGE_EVENT) {
				/*
				 * For port UP and DOWN events only the latest
				 * event counts. If we get a UP after DOWN it
				 * is sufficient to send just UP and vice versa.
				 * In the case of port CHANGE event it is valid
				 * only when the port is UP already but if we
				 * receive it after UP but before UP is
				 * delivered we still need to deliver CHANGE
				 * after we deliver UP event.
				 *
				 * We will not get a CHANGE event when the port
				 * is down or DOWN event is pending.
				 */
				portp->flags |= event_p->ev_port_flags;
				portp->status |= IBTL_HCA_PORT_CHG;
			} else if (code == IBT_CLNT_REREG_EVENT) {
				/*
				 * SM has requested a re-register of
				 * subscription to SM events notification.
				 */
				portp->status |= IBTL_HCA_PORT_ASYNC_CLNT_REREG;
			}

			hca_devp->hd_async_codes |= code;
		}

		if ((hca_devp->hd_async_flags & IBTL_ASYNC_PENDING) == 0) {
			hca_devp->hd_async_flags |= IBTL_ASYNC_PENDING;
			hca_devp->hd_async_link = NULL;
			if (ibtl_async_hca_list_end == NULL)
				ibtl_async_hca_list_start = hca_devp;
			else
				ibtl_async_hca_list_end->hd_async_link =
				    hca_devp;
			ibtl_async_hca_list_end = hca_devp;
			cv_signal(&ibtl_async_cv);
		}

		break;

	default:
		IBTF_DPRINTF_L1(ibtf_handlers, "ibc_async_handler: "
		    "invalid code (0x%x)", code);
	}

	mutex_exit(&ibtl_async_mutex);
}


/* Finally, make the async call to the client. */

static void
ibtl_async_client_call(ibtl_hca_t *ibt_hca, ibt_async_code_t code,
    ibt_async_event_t *event_p)
{
	ibtl_clnt_t		*clntp;
	void			*client_private;
	ibt_async_handler_t	async_handler;
	char			*client_name;

	IBTF_DPRINTF_L2(ibtf_handlers, "ibtl_async_client_call(%p, 0x%x, %p)",
	    ibt_hca, code, event_p);

	clntp = ibt_hca->ha_clnt_devp;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(ibtl_last_client_name))
	/* Record who is being called (just a debugging aid) */
	ibtl_last_client_name = client_name = clntp->clnt_name;
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(ibtl_last_client_name))

	client_private = clntp->clnt_private;
	async_handler = clntp->clnt_modinfop->mi_async_handler;

	if (code & (IBT_EVENT_COM_EST_QP | IBT_EVENT_COM_EST_EEC)) {
		mutex_enter(&ibtl_clnt_list_mutex);
		async_handler = ibtl_cm_async_handler;
		client_private = ibtl_cm_clnt_private;
		mutex_exit(&ibtl_clnt_list_mutex);
		ibt_hca = NULL;
		IBTF_DPRINTF_L2(ibtf_handlers, "ibtl_async_client_call: "
		    "calling CM for COM_EST");
	} else {
		IBTF_DPRINTF_L2(ibtf_handlers, "ibtl_async_client_call: "
		    "calling client '%s'", client_name);
	}
	if (async_handler != NULL)
		async_handler(client_private, ibt_hca, code, event_p);
	else
		IBTF_DPRINTF_L2(ibtf_handlers, "ibtl_async_client_call: "
		    "client '%s' has no async handler", client_name);
}

/*
 * Inform CM or DM about HCA events.
 *
 *	We use taskqs to allow simultaneous notification, with sleeping.
 *	Since taskqs only allow one argument, we define a structure
 *	because we need to pass in more than one argument.
 */

struct ibtl_mgr_s {
	ibtl_hca_devinfo_t	*mgr_hca_devp;
	ibt_async_handler_t	mgr_async_handler;
	void			*mgr_clnt_private;
};

/*
 * Asyncs of HCA level events for CM and DM.  Call CM or DM and tell them
 * about the HCA for the event recorded in the ibtl_hca_devinfo_t.
 */
static void
ibtl_do_mgr_async_task(void *arg)
{
	struct ibtl_mgr_s	*mgrp = (struct ibtl_mgr_s *)arg;
	ibtl_hca_devinfo_t	*hca_devp = mgrp->mgr_hca_devp;

	IBTF_DPRINTF_L2(ibtf_handlers, "ibtl_do_mgr_async_task(0x%x)",
	    hca_devp->hd_async_code);

	mgrp->mgr_async_handler(mgrp->mgr_clnt_private, NULL,
	    hca_devp->hd_async_code, &hca_devp->hd_async_event);
	kmem_free(mgrp, sizeof (*mgrp));

	mutex_enter(&ibtl_clnt_list_mutex);
	if (--hca_devp->hd_async_task_cnt == 0)
		cv_signal(&hca_devp->hd_async_task_cv);
	mutex_exit(&ibtl_clnt_list_mutex);
}

static void
ibt_cisco_embedded_sm_rereg_fix(void *arg)
{
	struct ibtl_mgr_s *mgrp = arg;
	ibtl_hca_devinfo_t *hca_devp;
	ibt_node_info_t node_info;
	ibt_status_t ibt_status;
	ibtl_async_port_event_t *portp;
	ib_lid_t sm_lid;
	ib_guid_t hca_guid;
	ibt_async_event_t *event_p;
	ibt_hca_portinfo_t *pinfop;
	uint8_t	port;

	hca_devp = mgrp->mgr_hca_devp;

	mutex_enter(&ibtl_clnt_list_mutex);
	event_p = &hca_devp->hd_async_event;
	port = event_p->ev_port;
	portp = &hca_devp->hd_async_port[port - 1];
	pinfop = &hca_devp->hd_portinfop[port - 1];
	sm_lid = pinfop->p_sm_lid;
	hca_guid = hca_devp->hd_hca_attr->hca_node_guid;
	mutex_exit(&ibtl_clnt_list_mutex);

	ibt_status = ((ibtl_node_info_cb_t)(uintptr_t)
	    mgrp->mgr_async_handler)(hca_guid, port, sm_lid, &node_info);
	if (ibt_status == IBT_SUCCESS) {
		if ((node_info.n_vendor_id == IBT_VENDOR_CISCO) &&
		    (node_info.n_node_type == IBT_NODE_TYPE_SWITCH)) {
			mutex_enter(&ibtl_async_mutex);
			portp->status |= IBTL_HCA_PORT_ASYNC_CLNT_REREG;
			hca_devp->hd_async_codes |= IBT_CLNT_REREG_EVENT;
			mutex_exit(&ibtl_async_mutex);
		}
	}
	kmem_free(mgrp, sizeof (*mgrp));

	mutex_enter(&ibtl_clnt_list_mutex);
	if (--hca_devp->hd_async_task_cnt == 0)
		cv_signal(&hca_devp->hd_async_task_cv);
	mutex_exit(&ibtl_clnt_list_mutex);
}

static void
ibtl_cm_get_node_info(ibtl_hca_devinfo_t *hca_devp,
    ibt_async_handler_t async_handler)
{
	struct ibtl_mgr_s *mgrp;

	if (async_handler == NULL)
		return;

	_NOTE(NO_COMPETING_THREADS_NOW)
	mgrp = kmem_alloc(sizeof (*mgrp), KM_SLEEP);
	mgrp->mgr_hca_devp = hca_devp;
	mgrp->mgr_async_handler = async_handler;
	mgrp->mgr_clnt_private = NULL;
	hca_devp->hd_async_task_cnt++;

	(void) taskq_dispatch(ibtl_async_taskq,
	    ibt_cisco_embedded_sm_rereg_fix, mgrp, TQ_SLEEP);
#ifndef lint
	_NOTE(COMPETING_THREADS_NOW)
#endif
}

static void
ibtl_tell_mgr(ibtl_hca_devinfo_t *hca_devp, ibt_async_handler_t async_handler,
    void *clnt_private)
{
	struct ibtl_mgr_s *mgrp;

	if (async_handler == NULL)
		return;

	_NOTE(NO_COMPETING_THREADS_NOW)
	mgrp = kmem_alloc(sizeof (*mgrp), KM_SLEEP);
	mgrp->mgr_hca_devp = hca_devp;
	mgrp->mgr_async_handler = async_handler;
	mgrp->mgr_clnt_private = clnt_private;
	hca_devp->hd_async_task_cnt++;

	(void) taskq_dispatch(ibtl_async_taskq, ibtl_do_mgr_async_task, mgrp,
	    TQ_SLEEP);
#ifndef lint
	_NOTE(COMPETING_THREADS_NOW)
#endif
}

/*
 * Per client-device asyncs for HCA level events.  Call each client that is
 * using the HCA for the event recorded in the ibtl_hca_devinfo_t.
 */
static void
ibtl_hca_client_async_task(void *arg)
{
	ibtl_hca_t		*ibt_hca = (ibtl_hca_t *)arg;
	ibtl_hca_devinfo_t	*hca_devp = ibt_hca->ha_hca_devp;
	ibtl_clnt_t		*clntp = ibt_hca->ha_clnt_devp;
	ibt_async_event_t	async_event;

	IBTF_DPRINTF_L3(ibtf_handlers, "ibtl_hca_client_async_task(%p, 0x%x)",
	    ibt_hca, hca_devp->hd_async_code);

	bcopy(&hca_devp->hd_async_event, &async_event, sizeof (async_event));
	ibtl_async_client_call(ibt_hca, hca_devp->hd_async_code, &async_event);

	mutex_enter(&ibtl_async_mutex);
	if (--ibt_hca->ha_async_cnt == 0 &&
	    (ibt_hca->ha_async_flags & IBTL_ASYNC_FREE_OBJECT)) {
		mutex_exit(&ibtl_async_mutex);
		kmem_free(ibt_hca, sizeof (ibtl_hca_t));
	} else
		mutex_exit(&ibtl_async_mutex);

	mutex_enter(&ibtl_clnt_list_mutex);
	if (--hca_devp->hd_async_task_cnt == 0)
		cv_signal(&hca_devp->hd_async_task_cv);
	if (--clntp->clnt_async_cnt == 0)
		cv_broadcast(&ibtl_clnt_cv);

	mutex_exit(&ibtl_clnt_list_mutex);
}

/*
 * Asyncs for HCA level events.
 *
 * The function continues to run until there are no more async
 * events/errors for this HCA.  An event is chosen for dispatch
 * to all clients of this HCA.  This thread dispatches them via
 * the ibtl_async_taskq, then sleeps until all tasks are done.
 *
 * This thread records the async_code and async_event in the
 * ibtl_hca_devinfo_t for all client taskq threads to reference.
 *
 * This is called from an async or taskq thread with ibtl_async_mutex held.
 */
static void
ibtl_do_hca_asyncs(ibtl_hca_devinfo_t *hca_devp)
{
	ibtl_hca_t			*ibt_hca;
	ibt_async_event_t		*eventp;
	ibt_async_code_t		code;
	ibtl_async_port_status_t  	temp;
	uint8_t				nports;
	uint8_t				port_minus1;
	ibtl_async_port_event_t		*portp;

	mutex_exit(&ibtl_async_mutex);

	mutex_enter(&ibtl_clnt_list_mutex);
	while (hca_devp->hd_async_busy)
		cv_wait(&hca_devp->hd_async_busy_cv, &ibtl_clnt_list_mutex);
	hca_devp->hd_async_busy = 1;
	mutex_enter(&ibtl_async_mutex);

	bzero(&hca_devp->hd_async_event, sizeof (hca_devp->hd_async_event));
	for (;;) {

		hca_devp->hd_async_event.ev_fma_ena = 0;

		code = hca_devp->hd_async_codes;
		if (code & IBT_ERROR_LOCAL_CATASTROPHIC) {
			code = IBT_ERROR_LOCAL_CATASTROPHIC;
			hca_devp->hd_async_event.ev_fma_ena =
			    hca_devp->hd_fma_ena;
		} else if (code & IBT_ERROR_PORT_DOWN) {
			code = IBT_ERROR_PORT_DOWN;
			temp = IBTL_HCA_PORT_DOWN;
		} else if (code & IBT_EVENT_PORT_UP) {
			code = IBT_EVENT_PORT_UP;
			temp = IBTL_HCA_PORT_UP;
		} else if (code & IBT_PORT_CHANGE_EVENT) {
			code = IBT_PORT_CHANGE_EVENT;
			temp = IBTL_HCA_PORT_CHG;
		} else if (code & IBT_CLNT_REREG_EVENT) {
			code = IBT_CLNT_REREG_EVENT;
			temp = IBTL_HCA_PORT_ASYNC_CLNT_REREG;
		} else {
			hca_devp->hd_async_codes = 0;
			code = 0;
		}

		if (code == 0) {
			hca_devp->hd_async_flags &= ~IBTL_ASYNC_PENDING;
			break;
		}
		hca_devp->hd_async_codes &= ~code;

		/* PORT_UP, PORT_CHANGE, PORT_DOWN or ASYNC_REREG */
		if ((code & IBT_PORT_EVENTS) != 0) {
			portp = hca_devp->hd_async_port;
			nports = hca_devp->hd_hca_attr->hca_nports;
			for (port_minus1 = 0; port_minus1 < nports;
			    port_minus1++) {
				/*
				 * Matching event in this port, let's go handle
				 * it.
				 */
				if ((portp[port_minus1].status & temp) != 0)
					break;
			}
			if (port_minus1 >= nports) {
				/* we checked again, but found nothing */
				continue;
			}
			IBTF_DPRINTF_L4(ibtf_handlers, "ibtl_do_hca_asyncs: "
			    "async: port# %x code %x", port_minus1 + 1, code);
			/* mark it to check for other ports after we're done */
			hca_devp->hd_async_codes |= code;

			/*
			 * Copy the event information into hca_devp and clear
			 * event information from the per port data.
			 */
			hca_devp->hd_async_event.ev_port = port_minus1 + 1;
			if (temp == IBTL_HCA_PORT_CHG) {
				hca_devp->hd_async_event.ev_port_flags =
				    hca_devp->hd_async_port[port_minus1].flags;
				hca_devp->hd_async_port[port_minus1].flags = 0;
			}
			hca_devp->hd_async_port[port_minus1].status &= ~temp;

			mutex_exit(&ibtl_async_mutex);
			ibtl_reinit_hca_portinfo(hca_devp, port_minus1 + 1);
			mutex_enter(&ibtl_async_mutex);
			eventp = &hca_devp->hd_async_event;
			eventp->ev_hca_guid =
			    hca_devp->hd_hca_attr->hca_node_guid;
		}

		hca_devp->hd_async_code = code;
		hca_devp->hd_async_event.ev_hca_guid =
		    hca_devp->hd_hca_attr->hca_node_guid;
		mutex_exit(&ibtl_async_mutex);

		/*
		 * Make sure to inform CM, DM, and IBMA if we know of them.
		 * Also, make sure not to inform them a second time, which
		 * would occur if they have the HCA open.
		 */

		if (ibtl_ibma_async_handler)
			ibtl_tell_mgr(hca_devp, ibtl_ibma_async_handler,
			    ibtl_ibma_clnt_private);
		/* wait for all tasks to complete */
		while (hca_devp->hd_async_task_cnt != 0)
			cv_wait(&hca_devp->hd_async_task_cv,
			    &ibtl_clnt_list_mutex);

		/*
		 * Hack Alert:
		 * The ibmf handler would have updated the Master SM LID if it
		 * was SM LID change event. Now lets check if the new Master SM
		 * is a Embedded Cisco Topspin SM.
		 */
		if ((code == IBT_PORT_CHANGE_EVENT) &&
		    eventp->ev_port_flags & IBT_PORT_CHANGE_SM_LID)
			ibtl_cm_get_node_info(hca_devp,
			    (ibt_async_handler_t)(uintptr_t)ibtl_node_info_cb);
		/* wait for node info task to complete */
		while (hca_devp->hd_async_task_cnt != 0)
			cv_wait(&hca_devp->hd_async_task_cv,
			    &ibtl_clnt_list_mutex);

		if (ibtl_dm_async_handler)
			ibtl_tell_mgr(hca_devp, ibtl_dm_async_handler,
			    ibtl_dm_clnt_private);
		if (ibtl_cm_async_handler)
			ibtl_tell_mgr(hca_devp, ibtl_cm_async_handler,
			    ibtl_cm_clnt_private);
		/* wait for all tasks to complete */
		while (hca_devp->hd_async_task_cnt != 0)
			cv_wait(&hca_devp->hd_async_task_cv,
			    &ibtl_clnt_list_mutex);

		for (ibt_hca = hca_devp->hd_clnt_list;
		    ibt_hca != NULL;
		    ibt_hca = ibt_hca->ha_clnt_link) {

			/* Managers are handled above */
			if (IBTL_HCA2MODI_P(ibt_hca)->mi_async_handler ==
			    ibtl_cm_async_handler)
				continue;
			if (IBTL_HCA2MODI_P(ibt_hca)->mi_async_handler ==
			    ibtl_dm_async_handler)
				continue;
			if (IBTL_HCA2MODI_P(ibt_hca)->mi_async_handler ==
			    ibtl_ibma_async_handler)
				continue;
			++ibt_hca->ha_clnt_devp->clnt_async_cnt;

			mutex_enter(&ibtl_async_mutex);
			ibt_hca->ha_async_cnt++;
			mutex_exit(&ibtl_async_mutex);
			hca_devp->hd_async_task_cnt++;
			(void) taskq_dispatch(ibtl_async_taskq,
			    ibtl_hca_client_async_task, ibt_hca, TQ_SLEEP);
		}

		/* wait for all tasks to complete */
		while (hca_devp->hd_async_task_cnt != 0)
			cv_wait(&hca_devp->hd_async_task_cv,
			    &ibtl_clnt_list_mutex);

		mutex_enter(&ibtl_async_mutex);
	}
	hca_devp->hd_async_code = 0;
	hca_devp->hd_async_busy = 0;
	cv_broadcast(&hca_devp->hd_async_busy_cv);
	mutex_exit(&ibtl_clnt_list_mutex);
}

/*
 * Asyncs for QP objects.
 *
 * The function continues to run until there are no more async
 * events/errors for this object.
 */
static void
ibtl_do_qp_asyncs(ibtl_qp_t *ibtl_qp)
{
	ibt_async_code_t	code;
	ibt_async_event_t	async_event;

	ASSERT(MUTEX_HELD(&ibtl_async_mutex));
	bzero(&async_event, sizeof (async_event));
	async_event.ev_chan_hdl = IBTL_QP2CHAN(ibtl_qp);

	while ((code = ibtl_qp->qp_async_codes) != 0) {
		async_event.ev_fma_ena = 0;
		if (ibtl_qp->qp_async_flags & IBTL_ASYNC_FREE_OBJECT)
			code = 0;	/* fallthrough to "kmem_free" */
		else if (code & IBT_ERROR_CATASTROPHIC_QP) {
			code = IBT_ERROR_CATASTROPHIC_QP;
			async_event.ev_fma_ena = ibtl_qp->qp_cat_fma_ena;
		} else if (code & IBT_ERROR_INVALID_REQUEST_QP) {
			code = IBT_ERROR_INVALID_REQUEST_QP;
			async_event.ev_fma_ena = ibtl_qp->qp_inv_fma_ena;
		} else if (code & IBT_ERROR_ACCESS_VIOLATION_QP) {
			code = IBT_ERROR_ACCESS_VIOLATION_QP;
			async_event.ev_fma_ena = ibtl_qp->qp_acc_fma_ena;
		} else if (code & IBT_ERROR_PATH_MIGRATE_REQ_QP) {
			code = IBT_ERROR_PATH_MIGRATE_REQ_QP;
			async_event.ev_fma_ena = ibtl_qp->qp_pth_fma_ena;
		} else if (code & IBT_EVENT_PATH_MIGRATED_QP)
			code = IBT_EVENT_PATH_MIGRATED_QP;
		else if (code & IBT_EVENT_SQD)
			code = IBT_EVENT_SQD;
		else if (code & IBT_EVENT_COM_EST_QP)
			code = IBT_EVENT_COM_EST_QP;
		else if (code & IBT_EVENT_EMPTY_QP)
			code = IBT_EVENT_EMPTY_QP;
		else {
			IBTF_DPRINTF_L2(ibtf_handlers, "ibtl_do_qp_asyncs: "
			    "async: unexpected QP async code 0x%x", code);
			ibtl_qp->qp_async_codes = 0;
			code = 0;
		}
		ibtl_qp->qp_async_codes &= ~code;

		if (code) {
			mutex_exit(&ibtl_async_mutex);
			ibtl_async_client_call(ibtl_qp->qp_hca,
			    code, &async_event);
			mutex_enter(&ibtl_async_mutex);
		}

		if (ibtl_qp->qp_async_flags & IBTL_ASYNC_FREE_OBJECT) {
			mutex_exit(&ibtl_async_mutex);
			cv_destroy(&(IBTL_QP2CHAN(ibtl_qp))->ch_cm_cv);
			mutex_destroy(&(IBTL_QP2CHAN(ibtl_qp))->ch_cm_mutex);
			kmem_free(IBTL_QP2CHAN(ibtl_qp),
			    sizeof (ibtl_channel_t));
			mutex_enter(&ibtl_async_mutex);
			return;
		}
	}
	ibtl_qp->qp_async_flags &= ~IBTL_ASYNC_PENDING;
}

/*
 * Asyncs for SRQ objects.
 *
 * The function continues to run until there are no more async
 * events/errors for this object.
 */
static void
ibtl_do_srq_asyncs(ibtl_srq_t *ibtl_srq)
{
	ibt_async_code_t	code;
	ibt_async_event_t	async_event;

	ASSERT(MUTEX_HELD(&ibtl_async_mutex));
	bzero(&async_event, sizeof (async_event));
	async_event.ev_srq_hdl = ibtl_srq;
	async_event.ev_fma_ena = ibtl_srq->srq_fma_ena;

	while ((code = ibtl_srq->srq_async_codes) != 0) {
		if (ibtl_srq->srq_async_flags & IBTL_ASYNC_FREE_OBJECT)
			code = 0;	/* fallthrough to "kmem_free" */
		else if (code & IBT_ERROR_CATASTROPHIC_SRQ)
			code = IBT_ERROR_CATASTROPHIC_SRQ;
		else if (code & IBT_EVENT_LIMIT_REACHED_SRQ)
			code = IBT_EVENT_LIMIT_REACHED_SRQ;
		else {
			IBTF_DPRINTF_L2(ibtf_handlers, "ibtl_do_srq_asyncs: "
			    "async: unexpected SRQ async code 0x%x", code);
			ibtl_srq->srq_async_codes = 0;
			code = 0;
		}
		ibtl_srq->srq_async_codes &= ~code;

		if (code) {
			mutex_exit(&ibtl_async_mutex);
			ibtl_async_client_call(ibtl_srq->srq_hca,
			    code, &async_event);
			mutex_enter(&ibtl_async_mutex);
		}

		if (ibtl_srq->srq_async_flags & IBTL_ASYNC_FREE_OBJECT) {
			mutex_exit(&ibtl_async_mutex);
			kmem_free(ibtl_srq, sizeof (struct ibtl_srq_s));
			mutex_enter(&ibtl_async_mutex);
			return;
		}
	}
	ibtl_srq->srq_async_flags &= ~IBTL_ASYNC_PENDING;
}

/*
 * Asyncs for CQ objects.
 *
 * The function continues to run until there are no more async
 * events/errors for this object.
 */
static void
ibtl_do_cq_asyncs(ibtl_cq_t *ibtl_cq)
{
	ibt_async_code_t	code;
	ibt_async_event_t	async_event;

	ASSERT(MUTEX_HELD(&ibtl_async_mutex));
	bzero(&async_event, sizeof (async_event));
	async_event.ev_cq_hdl = ibtl_cq;
	async_event.ev_fma_ena = ibtl_cq->cq_fma_ena;

	while ((code = ibtl_cq->cq_async_codes) != 0) {
		if (ibtl_cq->cq_async_flags & IBTL_ASYNC_FREE_OBJECT)
			code = 0;	/* fallthrough to "kmem_free" */
		else if (code & IBT_ERROR_CQ)
			code = IBT_ERROR_CQ;
		else {
			IBTF_DPRINTF_L2(ibtf_handlers, "ibtl_do_cq_asyncs: "
			    "async: unexpected CQ async code 0x%x", code);
			ibtl_cq->cq_async_codes = 0;
			code = 0;
		}
		ibtl_cq->cq_async_codes &= ~code;

		if (code) {
			mutex_exit(&ibtl_async_mutex);
			ibtl_async_client_call(ibtl_cq->cq_hca,
			    code, &async_event);
			mutex_enter(&ibtl_async_mutex);
		}

		if (ibtl_cq->cq_async_flags & IBTL_ASYNC_FREE_OBJECT) {
			mutex_exit(&ibtl_async_mutex);
			mutex_destroy(&ibtl_cq->cq_mutex);
			kmem_free(ibtl_cq, sizeof (struct ibtl_cq_s));
			mutex_enter(&ibtl_async_mutex);
			return;
		}
	}
	ibtl_cq->cq_async_flags &= ~IBTL_ASYNC_PENDING;
}

/*
 * Asyncs for EEC objects.
 *
 * The function continues to run until there are no more async
 * events/errors for this object.
 */
static void
ibtl_do_eec_asyncs(ibtl_eec_t *ibtl_eec)
{
	ibt_async_code_t	code;
	ibt_async_event_t	async_event;

	ASSERT(MUTEX_HELD(&ibtl_async_mutex));
	bzero(&async_event, sizeof (async_event));
	async_event.ev_chan_hdl = ibtl_eec->eec_channel;

	while ((code = ibtl_eec->eec_async_codes) != 0) {
		async_event.ev_fma_ena = 0;
		if (ibtl_eec->eec_async_flags & IBTL_ASYNC_FREE_OBJECT)
			code = 0;	/* fallthrough to "kmem_free" */
		else if (code & IBT_ERROR_CATASTROPHIC_EEC) {
			code = IBT_ERROR_CATASTROPHIC_CHAN;
			async_event.ev_fma_ena = ibtl_eec->eec_cat_fma_ena;
		} else if (code & IBT_ERROR_PATH_MIGRATE_REQ_EEC) {
			code = IBT_ERROR_PATH_MIGRATE_REQ;
			async_event.ev_fma_ena = ibtl_eec->eec_pth_fma_ena;
		} else if (code & IBT_EVENT_PATH_MIGRATED_EEC)
			code = IBT_EVENT_PATH_MIGRATED;
		else if (code & IBT_EVENT_COM_EST_EEC)
			code = IBT_EVENT_COM_EST;
		else {
			IBTF_DPRINTF_L2(ibtf_handlers, "ibtl_do_eec_asyncs: "
			    "async: unexpected code 0x%x", code);
			ibtl_eec->eec_async_codes = 0;
			code = 0;
		}
		ibtl_eec->eec_async_codes &= ~code;

		if (code) {
			mutex_exit(&ibtl_async_mutex);
			ibtl_async_client_call(ibtl_eec->eec_hca,
			    code, &async_event);
			mutex_enter(&ibtl_async_mutex);
		}

		if (ibtl_eec->eec_async_flags & IBTL_ASYNC_FREE_OBJECT) {
			mutex_exit(&ibtl_async_mutex);
			kmem_free(ibtl_eec, sizeof (struct ibtl_eec_s));
			mutex_enter(&ibtl_async_mutex);
			return;
		}
	}
	ibtl_eec->eec_async_flags &= ~IBTL_ASYNC_PENDING;
}

#ifdef __lock_lint
kmutex_t cpr_mutex;
#endif

/*
 * Loop forever, calling async_handlers until all of the async lists
 * are empty.
 */

static void
ibtl_async_thread(void)
{
#ifndef __lock_lint
	kmutex_t cpr_mutex;
#endif
	callb_cpr_t	cprinfo;

	_NOTE(MUTEX_PROTECTS_DATA(cpr_mutex, cprinfo))
	_NOTE(NO_COMPETING_THREADS_NOW)
	mutex_init(&cpr_mutex, NULL, MUTEX_DRIVER, NULL);
	CALLB_CPR_INIT(&cprinfo, &cpr_mutex, callb_generic_cpr,
	    "ibtl_async_thread");
#ifndef lint
	_NOTE(COMPETING_THREADS_NOW)
#endif

	mutex_enter(&ibtl_async_mutex);

	for (;;) {
		if (ibtl_async_hca_list_start) {
			ibtl_hca_devinfo_t *hca_devp;

			/* remove first entry from list */
			hca_devp = ibtl_async_hca_list_start;
			ibtl_async_hca_list_start = hca_devp->hd_async_link;
			hca_devp->hd_async_link = NULL;
			if (ibtl_async_hca_list_start == NULL)
				ibtl_async_hca_list_end = NULL;

			ibtl_do_hca_asyncs(hca_devp);

		} else if (ibtl_async_qp_list_start) {
			ibtl_qp_t *ibtl_qp;

			/* remove from list */
			ibtl_qp = ibtl_async_qp_list_start;
			ibtl_async_qp_list_start = ibtl_qp->qp_async_link;
			ibtl_qp->qp_async_link = NULL;
			if (ibtl_async_qp_list_start == NULL)
				ibtl_async_qp_list_end = NULL;

			ibtl_do_qp_asyncs(ibtl_qp);

		} else if (ibtl_async_srq_list_start) {
			ibtl_srq_t *ibtl_srq;

			/* remove from list */
			ibtl_srq = ibtl_async_srq_list_start;
			ibtl_async_srq_list_start = ibtl_srq->srq_async_link;
			ibtl_srq->srq_async_link = NULL;
			if (ibtl_async_srq_list_start == NULL)
				ibtl_async_srq_list_end = NULL;

			ibtl_do_srq_asyncs(ibtl_srq);

		} else if (ibtl_async_eec_list_start) {
			ibtl_eec_t *ibtl_eec;

			/* remove from list */
			ibtl_eec = ibtl_async_eec_list_start;
			ibtl_async_eec_list_start = ibtl_eec->eec_async_link;
			ibtl_eec->eec_async_link = NULL;
			if (ibtl_async_eec_list_start == NULL)
				ibtl_async_eec_list_end = NULL;

			ibtl_do_eec_asyncs(ibtl_eec);

		} else if (ibtl_async_cq_list_start) {
			ibtl_cq_t *ibtl_cq;

			/* remove from list */
			ibtl_cq = ibtl_async_cq_list_start;
			ibtl_async_cq_list_start = ibtl_cq->cq_async_link;
			ibtl_cq->cq_async_link = NULL;
			if (ibtl_async_cq_list_start == NULL)
				ibtl_async_cq_list_end = NULL;

			ibtl_do_cq_asyncs(ibtl_cq);

		} else {
			if (ibtl_async_thread_exit == IBTL_THREAD_EXIT)
				break;
			mutex_enter(&cpr_mutex);
			CALLB_CPR_SAFE_BEGIN(&cprinfo);
			mutex_exit(&cpr_mutex);

			cv_wait(&ibtl_async_cv, &ibtl_async_mutex);

			mutex_exit(&ibtl_async_mutex);
			mutex_enter(&cpr_mutex);
			CALLB_CPR_SAFE_END(&cprinfo, &cpr_mutex);
			mutex_exit(&cpr_mutex);
			mutex_enter(&ibtl_async_mutex);
		}
	}

	mutex_exit(&ibtl_async_mutex);

#ifndef __lock_lint
	mutex_enter(&cpr_mutex);
	CALLB_CPR_EXIT(&cprinfo);
#endif
	mutex_destroy(&cpr_mutex);
}


void
ibtl_free_qp_async_check(ibtl_qp_t *ibtl_qp)
{
	IBTF_DPRINTF_L3(ibtf_handlers, "ibtl_free_qp_async_check(%p)", ibtl_qp);

	mutex_enter(&ibtl_async_mutex);

	/*
	 * If there is an active async, mark this object to be freed
	 * by the async_thread when it's done.
	 */
	if (ibtl_qp->qp_async_flags & IBTL_ASYNC_PENDING) {
		ibtl_qp->qp_async_flags |= IBTL_ASYNC_FREE_OBJECT;
		mutex_exit(&ibtl_async_mutex);
	} else {	/* free the object now */
		mutex_exit(&ibtl_async_mutex);
		cv_destroy(&(IBTL_QP2CHAN(ibtl_qp))->ch_cm_cv);
		mutex_destroy(&(IBTL_QP2CHAN(ibtl_qp))->ch_cm_mutex);
		kmem_free(IBTL_QP2CHAN(ibtl_qp), sizeof (ibtl_channel_t));
	}
}

void
ibtl_free_cq_async_check(ibtl_cq_t *ibtl_cq)
{
	IBTF_DPRINTF_L3(ibtf_handlers, "ibtl_free_cq_async_check(%p)", ibtl_cq);

	mutex_enter(&ibtl_async_mutex);

	/* if there is an active async, mark this object to be freed */
	if (ibtl_cq->cq_async_flags & IBTL_ASYNC_PENDING) {
		ibtl_cq->cq_async_flags |= IBTL_ASYNC_FREE_OBJECT;
		mutex_exit(&ibtl_async_mutex);
	} else {	/* free the object now */
		mutex_exit(&ibtl_async_mutex);
		mutex_destroy(&ibtl_cq->cq_mutex);
		kmem_free(ibtl_cq, sizeof (struct ibtl_cq_s));
	}
}

void
ibtl_free_srq_async_check(ibtl_srq_t *ibtl_srq)
{
	IBTF_DPRINTF_L3(ibtf_handlers, "ibtl_free_srq_async_check(%p)",
	    ibtl_srq);

	mutex_enter(&ibtl_async_mutex);

	/* if there is an active async, mark this object to be freed */
	if (ibtl_srq->srq_async_flags & IBTL_ASYNC_PENDING) {
		ibtl_srq->srq_async_flags |= IBTL_ASYNC_FREE_OBJECT;
		mutex_exit(&ibtl_async_mutex);
	} else {	/* free the object now */
		mutex_exit(&ibtl_async_mutex);
		kmem_free(ibtl_srq, sizeof (struct ibtl_srq_s));
	}
}

void
ibtl_free_eec_async_check(ibtl_eec_t *ibtl_eec)
{
	IBTF_DPRINTF_L3(ibtf_handlers, "ibtl_free_eec_async_check(%p)",
	    ibtl_eec);

	mutex_enter(&ibtl_async_mutex);

	/* if there is an active async, mark this object to be freed */
	if (ibtl_eec->eec_async_flags & IBTL_ASYNC_PENDING) {
		ibtl_eec->eec_async_flags |= IBTL_ASYNC_FREE_OBJECT;
		mutex_exit(&ibtl_async_mutex);
	} else {	/* free the object now */
		mutex_exit(&ibtl_async_mutex);
		kmem_free(ibtl_eec, sizeof (struct ibtl_eec_s));
	}
}

/*
 * This function differs from above in that we assume this is called
 * from non-interrupt context, and never called from the async_thread.
 */

void
ibtl_free_hca_async_check(ibtl_hca_t *ibt_hca)
{
	IBTF_DPRINTF_L3(ibtf_handlers, "ibtl_free_hca_async_check(%p)",
	    ibt_hca);

	mutex_enter(&ibtl_async_mutex);

	/* if there is an active async, mark this object to be freed */
	if (ibt_hca->ha_async_cnt > 0) {
		ibt_hca->ha_async_flags |= IBTL_ASYNC_FREE_OBJECT;
		mutex_exit(&ibtl_async_mutex);
	} else {	/* free the object now */
		mutex_exit(&ibtl_async_mutex);
		kmem_free(ibt_hca, sizeof (ibtl_hca_t));
	}
}

/*
 * Completion Queue Handling.
 *
 *	A completion queue can be handled through a simple callback
 *	at interrupt level, or it may be queued for an ibtl_cq_thread
 *	to handle.  The latter is chosen during ibt_alloc_cq when the
 *	IBTF_CQ_HANDLER_IN_THREAD is specified.
 */

static void
ibtl_cq_handler_call(ibtl_cq_t *ibtl_cq)
{
	ibt_cq_handler_t	cq_handler;
	void			*arg;

	IBTF_DPRINTF_L4(ibtf_handlers, "ibtl_cq_handler_call(%p)", ibtl_cq);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*ibtl_cq))
	cq_handler = ibtl_cq->cq_comp_handler;
	arg = ibtl_cq->cq_arg;
	if (cq_handler != NULL)
		cq_handler(ibtl_cq, arg);
	else
		IBTF_DPRINTF_L2(ibtf_handlers, "ibtl_cq_handler_call: "
		    "no cq_handler for cq %p", ibtl_cq);
}

/*
 * Before ibt_free_cq can continue, we need to ensure no more cq_handler
 * callbacks can occur.  When we get the mutex, we know there are no
 * outstanding cq_handler callbacks.  We set the cq_handler to NULL to
 * prohibit future callbacks.
 */
void
ibtl_free_cq_check(ibtl_cq_t *ibtl_cq)
{
	mutex_enter(&ibtl_cq->cq_mutex);
	ibtl_cq->cq_comp_handler = NULL;
	mutex_exit(&ibtl_cq->cq_mutex);
	if (ibtl_cq->cq_in_thread) {
		mutex_enter(&ibtl_cq_mutex);
		--ibtl_cqs_using_threads;
		while (ibtl_cq->cq_impl_flags & IBTL_CQ_PENDING) {
			ibtl_cq->cq_impl_flags &= ~IBTL_CQ_CALL_CLIENT;
			ibtl_cq->cq_impl_flags |= IBTL_CQ_FREE;
			cv_wait(&ibtl_cq_cv, &ibtl_cq_mutex);
		}
		mutex_exit(&ibtl_cq_mutex);
	}
}

/*
 * Loop forever, calling cq_handlers until the cq list
 * is empty.
 */

static void
ibtl_cq_thread(void)
{
#ifndef __lock_lint
	kmutex_t cpr_mutex;
#endif
	callb_cpr_t	cprinfo;

	_NOTE(MUTEX_PROTECTS_DATA(cpr_mutex, cprinfo))
	_NOTE(NO_COMPETING_THREADS_NOW)
	mutex_init(&cpr_mutex, NULL, MUTEX_DRIVER, NULL);
	CALLB_CPR_INIT(&cprinfo, &cpr_mutex, callb_generic_cpr,
	    "ibtl_cq_thread");
#ifndef lint
	_NOTE(COMPETING_THREADS_NOW)
#endif

	mutex_enter(&ibtl_cq_mutex);

	for (;;) {
		if (ibtl_cq_list_start) {
			ibtl_cq_t *ibtl_cq;

			ibtl_cq = ibtl_cq_list_start;
			ibtl_cq_list_start = ibtl_cq->cq_link;
			ibtl_cq->cq_link = NULL;
			if (ibtl_cq == ibtl_cq_list_end)
				ibtl_cq_list_end = NULL;

			while (ibtl_cq->cq_impl_flags & IBTL_CQ_CALL_CLIENT) {
				ibtl_cq->cq_impl_flags &= ~IBTL_CQ_CALL_CLIENT;
				mutex_exit(&ibtl_cq_mutex);
				ibtl_cq_handler_call(ibtl_cq);
				mutex_enter(&ibtl_cq_mutex);
			}
			ibtl_cq->cq_impl_flags &= ~IBTL_CQ_PENDING;
			if (ibtl_cq->cq_impl_flags & IBTL_CQ_FREE)
				cv_broadcast(&ibtl_cq_cv);
		} else {
			if (ibtl_cq_thread_exit == IBTL_THREAD_EXIT)
				break;
			mutex_enter(&cpr_mutex);
			CALLB_CPR_SAFE_BEGIN(&cprinfo);
			mutex_exit(&cpr_mutex);

			cv_wait(&ibtl_cq_cv, &ibtl_cq_mutex);

			mutex_exit(&ibtl_cq_mutex);
			mutex_enter(&cpr_mutex);
			CALLB_CPR_SAFE_END(&cprinfo, &cpr_mutex);
			mutex_exit(&cpr_mutex);
			mutex_enter(&ibtl_cq_mutex);
		}
	}

	mutex_exit(&ibtl_cq_mutex);
#ifndef __lock_lint
	mutex_enter(&cpr_mutex);
	CALLB_CPR_EXIT(&cprinfo);
#endif
	mutex_destroy(&cpr_mutex);
}


/*
 * ibc_cq_handler()
 *
 *    Completion Queue Notification Handler.
 *
 */
/*ARGSUSED*/
void
ibc_cq_handler(ibc_clnt_hdl_t ibc_hdl, ibt_cq_hdl_t ibtl_cq)
{
	IBTF_DPRINTF_L4(ibtf_handlers, "ibc_cq_handler(%p, %p)",
	    ibc_hdl, ibtl_cq);

	if (ibtl_cq->cq_in_thread) {
		mutex_enter(&ibtl_cq_mutex);
		ibtl_cq->cq_impl_flags |= IBTL_CQ_CALL_CLIENT;
		if ((ibtl_cq->cq_impl_flags & IBTL_CQ_PENDING) == 0) {
			ibtl_cq->cq_impl_flags |= IBTL_CQ_PENDING;
			ibtl_cq->cq_link = NULL;
			if (ibtl_cq_list_end == NULL)
				ibtl_cq_list_start = ibtl_cq;
			else
				ibtl_cq_list_end->cq_link = ibtl_cq;
			ibtl_cq_list_end = ibtl_cq;
			cv_signal(&ibtl_cq_cv);
		}
		mutex_exit(&ibtl_cq_mutex);
		return;
	} else
		ibtl_cq_handler_call(ibtl_cq);
}


/*
 * ibt_enable_cq_notify()
 *      Enable Notification requests on the specified CQ.
 *
 *      ibt_cq          The CQ handle.
 *
 *      notify_type     Enable notifications for all (IBT_NEXT_COMPLETION)
 *                      completions, or the next Solicited completion
 *                      (IBT_NEXT_SOLICITED) only.
 *
 *	Completion notifications are disabled by setting the completion
 *	handler to NULL by calling ibt_set_cq_handler().
 */
ibt_status_t
ibt_enable_cq_notify(ibt_cq_hdl_t ibtl_cq, ibt_cq_notify_flags_t notify_type)
{
	IBTF_DPRINTF_L3(ibtf_handlers, "ibt_enable_cq_notify(%p, %d)",
	    ibtl_cq, notify_type);

	return (IBTL_CQ2CIHCAOPS_P(ibtl_cq)->ibc_notify_cq(
	    IBTL_CQ2CIHCA(ibtl_cq), ibtl_cq->cq_ibc_cq_hdl, notify_type));
}


/*
 * ibt_set_cq_handler()
 *      Register a work request completion handler with the IBTF.
 *
 *      ibt_cq                  The CQ handle.
 *
 *      completion_handler      The completion handler.
 *
 *      arg                     The IBTF client private argument to be passed
 *                              back to the client when calling the CQ
 *                              completion handler.
 *
 *	Completion notifications are disabled by setting the completion
 *	handler to NULL.  When setting the handler to NULL, no additional
 *	calls to the previous CQ handler will be initiated, but there may
 *	be one in progress.
 *
 *      This function does not otherwise change the state of previous
 *      calls to ibt_enable_cq_notify().
 */
void
ibt_set_cq_handler(ibt_cq_hdl_t ibtl_cq, ibt_cq_handler_t completion_handler,
    void *arg)
{
	IBTF_DPRINTF_L3(ibtf_handlers, "ibt_set_cq_handler(%p, %p, %p)",
	    ibtl_cq, completion_handler, arg);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*ibtl_cq))
	ibtl_cq->cq_comp_handler = completion_handler;
	ibtl_cq->cq_arg = arg;
}


/*
 * Inform IBT clients about New HCAs.
 *
 *	We use taskqs to allow simultaneous notification, with sleeping.
 *	Since taskqs only allow one argument, we define a structure
 *	because we need to pass in two arguments.
 */

struct ibtl_new_hca_s {
	ibtl_clnt_t		*nh_clntp;
	ibtl_hca_devinfo_t	*nh_hca_devp;
	ibt_async_code_t	nh_code;
};

static void
ibtl_tell_client_about_new_hca(void *arg)
{
	struct ibtl_new_hca_s	*new_hcap = (struct ibtl_new_hca_s *)arg;
	ibtl_clnt_t		*clntp = new_hcap->nh_clntp;
	ibt_async_event_t	async_event;
	ibtl_hca_devinfo_t	*hca_devp = new_hcap->nh_hca_devp;

	bzero(&async_event, sizeof (async_event));
	async_event.ev_hca_guid = hca_devp->hd_hca_attr->hca_node_guid;
	clntp->clnt_modinfop->mi_async_handler(
	    clntp->clnt_private, NULL, new_hcap->nh_code, &async_event);
	kmem_free(new_hcap, sizeof (*new_hcap));
#ifdef __lock_lint
	{
		ibt_hca_hdl_t hca_hdl;
		(void) ibt_open_hca(clntp, 0ULL, &hca_hdl);
	}
#endif
	mutex_enter(&ibtl_clnt_list_mutex);
	if (--hca_devp->hd_async_task_cnt == 0)
		cv_signal(&hca_devp->hd_async_task_cv);
	if (--clntp->clnt_async_cnt == 0)
		cv_broadcast(&ibtl_clnt_cv);
	mutex_exit(&ibtl_clnt_list_mutex);
}

/*
 * ibtl_announce_new_hca:
 *
 *	o First attach these clients in the given order
 *		IBMA
 *		IBCM
 *
 *	o Next attach all other clients in parallel.
 *
 * NOTE: Use the taskq to simultaneously notify all clients of the new HCA.
 * Retval from clients is ignored.
 */
void
ibtl_announce_new_hca(ibtl_hca_devinfo_t *hca_devp)
{
	ibtl_clnt_t		*clntp;
	struct ibtl_new_hca_s	*new_hcap;

	IBTF_DPRINTF_L2(ibtf_handlers, "ibtl_announce_new_hca(%p, %llX)",
	    hca_devp, hca_devp->hd_hca_attr->hca_node_guid);

	mutex_enter(&ibtl_clnt_list_mutex);

	clntp = ibtl_clnt_list;
	while (clntp != NULL) {
		if (clntp->clnt_modinfop->mi_clnt_class == IBT_IBMA) {
			IBTF_DPRINTF_L4(ibtf_handlers,
			    "ibtl_announce_new_hca: calling IBMF");
			if (clntp->clnt_modinfop->mi_async_handler) {
				_NOTE(NO_COMPETING_THREADS_NOW)
				new_hcap = kmem_alloc(sizeof (*new_hcap),
				    KM_SLEEP);
				new_hcap->nh_clntp = clntp;
				new_hcap->nh_hca_devp = hca_devp;
				new_hcap->nh_code = IBT_HCA_ATTACH_EVENT;
#ifndef lint
				_NOTE(COMPETING_THREADS_NOW)
#endif
				clntp->clnt_async_cnt++;
				hca_devp->hd_async_task_cnt++;

				(void) taskq_dispatch(ibtl_async_taskq,
				    ibtl_tell_client_about_new_hca, new_hcap,
				    TQ_SLEEP);
			}
			break;
		}
		clntp = clntp->clnt_list_link;
	}
	if (clntp != NULL)
		while (clntp->clnt_async_cnt > 0)
			cv_wait(&ibtl_clnt_cv, &ibtl_clnt_list_mutex);
	clntp = ibtl_clnt_list;
	while (clntp != NULL) {
		if (clntp->clnt_modinfop->mi_clnt_class == IBT_DM) {
			IBTF_DPRINTF_L4(ibtf_handlers, "ibtl_announce_new_hca: "
			    "calling  %s", clntp->clnt_modinfop->mi_clnt_name);
			if (clntp->clnt_modinfop->mi_async_handler) {
				_NOTE(NO_COMPETING_THREADS_NOW)
				new_hcap = kmem_alloc(sizeof (*new_hcap),
				    KM_SLEEP);
				new_hcap->nh_clntp = clntp;
				new_hcap->nh_hca_devp = hca_devp;
				new_hcap->nh_code = IBT_HCA_ATTACH_EVENT;
#ifndef lint
				_NOTE(COMPETING_THREADS_NOW)
#endif
				clntp->clnt_async_cnt++;
				hca_devp->hd_async_task_cnt++;

				mutex_exit(&ibtl_clnt_list_mutex);
				(void) ibtl_tell_client_about_new_hca(
				    new_hcap);
				mutex_enter(&ibtl_clnt_list_mutex);
			}
			break;
		}
		clntp = clntp->clnt_list_link;
	}

	clntp = ibtl_clnt_list;
	while (clntp != NULL) {
		if (clntp->clnt_modinfop->mi_clnt_class == IBT_CM) {
			IBTF_DPRINTF_L4(ibtf_handlers, "ibtl_announce_new_hca: "
			    "calling  %s", clntp->clnt_modinfop->mi_clnt_name);
			if (clntp->clnt_modinfop->mi_async_handler) {
				_NOTE(NO_COMPETING_THREADS_NOW)
				new_hcap = kmem_alloc(sizeof (*new_hcap),
				    KM_SLEEP);
				new_hcap->nh_clntp = clntp;
				new_hcap->nh_hca_devp = hca_devp;
				new_hcap->nh_code = IBT_HCA_ATTACH_EVENT;
#ifndef lint
				_NOTE(COMPETING_THREADS_NOW)
#endif
				clntp->clnt_async_cnt++;
				hca_devp->hd_async_task_cnt++;

				(void) taskq_dispatch(ibtl_async_taskq,
				    ibtl_tell_client_about_new_hca, new_hcap,
				    TQ_SLEEP);
			}
			break;
		}
		clntp = clntp->clnt_list_link;
	}
	if (clntp != NULL)
		while (clntp->clnt_async_cnt > 0)
			cv_wait(&ibtl_clnt_cv, &ibtl_clnt_list_mutex);
	clntp = ibtl_clnt_list;
	while (clntp != NULL) {
		if ((clntp->clnt_modinfop->mi_clnt_class != IBT_DM) &&
		    (clntp->clnt_modinfop->mi_clnt_class != IBT_CM) &&
		    (clntp->clnt_modinfop->mi_clnt_class != IBT_IBMA)) {
			IBTF_DPRINTF_L4(ibtf_handlers,
			    "ibtl_announce_new_hca: Calling %s ",
			    clntp->clnt_modinfop->mi_clnt_name);
			if (clntp->clnt_modinfop->mi_async_handler) {
				_NOTE(NO_COMPETING_THREADS_NOW)
				new_hcap = kmem_alloc(sizeof (*new_hcap),
				    KM_SLEEP);
				new_hcap->nh_clntp = clntp;
				new_hcap->nh_hca_devp = hca_devp;
				new_hcap->nh_code = IBT_HCA_ATTACH_EVENT;
#ifndef lint
				_NOTE(COMPETING_THREADS_NOW)
#endif
				clntp->clnt_async_cnt++;
				hca_devp->hd_async_task_cnt++;

				(void) taskq_dispatch(ibtl_async_taskq,
				    ibtl_tell_client_about_new_hca, new_hcap,
				    TQ_SLEEP);
			}
		}
		clntp = clntp->clnt_list_link;
	}

	/* wait for all tasks to complete */
	while (hca_devp->hd_async_task_cnt != 0)
		cv_wait(&hca_devp->hd_async_task_cv, &ibtl_clnt_list_mutex);

	/* wakeup thread that may be waiting to send an HCA async */
	ASSERT(hca_devp->hd_async_busy == 1);
	hca_devp->hd_async_busy = 0;
	cv_broadcast(&hca_devp->hd_async_busy_cv);
	mutex_exit(&ibtl_clnt_list_mutex);
}

/*
 * ibtl_detach_all_clients:
 *
 *	Return value - 0 for Success, 1 for Failure
 *
 *	o First detach general clients.
 *
 *	o Next detach these clients
 *		IBCM
 *		IBDM
 *
 *	o Finally, detach this client
 *		IBMA
 */
int
ibtl_detach_all_clients(ibtl_hca_devinfo_t *hca_devp)
{
	ib_guid_t		hcaguid = hca_devp->hd_hca_attr->hca_node_guid;
	ibtl_hca_t		*ibt_hca;
	ibtl_clnt_t		*clntp;
	int			retval;

	IBTF_DPRINTF_L2(ibtf_handlers, "ibtl_detach_all_clients(%llX)",
	    hcaguid);

	ASSERT(MUTEX_HELD(&ibtl_clnt_list_mutex));

	while (hca_devp->hd_async_busy)
		cv_wait(&hca_devp->hd_async_busy_cv, &ibtl_clnt_list_mutex);
	hca_devp->hd_async_busy = 1;

	/* First inform general clients asynchronously */
	hca_devp->hd_async_event.ev_hca_guid = hcaguid;
	hca_devp->hd_async_event.ev_fma_ena = 0;
	hca_devp->hd_async_event.ev_chan_hdl = NULL;
	hca_devp->hd_async_event.ev_cq_hdl = NULL;
	hca_devp->hd_async_code = IBT_HCA_DETACH_EVENT;

	ibt_hca = hca_devp->hd_clnt_list;
	while (ibt_hca != NULL) {
		clntp = ibt_hca->ha_clnt_devp;
		if (IBTL_GENERIC_CLIENT(clntp)) {
			++ibt_hca->ha_clnt_devp->clnt_async_cnt;
			mutex_enter(&ibtl_async_mutex);
			ibt_hca->ha_async_cnt++;
			mutex_exit(&ibtl_async_mutex);
			hca_devp->hd_async_task_cnt++;

			(void) taskq_dispatch(ibtl_async_taskq,
			    ibtl_hca_client_async_task, ibt_hca, TQ_SLEEP);
		}
		ibt_hca = ibt_hca->ha_clnt_link;
	}

	/* wait for all clients to complete */
	while (hca_devp->hd_async_task_cnt != 0) {
		cv_wait(&hca_devp->hd_async_task_cv, &ibtl_clnt_list_mutex);
	}
	/* Go thru the clients and check if any have not closed this HCA. */
	retval = 0;
	ibt_hca = hca_devp->hd_clnt_list;
	while (ibt_hca != NULL) {
		clntp = ibt_hca->ha_clnt_devp;
		if (IBTL_GENERIC_CLIENT(clntp)) {
			IBTF_DPRINTF_L2(ibtf_handlers,
			    "ibtl_detach_all_clients: "
			    "client '%s' failed to close the HCA.",
			    ibt_hca->ha_clnt_devp->clnt_modinfop->mi_clnt_name);
			retval = 1;
		}
		ibt_hca = ibt_hca->ha_clnt_link;
	}
	if (retval == 1)
		goto bailout;

	/* Next inform IBDM asynchronously */
	ibt_hca = hca_devp->hd_clnt_list;
	while (ibt_hca != NULL) {
		clntp = ibt_hca->ha_clnt_devp;
		if (clntp->clnt_modinfop->mi_clnt_class == IBT_DM) {
			++ibt_hca->ha_clnt_devp->clnt_async_cnt;
			mutex_enter(&ibtl_async_mutex);
			ibt_hca->ha_async_cnt++;
			mutex_exit(&ibtl_async_mutex);
			hca_devp->hd_async_task_cnt++;

			mutex_exit(&ibtl_clnt_list_mutex);
			ibtl_hca_client_async_task(ibt_hca);
			mutex_enter(&ibtl_clnt_list_mutex);
			break;
		}
		ibt_hca = ibt_hca->ha_clnt_link;
	}

	/*
	 * Next inform IBCM.
	 * As IBCM doesn't perform ibt_open_hca(), IBCM will not be
	 * accessible via hca_devp->hd_clnt_list.
	 * ibtl_cm_async_handler will NOT be NULL, if IBCM is registered.
	 */
	if (ibtl_cm_async_handler) {
		ibtl_tell_mgr(hca_devp, ibtl_cm_async_handler,
		    ibtl_cm_clnt_private);

		/* wait for all tasks to complete */
		while (hca_devp->hd_async_task_cnt != 0)
			cv_wait(&hca_devp->hd_async_task_cv,
			    &ibtl_clnt_list_mutex);
	}

	/* Go thru the clients and check if any have not closed this HCA. */
	retval = 0;
	ibt_hca = hca_devp->hd_clnt_list;
	while (ibt_hca != NULL) {
		clntp = ibt_hca->ha_clnt_devp;
		if (clntp->clnt_modinfop->mi_clnt_class != IBT_IBMA) {
			IBTF_DPRINTF_L2(ibtf_handlers,
			    "ibtl_detach_all_clients: "
			    "client '%s' failed to close the HCA.",
			    ibt_hca->ha_clnt_devp->clnt_modinfop->mi_clnt_name);
			retval = 1;
		}
		ibt_hca = ibt_hca->ha_clnt_link;
	}
	if (retval == 1)
		goto bailout;

	/* Finally, inform IBMA */
	ibt_hca = hca_devp->hd_clnt_list;
	while (ibt_hca != NULL) {
		clntp = ibt_hca->ha_clnt_devp;
		if (clntp->clnt_modinfop->mi_clnt_class == IBT_IBMA) {
			++ibt_hca->ha_clnt_devp->clnt_async_cnt;
			mutex_enter(&ibtl_async_mutex);
			ibt_hca->ha_async_cnt++;
			mutex_exit(&ibtl_async_mutex);
			hca_devp->hd_async_task_cnt++;

			(void) taskq_dispatch(ibtl_async_taskq,
			    ibtl_hca_client_async_task, ibt_hca, TQ_SLEEP);
		} else
			IBTF_DPRINTF_L2(ibtf_handlers,
			    "ibtl_detach_all_clients: "
			    "client '%s' is unexpectedly on the client list",
			    ibt_hca->ha_clnt_devp->clnt_modinfop->mi_clnt_name);
		ibt_hca = ibt_hca->ha_clnt_link;
	}

	/* wait for IBMA to complete */
	while (hca_devp->hd_async_task_cnt != 0) {
		cv_wait(&hca_devp->hd_async_task_cv, &ibtl_clnt_list_mutex);
	}

	/* Check if this HCA's client list is empty. */
	ibt_hca = hca_devp->hd_clnt_list;
	if (ibt_hca != NULL) {
		IBTF_DPRINTF_L2(ibtf_handlers,
		    "ibtl_detach_all_clients: "
		    "client '%s' failed to close the HCA.",
		    ibt_hca->ha_clnt_devp->clnt_modinfop->mi_clnt_name);
		retval = 1;
	} else
		retval = 0;

bailout:
	if (retval) {
		hca_devp->hd_state = IBTL_HCA_DEV_ATTACHED; /* fix hd_state */
		mutex_exit(&ibtl_clnt_list_mutex);
		ibtl_announce_new_hca(hca_devp);
		mutex_enter(&ibtl_clnt_list_mutex);
	} else {
		hca_devp->hd_async_busy = 0;
		cv_broadcast(&hca_devp->hd_async_busy_cv);
	}

	return (retval);
}

void
ibtl_free_clnt_async_check(ibtl_clnt_t *clntp)
{
	IBTF_DPRINTF_L3(ibtf_handlers, "ibtl_free_clnt_async_check(%p)", clntp);

	ASSERT(MUTEX_HELD(&ibtl_clnt_list_mutex));

	/* wait for all asyncs based on "ibtl_clnt_list" to complete */
	while (clntp->clnt_async_cnt != 0) {
		cv_wait(&ibtl_clnt_cv, &ibtl_clnt_list_mutex);
	}
}

static void
ibtl_dec_clnt_async_cnt(ibtl_clnt_t *clntp)
{
	mutex_enter(&ibtl_clnt_list_mutex);
	if (--clntp->clnt_async_cnt == 0) {
		cv_broadcast(&ibtl_clnt_cv);
	}
	mutex_exit(&ibtl_clnt_list_mutex);
}

static void
ibtl_inc_clnt_async_cnt(ibtl_clnt_t *clntp)
{
	mutex_enter(&ibtl_clnt_list_mutex);
	++clntp->clnt_async_cnt;
	mutex_exit(&ibtl_clnt_list_mutex);
}


/*
 * Functions and data structures to inform clients that a notification
 * has occurred about Multicast Groups that might interest them.
 */
struct ibtl_sm_notice {
	ibt_clnt_hdl_t		np_ibt_hdl;
	ib_gid_t		np_sgid;
	ibt_subnet_event_code_t	np_code;
	ibt_subnet_event_t	np_event;
};

static void
ibtl_sm_notice_task(void *arg)
{
	struct ibtl_sm_notice *noticep = (struct ibtl_sm_notice *)arg;
	ibt_clnt_hdl_t ibt_hdl = noticep->np_ibt_hdl;
	ibt_sm_notice_handler_t sm_notice_handler;

	sm_notice_handler = ibt_hdl->clnt_sm_trap_handler;
	if (sm_notice_handler != NULL)
		sm_notice_handler(ibt_hdl->clnt_sm_trap_handler_arg,
		    noticep->np_sgid, noticep->np_code, &noticep->np_event);
	kmem_free(noticep, sizeof (*noticep));
	ibtl_dec_clnt_async_cnt(ibt_hdl);
}

/*
 * Inform the client that MCG notices are not working at this time.
 */
void
ibtl_cm_sm_notice_init_failure(ibtl_cm_sm_init_fail_t *ifail)
{
	ibt_clnt_hdl_t ibt_hdl = ifail->smf_ibt_hdl;
	struct ibtl_sm_notice *noticep;
	ib_gid_t *sgidp = &ifail->smf_sgid[0];
	int i;

	for (i = 0; i < ifail->smf_num_sgids; i++) {
		_NOTE(NO_COMPETING_THREADS_NOW)
		noticep = kmem_zalloc(sizeof (*noticep), KM_SLEEP);
		noticep->np_ibt_hdl = ibt_hdl;
		noticep->np_sgid = *sgidp++;
		noticep->np_code = IBT_SM_EVENT_UNAVAILABLE;
#ifndef lint
		_NOTE(COMPETING_THREADS_NOW)
#endif
		ibtl_inc_clnt_async_cnt(ibt_hdl);
		(void) taskq_dispatch(ibtl_async_taskq,
		    ibtl_sm_notice_task, noticep, TQ_SLEEP);
	}
}

/*
 * Inform all clients of the event.
 */
void
ibtl_cm_sm_notice_handler(ib_gid_t sgid, ibt_subnet_event_code_t code,
    ibt_subnet_event_t *event)
{
	_NOTE(NO_COMPETING_THREADS_NOW)
	struct ibtl_sm_notice	*noticep;
	ibtl_clnt_t		*clntp;

	mutex_enter(&ibtl_clnt_list_mutex);
	clntp = ibtl_clnt_list;
	while (clntp != NULL) {
		if (clntp->clnt_sm_trap_handler) {
			noticep = kmem_zalloc(sizeof (*noticep), KM_SLEEP);
			noticep->np_ibt_hdl = clntp;
			noticep->np_sgid = sgid;
			noticep->np_code = code;
			noticep->np_event = *event;
			++clntp->clnt_async_cnt;
			(void) taskq_dispatch(ibtl_async_taskq,
			    ibtl_sm_notice_task, noticep, TQ_SLEEP);
		}
		clntp = clntp->clnt_list_link;
	}
	mutex_exit(&ibtl_clnt_list_mutex);
#ifndef lint
	_NOTE(COMPETING_THREADS_NOW)
#endif
}

/*
 * Record the handler for this client.
 */
void
ibtl_cm_set_sm_notice_handler(ibt_clnt_hdl_t ibt_hdl,
    ibt_sm_notice_handler_t sm_notice_handler, void *private)
{
	_NOTE(NO_COMPETING_THREADS_NOW)
	ibt_hdl->clnt_sm_trap_handler = sm_notice_handler;
	ibt_hdl->clnt_sm_trap_handler_arg = private;
#ifndef lint
	_NOTE(COMPETING_THREADS_NOW)
#endif
}


/*
 * ibtl_another_cq_handler_in_thread()
 *
 * Conditionally increase the number of cq_threads.
 * The number of threads grows, based on the number of cqs using threads.
 *
 * The table below controls the number of threads as follows:
 *
 *	Number of CQs	Number of cq_threads
 *		0		0
 *		1		1
 *		2-3		2
 *		4-5		3
 *		6-9		4
 *		10-15		5
 *		16-23		6
 *		24-31		7
 *		32+		8
 */

#define	IBTL_CQ_MAXTHREADS 8
static uint8_t ibtl_cq_scaling[IBTL_CQ_MAXTHREADS] = {
	1, 2, 4, 6, 10, 16, 24, 32
};

static kt_did_t ibtl_cq_did[IBTL_CQ_MAXTHREADS];

void
ibtl_another_cq_handler_in_thread(void)
{
	kthread_t *t;
	int my_idx;

	mutex_enter(&ibtl_cq_mutex);
	if ((ibtl_cq_threads == IBTL_CQ_MAXTHREADS) ||
	    (++ibtl_cqs_using_threads < ibtl_cq_scaling[ibtl_cq_threads])) {
		mutex_exit(&ibtl_cq_mutex);
		return;
	}
	my_idx = ibtl_cq_threads++;
	mutex_exit(&ibtl_cq_mutex);
	t = thread_create(NULL, 0, ibtl_cq_thread, NULL, 0, &p0, TS_RUN,
	    ibtl_pri - 1);
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(ibtl_cq_did))
	ibtl_cq_did[my_idx] = t->t_did;	/* save for thread_join() */
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(ibtl_cq_did))
}

void
ibtl_thread_init(void)
{
	IBTF_DPRINTF_L3(ibtf_handlers, "ibtl_thread_init()");

	mutex_init(&ibtl_async_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&ibtl_async_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&ibtl_clnt_cv, NULL, CV_DEFAULT, NULL);

	mutex_init(&ibtl_cq_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&ibtl_cq_cv, NULL, CV_DEFAULT, NULL);
}

void
ibtl_thread_init2(void)
{
	int i;
	static int initted = 0;
	kthread_t *t;

	mutex_enter(&ibtl_async_mutex);
	if (initted == 1) {
		mutex_exit(&ibtl_async_mutex);
		return;
	}
	initted = 1;
	mutex_exit(&ibtl_async_mutex);
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(ibtl_async_did))
	ibtl_async_did = kmem_zalloc(ibtl_async_thread_init * sizeof (kt_did_t),
	    KM_SLEEP);

	IBTF_DPRINTF_L3(ibtf_handlers, "ibtl_thread_init2()");

	for (i = 0; i < ibtl_async_thread_init; i++) {
		t = thread_create(NULL, 0, ibtl_async_thread, NULL, 0, &p0,
		    TS_RUN, ibtl_pri - 1);
		ibtl_async_did[i] = t->t_did; /* thread_join() */
	}
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(ibtl_async_did))
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(ibtl_cq_threads))
	for (i = 0; i < ibtl_cq_threads; i++) {
		t = thread_create(NULL, 0, ibtl_cq_thread, NULL, 0, &p0,
		    TS_RUN, ibtl_pri - 1);
		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(ibtl_cq_did))
		ibtl_cq_did[i] = t->t_did; /* save for thread_join() */
		_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(ibtl_cq_did))
	}
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(ibtl_cq_threads))
}

void
ibtl_thread_fini(void)
{
	int i;

	IBTF_DPRINTF_L3(ibtf_handlers, "ibtl_thread_fini()");

	/* undo the work done by ibtl_thread_init() */

	mutex_enter(&ibtl_cq_mutex);
	ibtl_cq_thread_exit = IBTL_THREAD_EXIT;
	cv_broadcast(&ibtl_cq_cv);
	mutex_exit(&ibtl_cq_mutex);

	mutex_enter(&ibtl_async_mutex);
	ibtl_async_thread_exit = IBTL_THREAD_EXIT;
	cv_broadcast(&ibtl_async_cv);
	mutex_exit(&ibtl_async_mutex);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(ibtl_cq_threads))
	for (i = 0; i < ibtl_cq_threads; i++)
		thread_join(ibtl_cq_did[i]);
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(ibtl_cq_threads))

	if (ibtl_async_did) {
		for (i = 0; i < ibtl_async_thread_init; i++)
			thread_join(ibtl_async_did[i]);

		kmem_free(ibtl_async_did,
		    ibtl_async_thread_init * sizeof (kt_did_t));
	}
	mutex_destroy(&ibtl_cq_mutex);
	cv_destroy(&ibtl_cq_cv);

	mutex_destroy(&ibtl_async_mutex);
	cv_destroy(&ibtl_async_cv);
	cv_destroy(&ibtl_clnt_cv);
}

/* ARGSUSED */
ibt_status_t ibtl_dummy_node_info_cb(ib_guid_t hca_guid, uint8_t port,
    ib_lid_t lid, ibt_node_info_t *node_info)
{
	return (IBT_SUCCESS);
}
