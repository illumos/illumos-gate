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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2017 Joyent, Inc.
 */

/*
 * sol_uverbs_event.c
 *
 * OFED User Verbs Kernel Async Event funtions
 *
 */
#include <sys/file.h>
#include <sys/fcntl.h>
#include <sys/vfs.h>
#include <sys/errno.h>
#include <sys/cred.h>
#include <sys/uio.h>
#include <sys/semaphore.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/ib/ibtl/ibvti.h>
#include <sys/ib/clients/of/ofa_solaris.h>
#include <sys/ib/clients/of/sol_ofs/sol_ofs_common.h>
#include <sys/ib/clients/of/ofed_kernel.h>
#include <sys/ib/clients/of/sol_uverbs/sol_uverbs.h>
#include <sys/ib/clients/of/sol_uverbs/sol_uverbs_event.h>

extern char	*sol_uverbs_dbg_str;

static void
uverbs_async_event_common(uverbs_uctxt_uobj_t *, uint64_t, uint32_t,
    llist_head_t *, uint32_t *);

/*
 * Function:
 *      sol_uverbs_event_file_close
 * Input:
 *      ufile	- Pointer to the event ufile
 *
 * Output:
 *      None
 * Returns:
 *      Zero on success, else error code.
 * Description:
 *	Called when all kernel references to the event file have been
 *	removed and the kernel (asynchronous) or user library (completion)
 *	have closed the file.
 */
void
sol_uverbs_event_file_close(uverbs_ufile_uobj_t *ufile)
{
	if (!ufile) {
		SOL_OFS_DPRINTF_L3(sol_uverbs_dbg_str,
		    "UFILE CLOSE: Ufile NULL\n");
		return;
	}

	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str,
	    "UFILE CLOSE: Is async? %s",
	    ufile->is_async ? "yes" : "no");

	/*
	 * Remove the user file from the user object table and
	 * releases appropriate references.  The object resources
	 * are freed when it is no longer referenced.
	 *
	 * If sol_ofs_uobj_remove() returns NULL then the obj was already
	 * removed.
	 */
	rw_enter(&(ufile->uobj.uo_lock), RW_WRITER);
	if (sol_ofs_uobj_remove(&uverbs_ufile_uo_tbl, &ufile->uobj)) {
		rw_exit(&(ufile->uobj.uo_lock));
		sol_ofs_uobj_deref(&ufile->uobj, uverbs_release_event_file);
	} else {
		rw_exit(&(ufile->uobj.uo_lock));
	}
}

/*
 * Function:
 *      sol_uverbs_event_file_read
 * Input:
 *      ufile	- The user file pointer of the event channel.
 *      uiop	- The user I/O pointer in which to place the event.
 *	cred	- Pointer to the callers credentials.
 * Output:
 *      uiop	- Upon success the caller's buffer has been updated with
 *		  the event details.
 * Returns:
 *      Zero on success, else error code.
 *		EAGAIN	- No event available and caller is non-
 *			  blocking.
 *		ERESTART- A signal was received.
 *		EINVAL	- Caller parameter/user buffer invalid.
 *		EFAULT	- Failure copying data to user.
 * Description:
 *      Perfrom a blocking read to retrieve an event (asynchronous or
 *	completion) for the user file specified.  If an event is available it
 *	is immediately returned. If an event is not available, then the
 *	caller will block unless the open flags indicate it is a non-
 *	blocking open.  If the caller does block it does so interruptable
 *	and therefore will return upon an event or receipt of a signal.
 */
/* ARGSUSED */
int
sol_uverbs_event_file_read(uverbs_ufile_uobj_t *ufile, struct uio *uiop,
    cred_t *cred)
{
	int			rc = 0;
	uverbs_event_t		*evt;
	llist_head_t		*entry;
	int			eventsz;
	int			ioflag;

	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str, "event_file_read(%p), "
	    "ufile = %p, is_async =%d, uio_resid=%d",
	    ufile, ufile->is_async, uiop->uio_resid);

	ioflag = uiop->uio_fmode & (FNONBLOCK | FNDELAY);

	mutex_enter(&ufile->lock);

	/*
	 * If Event list not empty and CQ event notification is disabled
	 * by sol_ucma, do not  return events. Either return EAGAIN (if
	 * flag is O_NONBLOCK, or wait using cv_wait_sig().
	 */
	if (ufile->ufile_notify_enabled == SOL_UVERBS2UCMA_CQ_NOTIFY_DISABLE &&
	    llist_empty(&ufile->event_list) != 0) {
		if (ioflag) {
			mutex_exit(&ufile->lock);
			SOL_OFS_DPRINTF_L3(sol_uverbs_dbg_str,
			    "event_file_read - notify disabled, no block");
			return (EAGAIN);
		}

		if (!cv_wait_sig(&ufile->poll_wait, &ufile->lock)) {
			mutex_exit(&ufile->lock);
			SOL_OFS_DPRINTF_L3(sol_uverbs_dbg_str,
			    "event_file_read - sig_wakeup");
			return (ERESTART);
		}
	}

	while (llist_empty(&ufile->event_list)) {
		if (ioflag) {
			mutex_exit(&ufile->lock);
			SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str,
			    "event_file_read - no events, no block");
			return (EAGAIN);
		}

		if (!cv_wait_sig(&ufile->poll_wait, &ufile->lock)) {
			mutex_exit(&ufile->lock);
			SOL_OFS_DPRINTF_L3(sol_uverbs_dbg_str,
			    "event_file_read - sig_wakeup");
			return (ERESTART);
		}
	}

	entry = ufile->event_list.nxt;
	evt   = entry->ptr;

	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str, "event_file_read: "
	    "Event entry found: entry:%p, event:%p, evt_list %p",
	    entry, evt, &evt->ev_list);

	if (ufile->is_async) {
		eventsz = sizeof (struct ib_uverbs_async_event_desc);
	} else {
		eventsz = sizeof (struct ib_uverbs_comp_event_desc);
	}

	if (eventsz > uiop->uio_resid) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "event_file_read - Event too big");
		rc  = EINVAL;
		evt = NULL;
	} else {
		llist_del(ufile->event_list.nxt);
		if (evt->ev_counter) {
			++(*evt->ev_counter);
			llist_del(&evt->ev_obj_list);
		}
	}

	mutex_exit(&ufile->lock);

	if (evt && (uiomove(evt, eventsz, UIO_READ, uiop) != 0)) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "EVENT FILE READ: Error writing ev");
		rc = EFAULT;
	}

	if (evt) {
		kmem_free(evt, sizeof (*evt));
	}

	return (rc);
}

/*
 * Function:
 *      sol_uverbs_event_file_poll
 * Input:
 *      ufile	- user file for desired completion channel event file
 *      events 	- The events that may occur.
 *	anyyet	- A flag that is non-zero if any files in the set
 *		  of descriptors has an event waiting.
 *	ct	- Pointer to the callers context.
 * Output:
 *	reventssp - A pointer updated to return a bitmask of events specified.
 *      phpp      - A pointer to a pollhead pointer, updated to reflect the
 *		    the event file's pollhead used for synchronization.
 * Returns:
 *      Zero on success, else error code.
 *		EINVAL    - Vnode does not point to valid event file.
 * Description:
 * 	Support for event channel polling interface, allows use of completion
 *	channel in asynchronous type environment.  If events may be read
 *      without blocking indicate a POLLIN | POLLRDNORM event; otherwise if
 *	no other descriptors in the set have data waiting, set the pollhead
 *	pointer to our the associated completion event file's pollhead.
 */
int
sol_uverbs_event_file_poll(uverbs_ufile_uobj_t *ufile, short events,
    int anyyet, short *reventsp, pollhead_t **phpp)
{
	short	revent = 0;

#ifdef DEBUG
	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str, "event_file_poll(%p, %x)",
	    ufile, events);
#endif

	if (!ufile) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str, "event_file_poll ",
		    "ufile %p", ufile);
		return (EINVAL);
	}

#ifdef DEBUG
	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str, "event_file_poll "
	    "ufile = %p, is_async =%d", ufile, ufile->is_async);
#endif

	mutex_enter(&ufile->lock);

	/*
	 * If poll request and event is ready.
	 */
	if ((events & (POLLIN | POLLRDNORM)) &&
	    !llist_empty(&ufile->event_list)) {

		SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str, "event_file_poll "
		    "Event entry available");

		revent |= POLLIN | POLLRDNORM;
	}

	/*
	 * If we didn't get an event or are edge-triggered
	 */
	if ((revent == 0 && !anyyet) || (events & POLLET)) {
		SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str, "event_file_poll "
		    "Event entry NOT available");

		*phpp = &ufile->poll_head;
	}

	mutex_exit(&ufile->lock);
	*reventsp = revent;
	return (0);
}

/*
 * Function:
 *      uverbs_alloc_event_file
 * Input:
 *      uctxt	 - The Solaris User Verbs user context associated with the
 *		   event channel.
 *      is_async - Indicates the file is for asynchronous events if non-zero;
 *                 other wise it is for completion events.
 * Output:
 *      None.
 * Returns:
 *      New user verb event file object or NULL on error.
 * Description:
 *	Allocate an asynchronous or completion event file
 */
uverbs_ufile_uobj_t *
uverbs_alloc_event_file(uverbs_uctxt_uobj_t *uctxt, int is_async)
{
	uverbs_ufile_uobj_t	*ufile;

	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str, "alloc_event_file(%p, %x)",
	    uctxt, is_async);

	ufile = kmem_zalloc(sizeof (*ufile), KM_NOSLEEP);
	if (!ufile) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "alloc_event_file: mem alloc fail");
		return (NULL);
	}
	ufile->ufile_notify_enabled = SOL_UVERBS2UCMA_CQ_NOTIFY_ENABLE;
	sol_ofs_uobj_init(&ufile->uobj, 0, SOL_UVERBS_UFILE_UOBJ_TYPE);
	rw_enter(&ufile->uobj.uo_lock, RW_WRITER);

	if (sol_ofs_uobj_add(&uverbs_ufile_uo_tbl, &ufile->uobj) != 0) {
		/*
		 * The initialization routine set's the initial reference,
		 * we dereference the object here to clean it up.
		 */
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "ALLOC UFILE: Object add failed");
		rw_exit(&ufile->uobj.uo_lock);
		ufile->uobj.uo_uobj_sz = sizeof (uverbs_ufile_uobj_t);
		sol_ofs_uobj_deref(&ufile->uobj, sol_ofs_uobj_free);
		return (NULL);
	}

	ufile->is_async		= is_async ? 1 : 0;
	llist_head_init(&ufile->event_list, NULL);

	mutex_init(&ufile->lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&ufile->poll_wait, NULL, CV_DRIVER, NULL);

	ufile->uctxt		= uctxt;
	ufile->uobj.uo_live	= 1;
	rw_exit(&ufile->uobj.uo_lock);
	return (ufile);
}

/*
 * Function:
 *      uverbs_release_event_file
 * Input:
 *      ufile	 - Pointer to the ufile user object that is being freed.
 * Output:
 *      None.
 * Returns:
 *      None.
 * Description:
 *	Release/destroy event file resources before freeing memory.  This
 *	routine should only be used if the event file is successfully
 *	created.
 */
void
uverbs_release_event_file(sol_ofs_uobj_t *uobj)
{
	uverbs_ufile_uobj_t	*ufile = (uverbs_ufile_uobj_t *)uobj;
	uverbs_event_t		*evt;
	llist_head_t		*entry;
	llist_head_t		*list_tmp;

	if (!ufile) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "UFILE RELEASE: Ufile NULL\n");
		return;
	}

	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str,
	    "UFILE RELEASE: Event file=%p, is async = %s",
	    ufile, ufile->is_async ? "yes" : "no");

	/*
	 * Release any events still queued to the event file.
	 */
	mutex_enter(&ufile->lock);

	entry = ufile->event_list.nxt;
	list_tmp = entry->nxt;
	while (entry != &ufile->event_list) {
		ASSERT(entry);
		evt = (uverbs_event_t *)entry->ptr;

		SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str,
		    "UFILE RELEASE: Deleting event %p on event file %p",
		    evt, ufile);

		llist_del(&evt->ev_list);
		kmem_free(evt, sizeof (*evt));
		entry = list_tmp;
		list_tmp = entry->nxt;
	}

	mutex_exit(&ufile->lock);

	cv_destroy(&ufile->poll_wait);
	mutex_destroy(&ufile->lock);
	sol_ofs_uobj_free(uobj);
}

/*
 * Function:
 *      uverbs_ibt_to_ofa_event_code
 * Input:
 *      code 	- The OFA event code.
 * Output:
 *      The OFED event code.
 * Returns:
 *      Returns the OFA equivalent of an IBT Asynchronous Event code, -1 if
 *	a valid translation does not exist.
 * Description:
 *      Map an IBT asynchronous event code to an OFED event code.
 */
enum ib_event_type
uverbs_ibt_to_ofa_event_code(ibt_async_code_t code)
{
	enum ib_event_type    ofa_code;

	switch (code) {
	case IBT_EVENT_PATH_MIGRATED:
		ofa_code = IB_EVENT_PATH_MIG;
		break;

	case IBT_EVENT_SQD:
		ofa_code = IB_EVENT_SQ_DRAINED;
		break;

	case IBT_EVENT_COM_EST:
		ofa_code = IB_EVENT_COMM_EST;
		break;

	case IBT_ERROR_CATASTROPHIC_CHAN:
	case IBT_ERROR_LOCAL_CATASTROPHIC:
		ofa_code = IB_EVENT_QP_FATAL;
		break;

	case IBT_ERROR_INVALID_REQUEST_CHAN:
		ofa_code = IB_EVENT_QP_REQ_ERR;
		break;

	case IBT_ERROR_ACCESS_VIOLATION_CHAN:
		ofa_code = IB_EVENT_QP_ACCESS_ERR;
		break;

	case IBT_ERROR_PATH_MIGRATE_REQ:
		ofa_code = IB_EVENT_PATH_MIG_ERR;
		break;

	case IBT_ERROR_CQ:
		ofa_code = IB_EVENT_CQ_ERR;
		break;

	case IBT_EVENT_PORT_UP:
		ofa_code = IB_EVENT_PORT_ACTIVE;
		break;

	case IBT_ERROR_PORT_DOWN:
		ofa_code = IB_EVENT_PORT_ERR;
		break;

	case IBT_HCA_ATTACH_EVENT:
		ofa_code = IB_EVENT_CLIENT_REREGISTER;
		break;

	case IBT_EVENT_LIMIT_REACHED_SRQ:
		ofa_code = IB_EVENT_SRQ_LIMIT_REACHED;
		break;

	case IBT_ERROR_CATASTROPHIC_SRQ:
		ofa_code = IB_EVENT_SRQ_ERR;
		break;

	case IBT_EVENT_EMPTY_CHAN:
		ofa_code = IB_EVENT_QP_LAST_WQE_REACHED;
		break;

	/*
	 * No mapping exists.
	 */
	case IBT_ASYNC_OPAQUE1:
	case IBT_ASYNC_OPAQUE2:
	case IBT_ASYNC_OPAQUE3:
	case IBT_ASYNC_OPAQUE4:
	case IBT_HCA_DETACH_EVENT:
	default:
		ofa_code = -1;
	}

	return (ofa_code);
}

/*
 * Function:
 *      uverbs_async_qp_event_handler
 * Input:
 *      clnt_private	- The IBT attach client handle.
 *	hca_hdl		- The IBT hca handle associated with the notification.
 *	code		- The OFED event identifier.
 *	event		- The IBT event.
 * Output:
 *      None
 * Returns:
 *      None
 * Description:
 *      Handle QP affiliated asynchronous event noficiation.
 */
/* ARGSUSED */
void
uverbs_async_qp_event_handler(void *clnt_private, ibt_hca_hdl_t hca_hdl,
    enum ib_event_type code, ibt_async_event_t *event)
{
	uverbs_uqp_uobj_t	*uqp;

	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str,
	    "async_qp_event_handler()");

	if (event->ev_chan_hdl == NULL) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "async_qp_event_handler: event handle NULL");
		return;
	}
	uqp = ibt_get_qp_private(event->ev_chan_hdl);
	ASSERT(uqp);
	if (uqp->uqp_free_state == SOL_UVERBS2UCMA_FREE_PENDING) {
		SOL_OFS_DPRINTF_L3(sol_uverbs_dbg_str,
		    "async_qp_event_handler: User QP context has been freed");
		return;
	}
	if (uqp->qp != event->ev_chan_hdl) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "async_qp_event_handler: QP handle mismatch");
		return;
	}

	uverbs_async_event_common(uqp->uctxt, uqp->uobj.uo_user_handle,
	    code, &uqp->async_list, &uqp->async_events_reported);

}

/*
 * Function:
 *      uverbs_async_cq_event_handler
 * Input:
 *      clnt_private	- The IBT attach client handle.
 *	hca_hdl		- The IBT hca handle associated with the notification.
 *	code		- The OFED event identifier.
 *	event		- The IBT event.
 * Output:
 *      None
 * Returns:
 *      None
 * Description:
 *      Handle a CQ affiliated asynchronous event notification.
 */
/* ARGSUSED */
void
uverbs_async_cq_event_handler(void *clnt_private, ibt_hca_hdl_t hca_hdl,
    enum ib_event_type code, ibt_async_event_t *event)
{
	uverbs_ucq_uobj_t	*ucq;

	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str,
	    "ASYNC CQ EVENT HANDLER:");

	if (event->ev_cq_hdl == NULL) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "ASYNC CQ EVENT HANDLER: event handle is NULL");
		return;
	}

	ucq = ibt_get_cq_private(event->ev_cq_hdl);
	if (ucq->cq != event->ev_cq_hdl) {
		SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str,
		    "ASYNC CQ EVENT HANDLER: CQ handle mismatch");
		return;
	}

	uverbs_async_event_common(ucq->uctxt, ucq->uobj.uo_user_handle,
	    code, &ucq->async_list, &ucq->async_events_reported);
}

/*
 * Function:
 *      uverbs_async_srq_event_handler
 * Input:
 *      clnt_private	- The IBT attach client handle.
 *	hca_hdl		- The IBT hca handle associated with the notification.
 *	code		- The OFED event identifier.
 *	event		- The IBT event.
 * Output:
 *      None
 * Returns:
 *      None
 * Description:
 *      Handle a shared receive queue asynchronous event notification.
 */
/* ARGSUSED */
void
uverbs_async_srq_event_handler(void *clnt_private, ibt_hca_hdl_t hca_hdl,
    enum ib_event_type code, ibt_async_event_t *event)
{
	uverbs_usrq_uobj_t	*usrq;

	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str,
	    "ASYNC SRQ EVENT HANDLER:");

	if (event->ev_srq_hdl == NULL) {
		SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str,
		    "ASYNC SRQ EVENT HANDLER: event handle is NULL");
		return;
	}

	usrq = ibt_get_srq_private(event->ev_srq_hdl);
	if (usrq->srq != event->ev_srq_hdl) {
		SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str,
		    "ASYNC SRQ EVENT HANDLER: SRQ handle mismatch");
		return;
	}

	uverbs_async_event_common(usrq->uctxt, usrq->uobj.uo_user_handle,
	    code, &usrq->async_list, &usrq->async_events_reported);
}

/*
 * Function:
 *      uverbs_async_unaff_event_handler
 * Input:
 *      clnt_private	- The IBT attach client handle.
 *	hca_hdl		- The IBT hca handle associated with the notification.
 *	code		- The OFED event identifier.
 *	event		- The IBT event.
 * Output:
 *      None
 * Returns:
 *      None
 * Description:
 *      Handle an unaffiliated asynchronous event notification.
 */
/* ARGSUSED */
void
uverbs_async_unaff_event_handler(void *clnt_private, ibt_hca_hdl_t hca_hdl,
    enum ib_event_type code, ibt_async_event_t *event)
{
	sol_ofs_uobj_table_t	*uo_tbl = &uverbs_uctxt_uo_tbl;
	sol_ofs_uobj_blk_t	*blk;
	uverbs_uctxt_uobj_t	*uctxt;
	int			i, j;

	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str,
	    "ASYNC UNAFF EVENT HANDLER:");

	/*
	 * Unaffiliated events are returned at the IBT client level.  We must
	 * return the event to all user context allocated for the specific
	 * HCA device specified.
	 */
	rw_enter(&uo_tbl->uobj_tbl_lock, RW_READER);

	for (i = 0; i < uo_tbl->uobj_tbl_used_blks; i++) {
		blk = uo_tbl->uobj_tbl_uo_root[i];
		if (blk == NULL) {
			continue;
		}
		for (j = 0; j < SOL_OFS_UO_BLKSZ; j++) {
			uctxt = (uverbs_uctxt_uobj_t *)blk->ofs_uoblk_blks[j];
			if (uctxt == NULL) {
				continue;
			}
			/*
			 * OK, check to see if this user context belongs
			 * to the idicated hca.
			 */
			if (uctxt->hca->hdl == hca_hdl && uctxt->async_evfile) {
				uverbs_async_event_common(uctxt,
				    event->ev_port, code, NULL, NULL);
			}
		}
	}
	rw_exit(&uo_tbl->uobj_tbl_lock);
}

/*
 * Function:
 *      uverbs_async_event_handler
 * Input:
 *      clnt_private	- The IBT attach client handle.
 *	hca_hdl		- The IBT hca handle associated with the notification.
 *	code		- The OFED event identifier.
 *	event		- The IBT event.
 * Output:
 *      None
 * Returns:
 *      None
 * Description:
 *	Main IBT asynchronous event handler registered at ibt_attach.
 *      Convert to OFA event type and forward to the appropriate
 *      asynchronous handler.
 */
void
uverbs_async_event_handler(void *clnt_private, ibt_hca_hdl_t hca_hdl,
    ibt_async_code_t code, ibt_async_event_t *event)
{
	enum ib_event_type		ofa_type;
	sol_uverbs_ib_event_handler_t	*handler;
	llist_head_t			*entry;
	sol_uverbs_hca_t		*hca;

	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str,
	    "ASYNNC EVENT HANDLER: entry, code=%d", code);

	ofa_type = uverbs_ibt_to_ofa_event_code(code);

	if ((int)ofa_type < 0) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "ASYNC EVENT HANDLER:Event %d did not map to OFA "
		    "Event", code);
		return;
	}

	switch (ofa_type) {
		case IB_EVENT_QP_FATAL:
		case IB_EVENT_QP_REQ_ERR:
		case IB_EVENT_QP_ACCESS_ERR:
		case IB_EVENT_QP_LAST_WQE_REACHED:
		case IB_EVENT_SQ_DRAINED:
		case IB_EVENT_PATH_MIG:
			/*
			 * These events are related with a QP
			 */
			uverbs_async_qp_event_handler(clnt_private, hca_hdl,
			    ofa_type, event);
			break;

		case IB_EVENT_CQ_ERR:
			/*
			 * These events are related with a CQ
			 */
			uverbs_async_cq_event_handler(clnt_private, hca_hdl,
			    ofa_type, event);
			break;

		case IB_EVENT_SRQ_ERR:
		case IB_EVENT_SRQ_LIMIT_REACHED:
			/*
			 * These events are related with a SRQ
			 */
			uverbs_async_srq_event_handler(clnt_private, hca_hdl,
			    ofa_type, event);
			break;


		case IB_EVENT_PORT_ERR:
		case IB_EVENT_PORT_ACTIVE:
		case IB_EVENT_LID_CHANGE:
		case IB_EVENT_PKEY_CHANGE:
		case IB_EVENT_SM_CHANGE:
		case IB_EVENT_CLIENT_REREGISTER:
		case IB_EVENT_DEVICE_FATAL:
		case IB_EVENT_PATH_MIG_ERR:
			/*
			 * Unaffiliated asynchronous notifications.
			 */
			uverbs_async_unaff_event_handler(clnt_private, hca_hdl,
			    ofa_type, event);
			break;

		default:
		break;
	}

	/*
	 * Give other kernel agents a notification.
	 */
	hca = sol_uverbs_ibt_hdl_to_hca(hca_hdl);
	if (hca) {
		mutex_enter(&hca->event_handler_lock);
		list_for_each(entry, &hca->event_handler_list) {
			handler = (sol_uverbs_ib_event_handler_t *)entry->ptr;

			ASSERT(handler != NULL);
			handler->handler(handler, hca_hdl, code, event);
		}
		mutex_exit(&hca->event_handler_lock);
	}
}

/*
 * Function:
 *      uverbs_async_event_common
 * Input:
 *      uctxt       	- Pointer to the user context associated with the
 *			affiliated event.
 *	element 	- The users handle to the associated object.
 *	event           - The event type.
 *	uobj_list       - The list to enqueue the asynchronous event.
 *      counter         - The counter to track the event delivery.
 * Output:
 *      None
 * Returns:
 *      None
 * Description:
 *      Create an asyncronous event and enqueue it on the specified list.
 *      Then wake callers that may  be blocked on the list.
 */
static void
uverbs_async_event_common(uverbs_uctxt_uobj_t  *uctxt, uint64_t element,
    uint32_t event, llist_head_t *obj_list, uint32_t *counter)
{
	uverbs_ufile_uobj_t	*ufile = uctxt->async_evfile;
	uverbs_event_t		*entry;

	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str, "async_event_common(%p, "
	    "%llx, %llx, %p, %p)", uctxt, element, event, obj_list, counter);

	if (!ufile) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str, "async_event_common "
		    "ufile %p", ufile);
		return;
	}

	mutex_enter(&ufile->lock);
	entry = kmem_zalloc(sizeof (*entry), KM_NOSLEEP);
	if (!entry) {
		mutex_exit(&ufile->lock);
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str, "async_event_common "
		    "kmem_zalloc failed");
		return;
	}

	entry->ev_desc.async.element    = element;
	entry->ev_desc.async.event_type = event;
	entry->ev_counter		= counter;

	llist_head_init(&entry->ev_list, entry);
	llist_head_init(&entry->ev_obj_list, entry);

	llist_add_tail(&entry->ev_list, &ufile->event_list);

	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str, "async_event_common "
	    "adding ASYNC entry-ev_list=%p, entry %p",
	    &entry->ev_list, entry);

	if (obj_list) {
		SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str, "async_event_common "
		    "adding ASYNC entry-ev_obj_list=%p, entry=%p",
		    &entry->ev_obj_list, entry);
		llist_add_tail(&entry->ev_obj_list, obj_list);
	}

	mutex_exit(&ufile->lock);
	cv_signal(&ufile->poll_wait);
	pollwakeup(&ufile->poll_head, POLLIN | POLLRDNORM);
}

/*
 * Function:
 *      uverbs_release_ucq_channel
 * Input:
 *	uctxt	- A pointer to the callers user context.
 *	ufile - A pointer to the event file associated with a CQ.
 *	ucq	- A pointer to the user CQ object.
 * Output:
 *      None
 * Returns:
 *      None
 * Description:
 * 	Release any completion and asynchronous events that may
 *	be queued to the specified completion channel/UCQ but not
 *	yet reaped.
 */
void
uverbs_release_ucq_channel(uverbs_uctxt_uobj_t *uctxt,
    uverbs_ufile_uobj_t *ufile, uverbs_ucq_uobj_t   *ucq)
{
	uverbs_event_t	*evt;
	llist_head_t	*entry;
	llist_head_t	*list_tmp;

	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str,
	    "RELEASE UCQ CHANNEL: uctxt=%p, ufile=%p, ucq=%p",
	    uctxt, ufile, ucq);

	/*
	 * Release completion events that have been queued on the CQ completion
	 * eventlist.
	 */
	if (ufile) {
		rw_enter(&ufile->uobj.uo_lock, RW_WRITER);
		ufile->ufile_cq_cnt--;
		if (ufile->ufile_cq_cnt) {
			rw_exit(&ufile->uobj.uo_lock);
			uverbs_release_ucq_uevents(ufile, ucq);
			return;
		}
		rw_exit(&ufile->uobj.uo_lock);
		SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str,
		    "release_ucq_chan : comp_list %p, prv %p, nxt %p",
		    &ucq->comp_list, ucq->comp_list.prv,
		    ucq->comp_list.nxt);
		mutex_enter(&ufile->lock);

		entry = ucq->comp_list.nxt;
		list_tmp = entry->nxt;
		while (entry != &ucq->comp_list) {
			ASSERT(entry);
			evt = (uverbs_event_t *)entry->ptr;

			SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str,
			    "RELEASE UCQ CHANNEL:Deleting event "
			    "on CQ comp list: %p", evt);
			llist_del(&evt->ev_list);
			llist_del(&evt->ev_obj_list);
			kmem_free(evt, sizeof (*evt));
			entry = list_tmp;
			list_tmp = entry->nxt;
		}
		mutex_exit(&ufile->lock);

		uverbs_release_ucq_uevents(ufile, ucq);
	}

}

/*
 * Function:
 *      uverbs_release_ucq_uevents
 * Input:
 *	ufile	- A pointer to the asynchronous event file associated with a QP.
 *	ucq	- A pointer to the user CQ object.
 * Output:
 *      None
 * Returns:
 *      None
 * Description:
 *      Free any user asynchronous events that have been queued for the
 *	user CQ object specified.
 */
void
uverbs_release_ucq_uevents(uverbs_ufile_uobj_t *ufile, uverbs_ucq_uobj_t *ucq)
{
	uverbs_event_t	*evt;
	llist_head_t	*entry;
	llist_head_t	*list_tmp;

	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str,
	    "RELEASE UCQ ASYNC EVENTS: ufile=%p, ucq=%p", ufile, ucq);

	if (ufile) {
		mutex_enter(&ufile->lock);

		entry = ucq->async_list.nxt;
		list_tmp = entry->nxt;
		while (entry != &ucq->async_list) {
			ASSERT(entry);
			evt = (uverbs_event_t *)entry->ptr;
			SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str,
			    "RELEASE UCQ EVENTS: Deleting event "
			    "on CQ async list: %p", evt);
			llist_del(&evt->ev_list);
			llist_del(&evt->ev_obj_list);
			kmem_free(evt, sizeof (*evt));
			entry = list_tmp;
			list_tmp = entry->nxt;
		}
		mutex_exit(&ufile->lock);
	}
}

/*
 * Function:
 *      uverbs_release_uqp_uevents
 * Input:
 *	ufile	- A pointer to the asynchronous event file associated with a QP.
 *	uqp	- A pointer to the user QP object.
 * Output:
 *      None
 * Returns:
 *      None
 * Description:
 *      Free any user asynchronous events that have been queued for the
 *	user QP object specified.
 */
void
uverbs_release_uqp_uevents(uverbs_ufile_uobj_t *ufile, uverbs_uqp_uobj_t *uqp)
{
	uverbs_event_t	*evt;
	llist_head_t	*entry;
	llist_head_t	*list_tmp;

	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str,
	    "RELEASE UQP EVENTS: ufile=%p, uqp=%p", ufile, uqp);

	if (ufile) {
		mutex_enter(&ufile->lock);
		entry = uqp->async_list.nxt;
		list_tmp = entry->nxt;
		while (entry != &uqp->async_list) {
			ASSERT(entry);
			evt = (uverbs_event_t *)entry->ptr;
			ASSERT(evt);

			SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str,
			    "RELEASE UQP EVENTS: Deleting event "
			    "ON qp async list: %p", evt);
			llist_del(&evt->ev_list);
			llist_del(&evt->ev_obj_list);
			kmem_free(evt, sizeof (*evt));
			entry = list_tmp;
			list_tmp = entry->nxt;
		}
		mutex_exit(&ufile->lock);
	}
}

/*
 * Function:
 *      uverbs_release_usrq_uevents
 * Input:
 *	ufile	- A pointer to the asynchronous event file associated with a
 *		  SRQ.
 *	uqp	- A pointer to the user SRQ object.
 * Output:
 *      None
 * Returns:
 *      None
 * Description:
 *      Free any user asynchronous events that have been queued for the
 *	user SRQ object specified.
 */
void
uverbs_release_usrq_uevents(uverbs_ufile_uobj_t *ufile,
    uverbs_usrq_uobj_t *usrq)
{
	uverbs_event_t	*evt;
	llist_head_t	*entry;
	llist_head_t	*list_tmp;

	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str,
	    "RELEASE USRQ EVENTS: ufile=%p, usrq=%p", ufile, usrq);

	if (ufile) {
		mutex_enter(&ufile->lock);

		entry = usrq->async_list.nxt;
		list_tmp = entry->nxt;
		while (entry != &usrq->async_list) {
			ASSERT(entry);
			evt = (uverbs_event_t *)entry->ptr;
			SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str,
			    "RELEASE SRQ EVENTS: Deleting event "
			    "on SRQ async list: %p", evt);
			llist_del(&evt->ev_list);
			llist_del(&evt->ev_obj_list);
			kmem_free(evt, sizeof (*evt));
			entry = list_tmp;
			list_tmp = entry->nxt;
		}
		mutex_exit(&ufile->lock);
	}
}
