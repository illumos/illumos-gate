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
 * Copyright 2000 by Cisco Systems, Inc.  All rights reserved.
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * iSCSI Software Initiator
 */

#include "iscsi.h"		/* main header */

static void iscsi_enqueue_cmd_tail(iscsi_cmd_t **head, iscsi_cmd_t **tail,
    iscsi_cmd_t *icmdp);


/*
 * +--------------------------------------------------------------------+
 * | public queue functions						|
 * +--------------------------------------------------------------------+
 *
 * Public queue locking rules.  When acquiring multiple queue locks
 * they MUST always be acquired in a forward order.  If a lock is
 * aquire in a reverese order it could lead to a deadlock panic.
 * The forward order of locking is described as shown below.
 *
 *		 pending -> cmdsn -> active -> completion
 *
 * If a cmd_mutex is held, it is either held after the pending queue
 * mutex or after the active queue mutex.
 */

/*
 * iscsi_init_queue - used to initialize iscsi queue
 */
void
iscsi_init_queue(iscsi_queue_t *queue)
{
	ASSERT(queue != NULL);

	queue->head = NULL;
	queue->tail = NULL;
	queue->count = 0;
	mutex_init(&queue->mutex, NULL, MUTEX_DRIVER, NULL);
}

/*
 * iscsi_destroy_queue - used to terminate iscsi queue
 */
void
iscsi_destroy_queue(iscsi_queue_t *queue)
{
	ASSERT(queue != NULL);
	ASSERT(queue->count == 0);

	mutex_destroy(&queue->mutex);
}

/*
 * iscsi_enqueue_pending_cmd - used to add a command in a pending queue
 */
void
iscsi_enqueue_pending_cmd(iscsi_sess_t *isp, iscsi_cmd_t *icmdp)
{
	ASSERT(isp != NULL);
	ASSERT(icmdp != NULL);
	ASSERT(mutex_owned(&isp->sess_queue_pending.mutex));

	icmdp->cmd_state = ISCSI_CMD_STATE_PENDING;
	if (icmdp->cmd_type == ISCSI_CMD_TYPE_SCSI) {
		iscsi_enqueue_cmd_tail(&isp->sess_queue_pending.head,
		    &isp->sess_queue_pending.tail, icmdp);
		isp->sess_queue_pending.count++;
		KSTAT_WAITQ_ENTER(isp);
	} else {
		iscsi_enqueue_cmd_head(&isp->sess_queue_pending.head,
		    &isp->sess_queue_pending.tail, icmdp);
		isp->sess_queue_pending.count++;
		KSTAT_WAITQ_ENTER(isp);
	}
	iscsi_sess_redrive_io(isp);
}


/*
 * iscsi_dequeue_pending_cmd - used to remove a command from a pending queue
 */
void
iscsi_dequeue_pending_cmd(iscsi_sess_t *isp, iscsi_cmd_t *icmdp)
{
	iscsi_status_t rval = ISCSI_STATUS_SUCCESS;

	ASSERT(isp != NULL);
	ASSERT(icmdp != NULL);
	ASSERT(mutex_owned(&isp->sess_queue_pending.mutex));

	rval = iscsi_dequeue_cmd(&isp->sess_queue_pending.head,
	    &isp->sess_queue_pending.tail, icmdp);
	if (ISCSI_SUCCESS(rval)) {
		isp->sess_queue_pending.count--;
		if (((kstat_io_t *)(&isp->stats.ks_io_data))->wcnt) {
			KSTAT_WAITQ_EXIT(isp);
		} else {
			cmn_err(CE_WARN,
			    "kstat wcnt == 0 when exiting waitq,"
			    " please check\n");
		}
	} else {
		ASSERT(FALSE);
	}
}

/*
 * iscsi_enqueue_active_cmd - used to add a command in a active queue
 *
 * This interface attempts to keep newer items are on the tail,
 * older items are on the head.  But, Do not assume that the list
 * is completely sorted.  If someone attempts to enqueue an item
 * that already has cmd_lbolt_active assigned and is older than
 * the current head, otherwise add to the tail.
 */
void
iscsi_enqueue_active_cmd(iscsi_conn_t *icp, iscsi_cmd_t *icmdp)
{
	iscsi_sess_t		*isp    = NULL;

	ASSERT(icp != NULL);
	ASSERT(icmdp != NULL);
	isp = icp->conn_sess;
	ASSERT(isp != NULL);

	/*
	 * When receiving data associated to a command it
	 * is temporarily removed from the active queue.
	 * Then once the data receive is completed it may
	 * be returned to the active queue.  If this was
	 * an aborting command we need to preserve its
	 * state.
	 */
	if (icmdp->cmd_state != ISCSI_CMD_STATE_ABORTING) {
		icmdp->cmd_state = ISCSI_CMD_STATE_ACTIVE;
	}

	/*
	 * It's possible that this is not a newly issued icmdp - we may
	 * have tried to abort it but the abort failed or was rejected
	 * and we are putting it back on the active list. So if it is older
	 * than the head of the active queue, put it at the head to keep
	 * the CommandTimeout valid.
	 */
	if (icmdp->cmd_lbolt_active == 0) {
		icmdp->cmd_lbolt_active = ddi_get_lbolt();
		iscsi_enqueue_cmd_tail(&icp->conn_queue_active.head,
		    &icp->conn_queue_active.tail, icmdp);
	} else if ((icp->conn_queue_active.head != NULL) &&
	    (icmdp->cmd_lbolt_active <
	    icp->conn_queue_active.head->cmd_lbolt_active)) {
		iscsi_enqueue_cmd_head(&icp->conn_queue_active.head,
		    &icp->conn_queue_active.tail, icmdp);
	} else {
		iscsi_enqueue_cmd_tail(&icp->conn_queue_active.head,
		    &icp->conn_queue_active.tail, icmdp);
	}
	icp->conn_queue_active.count++;

	if (icmdp->cmd_type == ISCSI_CMD_TYPE_SCSI) {
		KSTAT_RUNQ_ENTER(isp);
	}
}

/*
 * iscsi_dequeue_active_cmd - used to remove a command from a active queue
 */
void
iscsi_dequeue_active_cmd(iscsi_conn_t *icp, iscsi_cmd_t *icmdp)
{
	iscsi_status_t	rval	= ISCSI_STATUS_SUCCESS;
	iscsi_sess_t	*isp	= NULL;

	ASSERT(icp != NULL);
	ASSERT(icmdp != NULL);
	isp = icp->conn_sess;
	ASSERT(isp != NULL);
	ASSERT(mutex_owned(&icp->conn_queue_active.mutex));

	rval = iscsi_dequeue_cmd(&icp->conn_queue_active.head,
	    &icp->conn_queue_active.tail, icmdp);

	if (ISCSI_SUCCESS(rval)) {
		icp->conn_queue_active.count--;

		if (icmdp->cmd_type == ISCSI_CMD_TYPE_SCSI) {
			if (((kstat_io_t *)(&isp->stats.ks_io_data))->rcnt) {
				KSTAT_RUNQ_EXIT(isp);
			} else {
				cmn_err(CE_WARN,
				    "kstat rcnt == 0 when exiting runq,"
				    " please check\n");
			}
		}
	} else {
		ASSERT(FALSE);
	}
}

/*
 * iscsi_enqueue_completed_cmd - used to add a command in completion queue
 */
void
iscsi_enqueue_completed_cmd(iscsi_sess_t *isp, iscsi_cmd_t *icmdp)
{
	ASSERT(isp != NULL);
	ASSERT(icmdp != NULL);

	mutex_enter(&isp->sess_queue_completion.mutex);
	if (icmdp->cmd_state != ISCSI_CMD_STATE_COMPLETED) {
		icmdp->cmd_state = ISCSI_CMD_STATE_COMPLETED;
	} else {
		/*
		 * This command has already been completed, probably
		 * through the abort code path. It should  be in
		 * the process of being returned to to the upper
		 * layers, so do nothing.
		 */
		mutex_exit(&isp->sess_queue_completion.mutex);
		return;
	}
	iscsi_enqueue_cmd_tail(&isp->sess_queue_completion.head,
	    &isp->sess_queue_completion.tail, icmdp);
	++isp->sess_queue_completion.count;
	mutex_exit(&isp->sess_queue_completion.mutex);

	iscsi_thread_send_wakeup(isp->sess_ic_thread);
}

/*
 * iscsi_move_queue - used to move the whole contents of a queue
 *
 *   The source queue has to be initialized.  Its mutex is entered before
 * doing the actual move.  The destination queue should be initialized.
 * This function is intended to move a queue located in a shared location
 * into local space.  No mutex is needed for the destination queue.
 */
void
iscsi_move_queue(
	iscsi_queue_t	*src_queue,
	iscsi_queue_t	*dst_queue
)
{
	ASSERT(src_queue != NULL);
	ASSERT(dst_queue != NULL);
	mutex_enter(&src_queue->mutex);
	dst_queue->count = src_queue->count;
	dst_queue->head  = src_queue->head;
	dst_queue->tail  = src_queue->tail;
	src_queue->count = 0;
	src_queue->head  = NULL;
	src_queue->tail  = NULL;
	mutex_exit(&src_queue->mutex);
}

/*
 * +--------------------------------------------------------------------+
 * | private functions							|
 * +--------------------------------------------------------------------+
 */

/*
 * iscsi_dequeue_cmd - used to remove a command from a queue
 */
iscsi_status_t
iscsi_dequeue_cmd(iscsi_cmd_t **head, iscsi_cmd_t **tail, iscsi_cmd_t *icmdp)
{
#ifdef DEBUG
	iscsi_cmd_t	*tp	= NULL;
#endif

	ASSERT(head != NULL);
	ASSERT(tail != NULL);
	ASSERT(icmdp != NULL);

	if (*head == NULL) {
		/* empty queue, error */
		return (ISCSI_STATUS_INTERNAL_ERROR);
	} else if (*head == *tail) {
		/* one element queue */
		if (*head == icmdp) {
			*head = NULL;
			*tail = NULL;
		} else {
			return (ISCSI_STATUS_INTERNAL_ERROR);
		}
	} else {
		/* multi-element queue */
		if (*head == icmdp) {
			/* at the head */
			*head = icmdp->cmd_next;
			(*head)->cmd_prev = NULL;
		} else if (*tail == icmdp) {
			*tail = icmdp->cmd_prev;
			(*tail)->cmd_next = NULL;
		} else {
#ifdef DEBUG
			/* in the middle? */
			for (tp = (*head)->cmd_next; (tp != NULL) &&
			    (tp != icmdp); tp = tp->cmd_next)
				;
			if (tp == NULL) {
				/* not found */
				return (ISCSI_STATUS_INTERNAL_ERROR);
			}
#endif
			if (icmdp->cmd_prev == NULL) {
				return (ISCSI_STATUS_INTERNAL_ERROR);
			}
			icmdp->cmd_prev->cmd_next = icmdp->cmd_next;
			if (icmdp->cmd_next == NULL) {
				return (ISCSI_STATUS_INTERNAL_ERROR);
			}
			icmdp->cmd_next->cmd_prev = icmdp->cmd_prev;
		}
	}

	/* icmdp no longer in the queue */
	icmdp->cmd_prev = NULL;
	icmdp->cmd_next = NULL;
	return (ISCSI_STATUS_SUCCESS);
}

/*
 * iscsi_enqueue_cmd_head - used to add a command to the head of a queue
 */
void
iscsi_enqueue_cmd_head(iscsi_cmd_t **head, iscsi_cmd_t **tail,
    iscsi_cmd_t *icmdp)
{
	ASSERT(icmdp != NULL);
	ASSERT(icmdp->cmd_next == NULL);
	ASSERT(icmdp->cmd_prev == NULL);
	ASSERT(icmdp != *head);
	ASSERT(icmdp != *tail);

	if (*head == NULL) {
		/* empty queue */
		*head = *tail = icmdp;
		icmdp->cmd_prev = NULL;
		icmdp->cmd_next = NULL;
	} else {
		/* non-empty queue */
		icmdp->cmd_next = *head;
		icmdp->cmd_prev = NULL;
		(*head)->cmd_prev = icmdp;
		*head = icmdp;
	}
}

/*
 * iscsi_enqueue_cmd_tail - used to add a command to the tail of a queue
 */
static void
iscsi_enqueue_cmd_tail(iscsi_cmd_t **head, iscsi_cmd_t **tail,
    iscsi_cmd_t *icmdp)
{
	ASSERT(icmdp != NULL);
	ASSERT(icmdp->cmd_next == NULL);
	ASSERT(icmdp->cmd_prev == NULL);
	ASSERT(icmdp != *head);
	ASSERT(icmdp != *tail);

	if (*head == NULL) {
		/* empty queue */
		*head = *tail = icmdp;
		icmdp->cmd_prev = NULL;
		icmdp->cmd_next = NULL;
	} else {
		/* non-empty queue */
		icmdp->cmd_next = NULL;
		icmdp->cmd_prev = *tail;
		(*tail)->cmd_next = icmdp;
		*tail = icmdp;
	}
}
