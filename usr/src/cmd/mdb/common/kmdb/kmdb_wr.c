/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * The communication mechanism for requesting that the driver perform work on
 * behalf of the debugger.  Messages are passed and processed in FIFO order,
 * with no provision for high priority messages.  High priority messages, such
 * as debugger termination requests, should be passed using a different
 * mechanism.
 *
 * Two FIFO queues are used for communication - one from the debugger to the
 * driver, known as the driver_notify queue, and one from the driver to the
 * debugger, known as the debugger_notify queue.  Messages are added to one
 * queue, processed by the party on the other end, and are sent back as
 * acknowledgements on the other queue.  All messages must be acknowledged, in
 * part because the party who sent the message is the only one who can free it.
 *
 * Debugger-initiated work requests are usually triggered by dcmds such as
 * ::load.  In the case of a ::load, the debugger adds a load request to the
 * driver_notify queue.  The driver removes the request from the queue and
 * processes it.  When processing is complete, the message is turned into an
 * acknowledgement, and completion status is added.  The message is then added
 * to the debugger_notify queue.  Upon receipt, the debugger removes the
 * message from the queue, notes the completion status, and frees it.
 *
 * The driver can itself initiate unsolicited work, such as the automatic
 * loading of a dmod in response to a krtld module load notification.  In this
 * case, the driver loads the module and creates a work-completion message.
 * This completion is identical to the one sent in the solicited load case
 * above, with the exception of the acknowledgement bit, which isn't be set.
 * When the debugger receives the completion message, it notes the completion
 * status, and sends the message back to the driver via the driver_notify queue,
 * this time with the acknowledgement bit set.
 */

#include <sys/types.h>

#include <kmdb/kmdb_asmutil.h>
#include <kmdb/kmdb_wr_impl.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb.h>

/*
 * Called by the driver to pass a message to the debugger.  The debugger could
 * start running at any time.  Nodes are added to the queue in FIFO order, but
 * with links pointing in reverse order.
 */
void
kmdb_wr_debugger_notify(void *arg)
{
	kmdb_wr_t *new = arg;
	kmdb_wr_t *curtail;

	new->wn_next = new->wn_prev = NULL;
	membar_producer();

	do {
		if ((curtail = mdb.m_dbgwrtail) == NULL) {
			/*
			 * The queue is empty, because tail will only be NULL if
			 * head is NULL too.  We're the only one who can add
			 * to the queue, so we can blindly add our node.  The
			 * debugger can't look at tail until head is non-NULL,
			 * so we set tail first.
			 */
			mdb.m_dbgwrtail = new;
			membar_producer();
			mdb.m_dbgwrhead = new;
			membar_producer();
			break;
		}

		/*
		 * Point the new node at the current tail.  Attempt to set tail
		 * to point to our new node, but only as long as tail is what
		 * we think it is.
		 */
		new->wn_prev = curtail;
		membar_producer();
	} while (cas((uintptr_t *)&mdb.m_dbgwrtail, (uintptr_t)curtail,
	    (uintptr_t)new) != (uintptr_t)curtail);
}

/*
 * Called by the debugger to receive messages from the driver.  The driver
 * has added the nodes in FIFO order, but has only set the prev pointers.  We
 * have to correct that before processing the nodes.  This routine will not
 * be preempted.
 */
int
kmdb_wr_debugger_process(int (*cb)(kmdb_wr_t *, void *), void *arg)
{
	kmdb_wr_t *wn, *wnn;
	int i;

	if (mdb.m_dbgwrhead == NULL)
		return (0); /* The queue is empty, so there's nothing to do */

	/* Re-establish the next links so we can traverse in FIFO order */
	mdb.m_dbgwrtail->wn_next = NULL;
	for (wn = mdb.m_dbgwrtail; wn->wn_prev != NULL;
	    wn = wn->wn_prev)
		wn->wn_prev->wn_next = wn;

	/* We don't own wn after we've invoked the callback */
	wn = mdb.m_dbgwrhead;
	i = 0;
	do {
		wnn = wn->wn_next;
		i += cb(wn, arg);
	} while ((wn = wnn) != NULL);

	mdb.m_dbgwrhead = mdb.m_dbgwrtail = NULL;

	return (i);
}

/*
 * Called by the debugger to check queue status.
 */
int
kmdb_wr_debugger_notify_isempty(void)
{
	return (mdb.m_dbgwrhead == NULL);
}

/*
 * Called by the debugger to pass a message to the driver.  This routine will
 * not be preempted.
 */
void
kmdb_wr_driver_notify(void *arg)
{
	kmdb_wr_t *new = arg;

	/*
	 * We restrict ourselves to manipulating the rear of the queue.  We
	 * don't look at the head unless the tail is NULL.
	 */
	if (mdb.m_drvwrtail == NULL) {
		new->wn_next = new->wn_prev = NULL;
		mdb.m_drvwrhead = mdb.m_drvwrtail = new;
	} else {
		mdb.m_drvwrtail->wn_next = new;
		new->wn_prev = mdb.m_drvwrtail;
		new->wn_next = NULL;
		mdb.m_drvwrtail = new;
	}
}

/*
 * Called by the driver to receive messages from the debugger.  The debugger
 * could start running at any time.
 *
 * NOTE: This routine may run *after* mdb_destroy(), and may *NOT* use any MDB
 * services.
 */
int
kmdb_wr_driver_process(int (*cb)(kmdb_wr_t *, void *), void *arg)
{
	kmdb_wr_t *worklist, *wn, *wnn;
	int rc, rv, i;

	if ((worklist = mdb.m_drvwrhead) == NULL) {
		return (0); /* The queue is empty, so there's nothing to do */
	}

	mdb.m_drvwrhead = NULL;
	/* The debugger uses tail, so enqueues still work */
	membar_producer();
	mdb.m_drvwrtail = NULL;
	membar_producer();

	/*
	 * The current set of messages has been removed from the queue, so
	 * we can process them at our leisure.
	 */

	wn = worklist;
	rc = i = 0;
	do {
		wnn = wn->wn_next;
		if ((rv = cb(wn, arg)) < 0)
			rc = -1;
		else
			i += rv;
	} while ((wn = wnn) != NULL);

	return (rc == 0 ? i : -1);
}

/*
 * Called by the debugger to check queue status
 */
int
kmdb_wr_driver_notify_isempty(void)
{
	return (mdb.m_drvwrhead == NULL);
}
