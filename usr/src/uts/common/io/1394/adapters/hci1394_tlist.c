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
 * Copyright (c) 1999-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 * hci1394_tlist.c
 *   This implements a timed double linked list.
 *   This list supports:
 *	- addition of node to the end of the list
 *	- atomic deletion of node anywhere in list
 *	- get and remove node from head of list
 *	- enable/disable of timeout feature
 *	- timeout feature, if enabled, will remove each node on the list which
 *	  has been on the list for > timeout.  The callback provided will be
 *	  called for each node removed. The worst case time is around
 *	  timer_resolution after the timeout has occurred (i.e. if you set the
 *	  timer resolution to 50uS and the timeout to 100uS, you could get the
 *	  callback anywhere from 100uS to 150uS from when you added the node to
 *	  the list.  This is a general statement and ignores things like
 *	  interrupt latency, context switching, etc.  So if you see a time
 *	  around 155uS, don't complain :-)
 *	- The timer is only used when something is on the list
 */

#include <sys/kmem.h>
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/types.h>

#include <sys/1394/adapters/hci1394.h>


static clock_t t1394_tlist_nsectohz(hrtime_t  nS);
static void hci1394_tlist_remove(hci1394_tlist_t *list,
    hci1394_tlist_node_t *node);
static void hci1394_tlist_callback(void *tlist_handle);


/*
 * hci1394_tlist_init()
 *    Initialize the tlist.  The list will be protected by a mutex at the
 *    iblock_cookie passed in.  init() returns a handle to be used for the rest
 *    of the functions. If you do not wish to use the timeout feature, set
 *    (hci1394_timer_t *) to null.
 */
void
hci1394_tlist_init(hci1394_drvinfo_t *drvinfo, hci1394_tlist_timer_t *timer,
    hci1394_tlist_handle_t *tlist_handle)
{
	hci1394_tlist_t *list;


	ASSERT(tlist_handle != NULL);

	/* try to alloc the space to keep track of the list */
	list = kmem_alloc(sizeof (hci1394_tlist_t), KM_SLEEP);

	/* setup the return parameter */
	*tlist_handle = list;

	/* initialize the list structure */
	list->tl_drvinfo = drvinfo;
	list->tl_state = HCI1394_TLIST_TIMEOUT_OFF;
	list->tl_head = NULL;
	list->tl_tail = NULL;
	if (timer == NULL) {
		list->tl_timer_enabled = B_FALSE;
	} else {
		ASSERT(timer->tlt_callback != NULL);
		list->tl_timer_enabled = B_TRUE;
		list->tl_timer_info = *timer;
	}
	mutex_init(&list->tl_mutex, NULL, MUTEX_DRIVER,
	    drvinfo->di_iblock_cookie);
}


/*
 * hci1394_tlist_fini()
 *    Frees up the space allocated in init().  Notice that a pointer to the
 *    handle is used for the parameter.  fini() will set your handle to NULL
 *    before returning. Make sure that any pending timeouts are canceled.
 */
void
hci1394_tlist_fini(hci1394_tlist_handle_t *tlist_handle)
{
	hci1394_tlist_t *list;


	ASSERT(tlist_handle != NULL);

	list = (hci1394_tlist_t *)*tlist_handle;
	hci1394_tlist_timeout_cancel(list);
	mutex_destroy(&list->tl_mutex);
	kmem_free(list, sizeof (hci1394_tlist_t));

	/* set handle to null.  This helps catch bugs. */
	*tlist_handle = NULL;
}


/*
 * hci1394_tlist_add()
 *    Add the node to the tail of the linked list. The list is protected by a
 *    mutex at the iblock_cookie passed in during init.
 */
void
hci1394_tlist_add(hci1394_tlist_handle_t tlist_handle,
    hci1394_tlist_node_t *node)
{
	ASSERT(tlist_handle != NULL);
	ASSERT(node != NULL);

	mutex_enter(&tlist_handle->tl_mutex);

	/* add's always go at the end of the list */
	node->tln_next = NULL;

	/* Set state that this node is currently on the tlist */
	node->tln_on_list = B_TRUE;

	/* enter in the expire time (in uS) */
	if (tlist_handle->tl_timer_enabled == B_TRUE) {
		node->tln_expire_time = gethrtime() +
		    tlist_handle->tl_timer_info.tlt_timeout;
	}

	/* if there is nothing in the list */
	if (tlist_handle->tl_tail == NULL) {
		tlist_handle->tl_head = node;
		tlist_handle->tl_tail = node;
		node->tln_prev = NULL;

		if ((tlist_handle->tl_timer_enabled == B_TRUE) &&
		    (tlist_handle->tl_state == HCI1394_TLIST_TIMEOUT_OFF)) {
			/* turn the timer on */
			tlist_handle->tl_timeout_id = timeout(
			    hci1394_tlist_callback, tlist_handle,
			    t1394_tlist_nsectohz(
			    tlist_handle->tl_timer_info.tlt_timer_resolution));
			tlist_handle->tl_state = HCI1394_TLIST_TIMEOUT_ON;
		}
	} else {
		/* put the node on the end of the list */
		tlist_handle->tl_tail->tln_next = node;
		node->tln_prev = tlist_handle->tl_tail;
		tlist_handle->tl_tail = node;
		/*
		 * if timeouts are enabled,  we don't have to call
		 * timeout() because the timer is already on.
		 */
	}

	mutex_exit(&tlist_handle->tl_mutex);
}


/*
 * hci1394_tlist_delete()
 *    Remove the node from the list.  The node can be anywhere in the list. Make
 *    sure that the node is only removed once since different threads maybe
 *    trying to delete the same node at the same time.
 */
int
hci1394_tlist_delete(hci1394_tlist_handle_t tlist_handle,
    hci1394_tlist_node_t *node)
{
	ASSERT(tlist_handle != NULL);
	ASSERT(node != NULL);

	mutex_enter(&tlist_handle->tl_mutex);

	/*
	 * check for race condition.  Someone else may have already removed this
	 * node from the list. hci1394_tlist_delete() supports two threads
	 * trying to delete the node at the same time. The "losing" thread will
	 * have DDI_FAILURE returned.
	 */
	if (node->tln_on_list == B_FALSE) {
		mutex_exit(&tlist_handle->tl_mutex);
		return (DDI_FAILURE);
	}

	hci1394_tlist_remove(tlist_handle, node);
	mutex_exit(&tlist_handle->tl_mutex);

	return (DDI_SUCCESS);
}


/*
 * hci1394_tlist_get()
 *    get the node at the head of the linked list. This function also removes
 *    the node from the list.
 */
void
hci1394_tlist_get(hci1394_tlist_handle_t tlist_handle,
    hci1394_tlist_node_t **node)
{
	ASSERT(tlist_handle != NULL);
	ASSERT(node != NULL);

	mutex_enter(&tlist_handle->tl_mutex);

	/* set the return parameter */
	*node = tlist_handle->tl_head;

	/* remove the node from the tlist */
	if (*node != NULL) {
		hci1394_tlist_remove(tlist_handle, *node);
	}

	mutex_exit(&tlist_handle->tl_mutex);
}


/*
 * hci1394_tlist_peek()
 *    get the node at the head of the linked list. This function does not
 *    remove the node from the list.
 */
void
hci1394_tlist_peek(hci1394_tlist_handle_t tlist_handle,
    hci1394_tlist_node_t **node)
{
	ASSERT(tlist_handle != NULL);
	ASSERT(node != NULL);

	mutex_enter(&tlist_handle->tl_mutex);
	*node = tlist_handle->tl_head;
	mutex_exit(&tlist_handle->tl_mutex);
}


/*
 * hci1394_tlist_timeout_update()
 *    update the timeout to a different value. timeout is in uS.  The update
 *    does not happen immediately.  The new timeout will not take effect until
 *    the all of nodes currently present in the list are gone. It only makes
 *    sense to call this function when you have the timeout feature enabled.
 */
void
hci1394_tlist_timeout_update(hci1394_tlist_handle_t tlist_handle,
    hrtime_t timeout)
{
	ASSERT(tlist_handle != NULL);

	/* set timeout to the new timeout */
	tlist_handle->tl_timer_info.tlt_timeout = timeout;
}


/*
 * hci1394_tlist_timeout_cancel()
 *    cancel any scheduled timeouts.  This should be called after the list is
 *    empty and there is no chance for any other nodes to be placed on the list.
 *    This function is meant to be called during a suspend or detach.
 */
void
hci1394_tlist_timeout_cancel(hci1394_tlist_handle_t tlist_handle)
{
	ASSERT(tlist_handle != NULL);

	/*
	 * Cancel the timeout. Do NOT use the tlist mutex here. It could cause a
	 * deadlock.
	 */
	if (tlist_handle->tl_state == HCI1394_TLIST_TIMEOUT_ON) {
		(void) untimeout(tlist_handle->tl_timeout_id);
		tlist_handle->tl_state = HCI1394_TLIST_TIMEOUT_OFF;
	}
}


/*
 * hci1394_tlist_callback()
 *    The callback we use for the timeout() function. See if there are any nodes
 *    on the list which have timed out. If so, call the registered callback for
 *    each timed out node. We always start looking at the top of the list since
 *    the list is time sorted (oldest at the top).
 */
static void
hci1394_tlist_callback(void *tlist_handle)
{
	hci1394_tlist_t *list;
	hci1394_tlist_node_t *node;
	hrtime_t current_time;


	ASSERT(tlist_handle != NULL);

	list = (hci1394_tlist_t *)tlist_handle;

	mutex_enter(&list->tl_mutex);

	/*
	 * if there is something on the list, check to see if the oldest has
	 * expired.  If there is nothing on the list, there is no reason to
	 * renew the timeout.
	 */
	node = list->tl_head;
	current_time = gethrtime();
	while (node != NULL) {
		/*
		 * if current time is greater than the time the command expires,
		 * AND, the expire time has not rolled over, then the command
		 * has timed out.
		 */
		if (((uint64_t)current_time >=
		    (uint64_t)node->tln_expire_time) &&
		    (((uint64_t)node->tln_expire_time -
		    (uint64_t)list->tl_timer_info.tlt_timeout) <
		    (uint64_t)node->tln_expire_time)) {
			/* remove the node from the tlist */
			hci1394_tlist_remove(list, node);

			/*
			 * Call the timeout callback. We unlock the the mutex
			 * around the callback so that other transactions will
			 * not be blocked while the callback is running. This
			 * is OK to do here because we have already removed this
			 * entry from our list. This code should not reference
			 * "node" again after the callback! After the callback
			 * returns, we need to resync node to the head of the
			 * list since we released/acquired the list mutex around
			 * the callback.
			 */
			mutex_exit(&list->tl_mutex);
			list->tl_timer_info.tlt_callback(node,
			    list->tl_timer_info.tlt_callback_arg);
			mutex_enter(&list->tl_mutex);
			node = list->tl_head;

		/*
		 * else, if current time is greater than the time the command
		 * expires, AND, current_time is not about to rollover. (this
		 * works since it is in the else and we periodically sample
		 * well below the rollover time)
		 */
		} else if ((uint64_t)(current_time >=
		    (uint64_t)node->tln_expire_time) &&
		    (((uint64_t)current_time +
		    (uint64_t)list->tl_timer_info.tlt_timeout) >
		    (uint64_t)current_time)) {
			/* remove the node from the tlist */
			hci1394_tlist_remove(list, node);

			/*
			 * Call the timeout callback. We unlock the the mutex
			 * around the callback so that other transactions will
			 * not be blocked while the callback is running. This
			 * is OK to do here because we have already removed this
			 * entry from our list. This code should not reference
			 * "node" again after the callback! After the callback
			 * returns, we need to resync node to the head of the
			 * list since we released/acquired the list mutex around
			 * the callback.
			 */
			mutex_exit(&list->tl_mutex);
			list->tl_timer_info.tlt_callback(node,
			    list->tl_timer_info.tlt_callback_arg);
			mutex_enter(&list->tl_mutex);
			node = list->tl_head;

		} else {
			/*
			 * this command has not timed out.
			 * Since this list is time sorted, we are
			 * done looking for nodes that have expired
			 */
			break;
		}
	}

	/*
	 * if there are nodes still on the pending list, kick
	 * off the timer again.
	 */
	if (node != NULL) {
		list->tl_timeout_id = timeout(hci1394_tlist_callback, list,
		    t1394_tlist_nsectohz(
		    list->tl_timer_info.tlt_timer_resolution));
		list->tl_state = HCI1394_TLIST_TIMEOUT_ON;
	} else {
		list->tl_state = HCI1394_TLIST_TIMEOUT_OFF;
	}

	mutex_exit(&list->tl_mutex);
}


/*
 * hci1394_tlist_remove()
 *    This is an internal function which removes the given node from the list.
 *    The list MUST be locked before calling this function.
 */
static void
hci1394_tlist_remove(hci1394_tlist_t *list, hci1394_tlist_node_t *node)
{
	ASSERT(list != NULL);
	ASSERT(node != NULL);
	ASSERT(node->tln_on_list == B_TRUE);
	ASSERT(MUTEX_HELD(&list->tl_mutex));

	/* if this is the only node on the list */
	if ((list->tl_head == node) &&
	    (list->tl_tail == node)) {
		list->tl_head = NULL;
		list->tl_tail = NULL;

	/* if the node is at the head of the list */
	} else if (list->tl_head == node) {
		list->tl_head = node->tln_next;
		node->tln_next->tln_prev = NULL;

	/* if the node is at the tail of the list */
	} else if (list->tl_tail == node) {
		list->tl_tail = node->tln_prev;
		node->tln_prev->tln_next = NULL;

	/* if the node is in the middle of the list */
	} else {
		node->tln_prev->tln_next = node->tln_next;
		node->tln_next->tln_prev = node->tln_prev;
	}

	/* Set state that this node has been removed from the list */
	node->tln_on_list = B_FALSE;

	/* cleanup the node's link pointers */
	node->tln_prev = NULL;
	node->tln_next = NULL;
}


/*
 * t1394_tlist_nsectohz()
 *     Convert nS to hz.  This allows us to call timeout() but keep our time
 *     reference in nS.
 */
#define	HCI1394_TLIST_nS_TO_uS(nS)  ((clock_t)(nS / 1000))
static clock_t t1394_tlist_nsectohz(hrtime_t  nS)
{
	return (drv_usectohz(HCI1394_TLIST_nS_TO_uS(nS)));
}
