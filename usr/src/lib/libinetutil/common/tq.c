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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdlib.h>
#include <limits.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/stropts.h>	/* INFTIM */

#include <libinetutil.h>
#include "libinetutil_impl.h"

static iu_timer_node_t	*pending_delete_chain = NULL;

static void		destroy_timer(iu_tq_t *, iu_timer_node_t *);
static iu_timer_id_t	get_timer_id(iu_tq_t *);
static void		release_timer_id(iu_tq_t *, iu_timer_id_t);

/*
 * iu_tq_create(): creates, initializes and returns a timer queue for use
 *
 *   input: void
 *  output: iu_tq_t *: the new timer queue
 */

iu_tq_t *
iu_tq_create(void)
{
	return (calloc(1, sizeof (iu_tq_t)));
}

/*
 * iu_tq_destroy(): destroys an existing timer queue
 *
 *   input: iu_tq_t *: the timer queue to destroy
 *  output: void
 */

void
iu_tq_destroy(iu_tq_t *tq)
{
	iu_timer_node_t *node, *next_node;

	for (node = tq->iutq_head; node != NULL; node = next_node) {
		next_node = node->iutn_next;
		destroy_timer(tq, node);
	}

	free(tq);
}

/*
 * insert_timer(): inserts a timer node into a tq's timer list
 *
 *   input: iu_tq_t *: the timer queue
 *	    iu_timer_node_t *: the timer node to insert into the list
 *	    uint64_t: the number of milliseconds before this timer fires
 *  output: void
 */

static void
insert_timer(iu_tq_t *tq, iu_timer_node_t *node, uint64_t msec)
{
	iu_timer_node_t	*after = NULL;

	/*
	 * find the node to insert this new node "after".  we do this
	 * instead of the more intuitive "insert before" because with
	 * the insert before approach, a null `before' node pointer
	 * is overloaded in meaning (it could be null because there
	 * are no items in the list, or it could be null because this
	 * is the last item on the list, which are very different cases).
	 */

	node->iutn_abs_timeout = gethrtime() + MSEC2NSEC(msec);

	if (tq->iutq_head != NULL &&
	    tq->iutq_head->iutn_abs_timeout < node->iutn_abs_timeout)
		for (after = tq->iutq_head; after->iutn_next != NULL;
		    after = after->iutn_next)
			if (after->iutn_next->iutn_abs_timeout >
			    node->iutn_abs_timeout)
				break;

	node->iutn_next = after ? after->iutn_next : tq->iutq_head;
	node->iutn_prev = after;
	if (after == NULL)
		tq->iutq_head = node;
	else
		after->iutn_next = node;

	if (node->iutn_next != NULL)
		node->iutn_next->iutn_prev = node;
}

/*
 * remove_timer(): removes a timer node from the tq's timer list
 *
 *   input: iu_tq_t *: the timer queue
 *	    iu_timer_node_t *: the timer node to remove from the list
 *  output: void
 */

static void
remove_timer(iu_tq_t *tq, iu_timer_node_t *node)
{
	if (node->iutn_next != NULL)
		node->iutn_next->iutn_prev = node->iutn_prev;
	if (node->iutn_prev != NULL)
		node->iutn_prev->iutn_next = node->iutn_next;
	else
		tq->iutq_head = node->iutn_next;
}

/*
 * destroy_timer(): destroy a timer node
 *
 *  input: iu_tq_t *: the timer queue the timer node is associated with
 *	   iu_timer_node_t *: the node to free
 * output: void
 */

static void
destroy_timer(iu_tq_t *tq, iu_timer_node_t *node)
{
	release_timer_id(tq, node->iutn_timer_id);

	/*
	 * if we're in expire, don't delete the node yet, since it may
	 * still be referencing it (through the expire_next pointers)
	 */

	if (tq->iutq_in_expire) {
		node->iutn_pending_delete++;
		node->iutn_next = pending_delete_chain;
		pending_delete_chain = node;
	} else
		free(node);

}

/*
 * iu_schedule_timer(): creates and inserts a timer in the tq's timer list
 *
 *   input: iu_tq_t *: the timer queue
 *	    uint32_t: the number of seconds before this timer fires
 *	    iu_tq_callback_t *: the function to call when the timer fires
 *	    void *: an argument to pass to the called back function
 *  output: iu_timer_id_t: the new timer's timer id on success, -1 on failure
 */

iu_timer_id_t
iu_schedule_timer(iu_tq_t *tq, uint32_t sec, iu_tq_callback_t *callback,
    void *arg)
{
	return (iu_schedule_timer_ms(tq, sec * MILLISEC, callback, arg));
}

/*
 * iu_schedule_ms_timer(): creates and inserts a timer in the tq's timer list,
 *			   using millisecond granularity
 *
 *   input: iu_tq_t *: the timer queue
 *	    uint64_t: the number of milliseconds before this timer fires
 *	    iu_tq_callback_t *: the function to call when the timer fires
 *	    void *: an argument to pass to the called back function
 *  output: iu_timer_id_t: the new timer's timer id on success, -1 on failure
 */
iu_timer_id_t
iu_schedule_timer_ms(iu_tq_t *tq, uint64_t ms, iu_tq_callback_t *callback,
    void *arg)
{
	iu_timer_node_t	*node = calloc(1, sizeof (iu_timer_node_t));

	if (node == NULL)
		return (-1);

	node->iutn_callback	= callback;
	node->iutn_arg	= arg;
	node->iutn_timer_id	= get_timer_id(tq);
	if (node->iutn_timer_id == -1) {
		free(node);
		return (-1);
	}

	insert_timer(tq, node, ms);

	return (node->iutn_timer_id);
}

/*
 * iu_cancel_timer(): cancels a pending timer from a timer queue's timer list
 *
 *   input: iu_tq_t *: the timer queue
 *	    iu_timer_id_t: the timer id returned from iu_schedule_timer
 *	    void **: if non-NULL, a place to return the argument passed to
 *		     iu_schedule_timer
 *  output: int: 1 on success, 0 on failure
 */

int
iu_cancel_timer(iu_tq_t *tq, iu_timer_id_t timer_id, void **arg)
{
	iu_timer_node_t	*node;

	if (timer_id == -1)
		return (0);

	for (node = tq->iutq_head; node != NULL; node = node->iutn_next) {
		if (node->iutn_timer_id == timer_id) {
			if (arg != NULL)
				*arg = node->iutn_arg;
			remove_timer(tq, node);
			destroy_timer(tq, node);
			return (1);
		}
	}
	return (0);
}

/*
 * iu_adjust_timer(): adjusts the fire time of a timer in the tq's timer list
 *
 *   input: iu_tq_t *: the timer queue
 *	    iu_timer_id_t: the timer id returned from iu_schedule_timer
 *	    uint32_t: the number of seconds before this timer fires
 *  output: int: 1 on success, 0 on failure
 */

int
iu_adjust_timer(iu_tq_t *tq, iu_timer_id_t timer_id, uint32_t sec)
{
	iu_timer_node_t	*node;

	if (timer_id == -1)
		return (0);

	for (node = tq->iutq_head; node != NULL; node = node->iutn_next) {
		if (node->iutn_timer_id == timer_id) {
			remove_timer(tq, node);
			insert_timer(tq, node, sec * MILLISEC);
			return (1);
		}
	}
	return (0);
}

/*
 * iu_earliest_timer(): returns the time until the next timer fires on a tq
 *
 *   input: iu_tq_t *: the timer queue
 *  output: int: the number of milliseconds until the next timer (up to
 *	    a maximum value of INT_MAX), or INFTIM if no timers are pending.
 */

int
iu_earliest_timer(iu_tq_t *tq)
{
	unsigned long long	timeout_interval;
	hrtime_t		current_time = gethrtime();

	if (tq->iutq_head == NULL)
		return (INFTIM);

	/*
	 * event might've already happened if we haven't gotten a chance to
	 * run in a while; return zero and pretend it just expired.
	 */

	if (tq->iutq_head->iutn_abs_timeout <= current_time)
		return (0);

	/*
	 * since the timers are ordered in absolute time-to-fire, just
	 * subtract from the head of the list.
	 */

	timeout_interval =
	    (tq->iutq_head->iutn_abs_timeout - current_time) / 1000000;

	return (MIN(timeout_interval, INT_MAX));
}

/*
 * iu_expire_timers(): expires all pending timers on a given timer queue
 *
 *   input: iu_tq_t *: the timer queue
 *  output: int: the number of timers expired
 */

int
iu_expire_timers(iu_tq_t *tq)
{
	iu_timer_node_t	*node, *next_node;
	int		n_expired = 0;
	hrtime_t	current_time = gethrtime();

	/*
	 * in_expire is in the iu_tq_t instead of being passed through as
	 * an argument to remove_timer() below since the callback
	 * function may call iu_cancel_timer() itself as well.
	 */

	tq->iutq_in_expire++;

	/*
	 * this function builds another linked list of timer nodes
	 * through `expire_next' because the normal linked list
	 * may be changed as a result of callbacks canceling and
	 * scheduling timeouts, and thus can't be trusted.
	 */

	for (node = tq->iutq_head; node != NULL; node = node->iutn_next)
		node->iutn_expire_next = node->iutn_next;

	for (node = tq->iutq_head; node != NULL;
	    node = node->iutn_expire_next) {

		/*
		 * If the timeout is within 1 millisec of current time,
		 * consider it as expired already.  We do this because
		 * iu_earliest_timer() only has millisec granularity.
		 * So we should also use millisec grandularity in
		 * comparing timeout values.
		 */
		if (node->iutn_abs_timeout - current_time > 1000000)
			break;

		/*
		 * fringe condition: two timers fire at the "same
		 * time" (i.e., they're both scheduled called back in
		 * this loop) and one cancels the other.  in this
		 * case, the timer which has already been "cancelled"
		 * should not be called back.
		 */

		if (node->iutn_pending_delete)
			continue;

		/*
		 * we remove the timer before calling back the callback
		 * so that a callback which accidentally tries to cancel
		 * itself (through whatever means) doesn't succeed.
		 */

		n_expired++;
		remove_timer(tq, node);
		destroy_timer(tq, node);
		node->iutn_callback(tq, node->iutn_arg);
	}

	tq->iutq_in_expire--;

	/*
	 * any cancels that took place whilst we were expiring timeouts
	 * ended up on the `pending_delete_chain'.  delete them now
	 * that it's safe.
	 */

	for (node = pending_delete_chain; node != NULL; node = next_node) {
		next_node = node->iutn_next;
		free(node);
	}
	pending_delete_chain = NULL;

	return (n_expired);
}

/*
 * get_timer_id(): allocates a timer id from the pool
 *
 *   input: iu_tq_t *: the timer queue
 *  output: iu_timer_id_t: the allocated timer id, or -1 if none available
 */

static iu_timer_id_t
get_timer_id(iu_tq_t *tq)
{
	unsigned int	map_index;
	unsigned char	map_bit;
	boolean_t	have_wrapped = B_FALSE;

	for (; ; tq->iutq_next_timer_id++) {

		if (tq->iutq_next_timer_id >= IU_TIMER_ID_MAX) {
			if (have_wrapped)
				return (-1);

			have_wrapped = B_TRUE;
			tq->iutq_next_timer_id = 0;
		}

		map_index = tq->iutq_next_timer_id / CHAR_BIT;
		map_bit   = tq->iutq_next_timer_id % CHAR_BIT;

		if ((tq->iutq_timer_id_map[map_index] & (1 << map_bit)) == 0)
			break;
	}

	tq->iutq_timer_id_map[map_index] |= (1 << map_bit);
	return (tq->iutq_next_timer_id++);
}

/*
 * release_timer_id(): releases a timer id back into the pool
 *
 *   input: iu_tq_t *: the timer queue
 *	    iu_timer_id_t: the timer id to release
 *  output: void
 */

static void
release_timer_id(iu_tq_t *tq, iu_timer_id_t timer_id)
{
	unsigned int	map_index = timer_id / CHAR_BIT;
	unsigned char	map_bit	  = timer_id % CHAR_BIT;

	tq->iutq_timer_id_map[map_index] &= ~(1 << map_bit);
}
