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
 * Copyright (c) 1994, by Sun Microsytems, Inc.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Includes
 */

#include "queue.h"
#include "new.h"


/*
 * queue_init() - initializes a queue_node to be unlinked.
 */

void
queue_init(queue_node_t * q)
{
	q->next_p = q->prev_p = q;

}				/* end queue_init */


/*
 * queue_prepend() - prepends a queue_node to another in a list
 */

queue_node_t   *
queue_prepend(queue_node_t * h, queue_node_t * q)
{
	if (!h)
		return ((q) ? q : NULL);

	if (q) {
		queue_node_t   *qtail_p = q->prev_p;
		queue_node_t   *hnode_p = h->next_p;

		hnode_p->prev_p = qtail_p;
		h->next_p = q;

		q->prev_p = h;
		qtail_p->next_p = hnode_p;
	}
	return (h);

}				/* end queue_prepend */


/*
 * queue_append() - appends a queue_node to another in a list
 */

queue_node_t   *
queue_append(queue_node_t * h, queue_node_t * q)
{
	if (!h)
		return ((q) ? q : NULL);

	if (q) {
		queue_node_t   *htail_p = h->prev_p;
		queue_node_t   *qtail_p = q->prev_p;

		h->prev_p = qtail_p;
		htail_p->next_p = q;

		q->prev_p = htail_p;
		qtail_p->next_p = h;
	}
	return (h);

}				/* end queue_append */


/*
 * queue_remove() - removes a node from a list, returns a pointer to the next
 * node in the list.
 */

queue_node_t   *
queue_remove(queue_node_t * q)
{
	queue_node_t   *n;

	n = q->next_p;

	if (queue_isempty(q))
		return (NULL);

	q->next_p->prev_p = q->prev_p;
	q->prev_p->next_p = q->next_p;

	q->next_p = q->prev_p = q;

	return (n);

}				/* end queue_remove */


/*
 * queue_isempty()
 */

boolean_t
queue_isempty(queue_node_t * q)
{
	return ((q->next_p == q));

}				/* queue_isempty */


/*
 * queue_next() - returns the next element in a queue, or NULL if the
 * supplied previous item was the last.
 */

queue_node_t   *
queue_next(queue_node_t * h, queue_node_t * q)
{
	if (!h)
		return (NULL);

	if (!q)
		return (h);

	if (q->next_p == h)
		return (NULL);

	return (q->next_p);

}				/* end queue_next */
