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
 * Copyright (c) 1985,1997-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 * This file describes a virtual user input device (vuid) event queue
 * maintainence package (see ../sundev/vuid_event.h for a description
 * of what vuid is).  This header file defines the interface that a
 * client of this package sees.	 This package is used to maintain queues
 * of firm events awaiting deliver to some consumer.
 */

#ifndef _SYS_VUID_QUEUE_H
#define	_SYS_VUID_QUEUE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SunOS 1.6 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Vuid input queue structure.
 */
typedef struct	vuid_queue {
	struct	vuid_q_node *top;	/* input queue head (first in line) */
	struct	vuid_q_node *bottom;	/* input queue head (last in line) */
	struct	vuid_q_node *free;	/* input queue free list */
	int	num;			/* number of items currently on queue */
	int	size;			/* number of items allowed on queue */
} Vuid_queue;
#define	VUID_QUEUE_NULL ((Vuid_queue *)0)
#define	vq_used(vq) ((vq)->num)
#define	vq_avail(vq) ((vq)->size - (vq)->num)
#define	vq_size(vq) ((vq)->size)
#define	vq_is_empty(vq) ((vq)->top == VUID_Q_NODE_NULL)
#define	vq_is_full(vq) ((vq)->num == (vq)->size)

/*
 * Vuid input queue node structure.
 */
typedef struct	vuid_q_node {
	struct	vuid_q_node *next;	/* Next item in queue */
	struct	vuid_q_node *prev;	/* Previous item in queue */
	Firm_event firm_event;		/* Firm event */
} Vuid_q_node;
#define	VUID_Q_NODE_NULL	((Vuid_q_node *)0)

/*
 * Vuid input queue status codes.
 */
typedef enum	vuid_q_code {
	VUID_Q_OK = 0,		/* OK */
	VUID_Q_OVERFLOW = 1,	/* overflow */
	VUID_Q_EMPTY = 2	/* empty */
} Vuid_q_code;

extern	void vq_initialize(); /* (Vuid_queue *vq, caddr_t data, uint_t bytes) */
				/* Client allocates bytes worth of storage */
				/* and pass in a data. Client destroys the q */
				/* simply by releasing data. */
extern	Vuid_q_code vq_put();	/* (Vuid_queue *vq, Firm_event *firm_event) */
				/* Place firm_event on queue, position is */
				/* dependent on the firm event's time.	Can */
				/* return VUID_Q_OVERFLOW if no more room. */
extern	Vuid_q_code vq_get();	/* (Vuid_queue *vq, Firm_event *firm_event) */
				/* Place event on top of queue in firm_event. */
				/* Can return VUID_Q_EMPTY if no more events */
extern	Vuid_q_code vq_peek();	/* Like vq_get but doesn't remove from queue */
extern	Vuid_q_code vq_putback(); /* (Vuid_queue *vq, Firm_event *firm_event) */
				/* Push firm_event on top of queue.  Can */
				/* return VUID_Q_OVERFLOW if no more room. */

extern	int vq_compress();	/* (Vuid_queue *vq, factor)  Try to */
				/* collapse the queue to a size of 1/factor */
				/* by squeezing like valuator events together */
				/* Returns number collapsed */
extern	int vq_is_valuator();	/* (Vuid_q_node *vqn) if value is not 0 or 1 */
				/* || pair_type is FE_PAIR_DELTA or */
				/* FE_PAIR_ABSOLUTE */
extern	void vq_delete_node();	/* (Vuid_queue *vq, Vuid_q_node *vqn) */
				/* Deletes vqn from vq */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_VUID_QUEUE_H */
