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
 * Copyright 1994, 1997-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_INTR_H
#define	_SYS_INTR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Each cpu allocates an interrupt request pool with the size of
 * INTR_PENDING_MAX entries.
 * XXX this number needs to be tuned
 */
#define	INTR_PENDING_MAX	64
#define	INTR_POOL_SIZE		(sizeof (struct intr_req) * INTR_PENDING_MAX)

/*
 * Allocate threads and stacks for interrupt handling.
 */
#define	NINTR_THREADS	(LOCK_LEVEL)	/* number of interrupt threads */

/*
 * Each cpu allocates two arrays, intr_head[] and intr_tail[], with the size of
 * PIL_LEVELS each.
 *
 * The entry 0 of the arrays are the head and the tail of the interrupt
 * request free list.
 *
 * The entries 1-15 of the arrays are the head and the tail of interrupt
 * level 1-15 request queues.
 */
#define	PIL_LEVELS	16	/* 0    : for the interrupt request free list */
				/* 1-15 : for the pil level 1-15 */

#define	PIL_1	1
#define	PIL_2	2
#define	PIL_3	3
#define	PIL_4	4
#define	PIL_5	5
#define	PIL_6	6
#define	PIL_7	7
#define	PIL_8	8
#define	PIL_9	9
#define	PIL_10	10
#define	PIL_11	11
#define	PIL_12	12
#define	PIL_13	13
#define	PIL_14	14
#define	PIL_15	15

#ifndef _ASM
extern uint_t poke_cpu_inum;
extern size_t intr_add_max;
extern uint_t intr_add_div;
extern size_t intr_add_pools;
extern struct intr_req *intr_add_head;
extern struct intr_req *intr_add_tail;
extern void intr_init(struct cpu *);
extern void init_intr_pool(struct cpu *);
extern void cleanup_intr_pool(struct cpu *);

/*
 * interrupt request entry
 *
 *    - each cpu has an interrupt request free list formed thru
 *      init_intr_pool(); intr_head[0] and intr_tail[0] are the head
 *      and tail of the free list
 *
 *    - always get a free intr_req from the intr_head[0] and
 *      return a served intr_req to intr_tail[0]
 *
 *    - when vec_interrupt() is called, an interrupt request queue is built
 *      according to the pil level, intr_head[pil] points to the first
 *      interrupt request entry and intr_tail[pil] points to the last one
 *
 */
struct intr_req {
	uint_t 		intr_number;
	struct intr_req *intr_next;
};

#endif	/* !_ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_INTR_H */
