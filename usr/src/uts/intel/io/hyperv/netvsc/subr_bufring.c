/*
 * Copyright (c) 2007, 2008 Kip Macy <kmacy@freebsd.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2017 by Delphix. All rights reserved.
 */

#include <sys/param.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <sys/errno.h>
#include <sys/atomic.h>
#include <sys/cpuvar.h>
#include <sys/disp.h>
#include <sys/cpu.h>

#include "buf_ring.h"


/* ARGSUSED */
struct buf_ring *
buf_ring_alloc(int count, int flags, kmutex_t *lock)
{
	struct buf_ring *br;

	/*
	 * buf ring must be size power of 2
	 */
	VERIFY(ISP2(count));

	br = kmem_zalloc(sizeof (struct buf_ring) + count * sizeof (caddr_t),
	    flags);
	if (br == NULL)
		return (NULL);
#ifdef DEBUG_BUFRING
	br->br_lock = lock;
#endif
	br->br_prod_size = br->br_cons_size = count;
	br->br_prod_mask = br->br_cons_mask = count-1;
	br->br_prod_head = br->br_cons_head = 0;
	br->br_prod_tail = br->br_cons_tail = 0;

	return (br);
}

void
buf_ring_free(struct buf_ring *br)
{
	kmem_free(br, sizeof (struct buf_ring) + br->br_prod_size *
	    sizeof (caddr_t));
}

/*
 * multi-producer safe lock-free ring buffer enqueue
 *
 */
int
buf_ring_enqueue(struct buf_ring *br, void *buf)
{
	uint32_t prod_head, prod_next, cons_tail;
	int cas = -1;
#ifdef DEBUG_BUFRING
	int i;
	for (i = br->br_cons_head; i != br->br_prod_head;
	    i = ((i + 1) & br->br_cons_mask)) {
		if (br->br_ring[i] == buf) {
			panic("buf=%p already enqueue at %d prod=%d cons=%d",
			    buf, i, br->br_prod_tail, br->br_cons_tail);
		}
	}
#endif
	kpreempt_disable();
	do {
		prod_head = br->br_prod_head;
		prod_next = (prod_head + 1) & br->br_prod_mask;
		cons_tail = br->br_cons_tail;

		if (prod_next == cons_tail) {
			membar_consumer();
			if (prod_head == br->br_prod_head &&
			    cons_tail == br->br_cons_tail) {
				br->br_drops++;
				kpreempt_enable();
				return (ENOBUFS);
			}
			continue;
		}
		cas = atomic_cas_32(&br->br_prod_head, prod_head, prod_next);
	} while (cas != prod_head);

#ifdef DEBUG_BUFRING
	if (br->br_ring[prod_head] != NULL)
		panic("dangling value in enqueue");
#endif
	br->br_ring[prod_head] = buf;

	/*
	 * If there are other enqueues in progress
	 * that preceded us, we need to wait for them
	 * to complete
	 */
	while (br->br_prod_tail != prod_head)
		SMT_PAUSE();

	br->br_prod_tail = prod_next;
	kpreempt_enable();
	return (0);
}

/*
 * multi-consumer safe dequeue
 *
 */
void *
buf_ring_dequeue_mc(struct buf_ring *br)
{
	uint32_t cons_head, cons_next, cas;
	void *buf;

	kpreempt_disable();
	do {
		cons_head = br->br_cons_head;
		cons_next = (cons_head + 1) & br->br_cons_mask;

		if (cons_head == br->br_prod_tail) {
			kpreempt_enable();
			return (NULL);
		}
		cas = atomic_cas_32(&br->br_cons_head, cons_head, cons_next);
	} while (cas != cons_head);

	buf = br->br_ring[cons_head];
#ifdef DEBUG_BUFRING
	br->br_ring[cons_head] = NULL;
#endif
	/*
	 * If there are other dequeues in progress
	 * that preceded us, we need to wait for them
	 * to complete
	 */
	while (br->br_cons_tail != cons_head)
		SMT_PAUSE();

	br->br_cons_tail = cons_next;
	kpreempt_enable();

	return (buf);
}

/*
 * single-consumer dequeue
 * use where dequeue is protected by a lock
 * e.g. a network driver's tx queue lock
 */
void *
buf_ring_dequeue_sc(struct buf_ring *br)
{
	uint32_t cons_head, cons_next;
	uint32_t prod_tail;
	void *buf;

	cons_head = br->br_cons_head;
	prod_tail = br->br_prod_tail;

	if (cons_head == prod_tail)
		return (NULL);

	cons_next = (cons_head + 1) & br->br_cons_mask;

	br->br_cons_head = cons_next;
	buf = br->br_ring[cons_head];

#ifdef DEBUG_BUFRING
	br->br_ring[cons_head] = NULL;
	if (!MUTEX_HELD(br->br_lock))
		panic("lock not held on single consumer dequeue");
	if (br->br_cons_tail != cons_head) {
		panic("inconsistent list cons_tail=%d cons_head=%d",
		    br->br_cons_tail, cons_head);
	}
#endif
	br->br_cons_tail = cons_next;
	return (buf);
}
