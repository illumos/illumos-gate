/*
 * Copyright (c) 2007-2009 Kip Macy <kmacy@freebsd.org>
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
 *
 * $FreeBSD$
 *
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

#ifndef	_SYS_BUF_RING_H_
#define	_SYS_BUF_RING_H_

#include <sys/hyperv_illumos.h>
#include <sys/errno.h>
#include <sys/atomic.h>
#include <sys/debug.h>
#include <sys/cpuvar.h>
#include <sys/disp.h>
#include <sys/cpu.h>

#ifdef DEBUG_BUFRING
#include <sys/mutex.h>
#endif

struct buf_ring {
	volatile uint32_t	br_prod_head;
	volatile uint32_t	br_prod_tail;
	int			br_prod_size;
	int			br_prod_mask;
	uint64_t		br_drops;
	volatile uint32_t	br_cons_head __aligned(CACHE_LINE_SIZE);
	volatile uint32_t	br_cons_tail;
	int			br_cons_size;
	int			br_cons_mask;
#ifdef DEBUG_BUFRING
	kmutex_t		*br_lock;
#endif
	void			*br_ring[] __aligned(CACHE_LINE_SIZE);
};

static inline boolean_t
buf_ring_full(struct buf_ring *br)
{
	return (((br->br_prod_head + 1) & br->br_prod_mask) ==
	    br->br_cons_tail);
}

static inline boolean_t
buf_ring_empty(struct buf_ring *br)
{
	return (br->br_cons_head == br->br_prod_tail);
}

static inline int
buf_ring_count(struct buf_ring *br)
{
	return ((br->br_prod_size + br->br_prod_tail - br->br_cons_tail)
	    & br->br_prod_mask);
}

struct buf_ring *buf_ring_alloc(int count, int flags, kmutex_t *lock);
void buf_ring_free(struct buf_ring *br);
int buf_ring_enqueue(struct buf_ring *br, void *buf);
void *buf_ring_dequeue_mc(struct buf_ring *br);
void *buf_ring_dequeue_sc(struct buf_ring *br);


#endif /* _SYS_BUF_RING_H_ */
