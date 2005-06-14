/*
 * Copyright 2001-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1988, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)ring.h	8.1 (Berkeley) 6/6/93
 */

#ifndef _RING_H
#define	_RING_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * This defines a structure for a ring buffer.
 *
 * The circular buffer has two parts:
 * (((
 *	full:	[consume, supply)
 *	empty:	[supply, consume)
 * ]]]
 *
 */
typedef struct {
    unsigned char *consume;	/* where data comes out of */
    unsigned char *supply;	/* where data comes in to */
    unsigned char *bottom;	/* lowest address in buffer */
    unsigned char *top;		/* highest address+1 in buffer */
    unsigned char *mark;	/* marker (user defined) */
    unsigned char *clearto;	/* Data to this point is clear text */
    unsigned char *encryyptedto; /* Data is encrypted to here */
    int		size;		/* size in bytes of buffer */
    ulong_t	consumetime;	/* help us keep straight full, empty, etc. */
    ulong_t	supplytime;
} Ring;

/* Here are some functions and macros to deal with the ring buffer */

/* Initialization routine */
extern int ring_init(Ring *ring, unsigned char *buffer, int count);

/* Data movement routines */
extern void ring_supply_data(Ring *ring, unsigned char *buffer, int count);
#ifdef notdef
extern void ring_consume_data(Ring *ring, unsigned char *buffer, int count);
#endif

/* Buffer state transition routines */
extern void ring_supplied(Ring *ring, int count);
extern void ring_consumed(Ring *ring, int count);

/* Buffer state query routines */
extern int ring_at_mark(Ring *ring);
extern int ring_empty_count(Ring *ring);
extern int ring_empty_consecutive(Ring *ring);
extern int ring_full_count(Ring *ring);
extern int ring_full_consecutive(Ring *ring);

extern void ring_encrypt(Ring *ring, void (*func)());
extern void ring_clearto(Ring *ring);

extern void ring_clear_mark();
extern void ring_mark();


#ifdef	__cplusplus
}
#endif

#endif	/* _RING_H */
