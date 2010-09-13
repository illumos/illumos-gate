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
 * Copyright (c) 1997-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc.	*/
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T	*/
/*	  All Rights Reserved  	*/

#ifndef _SYS_XQUE_H
#define	_SYS_XQUE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Keyboard/mouse event queue entries
 */

typedef struct xqEvent {
	uchar_t	xq_type;	/* event type (see below) */
	uchar_t	xq_code;	/* when xq_type is XQ_KEY, => scan code; */
				/* when xq_type is XQ_MOTION or XQ_BUTTON, => */
				/*	bit 0 clear if right button pushed; */
				/*	bit 1 clear if middle button pushed; */
				/*	bit 2 clear if left button pushed; */
	char	xq_x;		/* delta x movement (mouse motion only) */
	char	xq_y;		/* delta y movement (mouse motion only) */
	time_t	xq_time; 	/* event timestamp in "milliseconds" */
} xqEvent;

/*	xq_type values		*/

#define	XQ_BUTTON	0	/* button state change only */
#define	XQ_MOTION	1	/* mouse movement (and maybe button change) */
#define	XQ_KEY		2	/* key pressed or released */

/*
 * The event queue
 */

typedef struct xqEventQueue {
	char	xq_sigenable;	/* allow signal when queue becomes non-empty */
				/* 0 => don't send signals */
				/* non-zero => send a signal if queue is */
				/*	empty and a new event is added */
	int	xq_head;	/* index into queue of next event to be */
				/* dequeued */
	int	xq_tail;	/* index into queue of next event slot to */
				/* be filled */
	time_t	xq_curtime;	/* time in milliseconds since 1/1/70 GMT */
	int	xq_size;	/* number of elements in xq_events array */
	xqEvent	xq_events[1];	/* configurable-size array of events */
} xqEventQueue;

#ifdef _KERNEL

/*
 * The driver's private data structure to keep track of xqEventQueue
 */

typedef struct xqInfo {
	xqEventQueue	*xq_queue;	/* pointer to the xqEventQueue */
					/* structure */
	caddr_t xq_private;
	caddr_t	xq_qaddr;	/* pointer to the SCO QUEUE structure */
	char	xq_qtype;	/* xque or SCO que */
	char	xq_buttons;
	char	xq_devices;	/* devices that uses the SCO que */
	char	xq_xlate;	/* Should we translate scancodes? */
	int	(*xq_addevent)();	/* xque or SCO que addevent routine */
	int	xq_ptail;	/* private copy of xq_tail */
	int	xq_psize;	/* private copy of xq_size */
	int	xq_signo;	/* signal number to send for xq_sigenable */
	proc_t	*xq_proc;	/* pointer to x server process */
				/* (for signalling) */
	int	xq_pid;		/* process id of server process */
	struct xqInfo	*xq_next,	/* next xqInfo structure in list */
			*xq_prev;	/* previous xqInfo structure in list */
	addr_t	xq_uaddr;
	unsigned	xq_npages;
} xqInfo;

/*  defined bits for xq_devices */

#define	QUE_KEYBOARD	1
#define	QUE_MOUSE	2

#endif	/* _KERNEL */

caddr_t xq_init();

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_XQUE_H */
