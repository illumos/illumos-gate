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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/


#ifndef _SYS_RT_H
#define	_SYS_RT_H

#include <sys/types.h>
#include <sys/thread.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Real-time dispatcher parameter table entry
 */
typedef struct	rtdpent {
	pri_t	rt_globpri;	/* global (class independent) priority */
	int	rt_quantum;	/* default quantum associated with this level */
} rtdpent_t;

/*
 * Real-time class specific proc structure
 */
typedef struct rtproc {
	int		rt_pquantum;	/* time quantum given to this proc */
	int		rt_timeleft;	/* time remaining in procs quantum */
	pri_t		rt_pri;		/* priority within rt class */
	ushort_t	rt_flags;	/* flags defined below */
	int		rt_tqsignal;	/* time quantum signal */
	kthread_id_t	rt_tp;		/* pointer to thread */
	struct rtproc	*rt_next;	/* link to next rtproc on list */
	struct rtproc	*rt_prev;	/* link to previous rtproc on list */
} rtproc_t;


/* Flags */
#define	RTBACKQ	0x0002		/* proc goes to back of disp q when preempted */


#ifdef _KERNEL
/*
 * Kernel version of real-time class specific parameter structure
 */
typedef struct	rtkparms {
	pri_t	rt_pri;
	int	rt_tqntm;
	int	rt_tqsig;	/* real-time time quantum signal */
	uint_t	rt_cflags;	/* real-time control flags */
} rtkparms_t;
#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_RT_H */
