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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_NXGE_NXGE_SERIALIZE_H
#define	_SYS_NXGE_NXGE_SERIALIZE_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	NXGE_TX_AVG_CNT		200000000
#define	NXGE_TX_AVG_RES		2000		/* sleep at least a tick */
#define	MAXHRS			3		/* # of packets to process */
#define	ONESEC			1000000000	/* one second */

#include <sys/stream.h>
#include <sys/mutex.h>
#include <sys/condvar.h>
#include <sys/kmem.h>
#include <sys/ddi.h>
#include <sys/callb.h>

/*
 * Thread state flags
 */
#define	NXGE_TX_STHREAD_RUNNING	0x0001	/* thread started */
#define	NXGE_TX_STHREAD_DESTROY	0x0002	/* thread is being destroyed */
#define	NXGE_TX_STHREAD_EXIT	0x0003	/* thread exits */

typedef int (onetrack_t)(mblk_t *, void *);

typedef struct {
	kmutex_t	lock;
	int		count;
	mblk_t		*head;
	mblk_t		*tail;
	void		*cookie;
	onetrack_t	*serialop;
	int		owned;
	/* Counter tracks the total time spent in serializer function */
	hrtime_t	totaltime;
	/*
	 * Counter tracks the total number of time the serializer
	 * function was called.
	 */
	long		totalcount;
	/*
	 * Counter maintains the average time spent in the serializer function
	 * and is derived as (totaltime/totalcount).
	 */
	int		avg;
	/*
	 * The lenght of the queue to which the serializer function
	 * will append data.
	 */
	int		length;
	kcondvar_t	serial_cv;
	kcondvar_t	timecv;
	kmutex_t	serial;
	uint32_t	s_state;
	boolean_t	s_need_signal;
	callb_cpr_t 	s_cprinfo;
	kthread_t 	*tx_sthread;
	kmutex_t	timelock;
} nxge_serialize_t;

/*
 * Prototypes definitions
 */
nxge_serialize_t *nxge_serialize_create(int, onetrack_t *, void *);
void nxge_serialize_destroy(nxge_serialize_t *);
void nxge_serialize_enter(nxge_serialize_t *, mblk_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_NXGE_NXGE_SERIALIZE_H */
