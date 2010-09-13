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
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	DSVCD_CONTAINER_H
#define	DSVCD_CONTAINER_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <synch.h>

#include "dsvclockd.h"

/*
 * Container-related data structures, functions and constants.  See
 * comments in container.c for a description of how to use the exported
 * functions.
 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Number of seconds to wait for container lockholders to relinquish all
 * locks on a given container (when it's being destroyed).
 */
#define	CN_DESTROY_WAIT	60

/*
 * Describes a thread waiting to access a given container; exactly one per
 * waiting thread.
 */
typedef struct dsvcd_waitlist {
	struct dsvcd_waitlist	*wl_next;	/* next waiter in list */
	struct dsvcd_waitlist	*wl_prev;	/* prev waiter in list */
	cond_t			wl_cv;		/* our condition variable */
	dsvcd_locktype_t	wl_locktype;	/* type of lock we want */
} dsvcd_waitlist_t;

/*
 * States for the host lock state machine.  The state machine is a simple
 * cycle of UNLOCKED->PENDING->{RD,WR}LOCKED->UNLOCKED->...
 */
enum cn_hlockstate { CN_HUNLOCKED, CN_HPENDING, CN_HRDLOCKED, CN_HWRLOCKED };

/*
 * Describes a given container within a datastore.  There is at most one of
 * these per datastore container (there may be none if there are no current
 * consumers of a given container within a datastore).  If there is more
 * than one open handle to a given container (through multiple calls to
 * open_d?()) there will still only be one dsvcd_container_t for that
 * container.  This object is used to synchronize access to an underlying
 * container through use of its custom reader/writer lock (it can't use the
 * rwlock_t's built into Solaris because we need locks that do not care if
 * the unlocking thread is the same as the locking thread).  It also
 * contains other per-container information like the container id.
 */
typedef struct dsvcd_container {
	char			*cn_id;		/* container's id */
	boolean_t		cn_crosshost;	/* synchronize across hosts */
	boolean_t		cn_closing;	/* container is going away */
	mutex_t			cn_lock;	/* protects preceding fields */

	dsvcd_waitlist_t	*cn_whead;	/* head of wait list */
	dsvcd_waitlist_t	*cn_wtail;	/* tail of wait list */
	int			cn_nholds;	/* num readers (-1 == writer) */
	mutex_t			cn_nholds_lock;	/* for nholds and waitlist */

	int			cn_hlockfd;	/* host lock file descriptor */
	int			cn_hlockcount;	/* current # of host locks */
	enum cn_hlockstate	cn_hlockstate;	/* host lock state */
	cond_t			cn_hlockcv;	/* host lock condvar */
	mutex_t			cn_hlock_lock;	/* mutex for cn_hlock* */

	/*
	 * These fields are used to keep metadata state regarding the
	 * container and are actually maintained by the containing
	 * datastore, not the container.
	 */
	uint_t			cn_nout;	/* number checked out */
	time_t			cn_lastrel;	/* last released */
	uint32_t		cn_idhash;	/* hash before modulation */
	struct dsvcd_container	*cn_next;	/* hash chain next */
	struct dsvcd_container	*cn_prev;	/* hash chain prev */
} dsvcd_container_t;

extern dsvcd_container_t	*cn_create(const char *, boolean_t);
extern void			cn_destroy(dsvcd_container_t *);
extern int			cn_rdlock(dsvcd_container_t *, boolean_t);
extern int			cn_wrlock(dsvcd_container_t *, boolean_t);
extern int			cn_unlock(dsvcd_container_t *);
extern dsvcd_locktype_t		cn_locktype(dsvcd_container_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* DSVCD_CONTAINER_H */
