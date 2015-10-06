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
 * Copyright (c) 1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 * Copyright 2015, Joyent, Inc.
 */

#ifndef	_SYS_DEVPOLL_H
#define	_SYS_DEVPOLL_H

#include <sys/poll_impl.h>
#include <sys/types32.h>

#ifdef	__cplusplus
extern "C" {
#endif


/* /dev/poll ioctl */
#define		DPIOC	(0xD0 << 8)
#define	DP_POLL		(DPIOC | 1)	/* poll on fds cached via /dev/poll */
#define	DP_ISPOLLED	(DPIOC | 2)	/* is this fd cached in /dev/poll */
#define	DP_PPOLL	(DPIOC | 3)	/* ppoll on fds cached via /dev/poll */
#define	DP_EPOLLCOMPAT	(DPIOC | 4)	/* turn on epoll compatibility */

#define	DEVPOLLSIZE	1000		/* /dev/poll table size increment */

/*
 * /dev/poll DP_POLL ioctl format
 */
typedef struct dvpoll {
	pollfd_t	*dp_fds;	/* pollfd array */
	nfds_t		dp_nfds;	/* num of pollfd's in dp_fds[] */
	int		dp_timeout;	/* time out in milisec */
	sigset_t	*dp_setp;	/* sigset, if any */
} dvpoll_t;

typedef struct dvpoll32 {
	caddr32_t	dp_fds;		/* pollfd array */
	uint32_t	dp_nfds;	/* num of pollfd's in dp_fds[] */
	int32_t		dp_timeout;	/* time out in milisec */
	caddr32_t	dp_setp;	/* sigset, if any */
} dvpoll32_t;

typedef struct dvpoll_epollfd {
	pollfd_t	dpep_pollfd;	/* must be first member */
	uint64_t	dpep_data;	/* data payload */
} dvpoll_epollfd_t;

#ifdef _KERNEL

typedef struct dp_entry {
	kmutex_t	dpe_lock;	/* protect a devpoll entry */
	pollcache_t	*dpe_pcache;	/* a ptr to pollcache */
	int		dpe_refcnt;	/* no. of ioctl lwp on the dpe */
	int		dpe_writerwait;	/* no. of waits on write */
	int		dpe_flag;	/* see below */
	kcondvar_t	dpe_cv;
} dp_entry_t;

#define	DP_WRITER_PRESENT	0x1	/* a write is in progress */
#define	DP_ISEPOLLCOMPAT	0x2	/* epoll compatibility mode */

#define	DP_REFRELE(dpep) {			\
	mutex_enter(&(dpep)->dpe_lock);		\
	ASSERT((dpep)->dpe_refcnt > 0);		\
	(dpep)->dpe_refcnt--;			\
	mutex_exit(&(dpep)->dpe_lock);		\
}
#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DEVPOLL_H */
