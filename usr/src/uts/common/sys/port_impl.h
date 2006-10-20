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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_PORT_IMPL_H
#define	_SYS_PORT_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Note:
 * The contents of this file are private to the implementation of the
 * Solaris system and event ports subsystem and are subject to change
 * at any time without notice.
 */

#include <sys/poll_impl.h>
#include <sys/port.h>
#include <sys/port_kernel.h>
#include <sys/vnode.h>

/*
 * port system call codes
 */
#define	PORT_CREATE	0	/* create a port */
#define	PORT_ASSOCIATE	1	/* register object or object list */
#define	PORT_DISSOCIATE	2	/* remove object association */
#define	PORT_SEND	3	/* send user-defined event to a port */
#define	PORT_SENDN	4	/* send user-defined event to a list of ports */
#define	PORT_GET	5	/* receive object with events */
#define	PORT_GETN	6	/* receive list of objects with events */
#define	PORT_ALERT	7	/* set port in alert mode */
#define	PORT_DISPATCH	8	/* dispatch object with events */

#define	PORT_SYS_NOPORT		0x100	/* system call without port-id */
#define	PORT_SYS_NOSHARE	0x200	/* non shareable event */
#define	PORT_CODE_MASK		0xff

/* port_dispatch() flags */
#define	PORT_SHARE_EVENT	0x01	/* event can be shared between procs */

/* port limits */
#define	PORT_MAX_LIST	8192	/* max. # of list ent. per syscall */

#ifdef _KERNEL

#define	PORT_SCACHE_SIZE	16	/* start source cache size */
#define	PORT_SHASH(cookie)	(cookie & (PORT_SCACHE_SIZE-1))

/* portkev_flags masks */
#define	PORT_CLEANUP_DONE	(PORT_KEV_FREE|PORT_KEV_DONEQ)
#define	PORT_KEV_CACHE		(PORT_KEV_CACHED|PORT_KEV_SCACHED)
#define	PORT_KEV_WIRED		(PORT_KEV_PRIVATE|PORT_KEV_CACHE)

#define	PORT_FREE_EVENT(pev)	(((pev)->portkev_flags & PORT_KEV_CACHE) == 0)

typedef struct port_alert {
	int	portal_events;		/* passed to alert event */
	pid_t	portal_pid;		/* owner of the alert mode */
	uintptr_t portal_object;	/* passed to alert event */
	void	*portal_user;		/* passed to alert event */
} port_alert_t;

/*
 * The port_queue_t structure is responsible for the management of all
 * event activities within a port.
 */
typedef struct port_queue {
	kmutex_t 	portq_mutex;
	kcondvar_t	portq_closecv;
	kcondvar_t	portq_block_cv;
	int		portq_flags;
	uint_t		portq_nent;	/* number of events in the queue */
	uint_t		portq_nget;	/* events required for waiting thread */
	uint_t		portq_tnent;	/* number of events in the temp queue */
	int		portq_thrcnt;	/* # of threads waiting for events */
	int		portq_getn;	/* # of threads retrieving events */
	struct	portget	*portq_thread;	/* queue of waiting threads */
	struct port_fdcache *portq_pcp;	/* fd cache */
	list_t		portq_list;	/* port event list */
	list_t		portq_get_list;	/* port event list for port_get(n) */
	kmutex_t	portq_source_mutex;
	port_source_t	**portq_scache;
	port_alert_t	portq_alert;	/* alert event data	*/
} port_queue_t;

/* defines for portq_flags */
#define	PORTQ_ALERT	   0x01	/* port in alert state */
#define	PORTQ_CLOSE	   0x02 /* closing port	*/
#define	PORTQ_WAIT_EVENTS  0x04 /* waiting for new events */
#define	PORTQ_POLLIN	   0x08 /* events available in the event queue */
#define	PORTQ_POLLOUT	   0x10 /* space available for new events */
#define	PORTQ_BLOCKED	   0x20 /* port is blocked by port_getn() */
#define	PORTQ_POLLWK_PEND  0x40 /* pollwakeup is pending, blocks port close */

#define	VTOEP(v)  ((struct port *)(v->v_data))
#define	EPTOV(ep) ((struct vnode *)(ep)->port_vnode)


typedef	struct	port {
	vnode_t		*port_vnode;
	kmutex_t	port_mutex;
	kcondvar_t	port_cv;	/* resource control */
	uint_t		port_flags;
	pid_t		port_pid;
	int		port_fd;
	uint_t		port_max_events; /* max. number of event per port */
	uint_t		port_max_list;	/* max. number of list structs	*/
	uint_t		port_curr;	/* current number of event structs */
	pollhead_t	port_pollhd;
	timespec_t	port_ctime;
	uid_t		port_uid;
	gid_t		port_gid;
	port_queue_t	port_queue;	/* global queue */
} port_t;

/* defines for port_flags */
#define	PORT_INIT	0x01		/* port initialized */
#define	PORT_CLOSED	0x02		/* owner closed the port */
#define	PORT_EVENTS	0x04		/* waiting for event resources */

/*
 * global control structure of port framework
 */
typedef	struct	port_control {
	kmutex_t	pc_mutex;
	uint_t		pc_nents;	/* ports currently allocated */
	struct	kmem_cache *pc_cache;	/* port event structures */
} port_control_t;


/*
 * Every thread waiting on an object will use this structure to store
 * all dependencies (flags, counters, events) before it awakes with
 * some events/transactions completed
 */
typedef	struct	portget {
	int		portget_state;
	uint_t		portget_nget;	/* number of expected events */
	pid_t		portget_pid;
	kcondvar_t	portget_cv;
	port_alert_t	portget_alert;
	struct	portget	*portget_next;
	struct	portget	*portget_prev;
} portget_t;

/* defines for portget_state */
#define	PORTGET_ALERT		0x01	/* wake up and return alert event */

extern	port_control_t	port_control;
extern	uint_t	port_max_list;

/*
 * port_getn() needs this structure to manage inter-process event delivery.
 */
typedef struct	port_gettimer {
	ushort_t	pgt_flags;
	ushort_t	pgt_loop;
	int		pgt_timecheck;
	timespec_t	pgt_rqtime;
	timespec_t	*pgt_rqtp;
	struct timespec	*pgt_timeout;
} port_gettimer_t;

/* pgt_flags */
#define	PORTGET_ONE		0x01	/* return only 1 object */
#define	PORTGET_WAIT_EVENTS	0x02	/* thread is waiting for new events */

/*
 * portfd_t is required to synchronize the association of fds with a port
 * and the per-process list of open files.
 * There is a pointer to a portfd structure in uf_entry_t.
 * If a fd is closed then closeandsetf() is able to detect the association of
 * the fd with a port or with a list of ports. closeandsetf() will dissociate
 * the fd from the port(s).
 */
typedef struct portfd {
	struct polldat	pfd_pd;
	struct portfd	*pfd_next;
	struct portfd	*pfd_prev;
} portfd_t;

#define	PFTOD(pfd)	(&(pfd)->pfd_pd)
#define	PDTOF(pdp)	((struct portfd *)(pdp))
#define	PORT_FD_BUCKET(pcp, fd) \
	(&(pcp)->pc_hash[((fd) % (pcp)->pc_hashsize)])

/*
 * port_kstat_t contains the event port kernel values which are
 * exported to kstat.
 * Currently only the number of active ports is exported.
 */
typedef struct port_kstat {
	kstat_named_t	pks_ports;
} port_kstat_t;

/* misc functions */
int	port_alloc_event_block(port_t *, int, int, struct port_kevent **);
void	port_push_eventq(port_queue_t *);
void	port_remove_done_event(struct port_kevent *);
struct	port_kevent *port_get_kevent(list_t *, struct port_kevent *);
void	port_block(port_queue_t *);
void	port_unblock(port_queue_t *);

/* PORT_SOURCE_FD cache management */
void port_pcache_remove_fd(port_fdcache_t *, portfd_t *);
void port_remove_fd_object(portfd_t *, struct port *, port_fdcache_t *);

/* file close management */
extern void addfd_port(int, portfd_t *);
extern void delfd_port(int, portfd_t *);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PORT_IMPL_H */
