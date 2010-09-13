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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_PORT_KERNEL_H
#define	_SYS_PORT_KERNEL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/vnode.h>
#include <sys/list.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Note:
 * The contents of this file are private to the implementation of the
 * Solaris system and event ports subsystem and are subject to change
 * at any time without notice.
 */

#ifdef _KERNEL

/*
 * The port_kevent_t struct represents the kernel internal port event.
 * Every event is associated to a port (portkev_port).
 */
typedef	struct	port_kevent {
	kmutex_t	portkev_lock;	/* used by PORT_SOURCE_FD source */
	int	portkev_source;		/* event: source */
	int	portkev_events; 	/* event: data */
	int	portkev_flags;		/* internal flags */
	pid_t	portkev_pid;		/* pid of process using this struct */
	long	portkev_object;		/* event: object */
	void	*portkev_user;		/* event: user-defined value */
	int	(*portkev_callback)(void *, int *, pid_t, int, void *);
	void	*portkev_arg;		/* event source callback arg */
	struct	port *portkev_port;	/* associated port */
	list_node_t portkev_node;	/* pointer to neighbor events */
} port_kevent_t;

/* portkev_flags */
#define	PORT_KEV_PRIVATE	0x01	/* subsystem private, don't free */
#define	PORT_KEV_CACHED		0x02	/* port local cached, don't free */
#define	PORT_KEV_SCACHED	0x04	/* source local cached, don't free */
#define	PORT_KEV_VALID		0x08	/* event associated and enabled */
#define	PORT_KEV_DONEQ		0x10	/* event is in done queue */
#define	PORT_KEV_FREE		0x20	/* free event and don't copyout it */
#define	PORT_KEV_NOSHARE	0x40	/* non-shareable across processes */

/* flags : port_alloc_event() */
#define	PORT_ALLOC_DEFAULT	0
#define	PORT_ALLOC_PRIVATE	PORT_KEV_PRIVATE
#define	PORT_ALLOC_CACHED	PORT_KEV_CACHED
#define	PORT_ALLOC_SCACHED	PORT_KEV_SCACHED

/* flags : callback function */
#define	PORT_CALLBACK_DEFAULT	0	/* free resources, event delivery */
#define	PORT_CALLBACK_CLOSE	1	/* free resources, don't copyout */
#define	PORT_CALLBACK_DISSOCIATE 2	/* dissociate object */

#define	PORT_DEFAULT_PORTS	0x02000
#define	PORT_MAX_PORTS		0x10000
#define	PORT_DEFAULT_EVENTS	0x10000	/* default # of events per port */
#define	PORT_MAX_EVENTS		UINT_MAX/2 /* max. # of events per port */

/*
 * port_source_t represents a source associated with a port.
 * The portsrc_close() function is required to notify the source when
 * a port is closed.
 */
typedef struct port_source {
	int	portsrc_source;
	int	portsrc_cnt;		/* # of associations */
	void	(*portsrc_close)(void *, int, pid_t, int);
	void	*portsrc_closearg;	/* callback arg */
	void	*portsrc_data;		/* Private data of source */
	struct port_source *portsrc_next;
	struct port_source *portsrc_prev;
} port_source_t;


/*
 * PORT_SOURCE_FILE cache structure.
 */
#define	PORTFOP_HASHSIZE	256	/* cache space for fop events */

/*
 * One cache for each port that uses PORT_SOURCE_FILE.
 */
typedef struct portfop_cache {
	kmutex_t	pfc_lock;	/* lock to protect cache */
	kcondvar_t	pfc_lclosecv;	/* last close cv */
	int		pfc_objcount;	/* track how many file obj are hashed */
	struct portfop	*pfc_hash[PORTFOP_HASHSIZE]; /* hash table */
} portfop_cache_t;

/*
 * PORT_SOURCE_FD cache per port.
 * One cache for each port that uses PORT_SOURCE_FD.
 * pc_lock must be the first element of port_fdcache_t to keep it
 * synchronized with the offset of pc_lock in pollcache_t (see pollrelock()).
 */
typedef struct port_fdcache {
	kmutex_t	pc_lock;	/* lock to protect portcache */
	kcondvar_t	pc_lclosecv;
	struct portfd	**pc_hash;	/* points to a hash table of ptrs */
	int		pc_hashsize;	/* the size of current hash table */
	int		pc_fdcount;	/* track how many fd's are hashed */
} port_fdcache_t;

/*
 * Structure of port_ksource_tab[] table.
 * The port_ksource_tab[] is required to allow kernel sources to become
 * associated with a port at the time of port creation. This feature is
 * required to avoid performance degradation in sub-systems, specially when
 * they should need to check the association on every event activity.
 */
typedef	struct	port_ksource {
	int	pks_source;
	void	(*pks_close)(void *, int, pid_t, int);
	void	*pks_closearg;
	void	*pks_portsrc;
} port_ksource_t;

/* event port and source management */
int	port_associate_ksource(int, int, struct port_source **,
    void (*)(void *, int, pid_t, int), void *arg,
    int (*)(port_kevent_t *, int, int, uintptr_t, void *));
int	port_dissociate_ksource(int, int, struct port_source *);

/* event management */
int	port_alloc_event(int, int, int, port_kevent_t **);
int	port_pollwkup(struct port *);
void	port_pollwkdone(struct port *);
void	port_send_event(port_kevent_t *);
void	port_free_event(port_kevent_t *);
void	port_init_event(port_kevent_t *, uintptr_t, void *,
    int (*)(void *, int *, pid_t, int, void *), void *);
int	port_dup_event(port_kevent_t *, port_kevent_t **, int);
int	port_associate_fd(struct port *, int, uintptr_t, int, void *);
int	port_dissociate_fd(struct port *, uintptr_t);
int	port_associate_fop(struct port *, int, uintptr_t, int, void *);
int	port_dissociate_fop(struct port *, uintptr_t);

/* misc functions */
void	port_free_event_local(port_kevent_t *, int counter);
int	port_alloc_event_local(struct port *, int, int, port_kevent_t **);
void	port_close_pfd(struct portfd *);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PORT_KERNEL_H */
