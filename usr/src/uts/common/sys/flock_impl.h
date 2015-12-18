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
 * Copyright 2015 Joyent, Inc.
 */

#ifndef _SYS_FLOCK_IMPL_H
#define	_SYS_FLOCK_IMPL_H

#include <sys/types.h>
#include <sys/fcntl.h>		/* flock definition */
#include <sys/file.h>		/* FREAD etc */
#include <sys/flock.h>		/* RCMD etc */
#include <sys/kmem.h>
#include <sys/user.h>
#include <sys/thread.h>
#include <sys/proc.h>
#include <sys/cred.h>
#include <sys/debug.h>
#include <sys/cmn_err.h>
#include <sys/errno.h>
#include <sys/systm.h>
#include <sys/vnode.h>
#include <sys/share.h>		/* just to get GETSYSID def */

#ifdef	__cplusplus
extern "C" {
#endif

struct	edge {
	struct	edge	*edge_adj_next;	/* adjacency list next */
	struct	edge	*edge_adj_prev; /* adjacency list prev */
	struct	edge	*edge_in_next;	/* incoming edges list next */
	struct	edge	*edge_in_prev;	/* incoming edges list prev */
	struct 	lock_descriptor	*from_vertex;	/* edge emanating from lock */
	struct 	lock_descriptor	*to_vertex;	/* edge pointing to lock */
};

typedef	struct	edge	edge_t;

struct lock_descriptor {
	struct	lock_descriptor	*l_next;	/* next active/sleep lock */
	struct	lock_descriptor	*l_prev;	/* previous active/sleep lock */
	struct	edge		l_edge;		/* edge for adj and in lists */
	struct	lock_descriptor	*l_stack;	/* for stack operations */
	struct	lock_descriptor	*l_stack1;	/* for stack operations */
	struct 	lock_descriptor *l_dstack;	/* stack for debug functions */
	struct	edge		*l_sedge;	/* start edge for graph alg. */
			int	l_index; 	/* used for barrier count */
		struct	graph	*l_graph;	/* graph this belongs to */
		vnode_t		*l_vnode;	/* vnode being locked */
			int	l_type;		/* type of lock */
			int	l_state;	/* state described below */
		u_offset_t	l_start;	/* start offset */
		u_offset_t	l_end;		/* end offset */
		flock64_t	l_flock;	/* original flock request */
			int	l_color;	/* color used for graph alg */
		kcondvar_t	l_cv;		/* wait condition for lock */
		int		pvertex;	/* index to proc vertex */
			int	l_status;	/* status described below */
		flk_nlm_status_t l_nlm_state;	/* state of NLM server */
		flk_callback_t	*l_callbacks;	/* callbacks, or NULL */
		zoneid_t	l_zoneid;	/* zone of request */
		file_t		*l_ofd;		/* OFD-style reference */
};

typedef struct 	lock_descriptor	lock_descriptor_t;

/*
 * Each graph holds locking information for some number of vnodes.  The
 * active and sleeping lists are circular, with a dummy head element.
 */

struct	graph {
	kmutex_t	gp_mutex;	/* mutex for this graph */
	struct	lock_descriptor	active_locks;
	struct	lock_descriptor	sleeping_locks;
	int index;	/* index of this graph into the hash table */
	int mark;	/* used for coloring the graph */
};

typedef	struct	graph	graph_t;

/*
 * The possible states a lock can be in.  These states are stored in the
 * 'l_status' member of the 'lock_descriptor_t' structure.  All locks start
 * life in the INITIAL state, and end up in the DEAD state.  Possible state
 * transitions are :
 *
 * INITIAL--> START    --> ACTIVE    --> DEAD
 *
 *                     --> DEAD
 *
 *        --> ACTIVE   --> DEAD          (new locks from flk_relation)
 *
 *        --> SLEEPING --> GRANTED   --> START     --> ACTIVE --> DEAD
 *
 *                                   --> INTR      --> DEAD
 *
 *                                   --> CANCELLED --> DEAD
 *
 *                                                 --> INTR   --> DEAD
 *
 *                     --> INTR      --> DEAD
 *
 *                     --> CANCELLED --> DEAD
 *
 *                                   --> INTR      --> DEAD
 *
 * Lock transitions are done in the following functions:
 * --> INITIAL		flk_get_lock(), reclock()
 * --> START		flk_execute_request()
 * --> ACTIVE		flk_insert_active_lock()
 * --> SLEEPING		flk_insert_sleeping_lock()
 * --> GRANTED		GRANT_WAKEUP
 * --> INTERRUPTED	INTERRUPT_WAKEUP
 * --> CANCELLED	CANCEL_WAKEUP
 * --> DEAD		reclock(), flk_delete_active_lock(), and
 *                          flk_cancel_sleeping_lock()
 */

#define	FLK_INITIAL_STATE	1	/* Initial state of all requests */
#define	FLK_START_STATE		2	/* Request has started execution */
#define	FLK_ACTIVE_STATE	3	/* In active queue */
#define	FLK_SLEEPING_STATE	4	/* Request is blocked */
#define	FLK_GRANTED_STATE	5	/* Request is granted */
#define	FLK_INTERRUPTED_STATE	6	/* Request is interrupted */
#define	FLK_CANCELLED_STATE	7	/* Request is cancelled */
#define	FLK_DEAD_STATE		8	/* Request is done - will be deleted */

/* flags defining state of locks */

/*
 * The LLM design has been modified so that lock states are now stored
 * in the l_status field of lock_descriptor_t.  The l_state field is
 * currently preserved for binary compatibility, but may be modified or
 * removed in a minor release of Solaris.  Note that both of these
 * fields (and the rest of the lock_descriptor_t structure) are private
 * to the implementation of the lock manager and should not be used
 * externally.
 */

#define	ACTIVE_LOCK		0x0001	/* in active queue */
#define	SLEEPING_LOCK		0x0002	/* in sleep queue */
#define	IO_LOCK			0x0004	/* is an IO lock */
#define	REFERENCED_LOCK		0x0008	/* referenced some where */
#define	QUERY_LOCK		0x0010	/* querying about lock */
#define	WILLING_TO_SLEEP_LOCK	0x0020	/* lock can be put in sleep queue */
#define	RECOMPUTE_LOCK		0x0040	/* used for recomputing dependencies */
#define	RECOMPUTE_DONE		0x0080	/* used for recomputing dependencies */
#define	BARRIER_LOCK		0x0100	/* used for recomputing dependencies */
#define	GRANTED_LOCK		0x0200	/* granted but still in sleep queue */
#define	CANCELLED_LOCK		0x0400	/* cancelled will be thrown out */
#define	DELETED_LOCK		0x0800	/* deleted - free at earliest */
#define	INTERRUPTED_LOCK	0x1000	/* pretend signal */
#define	LOCKMGR_LOCK		0x2000	/* remote lock (server-side) */
/* Clustering: flag for PXFS locks */
#define	PXFS_LOCK		0x4000	/* lock created by PXFS file system */
#define	NBMAND_LOCK		0x8000	/* non-blocking mandatory locking */

#define	HASH_SIZE	32
#define	HASH_SHIFT	(HASH_SIZE - 1)
#define	HASH_INDEX(vp)	(((uintptr_t)vp >> 7) & HASH_SHIFT)

/* extern definitions */

extern struct graph	*lock_graph[HASH_SIZE];
extern struct kmem_cache *flk_edge_cache;

/* Clustering: functions called by PXFS */
int flk_execute_request(lock_descriptor_t *);
void flk_cancel_sleeping_lock(lock_descriptor_t *, int);
void flk_set_state(lock_descriptor_t *, int);
graph_t *flk_get_lock_graph(vnode_t *, int);

/* flags used for readability in flock.c */

#define	FLK_USE_GRAPH	0	/* don't initialize the lock_graph */
#define	FLK_INIT_GRAPH	1	/* initialize the lock graph */
#define	NO_COLOR	0	/* vertex is not colored */
#define	NO_CHECK_CYCLE	0	/* don't mark vertex's in flk_add_edge */
#define	CHECK_CYCLE	1	/* mark vertex's in flk_add_edge */

#define	SAME_OWNER(lock1, lock2)	\
	(((lock1)->l_flock.l_pid == (lock2)->l_flock.l_pid) && \
		((lock1)->l_flock.l_sysid == (lock2)->l_flock.l_sysid) && \
		((lock1)->l_ofd == (lock2)->l_ofd))

#define	COLORED(vertex)		((vertex)->l_color == (vertex)->l_graph->mark)
#define	COLOR(vertex)		((vertex)->l_color = (vertex)->l_graph->mark)

/*
 * stack data structure and operations
 */

#define	STACK_INIT(stack)	((stack) = NULL)
#define	STACK_PUSH(stack, ptr, stack_link)	(ptr)->stack_link = (stack),\
				(stack) = (ptr)
#define	STACK_POP(stack, stack_link)	(stack) = (stack)->stack_link
#define	STACK_TOP(stack)	(stack)
#define	STACK_EMPTY(stack)	((stack) == NULL)


#define	ACTIVE_HEAD(gp)	(&(gp)->active_locks)

#define	SLEEPING_HEAD(gp)	(&(gp)->sleeping_locks)

#define	SET_LOCK_TO_FIRST_ACTIVE_VP(gp, lock, vp) \
{ \
	(lock) = (lock_descriptor_t *)vp->v_filocks;	\
}

#define	SET_LOCK_TO_FIRST_SLEEP_VP(gp, lock, vp) \
{ \
for ((lock) = SLEEPING_HEAD((gp))->l_next; ((lock) != SLEEPING_HEAD((gp)) && \
			(lock)->l_vnode != (vp)); (lock) = (lock)->l_next) \
			; \
(lock) = ((lock) == SLEEPING_HEAD((gp))) ? NULL : (lock); \
}

#define	OVERLAP(lock1, lock2) \
	(((lock1)->l_start <= (lock2)->l_start && \
		(lock2)->l_start <= (lock1)->l_end) || \
	((lock2)->l_start <= (lock1)->l_start && \
		(lock1)->l_start <= (lock2)->l_end))

#define	IS_INITIAL(lock)	((lock)->l_status == FLK_INITIAL_STATE)
#define	IS_ACTIVE(lock)		((lock)->l_status == FLK_ACTIVE_STATE)
#define	IS_SLEEPING(lock)	((lock)->l_status == FLK_SLEEPING_STATE)
#define	IS_GRANTED(lock)	((lock)->l_status == FLK_GRANTED_STATE)
#define	IS_INTERRUPTED(lock)	((lock)->l_status == FLK_INTERRUPTED_STATE)
#define	IS_CANCELLED(lock)	((lock)->l_status == FLK_CANCELLED_STATE)
#define	IS_DEAD(lock)		((lock)->l_status == FLK_DEAD_STATE)

#define	IS_QUERY_LOCK(lock)	((lock)->l_state & QUERY_LOCK)
#define	IS_RECOMPUTE(lock)	((lock)->l_state & RECOMPUTE_LOCK)
#define	IS_BARRIER(lock)	((lock)->l_state & BARRIER_LOCK)
#define	IS_DELETED(lock)	((lock)->l_state & DELETED_LOCK)
#define	IS_REFERENCED(lock)	((lock)->l_state & REFERENCED_LOCK)
#define	IS_IO_LOCK(lock)	((lock)->l_state & IO_LOCK)
#define	IS_WILLING_TO_SLEEP(lock)	\
		((lock)->l_state & WILLING_TO_SLEEP_LOCK)
#define	IS_LOCKMGR(lock)	((lock)->l_state & LOCKMGR_LOCK)
#define	IS_NLM_UP(lock)		((lock)->l_nlm_state == FLK_NLM_UP)
/* Clustering: Macro for PXFS locks */
#define	IS_PXFS(lock)		((lock)->l_state & PXFS_LOCK)

/*
 * "local" requests don't involve the NFS lock manager in any way.
 * "remote" requests can be on the server (requests from a remote client),
 * in which case they should be associated with a local vnode (UFS, tmpfs,
 * etc.).  These requests are flagged with LOCKMGR_LOCK and are made using
 * kernel service threads.  Remote requests can also be on an NFS client,
 * because the NFS lock manager uses local locking for some of its
 * bookkeeping.  These requests are made by regular user processes.
 */
#define	IS_LOCAL(lock)	(GETSYSID((lock)->l_flock.l_sysid) == 0)
#define	IS_REMOTE(lock)	(! IS_LOCAL(lock))

/* Clustering: Return value for blocking PXFS locks */
/*
 * For PXFS locks, reclock() will return this error code for requests that
 * need to block
 */
#define	PXFS_LOCK_BLOCKED -1

/* Clustering: PXFS callback function */
/*
 * This function is a callback from the LLM into the PXFS server module.  It
 * is initialized as a weak stub, and is functional when the pxfs server module
 * is loaded.
 */
extern void cl_flk_state_transition_notify(lock_descriptor_t *lock,
    int old_state, int new_state);

#define	BLOCKS(lock1, lock2)	(!SAME_OWNER((lock1), (lock2)) && \
					(((lock1)->l_type == F_WRLCK) || \
					((lock2)->l_type == F_WRLCK)) && \
					OVERLAP((lock1), (lock2)))

#define	COVERS(lock1, lock2)	\
		(((lock1)->l_start <= (lock2)->l_start) && \
			((lock1)->l_end >= (lock2)->l_end))

#define	IN_LIST_REMOVE(ep)	\
	{ \
	(ep)->edge_in_next->edge_in_prev = (ep)->edge_in_prev; \
	(ep)->edge_in_prev->edge_in_next = (ep)->edge_in_next; \
	}

#define	ADJ_LIST_REMOVE(ep)	\
	{ \
	(ep)->edge_adj_next->edge_adj_prev = (ep)->edge_adj_prev; \
	(ep)->edge_adj_prev->edge_adj_next = (ep)->edge_adj_next; \
	}

#define	NOT_BLOCKED(lock)	\
	((lock)->l_edge.edge_adj_next == &(lock)->l_edge && !IS_GRANTED(lock))

#define	GRANT_WAKEUP(lock)	\
	{	\
		flk_set_state(lock, FLK_GRANTED_STATE); \
		(lock)->l_state |= GRANTED_LOCK; \
		/* \
		 * Clustering: PXFS locks do not sleep in the LLM, \
		 * so there is no need to signal them \
		 */ \
		if (!IS_PXFS(lock)) { \
			cv_signal(&(lock)->l_cv); \
		} \
	}

#define	CANCEL_WAKEUP(lock)	\
	{ \
		flk_set_state(lock, FLK_CANCELLED_STATE); \
		(lock)->l_state |= CANCELLED_LOCK; \
		/* \
		 * Clustering: PXFS locks do not sleep in the LLM, \
		 * so there is no need to signal them \
		 */ \
		if (!IS_PXFS(lock)) { \
			cv_signal(&(lock)->l_cv); \
		} \
	}

#define	INTERRUPT_WAKEUP(lock)	\
	{ \
		flk_set_state(lock, FLK_INTERRUPTED_STATE); \
		(lock)->l_state |= INTERRUPTED_LOCK; \
		/* \
		 * Clustering: PXFS locks do not sleep in the LLM, \
		 * so there is no need to signal them \
		 */ \
		if (!IS_PXFS(lock)) { \
			cv_signal(&(lock)->l_cv); \
		} \
	}

#define	REMOVE_SLEEP_QUEUE(lock)	\
	{ \
	ASSERT(IS_SLEEPING(lock) || IS_GRANTED(lock) || \
	    IS_INTERRUPTED(lock) || IS_CANCELLED(lock)); \
	(lock)->l_state &= ~SLEEPING_LOCK; \
	(lock)->l_next->l_prev = (lock)->l_prev; \
	(lock)->l_prev->l_next = (lock)->l_next; \
	(lock)->l_next = (lock)->l_prev = (lock_descriptor_t *)NULL; \
	}

#define	NO_DEPENDENTS(lock)	\
	((lock)->l_edge.edge_in_next == &(lock)->l_edge)

#define	GRANT(lock)	\
	{ \
	(lock)->l_state |= GRANTED_LOCK; \
	flk_set_state(lock, FLK_GRANTED_STATE); \
	}

#define	FIRST_IN(lock)	((lock)->l_edge.edge_in_next)
#define	FIRST_ADJ(lock)	((lock)->l_edge.edge_adj_next)
#define	HEAD(lock)	(&(lock)->l_edge)
#define	NEXT_ADJ(ep)	((ep)->edge_adj_next)
#define	NEXT_IN(ep)	((ep)->edge_in_next)
#define	IN_ADJ_INIT(lock)	\
{	\
(lock)->l_edge.edge_adj_next = (lock)->l_edge.edge_adj_prev = &(lock)->l_edge; \
(lock)->l_edge.edge_in_next = (lock)->l_edge.edge_in_prev = &(lock)->l_edge; \
}

#define	COPY(lock1, lock2)	\
{	\
(lock1)->l_graph = (lock2)->l_graph; \
(lock1)->l_vnode = (lock2)->l_vnode; \
(lock1)->l_type = (lock2)->l_type; \
(lock1)->l_state = (lock2)->l_state; \
(lock1)->l_start = (lock2)->l_start; \
(lock1)->l_end = (lock2)->l_end; \
(lock1)->l_flock = (lock2)->l_flock; \
(lock1)->l_zoneid = (lock2)->l_zoneid; \
(lock1)->pvertex = (lock2)->pvertex; \
}

/*
 * Clustering
 */
/* Routines to set and get the NLM state in a lock request */
#define	SET_NLM_STATE(lock, nlm_state)	((lock)->l_nlm_state = nlm_state)
#define	GET_NLM_STATE(lock)	((lock)->l_nlm_state)
/*
 * NLM registry abstraction:
 *   Abstraction overview:
 *   This registry keeps track of the NLM servers via their nlmids
 *   that have requested locks at the LLM this registry is associated
 *   with.
 */
/* Routines to manipulate the NLM registry object state */
#define	FLK_REGISTRY_IS_NLM_UNKNOWN(nlmreg, nlmid) \
	    ((nlmreg)[nlmid] == FLK_NLM_UNKNOWN)
#define	FLK_REGISTRY_IS_NLM_UP(nlmreg, nlmid) \
	    ((nlmreg)[nlmid] == FLK_NLM_UP)
#define	FLK_REGISTRY_ADD_NLMID(nlmreg, nlmid) \
	    ((nlmreg)[nlmid] = FLK_NLM_UP)
#define	FLK_REGISTRY_CHANGE_NLM_STATE(nlmreg, nlmid, state) \
	    ((nlmreg)[nlmid] = state)

/* Indicates the effect of executing a request on the existing locks */

#define	FLK_UNLOCK	0x1	/* request unlocks the existing lock */
#define	FLK_DOWNGRADE	0x2	/* request downgrades the existing lock */
#define	FLK_UPGRADE	0x3	/* request upgrades the existing lock */
#define	FLK_STAY_SAME	0x4	/* request type is same as existing lock */


/*	proc graph definitions	*/

/*
 * Proc graph is the global process graph that maintains information
 * about the dependencies between processes. An edge is added between two
 * processes represented by proc_vertex's A and B, iff there exists l1
 * owned by process A in any of the lock_graph's dependent on l2
 * (thus having an edge to l2) owned by process B.
 */
struct proc_vertex {
	pid_t	pid;	/* pid of the process */
	long	sysid;	/* sysid of the process */
	struct proc_edge	*edge;	/* adajcent edges of this process */
	int incount;		/* Number of inedges to this process */
	struct proc_edge *p_sedge;	/* used for implementing stack alg. */
	struct proc_vertex	*p_stack;	/* used for stack alg. */
	int atime;	/* used for cycle detection algorithm */
	int dtime;	/* used for cycle detection algorithm */
	int index;	/* index into the  array of proc_graph vertices */
};

typedef	struct proc_vertex proc_vertex_t;

struct proc_edge {
	struct proc_edge	*next;	/* next edge in adjacency list */
	int  refcount;			/* reference count of this edge */
	struct proc_vertex	*to_proc;	/* process this points to */
};

typedef struct proc_edge proc_edge_t;


#define	PROC_CHUNK	100

struct proc_graph {
	struct proc_vertex **proc;	/* list of proc_vertexes */
	int gcount;		/* list size */
	int free;		/* number of free slots in the list */
	int mark;		/* used for graph coloring */
};

typedef struct proc_graph proc_graph_t;

extern	struct proc_graph	pgraph;

#define	PROC_SAME_OWNER(lock, pvertex)	\
	(((lock)->l_flock.l_pid == (pvertex)->pid) && \
		((lock)->l_flock.l_sysid == (pvertex)->sysid))

#define	PROC_ARRIVE(pvertex)	((pvertex)->atime = pgraph.mark)
#define	PROC_DEPART(pvertex)	((pvertex)->dtime = pgraph.mark)
#define	PROC_ARRIVED(pvertex)	((pvertex)->atime == pgraph.mark)
#define	PROC_DEPARTED(pvertex)  ((pvertex)->dtime == pgraph.mark)

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FLOCK_IMPL_H */
