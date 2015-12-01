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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/*	All Rights Reserved */

/*
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2015 Joyent, Inc.
 */

#include <sys/flock_impl.h>
#include <sys/vfs.h>
#include <sys/t_lock.h>		/* for <sys/callb.h> */
#include <sys/callb.h>
#include <sys/clconf.h>
#include <sys/cladm.h>
#include <sys/nbmlock.h>
#include <sys/cred.h>
#include <sys/policy.h>

/*
 * The following four variables are for statistics purposes and they are
 * not protected by locks. They may not be accurate but will at least be
 * close to the actual value.
 */

int	flk_lock_allocs;
int	flk_lock_frees;
int 	edge_allocs;
int	edge_frees;
int 	flk_proc_vertex_allocs;
int 	flk_proc_edge_allocs;
int	flk_proc_vertex_frees;
int	flk_proc_edge_frees;

static kmutex_t flock_lock;

#ifdef DEBUG
int check_debug = 0;
#define	CHECK_ACTIVE_LOCKS(gp)	if (check_debug) \
					check_active_locks(gp);
#define	CHECK_SLEEPING_LOCKS(gp)	if (check_debug) \
						check_sleeping_locks(gp);
#define	CHECK_OWNER_LOCKS(gp, pid, sysid, vp) 	\
		if (check_debug)	\
			check_owner_locks(gp, pid, sysid, vp);
#define	CHECK_LOCK_TRANSITION(old_state, new_state) \
	{ \
		if (check_lock_transition(old_state, new_state)) { \
			cmn_err(CE_PANIC, "Illegal lock transition \
			    from %d to %d", old_state, new_state); \
		} \
	}
#else

#define	CHECK_ACTIVE_LOCKS(gp)
#define	CHECK_SLEEPING_LOCKS(gp)
#define	CHECK_OWNER_LOCKS(gp, pid, sysid, vp)
#define	CHECK_LOCK_TRANSITION(old_state, new_state)

#endif /* DEBUG */

struct kmem_cache	*flk_edge_cache;

graph_t		*lock_graph[HASH_SIZE];
proc_graph_t	pgraph;

/*
 * Clustering.
 *
 * NLM REGISTRY TYPE IMPLEMENTATION
 *
 * Assumptions:
 *  1.  Nodes in a cluster are numbered starting at 1; always non-negative
 *	integers; maximum node id is returned by clconf_maximum_nodeid().
 *  2.  We use this node id to identify the node an NLM server runs on.
 */

/*
 * NLM registry object keeps track of NLM servers via their
 * nlmids (which are the node ids of the node in the cluster they run on)
 * that have requested locks at this LLM with which this registry is
 * associated.
 *
 * Representation of abstraction:
 *    rep = record[	states: array[nlm_state],
 *			lock: mutex]
 *
 *    Representation invariants:
 *	1. index i of rep.states is between 0 and n - 1 where n is number
 *	   of elements in the array, which happen to be the maximum number
 *	   of nodes in the cluster configuration + 1.
 *	2. map nlmid to index i of rep.states
 *		0   -> 0
 *		1   -> 1
 *		2   -> 2
 *		n-1 -> clconf_maximum_nodeid()+1
 *	3.  This 1-1 mapping is quite convenient and it avoids errors resulting
 *	    from forgetting to subtract 1 from the index.
 *	4.  The reason we keep the 0th index is the following.  A legitimate
 *	    cluster configuration includes making a UFS file system NFS
 *	    exportable.  The code is structured so that if you're in a cluster
 *	    you do one thing; otherwise, you do something else.  The problem
 *	    is what to do if you think you're in a cluster with PXFS loaded,
 *	    but you're using UFS not PXFS?  The upper two bytes of the sysid
 *	    encode the node id of the node where NLM server runs; these bytes
 *	    are zero for UFS.  Since the nodeid is used to index into the
 *	    registry, we can record the NLM server state information at index
 *	    0 using the same mechanism used for PXFS file locks!
 */
static flk_nlm_status_t *nlm_reg_status = NULL;	/* state array 0..N-1 */
static kmutex_t nlm_reg_lock;			/* lock to protect arrary */
static uint_t nlm_status_size;			/* size of state array */

/*
 * Although we need a global lock dependency graph (and associated data
 * structures), we also need a per-zone notion of whether the lock manager is
 * running, and so whether to allow lock manager requests or not.
 *
 * Thus, on a per-zone basis we maintain a ``global'' variable
 * (flk_lockmgr_status), protected by flock_lock, and set when the lock
 * manager is determined to be changing state (starting or stopping).
 *
 * Each graph/zone pair also has a copy of this variable, which is protected by
 * the graph's mutex.
 *
 * The per-graph copies are used to synchronize lock requests with shutdown
 * requests.  The global copy is used to initialize the per-graph field when a
 * new graph is created.
 */
struct flock_globals {
	flk_lockmgr_status_t flk_lockmgr_status;
	flk_lockmgr_status_t lockmgr_status[HASH_SIZE];
};

zone_key_t flock_zone_key;

static void create_flock(lock_descriptor_t *, flock64_t *);
static lock_descriptor_t	*flk_get_lock(void);
static void	flk_free_lock(lock_descriptor_t	*lock);
static void	flk_get_first_blocking_lock(lock_descriptor_t *request);
static int flk_process_request(lock_descriptor_t *);
static int flk_add_edge(lock_descriptor_t *, lock_descriptor_t *, int, int);
static edge_t *flk_get_edge(void);
static int flk_wait_execute_request(lock_descriptor_t *);
static int flk_relation(lock_descriptor_t *, lock_descriptor_t *);
static void flk_insert_active_lock(lock_descriptor_t *);
static void flk_delete_active_lock(lock_descriptor_t *, int);
static void flk_insert_sleeping_lock(lock_descriptor_t *);
static void flk_graph_uncolor(graph_t *);
static void flk_wakeup(lock_descriptor_t *, int);
static void flk_free_edge(edge_t *);
static void flk_recompute_dependencies(lock_descriptor_t *,
			lock_descriptor_t **,  int, int);
static int flk_find_barriers(lock_descriptor_t *);
static void flk_update_barriers(lock_descriptor_t *);
static int flk_color_reachables(lock_descriptor_t *);
static int flk_canceled(lock_descriptor_t *);
static void flk_delete_locks_by_sysid(lock_descriptor_t *);
static void report_blocker(lock_descriptor_t *, lock_descriptor_t *);
static void wait_for_lock(lock_descriptor_t *);
static void unlock_lockmgr_granted(struct flock_globals *);
static void wakeup_sleeping_lockmgr_locks(struct flock_globals *);

/* Clustering hooks */
static void cl_flk_change_nlm_state_all_locks(int, flk_nlm_status_t);
static void cl_flk_wakeup_sleeping_nlm_locks(int);
static void cl_flk_unlock_nlm_granted(int);

#ifdef DEBUG
static int check_lock_transition(int, int);
static void check_sleeping_locks(graph_t *);
static void check_active_locks(graph_t *);
static int no_path(lock_descriptor_t *, lock_descriptor_t *);
static void path(lock_descriptor_t *, lock_descriptor_t *);
static void check_owner_locks(graph_t *, pid_t, int, vnode_t *);
static int level_one_path(lock_descriptor_t *, lock_descriptor_t *);
static int level_two_path(lock_descriptor_t *, lock_descriptor_t *, int);
#endif

/*	proc_graph function definitions */
static int flk_check_deadlock(lock_descriptor_t *);
static void flk_proc_graph_uncolor(void);
static proc_vertex_t *flk_get_proc_vertex(lock_descriptor_t *);
static proc_edge_t *flk_get_proc_edge(void);
static void flk_proc_release(proc_vertex_t *);
static void flk_free_proc_edge(proc_edge_t *);
static void flk_update_proc_graph(edge_t *, int);

/* Non-blocking mandatory locking */
static int lock_blocks_io(nbl_op_t, u_offset_t, ssize_t, int, u_offset_t,
			u_offset_t);

static struct flock_globals *
flk_get_globals(void)
{
	/*
	 * The KLM module had better be loaded if we're attempting to handle
	 * lockmgr requests.
	 */
	ASSERT(flock_zone_key != ZONE_KEY_UNINITIALIZED);
	return (zone_getspecific(flock_zone_key, curproc->p_zone));
}

static flk_lockmgr_status_t
flk_get_lockmgr_status(void)
{
	struct flock_globals *fg;

	ASSERT(MUTEX_HELD(&flock_lock));

	if (flock_zone_key == ZONE_KEY_UNINITIALIZED) {
		/*
		 * KLM module not loaded; lock manager definitely not running.
		 */
		return (FLK_LOCKMGR_DOWN);
	}
	fg = flk_get_globals();
	return (fg->flk_lockmgr_status);
}

/*
 * This implements Open File Description (not descriptor) style record locking.
 * These locks can also be thought of as pid-less since they are not tied to a
 * specific process, thus they're preserved across fork.
 *
 * Called directly from fcntl.
 *
 * See reclock() for the implementation of the traditional POSIX style record
 * locking scheme (pid-ful). This function is derived from reclock() but
 * simplified and modified to work for OFD style locking.
 *
 * The two primary advantages of OFD style of locking are:
 * 1) It is per-file description, so closing a file descriptor that refers to a
 *    different file description for the same file will not drop the lock (i.e.
 *    two open's of the same file get different descriptions but a dup or fork
 *    will refer to the same description).
 * 2) Locks are preserved across fork(2).
 *
 * Because these locks are per-description a lock ptr lives at the f_filocks
 * member of the file_t and the lock_descriptor includes a file_t pointer
 * to enable unique lock identification and management.
 *
 * Since these locks are pid-less we cannot do deadlock detection with the
 * current process-oriented implementation. This is consistent with OFD locking
 * behavior on other operating systems such as Linux. Since we don't do
 * deadlock detection we never interact with the process graph that is
 * maintained for deadlock detection on the traditional POSIX-style locks.
 *
 * Future Work:
 *
 * The current implementation does not support record locks. That is,
 * currently the single lock must cover the entire file. This is validated in
 * fcntl. To support record locks the f_filock pointer in the file_t needs to
 * be changed to a list of pointers to the locks. That list needs to be
 * managed independently of the lock list on the vnode itself and it needs to
 * be maintained as record locks are created, split, coalesced and deleted.
 *
 * The current implementation does not support remote file systems (e.g.
 * NFS or CIFS). This is handled in fs_frlock(). The design of how OFD locks
 * interact with the NLM is not clear since the NLM protocol/implementation
 * appears to be oriented around locks associated with a process. A further
 * problem is that a design is needed for what nlm_send_siglost() should do and
 * where it will send SIGLOST. More recent versions of Linux apparently try to
 * emulate OFD locks on NFS by converting them to traditional POSIX style locks
 * that work with the NLM. It is not clear that this provides the correct
 * semantics in all cases.
 */
int
ofdlock(file_t *fp, int fcmd, flock64_t *lckdat, int flag, u_offset_t offset)
{
	int cmd = 0;
	vnode_t *vp;
	lock_descriptor_t	stack_lock_request;
	lock_descriptor_t	*lock_request;
	int error = 0;
	graph_t	*gp;
	int serialize = 0;

	if (fcmd != F_OFD_GETLK)
		cmd = SETFLCK;

	if (fcmd == F_OFD_SETLKW || fcmd == F_FLOCKW)
		cmd |= SLPFLCK;

	/* see block comment */
	VERIFY(lckdat->l_whence == 0);
	VERIFY(lckdat->l_start == 0);
	VERIFY(lckdat->l_len == 0);

	vp = fp->f_vnode;

	/*
	 * For reclock fs_frlock() would normally have set these in a few
	 * places but for us it's cleaner to centralize it here. Note that
	 * IGN_PID is -1. We use 0 for our pid-less locks.
	 */
	lckdat->l_pid = 0;
	lckdat->l_sysid = 0;

	/*
	 * Check access permissions
	 */
	if ((fcmd == F_OFD_SETLK || fcmd == F_OFD_SETLKW) &&
	    ((lckdat->l_type == F_RDLCK && (flag & FREAD) == 0) ||
	    (lckdat->l_type == F_WRLCK && (flag & FWRITE) == 0)))
		return (EBADF);

	/*
	 * for query and unlock we use the stack_lock_request
	 */
	if (lckdat->l_type == F_UNLCK || !(cmd & SETFLCK)) {
		lock_request = &stack_lock_request;
		(void) bzero((caddr_t)lock_request,
		    sizeof (lock_descriptor_t));

		/*
		 * following is added to make the assertions in
		 * flk_execute_request() pass
		 */
		lock_request->l_edge.edge_in_next = &lock_request->l_edge;
		lock_request->l_edge.edge_in_prev = &lock_request->l_edge;
		lock_request->l_edge.edge_adj_next = &lock_request->l_edge;
		lock_request->l_edge.edge_adj_prev = &lock_request->l_edge;
		lock_request->l_status = FLK_INITIAL_STATE;
	} else {
		lock_request = flk_get_lock();
		fp->f_filock = (struct filock *)lock_request;
	}
	lock_request->l_state = 0;
	lock_request->l_vnode = vp;
	lock_request->l_zoneid = getzoneid();
	lock_request->l_ofd = fp;

	/*
	 * Convert the request range into the canonical start and end
	 * values then check the validity of the lock range.
	 */
	error = flk_convert_lock_data(vp, lckdat, &lock_request->l_start,
	    &lock_request->l_end, offset);
	if (error)
		goto done;

	error = flk_check_lock_data(lock_request->l_start, lock_request->l_end,
	    MAXEND);
	if (error)
		goto done;

	ASSERT(lock_request->l_end >= lock_request->l_start);

	lock_request->l_type = lckdat->l_type;
	if (cmd & SLPFLCK)
		lock_request->l_state |= WILLING_TO_SLEEP_LOCK;

	if (!(cmd & SETFLCK)) {
		if (lock_request->l_type == F_RDLCK ||
		    lock_request->l_type == F_WRLCK)
			lock_request->l_state |= QUERY_LOCK;
	}
	lock_request->l_flock = (*lckdat);

	/*
	 * We are ready for processing the request
	 */

	if (fcmd != F_OFD_GETLK && lock_request->l_type != F_UNLCK &&
	    nbl_need_check(vp)) {
		nbl_start_crit(vp, RW_WRITER);
		serialize = 1;
	}

	/* Get the lock graph for a particular vnode */
	gp = flk_get_lock_graph(vp, FLK_INIT_GRAPH);

	mutex_enter(&gp->gp_mutex);

	lock_request->l_state |= REFERENCED_LOCK;
	lock_request->l_graph = gp;

	switch (lock_request->l_type) {
	case F_RDLCK:
	case F_WRLCK:
		if (IS_QUERY_LOCK(lock_request)) {
			flk_get_first_blocking_lock(lock_request);
			if (lock_request->l_ofd != NULL)
				lock_request->l_flock.l_pid = -1;
			(*lckdat) = lock_request->l_flock;
		} else {
			/* process the request now */
			error = flk_process_request(lock_request);
		}
		break;

	case F_UNLCK:
		/* unlock request will not block so execute it immediately */
		error = flk_execute_request(lock_request);
		break;

	default:
		error = EINVAL;
		break;
	}

	if (lock_request == &stack_lock_request) {
		flk_set_state(lock_request, FLK_DEAD_STATE);
	} else {
		lock_request->l_state &= ~REFERENCED_LOCK;
		if ((error != 0) || IS_DELETED(lock_request)) {
			flk_set_state(lock_request, FLK_DEAD_STATE);
			flk_free_lock(lock_request);
		}
	}

	mutex_exit(&gp->gp_mutex);
	if (serialize)
		nbl_end_crit(vp);

	return (error);

done:
	flk_set_state(lock_request, FLK_DEAD_STATE);
	if (lock_request != &stack_lock_request)
		flk_free_lock(lock_request);
	return (error);
}

/*
 * Remove any lock on the vnode belonging to the given file_t.
 * Called from closef on last close, file_t is locked.
 *
 * This is modeled on the cleanlocks() function but only removes the single
 * lock associated with fp.
 */
void
ofdcleanlock(file_t *fp)
{
	lock_descriptor_t *fplock, *lock, *nlock;
	vnode_t *vp;
	graph_t	*gp;

	ASSERT(MUTEX_HELD(&fp->f_tlock));

	if ((fplock = (lock_descriptor_t *)fp->f_filock) == NULL)
		return;

	fp->f_filock = NULL;
	vp = fp->f_vnode;

	gp = flk_get_lock_graph(vp, FLK_USE_GRAPH);

	if (gp == NULL)
		return;
	mutex_enter(&gp->gp_mutex);

	CHECK_SLEEPING_LOCKS(gp);
	CHECK_ACTIVE_LOCKS(gp);

	SET_LOCK_TO_FIRST_SLEEP_VP(gp, lock, vp);

	if (lock) {
		do {
			nlock = lock->l_next;
			if (fplock == lock) {
				CANCEL_WAKEUP(lock);
				break;
			}
			lock = nlock;
		} while (lock->l_vnode == vp);
	}

	SET_LOCK_TO_FIRST_ACTIVE_VP(gp, lock, vp);

	if (lock) {
		do {
			nlock = lock->l_next;
			if (fplock == lock) {
				flk_delete_active_lock(lock, 0);
				flk_wakeup(lock, 1);
				flk_free_lock(lock);
				break;
			}
			lock = nlock;
		} while (lock->l_vnode == vp);
	}

	CHECK_SLEEPING_LOCKS(gp);
	CHECK_ACTIVE_LOCKS(gp);
	mutex_exit(&gp->gp_mutex);
}

/*
 * Routine called from fs_frlock in fs/fs_subr.c
 *
 * This implements traditional POSIX style record locking. The two primary
 * drawbacks to this style of locking are:
 * 1) It is per-process, so any close of a file descriptor that refers to the
 *    file will drop the lock (e.g. lock /etc/passwd, call a library function
 *    which opens /etc/passwd to read the file, when the library closes it's
 *    file descriptor the application loses its lock and does not know).
 * 2) Locks are not preserved across fork(2).
 *
 * Because these locks are only assoiciated with a pid they are per-process.
 * This is why any close will drop the lock and is also why once the process
 * forks then the lock is no longer related to the new process. These locks can
 * be considered as pid-ful.
 *
 * See ofdlock() for the implementation of a similar but improved locking
 * scheme.
 */
int
reclock(vnode_t		*vp,
	flock64_t	*lckdat,
	int		cmd,
	int		flag,
	u_offset_t	offset,
	flk_callback_t	*flk_cbp)
{
	lock_descriptor_t	stack_lock_request;
	lock_descriptor_t	*lock_request;
	int error = 0;
	graph_t	*gp;
	int			nlmid;

	/*
	 * Check access permissions
	 */
	if ((cmd & SETFLCK) &&
	    ((lckdat->l_type == F_RDLCK && (flag & FREAD) == 0) ||
	    (lckdat->l_type == F_WRLCK && (flag & FWRITE) == 0)))
			return (EBADF);

	/*
	 * for query and unlock we use the stack_lock_request
	 */

	if ((lckdat->l_type == F_UNLCK) ||
	    !((cmd & INOFLCK) || (cmd & SETFLCK))) {
		lock_request = &stack_lock_request;
		(void) bzero((caddr_t)lock_request,
		    sizeof (lock_descriptor_t));

		/*
		 * following is added to make the assertions in
		 * flk_execute_request() to pass through
		 */

		lock_request->l_edge.edge_in_next = &lock_request->l_edge;
		lock_request->l_edge.edge_in_prev = &lock_request->l_edge;
		lock_request->l_edge.edge_adj_next = &lock_request->l_edge;
		lock_request->l_edge.edge_adj_prev = &lock_request->l_edge;
		lock_request->l_status = FLK_INITIAL_STATE;
	} else {
		lock_request = flk_get_lock();
	}
	lock_request->l_state = 0;
	lock_request->l_vnode = vp;
	lock_request->l_zoneid = getzoneid();

	/*
	 * Convert the request range into the canonical start and end
	 * values.  The NLM protocol supports locking over the entire
	 * 32-bit range, so there's no range checking for remote requests,
	 * but we still need to verify that local requests obey the rules.
	 */
	/* Clustering */
	if ((cmd & (RCMDLCK | PCMDLCK)) != 0) {
		ASSERT(lckdat->l_whence == 0);
		lock_request->l_start = lckdat->l_start;
		lock_request->l_end = (lckdat->l_len == 0) ? MAX_U_OFFSET_T :
		    lckdat->l_start + (lckdat->l_len - 1);
	} else {
		/* check the validity of the lock range */
		error = flk_convert_lock_data(vp, lckdat,
		    &lock_request->l_start, &lock_request->l_end,
		    offset);
		if (error) {
			goto done;
		}
		error = flk_check_lock_data(lock_request->l_start,
		    lock_request->l_end, MAXEND);
		if (error) {
			goto done;
		}
	}

	ASSERT(lock_request->l_end >= lock_request->l_start);

	lock_request->l_type = lckdat->l_type;
	if (cmd & INOFLCK)
		lock_request->l_state |= IO_LOCK;
	if (cmd & SLPFLCK)
		lock_request->l_state |= WILLING_TO_SLEEP_LOCK;
	if (cmd & RCMDLCK)
		lock_request->l_state |= LOCKMGR_LOCK;
	if (cmd & NBMLCK)
		lock_request->l_state |= NBMAND_LOCK;
	/*
	 * Clustering: set flag for PXFS locks
	 * We do not _only_ check for the PCMDLCK flag because PXFS locks could
	 * also be of type 'RCMDLCK'.
	 * We do not _only_ check the GETPXFSID() macro because local PXFS
	 * clients use a pxfsid of zero to permit deadlock detection in the LLM.
	 */

	if ((cmd & PCMDLCK) || (GETPXFSID(lckdat->l_sysid) != 0)) {
		lock_request->l_state |= PXFS_LOCK;
	}
	if (!((cmd & SETFLCK) || (cmd & INOFLCK))) {
		if (lock_request->l_type == F_RDLCK ||
		    lock_request->l_type == F_WRLCK)
			lock_request->l_state |= QUERY_LOCK;
	}
	lock_request->l_flock = (*lckdat);
	lock_request->l_callbacks = flk_cbp;

	/*
	 * We are ready for processing the request
	 */
	if (IS_LOCKMGR(lock_request)) {
		/*
		 * If the lock request is an NLM server request ....
		 */
		if (nlm_status_size == 0) { /* not booted as cluster */
			mutex_enter(&flock_lock);
			/*
			 * Bail out if this is a lock manager request and the
			 * lock manager is not supposed to be running.
			 */
			if (flk_get_lockmgr_status() != FLK_LOCKMGR_UP) {
				mutex_exit(&flock_lock);
				error = ENOLCK;
				goto done;
			}
			mutex_exit(&flock_lock);
		} else {			/* booted as a cluster */
			nlmid = GETNLMID(lock_request->l_flock.l_sysid);
			ASSERT(nlmid <= nlm_status_size && nlmid >= 0);

			mutex_enter(&nlm_reg_lock);
			/*
			 * If the NLM registry does not know about this
			 * NLM server making the request, add its nlmid
			 * to the registry.
			 */
			if (FLK_REGISTRY_IS_NLM_UNKNOWN(nlm_reg_status,
			    nlmid)) {
				FLK_REGISTRY_ADD_NLMID(nlm_reg_status, nlmid);
			} else if (!FLK_REGISTRY_IS_NLM_UP(nlm_reg_status,
			    nlmid)) {
				/*
				 * If the NLM server is already known (has made
				 * previous lock requests) and its state is
				 * not NLM_UP (means that NLM server is
				 * shutting down), then bail out with an
				 * error to deny the lock request.
				 */
				mutex_exit(&nlm_reg_lock);
				error = ENOLCK;
				goto done;
			}
			mutex_exit(&nlm_reg_lock);
		}
	}

	/* Now get the lock graph for a particular vnode */
	gp = flk_get_lock_graph(vp, FLK_INIT_GRAPH);

	/*
	 * We drop rwlock here otherwise this might end up causing a
	 * deadlock if this IOLOCK sleeps. (bugid # 1183392).
	 */

	if (IS_IO_LOCK(lock_request)) {
		VOP_RWUNLOCK(vp,
		    (lock_request->l_type == F_RDLCK) ?
		    V_WRITELOCK_FALSE : V_WRITELOCK_TRUE, NULL);
	}
	mutex_enter(&gp->gp_mutex);

	lock_request->l_state |= REFERENCED_LOCK;
	lock_request->l_graph = gp;

	switch (lock_request->l_type) {
	case F_RDLCK:
	case F_WRLCK:
		if (IS_QUERY_LOCK(lock_request)) {
			flk_get_first_blocking_lock(lock_request);
			if (lock_request->l_ofd != NULL)
				lock_request->l_flock.l_pid = -1;
			(*lckdat) = lock_request->l_flock;
			break;
		}

		/* process the request now */

		error = flk_process_request(lock_request);
		break;

	case F_UNLCK:
		/* unlock request will not block so execute it immediately */

		if (IS_LOCKMGR(lock_request) &&
		    flk_canceled(lock_request)) {
			error = 0;
		} else {
			error = flk_execute_request(lock_request);
		}
		break;

	case F_UNLKSYS:
		/*
		 * Recovery mechanism to release lock manager locks when
		 * NFS client crashes and restart. NFS server will clear
		 * old locks and grant new locks.
		 */

		if (lock_request->l_flock.l_sysid == 0) {
			mutex_exit(&gp->gp_mutex);
			return (EINVAL);
		}
		if (secpolicy_nfs(CRED()) != 0) {
			mutex_exit(&gp->gp_mutex);
			return (EPERM);
		}
		flk_delete_locks_by_sysid(lock_request);
		lock_request->l_state &= ~REFERENCED_LOCK;
		flk_set_state(lock_request, FLK_DEAD_STATE);
		flk_free_lock(lock_request);
		mutex_exit(&gp->gp_mutex);
		return (0);

	default:
		error = EINVAL;
		break;
	}

	/* Clustering: For blocked PXFS locks, return */
	if (error == PXFS_LOCK_BLOCKED) {
		lock_request->l_state &= ~REFERENCED_LOCK;
		mutex_exit(&gp->gp_mutex);
		return (error);
	}

	/*
	 * Now that we have seen the status of locks in the system for
	 * this vnode we acquire the rwlock if it is an IO_LOCK.
	 */

	if (IS_IO_LOCK(lock_request)) {
		(void) VOP_RWLOCK(vp,
		    (lock_request->l_type == F_RDLCK) ?
		    V_WRITELOCK_FALSE : V_WRITELOCK_TRUE, NULL);
		if (!error) {
			lckdat->l_type = F_UNLCK;

			/*
			 * This wake up is needed otherwise
			 * if IO_LOCK has slept the dependents on this
			 * will not be woken up at all. (bugid # 1185482).
			 */

			flk_wakeup(lock_request, 1);
			flk_set_state(lock_request, FLK_DEAD_STATE);
			flk_free_lock(lock_request);
		}
		/*
		 * else if error had occurred either flk_process_request()
		 * has returned EDEADLK in which case there will be no
		 * dependents for this lock or EINTR from flk_wait_execute_
		 * request() in which case flk_cancel_sleeping_lock()
		 * would have been done. same is true with EBADF.
		 */
	}

	if (lock_request == &stack_lock_request) {
		flk_set_state(lock_request, FLK_DEAD_STATE);
	} else {
		lock_request->l_state &= ~REFERENCED_LOCK;
		if ((error != 0) || IS_DELETED(lock_request)) {
			flk_set_state(lock_request, FLK_DEAD_STATE);
			flk_free_lock(lock_request);
		}
	}

	mutex_exit(&gp->gp_mutex);
	return (error);

done:
	flk_set_state(lock_request, FLK_DEAD_STATE);
	if (lock_request != &stack_lock_request)
		flk_free_lock(lock_request);
	return (error);
}

/*
 * Invoke the callbacks in the given list.  If before sleeping, invoke in
 * list order.  If after sleeping, invoke in reverse order.
 *
 * CPR (suspend/resume) support: if one of the callbacks returns a
 * callb_cpr_t, return it.   This will be used to make the thread CPR-safe
 * while it is sleeping.  There should be at most one callb_cpr_t for the
 * thread.
 * XXX This is unnecessarily complicated.  The CPR information should just
 * get passed in directly through VOP_FRLOCK and reclock, rather than
 * sneaking it in via a callback.
 */

callb_cpr_t *
flk_invoke_callbacks(flk_callback_t *cblist, flk_cb_when_t when)
{
	callb_cpr_t *cpr_callbackp = NULL;
	callb_cpr_t *one_result;
	flk_callback_t *cb;

	if (cblist == NULL)
		return (NULL);

	if (when == FLK_BEFORE_SLEEP) {
		cb = cblist;
		do {
			one_result = (*cb->cb_callback)(when, cb->cb_data);
			if (one_result != NULL) {
				ASSERT(cpr_callbackp == NULL);
				cpr_callbackp = one_result;
			}
			cb = cb->cb_next;
		} while (cb != cblist);
	} else {
		cb = cblist->cb_prev;
		do {
			one_result = (*cb->cb_callback)(when, cb->cb_data);
			if (one_result != NULL) {
				cpr_callbackp = one_result;
			}
			cb = cb->cb_prev;
		} while (cb != cblist->cb_prev);
	}

	return (cpr_callbackp);
}

/*
 * Initialize a flk_callback_t to hold the given callback.
 */

void
flk_init_callback(flk_callback_t *flk_cb,
	callb_cpr_t *(*cb_fcn)(flk_cb_when_t, void *), void *cbdata)
{
	flk_cb->cb_next = flk_cb;
	flk_cb->cb_prev = flk_cb;
	flk_cb->cb_callback = cb_fcn;
	flk_cb->cb_data = cbdata;
}

/*
 * Initialize an flk_callback_t and then link it into the head of an
 * existing list (which may be NULL).
 */

void
flk_add_callback(flk_callback_t *newcb,
		callb_cpr_t *(*cb_fcn)(flk_cb_when_t, void *),
		void *cbdata, flk_callback_t *cblist)
{
	flk_init_callback(newcb, cb_fcn, cbdata);

	if (cblist == NULL)
		return;

	newcb->cb_prev = cblist->cb_prev;
	newcb->cb_next = cblist;
	cblist->cb_prev->cb_next = newcb;
	cblist->cb_prev = newcb;
}

/*
 * Initialize the flk_edge_cache data structure and create the
 * nlm_reg_status array.
 */

void
flk_init(void)
{
	uint_t	i;

	flk_edge_cache = kmem_cache_create("flk_edges",
	    sizeof (struct edge), 0, NULL, NULL, NULL, NULL, NULL, 0);
	if (flk_edge_cache == NULL) {
		cmn_err(CE_PANIC, "Couldn't create flk_edge_cache\n");
	}
	/*
	 * Create the NLM registry object.
	 */

	if (cluster_bootflags & CLUSTER_BOOTED) {
		/*
		 * This routine tells you the maximum node id that will be used
		 * in the cluster.  This number will be the size of the nlm
		 * registry status array.  We add 1 because we will be using
		 * all entries indexed from 0 to maxnodeid; e.g., from 0
		 * to 64, for a total of 65 entries.
		 */
		nlm_status_size = clconf_maximum_nodeid() + 1;
	} else {
		nlm_status_size = 0;
	}

	if (nlm_status_size != 0) {	/* booted as a cluster */
		nlm_reg_status = (flk_nlm_status_t *)
		    kmem_alloc(sizeof (flk_nlm_status_t) * nlm_status_size,
		    KM_SLEEP);

		/* initialize all NLM states in array to NLM_UNKNOWN */
		for (i = 0; i < nlm_status_size; i++) {
			nlm_reg_status[i] = FLK_NLM_UNKNOWN;
		}
	}
}

/*
 * Zone constructor/destructor callbacks to be executed when a zone is
 * created/destroyed.
 */
/* ARGSUSED */
void *
flk_zone_init(zoneid_t zoneid)
{
	struct flock_globals *fg;
	uint_t i;

	fg = kmem_alloc(sizeof (*fg), KM_SLEEP);
	fg->flk_lockmgr_status = FLK_LOCKMGR_UP;
	for (i = 0; i < HASH_SIZE; i++)
		fg->lockmgr_status[i] = FLK_LOCKMGR_UP;
	return (fg);
}

/* ARGSUSED */
void
flk_zone_fini(zoneid_t zoneid, void *data)
{
	struct flock_globals *fg = data;

	kmem_free(fg, sizeof (*fg));
}

/*
 * Get a lock_descriptor structure with initialization of edge lists.
 */

static lock_descriptor_t *
flk_get_lock(void)
{
	lock_descriptor_t	*l;

	l = kmem_zalloc(sizeof (lock_descriptor_t), KM_SLEEP);

	cv_init(&l->l_cv, NULL, CV_DRIVER, NULL);
	l->l_edge.edge_in_next = &l->l_edge;
	l->l_edge.edge_in_prev = &l->l_edge;
	l->l_edge.edge_adj_next = &l->l_edge;
	l->l_edge.edge_adj_prev = &l->l_edge;
	l->pvertex = -1;
	l->l_status = FLK_INITIAL_STATE;
	flk_lock_allocs++;
	return (l);
}

/*
 * Free a lock_descriptor structure. Just sets the DELETED_LOCK flag
 * when some thread has a reference to it as in reclock().
 */

void
flk_free_lock(lock_descriptor_t	*lock)
{
	file_t *fp;

	ASSERT(IS_DEAD(lock));

	if ((fp = lock->l_ofd) != NULL)
		fp->f_filock = NULL;

	if (IS_REFERENCED(lock)) {
		lock->l_state |= DELETED_LOCK;
		return;
	}
	flk_lock_frees++;
	kmem_free((void *)lock, sizeof (lock_descriptor_t));
}

void
flk_set_state(lock_descriptor_t *lock, int new_state)
{
	/*
	 * Locks in the sleeping list may be woken up in a number of ways,
	 * and more than once.  If a sleeping lock is signaled awake more
	 * than once, then it may or may not change state depending on its
	 * current state.
	 * Also note that NLM locks that are sleeping could be moved to an
	 * interrupted state more than once if the unlock request is
	 * retransmitted by the NLM client - the second time around, this is
	 * just a nop.
	 * The ordering of being signaled awake is:
	 * INTERRUPTED_STATE > CANCELLED_STATE > GRANTED_STATE.
	 * The checks below implement this ordering.
	 */
	if (IS_INTERRUPTED(lock)) {
		if ((new_state == FLK_CANCELLED_STATE) ||
		    (new_state == FLK_GRANTED_STATE) ||
		    (new_state == FLK_INTERRUPTED_STATE)) {
			return;
		}
	}
	if (IS_CANCELLED(lock)) {
		if ((new_state == FLK_GRANTED_STATE) ||
		    (new_state == FLK_CANCELLED_STATE)) {
			return;
		}
	}
	CHECK_LOCK_TRANSITION(lock->l_status, new_state);
	if (IS_PXFS(lock)) {
		cl_flk_state_transition_notify(lock, lock->l_status, new_state);
	}
	lock->l_status = new_state;
}

/*
 * Routine that checks whether there are any blocking locks in the system.
 *
 * The policy followed is if a write lock is sleeping we don't allow read
 * locks before this write lock even though there may not be any active
 * locks corresponding to the read locks' region.
 *
 * flk_add_edge() function adds an edge between l1 and l2 iff there
 * is no path between l1 and l2. This is done to have a "minimum
 * storage representation" of the dependency graph.
 *
 * Another property of the graph is since only the new request throws
 * edges to the existing locks in the graph, the graph is always topologically
 * ordered.
 */

static int
flk_process_request(lock_descriptor_t *request)
{
	graph_t	*gp = request->l_graph;
	lock_descriptor_t *lock;
	int request_blocked_by_active = 0;
	int request_blocked_by_granted = 0;
	int request_blocked_by_sleeping = 0;
	vnode_t	*vp = request->l_vnode;
	int	error = 0;
	int request_will_wait = 0;
	int found_covering_lock = 0;
	lock_descriptor_t *covered_by = NULL;

	ASSERT(MUTEX_HELD(&gp->gp_mutex));
	request_will_wait = IS_WILLING_TO_SLEEP(request);

	/*
	 * check active locks
	 */

	SET_LOCK_TO_FIRST_ACTIVE_VP(gp, lock, vp);


	if (lock) {
		do {
			if (BLOCKS(lock, request)) {
				if (!request_will_wait)
					return (EAGAIN);
				request_blocked_by_active = 1;
				break;
			}
			/*
			 * Grant lock if it is for the same owner holding active
			 * lock that covers the request.
			 */

			if (SAME_OWNER(lock, request) &&
			    COVERS(lock, request) &&
			    (request->l_type == F_RDLCK))
				return (flk_execute_request(request));
			lock = lock->l_next;
		} while (lock->l_vnode == vp);
	}

	if (!request_blocked_by_active) {
			lock_descriptor_t *lk[1];
			lock_descriptor_t *first_glock = NULL;
		/*
		 * Shall we grant this?! NO!!
		 * What about those locks that were just granted and still
		 * in sleep queue. Those threads are woken up and so locks
		 * are almost active.
		 */
		SET_LOCK_TO_FIRST_SLEEP_VP(gp, lock, vp);
		if (lock) {
			do {
				if (BLOCKS(lock, request)) {
					if (IS_GRANTED(lock)) {
						request_blocked_by_granted = 1;
					} else {
						request_blocked_by_sleeping = 1;
					}
				}

				lock = lock->l_next;
			} while ((lock->l_vnode == vp));
			first_glock = lock->l_prev;
			ASSERT(first_glock->l_vnode == vp);
		}

		if (request_blocked_by_granted)
			goto block;

		if (!request_blocked_by_sleeping) {
			/*
			 * If the request isn't going to be blocked by a
			 * sleeping request, we know that it isn't going to
			 * be blocked; we can just execute the request --
			 * without performing costly deadlock detection.
			 */
			ASSERT(!request_blocked_by_active);
			return (flk_execute_request(request));
		} else if (request->l_type == F_RDLCK) {
			/*
			 * If we have a sleeping writer in the requested
			 * lock's range, block.
			 */
			goto block;
		}

		lk[0] = request;
		request->l_state |= RECOMPUTE_LOCK;
		SET_LOCK_TO_FIRST_ACTIVE_VP(gp, lock, vp);
		if (lock) {
			do {
				flk_recompute_dependencies(lock, lk, 1, 0);
				lock = lock->l_next;
			} while (lock->l_vnode == vp);
		}
		lock = first_glock;
		if (lock) {
			do {
				if (IS_GRANTED(lock)) {
				flk_recompute_dependencies(lock, lk, 1, 0);
				}
				lock = lock->l_prev;
			} while ((lock->l_vnode == vp));
		}
		request->l_state &= ~RECOMPUTE_LOCK;
		if (!NO_DEPENDENTS(request) && flk_check_deadlock(request))
			return (EDEADLK);
		return (flk_execute_request(request));
	}

block:
	if (request_will_wait)
		flk_graph_uncolor(gp);

	/* check sleeping locks */

	SET_LOCK_TO_FIRST_SLEEP_VP(gp, lock, vp);

	/*
	 * If we find a sleeping write lock that is a superset of the
	 * region wanted by request we can be assured that by adding an
	 * edge to this write lock we have paths to all locks in the
	 * graph that blocks the request except in one case and that is why
	 * another check for SAME_OWNER in the loop below. The exception
	 * case is when this process that owns the sleeping write lock 'l1'
	 * has other locks l2, l3, l4 that are in the system and arrived
	 * before l1. l1 does not have path to these locks as they are from
	 * same process. We break when we find a second covering sleeping
	 * lock l5 owned by a process different from that owning l1, because
	 * there cannot be any of l2, l3, l4, etc., arrived before l5, and if
	 * it has l1 would have produced a deadlock already.
	 */

	if (lock) {
		do {
			if (BLOCKS(lock, request)) {
				if (!request_will_wait)
					return (EAGAIN);
				if (COVERS(lock, request) &&
				    lock->l_type == F_WRLCK) {
					if (found_covering_lock &&
					    !SAME_OWNER(lock, covered_by)) {
						found_covering_lock++;
						break;
					}
					found_covering_lock = 1;
					covered_by = lock;
				}
				if (found_covering_lock &&
				    !SAME_OWNER(lock, covered_by)) {
					lock = lock->l_next;
					continue;
				}
				if ((error = flk_add_edge(request, lock,
				    !found_covering_lock, 0)))
					return (error);
			}
			lock = lock->l_next;
		} while (lock->l_vnode == vp);
	}

/*
 * found_covering_lock == 2 iff at this point 'request' has paths
 * to all locks that blocks 'request'. found_covering_lock == 1 iff at this
 * point 'request' has paths to all locks that blocks 'request' whose owners
 * are not same as the one that covers 'request' (covered_by above) and
 * we can have locks whose owner is same as covered_by in the active list.
 */

	if (request_blocked_by_active && found_covering_lock != 2) {
		SET_LOCK_TO_FIRST_ACTIVE_VP(gp, lock, vp);
		ASSERT(lock != NULL);
		do {
			if (BLOCKS(lock, request)) {
				if (found_covering_lock &&
				    !SAME_OWNER(lock, covered_by)) {
					lock = lock->l_next;
					continue;
				}
				if ((error = flk_add_edge(request, lock,
				    CHECK_CYCLE, 0)))
					return (error);
			}
			lock = lock->l_next;
		} while (lock->l_vnode == vp);
	}

	if (NOT_BLOCKED(request)) {
		/*
		 * request not dependent on any other locks
		 * so execute this request
		 */
		return (flk_execute_request(request));
	} else {
		/*
		 * check for deadlock
		 */
		if (flk_check_deadlock(request))
			return (EDEADLK);
		/*
		 * this thread has to sleep
		 */
		return (flk_wait_execute_request(request));
	}
}

/*
 * The actual execution of the request in the simple case is only to
 * insert the 'request' in the list of active locks if it is not an
 * UNLOCK.
 * We have to consider the existing active locks' relation to
 * this 'request' if they are owned by same process. flk_relation() does
 * this job and sees to that the dependency graph information is maintained
 * properly.
 */

int
flk_execute_request(lock_descriptor_t *request)
{
	graph_t	*gp = request->l_graph;
	vnode_t	*vp = request->l_vnode;
	lock_descriptor_t	*lock, *lock1;
	int done_searching = 0;

	CHECK_SLEEPING_LOCKS(gp);
	CHECK_ACTIVE_LOCKS(gp);

	ASSERT(MUTEX_HELD(&gp->gp_mutex));

	flk_set_state(request, FLK_START_STATE);

	ASSERT(NOT_BLOCKED(request));

	/* IO_LOCK requests are only to check status */

	if (IS_IO_LOCK(request))
		return (0);

	SET_LOCK_TO_FIRST_ACTIVE_VP(gp, lock, vp);

	if (lock == NULL && request->l_type == F_UNLCK)
		return (0);
	if (lock == NULL) {
		flk_insert_active_lock(request);
		return (0);
	}

	do {
		lock1 = lock->l_next;
		if (SAME_OWNER(request, lock)) {
			done_searching = flk_relation(lock, request);
		}
		lock = lock1;
	} while (lock->l_vnode == vp && !done_searching);

	/*
	 * insert in active queue
	 */

	if (request->l_type != F_UNLCK)
		flk_insert_active_lock(request);

	return (0);
}

/*
 * 'request' is blocked by some one therefore we put it into sleep queue.
 */
static int
flk_wait_execute_request(lock_descriptor_t *request)
{
	graph_t	*gp = request->l_graph;
	callb_cpr_t 	*cprp;		/* CPR info from callback */
	struct flock_globals *fg;
	int index;

	ASSERT(MUTEX_HELD(&gp->gp_mutex));
	ASSERT(IS_WILLING_TO_SLEEP(request));

	flk_insert_sleeping_lock(request);

	if (IS_LOCKMGR(request)) {
		index = HASH_INDEX(request->l_vnode);
		fg = flk_get_globals();

		if (nlm_status_size == 0) {	/* not booted as a cluster */
			if (fg->lockmgr_status[index] != FLK_LOCKMGR_UP) {
				flk_cancel_sleeping_lock(request, 1);
				return (ENOLCK);
			}
		} else {			/* booted as a cluster */
			/*
			 * If the request is an NLM server lock request,
			 * and the NLM state of the lock request is not
			 * NLM_UP (because the NLM server is shutting
			 * down), then cancel the sleeping lock and
			 * return error ENOLCK that will encourage the
			 * client to retransmit.
			 */
			if (!IS_NLM_UP(request)) {
				flk_cancel_sleeping_lock(request, 1);
				return (ENOLCK);
			}
		}
	}

	/* Clustering: For blocking PXFS locks, return */
	if (IS_PXFS(request)) {
		/*
		 * PXFS locks sleep on the client side.
		 * The callback argument is used to wake up the sleeper
		 * when the lock is granted.
		 * We return -1 (rather than an errno value) to indicate
		 * the client side should sleep
		 */
		return (PXFS_LOCK_BLOCKED);
	}

	if (request->l_callbacks != NULL) {
		/*
		 * To make sure the shutdown code works correctly, either
		 * the callback must happen after putting the lock on the
		 * sleep list, or we must check the shutdown status after
		 * returning from the callback (and before sleeping).  At
		 * least for now, we'll use the first option.  If a
		 * shutdown or signal or whatever happened while the graph
		 * mutex was dropped, that will be detected by
		 * wait_for_lock().
		 */
		mutex_exit(&gp->gp_mutex);

		cprp = flk_invoke_callbacks(request->l_callbacks,
		    FLK_BEFORE_SLEEP);

		mutex_enter(&gp->gp_mutex);

		if (cprp == NULL) {
			wait_for_lock(request);
		} else {
			mutex_enter(cprp->cc_lockp);
			CALLB_CPR_SAFE_BEGIN(cprp);
			mutex_exit(cprp->cc_lockp);
			wait_for_lock(request);
			mutex_enter(cprp->cc_lockp);
			CALLB_CPR_SAFE_END(cprp, cprp->cc_lockp);
			mutex_exit(cprp->cc_lockp);
		}

		mutex_exit(&gp->gp_mutex);
		(void) flk_invoke_callbacks(request->l_callbacks,
		    FLK_AFTER_SLEEP);
		mutex_enter(&gp->gp_mutex);
	} else {
		wait_for_lock(request);
	}

	if (IS_LOCKMGR(request)) {
		/*
		 * If the lock manager is shutting down, return an
		 * error that will encourage the client to retransmit.
		 */
		if (fg->lockmgr_status[index] != FLK_LOCKMGR_UP &&
		    !IS_GRANTED(request)) {
			flk_cancel_sleeping_lock(request, 1);
			return (ENOLCK);
		}
	}

	if (IS_INTERRUPTED(request)) {
		/* we got a signal, or act like we did */
		flk_cancel_sleeping_lock(request, 1);
		return (EINTR);
	}

	/* Cancelled if some other thread has closed the file */

	if (IS_CANCELLED(request)) {
		flk_cancel_sleeping_lock(request, 1);
		return (EBADF);
	}

	request->l_state &= ~GRANTED_LOCK;
	REMOVE_SLEEP_QUEUE(request);
	return (flk_execute_request(request));
}

/*
 * This routine adds an edge between from and to because from depends
 * to. If asked to check for deadlock it checks whether there are any
 * reachable locks from "from_lock" that is owned by the same process
 * as "from_lock".
 * NOTE: It is the caller's responsibility to make sure that the color
 * of the graph is consistent between the calls to flk_add_edge as done
 * in flk_process_request. This routine does not color and check for
 * deadlock explicitly.
 */

static int
flk_add_edge(lock_descriptor_t *from_lock, lock_descriptor_t *to_lock,
			int check_cycle, int update_graph)
{
	edge_t	*edge;
	edge_t	*ep;
	lock_descriptor_t	*vertex;
	lock_descriptor_t *vertex_stack;

	STACK_INIT(vertex_stack);

	/*
	 * if to vertex already has mark_color just return
	 * don't add an edge as it is reachable from from vertex
	 * before itself.
	 */

	if (COLORED(to_lock))
		return (0);

	edge = flk_get_edge();

	/*
	 * set the from and to vertex
	 */

	edge->from_vertex = from_lock;
	edge->to_vertex = to_lock;

	/*
	 * put in adjacency list of from vertex
	 */

	from_lock->l_edge.edge_adj_next->edge_adj_prev = edge;
	edge->edge_adj_next = from_lock->l_edge.edge_adj_next;
	edge->edge_adj_prev = &from_lock->l_edge;
	from_lock->l_edge.edge_adj_next = edge;

	/*
	 * put in list of to vertex
	 */

	to_lock->l_edge.edge_in_next->edge_in_prev = edge;
	edge->edge_in_next = to_lock->l_edge.edge_in_next;
	to_lock->l_edge.edge_in_next = edge;
	edge->edge_in_prev = &to_lock->l_edge;


	if (update_graph) {
		flk_update_proc_graph(edge, 0);
		return (0);
	}
	if (!check_cycle) {
		return (0);
	}

	STACK_PUSH(vertex_stack, from_lock, l_stack);

	while ((vertex = STACK_TOP(vertex_stack)) != NULL) {

		STACK_POP(vertex_stack, l_stack);

		for (ep = FIRST_ADJ(vertex);
		    ep != HEAD(vertex);
		    ep = NEXT_ADJ(ep)) {
			if (COLORED(ep->to_vertex))
				continue;
			COLOR(ep->to_vertex);
			if (SAME_OWNER(ep->to_vertex, from_lock))
				goto dead_lock;
			STACK_PUSH(vertex_stack, ep->to_vertex, l_stack);
		}
	}
	return (0);

dead_lock:

	/*
	 * remove all edges
	 */

	ep = FIRST_ADJ(from_lock);

	while (ep != HEAD(from_lock)) {
		IN_LIST_REMOVE(ep);
		from_lock->l_sedge = NEXT_ADJ(ep);
		ADJ_LIST_REMOVE(ep);
		flk_free_edge(ep);
		ep = from_lock->l_sedge;
	}
	return (EDEADLK);
}

/*
 * Get an edge structure for representing the dependency between two locks.
 */

static edge_t *
flk_get_edge()
{
	edge_t	*ep;

	ASSERT(flk_edge_cache != NULL);

	ep = kmem_cache_alloc(flk_edge_cache, KM_SLEEP);
	edge_allocs++;
	return (ep);
}

/*
 * Free the edge structure.
 */

static void
flk_free_edge(edge_t *ep)
{
	edge_frees++;
	kmem_cache_free(flk_edge_cache, (void *)ep);
}

/*
 * Check the relationship of request with lock and perform the
 * recomputation of dependencies, break lock if required, and return
 * 1 if request cannot have any more relationship with the next
 * active locks.
 * The 'lock' and 'request' are compared and in case of overlap we
 * delete the 'lock' and form new locks to represent the non-overlapped
 * portion of original 'lock'. This function has side effects such as
 * 'lock' will be freed, new locks will be added to the active list.
 */

static int
flk_relation(lock_descriptor_t *lock, lock_descriptor_t *request)
{
	int lock_effect;
	lock_descriptor_t *lock1, *lock2;
	lock_descriptor_t *topology[3];
	int nvertex = 0;
	int i;
	edge_t	*ep;
	graph_t	*gp = (lock->l_graph);


	CHECK_SLEEPING_LOCKS(gp);
	CHECK_ACTIVE_LOCKS(gp);

	ASSERT(MUTEX_HELD(&gp->gp_mutex));

	topology[0] = topology[1] = topology[2] = NULL;

	if (request->l_type == F_UNLCK)
		lock_effect = FLK_UNLOCK;
	else if (request->l_type == F_RDLCK &&
	    lock->l_type == F_WRLCK)
		lock_effect = FLK_DOWNGRADE;
	else if (request->l_type == F_WRLCK &&
	    lock->l_type == F_RDLCK)
		lock_effect = FLK_UPGRADE;
	else
		lock_effect = FLK_STAY_SAME;

	if (lock->l_end < request->l_start) {
		if (lock->l_end == request->l_start - 1 &&
		    lock_effect == FLK_STAY_SAME) {
			topology[0] = request;
			request->l_start = lock->l_start;
			nvertex = 1;
			goto recompute;
		} else {
			return (0);
		}
	}

	if (lock->l_start > request->l_end) {
		if (request->l_end == lock->l_start - 1 &&
		    lock_effect == FLK_STAY_SAME) {
			topology[0] = request;
			request->l_end = lock->l_end;
			nvertex = 1;
			goto recompute;
		} else {
			return (1);
		}
	}

	if (request->l_end < lock->l_end) {
		if (request->l_start > lock->l_start) {
			if (lock_effect == FLK_STAY_SAME) {
				request->l_start = lock->l_start;
				request->l_end = lock->l_end;
				topology[0] = request;
				nvertex = 1;
			} else {
				lock1 = flk_get_lock();
				lock2 = flk_get_lock();
				COPY(lock1, lock);
				COPY(lock2, lock);
				lock1->l_start = lock->l_start;
				lock1->l_end = request->l_start - 1;
				lock2->l_start = request->l_end + 1;
				lock2->l_end = lock->l_end;
				topology[0] = lock1;
				topology[1] = lock2;
				topology[2] = request;
				nvertex = 3;
			}
		} else if (request->l_start < lock->l_start) {
			if (lock_effect == FLK_STAY_SAME) {
				request->l_end = lock->l_end;
				topology[0] = request;
				nvertex = 1;
			} else {
				lock1 = flk_get_lock();
				COPY(lock1, lock);
				lock1->l_start = request->l_end + 1;
				topology[0] = lock1;
				topology[1] = request;
				nvertex = 2;
			}
		} else  {
			if (lock_effect == FLK_STAY_SAME) {
				request->l_start = lock->l_start;
				request->l_end = lock->l_end;
				topology[0] = request;
				nvertex = 1;
			} else {
				lock1 = flk_get_lock();
				COPY(lock1, lock);
				lock1->l_start = request->l_end + 1;
				topology[0] = lock1;
				topology[1] = request;
				nvertex = 2;
			}
		}
	} else if (request->l_end > lock->l_end) {
		if (request->l_start > lock->l_start)  {
			if (lock_effect == FLK_STAY_SAME) {
				request->l_start = lock->l_start;
				topology[0] = request;
				nvertex = 1;
			} else {
				lock1 = flk_get_lock();
				COPY(lock1, lock);
				lock1->l_end = request->l_start - 1;
				topology[0] = lock1;
				topology[1] = request;
				nvertex = 2;
			}
		} else if (request->l_start < lock->l_start)  {
			topology[0] = request;
			nvertex = 1;
		} else {
			topology[0] = request;
			nvertex = 1;
		}
	} else {
		if (request->l_start > lock->l_start) {
			if (lock_effect == FLK_STAY_SAME) {
				request->l_start = lock->l_start;
				topology[0] = request;
				nvertex = 1;
			} else {
				lock1 = flk_get_lock();
				COPY(lock1, lock);
				lock1->l_end = request->l_start - 1;
				topology[0] = lock1;
				topology[1] = request;
				nvertex = 2;
			}
		} else if (request->l_start < lock->l_start) {
			topology[0] = request;
			nvertex = 1;
		} else {
			if (lock_effect !=  FLK_UNLOCK) {
				topology[0] = request;
				nvertex = 1;
			} else {
				flk_delete_active_lock(lock, 0);
				flk_wakeup(lock, 1);
				flk_free_lock(lock);
				CHECK_SLEEPING_LOCKS(gp);
				CHECK_ACTIVE_LOCKS(gp);
				return (1);
			}
		}
	}

recompute:

	/*
	 * For unlock we don't send the 'request' to for recomputing
	 * dependencies because no lock will add an edge to this.
	 */

	if (lock_effect == FLK_UNLOCK) {
		topology[nvertex-1] = NULL;
		nvertex--;
	}
	for (i = 0; i < nvertex; i++) {
		topology[i]->l_state |= RECOMPUTE_LOCK;
		topology[i]->l_color = NO_COLOR;
	}

	ASSERT(FIRST_ADJ(lock) == HEAD(lock));

	/*
	 * we remove the adjacent edges for all vertices' to this vertex
	 * 'lock'.
	 */

	ep = FIRST_IN(lock);
	while (ep != HEAD(lock)) {
		ADJ_LIST_REMOVE(ep);
		ep = NEXT_IN(ep);
	}

	flk_delete_active_lock(lock, 0);

	/* We are ready for recomputing the dependencies now */

	flk_recompute_dependencies(lock, topology, nvertex, 1);

	for (i = 0; i < nvertex; i++) {
		topology[i]->l_state &= ~RECOMPUTE_LOCK;
		topology[i]->l_color = NO_COLOR;
	}


	if (lock_effect == FLK_UNLOCK) {
		nvertex++;
	}
	for (i = 0; i < nvertex - 1; i++) {
		flk_insert_active_lock(topology[i]);
	}


	if (lock_effect == FLK_DOWNGRADE || lock_effect == FLK_UNLOCK) {
		flk_wakeup(lock, 0);
	} else {
		ep = FIRST_IN(lock);
		while (ep != HEAD(lock)) {
			lock->l_sedge = NEXT_IN(ep);
			IN_LIST_REMOVE(ep);
			flk_update_proc_graph(ep, 1);
			flk_free_edge(ep);
			ep = lock->l_sedge;
		}
	}
	flk_free_lock(lock);

	CHECK_SLEEPING_LOCKS(gp);
	CHECK_ACTIVE_LOCKS(gp);
	return (0);
}

/*
 * Insert a lock into the active queue.
 */

static void
flk_insert_active_lock(lock_descriptor_t *new_lock)
{
	graph_t	*gp = new_lock->l_graph;
	vnode_t	*vp = new_lock->l_vnode;
	lock_descriptor_t *first_lock, *lock;

	ASSERT(MUTEX_HELD(&gp->gp_mutex));

	SET_LOCK_TO_FIRST_ACTIVE_VP(gp, lock, vp);
	first_lock = lock;

	if (first_lock != NULL) {
		for (; (lock->l_vnode == vp &&
		    lock->l_start < new_lock->l_start); lock = lock->l_next)
			;
	} else {
		lock = ACTIVE_HEAD(gp);
	}

	lock->l_prev->l_next = new_lock;
	new_lock->l_next = lock;
	new_lock->l_prev = lock->l_prev;
	lock->l_prev = new_lock;

	if (first_lock == NULL || (new_lock->l_start <= first_lock->l_start)) {
		vp->v_filocks = (struct filock *)new_lock;
	}
	flk_set_state(new_lock, FLK_ACTIVE_STATE);
	new_lock->l_state |= ACTIVE_LOCK;

	CHECK_ACTIVE_LOCKS(gp);
	CHECK_SLEEPING_LOCKS(gp);
}

/*
 * Delete the active lock : Performs two functions depending on the
 * value of second parameter. One is to remove from the active lists
 * only and other is to both remove and free the lock.
 */

static void
flk_delete_active_lock(lock_descriptor_t *lock, int free_lock)
{
	vnode_t *vp = lock->l_vnode;
	graph_t	*gp = lock->l_graph;

	ASSERT(MUTEX_HELD(&gp->gp_mutex));
	if (free_lock)
		ASSERT(NO_DEPENDENTS(lock));
	ASSERT(NOT_BLOCKED(lock));
	ASSERT(IS_ACTIVE(lock));

	ASSERT((vp->v_filocks != NULL));

	if (vp->v_filocks == (struct filock *)lock) {
		vp->v_filocks = (struct filock *)
		    ((lock->l_next->l_vnode == vp) ? lock->l_next :
		    NULL);
	}
	lock->l_next->l_prev = lock->l_prev;
	lock->l_prev->l_next = lock->l_next;
	lock->l_next = lock->l_prev = NULL;
	flk_set_state(lock, FLK_DEAD_STATE);
	lock->l_state &= ~ACTIVE_LOCK;

	if (free_lock)
		flk_free_lock(lock);
	CHECK_ACTIVE_LOCKS(gp);
	CHECK_SLEEPING_LOCKS(gp);
}

/*
 * Insert into the sleep queue.
 */

static void
flk_insert_sleeping_lock(lock_descriptor_t *request)
{
	graph_t *gp = request->l_graph;
	vnode_t	*vp = request->l_vnode;
	lock_descriptor_t	*lock;

	ASSERT(MUTEX_HELD(&gp->gp_mutex));
	ASSERT(IS_INITIAL(request));

	for (lock = gp->sleeping_locks.l_next; (lock != &gp->sleeping_locks &&
	    lock->l_vnode < vp); lock = lock->l_next)
		;

	lock->l_prev->l_next = request;
	request->l_prev = lock->l_prev;
	lock->l_prev = request;
	request->l_next = lock;
	flk_set_state(request, FLK_SLEEPING_STATE);
	request->l_state |= SLEEPING_LOCK;
}

/*
 * Cancelling a sleeping lock implies removing a vertex from the
 * dependency graph and therefore we should recompute the dependencies
 * of all vertices that have a path  to this vertex, w.r.t. all
 * vertices reachable from this vertex.
 */

void
flk_cancel_sleeping_lock(lock_descriptor_t *request, int remove_from_queue)
{
	graph_t	*gp = request->l_graph;
	vnode_t *vp = request->l_vnode;
	lock_descriptor_t **topology = NULL;
	edge_t	*ep;
	lock_descriptor_t *vertex, *lock;
	int nvertex = 0;
	int i;
	lock_descriptor_t *vertex_stack;

	STACK_INIT(vertex_stack);

	ASSERT(MUTEX_HELD(&gp->gp_mutex));
	/*
	 * count number of vertex pointers that has to be allocated
	 * All vertices that are reachable from request.
	 */

	STACK_PUSH(vertex_stack, request, l_stack);

	while ((vertex = STACK_TOP(vertex_stack)) != NULL) {
		STACK_POP(vertex_stack, l_stack);
		for (ep = FIRST_ADJ(vertex); ep != HEAD(vertex);
		    ep = NEXT_ADJ(ep)) {
			if (IS_RECOMPUTE(ep->to_vertex))
				continue;
			ep->to_vertex->l_state |= RECOMPUTE_LOCK;
			STACK_PUSH(vertex_stack, ep->to_vertex, l_stack);
			nvertex++;
		}
	}

	/*
	 * allocate memory for holding the vertex pointers
	 */

	if (nvertex) {
		topology = kmem_zalloc(nvertex * sizeof (lock_descriptor_t *),
		    KM_SLEEP);
	}

	/*
	 * one more pass to actually store the vertices in the
	 * allocated array.
	 * We first check sleeping locks and then active locks
	 * so that topology array will be in a topological
	 * order.
	 */

	nvertex = 0;
	SET_LOCK_TO_FIRST_SLEEP_VP(gp, lock, vp);

	if (lock) {
		do {
			if (IS_RECOMPUTE(lock)) {
				lock->l_index = nvertex;
				topology[nvertex++] = lock;
			}
			lock->l_color = NO_COLOR;
			lock = lock->l_next;
		} while (lock->l_vnode == vp);
	}

	SET_LOCK_TO_FIRST_ACTIVE_VP(gp, lock, vp);

	if (lock) {
		do {
			if (IS_RECOMPUTE(lock)) {
				lock->l_index = nvertex;
				topology[nvertex++] = lock;
			}
			lock->l_color = NO_COLOR;
			lock = lock->l_next;
		} while (lock->l_vnode == vp);
	}

	/*
	 * remove in and out edges of request
	 * They are freed after updating proc_graph below.
	 */

	for (ep = FIRST_IN(request); ep != HEAD(request); ep = NEXT_IN(ep)) {
		ADJ_LIST_REMOVE(ep);
	}


	if (remove_from_queue)
		REMOVE_SLEEP_QUEUE(request);

	/* we are ready to recompute */

	flk_recompute_dependencies(request, topology, nvertex, 1);

	ep = FIRST_ADJ(request);
	while (ep != HEAD(request)) {
		IN_LIST_REMOVE(ep);
		request->l_sedge = NEXT_ADJ(ep);
		ADJ_LIST_REMOVE(ep);
		flk_update_proc_graph(ep, 1);
		flk_free_edge(ep);
		ep = request->l_sedge;
	}


	/*
	 * unset the RECOMPUTE flag in those vertices
	 */

	for (i = 0; i < nvertex; i++) {
		topology[i]->l_state &= ~RECOMPUTE_LOCK;
	}

	/*
	 * free the topology
	 */
	if (nvertex)
		kmem_free((void *)topology,
		    (nvertex * sizeof (lock_descriptor_t *)));
	/*
	 * Possibility of some locks unblocked now
	 */

	flk_wakeup(request, 0);

	/*
	 * we expect to have a correctly recomputed graph  now.
	 */
	flk_set_state(request, FLK_DEAD_STATE);
	flk_free_lock(request);
	CHECK_SLEEPING_LOCKS(gp);
	CHECK_ACTIVE_LOCKS(gp);

}

/*
 * Uncoloring the graph is simply to increment the mark value of the graph
 * And only when wrap round takes place will we color all vertices in
 * the graph explicitly.
 */

static void
flk_graph_uncolor(graph_t *gp)
{
	lock_descriptor_t *lock;

	if (gp->mark == UINT_MAX) {
		gp->mark = 1;
	for (lock = ACTIVE_HEAD(gp)->l_next; lock != ACTIVE_HEAD(gp);
	    lock = lock->l_next)
			lock->l_color  = 0;

	for (lock = SLEEPING_HEAD(gp)->l_next; lock != SLEEPING_HEAD(gp);
	    lock = lock->l_next)
			lock->l_color  = 0;
	} else {
		gp->mark++;
	}
}

/*
 * Wake up locks that are blocked on the given lock.
 */

static void
flk_wakeup(lock_descriptor_t *lock, int adj_list_remove)
{
	edge_t	*ep;
	graph_t	*gp = lock->l_graph;
	lock_descriptor_t	*lck;

	ASSERT(MUTEX_HELD(&gp->gp_mutex));
	if (NO_DEPENDENTS(lock))
		return;
	ep = FIRST_IN(lock);
	do {
		/*
		 * delete the edge from the adjacency list
		 * of from vertex. if no more adjacent edges
		 * for this vertex wake this process.
		 */
		lck = ep->from_vertex;
		if (adj_list_remove)
			ADJ_LIST_REMOVE(ep);
		flk_update_proc_graph(ep, 1);
		if (NOT_BLOCKED(lck)) {
			GRANT_WAKEUP(lck);
		}
		lock->l_sedge = NEXT_IN(ep);
		IN_LIST_REMOVE(ep);
		flk_free_edge(ep);
		ep = lock->l_sedge;
	} while (ep != HEAD(lock));
	ASSERT(NO_DEPENDENTS(lock));
}

/*
 * The dependents of request, is checked for its dependency against the
 * locks in topology (called topology because the array is and should be in
 * topological order for this algorithm, if not in topological order the
 * inner loop below might add more edges than necessary. Topological ordering
 * of vertices satisfies the property that all edges will be from left to
 * right i.e., topology[i] can have an edge to  topology[j], iff i<j)
 * If lock l1 in the dependent set of request is dependent (blocked by)
 * on lock l2 in topology but does not have a path to it, we add an edge
 * in the inner loop below.
 *
 * We don't want to add an edge between l1 and l2 if there exists
 * already a path from l1 to l2, so care has to be taken for those vertices
 * that  have two paths to 'request'. These vertices are referred to here
 * as barrier locks.
 *
 * The barriers has to be found (those vertex that originally had two paths
 * to request) because otherwise we may end up adding edges unnecessarily
 * to vertices in topology, and thus barrier vertices can have an edge
 * to a vertex in topology as well a path to it.
 */

static void
flk_recompute_dependencies(lock_descriptor_t *request,
		lock_descriptor_t **topology,
			int nvertex, int update_graph)
{
	lock_descriptor_t *vertex, *lock;
	graph_t	*gp = request->l_graph;
	int i, count;
	int barrier_found = 0;
	edge_t	*ep;
	lock_descriptor_t *vertex_stack;

	STACK_INIT(vertex_stack);

	ASSERT(MUTEX_HELD(&gp->gp_mutex));
	if (nvertex == 0)
		return;
	flk_graph_uncolor(request->l_graph);
	barrier_found = flk_find_barriers(request);
	request->l_state |= RECOMPUTE_DONE;

	STACK_PUSH(vertex_stack, request, l_stack);
	request->l_sedge = FIRST_IN(request);


	while ((vertex = STACK_TOP(vertex_stack)) != NULL) {
		if (vertex->l_state & RECOMPUTE_DONE) {
			count = 0;
			goto next_in_edge;
		}
		if (IS_BARRIER(vertex)) {
			/* decrement the barrier count */
			if (vertex->l_index) {
				vertex->l_index--;
				/* this guy will be pushed again anyway ? */
				STACK_POP(vertex_stack, l_stack);
				if (vertex->l_index == 0)  {
				/*
				 * barrier is over we can recompute
				 * dependencies for this lock in the
				 * next stack pop
				 */
					vertex->l_state &= ~BARRIER_LOCK;
				}
				continue;
			}
		}
		vertex->l_state |= RECOMPUTE_DONE;
		flk_graph_uncolor(gp);
		count = flk_color_reachables(vertex);
		for (i = 0; i < nvertex; i++) {
			lock = topology[i];
			if (COLORED(lock))
				continue;
			if (BLOCKS(lock, vertex)) {
				(void) flk_add_edge(vertex, lock,
				    NO_CHECK_CYCLE, update_graph);
				COLOR(lock);
				count++;
				count += flk_color_reachables(lock);
			}

		}

next_in_edge:
		if (count == nvertex ||
		    vertex->l_sedge == HEAD(vertex)) {
			/* prune the tree below this */
			STACK_POP(vertex_stack, l_stack);
			vertex->l_state &= ~RECOMPUTE_DONE;
			/* update the barrier locks below this! */
			if (vertex->l_sedge != HEAD(vertex) && barrier_found) {
				flk_graph_uncolor(gp);
				flk_update_barriers(vertex);
			}
			continue;
		}

		ep = vertex->l_sedge;
		lock = ep->from_vertex;
		STACK_PUSH(vertex_stack, lock, l_stack);
		lock->l_sedge = FIRST_IN(lock);
		vertex->l_sedge = NEXT_IN(ep);
	}

}

/*
 * Color all reachable vertices from vertex that belongs to topology (here
 * those that have RECOMPUTE_LOCK set in their state) and yet uncolored.
 *
 * Note: we need to use a different stack_link l_stack1 because this is
 * called from flk_recompute_dependencies() that already uses a stack with
 * l_stack as stack_link.
 */

static int
flk_color_reachables(lock_descriptor_t *vertex)
{
	lock_descriptor_t *ver, *lock;
	int count;
	edge_t	*ep;
	lock_descriptor_t *vertex_stack;

	STACK_INIT(vertex_stack);

	STACK_PUSH(vertex_stack, vertex, l_stack1);
	count = 0;
	while ((ver = STACK_TOP(vertex_stack)) != NULL) {

		STACK_POP(vertex_stack, l_stack1);
		for (ep = FIRST_ADJ(ver); ep != HEAD(ver);
		    ep = NEXT_ADJ(ep)) {
			lock = ep->to_vertex;
			if (COLORED(lock))
				continue;
			COLOR(lock);
			if (IS_RECOMPUTE(lock))
				count++;
			STACK_PUSH(vertex_stack, lock, l_stack1);
		}

	}
	return (count);
}

/*
 * Called from flk_recompute_dependencies() this routine decrements
 * the barrier count of barrier vertices that are reachable from lock.
 */

static void
flk_update_barriers(lock_descriptor_t *lock)
{
	lock_descriptor_t *vertex, *lck;
	edge_t	*ep;
	lock_descriptor_t *vertex_stack;

	STACK_INIT(vertex_stack);

	STACK_PUSH(vertex_stack, lock, l_stack1);

	while ((vertex = STACK_TOP(vertex_stack)) != NULL) {
		STACK_POP(vertex_stack, l_stack1);
		for (ep = FIRST_IN(vertex); ep != HEAD(vertex);
		    ep = NEXT_IN(ep)) {
			lck = ep->from_vertex;
			if (COLORED(lck)) {
				if (IS_BARRIER(lck)) {
					ASSERT(lck->l_index > 0);
					lck->l_index--;
					if (lck->l_index == 0)
						lck->l_state &= ~BARRIER_LOCK;
				}
				continue;
			}
			COLOR(lck);
			if (IS_BARRIER(lck)) {
				ASSERT(lck->l_index > 0);
				lck->l_index--;
				if (lck->l_index == 0)
					lck->l_state &= ~BARRIER_LOCK;
			}
			STACK_PUSH(vertex_stack, lck, l_stack1);
		}
	}
}

/*
 * Finds all vertices that are reachable from 'lock' more than once and
 * mark them as barrier vertices and increment their barrier count.
 * The barrier count is one minus the total number of paths from lock
 * to that vertex.
 */

static int
flk_find_barriers(lock_descriptor_t *lock)
{
	lock_descriptor_t *vertex, *lck;
	int found = 0;
	edge_t	*ep;
	lock_descriptor_t *vertex_stack;

	STACK_INIT(vertex_stack);

	STACK_PUSH(vertex_stack, lock, l_stack1);

	while ((vertex = STACK_TOP(vertex_stack)) != NULL) {
		STACK_POP(vertex_stack, l_stack1);
		for (ep = FIRST_IN(vertex); ep != HEAD(vertex);
		    ep = NEXT_IN(ep)) {
			lck = ep->from_vertex;
			if (COLORED(lck)) {
				/* this is a barrier */
				lck->l_state |= BARRIER_LOCK;
				/* index will have barrier count */
				lck->l_index++;
				if (!found)
					found = 1;
				continue;
			}
			COLOR(lck);
			lck->l_index = 0;
			STACK_PUSH(vertex_stack, lck, l_stack1);
		}
	}
	return (found);
}

/*
 * Finds the first lock that is mainly responsible for blocking this
 * request.  If there is no such lock, request->l_flock.l_type is set to
 * F_UNLCK.  Otherwise, request->l_flock is filled in with the particulars
 * of the blocking lock.
 *
 * Note: It is possible a request is blocked by a sleeping lock because
 * of the fairness policy used in flk_process_request() to construct the
 * dependencies. (see comments before flk_process_request()).
 */

static void
flk_get_first_blocking_lock(lock_descriptor_t *request)
{
	graph_t	*gp = request->l_graph;
	vnode_t *vp = request->l_vnode;
	lock_descriptor_t *lock, *blocker;

	ASSERT(MUTEX_HELD(&gp->gp_mutex));
	blocker = NULL;
	SET_LOCK_TO_FIRST_ACTIVE_VP(gp, lock, vp);

	if (lock) {
		do {
			if (BLOCKS(lock, request)) {
				blocker = lock;
				break;
			}
			lock = lock->l_next;
		} while (lock->l_vnode == vp);
	}

	if (blocker == NULL && request->l_flock.l_type == F_RDLCK) {
		/*
		 * No active lock is blocking this request, but if a read
		 * lock is requested, it may also get blocked by a waiting
		 * writer. So search all sleeping locks and see if there is
		 * a writer waiting.
		 */
		SET_LOCK_TO_FIRST_SLEEP_VP(gp, lock, vp);
		if (lock) {
			do {
				if (BLOCKS(lock, request)) {
					blocker = lock;
					break;
				}
				lock = lock->l_next;
			} while (lock->l_vnode == vp);
		}
	}

	if (blocker) {
		report_blocker(blocker, request);
	} else
		request->l_flock.l_type = F_UNLCK;
}

/*
 * Get the graph_t structure associated with a vnode.
 * If 'initialize' is non-zero, and the graph_t structure for this vnode has
 * not yet been initialized, then a new element is allocated and returned.
 */
graph_t *
flk_get_lock_graph(vnode_t *vp, int initialize)
{
	graph_t *gp;
	graph_t *gp_alloc = NULL;
	int index = HASH_INDEX(vp);

	if (initialize == FLK_USE_GRAPH) {
		mutex_enter(&flock_lock);
		gp = lock_graph[index];
		mutex_exit(&flock_lock);
		return (gp);
	}

	ASSERT(initialize == FLK_INIT_GRAPH);

	if (lock_graph[index] == NULL) {

		gp_alloc = kmem_zalloc(sizeof (graph_t), KM_SLEEP);

		/* Initialize the graph */

		gp_alloc->active_locks.l_next =
		    gp_alloc->active_locks.l_prev =
		    (lock_descriptor_t *)ACTIVE_HEAD(gp_alloc);
		gp_alloc->sleeping_locks.l_next =
		    gp_alloc->sleeping_locks.l_prev =
		    (lock_descriptor_t *)SLEEPING_HEAD(gp_alloc);
		gp_alloc->index = index;
		mutex_init(&gp_alloc->gp_mutex, NULL, MUTEX_DEFAULT, NULL);
	}

	mutex_enter(&flock_lock);

	gp = lock_graph[index];

	/* Recheck the value within flock_lock */
	if (gp == NULL) {
		struct flock_globals *fg;

		/* We must have previously allocated the graph_t structure */
		ASSERT(gp_alloc != NULL);
		lock_graph[index] = gp = gp_alloc;
		/*
		 * The lockmgr status is only needed if KLM is loaded.
		 */
		if (flock_zone_key != ZONE_KEY_UNINITIALIZED) {
			fg = flk_get_globals();
			fg->lockmgr_status[index] = fg->flk_lockmgr_status;
		}
	}

	mutex_exit(&flock_lock);

	if ((gp_alloc != NULL) && (gp != gp_alloc)) {
		/* There was a race to allocate the graph_t and we lost */
		mutex_destroy(&gp_alloc->gp_mutex);
		kmem_free(gp_alloc, sizeof (graph_t));
	}

	return (gp);
}

/*
 * PSARC case 1997/292
 */
int
cl_flk_has_remote_locks_for_nlmid(vnode_t *vp, int nlmid)
{
	lock_descriptor_t *lock;
	int result = 0;
	graph_t *gp;
	int			lock_nlmid;

	/*
	 * Check to see if node is booted as a cluster. If not, return.
	 */
	if ((cluster_bootflags & CLUSTER_BOOTED) == 0) {
		return (0);
	}

	gp = flk_get_lock_graph(vp, FLK_USE_GRAPH);
	if (gp == NULL) {
		return (0);
	}

	mutex_enter(&gp->gp_mutex);

	SET_LOCK_TO_FIRST_ACTIVE_VP(gp, lock, vp);

	if (lock) {
		while (lock->l_vnode == vp) {
			/* get NLM id from sysid */
			lock_nlmid = GETNLMID(lock->l_flock.l_sysid);

			/*
			 * If NLM server request _and_ nlmid of lock matches
			 * nlmid of argument, then we've found a remote lock.
			 */
			if (IS_LOCKMGR(lock) && nlmid == lock_nlmid) {
				result = 1;
				goto done;
			}
			lock = lock->l_next;
		}
	}

	SET_LOCK_TO_FIRST_SLEEP_VP(gp, lock, vp);

	if (lock) {
		while (lock->l_vnode == vp) {
			/* get NLM id from sysid */
			lock_nlmid = GETNLMID(lock->l_flock.l_sysid);

			/*
			 * If NLM server request _and_ nlmid of lock matches
			 * nlmid of argument, then we've found a remote lock.
			 */
			if (IS_LOCKMGR(lock) && nlmid == lock_nlmid) {
				result = 1;
				goto done;
			}
			lock = lock->l_next;
		}
	}

done:
	mutex_exit(&gp->gp_mutex);
	return (result);
}

/*
 * Determine whether there are any locks for the given vnode with a remote
 * sysid.  Returns zero if not, non-zero if there are.
 *
 * Note that the return value from this function is potentially invalid
 * once it has been returned.  The caller is responsible for providing its
 * own synchronization mechanism to ensure that the return value is useful
 * (e.g., see nfs_lockcompletion()).
 */
int
flk_has_remote_locks(vnode_t *vp)
{
	lock_descriptor_t *lock;
	int result = 0;
	graph_t *gp;

	gp = flk_get_lock_graph(vp, FLK_USE_GRAPH);
	if (gp == NULL) {
		return (0);
	}

	mutex_enter(&gp->gp_mutex);

	SET_LOCK_TO_FIRST_ACTIVE_VP(gp, lock, vp);

	if (lock) {
		while (lock->l_vnode == vp) {
			if (IS_REMOTE(lock)) {
				result = 1;
				goto done;
			}
			lock = lock->l_next;
		}
	}

	SET_LOCK_TO_FIRST_SLEEP_VP(gp, lock, vp);

	if (lock) {
		while (lock->l_vnode == vp) {
			if (IS_REMOTE(lock)) {
				result = 1;
				goto done;
			}
			lock = lock->l_next;
		}
	}

done:
	mutex_exit(&gp->gp_mutex);
	return (result);
}

/*
 * Determine whether there are any locks for the given vnode with a remote
 * sysid matching given sysid.
 * Used by the new (open source) NFS Lock Manager (NLM)
 */
int
flk_has_remote_locks_for_sysid(vnode_t *vp, int sysid)
{
	lock_descriptor_t *lock;
	int result = 0;
	graph_t *gp;

	if (sysid == 0)
		return (0);

	gp = flk_get_lock_graph(vp, FLK_USE_GRAPH);
	if (gp == NULL) {
		return (0);
	}

	mutex_enter(&gp->gp_mutex);

	SET_LOCK_TO_FIRST_ACTIVE_VP(gp, lock, vp);

	if (lock) {
		while (lock->l_vnode == vp) {
			if (lock->l_flock.l_sysid == sysid) {
				result = 1;
				goto done;
			}
			lock = lock->l_next;
		}
	}

	SET_LOCK_TO_FIRST_SLEEP_VP(gp, lock, vp);

	if (lock) {
		while (lock->l_vnode == vp) {
			if (lock->l_flock.l_sysid == sysid) {
				result = 1;
				goto done;
			}
			lock = lock->l_next;
		}
	}

done:
	mutex_exit(&gp->gp_mutex);
	return (result);
}

/*
 * Determine if there are any locks owned by the given sysid.
 * Returns zero if not, non-zero if there are.  Note that this return code
 * could be derived from flk_get_{sleeping,active}_locks, but this routine
 * avoids all the memory allocations of those routines.
 *
 * This routine has the same synchronization issues as
 * flk_has_remote_locks.
 */

int
flk_sysid_has_locks(int sysid, int lck_type)
{
	int		has_locks = 0;
	lock_descriptor_t	*lock;
	graph_t 	*gp;
	int		i;

	for (i = 0; i < HASH_SIZE && !has_locks; i++) {
		mutex_enter(&flock_lock);
		gp = lock_graph[i];
		mutex_exit(&flock_lock);
		if (gp == NULL) {
			continue;
		}

		mutex_enter(&gp->gp_mutex);

		if (lck_type & FLK_QUERY_ACTIVE) {
			for (lock = ACTIVE_HEAD(gp)->l_next;
			    lock != ACTIVE_HEAD(gp) && !has_locks;
			    lock = lock->l_next) {
				if (lock->l_flock.l_sysid == sysid)
					has_locks = 1;
			}
		}

		if (lck_type & FLK_QUERY_SLEEPING) {
			for (lock = SLEEPING_HEAD(gp)->l_next;
			    lock != SLEEPING_HEAD(gp) && !has_locks;
			    lock = lock->l_next) {
				if (lock->l_flock.l_sysid == sysid)
					has_locks = 1;
			}
		}
		mutex_exit(&gp->gp_mutex);
	}

	return (has_locks);
}


/*
 * PSARC case 1997/292
 *
 * Requires: "sysid" is a pair [nlmid, sysid].  The lower half is 16-bit
 *  quantity, the real sysid generated by the NLM server; the upper half
 *  identifies the node of the cluster where the NLM server ran.
 *  This routine is only called by an NLM server running in a cluster.
 * Effects: Remove all locks held on behalf of the client identified
 *  by "sysid."
 */
void
cl_flk_remove_locks_by_sysid(int sysid)
{
	graph_t	*gp;
	int i;
	lock_descriptor_t *lock, *nlock;

	/*
	 * Check to see if node is booted as a cluster. If not, return.
	 */
	if ((cluster_bootflags & CLUSTER_BOOTED) == 0) {
		return;
	}

	ASSERT(sysid != 0);
	for (i = 0; i < HASH_SIZE; i++) {
		mutex_enter(&flock_lock);
		gp = lock_graph[i];
		mutex_exit(&flock_lock);

		if (gp == NULL)
			continue;

		mutex_enter(&gp->gp_mutex);	/*  get mutex on lock graph */

		/* signal sleeping requests so that they bail out */
		lock = SLEEPING_HEAD(gp)->l_next;
		while (lock != SLEEPING_HEAD(gp)) {
			nlock = lock->l_next;
			if (lock->l_flock.l_sysid == sysid) {
				INTERRUPT_WAKEUP(lock);
			}
			lock = nlock;
		}

		/* delete active locks */
		lock = ACTIVE_HEAD(gp)->l_next;
		while (lock != ACTIVE_HEAD(gp)) {
			nlock = lock->l_next;
			if (lock->l_flock.l_sysid == sysid) {
				flk_delete_active_lock(lock, 0);
				flk_wakeup(lock, 1);
				flk_free_lock(lock);
			}
			lock = nlock;
		}
		mutex_exit(&gp->gp_mutex);    /* release mutex on lock graph */
	}
}

/*
 * Delete all locks in the system that belongs to the sysid of the request.
 */

static void
flk_delete_locks_by_sysid(lock_descriptor_t *request)
{
	int	sysid  = request->l_flock.l_sysid;
	lock_descriptor_t *lock, *nlock;
	graph_t	*gp;
	int i;

	ASSERT(MUTEX_HELD(&request->l_graph->gp_mutex));
	ASSERT(sysid != 0);

	mutex_exit(&request->l_graph->gp_mutex);

	for (i = 0; i < HASH_SIZE; i++) {
		mutex_enter(&flock_lock);
		gp = lock_graph[i];
		mutex_exit(&flock_lock);

		if (gp == NULL)
			continue;

		mutex_enter(&gp->gp_mutex);

		/* signal sleeping requests so that they bail out */
		lock = SLEEPING_HEAD(gp)->l_next;
		while (lock != SLEEPING_HEAD(gp)) {
			nlock = lock->l_next;
			if (lock->l_flock.l_sysid == sysid) {
				INTERRUPT_WAKEUP(lock);
			}
			lock = nlock;
		}

		/* delete active locks */
		lock = ACTIVE_HEAD(gp)->l_next;
		while (lock != ACTIVE_HEAD(gp)) {
			nlock = lock->l_next;
			if (lock->l_flock.l_sysid == sysid) {
				flk_delete_active_lock(lock, 0);
				flk_wakeup(lock, 1);
				flk_free_lock(lock);
			}
			lock = nlock;
		}
		mutex_exit(&gp->gp_mutex);
	}

	mutex_enter(&request->l_graph->gp_mutex);
}

/*
 * Clustering: Deletes PXFS locks
 * Effects: Delete all locks on files in the given file system and with the
 *  given PXFS id.
 */
void
cl_flk_delete_pxfs_locks(struct vfs *vfsp, int pxfsid)
{
	lock_descriptor_t *lock, *nlock;
	graph_t	*gp;
	int i;

	for (i = 0; i < HASH_SIZE; i++) {
		mutex_enter(&flock_lock);
		gp = lock_graph[i];
		mutex_exit(&flock_lock);

		if (gp == NULL)
			continue;

		mutex_enter(&gp->gp_mutex);

		/* signal sleeping requests so that they bail out */
		lock = SLEEPING_HEAD(gp)->l_next;
		while (lock != SLEEPING_HEAD(gp)) {
			nlock = lock->l_next;
			if (lock->l_vnode->v_vfsp == vfsp) {
				ASSERT(IS_PXFS(lock));
				if (GETPXFSID(lock->l_flock.l_sysid) ==
				    pxfsid) {
					flk_set_state(lock,
					    FLK_CANCELLED_STATE);
					flk_cancel_sleeping_lock(lock, 1);
				}
			}
			lock = nlock;
		}

		/* delete active locks */
		lock = ACTIVE_HEAD(gp)->l_next;
		while (lock != ACTIVE_HEAD(gp)) {
			nlock = lock->l_next;
			if (lock->l_vnode->v_vfsp == vfsp) {
				ASSERT(IS_PXFS(lock));
				if (GETPXFSID(lock->l_flock.l_sysid) ==
				    pxfsid) {
					flk_delete_active_lock(lock, 0);
					flk_wakeup(lock, 1);
					flk_free_lock(lock);
				}
			}
			lock = nlock;
		}
		mutex_exit(&gp->gp_mutex);
	}
}

/*
 * Search for a sleeping lock manager lock which matches exactly this lock
 * request; if one is found, fake a signal to cancel it.
 *
 * Return 1 if a matching lock was found, 0 otherwise.
 */

static int
flk_canceled(lock_descriptor_t *request)
{
	lock_descriptor_t *lock, *nlock;
	graph_t *gp = request->l_graph;
	vnode_t *vp = request->l_vnode;

	ASSERT(MUTEX_HELD(&gp->gp_mutex));
	ASSERT(IS_LOCKMGR(request));
	SET_LOCK_TO_FIRST_SLEEP_VP(gp, lock, vp);

	if (lock) {
		while (lock->l_vnode == vp) {
			nlock = lock->l_next;
			if (SAME_OWNER(lock, request) &&
			    lock->l_start == request->l_start &&
			    lock->l_end == request->l_end) {
				INTERRUPT_WAKEUP(lock);
				return (1);
			}
			lock = nlock;
		}
	}
	return (0);
}

/*
 * Remove all non-OFD locks for the vnode belonging to the given pid and sysid.
 * That is, since OFD locks are pid-less we'll never match on the incoming
 * pid. OFD locks are removed earlier in the close() path via closef() and
 * ofdcleanlock().
 */
void
cleanlocks(vnode_t *vp, pid_t pid, int sysid)
{
	graph_t	*gp;
	lock_descriptor_t *lock, *nlock;
	lock_descriptor_t *link_stack;

	STACK_INIT(link_stack);

	gp = flk_get_lock_graph(vp, FLK_USE_GRAPH);

	if (gp == NULL)
		return;
	mutex_enter(&gp->gp_mutex);

	CHECK_SLEEPING_LOCKS(gp);
	CHECK_ACTIVE_LOCKS(gp);

	SET_LOCK_TO_FIRST_SLEEP_VP(gp, lock, vp);

	if (lock) {
		do {
			nlock = lock->l_next;
			if ((lock->l_flock.l_pid == pid ||
			    pid == IGN_PID) &&
			    lock->l_flock.l_sysid == sysid) {
				CANCEL_WAKEUP(lock);
			}
			lock = nlock;
		} while (lock->l_vnode == vp);
	}

	SET_LOCK_TO_FIRST_ACTIVE_VP(gp, lock, vp);

	if (lock) {
		do {
			nlock = lock->l_next;
			if ((lock->l_flock.l_pid == pid ||
			    pid == IGN_PID) &&
			    lock->l_flock.l_sysid == sysid) {
				flk_delete_active_lock(lock, 0);
				STACK_PUSH(link_stack, lock, l_stack);
			}
			lock = nlock;
		} while (lock->l_vnode == vp);
	}

	while ((lock = STACK_TOP(link_stack)) != NULL) {
		STACK_POP(link_stack, l_stack);
		flk_wakeup(lock, 1);
		flk_free_lock(lock);
	}

	CHECK_SLEEPING_LOCKS(gp);
	CHECK_ACTIVE_LOCKS(gp);
	CHECK_OWNER_LOCKS(gp, pid, sysid, vp);
	mutex_exit(&gp->gp_mutex);
}


/*
 * Called from 'fs' read and write routines for files that have mandatory
 * locking enabled.
 */

int
chklock(
	struct vnode	*vp,
	int 		iomode,
	u_offset_t	offset,
	ssize_t		len,
	int 		fmode,
	caller_context_t *ct)
{
	register int	i;
	struct flock64 	bf;
	int 		error = 0;

	bf.l_type = (iomode & FWRITE) ? F_WRLCK : F_RDLCK;
	bf.l_whence = 0;
	bf.l_start = offset;
	bf.l_len = len;
	if (ct == NULL) {
		bf.l_pid = curproc->p_pid;
		bf.l_sysid = 0;
	} else {
		bf.l_pid = ct->cc_pid;
		bf.l_sysid = ct->cc_sysid;
	}
	i = (fmode & (FNDELAY|FNONBLOCK)) ? INOFLCK : INOFLCK|SLPFLCK;
	if ((i = reclock(vp, &bf, i, 0, offset, NULL)) != 0 ||
	    bf.l_type != F_UNLCK)
		error = i ? i : EAGAIN;
	return (error);
}

/*
 * convoff - converts the given data (start, whence) to the
 * given whence.
 */
int
convoff(vp, lckdat, whence, offset)
	struct vnode 	*vp;
	struct flock64 	*lckdat;
	int 		whence;
	offset_t	offset;
{
	int 		error;
	struct vattr 	vattr;

	if ((lckdat->l_whence == 2) || (whence == 2)) {
		vattr.va_mask = AT_SIZE;
		if (error = VOP_GETATTR(vp, &vattr, 0, CRED(), NULL))
			return (error);
	}

	switch (lckdat->l_whence) {
	case 1:
		lckdat->l_start += offset;
		break;
	case 2:
		lckdat->l_start += vattr.va_size;
		/* FALLTHRU */
	case 0:
		break;
	default:
		return (EINVAL);
	}

	if (lckdat->l_start < 0)
		return (EINVAL);

	switch (whence) {
	case 1:
		lckdat->l_start -= offset;
		break;
	case 2:
		lckdat->l_start -= vattr.va_size;
		/* FALLTHRU */
	case 0:
		break;
	default:
		return (EINVAL);
	}

	lckdat->l_whence = (short)whence;
	return (0);
}


/* 	proc_graph function definitions */

/*
 * Function checks for deadlock due to the new 'lock'. If deadlock found
 * edges of this lock are freed and returned.
 */

static int
flk_check_deadlock(lock_descriptor_t *lock)
{
	proc_vertex_t	*start_vertex, *pvertex;
	proc_vertex_t *dvertex;
	proc_edge_t *pep, *ppep;
	edge_t	*ep, *nep;
	proc_vertex_t *process_stack;

	/*
	 * OFD style locks are not associated with any process so there is
	 * no proc graph for these. Thus we cannot, and do not, do deadlock
	 * detection.
	 */
	if (lock->l_ofd != NULL)
		return (0);

	STACK_INIT(process_stack);

	mutex_enter(&flock_lock);
	start_vertex = flk_get_proc_vertex(lock);
	ASSERT(start_vertex != NULL);

	/* construct the edges from this process to other processes */

	ep = FIRST_ADJ(lock);
	while (ep != HEAD(lock)) {
		proc_vertex_t *adj_proc;

		adj_proc = flk_get_proc_vertex(ep->to_vertex);
		for (pep = start_vertex->edge; pep != NULL; pep = pep->next) {
			if (pep->to_proc == adj_proc) {
				ASSERT(pep->refcount);
				pep->refcount++;
				break;
			}
		}
		if (pep == NULL) {
			pep = flk_get_proc_edge();
			pep->to_proc = adj_proc;
			pep->refcount = 1;
			adj_proc->incount++;
			pep->next = start_vertex->edge;
			start_vertex->edge = pep;
		}
		ep = NEXT_ADJ(ep);
	}

	ep = FIRST_IN(lock);

	while (ep != HEAD(lock)) {
		proc_vertex_t *in_proc;

		in_proc = flk_get_proc_vertex(ep->from_vertex);

		for (pep = in_proc->edge; pep != NULL; pep = pep->next) {
			if (pep->to_proc == start_vertex) {
				ASSERT(pep->refcount);
				pep->refcount++;
				break;
			}
		}
		if (pep == NULL) {
			pep = flk_get_proc_edge();
			pep->to_proc = start_vertex;
			pep->refcount = 1;
			start_vertex->incount++;
			pep->next = in_proc->edge;
			in_proc->edge = pep;
		}
		ep = NEXT_IN(ep);
	}

	if (start_vertex->incount == 0) {
		mutex_exit(&flock_lock);
		return (0);
	}

	flk_proc_graph_uncolor();

	start_vertex->p_sedge = start_vertex->edge;

	STACK_PUSH(process_stack, start_vertex, p_stack);

	while ((pvertex = STACK_TOP(process_stack)) != NULL) {
		for (pep = pvertex->p_sedge; pep != NULL; pep = pep->next) {
			dvertex = pep->to_proc;
			if (!PROC_ARRIVED(dvertex)) {
				STACK_PUSH(process_stack, dvertex, p_stack);
				dvertex->p_sedge = dvertex->edge;
				PROC_ARRIVE(pvertex);
				pvertex->p_sedge = pep->next;
				break;
			}
			if (!PROC_DEPARTED(dvertex))
				goto deadlock;
		}
		if (pep == NULL) {
			PROC_DEPART(pvertex);
			STACK_POP(process_stack, p_stack);
		}
	}
	mutex_exit(&flock_lock);
	return (0);

deadlock:

	/* we remove all lock edges and proc edges */

	ep = FIRST_ADJ(lock);
	while (ep != HEAD(lock)) {
		proc_vertex_t *adj_proc;
		adj_proc = flk_get_proc_vertex(ep->to_vertex);
		nep = NEXT_ADJ(ep);
		IN_LIST_REMOVE(ep);
		ADJ_LIST_REMOVE(ep);
		flk_free_edge(ep);
		ppep = start_vertex->edge;
		for (pep = start_vertex->edge; pep != NULL; ppep = pep,
		    pep = ppep->next) {
			if (pep->to_proc == adj_proc) {
				pep->refcount--;
				if (pep->refcount == 0) {
					if (pep == ppep) {
						start_vertex->edge = pep->next;
					} else {
						ppep->next = pep->next;
					}
					adj_proc->incount--;
					flk_proc_release(adj_proc);
					flk_free_proc_edge(pep);
				}
				break;
			}
		}
		ep = nep;
	}
	ep = FIRST_IN(lock);
	while (ep != HEAD(lock)) {
		proc_vertex_t *in_proc;
		in_proc = flk_get_proc_vertex(ep->from_vertex);
		nep = NEXT_IN(ep);
		IN_LIST_REMOVE(ep);
		ADJ_LIST_REMOVE(ep);
		flk_free_edge(ep);
		ppep = in_proc->edge;
		for (pep = in_proc->edge; pep != NULL; ppep = pep,
		    pep = ppep->next) {
			if (pep->to_proc == start_vertex) {
				pep->refcount--;
				if (pep->refcount == 0) {
					if (pep == ppep) {
						in_proc->edge = pep->next;
					} else {
						ppep->next = pep->next;
					}
					start_vertex->incount--;
					flk_proc_release(in_proc);
					flk_free_proc_edge(pep);
				}
				break;
			}
		}
		ep = nep;
	}
	flk_proc_release(start_vertex);
	mutex_exit(&flock_lock);
	return (1);
}

/*
 * Get a proc vertex. If lock's pvertex value gets a correct proc vertex
 * from the list we return that, otherwise we allocate one. If necessary,
 * we grow the list of vertices also.
 */

static proc_vertex_t *
flk_get_proc_vertex(lock_descriptor_t *lock)
{
	int i;
	proc_vertex_t	*pv;
	proc_vertex_t	**palloc;

	ASSERT(MUTEX_HELD(&flock_lock));
	if (lock->pvertex != -1) {
		ASSERT(lock->pvertex >= 0);
		pv = pgraph.proc[lock->pvertex];
		if (pv != NULL && PROC_SAME_OWNER(lock, pv)) {
			return (pv);
		}
	}
	for (i = 0; i < pgraph.gcount; i++) {
		pv = pgraph.proc[i];
		if (pv != NULL && PROC_SAME_OWNER(lock, pv)) {
			lock->pvertex = pv->index = i;
			return (pv);
		}
	}
	pv = kmem_zalloc(sizeof (struct proc_vertex), KM_SLEEP);
	pv->pid = lock->l_flock.l_pid;
	pv->sysid = lock->l_flock.l_sysid;
	flk_proc_vertex_allocs++;
	if (pgraph.free != 0) {
		for (i = 0; i < pgraph.gcount; i++) {
			if (pgraph.proc[i] == NULL) {
				pgraph.proc[i] = pv;
				lock->pvertex = pv->index = i;
				pgraph.free--;
				return (pv);
			}
		}
	}
	palloc = kmem_zalloc((pgraph.gcount + PROC_CHUNK) *
	    sizeof (proc_vertex_t *), KM_SLEEP);

	if (pgraph.proc) {
		bcopy(pgraph.proc, palloc,
		    pgraph.gcount * sizeof (proc_vertex_t *));

		kmem_free(pgraph.proc,
		    pgraph.gcount * sizeof (proc_vertex_t *));
	}
	pgraph.proc = palloc;
	pgraph.free += (PROC_CHUNK - 1);
	pv->index = lock->pvertex = pgraph.gcount;
	pgraph.gcount += PROC_CHUNK;
	pgraph.proc[pv->index] = pv;
	return (pv);
}

/*
 * Allocate a proc edge.
 */

static proc_edge_t *
flk_get_proc_edge()
{
	proc_edge_t *pep;

	pep = kmem_zalloc(sizeof (proc_edge_t), KM_SLEEP);
	flk_proc_edge_allocs++;
	return (pep);
}

/*
 * Free the proc edge. Called whenever its reference count goes to zero.
 */

static void
flk_free_proc_edge(proc_edge_t *pep)
{
	ASSERT(pep->refcount == 0);
	kmem_free((void *)pep, sizeof (proc_edge_t));
	flk_proc_edge_frees++;
}

/*
 * Color the graph explicitly done only when the mark value hits max value.
 */

static void
flk_proc_graph_uncolor()
{
	int i;

	if (pgraph.mark == UINT_MAX) {
		for (i = 0; i < pgraph.gcount; i++)
			if (pgraph.proc[i] != NULL) {
				pgraph.proc[i]->atime = 0;
				pgraph.proc[i]->dtime = 0;
			}
		pgraph.mark = 1;
	} else {
		pgraph.mark++;
	}
}

/*
 * Release the proc vertex iff both there are no in edges and out edges
 */

static void
flk_proc_release(proc_vertex_t *proc)
{
	ASSERT(MUTEX_HELD(&flock_lock));
	if (proc->edge == NULL && proc->incount == 0) {
		pgraph.proc[proc->index] = NULL;
		pgraph.free++;
		kmem_free(proc, sizeof (proc_vertex_t));
		flk_proc_vertex_frees++;
	}
}

/*
 * Updates process graph to reflect change in a lock_graph.
 * Note: We should call this function only after we have a correctly
 * recomputed lock graph. Otherwise we might miss a deadlock detection.
 * eg: in function flk_relation() we call this function after flk_recompute_
 * dependencies() otherwise if a process tries to lock a vnode hashed
 * into another graph it might sleep for ever.
 */

static void
flk_update_proc_graph(edge_t *ep, int delete)
{
	proc_vertex_t *toproc, *fromproc;
	proc_edge_t *pep, *prevpep;

	mutex_enter(&flock_lock);

	/*
	 * OFD style locks are not associated with any process so there is
	 * no proc graph for these.
	 */
	if (ep->from_vertex->l_ofd != NULL) {
		mutex_exit(&flock_lock);
		return;
	}

	toproc = flk_get_proc_vertex(ep->to_vertex);
	fromproc = flk_get_proc_vertex(ep->from_vertex);

	if (!delete)
		goto add;
	pep = prevpep = fromproc->edge;

	ASSERT(pep != NULL);
	while (pep != NULL) {
		if (pep->to_proc == toproc) {
			ASSERT(pep->refcount > 0);
			pep->refcount--;
			if (pep->refcount == 0) {
				if (pep == prevpep) {
					fromproc->edge = pep->next;
				} else {
					prevpep->next = pep->next;
				}
				toproc->incount--;
				flk_proc_release(toproc);
				flk_free_proc_edge(pep);
			}
			break;
		}
		prevpep = pep;
		pep = pep->next;
	}
	flk_proc_release(fromproc);
	mutex_exit(&flock_lock);
	return;
add:

	pep = fromproc->edge;

	while (pep != NULL) {
		if (pep->to_proc == toproc) {
			ASSERT(pep->refcount > 0);
			pep->refcount++;
			break;
		}
		pep = pep->next;
	}
	if (pep == NULL) {
		pep = flk_get_proc_edge();
		pep->to_proc = toproc;
		pep->refcount = 1;
		toproc->incount++;
		pep->next = fromproc->edge;
		fromproc->edge = pep;
	}
	mutex_exit(&flock_lock);
}

/*
 * Set the control status for lock manager requests.
 *
 */

/*
 * PSARC case 1997/292
 *
 * Requires: "nlmid" must be >= 1 and <= clconf_maximum_nodeid().
 * Effects: Set the state of the NLM server identified by "nlmid"
 *   in the NLM registry to state "nlm_state."
 *   Raises exception no_such_nlm if "nlmid" doesn't identify a known
 *   NLM server to this LLM.
 *   Note that when this routine is called with NLM_SHUTTING_DOWN there
 *   may be locks requests that have gotten started but not finished.  In
 *   particular, there may be blocking requests that are in the callback code
 *   before sleeping (so they're not holding the lock for the graph).  If
 *   such a thread reacquires the graph's lock (to go to sleep) after
 *   NLM state in the NLM registry  is set to a non-up value,
 *   it will notice the status and bail out.  If the request gets
 *   granted before the thread can check the NLM registry, let it
 *   continue normally.  It will get flushed when we are called with NLM_DOWN.
 *
 * Modifies: nlm_reg_obj (global)
 * Arguments:
 *    nlmid	(IN):    id uniquely identifying an NLM server
 *    nlm_state (IN):    NLM server state to change "nlmid" to
 */
void
cl_flk_set_nlm_status(int nlmid, flk_nlm_status_t nlm_state)
{
	/*
	 * Check to see if node is booted as a cluster. If not, return.
	 */
	if ((cluster_bootflags & CLUSTER_BOOTED) == 0) {
		return;
	}

	/*
	 * Check for development/debugging.  It is possible to boot a node
	 * in non-cluster mode, and then run a special script, currently
	 * available only to developers, to bring up the node as part of a
	 * cluster.  The problem is that running such a script does not
	 * result in the routine flk_init() being called and hence global array
	 * nlm_reg_status is NULL.  The NLM thinks it's in cluster mode,
	 * but the LLM needs to do an additional check to see if the global
	 * array has been created or not. If nlm_reg_status is NULL, then
	 * return, else continue.
	 */
	if (nlm_reg_status == NULL) {
		return;
	}

	ASSERT(nlmid <= nlm_status_size && nlmid >= 0);
	mutex_enter(&nlm_reg_lock);

	if (FLK_REGISTRY_IS_NLM_UNKNOWN(nlm_reg_status, nlmid)) {
		/*
		 * If the NLM server "nlmid" is unknown in the NLM registry,
		 * add it to the registry in the nlm shutting down state.
		 */
		FLK_REGISTRY_CHANGE_NLM_STATE(nlm_reg_status, nlmid,
		    FLK_NLM_SHUTTING_DOWN);
	} else {
		/*
		 * Change the state of the NLM server identified by "nlmid"
		 * in the NLM registry to the argument "nlm_state."
		 */
		FLK_REGISTRY_CHANGE_NLM_STATE(nlm_reg_status, nlmid,
		    nlm_state);
	}

	/*
	 *  The reason we must register the NLM server that is shutting down
	 *  with an LLM that doesn't already know about it (never sent a lock
	 *  request) is to handle correctly a race between shutdown and a new
	 *  lock request.  Suppose that a shutdown request from the NLM server
	 *  invokes this routine at the LLM, and a thread is spawned to
	 *  service the request. Now suppose a new lock request is in
	 *  progress and has already passed the first line of defense in
	 *  reclock(), which denies new locks requests from NLM servers
	 *  that are not in the NLM_UP state.  After the current routine
	 *  is invoked for both phases of shutdown, the routine will return,
	 *  having done nothing, and the lock request will proceed and
	 *  probably be granted.  The problem is that the shutdown was ignored
	 *  by the lock request because there was no record of that NLM server
	 *  shutting down.   We will be in the peculiar position of thinking
	 *  that we've shutdown the NLM server and all locks at all LLMs have
	 *  been discarded, but in fact there's still one lock held.
	 *  The solution is to record the existence of NLM server and change
	 *  its state immediately to NLM_SHUTTING_DOWN.  The lock request in
	 *  progress may proceed because the next phase NLM_DOWN will catch
	 *  this lock and discard it.
	 */
	mutex_exit(&nlm_reg_lock);

	switch (nlm_state) {
	case FLK_NLM_UP:
		/*
		 * Change the NLM state of all locks still held on behalf of
		 * the NLM server identified by "nlmid" to NLM_UP.
		 */
		cl_flk_change_nlm_state_all_locks(nlmid, FLK_NLM_UP);
		break;

	case FLK_NLM_SHUTTING_DOWN:
		/*
		 * Wake up all sleeping locks for the NLM server identified
		 * by "nlmid." Note that eventually all woken threads will
		 * have their lock requests cancelled and descriptors
		 * removed from the sleeping lock list.  Note that the NLM
		 * server state associated with each lock descriptor is
		 * changed to FLK_NLM_SHUTTING_DOWN.
		 */
		cl_flk_wakeup_sleeping_nlm_locks(nlmid);
		break;

	case FLK_NLM_DOWN:
		/*
		 * Discard all active, granted locks for this NLM server
		 * identified by "nlmid."
		 */
		cl_flk_unlock_nlm_granted(nlmid);
		break;

	default:
		panic("cl_set_nlm_status: bad status (%d)", nlm_state);
	}
}

/*
 * Set the control status for lock manager requests.
 *
 * Note that when this routine is called with FLK_WAKEUP_SLEEPERS, there
 * may be locks requests that have gotten started but not finished.  In
 * particular, there may be blocking requests that are in the callback code
 * before sleeping (so they're not holding the lock for the graph).  If
 * such a thread reacquires the graph's lock (to go to sleep) after
 * flk_lockmgr_status is set to a non-up value, it will notice the status
 * and bail out.  If the request gets granted before the thread can check
 * flk_lockmgr_status, let it continue normally.  It will get flushed when
 * we are called with FLK_LOCKMGR_DOWN.
 */

void
flk_set_lockmgr_status(flk_lockmgr_status_t status)
{
	int i;
	graph_t *gp;
	struct flock_globals *fg;

	fg = flk_get_globals();
	ASSERT(fg != NULL);

	mutex_enter(&flock_lock);
	fg->flk_lockmgr_status = status;
	mutex_exit(&flock_lock);

	/*
	 * If the lock manager is coming back up, all that's needed is to
	 * propagate this information to the graphs.  If the lock manager
	 * is going down, additional action is required, and each graph's
	 * copy of the state is updated atomically with this other action.
	 */
	switch (status) {
	case FLK_LOCKMGR_UP:
		for (i = 0; i < HASH_SIZE; i++) {
			mutex_enter(&flock_lock);
			gp = lock_graph[i];
			mutex_exit(&flock_lock);
			if (gp == NULL)
				continue;
			mutex_enter(&gp->gp_mutex);
			fg->lockmgr_status[i] = status;
			mutex_exit(&gp->gp_mutex);
		}
		break;
	case FLK_WAKEUP_SLEEPERS:
		wakeup_sleeping_lockmgr_locks(fg);
		break;
	case FLK_LOCKMGR_DOWN:
		unlock_lockmgr_granted(fg);
		break;
	default:
		panic("flk_set_lockmgr_status: bad status (%d)", status);
		break;
	}
}

/*
 * This routine returns all the locks that are active or sleeping and are
 * associated with a particular set of identifiers.  If lock_state != 0, then
 * only locks that match the lock_state are returned. If lock_state == 0, then
 * all locks are returned. If pid == NOPID, the pid is ignored.  If
 * use_sysid is FALSE, then the sysid is ignored.  If vp is NULL, then the
 * vnode pointer is ignored.
 *
 * A list containing the vnode pointer and an flock structure
 * describing the lock is returned.  Each element in the list is
 * dynamically allocated and must be freed by the caller.  The
 * last item in the list is denoted by a NULL value in the ll_next
 * field.
 *
 * The vnode pointers returned are held.  The caller is responsible
 * for releasing these.  Note that the returned list is only a snapshot of
 * the current lock information, and that it is a snapshot of a moving
 * target (only one graph is locked at a time).
 */

locklist_t *
get_lock_list(int list_type, int lock_state, int sysid, boolean_t use_sysid,
		pid_t pid, const vnode_t *vp, zoneid_t zoneid)
{
	lock_descriptor_t	*lock;
	lock_descriptor_t	*graph_head;
	locklist_t		listhead;
	locklist_t		*llheadp;
	locklist_t		*llp;
	locklist_t		*lltp;
	graph_t			*gp;
	int			i;
	int			first_index; /* graph index */
	int			num_indexes; /* graph index */

	ASSERT((list_type == FLK_ACTIVE_STATE) ||
	    (list_type == FLK_SLEEPING_STATE));

	/*
	 * Get a pointer to something to use as a list head while building
	 * the rest of the list.
	 */
	llheadp = &listhead;
	lltp = llheadp;
	llheadp->ll_next = (locklist_t *)NULL;

	/* Figure out which graphs we want to look at. */
	if (vp == NULL) {
		first_index = 0;
		num_indexes = HASH_SIZE;
	} else {
		first_index = HASH_INDEX(vp);
		num_indexes = 1;
	}

	for (i = first_index; i < first_index + num_indexes; i++) {
		mutex_enter(&flock_lock);
		gp = lock_graph[i];
		mutex_exit(&flock_lock);
		if (gp == NULL) {
			continue;
		}

		mutex_enter(&gp->gp_mutex);
		graph_head = (list_type == FLK_ACTIVE_STATE) ?
		    ACTIVE_HEAD(gp) : SLEEPING_HEAD(gp);
		for (lock = graph_head->l_next;
		    lock != graph_head;
		    lock = lock->l_next) {
			if (use_sysid && lock->l_flock.l_sysid != sysid)
				continue;
			if (pid != NOPID && lock->l_flock.l_pid != pid)
				continue;
			if (vp != NULL && lock->l_vnode != vp)
				continue;
			if (lock_state && !(lock_state & lock->l_state))
				continue;
			if (zoneid != lock->l_zoneid && zoneid != ALL_ZONES)
				continue;
			/*
			 * A matching lock was found.  Allocate
			 * space for a new locklist entry and fill
			 * it in.
			 */
			llp = kmem_alloc(sizeof (locklist_t), KM_SLEEP);
			lltp->ll_next = llp;
			VN_HOLD(lock->l_vnode);
			llp->ll_vp = lock->l_vnode;
			create_flock(lock, &(llp->ll_flock));
			llp->ll_next = (locklist_t *)NULL;
			lltp = llp;
		}
		mutex_exit(&gp->gp_mutex);
	}

	llp = llheadp->ll_next;
	return (llp);
}

/*
 * These two functions are simply interfaces to get_lock_list.  They return
 * a list of sleeping or active locks for the given sysid and pid.  See
 * get_lock_list for details.
 *
 * In either case we don't particularly care to specify the zone of interest;
 * the sysid-space is global across zones, so the sysid will map to exactly one
 * zone, and we'll return information for that zone.
 */

locklist_t *
flk_get_sleeping_locks(int sysid, pid_t pid)
{
	return (get_lock_list(FLK_SLEEPING_STATE, 0, sysid, B_TRUE, pid, NULL,
	    ALL_ZONES));
}

locklist_t *
flk_get_active_locks(int sysid, pid_t pid)
{
	return (get_lock_list(FLK_ACTIVE_STATE, 0, sysid, B_TRUE, pid, NULL,
	    ALL_ZONES));
}

/*
 * Another interface to get_lock_list.  This one returns all the active
 * locks for a given vnode.  Again, see get_lock_list for details.
 *
 * We don't need to specify which zone's locks we're interested in.  The matter
 * would only be interesting if the vnode belonged to NFS, and NFS vnodes can't
 * be used by multiple zones, so the list of locks will all be from the right
 * zone.
 */

locklist_t *
flk_active_locks_for_vp(const vnode_t *vp)
{
	return (get_lock_list(FLK_ACTIVE_STATE, 0, 0, B_FALSE, NOPID, vp,
	    ALL_ZONES));
}

/*
 * Another interface to get_lock_list.  This one returns all the active
 * nbmand locks for a given vnode.  Again, see get_lock_list for details.
 *
 * See the comment for flk_active_locks_for_vp() for why we don't care to
 * specify the particular zone of interest.
 */
locklist_t *
flk_active_nbmand_locks_for_vp(const vnode_t *vp)
{
	return (get_lock_list(FLK_ACTIVE_STATE, NBMAND_LOCK, 0, B_FALSE,
	    NOPID, vp, ALL_ZONES));
}

/*
 * Another interface to get_lock_list.  This one returns all the active
 * nbmand locks for a given pid.  Again, see get_lock_list for details.
 *
 * The zone doesn't need to be specified here; the locks held by a
 * particular process will either be local (ie, non-NFS) or from the zone
 * the process is executing in.  This is because other parts of the system
 * ensure that an NFS vnode can't be used in a zone other than that in
 * which it was opened.
 */
locklist_t *
flk_active_nbmand_locks(pid_t pid)
{
	return (get_lock_list(FLK_ACTIVE_STATE, NBMAND_LOCK, 0, B_FALSE,
	    pid, NULL, ALL_ZONES));
}

/*
 * Free up all entries in the locklist.
 */
void
flk_free_locklist(locklist_t *llp)
{
	locklist_t *next_llp;

	while (llp) {
		next_llp = llp->ll_next;
		VN_RELE(llp->ll_vp);
		kmem_free(llp, sizeof (*llp));
		llp = next_llp;
	}
}

static void
cl_flk_change_nlm_state_all_locks(int nlmid, flk_nlm_status_t nlm_state)
{
	/*
	 * For each graph "lg" in the hash table lock_graph do
	 * a.  Get the list of sleeping locks
	 * b.  For each lock descriptor in the list do
	 *	i.   If the requested lock is an NLM server request AND
	 *		the nlmid is the same as the routine argument then
	 *		change the lock descriptor's state field to
	 *		"nlm_state."
	 * c.  Get the list of active locks
	 * d.  For each lock descriptor in the list do
	 *	i.   If the requested lock is an NLM server request AND
	 *		the nlmid is the same as the routine argument then
	 *		change the lock descriptor's state field to
	 *		"nlm_state."
	 */

	int			i;
	graph_t			*gp;			/* lock graph */
	lock_descriptor_t	*lock;			/* lock */
	lock_descriptor_t	*nlock = NULL;		/* next lock */
	int			lock_nlmid;

	for (i = 0; i < HASH_SIZE; i++) {
		mutex_enter(&flock_lock);
		gp = lock_graph[i];
		mutex_exit(&flock_lock);
		if (gp == NULL) {
			continue;
		}

		/* Get list of sleeping locks in current lock graph. */
		mutex_enter(&gp->gp_mutex);
		for (lock = SLEEPING_HEAD(gp)->l_next;
		    lock != SLEEPING_HEAD(gp);
		    lock = nlock) {
			nlock = lock->l_next;
			/* get NLM id */
			lock_nlmid = GETNLMID(lock->l_flock.l_sysid);

			/*
			 * If NLM server request AND nlmid of lock matches
			 * nlmid of argument, then set the NLM state of the
			 * lock to "nlm_state."
			 */
			if (IS_LOCKMGR(lock) && nlmid == lock_nlmid) {
				SET_NLM_STATE(lock, nlm_state);
			}
		}

		/* Get list of active locks in current lock graph. */
		for (lock = ACTIVE_HEAD(gp)->l_next;
		    lock != ACTIVE_HEAD(gp);
		    lock = nlock) {
			nlock = lock->l_next;
			/* get NLM id */
			lock_nlmid = GETNLMID(lock->l_flock.l_sysid);

			/*
			 * If NLM server request AND nlmid of lock matches
			 * nlmid of argument, then set the NLM state of the
			 * lock to "nlm_state."
			 */
			if (IS_LOCKMGR(lock) && nlmid == lock_nlmid) {
				ASSERT(IS_ACTIVE(lock));
				SET_NLM_STATE(lock, nlm_state);
			}
		}
		mutex_exit(&gp->gp_mutex);
	}
}

/*
 * Requires: "nlmid" >= 1 and <= clconf_maximum_nodeid().
 * Effects: Find all sleeping lock manager requests _only_ for the NLM server
 *   identified by "nlmid." Poke those lock requests.
 */
static void
cl_flk_wakeup_sleeping_nlm_locks(int nlmid)
{
	lock_descriptor_t *lock;
	lock_descriptor_t *nlock = NULL; /* next lock */
	int i;
	graph_t *gp;
	int	lock_nlmid;

	for (i = 0; i < HASH_SIZE; i++) {
		mutex_enter(&flock_lock);
		gp = lock_graph[i];
		mutex_exit(&flock_lock);
		if (gp == NULL) {
			continue;
		}

		mutex_enter(&gp->gp_mutex);
		for (lock = SLEEPING_HEAD(gp)->l_next;
		    lock != SLEEPING_HEAD(gp);
		    lock = nlock) {
			nlock = lock->l_next;
			/*
			 * If NLM server request _and_ nlmid of lock matches
			 * nlmid of argument, then set the NLM state of the
			 * lock to NLM_SHUTTING_DOWN, and wake up sleeping
			 * request.
			 */
			if (IS_LOCKMGR(lock)) {
				/* get NLM id */
				lock_nlmid =
				    GETNLMID(lock->l_flock.l_sysid);
				if (nlmid == lock_nlmid) {
					SET_NLM_STATE(lock,
					    FLK_NLM_SHUTTING_DOWN);
					INTERRUPT_WAKEUP(lock);
				}
			}
		}
		mutex_exit(&gp->gp_mutex);
	}
}

/*
 * Requires: "nlmid" >= 1 and <= clconf_maximum_nodeid()
 * Effects:  Find all active (granted) lock manager locks _only_ for the
 *   NLM server identified by "nlmid" and release them.
 */
static void
cl_flk_unlock_nlm_granted(int nlmid)
{
	lock_descriptor_t *lock;
	lock_descriptor_t *nlock = NULL; /* next lock */
	int i;
	graph_t *gp;
	int	lock_nlmid;

	for (i = 0; i < HASH_SIZE; i++) {
		mutex_enter(&flock_lock);
		gp = lock_graph[i];
		mutex_exit(&flock_lock);
		if (gp == NULL) {
			continue;
		}

		mutex_enter(&gp->gp_mutex);
		for (lock = ACTIVE_HEAD(gp)->l_next;
		    lock != ACTIVE_HEAD(gp);
		    lock = nlock) {
			nlock = lock->l_next;
			ASSERT(IS_ACTIVE(lock));

			/*
			 * If it's an  NLM server request _and_ nlmid of
			 * the lock matches nlmid of argument, then
			 * remove the active lock the list, wakup blocked
			 * threads, and free the storage for the lock.
			 * Note that there's no need to mark the NLM state
			 * of this lock to NLM_DOWN because the lock will
			 * be deleted anyway and its storage freed.
			 */
			if (IS_LOCKMGR(lock)) {
				/* get NLM id */
				lock_nlmid = GETNLMID(lock->l_flock.l_sysid);
				if (nlmid == lock_nlmid) {
					flk_delete_active_lock(lock, 0);
					flk_wakeup(lock, 1);
					flk_free_lock(lock);
				}
			}
		}
		mutex_exit(&gp->gp_mutex);
	}
}

/*
 * Find all sleeping lock manager requests and poke them.
 */
static void
wakeup_sleeping_lockmgr_locks(struct flock_globals *fg)
{
	lock_descriptor_t *lock;
	lock_descriptor_t *nlock = NULL; /* next lock */
	int i;
	graph_t *gp;
	zoneid_t zoneid = getzoneid();

	for (i = 0; i < HASH_SIZE; i++) {
		mutex_enter(&flock_lock);
		gp = lock_graph[i];
		mutex_exit(&flock_lock);
		if (gp == NULL) {
			continue;
		}

		mutex_enter(&gp->gp_mutex);
		fg->lockmgr_status[i] = FLK_WAKEUP_SLEEPERS;
		for (lock = SLEEPING_HEAD(gp)->l_next;
		    lock != SLEEPING_HEAD(gp);
		    lock = nlock) {
			nlock = lock->l_next;
			if (IS_LOCKMGR(lock) && lock->l_zoneid == zoneid) {
				INTERRUPT_WAKEUP(lock);
			}
		}
		mutex_exit(&gp->gp_mutex);
	}
}


/*
 * Find all active (granted) lock manager locks and release them.
 */
static void
unlock_lockmgr_granted(struct flock_globals *fg)
{
	lock_descriptor_t *lock;
	lock_descriptor_t *nlock = NULL; /* next lock */
	int i;
	graph_t *gp;
	zoneid_t zoneid = getzoneid();

	for (i = 0; i < HASH_SIZE; i++) {
		mutex_enter(&flock_lock);
		gp = lock_graph[i];
		mutex_exit(&flock_lock);
		if (gp == NULL) {
			continue;
		}

		mutex_enter(&gp->gp_mutex);
		fg->lockmgr_status[i] = FLK_LOCKMGR_DOWN;
		for (lock = ACTIVE_HEAD(gp)->l_next;
		    lock != ACTIVE_HEAD(gp);
		    lock = nlock) {
			nlock = lock->l_next;
			if (IS_LOCKMGR(lock) && lock->l_zoneid == zoneid) {
				ASSERT(IS_ACTIVE(lock));
				flk_delete_active_lock(lock, 0);
				flk_wakeup(lock, 1);
				flk_free_lock(lock);
			}
		}
		mutex_exit(&gp->gp_mutex);
	}
}


/*
 * Wait until a lock is granted, cancelled, or interrupted.
 */

static void
wait_for_lock(lock_descriptor_t *request)
{
	graph_t *gp = request->l_graph;

	ASSERT(MUTEX_HELD(&gp->gp_mutex));

	while (!(IS_GRANTED(request)) && !(IS_CANCELLED(request)) &&
	    !(IS_INTERRUPTED(request))) {
		if (!cv_wait_sig(&request->l_cv, &gp->gp_mutex)) {
			flk_set_state(request, FLK_INTERRUPTED_STATE);
			request->l_state |= INTERRUPTED_LOCK;
		}
	}
}

/*
 * Create an flock structure from the existing lock information
 *
 * This routine is used to create flock structures for the lock manager
 * to use in a reclaim request.  Since the lock was originated on this
 * host, it must be conforming to UNIX semantics, so no checking is
 * done to make sure it falls within the lower half of the 32-bit range.
 */

static void
create_flock(lock_descriptor_t *lp, flock64_t *flp)
{
	ASSERT(lp->l_end == MAX_U_OFFSET_T || lp->l_end <= MAXEND);
	ASSERT(lp->l_end >= lp->l_start);

	flp->l_type = lp->l_type;
	flp->l_whence = 0;
	flp->l_start = lp->l_start;
	flp->l_len = (lp->l_end == MAX_U_OFFSET_T) ? 0 :
	    (lp->l_end - lp->l_start + 1);
	flp->l_sysid = lp->l_flock.l_sysid;
	flp->l_pid = lp->l_flock.l_pid;
}

/*
 * Convert flock_t data describing a lock range into unsigned long starting
 * and ending points, which are put into lock_request.  Returns 0 or an
 * errno value.
 * Large Files: max is passed by the caller and we return EOVERFLOW
 * as defined by LFS API.
 */

int
flk_convert_lock_data(vnode_t *vp, flock64_t *flp,
    u_offset_t *start, u_offset_t *end, offset_t offset)
{
	struct vattr	vattr;
	int	error;

	/*
	 * Determine the starting point of the request
	 */
	switch (flp->l_whence) {
	case 0:		/* SEEK_SET */
		*start = (u_offset_t)flp->l_start;
		break;
	case 1:		/* SEEK_CUR */
		*start = (u_offset_t)(flp->l_start + offset);
		break;
	case 2:		/* SEEK_END */
		vattr.va_mask = AT_SIZE;
		if (error = VOP_GETATTR(vp, &vattr, 0, CRED(), NULL))
			return (error);
		*start = (u_offset_t)(flp->l_start + vattr.va_size);
		break;
	default:
		return (EINVAL);
	}

	/*
	 * Determine the range covered by the request.
	 */
	if (flp->l_len == 0)
		*end = MAX_U_OFFSET_T;
	else if ((offset_t)flp->l_len > 0) {
		*end = (u_offset_t)(*start + (flp->l_len - 1));
	} else {
		/*
		 * Negative length; why do we even allow this ?
		 * Because this allows easy specification of
		 * the last n bytes of the file.
		 */
		*end = *start;
		*start += (u_offset_t)flp->l_len;
		(*start)++;
	}
	return (0);
}

/*
 * Check the validity of lock data.  This can used by the NFS
 * frlock routines to check data before contacting the server.  The
 * server must support semantics that aren't as restrictive as
 * the UNIX API, so the NFS client is required to check.
 * The maximum is now passed in by the caller.
 */

int
flk_check_lock_data(u_offset_t start, u_offset_t end, offset_t max)
{
	/*
	 * The end (length) for local locking should never be greater
	 * than MAXEND. However, the representation for
	 * the entire file is MAX_U_OFFSET_T.
	 */
	if ((start > max) ||
	    ((end > max) && (end != MAX_U_OFFSET_T))) {
		return (EINVAL);
	}
	if (start > end) {
		return (EINVAL);
	}
	return (0);
}

/*
 * Fill in request->l_flock with information about the lock blocking the
 * request.  The complexity here is that lock manager requests are allowed
 * to see into the upper part of the 32-bit address range, whereas local
 * requests are only allowed to see signed values.
 *
 * What should be done when "blocker" is a lock manager lock that uses the
 * upper portion of the 32-bit range, but "request" is local?  Since the
 * request has already been determined to have been blocked by the blocker,
 * at least some portion of "blocker" must be in the range of the request,
 * or the request extends to the end of file.  For the first case, the
 * portion in the lower range is returned with the indication that it goes
 * "to EOF."  For the second case, the last byte of the lower range is
 * returned with the indication that it goes "to EOF."
 */

static void
report_blocker(lock_descriptor_t *blocker, lock_descriptor_t *request)
{
	flock64_t *flrp;			/* l_flock portion of request */

	ASSERT(blocker != NULL);

	flrp = &request->l_flock;
	flrp->l_whence = 0;
	flrp->l_type = blocker->l_type;
	flrp->l_pid = blocker->l_flock.l_pid;
	flrp->l_sysid = blocker->l_flock.l_sysid;
	request->l_ofd = blocker->l_ofd;

	if (IS_LOCKMGR(request)) {
		flrp->l_start = blocker->l_start;
		if (blocker->l_end == MAX_U_OFFSET_T)
			flrp->l_len = 0;
		else
			flrp->l_len = blocker->l_end - blocker->l_start + 1;
	} else {
		if (blocker->l_start > MAXEND) {
			flrp->l_start = MAXEND;
			flrp->l_len = 0;
		} else {
			flrp->l_start = blocker->l_start;
			if (blocker->l_end == MAX_U_OFFSET_T)
				flrp->l_len = 0;
			else
				flrp->l_len = blocker->l_end -
				    blocker->l_start + 1;
		}
	}
}

/*
 * PSARC case 1997/292
 */
/*
 * This is the public routine exported by flock.h.
 */
void
cl_flk_change_nlm_state_to_unknown(int nlmid)
{
	/*
	 * Check to see if node is booted as a cluster. If not, return.
	 */
	if ((cluster_bootflags & CLUSTER_BOOTED) == 0) {
		return;
	}

	/*
	 * See comment in cl_flk_set_nlm_status().
	 */
	if (nlm_reg_status == NULL) {
		return;
	}

	/*
	 * protect NLM registry state with a mutex.
	 */
	ASSERT(nlmid <= nlm_status_size && nlmid >= 0);
	mutex_enter(&nlm_reg_lock);
	FLK_REGISTRY_CHANGE_NLM_STATE(nlm_reg_status, nlmid, FLK_NLM_UNKNOWN);
	mutex_exit(&nlm_reg_lock);
}

/*
 * Return non-zero if the given I/O request conflicts with an active NBMAND
 * lock.
 * If svmand is non-zero, it means look at all active locks, not just NBMAND
 * locks.
 */

int
nbl_lock_conflict(vnode_t *vp, nbl_op_t op, u_offset_t offset,
		ssize_t length, int svmand, caller_context_t *ct)
{
	int conflict = 0;
	graph_t			*gp;
	lock_descriptor_t	*lock;
	pid_t pid;
	int sysid;

	if (ct == NULL) {
		pid = curproc->p_pid;
		sysid = 0;
	} else {
		pid = ct->cc_pid;
		sysid = ct->cc_sysid;
	}

	mutex_enter(&flock_lock);
	gp = lock_graph[HASH_INDEX(vp)];
	mutex_exit(&flock_lock);
	if (gp == NULL)
		return (0);

	mutex_enter(&gp->gp_mutex);
	SET_LOCK_TO_FIRST_ACTIVE_VP(gp, lock, vp);

	for (; lock && lock->l_vnode == vp; lock = lock->l_next) {
		if ((svmand || (lock->l_state & NBMAND_LOCK)) &&
		    (lock->l_flock.l_sysid != sysid ||
		    lock->l_flock.l_pid != pid) &&
		    lock_blocks_io(op, offset, length,
		    lock->l_type, lock->l_start, lock->l_end)) {
			conflict = 1;
			break;
		}
	}
	mutex_exit(&gp->gp_mutex);

	return (conflict);
}

/*
 * Return non-zero if the given I/O request conflicts with the given lock.
 */

static int
lock_blocks_io(nbl_op_t op, u_offset_t offset, ssize_t length,
	    int lock_type, u_offset_t lock_start, u_offset_t lock_end)
{
	ASSERT(op == NBL_READ || op == NBL_WRITE || op == NBL_READWRITE);
	ASSERT(lock_type == F_RDLCK || lock_type == F_WRLCK);

	if (op == NBL_READ && lock_type == F_RDLCK)
		return (0);

	if (offset <= lock_start && lock_start < offset + length)
		return (1);
	if (lock_start <= offset && offset <= lock_end)
		return (1);

	return (0);
}

#ifdef DEBUG
static void
check_active_locks(graph_t *gp)
{
	lock_descriptor_t *lock, *lock1;
	edge_t	*ep;

	for (lock = ACTIVE_HEAD(gp)->l_next; lock != ACTIVE_HEAD(gp);
	    lock = lock->l_next) {
		ASSERT(IS_ACTIVE(lock));
		ASSERT(NOT_BLOCKED(lock));
		ASSERT(!IS_BARRIER(lock));

		ep = FIRST_IN(lock);

		while (ep != HEAD(lock)) {
			ASSERT(IS_SLEEPING(ep->from_vertex));
			ASSERT(!NOT_BLOCKED(ep->from_vertex));
			ep = NEXT_IN(ep);
		}

		for (lock1 = lock->l_next; lock1 != ACTIVE_HEAD(gp);
		    lock1 = lock1->l_next) {
			if (lock1->l_vnode == lock->l_vnode) {
			if (BLOCKS(lock1, lock)) {
				cmn_err(CE_PANIC,
				    "active lock %p blocks %p",
				    (void *)lock1, (void *)lock);
			} else if (BLOCKS(lock, lock1)) {
				cmn_err(CE_PANIC,
				    "active lock %p blocks %p",
				    (void *)lock, (void *)lock1);
			}
			}
		}
	}
}

/*
 * Effect: This functions checks to see if the transition from 'old_state' to
 *	'new_state' is a valid one.  It returns 0 if the transition is valid
 *	and 1 if it is not.
 *	For a map of valid transitions, see sys/flock_impl.h
 */
static int
check_lock_transition(int old_state, int new_state)
{
	switch (old_state) {
	case FLK_INITIAL_STATE:
		if ((new_state == FLK_START_STATE) ||
		    (new_state == FLK_SLEEPING_STATE) ||
		    (new_state == FLK_ACTIVE_STATE) ||
		    (new_state == FLK_DEAD_STATE)) {
			return (0);
		} else {
			return (1);
		}
	case FLK_START_STATE:
		if ((new_state == FLK_ACTIVE_STATE) ||
		    (new_state == FLK_DEAD_STATE)) {
			return (0);
		} else {
			return (1);
		}
	case FLK_ACTIVE_STATE:
		if (new_state == FLK_DEAD_STATE) {
			return (0);
		} else {
			return (1);
		}
	case FLK_SLEEPING_STATE:
		if ((new_state == FLK_GRANTED_STATE) ||
		    (new_state == FLK_INTERRUPTED_STATE) ||
		    (new_state == FLK_CANCELLED_STATE)) {
			return (0);
		} else {
			return (1);
		}
	case FLK_GRANTED_STATE:
		if ((new_state == FLK_START_STATE) ||
		    (new_state == FLK_INTERRUPTED_STATE) ||
		    (new_state == FLK_CANCELLED_STATE)) {
			return (0);
		} else {
			return (1);
		}
	case FLK_CANCELLED_STATE:
		if ((new_state == FLK_INTERRUPTED_STATE) ||
		    (new_state == FLK_DEAD_STATE)) {
			return (0);
		} else {
			return (1);
		}
	case FLK_INTERRUPTED_STATE:
		if (new_state == FLK_DEAD_STATE) {
			return (0);
		} else {
			return (1);
		}
	case FLK_DEAD_STATE:
		/* May be set more than once */
		if (new_state == FLK_DEAD_STATE) {
			return (0);
		} else {
			return (1);
		}
	default:
		return (1);
	}
}

static void
check_sleeping_locks(graph_t *gp)
{
	lock_descriptor_t *lock1, *lock2;
	edge_t *ep;
	for (lock1 = SLEEPING_HEAD(gp)->l_next; lock1 != SLEEPING_HEAD(gp);
	    lock1 = lock1->l_next) {
				ASSERT(!IS_BARRIER(lock1));
	for (lock2 = lock1->l_next; lock2 != SLEEPING_HEAD(gp);
	    lock2 = lock2->l_next) {
		if (lock1->l_vnode == lock2->l_vnode) {
			if (BLOCKS(lock2, lock1)) {
				ASSERT(!IS_GRANTED(lock1));
				ASSERT(!NOT_BLOCKED(lock1));
				path(lock1, lock2);
			}
		}
	}

	for (lock2 = ACTIVE_HEAD(gp)->l_next; lock2 != ACTIVE_HEAD(gp);
	    lock2 = lock2->l_next) {
				ASSERT(!IS_BARRIER(lock1));
		if (lock1->l_vnode == lock2->l_vnode) {
			if (BLOCKS(lock2, lock1)) {
				ASSERT(!IS_GRANTED(lock1));
				ASSERT(!NOT_BLOCKED(lock1));
				path(lock1, lock2);
			}
		}
	}
	ep = FIRST_ADJ(lock1);
	while (ep != HEAD(lock1)) {
		ASSERT(BLOCKS(ep->to_vertex, lock1));
		ep = NEXT_ADJ(ep);
	}
	}
}

static int
level_two_path(lock_descriptor_t *lock1, lock_descriptor_t *lock2, int no_path)
{
	edge_t	*ep;
	lock_descriptor_t	*vertex;
	lock_descriptor_t *vertex_stack;

	STACK_INIT(vertex_stack);

	flk_graph_uncolor(lock1->l_graph);
	ep = FIRST_ADJ(lock1);
	ASSERT(ep != HEAD(lock1));
	while (ep != HEAD(lock1)) {
		if (no_path)
			ASSERT(ep->to_vertex != lock2);
		STACK_PUSH(vertex_stack, ep->to_vertex, l_dstack);
		COLOR(ep->to_vertex);
		ep = NEXT_ADJ(ep);
	}

	while ((vertex = STACK_TOP(vertex_stack)) != NULL) {
		STACK_POP(vertex_stack, l_dstack);
		for (ep = FIRST_ADJ(vertex); ep != HEAD(vertex);
		    ep = NEXT_ADJ(ep)) {
			if (COLORED(ep->to_vertex))
				continue;
			COLOR(ep->to_vertex);
			if (ep->to_vertex == lock2)
				return (1);

			STACK_PUSH(vertex_stack, ep->to_vertex, l_dstack);
		}
	}
	return (0);
}

static void
check_owner_locks(graph_t *gp, pid_t pid, int sysid, vnode_t *vp)
{
	lock_descriptor_t *lock;

	/* Ignore OFD style locks since they're not process-wide. */
	if (pid == 0)
		return;

	SET_LOCK_TO_FIRST_ACTIVE_VP(gp, lock, vp);

	if (lock) {
		while (lock != ACTIVE_HEAD(gp) && (lock->l_vnode == vp)) {
			if (lock->l_flock.l_pid == pid &&
			    lock->l_flock.l_sysid == sysid)
				cmn_err(CE_PANIC,
				    "owner pid %d's lock %p in active queue",
				    pid, (void *)lock);
			lock = lock->l_next;
		}
	}
	SET_LOCK_TO_FIRST_SLEEP_VP(gp, lock, vp);

	if (lock) {
		while (lock != SLEEPING_HEAD(gp) && (lock->l_vnode == vp)) {
			if (lock->l_flock.l_pid == pid &&
			    lock->l_flock.l_sysid == sysid)
				cmn_err(CE_PANIC,
				    "owner pid %d's lock %p in sleep queue",
				    pid, (void *)lock);
			lock = lock->l_next;
		}
	}
}

static int
level_one_path(lock_descriptor_t *lock1, lock_descriptor_t *lock2)
{
	edge_t *ep = FIRST_ADJ(lock1);

	while (ep != HEAD(lock1)) {
		if (ep->to_vertex == lock2)
			return (1);
		else
			ep = NEXT_ADJ(ep);
	}
	return (0);
}

static int
no_path(lock_descriptor_t *lock1, lock_descriptor_t *lock2)
{
	return (!level_two_path(lock1, lock2, 1));
}

static void
path(lock_descriptor_t *lock1, lock_descriptor_t *lock2)
{
	if (level_one_path(lock1, lock2)) {
		if (level_two_path(lock1, lock2, 0) != 0) {
			cmn_err(CE_WARN,
			    "one edge one path from lock1 %p lock2 %p",
			    (void *)lock1, (void *)lock2);
		}
	} else if (no_path(lock1, lock2)) {
		cmn_err(CE_PANIC,
		    "No path from  lock1 %p to lock2 %p",
		    (void *)lock1, (void *)lock2);
	}
}
#endif /* DEBUG */
