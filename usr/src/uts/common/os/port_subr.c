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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file containts all the functions required for interactions of
 * event sources with the event port file system.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/file.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/bitmap.h>
#include <sys/rctl.h>
#include <sys/atomic.h>
#include <sys/poll_impl.h>
#include <sys/port_impl.h>

/*
 * Maximum number of elements allowed to be passed in a single call of a
 * port function (port_sendn(), port_getn().  We need to allocate kernel memory
 * for all of them at once, so we can't let it scale without limit.
 */
uint_t		port_max_list = PORT_MAX_LIST;
port_control_t	port_control;	/* Event port framework main structure */

/*
 * Block other threads from using a port.
 * We enter holding portq->portq_mutex but
 * we may drop and reacquire this lock.
 * Callers must deal with this fact.
 */
void
port_block(port_queue_t *portq)
{
	ASSERT(MUTEX_HELD(&portq->portq_mutex));

	while (portq->portq_flags & PORTQ_BLOCKED)
		cv_wait(&portq->portq_block_cv, &portq->portq_mutex);
	portq->portq_flags |= PORTQ_BLOCKED;
}

/*
 * Undo port_block(portq).
 */
void
port_unblock(port_queue_t *portq)
{
	ASSERT(MUTEX_HELD(&portq->portq_mutex));

	portq->portq_flags &= ~PORTQ_BLOCKED;
	cv_signal(&portq->portq_block_cv);
}

/*
 * Called from pollwakeup(PORT_SOURCE_FD source) to determine
 * if the port's fd needs to be notified of poll events. If yes,
 * we mark the port indicating that pollwakeup() is referring
 * it so that the port_t does not disappear.  pollwakeup()
 * calls port_pollwkdone() after notifying. In port_pollwkdone(),
 * we clear the hold on the port_t (clear PORTQ_POLLWK_PEND).
 */
int
port_pollwkup(port_t *pp)
{
	int events = 0;
	port_queue_t *portq;
	portq = &pp->port_queue;
	mutex_enter(&portq->portq_mutex);

	/*
	 * Normally, we should not have a situation where PORTQ_POLLIN
	 * and PORTQ_POLLWK_PEND are set at the same time, but it is
	 * possible. So, in pollwakeup() we ensure that no new fd's get
	 * added to the pollhead between the time it notifies poll events
	 * and calls poll_wkupdone() where we clear the PORTQ_POLLWK_PEND flag.
	 */
	if (portq->portq_flags & PORTQ_POLLIN &&
	    !(portq->portq_flags & PORTQ_POLLWK_PEND)) {
		portq->portq_flags &= ~PORTQ_POLLIN;
		portq->portq_flags |= PORTQ_POLLWK_PEND;
		events = POLLIN;
	}
	mutex_exit(&portq->portq_mutex);
	return (events);
}

void
port_pollwkdone(port_t *pp)
{
	port_queue_t *portq;
	portq = &pp->port_queue;
	ASSERT(portq->portq_flags & PORTQ_POLLWK_PEND);
	mutex_enter(&portq->portq_mutex);
	portq->portq_flags &= ~PORTQ_POLLWK_PEND;
	cv_signal(&pp->port_cv);
	mutex_exit(&portq->portq_mutex);
}


/*
 * The port_send_event() function is used by all event sources to submit
 * trigerred events to a port. All the data  required for the event management
 * is already stored in the port_kevent_t structure.
 * The event port internal data is stored in the port_kevent_t structure
 * during the allocation time (see port_alloc_event()). The data related to
 * the event itself and to the event source management is stored in the
 * port_kevent_t structure between the allocation time and submit time
 * (see port_init_event()).
 *
 * This function is often called from interrupt level.
 */
void
port_send_event(port_kevent_t *pkevp)
{
	port_queue_t	*portq;

	portq = &pkevp->portkev_port->port_queue;
	mutex_enter(&portq->portq_mutex);

	if (pkevp->portkev_flags & PORT_KEV_DONEQ) {
		/* Event already in the port queue */
		if (pkevp->portkev_source == PORT_SOURCE_FD) {
			mutex_exit(&pkevp->portkev_lock);
		}
		mutex_exit(&portq->portq_mutex);
		return;
	}

	/* put event in the port queue */
	list_insert_tail(&portq->portq_list, pkevp);
	portq->portq_nent++;

	/*
	 * Remove the PORTQ_WAIT_EVENTS flag to indicate
	 * that new events are available.
	 */
	portq->portq_flags &= ~PORTQ_WAIT_EVENTS;
	pkevp->portkev_flags |= PORT_KEV_DONEQ;		/* event enqueued */

	if (pkevp->portkev_source == PORT_SOURCE_FD) {
		mutex_exit(&pkevp->portkev_lock);
	}

	/* Check if thread is in port_close() waiting for outstanding events */
	if (portq->portq_flags & PORTQ_CLOSE) {
		/* Check if all outstanding events are already in port queue */
		if (pkevp->portkev_port->port_curr <= portq->portq_nent)
			cv_signal(&portq->portq_closecv);
	}

	if (portq->portq_getn == 0) {
		/*
		 * No thread retrieving events -> check if enough events are
		 * available to satify waiting threads.
		 */
		if (portq->portq_thread &&
		    (portq->portq_nent >= portq->portq_nget))
			cv_signal(&portq->portq_thread->portget_cv);
	}

	/*
	 * If some thread is polling the port's fd, then notify it.
	 * For PORT_SOURCE_FD source, we don't need to call pollwakeup()
	 * here as it will result in a recursive call(PORT_SOURCE_FD source
	 * is pollwakeup()). Therefore pollwakeup() itself will  notify the
	 * ports if being polled.
	 */
	if (pkevp->portkev_source != PORT_SOURCE_FD &&
	    portq->portq_flags & PORTQ_POLLIN) {
		port_t	*pp;

		portq->portq_flags &= ~PORTQ_POLLIN;
		/*
		 * Need to save port_t for calling pollwakeup since port_getn()
		 * may end up freeing pkevp once portq_mutex is dropped.
		 */
		pp = pkevp->portkev_port;
		mutex_exit(&portq->portq_mutex);
		pollwakeup(&pp->port_pollhd, POLLIN);
	} else {
		mutex_exit(&portq->portq_mutex);
	}
}

/*
 * The port_alloc_event() function has to be used by all event sources
 * to request an slot for event notification.
 * The slot reservation could be denied because of lack of resources.
 * For that reason the event source should allocate an event slot as early
 * as possible and be prepared to get an error code instead of the
 * port event pointer.
 * Al current event sources allocate an event slot during a system call
 * entry. They return an error code to the application if an event slot
 * could not be reserved.
 * It is also recommended to associate the event source with the port
 * before some other port function is used.
 * The port argument is a file descriptor obtained by the application as
 * a return value of port_create().
 * Possible values of flags are:
 * PORT_ALLOC_DEFAULT
 *	This is the standard type of port events. port_get(n) will free this
 *	type of event structures as soon as the events are delivered to the
 *	application.
 * PORT_ALLOC_PRIVATE
 *	This type of event will be use for private use of the event source.
 *	The port_get(n) function will deliver events of such an structure to
 *	the application but it will not free the event structure itself.
 *	The event source must free this structure using port_free_event().
 * PORT_ALLOC_CACHED
 *	This type of events is used when the event source helds an own
 *	cache.
 *	The port_get(n) function will deliver events of such an structure to
 *	the application but it will not free the event structure itself.
 *	The event source must free this structure using port_free_event().
 */
int
port_alloc_event(int port, int flags, int source, port_kevent_t **pkevpp)
{
	port_t		*pp;
	file_t		*fp;
	port_kevent_t	*pkevp;

	if ((fp = getf(port)) == NULL)
		return (EBADF);

	if (fp->f_vnode->v_type != VPORT) {
		releasef(port);
		return (EBADFD);
	}

	pkevp = kmem_cache_alloc(port_control.pc_cache, KM_NOSLEEP);
	if (pkevp == NULL) {
		releasef(port);
		return (ENOMEM);
	}

	/*
	 * port_max_events is controlled by the resource control
	 * process.port-max-events
	 */
	pp = VTOEP(fp->f_vnode);
	mutex_enter(&pp->port_queue.portq_mutex);
	if (pp->port_curr >= pp->port_max_events) {
		mutex_exit(&pp->port_queue.portq_mutex);
		kmem_cache_free(port_control.pc_cache, pkevp);
		releasef(port);
		return (EAGAIN);
	}
	pp->port_curr++;
	mutex_exit(&pp->port_queue.portq_mutex);

	bzero(pkevp, sizeof (port_kevent_t));
	mutex_init(&pkevp->portkev_lock, NULL, MUTEX_DEFAULT, NULL);
	pkevp->portkev_source = source;
	pkevp->portkev_flags = flags;
	pkevp->portkev_pid = curproc->p_pid;
	pkevp->portkev_port = pp;
	*pkevpp = pkevp;
	releasef(port);
	return (0);
}

/*
 * This function is faster than the standard port_alloc_event() and
 * can be used when the event source already allocated an event from
 * a port.
 */
int
port_dup_event(port_kevent_t *pkevp, port_kevent_t **pkevdupp, int flags)
{
	int	error;

	error = port_alloc_event_local(pkevp->portkev_port,
	    pkevp->portkev_source, flags, pkevdupp);
	if (error == 0)
		(*pkevdupp)->portkev_pid = pkevp->portkev_pid;
	return (error);
}

/*
 * port_alloc_event_local() is reserved for internal use only.
 * It is doing the same job as port_alloc_event() but with the event port
 * pointer as the first argument.
 * The check of the validity of the port file descriptor is skipped here.
 */
int
port_alloc_event_local(port_t *pp, int source, int flags,
    port_kevent_t **pkevpp)
{
	port_kevent_t	*pkevp;

	pkevp = kmem_cache_alloc(port_control.pc_cache, KM_NOSLEEP);
	if (pkevp == NULL)
		return (ENOMEM);

	mutex_enter(&pp->port_queue.portq_mutex);
	if (pp->port_curr >= pp->port_max_events) {
		mutex_exit(&pp->port_queue.portq_mutex);
		kmem_cache_free(port_control.pc_cache, pkevp);
		return (EAGAIN);
	}
	pp->port_curr++;
	mutex_exit(&pp->port_queue.portq_mutex);

	bzero(pkevp, sizeof (port_kevent_t));
	mutex_init(&pkevp->portkev_lock, NULL, MUTEX_DEFAULT, NULL);
	pkevp->portkev_flags = flags;
	pkevp->portkev_port = pp;
	pkevp->portkev_source = source;
	pkevp->portkev_pid = curproc->p_pid;
	*pkevpp = pkevp;
	return (0);
}

/*
 * port_alloc_event_block() has the same functionality of port_alloc_event() +
 * - it blocks if not enough event slots are available and
 * - it blocks if not enough memory is available.
 * Currently port_dispatch() is using this function to increase the
 * reliability of event delivery for library event sources.
 */
int
port_alloc_event_block(port_t *pp, int source, int flags,
    port_kevent_t **pkevpp)
{
	port_kevent_t *pkevp =
	    kmem_cache_alloc(port_control.pc_cache, KM_SLEEP);

	mutex_enter(&pp->port_queue.portq_mutex);
	while (pp->port_curr >= pp->port_max_events) {
		if (!cv_wait_sig(&pp->port_cv, &pp->port_queue.portq_mutex)) {
			/* signal detected */
			mutex_exit(&pp->port_queue.portq_mutex);
			kmem_cache_free(port_control.pc_cache, pkevp);
			return (EINTR);
		}
	}
	pp->port_curr++;
	mutex_exit(&pp->port_queue.portq_mutex);

	bzero(pkevp, sizeof (port_kevent_t));
	mutex_init(&pkevp->portkev_lock, NULL, MUTEX_DEFAULT, NULL);
	pkevp->portkev_flags = flags;
	pkevp->portkev_port = pp;
	pkevp->portkev_source = source;
	pkevp->portkev_pid = curproc->p_pid;
	*pkevpp = pkevp;
	return (0);
}

/*
 * Take an event out of the port queue
 */
static void
port_remove_event_doneq(port_kevent_t *pkevp, port_queue_t *portq)
{
	ASSERT(MUTEX_HELD(&portq->portq_mutex));
	list_remove(&portq->portq_list, pkevp);
	portq->portq_nent--;
	pkevp->portkev_flags &= ~PORT_KEV_DONEQ;
}

/*
 * The port_remove_done_event() function takes a fired event out of the
 * port queue.
 * Currently this function is required to cancel a fired event because
 * the application is delivering new association data (see port_associate_fd()).
 */
int
port_remove_done_event(port_kevent_t *pkevp)
{
	port_queue_t	*portq;
	int	removed = 0;

	portq = &pkevp->portkev_port->port_queue;
	mutex_enter(&portq->portq_mutex);
	/* wait for port_get() or port_getn() */
	port_block(portq);
	if (pkevp->portkev_flags & PORT_KEV_DONEQ) {
		/* event still in port queue */
		if (portq->portq_getn) {
			/*
			 * There could be still fired events in the temp queue;
			 * push those events back to the port queue and
			 * remove requested event afterwards.
			 */
			port_push_eventq(portq);
		}
		/* now remove event from the port queue */
		port_remove_event_doneq(pkevp, portq);
		removed = 1;
	}
	port_unblock(portq);
	mutex_exit(&portq->portq_mutex);
	return (removed);
}

/*
 * Return port event back to the kmem_cache.
 * If the event is currently in the port queue the event itself will only
 * be set as invalid. The port_get(n) function will not deliver such events
 * to the application and it will return them back to the kmem_cache.
 */
void
port_free_event(port_kevent_t *pkevp)
{
	port_queue_t	*portq;
	port_t		*pp;

	pp = pkevp->portkev_port;
	if (pp == NULL)
		return;
	if (pkevp->portkev_flags & PORT_ALLOC_PRIVATE) {
		port_free_event_local(pkevp, 0);
		return;
	}

	portq = &pp->port_queue;
	mutex_enter(&portq->portq_mutex);
	port_block(portq);
	if (pkevp->portkev_flags & PORT_KEV_DONEQ) {
		pkevp->portkev_flags |= PORT_KEV_FREE;
		pkevp->portkev_callback = NULL;
		port_unblock(portq);
		mutex_exit(&portq->portq_mutex);
		return;
	}
	port_unblock(portq);

	if (pkevp->portkev_flags & PORT_KEV_CACHED) {
		mutex_exit(&portq->portq_mutex);
		return;
	}

	if (--pp->port_curr < pp->port_max_events)
		cv_signal(&pp->port_cv);
	if (portq->portq_flags & PORTQ_CLOSE) {
		/*
		 * Another thread is closing the event port.
		 * That thread will sleep until all allocated event
		 * structures returned to the event port framework.
		 * The portq_mutex is used to synchronize the status
		 * of the allocated event structures (port_curr).
		 */
		if (pp->port_curr <= portq->portq_nent)
			cv_signal(&portq->portq_closecv);
	}
	mutex_exit(&portq->portq_mutex);
	port_free_event_local(pkevp, 1);
}

/*
 * This event port internal function is used by port_free_event() and
 * other port internal functions to return event structures back to the
 * kmem_cache.
 */
void
port_free_event_local(port_kevent_t *pkevp, int counter)
{
	port_t *pp = pkevp->portkev_port;
	port_queue_t *portq = &pp->port_queue;
	int wakeup;

	pkevp->portkev_callback = NULL;
	pkevp->portkev_flags = 0;
	pkevp->portkev_port = NULL;
	mutex_destroy(&pkevp->portkev_lock);
	kmem_cache_free(port_control.pc_cache, pkevp);

	mutex_enter(&portq->portq_mutex);
	if (counter == 0) {
		if (--pp->port_curr < pp->port_max_events)
			cv_signal(&pp->port_cv);
	}
	wakeup = (portq->portq_flags & PORTQ_POLLOUT);
	portq->portq_flags &= ~PORTQ_POLLOUT;
	mutex_exit(&portq->portq_mutex);

	/* Submit a POLLOUT event if requested */
	if (wakeup)
		pollwakeup(&pp->port_pollhd, POLLOUT);
}

/*
 * port_init_event(port_event_t *pev, uintptr_t object, void *user,
 *	int (*port_callback)(void *, int *, pid_t, int, void *), void *sysarg);
 *	This function initializes most of the "wired" elements of the port
 *	event structure. This is normally being used just after the allocation
 *	of the port event structure.
 *	pkevp	: pointer to the port event structure
 *	object	: object associated with this event structure
 *	user	: user defined pointer delivered with the association function
 *	port_callback:
 *		  Address of the callback function which will be called
 *		  - just before the event is delivered to the application.
 *		    The callback function is called in user context and can be
 *		    used for copyouts, e.g.
 *		  - on close() or dissociation of the event. The sub-system
 *		    must remove immediately every existing association of
 *		    some object with this event.
 *	sysarg	: event source propietary data
 */
void
port_init_event(port_kevent_t *pkevp, uintptr_t object, void *user,
    int (*port_callback)(void *, int *, pid_t, int, void *),
    void *sysarg)
{
	pkevp->portkev_object = object;
	pkevp->portkev_user = user;
	pkevp->portkev_callback = port_callback;
	pkevp->portkev_arg = sysarg;
}

/*
 * This routine removes a portfd_t from the fd cache's hash table.
 */
void
port_pcache_remove_fd(port_fdcache_t *pcp, portfd_t *pfd)
{
	polldat_t	*lpdp;
	polldat_t	*cpdp;
	portfd_t	**bucket;
	polldat_t	*pdp = PFTOD(pfd);

	ASSERT(MUTEX_HELD(&pcp->pc_lock));
	bucket = PORT_FD_BUCKET(pcp, pdp->pd_fd);
	cpdp = PFTOD(*bucket);
	if (pdp == cpdp) {
		*bucket = PDTOF(pdp->pd_hashnext);
		if (--pcp->pc_fdcount == 0) {
			/*
			 * signal the thread which may have blocked in
			 * port_close_sourcefd() on lastclose waiting
			 * for pc_fdcount to drop to 0.
			 */
			cv_signal(&pcp->pc_lclosecv);
		}
		kmem_free(pfd, sizeof (portfd_t));
		return;
	}

	while (cpdp != NULL) {
		lpdp = cpdp;
		cpdp = cpdp->pd_hashnext;
		if (cpdp == pdp) {
			/* polldat struct found */
			lpdp->pd_hashnext = pdp->pd_hashnext;
			if (--pcp->pc_fdcount == 0) {
				/*
				 * signal the thread which may have blocked in
				 * port_close_sourcefd() on lastclose waiting
				 * for pc_fdcount to drop to 0.
				 */
				cv_signal(&pcp->pc_lclosecv);
			}
			break;
		}
	}
	ASSERT(cpdp != NULL);
	kmem_free(pfd, sizeof (portfd_t));
}

/*
 * The port_push_eventq() function is used to move all remaining events
 * from the temporary queue used in port_get(n)() to the standard port
 * queue.
 */
void
port_push_eventq(port_queue_t *portq)
{
	/*
	 * Append temporary portq_get_list to the port queue. On return
	 * the temporary portq_get_list is empty.
	 */
	list_move_tail(&portq->portq_list, &portq->portq_get_list);
	portq->portq_nent += portq->portq_tnent;
	portq->portq_tnent = 0;
}

/*
 * The port_remove_fd_object() function frees all resources associated with
 * delivered portfd_t structure. Returns 1 if the port_kevent was found
 * and removed from the port queue.
 */
int
port_remove_fd_object(portfd_t *pfd, port_t *pp, port_fdcache_t *pcp)
{
	port_queue_t	*portq;
	polldat_t	*pdp = PFTOD(pfd);
	port_kevent_t	*pkevp;
	int		error;
	int		removed = 0;

	ASSERT(MUTEX_HELD(&pcp->pc_lock));
	if (pdp->pd_php != NULL) {
		pollhead_delete(pdp->pd_php, pdp);
		pdp->pd_php = NULL;
	}
	pkevp =  pdp->pd_portev;
	portq = &pp->port_queue;
	mutex_enter(&portq->portq_mutex);
	port_block(portq);
	if (pkevp->portkev_flags & PORT_KEV_DONEQ) {
		if (portq->portq_getn && portq->portq_tnent) {
			/*
			 * move events from the temporary "get" queue
			 * back to the port queue
			 */
			port_push_eventq(portq);
		}
		/* cleanup merged port queue */
		port_remove_event_doneq(pkevp, portq);
		removed = 1;
	}
	port_unblock(portq);
	mutex_exit(&portq->portq_mutex);
	if (pkevp->portkev_callback) {
		(void) (*pkevp->portkev_callback)(pkevp->portkev_arg,
		    &error, pkevp->portkev_pid, PORT_CALLBACK_DISSOCIATE,
		    pkevp);
	}
	port_free_event_local(pkevp, 0);

	/* remove polldat struct */
	port_pcache_remove_fd(pcp, pfd);
	return (removed);
}

/*
 * The port_close_fd() function dissociates a file descriptor from a port
 * and removes all allocated resources.
 * close(2) detects in the uf_entry_t structure that the fd is associated
 * with a port (at least one port).
 * The fd can be associated with several ports.
 */
void
port_close_pfd(portfd_t *pfd)
{
	port_t		*pp;
	port_fdcache_t	*pcp;

	/*
	 * the portfd_t passed in should be for this proc.
	 */
	ASSERT(curproc->p_pid == PFTOD(pfd)->pd_portev->portkev_pid);
	pp = PFTOD(pfd)->pd_portev->portkev_port;
	pcp = pp->port_queue.portq_pcp;
	mutex_enter(&pcp->pc_lock);
	(void) port_remove_fd_object(pfd, pp, pcp);
	mutex_exit(&pcp->pc_lock);
}

/*
 * The port_associate_ksource() function associates an event source with a port.
 * On port_close() all associated sources are requested to free all local
 * resources associated with the event port.
 * The association of a source with a port can only be done one time. Further
 * calls of this function will only increment the reference counter.
 * The allocated port_source_t structure is removed from the port as soon as
 * the reference counter becomes 0.
 */
/* ARGSUSED */
int
port_associate_ksource(int port, int source, port_source_t **portsrc,
    void (*port_src_close)(void *, int, pid_t, int), void *arg,
    int (*port_src_associate)(port_kevent_t *, int, int, uintptr_t, void *))
{
	port_t		*pp;
	file_t		*fp;
	port_source_t	**ps;
	port_source_t	*pse;

	if ((fp = getf(port)) == NULL)
		return (EBADF);

	if (fp->f_vnode->v_type != VPORT) {
		releasef(port);
		return (EBADFD);
	}
	pp = VTOEP(fp->f_vnode);

	mutex_enter(&pp->port_queue.portq_source_mutex);
	ps = &pp->port_queue.portq_scache[PORT_SHASH(source)];
	for (pse = *ps; pse != NULL; pse = pse->portsrc_next) {
		if (pse->portsrc_source == source)
			break;
	}

	if (pse == NULL) {
		/* Create association of the event source with the port */
		pse = kmem_zalloc(sizeof (port_source_t), KM_NOSLEEP);
		if (pse == NULL) {
			mutex_exit(&pp->port_queue.portq_source_mutex);
			releasef(port);
			return (ENOMEM);
		}
		pse->portsrc_source = source;
		pse->portsrc_close = port_src_close;
		pse->portsrc_closearg = arg;
		pse->portsrc_cnt = 1;
		if (*ps)
			pse->portsrc_next = (*ps)->portsrc_next;
		*ps = pse;
	} else {
		/* entry already available, source is only requesting count */
		pse->portsrc_cnt++;
	}
	mutex_exit(&pp->port_queue.portq_source_mutex);
	releasef(port);
	if (portsrc)
		*portsrc = pse;
	return (0);
}

/*
 * The port_dissociate_ksource() function dissociates an event source from
 * a port.
 */
int
port_dissociate_ksource(int port, int source, port_source_t *ps)
{
	port_t		*pp;
	file_t		*fp;
	port_source_t	**psh;

	if (ps == NULL)
		return (EINVAL);

	if ((fp = getf(port)) == NULL)
		return (EBADF);

	if (fp->f_vnode->v_type != VPORT) {
		releasef(port);
		return (EBADFD);
	}
	pp = VTOEP(fp->f_vnode);

	mutex_enter(&pp->port_queue.portq_source_mutex);
	if (--ps->portsrc_cnt == 0) {
		/* last association removed -> free source structure */
		if (ps->portsrc_prev == NULL) {
			/* first entry */
			psh = &pp->port_queue.portq_scache[PORT_SHASH(source)];
			*psh = ps->portsrc_next;
			if (ps->portsrc_next)
				ps->portsrc_next->portsrc_prev = NULL;
		} else {
			ps->portsrc_prev->portsrc_next = ps->portsrc_next;
			if (ps->portsrc_next)
				ps->portsrc_next->portsrc_prev =
				    ps->portsrc_prev;
		}
		kmem_free(ps, sizeof (port_source_t));
	}
	mutex_exit(&pp->port_queue.portq_source_mutex);
	releasef(port);
	return (0);
}

void
free_fopdata(vnode_t *vp)
{
	portfop_vp_t *pvp;
	pvp = vp->v_fopdata;
	ASSERT(pvp->pvp_femp == NULL);
	mutex_destroy(&pvp->pvp_mutex);
	list_destroy(&pvp->pvp_pfoplist);
	kmem_free(pvp, sizeof (*pvp));
	vp->v_fopdata = NULL;
}
