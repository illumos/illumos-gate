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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <sys/types.h>
#include <sys/systm.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/sysmacros.h>
#include <sys/debug.h>
#include <sys/poll_impl.h>
#include <sys/port_impl.h>

#define	PORTHASH_START	256	/* start cache space for events */
#define	PORTHASH_MULT	2	/* growth threshold and factor */

/* local functions */
static int	port_fd_callback(void *, int *, pid_t, int, void *);
static int	port_bind_pollhead(pollhead_t **, polldat_t *, short *);
static void	port_close_sourcefd(void *, int, pid_t, int);
static void	port_cache_insert_fd(port_fdcache_t *, polldat_t *);

/*
 * port_fd_callback()
 * The event port framework uses callback functions to notify associated
 * event sources about actions on source specific objects.
 * The source itself defines the "arg" required to identify the object with
 * events. In the port_fd_callback() case the "arg" is a pointer to portfd_t
 * structure. The portfd_t structure is specific for PORT_SOURCE_FD source.
 * The port_fd_callback() function is notified in three cases:
 * - PORT_CALLBACK_DEFAULT
 *	The object (fd) will be delivered to the application.
 * - PORT_CALLBACK_DISSOCIATE
 *	The object (fd) will be dissociated from  the port.
 * - PORT_CALLBACK_CLOSE
 *	The object (fd) will be dissociated from the port because the port
 *	is being closed.
 * A fd is shareable between processes only when
 * - processes have the same fd id and
 * - processes have the same fp.
 * A fd becomes shareable:
 * - on fork() across parent and child process and
 * - when I_SENDFD is used to pass file descriptors between parent and child
 *   immediately after fork() (the sender and receiver must get the same
 *   file descriptor id).
 * If a fd is shared between processes, all involved processes will get
 * the same rights related to re-association of the fd with the port and
 * retrieve of events from that fd.
 * The process which associated the fd with a port for the first time
 * becomes also the owner of the association. Only the owner of the
 * association is allowed to dissociate the fd from the port.
 */
/* ARGSUSED */
static int
port_fd_callback(void *arg, int *events, pid_t pid, int flag, void *evp)
{
	portfd_t	*pfd = (portfd_t *)arg;
	polldat_t	*pdp = PFTOD(pfd);
	port_fdcache_t	*pcp;
	file_t		*fp;
	int		error;

	ASSERT((pdp != NULL) && (events != NULL));
	switch (flag) {
	case PORT_CALLBACK_DEFAULT:
		if (curproc->p_pid != pid) {
			/*
			 * Check if current process is allowed to retrieve
			 * events from this fd.
			 */
			fp = getf(pdp->pd_fd);
			if (fp == NULL) {
				error = EACCES; /* deny delivery of events */
				break;
			}
			releasef(pdp->pd_fd);
			if (fp != pdp->pd_fp) {
				error = EACCES; /* deny delivery of events */
				break;
			}
		}
		*events = pdp->pd_portev->portkev_events; /* update events */
		error = 0;
		break;
	case PORT_CALLBACK_DISSOCIATE:
		error = 0;
		break;
	case PORT_CALLBACK_CLOSE:
		/* remove polldat/portfd struct */
		pdp->pd_portev = NULL;
		pcp = (port_fdcache_t *)pdp->pd_pcache;
		mutex_enter(&pcp->pc_lock);
		pdp->pd_fp = NULL;
		pdp->pd_events = 0;
		if (pdp->pd_php != NULL) {
			pollhead_delete(pdp->pd_php, pdp);
			pdp->pd_php = NULL;
		}
		port_pcache_remove_fd(pcp, pfd);
		mutex_exit(&pcp->pc_lock);
		error = 0;
		break;
	default:
		error = EINVAL;
		break;
	}
	return (error);
}

/*
 * This routine returns a pointer to a cached poll fd entry, or NULL if it
 * does not find it in the hash table.
 * The fd is used as index.
 * The fd and the fp are used to detect a valid entry.
 * This function returns a pointer to a valid portfd_t structure only when
 * the fd and the fp in the args match the entries in polldat_t.
 */
portfd_t *
port_cache_lookup_fp(port_fdcache_t *pcp, int fd, file_t *fp)
{
	polldat_t	*pdp;
	portfd_t	**bucket;

	ASSERT(MUTEX_HELD(&pcp->pc_lock));
	bucket = PORT_FD_BUCKET(pcp, fd);
	pdp = PFTOD(*bucket);
	while (pdp != NULL) {
		if (pdp->pd_fd == fd && pdp->pd_fp == fp)
			break;
		pdp = pdp->pd_hashnext;
	}
	return (PDTOF(pdp));
}

/*
 * port_associate_fd()
 * This function associates new file descriptors with a port or
 * reactivate already associated file descriptors.
 * The reactivation also updates the events types to be checked and the
 * attached user pointer.
 * Per port a cache is used to store associated file descriptors.
 * Internally the VOP_POLL interface is used to poll for existing events.
 * The VOP_POLL interface can also deliver a pointer to a pollhead_t structure
 * which is used to enqueue polldat_t structures with pending events.
 * If VOP_POLL immediately returns valid events (revents) then those events
 * will be submitted to the event port with port_send_event().
 * Otherwise VOP_POLL does not return events but it delivers a pointer to a
 * pollhead_t structure. In such a case the corresponding file system behind
 * VOP_POLL will use the pollwakeup() function to notify about existing
 * events.
 */
int
port_associate_fd(port_t *pp, int source, uintptr_t object, int events,
    void *user)
{
	port_fdcache_t	*pcp;
	int		fd;
	struct pollhead	*php = NULL;
	portfd_t	*pfd;
	polldat_t	*pdp;
	file_t		*fp;
	port_kevent_t	*pkevp;
	short		revents;
	int		error = 0;
	int		active;

	pcp = pp->port_queue.portq_pcp;
	if (object > (uintptr_t)INT_MAX)
		return (EBADFD);

	fd = object;

	if ((fp = getf(fd)) == NULL)
		return (EBADFD);

	mutex_enter(&pcp->pc_lock);

	if (pcp->pc_hash == NULL) {
		/*
		 * This is the first time that a fd is being associated with
		 * the current port:
		 * - create PORT_SOURCE_FD cache
		 * - associate PORT_SOURCE_FD source with the port
		 */
		error = port_associate_ksource(pp->port_fd, PORT_SOURCE_FD,
		    NULL, port_close_sourcefd, pp, NULL);
		if (error) {
			mutex_exit(&pcp->pc_lock);
			releasef(fd);
			return (error);
		}

		/* create polldat cache */
		pcp->pc_hashsize = PORTHASH_START;
		pcp->pc_hash = kmem_zalloc(pcp->pc_hashsize *
		    sizeof (portfd_t *), KM_SLEEP);
		pfd = NULL;
	} else {
		/* Check if the fd/fp is already associated with the port */
		pfd = port_cache_lookup_fp(pcp, fd, fp);
	}

	if (pfd == NULL) {
		/*
		 * new entry
		 * Allocate a polldat_t structure per fd
		 * The use of the polldat_t structure to cache file descriptors
		 * is required to be able to share the pollwakeup() function
		 * with poll(2) and devpoll(7d).
		 */
		pfd = kmem_zalloc(sizeof (portfd_t), KM_SLEEP);
		pdp = PFTOD(pfd);
		pdp->pd_fd = fd;
		pdp->pd_fp = fp;
		pdp->pd_pcache = (void *)pcp;

		/* Allocate a port event structure per fd */
		error = port_alloc_event_local(pp, source, PORT_ALLOC_CACHED,
		    &pdp->pd_portev);
		if (error) {
			kmem_free(pfd, sizeof (portfd_t));
			releasef(fd);
			mutex_exit(&pcp->pc_lock);
			return (error);
		}
		pkevp = pdp->pd_portev;
		pkevp->portkev_callback = port_fd_callback;
		pkevp->portkev_arg = pfd;

		/* add portfd_t entry  to the cache */
		port_cache_insert_fd(pcp, pdp);
		pkevp->portkev_object = fd;
		pkevp->portkev_user = user;

		/*
		 * Add current port to the file descriptor interested list
		 * The members of the list are notified when the file descriptor
		 * is closed.
		 */
		addfd_port(fd, pfd);
	} else {
		/*
		 * The file descriptor is already associated with the port
		 */
		pdp = PFTOD(pfd);
		pkevp = pdp->pd_portev;

		/*
		 * Check if the re-association happens before the last
		 * submitted event of the file descriptor was retrieved.
		 * Clear the PORT_KEV_VALID flag if set. No new events
		 * should get submitted after this flag is cleared.
		 */
		mutex_enter(&pkevp->portkev_lock);
		if (pkevp->portkev_flags & PORT_KEV_VALID) {
			pkevp->portkev_flags &= ~PORT_KEV_VALID;
		}
		if (pkevp->portkev_flags & PORT_KEV_DONEQ) {
			mutex_exit(&pkevp->portkev_lock);
			/*
			 * Remove any events that where already fired
			 * for this fd and are still in the port queue.
			 */
			(void) port_remove_done_event(pkevp);
		} else {
			mutex_exit(&pkevp->portkev_lock);
		}
		pkevp->portkev_user = user;
	}

	pfd->pfd_thread = curthread;
	mutex_enter(&pkevp->portkev_lock);
	pkevp->portkev_events = 0;	/* no fired events */
	pdp->pd_events = events;	/* events associated */
	/*
	 * allow new events.
	 */
	pkevp->portkev_flags |= PORT_KEV_VALID;
	mutex_exit(&pkevp->portkev_lock);

	/*
	 * do VOP_POLL and cache this poll fd.
	 *
	 * XXX - pollrelock() logic needs to know
	 * which pollcache lock to grab. It'd be a
	 * cleaner solution if we could pass pcp as
	 * an arguement in VOP_POLL interface instead
	 * of implicitly passing it using thread_t
	 * struct. On the other hand, changing VOP_POLL
	 * interface will require all driver/file system
	 * poll routine to change.
	 */
	curthread->t_pollcache = (pollcache_t *)pcp;
	error = VOP_POLL(fp->f_vnode, events, 0, &revents, &php, NULL);
	curthread->t_pollcache = NULL;

	/*
	 * The pc_lock can get dropped and reaquired in VOP_POLL.
	 * In the window pc_lock is dropped another thread in
	 * port_dissociate can remove the pfd from the port cache
	 * and free the pfd.
	 * It is also possible for another thread to sneak in and do a
	 * port_associate on the same fd during the same window.
	 * For both these cases return the current value of error.
	 * The application should take care to ensure that the threads
	 * do not race with each other for association and disassociation
	 * of the same fd.
	 */
	if (((pfd = port_cache_lookup_fp(pcp, fd, fp)) == NULL) ||
	    (pfd->pfd_thread != curthread)) {
		releasef(fd);
		mutex_exit(&pcp->pc_lock);
		return (error);
	}

	/*
	 * To keep synchronization between VOP_POLL above and
	 * pollhead_insert below, it is necessary to
	 * call VOP_POLL() again (see port_bind_pollhead()).
	 */
	if (error) {
		goto errout;
	}

	if (php != NULL && (pdp->pd_php != php)) {
		/*
		 * No events delivered yet.
		 * Bind pollhead pointer with current polldat_t structure.
		 * Sub-system will call pollwakeup() later with php as
		 * argument.
		 */
		error = port_bind_pollhead(&php, pdp, &revents);
		/*
		 * The pc_lock can get dropped and reaquired in VOP_POLL.
		 * In the window pc_lock is dropped another thread in
		 * port_dissociate can remove the pfd from the port cache
		 * and free the pfd.
		 * It is also possible for another thread to sneak in and do a
		 * port_associate on the same fd during the same window.
		 * For both these cases return the current value of error.
		 * The application should take care to ensure that the threads
		 * do not race with each other for association
		 * and disassociation of the same fd.
		 */
		if (((pfd = port_cache_lookup_fp(pcp, fd, fp)) == NULL) ||
		    (pfd->pfd_thread != curthread)) {
			releasef(fd);
			mutex_exit(&pcp->pc_lock);
			return (error);
		}

		if (error) {
			goto errout;
		}
	}

	/*
	 * Check if new events where detected and no events have been
	 * delivered. The revents was already set after the VOP_POLL
	 * above or it was updated in port_bind_pollhead().
	 */
	mutex_enter(&pkevp->portkev_lock);
	if (revents && (pkevp->portkev_flags & PORT_KEV_VALID)) {
		ASSERT((pkevp->portkev_flags & PORT_KEV_DONEQ) == 0);
		pkevp->portkev_flags &= ~PORT_KEV_VALID;
		revents = revents & (pdp->pd_events | POLLHUP | POLLERR);
		/* send events to the event port */
		pkevp->portkev_events = revents;
		/*
		 * port_send_event will release the portkev_lock mutex.
		 */
		port_send_event(pkevp);
	} else {
		mutex_exit(&pkevp->portkev_lock);
	}

	releasef(fd);
	mutex_exit(&pcp->pc_lock);
	return (error);

errout:
	delfd_port(fd, pfd);
	/*
	 * If the portkev is not valid, then an event was
	 * delivered.
	 *
	 * If an event was delivered and got picked up, then
	 * we return error = 0 treating this as a successful
	 * port associate call. The thread which received
	 * the event gets control of the object.
	 */
	active = 0;
	mutex_enter(&pkevp->portkev_lock);
	if (pkevp->portkev_flags & PORT_KEV_VALID) {
		pkevp->portkev_flags &= ~PORT_KEV_VALID;
		active = 1;
	}
	mutex_exit(&pkevp->portkev_lock);

	if (!port_remove_fd_object(pfd, pp, pcp) && !active) {
		error = 0;
	}
	releasef(fd);
	mutex_exit(&pcp->pc_lock);
	return (error);
}

/*
 * The port_dissociate_fd() function dissociates the delivered file
 * descriptor from the event port and removes already fired events.
 * If a fd is shared between processes, all involved processes will get
 * the same rights related to re-association of the fd with the port and
 * retrieve of events from that fd.
 * The process which associated the fd with a port for the first time
 * becomes also the owner of the association. Only the owner of the
 * association is allowed to dissociate the fd from the port.
 */
int
port_dissociate_fd(port_t *pp, uintptr_t object)
{
	int		fd;
	port_fdcache_t	*pcp;
	portfd_t	*pfd;
	file_t		*fp;
	int		active;
	port_kevent_t	*pkevp;

	if (object > (uintptr_t)INT_MAX)
		return (EBADFD);

	fd = object;
	pcp = pp->port_queue.portq_pcp;

	mutex_enter(&pcp->pc_lock);
	if (pcp->pc_hash == NULL) {
		/* no file descriptor cache available */
		mutex_exit(&pcp->pc_lock);
		return (ENOENT);
	}
	if ((fp = getf(fd)) == NULL) {
		mutex_exit(&pcp->pc_lock);
		return (EBADFD);
	}
	pfd = port_cache_lookup_fp(pcp, fd, fp);
	if (pfd == NULL) {
		releasef(fd);
		mutex_exit(&pcp->pc_lock);
		return (ENOENT);
	}
	/* only association owner is allowed to remove the association */
	if (curproc->p_pid != PFTOD(pfd)->pd_portev->portkev_pid) {
		releasef(fd);
		mutex_exit(&pcp->pc_lock);
		return (EACCES);
	}

	/* remove port from the file descriptor interested list */
	delfd_port(fd, pfd);

	/*
	 * Deactivate the association. No events get posted after
	 * this.
	 */
	pkevp = PFTOD(pfd)->pd_portev;
	mutex_enter(&pkevp->portkev_lock);
	if (pkevp->portkev_flags & PORT_KEV_VALID) {
		pkevp->portkev_flags &= ~PORT_KEV_VALID;
		active = 1;
	} else {
		active = 0;
	}
	mutex_exit(&pkevp->portkev_lock);

	/* remove polldat & port event structure */
	if (port_remove_fd_object(pfd, pp, pcp)) {
		/*
		 * An event was found and removed from the
		 * port done queue. This means the event has not yet
		 * been retrived. In this case we treat this as an active
		 * association.
		 */
		ASSERT(active == 0);
		active = 1;
	}
	releasef(fd);
	mutex_exit(&pcp->pc_lock);

	/*
	 * Return ENOENT if there was no active association.
	 */
	return ((active ? 0 : ENOENT));
}

/*
 * Associate event port polldat_t structure with sub-system pointer to
 * a polhead_t structure.
 */
static int
port_bind_pollhead(pollhead_t **php, polldat_t *pdp, short *revents)
{
	int		error;
	file_t		*fp;

	/* polldat_t associated with another pollhead_t pointer */
	if (pdp->pd_php != NULL)
		pollhead_delete(pdp->pd_php, pdp);

	/*
	 * Before pollhead_insert() pollwakeup() will not detect a polldat
	 * entry in the ph_list and the event notification will disappear.
	 * This happens because polldat_t is still not associated with
	 * the pointer to the pollhead_t structure.
	 */
	pollhead_insert(*php, pdp);

	/*
	 * From now on event notification can be detected in pollwakeup(),
	 * Use VOP_POLL() again to check the current status of the event.
	 */
	pdp->pd_php = *php;
	fp = pdp->pd_fp;
	curthread->t_pollcache = (pollcache_t *)pdp->pd_pcache;
	error = VOP_POLL(fp->f_vnode, pdp->pd_events, 0, revents, php, NULL);
	curthread->t_pollcache = NULL;
	return (error);
}

/*
 * Grow the hash table. Rehash all the elements on the hash table.
 */
static void
port_cache_grow_hashtbl(port_fdcache_t *pcp)
{
	portfd_t	**oldtbl;
	polldat_t	*pdp;
	portfd_t	*pfd;
	polldat_t	*pdp1;
	int		oldsize;
	int		i;

	ASSERT(MUTEX_HELD(&pcp->pc_lock));
	oldsize = pcp->pc_hashsize;
	oldtbl = pcp->pc_hash;
	pcp->pc_hashsize *= PORTHASH_MULT;
	pcp->pc_hash = kmem_zalloc(pcp->pc_hashsize * sizeof (portfd_t *),
	    KM_SLEEP);
	/*
	 * rehash existing elements
	 */
	pcp->pc_fdcount = 0;
	for (i = 0; i < oldsize; i++) {
		pfd = oldtbl[i];
		pdp = PFTOD(pfd);
		while (pdp != NULL) {
			pdp1 = pdp->pd_hashnext;
			port_cache_insert_fd(pcp, pdp);
			pdp = pdp1;
		}
	}
	kmem_free(oldtbl, oldsize * sizeof (portfd_t *));
}
/*
 * This routine inserts a polldat into the portcache's hash table. It
 * may be necessary to grow the size of the hash table.
 */
static void
port_cache_insert_fd(port_fdcache_t *pcp, polldat_t *pdp)
{
	portfd_t	**bucket;

	ASSERT(MUTEX_HELD(&pcp->pc_lock));
	if (pcp->pc_fdcount > (pcp->pc_hashsize * PORTHASH_MULT))
		port_cache_grow_hashtbl(pcp);
	bucket = PORT_FD_BUCKET(pcp, pdp->pd_fd);
	pdp->pd_hashnext = PFTOD(*bucket);
	*bucket = PDTOF(pdp);
	pcp->pc_fdcount++;
}


/*
 * The port_remove_portfd() function dissociates the port from the fd
 * and vive versa.
 */
static void
port_remove_portfd(polldat_t *pdp, port_fdcache_t *pcp)
{
	port_t	*pp;
	file_t	*fp;
	int	fd;

	ASSERT(MUTEX_HELD(&pcp->pc_lock));
	pp = pdp->pd_portev->portkev_port;
	fp = getf(fd = pdp->pd_fd);
	/*
	 * If we did not get the fp for pd_fd but its portfd_t
	 * still exist in the cache, it means the pd_fd is being
	 * closed by some other thread which will also free the portfd_t.
	 */
	if (fp != NULL) {
		delfd_port(pdp->pd_fd, PDTOF(pdp));
		(void) port_remove_fd_object(PDTOF(pdp), pp, pcp);
		releasef(fd);
	}
}

/*
 * This function is used by port_close_sourcefd() to destroy the cache
 * on last close.
 */
static void
port_pcache_destroy(port_fdcache_t *pcp)
{
	ASSERT(pcp->pc_fdcount == 0);
	kmem_free(pcp->pc_hash, sizeof (polldat_t *) * pcp->pc_hashsize);
	mutex_destroy(&pcp->pc_lock);
	kmem_free(pcp, sizeof (port_fdcache_t));
}

/*
 * port_close() calls this function to request the PORT_SOURCE_FD source
 * to remove/free all resources allocated and associated with the port.
 */
/* ARGSUSED */
static void
port_close_sourcefd(void *arg, int port, pid_t pid, int lastclose)
{
	port_t		*pp = arg;
	port_fdcache_t	*pcp;
	portfd_t	**hashtbl;
	polldat_t	*pdp;
	polldat_t	*pdpnext;
	int		index;

	pcp = pp->port_queue.portq_pcp;
	if (pcp == NULL)
		/* no cache available -> nothing to do */
		return;

	mutex_enter(&pcp->pc_lock);
	/*
	 * Scan the cache and free all allocated portfd_t and port_kevent_t
	 * structures.
	 */
	hashtbl = pcp->pc_hash;
	for (index = 0; index < pcp->pc_hashsize; index++) {
		for (pdp = PFTOD(hashtbl[index]); pdp != NULL; pdp = pdpnext) {
			pdpnext = pdp->pd_hashnext;
			if (pid == pdp->pd_portev->portkev_pid) {
				/*
				 * remove polldat + port_event_t from cache
				 * only when current process did the
				 * association.
				 */
				port_remove_portfd(pdp, pcp);
			}
		}
	}
	if (lastclose) {
		/*
		 * Wait for all the portfd's to be freed.
		 * The remaining portfd_t's are the once we did not
		 * free in port_remove_portfd since some other thread
		 * is closing the fd. These threads will free the portfd_t's
		 * once we drop the pc_lock mutex.
		 */
		while (pcp->pc_fdcount) {
			(void) cv_wait_sig(&pcp->pc_lclosecv, &pcp->pc_lock);
		}
		/* event port vnode will be destroyed -> remove everything */
		pp->port_queue.portq_pcp = NULL;
	}
	mutex_exit(&pcp->pc_lock);
	/*
	 * last close:
	 * pollwakeup() can not further interact with this cache
	 * (all polldat structs are removed from pollhead entries).
	 */
	if (lastclose)
		port_pcache_destroy(pcp);
}
