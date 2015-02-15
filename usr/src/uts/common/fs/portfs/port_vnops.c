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

/*
 * Copyright (c) 2014, Joyent, Inc.  All rights reserved.
 */

#include <sys/types.h>
#include <sys/vnode.h>
#include <sys/vfs_opreg.h>
#include <sys/kmem.h>
#include <fs/fs_subr.h>
#include <sys/proc.h>
#include <sys/kstat.h>
#include <sys/port_impl.h>

/* local functions */
static int port_open(struct vnode **, int, cred_t *, caller_context_t *);
static int port_close(struct vnode *, int, int, offset_t, cred_t *,
	caller_context_t *);
static int port_getattr(struct vnode *, struct vattr *, int, cred_t *,
	caller_context_t *);
static int port_access(struct vnode *, int, int, cred_t *, caller_context_t *);
static int port_realvp(vnode_t *, vnode_t **, caller_context_t *);
static int port_poll(vnode_t *, short, int, short *, struct pollhead **,
	caller_context_t *);
static void port_inactive(struct vnode *, cred_t *, caller_context_t *);

const fs_operation_def_t port_vnodeops_template[] = {
	VOPNAME_OPEN,		{ .vop_open = port_open },
	VOPNAME_CLOSE,		{ .vop_close = port_close },
	VOPNAME_GETATTR,	{ .vop_getattr = port_getattr },
	VOPNAME_ACCESS,		{ .vop_access = port_access },
	VOPNAME_INACTIVE,	{ .vop_inactive = port_inactive },
	VOPNAME_FRLOCK,		{ .error = fs_error },
	VOPNAME_REALVP,		{ .vop_realvp = port_realvp },
	VOPNAME_POLL,		{ .vop_poll = port_poll },
	VOPNAME_PATHCONF,	{ .error = fs_error },
	VOPNAME_DISPOSE,	{ .error = fs_error },
	VOPNAME_GETSECATTR,	{ .error = fs_error },
	VOPNAME_SHRLOCK,	{ .error = fs_error },
	NULL,			NULL
};

/* ARGSUSED */
static int
port_open(struct vnode **vpp, int flag, cred_t *cr, caller_context_t *ct)
{
	return (0);
}

/*
 * port_discard_events() scans the port event queue for events owned
 * by current proc. Non-shareable events will be discarded, all other
 * events remain in the event queue.
 */
void
port_discard_events(port_queue_t *portq)
{
	port_kevent_t	*kevp;
	pid_t		pid = curproc->p_pid;

	/*
	 * The call to port_block() is required to avoid interaction
	 * with other threads in port_get(n).
	 */
	mutex_enter(&portq->portq_mutex);
	port_block(portq);
	port_push_eventq(portq);	/* empty temporary queue */
	kevp = list_head(&portq->portq_list);
	while (kevp) {
		if (kevp->portkev_pid == pid) {
			/* own event, check if it is shareable */
			if (kevp->portkev_flags & PORT_KEV_NOSHARE)
				kevp->portkev_flags |= PORT_KEV_FREE;
		}
		kevp = list_next(&portq->portq_list, kevp);
	}
	port_unblock(portq);
	mutex_exit(&portq->portq_mutex);
}

/*
 * Called from port_close().
 * Free all kernel events structures which are still in the event queue.
 */
static void
port_close_events(port_queue_t *portq)
{
	port_kevent_t	*pkevp;
	int		events;		/* ignore events */

	mutex_enter(&portq->portq_mutex);
	while (pkevp = list_head(&portq->portq_list)) {
		portq->portq_nent--;
		list_remove(&portq->portq_list, pkevp);
		if (pkevp->portkev_callback) {
			(void) (*pkevp->portkev_callback)(pkevp->portkev_arg,
			    &events, pkevp->portkev_pid, PORT_CALLBACK_CLOSE,
			    pkevp);
		}
		mutex_exit(&portq->portq_mutex);
		port_free_event_local(pkevp, 0);
		mutex_enter(&portq->portq_mutex);
	}

	/*
	 * Wait for any thread in pollwakeup(), accessing this port to
	 * finish.
	 */
	while (portq->portq_flags & PORTQ_POLLWK_PEND) {
		cv_wait(&portq->portq_closecv, &portq->portq_mutex);
	}
	mutex_exit(&portq->portq_mutex);
}

/*
 * The port_close() function is called from standard close(2) when
 * the file descriptor is of type S_IFPORT/VPORT.
 * Port file descriptors behave like standard file descriptors. It means,
 * the port file/vnode is only destroyed on last close.
 * If the reference counter is > 1 then
 * - sources associated with the port will be notified about the close,
 * - objects associated with the port will be dissociated,
 * - pending and delivered events will be discarded.
 * On last close all references and caches will be removed. The vnode itself
 * will be destroyed with VOP_RELE().
 */
/* ARGSUSED */
static int
port_close(struct vnode *vp, int flag, int count, offset_t offset, cred_t *cr,
    caller_context_t *ct)
{
	port_t		*pp;
	port_queue_t	*portq;
	port_source_t	*ps;
	port_source_t	*ps_next;
	int		source;

	pp = VTOEP(vp);
	mutex_enter(&pp->port_mutex);
	if (pp->port_flags & PORT_CLOSED) {
		mutex_exit(&pp->port_mutex);
		return (0);
	}
	mutex_exit(&pp->port_mutex);

	portq = &pp->port_queue;
	if (count > 1) {
		/*
		 * It is not the last close.
		 * Remove/free all event resources owned by the current proc
		 * First notify all with the port associated sources about the
		 * close(2). The last argument of the close callback function
		 * advises the source about the type of of the close.
		 * If the port was set in alert mode by the curren process then
		 * remove the alert mode.
		 */

		/* check alert mode of the port */
		mutex_enter(&portq->portq_mutex);
		if ((portq->portq_flags & PORTQ_ALERT) &&
		    (portq->portq_alert.portal_pid == curproc->p_pid))
			portq->portq_flags &= ~PORTQ_ALERT;
		mutex_exit(&portq->portq_mutex);

		/* notify all event sources about port_close() */
		mutex_enter(&portq->portq_source_mutex);
		for (source = 0; source < PORT_SCACHE_SIZE; source++) {
			ps = portq->portq_scache[PORT_SHASH(source)];
			for (; ps != NULL; ps = ps->portsrc_next) {
				if (ps->portsrc_close != NULL)
					(*ps->portsrc_close)
					    (ps->portsrc_closearg, pp->port_fd,
					    curproc->p_pid, 0);
			}
		}
		mutex_exit(&portq->portq_source_mutex);
		port_discard_events(&pp->port_queue);
		return (0);
	}

	/*
	 * We are executing the last close of the port -> discard everything
	 * Make sure that all threads/processes accessing this port leave
	 * the kernel immediately.
	 */

	mutex_enter(&portq->portq_mutex);
	portq->portq_flags |= PORTQ_CLOSE;
	while (portq->portq_thrcnt > 0) {
		if (portq->portq_thread != NULL)
			cv_signal(&portq->portq_thread->portget_cv);
		cv_wait(&portq->portq_closecv, &portq->portq_mutex);
	}
	mutex_exit(&portq->portq_mutex);

	/*
	 * Send "last close" message to associated sources.
	 * - new event allocation requests are being denied since uf_file entry
	 *   was set to NULL in closeandsetf().
	 * - all still allocated event structures must be returned to the
	 *   port immediately:
	 *	- call port_free_event(*event) or
	 *	- call port_send_event(*event) to complete event operations
	 *	  which need activities in a dedicated process environment.
	 * The port_close() function waits until all allocated event structures
	 * are delivered back to the port.
	 */

	mutex_enter(&portq->portq_source_mutex);
	for (source = 0; source < PORT_SCACHE_SIZE; source++) {
		ps = portq->portq_scache[PORT_SHASH(source)];
		for (; ps != NULL; ps = ps_next) {
			ps_next = ps->portsrc_next;
			if (ps->portsrc_close != NULL)
				(*ps->portsrc_close)(ps->portsrc_closearg,
				    pp->port_fd, curproc->p_pid, 1);
			kmem_free(ps, sizeof (port_source_t));
		}
	}
	kmem_free(portq->portq_scache,
	    PORT_SCACHE_SIZE * sizeof (port_source_t *));
	portq->portq_scache = NULL;
	mutex_exit(&portq->portq_source_mutex);

	mutex_enter(&portq->portq_mutex);
	/* Wait for outstanding events */
	while (pp->port_curr > portq->portq_nent)
		cv_wait(&portq->portq_closecv, &portq->portq_mutex);
	mutex_exit(&portq->portq_mutex);

	/*
	 * If PORT_SOURCE_FD objects were not associated with the port then
	 * it is necessary to free the port_fdcache structure here.
	 */

	if (portq->portq_pcp != NULL) {
		mutex_destroy(&portq->portq_pcp->pc_lock);
		kmem_free(portq->portq_pcp, sizeof (port_fdcache_t));
		portq->portq_pcp = NULL;
	}

	/*
	 * Now all events are passed back to the port,
	 * discard remaining events in the port queue
	 */

	port_close_events(portq);
	return (0);
}

/*
 * The port_poll() function is the VOP_POLL() entry of event ports.
 * Event ports return:
 * POLLIN  : events are available in the event queue
 * POLLOUT : event queue can still accept events
 */
/*ARGSUSED*/
static int
port_poll(vnode_t *vp, short events, int anyyet, short *reventsp,
    struct pollhead **phpp, caller_context_t *ct)
{
	port_t		*pp;
	port_queue_t	*portq;
	short		levents;

	pp = VTOEP(vp);
	portq = &pp->port_queue;
	levents = 0;
	mutex_enter(&portq->portq_mutex);
	if (portq->portq_nent)
		levents = POLLIN;
	if (pp->port_curr < pp->port_max_events)
		levents |= POLLOUT;
	levents &= events;
	*reventsp = levents;
	if ((levents == 0 && !anyyet) || (events & POLLET)) {
		*phpp = &pp->port_pollhd;
		portq->portq_flags |= events & POLLIN ? PORTQ_POLLIN : 0;
		portq->portq_flags |= events & POLLOUT ? PORTQ_POLLOUT : 0;
	}
	mutex_exit(&portq->portq_mutex);
	return (0);
}


/* ARGSUSED */
static int
port_getattr(struct vnode *vp, struct vattr *vap, int flags, cred_t *cr,
    caller_context_t *ct)
{
	port_t	*pp;
	extern dev_t portdev;

	pp = VTOEP(vp);

	vap->va_type = vp->v_type;	/* vnode type (for create) */
	vap->va_mode = 0;		/* file access mode */
	vap->va_uid = pp->port_uid;	/* owner user id */
	vap->va_gid = pp->port_gid;	/* owner group id */
	vap->va_fsid = portdev;		/* file system id  */
	vap->va_nodeid = (ino64_t)0;	/* node id */
	vap->va_nlink = vp->v_count;	/* number of references to file */
	vap->va_size = (u_offset_t)pp->port_queue.portq_nent; /* file size */
	vap->va_atime = pp->port_ctime;	/* time of last access */
	vap->va_mtime = pp->port_ctime;	/* time of last modification */
	vap->va_ctime = pp->port_ctime;	/* time file ``created'' */
	vap->va_rdev = portdev;		/* device the file represents */
	vap->va_blksize = 0;		/* fundamental block size */
	vap->va_nblocks = (fsblkcnt64_t)0;	/* # of blocks allocated */
	vap->va_seq = 0;		/* sequence number */

	return (0);
}

/*
 * Destroy the port.
 */
/* ARGSUSED */
static void
port_inactive(struct vnode *vp, cred_t *cr, caller_context_t *ct)
{
	port_t 	*pp = VTOEP(vp);
	extern 	port_kstat_t port_kstat;

	mutex_enter(&port_control.pc_mutex);
	port_control.pc_nents--;
	curproc->p_portcnt--;
	port_kstat.pks_ports.value.ui32--;
	mutex_exit(&port_control.pc_mutex);
	vn_free(vp);
	mutex_destroy(&pp->port_mutex);
	mutex_destroy(&pp->port_queue.portq_mutex);
	mutex_destroy(&pp->port_queue.portq_source_mutex);
	kmem_free(pp, sizeof (port_t));
}

/* ARGSUSED */
static int
port_access(struct vnode *vp, int mode, int flags, cred_t *cr,
    caller_context_t *ct)
{
	return (0);
}

/* ARGSUSED */
static int
port_realvp(vnode_t *vp, vnode_t **vpp, caller_context_t *ct)
{
	*vpp = vp;
	return (0);
}
