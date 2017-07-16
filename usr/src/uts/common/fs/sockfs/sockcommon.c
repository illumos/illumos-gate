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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2017 Sebastian Wiedenroth
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/debug.h>
#include <sys/cmn_err.h>
#include <sys/vfs.h>
#include <sys/policy.h>
#include <sys/modctl.h>

#include <sys/sunddi.h>

#include <sys/strsun.h>
#include <sys/stropts.h>
#include <sys/strsubr.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/uio.h>

#include <inet/ipclassifier.h>
#include <fs/sockfs/sockcommon.h>
#include <fs/sockfs/sockfilter_impl.h>
#include <fs/sockfs/nl7c.h>
#include <fs/sockfs/socktpi.h>
#include <fs/sockfs/sodirect.h>
#include <inet/ip.h>

extern int xnet_skip_checks, xnet_check_print, xnet_truncate_print;

/*
 * Common socket access functions.
 *
 * Instead of accessing the sonode switch directly (i.e., SOP_xxx()),
 * the socket_xxx() function should be used.
 */

/*
 * Try to create a new sonode of the requested <family, type, protocol>.
 */
/* ARGSUSED */
struct sonode *
socket_create(int family, int type, int protocol, char *devpath, char *mod,
    int flags, int version, struct cred *cr, int *errorp)
{
	struct sonode *so;
	struct sockparams *sp = NULL;
	int saved_error;

	/*
	 * Look for a sockparams entry that match the given criteria.
	 * solookup() returns with the entry held.
	 */
	*errorp = solookup(family, type, protocol, &sp);
	saved_error = *errorp;
	if (sp == NULL) {
		int kmflags = (flags == SOCKET_SLEEP) ? KM_SLEEP : KM_NOSLEEP;
		/*
		 * There is no matching sockparams entry. An ephemeral entry is
		 * created if the caller specifies a device or a socket module.
		 */
		if (devpath != NULL) {
			saved_error = 0;
			sp = sockparams_hold_ephemeral_bydev(family, type,
			    protocol, devpath, kmflags, errorp);
		} else if (mod != NULL) {
			saved_error = 0;
			sp = sockparams_hold_ephemeral_bymod(family, type,
			    protocol, mod, kmflags, errorp);
		} else {
			*errorp = solookup(family, type, 0, &sp);
		}

		if (sp == NULL) {
			if (saved_error && (*errorp == EPROTONOSUPPORT ||
			    *errorp == EPROTOTYPE || *errorp == ENOPROTOOPT))
				*errorp = saved_error;
			return (NULL);
		}
	}

	ASSERT(sp->sp_smod_info != NULL);
	ASSERT(flags == SOCKET_SLEEP || flags == SOCKET_NOSLEEP);
	sp->sp_stats.sps_ncreate.value.ui64++;
	so = sp->sp_smod_info->smod_sock_create_func(sp, family, type,
	    protocol, version, flags, errorp, cr);
	if (so == NULL) {
		SOCKPARAMS_DEC_REF(sp);
	} else {
		if ((*errorp = SOP_INIT(so, NULL, cr, flags)) == 0) {
			/* Cannot fail, only bumps so_count */
			(void) VOP_OPEN(&SOTOV(so), FREAD|FWRITE, cr, NULL);
		} else {
			if (saved_error && (*errorp == EPROTONOSUPPORT ||
			    *errorp == EPROTOTYPE || *errorp == ENOPROTOOPT))
				*errorp = saved_error;
			socket_destroy(so);
			so = NULL;
		}
	}
	return (so);
}

struct sonode *
socket_newconn(struct sonode *parent, sock_lower_handle_t lh,
    sock_downcalls_t *dc, int flags, int *errorp)
{
	struct sonode *so;
	struct sockparams *sp;
	struct cred *cr;

	if ((cr = CRED()) == NULL)
		cr = kcred;

	sp = parent->so_sockparams;
	ASSERT(sp != NULL);

	sp->sp_stats.sps_ncreate.value.ui64++;
	so = sp->sp_smod_info->smod_sock_create_func(sp, parent->so_family,
	    parent->so_type, parent->so_protocol, parent->so_version, flags,
	    errorp, cr);
	if (so != NULL) {
		SOCKPARAMS_INC_REF(sp);

		so->so_proto_handle = lh;
		so->so_downcalls = dc;
		/*
		 * This function may be called in interrupt context, and CRED()
		 * will be NULL. In this case, pass in kcred.
		 */
		if ((*errorp = SOP_INIT(so, parent, cr, flags)) == 0) {
			/* Cannot fail, only bumps so_count */
			(void) VOP_OPEN(&SOTOV(so), FREAD|FWRITE, cr, NULL);
		} else  {
			socket_destroy(so);
			so = NULL;
		}
	}

	return (so);
}

/*
 * Bind local endpoint.
 */
int
socket_bind(struct sonode *so, struct sockaddr *name, socklen_t namelen,
    int flags, cred_t *cr)
{
	return (SOP_BIND(so, name, namelen, flags, cr));
}

/*
 * Turn socket into a listen socket.
 */
int
socket_listen(struct sonode *so, int backlog, cred_t *cr)
{
	if (backlog < 0) {
		backlog = 0;
	}

	/*
	 * Use the same qlimit as in BSD. BSD checks the qlimit
	 * before queuing the next connection implying that a
	 * listen(sock, 0) allows one connection to be queued.
	 * BSD also uses 1.5 times the requested backlog.
	 *
	 * XNS Issue 4 required a strict interpretation of the backlog.
	 * This has been waived subsequently for Issue 4 and the change
	 * incorporated in XNS Issue 5. So we aren't required to do
	 * anything special for XPG apps.
	 */
	if (backlog >= (INT_MAX - 1) / 3)
		backlog = INT_MAX;
	else
		backlog = backlog * 3 / 2 + 1;

	return (SOP_LISTEN(so, backlog, cr));
}

/*
 * Accept incoming connection.
 */
int
socket_accept(struct sonode *lso, int fflag, cred_t *cr, struct sonode **nsop)
{
	return (SOP_ACCEPT(lso, fflag, cr, nsop));
}

/*
 * Active open.
 */
int
socket_connect(struct sonode *so, struct sockaddr *name,
    socklen_t namelen, int fflag, int flags, cred_t *cr)
{
	int error;

	/*
	 * Handle a connect to a name parameter of type AF_UNSPEC like a
	 * connect to a null address. This is the portable method to
	 * unconnect a socket.
	 */
	if ((namelen >= sizeof (sa_family_t)) &&
	    (name->sa_family == AF_UNSPEC)) {
		name = NULL;
		namelen = 0;
	}

	error = SOP_CONNECT(so, name, namelen, fflag, flags, cr);

	if (error == EHOSTUNREACH && flags & _SOCONNECT_XPG4_2) {
		/*
		 * X/Open specification contains a requirement that
		 * ENETUNREACH be returned but does not require
		 * EHOSTUNREACH. In order to keep the test suite
		 * happy we mess with the errno here.
		 */
		error = ENETUNREACH;
	}

	return (error);
}

/*
 * Get address of remote node.
 */
int
socket_getpeername(struct sonode *so, struct sockaddr *addr,
    socklen_t *addrlen, boolean_t accept, cred_t *cr)
{
	ASSERT(*addrlen > 0);
	return (SOP_GETPEERNAME(so, addr, addrlen, accept, cr));

}

/*
 * Get local address.
 */
int
socket_getsockname(struct sonode *so, struct sockaddr *addr,
    socklen_t *addrlen, cred_t *cr)
{
	return (SOP_GETSOCKNAME(so, addr, addrlen, cr));

}

/*
 * Called from shutdown().
 */
int
socket_shutdown(struct sonode *so, int how, cred_t *cr)
{
	return (SOP_SHUTDOWN(so, how, cr));
}

/*
 * Get socket options.
 */
/*ARGSUSED*/
int
socket_getsockopt(struct sonode *so, int level, int option_name,
    void *optval, socklen_t *optlenp, int flags, cred_t *cr)
{
	return (SOP_GETSOCKOPT(so, level, option_name, optval,
	    optlenp, flags, cr));
}

/*
 * Set socket options
 */
int
socket_setsockopt(struct sonode *so, int level, int option_name,
    const void *optval, t_uscalar_t optlen, cred_t *cr)
{
	int val = 1;
	/* Caller allocates aligned optval, or passes null */
	ASSERT(((uintptr_t)optval & (sizeof (t_scalar_t) - 1)) == 0);
	/* If optval is null optlen is 0, and vice-versa */
	ASSERT(optval != NULL || optlen == 0);
	ASSERT(optlen != 0 || optval == NULL);

	if (optval == NULL && optlen == 0)
		optval = &val;

	return (SOP_SETSOCKOPT(so, level, option_name, optval, optlen, cr));
}

int
socket_sendmsg(struct sonode *so, struct nmsghdr *msg, struct uio *uiop,
    cred_t *cr)
{
	int error = 0;
	ssize_t orig_resid = uiop->uio_resid;

	/*
	 * Do not bypass the cache if we are doing a local (AF_UNIX) write.
	 */
	if (so->so_family == AF_UNIX)
		uiop->uio_extflg |= UIO_COPY_CACHED;
	else
		uiop->uio_extflg &= ~UIO_COPY_CACHED;

	error = SOP_SENDMSG(so, msg, uiop, cr);
	switch (error) {
	default:
		break;
	case EINTR:
	case ENOMEM:
	/* EAGAIN is EWOULDBLOCK */
	case EWOULDBLOCK:
		/* We did a partial send */
		if (uiop->uio_resid != orig_resid)
			error = 0;
		break;
	case EPIPE:
		if (((so->so_mode & SM_KERNEL) == 0) &&
		    ((msg->msg_flags & MSG_NOSIGNAL) == 0)) {
			tsignal(curthread, SIGPIPE);
		}
		break;
	}

	return (error);
}

int
socket_sendmblk(struct sonode *so, struct nmsghdr *msg, int fflag,
    struct cred *cr, mblk_t **mpp)
{
	int error = 0;

	error = SOP_SENDMBLK(so, msg, fflag, cr, mpp);
	if (error == EPIPE) {
		tsignal(curthread, SIGPIPE);
	}
	return (error);
}

int
socket_recvmsg(struct sonode *so, struct nmsghdr *msg, struct uio *uiop,
    cred_t *cr)
{
	int error;
	ssize_t orig_resid = uiop->uio_resid;

	/*
	 * Do not bypass the cache when reading data, as the application
	 * is likely to access the data shortly.
	 */
	uiop->uio_extflg |= UIO_COPY_CACHED;

	error = SOP_RECVMSG(so, msg, uiop, cr);

	switch (error) {
	case EINTR:
	/* EAGAIN is EWOULDBLOCK */
	case EWOULDBLOCK:
		/* We did a partial read */
		if (uiop->uio_resid != orig_resid)
			error = 0;
		break;
	default:
		break;
	}
	return (error);
}

int
socket_ioctl(struct sonode *so, int cmd, intptr_t arg, int mode,
    struct cred *cr, int32_t *rvalp)
{
	return (SOP_IOCTL(so, cmd, arg, mode, cr, rvalp));
}

int
socket_poll(struct sonode *so, short events, int anyyet, short *reventsp,
    struct pollhead **phpp)
{
	return (SOP_POLL(so, events, anyyet, reventsp, phpp));
}

int
socket_close(struct sonode *so, int flag, struct cred *cr)
{
	return (VOP_CLOSE(SOTOV(so), flag, 1, 0, cr, NULL));
}

int
socket_close_internal(struct sonode *so, int flag, cred_t *cr)
{
	ASSERT(so->so_count == 0);

	return (SOP_CLOSE(so, flag, cr));
}

void
socket_destroy(struct sonode *so)
{
	vn_invalid(SOTOV(so));
	VN_RELE(SOTOV(so));
}

/* ARGSUSED */
void
socket_destroy_internal(struct sonode *so, cred_t *cr)
{
	struct sockparams *sp = so->so_sockparams;
	ASSERT(so->so_count == 0 && sp != NULL);

	sp->sp_smod_info->smod_sock_destroy_func(so);

	SOCKPARAMS_DEC_REF(sp);
}

/*
 * TODO Once the common vnode ops is available, then the vnops argument
 * should be removed.
 */
/*ARGSUSED*/
int
sonode_constructor(void *buf, void *cdrarg, int kmflags)
{
	struct sonode *so = buf;
	struct vnode *vp;

	vp = so->so_vnode = vn_alloc(kmflags);
	if (vp == NULL) {
		return (-1);
	}
	vp->v_data = so;
	vn_setops(vp, socket_vnodeops);

	so->so_priv 		= NULL;
	so->so_oobmsg		= NULL;

	so->so_proto_handle	= NULL;

	so->so_peercred 	= NULL;

	so->so_rcv_queued	= 0;
	so->so_rcv_q_head 	= NULL;
	so->so_rcv_q_last_head 	= NULL;
	so->so_rcv_head		= NULL;
	so->so_rcv_last_head	= NULL;
	so->so_rcv_wanted	= 0;
	so->so_rcv_timer_interval = SOCKET_NO_RCVTIMER;
	so->so_rcv_timer_tid	= 0;
	so->so_rcv_thresh	= 0;

	list_create(&so->so_acceptq_list, sizeof (struct sonode),
	    offsetof(struct sonode, so_acceptq_node));
	list_create(&so->so_acceptq_defer, sizeof (struct sonode),
	    offsetof(struct sonode, so_acceptq_node));
	list_link_init(&so->so_acceptq_node);
	so->so_acceptq_len	= 0;
	so->so_backlog		= 0;
	so->so_listener		= NULL;

	so->so_snd_qfull	= B_FALSE;

	so->so_filter_active	= 0;
	so->so_filter_tx	= 0;
	so->so_filter_defertime = 0;
	so->so_filter_top	= NULL;
	so->so_filter_bottom	= NULL;

	mutex_init(&so->so_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&so->so_acceptq_lock, NULL, MUTEX_DEFAULT, NULL);
	rw_init(&so->so_fallback_rwlock, NULL, RW_DEFAULT, NULL);
	cv_init(&so->so_state_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&so->so_single_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&so->so_read_cv, NULL, CV_DEFAULT, NULL);

	cv_init(&so->so_acceptq_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&so->so_snd_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&so->so_rcv_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&so->so_copy_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&so->so_closing_cv, NULL, CV_DEFAULT, NULL);

	return (0);
}

/*ARGSUSED*/
void
sonode_destructor(void *buf, void *cdrarg)
{
	struct sonode *so = buf;
	struct vnode *vp = SOTOV(so);

	ASSERT(so->so_priv == NULL);
	ASSERT(so->so_peercred == NULL);

	ASSERT(so->so_oobmsg == NULL);

	ASSERT(so->so_rcv_q_head == NULL);

	list_destroy(&so->so_acceptq_list);
	list_destroy(&so->so_acceptq_defer);
	ASSERT(!list_link_active(&so->so_acceptq_node));
	ASSERT(so->so_listener == NULL);

	ASSERT(so->so_filter_active == 0);
	ASSERT(so->so_filter_tx == 0);
	ASSERT(so->so_filter_top == NULL);
	ASSERT(so->so_filter_bottom == NULL);

	ASSERT(vp->v_data == so);
	ASSERT(vn_matchops(vp, socket_vnodeops));

	vn_free(vp);

	mutex_destroy(&so->so_lock);
	mutex_destroy(&so->so_acceptq_lock);
	rw_destroy(&so->so_fallback_rwlock);

	cv_destroy(&so->so_state_cv);
	cv_destroy(&so->so_single_cv);
	cv_destroy(&so->so_read_cv);
	cv_destroy(&so->so_acceptq_cv);
	cv_destroy(&so->so_snd_cv);
	cv_destroy(&so->so_rcv_cv);
	cv_destroy(&so->so_closing_cv);
}

void
sonode_init(struct sonode *so, struct sockparams *sp, int family,
    int type, int protocol, sonodeops_t *sops)
{
	vnode_t *vp;

	vp = SOTOV(so);

	so->so_flag	= 0;

	so->so_state	= 0;
	so->so_mode	= 0;

	so->so_count	= 0;

	so->so_family	= family;
	so->so_type	= type;
	so->so_protocol	= protocol;

	SOCK_CONNID_INIT(so->so_proto_connid);

	so->so_options	= 0;
	so->so_linger.l_onoff   = 0;
	so->so_linger.l_linger = 0;
	so->so_sndbuf	= 0;
	so->so_error	= 0;
	so->so_rcvtimeo	= 0;
	so->so_sndtimeo = 0;
	so->so_xpg_rcvbuf = 0;

	ASSERT(so->so_oobmsg == NULL);
	so->so_oobmark	= 0;
	so->so_pgrp	= 0;

	ASSERT(so->so_peercred == NULL);

	so->so_zoneid = getzoneid();

	so->so_sockparams = sp;

	so->so_ops = sops;

	so->so_not_str = (sops != &sotpi_sonodeops);

	so->so_proto_handle = NULL;

	so->so_downcalls = NULL;

	so->so_copyflag = 0;

	vn_reinit(vp);
	vp->v_vfsp	= rootvfs;
	vp->v_type	= VSOCK;
	vp->v_rdev	= sockdev;

	so->so_snd_qfull = B_FALSE;
	so->so_minpsz = 0;

	so->so_rcv_wakeup = B_FALSE;
	so->so_snd_wakeup = B_FALSE;
	so->so_flowctrld = B_FALSE;

	so->so_pollev = 0;
	bzero(&so->so_poll_list, sizeof (so->so_poll_list));
	bzero(&so->so_proto_props, sizeof (struct sock_proto_props));

	bzero(&(so->so_ksock_callbacks), sizeof (ksocket_callbacks_t));
	so->so_ksock_cb_arg = NULL;

	so->so_max_addr_len = sizeof (struct sockaddr_storage);

	so->so_direct = NULL;

	vn_exists(vp);
}

void
sonode_fini(struct sonode *so)
{
	vnode_t *vp;

	ASSERT(so->so_count == 0);

	if (so->so_rcv_timer_tid) {
		ASSERT(MUTEX_NOT_HELD(&so->so_lock));
		(void) untimeout(so->so_rcv_timer_tid);
		so->so_rcv_timer_tid = 0;
	}

	if (so->so_poll_list.ph_list != NULL) {
		pollwakeup(&so->so_poll_list, POLLERR);
		pollhead_clean(&so->so_poll_list);
	}

	if (so->so_direct != NULL)
		sod_sock_fini(so);

	vp = SOTOV(so);
	vn_invalid(vp);

	if (so->so_peercred != NULL) {
		crfree(so->so_peercred);
		so->so_peercred = NULL;
	}
	/* Detach and destroy filters */
	if (so->so_filter_top != NULL)
		sof_sonode_cleanup(so);

	ASSERT(list_is_empty(&so->so_acceptq_list));
	ASSERT(list_is_empty(&so->so_acceptq_defer));
	ASSERT(!list_link_active(&so->so_acceptq_node));

	ASSERT(so->so_rcv_queued == 0);
	ASSERT(so->so_rcv_q_head == NULL);
	ASSERT(so->so_rcv_q_last_head == NULL);
	ASSERT(so->so_rcv_head == NULL);
	ASSERT(so->so_rcv_last_head == NULL);
}
