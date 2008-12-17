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
#include <sys/sodirect.h>
#include <sys/uio.h>

#include <inet/ipclassifier.h>
#include <fs/sockfs/sockcommon.h>
#include <fs/sockfs/nl7c.h>
#include <fs/sockfs/socktpi.h>
#include <inet/ip.h>

extern int xnet_skip_checks, xnet_check_print, xnet_truncate_print;

static struct kmem_cache *sock_sod_cache;

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

	/*
	 * Look for a sockparams entry that match the given criteria.
	 * solookup() returns with the entry held.
	 */
	*errorp = solookup(family, type, protocol, &sp);
	if (sp == NULL) {
		int kmflags = (flags == SOCKET_SLEEP) ? KM_SLEEP : KM_NOSLEEP;
		/*
		 * There is no matching sockparams entry. An ephemeral entry is
		 * created if the caller specifies a device or a socket module.
		 */
		if (devpath != NULL) {
			sp = sockparams_hold_ephemeral_bydev(family, type,
			    protocol, devpath, kmflags, errorp);
		} else if (mod != NULL) {
			sp = sockparams_hold_ephemeral_bymod(family, type,
			    protocol, mod, kmflags, errorp);
		} else {
			return (NULL);
		}

		if (sp == NULL)
			return (NULL);
	}

	ASSERT(sp->sp_smod_info != NULL);
	ASSERT(flags == SOCKET_SLEEP || flags == SOCKET_NOSLEEP);
	so = sp->sp_smod_info->smod_sock_create_func(sp, family, type,
	    protocol, version, flags, errorp, cr);
	if (so == NULL) {
		SOCKPARAMS_DEC_REF(sp);
	} else {
		if ((*errorp = SOP_INIT(so, NULL, cr, flags)) == 0) {
			/* Cannot fail, only bumps so_count */
			(void) VOP_OPEN(&SOTOV(so), FREAD|FWRITE, cr, NULL);
		} else {
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
socket_connect(struct sonode *so, const struct sockaddr *name,
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
	/* Caller allocates aligned optval, or passes null */
	ASSERT(((uintptr_t)optval & (sizeof (t_scalar_t) - 1)) == 0);
	/* If optval is null optlen is 0, and vice-versa */
	ASSERT(optval != NULL || optlen == 0);
	ASSERT(optlen != 0 || optval == NULL);

	/* No options should be zero-length */
	if (optlen == 0)
		return (EINVAL);

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
	case ETIME:
	case EWOULDBLOCK:
		/* We did a partial send */
		if (uiop->uio_resid != orig_resid)
			error = 0;
		break;
	case EPIPE:
		if ((so->so_mode & SM_KERNEL) == 0)
			tsignal(curthread, SIGPIPE);
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
	case ETIME:
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

	so->so_acceptq_head	= NULL;
	so->so_acceptq_tail	= &so->so_acceptq_head;
	so->so_acceptq_next	= NULL;
	so->so_acceptq_len	= 0;
	so->so_backlog		= 0;

	so->so_snd_qfull	= B_FALSE;

	mutex_init(&so->so_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&so->so_acceptq_lock, NULL, MUTEX_DEFAULT, NULL);
	rw_init(&so->so_fallback_rwlock, NULL, RW_DEFAULT, NULL);
	cv_init(&so->so_state_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&so->so_want_cv, NULL, CV_DEFAULT, NULL);

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

	ASSERT(so->so_acceptq_head == NULL);
	ASSERT(so->so_acceptq_tail == &so->so_acceptq_head);
	ASSERT(so->so_acceptq_next == NULL);

	ASSERT(vp->v_data == so);
	ASSERT(vn_matchops(vp, socket_vnodeops));

	vn_free(vp);

	mutex_destroy(&so->so_lock);
	mutex_destroy(&so->so_acceptq_lock);
	rw_destroy(&so->so_fallback_rwlock);

	cv_destroy(&so->so_state_cv);
	cv_destroy(&so->so_want_cv);
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

	ASSERT(so->so_acceptq_head == NULL);
	ASSERT(so->so_acceptq_tail == &so->so_acceptq_head);
	ASSERT(so->so_acceptq_next == NULL);

	vn_reinit(vp);
	vp->v_vfsp	= rootvfs;
	vp->v_type	= VSOCK;
	vp->v_rdev	= sockdev;

	so->so_rcv_queued = 0;
	so->so_rcv_q_head = NULL;
	so->so_rcv_q_last_head = NULL;
	so->so_rcv_head	= NULL;
	so->so_rcv_last_head = NULL;

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
	mblk_t *mp;
	vnode_t *vp;

	ASSERT(so->so_count == 0);

	if (so->so_rcv_timer_tid) {
		ASSERT(MUTEX_NOT_HELD(&so->so_lock));
		(void) untimeout(so->so_rcv_timer_tid);
		so->so_rcv_timer_tid = 0;
	}

	so_acceptq_flush(so);

	if ((mp = so->so_oobmsg) != NULL) {
		freemsg(mp);
		so->so_oobmsg = NULL;
		so->so_state &= ~(SS_OOBPEND|SS_HAVEOOBDATA|SS_HADOOBDATA|
		    SS_RCVATMARK);
	}

	if (so->so_poll_list.ph_list != NULL) {
		pollwakeup(&so->so_poll_list, POLLERR);
		pollhead_clean(&so->so_poll_list);
	}

	if (so->so_direct != NULL) {
		sodirect_t *sodp = so->so_direct;

		ASSERT(sodp->sod_uioafh == NULL);

		so->so_direct = NULL;
		kmem_cache_free(sock_sod_cache, sodp);
	}

	vp = SOTOV(so);
	vn_invalid(vp);

	if (so->so_peercred != NULL) {
		crfree(so->so_peercred);
		so->so_peercred = NULL;
	}
}

/*
 * This function is called at the beginning of recvmsg().
 *
 * If I/OAT is enabled on this sonode, initialize the uioa state machine
 * with state UIOA_ALLOC.
 */
uio_t *
sod_rcv_init(struct sonode *so, int flags, struct uio **uiopp)
{
	struct uio *suiop;
	struct uio *uiop;
	sodirect_t *sodp = so->so_direct;

	if (sodp == NULL)
		return (NULL);

	suiop = NULL;
	uiop = *uiopp;

	mutex_enter(sodp->sod_lockp);
	if (uiop->uio_resid >= uioasync.mincnt &&
	    sodp != NULL && (sodp->sod_state & SOD_ENABLED) &&
	    uioasync.enabled && !(flags & MSG_PEEK) &&
	    !(so->so_state & SS_CANTRCVMORE)) {
		/*
		 * Big enough I/O for uioa min setup and an sodirect socket
		 * and sodirect enabled and uioa enabled and I/O will be done
		 * and not EOF so initialize the sodirect_t uioa_t with "uiop".
		 */
		if (!uioainit(uiop, &sodp->sod_uioa)) {
			/*
			 * Successful uioainit() so the uio_t part of the
			 * uioa_t will be used for all uio_t work to follow,
			 * we return the original "uiop" in "suiop".
			 */
			suiop = uiop;
			*uiopp = (uio_t *)&sodp->sod_uioa;
			/*
			 * Before returning to the caller the passed in uio_t
			 * "uiop" will be updated via a call to uioafini()
			 * below.
			 *
			 * Note, the uioa.uioa_state isn't set to UIOA_ENABLED
			 * here as first we have to uioamove() any currently
			 * queued M_DATA mblk_t(s) so it will be done later.
			 */
		}
		/*
		 * In either uioainit() success or not case note the number
		 * of uio bytes the caller wants for sod framework and/or
		 * transport (e.g. TCP) strategy.
		 */
		sodp->sod_want = uiop->uio_resid;
	} else if (sodp != NULL && (sodp->sod_state & SOD_ENABLED)) {
		/*
		 * No uioa but still using sodirect so note the number of
		 * uio bytes the caller wants for sodirect framework and/or
		 * transport (e.g. TCP) strategy.
		 */
		sodp->sod_want = uiop->uio_resid;
	}
	mutex_exit(sodp->sod_lockp);

	return (suiop);
}

/*
 * This function is called at the end of recvmsg(), it finializes all the I/OAT
 * operations, and reset the uioa state to UIOA_ALLOC.
 */
int
sod_rcv_done(struct sonode *so, struct uio *suiop, struct uio *uiop)
{
	int error = 0;
	sodirect_t *sodp = so->so_direct;
	mblk_t *mp;

	if (sodp == NULL) {
		return (0);
	}

	ASSERT(MUTEX_HELD(sodp->sod_lockp));
	/* Finish any sodirect and uioa processing */
	if (suiop != NULL) {
		/* Finish any uioa_t processing */

		ASSERT(uiop == (uio_t *)&sodp->sod_uioa);
		error = uioafini(suiop, (uioa_t *)uiop);
		if ((mp = sodp->sod_uioafh) != NULL) {
			sodp->sod_uioafh = NULL;
			sodp->sod_uioaft = NULL;
			freemsg(mp);
		}
	}
	ASSERT(sodp->sod_uioafh == NULL);
	if (!(sodp->sod_state & SOD_WAKE_NOT)) {
		/* Awoke */
		sodp->sod_state &= SOD_WAKE_CLR;
		sodp->sod_state |= SOD_WAKE_NOT;
	}
	/* Last, clear sod_want value */
	sodp->sod_want = 0;

	return (error);
}

/*
 * Schedule a uioamove() on a mblk. This is ususally called from
 * protocols (e.g. TCP) on a I/OAT enabled sonode.
 */
mblk_t *
sod_uioa_mblk_init(struct sodirect_s *sodp, mblk_t *mp, size_t msg_size)
{
	uioa_t *uioap = &sodp->sod_uioa;
	mblk_t *mp1 = mp;
	mblk_t *lmp = NULL;

	ASSERT(DB_TYPE(mp) == M_DATA);
	ASSERT(msg_size == msgdsize(mp));

	/* Caller must have lock held */
	ASSERT(MUTEX_HELD(sodp->sod_lockp));

	if (uioap->uioa_state & UIOA_ENABLED) {
		/* Uioa is enabled */

		if (msg_size > uioap->uio_resid) {
			/*
			 * There isn't enough uio space for the mblk_t chain
			 * so disable uioa such that this and any additional
			 * mblk_t data is handled by the socket and schedule
			 * the socket for wakeup to finish this uioa.
			 */
			uioap->uioa_state &= UIOA_CLR;
			uioap->uioa_state |= UIOA_FINI;
			if (sodp->sod_state & SOD_WAKE_NOT) {
				sodp->sod_state &= SOD_WAKE_CLR;
				sodp->sod_state |= SOD_WAKE_NEED;
			}
			return (mp);
		}
		do {
			uint32_t	len = MBLKL(mp1);

			if (!uioamove(mp1->b_rptr, len, UIO_READ, uioap)) {
				/* Scheduled, mark dblk_t as such */
				DB_FLAGS(mp1) |= DBLK_UIOA;
			} else {
				/* Error, turn off async processing */
				uioap->uioa_state &= UIOA_CLR;
				uioap->uioa_state |= UIOA_FINI;
				break;
			}
			lmp = mp1;
		} while ((mp1 = mp1->b_cont) != NULL);

		if (mp1 != NULL || uioap->uio_resid == 0) {
			/*
			 * Not all mblk_t(s) uioamoved (error) or all uio
			 * space has been consumed so schedule the socket
			 * for wakeup to finish this uio.
			 */
			sodp->sod_state &= SOD_WAKE_CLR;
			sodp->sod_state |= SOD_WAKE_NEED;

			/* Break the mblk chain if neccessary. */
			if (mp1 != NULL && lmp != NULL) {
				mp->b_next = mp1;
				lmp->b_cont = NULL;
			}
		}
	}
	return (mp1);
}

/*
 * This function is called on a mblk that thas been successfully uioamoved().
 */
void
sod_uioa_mblk_done(sodirect_t *sodp, mblk_t *bp)
{
	if (bp != NULL && (bp->b_datap->db_flags & DBLK_UIOA)) {
		/*
		 * A uioa flaged mblk_t chain, already uio processed,
		 * add it to the sodirect uioa pending free list.
		 *
		 * Note, a b_cont chain headed by a DBLK_UIOA enable
		 * mblk_t must have all mblk_t(s) DBLK_UIOA enabled.
		 */
		mblk_t	*bpt = sodp->sod_uioaft;

		ASSERT(sodp != NULL);

		/*
		 * Add first mblk_t of "bp" chain to current sodirect uioa
		 * free list tail mblk_t, if any, else empty list so new head.
		 */
		if (bpt == NULL)
			sodp->sod_uioafh = bp;
		else
			bpt->b_cont = bp;

		/*
		 * Walk mblk_t "bp" chain to find tail and adjust rptr of
		 * each to reflect that uioamove() has consumed all data.
		 */
		bpt = bp;
		for (;;) {
			ASSERT(bpt->b_datap->db_flags & DBLK_UIOA);

			bpt->b_rptr = bpt->b_wptr;
			if (bpt->b_cont == NULL)
				break;
			bpt = bpt->b_cont;
		}
		/* New sodirect uioa free list tail */
		sodp->sod_uioaft = bpt;

		/* Only dequeue once with data returned per uioa_t */
		if (sodp->sod_uioa.uioa_state & UIOA_ENABLED) {
			sodp->sod_uioa.uioa_state &= UIOA_CLR;
			sodp->sod_uioa.uioa_state |= UIOA_FINI;
		}
	}
}

/*
 * When transit from UIOA_INIT state to UIOA_ENABLE state in recvmsg(), call
 * this function on a non-STREAMS socket to schedule uioamove() on the data
 * that has already queued in this socket.
 */
void
sod_uioa_so_init(struct sonode *so, struct sodirect_s *sodp, struct uio *uiop)
{
	uioa_t	*uioap = (uioa_t *)uiop;
	mblk_t	*lbp;
	mblk_t	*wbp;
	mblk_t	*bp;
	int	len;
	int	error;
	boolean_t in_rcv_q = B_TRUE;

	ASSERT(MUTEX_HELD(sodp->sod_lockp));
	ASSERT(&sodp->sod_uioa == uioap);

	/*
	 * Walk first b_cont chain in sod_q
	 * and schedule any M_DATA mblk_t's for uio asynchronous move.
	 */
	bp = so->so_rcv_q_head;

again:
	/* Walk the chain */
	lbp = NULL;
	wbp = bp;

	do {
		if (bp == NULL)
			break;

		if (wbp->b_datap->db_type != M_DATA) {
			/* Not M_DATA, no more uioa */
			goto nouioa;
		}
		if ((len = wbp->b_wptr - wbp->b_rptr) > 0) {
			/* Have a M_DATA mblk_t with data */
			if (len > uioap->uio_resid || (so->so_oobmark > 0 &&
			    len + uioap->uioa_mbytes >= so->so_oobmark)) {
				/* Not enough uio sapce, or beyond oobmark */
				goto nouioa;
			}
			ASSERT(!(wbp->b_datap->db_flags & DBLK_UIOA));
			error = uioamove(wbp->b_rptr, len,
			    UIO_READ, uioap);
			if (!error) {
				/* Scheduled, mark dblk_t as such */
				wbp->b_datap->db_flags |= DBLK_UIOA;
			} else {
				/* Break the mblk chain */
				goto nouioa;
			}
		}
		/* Save last wbp processed */
		lbp = wbp;
	} while ((wbp = wbp->b_cont) != NULL);

	if (in_rcv_q && (bp == NULL || bp->b_next == NULL)) {
		/*
		 * We get here only once to process the sonode dump area
		 * if so_rcv_q_head is NULL or all the mblks have been
		 * successfully uioamoved()ed.
		 */
		in_rcv_q = B_FALSE;

		/* move to dump area */
		bp = so->so_rcv_head;
		goto again;
	}

	return;

nouioa:
	/* No more uioa */
	uioap->uioa_state &= UIOA_CLR;
	uioap->uioa_state |= UIOA_FINI;

	/*
	 * If we processed 1 or more mblk_t(s) then we need to split the
	 * current mblk_t chain in 2 so that all the uioamove()ed mblk_t(s)
	 * are in the current chain and the rest are in the following new
	 * chain.
	 */
	if (lbp != NULL) {
		/* New end of current chain */
		lbp->b_cont = NULL;

		/* Insert new chain wbp after bp */
		if ((wbp->b_next = bp->b_next) == NULL) {
			/*
			 * No need to grab so_lock, since sod_lockp
			 * points to so_lock.
			 */
			if (in_rcv_q)
				so->so_rcv_q_last_head = wbp;
			else
				so->so_rcv_last_head = wbp;
		}
		bp->b_next = wbp;
		bp->b_next->b_prev = bp->b_prev;
		bp->b_prev = lbp;
	}
}

/*
 * Initialize sodirect data structures on a socket.
 */
void
sod_sock_init(struct sonode *so, struct stdata *stp, sod_enq_func enq_func,
    sod_wakeup_func wake_func, kmutex_t *lockp)
{
	sodirect_t	*sodp;

	ASSERT(so->so_direct == NULL);

	so->so_state |= SS_SODIRECT;

	sodp = kmem_cache_alloc(sock_sod_cache, KM_SLEEP);
	sodp->sod_state = SOD_ENABLED | SOD_WAKE_NOT;
	sodp->sod_want = 0;
	sodp->sod_q = (stp != NULL) ? RD(stp->sd_wrq) : NULL;
	sodp->sod_enqueue = enq_func;
	sodp->sod_wakeup = wake_func;
	sodp->sod_uioafh = NULL;
	sodp->sod_uioaft = NULL;
	sodp->sod_lockp = lockp;
	/*
	 * Remainder of the sod_uioa members are left uninitialized
	 * but will be initialized later by uioainit() before uioa
	 * is enabled.
	 */
	sodp->sod_uioa.uioa_state = UIOA_ALLOC;
	so->so_direct = sodp;
	if (stp != NULL)
		stp->sd_sodirect = sodp;
}

/*
 * Init the sodirect kmem cache while sockfs is loading.
 */
void
sod_init()
{
	/* Allocate sodirect_t kmem_cache */
	sock_sod_cache = kmem_cache_create("sock_sod_cache",
	    sizeof (sodirect_t), 0, NULL, NULL, NULL, NULL, NULL, 0);
}

ssize_t
sod_uioa_mblk(struct sonode *so, mblk_t *mp)
{
	sodirect_t *sodp = so->so_direct;

	ASSERT(sodp != NULL);
	ASSERT(MUTEX_HELD(sodp->sod_lockp));

	ASSERT(sodp->sod_state & SOD_ENABLED);
	ASSERT(sodp->sod_uioa.uioa_state != (UIOA_ALLOC|UIOA_INIT));

	ASSERT(sodp->sod_uioa.uioa_state & (UIOA_ENABLED|UIOA_FINI));

	if (mp == NULL && so->so_rcv_q_head != NULL) {
		mp = so->so_rcv_q_head;
		ASSERT(mp->b_prev != NULL);
		mp->b_prev = NULL;
		so->so_rcv_q_head = mp->b_next;
		if (so->so_rcv_q_head == NULL) {
			so->so_rcv_q_last_head = NULL;
		}
		mp->b_next = NULL;
	}

	sod_uioa_mblk_done(sodp, mp);

	if (so->so_rcv_q_head == NULL && so->so_rcv_head != NULL &&
	    DB_TYPE(so->so_rcv_head) == M_DATA &&
	    (DB_FLAGS(so->so_rcv_head) & DBLK_UIOA)) {
		/* more arrived */
		ASSERT(so->so_rcv_q_head == NULL);
		mp = so->so_rcv_head;
		so->so_rcv_head = mp->b_next;
		if (so->so_rcv_head == NULL)
			so->so_rcv_last_head = NULL;
		mp->b_prev = mp->b_next = NULL;
		sod_uioa_mblk_done(sodp, mp);
	}

#ifdef DEBUG
	if (so->so_rcv_q_head != NULL) {
		mblk_t *m = so->so_rcv_q_head;
		while (m != NULL) {
			if (DB_FLAGS(m) & DBLK_UIOA) {
				cmn_err(CE_PANIC, "Unexpected I/OAT mblk %p"
				    " in so_rcv_q_head.\n", (void *)m);
			}
			m = m->b_next;
		}
	}
	if (so->so_rcv_head != NULL) {
		mblk_t *m = so->so_rcv_head;
		while (m != NULL) {
			if (DB_FLAGS(m) & DBLK_UIOA) {
				cmn_err(CE_PANIC, "Unexpected I/OAT mblk %p"
				    " in so_rcv_head.\n", (void *)m);
			}
			m = m->b_next;
		}
	}
#endif
	return (sodp->sod_uioa.uioa_mbytes);
}
