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

#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/buf.h>
#include <sys/debug.h>
#include <sys/errno.h>
#include <sys/uio.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/vnode.h>
#include <sys/stropts.h>
#include <sys/cmn_err.h>
#include <sys/sysmacros.h>
#include <sys/stream.h>
#include <sys/strsun.h>

#include <sys/socket.h>
#include <sys/socketvar.h>

#include <sys/project.h>
#include <sys/strsubr.h>

#include <fs/fs_subr.h>

#include <sys/esunddi.h>
#include <sys/ddi.h>

#include <sys/filio.h>
#include <sys/sockio.h>

#include <inet/sdp_itf.h>
#include "socksdp.h"

/*
 * SDP sockfs vnode operations
 */
static int socksdpv_open(struct vnode **, int, struct cred *,
    caller_context_t *);
static int socksdpv_close(struct vnode *, int, int, offset_t,
    struct cred *, caller_context_t *);
static int socksdpv_read(struct vnode *, struct uio *, int, struct cred *,
    caller_context_t *);
static int socksdpv_write(struct vnode *, struct uio *, int, struct cred *,
    caller_context_t *);
static int socksdpv_ioctl(struct vnode *, int, intptr_t, int,
    struct cred *, int32_t *, caller_context_t *);
static int socksdp_setfl(vnode_t *, int, int, cred_t *, caller_context_t *);
static void socksdpv_inactive(struct vnode *, struct cred *,
    caller_context_t *);
static int socksdpv_poll(struct vnode *, short, int, short *,
    struct pollhead **, caller_context_t *);

const fs_operation_def_t socksdp_vnodeops_template[] = {
	VOPNAME_OPEN,		{ .vop_open = socksdpv_open },
	VOPNAME_CLOSE,		{ .vop_close = socksdpv_close },
	VOPNAME_READ,		{ .vop_read = socksdpv_read },
	VOPNAME_WRITE,		{ .vop_write = socksdpv_write },
	VOPNAME_IOCTL,		{ .vop_ioctl = socksdpv_ioctl },
	VOPNAME_SETFL,		{ .vop_setfl = socksdp_setfl },
	VOPNAME_GETATTR,	{ .vop_getattr = socktpi_getattr },
	VOPNAME_SETATTR,	{ .vop_setattr = socktpi_setattr },
	VOPNAME_ACCESS,		{ .vop_access = socktpi_access },
	VOPNAME_FSYNC,		{ .vop_fsync = socktpi_fsync },
	VOPNAME_INACTIVE,	{ .vop_inactive = socksdpv_inactive },
	VOPNAME_FID,		{ .vop_fid = socktpi_fid },
	VOPNAME_SEEK,		{ .vop_seek = socktpi_seek },
	VOPNAME_POLL,		{ .vop_poll = socksdpv_poll },
	VOPNAME_DISPOSE,	{ .error = fs_error },
	NULL,			NULL
};
struct vnodeops *socksdp_vnodeops;

/*ARGSUSED3*/
static int
socksdpv_open(struct vnode **vpp, int flag, struct cred *cr,
    caller_context_t *ct)
{
	struct sonode *so;
	struct sdp_sonode *ss;
	struct vnode *vp = *vpp;
	int error = EPROTONOSUPPORT;	/* in case sdpib fails to load */
	sdp_sockbuf_limits_t sbl;
	sdp_upcalls_t *upcalls;

	flag &= ~FCREAT;		/* paranoia */

	so = VTOSO(vp);
	ss = SOTOSDO(so);

	mutex_enter(&so->so_lock);
	so->so_count++;			/* one more open reference */
	ASSERT(so->so_count != 0);	/* wraparound */
	mutex_exit(&so->so_lock);

	ASSERT(vp->v_type == VSOCK);

	if (flag & SO_ACCEPTOR) {
		ASSERT(so->so_type == SOCK_STREAM);
		return (0);
	}

	/*
	 * Active open.
	 */
	upcalls = &sosdp_sock_upcalls;

	/*
	 * When the necessary hardware is not available, the sdp_create stub
	 * will evaluate to nomod_zero, which leaves 'error' untouched. Hence
	 * the EPROTONOSUPPORT above. A successful call to sdp_create clears
	 * the error.
	 */
	so->so_priv = sdp_create(ss, NULL, so->so_family, SDP_CAN_BLOCK,
	    upcalls, &sbl, cr, &error);
	if (so->so_priv == NULL) {
		ASSERT(error != 0);
		mutex_enter(&so->so_lock);
		ASSERT(so->so_count > 0);
		so->so_count--;		/* one less open reference */
		mutex_exit(&so->so_lock);
		return (error);
	}
	so->so_rcvbuf = sbl.sbl_rxbuf;
	so->so_rcvlowat = sbl.sbl_rxlowat;
	so->so_sndbuf = sbl.sbl_txbuf;
	so->so_sndlowat = sbl.sbl_txlowat;

	return (error);
}

/*ARGSUSED*/
static int
socksdpv_close(struct vnode *vp, int flag, int count, offset_t offset,
    struct cred *cr, caller_context_t *ct)
{
	int sendsig = 0;
	int error = 0;
	struct sonode *so;
	struct sdp_sonode *ss;

	so = VTOSO(vp);
	ss = SOTOSDO(so);

	cleanlocks(vp, ttoproc(curthread)->p_pid, 0);
	cleanshares(vp, ttoproc(curthread)->p_pid);

	ASSERT(vp->v_stream == NULL);
	if (count > 1) {
		dprint(2, ("socksdpv_close: count %d\n", count));
		return (0);
	}

	mutex_enter(&so->so_lock);
	so_lock_single(so);	/* Set SOLOCKED */
	ASSERT(so->so_count > 0);
	so->so_count--;			/* one fewer open reference */

	dprint(2, ("socksdpv_close: %p so_count %d\n", so, so->so_count));

	if (so->so_count == 0) {
		/*
		 * Need to set flags as there might be ops in progress on
		 * this socket.
		 *
		 * If socket already disconnected/disconnecting,
		 * don't send signal (again).
		 */
		if (!(so->so_state & SS_CANTRCVMORE))
			sendsig |= SDPSIG_READ;
		if (!(so->so_state & SS_CANTSENDMORE))
			sendsig |= SDPSIG_WRITE;
		soisdisconnected(so, 0);
		mutex_exit(&so->so_lock);

		/*
		 * Initiate connection shutdown.
		 */
		error = sdp_disconnect(so->so_priv, flag);

		mutex_enter(&so->so_lock);
		if (sendsig != 0)
			sosdp_sendsig(ss, sendsig);
		mutex_exit(&so->so_lock);

		pollwakeup(&ss->ss_poll_list, POLLIN|POLLRDNORM|POLLOUT);
	}
	mutex_enter(&so->so_lock);
	so_unlock_single(so, SOLOCKED);
	mutex_exit(&so->so_lock);

	return (error);
}

/*ARGSUSED2*/
static int
socksdpv_read(struct vnode *vp, struct uio *uiop, int ioflag, struct cred *cr,
    caller_context_t *ct)
{
	struct sonode *so = VTOSO(vp);
	struct nmsghdr lmsg;

	if (so->so_type != SOCK_STREAM) {
		return (EOPNOTSUPP);
	}

	ASSERT(vp->v_type == VSOCK);
	so_update_attrs(so, SOACC);
	lmsg.msg_namelen = 0;
	lmsg.msg_controllen = 0;
	lmsg.msg_flags = 0;
	return (sosdp_recvmsg(so, &lmsg, uiop));
}

/*
 * Send data, see sosdp_sendmsg()
 */
/*ARGSUSED2*/
static int
socksdpv_write(struct vnode *vp, struct uio *uiop, int ioflag, struct cred *cr,
    caller_context_t *ct)
{
	struct sonode *so;
	ssize_t count;
	int error;
	int flags = 0;

	so = VTOSO(vp);

	mutex_enter(&so->so_lock);
	if (so->so_state & SS_CANTSENDMORE) {
		mutex_exit(&so->so_lock);
		tsignal(curthread, SIGPIPE);
		return (EPIPE);
	}

	if (so->so_error != 0) {
		error = sogeterr(so);
		if (error != 0) {
			mutex_exit(&so->so_lock);
			return (error);
		}
	}

	if (uiop->uio_fmode & (FNDELAY|FNONBLOCK))
		flags |= MSG_DONTWAIT;

	if (!(so->so_state & (SS_ISCONNECTING | SS_ISCONNECTED))) {
		mutex_exit(&so->so_lock);
		return (ENOTCONN);
	}
	count = uiop->uio_resid;
	mutex_exit(&so->so_lock);

	if (count == 0) {
		return (0);
	}
	so_update_attrs(so, SOMOD);

	error = sdp_send(so->so_priv, NULL, count, flags, uiop);
	return (error);
}

/*ARGSUSED4*/
static int
socksdpv_ioctl(struct vnode *vp, int cmd, intptr_t arg, int mode,
    struct cred *cr, int32_t *rvalp, caller_context_t *ct)
{
	struct sonode *so;
	struct sdp_sonode *ss;
	int32_t value;
	int error, intval;
	pid_t pid;

	so = VTOSO(vp);
	ss = SOTOSDO(so);

	/* handle socket specific ioctls */
	switch (cmd) {
	case FIONBIO:
		if (so_copyin((void *)arg, &value, sizeof (int32_t),
		    (mode & (int)FKIOCTL))) {
			return (EFAULT);
		}
		mutex_enter(&so->so_lock);
		if (value != 0) {
			so->so_state |= SS_NDELAY;
		} else {
			so->so_state &= ~SS_NDELAY;
		}
		mutex_exit(&so->so_lock);
		return (0);

	case FIOASYNC:
		if (so_copyin((void *)arg, &value, sizeof (int32_t),
		    (mode & (int)FKIOCTL))) {
			return (EFAULT);
		}
		mutex_enter(&so->so_lock);

		if (value) {
			/* Turn on SIGIO */
			so->so_state |= SS_ASYNC;
		} else {
			/* Turn off SIGIO */
			so->so_state &= ~SS_ASYNC;
		}
		mutex_exit(&so->so_lock);
		return (0);

	case SIOCSPGRP:
	case FIOSETOWN:
		if (so_copyin((void *)arg, &pid, sizeof (pid_t),
		    (mode & (int)FKIOCTL))) {
			return (EFAULT);
		}
		mutex_enter(&so->so_lock);

		error = (pid != so->so_pgrp) ? sosdp_chgpgrp(ss, pid) : 0;
		mutex_exit(&so->so_lock);
		return (error);

	case SIOCGPGRP:
	case FIOGETOWN:
		if (so_copyout(&so->so_pgrp, (void *)arg,
		    sizeof (pid_t), (mode & (int)FKIOCTL)))
			return (EFAULT);
		return (0);

	case SIOCATMARK:
		intval = 0;
		error = sdp_ioctl(so->so_priv, cmd, &intval, cr);
		if (so_copyout(&intval, (void *)arg, sizeof (int),
		    (mode & (int)FKIOCTL)))
			return (EFAULT);
		return (0);


	case SIOCSENABLESDP: {
		int32_t enable;

		/*
		 * System wide enable SDP
		 */

		if (so_copyin((void *)arg, &enable, sizeof (int32_t),
		    mode & (int)FKIOCTL))
			return (EFAULT);

		error = sdp_ioctl(so->so_priv, cmd, &enable, cr);
		if (so_copyout(&enable, (void *)arg,
		    sizeof (int32_t), (mode & (int)FKIOCTL)))
			return (EFAULT);
		return (0);
	}
		/* from strioctl */
	case FIONREAD:
		/*
		 * Return number of bytes of data in all data messages
		 * in queue in "arg".
		 * For stream socket, amount of available data.
		 */
		if (so->so_state & SS_ACCEPTCONN) {
			intval = 0;
		} else {
			mutex_enter(&so->so_lock);
			intval = sdp_polldata(so->so_priv, SDP_READ);
			mutex_exit(&so->so_lock);
		}
		if (so_copyout(&intval, (void *)arg, sizeof (intval),
		    (mode & (int)FKIOCTL)))
			return (EFAULT);
		return (0);
	default:
		return (EINVAL);
	}

}

/*
 * Allow any flags. Record FNDELAY and FNONBLOCK so that they can be inherited
 * from listener to acceptor.
 */
/* ARGSUSED */
static int
socksdp_setfl(vnode_t *vp, int oflags, int nflags, cred_t *cr,
    caller_context_t *ct)
{
	struct sonode *so;

	so = VTOSO(vp);

	mutex_enter(&so->so_lock);
	if (nflags & FNDELAY)
		so->so_state |= SS_NDELAY;
	else
		so->so_state &= ~SS_NDELAY;
	if (nflags & FNONBLOCK)
		so->so_state |= SS_NONBLOCK;
	else
		so->so_state &= ~SS_NONBLOCK;
	mutex_exit(&so->so_lock);
	return (0);
}

/*ARGSUSED*/
static void
socksdpv_inactive(struct vnode *vp, struct cred *cr, caller_context_t *ct)
{
	struct sonode *so;

	so = VTOSO(vp);

	mutex_enter(&vp->v_lock);
	/*
	 * If no one has reclaimed the vnode, remove from the
	 * cache now.
	 */
	if (vp->v_count < 1)
		cmn_err(CE_PANIC, "socksdpv_inactive: Bad v_count");

	/*
	 * Drop the temporary hold by vn_rele now
	 */
	if (--vp->v_count != 0) {
		mutex_exit(&vp->v_lock);
		return;
	}
	mutex_exit(&vp->v_lock);

	/* We are the sole owner of so now */

	ASSERT(!vn_has_cached_data(vp));
	if (so->so_priv) {
		sdp_close(so->so_priv);
	}
	so->so_priv = NULL;
	sosdp_free(so);
}

/*
 * Check socktpi_poll() on why so_lock is not held in this function.
 */
/*ARGSUSED5*/
static int
socksdpv_poll(struct vnode *vp, short events, int anyyet, short *reventsp,
    struct pollhead **phpp, caller_context_t *ct)
{
	struct sonode *so;
	struct sdp_sonode *ss;
	short origevents = events;
	int so_state;

	so = VTOSO(vp);
	ss = SOTOSDO(so);
	so_state = so->so_state;


	ASSERT(vp->v_type == VSOCK);
	ASSERT(vp->v_stream == NULL);
	ASSERT(so->so_version != SOV_STREAM);

	if (!(so_state & SS_ISCONNECTED) && (so->so_type == SOCK_STREAM)) {
		/*
		 * Not connected yet - turn off write side events
		 */
		events &= ~(POLLOUT|POLLWRBAND);
	}

	/*
	 * Check for errors
	 */
	if (so->so_error != 0 &&
	    ((POLLIN|POLLRDNORM|POLLOUT) & origevents)  != 0) {
		*reventsp = (POLLIN|POLLRDNORM|POLLOUT) & origevents;
		return (0);
	}

	*reventsp = 0;

	/*
	 * Don't mark socket as writable until TX queued data is
	 * below watermark.
	 */
	if (so->so_type == SOCK_STREAM) {
		if (sdp_polldata(so->so_priv, SDP_XMIT)) {
			*reventsp |= POLLOUT & events;
		}
	} else {
		*reventsp = 0;
		goto done;
	}

	if (sdp_polldata(so->so_priv, SDP_READ)) {
		*reventsp |= (POLLIN|POLLRDNORM) & events;
	}

	if ((so_state & (SS_HASCONNIND|SS_CANTRCVMORE)) != 0) {
		*reventsp |= (POLLIN|POLLRDNORM) & events;
	}

done:
	if (!*reventsp && !anyyet) {
		*phpp = &ss->ss_poll_list;
	}

	return (0);
}
