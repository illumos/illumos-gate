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
#include <sys/thread.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bitmap.h>
#include <sys/buf.h>
#include <sys/cmn_err.h>
#include <sys/conf.h>
#include <sys/debug.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/fcntl.h>
#include <sys/flock.h>
#include <sys/file.h>
#include <sys/kmem.h>
#include <sys/mman.h>
#include <sys/open.h>
#include <sys/swap.h>
#include <sys/sysmacros.h>
#include <sys/uio.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/vnode.h>
#include <sys/poll.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/suntpi.h>
#include <sys/ioctl.h>
#include <sys/sockio.h>
#include <sys/filio.h>
#include <sys/stat.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <sys/session.h>
#include <sys/vmsystm.h>
#include <sys/vtrace.h>
#include <sys/policy.h>

#include <sys/socket.h>
#include <sys/socketvar.h>
#include <netinet/in.h>
#include <sys/un.h>

#define	_SUN_TPI_VERSION	2
#include <sys/tihdr.h>

#include <vm/seg.h>
#include <vm/seg_map.h>
#include <vm/page.h>
#include <vm/pvn.h>
#include <vm/seg_dev.h>
#include <vm/seg_vn.h>

#include <fs/fs_subr.h>

#include <sys/esunddi.h>
#include <sys/autoconf.h>

#include <fs/sockfs/nl7c.h>
#include <fs/sockfs/nl7curi.h>

#include <inet/udp_impl.h>
#include <inet/tcp_impl.h>

#include <inet/kssl/ksslapi.h>

static int socktpi_close(struct vnode *, int, int, offset_t, struct cred *,
    caller_context_t *);
static int socktpi_read(struct vnode *, struct uio *, int, struct cred *,
    caller_context_t *);
static int socktpi_write(struct vnode *, struct uio *, int, struct cred *,
    caller_context_t *);
static int socktpi_plumbioctl(struct vnode *, int, intptr_t, int, struct cred *,
    int32_t *);
static void socktpi_inactive(struct vnode *, struct cred *, caller_context_t *);
static int socktpi_poll(struct vnode *, short, int, short *,
    struct pollhead **, caller_context_t *);

struct vnodeops *socktpi_vnodeops;

const fs_operation_def_t socktpi_vnodeops_template[] = {
	VOPNAME_OPEN,		{ .vop_open = socktpi_open },
	VOPNAME_CLOSE,		{ .vop_close = socktpi_close },
	VOPNAME_READ,		{ .vop_read = socktpi_read },
	VOPNAME_WRITE,		{ .vop_write = socktpi_write },
	VOPNAME_IOCTL,		{ .vop_ioctl = socktpi_ioctl },
	VOPNAME_SETFL,		{ .vop_setfl = socktpi_setfl },
	VOPNAME_GETATTR,	{ .vop_getattr = socktpi_getattr },
	VOPNAME_SETATTR,	{ .vop_setattr = socktpi_setattr },
	VOPNAME_ACCESS,		{ .vop_access = socktpi_access },
	VOPNAME_FSYNC,		{ .vop_fsync = socktpi_fsync },
	VOPNAME_INACTIVE,	{ .vop_inactive = socktpi_inactive },
	VOPNAME_FID,		{ .vop_fid = socktpi_fid },
	VOPNAME_SEEK,		{ .vop_seek = socktpi_seek },
	VOPNAME_POLL,		{ .vop_poll = socktpi_poll },
	VOPNAME_DISPOSE,	{ .error = fs_error },
	NULL,			NULL
};

/*
 * Do direct function call to the transport layer below; this would
 * also allow the transport to utilize read-side synchronous stream
 * interface if necessary.  This is a /etc/system tunable that must
 * not be modified on a running system.  By default this is enabled
 * for performance reasons and may be disabled for debugging purposes.
 */
boolean_t socktpi_direct = B_TRUE;

/*
 * Open routine used by socket() call. Note that vn_open checks for
 * VSOCK and fails the open (and VOP_OPEN is fs_nosys). The VSOCK check is
 * needed since VSOCK type vnodes exist in various underlying filesystems as
 * a result of an AF_UNIX bind to a pathname.
 *
 * Sockets assume that the driver will clone (either itself
 * or by using the clone driver) i.e. a socket() call will always
 * result in a new vnode being created. This routine single-threads
 * open/closes for a given vnode which is probably not needed.
 */
int
socktpi_open(struct vnode **vpp, int flag, struct cred *cr,
    caller_context_t *ct)
{
	major_t maj;
	dev_t newdev;
	struct vnode *vp = *vpp;
	struct sonode *so;
	int error = 0;
	struct stdata *stp;

	dprint(1, ("socktpi_open()\n"));
	flag &= ~FCREAT;		/* paranoia */

	so = VTOSO(vp);

	mutex_enter(&so->so_lock);
	so->so_count++;			/* one more open reference */
	ASSERT(so->so_count != 0);	/* wraparound */
	if (so->so_count == 1)
		so->so_zoneid = getzoneid();
	mutex_exit(&so->so_lock);

	ASSERT(vp->v_type == VSOCK);

	newdev = vp->v_rdev;
	maj = getmajor(newdev);
	ASSERT(STREAMSTAB(maj));

	mutex_enter(&so->so_lock);
	so_lock_single(so);	/* Set SOLOCKED */
	mutex_exit(&so->so_lock);

	error = stropen(vp, &newdev, flag, cr);

	stp = vp->v_stream;
	if (error == 0) {
		if (so->so_flag & SOCLONE)
			ASSERT(newdev != vp->v_rdev);
		mutex_enter(&so->so_lock);
		so->so_dev = newdev;
		vp->v_rdev = newdev;
		so_unlock_single(so, SOLOCKED);
		mutex_exit(&so->so_lock);

		if (stp->sd_flag & STRISTTY) {
			/*
			 * this is a post SVR4 tty driver - a socket can not
			 * be a controlling terminal. Fail the open.
			 */
			(void) socktpi_close(vp, flag, 1, (offset_t)0, cr, ct);
			return (ENOTTY);	/* XXX */
		}

		ASSERT(stp->sd_wrq != NULL);
		so->so_provinfo = tpi_findprov(stp->sd_wrq);

		/*
		 * If caller is interested in doing direct function call
		 * interface to/from transport module, probe the module
		 * directly beneath the streamhead to see if it qualifies.
		 *
		 * We turn off the direct interface when qualifications fail.
		 * In the acceptor case, we simply turn off the SS_DIRECT
		 * flag on the socket. We do the fallback after the accept
		 * has completed, before the new socket is returned to the
		 * application.
		 */
		if (so->so_state & SS_DIRECT) {
			queue_t *tq = stp->sd_wrq->q_next;

			/*
			 * SS_DIRECT is currently supported and tested
			 * only for tcp/udp; this is the main reason to
			 * have the following assertions.
			 */
			ASSERT(so->so_family == AF_INET ||
			    so->so_family == AF_INET6);
			ASSERT(so->so_protocol == IPPROTO_UDP ||
			    so->so_protocol == IPPROTO_TCP ||
			    so->so_protocol == IPPROTO_IP);
			ASSERT(so->so_type == SOCK_DGRAM ||
			    so->so_type == SOCK_STREAM);

			/*
			 * Abort direct call interface if the module directly
			 * underneath the stream head is not defined with the
			 * _D_DIRECT flag.  This could happen in the tcp or
			 * udp case, when some other module is autopushed
			 * above it, or for some reasons the expected module
			 * isn't purely D_MP (which is the main requirement).
			 *
			 * Else, SS_DIRECT is valid. If the read-side Q has
			 * _QSODIRECT set then and uioasync is enabled then
			 * set SS_SODIRECT to enable sodirect.
			 */
			if (!socktpi_direct || !(tq->q_flag & _QDIRECT) ||
			    !(_OTHERQ(tq)->q_flag & _QDIRECT)) {
				int rval;

				/* Continue on without direct calls */
				so->so_state &= ~SS_DIRECT;
				if (!(flag & SO_ACCEPTOR)) {
					if ((error = strioctl(vp,
					    _SIOCSOCKFALLBACK, 0, 0, K_TO_K,
					    CRED(), &rval)) != 0) {
						(void) socktpi_close(vp, flag,
						    1, (offset_t)0, cr, ct);
						return (error);
					}
				}
			} else if ((_OTHERQ(tq)->q_flag & _QSODIRECT) &&
			    uioasync.enabled) {
				/* Enable sodirect */
				so->so_state |= SS_SODIRECT;
			}
		}
	} else {
		/*
		 * While the same socket can not be reopened (unlike specfs)
		 * the stream head sets STREOPENFAIL when the autopush fails.
		 */
		if ((stp != NULL) &&
		    (stp->sd_flag & STREOPENFAIL)) {
			/*
			 * Open failed part way through.
			 */
			mutex_enter(&stp->sd_lock);
			stp->sd_flag &= ~STREOPENFAIL;
			mutex_exit(&stp->sd_lock);

			mutex_enter(&so->so_lock);
			so_unlock_single(so, SOLOCKED);
			mutex_exit(&so->so_lock);
			(void) socktpi_close(vp, flag, 1,
			    (offset_t)0, cr, ct);
			return (error);
			/*NOTREACHED*/
		}
		ASSERT(stp == NULL);
		mutex_enter(&so->so_lock);
		so_unlock_single(so, SOLOCKED);
		ASSERT(so->so_count > 0);
		so->so_count--;		/* one less open reference */
		mutex_exit(&so->so_lock);
	}
	TRACE_4(TR_FAC_SOCKFS, TR_SOCKFS_OPEN,
	    "sockfs open:maj %d vp %p so %p error %d", maj,
	    vp, so, error);
	return (error);
}

/*ARGSUSED2*/
static int
socktpi_close(
	struct vnode	*vp,
	int		flag,
	int		count,
	offset_t	offset,
	struct cred	*cr,
	caller_context_t *ct)
{
	struct sonode *so;
	dev_t dev;
	int error = 0;

	so = VTOSO(vp);

	dprintso(so, 1, ("socktpi_close(%p, %x, %d) %s\n",
	    (void *)vp, flag, count, pr_state(so->so_state, so->so_mode)));

	cleanlocks(vp, ttoproc(curthread)->p_pid, 0);
	cleanshares(vp, ttoproc(curthread)->p_pid);
	if (vp->v_stream)
		strclean(vp);
	if (count > 1)
		return (0);

	dev = so->so_dev;

	ASSERT(vp->v_type == VSOCK);
	ASSERT(STREAMSTAB(getmajor(dev)));

	mutex_enter(&so->so_lock);
	so_lock_single(so);	/* Set SOLOCKED */
	ASSERT(so->so_count > 0);
	so->so_count--;			/* one fewer open reference */

	/*
	 * Only call NL7C's close on last open reference.
	 */
	if (so->so_count == 0 && (so->so_nl7c_flags & NL7C_ENABLED)) {
		so->so_nl7c_flags = 0;
		nl7c_close(so);
	}

	/*
	 * Only call the close routine when the last open reference through
	 * any [s, v]node goes away.
	 */
	if (so->so_count == 0 && vp->v_stream != NULL) {
		vnode_t *ux_vp;

		if (so->so_family == AF_UNIX) {
			/* Could avoid this when CANTSENDMORE for !dgram */
			so_unix_close(so);
		}

		mutex_exit(&so->so_lock);
		/*
		 * Disassemble the linkage from the AF_UNIX underlying file
		 * system vnode to this socket (by atomically clearing
		 * v_stream in vn_rele_stream) before strclose clears sd_vnode
		 * and frees the stream head.
		 */
		if ((ux_vp = so->so_ux_bound_vp) != NULL) {
			ASSERT(ux_vp->v_stream);
			so->so_ux_bound_vp = NULL;
			vn_rele_stream(ux_vp);
		}
		if (so->so_family == AF_INET || so->so_family == AF_INET6) {
			strsetrwputdatahooks(SOTOV(so), NULL, NULL);
			if (so->so_kssl_ent != NULL) {
				kssl_release_ent(so->so_kssl_ent, so,
				    so->so_kssl_type);
				so->so_kssl_ent = NULL;
			}
			if (so->so_kssl_ctx != NULL) {
				kssl_release_ctx(so->so_kssl_ctx);
				so->so_kssl_ctx = NULL;
			}
			so->so_kssl_type = KSSL_NO_PROXY;
		}
		error = strclose(vp, flag, cr);
		vp->v_stream = NULL;
		mutex_enter(&so->so_lock);
	}

	/*
	 * Flush the T_DISCON_IND on so_discon_ind_mp.
	 */
	if (so->so_count == 0)
		so_flush_discon_ind(so);

	so_unlock_single(so, SOLOCKED);
	mutex_exit(&so->so_lock);

	/*
	 * Decrement the device driver's reference count for streams
	 * opened via the clone dip. The driver was held in clone_open().
	 * The absence of clone_close() forces this asymmetry.
	 */
	if (so->so_flag & SOCLONE)
		ddi_rele_driver(getmajor(dev));

	return (error);
}

/*ARGSUSED2*/
static int
socktpi_read(
	struct vnode	*vp,
	struct uio	*uiop,
	int		ioflag,
	struct cred	*cr,
	caller_context_t *ct)
{
	struct sonode *so = VTOSO(vp);
	struct nmsghdr lmsg;

	dprintso(so, 1, ("socktpi_read(%p) %s\n",
	    (void *)so, pr_state(so->so_state, so->so_mode)));

	ASSERT(vp->v_type == VSOCK);
	so_update_attrs(so, SOACC);

	uiop->uio_extflg |= UIO_COPY_CACHED;

	if (so->so_version == SOV_STREAM) {
		/* The imaginary "sockmod" has been popped - act as a stream */
		return (strread(vp, uiop, cr));
	}
	lmsg.msg_namelen = 0;
	lmsg.msg_controllen = 0;
	lmsg.msg_flags = 0;
	return (sotpi_recvmsg(so, &lmsg, uiop));
}

/* ARGSUSED2 */
static int
socktpi_write(
	struct vnode	*vp,
	struct uio	*uiop,
	int		ioflag,
	struct cred	*cr,
	caller_context_t *ct)
{
	struct sonode *so = VTOSO(vp);
	int so_state;
	int so_mode;
	int error;

	dprintso(so, 1, ("socktpi_write(%p) %s\n",
	    (void *)so, pr_state(so->so_state, so->so_mode)));

	ASSERT(vp->v_type == VSOCK);

	if (so->so_family == AF_UNIX)
		uiop->uio_extflg |= UIO_COPY_CACHED;
	else
		uiop->uio_extflg &= ~UIO_COPY_CACHED;
	if (so->so_version == SOV_STREAM) {
		/* The imaginary "sockmod" has been popped - act as a stream */
		so_update_attrs(so, SOMOD);
		return (strwrite(vp, uiop, cr));
	}
	/* State checks */
	so_state = so->so_state;
	so_mode = so->so_mode;
	if (so_state & SS_CANTSENDMORE) {
		tsignal(curthread, SIGPIPE);
		return (EPIPE);
	}

	if (so->so_error != 0) {
		mutex_enter(&so->so_lock);
		error = sogeterr(so);
		if (error != 0) {
			mutex_exit(&so->so_lock);
			return (error);
		}
		mutex_exit(&so->so_lock);
	}

	if ((so_state & (SS_ISCONNECTED|SS_ISBOUND)) !=
	    (SS_ISCONNECTED|SS_ISBOUND)) {
		if (so_mode & SM_CONNREQUIRED)
			return (ENOTCONN);
		else
			return (EDESTADDRREQ);
	}

	if (!(so_mode & SM_CONNREQUIRED)) {
		/*
		 * Note that this code does not prevent so_faddr_sa
		 * from changing while it is being used. Thus
		 * if an "unconnect"+connect occurs concurrently with
		 * this write the datagram might be delivered to a
		 * garbled address.
		 */
		so_update_attrs(so, SOMOD);
		return (sosend_dgram(so, so->so_faddr_sa,
		    (t_uscalar_t)so->so_faddr_len, uiop, 0));
	}
	so_update_attrs(so, SOMOD);

	if (so_mode & SM_BYTESTREAM) {
		/* Send M_DATA messages */
		if ((so->so_nl7c_flags & NL7C_ENABLED) &&
		    (error = nl7c_data(so, uiop)) >= 0) {
			/* NL7C consumed the data */
			return (error);
		}
		if ((so_state & SS_DIRECT) &&
		    canputnext(vp->v_stream->sd_wrq)) {
			return (sostream_direct(so, uiop, NULL, cr));
		}
		return (strwrite(vp, uiop, cr));
	} else {
		/* Send T_DATA_REQ messages without MORE_flag set */
		return (sosend_svc(so, uiop, T_DATA_REQ, 0, 0));
	}
}

int
so_copyin(const void *from, void *to, size_t size, int fromkernel)
{
	if (fromkernel) {
		bcopy(from, to, size);
		return (0);
	}
	return (xcopyin(from, to, size));
}

int
so_copyout(const void *from, void *to, size_t size, int tokernel)
{
	if (tokernel) {
		bcopy(from, to, size);
		return (0);
	}
	return (xcopyout(from, to, size));
}

/*ARGSUSED6*/
int
socktpi_ioctl(struct vnode *vp, int cmd, intptr_t arg, int mode,
    struct cred *cr, int32_t *rvalp, caller_context_t *ct)
{
	struct sonode *so = VTOSO(vp);
	int error = 0;

	ASSERT(vp->v_type == VSOCK);
	dprintso(so, 0, ("socktpi_ioctl: cmd 0x%x, arg 0x%lx, state %s\n",
	    cmd, arg, pr_state(so->so_state, so->so_mode)));

	switch (cmd) {
	case _I_INSERT:
	case _I_REMOVE:
		/*
		 * Since there's no compelling reason to support these ioctls
		 * on sockets, and doing so would increase the complexity
		 * markedly, prevent it.
		 */
		return (EOPNOTSUPP);

	case I_FIND:
	case I_LIST:
	case I_LOOK:
	case I_POP:
	case I_PUSH:
		/*
		 * To prevent races and inconsistencies between the actual
		 * state of the stream and the state according to the sonode,
		 * we serialize all operations which modify or operate on the
		 * list of modules on the socket's stream.
		 */
		mutex_enter(&so->so_plumb_lock);
		error = socktpi_plumbioctl(vp, cmd, arg, mode, cr, rvalp);
		mutex_exit(&so->so_plumb_lock);
		return (error);

	default:
		if (so->so_version != SOV_STREAM)
			break;

		/*
		 * The imaginary "sockmod" has been popped; act as a stream.
		 */
		return (strioctl(vp, cmd, arg, mode, U_TO_K, cr, rvalp));
	}

	ASSERT(so->so_version != SOV_STREAM);

	/*
	 * Process socket-specific ioctls.
	 */
	switch (cmd) {
	case FIONBIO: {
		int32_t value;

		if (so_copyin((void *)arg, &value, sizeof (int32_t),
		    (mode & (int)FKIOCTL)))
			return (EFAULT);

		mutex_enter(&so->so_lock);
		if (value) {
			so->so_state |= SS_NDELAY;
		} else {
			so->so_state &= ~SS_NDELAY;
		}
		mutex_exit(&so->so_lock);
		return (0);
	}

	case FIOASYNC: {
		int32_t value;

		if (so_copyin((void *)arg, &value, sizeof (int32_t),
		    (mode & (int)FKIOCTL)))
			return (EFAULT);

		mutex_enter(&so->so_lock);
		/*
		 * SS_ASYNC flag not already set correctly?
		 * (!value != !(so->so_state & SS_ASYNC))
		 * but some engineers find that too hard to read.
		 */
		if (value == 0 && (so->so_state & SS_ASYNC) != 0 ||
		    value != 0 && (so->so_state & SS_ASYNC) == 0)
			error = so_flip_async(so, vp, mode, cr);
		mutex_exit(&so->so_lock);
		return (error);
	}

	case SIOCSPGRP:
	case FIOSETOWN: {
		pid_t pgrp;

		if (so_copyin((void *)arg, &pgrp, sizeof (pid_t),
		    (mode & (int)FKIOCTL)))
			return (EFAULT);

		mutex_enter(&so->so_lock);
		dprintso(so, 1, ("setown: new %d old %d\n", pgrp, so->so_pgrp));
		/* Any change? */
		if (pgrp != so->so_pgrp)
			error = so_set_siggrp(so, vp, pgrp, mode, cr);
		mutex_exit(&so->so_lock);
		return (error);
	}
	case SIOCGPGRP:
	case FIOGETOWN:
		if (so_copyout(&so->so_pgrp, (void *)arg,
		    sizeof (pid_t), (mode & (int)FKIOCTL)))
			return (EFAULT);
		return (0);

	case SIOCATMARK: {
		int retval;
		uint_t so_state;

		/*
		 * strwaitmark has a finite timeout after which it
		 * returns -1 if the mark state is undetermined.
		 * In order to avoid any race between the mark state
		 * in sockfs and the mark state in the stream head this
		 * routine loops until the mark state can be determined
		 * (or the urgent data indication has been removed by some
		 * other thread).
		 */
		do {
			mutex_enter(&so->so_lock);
			so_state = so->so_state;
			mutex_exit(&so->so_lock);
			if (so_state & SS_RCVATMARK) {
				retval = 1;
			} else if (!(so_state & SS_OOBPEND)) {
				/*
				 * No SIGURG has been generated -- there is no
				 * pending or present urgent data. Thus can't
				 * possibly be at the mark.
				 */
				retval = 0;
			} else {
				/*
				 * Have the stream head wait until there is
				 * either some messages on the read queue, or
				 * STRATMARK or STRNOTATMARK gets set. The
				 * STRNOTATMARK flag is used so that the
				 * transport can send up a MSGNOTMARKNEXT
				 * M_DATA to indicate that it is not
				 * at the mark and additional data is not about
				 * to be send upstream.
				 *
				 * If the mark state is undetermined this will
				 * return -1 and we will loop rechecking the
				 * socket state.
				 */
				retval = strwaitmark(vp);
			}
		} while (retval == -1);

		if (so_copyout(&retval, (void *)arg, sizeof (int),
		    (mode & (int)FKIOCTL)))
			return (EFAULT);
		return (0);
	}

	case I_FDINSERT:
	case I_SENDFD:
	case I_RECVFD:
	case I_ATMARK:
	case _SIOCSOCKFALLBACK:
		/*
		 * These ioctls do not apply to sockets. I_FDINSERT can be
		 * used to send M_PROTO messages without modifying the socket
		 * state. I_SENDFD/RECVFD should not be used for socket file
		 * descriptor passing since they assume a twisted stream.
		 * SIOCATMARK must be used instead of I_ATMARK.
		 *
		 * _SIOCSOCKFALLBACK from an application should never be
		 * processed.  It is only generated by socktpi_open() or
		 * in response to I_POP or I_PUSH.
		 */
#ifdef DEBUG
		zcmn_err(getzoneid(), CE_WARN,
		    "Unsupported STREAMS ioctl 0x%x on socket. "
		    "Pid = %d\n", cmd, curproc->p_pid);
#endif /* DEBUG */
		return (EOPNOTSUPP);

	case _I_GETPEERCRED:
		if ((mode & FKIOCTL) == 0)
			return (EINVAL);

		mutex_enter(&so->so_lock);
		if ((so->so_mode & SM_CONNREQUIRED) == 0) {
			error = ENOTSUP;
		} else if ((so->so_state & SS_ISCONNECTED) == 0) {
			error = ENOTCONN;
		} else if (so->so_peercred != NULL) {
			k_peercred_t *kp = (k_peercred_t *)arg;
			kp->pc_cr = so->so_peercred;
			kp->pc_cpid = so->so_cpid;
			crhold(so->so_peercred);
		} else {
			error = EINVAL;
		}
		mutex_exit(&so->so_lock);
		return (error);

	default:
		/*
		 * Do the higher-order bits of the ioctl cmd indicate
		 * that it is an I_* streams ioctl?
		 */
		if ((cmd & 0xffffff00U) == STR &&
		    so->so_version == SOV_SOCKBSD) {
#ifdef DEBUG
			zcmn_err(getzoneid(), CE_WARN,
			    "Unsupported STREAMS ioctl 0x%x on socket. "
			    "Pid = %d\n", cmd, 	curproc->p_pid);
#endif /* DEBUG */
			return (EOPNOTSUPP);
		}
		return (strioctl(vp, cmd, arg, mode, U_TO_K, cr, rvalp));
	}
}

/*
 * Handle plumbing-related ioctls.
 */
static int
socktpi_plumbioctl(struct vnode *vp, int cmd, intptr_t arg, int mode,
    struct cred *cr, int32_t *rvalp)
{
	static const char sockmod_name[] = "sockmod";
	struct sonode	*so = VTOSO(vp);
	char		mname[FMNAMESZ + 1];
	int		error;

	ASSERT(MUTEX_HELD(&so->so_plumb_lock));

	if (so->so_version == SOV_SOCKBSD)
		return (EOPNOTSUPP);

	if (so->so_version == SOV_STREAM) {
		/*
		 * The imaginary "sockmod" has been popped - act as a stream.
		 * If this is a push of sockmod then change back to a socket.
		 */
		if (cmd == I_PUSH) {
			error = ((mode & FKIOCTL) ? copystr : copyinstr)(
			    (void *)arg, mname, sizeof (mname), NULL);

			if (error == 0 && strcmp(mname, sockmod_name) == 0) {
				dprintso(so, 0, ("socktpi_ioctl: going to "
				    "socket version\n"));
				so_stream2sock(so);
				return (0);
			}
		}
		return (strioctl(vp, cmd, arg, mode, U_TO_K, cr, rvalp));
	}

	switch (cmd) {
	case I_PUSH:
		if (so->so_state & SS_DIRECT) {
			mutex_enter(&so->so_lock);
			so_lock_single(so);
			mutex_exit(&so->so_lock);

			error = strioctl(vp, _SIOCSOCKFALLBACK, 0, 0, K_TO_K,
			    CRED(), rvalp);

			mutex_enter(&so->so_lock);
			if (error == 0)
				so->so_state &= ~SS_DIRECT;
			so_unlock_single(so, SOLOCKED);
			mutex_exit(&so->so_lock);

			if (error != 0)
				return (error);
		}

		error = strioctl(vp, cmd, arg, mode, U_TO_K, cr, rvalp);
		if (error == 0)
			so->so_pushcnt++;
		return (error);

	case I_POP:
		if (so->so_pushcnt == 0) {
			/* Emulate sockmod being popped */
			dprintso(so, 0,
			    ("socktpi_ioctl: going to STREAMS version\n"));
			return (so_sock2stream(so));
		}

		error = strioctl(vp, cmd, arg, mode, U_TO_K, cr, rvalp);
		if (error == 0)
			so->so_pushcnt--;
		return (error);

	case I_LIST: {
		struct str_mlist *kmlistp, *umlistp;
		struct str_list	kstrlist;
		ssize_t		kstrlistsize;
		int		i, nmods;

		STRUCT_DECL(str_list, ustrlist);
		STRUCT_INIT(ustrlist, mode);

		if (arg == NULL) {
			error = strioctl(vp, cmd, arg, mode, U_TO_K, cr, rvalp);
			if (error == 0)
				(*rvalp)++;	/* Add one for sockmod */
			return (error);
		}

		error = so_copyin((void *)arg, STRUCT_BUF(ustrlist),
		    STRUCT_SIZE(ustrlist), mode & FKIOCTL);
		if (error != 0)
			return (error);

		nmods = STRUCT_FGET(ustrlist, sl_nmods);
		if (nmods <= 0)
			return (EINVAL);
		/*
		 * Ceiling nmods at nstrpush to prevent someone from
		 * maliciously consuming lots of kernel memory.
		 */
		nmods = MIN(nmods, nstrpush);

		kstrlistsize = (nmods + 1) * sizeof (struct str_mlist);
		kstrlist.sl_nmods = nmods;
		kstrlist.sl_modlist = kmem_zalloc(kstrlistsize, KM_SLEEP);

		error = strioctl(vp, cmd, (intptr_t)&kstrlist, mode, K_TO_K,
		    cr, rvalp);
		if (error != 0)
			goto done;

		/*
		 * Considering the module list as a 0-based array of sl_nmods
		 * modules, sockmod should conceptually exist at slot
		 * so_pushcnt.  Insert sockmod at this location by sliding all
		 * of the module names after so_pushcnt over by one.  We know
		 * that there will be room to do this since we allocated
		 * sl_modlist with an additional slot.
		 */
		for (i = kstrlist.sl_nmods; i > so->so_pushcnt; i--)
			kstrlist.sl_modlist[i] = kstrlist.sl_modlist[i - 1];

		(void) strcpy(kstrlist.sl_modlist[i].l_name, sockmod_name);
		kstrlist.sl_nmods++;

		/*
		 * Copy all of the entries out to ustrlist.
		 */
		kmlistp = kstrlist.sl_modlist;
		umlistp = STRUCT_FGETP(ustrlist, sl_modlist);
		for (i = 0; i < nmods && i < kstrlist.sl_nmods; i++) {
			error = so_copyout(kmlistp++, umlistp++,
			    sizeof (struct str_mlist), mode & FKIOCTL);
			if (error != 0)
				goto done;
		}

		error = so_copyout(&i, (void *)arg, sizeof (int32_t),
		    mode & FKIOCTL);
		if (error == 0)
			*rvalp = 0;
	done:
		kmem_free(kstrlist.sl_modlist, kstrlistsize);
		return (error);
	}
	case I_LOOK:
		if (so->so_pushcnt == 0) {
			return (so_copyout(sockmod_name, (void *)arg,
			    sizeof (sockmod_name), mode & FKIOCTL));
		}
		return (strioctl(vp, cmd, arg, mode, U_TO_K, cr, rvalp));

	case I_FIND:
		error = strioctl(vp, cmd, arg, mode, U_TO_K, cr, rvalp);
		if (error && error != EINVAL)
			return (error);

		/* if not found and string was sockmod return 1 */
		if (*rvalp == 0 || error == EINVAL) {
			error = ((mode & FKIOCTL) ? copystr : copyinstr)(
			    (void *)arg, mname, sizeof (mname), NULL);
			if (error == ENAMETOOLONG)
				error = EINVAL;

			if (error == 0 && strcmp(mname, sockmod_name) == 0)
				*rvalp = 1;
		}
		return (error);

	default:
		panic("socktpi_plumbioctl: unknown ioctl %d", cmd);
		break;
	}

	return (0);
}

/*
 * Allow any flags. Record FNDELAY and FNONBLOCK so that they can be inherited
 * from listener to acceptor.
 */
/* ARGSUSED */
int
socktpi_setfl(vnode_t *vp, int oflags, int nflags, cred_t *cr,
    caller_context_t *ct)
{
	struct sonode *so;
	int error = 0;

	so = VTOSO(vp);

	dprintso(so, 0, ("socktpi_setfl: oflags 0x%x, nflags 0x%x, state %s\n",
	    oflags, nflags, pr_state(so->so_state, so->so_mode)));
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

	/*
	 * Sets/clears the SS_ASYNC flag based on the presence/absence
	 * of the FASYNC flag passed to fcntl(F_SETFL).
	 * This exists solely for BSD fcntl() FASYNC compatibility.
	 */
	so = VTOSO(vp->v_stream->sd_vnode);

	if (so->so_version != SOV_STREAM) {
		mutex_enter(&so->so_lock);

		/*
		 * SS_ASYNC flag not already set correctly?
		 * (!(nflags & FASYNC) != !(so->so_state & SS_ASYNC))
		 * but some engineers find that too hard to read.
		 */
		if ((nflags & FASYNC) == 0 && (so->so_state & SS_ASYNC) != 0 ||
		    (nflags & FASYNC) != 0 && (so->so_state & SS_ASYNC) == 0)
			error = so_flip_async(so, SOTOV(so), 0, CRED());
		mutex_exit(&so->so_lock);
	}
	return (error);
}

/*
 * Get the made up attributes for the vnode.
 * 4.3BSD returns the current time for all the timestamps.
 * 4.4BSD returns 0 for all the timestamps.
 * Here we use the access and modified times recorded in the sonode.
 *
 * Just like in BSD there is not effect on the underlying file system node
 * bound to an AF_UNIX pathname.
 *
 * When sockmod has been popped this will act just like a stream. Since
 * a socket is always a clone there is no need to inspect the attributes
 * of the "realvp".
 */
/* ARGSUSED */
int
socktpi_getattr(
	struct vnode	*vp,
	struct vattr	*vap,
	int		flags,
	struct cred	*cr,
	caller_context_t *ct)
{
	dev_t	fsid;
	struct sonode *so;
	static int	sonode_shift	= 0;

	/*
	 * Calculate the amount of bitshift to a sonode pointer which will
	 * still keep it unique.  See below.
	 */
	if (sonode_shift == 0)
		sonode_shift = highbit(sizeof (struct sonode));
	ASSERT(sonode_shift > 0);

	so = VTOSO(vp);
	fsid = so->so_fsid;

	if (so->so_version == SOV_STREAM) {
		/*
		 * The imaginary "sockmod" has been popped - act
		 * as a stream
		 */
		vap->va_type = VCHR;
		vap->va_mode = 0;
	} else {
		vap->va_type = vp->v_type;
		vap->va_mode = S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|
		    S_IROTH|S_IWOTH;
	}
	vap->va_uid = vap->va_gid = 0;
	vap->va_fsid = fsid;
	/*
	 * If the va_nodeid is > MAX_USHORT, then i386 stats might fail.
	 * So we shift down the sonode pointer to try and get the most
	 * uniqueness into 16-bits.
	 */
	vap->va_nodeid = ((ino_t)so >> sonode_shift) & 0xFFFF;
	vap->va_nlink = 0;
	vap->va_size = 0;

	/*
	 * We need to zero out the va_rdev to avoid some fstats getting
	 * EOVERFLOW.  This also mimics SunOS 4.x and BSD behavior.
	 */
	vap->va_rdev = (dev_t)0;
	vap->va_blksize = MAXBSIZE;
	vap->va_nblocks = btod(vap->va_size);

	mutex_enter(&so->so_lock);
	vap->va_atime.tv_sec = so->so_atime;
	vap->va_mtime.tv_sec = so->so_mtime;
	vap->va_ctime.tv_sec = so->so_ctime;
	mutex_exit(&so->so_lock);

	vap->va_atime.tv_nsec = 0;
	vap->va_mtime.tv_nsec = 0;
	vap->va_ctime.tv_nsec = 0;
	vap->va_seq = 0;

	return (0);
}

/*
 * Set attributes.
 * Just like in BSD there is not effect on the underlying file system node
 * bound to an AF_UNIX pathname.
 *
 * When sockmod has been popped this will act just like a stream. Since
 * a socket is always a clone there is no need to modify the attributes
 * of the "realvp".
 */
/* ARGSUSED */
int
socktpi_setattr(
	struct vnode	*vp,
	struct vattr	*vap,
	int		flags,
	struct cred	*cr,
	caller_context_t *ct)
{
	struct sonode *so = VTOSO(vp);

	/*
	 * If times were changed, update sonode.
	 */
	mutex_enter(&so->so_lock);
	if (vap->va_mask & AT_ATIME)
		so->so_atime = vap->va_atime.tv_sec;
	if (vap->va_mask & AT_MTIME) {
		so->so_mtime = vap->va_mtime.tv_sec;
		so->so_ctime = gethrestime_sec();
	}
	mutex_exit(&so->so_lock);

	return (0);
}

int
socktpi_access(struct vnode *vp, int mode, int flags, struct cred *cr,
    caller_context_t *ct)
{
	struct vnode *accessvp;
	struct sonode *so = VTOSO(vp);

	if ((accessvp = so->so_accessvp) != NULL)
		return (VOP_ACCESS(accessvp, mode, flags, cr, ct));
	else
		return (0);	/* Allow all access. */
}

/*
 * 4.3BSD and 4.4BSD fail a fsync on a socket with EINVAL.
 * This code does the same to be compatible and also to not give an
 * application the impression that the data has actually been "synced"
 * to the other end of the connection.
 */
/* ARGSUSED */
int
socktpi_fsync(struct vnode *vp, int syncflag, struct cred *cr,
    caller_context_t *ct)
{
	return (EINVAL);
}

/* ARGSUSED */
static void
socktpi_inactive(struct vnode *vp, struct cred *cr, caller_context_t *ct)
{
	struct sonode *so = VTOSO(vp);

	mutex_enter(&vp->v_lock);
	/*
	 * If no one has reclaimed the vnode, remove from the
	 * cache now.
	 */
	if (vp->v_count < 1)
		cmn_err(CE_PANIC, "socktpi_inactive: Bad v_count");

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
	sockfree(so);
}

/* ARGSUSED */
int
socktpi_fid(struct vnode *vp, struct fid *fidp, caller_context_t *ct)
{
	return (EINVAL);
}

/*
 * Sockets are not seekable.
 * (and there is a bug to fix STREAMS to make them fail this as well).
 */
/*ARGSUSED*/
int
socktpi_seek(struct vnode *vp, offset_t ooff, offset_t *noffp,
    caller_context_t *ct)
{
	return (ESPIPE);
}

/*
 * Wrapper around the streams poll routine that implements socket poll
 * semantics.
 * Sockfs never calls pollwakeup() itself - the stream head takes care
 * of all pollwakeups. Since sockfs never holds so_lock when calling the
 * stream head there can never be a deadlock due to holding so_lock across
 * pollwakeup and acquiring so_lock in this routine.
 *
 * However, since the performance of VOP_POLL is critical we avoid
 * acquiring so_lock here. This is based on the following assumptions:
 *  - The poll implementation holds locks to serialize the VOP_POLL call
 *	and a pollwakeup for the same pollhead. This ensures that should
 *	so_state etc change during a socktpi_poll() call, the pollwakeup()
 *	(which strsock_* and strrput() conspire to issue) is issued after
 *	the state change. Thus the pollwakeup will block until VOP_POLL has
 *	returned, and then wake up poll and have it call VOP_POLL again.
 *
 *  - The reading of so_state without holding so_lock does not result in
 *	stale data (older than the latest state change that has dropped
 *	so_lock). This is ensured as mutex_exit() issues the appropriate
 *	memory barrier to force the data into the coherency domain.
 *
 *  - Whilst so_state may change during the VOP_POLL call, (SS_HASCONNIND
 *	may have been set by an arriving connection), the above two factors
 *	guarantee validity of SS_ISCONNECTED/SM_CONNREQUIRED in the entry
 *	time snapshot. In order to capture the arrival of a connection while
 *	VOP_POLL was in progress, we then check real so_state, (so->so_state)
 *	for SS_HASCONNIND and set appropriate events to ensure poll_common()
 *	will not sleep.
 */
/*ARGSUSED5*/
static int
socktpi_poll(
	struct vnode	*vp,
	short		events,
	int		anyyet,
	short		*reventsp,
	struct pollhead **phpp,
	caller_context_t *ct)
{
	short origevents = events;
	struct sonode *so = VTOSO(vp);
	int error;
	int so_state = so->so_state;	/* snapshot */

	dprintso(so, 0, ("socktpi_poll(%p): state %s err %d\n",
	    (void *)vp, pr_state(so_state, so->so_mode), so->so_error));

	ASSERT(vp->v_type == VSOCK);
	ASSERT(vp->v_stream != NULL);

	if (so->so_version == SOV_STREAM) {
		/* The imaginary "sockmod" has been popped - act as a stream */
		return (strpoll(vp->v_stream, events, anyyet,
		    reventsp, phpp));
	}

	if (!(so_state & SS_ISCONNECTED) &&
	    (so->so_mode & SM_CONNREQUIRED)) {
		/* Not connected yet - turn off write side events */
		events &= ~(POLLOUT|POLLWRBAND);
	}
	/*
	 * Check for errors without calling strpoll if the caller wants them.
	 * In sockets the errors are represented as input/output events
	 * and there is no need to ask the stream head for this information.
	 */
	if (so->so_error != 0 &&
	    ((POLLIN|POLLRDNORM|POLLOUT) & origevents)  != 0) {
		*reventsp = (POLLIN|POLLRDNORM|POLLOUT) & origevents;
		return (0);
	}
	/*
	 * Ignore M_PROTO only messages such as the T_EXDATA_IND messages.
	 * These message with only an M_PROTO/M_PCPROTO part and no M_DATA
	 * will not trigger a POLLIN event with POLLRDDATA set.
	 * The handling of urgent data (causing POLLRDBAND) is done by
	 * inspecting SS_OOBPEND below.
	 */
	events |= POLLRDDATA;

	/*
	 * After shutdown(output) a stream head write error is set.
	 * However, we should not return output events.
	 */
	events |= POLLNOERR;
	error = strpoll(vp->v_stream, events, anyyet,
	    reventsp, phpp);
	if (error)
		return (error);

	ASSERT(!(*reventsp & POLLERR));

	/*
	 * Notes on T_CONN_IND handling for sockets.
	 *
	 * If strpoll() returned without events, SR_POLLIN is guaranteed
	 * to be set, ensuring any subsequent strrput() runs pollwakeup().
	 *
	 * Since the so_lock is not held, soqueueconnind() may have run
	 * and a T_CONN_IND may be waiting. We now check for SS_HASCONNIND
	 * in the current so_state and set appropriate events to ensure poll
	 * returns.
	 *
	 * However:
	 * If the T_CONN_IND hasn't arrived by the time strpoll() returns,
	 * when strrput() does run for an arriving M_PROTO with T_CONN_IND
	 * the following actions will occur; taken together they ensure the
	 * syscall will return.
	 *
	 * 1. If a socket, soqueueconnind() will set SS_HASCONNIND but if
	 *	the accept() was run on a non-blocking socket sowaitconnind()
	 *	may have already returned EWOULDBLOCK, so not be waiting to
	 *	process the message. Additionally socktpi_poll() has probably
	 *	proceeded past the SS_HASCONNIND check below.
	 * 2. strrput() runs pollwakeup()->pollnotify()->cv_signal() to wake
	 *	this thread,  however that could occur before poll_common()
	 *	has entered cv_wait.
	 * 3. pollnotify() sets T_POLLWAKE, while holding the pc_lock.
	 *
	 * Before proceeding to cv_wait() in poll_common() for an event,
	 * poll_common() atomically checks for T_POLLWAKE under the pc_lock,
	 * and if set, re-calls strpoll() to ensure the late arriving
	 * T_CONN_IND is recognized, and pollsys() returns.
	 */
	if (so->so_state & (SS_HASCONNIND|SS_OOBPEND)) {
		if (so->so_state & SS_HASCONNIND)
			*reventsp |= (POLLIN|POLLRDNORM) & events;
		if (so->so_state & SS_OOBPEND)
			*reventsp |= POLLRDBAND & events;
	}

	if (so->so_nl7c_rcv_mp != NULL) {
		*reventsp |= (POLLIN|POLLRDNORM) & events;
	}
	if ((so->so_nl7c_flags & NL7C_ENABLED) &&
	    ((POLLIN|POLLRDNORM) & *reventsp)) {
		so->so_nl7c_flags |= NL7C_POLLIN;
	}

	return (0);
}

/*
 * Wrapper for getmsg. If the socket has been converted to a stream
 * pass the request to the stream head.
 */
int
sock_getmsg(
	struct vnode *vp,
	struct strbuf *mctl,
	struct strbuf *mdata,
	uchar_t *prip,
	int *flagsp,
	int fmode,
	rval_t *rvp
)
{
	struct sonode *so;

	ASSERT(vp->v_type == VSOCK);
	/*
	 * Use the stream head to find the real socket vnode.
	 * This is needed when namefs sits above sockfs.  Some
	 * sockets (like SCTP) are not streams.
	 */
	if (!vp->v_stream) {
		return (ENOSTR);
	}
	ASSERT(vp->v_stream->sd_vnode);
	vp = vp->v_stream->sd_vnode;
	ASSERT(vn_matchops(vp, socktpi_vnodeops));
	so = VTOSO(vp);

	dprintso(so, 1, ("sock_getmsg(%p) %s\n",
	    (void *)so, pr_state(so->so_state, so->so_mode)));

	if (so->so_version == SOV_STREAM) {
		/* The imaginary "sockmod" has been popped - act as a stream */
		return (strgetmsg(vp, mctl, mdata, prip, flagsp, fmode, rvp));
	}
	eprintsoline(so, ENOSTR);
	return (ENOSTR);
}

/*
 * Wrapper for putmsg. If the socket has been converted to a stream
 * pass the request to the stream head.
 *
 * Note that a while a regular socket (SOV_SOCKSTREAM) does support the
 * streams ioctl set it does not support putmsg and getmsg.
 * Allowing putmsg would prevent sockfs from tracking the state of
 * the socket/transport and would also invalidate the locking in sockfs.
 */
int
sock_putmsg(
	struct vnode *vp,
	struct strbuf *mctl,
	struct strbuf *mdata,
	uchar_t pri,
	int flag,
	int fmode
)
{
	struct sonode *so;

	ASSERT(vp->v_type == VSOCK);
	/*
	 * Use the stream head to find the real socket vnode.
	 * This is needed when namefs sits above sockfs.
	 */
	if (!vp->v_stream) {
		return (ENOSTR);
	}
	ASSERT(vp->v_stream->sd_vnode);
	vp = vp->v_stream->sd_vnode;
	ASSERT(vn_matchops(vp, socktpi_vnodeops));
	so = VTOSO(vp);

	dprintso(so, 1, ("sock_putmsg(%p) %s\n",
	    (void *)so, pr_state(so->so_state, so->so_mode)));

	if (so->so_version == SOV_STREAM) {
		/* The imaginary "sockmod" has been popped - act as a stream */
		return (strputmsg(vp, mctl, mdata, pri, flag, fmode));
	}
	eprintsoline(so, ENOSTR);
	return (ENOSTR);
}

/*
 * Special function called only from f_getfl().
 * Returns FASYNC if the SS_ASYNC flag is set on a socket, else 0.
 * No locks are acquired here, so it is safe to use while uf_lock is held.
 * This exists solely for BSD fcntl() FASYNC compatibility.
 */
int
sock_getfasync(vnode_t *vp)
{
	struct sonode *so;

	ASSERT(vp->v_type == VSOCK);
	so = VTOSO(vp->v_stream->sd_vnode);
	if (so->so_version == SOV_STREAM || !(so->so_state & SS_ASYNC))
		return (0);
	return (FASYNC);
}
