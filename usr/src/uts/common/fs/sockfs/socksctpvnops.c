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

#include <netinet/sctp.h>
#include <inet/sctp_itf.h>
#include "socksctp.h"

/*
 * SCTP sockfs vnode operations
 */
static int socksctpv_open(struct vnode **, int, struct cred *,
    caller_context_t *);
static int socksctpv_close(struct vnode *, int, int, offset_t,
    struct cred *, caller_context_t *);
static int socksctpv_read(struct vnode *, struct uio *, int, struct cred *,
    caller_context_t *);
static int socksctpv_write(struct vnode *, struct uio *, int, struct cred *,
    caller_context_t *);
static int socksctpv_ioctl(struct vnode *, int, intptr_t, int,
    struct cred *, int32_t *, caller_context_t *);
static int socksctp_setfl(vnode_t *, int, int, cred_t *, caller_context_t *);
static void socksctpv_inactive(struct vnode *, struct cred *,
    caller_context_t *);
static int socksctpv_poll(struct vnode *, short, int, short *,
    struct pollhead **, caller_context_t *);

const fs_operation_def_t socksctp_vnodeops_template[] = {
	VOPNAME_OPEN,		{ .vop_open = socksctpv_open },
	VOPNAME_CLOSE,		{ .vop_close = socksctpv_close },
	VOPNAME_READ,		{ .vop_read = socksctpv_read },
	VOPNAME_WRITE,		{ .vop_write = socksctpv_write },
	VOPNAME_IOCTL,		{ .vop_ioctl = socksctpv_ioctl },
	VOPNAME_SETFL,		{ .vop_setfl = socksctp_setfl },
	VOPNAME_GETATTR,	{ .vop_getattr = socktpi_getattr },
	VOPNAME_SETATTR,	{ .vop_setattr = socktpi_setattr },
	VOPNAME_ACCESS,		{ .vop_access = socktpi_access },
	VOPNAME_FSYNC,		{ .vop_fsync = socktpi_fsync },
	VOPNAME_INACTIVE,	{ .vop_inactive = socksctpv_inactive },
	VOPNAME_FID,		{ .vop_fid = socktpi_fid },
	VOPNAME_SEEK,		{ .vop_seek = socktpi_seek },
	VOPNAME_POLL,		{ .vop_poll = socksctpv_poll },
	VOPNAME_DISPOSE,	{ .error = fs_error },
	NULL,			NULL
};
struct vnodeops *socksctp_vnodeops;

/*ARGSUSED3*/
static int
socksctpv_open(struct vnode **vpp, int flag, struct cred *cr,
    caller_context_t *ct)
{
	struct sonode *so;
	struct sctp_sonode *ss;
	struct vnode *vp = *vpp;
	int error = 0;
	sctp_sockbuf_limits_t sbl;
	sctp_upcalls_t *upcalls;

	flag &= ~FCREAT;		/* paranoia */

	so = VTOSO(vp);
	ss = SOTOSSO(so);

	mutex_enter(&so->so_lock);
	so->so_count++;			/* one more open reference */
	ASSERT(so->so_count != 0);	/* wraparound */
	mutex_exit(&so->so_lock);

	ASSERT(vp->v_type == VSOCK);

	if (flag & SO_ACCEPTOR) {
		ASSERT(so->so_type == SOCK_STREAM);
		/*
		 * Protocol control block already created
		 */
		return (0);
	}

	/*
	 * Active open.
	 */
	if (so->so_type == SOCK_STREAM) {
		upcalls = &sosctp_sock_upcalls;
	} else {
		ASSERT(so->so_type == SOCK_SEQPACKET);
		upcalls = &sosctp_assoc_upcalls;
	}
	so->so_priv = sctp_create(ss, NULL, so->so_family, SCTP_CAN_BLOCK,
	    upcalls, &sbl, cr);
	if (so->so_priv == NULL) {
		error = ENOMEM;
		mutex_enter(&so->so_lock);
		ASSERT(so->so_count > 0);
		so->so_count--;		/* one less open reference */
		mutex_exit(&so->so_lock);
	}
	so->so_rcvbuf = sbl.sbl_rxbuf;
	so->so_rcvlowat = sbl.sbl_rxlowat;
	so->so_sndbuf = sbl.sbl_txbuf;
	so->so_sndlowat = sbl.sbl_txlowat;

	return (error);
}

/*ARGSUSED*/
static int
socksctpv_close(struct vnode *vp, int flag, int count, offset_t offset,
    struct cred *cr, caller_context_t *ct)
{
	struct sonode *so;
	struct sctp_sonode *ss;
	struct sctp_sa_id *ssi;
	struct sctp_soassoc *ssa;
	int sendsig = 0;
	int32_t i;

	so = VTOSO(vp);
	ss = SOTOSSO(so);

	cleanlocks(vp, ttoproc(curthread)->p_pid, 0);
	cleanshares(vp, ttoproc(curthread)->p_pid);

	ASSERT(vp->v_stream == NULL);
	if (count > 1) {
		dprint(2, ("socksctpv_close: count %d\n", count));
		return (0);
	}

	mutex_enter(&so->so_lock);
	so_lock_single(so);	/* Set SOLOCKED */
	ASSERT(so->so_count > 0);
	so->so_count--;			/* one fewer open reference */

	dprint(2, ("socksctpv_close: %p so_count %d\n", (void *)so,
	    so->so_count));

	if (so->so_count == 0) {
		/*
		 * Need to set flags as there might be ops in progress on
		 * this socket.
		 *
		 * If socket already disconnected/disconnecting,
		 * don't send signal (again).
		 */
		if (!(so->so_state & SS_CANTRCVMORE))
			sendsig |= SCTPSIG_READ;
		if (!(so->so_state & SS_CANTSENDMORE))
			sendsig |= SCTPSIG_WRITE;
		soisdisconnected(so, 0);
		mutex_exit(&so->so_lock);

		/*
		 * Initiate connection shutdown.  Update SCTP's receive
		 * window.
		 */
		sctp_recvd(so->so_priv, so->so_rcvbuf - ss->ss_rxqueued);
		(void) sctp_disconnect(so->so_priv);

		/*
		 * New associations can't come in, but old ones might get
		 * closed in upcall. Protect against that by taking a reference
		 * on the association.
		 */
		mutex_enter(&so->so_lock);
		ssi = ss->ss_assocs;
		for (i = 0; i < ss->ss_maxassoc; i++, ssi++) {
			if ((ssa = ssi->ssi_assoc) != NULL) {
				SSA_REFHOLD(ssa);
				sosctp_assoc_isdisconnected(ssa, 0);
				mutex_exit(&so->so_lock);

				sctp_recvd(ssa->ssa_conn, so->so_rcvbuf -
				    ssa->ssa_rxqueued);
				(void) sctp_disconnect(ssa->ssa_conn);

				mutex_enter(&so->so_lock);
				SSA_REFRELE(ss, ssa);
			}
		}
		if (sendsig != 0) {
			sosctp_sendsig(ss, sendsig);
		}
		mutex_exit(&so->so_lock);
		pollwakeup(&ss->ss_poll_list, POLLIN|POLLRDNORM|POLLOUT);
	}
	mutex_enter(&so->so_lock);
	so_unlock_single(so, SOLOCKED);
	mutex_exit(&so->so_lock);

	return (0);
}

/*ARGSUSED2*/
static int
socksctpv_read(struct vnode *vp, struct uio *uiop, int ioflag, struct cred *cr,
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
	return (sosctp_recvmsg(so, &lmsg, uiop));
}

/*
 * Send data, see sosctp_sendmsg()
 */
/*ARGSUSED2*/
static int
socksctpv_write(struct vnode *vp, struct uio *uiop, int ioflag, struct cred *cr,
    caller_context_t *ct)
{
	struct sctp_sonode *ss;
	struct sonode *so;
	mblk_t *head;
	ssize_t count, msglen;
	int error;

	so = VTOSO(vp);
	ss = SOTOSSO(so);

	if (so->so_type != SOCK_STREAM) {
		return (EOPNOTSUPP);
	}

	mutex_enter(&so->so_lock);

	for (;;) {
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

		if (ss->ss_txqueued < so->so_sndbuf)
			break;

		if (uiop->uio_fmode & (FNDELAY|FNONBLOCK)) {
			mutex_exit(&so->so_lock);
			return (EAGAIN);
		} else {
			/*
			 * Xmit window full in a blocking socket.
			 * Wait for space to become available and try again.
			 */
			error = cv_wait_sig(&ss->ss_txdata_cv, &so->so_lock);
			if (error == 0) { /* signal */
				mutex_exit(&so->so_lock);
				return (EINTR);
			}
		}
	}

	if (!(so->so_state & (SS_ISCONNECTING | SS_ISCONNECTED))) {
		mutex_exit(&so->so_lock);
		return (ENOTCONN);
	}

	msglen = count = uiop->uio_resid;
	/* Don't allow sending a message larger than the send buffer size. */
	if (msglen > so->so_sndbuf) {
		mutex_exit(&so->so_lock);
		return (EMSGSIZE);
	}
	ss->ss_txqueued += msglen;

	mutex_exit(&so->so_lock);

	if (count == 0) {
		return (0);
	}

	head = sctp_alloc_hdr(NULL, 0, NULL, 0, SCTP_CAN_BLOCK);
	if (head == NULL) {
		error = EINTR;
		goto error_ret;
	}

	/* Copy in the message. */
	if ((error = sosctp_uiomove(head, count, ss->ss_wrsize, ss->ss_wroff,
	    uiop, 0, cr)) != 0) {
		goto error_ret;
	}
	so_update_attrs(so, SOMOD);

	error = sctp_sendmsg(so->so_priv, head, 0);
	if (error == 0)
		return (0);

error_ret:
	mutex_enter(&so->so_lock);
	ss->ss_txqueued -= msglen;
	cv_broadcast(&ss->ss_txdata_cv);
	mutex_exit(&so->so_lock);
	freemsg(head);
	return (error);
}

/*ARGSUSED4*/
static int
socksctpv_ioctl(struct vnode *vp, int cmd, intptr_t arg, int mode,
    struct cred *cr, int32_t *rvalp, caller_context_t *ct)
{
	struct sonode		*so;
	struct sctp_sonode	*ss;
	int32_t			value;
	int			error;
	int			intval;
	pid_t			pid;
	struct sctp_soassoc	*ssa;
	void			*conn;
	void			*buf;
	STRUCT_DECL(sctpopt, opt);
	uint32_t		optlen;
	int			buflen;

	so = VTOSO(vp);
	ss = SOTOSSO(so);

	/* handle socket specific ioctls */
	switch (cmd) {
	case FIONBIO:
		if (so_copyin((void *)arg, &value, sizeof (int32_t),
		    (mode & (int)FKIOCTL))) {
			return (EFAULT);
		}
		mutex_enter(&so->so_lock);
		if (value) {
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

		error = (pid != so->so_pgrp) ? sosctp_chgpgrp(ss, pid) : 0;
		mutex_exit(&so->so_lock);
		return (error);

	case SIOCGPGRP:
	case FIOGETOWN:
		if (so_copyout(&so->so_pgrp, (void *)arg,
		    sizeof (pid_t), (mode & (int)FKIOCTL)))
			return (EFAULT);
		return (0);

	case SIOCATMARK:
		/*
		 * No support for urgent data.
		 */
		intval = 0;

		if (so_copyout(&intval, (void *)arg, sizeof (int),
		    (mode & (int)FKIOCTL)))
			return (EFAULT);
		return (0);

		/* from strioctl */
	case FIONREAD:
		/*
		 * Return number of bytes of data in all data messages
		 * in queue in "arg".
		 * For stream socket, amount of available data.
		 * For sock_dgram, # of available bytes + addresses.
		 */
		intval = (so->so_state & SS_ACCEPTCONN) ? 0 :
		    MIN(ss->ss_rxqueued, INT_MAX);
		if (so_copyout(&intval, (void *)arg, sizeof (intval),
		    (mode & (int)FKIOCTL)))
			return (EFAULT);
		return (0);

	case SIOCSCTPGOPT:
		STRUCT_INIT(opt, mode);

		if (so_copyin((void *)arg, STRUCT_BUF(opt), STRUCT_SIZE(opt),
		    (mode & (int)FKIOCTL))) {
			return (EFAULT);
		}
		if ((optlen = STRUCT_FGET(opt, sopt_len)) > SO_MAXARGSIZE)
			return (EINVAL);

		/*
		 * Find the correct sctp_t based on whether it is 1-N socket
		 * or not.
		 */
		intval = STRUCT_FGET(opt, sopt_aid);
		mutex_enter(&so->so_lock);
		if ((so->so_type == SOCK_SEQPACKET) && intval) {
			if ((error = sosctp_assoc(ss, intval, &ssa)) != 0) {
				mutex_exit(&so->so_lock);
				return (error);
			}
			conn = ssa->ssa_conn;
			ASSERT(conn != NULL);
		} else {
			conn = so->so_priv;
			ssa = NULL;
		}
		mutex_exit(&so->so_lock);

		/* Copyin the option buffer and then call sctp_get_opt(). */
		buflen = optlen;
		/* Let's allocate a buffer enough to hold an int */
		if (buflen < sizeof (uint32_t))
			buflen = sizeof (uint32_t);
		buf = kmem_alloc(buflen, KM_SLEEP);
		if (so_copyin(STRUCT_FGETP(opt, sopt_val), buf, optlen,
		    (mode & (int)FKIOCTL))) {
			if (ssa != NULL) {
				mutex_enter(&so->so_lock);
				SSA_REFRELE(ss, ssa);
				mutex_exit(&so->so_lock);
			}
			kmem_free(buf, buflen);
			return (EFAULT);
		}
		/* The option level has to be IPPROTO_SCTP */
		error = sctp_get_opt(conn, IPPROTO_SCTP,
		    STRUCT_FGET(opt, sopt_name), buf, &optlen);
		if (ssa != NULL) {
			mutex_enter(&so->so_lock);
			SSA_REFRELE(ss, ssa);
			mutex_exit(&so->so_lock);
		}
		optlen = MIN(buflen, optlen);
		/* No error, copyout the result with the correct buf len. */
		if (error == 0) {
			STRUCT_FSET(opt, sopt_len, optlen);
			if (so_copyout(STRUCT_BUF(opt), (void *)arg,
			    STRUCT_SIZE(opt), (mode & (int)FKIOCTL))) {
				error = EFAULT;
			} else if (so_copyout(buf, STRUCT_FGETP(opt, sopt_val),
			    optlen, (mode & (int)FKIOCTL))) {
				error = EFAULT;
			}
		}
		kmem_free(buf, buflen);
		return (error);

	case SIOCSCTPSOPT:
		STRUCT_INIT(opt, mode);

		if (so_copyin((void *)arg, STRUCT_BUF(opt), STRUCT_SIZE(opt),
		    (mode & (int)FKIOCTL))) {
			return (EFAULT);
		}
		if ((optlen = STRUCT_FGET(opt, sopt_len)) > SO_MAXARGSIZE)
			return (EINVAL);

		/*
		 * Find the correct sctp_t based on whether it is 1-N socket
		 * or not.
		 */
		intval = STRUCT_FGET(opt, sopt_aid);
		mutex_enter(&so->so_lock);
		if (intval != 0) {
			if ((error = sosctp_assoc(ss, intval, &ssa)) != 0) {
				mutex_exit(&so->so_lock);
				return (error);
			}
			conn = ssa->ssa_conn;
			ASSERT(conn != NULL);
		} else {
			conn = so->so_priv;
			ssa = NULL;
		}
		mutex_exit(&so->so_lock);

		/* Copyin the option buffer and then call sctp_set_opt(). */
		buf = kmem_alloc(optlen, KM_SLEEP);
		if (so_copyin(STRUCT_FGETP(opt, sopt_val), buf, optlen,
		    (mode & (int)FKIOCTL))) {
			if (ssa != NULL) {
				mutex_enter(&so->so_lock);
				SSA_REFRELE(ss, ssa);
				mutex_exit(&so->so_lock);
			}
			kmem_free(buf, intval);
			return (EFAULT);
		}
		/* The option level has to be IPPROTO_SCTP */
		error = sctp_set_opt(conn, IPPROTO_SCTP,
		    STRUCT_FGET(opt, sopt_name), buf, optlen);
		if (ssa) {
			mutex_enter(&so->so_lock);
			SSA_REFRELE(ss, ssa);
			mutex_exit(&so->so_lock);
		}
		kmem_free(buf, optlen);
		return (error);

	case SIOCSCTPPEELOFF: {
		struct sonode *nso;
		struct sctp_uc_swap us;
		int nfd;
		struct file *nfp;
		struct vnode *nvp = NULL, *accessvp;

		dprint(2, ("sctppeeloff %p\n", (void *)ss));

		if (so->so_type != SOCK_SEQPACKET) {
			return (EOPNOTSUPP);
		}
		if (so_copyin((void *)arg, &intval, sizeof (intval),
		    (mode & (int)FKIOCTL))) {
			return (EFAULT);
		}
		if (intval == 0) {
			return (EINVAL);
		}

		/*
		 * Find accessvp. This is different from parent's vp,
		 * as the socket type is different.
		 */
		accessvp = solookup(so->so_family, SOCK_STREAM,
		    so->so_protocol, NULL, &error);
		if (accessvp == NULL) {
			return (error);
		}

		/*
		 * Allocate the user fd.
		 */
		if ((nfd = ufalloc(0)) == -1) {
			eprintsoline(so, EMFILE);
			return (EMFILE);
		}

		/*
		 * Copy the fd out.
		 */
		if (so_copyout(&nfd, (void *)arg, sizeof (nfd),
		    (mode & (int)FKIOCTL))) {
			error = EFAULT;
			goto err;
		}
		mutex_enter(&so->so_lock);

		/*
		 * Don't use sosctp_assoc() in order to peel off disconnected
		 * associations.
		 */
		ssa = ((uint32_t)intval >= ss->ss_maxassoc) ? NULL :
		    ss->ss_assocs[intval].ssi_assoc;
		if (ssa == NULL) {
			mutex_exit(&so->so_lock);
			error = EINVAL;
			goto err;
		}
		SSA_REFHOLD(ssa);

		nso = sosctp_create(accessvp, so->so_family, SOCK_STREAM,
		    so->so_protocol, so->so_version, so, &error);
		if (nso == NULL) {
			SSA_REFRELE(ss, ssa);
			mutex_exit(&so->so_lock);
			goto err;
		}
		nvp = SOTOV(nso);
		so_lock_single(so);
		mutex_exit(&so->so_lock);
		us.sus_handle = SOTOSSO(nso);
		us.sus_upcalls = &sosctp_sock_upcalls;

		/*
		 * Upcalls to new socket are blocked for the duration of
		 * downcall.
		 */
		mutex_enter(&nso->so_lock);

		error = sctp_set_opt(ssa->ssa_conn, IPPROTO_SCTP, SCTP_UC_SWAP,
		    &us, sizeof (us));
		if (error) {
			goto peelerr;
		}
		error = falloc(nvp, FWRITE|FREAD, &nfp, NULL);
		if (error) {
			goto peelerr;
		}

		/*
		 * fill in the entries that falloc reserved
		 */
		nfp->f_vnode = nvp;
		mutex_exit(&nfp->f_tlock);
		setf(nfd, nfp);

		mutex_enter(&so->so_lock);

		sosctp_assoc_move(ss, SOTOSSO(nso), ssa);

		mutex_exit(&nso->so_lock);

		ssa->ssa_conn = NULL;
		sosctp_assoc_free(ss, ssa);

		so_unlock_single(so, SOLOCKED);
		mutex_exit(&so->so_lock);

		return (0);

err:
		setf(nfd, NULL);
		eprintsoline(so, error);
		return (error);

peelerr:
		mutex_exit(&nso->so_lock);
		mutex_enter(&so->so_lock);
		ASSERT(nso->so_count == 1);
		nso->so_count = 0;
		so_unlock_single(so, SOLOCKED);
		SSA_REFRELE(ss, ssa);
		mutex_exit(&so->so_lock);
		/* held in VOP_OPEN() */
		ddi_rele_driver(getmajor(nso->so_dev));
		setf(nfd, NULL);
		ASSERT(nvp->v_count == 1);
		VN_RELE(nvp);
		eprintsoline(so, error);
		return (error);
	}
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
socksctp_setfl(vnode_t *vp, int oflags, int nflags, cred_t *cr,
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
socksctpv_inactive(struct vnode *vp, struct cred *cr, caller_context_t *ct)
{
	struct sonode *so;
	struct sctp_sonode *ss;
	struct sctp_sa_id *ssi;
	struct sctp_soassoc *ssa;
	int32_t i;

	so = VTOSO(vp);
	ss = SOTOSSO(so);

	mutex_enter(&vp->v_lock);
	/*
	 * If no one has reclaimed the vnode, remove from the
	 * cache now.
	 */
	if (vp->v_count < 1)
		cmn_err(CE_PANIC, "socksctpv_inactive: Bad v_count");

	/*
	 * Drop the temporary hold by vn_rele now
	 */
	if (--vp->v_count != 0) {
		mutex_exit(&vp->v_lock);
		return;
	}
	mutex_exit(&vp->v_lock);

	/* We are the sole owner of so now */

	/*
	 * New associations can't come in, but old ones might get
	 * closed in upcall. Protect against that by taking a reference
	 * on the association.
	 */
	mutex_enter(&so->so_lock);

	ssi = ss->ss_assocs;
	for (i = 0; i < ss->ss_maxassoc; i++, ssi++) {
		if ((ssa = ssi->ssi_assoc) != NULL) {
			SSA_REFHOLD(ssa);
			mutex_exit(&so->so_lock);

			sctp_close(ssa->ssa_conn);

			mutex_enter(&so->so_lock);
			ssa->ssa_conn = NULL;
			sosctp_assoc_free(ss, ssa);
		}
	}
	mutex_exit(&so->so_lock);

	ASSERT(!vn_has_cached_data(vp));
	if (so->so_priv) {
		sctp_close(so->so_priv);
	}
	so->so_priv = NULL;
	sosctp_free(so);
}

/*
 * Check socktpi_poll() on why so_lock is not held in this function.
 */
/*ARGSUSED5*/
static int
socksctpv_poll(struct vnode *vp, short events, int anyyet, short *reventsp,
    struct pollhead **phpp, caller_context_t *ct)
{
	struct sonode *so;
	struct sctp_sonode *ss;
	short origevents = events;
	int so_state;

	so = VTOSO(vp);
	ss = SOTOSSO(so);
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
		if (ss->ss_txqueued < so->so_sndlowat) {
			*reventsp |= POLLOUT & events;
		}
	} else {
		*reventsp |= POLLOUT & events;
	}
	if (ss->ss_rxdata) {
		*reventsp |= (POLLIN|POLLRDNORM) & events;
	}
	if ((so_state & (SS_HASCONNIND|SS_CANTRCVMORE)) != 0) {
		*reventsp |= (POLLIN|POLLRDNORM) & events;
	}

	if (!*reventsp && !anyyet) {
		*phpp = &ss->ss_poll_list;
	}

	return (0);
}
