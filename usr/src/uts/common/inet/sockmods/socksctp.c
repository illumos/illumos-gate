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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2015 Joyent, Inc.  All rights reserved.
 */

#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/buf.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/debug.h>
#include <sys/errno.h>
#include <sys/stropts.h>
#include <sys/cmn_err.h>
#include <sys/sysmacros.h>
#include <sys/filio.h>
#include <sys/policy.h>

#include <sys/project.h>
#include <sys/tihdr.h>
#include <sys/strsubr.h>
#include <sys/esunddi.h>
#include <sys/ddi.h>

#include <sys/sockio.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/strsun.h>

#include <netinet/sctp.h>
#include <inet/sctp_itf.h>
#include <fs/sockfs/sockcommon.h>
#include "socksctp.h"

/*
 * SCTP sockfs sonode operations, 1-1 socket
 */
static int sosctp_init(struct sonode *, struct sonode *, struct cred *, int);
static int sosctp_accept(struct sonode *, int, struct cred *, struct sonode **);
static int sosctp_bind(struct sonode *, struct sockaddr *, socklen_t, int,
    struct cred *);
static int sosctp_listen(struct sonode *, int, struct cred *);
static int sosctp_connect(struct sonode *, struct sockaddr *, socklen_t,
    int, int, struct cred *);
static int sosctp_recvmsg(struct sonode *, struct nmsghdr *, struct uio *,
    struct cred *);
static int sosctp_sendmsg(struct sonode *, struct nmsghdr *, struct uio *,
    struct cred *);
static int sosctp_getpeername(struct sonode *, struct sockaddr *, socklen_t *,
    boolean_t, struct cred *);
static int sosctp_getsockname(struct sonode *, struct sockaddr *, socklen_t *,
    struct cred *);
static int sosctp_shutdown(struct sonode *, int, struct cred *);
static int sosctp_getsockopt(struct sonode *, int, int, void *, socklen_t *,
    int, struct cred *);
static int sosctp_setsockopt(struct sonode *, int, int, const void *,
    socklen_t, struct cred *);
static int sosctp_ioctl(struct sonode *, int, intptr_t, int, struct cred *,
    int32_t *);
static int sosctp_close(struct sonode *, int, struct cred *);
void sosctp_fini(struct sonode *, struct cred *);

/*
 * SCTP sockfs sonode operations, 1-N socket
 */
static int sosctp_seq_connect(struct sonode *, struct sockaddr *,
    socklen_t, int, int, struct cred *);
static int sosctp_seq_sendmsg(struct sonode *, struct nmsghdr *, struct uio *,
    struct cred *);

/*
 * Socket association upcalls, 1-N socket connection
 */
sock_upper_handle_t sctp_assoc_newconn(sock_upper_handle_t,
    sock_lower_handle_t, sock_downcalls_t *, struct cred *, pid_t,
    sock_upcalls_t **);
static void sctp_assoc_connected(sock_upper_handle_t, sock_connid_t,
    struct cred *, pid_t);
static int sctp_assoc_disconnected(sock_upper_handle_t, sock_connid_t, int);
static void sctp_assoc_disconnecting(sock_upper_handle_t, sock_opctl_action_t,
    uintptr_t arg);
static ssize_t sctp_assoc_recv(sock_upper_handle_t, mblk_t *, size_t, int,
    int *, boolean_t *);
static void sctp_assoc_xmitted(sock_upper_handle_t, boolean_t);
static void sctp_assoc_properties(sock_upper_handle_t,
    struct sock_proto_props *);

sonodeops_t sosctp_sonodeops = {
	sosctp_init,			/* sop_init	*/
	sosctp_accept,			/* sop_accept	*/
	sosctp_bind,			/* sop_bind	*/
	sosctp_listen,			/* sop_listen	*/
	sosctp_connect,			/* sop_connect	*/
	sosctp_recvmsg,			/* sop_recvmsg	*/
	sosctp_sendmsg,			/* sop_sendmsg	*/
	so_sendmblk_notsupp,		/* sop_sendmblk	*/
	sosctp_getpeername,		/* sop_getpeername */
	sosctp_getsockname,		/* sop_getsockname */
	sosctp_shutdown,		/* sop_shutdown */
	sosctp_getsockopt,		/* sop_getsockopt */
	sosctp_setsockopt,		/* sop_setsockopt */
	sosctp_ioctl,			/* sop_ioctl	*/
	so_poll,			/* sop_poll	*/
	sosctp_close,			/* sop_close 	*/
};

sonodeops_t sosctp_seq_sonodeops = {
	sosctp_init,			/* sop_init	*/
	so_accept_notsupp,		/* sop_accept	*/
	sosctp_bind,			/* sop_bind	*/
	sosctp_listen,			/* sop_listen	*/
	sosctp_seq_connect,		/* sop_connect	*/
	sosctp_recvmsg,			/* sop_recvmsg	*/
	sosctp_seq_sendmsg,		/* sop_sendmsg	*/
	so_sendmblk_notsupp,		/* sop_sendmblk	*/
	so_getpeername_notsupp,		/* sop_getpeername */
	sosctp_getsockname,		/* sop_getsockname */
	so_shutdown_notsupp,		/* sop_shutdown */
	sosctp_getsockopt,		/* sop_getsockopt */
	sosctp_setsockopt,		/* sop_setsockopt */
	sosctp_ioctl,			/* sop_ioctl	*/
	so_poll,			/* sop_poll	*/
	sosctp_close,			/* sop_close 	*/
};

/* All the upcalls expect the upper handle to be sonode. */
sock_upcalls_t sosctp_sock_upcalls = {
	so_newconn,
	so_connected,
	so_disconnected,
	so_opctl,
	so_queue_msg,
	so_set_prop,
	so_txq_full,
	NULL,			/* su_signal_oob */
};

/* All the upcalls expect the upper handle to be sctp_sonode/sctp_soassoc. */
sock_upcalls_t sosctp_assoc_upcalls = {
	sctp_assoc_newconn,
	sctp_assoc_connected,
	sctp_assoc_disconnected,
	sctp_assoc_disconnecting,
	sctp_assoc_recv,
	sctp_assoc_properties,
	sctp_assoc_xmitted,
	NULL,			/* su_recv_space */
	NULL,			/* su_signal_oob */
};

/* ARGSUSED */
static int
sosctp_init(struct sonode *so, struct sonode *pso, struct cred *cr, int flags)
{
	struct sctp_sonode *ss;
	struct sctp_sonode *pss;
	sctp_sockbuf_limits_t sbl;
	int err;

	ss = SOTOSSO(so);

	if (pso != NULL) {
		/*
		 * Passive open, just inherit settings from parent. We should
		 * not end up here for SOCK_SEQPACKET type sockets, since no
		 * new sonode is created in that case.
		 */
		ASSERT(so->so_type == SOCK_STREAM);
		pss = SOTOSSO(pso);

		mutex_enter(&pso->so_lock);
		so->so_state |= (SS_ISBOUND | SS_ISCONNECTED |
		    (pso->so_state & SS_ASYNC));
		sosctp_so_inherit(pss, ss);
		so->so_proto_props = pso->so_proto_props;
		so->so_mode = pso->so_mode;
		mutex_exit(&pso->so_lock);

		return (0);
	}

	if ((err = secpolicy_basic_net_access(cr)) != 0)
		return (err);

	if (so->so_type == SOCK_STREAM) {
		so->so_proto_handle = (sock_lower_handle_t)sctp_create(so,
		    NULL, so->so_family, so->so_type, SCTP_CAN_BLOCK,
		    &sosctp_sock_upcalls, &sbl, cr);
		so->so_mode = SM_CONNREQUIRED;
	} else {
		ASSERT(so->so_type == SOCK_SEQPACKET);
		so->so_proto_handle = (sock_lower_handle_t)sctp_create(ss,
		    NULL, so->so_family, so->so_type, SCTP_CAN_BLOCK,
		    &sosctp_assoc_upcalls, &sbl, cr);
	}

	if (so->so_proto_handle == NULL)
		return (ENOMEM);

	so->so_rcvbuf = sbl.sbl_rxbuf;
	so->so_rcvlowat = sbl.sbl_rxlowat;
	so->so_sndbuf = sbl.sbl_txbuf;
	so->so_sndlowat = sbl.sbl_txlowat;

	return (0);
}

/*
 * Accept incoming connection.
 */
/*ARGSUSED*/
static int
sosctp_accept(struct sonode *so, int fflag, struct cred *cr,
    struct sonode **nsop)
{
	int error = 0;

	if ((so->so_state & SS_ACCEPTCONN) == 0)
		return (EINVAL);

	error = so_acceptq_dequeue(so, (fflag & (FNONBLOCK|FNDELAY)), nsop);

	return (error);
}

/*
 * Bind local endpoint.
 */
/*ARGSUSED*/
static int
sosctp_bind(struct sonode *so, struct sockaddr *name, socklen_t namelen,
    int flags, struct cred *cr)
{
	int error;

	if (!(flags & _SOBIND_LOCK_HELD)) {
		mutex_enter(&so->so_lock);
		so_lock_single(so);	/* Set SOLOCKED */
	} else {
		ASSERT(MUTEX_HELD(&so->so_lock));
	}

	/*
	 * X/Open requires this check
	 */
	if (so->so_state & SS_CANTSENDMORE) {
		error = EINVAL;
		goto done;
	}


	/*
	 * Protocol module does address family checks.
	 */
	mutex_exit(&so->so_lock);

	error = sctp_bind((struct sctp_s *)so->so_proto_handle, name, namelen);

	mutex_enter(&so->so_lock);
	if (error == 0) {
		so->so_state |= SS_ISBOUND;
	} else {
		eprintsoline(so, error);
	}
done:
	if (!(flags & _SOBIND_LOCK_HELD)) {
		so_unlock_single(so, SOLOCKED);
		mutex_exit(&so->so_lock);
	} else {
		/* If the caller held the lock don't release it here */
		ASSERT(MUTEX_HELD(&so->so_lock));
		ASSERT(so->so_flag & SOLOCKED);
	}

	return (error);
}

/*
 * Turn socket into a listen socket.
 */
/* ARGSUSED */
static int
sosctp_listen(struct sonode *so, int backlog, struct cred *cr)
{
	int error = 0;

	mutex_enter(&so->so_lock);
	so_lock_single(so);

	/*
	 * If this socket is trying to do connect, or if it has
	 * been connected, disallow.
	 */
	if (so->so_state & (SS_ISCONNECTING | SS_ISCONNECTED |
	    SS_ISDISCONNECTING | SS_CANTRCVMORE | SS_CANTSENDMORE)) {
		error = EINVAL;
		eprintsoline(so, error);
		goto done;
	}

	if (backlog < 0) {
		backlog = 0;
	}

	/*
	 * If listen() is only called to change backlog, we don't
	 * need to notify protocol module.
	 */
	if (so->so_state & SS_ACCEPTCONN) {
		so->so_backlog = backlog;
		goto done;
	}

	mutex_exit(&so->so_lock);
	error = sctp_listen((struct sctp_s *)so->so_proto_handle);
	mutex_enter(&so->so_lock);
	if (error == 0) {
		so->so_state |= (SS_ACCEPTCONN|SS_ISBOUND);
		so->so_backlog = backlog;
	} else {
		eprintsoline(so, error);
	}
done:
	so_unlock_single(so, SOLOCKED);
	mutex_exit(&so->so_lock);

	return (error);
}

/*
 * Active open.
 */
/*ARGSUSED*/
static int
sosctp_connect(struct sonode *so, struct sockaddr *name,
    socklen_t namelen, int fflag, int flags, struct cred *cr)
{
	int error = 0;
	pid_t pid = curproc->p_pid;

	ASSERT(so->so_type == SOCK_STREAM);

	mutex_enter(&so->so_lock);
	so_lock_single(so);

	/*
	 * Can't connect() after listen(), or if the socket is already
	 * connected.
	 */
	if (so->so_state & (SS_ACCEPTCONN|SS_ISCONNECTED|SS_ISCONNECTING)) {
		if (so->so_state & SS_ISCONNECTED) {
			error = EISCONN;
		} else if (so->so_state & SS_ISCONNECTING) {
			error = EALREADY;
		} else {
			error = EOPNOTSUPP;
		}
		eprintsoline(so, error);
		goto done;
	}

	/*
	 * Check for failure of an earlier call
	 */
	if (so->so_error != 0) {
		error = sogeterr(so, B_TRUE);
		eprintsoline(so, error);
		goto done;
	}

	/*
	 * Connection is closing, or closed, don't allow reconnect.
	 * TCP allows this to proceed, but the socket remains unwriteable.
	 * BSD returns EINVAL.
	 */
	if (so->so_state & (SS_ISDISCONNECTING|SS_CANTRCVMORE|
	    SS_CANTSENDMORE)) {
		error = EINVAL;
		eprintsoline(so, error);
		goto done;
	}

	if (name == NULL || namelen == 0) {
		error = EINVAL;
		eprintsoline(so, error);
		goto done;
	}

	soisconnecting(so);
	mutex_exit(&so->so_lock);

	error = sctp_connect((struct sctp_s *)so->so_proto_handle,
	    name, namelen, cr, pid);

	mutex_enter(&so->so_lock);
	if (error == 0) {
		/*
		 * Allow other threads to access the socket
		 */
		error = sowaitconnected(so, fflag, 0);
	}
done:
	so_unlock_single(so, SOLOCKED);
	mutex_exit(&so->so_lock);
	return (error);
}

/*
 * Active open for 1-N sockets, create a new association and
 * call connect on that.
 * If there parent hasn't been bound yet (this is the first association),
 * make it so.
 */
static int
sosctp_seq_connect(struct sonode *so, struct sockaddr *name,
    socklen_t namelen, int fflag, int flags, struct cred *cr)
{
	struct sctp_soassoc *ssa;
	struct sctp_sonode *ss;
	int error;

	ASSERT(so->so_type == SOCK_SEQPACKET);

	mutex_enter(&so->so_lock);
	so_lock_single(so);

	if (name == NULL || namelen == 0) {
		error = EINVAL;
		eprintsoline(so, error);
		goto done;
	}

	ss = SOTOSSO(so);

	error = sosctp_assoc_createconn(ss, name, namelen, NULL, 0, fflag,
	    cr, &ssa);
	if (error != 0) {
		if ((error == EHOSTUNREACH) && (flags & _SOCONNECT_XPG4_2)) {
			error = ENETUNREACH;
		}
	}
	if (ssa != NULL) {
		SSA_REFRELE(ss, ssa);
	}

done:
	so_unlock_single(so, SOLOCKED);
	mutex_exit(&so->so_lock);
	return (error);
}

/*
 * Receive data.
 */
/* ARGSUSED */
static int
sosctp_recvmsg(struct sonode *so, struct nmsghdr *msg, struct uio *uiop,
    struct cred *cr)
{
	struct sctp_sonode *ss = SOTOSSO(so);
	struct sctp_soassoc *ssa = NULL;
	int flags, error = 0;
	struct T_unitdata_ind *tind;
	ssize_t orig_resid = uiop->uio_resid;
	int len, count, readcnt = 0;
	socklen_t controllen, namelen;
	void *opt;
	mblk_t *mp;
	rval_t	rval;

	controllen = msg->msg_controllen;
	namelen = msg->msg_namelen;
	flags = msg->msg_flags;
	msg->msg_flags = 0;
	msg->msg_controllen = 0;
	msg->msg_namelen = 0;

	if (so->so_type == SOCK_STREAM) {
		if (!(so->so_state & (SS_ISCONNECTED|SS_ISCONNECTING|
		    SS_CANTRCVMORE))) {
			return (ENOTCONN);
		}
	} else {
		/* NOTE: Will come here from vop_read() as well */
		/* For 1-N socket, recv() cannot be used. */
		if (namelen == 0)
			return (EOPNOTSUPP);
		/*
		 * If there are no associations, and no new connections are
		 * coming in, there's not going to be new messages coming
		 * in either.
		 */
		if (so->so_rcv_q_head == NULL && so->so_rcv_head == NULL &&
		    ss->ss_assoccnt == 0 && !(so->so_state & SS_ACCEPTCONN)) {
			return (ENOTCONN);
		}
	}

	/*
	 * out-of-band data not supported.
	 */
	if (flags & MSG_OOB) {
		return (EOPNOTSUPP);
	}

	/*
	 * flag possibilities:
	 *
	 * MSG_PEEK	Don't consume data
	 * MSG_WAITALL	Wait for full quantity of data (ignored if MSG_PEEK)
	 * MSG_DONTWAIT Non-blocking (same as FNDELAY | FNONBLOCK)
	 *
	 * MSG_WAITALL can return less than the full buffer if either
	 *
	 * 1. we would block and we are non-blocking
	 * 2. a full message cannot be delivered
	 *
	 * Given that we always get a full message from proto below,
	 * MSG_WAITALL is not meaningful.
	 */

	mutex_enter(&so->so_lock);

	/*
	 * Allow just one reader at a time.
	 */
	error = so_lock_read_intr(so,
	    uiop->uio_fmode | ((flags & MSG_DONTWAIT) ? FNONBLOCK : 0));
	if (error) {
		mutex_exit(&so->so_lock);
		return (error);
	}
	mutex_exit(&so->so_lock);
again:
	error = so_dequeue_msg(so, &mp, uiop, &rval, flags | MSG_DUPCTRL);
	if (mp != NULL) {
		if (so->so_type == SOCK_SEQPACKET) {
			ssa = *(struct sctp_soassoc **)DB_BASE(mp);
		}

		tind = (struct T_unitdata_ind *)mp->b_rptr;

		len = tind->SRC_length;

		if (namelen > 0 && len > 0) {

			opt = sogetoff(mp, tind->SRC_offset, len, 1);

			ASSERT(opt != NULL);

			msg->msg_name = kmem_alloc(len, KM_SLEEP);
			msg->msg_namelen = len;

			bcopy(opt, msg->msg_name, len);
		}

		len = tind->OPT_length;
		if (controllen == 0) {
			if (len > 0) {
				msg->msg_flags |= MSG_CTRUNC;
			}
		} else if (len > 0) {
			opt = sogetoff(mp, tind->OPT_offset, len,
			    __TPI_ALIGN_SIZE);

			ASSERT(opt != NULL);
			sosctp_pack_cmsg(opt, msg, len);
		}

		if (mp->b_flag & SCTP_NOTIFICATION) {
			msg->msg_flags |= MSG_NOTIFICATION;
		}

		if (!(mp->b_flag & SCTP_PARTIAL_DATA) &&
		    !(rval.r_val1 & MOREDATA)) {
			msg->msg_flags |= MSG_EOR;
		}
		freemsg(mp);
	}
done:
	if (!(flags & MSG_PEEK))
		readcnt = orig_resid - uiop->uio_resid;
	/*
	 * Determine if we need to update SCTP about the buffer
	 * space.  For performance reason, we cannot update SCTP
	 * every time a message is read.  The socket buffer low
	 * watermark is used as the threshold.
	 */
	if (ssa == NULL) {
		mutex_enter(&so->so_lock);
		count = so->so_rcvbuf - so->so_rcv_queued;

		ASSERT(so->so_rcv_q_head != NULL ||
		    so->so_rcv_head != NULL ||
		    so->so_rcv_queued == 0);

		so_unlock_read(so);

		/*
		 * so_dequeue_msg() sets r_val2 to true if flow control was
		 * cleared and we need to update SCTP.  so_flowctrld was
		 * cleared in so_dequeue_msg() via so_check_flow_control().
		 */
		if (rval.r_val2) {
			mutex_exit(&so->so_lock);
			sctp_recvd((struct sctp_s *)so->so_proto_handle, count);
		} else {
			mutex_exit(&so->so_lock);
		}
	} else {
		/*
		 * Each association keeps track of how much data it has
		 * queued; we need to update the value here. Note that this
		 * is slightly different from SOCK_STREAM type sockets, which
		 * does not need to update the byte count, as it is already
		 * done in so_dequeue_msg().
		 */
		mutex_enter(&so->so_lock);
		ssa->ssa_rcv_queued -= readcnt;
		count = so->so_rcvbuf - ssa->ssa_rcv_queued;

		so_unlock_read(so);

		if (readcnt > 0 && ssa->ssa_flowctrld &&
		    ssa->ssa_rcv_queued < so->so_rcvlowat) {
			/*
			 * Need to clear ssa_flowctrld, different from 1-1
			 * style.
			 */
			ssa->ssa_flowctrld = B_FALSE;
			mutex_exit(&so->so_lock);
			sctp_recvd(ssa->ssa_conn, count);
			mutex_enter(&so->so_lock);
		}

		/*
		 * MOREDATA flag is set if all data could not be copied
		 */
		if (!(flags & MSG_PEEK) && !(rval.r_val1 & MOREDATA)) {
			SSA_REFRELE(ss, ssa);
		}
		mutex_exit(&so->so_lock);
	}

	return (error);
}

int
sosctp_uiomove(mblk_t *hdr_mp, ssize_t count, ssize_t blk_size, int wroff,
    struct uio *uiop, int flags)
{
	ssize_t size;
	int error;
	mblk_t *mp;
	dblk_t *dp;

	if (blk_size == INFPSZ)
		blk_size = count;

	/*
	 * Loop until we have all data copied into mblk's.
	 */
	while (count > 0) {
		size = MIN(count, blk_size);

		/*
		 * As a message can be splitted up and sent in different
		 * packets, each mblk will have the extra space before
		 * data to accommodate what SCTP wants to put in there.
		 */
		while ((mp = allocb(size + wroff, BPRI_MED)) == NULL) {
			if ((uiop->uio_fmode & (FNDELAY|FNONBLOCK)) ||
			    (flags & MSG_DONTWAIT)) {
				return (EAGAIN);
			}
			if ((error = strwaitbuf(size + wroff, BPRI_MED))) {
				return (error);
			}
		}

		dp = mp->b_datap;
		dp->db_cpid = curproc->p_pid;
		ASSERT(wroff <= dp->db_lim - mp->b_wptr);
		mp->b_rptr += wroff;
		error = uiomove(mp->b_rptr, size, UIO_WRITE, uiop);
		if (error != 0) {
			freeb(mp);
			return (error);
		}
		mp->b_wptr = mp->b_rptr + size;
		count -= size;
		hdr_mp->b_cont = mp;
		hdr_mp = mp;
	}
	return (0);
}

/*
 * Send message.
 */
static int
sosctp_sendmsg(struct sonode *so, struct nmsghdr *msg, struct uio *uiop,
    struct cred *cr)
{
	mblk_t *mctl;
	struct cmsghdr *cmsg;
	struct sctp_sndrcvinfo *sinfo;
	int optlen, flags, fflag;
	ssize_t count, msglen;
	int error;

	ASSERT(so->so_type == SOCK_STREAM);

	flags = msg->msg_flags;
	if (flags & MSG_OOB) {
		/*
		 * No out-of-band data support.
		 */
		return (EOPNOTSUPP);
	}

	if (msg->msg_controllen != 0) {
		optlen = msg->msg_controllen;
		cmsg = sosctp_find_cmsg(msg->msg_control, optlen, SCTP_SNDRCV);
		if (cmsg != NULL) {
			if (cmsg->cmsg_len <
			    (sizeof (*sinfo) + sizeof (*cmsg))) {
				eprintsoline(so, EINVAL);
				return (EINVAL);
			}
			sinfo = (struct sctp_sndrcvinfo *)(cmsg + 1);

			/* Both flags should not be set together. */
			if ((sinfo->sinfo_flags & MSG_EOF) &&
			    (sinfo->sinfo_flags & MSG_ABORT)) {
				eprintsoline(so, EINVAL);
				return (EINVAL);
			}

			/* Initiate a graceful shutdown. */
			if (sinfo->sinfo_flags & MSG_EOF) {
				/* Can't include data in MSG_EOF message. */
				if (uiop->uio_resid != 0) {
					eprintsoline(so, EINVAL);
					return (EINVAL);
				}

				/*
				 * This is the same sequence as done in
				 * shutdown(SHUT_WR).
				 */
				mutex_enter(&so->so_lock);
				so_lock_single(so);
				socantsendmore(so);
				cv_broadcast(&so->so_snd_cv);
				so->so_state |= SS_ISDISCONNECTING;
				mutex_exit(&so->so_lock);

				pollwakeup(&so->so_poll_list, POLLOUT);
				sctp_recvd((struct sctp_s *)so->so_proto_handle,
				    so->so_rcvbuf);
				error = sctp_disconnect(
				    (struct sctp_s *)so->so_proto_handle);

				mutex_enter(&so->so_lock);
				so_unlock_single(so, SOLOCKED);
				mutex_exit(&so->so_lock);
				return (error);
			}
		}
	} else {
		optlen = 0;
	}

	mutex_enter(&so->so_lock);
	for (;;) {
		if (so->so_state & SS_CANTSENDMORE) {
			mutex_exit(&so->so_lock);
			return (EPIPE);
		}

		if (so->so_error != 0) {
			error = sogeterr(so, B_TRUE);
			mutex_exit(&so->so_lock);
			return (error);
		}

		if (!so->so_snd_qfull)
			break;

		if (so->so_state & SS_CLOSING) {
			mutex_exit(&so->so_lock);
			return (EINTR);
		}
		/*
		 * Xmit window full in a blocking socket.
		 */
		if ((uiop->uio_fmode & (FNDELAY|FNONBLOCK)) ||
		    (flags & MSG_DONTWAIT)) {
			mutex_exit(&so->so_lock);
			return (EAGAIN);
		} else {
			/*
			 * Wait for space to become available and try again.
			 */
			error = cv_wait_sig(&so->so_snd_cv, &so->so_lock);
			if (!error) { /* signal */
				mutex_exit(&so->so_lock);
				return (EINTR);
			}
		}
	}
	msglen = count = uiop->uio_resid;

	/* Don't allow sending a message larger than the send buffer size. */
	/* XXX Transport module need to enforce this */
	if (msglen > so->so_sndbuf) {
		mutex_exit(&so->so_lock);
		return (EMSGSIZE);
	}

	/*
	 * Allow piggybacking data on handshake messages (SS_ISCONNECTING).
	 */
	if (!(so->so_state & (SS_ISCONNECTING | SS_ISCONNECTED))) {
		/*
		 * We need to check here for listener so that the
		 * same error will be returned as with a TCP socket.
		 * In this case, sosctp_connect() returns EOPNOTSUPP
		 * while a TCP socket returns ENOTCONN instead.  Catch it
		 * here to have the same behavior as a TCP socket.
		 *
		 * We also need to make sure that the peer address is
		 * provided before we attempt to do the connect.
		 */
		if ((so->so_state & SS_ACCEPTCONN) ||
		    msg->msg_name == NULL) {
			mutex_exit(&so->so_lock);
			error = ENOTCONN;
			goto error_nofree;
		}
		mutex_exit(&so->so_lock);
		fflag = uiop->uio_fmode;
		if (flags & MSG_DONTWAIT) {
			fflag |= FNDELAY;
		}
		error = sosctp_connect(so, msg->msg_name, msg->msg_namelen,
		    fflag, (so->so_version == SOV_XPG4_2) * _SOCONNECT_XPG4_2,
		    cr);
		if (error) {
			/*
			 * Check for non-fatal errors, socket connected
			 * while the lock had been lifted.
			 */
			if (error != EISCONN && error != EALREADY) {
				goto error_nofree;
			}
			error = 0;
		}
	} else {
		mutex_exit(&so->so_lock);
	}

	mctl = sctp_alloc_hdr(msg->msg_name, msg->msg_namelen,
	    msg->msg_control, optlen, SCTP_CAN_BLOCK);
	if (mctl == NULL) {
		error = EINTR;
		goto error_nofree;
	}

	/* Copy in the message. */
	if ((error = sosctp_uiomove(mctl, count, so->so_proto_props.sopp_maxblk,
	    so->so_proto_props.sopp_wroff, uiop, flags)) != 0) {
		goto error_ret;
	}
	error = sctp_sendmsg((struct sctp_s *)so->so_proto_handle, mctl, 0);
	if (error == 0)
		return (0);

error_ret:
	freemsg(mctl);
error_nofree:
	mutex_enter(&so->so_lock);
	if ((error == EPIPE) && (so->so_state & SS_CANTSENDMORE)) {
		/*
		 * We received shutdown between the time lock was
		 * lifted and call to sctp_sendmsg().
		 */
		mutex_exit(&so->so_lock);
		return (EPIPE);
	}
	mutex_exit(&so->so_lock);
	return (error);
}

/*
 * Send message on 1-N socket. Connects automatically if there is
 * no association.
 */
static int
sosctp_seq_sendmsg(struct sonode *so, struct nmsghdr *msg, struct uio *uiop,
    struct cred *cr)
{
	struct sctp_sonode *ss;
	struct sctp_soassoc *ssa;
	struct cmsghdr *cmsg;
	struct sctp_sndrcvinfo *sinfo;
	int aid = 0;
	mblk_t *mctl;
	int namelen, optlen, flags;
	ssize_t count, msglen;
	int error;
	uint16_t s_flags = 0;

	ASSERT(so->so_type == SOCK_SEQPACKET);

	/*
	 * There shouldn't be problems with alignment, as the memory for
	 * msg_control was alloced with kmem_alloc.
	 */
	cmsg = sosctp_find_cmsg(msg->msg_control, msg->msg_controllen,
	    SCTP_SNDRCV);
	if (cmsg != NULL) {
		if (cmsg->cmsg_len < (sizeof (*sinfo) + sizeof (*cmsg))) {
			eprintsoline(so, EINVAL);
			return (EINVAL);
		}
		sinfo = (struct sctp_sndrcvinfo *)(cmsg + 1);
		s_flags = sinfo->sinfo_flags;
		aid = sinfo->sinfo_assoc_id;
	}

	ss = SOTOSSO(so);
	namelen = msg->msg_namelen;

	if (msg->msg_controllen > 0) {
		optlen = msg->msg_controllen;
	} else {
		optlen = 0;
	}

	mutex_enter(&so->so_lock);

	/*
	 * If there is no association id, connect to address specified
	 * in msg_name.  Otherwise look up the association using the id.
	 */
	if (aid == 0) {
		/*
		 * Connect and shutdown cannot be done together, so check for
		 * MSG_EOF.
		 */
		if (msg->msg_name == NULL || namelen == 0 ||
		    (s_flags & MSG_EOF)) {
			error = EINVAL;
			eprintsoline(so, error);
			goto done;
		}
		flags = uiop->uio_fmode;
		if (msg->msg_flags & MSG_DONTWAIT) {
			flags |= FNDELAY;
		}
		so_lock_single(so);
		error = sosctp_assoc_createconn(ss, msg->msg_name, namelen,
		    msg->msg_control, optlen, flags, cr, &ssa);
		if (error) {
			if ((so->so_version == SOV_XPG4_2) &&
			    (error == EHOSTUNREACH)) {
				error = ENETUNREACH;
			}
			if (ssa == NULL) {
				/*
				 * Fatal error during connect(). Bail out.
				 * If ssa exists, it means that the handshake
				 * is in progress.
				 */
				eprintsoline(so, error);
				so_unlock_single(so, SOLOCKED);
				goto done;
			}
			/*
			 * All the errors are non-fatal ones, don't return
			 * e.g. EINPROGRESS from sendmsg().
			 */
			error = 0;
		}
		so_unlock_single(so, SOLOCKED);
	} else {
		if ((error = sosctp_assoc(ss, aid, &ssa)) != 0) {
			eprintsoline(so, error);
			goto done;
		}
	}

	/*
	 * Now we have an association.
	 */
	flags = msg->msg_flags;

	/*
	 * MSG_EOF initiates graceful shutdown.
	 */
	if (s_flags & MSG_EOF) {
		if (uiop->uio_resid) {
			/*
			 * Can't include data in MSG_EOF message.
			 */
			error = EINVAL;
		} else {
			mutex_exit(&so->so_lock);
			ssa->ssa_state |= SS_ISDISCONNECTING;
			sctp_recvd(ssa->ssa_conn, so->so_rcvbuf);
			error = sctp_disconnect(ssa->ssa_conn);
			mutex_enter(&so->so_lock);
		}
		goto refrele;
	}

	for (;;) {
		if (ssa->ssa_state & SS_CANTSENDMORE) {
			SSA_REFRELE(ss, ssa);
			mutex_exit(&so->so_lock);
			return (EPIPE);
		}
		if (ssa->ssa_error != 0) {
			error = ssa->ssa_error;
			ssa->ssa_error = 0;
			goto refrele;
		}

		if (!ssa->ssa_snd_qfull)
			break;

		if (so->so_state & SS_CLOSING) {
			error = EINTR;
			goto refrele;
		}
		if ((uiop->uio_fmode & (FNDELAY|FNONBLOCK)) ||
		    (flags & MSG_DONTWAIT)) {
			error = EAGAIN;
			goto refrele;
		} else {
			/*
			 * Wait for space to become available and try again.
			 */
			error = cv_wait_sig(&so->so_snd_cv, &so->so_lock);
			if (!error) { /* signal */
				error = EINTR;
				goto refrele;
			}
		}
	}

	msglen = count = uiop->uio_resid;

	/* Don't allow sending a message larger than the send buffer size. */
	if (msglen > so->so_sndbuf) {
		error = EMSGSIZE;
		goto refrele;
	}

	/*
	 * Update TX buffer usage here so that we can lift the socket lock.
	 */
	mutex_exit(&so->so_lock);

	mctl = sctp_alloc_hdr(msg->msg_name, namelen, msg->msg_control,
	    optlen, SCTP_CAN_BLOCK);
	if (mctl == NULL) {
		error = EINTR;
		goto lock_rele;
	}

	/* Copy in the message. */
	if ((error = sosctp_uiomove(mctl, count, ssa->ssa_wrsize,
	    ssa->ssa_wroff, uiop, flags)) != 0) {
		goto lock_rele;
	}
	error = sctp_sendmsg((struct sctp_s *)ssa->ssa_conn, mctl, 0);
lock_rele:
	mutex_enter(&so->so_lock);
	if (error != 0) {
		freemsg(mctl);
		if ((error == EPIPE) && (ssa->ssa_state & SS_CANTSENDMORE)) {
			/*
			 * We received shutdown between the time lock was
			 * lifted and call to sctp_sendmsg().
			 */
			SSA_REFRELE(ss, ssa);
			mutex_exit(&so->so_lock);
			return (EPIPE);
		}
	}

refrele:
	SSA_REFRELE(ss, ssa);
done:
	mutex_exit(&so->so_lock);
	return (error);
}

/*
 * Get address of remote node.
 */
/* ARGSUSED */
static int
sosctp_getpeername(struct sonode *so, struct sockaddr *addr, socklen_t *addrlen,
    boolean_t accept, struct cred *cr)
{
	return (sctp_getpeername((struct sctp_s *)so->so_proto_handle, addr,
	    addrlen));
}

/*
 * Get local address.
 */
/* ARGSUSED */
static int
sosctp_getsockname(struct sonode *so, struct sockaddr *addr, socklen_t *addrlen,
    struct cred *cr)
{
	return (sctp_getsockname((struct sctp_s *)so->so_proto_handle, addr,
	    addrlen));
}

/*
 * Called from shutdown().
 */
/* ARGSUSED */
static int
sosctp_shutdown(struct sonode *so, int how, struct cred *cr)
{
	uint_t state_change;
	int wakesig = 0;
	int error = 0;

	mutex_enter(&so->so_lock);
	/*
	 * Record the current state and then perform any state changes.
	 * Then use the difference between the old and new states to
	 * determine which needs to be done.
	 */
	state_change = so->so_state;

	switch (how) {
	case SHUT_RD:
		socantrcvmore(so);
		break;
	case SHUT_WR:
		socantsendmore(so);
		break;
	case SHUT_RDWR:
		socantsendmore(so);
		socantrcvmore(so);
		break;
	default:
		mutex_exit(&so->so_lock);
		return (EINVAL);
	}

	state_change = so->so_state & ~state_change;

	if (state_change & SS_CANTRCVMORE) {
		if (so->so_rcv_q_head == NULL) {
			cv_signal(&so->so_rcv_cv);
		}
		wakesig = POLLIN|POLLRDNORM;

		socket_sendsig(so, SOCKETSIG_READ);
	}
	if (state_change & SS_CANTSENDMORE) {
		cv_broadcast(&so->so_snd_cv);
		wakesig |= POLLOUT;

		so->so_state |= SS_ISDISCONNECTING;
	}
	mutex_exit(&so->so_lock);

	pollwakeup(&so->so_poll_list, wakesig);

	if (state_change & SS_CANTSENDMORE) {
		sctp_recvd((struct sctp_s *)so->so_proto_handle, so->so_rcvbuf);
		error = sctp_disconnect((struct sctp_s *)so->so_proto_handle);
	}

	/*
	 * HACK: sctp_disconnect() may return EWOULDBLOCK.  But this error is
	 * not documented in standard socket API.  Catch it here.
	 */
	if (error == EWOULDBLOCK)
		error = 0;
	return (error);
}

/*
 * Get socket options.
 */
/*ARGSUSED5*/
static int
sosctp_getsockopt(struct sonode *so, int level, int option_name,
    void *optval, socklen_t *optlenp, int flags, struct cred *cr)
{
	socklen_t maxlen = *optlenp;
	socklen_t len;
	socklen_t optlen;
	uint8_t	buffer[4];
	void	*optbuf = &buffer;
	int	error = 0;

	if (level == SOL_SOCKET) {
		switch (option_name) {
		/* Not supported options */
		case SO_SNDTIMEO:
		case SO_RCVTIMEO:
		case SO_EXCLBIND:
			eprintsoline(so, ENOPROTOOPT);
			return (ENOPROTOOPT);
		default:
			error = socket_getopt_common(so, level, option_name,
			    optval, optlenp, flags);
			if (error >= 0)
				return (error);
			/* Pass the request to the protocol */
			break;
		}
	}

	if (level == IPPROTO_SCTP) {
		/*
		 * Should go through ioctl().
		 */
		return (EINVAL);
	}

	if (maxlen > sizeof (buffer)) {
		optbuf = kmem_alloc(maxlen, KM_SLEEP);
	}
	optlen = maxlen;

	/*
	 * If the resulting optlen is greater than the provided maxlen, then
	 * we sliently trucate.
	 */
	error = sctp_get_opt((struct sctp_s *)so->so_proto_handle, level,
	    option_name, optbuf, &optlen);

	if (error != 0) {
		eprintsoline(so, error);
		goto free;
	}
	len = optlen;

copyout:

	len = MIN(len, maxlen);
	bcopy(optbuf, optval, len);
	*optlenp = optlen;
free:
	if (optbuf != &buffer) {
		kmem_free(optbuf, maxlen);
	}

	return (error);
}

/*
 * Set socket options
 */
/* ARGSUSED */
static int
sosctp_setsockopt(struct sonode *so, int level, int option_name,
    const void *optval, t_uscalar_t optlen, struct cred *cr)
{
	struct sctp_sonode *ss = SOTOSSO(so);
	struct sctp_soassoc *ssa = NULL;
	sctp_assoc_t id;
	int error, rc;
	void *conn = NULL;

	mutex_enter(&so->so_lock);

	/*
	 * For some SCTP level options, one can select the association this
	 * applies to.
	 */
	if (so->so_type == SOCK_STREAM) {
		conn = so->so_proto_handle;
	} else {
		/*
		 * SOCK_SEQPACKET only
		 */
		id = 0;
		if (level == IPPROTO_SCTP) {
			switch (option_name) {
			case SCTP_RTOINFO:
			case SCTP_ASSOCINFO:
			case SCTP_SET_PEER_PRIMARY_ADDR:
			case SCTP_PRIMARY_ADDR:
			case SCTP_PEER_ADDR_PARAMS:
				/*
				 * Association ID is the first element
				 * params struct
				 */
				if (optlen < sizeof (sctp_assoc_t)) {
					error = EINVAL;
					eprintsoline(so, error);
					goto done;
				}
				id = *(sctp_assoc_t *)optval;
				break;
			case SCTP_DEFAULT_SEND_PARAM:
				if (optlen != sizeof (struct sctp_sndrcvinfo)) {
					error = EINVAL;
					eprintsoline(so, error);
					goto done;
				}
				id = ((struct sctp_sndrcvinfo *)
				    optval)->sinfo_assoc_id;
				break;
			case SCTP_INITMSG:
				/*
				 * Only applies to future associations
				 */
				conn = so->so_proto_handle;
				break;
			default:
				break;
			}
		} else if (level == SOL_SOCKET) {
			if (option_name == SO_LINGER) {
				error = EOPNOTSUPP;
				eprintsoline(so, error);
				goto done;
			}
			/*
			 * These 2 options are applied to all associations.
			 * The other socket level options are only applied
			 * to the socket (not associations).
			 */
			if ((option_name != SO_RCVBUF) &&
			    (option_name != SO_SNDBUF)) {
				conn = so->so_proto_handle;
			}
		} else {
			conn = NULL;
		}

		/*
		 * If association ID was specified, do op on that assoc.
		 * Otherwise set the default setting of a socket.
		 */
		if (id != 0) {
			if ((error = sosctp_assoc(ss, id, &ssa)) != 0) {
				eprintsoline(so, error);
				goto done;
			}
			conn = ssa->ssa_conn;
		}
	}
	dprint(2, ("sosctp_setsockopt %p (%d) - conn %p %d %d id:%d\n",
	    (void *)ss, so->so_type, (void *)conn, level, option_name, id));

	ASSERT(ssa == NULL || (ssa != NULL && conn != NULL));
	if (conn != NULL) {
		mutex_exit(&so->so_lock);
		error = sctp_set_opt((struct sctp_s *)conn, level, option_name,
		    optval, optlen);
		mutex_enter(&so->so_lock);
		if (ssa != NULL)
			SSA_REFRELE(ss, ssa);
	} else {
		/*
		 * 1-N socket, and we have to apply the operation to ALL
		 * associations. Like with anything of this sort, the
		 * problem is what to do if the operation fails.
		 * Just try to apply the setting to everyone, but store
		 * error number if someone returns such.  And since we are
		 * looping through all possible aids, some of them can be
		 * invalid.  We just ignore this kind (sosctp_assoc()) of
		 * errors.
		 */
		sctp_assoc_t aid;

		mutex_exit(&so->so_lock);
		error = sctp_set_opt((struct sctp_s *)so->so_proto_handle,
		    level, option_name, optval, optlen);
		mutex_enter(&so->so_lock);
		for (aid = 1; aid < ss->ss_maxassoc; aid++) {
			if (sosctp_assoc(ss, aid, &ssa) != 0)
				continue;
			mutex_exit(&so->so_lock);
			rc = sctp_set_opt((struct sctp_s *)ssa->ssa_conn, level,
			    option_name, optval, optlen);
			mutex_enter(&so->so_lock);
			SSA_REFRELE(ss, ssa);
			if (error == 0) {
				error = rc;
			}
		}
	}
done:
	mutex_exit(&so->so_lock);
	return (error);
}

/*ARGSUSED*/
static int
sosctp_ioctl(struct sonode *so, int cmd, intptr_t arg, int mode,
    struct cred *cr, int32_t *rvalp)
{
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

		error = (pid != so->so_pgrp) ? socket_chgpgrp(so, pid) : 0;
		mutex_exit(&so->so_lock);
		return (error);

	case SIOCGPGRP:
	case FIOGETOWN:
		if (so_copyout(&so->so_pgrp, (void *)arg,
		    sizeof (pid_t), (mode & (int)FKIOCTL)))
			return (EFAULT);
		return (0);

	case FIONREAD:
		/* XXX: Cannot be used unless standard buffer is used */
		/*
		 * Return number of bytes of data in all data messages
		 * in queue in "arg".
		 * For stream socket, amount of available data.
		 * For sock_dgram, # of available bytes + addresses.
		 */
		intval = (so->so_state & SS_ACCEPTCONN) ? 0 :
		    MIN(so->so_rcv_queued, INT_MAX);
		if (so_copyout(&intval, (void *)arg, sizeof (intval),
		    (mode & (int)FKIOCTL)))
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
	case _I_GETPEERCRED: {
		int error = 0;

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
	}
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
			conn = so->so_proto_handle;
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
		error = sctp_get_opt((struct sctp_s *)conn, IPPROTO_SCTP,
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
			conn = so->so_proto_handle;
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
		error = sctp_set_opt((struct sctp_s *)conn, IPPROTO_SCTP,
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
		struct vnode *nvp = NULL;
		struct sockparams *sp;

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
		 * Find sockparams. This is different from parent's entry,
		 * as the socket type is different.
		 */
		error = solookup(so->so_family, SOCK_STREAM, so->so_protocol,
		    &sp);
		if (error != 0)
			return (error);

		/*
		 * Allocate the user fd.
		 */
		if ((nfd = ufalloc(0)) == -1) {
			eprintsoline(so, EMFILE);
			SOCKPARAMS_DEC_REF(sp);
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

		nso = socksctp_create(sp, so->so_family, SOCK_STREAM,
		    so->so_protocol, so->so_version, SOCKET_NOSLEEP,
		    &error, cr);
		if (nso == NULL) {
			SSA_REFRELE(ss, ssa);
			mutex_exit(&so->so_lock);
			goto err;
		}
		nvp = SOTOV(nso);
		so_lock_single(so);
		mutex_exit(&so->so_lock);

		/* cannot fail, only inheriting properties */
		(void) sosctp_init(nso, so, CRED(), 0);

		/*
		 * We have a single ref on the new socket. This is normally
		 * handled by socket_{create,newconn}, but since they are not
		 * used we have to do it here.
		 */
		nso->so_count = 1;

		us.sus_handle = nso;
		us.sus_upcalls = &sosctp_sock_upcalls;

		/*
		 * Upcalls to new socket are blocked for the duration of
		 * downcall.
		 */
		mutex_enter(&nso->so_lock);

		error = sctp_set_opt((struct sctp_s *)ssa->ssa_conn,
		    IPPROTO_SCTP, SCTP_UC_SWAP, &us, sizeof (us));
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
		SOCKPARAMS_DEC_REF(sp);
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

		setf(nfd, NULL);
		ASSERT(nvp->v_count == 1);
		socket_destroy(nso);
		eprintsoline(so, error);
		return (error);
	}
	default:
		return (EINVAL);
	}
}

/*ARGSUSED*/
static int
sosctp_close(struct sonode *so, int flag, struct cred *cr)
{
	struct sctp_sonode *ss;
	struct sctp_sa_id *ssi;
	struct sctp_soassoc *ssa;
	int32_t i;

	ss = SOTOSSO(so);

	/*
	 * Initiate connection shutdown.  Tell SCTP if there is any data
	 * left unread.
	 */
	sctp_recvd((struct sctp_s *)so->so_proto_handle,
	    so->so_rcvbuf - so->so_rcv_queued);
	(void) sctp_disconnect((struct sctp_s *)so->so_proto_handle);

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
			    ssa->ssa_rcv_queued);
			(void) sctp_disconnect(ssa->ssa_conn);

			mutex_enter(&so->so_lock);
			SSA_REFRELE(ss, ssa);
		}
	}
	mutex_exit(&so->so_lock);

	return (0);
}

/*
 * Closes incoming connections which were never accepted, frees
 * resources.
 */
/* ARGSUSED */
void
sosctp_fini(struct sonode *so, struct cred *cr)
{
	struct sctp_sonode *ss;
	struct sctp_sa_id *ssi;
	struct sctp_soassoc *ssa;
	int32_t i;

	ss = SOTOSSO(so);

	ASSERT(so->so_ops == &sosctp_sonodeops ||
	    so->so_ops == &sosctp_seq_sonodeops);

	/* We are the sole owner of so now */
	mutex_enter(&so->so_lock);

	/* Free all pending connections */
	so_acceptq_flush(so, B_TRUE);

	ssi = ss->ss_assocs;
	for (i = 0; i < ss->ss_maxassoc; i++, ssi++) {
		if ((ssa = ssi->ssi_assoc) != NULL) {
			SSA_REFHOLD(ssa);
			mutex_exit(&so->so_lock);

			sctp_close((struct sctp_s *)ssa->ssa_conn);

			mutex_enter(&so->so_lock);
			ssa->ssa_conn = NULL;
			sosctp_assoc_free(ss, ssa);
		}
	}
	if (ss->ss_assocs != NULL) {
		ASSERT(ss->ss_assoccnt == 0);
		kmem_free(ss->ss_assocs,
		    ss->ss_maxassoc * sizeof (struct sctp_sa_id));
	}
	mutex_exit(&so->so_lock);

	if (so->so_proto_handle)
		sctp_close((struct sctp_s *)so->so_proto_handle);
	so->so_proto_handle = NULL;

	/*
	 * Note until sctp_close() is called, SCTP can still send up
	 * messages, such as event notifications.  So we should flush
	 * the recevie buffer after calling sctp_close().
	 */
	mutex_enter(&so->so_lock);
	so_rcv_flush(so);
	mutex_exit(&so->so_lock);

	sonode_fini(so);
}

/*
 * Upcalls from SCTP
 */

/*
 * This is the upcall function for 1-N (SOCK_SEQPACKET) socket when a new
 * association is created.  Note that the first argument (handle) is of type
 * sctp_sonode *, which is the one changed to a listener for new
 * associations.  All the other upcalls for 1-N socket take sctp_soassoc *
 * as handle.  The only exception is the su_properties upcall, which
 * can take both types as handle.
 */
/* ARGSUSED */
sock_upper_handle_t
sctp_assoc_newconn(sock_upper_handle_t parenthandle,
    sock_lower_handle_t connind, sock_downcalls_t *dc,
    struct cred *peer_cred, pid_t peer_cpid, sock_upcalls_t **ucp)
{
	struct sctp_sonode *lss = (struct sctp_sonode *)parenthandle;
	struct sonode *lso = &lss->ss_so;
	struct sctp_soassoc *ssa;
	sctp_assoc_t id;

	ASSERT(lss->ss_type == SOSCTP_SOCKET);
	ASSERT(lso->so_state & SS_ACCEPTCONN);
	ASSERT(lso->so_proto_handle != NULL); /* closed conn */
	ASSERT(lso->so_type == SOCK_SEQPACKET);

	mutex_enter(&lso->so_lock);

	if ((id = sosctp_aid_get(lss)) == -1) {
		/*
		 * Array not large enough; increase size.
		 */
		if (sosctp_aid_grow(lss, lss->ss_maxassoc, KM_NOSLEEP) < 0) {
			mutex_exit(&lso->so_lock);
			return (NULL);
		}
		id = sosctp_aid_get(lss);
		ASSERT(id != -1);
	}

	/*
	 * Create soassoc for this connection
	 */
	ssa = sosctp_assoc_create(lss, KM_NOSLEEP);
	if (ssa == NULL) {
		mutex_exit(&lso->so_lock);
		return (NULL);
	}
	sosctp_aid_reserve(lss, id, 1);
	lss->ss_assocs[id].ssi_assoc = ssa;
	++lss->ss_assoccnt;
	ssa->ssa_id = id;
	ssa->ssa_conn = (struct sctp_s *)connind;
	ssa->ssa_state = (SS_ISBOUND | SS_ISCONNECTED);
	ssa->ssa_wroff = lss->ss_wroff;
	ssa->ssa_wrsize = lss->ss_wrsize;

	mutex_exit(&lso->so_lock);

	*ucp = &sosctp_assoc_upcalls;

	return ((sock_upper_handle_t)ssa);
}

/* ARGSUSED */
static void
sctp_assoc_connected(sock_upper_handle_t handle, sock_connid_t id,
    struct cred *peer_cred, pid_t peer_cpid)
{
	struct sctp_soassoc *ssa = (struct sctp_soassoc *)handle;
	struct sonode *so = &ssa->ssa_sonode->ss_so;

	ASSERT(so->so_type == SOCK_SEQPACKET);
	ASSERT(ssa->ssa_conn);

	mutex_enter(&so->so_lock);
	sosctp_assoc_isconnected(ssa);
	mutex_exit(&so->so_lock);
}

/* ARGSUSED */
static int
sctp_assoc_disconnected(sock_upper_handle_t handle, sock_connid_t id, int error)
{
	struct sctp_soassoc *ssa = (struct sctp_soassoc *)handle;
	struct sonode *so = &ssa->ssa_sonode->ss_so;
	int ret;

	ASSERT(so->so_type == SOCK_SEQPACKET);
	ASSERT(ssa->ssa_conn != NULL);

	mutex_enter(&so->so_lock);
	sosctp_assoc_isdisconnected(ssa, error);
	if (ssa->ssa_refcnt == 1) {
		ret = 1;
		ssa->ssa_conn = NULL;
	} else {
		ret = 0;
	}
	SSA_REFRELE(SOTOSSO(so), ssa);

	cv_broadcast(&so->so_snd_cv);

	mutex_exit(&so->so_lock);

	return (ret);
}

/* ARGSUSED */
static void
sctp_assoc_disconnecting(sock_upper_handle_t handle, sock_opctl_action_t action,
    uintptr_t arg)
{
	struct sctp_soassoc *ssa = (struct sctp_soassoc *)handle;
	struct sonode *so = &ssa->ssa_sonode->ss_so;

	ASSERT(so->so_type == SOCK_SEQPACKET);
	ASSERT(ssa->ssa_conn != NULL);
	ASSERT(action == SOCK_OPCTL_SHUT_SEND);

	mutex_enter(&so->so_lock);
	sosctp_assoc_isdisconnecting(ssa);
	mutex_exit(&so->so_lock);
}

/* ARGSUSED */
static ssize_t
sctp_assoc_recv(sock_upper_handle_t handle, mblk_t *mp, size_t len, int flags,
    int *errorp, boolean_t *forcepush)
{
	struct sctp_soassoc *ssa = (struct sctp_soassoc *)handle;
	struct sctp_sonode *ss = ssa->ssa_sonode;
	struct sonode *so = &ss->ss_so;
	struct T_unitdata_ind *tind;
	mblk_t *mp2;
	union sctp_notification *sn;
	struct sctp_sndrcvinfo *sinfo;
	ssize_t space_available;

	ASSERT(ssa->ssa_type == SOSCTP_ASSOC);
	ASSERT(so->so_type == SOCK_SEQPACKET);
	ASSERT(ssa->ssa_conn != NULL); /* closed conn */
	ASSERT(mp != NULL);

	ASSERT(errorp != NULL);
	*errorp = 0;

	/*
	 * Should be getting T_unitdata_req's only.
	 * Must have address as part of packet.
	 */
	tind = (struct T_unitdata_ind *)mp->b_rptr;
	ASSERT((DB_TYPE(mp) == M_PROTO) &&
	    (tind->PRIM_type == T_UNITDATA_IND));
	ASSERT(tind->SRC_length);

	mutex_enter(&so->so_lock);

	/*
	 * For notify messages, need to fill in association id.
	 * For data messages, sndrcvinfo could be in ancillary data.
	 */
	if (mp->b_flag & SCTP_NOTIFICATION) {
		mp2 = mp->b_cont;
		sn = (union sctp_notification *)mp2->b_rptr;
		switch (sn->sn_header.sn_type) {
		case SCTP_ASSOC_CHANGE:
			sn->sn_assoc_change.sac_assoc_id = ssa->ssa_id;
			break;
		case SCTP_PEER_ADDR_CHANGE:
			sn->sn_paddr_change.spc_assoc_id = ssa->ssa_id;
			break;
		case SCTP_REMOTE_ERROR:
			sn->sn_remote_error.sre_assoc_id = ssa->ssa_id;
			break;
		case SCTP_SEND_FAILED:
			sn->sn_send_failed.ssf_assoc_id = ssa->ssa_id;
			break;
		case SCTP_SHUTDOWN_EVENT:
			sn->sn_shutdown_event.sse_assoc_id = ssa->ssa_id;
			break;
		case SCTP_ADAPTATION_INDICATION:
			sn->sn_adaptation_event.sai_assoc_id = ssa->ssa_id;
			break;
		case SCTP_PARTIAL_DELIVERY_EVENT:
			sn->sn_pdapi_event.pdapi_assoc_id = ssa->ssa_id;
			break;
		default:
			ASSERT(0);
			break;
		}
	} else {
		if (tind->OPT_length > 0) {
			struct cmsghdr	*cmsg;
			char		*cend;

			cmsg = (struct cmsghdr *)
			    ((uchar_t *)mp->b_rptr + tind->OPT_offset);
			cend = (char *)cmsg + tind->OPT_length;
			for (;;) {
				if ((char *)(cmsg + 1) > cend ||
				    ((char *)cmsg + cmsg->cmsg_len) > cend) {
					break;
				}
				if ((cmsg->cmsg_level == IPPROTO_SCTP) &&
				    (cmsg->cmsg_type == SCTP_SNDRCV)) {
					sinfo = (struct sctp_sndrcvinfo *)
					    (cmsg + 1);
					sinfo->sinfo_assoc_id = ssa->ssa_id;
					break;
				}
				if (cmsg->cmsg_len > 0) {
					cmsg = (struct cmsghdr *)
					    ((uchar_t *)cmsg + cmsg->cmsg_len);
				} else {
					break;
				}
			}
		}
	}

	/*
	 * SCTP has reserved space in the header for storing a pointer.
	 * Put the pointer to assocation there, and queue the data.
	 */
	SSA_REFHOLD(ssa);
	ASSERT((mp->b_rptr - DB_BASE(mp)) >= sizeof (ssa));
	*(struct sctp_soassoc **)DB_BASE(mp) = ssa;

	ssa->ssa_rcv_queued += len;
	space_available = so->so_rcvbuf - ssa->ssa_rcv_queued;
	if (space_available <= 0)
		ssa->ssa_flowctrld = B_TRUE;

	so_enqueue_msg(so, mp, len);

	/* so_notify_data drops so_lock */
	so_notify_data(so, len);

	return (space_available);
}

static void
sctp_assoc_xmitted(sock_upper_handle_t handle, boolean_t qfull)
{
	struct sctp_soassoc *ssa = (struct sctp_soassoc *)handle;
	struct sctp_sonode *ss = ssa->ssa_sonode;

	ASSERT(ssa->ssa_type == SOSCTP_ASSOC);
	ASSERT(ss->ss_so.so_type == SOCK_SEQPACKET);
	ASSERT(ssa->ssa_conn != NULL);

	mutex_enter(&ss->ss_so.so_lock);

	ssa->ssa_snd_qfull = qfull;

	/*
	 * Wake blocked writers.
	 */
	cv_broadcast(&ss->ss_so.so_snd_cv);

	mutex_exit(&ss->ss_so.so_lock);
}

static void
sctp_assoc_properties(sock_upper_handle_t handle,
    struct sock_proto_props *soppp)
{
	struct sctp_soassoc *ssa = (struct sctp_soassoc *)handle;
	struct sonode *so;

	if (ssa->ssa_type == SOSCTP_ASSOC) {
		so = &ssa->ssa_sonode->ss_so;

		mutex_enter(&so->so_lock);

		/* Per assoc_id properties. */
		if (soppp->sopp_flags & SOCKOPT_WROFF)
			ssa->ssa_wroff = soppp->sopp_wroff;
		if (soppp->sopp_flags & SOCKOPT_MAXBLK)
			ssa->ssa_wrsize = soppp->sopp_maxblk;
	} else {
		so = &((struct sctp_sonode *)handle)->ss_so;
		mutex_enter(&so->so_lock);

		if (soppp->sopp_flags & SOCKOPT_WROFF)
			so->so_proto_props.sopp_wroff = soppp->sopp_wroff;
		if (soppp->sopp_flags & SOCKOPT_MAXBLK)
			so->so_proto_props.sopp_maxblk = soppp->sopp_maxblk;
		if (soppp->sopp_flags & SOCKOPT_RCVHIWAT) {
			ssize_t lowat;

			so->so_rcvbuf = soppp->sopp_rxhiwat;
			/*
			 * The low water mark should be adjusted properly
			 * if the high water mark is changed.  It should
			 * not be bigger than 1/4 of high water mark.
			 */
			lowat = soppp->sopp_rxhiwat >> 2;
			if (so->so_rcvlowat > lowat) {
				/* Sanity check... */
				if (lowat == 0)
					so->so_rcvlowat = soppp->sopp_rxhiwat;
				else
					so->so_rcvlowat = lowat;
			}
		}
	}
	mutex_exit(&so->so_lock);
}
