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
 *
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/time.h>
#include <sys/varargs.h>
#include <sys/modctl.h>
#include <sys/pathname.h>
#include <sys/vnode.h>
#include <sys/socket.h>
#include <sys/ksocket.h>
#undef mem_free /* XXX Remove this after we convert everything to kmem_alloc */

#include <smbsrv/smb_vops.h>
#include <smbsrv/smb.h>
#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_kstat.h>

/*
 * SMB Network Socket API
 *
 * smb_socreate:	Creates an socket based on domain/type.
 * smb_soshutdown:	Disconnect a socket created with smb_socreate
 * smb_sodestroy:	Release resources associated with a socket
 * smb_sosend:		Send the contents of a buffer on a socket
 * smb_sorecv:		Receive data into a buffer from a socket
 * smb_iov_sosend:	Send the contents of an iovec on a socket
 * smb_iov_sorecv:	Receive data into an iovec from a socket
 */

ksocket_t
smb_socreate(int domain, int type, int protocol)
{
	ksocket_t	sock;
	int		err = 0;

	err = ksocket_socket(&sock, domain, type, protocol, KSOCKET_SLEEP,
	    CRED());

	if (err != 0)
		return (NULL);
	else
		return (sock);
}

/*
 * smb_soshutdown will disconnect the socket and prevent subsequent PDU
 * reception and transmission.  The sonode still exists but its state
 * gets modified to indicate it is no longer connected.  Calls to
 * smb_sorecv/smb_iov_sorecv will return so smb_soshutdown can be used
 * regain control of a thread stuck in smb_sorecv.
 */
void
smb_soshutdown(ksocket_t so)
{
	(void) ksocket_shutdown(so, SHUT_RDWR, CRED());
}

/*
 * smb_sodestroy releases all resources associated with a socket previously
 * created with smb_socreate.  The socket must be shutdown using smb_soshutdown
 * before the socket is destroyed with smb_sodestroy, otherwise undefined
 * behavior will result.
 */
void
smb_sodestroy(ksocket_t so)
{
	(void) ksocket_close(so, CRED());
}

int
smb_sorecv(ksocket_t so, void *msg, size_t len)
{
	size_t recvd;
	int err;

	ASSERT(so != NULL);
	ASSERT(len != 0);

	if ((err = ksocket_recv(so, msg, len, MSG_WAITALL, &recvd,
	    CRED())) != 0) {
		return (err);
	}

	/* Successful receive */
	return ((recvd == len) ? 0 : -1);
}

/*
 * smb_net_txl_constructor
 *
 *	Transmit list constructor
 */
void
smb_net_txl_constructor(smb_txlst_t *txl)
{
	ASSERT(txl->tl_magic != SMB_TXLST_MAGIC);

	mutex_init(&txl->tl_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&txl->tl_wait_cv, NULL, CV_DEFAULT, NULL);
	txl->tl_active = B_FALSE;
	txl->tl_magic = SMB_TXLST_MAGIC;
}

/*
 * smb_net_txl_destructor
 *
 *	Transmit list destructor
 */
void
smb_net_txl_destructor(smb_txlst_t *txl)
{
	ASSERT(txl->tl_magic == SMB_TXLST_MAGIC);

	txl->tl_magic = 0;
	cv_destroy(&txl->tl_wait_cv);
	mutex_destroy(&txl->tl_mutex);
}

/*
 * smb_net_send_uio
 *
 * This routine puts the transmit buffer passed in on the wire.
 * If another thread is already sending, block on the CV.
 */
int
smb_net_send_uio(smb_session_t *s, struct uio *uio)
{
	struct msghdr msg;
	size_t sent;
	smb_txlst_t *txl = &s->s_txlst;
	int rc = 0;

	DTRACE_PROBE1(send__wait__start, struct smb_session_t *, s);

	/*
	 * Wait for our turn to send.
	 */
	mutex_enter(&txl->tl_mutex);
	while (txl->tl_active)
		cv_wait(&txl->tl_wait_cv, &txl->tl_mutex);

	/*
	 * Did the connection close while we waited?
	 */
	switch (s->s_state) {
	case SMB_SESSION_STATE_DISCONNECTED:
	case SMB_SESSION_STATE_TERMINATED:
		rc = ENOTCONN;
		break;
	default:
		txl->tl_active = B_TRUE;
		break;
	}
	mutex_exit(&txl->tl_mutex);

	DTRACE_PROBE1(send__wait__done, struct smb_session_t *, s);
	if (rc != 0)
		return (rc);

	/*
	 * OK, try to send.
	 *
	 * This should block until we've sent it all,
	 * or given up due to errors (socket closed).
	 */
	bzero(&msg, sizeof (msg));
	msg.msg_iov = uio->uio_iov;
	msg.msg_iovlen = uio->uio_iovcnt;
	while (uio->uio_resid > 0) {
		rc = ksocket_sendmsg(s->sock, &msg, 0, &sent, CRED());
		if (rc != 0)
			break;
		uio->uio_resid -= sent;
	}

	mutex_enter(&txl->tl_mutex);
	txl->tl_active = B_FALSE;
	cv_signal(&txl->tl_wait_cv);
	mutex_exit(&txl->tl_mutex);

	return (rc);
}
