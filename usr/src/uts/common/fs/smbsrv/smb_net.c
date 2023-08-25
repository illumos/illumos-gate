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
 * Copyright 2022 RackTop Systems, Inc.
 * Copyright 2011-2021 Tintri by DDN, Inc. All rights reserved.
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
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
#include <sys/stream.h>
#include <sys/strsubr.h>

#include <smbsrv/smb_vops.h>
#include <smbsrv/smb.h>
#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_kstat.h>

/*
 * How many iovec we'll handle as a local array (no allocation)
 * See also IOV_MAX_STACK <sys/limits.h> but we need this to
 * work also with _FAKE_KERNEL
 */
#define	SMB_LOCAL_IOV_MAX	16

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
 * Receive a message as an mbuf chain (returned in *mpp)
 * where the length requested is len.
 *
 * Some day hopefully this will be able to receive an actual
 * mblk chain from the network stack (without copying), and
 * either wrap those to create mbufs, or use mblks directly.
 * For now, we allocate buffers here to recv into.
 */
int
smb_net_recv_mbufs(smb_session_t *s, mbuf_t **mpp, size_t len)
{
	struct nmsghdr	msg;
	uio_t	uio;
	iovec_t iov[SMB_LOCAL_IOV_MAX];
	mbuf_t	*mhead = NULL;
	size_t	rlen;
	int	rc;

	bzero(&msg, sizeof (msg));
	bzero(&uio, sizeof (uio));
	ASSERT(len > 0);

	mhead = smb_mbuf_alloc_chain(len);

	uio.uio_resid = len;
	uio.uio_iov = iov;
	uio.uio_iovcnt = SMB_LOCAL_IOV_MAX;

	rc = smb_mbuf_mkuio(mhead, &uio);
	if (rc != 0)
		goto errout;

	msg.msg_iov = uio.uio_iov;
	msg.msg_iovlen = uio.uio_iovcnt;
	rlen = len;
	rc = ksocket_recvmsg(s->sock, &msg, MSG_WAITALL, &rlen, CRED());
	if (rc != 0)
		goto errout;
	if (rlen != len) {
		rc = SET_ERROR(EIO);
		goto errout;
	}

	*mpp = mhead;
	return (rc);

errout:
	m_freem(mhead);
	return (rc);
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

static void
smb_net_send_free(void *arg)
{
	mbuf_t *m = arg;
	(void) m_free(m);
}

/*
 * Create an mblk that wraps the passed mbuf
 *
 * Note we need a place to store a frtn_t for each mbuf.
 * For M_EXT packets (most are) we have lots of unused space
 * after the headers: M_dat.MH.MH_dat.MH_ext (a.k.a. m_ext)
 * If not M_EXT but there's enough trailing space, just use
 * the trailing space, otherwise convert to external type
 * (which means copying the data, so do only if necessary).
 *
 * To simplify the code, the frtn_t is always located at the
 * end of the mbuf (in space we make sure is unused).
 */
static mblk_t *
smb_net_wrap_mbuf(mbuf_t *mbuf)
{
	frtn_t		*frtn;
	mblk_t		*mblk;

	if ((mbuf->m_flags & M_EXT) == 0 &&
	    M_TRAILINGSPACE(mbuf) < sizeof (*frtn)) {
		/*
		 * Convert to M_EXT type, like MCLGET(),
		 * but copy before updating mbuf->m_ext,
		 * which would otherwise overwrite data.
		 */
		caddr_t buf = smb_mbufcl_alloc();
		ASSERT(mbuf->m_len <= MLEN);
		bcopy(mbuf->m_data, buf, mbuf->m_len);
		mbuf->m_ext.ext_buf = buf;
		mbuf->m_data = buf;
		mbuf->m_flags |= M_EXT;
		mbuf->m_ext.ext_size = MCLBYTES;
		mbuf->m_ext.ext_free = smb_mbufcl_free;
	}

	/*
	 * Store frtn_t at the end of the mbuf data area.
	 * Note: This is the _internal_ data area (unused)
	 * not the external data pointed to by m_data.
	 */
	frtn = (void *) &mbuf->m_dat[MLEN - sizeof (*frtn)];

	frtn->free_func = smb_net_send_free;
	frtn->free_arg = (caddr_t)mbuf;

	mblk = esballoca_wait((void *)mbuf->m_data, mbuf->m_len,
	    BPRI_MED, frtn);
	if (mblk != NULL) {
		mblk->b_wptr += mbuf->m_len;
		mblk->b_datap->db_type = M_DATA;
	}

	return (mblk);
}

/*
 * This routine sends an mbuf chain by encapsulating each segment
 * with an mblk_t setup with external storage (zero-copy).
 *
 * Note: the mbufs passed in are free'd via smb_net_send_free.
 */
static int
smb_net_send_mblks(smb_session_t *s, mbuf_t *mbuf_head)
{
	struct nmsghdr	msg;
	mblk_t	*mblk_head;
	mblk_t	*mblk_prev;
	mblk_t	*mblk;
	mbuf_t	*mbuf_prev;
	mbuf_t	*mbuf;
	smb_txlst_t *txl;
	int	rc = 0;

	bzero(&msg, sizeof (msg));

	mblk_prev = NULL;
	mblk_head = NULL;
	mbuf_prev = NULL;
	mbuf = mbuf_head;
	while (mbuf != NULL) {
		mblk = smb_net_wrap_mbuf(mbuf);
		if (mblk == NULL) {
			rc = ENOSR;
			break;
		}
		if (mblk_head == NULL)
			mblk_head = mblk;
		if (mblk_prev != NULL)
			mblk_prev->b_cont = mblk;

		mblk_prev = mblk;
		mbuf_prev = mbuf;
		mbuf = mbuf->m_next;
	}
	if (rc != 0) {
		/* Bailed with ENOSR. Cleanup */
		if (mbuf != NULL) {
			if (mbuf_prev != NULL)
				mbuf_prev->m_next = NULL;
			m_freem(mbuf);
		}
		if (mblk_head != NULL)
			freemsg(mblk_head);
		return (rc);
	}

	/*
	 * Wait for our turn to send.
	 */
	DTRACE_PROBE1(send__wait__start, struct smb_session_t *, s);
	txl = &s->s_txlst;
	mutex_enter(&txl->tl_mutex);
	while (txl->tl_active)
		cv_wait(&txl->tl_wait_cv, &txl->tl_mutex);
	txl->tl_active = B_TRUE;
	mutex_exit(&txl->tl_mutex);
	DTRACE_PROBE1(send__wait__done, struct smb_session_t *, s);

	/*
	 * OK, send it.
	 */
	rc = ksocket_sendmblk(s->sock, &msg, 0, &mblk_head, CRED());
	if (rc != 0) {
		if (mblk_head != NULL) {
			freemsg(mblk_head);
			mblk_head = NULL;
		}
	}

	mutex_enter(&txl->tl_mutex);
	txl->tl_active = B_FALSE;
	cv_signal(&txl->tl_wait_cv);
	mutex_exit(&txl->tl_mutex);

	return (rc);
}

/*
 * This routine sends an mbuf chain by copying its segments
 * (scatter/gather) via UIO.
 *
 * The mbuf chain is always free'd (error or not)
 */
static int
smb_net_send_uio(smb_session_t *s, mbuf_t *mbuf_head)
{
	struct nmsghdr	msg;
	uio_t	uio;
	iovec_t iov_local[SMB_LOCAL_IOV_MAX];
	mbuf_t	*mbuf;
	smb_txlst_t *txl;
	smb_vdb_t *vdb = NULL;
	size_t sent;
	int	len, nseg, rc;

	bzero(&msg, sizeof (msg));
	bzero(&uio, sizeof (uio));

	len = nseg = 0;
	for (mbuf = mbuf_head;
	     mbuf != NULL;
	     mbuf = mbuf->m_next) {
		nseg++;
		len += mbuf->m_len;
	}

	if (nseg <= SMB_LOCAL_IOV_MAX) {
		uio.uio_iov = iov_local;
		uio.uio_iovcnt = SMB_LOCAL_IOV_MAX;
	} else {
		vdb = kmem_alloc(sizeof (*vdb), KM_SLEEP);
		uio.uio_iov = &vdb->vdb_iovec[0];
		uio.uio_iovcnt = MAX_IOVEC;
	}
	uio.uio_resid = len;

	rc = smb_mbuf_mkuio(mbuf_head, &uio);
	if (rc != 0)
		goto out;

	DTRACE_PROBE1(send__wait__start, struct smb_session_t *, s);

	/*
	 * Wait for our turn to send.
	 */
	txl = &s->s_txlst;
	mutex_enter(&txl->tl_mutex);
	while (txl->tl_active)
		cv_wait(&txl->tl_wait_cv, &txl->tl_mutex);
	txl->tl_active = B_TRUE;
	mutex_exit(&txl->tl_mutex);

	DTRACE_PROBE1(send__wait__done, struct smb_session_t *, s);

	/*
	 * OK, try to send.
	 *
	 * This should block until we've sent it all,
	 * or given up due to errors (socket closed).
	 */
	msg.msg_iov = uio.uio_iov;
	msg.msg_iovlen = uio.uio_iovcnt;
	while (uio.uio_resid > 0) {
		rc = ksocket_sendmsg(s->sock, &msg, 0, &sent, CRED());
		if (rc != 0)
			break;
		uio.uio_resid -= sent;
	}

	mutex_enter(&txl->tl_mutex);
	txl->tl_active = B_FALSE;
	cv_signal(&txl->tl_wait_cv);
	mutex_exit(&txl->tl_mutex);

out:
	if (vdb != NULL)
		kmem_free(vdb, sizeof (*vdb));
	m_freem(mbuf_head);
	return (rc);
}

/*
 * This has an optional code path calling ksocket_sendmblk,
 * which is faster than ksocket_sendmsg (UIO copying) in some
 * configurations, but needs work before it's uniformly faster.
 * In particular, the ksocket_sendmblk code path probably needs
 * to do more like socopyinuio etc, checking the send socket
 * SO_SND_BUFINFO, SO_SND_COPYAVOID, etc. to find out what is
 * the preferred MSS, header space, copying preference, etc.
 *
 * As it is, this works well with some NIC drivers, particularly
 * with MTU=9000 as is typical in high performance setups, so
 * this remains available via this tunable for now.
 */
int smb_send_mblks = 0;

/*
 * smb_net_send_mbufs
 *
 * Send the buf chain using either mblk encapsulation (zero-copy)
 * or via scatter/gather UIO vector, based on the setting.
 */
int
smb_net_send_mbufs(smb_session_t *s, mbuf_t *mbuf_head)
{
	int rc;

	if (smb_send_mblks != 0) {
		rc = smb_net_send_mblks(s, mbuf_head);
	} else {
		rc = smb_net_send_uio(s, mbuf_head);
	}
	return (rc);
}
