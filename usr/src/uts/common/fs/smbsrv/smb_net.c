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
#include <sys/param.h>
#include <sys/cpuvar.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/time.h>
#include <sys/varargs.h>
#include <sys/modctl.h>
#include <sys/pathname.h>
#include <sys/fs/snode.h>
#include <sys/fs/dv_node.h>
#include <sys/vnode.h>
#undef mem_free /* XXX Remove this after we convert everything to kmem_alloc */

#include <smbsrv/smb_vops.h>
#include <smbsrv/smb.h>
#include <smbsrv/mlsvc.h>
#include <smbsrv/smbvar.h>
#include <smbsrv/smb_kproto.h>

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

struct sonode *
smb_socreate(int domain, int type, int protocol)
{
	vnode_t		*dvp		= NULL;
	vnode_t		*vp		= NULL;
	struct snode	*csp		= NULL;
	int		err		= 0;
	major_t		maj;

	if ((vp = solookup(domain, type, protocol, NULL, &err)) == NULL) {

		/*
		 * solookup calls sogetvp if the vp is not found in the cache.
		 * Since the call to sogetvp is hardwired to use USERSPACE
		 * and declared static we'll do the work here instead.
		 */
		err = lookupname(type == SOCK_STREAM ? "/dev/tcp" : "/dev/udp",
		    UIO_SYSSPACE, FOLLOW, NULLVPP, &vp);
		if (err)
			return (NULL);

		/* Check that it is the correct vnode */
		if (vp->v_type != VCHR) {
			VN_RELE(vp);
			return (NULL);
		}

		csp = VTOS(VTOS(vp)->s_commonvp);
		if (!(csp->s_flag & SDIPSET)) {
			char    *pathname = kmem_alloc(MAXPATHLEN, KM_SLEEP);
			err = ddi_dev_pathname(vp->v_rdev, S_IFCHR,
			    pathname);
			if (err == 0) {
				err = devfs_lookupname(pathname, NULLVPP,
				    &dvp);
			}
			VN_RELE(vp);
			kmem_free(pathname, MAXPATHLEN);
			if (err != 0) {
				return (NULL);
			}
			vp = dvp;
		}

		maj = getmajor(vp->v_rdev);
		if (!STREAMSTAB(maj)) {
			VN_RELE(vp);
			return (NULL);
		}
	}

	return (socreate(vp, domain, type, protocol, SOV_DEFAULT, NULL, &err));
}

/*
 * smb_soshutdown will disconnect the socket and prevent subsequent PDU
 * reception and transmission.  The sonode still exists but its state
 * gets modified to indicate it is no longer connected.  Calls to
 * smb_sorecv/smb_iov_sorecv will return so smb_soshutdown can be used
 * regain control of a thread stuck in smb_sorecv.
 */
void
smb_soshutdown(struct sonode *so)
{
	(void) soshutdown(so, SHUT_RDWR);
}

/*
 * smb_sodestroy releases all resources associated with a socket previously
 * created with smb_socreate.  The socket must be shutdown using smb_soshutdown
 * before the socket is destroyed with smb_sodestroy, otherwise undefined
 * behavior will result.
 */
void
smb_sodestroy(struct sonode *so)
{
	vnode_t *vp = SOTOV(so);

	(void) VOP_CLOSE(vp, 0, 1, 0, kcred, NULL);
	VN_RELE(vp);
}

int
smb_sorecv(struct sonode *so, void *msg, size_t len)
{
	iovec_t iov;
	int err;

	ASSERT(so != NULL);
	ASSERT(len != 0);

	/*
	 * Fill in iovec and receive data
	 */
	iov.iov_base = msg;
	iov.iov_len = len;

	if ((err = smb_iov_sorecv(so, &iov, 1, len)) != 0) {
		return (err);
	}

	/* Successful receive */
	return (0);
}

/*
 * smb_iov_sorecv - Receives an iovec from a connection
 *
 * This function gets the data asked for from the socket.  It will return
 * only when all the requested data has been retrieved or if an error
 * occurs.
 *
 * Returns 0 for success, the socket errno value if sorecvmsg fails, and
 * -1 if sorecvmsg returns success but uio_resid != 0
 */
int
smb_iov_sorecv(struct sonode *so, iovec_t *iop, int iovlen, size_t total_len)
{
	struct msghdr		msg;
	struct uio		uio;
	int			error;

	ASSERT(iop != NULL);

	/* Initialization of the message header. */
	bzero(&msg, sizeof (msg));
	msg.msg_iov	= iop;
	msg.msg_flags	= MSG_WAITALL;
	msg.msg_iovlen	= iovlen;

	/* Initialization of the uio structure. */
	bzero(&uio, sizeof (uio));
	uio.uio_iov	= iop;
	uio.uio_iovcnt	= iovlen;
	uio.uio_segflg	= UIO_SYSSPACE;
	uio.uio_resid	= total_len;

	if ((error = sorecvmsg(so, &msg, &uio)) == 0) {
		/* Received data */
		if (uio.uio_resid == 0) {
			/* All requested data received.  Success */
			return (0);
		} else {
			/* Not all data was sent.  Failure */
			return (-1);
		}
	}

	/* Receive failed */
	return (error);
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
	list_create(&txl->tl_list, sizeof (smb_txbuf_t),
	    offsetof(smb_txbuf_t, tb_lnd));
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
	list_destroy(&txl->tl_list);
	mutex_destroy(&txl->tl_mutex);
}

/*
 * smb_net_txb_alloc
 *
 *	Transmit buffer allocator
 */
smb_txbuf_t *
smb_net_txb_alloc(void)
{
	smb_txbuf_t	*txb;

	txb = kmem_alloc(sizeof (smb_txbuf_t), KM_SLEEP);

	bzero(&txb->tb_lnd, sizeof (txb->tb_lnd));
	txb->tb_len = 0;
	txb->tb_magic = SMB_TXBUF_MAGIC;

	return (txb);
}

/*
 * smb_net_txb_free
 *
 *	Transmit buffer deallocator
 */
void
smb_net_txb_free(smb_txbuf_t *txb)
{
	ASSERT(txb->tb_magic == SMB_TXBUF_MAGIC);
	ASSERT(!list_link_active(&txb->tb_lnd));

	txb->tb_magic = 0;
	kmem_free(txb, sizeof (smb_txbuf_t));
}

/*
 * smb_net_txb_send
 *
 *	This routine puts the transmit buffer passed in on the wire. If another
 *	thread is already draining the transmit list, the transmit buffer is
 *	queued and the routine returns immediately.
 */
int
smb_net_txb_send(struct sonode *so, smb_txlst_t *txl, smb_txbuf_t *txb)
{
	list_t		local;
	int		rc = 0;
	iovec_t		iov;
	struct msghdr	msg;
	struct uio	uio;

	ASSERT(txl->tl_magic == SMB_TXLST_MAGIC);

	mutex_enter(&txl->tl_mutex);
	list_insert_tail(&txl->tl_list, txb);
	if (txl->tl_active) {
		mutex_exit(&txl->tl_mutex);
		return (0);
	}

	txl->tl_active = B_TRUE;
	list_create(&local, sizeof (smb_txbuf_t),
	    offsetof(smb_txbuf_t, tb_lnd));

	while (!list_is_empty(&txl->tl_list)) {
		list_move_tail(&local, &txl->tl_list);
		mutex_exit(&txl->tl_mutex);
		while ((txb = list_head(&local)) != NULL) {
			ASSERT(txb->tb_magic == SMB_TXBUF_MAGIC);
			list_remove(&local, txb);

			iov.iov_base = (void *)txb->tb_data;
			iov.iov_len = txb->tb_len;

			bzero(&msg, sizeof (msg));
			msg.msg_iov	= &iov;
			msg.msg_flags	= MSG_WAITALL;
			msg.msg_iovlen	= 1;

			bzero(&uio, sizeof (uio));
			uio.uio_iov	= &iov;
			uio.uio_iovcnt	= 1;
			uio.uio_segflg	= UIO_SYSSPACE;
			uio.uio_resid	= txb->tb_len;

			rc = sosendmsg(so, &msg, &uio);

			smb_net_txb_free(txb);

			if ((rc == 0) && (uio.uio_resid == 0))
					continue;

			if (rc == 0)
				rc = -1;

			while ((txb = list_head(&local)) != NULL) {
				ASSERT(txb->tb_magic == SMB_TXBUF_MAGIC);
				list_remove(&local, txb);
				smb_net_txb_free(txb);
			}
			break;
		}
		mutex_enter(&txl->tl_mutex);

		if (rc == 0)
			continue;

		while ((txb = list_head(&txl->tl_list)) != NULL) {
			ASSERT(txb->tb_magic == SMB_TXBUF_MAGIC);
			list_remove(&txl->tl_list, txb);
			smb_net_txb_free(txb);
		}
		break;
	}
	txl->tl_active = B_FALSE;
	mutex_exit(&txl->tl_mutex);

	return (rc);
}
