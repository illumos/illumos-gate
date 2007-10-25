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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
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
smb_sosend(struct sonode *so, void *msg, size_t len)
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

	if ((err = smb_iov_sosend(so, &iov, 1, len)) != 0) {
		return (err);
	}

	/* Successful receive */
	return (0);
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
 * smb_iov_sosend - Sends an iovec on a connection.
 *
 * This function puts the data provided on the wire by calling sosendmsg.
 * It will return only when all the data has been sent or if an error
 * occurs.
 *
 * Returns 0 for success, the socket errno value if sosendmsg fails, and
 * -1 if sosendmsg returns success but uio_resid != 0
 */
int
smb_iov_sosend(struct sonode *so, iovec_t *iop, int iovlen, size_t total_len)
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

	if ((error = sosendmsg(so, &msg, &uio)) == 0) {
		/* Data sent */
		if (uio.uio_resid == 0) {
			/* All data sent.  Success. */
			return (0);
		} else {
			/* Not all data was sent.  Failure */
			return (-1);
		}
	}

	/* Send failed */
	return (error);
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
