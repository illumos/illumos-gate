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

#include <sys/file.h>
#include <sys/stropts.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysmacros.h>
#include <sys/filio.h>		/* FIO* ioctls */
#include <sys/sockio.h>		/* SIOC* ioctls */
#include <sys/cmn_err.h>
#include <sys/ksocket.h>
#include <io/ksocket/ksocket_impl.h>
#include <fs/sockfs/sockcommon.h>

#define	SOCKETMOD_TCP	"tcp"
#define	SOCKETMOD_UDP	"udp"
/*
 * Kernel Sockets
 *
 * Mostly a wrapper around the private socket_* functions.
 */
int
ksocket_socket(ksocket_t *ksp, int domain, int type, int protocol, int flags,
    struct cred *cr)
{
	static const int version = SOV_DEFAULT;
	int error = 0;
	struct sonode *so;
	*ksp = NULL;

	if (domain == AF_NCA || domain == AF_UNIX)
		return (EAFNOSUPPORT);

	ASSERT(flags == KSOCKET_SLEEP || flags == KSOCKET_NOSLEEP);
	so = socket_create(domain, type, protocol, NULL, NULL, version, flags,
	    cr, &error);
	if (so == NULL) {
		if (error == EAFNOSUPPORT) {
			char *mod = NULL;

			/*
			 * Could be that root file sytem is not loaded or
			 * soconfig has not run yet.
			 */
			if (type == SOCK_STREAM && (domain == AF_INET ||
			    domain == AF_INET6) && (protocol == 0 ||
			    protocol == IPPROTO_TCP)) {
					mod = SOCKETMOD_TCP;
			} else if (type == SOCK_DGRAM && (domain == AF_INET ||
			    domain == AF_INET6) && (protocol == 0 ||
			    protocol == IPPROTO_UDP)) {
					mod = SOCKETMOD_UDP;
			} else {
				return (EAFNOSUPPORT);
			}

			so = socket_create(domain, type, protocol, NULL,
			    mod, version, flags, cr, &error);
			if (so == NULL)
				return (error);
		} else {
			return (error);
		}
	}

	so->so_mode |= SM_KERNEL;

	*ksp = SOTOKS(so);

	return (0);
}
int
ksocket_bind(ksocket_t ks, struct sockaddr *addr, socklen_t addrlen,
    struct cred *cr)
{
	int error;

	if (!KSOCKET_VALID(ks))
		return (ENOTSOCK);

	error = socket_bind(KSTOSO(ks), addr, addrlen, _SOBIND_SOCKBSD, cr);

	return (error);
}

int
ksocket_listen(ksocket_t ks, int backlog, struct cred *cr)
{
	if (!KSOCKET_VALID(ks))
		return (ENOTSOCK);

	return (socket_listen(KSTOSO(ks), backlog, cr));
}

int
ksocket_accept(ksocket_t ks, struct sockaddr *addr,
    socklen_t *addrlenp, ksocket_t *nks, struct cred *cr)
{
	int error;
	struct sonode *nso = NULL;

	*nks = NULL;

	if (!KSOCKET_VALID(ks))
		return (ENOTSOCK);

	if (addr != NULL && addrlenp == NULL)
		return (EFAULT);

	error = socket_accept(KSTOSO(ks), KSOCKET_FMODE(ks), cr, &nso);
	if (error != 0)
		return (error);

	ASSERT(nso != NULL);

	nso->so_mode |= SM_KERNEL;

	if (addr != NULL && addrlenp != NULL) {
		error = socket_getpeername(nso, addr, addrlenp, B_TRUE, cr);
		if (error != 0) {
			(void) socket_close(nso, 0, cr);
			socket_destroy(nso);
			return ((error == ENOTCONN) ? ECONNABORTED : error);
		}
	}

	*nks = SOTOKS(nso);

	return (error);
}

int
ksocket_connect(ksocket_t ks, const struct sockaddr *addr, socklen_t addrlen,
    struct cred *cr)
{
	if (!KSOCKET_VALID(ks))
		return (ENOTSOCK);

	return (socket_connect(KSTOSO(ks), addr, addrlen,
	    KSOCKET_FMODE(ks), 0, cr));
}

int
ksocket_send(ksocket_t ks, void *msg, size_t msglen, int flags,
    size_t *sent, struct cred *cr)
{
	int error;
	struct nmsghdr msghdr;
	struct uio auio;
	struct iovec iov;

	if (!KSOCKET_VALID(ks)) {
		if (sent != NULL)
			*sent = 0;
		return (ENOTSOCK);
	}

	iov.iov_base = msg;
	iov.iov_len = msglen;

	bzero(&auio, sizeof (struct uio));
	auio.uio_loffset = 0;
	auio.uio_iov = &iov;
	auio.uio_iovcnt = 1;
	auio.uio_resid = msglen;
	if (flags & MSG_USERSPACE)
		auio.uio_segflg = UIO_USERSPACE;
	else
		auio.uio_segflg = UIO_SYSSPACE;
	auio.uio_extflg = UIO_COPY_DEFAULT;
	auio.uio_limit = 0;
	auio.uio_fmode = KSOCKET_FMODE(ks);

	msghdr.msg_name = NULL;
	msghdr.msg_namelen = 0;
	msghdr.msg_control = NULL;
	msghdr.msg_controllen = 0;
	msghdr.msg_flags = flags | MSG_EOR;

	error = socket_sendmsg(KSTOSO(ks), &msghdr, &auio, cr);
	if (error != 0) {
		if (sent != NULL)
			*sent = 0;
		return (error);
	}

	if (sent != NULL)
		*sent = msglen - auio.uio_resid;
	return (0);
}

int
ksocket_sendto(ksocket_t ks, void *msg, size_t msglen, int flags,
    struct sockaddr *name, socklen_t namelen, size_t *sent, struct cred *cr)
{
	int error;
	struct nmsghdr msghdr;
	struct uio auio;
	struct iovec iov;

	if (!KSOCKET_VALID(ks)) {
		if (sent != NULL)
			*sent = 0;
		return (ENOTSOCK);
	}

	iov.iov_base = msg;
	iov.iov_len = msglen;

	bzero(&auio, sizeof (struct uio));
	auio.uio_loffset = 0;
	auio.uio_iov = &iov;
	auio.uio_iovcnt = 1;
	auio.uio_resid = msglen;
	if (flags & MSG_USERSPACE)
		auio.uio_segflg = UIO_USERSPACE;
	else
		auio.uio_segflg = UIO_SYSSPACE;
	auio.uio_extflg = UIO_COPY_DEFAULT;
	auio.uio_limit = 0;
	auio.uio_fmode = KSOCKET_FMODE(ks);

	msghdr.msg_iov = &iov;
	msghdr.msg_iovlen = 1;
	msghdr.msg_name = (char *)name;
	msghdr.msg_namelen = namelen;
	msghdr.msg_control = NULL;
	msghdr.msg_controllen = 0;
	msghdr.msg_flags = flags | MSG_EOR;

	error = socket_sendmsg(KSTOSO(ks), &msghdr, &auio, cr);
	if (error != 0) {
		if (sent != NULL)
			*sent = 0;
		return (error);
	}
	if (sent != NULL)
		*sent = msglen - auio.uio_resid;
	return (0);
}

int
ksocket_sendmsg(ksocket_t ks, struct nmsghdr *msg, int flags,
    size_t *sent, struct cred *cr)
{
	int error;
	ssize_t len;
	int i;
	struct uio auio;

	if (!KSOCKET_VALID(ks)) {
		if (sent != NULL)
			*sent = 0;
		return (ENOTSOCK);
	}

	bzero(&auio, sizeof (struct uio));
	auio.uio_loffset = 0;
	auio.uio_iov = msg->msg_iov;
	auio.uio_iovcnt = msg->msg_iovlen;
	if (flags & MSG_USERSPACE)
		auio.uio_segflg = UIO_USERSPACE;
	else
		auio.uio_segflg = UIO_SYSSPACE;
	auio.uio_extflg = UIO_COPY_DEFAULT;
	auio.uio_limit = 0;
	auio.uio_fmode = KSOCKET_FMODE(ks);
	len = 0;
	for (i = 0; i < msg->msg_iovlen; i++) {
		ssize_t iovlen;
		iovlen = (msg->msg_iov)[i].iov_len;
		len += iovlen;
		if (len < 0 || iovlen < 0)
			return (EINVAL);
	}
	auio.uio_resid = len;

	msg->msg_flags = flags | MSG_EOR;

	error = socket_sendmsg(KSTOSO(ks), msg, &auio, cr);
	if (error != 0) {
		if (sent != NULL)
			*sent = 0;
		return (error);
	}

	if (sent != NULL)
		*sent = len - auio.uio_resid;
	return (0);
}


int
ksocket_recv(ksocket_t ks, void *msg, size_t msglen, int flags,
    size_t *recv, struct cred *cr)
{
	int error;
	struct nmsghdr msghdr;
	struct uio auio;
	struct iovec iov;

	if (!KSOCKET_VALID(ks)) {
		if (recv != NULL)
			*recv = 0;
		return (ENOTSOCK);
	}

	iov.iov_base = msg;
	iov.iov_len = msglen;

	bzero(&auio, sizeof (struct uio));
	auio.uio_loffset = 0;
	auio.uio_iov = &iov;
	auio.uio_iovcnt = 1;
	auio.uio_resid = msglen;
	if (flags & MSG_USERSPACE)
		auio.uio_segflg = UIO_USERSPACE;
	else
		auio.uio_segflg = UIO_SYSSPACE;
	auio.uio_extflg = UIO_COPY_DEFAULT;
	auio.uio_limit = 0;
	auio.uio_fmode = KSOCKET_FMODE(ks);

	msghdr.msg_name = NULL;
	msghdr.msg_namelen = 0;
	msghdr.msg_control = NULL;
	msghdr.msg_controllen = 0;
	msghdr.msg_flags = flags & (MSG_OOB | MSG_PEEK | MSG_WAITALL |
	    MSG_DONTWAIT | MSG_USERSPACE);

	error = socket_recvmsg(KSTOSO(ks), &msghdr, &auio, cr);
	if (error != 0) {
		if (recv != NULL)
			*recv = 0;
		return (error);
	}

	if (recv != NULL)
		*recv = msglen - auio.uio_resid;
	return (0);
}

int
ksocket_recvfrom(ksocket_t ks, void *msg, size_t msglen, int flags,
    struct sockaddr *name, socklen_t *namelen, size_t *recv, struct cred *cr)
{
	int error;
	struct nmsghdr msghdr;
	struct uio auio;
	struct iovec iov;

	if (!KSOCKET_VALID(ks)) {
		if (recv != NULL)
			*recv = 0;
		return (ENOTSOCK);
	}

	iov.iov_base = msg;
	iov.iov_len = msglen;

	bzero(&auio, sizeof (struct uio));
	auio.uio_loffset = 0;
	auio.uio_iov = &iov;
	auio.uio_iovcnt = 1;
	auio.uio_resid = msglen;
	if (flags & MSG_USERSPACE)
		auio.uio_segflg = UIO_USERSPACE;
	else
		auio.uio_segflg = UIO_SYSSPACE;
	auio.uio_extflg = UIO_COPY_DEFAULT;
	auio.uio_limit = 0;
	auio.uio_fmode = KSOCKET_FMODE(ks);

	msghdr.msg_name = (char *)name;
	msghdr.msg_namelen = *namelen;
	msghdr.msg_control = NULL;
	msghdr.msg_controllen = 0;
	msghdr.msg_flags = flags & (MSG_OOB | MSG_PEEK | MSG_WAITALL |
	    MSG_DONTWAIT | MSG_USERSPACE);

	error = socket_recvmsg(KSTOSO(ks), &msghdr, &auio, cr);
	if (error != 0) {
		if (recv != NULL)
			*recv = 0;
		return (error);
	}
	if (recv != NULL)
		*recv = msglen - auio.uio_resid;

	bcopy(msghdr.msg_name, name, msghdr.msg_namelen);
	bcopy(&msghdr.msg_namelen, namelen, sizeof (msghdr.msg_namelen));
	return (0);
}

int
ksocket_recvmsg(ksocket_t ks, struct nmsghdr *msg, int flags, size_t *recv,
    struct cred *cr)
{
	int error;
	ssize_t len;
	int i;
	struct uio auio;

	if (!KSOCKET_VALID(ks)) {
		if (recv != NULL)
			*recv = 0;
		return (ENOTSOCK);
	}

	bzero(&auio, sizeof (struct uio));
	auio.uio_loffset = 0;
	auio.uio_iov = msg->msg_iov;
	auio.uio_iovcnt = msg->msg_iovlen;
	if (msg->msg_flags & MSG_USERSPACE)
		auio.uio_segflg = UIO_USERSPACE;
	else
		auio.uio_segflg = UIO_SYSSPACE;
	auio.uio_extflg = UIO_COPY_DEFAULT;
	auio.uio_limit = 0;
	auio.uio_fmode = KSOCKET_FMODE(ks);
	len = 0;

	for (i = 0; i < msg->msg_iovlen; i++) {
		ssize_t iovlen;
		iovlen = (msg->msg_iov)[i].iov_len;
		len += iovlen;
		if (len < 0 || iovlen < 0)
			return (EINVAL);
	}
	auio.uio_resid = len;

	msg->msg_flags = flags & (MSG_OOB | MSG_PEEK | MSG_WAITALL |
	    MSG_DONTWAIT | MSG_USERSPACE);

	error = socket_recvmsg(KSTOSO(ks), msg, &auio, cr);
	if (error != 0) {
		if (recv != NULL)
			*recv = 0;
		return (error);
	}
	if (recv != NULL)
		*recv = len - auio.uio_resid;
	return (0);

}

int
ksocket_shutdown(ksocket_t ks, int how, struct cred *cr)
{
	struct sonode *so;

	if (!KSOCKET_VALID(ks))
		return (ENOTSOCK);

	so = KSTOSO(ks);

	return (socket_shutdown(so, how, cr));
}

int
ksocket_close(ksocket_t ks, struct cred *cr)
{
	struct sonode *so;
	so = KSTOSO(ks);

	mutex_enter(&so->so_lock);

	if (!KSOCKET_VALID(ks)) {
		mutex_exit(&so->so_lock);
		return (ENOTSOCK);
	}

	so->so_state |= SS_CLOSING;

	if (so->so_count > 1) {
		mutex_enter(&so->so_acceptq_lock);
		cv_broadcast(&so->so_acceptq_cv);
		mutex_exit(&so->so_acceptq_lock);
		cv_broadcast(&so->so_rcv_cv);
		cv_broadcast(&so->so_state_cv);
		cv_broadcast(&so->so_want_cv);
		cv_broadcast(&so->so_snd_cv);
		cv_broadcast(&so->so_copy_cv);
	}
	while (so->so_count > 1)
		cv_wait(&so->so_closing_cv, &so->so_lock);

	mutex_exit(&so->so_lock);
	/* Remove callbacks, if any */
	(void) ksocket_setcallbacks(ks, NULL, NULL, cr);

	(void) socket_close(so, 0, cr);
	socket_destroy(so);

	return (0);
}

int
ksocket_getsockname(ksocket_t ks, struct sockaddr *addr, socklen_t *addrlen,
    struct cred *cr)
{
	struct sonode *so;

	if (!KSOCKET_VALID(ks))
		return (ENOTSOCK);

	so = KSTOSO(ks);

	if (addrlen == NULL || (addr == NULL && *addrlen != 0))
		return (EFAULT);

	return (socket_getsockname(so, addr, addrlen, cr));
}

int
ksocket_getpeername(ksocket_t ks, struct sockaddr *addr, socklen_t *addrlen,
    struct cred *cr)
{
	struct sonode *so;

	if (!KSOCKET_VALID(ks))
		return (ENOTSOCK);

	so = KSTOSO(ks);

	if (addrlen == NULL || (addr == NULL && *addrlen != 0))
		return (EFAULT);

	return (socket_getpeername(so, addr, addrlen, B_FALSE, cr));
}

int
ksocket_getsockopt(ksocket_t ks, int level, int optname, void *optval,
    int *optlen, struct cred *cr)
{
	struct sonode *so;

	if (!KSOCKET_VALID(ks))
		return (ENOTSOCK);

	so = KSTOSO(ks);

	if (optlen == NULL)
		return (EFAULT);
	if (*optlen > SO_MAXARGSIZE)
		return (EINVAL);

	return (socket_getsockopt(so, level, optname, optval,
	    (socklen_t *)optlen, 0, cr));
}

int
ksocket_setsockopt(ksocket_t ks, int level, int optname, const void *optval,
    int optlen, struct cred *cr)
{
	struct sonode *so;

	if (!KSOCKET_VALID(ks))
		return (ENOTSOCK);

	so = KSTOSO(ks);

	if (optval == NULL)
		optlen = 0;

	return (socket_setsockopt(so, level, optname, optval,
	    (t_uscalar_t)optlen, cr));
}

/* ARGSUSED */
int
ksocket_setcallbacks(ksocket_t ks, ksocket_callbacks_t *cb, void *arg,
    struct cred *cr)
{
	struct sonode *so;

	if (!KSOCKET_VALID(ks))
		return (ENOTSOCK);

	so = KSTOSO(ks);

	if (cb == NULL && arg != NULL)
		return (EFAULT);
	if (cb == NULL) {
		mutex_enter(&so->so_lock);
		bzero(&(so->so_ksock_callbacks), sizeof (ksocket_callbacks_t));
		so->so_ksock_cb_arg = NULL;
		mutex_exit(&so->so_lock);
	} else {
		mutex_enter(&so->so_lock);
		SETCALLBACK(so, cb, connected, KSOCKET_CB_CONNECTED)
		SETCALLBACK(so, cb, connectfailed, KSOCKET_CB_CONNECTFAILED)
		SETCALLBACK(so, cb, disconnected, KSOCKET_CB_DISCONNECTED)
		SETCALLBACK(so, cb, newdata, KSOCKET_CB_NEWDATA)
		SETCALLBACK(so, cb, newconn, KSOCKET_CB_NEWCONN)
		SETCALLBACK(so, cb, cansend, KSOCKET_CB_CANSEND)
		SETCALLBACK(so, cb, oobdata, KSOCKET_CB_OOBDATA)
		SETCALLBACK(so, cb, cantsendmore, KSOCKET_CB_CANTSENDMORE)
		SETCALLBACK(so, cb, cantrecvmore, KSOCKET_CB_CANTRECVMORE)
		so->so_ksock_cb_arg = arg;
		mutex_exit(&so->so_lock);
	}
	return (0);
}

int
ksocket_ioctl(ksocket_t ks, int cmd, intptr_t arg, int *rvalp, struct cred *cr)
{
	struct sonode *so;
	int rval;

	if (!KSOCKET_VALID(ks))
		return (ENOTSOCK);

	so = KSTOSO(ks);

	switch (cmd) {
	default:
		/* STREAM iotcls are not supported */
		if ((cmd & 0xffffff00U) == STR) {
			rval = EOPNOTSUPP;
		} else {
			rval = socket_ioctl(so, cmd, arg,
			    KSOCKET_FMODE(ks) | FKIOCTL, cr, rvalp);
		}
		break;
	case FIOASYNC:
	case SIOCSPGRP:
	case FIOSETOWN:
	case SIOCGPGRP:
	case FIOGETOWN:
		rval = EOPNOTSUPP;
		break;
	}

	return (rval);
}

int
ksocket_sendmblk(ksocket_t ks, struct nmsghdr *msg, int flags,
    mblk_t **mpp, cred_t *cr)
{
	struct		sonode *so;
	int		i_val;
	socklen_t	val_len;
	mblk_t		*mp = *mpp;
	int		error;

	if (!KSOCKET_VALID(ks))
		return (ENOTSOCK);

	so = KSTOSO(ks);

	if (flags & MSG_MBLK_QUICKRELE) {
		error = socket_getsockopt(so, SOL_SOCKET, SO_SND_COPYAVOID,
		    &i_val, &val_len, 0, CRED());
		if (error != 0)
			return (error);

		/* Zero copy is not enable */
		if (i_val == 0)
			return (ECANCELED);

		for (; mp != NULL; mp = mp->b_cont)
			mp->b_datap->db_struioflag |= STRUIO_ZC;
	}

	error = socket_sendmblk(so, msg, flags, cr, mpp);

	return (error);
}


void
ksocket_hold(ksocket_t ks)
{
	struct sonode *so;
	so = KSTOSO(ks);

	if (!mutex_owned(&so->so_lock)) {
		mutex_enter(&so->so_lock);
		so->so_count++;
		mutex_exit(&so->so_lock);
	} else
		so->so_count++;
}

void
ksocket_rele(ksocket_t ks)
{
	struct sonode *so;

	so = KSTOSO(ks);
	/*
	 * When so_count equals 1 means no thread working on this ksocket
	 */
	if (so->so_count < 2)
		cmn_err(CE_PANIC, "ksocket_rele: sonode ref count 0 or 1");

	if (!mutex_owned(&so->so_lock)) {
		mutex_enter(&so->so_lock);
		if (--so->so_count == 1)
			cv_signal(&so->so_closing_cv);
		mutex_exit(&so->so_lock);
	} else {
		if (--so->so_count == 1)
			cv_signal(&so->so_closing_cv);
	}
}
