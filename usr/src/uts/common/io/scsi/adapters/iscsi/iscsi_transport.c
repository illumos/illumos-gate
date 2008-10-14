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

#include <iscsi_transport.h>
#include <sys/socket.h>
#include <sys/strsubr.h>
#include <sys/socketvar.h>
#ifdef _KERNEL
#include <sys/sunddi.h>
#else
#include <stdlib.h>
#endif
#include <iscsi.h>

static transport_services_t *hba_transport = NULL;

static
void
*iscsi_socket(int domain, int type, int protocol)
{
	/* This routine should return a pointer to struct sonode */
	return ((void *)iscsi_net_create(domain, type, protocol));
}

static
int
iscsi_bind(void *socket, struct sockaddr *name, int name_len,
	int backlog, int flags)
{
	return (sobind((struct sonode *)socket, name, name_len,
	    backlog, flags));
}

static
int
iscsi_connect(void *socket, struct sockaddr *name, int name_len,
	int fflag, int flags)
{
	return (soconnect((struct sonode *)socket, name, name_len, fflag,
	    flags));
}

static
int
iscsi_listen(void *socket, int backlog)
{
	return (solisten((struct sonode *)socket, backlog));
}

static
void *
iscsi_accept(void *socket, struct sockaddr *addr, int *addr_len)
{
	struct sonode *listening_socket;

	(void) soaccept((struct sonode *)socket,
	    ((struct sonode *)socket)->so_flag,
	    &listening_socket);
	if (listening_socket != NULL) {
		bcopy(listening_socket->so_faddr_sa, addr,
		    (socklen_t)listening_socket->so_faddr_len);
		*addr_len = listening_socket->so_faddr_len;
	} else {
		*addr_len = 0;
	}

	return ((void *)listening_socket);
}

/* ARGSUSED */
static
ssize_t
iscsi_sendmsg(void *socket, struct msghdr *msg, int flags)
{
	int i = 0;
	int total_length = 0;
	struct uio uio;

	/* Initialization of the uio structure. */
	bzero(&uio, sizeof (uio));
	uio.uio_iov = msg->msg_iov;
	uio.uio_iovcnt = msg->msg_iovlen;
	uio.uio_segflg  = UIO_SYSSPACE;

	for (i = 0; i < msg->msg_iovlen; i++) {
		total_length += (msg->msg_iov)[i].iov_len;
	}
	uio.uio_resid = total_length;

	(void) sosendmsg((struct sonode *)socket, msg, &uio);
	return (total_length - uio.uio_resid);
}

/* ARGSUSED */
static
ssize_t
iscsi_recvmsg(void *socket, struct msghdr *msg, int flags)
{
	int i = 0;
	int total_length = 0;
	struct uio uio;

	/* Initialization of the uio structure. */
	bzero(&uio, sizeof (uio));
	uio.uio_iov = msg->msg_iov;
	uio.uio_iovcnt = msg->msg_iovlen;
	uio.uio_segflg  = UIO_SYSSPACE;

	for (i = 0; i < msg->msg_iovlen; i++) {
		total_length += (msg->msg_iov)[i].iov_len;
	}
	uio.uio_resid = total_length;

	if (!sorecvmsg((struct sonode *)socket, msg, &uio)) {
		return (total_length - uio.uio_resid);
	}

	return (0);
}

static
int
iscsi_getsockname(void *socket)
{
	return (sogetsockname((struct sonode *)socket));
}

static
int
iscsi_getsockopt(void *socket, int level, int option_name,
	void *option_val, int *option_len, int flags)
{
	return (sogetsockopt((struct sonode *)socket, level,
	    option_name, option_val, (socklen_t *)option_len, flags));
}

static
int
iscsi_setsockopt(void *socket, int level, int option_name,
	void *option_val, int option_len)
{
	return (sosetsockopt((struct sonode *)socket, level,
	    option_name, option_val, option_len));
}

static
int
iscsi_shutdown(void *socket, int how)
{
	return (soshutdown((struct sonode *)socket, how));
}

static
void
iscsi_close(void *socket)
{
	vnode_t *vp = SOTOV((struct sonode *)socket);
	(void) soshutdown((struct sonode *)socket, 2);
	(void) VOP_CLOSE(vp, 0, 1, 0, kcred, NULL);
	VN_RELE(vp);
}

static
int
iscsi_poll(void *socket, clock_t timeout)
{
	int pflag;
	uchar_t pri;
	rval_t rval;

	pri = 0;
	pflag = MSG_ANY;
	return (kstrgetmsg(SOTOV((struct sonode *)socket), NULL, NULL,
	    &pri, &pflag, timeout, &rval));
}

transport_services_t
*get_hba_transport()
{
	if (hba_transport == NULL) {
		hba_transport = kmem_zalloc(sizeof (transport_services_t),
		    KM_SLEEP);
		hba_transport->tcp_conf.valid = B_FALSE;
		hba_transport->socket = iscsi_socket;
		hba_transport->bind = iscsi_bind;
		hba_transport->connect = iscsi_connect;
		hba_transport->listen = iscsi_listen;
		hba_transport->accept = iscsi_accept;
		hba_transport->sendmsg = iscsi_sendmsg;
		hba_transport->recvmsg = iscsi_recvmsg;
		hba_transport->getsockname = iscsi_getsockname;
		hba_transport->getsockopt = iscsi_getsockopt;
		hba_transport->setsockopt = iscsi_setsockopt;
		hba_transport->shutdown = iscsi_shutdown;
		hba_transport->close = iscsi_close;
		hba_transport->poll = iscsi_poll;
	}

	return (hba_transport);
}

void
free_hba_transport(transport_services_t *hba_transport)
{
	ASSERT(hba_transport != NULL);
	kmem_free(hba_transport, sizeof (transport_services_t));
	hba_transport = NULL;
}
