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

/* Copyright (c) 2013, OmniTI Computer Consulting, Inc. All rights reserved. */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/socketvar.h>
#include <sys/sockio.h>

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <stropts.h>
#include <stdio.h>
#include <strings.h>
#include <netinet/sctp.h>

#pragma weak bind = _bind
#pragma weak listen = _listen
#pragma weak accept = _accept
#pragma weak accept4 = _accept4
#pragma weak connect = _connect
#pragma weak shutdown = _shutdown
#pragma weak recv = _recv
#pragma weak recvfrom = _recvfrom
#pragma weak recvmsg = _recvmsg
#pragma weak send = _send
#pragma weak sendmsg = _sendmsg
#pragma weak sendto = _sendto
#pragma weak getpeername = _getpeername
#pragma weak getsockname = _getsockname
#pragma weak getsockopt = _getsockopt
#pragma weak setsockopt = _setsockopt

extern int _so_bind();
extern int _so_listen();
extern int _so_accept();
extern int _so_connect();
extern int _so_shutdown();
extern int _so_recv();
extern int _so_recvfrom();
extern int _so_recvmsg();
extern int _so_send();
extern int _so_sendmsg();
extern int _so_sendto();
extern int _so_getpeername();
extern int _so_getsockopt();
extern int _so_setsockopt();
extern int _so_getsockname();

/*
 * Note that regular sockets use SOV_SOCKBSD here to not allow a rebind of an
 * already bound socket.
 */
int
_bind(int sock, struct sockaddr *addr, int addrlen)
{
	return (_so_bind(sock, addr, addrlen, SOV_SOCKBSD));
}

int
_listen(int sock, int backlog)
{
	return (_so_listen(sock, backlog, SOV_DEFAULT));
}

int
_accept(int sock, struct sockaddr *addr, int *addrlen)
{
	return (_so_accept(sock, addr, addrlen, SOV_DEFAULT, 0));
}

int
_accept4(int sock, struct sockaddr *addr, int *addrlen, int flags)
{
	return (_so_accept(sock, addr, addrlen, SOV_DEFAULT, flags));
}

int
_connect(int sock, struct sockaddr *addr, int addrlen)
{
	return (_so_connect(sock, addr, addrlen, SOV_DEFAULT));
}

int
_shutdown(int sock, int how)
{
	return (_so_shutdown(sock, how, SOV_DEFAULT));
}

int
_recv(int sock, char *buf, int len, int flags)
{
	return (_so_recv(sock, buf, len, flags & ~MSG_XPG4_2));
}

int
_recvfrom(int sock, char *buf, int len, int flags,
	struct sockaddr *addr, int *addrlen)
{
	return (_so_recvfrom(sock, buf, len, flags & ~MSG_XPG4_2,
	    addr, addrlen));
}

int
_recvmsg(int sock, struct msghdr *msg, int flags)
{
	return (_so_recvmsg(sock, msg, flags & ~MSG_XPG4_2));
}

int
_send(int sock, char *buf, int len, int flags)
{
	return (_so_send(sock, buf, len, flags & ~MSG_XPG4_2));
}

int
_sendmsg(int sock, struct msghdr *msg, int flags)
{
	return (_so_sendmsg(sock, msg, flags & ~MSG_XPG4_2));
}

int
_sendto(int sock, char *buf, int len, int flags,
	struct sockaddr *addr, int *addrlen)
{
	return (_so_sendto(sock, buf, len, flags & ~MSG_XPG4_2,
	    addr, addrlen));
}

int
_getpeername(int sock, struct sockaddr *name, int *namelen)
{
	return (_so_getpeername(sock, name, namelen, SOV_DEFAULT));
}

int
_getsockname(int sock, struct sockaddr *name, int *namelen)
{
	return (_so_getsockname(sock, name, namelen, SOV_DEFAULT));
}

int
_getsockopt(int sock, int level, int optname, char *optval, int *optlen)
{
	if (level == IPPROTO_SCTP) {
		sctp_assoc_t id = 0;
		socklen_t len = *optlen;
		int err = 0;
		struct sctpopt sopt;

		switch (optname) {
		case SCTP_RTOINFO:
		case SCTP_ASSOCINFO:
		case SCTP_SET_PEER_PRIMARY_ADDR:
		case SCTP_PRIMARY_ADDR:
		case SCTP_PEER_ADDR_PARAMS:
		case SCTP_STATUS:
		case SCTP_GET_PEER_ADDR_INFO:
			/*
			 * Association ID is the first element params struct
			 */
			bcopy(optval, &id, sizeof (id));
			break;
		case SCTP_DEFAULT_SEND_PARAM:
			bcopy(&((struct sctp_sndrcvinfo *)
			    optval)->sinfo_assoc_id, &id, sizeof (id));
			break;
		}

		sopt.sopt_aid = id;
		sopt.sopt_name = optname;
		sopt.sopt_val = optval;
		sopt.sopt_len = len;
		if (ioctl(sock, SIOCSCTPGOPT, &sopt) == -1) {
			err = -1;
		} else {
			*optlen = sopt.sopt_len;
		}
		return (err);
	} else {
		return (_so_getsockopt(sock, level, optname, optval, optlen,
		    SOV_DEFAULT));
	}
}

int
_setsockopt(int sock, int level, int optname, char *optval, int optlen)
{
	return (_so_setsockopt(sock, level, optname, optval, optlen,
	    SOV_DEFAULT));
}

int
__xnet_bind(int sock, const struct sockaddr *addr, socklen_t addrlen)
{
	return (_so_bind(sock, addr, addrlen, SOV_XPG4_2));
}


int
__xnet_listen(int sock, int backlog)
{
	return (_so_listen(sock, backlog, SOV_XPG4_2));
}

int
__xnet_connect(int sock, const struct sockaddr *addr, socklen_t addrlen)
{
	return (_so_connect(sock, addr, addrlen, SOV_XPG4_2));
}

int
__xnet_recvmsg(int sock, struct msghdr *msg, int flags)
{
	return (_so_recvmsg(sock, msg, flags | MSG_XPG4_2));
}

int
__xnet_sendmsg(int sock, const struct msghdr *msg, int flags)
{
	return (_so_sendmsg(sock, msg, flags | MSG_XPG4_2));
}

int
__xnet_sendto(int sock, const void *buf, size_t len, int flags,
	const struct sockaddr *addr, socklen_t addrlen)
{
	return (_so_sendto(sock, buf, len, flags | MSG_XPG4_2,
	    addr, addrlen));
}

int
__xnet_getsockopt(int sock, int level, int option_name,
	void *option_value, socklen_t *option_lenp)
{
	if (level == IPPROTO_SCTP) {
		return (_getsockopt(sock, level, option_name, option_value,
		    (int *)option_lenp));
	} else {
		return (_so_getsockopt(sock, level, option_name, option_value,
		    option_lenp, SOV_XPG4_2));
	}
}
