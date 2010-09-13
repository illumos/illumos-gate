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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/stropts.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/socket_proto.h>


/*ARGSUSED*/
int
sock_accept_notsupp(sock_lower_handle_t low1, sock_lower_handle_t low2,
    sock_upper_handle_t upper, struct cred *cr)
{
	return (EOPNOTSUPP);
}

/*ARGSUSED*/
int
sock_bind_notsupp(sock_lower_handle_t handle, struct sockaddr *name,
    socklen_t namelen, struct cred *cr)
{
	return (EOPNOTSUPP);
}

/*ARGSUSED*/
int
sock_listen_notsupp(sock_lower_handle_t handle, int backlog,
    struct cred *cr)
{
	return (EOPNOTSUPP);
}

/*ARGSUSED*/
int
sock_connect_notsupp(sock_lower_handle_t handle,
    const struct sockaddr *name, socklen_t namelen, sock_connid_t *conp,
    struct cred *cr)
{
	return (EOPNOTSUPP);
}

/*ARGSUSED*/
int
sock_getsockname_notsupp(sock_lower_handle_t handle, struct sockaddr *sa,
    socklen_t *len, struct cred *cr)
{
	return (EOPNOTSUPP);
}

/*ARGSUSED*/
int
sock_getpeername_notsupp(sock_lower_handle_t handle, struct sockaddr *addr,
    socklen_t *addrlen, struct cred *cr)
{
	return (EOPNOTSUPP);
}

/*ARGSUSED*/
int
sock_getsockopt_notsupp(sock_lower_handle_t handle, int level,
    int option_name, void *optval, socklen_t *optlenp, struct cred *cr)
{
	return (EOPNOTSUPP);
}

/*ARGSUSED*/
int
sock_setsockopt_notsupp(sock_lower_handle_t handle, int level,
    int option_name, const void *optval, socklen_t optlen, struct cred *cr)
{
	return (EOPNOTSUPP);
}

/*ARGSUSED*/
int
sock_send_notsupp(sock_lower_handle_t handle, mblk_t *mp,
    struct msghdr *msg, struct cred *cr)
{
	return (EOPNOTSUPP);
}

/*ARGSUSED*/
int
sock_senduio_notsupp(sock_lower_handle_t handle, struct uio *uiop,
    struct nmsghdr *msg, struct cred *cr)
{
	return (EOPNOTSUPP);
}

/*ARGSUSED*/
int
sock_recvuio_notsupp(sock_lower_handle_t handle, struct uio *uiop,
    struct nmsghdr *msg, struct cred *cr)
{
	return (EOPNOTSUPP);
}

/*ARGSUSED*/
short
sock_poll_notsupp(sock_lower_handle_t handle, short events, int anyyet,
    cred_t *cred)
{
	return (EOPNOTSUPP);
}

/*ARGSUSED*/
int
sock_shutdown_notsupp(sock_lower_handle_t handle, int how, struct cred *cr)
{
	return (EOPNOTSUPP);
}

/*ARGSUSED*/
void
sock_clr_flowctrl_notsupp(sock_lower_handle_t proto_handle)
{
}

/*ARGSUSED*/
int
sock_ioctl_notsupp(sock_lower_handle_t handle, int cmd, intptr_t arg,
    int mode, int32_t *rvalp, cred_t *cred)
{
	return (EOPNOTSUPP);
}

/* ARGSUSED */
int
sock_close_notsupp(sock_lower_handle_t proto_handle, int flags, cred_t *cr)
{
	return (EOPNOTSUPP);
}

sock_downcalls_t sock_down_notsupp = {
	NULL,
	sock_accept_notsupp,
	sock_bind_notsupp,
	sock_listen_notsupp,
	sock_connect_notsupp,
	sock_getpeername_notsupp,
	sock_getsockname_notsupp,
	sock_getsockopt_notsupp,
	sock_setsockopt_notsupp,
	sock_send_notsupp,
	sock_senduio_notsupp,
	sock_recvuio_notsupp,
	sock_poll_notsupp,
	sock_shutdown_notsupp,
	sock_clr_flowctrl_notsupp,
	sock_ioctl_notsupp,
	sock_close_notsupp,
};
