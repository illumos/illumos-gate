/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/promif.h>
#include <socket_impl.h>
#include <netinet/in.h>
#include <tcp_inet.h>
#include <errno.h>

/* ARGSUSED */
void
tcp_socket_init(struct inetboot_socket *arg)
{
	errno = EPROTOTYPE;
}

/* ARGSUSED */
int
tcp_connect(int arg)
{
	errno = EPROTOTYPE;
	return (-1);
}

/* ARGSUSED */
int
tcp_listen(int arg0, int arg1)
{
	errno = EOPNOTSUPP;
	return (-1);
}

/* ARGSUSED */
int
tcp_bind(int arg0)
{
	errno = EBADF;
	return (-1);
}

/* ARGSUSED */
int
tcp_send(int arg0, tcp_t *arg1, const void *arg2, int arg3)
{
	errno = EBADF;
	return (-1);
}

/* ARGSUSED */
int
tcp_opt_set(tcp_t *arg0, int arg1, int arg2, const void *arg3, socklen_t arg4)
{
	errno = ENOPROTOOPT;
	return (-1);
}

/* ARGSUSED */
int
tcp_accept(int arg0, struct sockaddr *arg1, socklen_t *arg2)
{
	errno = EBADF;
	return (-1);
}

/* ARGSUSED */
int
tcp_shutdown(int arg)
{
	errno = EBADF;
	return (-1);
}

/* ARGSUSED */
void
tcp_rcv_drain_sock(int sock_id)
{
	errno = EBADF;
}
