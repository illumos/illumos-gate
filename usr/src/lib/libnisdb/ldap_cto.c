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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <dlfcn.h>
#include <rpcsvc/nis.h>

#include "ldap_util.h"

#include "nis_parse_ldap_conf.h"

/*
 * Interpose socket(3SOCKET), so that we can set the connect timeout.
 * Obviously, this will affect every socket in the application. However,
 * NIS+ (or, rather, RPC) uses TLI, not sockets, so the only sockets
 * should be those used by libldap.
 */
int
socket(int domain, int type, int protocol) {
	int		ret;
	static int	(*fptr)() = 0;
	int		timeout = 1000 * proxyInfo.bind_timeout.tv_sec +
					proxyInfo.bind_timeout.tv_usec / 1000;

	if (fptr == 0) {
		fptr = (int (*)())dlsym(RTLD_NEXT, "socket");
		if (fptr == 0) {
			logmsg(MSG_NOTIMECHECK, LOG_ERR,
				"socket: load error: %s",
				dlerror());
			return (-1);
		}
	}

	ret = (*fptr) (domain, type, protocol);

	if (ret >= 0 && timeout > 0) {
		if (setsockopt(ret, IPPROTO_TCP, TCP_CONN_ABORT_THRESHOLD,
				&timeout, sizeof (timeout)) != 0)
			logmsg(MSG_NOTIMECHECK, LOG_ERR,
	"setsockopt(IPPROTO_TCP/TCP_CONN_ABORT_THRESHOLD, %d) => errno = %d",
				timeout, errno);
	}

	return (ret);
}
