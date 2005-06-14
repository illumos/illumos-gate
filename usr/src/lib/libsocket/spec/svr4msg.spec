#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

function	recvmsg
include		"svr4msg_spec.h", <sys/types.h>, <sys/socket.h>
declaration	ssize_t recvmsg(int s, struct SVR4_msghdr *msg, int flags)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
errno		EBADF EINTR EIO ENOMEM ENOSR ENOTSOCK ESTALE EWOULDBLOCK
exception	$return == -1
end

function	sendmsg
include		"svr4msg_spec.h", <sys/types.h>, <sys/socket.h>
declaration	ssize_t sendmsg(int s, const struct SVR4_msghdr *msg, int flags )
version		i386=SUNW_0.7	sparc=SISCD_2.3	sparcv9=SUNW_0.7 amd64=SUNW_0.7
errno		EBADF EINTR EINVAL EMSGSIZE ENOMEM ENOSR ENOTSOCK EWOULDBLOCK
exception	$return == -1
end

#
# weak interfaces
#
function	_recvmsg
weak		recvmsg
version		SUNWprivate_1.1
end

function	_sendmsg
weak		sendmsg
version		SUNWprivate_1.1
end

function	_socket
weak		socket
version		SUNWprivate_1.1
end		

function	_socketpair
weak		socketpair
version		SUNWprivate_1.1
end		

function	_bind
weak		bind
version		SUNWprivate_1.1
end		

function	_listen
weak		listen
version		SUNWprivate_1.1
end		

function	_accept
weak		accept
version		SUNWprivate_1.1
end		

function	_connect
weak		connect
version		SUNWprivate_1.1
end		

function	_shutdown
weak		shutdown
version		SUNWprivate_1.1
end		

function	_recv
weak		recv
version		SUNWprivate_1.1
end		

function	_recvfrom
weak		recvfrom
version		SUNWprivate_1.1
end		

function	_send
weak		send
version		SUNWprivate_1.1
end		

function	_sendto
weak		sendto
version		SUNWprivate_1.1
end		

function	_getpeername
weak		getpeername
version		SUNWprivate_1.1
end		

function	_getsockname
weak		getsockname
version		SUNWprivate_1.1
end		

function	_getsockopt
weak		getsockopt
version		SUNWprivate_1.1
end		

function	_setsockopt
weak		setsockopt
version		SUNWprivate_1.1
end		

