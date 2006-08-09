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
#ident	"%Z%%M%	%I%	%E% SMI"
#

function	__xnet_recvmsg
include		"xpgmsg_spec.h", <sys/types.h>, <sys/socket.h>
declaration	ssize_t __xnet_recvmsg(int socket, struct XPG_msghdr *msg, \
			int flags)
version		SUNW_1.1
errno		EBADF ENOTSOCK EINVAL EWOULDBLOCK EAGAIN EINTR EOPNOTSUPP \
			ENOTCONN ETIMEDOUT ECONNRESET EIO ENOBUFS ENOMEM ENOSR
exception	$return == -1
end

function	__xnet_sendmsg
include		"xpgmsg_spec.h", <sys/types.h>, <sys/socket.h>
declaration	ssize_t __xnet_sendmsg(int socket, const struct XPG_msghdr *msg, \
			int flags )
version		SUNW_1.1
errno		EAFNOSUPPORT EBADF ECONNRESET EINTR EINVAL EMSGSIZE ENOTCONN \
			ENOTSOCK EOPNOTSUPP EPIPE EWOULDBLOCK EAGAIN EACCES EIO \
			ELOOP ENAMETOOLONG ENOENT ENOTDIR EDESTADDRREQ EHOSTUNREACH \
			EISCONN ENETDOWN ENETUNREACH ENOBUFS ENOSR
exception	$return == -1
end
