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

function	sctp_bindx
include		<sys/types.h>, <sys/socket.h>, <netinet/sctp.h>
declaration	int sctp_bindx(int s, void *addrs, int addrcnt, int flags)
version		SUNW_1.1
errno		EBADF EINVAL ENOMEM EOPNOTSUPP EAFNOSUPPORT ENOTSOCK EFAULT \
		EPERM EADDRNOTAVAIL
exception	$return == -1
end

function	sctp_getladdrs
include		<sys/types.h>, <sys/socket.h>, <netinet/sctp.h>
declaration	int sctp_getladdrs(int s, sctp_assoc_t id, void **addrs)
version		SUNW_1.1
errno		EBADF EINVAL ENOMEM ENOTSOCK EFAULT EPERM
exception	$return == -1
end

function	sctp_getpaddrs
include		<sys/types.h>, <sys/socket.h>, <netinet/sctp.h>
declaration	int sctp_getpaddrs(int s, sctp_assoc_t id, void **addrs)
version		SUNW_1.1
errno		EBADF EINVAL ENOTCONN ENOMEM EOPNOTSUPP EFAULT
exception	$return == -1
end

function	sctp_freeladdrs
include		<sys/types.h>
declaration	void sctp_freeladdrs(void *addrs)
version		SUNW_1.1
end

function	sctp_freepaddrs
include		<sys/types.h>
declaration	void sctp_freepaddrs(void *addrs)
version		SUNW_1.1
end

function	sctp_opt_info
include		<sys/types.h>, <sys/socket.h>, <netinet/sctp.h>
declaration	int sctp_opt_info(int s, sctp_assoc_t id, int opt, void *arg, \
			 socklen_t *size)
version		SUNW_1.1
errno		EBADF EINVAL ENOMEM EOPNOTSUPP
exception	$return == -1
end

function	sctp_peeloff
include		<sys/types.h>, <sys/socket.h>, <netinet/sctp.h>
declaration	int sctp_peeloff(int s, sctp_assoc_t id)
version		SUNW_1.1
errno		EBADF EFAULT EINVAL EMFILE ENOMEM EOPNOTSUPP
exception	$return == -1
end

function	sctp_recvmsg
include		<sys/types.h>, <sys/socket.h>, <netinet/sctp.h>
declaration	ssize_t sctp_recvmsg(int s, void *msg, size_t len, \
			struct sockaddr *from, socklen_t *fromlen, \
                        struct sctp_sndrcvinfo *sinfo, int *msg_flags)
version		SUNW_1.1
errno		EBADF EINTR EIO ENOMEM ENOSR ENOTSOCK ESTALE EWOULDBLOCK
exception	$return == -1
end

function	sctp_send
include		<sys/types.h>, <sys/socket.h>, <netinet/sctp.h>
declaration	ssize_t sctp_send(int s, const void *msg, size_t len, \
			const struct sctp_sndrcvinfo *sinfo, int flags)
version		SUNW_1.1
errno		EBADF EINTR EINVAL EMSGSIZE ENOMEM ENOSR ENOTSOCK EWOULDBLOCK
exception	$return == -1
end

function	sctp_sendmsg
include		<sys/types.h>, <sys/socket.h>, <netinet/sctp.h>
declaration	ssize_t sctp_sendmsg(int s, const void *msg, size_t len, \
			const struct sockaddr *to, socklen_t tolen, \
			uint32_t ppid, uint32_t flags, uint16_t stream_no, \
			uint32_t timetolive, uint32_t context)
version		SUNW_1.1
errno		EBADF EINTR EINVAL EMSGSIZE ENOMEM ENOSR ENOTSOCK EWOULDBLOCK
exception	$return == -1
end
