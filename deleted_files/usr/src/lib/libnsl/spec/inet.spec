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
# NOTE: Look at "versions" file for more details on why there may 
# appear to be "gaps" in version number space.
#

function	inet_addr
include		<sys/types.h>, <sys/socket.h>, <netinet/in.h>, <arpa/inet.h>
declaration	in_addr_t inet_addr(const char *cp)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
end

function	inet_netof
include		<sys/types.h>, <sys/socket.h>, <netinet/in.h>, <arpa/inet.h>
declaration	in_addr_t inet_netof(struct in_addr in)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
end

function	inet_ntoa
include		<sys/types.h>, <sys/socket.h>, <netinet/in.h>, <arpa/inet.h>
declaration	char *inet_ntoa(const struct in_addr in)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == 0
end

function	inet_ntoa_r
declaration	char *inet_ntoa_r(struct in_addr in, char *b)
version		SUNW_0.7
end

function	inet_ntop
include		<sys/socket.h>, <arpa/inet.h>
declaration	const char *inet_ntop(int af, const void *src, char *dst, socklen_t size)
version		SUNW_1.7
exception	$return == 0
end

function	inet_pton
include		<sys/socket.h>, <arpa/inet.h>
declaration	int inet_pton(int af, const char *src, void *dst)
version		SUNW_1.7
exception	$return == -1
end

function	inet_aton
include		<sys/types.h>, <sys/socket.h>, <netinet/in.h>, <arpa/inet.h>
declaration	char *inet_ntoa(const struct in_addr in)
version		SUNW_1.10
exception	$return == 0
end

function	_inet_aton
weak		inet_aton
include		<sys/types.h>, <sys/socket.h>, <netinet/in.h>, <arpa/inet.h>
declaration	char *inet_ntoa(const struct in_addr in)
version		SUNW_1.10
exception	$return == 0
end
