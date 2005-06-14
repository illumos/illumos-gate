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

function	netdir_getbyname
include		<netdir.h>
declaration	int netdir_getbyname(struct netconfig  *config, \
			struct nd_hostserv *service, \
			struct nd_addrlist **addrs)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
end

function	netdir_getbyaddr
include		<netdir.h>
declaration	int netdir_getbyaddr(struct netconfig  *config, \
			struct nd_hostservlist **service, \
			struct netbuf  *netaddr)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
end

function	netdir_free
include		<netdir.h>
declaration	void netdir_free(void *ptr, const int struct_type)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
end

function	netdir_options
include		<netdir.h>
declaration	int netdir_options(struct netconfig *config, \
			int option, int fildes, char *point_to_args)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == -1
end

function	taddr2uaddr
include		<netdir.h>
declaration	char *taddr2uaddr(struct netconfig *config, struct netbuf *addr)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == 0
end

function	uaddr2taddr
include		<netdir.h>
declaration	struct netbuf *uaddr2taddr(struct netconfig *config, \
			char *uaddr)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == 0
end

function	netdir_perror
include		<netdir.h>
declaration	void netdir_perror(char *s)
version		SUNW_0.7
end

function	netdir_sperror
include		<netdir.h>
declaration	char *netdir_sperror(void)
version		SUNW_0.7
exception	$return == 0
end

