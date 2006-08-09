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
# lib/libinetcfg/spec/inetcfg.spec

function	icfg_errmsg
include		<inetcfg.h>
declaration	const char *icfg_errmsg(int index)
version		SUNWprivate_1.1
end

function	icfg_open
include		<inetcfg.h>
declaration	int icfg_open(icfg_handle_t *handle, \
		    const icfg_if_t *interface)
version		SUNWprivate_1.1
end

function	icfg_close
include		<inetcfg.h>
declaration	void icfg_close(icfg_handle_t handle)
version		SUNWprivate_1.1
end

function	icfg_set_tunnel_dest
include		<inetcfg.h>
declaration	int icfg_set_tunnel_dest(icfg_handle_t handle, \
		    const struct sockaddr *addr, socklen_t addrlen)
version		SUNWprivate_1.1
end

function	icfg_set_tunnel_src
include		<inetcfg.h>
declaration	int icfg_set_tunnel_src(icfg_handle_t handle, \
		    const struct sockaddr *addr, socklen_t addrlen)
version		SUNWprivate_1.1
end

function	icfg_set_tunnel_hoplimit
include		<inetcfg.h>
declaration	int icfg_set_tunnel_hoplimit(icfg_handle_t handle, \
		    uint8_t limit)
version		SUNWprivate_1.1
end

function	icfg_set_tunnel_encaplimit
include		<inetcfg.h>
declaration	int icfg_set_tunnel_encaplimit(icfg_handle_t handle, \
		    int16_t limit)
version		SUNWprivate_1.1
end

function	icfg_get_tunnel_dest
include		<inetcfg.h>
declaration	int icfg_get_tunnel_dest(icfg_handle_t handle, \
		    struct sockaddr *addr, socklen_t *addrlen)
version		SUNWprivate_1.1
end

function	icfg_get_tunnel_src
include		<inetcfg.h>
declaration	int icfg_get_tunnel_src(icfg_handle_t handle, \
		    struct sockaddr *addr, socklen_t *addrlen)
version		SUNWprivate_1.1
end

function	icfg_get_tunnel_hoplimit
include		<inetcfg.h>
declaration	int icfg_get_tunnel_hoplimit(icfg_handle_t handle, \
		    uint8_t *limit)
version		SUNWprivate_1.1
end

function	icfg_get_tunnel_encaplimit
include		<inetcfg.h>
declaration	int icfg_get_tunnel_encaplimit(icfg_handle_t handle, \
		    int16_t *limit)
version		SUNWprivate_1.1
end

function	icfg_get_tunnel_lower
include		<inetcfg.h>
declaration	int icfg_get_tunnel_lower(icfg_handle_t handle, \
		    int *protocol)
version		SUNWprivate_1.1
end

function	icfg_get_tunnel_upper
include		<inetcfg.h>
declaration	int icfg_get_tunnel_upper(icfg_handle_t handle, \
		    int *protocol)
version		SUNWprivate_1.1
end

function	icfg_refresh_tunnel_cache
include		<inetcfg.h>
declaration	int icfg_refresh_tunnel_cache(icfg_handle_t handle)
version		SUNWprivate_1.1
end

function	icfg_set_flags
include		<inetcfg.h>
declaration	int icfg_set_flags(icfg_handle_t handle, uint64_t flags)
version		SUNWprivate_1.1
end

function	icfg_set_metric
include		<inetcfg.h>
declaration	int icfg_set_metric(icfg_handle_t handle, int metric)
version		SUNWprivate_1.1
end

function	icfg_set_mtu
include		<inetcfg.h>
declaration	int icfg_set_mtu(icfg_handle_t handle, uint_t mtu)
version		SUNWprivate_1.1
end

function	icfg_set_index
include		<inetcfg.h>
declaration	int icfg_set_index(icfg_handle_t handle, int index)
version		SUNWprivate_1.1
end

function	icfg_set_netmask
include		<inetcfg.h>
declaration	int icfg_set_netmask(icfg_handle_t handle, \
		    const struct sockaddr_in *addr)
version		SUNWprivate_1.1
end

function	icfg_set_broadcast
include		<inetcfg.h>
declaration	int icfg_set_broadcast(icfg_handle_t handle, \
		    const struct sockaddr_in *addr)
version		SUNWprivate_1.1
end

function	icfg_set_prefixlen
include		<inetcfg.h>
declaration	int icfg_set_prefixlen(icfg_handle_t handle, int prefixlen)
version		SUNWprivate_1.1
end

function	icfg_set_addr
include		<inetcfg.h>
declaration	int icfg_set_addr(icfg_handle_t handle, \
		    const struct sockaddr *addr, socklen_t addrlen)
version		SUNWprivate_1.1
end

function	icfg_set_token
include		<inetcfg.h>
declaration	int icfg_set_token(icfg_handle_t handle, \
		    const struct sockaddr_in6 *addr, int prefixlen)
version		SUNWprivate_1.1
end

function	icfg_set_subnet
include		<inetcfg.h>
declaration	int icfg_set_subnet(icfg_handle_t handle, \
		    const struct sockaddr *addr, socklen_t addrlen, \
		    int prefixlen)
version		SUNWprivate_1.1
end

function	icfg_set_dest_addr
include		<inetcfg.h>
declaration	int icfg_set_dest_addr(icfg_handle_t handle, \
		    const struct sockaddr *addr, socklen_t addrlen)
version		SUNWprivate_1.1
end

function	icfg_get_addr
include		<inetcfg.h>
declaration	int icfg_get_addr(icfg_handle_t handle, struct sockaddr *addr,\
		    socklen_t *addrlen, int *prefixlen, boolean_t force)
version		SUNWprivate_1.1
end

function	icfg_get_token
include		<inetcfg.h>
declaration	int icfg_get_token(icfg_handle_t handle, \
		    struct sockaddr_in6 *addr, int *prefixlen, boolean_t force)
version		SUNWprivate_1.1
end

function	icfg_get_subnet
include		<inetcfg.h>
declaration	int icfg_get_subnet(icfg_handle_t handle, \
		    struct sockaddr *addr, socklen_t *addrlen, \
		    int *prefixlen, boolean_t force)
version		SUNWprivate_1.1
end

function	icfg_get_netmask
include		<inetcfg.h>
declaration	int icfg_get_netmask(icfg_handle_t handle, \
		    struct sockaddr_in *addr)
version		SUNWprivate_1.1
end

function	icfg_get_broadcast
include		<inetcfg.h>
declaration	int icfg_get_broadcast(icfg_handle_t handle, \
		    struct sockaddr_in *addr)
version		SUNWprivate_1.1
end

function	icfg_get_dest_addr
include		<inetcfg.h>
declaration	int icfg_get_dest_addr(icfg_handle_t handle, \
		    struct sockaddr *addr, socklen_t *addrlen)
version		SUNWprivate_1.1
end

function	icfg_get_groupname
include		<inetcfg.h>
declaration	int icfg_get_groupname(icfg_handle_t handle, \
		    char *groupname, size_t len)
version		SUNWprivate_1.1
end

function	icfg_get_flags
include		<inetcfg.h>
declaration	int icfg_get_flags(icfg_handle_t handle, \
		    uint64_t *flags)
version		SUNWprivate_1.1
end

function	icfg_get_metric
include		<inetcfg.h>
declaration	int icfg_get_metric(icfg_handle_t handle, int *metric)
version		SUNWprivate_1.1
end

function	icfg_get_mtu
include		<inetcfg.h>
declaration	int icfg_get_mtu(icfg_handle_t handle, uint_t *mtu)
version		SUNWprivate_1.1
end

function	icfg_get_index
include		<inetcfg.h>
declaration	int icfg_get_index(icfg_handle_t handle, int *index)
version		SUNWprivate_1.1
end

function	icfg_get_if_list
include		<inetcfg.h>
declaration	int icfg_get_if_list(icfg_if_t **if_list, int *numif, \
		    int proto, int type)
version		SUNWprivate_1.1
end

function	icfg_free_if_list
include		<inetcfg.h>
declaration	void icfg_free_if_list(icfg_if_t *if_list)
version		SUNWprivate_1.1
end

function	icfg_iterate_if
include		<inetcfg.h>
declaration	int icfg_iterate_if(int proto, int type, void *arg, \
		    int (*callback)(icfg_if_t *interface, void *arg))
version		SUNWprivate_1.1
end

function	icfg_is_logical
include		<inetcfg.h>
declaration	boolean_t icfg_is_logical(icfg_handle_t handle)
version		SUNWprivate_1.1
end

function	icfg_sockaddr_to_str
include		<inetcfg.h>
declaration	int icfg_sockaddr_to_str(sa_family_t af, \
		    const struct sockaddr *sockaddr, char *addr, size_t len)
version		SUNWprivate_1.1
end

function	icfg_str_to_sockaddr
include		<inetcfg.h>
declaration	int icfg_str_to_sockaddr(sa_family_t af, const char *straddr, \
		    struct sockaddr *sockaddr, socklen_t *)
version		SUNWprivate_1.1
end
