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
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libdhcpsvc/modules/templates/spec/public.spec

#
# This is the authoritative specfile for all public modules
#

function	status
include		<dhcp_svc_public.h>
declaration	int status(const char *location)
end

function	version
include		<dhcp_svc_public.h>
declaration	int version(int *vp)
end

function	mklocation
include		<dhcp_svc_public.h>
declaration	int mklocation(const char *location)
end

function	list_dn
include		<dhcp_svc_public.h>
declaration	int list_dn(const char *location, char ***listppp, \
		    uint_t *count)
end

function	open_dn
include		<dhcp_svc_public.h>
declaration	int open_dn(void **handlep, const char *location, uint_t flags,\
		    const struct in_addr *netp, const struct in_addr *maskp)
end

function	close_dn
include		<dhcp_svc_public.h>
declaration	int close_dn(void **handlep)
end

function	remove_dn
include		<dhcp_svc_public.h>
declaration	int remove_dn(const char *location, const struct in_addr *netp)
end		

function	lookup_dn
include		<dhcp_svc_public.h>
declaration	int lookup_dn(void *handle, boolean_t partial, uint_t query, \
		    int count, const dn_rec_t *targetp, \
		    dn_rec_list_t **recordsp, uint_t *nrecordsp)
end		

function	add_dn
include         <dhcp_svc_public.h>
declaration	int add_dn(void *handle, dn_rec_t *addp)
end

function	modify_dn
include         <dhcp_svc_public.h>
declaration	int modify_dn(void *handle, const dn_rec_t *origp, \
		    dn_rec_t *newp)
end

function	delete_dn
include         <dhcp_svc_public.h>
declaration	int delete_dn(void *handle, const dn_rec_t *pnp)
end

function	list_dt
include		<dhcp_svc_public.h>
declaration	int list_dt(const char *location, char ***listppp, \
		    uint_t *count)
end

function	open_dt
include         <dhcp_svc_public.h>
declaration	int open_dt(void **handlep, const char *location, \
		    uint_t flags)
end

function	close_dt
include         <dhcp_svc_public.h>
declaration	int close_dt(void **handlep)
end

function	remove_dt
include         <dhcp_svc_public.h>
declaration	int remove_dt(const char *location)
end

function	lookup_dt
include         <dhcp_svc_public.h>
declaration	int lookup_dt(void *handle, boolean_t partial, uint_t query, \
		    int count, const dt_rec_t *targetp, \
		    dt_rec_list_t **recordsp, uint_t *nrecordsp)
end

function	add_dt
include         <dhcp_svc_public.h>
declaration	int add_dt(void *handle, dt_rec_t *addp)
end

function	modify_dt
include         <dhcp_svc_public.h>
declaration	int modify_dt(void *handle, const dt_rec_t *origp, \
		    dt_rec_t *newp)
end

function	delete_dt
include         <dhcp_svc_public.h>
declaration	int delete_dt(void *handle, const dt_rec_t *dtp)
end
