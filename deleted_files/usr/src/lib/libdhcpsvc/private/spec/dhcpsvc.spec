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
# lib/libdhcpsvc/private/spec/dhcpsvc.spec

function	dhcpsvc_errmsg
include		<dhcp_svc_public.h>
declaration	const char *dhcpsvc_errmsg(unsigned int index)
version		SUNWprivate_1.1
end

function	alloc_dtrec
include		<dhcp_svc_public.h>
declaration 	dt_rec_t *alloc_dtrec(const char *key, char type, \
		    const char *value)
version		SUNWprivate_1.1
end

function	alloc_dnrec
include		<dhcp_svc_public.h>
declaration	dn_rec_t *alloc_dnrec(const uchar_t *cid, uchar_t cid_len, \
		    uchar_t flags, struct in_addr cip, struct in_addr sip, \
		    lease_t lease, const char *macro, const char *comment);
version		SUNWprivate_1.1
end

function	add_dtrec_to_list
include		<dhcp_svc_public.h>
declaration 	dt_rec_list_t *add_dtrec_to_list(dt_rec_t *item, \
		    dt_rec_list_t *list);
version		SUNWprivate_1.1
end

function	add_dnrec_to_list
include		<dhcp_svc_public.h>
declaration 	dn_rec_list_t *add_dnrec_to_list(dn_rec_t *item, \
		    dn_rec_list_t *list);
version		SUNWprivate_1.1
end

function	free_dtrec
include		<dhcp_svc_public.h>
declaration 	void free_dtrec(dt_rec_t *dtp)
version		SUNWprivate_1.1
end

function	free_dtrec_list
include		<dhcp_svc_public.h>
declaration 	void free_dtrec_list(dt_rec_list_t *dtlp)
version		SUNWprivate_1.1
end

function	free_dnrec
include		<dhcp_svc_public.h>
declaration 	void free_dnrec(dn_rec_t *dnp)
version		SUNWprivate_1.1
end

function	free_dnrec_list
include		<dhcp_svc_public.h>
declaration 	void free_dnrec_list(dn_rec_list_t *dnlp)
version		SUNWprivate_1.1
end

function	add_dsvc_conf
include		<dhcp_svc_confopt.h>
declaration	int add_dsvc_conf(dhcp_confopt_t **ddpp, const char *key, \
			const char *value)
version		SUNWprivate_1.1
end

function	read_dsvc_conf
include		<dhcp_svc_confopt.h>
declaration	int read_dsvc_conf(dhcp_confopt_t **ddpp)
version		SUNWprivate_1.1
end

function	replace_dsvc_conf
include		<dhcp_svc_confopt.h>
declaration	int replace_dsvc_conf(dhcp_confopt_t **ddpp, \
			const char *key, const char *value)
version		SUNWprivate_1.1
end

function	write_dsvc_conf
include		<dhcp_svc_confopt.h>
declaration	int write_dsvc_conf(dhcp_confopt_t *ddp, mode_t mode)
version		SUNWprivate_1.1
end

function	free_dsvc_conf
include		<dhcp_svc_confopt.h>
declaration	void free_dsvc_conf(dhcp_confopt_t *ddp)
version		SUNWprivate_1.1
end

function	delete_dsvc_conf
include		<dhcp_svc_confopt.h>
declaration	int delete_dsvc_conf(void)
version		SUNWprivate_1.1
end

function	query_dsvc_conf
include		<dhcp_svc_confopt.h>
declaration	int query_dsvc_conf(dhcp_confopt_t *ddp, const char *key, \
		    char **value)
version		SUNWprivate_1.1
end

function	confopt_to_datastore
include         <dhcp_svc_private.h>
declaration	int confopt_to_datastore(dhcp_confopt_t *ddp, \
		    dsvc_datastore_t *dsp)
version		SUNWprivate_1.1
end

function	enumerate_dd
include         <dhcp_svc_private.h>
declaration	int enumerate_dd(char ***modules, int *nump)
version		SUNWprivate_1.1
end

function	list_dd
include         <dhcp_svc_private.h>
declaration	int list_dd(dsvc_datastore_t *dsp, dsvc_contype_t type, \
		    char ***listppp, uint_t *count)
version		SUNWprivate_1.1
end

function	status_dd
include		<dhcp_svc_private.h>
declaration	int status_dd(dsvc_datastore_t *ddp)
version		SUNWprivate_1.1
end

function	mklocation_dd
include		<dhcp_svc_private.h>
declaration	int mklocation_dd(dsvc_datastore_t *ddp)
version		SUNWprivate_1.1
end

function	add_dd_entry
include		<dhcp_svc_private.h>
declaration	int add_dd_entry(dsvc_handle_t handle, void *newp)
version		SUNWprivate_1.1
end

function	modify_dd_entry
include		<dhcp_svc_private.h>
declaration	int modify_dd_entry(dsvc_handle_t handle, const void *origp, \
		    void *newp)
version		SUNWprivate_1.1
end

function	delete_dd_entry
include		<dhcp_svc_private.h>
declaration	int delete_dd_entry(dsvc_handle_t handle, void *entryp)
version		SUNWprivate_1.1
end

function	close_dd
include		<dhcp_svc_private.h>
declaration	int close_dd(dsvc_handle_t *handlep)
version		SUNWprivate_1.1
end

function	remove_dd
include		<dhcp_svc_private.h>
declaration	int remove_dd(dsvc_datastore_t *ddp, dsvc_contype_t type, \
		    const char *name)
version		SUNWprivate_1.1
end

function	open_dd
include		<dhcp_svc_private.h>
declaration	int open_dd(dsvc_handle_t *handlep, dsvc_datastore_t *ddp, \
		    dsvc_contype_t type, const char *name, uint_t flags)
version		SUNWprivate_1.1
end

function	lookup_dd
include		<dhcp_svc_private.h>
declaration	int lookup_dd(dsvc_handle_t handle, boolean_t partial, \
		    uint_t query, int count, const void *targetp, \
		    void **recordsp, uint_t *nrecordsp)
version		SUNWprivate_1.1
end

function	free_dd
include		<dhcp_svc_private.h>
declaration	void free_dd(dsvc_handle_t handle, void *entryp)
version		SUNWprivate_1.1
end

function	free_dd_list
include		<dhcp_svc_private.h>
declaration	void free_dd_list(dsvc_handle_t handle, void *listp)
version		SUNWprivate_1.1
end

function	module_synchtype
include         <dhcp_svc_private.h>
declaration	int module_synchtype(dsvc_datastore_t *ddp, \
		    dsvc_synchtype_t *synchtypep)
version		SUNWprivate_1.1
end


