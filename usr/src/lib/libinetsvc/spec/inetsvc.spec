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

function	get_prop_table
include		<inetsvc.h>
declaration	inetd_prop_t *get_prop_table(size_t *num_elements)
version		SUNWprivate_1.1
end

function	get_prop_value
include		<inetsvc.h>
declaration	void *get_prop_value(const inetd_prop_t *prop, char *name)
version		SUNWprivate_1.1
end

function	put_prop_value
include		<inetsvc.h>
declaration	int put_prop_value(inetd_prop_t *prop, char *name, void *value)
version		SUNWprivate_1.1
end

function	valid_props
include		<inetsvc.h>
declaration	boolean_t valid_props(inetd_prop_t *prop)
version		SUNWprivate_1.1
end

function	valid_default_prop
include		<inetsvc.h>
declaration	boolean_t valid_default_prop(char *name, void *value)
version		SUNWprivate_1.1
end

function	read_prop
include		<inetsvc.h>
declaration	scf_error_t read_prop(scf_handle_t *h, inetd_prop_t *iprop,
		    int index, const char *inst, const char *pg_name)
version		SUNWprivate_1.1
end

function	read_instance_props
include		<inetsvc.h>
declaration	inetd_prop_t *read_instance_props(scf_handle_t *h,
		    const char *instance, size_t *num_elements,
		    scf_error_t *err)
version		SUNWprivate_1.1
end

function	read_default_props
include		<inetsvc.h>
declaration	inetd_prop_t *read_default_props(scf_handle_t *h,
		   size_t *num_elements, scf_error_t *err)
version		SUNWprivate_1.1
end

function	free_instance_props
include		<inetsvc.h>
declaration	void free_instance_props(inetd_prop_t *prop)
version		SUNWprivate_1.1
end

function	connect_to_inetd
include		<inetsvc.h>
declaration	int connect_to_inetd(void)
version		SUNWprivate_1.1
end

function	refresh_inetd
include		<inetsvc.h>
declaration	int refresh_inetd(void)
version		SUNWprivate_1.1
end

function	get_sock_type_id
include		<inetsvc.h>
declaration	int get_sock_type_id(const char *type_str);
version		SUNWprivate_1.1
end

function	get_rpc_prognum
include		<inetsvc.h>
declaration	int get_rpc_prognum(const char *svc_name);
version		SUNWprivate_1.1
end

function	calculate_hash
include		<inetsvc.h>
declaration	int calculate_hash(const char *pathname, char **hash);
version		SUNWprivate_1.1
end

function	retrieve_inetd_hash
include		<inetsvc.h>
declaration	scf_error_t retrieve_inetd_hash(char **hash)
version		SUNWprivate_1.1
end

function	store_inetd_hash
include		<inetsvc.h>
declaration	scf_error_t store_inetd_hash(const char *hash)
version		SUNWprivate_1.1
end

function	inet_ntop_native
include		<inetsvc.h>
declaration	const char *inet_ntop_native(int af, const void *addr,
		    char *dst, size_t size)
version		SUNWprivate_1.1
end

function	setproctitle
include		<inetsvc.h>
declaration	void setproctitle(const char *svc_name, int s, char **argv);
version		SUNWprivate_1.1
end

function	dg_template
include		<inetsvc.h>
declaration 	void dg_template(void (*cb)(int, const struct sockaddr *, int,
		    const void *, size_t), int s, void *buf, size_t buflen);
version		SUNWprivate_1.1
end

function	safe_write
include		<inetsvc.h>
declaration 	int safe_write(int fd, const void *buf, size_t sz);
version		SUNWprivate_1.1
end

function	safe_sendto
include		<inetsvc.h>
declaration	int safe_sendto(int fd, const void *buf, size_t sz, int flags,
		    const struct sockaddr *to, int tolen);
version		SUNWprivate_1.1
end

function	get_protos	
include		<inetsvc.h>
declaration	char **get_protos(const char *pstr);
version		SUNWprivate_1.1
end

function	get_netids
include		<inetsvc.h>
declaration	char **get_netids(char *proto);
version		SUNWprivate_1.1
end

function	destroy_strings
include		<inetsvc.h>
declaration	void destroy_strings(char **strs);
version		SUNWprivate_1.1
end

function	destroy_basic_cfg
include		<inetsvc.h>
declaration	void destroy_basic_cfg(basic_cfg_t *cfg)
version		SUNWprivate_1.1
end

function	destroy_proto_list
include		<inetsvc.h>
declaration	void destroy_proto_list(basic_cfg_t *cfg)
version		SUNWprivate_1.1
end

