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
# lib/libnsl/spec/nis.spec

function	dbmclose
version		SUNW_0.7
end

function	dbminit
version		SUNW_0.7
end

function	nis_sperrno
include		<rpcsvc/nis.h>
declaration	char *nis_sperrno(const nis_error status)
version		SUNW_0.7
exception	$return == 0
end

function	nis_perror
include		<rpcsvc/nis.h>
declaration	void nis_perror(nis_error status, char *label)
version		SUNW_0.7
end

function	nis_lerror
include		<rpcsvc/nis.h>
declaration	void nis_lerror(nis_error status, char *label)
version		SUNW_0.7
end

function	nis_sperror_r
include		<rpcsvc/nis.h>
declaration	char *nis_sperror_r(nis_error status, char *label, \
			char * buf, int length)
version		SUNW_0.7
exception	$return == 0
end

function	nis_sperror
include		<rpcsvc/nis.h>
declaration	char *nis_sperror(nis_error status, char *label)
version		SUNW_0.7
exception	$return == 0
end

function	nis_ismember
include		<rpcsvc/nis.h>
declaration	bool_t nis_ismember(const nis_name principal, \
			const nis_name group)
version		SUNW_0.7
exception	$return == FALSE
end

function	nis_addmember
include		<rpcsvc/nis.h>
declaration	nis_error nis_addmember(const nis_name member, \
			const nis_name group)
version		SUNW_0.7
exception	$return != NIS_SUCCESS
end

function	nis_removemember
include		<rpcsvc/nis.h>
declaration	nis_error nis_removemember(const nis_name member, \
			const nis_name group)
version		SUNW_0.7
exception	$return != NIS_SUCCESS
end

function	nis_creategroup
include		<rpcsvc/nis.h>
declaration	nis_error nis_creategroup(nis_name group, uint_t flags)
version		SUNW_0.7
exception	$return != NIS_SUCCESS
end

function	nis_destroygroup
include		<rpcsvc/nis.h>
declaration	nis_error nis_destroygroup(const nis_name group)
version		SUNW_0.7
exception	$return != NIS_SUCCESS
end

function	nis_print_group_entry
include		<rpcsvc/nis.h>
declaration	void nis_print_group_entry(const nis_name group)
version		SUNW_0.7
end

function	nis_verifygroup
include		<rpcsvc/nis.h>
declaration	nis_error nis_verifygroup(const nis_name group)
version		SUNW_0.7
exception	$return != NIS_SUCCESS
end

function	nis_local_directory
include		<rpcsvc/nis.h>
declaration	nis_name nis_local_directory(void)
version		SUNW_0.7
exception	$return == 0
end

function	nis_local_host
include		<rpcsvc/nis.h>
declaration	nis_name nis_local_host(void)
version		SUNW_0.7
exception	$return == 0
end

function	nis_local_group
include		<rpcsvc/nis.h>
declaration	nis_name nis_local_group(void)
version		SUNW_0.7
exception	$return == 0
end

function	nis_local_principal
include		<rpcsvc/nis.h>
declaration	nis_name nis_local_principal(void)
version		SUNW_0.7
exception	$return == 0
end

function	nis_lookup
include		<rpcsvc/nis.h>
declaration	nis_result *nis_lookup(nis_name name, uint_t flags)
version		SUNW_0.7
exception	$return->status != NIS_SUCCESS
end

function	nis_add
include		<rpcsvc/nis.h>
declaration	nis_result *nis_add(nis_name name, nis_object *obj)
version		SUNW_0.7
exception	$return->status != NIS_SUCCESS
end

function	nis_remove
include		<rpcsvc/nis.h>
declaration	nis_result *nis_remove(nis_name name, nis_object *obj)
version		SUNW_0.7
exception	$return->status != NIS_SUCCESS
end

function	nis_modify
include		<rpcsvc/nis.h>
declaration	nis_result *nis_modify(nis_name name, nis_object *obj)
version		SUNW_0.7
exception	$return->status != NIS_SUCCESS
end

function	nis_ping
include		<rpcsvc/nis.h>
declaration	void nis_ping(nis_name dirname, uint32_t utime, nis_object *dirobj)
version		SUNW_0.7
end

function	nis_checkpoint
include		<rpcsvc/nis.h>
declaration	nis_result *nis_checkpoint(const nis_name dirname)
version		SUNW_0.7
exception	$return == 0
end

function	nis_mkdir
include		<rpcsvc/nis.h>
declaration	nis_error nis_mkdir(nis_name dirname, nis_server *machine)
version		SUNW_0.7
exception	$return != NIS_SUCCESS
end

function	nis_rmdir
include		<rpcsvc/nis.h>
declaration	nis_error nis_rmdir(nis_name dirname, nis_server *machine)
version		SUNW_0.7
exception	$return != NIS_SUCCESS
end

function	nis_servstate
include		<rpcsvc/nis.h>
declaration	nis_error nis_servstate(nis_server *machine, \
			nis_tag *tags, int numtags, nis_tag **result)
version		SUNW_0.7
exception	$return != NIS_SUCCESS
end

function	nis_stats
include		<rpcsvc/nis.h>
declaration	nis_error nis_stats(nis_server *machine, \
			nis_tag *tags, int numtags, nis_tag **result)
version		SUNW_0.7
exception	$return != NIS_SUCCESS
end

function	nis_freetags
include		<rpcsvc/nis.h>
declaration	void nis_freetags(nis_tag *tags, const int numtags)
version		SUNW_0.7
end

function	nis_getservlist
include		<rpcsvc/nis.h>
declaration	nis_server **nis_getservlist(const nis_name dirname)
version		SUNW_0.7
exception	$return == 0
end

function	nis_freeservlist
include		<rpcsvc/nis.h>
declaration	void nis_freeservlist(nis_server **machines)
version		SUNW_0.7
end

function	nis_leaf_of
include		<rpcsvc/nis.h>
declaration	nis_name nis_leaf_of(const nis_name name)
version		SUNW_0.7
end

function	nis_name_of
include		<rpcsvc/nis.h>
declaration	nis_name nis_name_of(const nis_name name)
version		SUNW_0.7
end

function	nis_domain_of
include		<rpcsvc/nis.h>
declaration	nis_name nis_domain_of(const nis_name name)
version		SUNW_0.7
end

function	nis_getnames
include		<rpcsvc/nis.h>
declaration	nis_name *nis_getnames(const nis_name name)
version		SUNW_0.7
exception	$return == 0
end

function	nis_freenames
include		<rpcsvc/nis.h>
declaration	void nis_freenames(nis_name *namelist)
### APPENDED
version		SUNW_0.7
version		SUNW_0.7
end

function	nis_dir_cmp
include		<rpcsvc/nis.h>
declaration	name_pos nis_dir_cmp(const nis_name n1, const nis_name n2)
version		SUNW_0.7
end

function	nis_clone_object
include		<rpcsvc/nis.h>
declaration	nis_object *nis_clone_object(nis_object *src, \
			nis_object *dest)
version		SUNW_0.7
exception	$return == 0
end

function	nis_destroy_object
include		<rpcsvc/nis.h>
declaration	void nis_destroy_object(nis_object *obj)
version		SUNW_0.7
end

function	nis_print_object
include		<rpcsvc/nis.h>
declaration	void nis_print_object(nis_object *obj)
version		SUNW_0.7
end

function	nis_list
include		<rpcsvc/nis.h>
declaration	nis_result *nis_list(nis_name name, \
			uint_t flags, int (*callback)(nis_name table_name, \
			nis_object *object, void *userdata), \
			void *userdata)
version		SUNW_0.7
exception	$return == 0
end

function	nis_add_entry
include		<rpcsvc/nis.h>
declaration	nis_result *nis_add_entry(nis_name table_name, \
			nis_object *object, uint_t flags)
version		SUNW_0.7
exception	$return == 0
end

function	nis_remove_entry
include		<rpcsvc/nis.h>
declaration	nis_result *nis_remove_entry(nis_name name, \
			nis_object *object, uint_t flags)
version		SUNW_0.7
exception	$return == 0
end

function	nis_modify_entry
include		<rpcsvc/nis.h>
declaration	nis_result *nis_modify_entry(nis_name name, \
			nis_object *object, uint_t flags)
version		SUNW_0.7
exception	$return == 0
end

function	nis_first_entry
include		<rpcsvc/nis.h>
declaration	nis_result *nis_first_entry(const nis_name table_name)
version		SUNW_0.7
exception	$return == 0
end

function	nis_next_entry
include		<rpcsvc/nis.h>
declaration	nis_result *nis_next_entry(nis_name table_name, netobj *cookie)
version		SUNW_0.7
exception	$return == 0
end

function	nis_freeresult
include		<rpcsvc/nis.h>
declaration	void nis_freeresult(nis_result *result)
version		SUNW_0.7
end

function	delete
version		SUNW_0.7
end

function	nis_data
version		SUNWprivate_1.1
end

function	nis_dump
version		SUNWprivate_1.1
end

function	nis_dumplog
version		SUNWprivate_1.1
end

function	nis_find_item
version		SUNWprivate_1.1
end

function	nis_finddirectory
version		SUNWprivate_1.1
end

function	nis_free_request
version		SUNWprivate_1.1
end

function	nis_get_request
version		SUNWprivate_1.1
end

function	nis_get_static_storage
version		SUNWprivate_1.1
end

function	nis_in_table
version		SUNWprivate_1.1
end

function	nis_insert_item
version		SUNWprivate_1.1
end

function	nis_insert_name
version		SUNWprivate_1.1
end

function	nis_leaf_of_r
version		SUNW_0.7
end

function	nis_make_error
version		SUNWprivate_1.1
end

function	nis_make_rpchandle
version		SUNWprivate_1.1
end

function	nis_print_directory
version		SUNWprivate_1.1
end

function	nis_print_entry
version		SUNWprivate_1.1
end

function	nis_print_group
version		SUNWprivate_1.1
end

function	nis_print_link
version		SUNWprivate_1.1
end

function	nis_print_rights
version		SUNWprivate_1.1
end

function	nis_print_table
version		SUNWprivate_1.1
end

function	nis_read_obj
version		SUNWprivate_1.1
end

function	nis_remove_item
version		SUNWprivate_1.1
end

function	nis_remove_name
version		SUNWprivate_1.1
end

function	nis_write_obj
version		SUNWprivate_1.1
end

