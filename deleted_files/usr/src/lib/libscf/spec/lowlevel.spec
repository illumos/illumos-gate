#
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
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
# The low-level repository interfaces
#

function	_scf_handle_decorations
header		<libscf_priv.h>
declaration	int _scf_handle_decorations(scf_handle_t *, scf_decoration_func *, scf_value_t *, void *)
version		SUNWprivate_1.1
end

function	_scf_pg_wait
include		<libscf.h>
declaration	int _scf_pg_wait(scf_propertygroup_t *, int)
version		SUNWprivate_1.1
end

function	_scf_notify_add_pgname
include		<libscf.h>
declaration	int _scf_notify_add_pgname(scf_handle_t *, const char *)
version		SUNWprivate_1.1
end

function	_scf_notify_add_pgtype
include		<libscf.h>
declaration	int _scf_notify_add_pgtype(scf_handle_t *, const char *)
version		SUNWprivate_1.1
end

function	_scf_notify_wait
include		<libscf.h>
declaration	int _scf_notify_wait(scf_propertygroup_t *, char *, size_t)
version		SUNWprivate_1.1
end

function	_scf_request_backup
include		<libscf.h>
declaration	int _scf_request_backup(scf_handle_t *, const char *)
version		SUNWprivate_1.1
end

function	_scf_snapshot_take_new
include		<libscf.h>
declaration	int _scf_snapshot_take_new(scf_instance_t *, const char *, scf_snapshot_t *)
version		SUNWprivate_1.1
end

function	_scf_snapshot_take_new_named
include		<libscf.h>
declaration	int _scf_snapshot_take_new(scf_instance_t *, const char *, const char *, const char *, scf_snapshot_t *)
version		SUNWprivate_1.1
end

function	_scf_snapshot_take_attach
include		<libscf.h>
declaration	int _scf_snapshot_take_attach(scf_instance_t *, scf_snapshot_t *)
version		SUNWprivate_1.1
end

function	_scf_snapshot_attach
include		<libscf.h>
declaration	int _scf_snapshot_attach(scf_snapshot_t *, scf_snapshot_t *)
version		SUNWprivate_1.1
end

function	_scf_snapshot_delete
include		<libscf.h>
declaration	int _scf_snapshot_delete(scf_snapshot_t *)
version		SUNWprivate_1.1
end

function	scf_cmp_pattern
include		<libscf.h>
declaration	int scf_cmp_pattern(char *, scf_pattern_t *)
version		SUNWprivate_1.1
end

function	scf_parse_fmri
include		<libscf.h>
declaration	int scf_parse_fmri(char *, int *, const char **, const char **, const char **, const char **, const char **)
version		SUNWprivate_1.1
end

function	scf_parse_svc_fmri
include		<libscf.h>
declaration	int scf_parse_svc_fmri(char *, const char **, const char **, const char **, const char **, const char **)
version		SUNWprivate_1.1
end

function	scf_parse_file_fmri
include		<libscf.h>
declaration	int scf_parse_file_fmri(char *, const char **, const char **);
version		SUNWprivate_1.1
end

function	scf_walk_fmri
include		<libscf.h>
declaration	int scf_walk_fmri(scf_handle_t *, int, const char **, scf_walk_callback, void *, int *, void (*)(const char *, ...));
version		SUNWprivate_1.1
end

function	scf_canonify_fmri
include		<libscf.h>
declaration	ssize_t scf_canonify_fmri(const char *, char *, size_t)
version		SUNWprivate_1.1
end

function	scf_type_to_string
include		<libscf.h>
declaration	const char *scf_type_to_string(scf_type_t)
version		SUNWprivate_1.1
end

function	scf_string_to_type
include		<libscf.h>
declaration	scf_type_t scf_string_to_type(const char *)
version		SUNWprivate_1.1
end

function	scf_entry_add_value
include		<libscf.h>
declaration	int scf_entry_add_value(scf_transaction_entry_t *, scf_value_t *)
version		SUNW_1.1
end

function	scf_entry_create
include		<libscf.h>
declaration	scf_transaction_entry_t *scf_entry_create(scf_handle_t *)
version		SUNW_1.1
end

function	scf_entry_destroy
include		<libscf.h>
declaration	void scf_entry_destroy(scf_transaction_entry_t *)
version		SUNW_1.1
end

function	scf_entry_destroy_children
include		<libscf.h>
declaration	void scf_entry_destroy_children(scf_transaction_entry_t *)
version		SUNW_1.1
end

function	scf_entry_handle
include		<libscf.h>
declaration	scf_handle_t *scf_entry_handle(const scf_transaction_entry_t *)
version		SUNW_1.1
end

function	scf_entry_reset
include		<libscf.h>
declaration	void scf_entry_reset(scf_transaction_entry_t *)
version		SUNW_1.1
end

function	scf_error
include		<libscf.h>
declaration	scf_error_t scf_error(void)
version		SUNW_1.1
end

function	scf_handle_bind
include		<libscf.h>
declaration	int scf_handle_bind(scf_handle_t *)
version		SUNW_1.1
end

function	scf_handle_create
include		<libscf.h>
declaration	scf_handle_t *scf_handle_create(scf_version_t)
version		SUNW_1.1
end

function	scf_handle_decode_fmri
include		<libscf.h>
declaration	int scf_handle_decode_fmri(scf_handle_t *, const char *, scf_scope_t *, scf_service_t *, scf_instance_t *, scf_propertygroup_t *, scf_property_t *, int)
version		SUNW_1.1
end

function	scf_handle_decorate
include		<libscf.h>
declaration	int scf_handle_decorate(scf_handle_t *, const char *, scf_value_t *)
version		SUNW_1.1
end

function	scf_handle_destroy
include		<libscf.h>
declaration	void scf_handle_destroy(scf_handle_t *)
version		SUNW_1.1
end

function	scf_handle_get_scope
include		<libscf.h>
declaration	int scf_handle_get_scope(scf_handle_t *, const char *, scf_scope_t *)
version		SUNW_1.1
end

function	scf_handle_unbind
include		<libscf.h>
declaration	int scf_handle_unbind(scf_handle_t *)
version		SUNW_1.1
end

function	scf_instance_add_pg
include		<libscf.h>
declaration	int scf_instance_add_pg(const scf_instance_t *, const char *, const char *, uint32_t, scf_propertygroup_t *)
version		SUNW_1.1
end

function	scf_instance_create
include		<libscf.h>
declaration	scf_instance_t *scf_instance_create(scf_handle_t *)
version		SUNW_1.1
end

function	scf_instance_delete
include		<libscf.h>
declaration	int scf_instance_delete(scf_instance_t *)
version		SUNW_1.1
end

function	scf_instance_destroy
include		<libscf.h>
declaration	void scf_instance_destroy(scf_instance_t *)
version		SUNW_1.1
end

function	scf_instance_get_name
include		<libscf.h>
declaration	ssize_t scf_instance_get_name(const scf_instance_t *, char *, size_t)
version		SUNW_1.1
end

function	scf_instance_get_parent
include		<libscf.h>
declaration	int scf_instance_get_parent(const scf_instance_t *, scf_service_t *)
version		SUNW_1.1
end

function	scf_instance_get_pg
include		<libscf.h>
declaration	int scf_instance_get_pg(const scf_instance_t *, const char *, scf_propertygroup_t *)
version		SUNW_1.1
end

function	scf_instance_get_pg_composed
include		<libscf.h>
declaration	int scf_instance_get_pg_composed(const scf_instance_t *, const scf_snapshot_t *, const char *, scf_propertygroup_t *)
version		SUNW_1.1
end

function	scf_instance_get_snapshot
include		<libscf.h>
declaration	int scf_instance_get_snapshot(const scf_instance_t *, const char *, scf_snapshot_t *)
version		SUNW_1.1
end

function	scf_instance_handle
include		<libscf.h>
declaration	scf_handle_t *scf_instance_handle(const scf_instance_t *)
version		SUNW_1.1
end

function	scf_instance_to_fmri
include		<libscf.h>
declaration	ssize_t scf_instance_to_fmri(const scf_instance_t *, char *, size_t)
version		SUNW_1.1
end

function	scf_iter_create
include		<libscf.h>
declaration	scf_iter_t *scf_iter_create(scf_handle_t *)
version		SUNW_1.1
end

function	scf_iter_destroy
include		<libscf.h>
declaration	void scf_iter_destroy(scf_iter_t *)
version		SUNW_1.1
end

function	scf_iter_handle
include		<libscf.h>
declaration	scf_handle_t *scf_iter_handle(const scf_iter_t *)
version		SUNW_1.1
end

function	scf_iter_handle_scopes
include		<libscf.h>
declaration	int scf_iter_handle_scopes(scf_iter_t *, const scf_handle_t *)
version		SUNW_1.1
end

function	scf_iter_instance_pgs
include		<libscf.h>
declaration	int scf_iter_instance_pgs(scf_iter_t *, const scf_instance_t *)
version		SUNW_1.1
end

function	scf_iter_instance_pgs_composed
include		<libscf.h>
declaration	int scf_iter_instance_pgs_composed(scf_iter_t *, const scf_instance_t *, const scf_snapshot_t *)
version		SUNW_1.1
end

function	scf_iter_instance_pgs_typed
include		<libscf.h>
declaration	int scf_iter_instance_pgs_typed(scf_iter_t *, const scf_instance_t *, const char *)
version		SUNW_1.1
end

function	scf_iter_instance_pgs_typed_composed
include		<libscf.h>
declaration	int scf_iter_instance_pgs_typed_composed(scf_iter_t *, const scf_instance_t *, const scf_snapshot_t *, const char *)
version		SUNW_1.1
end

function	scf_iter_instance_snapshots
include		<libscf.h>
declaration	int scf_iter_instance_snapshots(scf_iter_t *, const scf_instance_t *)
version		SUNW_1.1
end

function	scf_iter_next_instance
include		<libscf.h>
declaration	int scf_iter_next_instance(scf_iter_t *, scf_instance_t *)
version		SUNW_1.1
end

function	scf_iter_next_pg
include		<libscf.h>
declaration	int scf_iter_next_pg(scf_iter_t *, scf_propertygroup_t *)
version		SUNW_1.1
end

function	scf_iter_next_property
include		<libscf.h>
declaration	int scf_iter_next_property(scf_iter_t *, scf_property_t *)
version		SUNW_1.1
end

function	scf_iter_next_scope
include		<libscf.h>
declaration	int scf_iter_next_scope(scf_iter_t *, scf_scope_t *)
version		SUNW_1.1
end

function	scf_iter_next_service
include		<libscf.h>
declaration	int scf_iter_next_service(scf_iter_t *, scf_service_t *)
version		SUNW_1.1
end

function	scf_iter_next_snapshot
include		<libscf.h>
declaration	int scf_iter_next_snapshot(scf_iter_t *, scf_snapshot_t *)
version		SUNW_1.1
end

function	scf_iter_next_value
include		<libscf.h>
declaration	int scf_iter_next_value(scf_iter_t *, scf_value_t *)
version		SUNW_1.1
end

function	scf_iter_pg_properties
include		<libscf.h>
declaration	int scf_iter_pg_properties(scf_iter_t *, const scf_propertygroup_t *)
version		SUNW_1.1
end

function	scf_iter_property_values
include		<libscf.h>
declaration	int scf_iter_property_values(scf_iter_t *, const scf_property_t *)
version		SUNW_1.1
end

function	scf_iter_reset
include		<libscf.h>
declaration	void scf_iter_reset(scf_iter_t *)
version		SUNW_1.1
end

function	scf_iter_scope_services
include		<libscf.h>
declaration	int scf_iter_scope_services(scf_iter_t *, const scf_scope_t *)
version		SUNW_1.1
end

function	scf_iter_service_instances
include		<libscf.h>
declaration	int scf_iter_service_instances(scf_iter_t *, const scf_service_t *)
version		SUNW_1.1
end

function	scf_iter_service_pgs
include		<libscf.h>
declaration	int scf_iter_service_pgs(scf_iter_t *, const scf_service_t *)
version		SUNW_1.1
end

function	scf_iter_service_pgs_typed
include		<libscf.h>
declaration	int scf_iter_service_pgs_typed(scf_iter_t *, const scf_service_t *, const char *)
version		SUNW_1.1
end

function	scf_iter_snaplevel_pgs
include		<libscf.h>
declaration	int scf_iter_snaplevel_pgs(scf_iter_t *, const scf_snaplevel_t *)
version		SUNW_1.1
end

function	scf_iter_snaplevel_pgs_typed
include		<libscf.h>
declaration	int scf_iter_snaplevel_pgs_typed(scf_iter_t *, const scf_snaplevel_t *, const char *)
version		SUNW_1.1
end

function	scf_limit
include		<libscf.h>
declaration	ssize_t scf_limit(uint32_t code)
version		SUNW_1.1
end

function	scf_myname
include		<libscf.h>
declaration	ssize_t scf_myname(scf_handle_t *, char *, size_t)
version		SUNW_1.1
end

function	scf_pg_create
include		<libscf.h>
declaration	scf_propertygroup_t *scf_pg_create(scf_handle_t *)
version		SUNW_1.1
end

function	scf_pg_delete
include		<libscf.h>
declaration	int scf_pg_delete(scf_propertygroup_t *)
version		SUNW_1.1
end

function	scf_pg_destroy
include		<libscf.h>
declaration	void scf_pg_destroy(scf_propertygroup_t *)
version		SUNW_1.1
end

function	scf_pg_get_flags
include		<libscf.h>
declaration	int scf_pg_get_flags(const scf_propertygroup_t *, uint32_t *)
version		SUNW_1.1
end

function	scf_pg_get_name
include		<libscf.h>
declaration	ssize_t scf_pg_get_name(const scf_propertygroup_t *, char *, size_t)
version		SUNW_1.1
end

function	scf_pg_get_parent_instance
include		<libscf.h>
declaration	int scf_pg_get_parent_instance(const scf_propertygroup_t *, scf_instance_t *)
version		SUNW_1.1
end

function	scf_pg_get_parent_service
include		<libscf.h>
declaration	int scf_pg_get_parent_service(const scf_propertygroup_t *, scf_service_t *)
version		SUNW_1.1
end

function	scf_pg_get_parent_snaplevel
include		<libscf.h>
declaration	int scf_pg_get_parent_snaplevel(const scf_propertygroup_t *, scf_snaplevel_t *)
version		SUNW_1.1
end

function	scf_pg_get_property
include		<libscf.h>
declaration	int scf_pg_get_property(const scf_propertygroup_t *, const char *, scf_property_t *)
version		SUNW_1.1
end

function	scf_pg_get_type
include		<libscf.h>
declaration	ssize_t scf_pg_get_type(const scf_propertygroup_t *, char *, size_t)
version		SUNW_1.1
end

function	scf_pg_get_underlying_pg
include		<libscf.h>
declaration	int scf_pg_get_underlying_pg(const scf_propertygroup_t *, scf_propertygroup_t *)
version		SUNW_1.1
end

function	scf_pg_handle
include		<libscf.h>
declaration	scf_handle_t *scf_pg_handle(const scf_propertygroup_t *)
version		SUNW_1.1
end

function	scf_pg_to_fmri
include		<libscf.h>
declaration	ssize_t scf_pg_to_fmri(const scf_propertygroup_t *,  char *, size_t)
version		SUNW_1.1
end

function	scf_pg_update
include		<libscf.h>
declaration	int scf_pg_update(scf_propertygroup_t *)
version		SUNW_1.1
end

function	scf_property_create
include		<libscf.h>
declaration	scf_property_t *scf_property_create(scf_handle_t *)
version		SUNW_1.1
end

function	scf_property_destroy
include		<libscf.h>
declaration	void scf_property_destroy(scf_property_t *)
version		SUNW_1.1
end

function	scf_property_get_name
include		<libscf.h>
declaration	ssize_t scf_property_get_name(const scf_property_t *, char *, size_t)
version		SUNW_1.1
end

function	scf_property_get_value
include		<libscf.h>
declaration	int scf_property_get_value(const scf_property_t *, scf_value_t *)
version		SUNW_1.1
end

function	scf_property_handle
include		<libscf.h>
declaration	scf_handle_t *scf_property_handle(const scf_property_t *)
version		SUNW_1.1
end

function	scf_property_is_type
include		<libscf.h>
declaration	int scf_property_is_type(const scf_property_t *, scf_type_t)
version		SUNW_1.1
end

function	scf_property_to_fmri
include		<libscf.h>
declaration	ssize_t scf_property_to_fmri(const scf_property_t *, char *, size_t)
version		SUNW_1.1
end

function	scf_property_type
include		<libscf.h>
declaration	int scf_property_type(const scf_property_t *, scf_type_t *)
version		SUNW_1.1
end

function	scf_scope_add_service
include		<libscf.h>
declaration	int scf_scope_add_service(const scf_scope_t *, const char *, scf_service_t *)
version		SUNW_1.1
end

function	scf_scope_create
include		<libscf.h>
declaration	scf_scope_t *scf_scope_create(scf_handle_t *)
version		SUNW_1.1
end

function	scf_scope_destroy
include		<libscf.h>
declaration	void scf_scope_destroy(scf_scope_t *)
version		SUNW_1.1
end

function	scf_scope_get_name
include		<libscf.h>
declaration	ssize_t scf_scope_get_name(const scf_scope_t *, char *, size_t)
version		SUNW_1.1
end

function	scf_scope_get_parent
include		<libscf.h>
declaration	int scf_scope_get_parent(const scf_scope_t *, scf_scope_t *)
version		SUNW_1.1
end

function	scf_scope_get_service
include		<libscf.h>
declaration	int scf_scope_get_service(const scf_scope_t *, const char *, scf_service_t *)
version		SUNW_1.1
end

function	scf_scope_handle
include		<libscf.h>
declaration	scf_handle_t *scf_scope_handle(const scf_scope_t *)
version		SUNW_1.1
end

function	scf_scope_to_fmri
include		<libscf.h>
declaration	ssize_t scf_scope_to_fmri(const scf_scope_t *, char *, size_t)
version		SUNW_1.1
end

function	scf_service_add_instance
include		<libscf.h>
declaration	int scf_service_add_instance(const scf_service_t *, const char *, scf_instance_t *)
version		SUNW_1.1
end

function	scf_service_add_pg
include		<libscf.h>
declaration	int scf_service_add_pg(const scf_service_t *, const char *, const char *, uint32_t, scf_propertygroup_t *)
version		SUNW_1.1
end

function	scf_service_create
include		<libscf.h>
declaration	scf_service_t *scf_service_create(scf_handle_t *)
version		SUNW_1.1
end

function	scf_service_delete
include		<libscf.h>
declaration	int scf_service_delete(scf_service_t *)
version		SUNW_1.1
end

function	scf_service_destroy
include		<libscf.h>
declaration	void scf_service_destroy(scf_service_t *)
version		SUNW_1.1
end

function	scf_service_get_instance
include		<libscf.h>
declaration	int scf_service_get_instance(const scf_service_t *, const char *, scf_instance_t *)
version		SUNW_1.1
end

function	scf_service_get_name
include		<libscf.h>
declaration	ssize_t scf_service_get_name(const scf_service_t *, char *, size_t)
version		SUNW_1.1
end

function	scf_service_get_parent
include		<libscf.h>
declaration	int scf_service_get_parent(const scf_service_t *, scf_scope_t *)
version		SUNW_1.1
end

function	scf_service_get_pg
include		<libscf.h>
declaration	int scf_service_get_pg(const scf_service_t *, const char *, scf_propertygroup_t *)
version		SUNW_1.1
end

function	scf_service_handle
include		<libscf.h>
declaration	scf_handle_t *scf_service_handle(const scf_service_t *)
version		SUNW_1.1
end

function	scf_service_to_fmri
include		<libscf.h>
declaration	ssize_t scf_service_to_fmri(const scf_service_t *, char *, size_t)
version		SUNW_1.1
end

function	scf_snaplevel_create
include		<libscf.h>
declaration	scf_snaplevel_t *scf_snaplevel_create(scf_handle_t *)
version		SUNW_1.1
end

function	scf_snaplevel_destroy
include		<libscf.h>
declaration	void scf_snaplevel_destroy(scf_snaplevel_t *)
version		SUNW_1.1
end

function	scf_snaplevel_get_instance_name
include		<libscf.h>
declaration	ssize_t scf_snaplevel_get_instance_name(const scf_snaplevel_t *, char *, size_t)
version		SUNW_1.1
end

function	scf_snaplevel_get_next_snaplevel
include		<libscf.h>
declaration	int scf_snaplevel_get_next_snaplevel(const scf_snaplevel_t *, scf_snaplevel_t *)
version		SUNW_1.1
end

function	scf_snaplevel_get_parent
include		<libscf.h>
declaration	int scf_snaplevel_get_parent(const scf_snaplevel_t *, scf_snapshot_t *)
version		SUNW_1.1
end

function	scf_snaplevel_get_pg
include		<libscf.h>
declaration	int scf_snaplevel_get_pg(const scf_snaplevel_t *, scf_propertygroup_t *)
version		SUNW_1.1
end

function	scf_snaplevel_get_scope_name
include		<libscf.h>
declaration	ssize_t scf_snaplevel_get_scope_name(const scf_snaplevel_t *, char *, size_t)
version		SUNW_1.1
end

function	scf_snaplevel_get_service_name
include		<libscf.h>
declaration	ssize_t scf_snaplevel_get_service_name(const scf_snaplevel_t *, char *, size_t)
version		SUNW_1.1
end

function	scf_snaplevel_handle
include		<libscf.h>
declaration	scf_handle_t *scf_snaplevel_handle(const scf_snaplevel_t *)
version		SUNW_1.1
end

function	scf_snapshot_create
include		<libscf.h>
declaration	scf_snapshot_t *scf_snapshot_create(scf_handle_t *)
version		SUNW_1.1
end

function	scf_snapshot_destroy
include		<libscf.h>
declaration	void scf_snapshot_destroy(scf_snapshot_t *)
version		SUNW_1.1
end

function	scf_snapshot_get_base_snaplevel
include		<libscf.h>
declaration	int scf_snapshot_get_base_snaplevel(const scf_snapshot_t *, scf_snaplevel_t *)
version		SUNW_1.1
end

function	scf_snapshot_get_name
include		<libscf.h>
declaration	ssize_t scf_snapshot_get_name(const scf_snapshot_t *, char *, size_t)
version		SUNW_1.1
end

function	scf_snapshot_get_parent
include		<libscf.h>
declaration	int scf_snapshot_get_parent(const scf_snapshot_t *, scf_instance_t *)
version		SUNW_1.1
end

function	scf_snapshot_handle
include		<libscf.h>
declaration	scf_handle_t *scf_snapshot_handle(const scf_snapshot_t *)
version		SUNW_1.1
end

function	scf_snapshot_update
include		<libscf.h>
declaration	int scf_snapshot_update(scf_snapshot_t *)
version		SUNW_1.1
end

function	scf_strerror
include		<libscf.h>
declaration	const char *scf_strerror(scf_error_t)
version		SUNW_1.1
end

function	scf_transaction_property_change
include		<libscf.h>
declaration	int scf_transaction_property_change(scf_transaction_t *, scf_transaction_entry_t *, const char *, scf_type_t)
version		SUNW_1.1
end

function	scf_transaction_property_change_type
include		<libscf.h>
declaration	int scf_transaction_property_change_type(scf_transaction_t *, scf_transaction_entry_t *, const char *, scf_type_t)
version		SUNW_1.1
end

function	scf_transaction_property_delete
include		<libscf.h>
declaration	int scf_transaction_property_delete(scf_transaction_t *, scf_transaction_entry_t *, const char *)
version		SUNW_1.1
end

function	scf_transaction_property_new
include		<libscf.h>
declaration	int scf_transaction_property_new(scf_transaction_t *, scf_transaction_entry_t *, const char *, scf_type_t)
version		SUNW_1.1
end

function	scf_transaction_commit
include		<libscf.h>
declaration	int scf_transaction_commit(scf_transaction_t *)
version		SUNW_1.1
end

function	scf_transaction_create
include		<libscf.h>
declaration	scf_transaction_t *scf_transaction_create(scf_handle_t *)
version		SUNW_1.1
end

function	scf_transaction_destroy
include		<libscf.h>
declaration	void scf_transaction_destroy(scf_transaction_t *)
version		SUNW_1.1
end

function	scf_transaction_destroy_children
include		<libscf.h>
declaration	void scf_transaction_destroy_children(scf_transaction_t *)
version		SUNW_1.1
end

function	scf_transaction_handle
include		<libscf.h>
declaration	scf_handle_t *scf_transaction_handle(const scf_transaction_t *)
version		SUNW_1.1
end

function	scf_transaction_reset
include		<libscf.h>
declaration	void scf_transaction_reset(scf_transaction_t *)
version		SUNW_1.1
end

function	scf_transaction_reset_all
include		<libscf.h>
declaration	void scf_transaction_reset(scf_transaction_t *)
version		SUNW_1.1
end

function	scf_transaction_start
include		<libscf.h>
declaration	int scf_transaction_start(scf_transaction_t *, scf_propertygroup_t *)
version		SUNW_1.1
end

function	scf_type_base_type
include		<libscf.h>
declaration	int scf_type_base_type(scf_type_t type, scf_type_t *out)
version		SUNW_1.1
end

function	scf_value_base_type
include		<libscf.h>
declaration	scf_type_t scf_value_base_type(const scf_value_t *)
version		SUNW_1.1
end

function	scf_value_create
include		<libscf.h>
declaration	scf_value_t *scf_value_create(scf_handle_t *)
version		SUNW_1.1
end

function	scf_value_destroy
include		<libscf.h>
declaration	void scf_value_destroy(scf_value_t *)
version		SUNW_1.1
end

function	scf_value_get_as_string
include		<libscf.h>
declaration	ssize_t scf_value_get_as_string(const scf_value_t *, char *, size_t)
version		SUNW_1.1
end

function	scf_value_get_as_string_typed
include		<libscf.h>
declaration	ssize_t scf_value_get_as_string_typed(const scf_value_t *, scf_type_t, char *, size_t)
version		SUNW_1.1
end

function	scf_value_get_astring
include		<libscf.h>
declaration	ssize_t scf_value_get_astring(const scf_value_t *, char *, size_t)
version		SUNW_1.1
end

function	scf_value_get_boolean
include		<libscf.h>
declaration	int scf_value_get_boolean(const scf_value_t *, uint8_t *)
version		SUNW_1.1
end

function	scf_value_get_count
include		<libscf.h>
declaration	int scf_value_get_count(const scf_value_t *, uint64_t *)
version		SUNW_1.1
end

function	scf_value_get_integer
include		<libscf.h>
declaration	int scf_value_get_integer(const scf_value_t *, int64_t *)
version		SUNW_1.1
end

function	scf_value_get_opaque
include		<libscf.h>
declaration	ssize_t scf_value_get_opaque(const scf_value_t *, void *, size_t)
version		SUNW_1.1
end

function	scf_value_get_time
include		<libscf.h>
declaration	int scf_value_get_time(const scf_value_t *, int64_t *, int32_t *)
version		SUNW_1.1
end

function	scf_value_get_ustring
include		<libscf.h>
declaration	ssize_t scf_value_get_ustring(const scf_value_t *, char *, size_t)
version		SUNW_1.1
end

function	scf_value_handle
include		<libscf.h>
declaration	scf_handle_t *scf_value_handle(const scf_value_t *)
version		SUNW_1.1
end

function	scf_value_is_type
include		<libscf.h>
declaration	int scf_value_is_type(const scf_value_t *, scf_type_t)
version		SUNW_1.1
end

function	scf_value_reset
include		<libscf.h>
declaration	void scf_value_reset(scf_value_t *)
version		SUNW_1.1
end

function	scf_value_set_astring
include		<libscf.h>
declaration	int scf_value_set_astring(scf_value_t *, const char *)
version		SUNW_1.1
end

function	scf_value_set_boolean
include		<libscf.h>
declaration	void scf_value_set_boolean(scf_value_t *, uint8_t)
version		SUNW_1.1
end

function	scf_value_set_count
include		<libscf.h>
declaration	void scf_value_set_count(scf_value_t *, uint64_t)
version		SUNW_1.1
end

function	scf_value_set_from_string
include		<libscf.h>
declaration	int scf_value_set_from_string(scf_value_t *, scf_type_t, const char *)
version		SUNW_1.1
end

function	scf_value_set_integer
include		<libscf.h>
declaration	void scf_value_set_integer(scf_value_t *, int64_t)
version		SUNW_1.1
end

function	scf_value_set_opaque
include		<libscf.h>
declaration	int scf_value_set_opaque(scf_value_t *, const void *, size_t)
version		SUNW_1.1
end

function	scf_value_set_time
include		<libscf.h>
declaration	int scf_value_set_time(scf_value_t *, int64_t, int32_t)
version		SUNW_1.1
end

function	scf_value_set_ustring
include		<libscf.h>
declaration	int scf_value_set_ustring(scf_value_t *, const char *)
version		SUNW_1.1
end

function	scf_value_type
include		<libscf.h>
declaration	scf_type_t scf_value_type(const scf_value_t *)
version		SUNW_1.1
end
