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
#ident	"%Z%%M%	%I%	%E% SMI"#
# lib/libpool/spec/pool.spec
#

function	pool_version
declaration	uint_t pool_version(uint_t ver)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_error
declaration	int pool_error(void)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_strerror
declaration	const char *pool_strerror(int errno)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_conf_close
declaration	int pool_conf_close(pool_conf_t *conf)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_conf_remove
declaration	int pool_conf_remove(pool_conf_t *conf)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_conf_alloc
declaration	pool_conf_t *pool_conf_alloc(void)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_conf_free
declaration	void pool_conf_free(pool_conf_t *conf)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_conf_status
declaration	pool_conf_state_t pool_conf_status(const pool_conf_t *conf)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_conf_location
declaration	const char *pool_conf_location(const pool_conf_t *conf)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_conf_open
declaration	int pool_conf_open(pool_conf_t *conf, const char *location, int discover)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_conf_rollback
declaration	int pool_conf_rollback(pool_conf_t *conf)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_conf_commit
declaration	int pool_conf_commit(pool_conf_t *conf, int active)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_conf_export
declaration	int pool_conf_export(const pool_conf_t *conf, const char *location, pool_export_format_t fmt)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_conf_validate
declaration	int pool_conf_validate(const pool_conf_t *conf, pool_valid_level_t level)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_get_pool
declaration	pool_t *pool_get_pool(const pool_conf_t *conf, const char *name)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_query_pools
declaration	pool_t **pool_query_pools(const pool_conf_t *conf, uint_t *size, pool_value_t **props)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_resource_info
declaration	char *pool_resource_info(const pool_conf_t *conf, const pool_resource_t *res, int deep)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_get_resource
declaration	pool_resource_t *pool_get_resource(const pool_conf_t *conf, const char *type, const char *name)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_query_resources
declaration	pool_resource_t **pool_query_resources(const pool_conf_t *conf, uint_t *size, pool_value_t **props)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_query_components
declaration	pool_component_t **pool_query_components(const pool_conf_t *conf, uint_t *size, pool_value_t **props)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_resource_create
declaration	pool_resource_t *pool_resource_create(pool_conf_t *conf, const char *type, const char *name)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_resource_destroy
declaration	int pool_resource_destroy(pool_conf_t *conf, pool_resource_t *res)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_resource_transfer
declaration	int pool_resource_transfer(pool_conf_t *conf, pool_resource_t *src, pool_resource_t *tgt, uint64_t size)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_resource_xtransfer
declaration	int pool_resource_xtransfer(pool_conf_t *conf, pool_resource_t *src, pool_resource_t *tgt, pool_component_t **rl)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_query_resource_components
declaration	pool_component_t **pool_query_resource_components(const pool_conf_t *conf, const pool_resource_t *res, uint_t *size, pool_value_t **props)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_create
declaration	pool_t *pool_create(pool_conf_t *conf, const char *name)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_destroy
declaration	int pool_destroy(pool_conf_t *conf, pool_t *pool)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_associate
declaration	int pool_associate(pool_conf_t *conf, pool_t *pool, const pool_resource_t *res)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_dissociate
declaration	int pool_dissociate(pool_conf_t *conf, pool_t *pool, const pool_resource_t *res)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_info
declaration	char *pool_info(const pool_conf_t *conf, const pool_t *pool, int deep)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_set_binding
declaration	int pool_set_binding(const char *name, idtype_t idtype, id_t id)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_get_binding
declaration	char *pool_get_binding(pid_t pid)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_query_pool_resources
declaration	pool_resource_t **pool_query_pool_resources(const pool_conf_t *conf, const pool_t *pool, uint_t *size, pool_value_t **props)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_get_owning_resource
declaration	pool_resource_t *pool_get_owning_resource(const pool_conf_t *conf, const pool_component_t *comp)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_component_info
declaration	char *pool_component_info(const pool_conf_t *conf, const pool_component_t *comp, int deep)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_get_property
declaration	pool_value_class_t pool_get_property(const pool_conf_t *conf, const pool_elem_t *pe, const char *name, pool_value_t *val)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_put_property
declaration	int pool_put_property(pool_conf_t *conf, pool_elem_t *pe, const char *name, const pool_value_t *val)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_rm_property
declaration	int pool_rm_property(pool_conf_t *conf, pool_elem_t *pe, const char *name)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_walk_properties
declaration	int pool_walk_properties(pool_conf_t *conf, pool_elem_t *elem, void *arg, int (*prop_callback)(pool_conf_t *conf, pool_elem_t *elem, const char *name, pool_value_t *prop, void *arg))
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_value_get_uint64
declaration	int pool_value_get_uint64(const pool_value_t *pv, uint64_t *result)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_value_get_int64
declaration	int pool_value_get_int64(const pool_value_t *pv, int64_t *result)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_value_get_double
declaration	int pool_value_get_double(const pool_value_t *pv, double *result)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_value_get_bool
declaration	int pool_value_get_bool(const pool_value_t *pv, uchar_t *result)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_value_get_string
declaration	int pool_value_get_string(const pool_value_t *pv, const char **result)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_value_get_type
declaration	pool_value_class_t pool_value_get_type(const pool_value_t *pv)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_value_set_uint64
declaration	void pool_value_set_uint64(pool_value_t *pv, uint64_t val)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_value_set_int64
declaration	void pool_value_set_int64(pool_value_t *pv, int64_t val)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_value_set_double
declaration	void pool_value_set_double(pool_value_t *pv, double val)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_value_set_bool
declaration	void pool_value_set_bool(pool_value_t *pv, uchar_t val)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_value_set_string
declaration	int pool_value_set_string(pool_value_t *pv, const char *val)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_value_get_name
declaration	const char *pool_value_get_name(const pool_value_t *pv)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_value_set_name
declaration	int pool_value_set_name(pool_value_t *pv, const char *name)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_value_alloc
declaration	pool_value_t *pool_value_alloc(void)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_value_free
declaration	void pool_value_free(pool_value_t *val)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_conf_info
declaration	char *pool_conf_info(const pool_conf_t *pp, int level)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_conf_to_elem
declaration	pool_elem_t *pool_conf_to_elem(const pool_conf_t *pp)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_to_elem
declaration	pool_elem_t *pool_to_elem(const pool_conf_t *conf, const pool_t *pp)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_resource_to_elem
declaration	pool_elem_t *pool_resource_to_elem(const pool_conf_t *conf, const pool_resource_t *prs)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_component_to_elem
declaration	pool_elem_t *pool_component_to_elem(const pool_conf_t *conf, const pool_component_t *pr)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_static_location
declaration	const char *pool_static_location(void)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_dynamic_location
declaration	const char *pool_dynamic_location(void)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_walk_pools
declaration	int pool_walk_pools(pool_conf_t *conf, void *arg, int (*callback)(pool_conf_t *conf, pool_t *pool, void *arg))
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_walk_resources
declaration	int pool_walk_resources(pool_conf_t *conf, pool_t *pool, void *arg, int (*callback)(pool_conf_t *conf, pool_resource_t *res, void *arg))
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_walk_components
declaration	int pool_walk_components(pool_conf_t *conf, pool_resource_t *res, void *arg, int (*callback)(pool_conf_t *conf, pool_component_t *comp, void *arg))
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_get_resource_binding
declaration	char *pool_get_resource_binding(const char *resource_type, pid_t pid)
include		<pool.h>
arch		all
version		SUNWprivate_1.1
end

function	pool_resource_type_list
declaration	int pool_resource_type_list(const char **typelist, uint_t *numtypes);
include		<pool.h>
arch		all
version		SUNWprivate_1.2
end

function	pool_get_status
declaration	int pool_get_status(int *state);
include		<pool.h>
arch		all
version		SUNWprivate_1.2
end

function	pool_set_status
declaration	int pool_set_status(int state);
include		<pool.h>
arch		all
version		SUNWprivate_1.2
end

function	pool_conf_update
declaration	int pool_conf_update(const pool_conf_t *conf, int *changed);
include		<pool.h>
arch		all
version		SUNWprivate_1.2
end
