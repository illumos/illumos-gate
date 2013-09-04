#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet
# at http://www.illumos.org/license/CDDL.
#

#
# Copyright 2011, Richard Lowe
# Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
#

include		$(SRC)/Makefile.master

MANSECT= 	3pool

MANFILES=	pool_associate.3pool		\
	 	pool_component_info.3pool	\
	 	pool_component_to_elem.3pool	\
	 	pool_conf_alloc.3pool		\
	 	pool_dynamic_location.3pool	\
	 	pool_error.3pool		\
	 	pool_get_binding.3pool		\
	 	pool_get_pool.3pool		\
	 	pool_get_property.3pool		\
	 	pool_resource_create.3pool	\
	 	pool_value_alloc.3pool		\
	 	pool_walk_components.3pool

MANLINKS=	pool_conf_close.3pool			\
		pool_conf_commit.3pool			\
		pool_conf_export.3pool			\
		pool_conf_free.3pool			\
		pool_conf_info.3pool			\
		pool_conf_location.3pool		\
		pool_conf_open.3pool			\
		pool_conf_remove.3pool			\
		pool_conf_rollback.3pool		\
		pool_conf_status.3pool			\
		pool_conf_to_elem.3pool			\
		pool_conf_update.3pool			\
		pool_conf_validate.3pool		\
		pool_create.3pool			\
		pool_destroy.3pool			\
		pool_dissociate.3pool			\
		pool_get_owning_resource.3pool		\
		pool_get_resource.3pool			\
		pool_get_resource_binding.3pool		\
		pool_get_status.3pool			\
		pool_info.3pool				\
		pool_put_property.3pool			\
		pool_query_components.3pool		\
		pool_query_pool_resources.3pool		\
		pool_query_pools.3pool			\
		pool_query_resource_components.3pool	\
		pool_query_resources.3pool		\
		pool_resource_destroy.3pool		\
		pool_resource_info.3pool		\
		pool_resource_to_elem.3pool		\
		pool_resource_transfer.3pool		\
		pool_resource_type_list.3pool		\
		pool_resource_xtransfer.3pool		\
		pool_rm_property.3pool			\
		pool_set_binding.3pool			\
		pool_set_status.3pool			\
		pool_static_location.3pool		\
		pool_strerror.3pool			\
		pool_to_elem.3pool			\
		pool_value_free.3pool			\
		pool_value_get_bool.3pool		\
		pool_value_get_double.3pool		\
		pool_value_get_int64.3pool		\
		pool_value_get_name.3pool		\
		pool_value_get_string.3pool		\
		pool_value_get_type.3pool		\
		pool_value_get_uint64.3pool		\
		pool_value_set_bool.3pool		\
		pool_value_set_double.3pool		\
		pool_value_set_int64.3pool		\
		pool_value_set_name.3pool		\
		pool_value_set_string.3pool		\
		pool_value_set_uint64.3pool		\
		pool_version.3pool			\
		pool_walk_pools.3pool			\
		pool_walk_properties.3pool		\
		pool_walk_resources.3pool

pool_create.3pool			:= LINKSRC = pool_associate.3pool
pool_destroy.3pool			:= LINKSRC = pool_associate.3pool
pool_dissociate.3pool			:= LINKSRC = pool_associate.3pool
pool_info.3pool				:= LINKSRC = pool_associate.3pool
pool_query_pool_resources.3pool		:= LINKSRC = pool_associate.3pool

pool_get_owning_resource.3pool		:= LINKSRC = pool_component_info.3pool

pool_conf_to_elem.3pool			:= LINKSRC = pool_component_to_elem.3pool
pool_resource_to_elem.3pool		:= LINKSRC = pool_component_to_elem.3pool
pool_to_elem.3pool			:= LINKSRC = pool_component_to_elem.3pool

pool_conf_close.3pool			:= LINKSRC = pool_conf_alloc.3pool
pool_conf_commit.3pool			:= LINKSRC = pool_conf_alloc.3pool
pool_conf_export.3pool			:= LINKSRC = pool_conf_alloc.3pool
pool_conf_free.3pool			:= LINKSRC = pool_conf_alloc.3pool
pool_conf_info.3pool			:= LINKSRC = pool_conf_alloc.3pool
pool_conf_location.3pool		:= LINKSRC = pool_conf_alloc.3pool
pool_conf_open.3pool			:= LINKSRC = pool_conf_alloc.3pool
pool_conf_remove.3pool			:= LINKSRC = pool_conf_alloc.3pool
pool_conf_rollback.3pool		:= LINKSRC = pool_conf_alloc.3pool
pool_conf_status.3pool			:= LINKSRC = pool_conf_alloc.3pool
pool_conf_update.3pool			:= LINKSRC = pool_conf_alloc.3pool
pool_conf_validate.3pool		:= LINKSRC = pool_conf_alloc.3pool

pool_get_status.3pool			:= LINKSRC = pool_dynamic_location.3pool
pool_resource_type_list.3pool		:= LINKSRC = pool_dynamic_location.3pool
pool_set_status.3pool			:= LINKSRC = pool_dynamic_location.3pool
pool_static_location.3pool		:= LINKSRC = pool_dynamic_location.3pool
pool_version.3pool			:= LINKSRC = pool_dynamic_location.3pool

pool_strerror.3pool			:= LINKSRC = pool_error.3pool

pool_get_resource_binding.3pool		:= LINKSRC = pool_get_binding.3pool
pool_set_binding.3pool			:= LINKSRC = pool_get_binding.3pool

pool_get_resource.3pool			:= LINKSRC = pool_get_pool.3pool
pool_query_components.3pool		:= LINKSRC = pool_get_pool.3pool
pool_query_pools.3pool			:= LINKSRC = pool_get_pool.3pool
pool_query_resources.3pool		:= LINKSRC = pool_get_pool.3pool

pool_put_property.3pool			:= LINKSRC = pool_get_property.3pool
pool_rm_property.3pool			:= LINKSRC = pool_get_property.3pool
pool_walk_properties.3pool		:= LINKSRC = pool_get_property.3pool

pool_query_resource_components.3pool	:= LINKSRC = pool_resource_create.3pool
pool_resource_destroy.3pool		:= LINKSRC = pool_resource_create.3pool
pool_resource_info.3pool		:= LINKSRC = pool_resource_create.3pool
pool_resource_transfer.3pool		:= LINKSRC = pool_resource_create.3pool
pool_resource_xtransfer.3pool		:= LINKSRC = pool_resource_create.3pool

pool_value_free.3pool			:= LINKSRC = pool_value_alloc.3pool
pool_value_get_bool.3pool		:= LINKSRC = pool_value_alloc.3pool
pool_value_get_double.3pool		:= LINKSRC = pool_value_alloc.3pool
pool_value_get_int64.3pool		:= LINKSRC = pool_value_alloc.3pool
pool_value_get_name.3pool		:= LINKSRC = pool_value_alloc.3pool
pool_value_get_string.3pool		:= LINKSRC = pool_value_alloc.3pool
pool_value_get_type.3pool		:= LINKSRC = pool_value_alloc.3pool
pool_value_get_uint64.3pool		:= LINKSRC = pool_value_alloc.3pool
pool_value_set_bool.3pool		:= LINKSRC = pool_value_alloc.3pool
pool_value_set_double.3pool		:= LINKSRC = pool_value_alloc.3pool
pool_value_set_int64.3pool		:= LINKSRC = pool_value_alloc.3pool
pool_value_set_name.3pool		:= LINKSRC = pool_value_alloc.3pool
pool_value_set_string.3pool		:= LINKSRC = pool_value_alloc.3pool
pool_value_set_uint64.3pool		:= LINKSRC = pool_value_alloc.3pool

pool_walk_pools.3pool			:= LINKSRC = pool_walk_components.3pool
pool_walk_resources.3pool		:= LINKSRC = pool_walk_components.3pool

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(ROOTMANLINKS)
