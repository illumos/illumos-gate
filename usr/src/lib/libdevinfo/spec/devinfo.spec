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
# lib/libdevinfo/spec/devinfo.spec

function	di_init
include		<libdevinfo.h>
declaration	di_node_t di_init(const char *phys_path, uint_t flag)
version		SUNW_1.1
end		

function	di_fini
include		<libdevinfo.h>
declaration	void di_fini(di_node_t root)
version		SUNW_1.1
end		

function	di_parent_node
include		<libdevinfo.h>
declaration	di_node_t di_parent_node(di_node_t node)
version		SUNW_1.1
end		

function	di_sibling_node
include		<libdevinfo.h>
declaration	di_node_t di_sibling_node(di_node_t node)
version		SUNW_1.1
end		

function	di_child_node
include		<libdevinfo.h>
declaration	di_node_t di_child_node(di_node_t node)
version		SUNW_1.1
end		

function	di_drv_first_node
include		<libdevinfo.h>
declaration	di_node_t di_drv_first_node(const char *drv_name, \
			di_node_t root)
version		SUNW_1.1
end		

function	di_drv_next_node
include		<libdevinfo.h>
declaration	di_node_t di_drv_next_node(di_node_t node)
version		SUNW_1.1
end		

function	di_walk_node
include		<libdevinfo.h>
declaration	int di_walk_node(di_node_t root, uint_t flag, void *arg, \
			int (*node_callback)(di_node_t, void *))
version		SUNW_1.1
end		

function	di_walk_minor
include		<libdevinfo.h>
declaration	int di_walk_minor(di_node_t root, const char *minor_type, \
			uint_t flag, void *arg, \
			int (*minor_callback)(di_node_t, di_minor_t, void *))
version		SUNW_1.1
end		

function	di_node_name
include		<libdevinfo.h>
declaration	char * di_node_name(di_node_t node)
version		SUNW_1.1
end		

function	di_bus_addr
include		<libdevinfo.h>
declaration	char * di_bus_addr(di_node_t node)
version		SUNW_1.1
end		

function	di_binding_name
include		<libdevinfo.h>
declaration	char * di_binding_name(di_node_t node)
version		SUNW_1.1
end		

function	di_compatible_names
include		<libdevinfo.h>
declaration	int di_compatible_names(di_node_t node, char **names)
version		SUNW_1.1
end		

function	di_instance
include		<libdevinfo.h>
declaration	int di_instance(di_node_t node)
version		SUNW_1.1
end		

function	di_nodeid
include		<libdevinfo.h>
declaration	int di_nodeid(di_node_t node)
version		SUNW_1.1
end		

function	di_state
include		<libdevinfo.h>
declaration	uint_t di_state(di_node_t node)
version		SUNW_1.1
end		

function	di_devid
include		<libdevinfo.h>
declaration	ddi_devid_t di_devid(di_node_t node)
version		SUNW_1.1
end		

function	di_driver_name
include		<libdevinfo.h>
declaration	char * di_driver_name(di_node_t node)
version		SUNW_1.1
end		

function	di_driver_ops
include		<libdevinfo.h>
declaration	uint_t di_driver_ops(di_node_t node)
version		SUNW_1.1
end		

function	di_devfs_path
include		<libdevinfo.h>
declaration	char * di_devfs_path(di_node_t node)
version		SUNW_1.1
end		

function	di_devfs_path_free
include		<libdevinfo.h>
declaration	void di_devfs_path_free(char *buf)
version		SUNW_1.1
end		

function	di_minor_next
include		<libdevinfo.h>
declaration	di_minor_t di_minor_next(di_node_t node, di_minor_t minor)
version		SUNW_1.1
end		

function	di_minor_type
include		<libdevinfo.h>
declaration	ddi_minor_type di_minor_type(di_minor_t minor)
version		SUNW_1.1
end		

function	di_minor_name
include		<libdevinfo.h>
declaration	char * di_minor_name(di_minor_t minor)
version		SUNW_1.1
end		

function	di_minor_devt
include		<libdevinfo.h>
declaration	dev_t di_minor_devt(di_minor_t minor)
version		SUNW_1.1
end		

function	di_minor_spectype
include		<libdevinfo.h>
declaration	int di_minor_spectype(di_minor_t minor)
version		SUNW_1.1
end		

function	di_minor_nodetype
include		<libdevinfo.h>
declaration	char * di_minor_nodetype(di_minor_t minor)
version		SUNW_1.1
end		

function	di_prop_next
include		<libdevinfo.h>
declaration	di_prop_t di_prop_next(di_node_t node, di_prop_t prop)
version		SUNW_1.1
end		

function	di_prop_devt
include		<libdevinfo.h>
declaration	dev_t di_prop_devt(di_prop_t prop)
version		SUNW_1.1
end		

function	di_prop_name
include		<libdevinfo.h>
declaration	char * di_prop_name(di_prop_t prop)
version		SUNW_1.1
end		

function	di_prop_type
include		<libdevinfo.h>
declaration	int di_prop_type(di_prop_t prop)
version		SUNW_1.1
end		

function	di_prop_ints
include		<libdevinfo.h>
declaration	int di_prop_ints(di_prop_t prop, int **prop_data)
version		SUNW_1.1
end		

function	di_prop_int64
include		<libdevinfo.h>
declaration	int di_prop_int64(di_prop_t prop, int64_t **prop_data)
version		SUNW_1.1
end

function	di_prop_strings
include		<libdevinfo.h>
declaration	int di_prop_strings(di_prop_t prop, char **prop_data)
version		SUNW_1.1
end		

function	di_prop_bytes
include		<libdevinfo.h>
declaration	int di_prop_bytes(di_prop_t prop, uchar_t **prop_data)
version		SUNW_1.1
end		

function	di_prop_lookup_ints
include		<libdevinfo.h>
declaration	int di_prop_lookup_ints(dev_t dev, di_node_t node, \
			const char *prop_name, int **prop_data)
version		SUNW_1.1
end		

function	di_prop_lookup_int64
include		<libdevinfo.h>
declaration	int di_prop_lookup_int64(dev_t dev, di_node_t node, \
			const char *prop_name, int64_t **prop_data)
version		SUNW_1.1
end

function	di_prop_lookup_strings
include		<libdevinfo.h>
declaration	int di_prop_lookup_strings(dev_t dev, di_node_t node, \
			const char *prop_name, char **prop_data)
version		SUNW_1.1
end		

function	di_prop_lookup_bytes
include		<libdevinfo.h>
declaration	int di_prop_lookup_bytes(dev_t dev, di_node_t node, \
			const char *prop_name, uchar_t **prop_data)
version		SUNW_1.1
end		

function	di_prom_init
include		<libdevinfo.h>
declaration	di_prom_handle_t di_prom_init(void)
version		SUNW_1.1
end		

function	di_prom_fini
include		<libdevinfo.h>
declaration	void di_prom_fini(di_prom_handle_t ph)
version		SUNW_1.1
end		

function	di_prom_prop_next
include		<libdevinfo.h>
declaration	di_prom_prop_t di_prom_prop_next(di_prom_handle_t ph, \
			di_node_t node, di_prom_prop_t prom_prop)
version		SUNW_1.1
end		

function	di_prom_prop_name
include		<libdevinfo.h>
declaration	char * di_prom_prop_name(di_prom_prop_t prom_prop)
version		SUNW_1.1
end		

function	di_prom_prop_data
include		<libdevinfo.h>
declaration	int di_prom_prop_data(di_prom_prop_t prom_prop, \
			uchar_t **prom_prop_data)
version		SUNW_1.1
end		

function	di_prom_prop_lookup_ints
include		<libdevinfo.h>
declaration	int di_prom_prop_lookup_ints(di_prom_handle_t ph, \
			di_node_t node, const char *prom_prop_name, \
			int **prom_prop_data)
version		SUNW_1.1
end		

function	di_prom_prop_lookup_strings
include		<libdevinfo.h>
declaration	int di_prom_prop_lookup_strings(di_prom_handle_t ph, \
			di_node_t node, const char *prom_prop_name, \
			char **prom_prop_data)
version		SUNW_1.1
end		

function	di_prom_prop_lookup_bytes
include		<libdevinfo.h>
declaration	int di_prom_prop_lookup_bytes(di_prom_handle_t ph, \
			di_node_t node, const char *prom_prop_name, \
			uchar_t **prom_prop_data)
version		SUNW_1.1
end		

function	devfs_path_to_drv
include		<libdevinfo.h>, <device_info.h>
declaration	int devfs_path_to_drv(char *devfs_path, char *drv_buf)
version		SUNWprivate_1.1
end		

function	devfs_dev_to_prom_name
include		<libdevinfo.h>
declaration	int devfs_dev_to_prom_name(char *dev_path, char *prom_path)
version		SUNWprivate_1.1
end		

function	devfs_resolve_aliases
include		<libdevinfo.h>
declaration	char * devfs_resolve_aliases(char *drv)
version		SUNWprivate_1.1
end		

function	devfs_bootdev_set_list
include		<libdevinfo.h>
declaration	int devfs_bootdev_set_list(const char *dev_name, \
			const u_int options)
version		SUNWprivate_1.1
end		

function	devfs_bootdev_modifiable
include		<libdevinfo.h>
declaration	int devfs_bootdev_modifiable(void)
version		SUNWprivate_1.1
end		

function	devfs_bootdev_get_list
include		<libdevinfo.h>
declaration	int devfs_bootdev_get_list(const char *default_root, \
			struct boot_dev ***bootdev_list)
version		SUNWprivate_1.1
end		

function	devfs_bootdev_free_list
include		<libdevinfo.h>
declaration	void devfs_bootdev_free_list(struct boot_dev **array)
version		SUNWprivate_1.1
end		

function	devfs_get_all_prom_names
include		<libdevinfo.h>
declaration	int devfs_get_all_prom_names(const char *, uint_t, \
			struct devfs_prom_path **)
version		SUNWprivate_1.1
end		

function	devfs_free_all_prom_names
include		<libdevinfo.h>
declaration	void devfs_free_all_prom_names(struct devfs_prom_path *)
version		SUNWprivate_1.1
end

function	devfs_get_prom_names
include		<libdevinfo.h>
declaration	int devfs_get_prom_names(const char *dev_name, \
			u_int options, char ***prom_list)
version		SUNWprivate_1.1
end		


#
# Evolving (LDI PSARC/2001/769 and PSARC/2003/537)
#
function	di_node_private_set
include		<libdevinfo.h>
declaration	void di_node_private_set(di_node_t node, void *data)
version		SUNW_1.3
end		

function	di_node_private_get
include		<libdevinfo.h>
declaration	void *di_node_private_get(di_node_t node)
version		SUNW_1.3
end		

function	di_minor_private_set
include		<libdevinfo.h>
declaration	void di_minor_private_set(di_minor_t minor, void *data)
version		SUNW_1.3
end		

function	di_minor_private_get
include		<libdevinfo.h>
declaration	void *di_minor_private_get(di_minor_t minor)
version		SUNW_1.3
end		

function	di_lnode_private_set
include		<libdevinfo.h>
declaration	void di_lnode_private_set(di_lnode_t lnode, void *data)
version		SUNW_1.3
end		

function	di_lnode_private_get
include		<libdevinfo.h>
declaration	void *di_lnode_private_get(di_lnode_t lnode)
version		SUNW_1.3
end		

function	di_link_private_set
include		<libdevinfo.h>
declaration	void di_link_private_set(di_link_t link, void *data)
version		SUNW_1.3
end		

function	di_link_private_get
include		<libdevinfo.h>
declaration	void *di_link_private_get(di_link_t link)
version		SUNW_1.3
end		

function	di_walk_link
include		<libdevinfo.h>
declaration	int di_walk_link(di_node_t root, uint_t flag, uint_t endpoint, \
			void *arg, int (*link_callback)(di_link_t, void *))
version		SUNW_1.3
end		

function	di_walk_lnode
include		<libdevinfo.h>
declaration	int di_walk_lnode(di_node_t root, uint_t flag, void *arg, \
			int (*lnode_callback)(di_lnode_t, void *))
version		SUNW_1.3
end		

function	di_link_next_by_node
include		<libdevinfo.h>
declaration	di_link_t di_link_next_by_node(di_node_t node, di_link_t link, \
			uint_t endpoint)
version		SUNW_1.3
end		

function	di_link_next_by_lnode
include		<libdevinfo.h>
declaration	di_link_t di_link_next_by_lnode(di_lnode_t lnode, \
			di_link_t link, uint_t endpoint)
version		SUNW_1.3
end		

function	di_link_to_lnode
include		<libdevinfo.h>
declaration	di_lnode_t di_link_to_lnode(di_link_t link, uint_t endpoint)
version		SUNW_1.3
end		

function	di_lnode_next
include		<libdevinfo.h>
declaration	di_lnode_t di_lnode_next(di_node_t node, di_lnode_t lnode)
version		SUNW_1.3
end		

function	di_lnode_name
include		<libdevinfo.h>
declaration	char *di_lnode_name(di_lnode_t lnode)
version		SUNW_1.3
end		

function	di_lnode_devinfo
include		<libdevinfo.h>
declaration	di_node_t di_lnode_devinfo(di_lnode_t lnode)
version		SUNW_1.3
end		

function	di_lnode_devt
include		<libdevinfo.h>
declaration	int di_lnode_devt(di_lnode_t lnode, dev_t *devt)
version		SUNW_1.3
end		

function	di_link_spectype
include		<libdevinfo.h>
declaration	int di_link_spectype(di_link_t link)
version		SUNW_1.3
end		

function	di_driver_major
include		<libdevinfo.h>
declaration	int di_driver_major(di_node_t node)
version		SUNW_1.3
end		

function	di_devfs_minor_path
include		<libdevinfo.h>
declaration	char * di_devfs_minor_path(di_minor_t minor)
version		SUNW_1.3
end		


#
# Sun private devlinks interfaces
#
function	di_devlink_init
include		<libdevinfo.h>
declaration	di_devlink_handle_t di_devlink_init(const char *name, \
			uint_t flags)
version		SUNWprivate_1.1
end		

function	di_devlink_fini
include		<libdevinfo.h>
declaration	int di_devlink_fini(di_devlink_handle_t *hdlp)
version		SUNWprivate_1.1
end		

function	di_devlink_walk
include		<libdevinfo.h>
declaration	int di_devlink_walk(di_devlink_handle_t hdl, \
			const char *re, const char *minor_path, \
			uint_t flags, void *arg, \
			int (*fcn)(di_devlink_t, void *))
			
version		SUNWprivate_1.1
end		

function	di_devlink_path
include		<libdevinfo.h>
declaration	const char *di_devlink_path(di_devlink_t devlink)
version		SUNWprivate_1.1
end		

function	di_devlink_content
include		<libdevinfo.h>
declaration	const char *di_devlink_content(di_devlink_t devlink)
version		SUNWprivate_1.1
end		

function	di_devlink_type
include		<libdevinfo.h>
declaration	int di_devlink_type(di_devlink_t devlink)
version		SUNWprivate_1.1
end		

function	di_devlink_dup
include		<libdevinfo.h>
declaration	di_devlink_t di_devlink_dup(di_devlink_t devlink)
version		SUNWprivate_1.1
end		

function	di_devlink_free
include		<libdevinfo.h>
declaration	int di_devlink_free(di_devlink_t devlink)
version		SUNWprivate_1.1
end		

#
# Project private devlinks interfaces
#
function	di_devlink_open
include		<libdevinfo.h>
declaration	di_devlink_handle_t di_devlink_open(const char *root_dir, \
			uint_t flags)
version		SUNWprivate_1.1
end		

function	di_devlink_close
include		<libdevinfo.h>
declaration	int di_devlink_close(di_devlink_handle_t *hdlp, int flag)
version		SUNWprivate_1.1
end		

function	di_devlink_rm_link
include		<libdevinfo.h>
declaration	int di_devlink_rm_link(di_devlink_handle_t hdl, \
			const char *link)
version		SUNWprivate_1.1
end		

function	di_devlink_add_link
include		<libdevinfo.h>
declaration	int di_devlink_add_link(di_devlink_handle_t hdl, \
			const char *link, const char *content, int flags)
version		SUNWprivate_1.1
end		

function	di_devlink_update
include		<libdevinfo.h>
declaration	int di_devlink_update(di_devlink_handle_t hdl)
version		SUNWprivate_1.1
end		

function	di_devlink_init_root
include		<libdevinfo.h>
declaration	di_devlink_handle_t di_devlink_init_root(const char *root, \
			const char *name, uint_t flags)
version		SUNWprivate_1.1
end		
#
# Consolidation private PSARC 1997/127
#
function	di_init_impl
include		<libdevinfo.h>
declaration	di_node_t di_init_impl(const char *phys_path, uint_t flag, \
			struct di_priv_data *priv)
version		SUNWprivate_1.1
end		

function	di_init_driver
include		<libdevinfo.h>
declaration	di_node_t di_init_driver(const char *drv_name, uint_t flag)
version		SUNWprivate_1.1
end		

function	di_prop_drv_next
include		<libdevinfo.h>
declaration	di_prop_t di_prop_drv_next(di_node_t node, di_prop_t prop)
version		SUNWprivate_1.1
end		

function	di_prop_sys_next
include		<libdevinfo.h>
declaration	di_prop_t di_prop_sys_next(di_node_t node, di_prop_t prop)
version		SUNWprivate_1.1
end		

function	di_prop_global_next
include		<libdevinfo.h>
declaration	di_prop_t di_prop_global_next(di_node_t node, di_prop_t prop)
version		SUNWprivate_1.1
end		

function	di_prop_hw_next
include		<libdevinfo.h>
declaration	di_prop_t di_prop_hw_next(di_node_t node, di_prop_t prop)
version		SUNWprivate_1.1
end		

function	di_prop_rawdata
include		<libdevinfo.h>
declaration	int di_prop_rawdata(di_prop_t prop, uchar_t **prop_data)
version		SUNWprivate_1.1
end		

function	di_parent_private_data
include		<libdevinfo.h>
declaration	void * di_parent_private_data(di_node_t node)
version		SUNWprivate_1.1
end		

function	di_driver_private_data
include		<libdevinfo.h>
declaration	void * di_driver_private_data(di_node_t node)
version		SUNWprivate_1.1
end		

function	di_node_state
include		<libdevinfo.h>
declaration	ddi_node_state_t di_node_state(di_node_t node)
version		SUNWprivate_1.1
end		


#
# Consolidation private PSARC 1999/647
#
# di_path_next is replaced by di_path_next_phci/client
#
function	di_path_next
include		<libdevinfo.h>
declaration	di_path_t di_path_next(di_node_t node, di_path_t path)
version		SUNWprivate_1.1
end

function	di_path_next_phci
include		<libdevinfo.h>
declaration	di_path_t di_path_next_phci(di_node_t node, di_path_t path)
version		SUNWprivate_1.1
end

function	di_path_next_client
include		<libdevinfo.h>
declaration	di_path_t di_path_next_client(di_node_t node, di_path_t path)
version		SUNWprivate_1.1
end

#
# Consolidation private PSARC 1999/647
#
function	di_path_state
include		<libdevinfo.h>
declaration	di_path_state_t di_path_state(di_path_t path)
version		SUNWprivate_1.1
end

#
# Consolidation private PSARC 1999/647
#
function	di_path_addr
include		<libdevinfo.h>
declaration	char *di_path_addr(di_path_t path, char *buf)
version		SUNWprivate_1.1
end

#
# Consolidation private PSARC 1999/647
#
function	di_path_client_node
include		<libdevinfo.h>
declaration	di_node_t di_path_client_node(di_path_t path)
version		SUNWprivate_1.1
end

#
# Consolidation private PSARC 1999/647
#
function	di_path_phci_node
include		<libdevinfo.h>
declaration	di_node_t di_path_phci_node(di_path_t path)
version		SUNWprivate_1.1
end

#
# Consolidation private PSARC 1999/647
#
function	di_path_prop_next
include		<libdevinfo.h>
declaration	di_path_prop_t di_path_prop_next(di_path_t path, \
			di_path_prop_t prop)
version		SUNWprivate_1.1
end

#
# Consolidation private PSARC 1999/647
#
function	di_path_prop_name
include		<libdevinfo.h>
declaration	char* di_path_prop_name(di_path_prop_t prop)
version		SUNWprivate_1.1
end

#
# Consolidation private PSARC 1999/647
#
function	di_path_prop_type
include		<libdevinfo.h>
declaration	int di_path_prop_type(di_path_prop_t prop)
version		SUNWprivate_1.1
end

#
# Consolidation private PSARC 1999/647
#
function	di_path_prop_len
include		<libdevinfo.h>
declaration	int di_path_prop_len(di_path_prop_t prop)
version		SUNWprivate_1.1
end

#
# Consolidation private PSARC 1999/647
#
function	di_path_prop_bytes
include		<libdevinfo.h>
declaration	int di_path_prop_bytes(di_path_prop_t prop, uchar_t **prop_data)
version		SUNWprivate_1.1
end

#
# Consolidation private PSARC 1999/647
#
function	di_path_prop_ints
include		<libdevinfo.h>
declaration	int di_path_prop_ints(di_path_prop_t prop, int **prop_data)
version		SUNWprivate_1.1
end

#
# Consolidation private PSARC 1999/647
#
function	di_path_prop_int64s
include		<libdevinfo.h>
declaration	int di_path_prop_int64s(di_path_prop_t prop, \
			int64_t **prop_data)
version		SUNWprivate_1.1
end

#
# Consolidation private PSARC 1999/647
#
function	di_path_prop_strings
include		<libdevinfo.h>
declaration	int di_path_prop_strings(di_path_prop_t prop, char **prop_data)
version		SUNWprivate_1.1
end

#
# Consolidation private PSARC 1999/647
#
function	di_path_prop_lookup_bytes
include		<libdevinfo.h>
declaration	int di_path_prop_lookup_bytes(di_path_t path, \
			const char *prop_name, uchar_t **prop_data)
version		SUNWprivate_1.1
end

#
# Consolidation private PSARC 1999/647
#
function	di_path_prop_lookup_ints
include		<libdevinfo.h>
declaration	int di_path_prop_lookup_ints(di_path_t path, \
			const char *prop_name, int **prop_data)
version		SUNWprivate_1.1
end

#
# Consolidation private PSARC 1999/647
#
function	di_path_prop_lookup_int64s
include		<libdevinfo.h>
declaration	int di_path_prop_lookup_int64s(di_path_t path, \
			const char *prop_name, int64_t **prop_data)
version		SUNWprivate_1.1
end

#
# Consolidation private PSARC 1999/647
#
function	di_path_prop_lookup_strings
include		<libdevinfo.h>
declaration	int di_path_prop_lookup_strings(di_path_t path, \
			const char *prop_name, char **prop_data)
version		SUNWprivate_1.1
end

#
# Project private (devfs project)
#
function	di_minor_devinfo
include		<libdevinfo.h>
declaration	di_node_t di_minor_devinfo(di_minor_t minor)
version		SUNWprivate_1.1
end		

#
# Project private function (PSARC/2004/169)
#
function	di_lookup_node
include		<libdevinfo.h>
declaration	di_node_t di_lookup_node(di_node_t root, char *path)
version		SUNWprivate_1.1
end

#
# Project private function (devfsadmd)
#
function	di_devlink_cache_walk
include		<libdevinfo.h>
declaration	int di_devlink_cache_walk(di_devlink_handle_t hdp, \
		        const char *re, const char *path, \
		        uint_t flags, void *arg, \
		        int (*devlink_callback)(di_devlink_t, void *))
version		SUNWprivate_1.1
end

#
# Consolidation private PSARC 2003/612
#
function	di_devperm_login
include		<libdevinfo.h>
declaration	int di_devperm_login(const char *ttyn, uid_t uid, gid_t gid, \
			void (*errmsg)(char *errstring))
version		SUNWprivate_1.1
end		

function	di_devperm_logout
include		<libdevinfo.h>
declaration	int di_devperm_logout(const char *ttyn)
version		SUNWprivate_1.1
end		

#
# Private functions for solaris installation programs.
#
function	devfs_target2install
include		<device_info.h>
declaration	int devfs_target2install(const char *rootdir, \
			const char *devname, char *buf, size_t bufsz)
version		SUNWprivate_1.1
end

function	devfs_install2target
include		<device_info.h>
declaration	int devfs_install2target(const char *rootdir, \
			const char *devname, char *buf, size_t bufsz)
version		SUNWprivate_1.1
end

function	devfs_read_minor_perm
include		<device_info.h>
declaration	struct mperm *devfs_read_minor_perm( \
			void (*cb)(minorperm_err_t, int))
version		SUNWprivate_1.1
end

function	devfs_free_minor_perm
include		<device_info.h>
declaration	void devfs_free_minor_perm(struct mperm *)
version		SUNWprivate_1.1
end

function	devfs_load_minor_perm
include		<device_info.h>
declaration	int devfs_load_minor_perm(struct mperm *, \
			void (*cb)(minorperm_err_t, int))
version		SUNWprivate_1.1
end

function	devfs_add_minor_perm
include		<device_info.h>
declaration	int devfs_add_minor_perm(char *drv, \
			void (*cb)(minorperm_err_t, int))
version		SUNWprivate_1.1
end

function	devfs_rm_minor_perm
include		<device_info.h>
declaration	int devfs_rm_minor_perm(char *drv, \
			void (*cb)(minorperm_err_t, int))
version		SUNWprivate_1.1
end
