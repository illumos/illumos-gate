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
# Copyright 2012 Nexenta Systems, Inc. All rights reserved.
#

file path=usr/share/man/man3devinfo/di_binding_name.3devinfo
file path=usr/share/man/man3devinfo/di_child_node.3devinfo
file path=usr/share/man/man3devinfo/di_devfs_path.3devinfo
file path=usr/share/man/man3devinfo/di_devlink_dup.3devinfo
file path=usr/share/man/man3devinfo/di_devlink_init.3devinfo
file path=usr/share/man/man3devinfo/di_devlink_path.3devinfo
file path=usr/share/man/man3devinfo/di_devlink_walk.3devinfo
file path=usr/share/man/man3devinfo/di_init.3devinfo
file path=usr/share/man/man3devinfo/di_link_next_by_node.3devinfo
file path=usr/share/man/man3devinfo/di_link_spectype.3devinfo
file path=usr/share/man/man3devinfo/di_lnode_name.3devinfo
file path=usr/share/man/man3devinfo/di_lnode_next.3devinfo
file path=usr/share/man/man3devinfo/di_minor_devt.3devinfo
file path=usr/share/man/man3devinfo/di_minor_next.3devinfo
file path=usr/share/man/man3devinfo/di_node_private_set.3devinfo
file path=usr/share/man/man3devinfo/di_path_bus_addr.3devinfo
file path=usr/share/man/man3devinfo/di_path_client_next_path.3devinfo
file path=usr/share/man/man3devinfo/di_path_prop_bytes.3devinfo
file path=usr/share/man/man3devinfo/di_path_prop_lookup_bytes.3devinfo
file path=usr/share/man/man3devinfo/di_path_prop_next.3devinfo
file path=usr/share/man/man3devinfo/di_prom_init.3devinfo
file path=usr/share/man/man3devinfo/di_prom_prop_data.3devinfo
file path=usr/share/man/man3devinfo/di_prom_prop_lookup_bytes.3devinfo
file path=usr/share/man/man3devinfo/di_prop_bytes.3devinfo
file path=usr/share/man/man3devinfo/di_prop_lookup_bytes.3devinfo
file path=usr/share/man/man3devinfo/di_prop_next.3devinfo
file path=usr/share/man/man3devinfo/di_walk_link.3devinfo
file path=usr/share/man/man3devinfo/di_walk_lnode.3devinfo
file path=usr/share/man/man3devinfo/di_walk_minor.3devinfo
file path=usr/share/man/man3devinfo/di_walk_node.3devinfo
link path=usr/share/man/man3devinfo/di_bus_addr.3devinfo \
    target=di_binding_name.3devinfo
link path=usr/share/man/man3devinfo/di_compatible_names.3devinfo \
    target=di_binding_name.3devinfo
link path=usr/share/man/man3devinfo/di_devfs_minor_path.3devinfo \
    target=di_devfs_path.3devinfo
link path=usr/share/man/man3devinfo/di_devfs_path_free.3devinfo \
    target=di_devfs_path.3devinfo
link path=usr/share/man/man3devinfo/di_devid.3devinfo \
    target=di_binding_name.3devinfo
link path=usr/share/man/man3devinfo/di_devlink_content.3devinfo \
    target=di_devlink_path.3devinfo
link path=usr/share/man/man3devinfo/di_devlink_fini.3devinfo \
    target=di_devlink_init.3devinfo
link path=usr/share/man/man3devinfo/di_devlink_free.3devinfo \
    target=di_devlink_dup.3devinfo
link path=usr/share/man/man3devinfo/di_devlink_type.3devinfo \
    target=di_devlink_path.3devinfo
link path=usr/share/man/man3devinfo/di_driver_major.3devinfo \
    target=di_binding_name.3devinfo
link path=usr/share/man/man3devinfo/di_driver_name.3devinfo \
    target=di_binding_name.3devinfo
link path=usr/share/man/man3devinfo/di_driver_ops.3devinfo \
    target=di_binding_name.3devinfo
link path=usr/share/man/man3devinfo/di_drv_first_node.3devinfo \
    target=di_child_node.3devinfo
link path=usr/share/man/man3devinfo/di_drv_next_node.3devinfo \
    target=di_child_node.3devinfo
link path=usr/share/man/man3devinfo/di_fini.3devinfo target=di_init.3devinfo
link path=usr/share/man/man3devinfo/di_instance.3devinfo \
    target=di_binding_name.3devinfo
link path=usr/share/man/man3devinfo/di_link_next_by_lnode.3devinfo \
    target=di_link_next_by_node.3devinfo
link path=usr/share/man/man3devinfo/di_link_private_get.3devinfo \
    target=di_node_private_set.3devinfo
link path=usr/share/man/man3devinfo/di_link_private_set.3devinfo \
    target=di_node_private_set.3devinfo
link path=usr/share/man/man3devinfo/di_link_to_lnode.3devinfo \
    target=di_link_spectype.3devinfo
link path=usr/share/man/man3devinfo/di_lnode_devinfo.3devinfo \
    target=di_lnode_name.3devinfo
link path=usr/share/man/man3devinfo/di_lnode_devt.3devinfo \
    target=di_lnode_name.3devinfo
link path=usr/share/man/man3devinfo/di_lnode_private_get.3devinfo \
    target=di_node_private_set.3devinfo
link path=usr/share/man/man3devinfo/di_lnode_private_set.3devinfo \
    target=di_node_private_set.3devinfo
link path=usr/share/man/man3devinfo/di_minor_name.3devinfo \
    target=di_minor_devt.3devinfo
link path=usr/share/man/man3devinfo/di_minor_nodetype.3devinfo \
    target=di_minor_devt.3devinfo
link path=usr/share/man/man3devinfo/di_minor_private_get.3devinfo \
    target=di_node_private_set.3devinfo
link path=usr/share/man/man3devinfo/di_minor_private_set.3devinfo \
    target=di_node_private_set.3devinfo
link path=usr/share/man/man3devinfo/di_minor_spectype.3devinfo \
    target=di_minor_devt.3devinfo
link path=usr/share/man/man3devinfo/di_node_name.3devinfo \
    target=di_binding_name.3devinfo
link path=usr/share/man/man3devinfo/di_node_private_get.3devinfo \
    target=di_node_private_set.3devinfo
link path=usr/share/man/man3devinfo/di_nodeid.3devinfo \
    target=di_binding_name.3devinfo
link path=usr/share/man/man3devinfo/di_parent_node.3devinfo \
    target=di_child_node.3devinfo
link path=usr/share/man/man3devinfo/di_path_client_devfs_path.3devinfo \
    target=di_devfs_path.3devinfo
link path=usr/share/man/man3devinfo/di_path_client_node.3devinfo \
    target=di_path_bus_addr.3devinfo
link path=usr/share/man/man3devinfo/di_path_devfs_path.3devinfo \
    target=di_devfs_path.3devinfo
link path=usr/share/man/man3devinfo/di_path_instance.3devinfo \
    target=di_path_bus_addr.3devinfo
link path=usr/share/man/man3devinfo/di_path_node_name.3devinfo \
    target=di_path_bus_addr.3devinfo
link path=usr/share/man/man3devinfo/di_path_phci_next_path.3devinfo \
    target=di_path_client_next_path.3devinfo
link path=usr/share/man/man3devinfo/di_path_phci_node.3devinfo \
    target=di_path_bus_addr.3devinfo
link path=usr/share/man/man3devinfo/di_path_private_get.3devinfo \
    target=di_node_private_set.3devinfo
link path=usr/share/man/man3devinfo/di_path_private_set.3devinfo \
    target=di_node_private_set.3devinfo
link path=usr/share/man/man3devinfo/di_path_prop_int64s.3devinfo \
    target=di_path_prop_bytes.3devinfo
link path=usr/share/man/man3devinfo/di_path_prop_ints.3devinfo \
    target=di_path_prop_bytes.3devinfo
link path=usr/share/man/man3devinfo/di_path_prop_lookup_int64s.3devinfo \
    target=di_path_prop_lookup_bytes.3devinfo
link path=usr/share/man/man3devinfo/di_path_prop_lookup_ints.3devinfo \
    target=di_path_prop_lookup_bytes.3devinfo
link path=usr/share/man/man3devinfo/di_path_prop_lookup_strings.3devinfo \
    target=di_path_prop_lookup_bytes.3devinfo
link path=usr/share/man/man3devinfo/di_path_prop_name.3devinfo \
    target=di_path_prop_bytes.3devinfo
link path=usr/share/man/man3devinfo/di_path_prop_strings.3devinfo \
    target=di_path_prop_bytes.3devinfo
link path=usr/share/man/man3devinfo/di_path_prop_type.3devinfo \
    target=di_path_prop_bytes.3devinfo
link path=usr/share/man/man3devinfo/di_path_state.3devinfo \
    target=di_path_bus_addr.3devinfo
link path=usr/share/man/man3devinfo/di_prom_fini.3devinfo \
    target=di_prom_init.3devinfo
link path=usr/share/man/man3devinfo/di_prom_prop_lookup_ints.3devinfo \
    target=di_prom_prop_lookup_bytes.3devinfo
link path=usr/share/man/man3devinfo/di_prom_prop_lookup_strings.3devinfo \
    target=di_prom_prop_lookup_bytes.3devinfo
link path=usr/share/man/man3devinfo/di_prom_prop_name.3devinfo \
    target=di_prom_prop_data.3devinfo
link path=usr/share/man/man3devinfo/di_prom_prop_next.3devinfo \
    target=di_prom_prop_data.3devinfo
link path=usr/share/man/man3devinfo/di_prop_devt.3devinfo \
    target=di_prop_bytes.3devinfo
link path=usr/share/man/man3devinfo/di_prop_int64.3devinfo \
    target=di_prop_bytes.3devinfo
link path=usr/share/man/man3devinfo/di_prop_ints.3devinfo \
    target=di_prop_bytes.3devinfo
link path=usr/share/man/man3devinfo/di_prop_lookup_int64.3devinfo \
    target=di_prop_lookup_bytes.3devinfo
link path=usr/share/man/man3devinfo/di_prop_lookup_ints.3devinfo \
    target=di_prop_lookup_bytes.3devinfo
link path=usr/share/man/man3devinfo/di_prop_lookup_strings.3devinfo \
    target=di_prop_lookup_bytes.3devinfo
link path=usr/share/man/man3devinfo/di_prop_name.3devinfo \
    target=di_prop_bytes.3devinfo
link path=usr/share/man/man3devinfo/di_prop_strings.3devinfo \
    target=di_prop_bytes.3devinfo
link path=usr/share/man/man3devinfo/di_prop_type.3devinfo \
    target=di_prop_bytes.3devinfo
link path=usr/share/man/man3devinfo/di_sibling_node.3devinfo \
    target=di_child_node.3devinfo
