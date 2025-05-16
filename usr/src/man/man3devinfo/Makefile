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

MANSECT=	3devinfo

MANFILES=	di_binding_name.3devinfo		\
		di_child_node.3devinfo			\
		di_devfs_path.3devinfo			\
		di_devlink_dup.3devinfo			\
		di_devlink_init.3devinfo		\
		di_devlink_path.3devinfo		\
		di_devlink_walk.3devinfo		\
		di_init.3devinfo			\
		di_link_next_by_node.3devinfo		\
		di_link_spectype.3devinfo		\
		di_lnode_name.3devinfo			\
		di_lnode_next.3devinfo			\
		di_minor_devt.3devinfo			\
		di_minor_next.3devinfo			\
		di_node_private_set.3devinfo		\
		di_path_bus_addr.3devinfo		\
		di_path_client_next_path.3devinfo	\
		di_path_prop_bytes.3devinfo		\
		di_path_prop_lookup_bytes.3devinfo	\
		di_path_prop_next.3devinfo		\
		di_prom_init.3devinfo			\
		di_prom_prop_data.3devinfo		\
		di_prom_prop_lookup_bytes.3devinfo	\
		di_prop_bytes.3devinfo			\
		di_prop_lookup_bytes.3devinfo		\
		di_prop_next.3devinfo			\
		di_walk_link.3devinfo			\
		di_walk_lnode.3devinfo			\
		di_walk_minor.3devinfo			\
		di_walk_node.3devinfo

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(MANLINK_SRCS)
	$(MANLINK_INSTALL)
