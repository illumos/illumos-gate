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

MANSECT=	3picltree

MANFILES=	libpicltree.3picltree			\
		picld_log.3picltree			\
		picld_plugin_register.3picltree		\
		ptree_add_node.3picltree		\
		ptree_add_prop.3picltree		\
		ptree_create_and_add_node.3picltree	\
		ptree_create_and_add_prop.3picltree	\
		ptree_create_node.3picltree		\
		ptree_create_prop.3picltree		\
		ptree_create_table.3picltree		\
		ptree_find_node.3picltree		\
		ptree_get_first_prop.3picltree		\
		ptree_get_frutree_parent.3picltree	\
		ptree_get_next_by_row.3picltree		\
		ptree_get_node_by_path.3picltree	\
		ptree_get_prop_by_name.3picltree	\
		ptree_get_propinfo.3picltree		\
		ptree_get_propinfo_by_name.3picltree	\
		ptree_get_propval.3picltree		\
		ptree_get_root.3picltree		\
		ptree_init_propinfo.3picltree		\
		ptree_post_event.3picltree		\
		ptree_register_handler.3picltree	\
		ptree_unregister_handler.3picltree	\
		ptree_update_propval.3picltree		\
		ptree_walk_tree_by_class.3picltree

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(MANLINK_SRCS)
	$(MANLINK_INSTALL)
