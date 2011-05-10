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

# Copyright 2011, Richard Lowe

include ../../Makefile.master

MANSECT = 	3picl

MANFILES =	libpicl.3picl			\
	 	picl_find_node.3picl		\
	 	picl_get_first_prop.3picl	\
	 	picl_get_frutree_parent.3picl	\
	 	picl_get_next_by_row.3picl	\
	 	picl_get_node_by_path.3picl	\
	 	picl_get_prop_by_name.3picl	\
	 	picl_get_propinfo.3picl		\
	 	picl_get_propinfo_by_name.3picl \
	 	picl_get_propval.3picl		\
	 	picl_get_root.3picl		\
	 	picl_initialize.3picl		\
	 	picl_set_propval.3picl		\
	 	picl_shutdown.3picl		\
	 	picl_strerror.3picl		\
	 	picl_wait.3picl			\
	 	picl_walk_tree_by_class.3picl

MANSOFILES =	picl_get_next_by_col.3picl	\
		picl_get_next_prop.3picl	\
		picl_get_propval_by_name.3picl	\
		picl_set_propval_by_name.3picl

MANFILES +=	$(MANSOFILES)

picl_get_next_prop.3picl	:= SOSRC = man3picl/picl_get_first_prop.3picl

picl_get_next_by_col.3picl	:= SOSRC = man3picl/picl_get_next_by_row.3picl

picl_get_propval_by_name.3picl	:= SOSRC = man3picl/picl_get_propval.3picl
picl_set_propval_by_name.3picl	:= SOSRC = man3picl/picl_set_propval.3picl

.KEEP_STATE:

include ../Makefile.man

install: $(ROOTMANFILES)
