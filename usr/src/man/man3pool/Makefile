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

MANSECT=	3pool

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

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(MANLINK_SRCS)
	$(MANLINK_INSTALL)
