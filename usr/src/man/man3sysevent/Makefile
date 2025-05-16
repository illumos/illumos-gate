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

MANSECT=	3sysevent

MANFILES=	sysevent_bind_handle.3sysevent		\
		sysevent_free.3sysevent			\
		sysevent_get_attr_list.3sysevent	\
		sysevent_get_class_name.3sysevent	\
		sysevent_get_vendor_name.3sysevent	\
		sysevent_post_event.3sysevent		\
		sysevent_subscribe_event.3sysevent	\
		sysevents.3sysevent

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(MANLINK_SRCS)
	$(MANLINK_INSTALL)
