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

MANSECT=	3commputil

MANFILES=	sdp_add_origin.3commputil		\
		sdp_clone_session.3commputil		\
		sdp_delete_all_field.3commputil		\
		sdp_delete_media.3commputil		\
		sdp_find_attribute.3commputil		\
		sdp_find_media.3commputil		\
		sdp_find_media_rtpmap.3commputil	\
		sdp_new_session.3commputil		\
		sdp_parse.3commputil			\
		sdp_session_to_str.3commputil

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(MANLINK_SRCS)
	$(MANLINK_INSTALL)
