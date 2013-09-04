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

MANSECT= 	3cfgadm

MANFILES= 	config_admin.3cfgadm

MANLINKS=	config_ap_id_cmp.3cfgadm	\
		config_change_state.3cfgadm	\
		config_list.3cfgadm		\
		config_list_ext.3cfgadm		\
		config_private_func.3cfgadm	\
		config_stat.3cfgadm		\
		config_strerror.3cfgadm		\
		config_test.3cfgadm		\
		config_unload_libs.3cfgadm

config_ap_id_cmp.3cfgadm	:= LINKSRC = config_admin.3cfgadm
config_change_state.3cfgadm	:= LINKSRC = config_admin.3cfgadm
config_list.3cfgadm		:= LINKSRC = config_admin.3cfgadm
config_list_ext.3cfgadm		:= LINKSRC = config_admin.3cfgadm
config_private_func.3cfgadm	:= LINKSRC = config_admin.3cfgadm
config_stat.3cfgadm		:= LINKSRC = config_admin.3cfgadm
config_strerror.3cfgadm		:= LINKSRC = config_admin.3cfgadm
config_test.3cfgadm		:= LINKSRC = config_admin.3cfgadm
config_unload_libs.3cfgadm	:= LINKSRC = config_admin.3cfgadm

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(ROOTMANLINKS)
