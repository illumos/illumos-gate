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

MANSECT= 	3iscsit

MANFILES= 	it_config_load.3iscsit		\
	 	it_ini_create.3iscsit		\
		it_portal_create.3iscsit	\
		it_tgt_create.3iscsit		\
		it_tpg_create.3iscsit

MANLINKS=	it_config_commit.3iscsit	\
		it_config_free.3iscsit		\
		it_config_setprop.3iscsit	\
		it_ini_delete.3iscsit		\
		it_ini_free.3iscsit		\
		it_ini_setprop.3iscsit		\
		it_portal_delete.3iscsit	\
		it_tgt_delete.3iscsit		\
		it_tgt_free.3iscsit		\
		it_tgt_setprop.3iscsit		\
		it_tpg_delete.3iscsit		\
		it_tpg_free.3iscsit		\
		it_tpgt_create.3iscsit		\
		it_tpgt_delete.3iscsit		\
		it_tpgt_free.3iscsit

it_config_commit.3iscsit	:= LINKSRC = it_config_load.3iscsit
it_config_free.3iscsit		:= LINKSRC = it_config_load.3iscsit
it_config_setprop.3iscsit	:= LINKSRC = it_config_load.3iscsit

it_ini_delete.3iscsit		:= LINKSRC = it_ini_create.3iscsit
it_ini_free.3iscsit		:= LINKSRC = it_ini_create.3iscsit
it_ini_setprop.3iscsit		:= LINKSRC = it_ini_create.3iscsit

it_portal_delete.3iscsit	:= LINKSRC = it_portal_create.3iscsit

it_tgt_delete.3iscsit		:= LINKSRC = it_tgt_create.3iscsit
it_tgt_free.3iscsit		:= LINKSRC = it_tgt_create.3iscsit
it_tgt_setprop.3iscsit		:= LINKSRC = it_tgt_create.3iscsit
it_tpgt_create.3iscsit		:= LINKSRC = it_tgt_create.3iscsit
it_tpgt_delete.3iscsit		:= LINKSRC = it_tgt_create.3iscsit
it_tpgt_free.3iscsit		:= LINKSRC = it_tgt_create.3iscsit

it_tpg_delete.3iscsit		:= LINKSRC = it_tpg_create.3iscsit
it_tpg_free.3iscsit		:= LINKSRC = it_tpg_create.3iscsit

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(ROOTMANLINKS)
