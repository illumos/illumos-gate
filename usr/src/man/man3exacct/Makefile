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

MANSECT= 	3exacct

MANFILES= 	ea_error.3exacct		\
		ea_open.3exacct			\
		ea_pack_object.3exacct		\
		ea_set_item.3exacct

MANLINKS=	ea_alloc.3exacct		\
		ea_attach_to_group.3exacct	\
		ea_attach_to_object.3exacct	\
		ea_close.3exacct		\
		ea_copy_object.3exacct		\
		ea_copy_object_tree.3exacct	\
		ea_free.3exacct			\
		ea_free_item.3exacct		\
		ea_free_object.3exacct		\
		ea_get_creator.3exacct		\
		ea_get_hostname.3exacct		\
		ea_get_object.3exacct		\
		ea_get_object_tree.3exacct	\
		ea_match_object_catalog.3exacct	\
		ea_next_object.3exacct		\
		ea_previous_object.3exacct	\
		ea_set_group.3exacct		\
		ea_strdup.3exacct		\
		ea_strfree.3exacct		\
		ea_unpack_object.3exacct	\
		ea_write_object.3exacct

ea_close.3exacct		:= LINKSRC = ea_open.3exacct

ea_copy_object.3exacct		:= LINKSRC = ea_pack_object.3exacct
ea_copy_object_tree.3exacct	:= LINKSRC = ea_pack_object.3exacct
ea_get_creator.3exacct		:= LINKSRC = ea_pack_object.3exacct
ea_get_hostname.3exacct		:= LINKSRC = ea_pack_object.3exacct
ea_get_object.3exacct		:= LINKSRC = ea_pack_object.3exacct
ea_get_object_tree.3exacct	:= LINKSRC = ea_pack_object.3exacct
ea_next_object.3exacct		:= LINKSRC = ea_pack_object.3exacct
ea_previous_object.3exacct	:= LINKSRC = ea_pack_object.3exacct
ea_unpack_object.3exacct	:= LINKSRC = ea_pack_object.3exacct
ea_write_object.3exacct		:= LINKSRC = ea_pack_object.3exacct

ea_alloc.3exacct		:= LINKSRC = ea_set_item.3exacct
ea_attach_to_group.3exacct	:= LINKSRC = ea_set_item.3exacct
ea_attach_to_object.3exacct	:= LINKSRC = ea_set_item.3exacct
ea_free.3exacct			:= LINKSRC = ea_set_item.3exacct
ea_free_item.3exacct		:= LINKSRC = ea_set_item.3exacct
ea_free_object.3exacct		:= LINKSRC = ea_set_item.3exacct
ea_match_object_catalog.3exacct	:= LINKSRC = ea_set_item.3exacct
ea_set_group.3exacct		:= LINKSRC = ea_set_item.3exacct
ea_strdup.3exacct		:= LINKSRC = ea_set_item.3exacct
ea_strfree.3exacct		:= LINKSRC = ea_set_item.3exacct

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(ROOTMANLINKS)
