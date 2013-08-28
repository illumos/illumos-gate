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

MANSECT= 	3devid

MANFILES= 	devid_get.3devid

MANLINKS=	devid_compare.3devid		\
		devid_deviceid_to_nmlist.3devid	\
		devid_free.3devid		\
		devid_free_nmlist.3devid	\
		devid_get_minor_name.3devid	\
		devid_sizeof.3devid		\
		devid_str_decode.3devid		\
		devid_str_encode.3devid		\
		devid_str_free.3devid		\
		devid_valid.3devid

devid_compare.3devid		:= LINKSRC = devid_get.3devid
devid_deviceid_to_nmlist.3devid := LINKSRC = devid_get.3devid
devid_free.3devid		:= LINKSRC = devid_get.3devid
devid_free_nmlist.3devid	:= LINKSRC = devid_get.3devid
devid_get_minor_name.3devid	:= LINKSRC = devid_get.3devid
devid_sizeof.3devid		:= LINKSRC = devid_get.3devid
devid_str_decode.3devid		:= LINKSRC = devid_get.3devid
devid_str_encode.3devid		:= LINKSRC = devid_get.3devid
devid_str_free.3devid		:= LINKSRC = devid_get.3devid
devid_valid.3devid		:= LINKSRC = devid_get.3devid

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(ROOTMANLINKS)
