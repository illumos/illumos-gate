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

MANSECT= 	9p

MANFILES= 	ddi-forceattach.9p		\
	 	inquiry-device-type.9p		\
	 	no-involuntary-power-cycles.9p	\
	 	pm-components.9p		\
	 	pm.9p				\
	 	removable-media.9p		\
	 	size.9p

MANLINKS=	Nblock.9p		\
	 	blksize.9p		\
	 	ddi-no-autodetach.9p	\
	 	device-blksize.9p	\
	 	device-nblocks.9p	\
	 	inquiry-product-id.9p	\
	 	inquiry-revision-id.9p	\
	 	inquiry-serial-no.9p	\
	 	inquiry-vendor-id.9p

ddi-no-autodetach.9p	:= LINKSRC = ddi-forceattach.9p

inquiry-product-id.9p	:= LINKSRC = inquiry-device-type.9p
inquiry-revision-id.9p	:= LINKSRC = inquiry-device-type.9p
inquiry-serial-no.9p	:= LINKSRC = inquiry-device-type.9p
inquiry-vendor-id.9p	:= LINKSRC = inquiry-device-type.9p

Nblock.9p		:= LINKSRC = size.9p
blksize.9p		:= LINKSRC = size.9p
device-blksize.9p	:= LINKSRC = size.9p
device-nblocks.9p	:= LINKSRC = size.9p

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(ROOTMANLINKS)
