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

MANSECT = 	9p

MANFILES = 	ddi-forceattach.9p		\
	 	inquiry-device-type.9p		\
	 	no-involuntary-power-cycles.9p	\
	 	pm-components.9p		\
	 	pm.9p				\
	 	removable-media.9p		\
	 	size.9p

MANSOFILES =	Nblock.9p		\
	 	blksize.9p		\
	 	ddi-no-autodetach.9p	\
	 	device-blksize.9p	\
	 	device-nblocks.9p	\
	 	inquiry-product-id.9p	\
	 	inquiry-revision-id.9p	\
	 	inquiry-serial-no.9p	\
	 	inquiry-vendor-id.9p

MANFILES +=	$(MANSOFILES)

ddi-no-autodetach.9p	:= SOSRC = man9p/ddi-forceattach.9p

inquiry-product-id.9p	:= SOSRC = man9p/inquiry-device-type.9p
inquiry-revision-id.9p	:= SOSRC = man9p/inquiry-device-type.9p
inquiry-serial-no.9p	:= SOSRC = man9p/inquiry-device-type.9p
inquiry-vendor-id.9p	:= SOSRC = man9p/inquiry-device-type.9p

Nblock.9p		:= SOSRC = man9p/size.9p
blksize.9p		:= SOSRC = man9p/size.9p
device-blksize.9p	:= SOSRC = man9p/size.9p
device-nblocks.9p	:= SOSRC = man9p/size.9p


.KEEP_STATE:

include ../Makefile.man

install: $(ROOTMANFILES)
