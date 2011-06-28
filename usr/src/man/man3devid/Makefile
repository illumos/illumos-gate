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

MANSECT = 	3devid

MANFILES = 	devid_get.3devid

MANSOFILES =	devid_compare.3devid		\
		devid_deviceid_to_nmlist.3devid	\
		devid_free.3devid		\
		devid_free_nmlist.3devid	\
		devid_get_minor_name.3devid	\
		devid_sizeof.3devid		\
		devid_str_decode.3devid		\
		devid_str_encode.3devid		\
		devid_str_free.3devid		\
		devid_valid.3devid

MANFILES +=	$(MANSOFILES)

devid_compare.3devid		:= SOSRC = man3devid/devid_get.3devid
devid_deviceid_to_nmlist.3devid := SOSRC = man3devid/devid_get.3devid
devid_free.3devid		:= SOSRC = man3devid/devid_get.3devid
devid_free_nmlist.3devid	:= SOSRC = man3devid/devid_get.3devid
devid_get_minor_name.3devid	:= SOSRC = man3devid/devid_get.3devid
devid_sizeof.3devid		:= SOSRC = man3devid/devid_get.3devid
devid_str_decode.3devid		:= SOSRC = man3devid/devid_get.3devid
devid_str_encode.3devid		:= SOSRC = man3devid/devid_get.3devid
devid_str_free.3devid		:= SOSRC = man3devid/devid_get.3devid
devid_valid.3devid		:= SOSRC = man3devid/devid_get.3devid

.KEEP_STATE:

include ../Makefile.man

install: $(ROOTMANFILES)
