#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
#

LIBRARY =	libtermcap.a
VERS =		.1

# install this library in the root filesystem
include ../../Makefile.rootfs

COMPATLINKS +=	usr/ccs/lib/libtermcap.so
COMPATLINKS64 += usr/ccs/lib/$(MACH64)/libtermcap.so

$(ROOT)/usr/ccs/lib/libtermcap.so := \
	COMPATLINKTARGET=../../../lib/libtermcap.so.1
$(ROOT)/usr/ccs/lib/$(MACH64)/libtermcap.so := \
	COMPATLINKTARGET=../../../../lib/$(MACH64)/libtermcap.so.1

DYNFLAGS +=	$(ZLOADFLTR)
