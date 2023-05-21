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
# Copyright 2015 Joyent, Inc.
#

LIBRARY =	libvarpd.a
VERS =		.1
OBJECTS =	libvarpd.o \
		libvarpd_arp.o \
		libvarpd_client.o \
		libvarpd_door.o \
		libvarpd_overlay.o \
		libvarpd_panic.o \
		libvarpd_persist.o \
		libvarpd_prop.o \
		libvarpd_plugin.o \
		libvarpd_util.o

include ../../../Makefile.lib

# install this library in the root filesystem
include ../../../Makefile.rootfs

LIBS =		$(DYNLIB)
LDLIBS +=	-lc -lavl -lumem -lidspace -lnvpair -lmd -lrename
CPPFLAGS +=	-I../common

CSTD=		$(CSTD_GNU99)

SRCDIR =	../common

.KEEP_STATE:

all:	$(LIBS)

include ../../../Makefile.targ
