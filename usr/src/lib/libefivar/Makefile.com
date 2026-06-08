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
# Copyright 2026 Argo Technology East
#

LIBRARY =	libefivar.a
VERS =		.1
OBJECTS =	efivar.o efi_load_option.o efi_devpath.o

include ../../Makefile.lib

# install in the root filesystem so utilities that ship there
# (efibootmgr(8) and friends) can link against it
include ../../Makefile.rootfs

SRCDIR =	../common

CPPFLAGS +=	-I../common
LIBS =		$(DYNLIB)
LDLIBS +=	-lc
CFLAGS +=	$(CCVERBOSE)

.KEEP_STATE:

all: $(LIBS)

include ../../Makefile.targ
