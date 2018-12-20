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
# Copyright 2018 Joyent, Inc.
#

LIBRARY =	libvmm.a
VERS =		.1

OBJECTS =	libvmm.o list.o

include ../Makefile.lib
include ../Makefile.lib.64
include ../Makefile.rootfs

SRCDIR =	.
COMDIR =	$(SRC)/common/list

LIBS = $(DYNLIB)

# The FreeBSD compat and contrib headers need to be first in the search
# path, hence we can't just append them to CPPFLAGS. So we assign CPPFLAGS
# directly and pull in CPPFLAGS.master at the appropriate place.
CPPFLAGS =	-I$(COMPAT)/freebsd -I$(CONTRIB)/freebsd \
		-I$(COMPAT)/freebsd/amd64 -I$(CONTRIB)/freebsd/amd64 \
		$(CPPFLAGS.master) -I$(SRC)/uts/i86pc

LDLIBS +=	-lc -lvmmapi

HDRS =		libvmm.h
HDRDIR =	.
CHECKHDRS =	$(HDRS:%.h=%.check)

.KEEP_STATE:

all: $(LIBS)

install_h: $(ROOTHDRS)

check: $(CHECKHDRS)

pics/%.o: $(COMDIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

install: install_h all $(ROOTLIBS64)

include ../Makefile.targ
