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
# Copyright 2013 Pluribus Networks Inc.
#

LIBRARY	= libvmmapi.a
VERS		= .1

OBJECTS	= vmmapi.o expand_number.o

# include library definitions
include ../../Makefile.lib

# install this library in the root filesystem
include ../../Makefile.rootfs

SRCDIR		= ../common

LIBS		= $(DYNLIB) $(LINTLIB)

CPPFLAGS	= -I$(COMPAT)/freebsd -I$(CONTRIB)/freebsd \
	$(CPPFLAGS.master) -I$(SRC)/uts/i86pc

$(LINTLIB) :=	SRCS = $(SRCDIR)/$(LINTSRC)

LDLIBS		+= -lc

.KEEP_STATE:

all: $(LIBS)

lint: lintcheck

pics/%.o: $(CONTRIB)/freebsd/lib/libutil/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o: ../common/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

# include library targets
include ../../Makefile.targ
