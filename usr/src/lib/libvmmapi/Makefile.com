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
# Copyright 2019 Joyent, Inc.

LIBRARY	= libvmmapi.a
VERS		= .1

OBJECTS	= vmmapi.o expand_number.o

# include library definitions
include ../../Makefile.lib

# install this library in the root filesystem
include ../../Makefile.rootfs

SRCDIR		= ../common

LIBS		= $(DYNLIB)

CPPFLAGS	= -I$(COMPAT)/bhyve -I$(CONTRIB)/bhyve \
	-I$(COMPAT)/bhyve/amd64 -I$(CONTRIB)/bhyve/amd64 \
	$(CPPFLAGS.master) -I$(SRC)/uts/intel

SMOFF += all_func_returns

LDLIBS		+= -lc

.KEEP_STATE:

all: $(LIBS)

pics/%.o: $(CONTRIB)/bhyve/lib/libutil/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o: ../common/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

# include library targets
include ../../Makefile.targ
