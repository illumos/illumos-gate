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

# Copyright 2015, Richard Lowe.

LIBRARY = libbsd.a
VERS = .1
OBJECTS = bsd.o

include $(SRC)/lib/Makefile.lib
include ../../Makefile.com

LIBS = $(LIBRARY)
SRCDIR = $(SRC)/cmd/make/lib/bsd
CPPFLAGS += -D_FILE_OFFSET_BITS=64

all: $(LIBS)

install: all

lint:

include $(SRC)/lib/Makefile.targ
