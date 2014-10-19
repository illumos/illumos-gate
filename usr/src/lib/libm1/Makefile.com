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
# Copyright 2011, Richard Lowe.
#


LIBRARY 	= libm.a
VERS 		= .1

LIBMDIR		= $(SRC)/lib/libm

OBJECTS		= libmv1.o

include		$(SRC)/lib/Makefile.lib
include		$(SRC)/lib/Makefile.rootfs
include 	$(LIBMDIR)/Makefile.libm.com

LIBS 		= $(DYNLIB)
SRCS		= $(OBJECTS:%.o=../common/%.c)
SRCDIR		= ../common/

CPPFLAGS	+= -DLIBM_BUILD
MAPFILEDIR	= ../common/
DYNFLAGS 	+= -zignore -Wl,-F'libm.so.2'
LINTFLAGS64     += -errchk=longptr64

.KEEP_STATE:

all: $(LIBS)

lint: lintcheck
