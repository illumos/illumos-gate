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

LIBRARY = libppt.a
VERS = .1

OBJECTS = libppt.o

include $(SRC)/lib/Makefile.lib

SRCDIR = ../common

LIBS = $(DYNLIB) $(LINTLIB)
SRCS =	$(SRCDIR)/libppt.c

CSTD=	$(CSTD_GNU99)
C99LMODE=	-Xc99=%all

#
# lint doesn't like %4s in sscanf().
#
LINTFLAGS += -erroff=E_BAD_FORMAT_ARG_TYPE2
LINTFLAGS64 += -erroff=E_BAD_FORMAT_ARG_TYPE2

$(LINTLIB) := SRCS = $(SRCDIR)/$(LINTSRC)
LDLIBS += -lpcidb -ldevinfo -lcmdutils -lnvpair -lc

.KEEP_STATE:

all: $(LIBS)

lint: lintcheck

include $(SRC)/lib/Makefile.targ
