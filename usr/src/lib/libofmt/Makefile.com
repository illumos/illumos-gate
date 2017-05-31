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
# Copyright 2017 Nexenta Systems, Inc.
#

LIBRARY=	libofmt.a
VERS=		.1

OBJECTS=	ofmt.o

include		$(SRC)/lib/Makefile.lib
include		$(SRC)/lib/Makefile.rootfs

SRCDIR=		../common

LIBS=		$(DYNLIB) $(LINTLIB)
SRCS=		$(SRCDIR)/ofmt.c

LDLIBS +=	-lc

.KEEP_STATE:

all:		$(LIBS)

lint:		lintcheck

include		$(SRC)/lib/Makefile.targ
