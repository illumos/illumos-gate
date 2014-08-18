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
# Copyright (c) 2014 Joyent, Inc. All rights reserved.
#

include		../../Makefile.lib

LIBRARY =	libvnd.a
VERS =		.1
OBJECTS =	libvnd.o

include ../../Makefile.lib

LIBS =		$(DYNLIB) $(LINTLIB)
LDLIBS +=	-lc
CPPFLAGS +=	-I../common

SRCDIR =	../common

C99MODE=	-xc99=%all
C99LMODE=	-Xc99=%all

.KEEP_STATE:

all:	$(LIBS)

lint:	lintcheck

include ../../Makefile.targ
