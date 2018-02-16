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
# Copyright 2018, Joyent, Inc.
#

LIBRARY =	libcustr.a
VERS =		.1
OBJECTS =	custr.o

include $(SRC)/lib/Makefile.lib

# Things out of /sbin like dladm require custr, so it should go into /lib so
# they can work in case /usr is split
include $(SRC)/lib/Makefile.rootfs

LIBS =		$(DYNLIB) $(LINTLIB)
LDLIBS +=	-lc
CPPFLAGS +=	-D__EXTENSIONS__

SRCDIR =	../common

.KEEP_STATE:

all: $(LIBS)

lint: lintcheck

include $(SRC)/lib/Makefile.targ
