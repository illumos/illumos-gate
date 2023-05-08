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
# Copyright 2019, Joyent, Inc.
#

LIBRARY =	libpcsc.a
VERS =		.1
OBJECTS =	libpcsc.o list.o

include ../../Makefile.lib

LIBS =		$(DYNLIB)
LDLIBS +=	-lc
CPPFLAGS +=	-I../common

SRCDIR =	../common

CSTD =		$(CSTD_GNU99)

.KEEP_STATE:

all:	$(LIBS)

objs/%.o pics/%.o: $(SRC)/common/list/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

include ../../Makefile.targ
