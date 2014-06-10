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
# Copyright (c) 2014 Joyent, Inc.  All rights reserved.
#

LIBRARY =	libidspace.a
VERS =		.1
OBJECTS =	id_space.o \
		libidspace.o
COMDIR =	$(SRC)/common/idspace

include ../../Makefile.lib

SRCDIR =	../common
SRCS =		../../../common/idspace/id_space.c
LIBS =		$(DYNLIB) $(LINTLIB)

LDLIBS += 	-lc -lumem

$(LINTLIB) := 	SRCS = $(SRCDIR)/$(LINTSRC)

.KEEP_STATE:

all: $(LIBS)

lint: lintcheck

include ../../Makefile.targ

objs/%.o pics/%.o: $(COMDIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
