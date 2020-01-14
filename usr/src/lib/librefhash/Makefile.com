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
# Copyright 2020 Joyent, Inc.
#

LIBRARY =	librefhash.a
VERS =		.1
OBJECTS =	list.o \
		refhash.o
HASHCOMDIR =	$(SRC)/common/refhash
LISTCOMDIR =	$(SRC)/common/list

include ../../Makefile.lib

SRCDIR =	../common
SRCS =		$(HASHCOMDIR)/refhash.c $(LISTCOMDIR)/list.c
LIBS =		$(DYNLIB)

LDLIBS += 	-lc -lumem

.KEEP_STATE:

all: $(LIBS)

include ../../Makefile.targ

objs/%.o pics/%.o: $(LISTCOMDIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

objs/%.o pics/%.o: $(HASHCOMDIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
