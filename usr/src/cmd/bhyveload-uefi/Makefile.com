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

PROG= bhyveload-uefi

SRCS = ../bhyveload-uefi.c expand_number.c
OBJS = bhyveload-uefi.o expand_number.o

include ../../Makefile.cmd

.KEEP_STATE:

CFLAGS +=	$(CCVERBOSE)
CPPFLAGS =	-I$(COMPAT)/freebsd -I$(CONTRIB)/freebsd $(CPPFLAGS.master) \
	        -I$(ROOT)/usr/platform/i86pc/include
LDLIBS +=	-lvmmapi

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDFLAGS) $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTUSRSBINPROG)

clean:
	$(RM) $(OBJS)

lint:	lint_SRCS

include ../../Makefile.targ

%.o: ../%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

%.o: $(CONTRIB)/freebsd/lib/libutil/%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

