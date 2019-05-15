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
# Copyright 2019 Joyent, Inc.
#

PROG =		bhyvectl

include ../Makefile.cmd
include ../Makefile.cmd.64

SRCS =		bhyvectl.c
OBJS =		$(SRCS:.c=.o) humanize_number.o

CLEANFILES =	$(PROG)
CLOBBERFILES +=	$(ROOTUSRSBINPROG)

.KEEP_STATE:

CFLAGS +=	$(CCVERBOSE)
CPPFLAGS =	-I$(COMPAT)/freebsd -I$(CONTRIB)/freebsd \
		-I$(COMPAT)/freebsd/amd64 -I$(CONTRIB)/freebsd/amd64 \
		$(CPPFLAGS.master) \
		-I$(ROOT)/usr/platform/i86pc/include \
		-I$(SRC)/uts/i86pc/io/vmm
LDLIBS +=	-lvmmapi

CERRWARN +=	-_gcc=-Wno-uninitialized

# main() is too hairy for smatch
bhyvectl.o := SMATCH=off

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDFLAGS) $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTUSRSBINPROG)

clean:
	$(RM) $(OBJS) $(CLEANFILES)

lint:	lint_SRCS

include ../Makefile.targ

%.o: $(CONTRIB)/freebsd/lib/libutil/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
