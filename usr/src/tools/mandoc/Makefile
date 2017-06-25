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

CMDDIR=		$(SRC)/cmd/mandoc
LCDIR=		$(SRC)/lib/libc/port

include		$(SRC)/tools/Makefile.tools
include		$(CMDDIR)/Makefile.common

OBJS +=		fts.o \
		reallocarray.o \
		strtonum.o

CPPFLAGS +=	-I. -include fts.h

.KEEP_STATE:

all:		$(PROG)

install:	all $(ROOTONBLDMACHPROG)

clean:
		$(RM) $(PROG) $(OBJS)

$(PROG):	$(OBJS)
		$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
		$(POST_PROCESS)

%.o:		$(CMDDIR)/%.c
		$(COMPILE.c) -o $@ $<

%.o:		$(LCDIR)/gen/%.c
		$(COMPILE.c) -o $@ $<

include		$(SRC)/tools/Makefile.targ
