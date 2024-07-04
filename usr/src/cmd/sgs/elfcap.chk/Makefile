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
# Copyright 2022 Oxide Computer Company
#

PROG	= elfcap.chk
OBJS	= elfcap_chk.o elfcap.o

include	$(SRC)/Makefile.master
include	$(SRC)/Makefile.master.64
include	$(SRC)/Makefile.native
include	../Makefile.com

CSTD =		$(GNU_C99)
NATIVE_LIBS +=	libc.so
#
# We reach into the tools include area which provides us with a snapshot
# of all of the data that we need. This does mean that if someone is in
# bldenv and does incremental builds that change the related ELF header
# files they will need to rebuild that, but the same is true if we move
# this into tools (and it becomes more annoying).
#
CPPFLAGS =	-I$(SRC)/tools/sgs/include $(CPPFLAGS.native) -I$(ELFCAP)
LDFLAGS += $(BDIRECT)

all: $(PROG)

install: $(PROG)

check: $(PROG)
	./$(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS)
	$(POST_PROCESS)

%.o: %.c
	$(COMPILE.c) $<

%.o: $(ELFCAP)/%.c
	$(COMPILE.c) $<

clean:
	$(RM) $(OBJS)

clobber: clean
	$(RM) $(PROG)
