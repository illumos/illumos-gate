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
# Copyright 2014 Garrett D'Amore <garrett@damore.org>
# Copyright 2018, Joyent, Inc.
#

include $(SRC)/Makefile.master

TESTSUBDIR = common

PROG = c_symbols_test cxx_symbols_test

$(BUILD32) PROG32 = $(PROG:%=%_32)
$(BUILD64) PROG64= $(PROG:%=%_64)

SRCS = $(PROG:%=%.c) hdr_test_common.c
COBJS = c_symbols_test.o hdr_test_common.o
CXXOBJS = cxx_symbols_test.o hdr_test_common.o

COBJS32 = $(COBJS:%.o=%_32.o)
CXXOBJS32 = $(CXXOBJS:%.o=%_32.o)
COBJS64 = $(COBJS:%.o=%_64.o)
CXXOBJS64 = $(CXXOBJS:%.o=%_64.o)

# This gets CSTD, *FLAGS, *DIR
include ../Makefile.com

LDLIBS += -lcustr
LDLIBS64 += -lcustr

CMDS =	$(PROG32:%=$(TESTDIR)/%) \
	$(PROG64:%=$(TESTDIR)/%)

all: $(PROG32) $(PROG64)

install: $(TESTDIR) $(CMDS)

clobber: clean
	-$(RM) $(PROG32) $(PROG64)

clean:
	-$(RM) $(COBJS32) $(CXXOBJS32) $(COBJS64) $(CXXOBJS64)

c_symbols_test_32: $(COBJS32)
	$(LINK.c) $(COBJS32) -o $@ $(LDLIBS)
	$(POST_PROCESS)

cxx_symbols_test_32: $(CXXOBJS32)
	$(LINK.c) $(CXXOBJS32) -o $@ $(LDLIBS)
	$(POST_PROCESS)

c_symbols_test_64: $(COBJS64)
	$(LINK64.c) $(COBJS64) -o $@ $(LDLIBS64)
	$(POST_PROCESS)

cxx_symbols_test_64: $(CXXOBJS64)
	$(LINK64.c) $(CXXOBJS64) -o $@ $(LDLIBS64)
	$(POST_PROCESS)

%_32.o: %.c
	$(COMPILE.c) -o $@ $(CFLAGS_$(MACH)) -DARCH=\"$(MACH)\" $<
	$(POST_PROCESS_O)

%_64.o: %.c
	$(COMPILE64.c) -o $@ $(CFLAGS_$(MACH64)) -DARCH=\"$(MACH64)\" $<
	$(POST_PROCESS_O)
