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
# Copyright 2021 OmniOS Community Edition (OmniOSce) Association.
#

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/test/Makefile.com

PROG = definit_test.32 definit_test.64

OBJS = definit.o definit_test.o
OBJS32 = $(OBJS:.o=.32.o)
OBJS64 = $(OBJS:.o=.64.o)

DATAFILES = init.data init.expected

CSTD = $(CSTD_GNU99)
CPPFLAGS += -I$(SRC)/common/definit

ROOTOPTPKG = $(ROOT)/opt/os-tests
TESTDIR = $(ROOTOPTPKG)/tests/definit

CMDS = $(PROG:%=$(TESTDIR)/%) $(TESTDIR)/definit
$(CMDS) := FILEMODE = 0555
DATA = $(DATAFILES:%=$(TESTDIR)/%)
$(DATA) := FILEMODE = 0444

LDLIBS += -lc
LDLIBS64 += -lc

all: $(PROG)

install: $(CMDS) $(DATA)

clobber: clean
	-$(RM) $(PROG)

clean:
	-$(RM) $(OBJS32) $(OBJS64)

$(CMDS): $(TESTDIR) $(PROG)

$(TESTDIR):
	$(INS.dir)

$(TESTDIR)/%: %
	$(INS.file)

$(TESTDIR)/%: %.ksh
	$(INS.rename)

%.32.o: %.c
	$(COMPILE.c) $< -o $@

%.64.o: %.c
	$(COMPILE64.c) $< -o $@

%.32.o: $(SRC)/common/definit/%.c
	$(COMPILE.c) $< -o $@

%.64.o: $(SRC)/common/definit/%.c
	$(COMPILE64.c) $< -o $@

definit_test.64: $(OBJS64)
	$(LINK64.c) -o $@ $(OBJS64) $(LDLIBS64)
	$(POST_PROCESS)

definit_test.32: $(OBJS32)
	$(LINK.c) -o $@ $(OBJS32) $(LDLIBS)
	$(POST_PROCESS)


